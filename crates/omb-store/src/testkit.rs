//! Private integration-test fixture, included only by testkit-gated test targets.
use rustix::process::{Pid, Signal};
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::PathBuf,
    process::{Command as StdCommand, Stdio},
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
fn random() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn private(path: &std::path::Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
pub struct ClientOwner(Option<tokio_postgres::Client>);
impl std::ops::Deref for ClientOwner {
    type Target = tokio_postgres::Client;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for ClientOwner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}
pub struct Session {
    pub client: ClientOwner,
    driver: Option<JoinHandle<Result<(), tokio_postgres::Error>>>,
}
impl Session {
    pub async fn close(mut self) {
        self.client.0.take();
        let mut driver = self.driver.take().unwrap();
        match timeout(Duration::from_secs(5), &mut driver).await {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => {
                driver.abort();
                let _ = driver.await;
                panic!("own test driver close deadline; cancellation joined");
            }
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.client.0.take();
        if let Some(driver) = self.driver.take() {
            driver.abort();
            eprintln!(
                "own test session dropped without async close; driver abort requested, destruction unconfirmed; failed fixture retained"
            );
        }
    }
}
pub struct Fixture {
    root: PathBuf,
    child: Option<Child>,
    port: u16,
    password: String,
}
impl Fixture {
    pub async fn new() -> Self {
        let bin = PathBuf::from(
            std::env::var_os("OMB_TEST_PG_BIN_DIR")
                .expect("explicit own PG17.11 binary directory required"),
        );
        assert!(bin.is_absolute());
        let root = std::env::temp_dir().join(format!("omb-store-{}", random()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let password = format!("{}{}", random(), random());
        private(&root.join("password"), password.as_bytes());
        private(&root.join("pg.log"), b"");
        let log = fs::OpenOptions::new()
            .append(true)
            .open(root.join("pg.log"))
            .unwrap();
        let mut initdb = Command::new(bin.join("initdb"));
        initdb
            .arg("-D")
            .arg(root.join("data"))
            .args([
                "-U",
                "openmybot",
                "--auth=scram-sha-256",
                "-E",
                "UTF8",
                "--locale=C",
            ])
            .arg(format!("--pwfile={}", root.join("password").display()))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let mut initializing = initdb.kill_on_drop(true).spawn().unwrap();
        let status = match timeout(Duration::from_secs(30), initializing.wait()).await {
            Ok(result) => result.unwrap(),
            Err(_) => {
                let _ = initializing.start_kill();
                let _ = timeout(Duration::from_secs(5), initializing.wait()).await;
                panic!("own initdb deadline; fixture retained");
            }
        };
        println!("own initdb exit={:?}", status.code());
        assert!(status.success());
        fs::remove_file(root.join("password")).unwrap();
        let mut fixture = Self {
            root,
            child: None,
            port: 0,
            password,
        };
        let limit = deadline();
        for _ in 0..16 {
            let mut bytes = [0; 2];
            getrandom::fill(&mut bytes).unwrap();
            fixture.port = 49152 + u16::from_le_bytes(bytes) % 16384;
            let log = fs::OpenOptions::new()
                .append(true)
                .open(fixture.root.join("pg.log"))
                .unwrap();
            let mut command = StdCommand::new(bin.join("postgres"));
            command
                .arg("-D")
                .arg(fixture.root.join("data"))
                .args([
                    "-c",
                    "listen_addresses=127.0.0.1",
                    "-c",
                    &format!("port={}", fixture.port),
                    "-c",
                    "unix_socket_directories=",
                    "-c",
                    "timezone=America/Los_Angeles",
                    "-c",
                    "track_activity_query_size=16384",
                ])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .process_group(0);
            fixture.child = Some(Command::from(command).kill_on_drop(true).spawn().unwrap());
            loop {
                if fixture
                    .child
                    .as_mut()
                    .unwrap()
                    .try_wait()
                    .unwrap()
                    .is_some()
                {
                    fixture.child.take();
                    break;
                }
                assert!(Instant::now() < limit, "own PostgreSQL ready deadline");
                let record = fs::read_to_string(fixture.root.join("data/postmaster.pid"))
                    .unwrap_or_default();
                let lines: Vec<_> = record.lines().collect();
                if lines.len() >= 8
                    && lines[0].parse::<u32>().ok() == fixture.child.as_ref().unwrap().id()
                    && lines[3].parse::<u16>().ok() == Some(fixture.port)
                    && lines[7].trim() == "ready"
                {
                    let session = fixture.connect().await;
                    let row=session.client.query_one("SELECT current_setting('server_version_num'),current_setting('TimeZone'),current_setting('track_activity_query_size'),current_setting('data_directory')",&[]).await.unwrap();
                    assert_eq!(row.get::<_, String>(0), "170011");
                    assert_eq!(row.get::<_, String>(1), "America/Los_Angeles");
                    assert_eq!(row.get::<_, String>(2), "16kB");
                    assert_eq!(
                        fs::canonicalize(row.get::<_, String>(3)).unwrap(),
                        fs::canonicalize(fixture.root.join("data")).unwrap()
                    );
                    session.close().await;
                    return fixture;
                }
                sleep(Duration::from_millis(25)).await;
            }
        }
        panic!("own PostgreSQL port attempts exhausted")
    }
    /// A client and its driver task for components that own their connection.
    #[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
    pub async fn open(
        &mut self,
    ) -> (
        tokio_postgres::Client,
        JoinHandle<Result<(), tokio_postgres::Error>>,
    ) {
        let mut session = self.connect().await;
        (
            session.client.0.take().unwrap(),
            session.driver.take().unwrap(),
        )
    }
    pub async fn connect(&mut self) -> Session {
        assert!(self.child.as_mut().unwrap().try_wait().unwrap().is_none());
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(self.port)
            .user("openmybot")
            .password(&self.password)
            .dbname("postgres")
            .connect_timeout(Duration::from_secs(1));
        let (client, connection) = timeout(
            Duration::from_secs(2),
            config.connect(tokio_postgres::NoTls),
        )
        .await
        .unwrap()
        .unwrap();
        Session {
            client: ClientOwner(Some(client)),
            driver: Some(tokio::spawn(connection)),
        }
    }
    pub async fn stop(mut self) {
        if let Some(mut child) = self.child.take() {
            let pid = Pid::from_raw(child.id().unwrap() as i32).unwrap();
            let mut reaped = false;
            let mut exit_code = None;
            for signal in [Signal::INT, Signal::QUIT] {
                let _ = rustix::process::kill_process(pid, signal);
                match timeout(Duration::from_secs(30), child.wait()).await {
                    Ok(Ok(status)) => {
                        exit_code = status.code();
                        reaped = true;
                        break;
                    }
                    Ok(Err(_)) => break,
                    Err(_) => (),
                }
            }
            if !reaped {
                let _ = child.start_kill();
                match timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(Ok(status)) => {
                        reaped = true;
                        exit_code = status.code();
                    }
                    _ => reaped = false,
                }
            }
            if !reaped {
                self.child = Some(child);
                panic!("own PG wait unconfirmed; preserve fixture");
            }
            println!("own PostgreSQL child reaped; native_exit={exit_code:?}");
        }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Some(raw) = child.id() {
                let _ =
                    rustix::process::kill_process(Pid::from_raw(raw as i32).unwrap(), Signal::INT);
            }
            let stop = std::time::Instant::now() + Duration::from_secs(35);
            while std::time::Instant::now() < stop {
                if child.try_wait().ok().flatten().is_some() {
                    eprintln!("failed own fixture: PG child reaped; directory retained");
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.start_kill();
            let limit = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < limit {
                if child.try_wait().ok().flatten().is_some() {
                    eprintln!("failed own fixture: PG child reaped; directory retained");
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            eprintln!("failed own fixture: PG wait unconfirmed; directory retained");
        }
    }
}
/// Receiver rows are created by a later task; tests insert an active one directly.
#[allow(dead_code, reason = "used by the pairing and bindings targets only")]
pub async fn insert_receiver(
    client: &tokio_postgres::Client,
    channel: &str,
    source_key: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,credential_envelope,status,created_at,activated_at,revision) VALUES ($1,'receiver',$2,$3,'test-envelope','active',statement_timestamp(),statement_timestamp(),1)",&[&id,&channel,&source_key]).await.unwrap();
    id
}
/// Moves a pending row's expiry relative to the database clock.
#[allow(dead_code, reason = "used by the pairing target only")]
pub async fn set_pairing_expires_at(
    client: &tokio_postgres::Client,
    binding_id: uuid::Uuid,
    seconds_from_now: f64,
) {
    assert_eq!(client.execute("UPDATE openmybot.channel_bindings SET pairing_expires_at=statement_timestamp()+make_interval(secs=>$2) WHERE binding_id=$1",&[&binding_id,&seconds_from_now]).await.unwrap(),1);
}
/// Moves one accepted event relative to the database clock.
#[allow(dead_code, reason = "used by the pairing target only")]
pub async fn set_accepted_at(
    client: &tokio_postgres::Client,
    event_key: &str,
    seconds_from_now: f64,
) {
    assert_eq!(client.execute("UPDATE openmybot.channel_events SET accepted_at=statement_timestamp()+make_interval(secs=>$2) WHERE event_key=$1",&[&event_key,&seconds_from_now]).await.unwrap(),1);
}
/// An active receiver row with a caller-chosen id and credential envelope.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_receiver_with(
    client: &tokio_postgres::Client,
    binding_id: uuid::Uuid,
    channel: &str,
    source_key: &str,
    envelope: &str,
) {
    assert_eq!(client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,credential_envelope,status,created_at,activated_at,revision) VALUES ($1,'receiver',$2,$3,$4,'active',statement_timestamp(),statement_timestamp(),1)",&[&binding_id,&channel,&source_key,&envelope]).await.unwrap(),1);
}
/// Moves one timestamp column of an event or gap row relative to the database clock.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn shift_event(
    client: &tokio_postgres::Client,
    record_id: uuid::Uuid,
    column: &str,
    seconds_from_now: f64,
) {
    let sql = format!(
        "UPDATE openmybot.channel_events SET {column}=statement_timestamp()+make_interval(secs=>$2) WHERE record_id=$1"
    );
    assert_eq!(
        client
            .execute(&sql, &[&record_id, &seconds_from_now])
            .await
            .unwrap(),
        1
    );
}
/// Writes the terminal columns that a later task's terminal subscriber owns.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn set_terminal(client: &tokio_postgres::Client, record_id: uuid::Uuid, kind: &str) {
    assert_eq!(client.execute("UPDATE openmybot.channel_events SET terminal_kind=$2,terminal_at=statement_timestamp() WHERE record_id=$1",&[&record_id,&kind]).await.unwrap(),1);
}
/// One row as JSON, selected by its uuid key column.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn read_row(
    client: &tokio_postgres::Client,
    table: &str,
    key: &str,
    id: uuid::Uuid,
) -> serde_json::Value {
    let sql = format!("SELECT row_to_json(t) FROM openmybot.{table} t WHERE {key}=$1");
    client.query_one(&sql, &[&id]).await.unwrap().get(0)
}
/// An active sender row on the receiver's source, revision 1, with the given identity and thread.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_sender(
    client: &tokio_postgres::Client,
    channel: &str,
    source_key: &str,
    sender_key: &str,
    thread_id: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,chat_key,workspace_dir,thread_id,granted_generation,revision,status,created_at,activated_at) VALUES ($1,'sender',$2,$3,$4,$4,'/workspaces/project',$5,1,1,'active',statement_timestamp(),statement_timestamp())",&[&id,&channel,&source_key,&sender_key,&thread_id]).await.unwrap(),1);
    id
}
/// An active host binding on the given workspace, revision 1.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_host_binding(client: &tokio_postgres::Client, workspace: &str) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,workspace_dir,granted_generation,revision,status,created_at,activated_at) VALUES ($1,'host','host','crabcode','host:crabcode',$2,1,1,'active',statement_timestamp(),statement_timestamp())",&[&id,&workspace]).await.unwrap(),1);
    id
}
/// Like `insert_sender`, on the given channel and workspace.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_sender_in(
    client: &tokio_postgres::Client,
    channel: &str,
    source_key: &str,
    sender_key: &str,
    thread_id: &str,
    workspace: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,chat_key,workspace_dir,thread_id,granted_generation,revision,status,created_at,activated_at) VALUES ($1,'sender',$2,$3,$4,$4,$5,$6,1,1,'active',statement_timestamp(),statement_timestamp())",&[&id,&channel,&source_key,&sender_key,&workspace,&thread_id]).await.unwrap(),1);
    id
}
/// An accepted message of the binding carrying the given run, thread and dispatch status.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_event_for_run(
    client: &tokio_postgres::Client,
    binding_id: uuid::Uuid,
    run_id: &str,
    thread_id: &str,
    status: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) SELECT $1,'event',b.channel_kind,b.source_key,$6,statement_timestamp(),b.binding_id,'accepted_message','test message',sha256('test message'::bytea),$3,$4,$5 FROM openmybot.channel_bindings b WHERE b.binding_id=$2",&[&id,&binding_id,&run_id,&thread_id,&status,&format!("op:{id}")]).await.unwrap(),1);
    id
}
/// The control interface's decision, under a control token row written for it. Built only as
/// `omb_store::testkit`: the targets that include this file by path have no crate items.
#[cfg(not(test))]
pub async fn decide(
    client: &tokio_postgres::Client,
    permission_id: &str,
    decision: crate::Decision,
) -> crate::Decided {
    let token = uuid::Uuid::now_v7();
    let mut digest = [0; 32];
    getrandom::fill(&mut digest).unwrap();
    assert_eq!(client.execute("INSERT INTO openmybot.control_tokens(token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier,pg_timeline_id,restore_detected,created_at,last_heartbeat_at,revoked_at,revoke_reason) VALUES ($1,$2,1,'0123456789abcdef0123456789abcdef01234567','0.0.0','test',1,false,statement_timestamp(),statement_timestamp(),statement_timestamp(),'daemon_stop')",&[&token,&digest.as_slice()]).await.unwrap(),1);
    crate::decide_permission(client, permission_id, decision, token, deadline())
        .await
        .unwrap()
}
/// An undecided permission row of the run that expires `expires_in_secs` after the database clock.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_permission_row(
    client: &tokio_postgres::Client,
    binding_id: uuid::Uuid,
    run_id: &str,
    permission_id: &str,
    expires_in_secs: f64,
) {
    assert_eq!(client.execute("INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,native_request_id,tool_name,input_summary,input_sha256,requested_at,expires_at) VALUES (gen_random_uuid(),'permission',$2,$1,$3,$3,'Write','{\"file_path\":\"notes.txt\"}',sha256('notes.txt'::bytea),statement_timestamp(),statement_timestamp()+make_interval(secs=>$4))",&[&binding_id,&run_id,&permission_id,&expires_in_secs]).await.unwrap(),1);
}
/// One permission row as JSON.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn permission_row_json(
    client: &tokio_postgres::Client,
    permission_id: &str,
) -> serde_json::Value {
    client.query_one("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='permission' AND permission_id=$1",&[&permission_id]).await.unwrap().get(0)
}
/// A delivery row on the binding's channel and chat; a finished status gets `finished_at`, and
/// `next_attempt_in_secs` schedules it relative to the database clock.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_delivery(
    client: &tokio_postgres::Client,
    binding: uuid::Uuid,
    kind: &str,
    key: &str,
    body: Option<&str>,
    status: &str,
    next_attempt_in_secs: Option<f64>,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,body,status,next_attempt_at,created_at,finished_at) SELECT $1,b.binding_id,b.channel_kind,b.chat_key,$3,$4,$5,$6,statement_timestamp()+make_interval(secs=>$7),statement_timestamp(),CASE WHEN $6 IN ('sent','failed','unknown') THEN statement_timestamp() END FROM openmybot.channel_bindings b WHERE b.binding_id=$2",&[&id,&binding,&kind,&key,&body,&status,&next_attempt_in_secs]).await.unwrap(),1);
    id
}
/// A session row of the run that already ended with `end_reason`, its summary and artifacts.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_ended_session(
    client: &tokio_postgres::Client,
    binding: uuid::Uuid,
    run_id: &str,
    end_reason: &str,
    summary: Option<&str>,
    artifacts: &[&str],
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at,ended_at,end_reason,result_summary,artifact_paths,stderr_tail) SELECT $1,'session',$3,b.binding_id,'crabcode',b.workspace_dir,statement_timestamp(),statement_timestamp(),$4,$5,$6,'' FROM openmybot.channel_bindings b WHERE b.binding_id=$2",&[&id,&binding,&run_id,&end_reason,&summary,&artifacts]).await.unwrap(),1);
    id
}
/// A session row of the run that started and never ended, with the given process group.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn insert_orphan_session(
    client: &tokio_postgres::Client,
    binding: uuid::Uuid,
    run_id: &str,
    pgid: Option<i32>,
) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    assert_eq!(client.execute("INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at,child_pid,pgid) SELECT $1,'session',$3,b.binding_id,'crabcode',b.workspace_dir,statement_timestamp(),$4,$4 FROM openmybot.channel_bindings b WHERE b.binding_id=$2",&[&id,&binding,&run_id,&pgid]).await.unwrap(),1);
    id
}
/// Moves one timestamp column of one row, selected by its uuid key, relative to the database clock.
#[allow(dead_code, reason = "used by omb_store::testkit consumers only")]
pub async fn shift_column(
    client: &tokio_postgres::Client,
    table: &str,
    key_column: &str,
    id: uuid::Uuid,
    column: &str,
    seconds_from_now: f64,
) {
    let sql = format!(
        "UPDATE openmybot.{table} SET {column}=statement_timestamp()+make_interval(secs=>$2) WHERE {key_column}=$1"
    );
    assert_eq!(
        client
            .execute(&sql, &[&id, &seconds_from_now])
            .await
            .unwrap(),
        1
    );
}
