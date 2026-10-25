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
pub(crate) fn deadline() -> Instant {
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
pub(crate) struct ClientOwner(Option<tokio_postgres::Client>);
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
pub(crate) struct Session {
    pub(crate) client: ClientOwner,
    driver: Option<JoinHandle<Result<(), tokio_postgres::Error>>>,
}
impl Session {
    pub(crate) async fn close(mut self) {
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
pub(crate) struct Fixture {
    root: PathBuf,
    child: Option<Child>,
    port: u16,
    password: String,
}
impl Fixture {
    pub(crate) async fn new() -> Self {
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
    pub(crate) async fn connect(&mut self) -> Session {
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
    pub(crate) async fn stop(mut self) {
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
