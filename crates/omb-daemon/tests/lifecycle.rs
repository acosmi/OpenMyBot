//! Own disposable clusters only. Run ignored cases serially with OMB_TEST_PG_BIN_DIR set explicitly.
use omb_daemon::{
    DaemonError, DaemonOptions, ErrorClass, InitOptions, StatusOptions, StatusSnapshot, daemon,
    init, status,
};
use rustix::process::{Pid, Signal};
use std::{
    cell::Cell,
    fs,
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
struct Fixture {
    root: PathBuf,
    pg_bin: PathBuf,
    last_pg_pid: Cell<Option<u32>>,
}
impl Fixture {
    fn new() -> Self {
        let pg_bin = std::env::var_os("OMB_TEST_PG_BIN_DIR")
            .map(PathBuf::from)
            .expect("explicit own PG17.11 test binary directory required");
        assert!(pg_bin.is_absolute());
        let mut bytes = [0; 5];
        getrandom::fill(&mut bytes).unwrap();
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let root = std::env::temp_dir().join(format!("omb{suffix}"));
        assert!(
            root.join("run/control.sock")
                .as_os_str()
                .as_encoded_bytes()
                .len()
                <= 103
        );
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self {
            root,
            pg_bin,
            last_pg_pid: Cell::new(None),
        }
    }
    async fn initialize(&self) {
        init(InitOptions {
            data_dir: self.root.clone(),
            pg_bin_dir: self.pg_bin.clone(),
        })
        .await
        .unwrap();
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(self.root.join("pg/data/postgresql.conf"))
            .unwrap();
        config
            .write_all(b"\ntimezone='America/Los_Angeles'\ntrack_activity_query_size=16384\n")
            .unwrap();
    }
    fn spawn(&self, name: &str) -> OwnedDaemon {
        let mut random = [0; 4];
        getrandom::fill(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let out = self.root.join(format!("{suffix}.out"));
        let err = self.root.join(format!("{suffix}.err"));
        private_file(&out, b"");
        private_file(&err, b"");
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--include-ignored", "--nocapture"])
            .env_clear()
            .env("OMB_TEST_CHILD_DATA", &self.root)
            .env("OMB_TEST_CHILD", "daemon")
            .stdin(Stdio::null())
            .stdout(fs::OpenOptions::new().append(true).open(&out).unwrap())
            .stderr(fs::OpenOptions::new().append(true).open(&err).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        println!(
            "spawn own test daemon pid={}; command=isolated lifecycle test child",
            child.id()
        );
        OwnedDaemon {
            child: Some(child),
            out,
            err,
        }
    }
    async fn ready(&self) -> StatusSnapshot {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(snapshot) = status(StatusOptions {
                data_dir: self.root.clone(),
            })
            .await
            {
                self.last_pg_pid.set(Some(snapshot.pg_pid));
                return snapshot;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "own daemon readiness deadline"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    fn no_pg(&self) {
        if let Some(pid) = self.last_pg_pid.get().and_then(|p| Pid::from_raw(p as i32)) {
            assert_eq!(
                rustix::process::test_kill_process(pid),
                Err(rustix::io::Errno::SRCH)
            );
            assert_eq!(
                rustix::process::test_kill_process_group(pid),
                Err(rustix::io::Errno::SRCH)
            );
        }
        if let Ok(text) = fs::read_to_string(self.root.join("pg/data/postmaster.pid"))
            && let Some(pid) = text
                .lines()
                .next()
                .and_then(|s| s.parse::<i32>().ok())
                .and_then(Pid::from_raw)
        {
            assert_eq!(
                rustix::process::test_kill_process(pid),
                Err(rustix::io::Errno::SRCH),
                "own PostgreSQL remains alive"
            );
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Keep a failed fixture when a process remains, so evidence/data cannot be erased underneath it.
        let running = fs::read_to_string(self.root.join("pg/data/postmaster.pid"))
            .ok()
            .and_then(|s| s.lines().next()?.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok());
        if !running {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
struct OwnedDaemon {
    child: Option<Child>,
    out: PathBuf,
    err: PathBuf,
}
impl OwnedDaemon {
    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn signal(&self, signal: Signal) {
        rustix::process::kill_process(Pid::from_raw(self.pid() as i32).unwrap(), signal).unwrap();
    }
    async fn wait(&mut self) -> i32 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                let code = status.code().unwrap_or(-1);
                self.child.take();
                println!("own daemon exit={code}; child reaped");
                return code;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "own daemon stop deadline"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn stop(&mut self, signal: Signal) {
        self.signal(signal);
        assert_eq!(self.wait().await, 0);
    }
    fn output(&self) -> String {
        format!(
            "{}{}",
            fs::read_to_string(&self.out).unwrap(),
            fs::read_to_string(&self.err).unwrap()
        )
    }
}
impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process(
                Pid::from_raw(child.id() as i32).unwrap(),
                Signal::TERM,
            );
            let deadline = Instant::now() + Duration::from_secs(90);
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
async fn child_entry() -> bool {
    if std::env::var_os("OMB_TEST_CHILD").as_deref() != Some(std::ffi::OsStr::new("daemon")) {
        return false;
    }
    let result = daemon(DaemonOptions {
        data_dir: PathBuf::from(std::env::var_os("OMB_TEST_CHILD_DATA").unwrap()),
    })
    .await;
    let code = match result {
        Ok(()) => 0,
        Err(error) => {
            println!("{}", error.code());
            match error.class() {
                ErrorClass::Usage => 2,
                ErrorClass::NotRunning => 3,
                ErrorClass::Rejected => 4,
                ErrorClass::Internal => 5,
            }
        }
    };
    std::process::exit(code)
}
async fn connect_own(
    fixture: &Fixture,
) -> (
    tokio_postgres::Client,
    tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    let pid = fs::read_to_string(fixture.root.join("pg/data/postmaster.pid")).unwrap();
    let port: u16 = pid.lines().nth(3).unwrap().parse().unwrap();
    let password = fs::read_to_string(fixture.root.join("pg/password")).unwrap();
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("openmybot")
        .password(password)
        .dbname("openmybot")
        .connect_timeout(Duration::from_secs(1));
    let (client, connection) = tokio::time::timeout(
        Duration::from_secs(2),
        config.connect(tokio_postgres::NoTls),
    )
    .await
    .unwrap()
    .unwrap();
    (client, tokio::spawn(connection))
}
async fn close_own(
    client: tokio_postgres::Client,
    mut driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
) {
    drop(client);
    match tokio::time::timeout(Duration::from_secs(5), &mut driver).await {
        Ok(result) => result.unwrap().unwrap(),
        Err(_) => {
            driver.abort();
            let _ = driver.await;
            panic!("own test driver close timeout; cancelled and joined");
        }
    }
}
async fn query_own(fixture: &Fixture, query: &str) -> Vec<tokio_postgres::Row> {
    let (client, driver) = connect_own(fixture).await;
    let result = tokio::time::timeout(Duration::from_secs(10), client.query(query, &[])).await;
    close_own(client, driver).await;
    result.unwrap().unwrap()
}
fn assert_private(path: &Path, mode: u32) {
    let meta = fs::symlink_metadata(path).unwrap();
    assert!(!meta.file_type().is_symlink());
    assert_eq!(meta.mode() & 0o7777, mode);
    assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
}

#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; run serially"]
async fn init_creates_private_independent_pg_cluster() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    let result = init(InitOptions {
        data_dir: fixture.root.clone(),
        pg_bin_dir: fixture.pg_bin.clone(),
    })
    .await
    .unwrap();
    assert!(result.deployment_id.starts_with("omb-local-"));
    assert_eq!(result.deployment_id.len(), 42);
    for dir in [
        "",
        "keys",
        "pg",
        "pg/data",
        "run",
        "tenant",
        "hosts",
        "hosts/crabcode",
        "hosts/crabcode/tmp",
        "logs",
    ] {
        assert_private(&fixture.root.join(dir), 0o700);
    }
    for file in [
        "config.toml",
        "keys/vault-kek.key",
        "keys/app-master.key",
        "pg/password",
        "pg/data/pg_hba.conf",
    ] {
        assert_private(&fixture.root.join(file), 0o600);
    }
    let vault = fs::read(fixture.root.join("keys/vault-kek.key")).unwrap();
    let master = fs::read(fixture.root.join("keys/app-master.key")).unwrap();
    assert_eq!(vault.len(), 32);
    assert_eq!(master.len(), 32);
    assert_ne!(vault, master);
    let password = fs::read(fixture.root.join("pg/password")).unwrap();
    assert_eq!(password.len(), 64);
    assert!(
        password
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    );
    assert_eq!(
        fs::read(fixture.root.join("pg/data/pg_hba.conf")).unwrap(),
        b"host all openmybot 127.0.0.1/32 scram-sha-256"
    );
    assert!(!fixture.root.join("pg/initdb-password").exists());
    fixture.no_pg();
    let status = Command::new(fixture.pg_bin.join("postgres"))
        .args(["--single", "-D"])
        .arg(fixture.root.join("pg/data"))
        .arg("openmybot")
        .env_clear()
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "initialized database must exist");
    fixture.no_pg();
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; run serially"]
async fn init_refuses_nonempty_directory_without_mutation() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    private_file(&fixture.root.join("sentinel"), b"preserve bytes");
    let before = fs::read(fixture.root.join("sentinel")).unwrap();
    assert_eq!(
        init(InitOptions {
            data_dir: fixture.root.clone(),
            pg_bin_dir: fixture.pg_bin.clone()
        })
        .await
        .unwrap_err(),
        DaemonError::DataDirNotEmpty
    );
    assert_eq!(fs::read_dir(&fixture.root).unwrap().count(), 1);
    assert_eq!(fs::read(fixture.root.join("sentinel")).unwrap(), before);
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; run serially"]
async fn daemon_assembles_existing_engine_and_serves_status() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    fixture.initialize().await;
    let mut process = fixture.spawn("daemon_assembles_existing_engine_and_serves_status");
    let snapshot = fixture.ready().await;
    assert_eq!(snapshot.daemon_pid, process.pid());
    assert_eq!(snapshot.pg_server_version_num, 170011);
    assert_eq!(snapshot.engine_pin, env!("OMB_ENGINE_PIN"));
    assert!(snapshot.pg_pid > 0);
    let rows=query_own(&fixture,"SELECT current_setting('server_version_num'),current_setting('TimeZone'),current_setting('track_activity_query_size'),(SELECT count(*)::bigint FROM pg_namespace WHERE nspname='openmybot')").await;
    assert_eq!(rows[0].get::<_, String>(0), "170011");
    assert_eq!(rows[0].get::<_, String>(1), "America/Los_Angeles");
    assert_eq!(rows[0].get::<_, String>(2), "16kB");
    assert_eq!(rows[0].get::<_, i64>(3), 1);
    #[cfg(target_os = "macos")]
    {
        for protocol in ["tcp-listeners", "udp-bindings"] {
            let mut command = Command::new("/usr/sbin/lsof");
            command.args(["-nP", "-a", "-p", &snapshot.daemon_pid.to_string()]);
            if protocol == "tcp-listeners" {
                command.args(["-iTCP", "-sTCP:LISTEN"]);
            } else {
                command.arg("-iUDP");
            }
            let observed = command.output().unwrap();
            println!(
                "daemon {protocol} lsof exit={:?}; stderr_bytes={}",
                observed.status.code(),
                observed.stderr.len()
            );
            assert_eq!(observed.status.code(), Some(1));
            assert!(observed.stdout.is_empty());
            assert!(observed.stderr.is_empty());
        }
        let pg = Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &snapshot.pg_pid.to_string(),
                "-iTCP",
                "-sTCP:LISTEN",
            ])
            .output()
            .unwrap();
        println!(
            "PG listener lsof exit={:?}; stderr_bytes={}",
            pg.status.code(),
            pg.stderr.len()
        );
        assert!(pg.status.success());
        assert!(pg.stderr.is_empty());
        let output = String::from_utf8(pg.stdout).unwrap();
        assert!(output.contains("127.0.0.1:"));
        assert!(!output.contains("*:"));
        assert_eq!(output.lines().skip(1).count(), 1);
    }
    process.stop(Signal::TERM).await;
    fixture.no_pg();
    for secret in [
        fs::read(fixture.root.join("pg/password")).unwrap(),
        fs::read(fixture.root.join("keys/app-master.key")).unwrap(),
        fs::read(fixture.root.join("keys/vault-kek.key")).unwrap(),
    ] {
        assert!(
            !process
                .output()
                .as_bytes()
                .windows(secret.len())
                .any(|bytes| bytes == secret)
        );
        let log = fs::read(fixture.root.join("logs/postgres.log")).unwrap();
        assert!(!log.windows(secret.len()).any(|bytes| bytes == secret));
    }
}
async fn old_token_rejected(root: &Path, token: &[u8]) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };
    let mut stream = UnixStream::connect(root.join("run/control.sock"))
        .await
        .unwrap();
    let text=serde_json::to_vec(&serde_json::json!({"type":"hello","token":std::str::from_utf8(token).unwrap(),"client":"cli","client_version":"0.0.0"})).unwrap();
    stream
        .write_all(&(text.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&text).await.unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes).await;
    assert!(bytes.is_empty());
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; ten isolated repetitions"]
async fn t10_restart_rotates_token_and_rejects_previous_token() {
    if child_entry().await {
        return;
    }
    for _ in 0..10 {
        let fixture = Fixture::new();
        fixture.initialize().await;
        let mut first = fixture.spawn("t10_restart_rotates_token_and_rejects_previous_token");
        fixture.ready().await;
        let token = fs::read(fixture.root.join("run/control.token")).unwrap();
        first.stop(Signal::TERM).await;
        fixture.no_pg();
        let mut second = fixture.spawn("t10_restart_rotates_token_and_rejects_previous_token");
        fixture.ready().await;
        let next = fs::read(fixture.root.join("run/control.token")).unwrap();
        assert_ne!(token, next);
        assert_eq!(next.len(), 64);
        assert_private(&fixture.root.join("run/control.token"), 0o600);
        old_token_rejected(&fixture.root, &token).await;
        let snapshot = status(StatusOptions {
            data_dir: fixture.root.clone(),
        })
        .await
        .unwrap();
        assert_eq!(snapshot.authentication_failures, 1);
        second.stop(Signal::TERM).await;
        fixture.no_pg();
    }
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; ten isolated repetitions"]
async fn daemon_lock_excludes_concurrent_start() {
    if child_entry().await {
        return;
    }
    for _ in 0..10 {
        let fixture = Fixture::new();
        fixture.initialize().await;
        let mut a = fixture.spawn("daemon_lock_excludes_concurrent_start");
        let mut b = fixture.spawn("daemon_lock_excludes_concurrent_start");
        let winner = fixture.ready().await;
        let (winner, loser) = if winner.daemon_pid == a.pid() {
            (&mut a, &mut b)
        } else {
            assert_eq!(winner.daemon_pid, b.pid());
            (&mut b, &mut a)
        };
        assert_eq!(loser.wait().await, 4);
        assert!(loser.output().contains("daemon_already_running"));
        let still = status(StatusOptions {
            data_dir: fixture.root.clone(),
        })
        .await
        .unwrap();
        assert_eq!(still.daemon_pid, winner.pid());
        winner.stop(Signal::TERM).await;
        fixture.no_pg();
    }
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; ten isolated repetitions per signal"]
async fn signal_shutdown_removes_runtime_files_and_stops_pg() {
    if child_entry().await {
        return;
    }
    for signal in [Signal::INT, Signal::TERM] {
        for _ in 0..10 {
            let fixture = Fixture::new();
            fixture.initialize().await;
            let mut process = fixture.spawn("signal_shutdown_removes_runtime_files_and_stops_pg");
            fixture.ready().await;
            let requests = tokio::spawn({
                let root = fixture.root.clone();
                async move {
                    for _ in 0..10 {
                        let _ = status(StatusOptions {
                            data_dir: root.clone(),
                        })
                        .await;
                    }
                }
            });
            process.stop(signal).await;
            requests.await.unwrap();
            fixture.no_pg();
            assert!(!fixture.root.join("run/control.sock").exists());
            assert!(!fixture.root.join("run/control.token").exists());
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(fixture.root.join("run/daemon.lock"))
                .unwrap();
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires explicit own PG17.11 binaries; run serially"]
async fn startup_failure_releases_owned_pg_and_lock() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    fixture.initialize().await;
    // A package write failure occurs after this daemon has started its own PostgreSQL.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(fixture.root.join("tenant/brand.yaml"))
        .unwrap();
    let mut process = fixture.spawn("startup_failure_releases_owned_pg_and_lock");
    assert_eq!(process.wait().await, 5);
    assert!(process.output().contains("tenant_package_failed"));
    fixture.no_pg();
    assert!(!fixture.root.join("run/control.sock").exists());
    assert!(!fixture.root.join("run/control.token").exists());
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join("run/daemon.lock"))
        .unwrap();
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
}

async fn wait_for_token(fixture: &Fixture) {
    let limit = tokio::time::Instant::now() + Duration::from_secs(120);
    while !fixture.root.join("run/control.token").exists() {
        assert!(
            tokio::time::Instant::now() < limit,
            "own token publication deadline"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
async fn inspect_stopped(fixture: &Fixture, query: &str) -> Vec<tokio_postgres::Row> {
    let password = fs::read_to_string(fixture.root.join("pg/password")).unwrap();
    let limit = tokio::time::Instant::now() + Duration::from_secs(30);
    for _ in 0..16 {
        let mut bytes = [0; 2];
        getrandom::fill(&mut bytes).unwrap();
        let port = 49152 + u16::from_le_bytes(bytes) % 16384;
        let out = fixture.root.join(format!("inspect-{port}.out"));
        let err = fixture.root.join(format!("inspect-{port}.err"));
        private_file(&out, b"");
        private_file(&err, b"");
        let child = Command::new(fixture.pg_bin.join("postgres"))
            .arg("-D")
            .arg(fixture.root.join("pg/data"))
            .args([
                "-c",
                "listen_addresses=127.0.0.1",
                "-c",
                &format!("port={port}"),
                "-c",
                "unix_socket_directories=",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(fs::OpenOptions::new().append(true).open(&out).unwrap())
            .stderr(fs::OpenOptions::new().append(true).open(&err).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut owner = OwnedDaemon {
            child: Some(child),
            out,
            err,
        };
        let pid = owner.pid();
        let mut ready = false;
        while tokio::time::Instant::now() < limit {
            if owner.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            let record =
                fs::read_to_string(fixture.root.join("pg/data/postmaster.pid")).unwrap_or_default();
            let lines: Vec<_> = record.lines().collect();
            if lines.len() >= 8
                && lines[0].parse::<u32>().ok() == Some(pid)
                && lines[3].parse::<u16>().ok() == Some(port)
                && lines[7].trim() == "ready"
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if !ready {
            if owner.child.as_mut().unwrap().try_wait().unwrap().is_none() {
                owner.signal(Signal::INT);
            }
            let _ = owner.wait().await;
            continue;
        }
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(port)
            .user("openmybot")
            .password(&password)
            .dbname("openmybot")
            .connect_timeout(Duration::from_secs(1));
        let connected = tokio::time::timeout(
            Duration::from_secs(2),
            config.connect(tokio_postgres::NoTls),
        )
        .await;
        let result = match connected {
            Ok(Ok((client, connection))) => {
                let driver = tokio::spawn(connection);
                let result = tokio::time::timeout(Duration::from_secs(10), async {
                    if query.starts_with("CREATE ") {
                        client.batch_execute(query).await.map(|()| Vec::new())
                    } else {
                        client.query(query, &[]).await
                    }
                })
                .await;
                close_own(client, driver).await;
                result
                    .map_err(|_| "inspection query timeout")
                    .and_then(|r| r.map_err(|_| "inspection query failed"))
            }
            _ => Err("inspection connection failed"),
        };
        owner.stop(Signal::INT).await;
        return result.expect("own inspection result after child reaped");
    }
    panic!("own inspection PostgreSQL unavailable")
}
fn assert_runtime_released(fixture: &Fixture) {
    fixture.no_pg();
    assert!(!fixture.root.join("run/control.sock").exists());
    assert!(!fixture.root.join("run/control.token").exists());
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.root.join("run/daemon.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn daemon_runs_store_migrations_before_control_token_publication() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    fixture.initialize().await;
    let mut process =
        fixture.spawn("daemon_runs_store_migrations_before_control_token_publication");
    wait_for_token(&fixture).await;
    let rows=query_own(&fixture,"SELECT (SELECT count(*)::bigint FROM openmybot.omb_migrations),(SELECT count(*)::bigint FROM information_schema.tables WHERE table_schema='openmybot')").await;
    assert_eq!(rows[0].get::<_, i64>(0), 1);
    assert_eq!(rows[0].get::<_, i64>(1), 6);
    fixture.ready().await;
    let token = fs::read(fixture.root.join("run/control.token")).unwrap();
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(&token).to_vec();
    let rows=query_own(&fixture,"SELECT token_sha256,engine_pin,daemon_pid FROM openmybot.control_tokens WHERE revoked_at IS NULL").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, Vec<u8>>(0), digest);
    assert_eq!(rows[0].get::<_, String>(1), env!("OMB_ENGINE_PIN"));
    assert_eq!(rows[0].get::<_, i32>(2), process.pid() as i32);
    process.stop(Signal::TERM).await;
    assert_runtime_released(&fixture);
}
#[tokio::test]
#[ignore = "own PG17.11; ten fresh clusters; serial"]
async fn daemon_restart_rotates_digest_and_records_restart_reason() {
    if child_entry().await {
        return;
    }
    for _ in 0..10 {
        let fixture = Fixture::new();
        fixture.initialize().await;
        let mut first = fixture.spawn("daemon_restart_rotates_digest_and_records_restart_reason");
        fixture.ready().await;
        let old = fs::read(fixture.root.join("run/control.token")).unwrap();
        let old_id = query_own(
            &fixture,
            "SELECT token_id FROM openmybot.control_tokens WHERE revoked_at IS NULL",
        )
        .await[0]
            .get::<_, uuid::Uuid>(0);
        first.signal(Signal::KILL);
        assert_eq!(first.wait().await, -1);
        let mut second = fixture.spawn("daemon_restart_rotates_digest_and_records_restart_reason");
        fixture.ready().await;
        let next = fs::read(fixture.root.join("run/control.token")).unwrap();
        assert_ne!(old, next);
        let rows=query_own(&fixture,&format!("SELECT revoke_reason,revoked_at IS NOT NULL FROM openmybot.control_tokens WHERE token_id='{old_id}'")).await;
        assert_eq!(rows[0].get::<_, String>(0), "daemon_restart");
        assert!(rows[0].get::<_, bool>(1));
        assert_eq!(
            query_own(
                &fixture,
                "SELECT count(*)::bigint FROM openmybot.control_tokens WHERE revoked_at IS NULL"
            )
            .await[0]
                .get::<_, i64>(0),
            1
        );
        second.stop(Signal::TERM).await;
        assert_runtime_released(&fixture);
    }
}
#[tokio::test]
#[ignore = "own PG17.11; ten repetitions for each signal; serial"]
async fn daemon_stop_records_revocation_before_owned_pg_shutdown() {
    if child_entry().await {
        return;
    }
    for signal in [Signal::INT, Signal::TERM] {
        for _ in 0..10 {
            let fixture = Fixture::new();
            fixture.initialize().await;
            let mut process =
                fixture.spawn("daemon_stop_records_revocation_before_owned_pg_shutdown");
            fixture.ready().await;
            let id = query_own(
                &fixture,
                "SELECT token_id FROM openmybot.control_tokens WHERE revoked_at IS NULL",
            )
            .await[0]
                .get::<_, uuid::Uuid>(0);
            process.stop(signal).await;
            assert_runtime_released(&fixture);
            let rows=inspect_stopped(&fixture,&format!("SELECT revoke_reason,revoked_at IS NOT NULL FROM openmybot.control_tokens WHERE token_id='{id}'")).await;
            assert_eq!(rows[0].get::<_, String>(0), "daemon_stop");
            assert!(rows[0].get::<_, bool>(1));
        }
    }
    for signal in [Signal::INT, Signal::TERM] {
        let fixture = Fixture::new();
        fixture.initialize().await;
        let mut process = fixture.spawn("daemon_stop_records_revocation_before_owned_pg_shutdown");
        fixture.ready().await;
        let id = query_own(
            &fixture,
            "SELECT token_id FROM openmybot.control_tokens WHERE revoked_at IS NULL",
        )
        .await[0]
            .get::<_, uuid::Uuid>(0);
        let (client, driver) = connect_own(&fixture).await;
        let injected=tokio::time::timeout(Duration::from_secs(10),client.batch_execute("CREATE FUNCTION openmybot.fixture_stop_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.revoke_reason='daemon_stop' THEN RAISE EXCEPTION 'owned fixture stop failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_stop_failure BEFORE UPDATE ON openmybot.control_tokens FOR EACH ROW EXECUTE FUNCTION openmybot.fixture_stop_failure()")).await;
        close_own(client, driver).await;
        injected.unwrap().unwrap();
        process.signal(signal);
        assert_eq!(process.wait().await, 5);
        assert!(process.output().contains("control_token_failed"));
        assert_runtime_released(&fixture);
        let rows=inspect_stopped(&fixture,&format!("SELECT revoked_at IS NULL AND revoke_reason IS NULL FROM openmybot.control_tokens WHERE token_id='{id}'")).await;
        assert!(rows[0].get::<_, bool>(0));
    }
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn migration_refusal_cleans_owned_pg_runtime_files_and_lock() {
    if child_entry().await {
        return;
    }
    let fixture = Fixture::new();
    fixture.initialize().await;
    let mut first = fixture.spawn("migration_refusal_cleans_owned_pg_runtime_files_and_lock");
    fixture.ready().await;
    first.stop(Signal::TERM).await;
    assert_runtime_released(&fixture);
    inspect_stopped(&fixture,"UPDATE openmybot.omb_migrations SET sha256=decode(repeat('00',32),'hex') RETURNING version").await;
    let mut second = fixture.spawn("migration_refusal_cleans_owned_pg_runtime_files_and_lock");
    assert_eq!(second.wait().await, 4);
    assert!(second.output().contains("omb_migration_drift"));
    assert_runtime_released(&fixture);
    let delayed = Fixture::new();
    delayed.initialize().await;
    let mut seed = delayed.spawn("migration_refusal_cleans_owned_pg_runtime_files_and_lock");
    delayed.ready().await;
    seed.stop(Signal::TERM).await;
    assert_runtime_released(&delayed);
    inspect_stopped(&delayed,"CREATE FUNCTION openmybot.fixture_migration_delay() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF current_query() LIKE '%CREATE SCHEMA IF NOT EXISTS openmybot%' THEN PERFORM pg_sleep(35); END IF; END $$; CREATE EVENT TRIGGER fixture_migration_delay ON ddl_command_start EXECUTE FUNCTION openmybot.fixture_migration_delay(); SELECT true").await;
    let mut failing = delayed.spawn("migration_refusal_cleans_owned_pg_runtime_files_and_lock");
    assert_eq!(failing.wait().await, 5);
    assert!(failing.output().contains("omb_migration_failed"));
    assert_runtime_released(&delayed);
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn assembly_failure_after_token_insert_records_controlled_stop() {
    if child_entry().await {
        return;
    }
    for _ in 0..10 {
        let fixture = Fixture::new();
        fixture.initialize().await;
        let mut setup =
            fixture.spawn("assembly_failure_after_token_insert_records_controlled_stop");
        fixture.ready().await;
        setup.stop(Signal::TERM).await;
        assert_runtime_released(&fixture);
        // Test-only trigger establishes an observed barrier before insertion: the daemon holds
        // marker and waits for the parent's gate lock. No timing assumption or product knob.
        inspect_stopped(&fixture,"CREATE FUNCTION openmybot.fixture_insert_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(77881234); WHILE NOT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=77881235 AND granted AND pid<>pg_backend_pid()) LOOP PERFORM pg_sleep(0.01); END LOOP; PERFORM pg_advisory_xact_lock(77881235); RETURN NEW; END $$; CREATE TRIGGER fixture_gate BEFORE INSERT ON openmybot.control_tokens FOR EACH ROW EXECUTE FUNCTION openmybot.fixture_insert_gate(); SELECT true").await;
        let mut process =
            fixture.spawn("assembly_failure_after_token_insert_records_controlled_stop");
        let daemon_pid = process.pid();
        wait_for_token(&fixture).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let row=query_own(&fixture,"SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=77881234 AND granted)").await;
            if row[0].get::<_, bool>(0) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "insert marker deadline"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let (client, driver) = connect_own(&fixture).await;
        client
            .query_one("SELECT pg_advisory_lock(77881235)", &[])
            .await
            .unwrap();
        loop {
            let row=query_own(&fixture,"SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=77881235 AND NOT granted)").await;
            if row[0].get::<_, bool>(0) {
                break;
            }
            assert!(tokio::time::Instant::now() < limit, "insert gate deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(fixture.root.join("keys/vault-kek.key"))
            .unwrap()
            .write_all(b"x")
            .unwrap();
        client
            .query_one("SELECT pg_advisory_unlock(77881235)", &[])
            .await
            .unwrap();
        close_own(client, driver).await;
        assert_eq!(process.wait().await, 5);
        assert!(process.output().contains("engine_assembly_failed"));
        assert_runtime_released(&fixture);
        let rows=inspect_stopped(&fixture,&format!("SELECT token_id,revoke_reason,revoked_at IS NOT NULL FROM openmybot.control_tokens WHERE daemon_pid={daemon_pid}")).await;
        assert_eq!(rows.len(), 1);
        let _: uuid::Uuid = rows[0].get(0);
        assert_eq!(rows[0].get::<_, String>(1), "daemon_stop");
        assert!(rows[0].get::<_, bool>(2));
    }
}
