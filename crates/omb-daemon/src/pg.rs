use crate::{
    DaemonError,
    config::{self, Config, HBA},
};
use rustix::process::{Pid, Signal};
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    time::{Duration, SystemTime},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout, timeout_at},
};

const READY: Duration = Duration::from_secs(30);
const STOP: Duration = Duration::from_secs(30);

pub(crate) fn map_store_error(error: omb_store::StoreError) -> DaemonError {
    match error {
        omb_store::StoreError::MigrationDrift => DaemonError::OmbMigrationDrift,
        omb_store::StoreError::SchemaNewer => DaemonError::OmbSchemaNewer,
        omb_store::StoreError::MigrationFailed => DaemonError::OmbMigrationFailed,
        omb_store::StoreError::ControlTokenFailed => DaemonError::ControlTokenFailed,
        omb_store::StoreError::ChannelAlreadyBound => DaemonError::ChannelAlreadyBound,
        omb_store::StoreError::ReceiverNotActive => DaemonError::ReceiverNotActive,
        omb_store::StoreError::BindingNotFound => DaemonError::BindingNotFound,
        omb_store::StoreError::BindingStateInvalid => DaemonError::BindingStateInvalid,
        omb_store::StoreError::BindingFailed => DaemonError::BindingFailed,
        omb_store::StoreError::EventFailed
        | omb_store::StoreError::DispatchFailed
        | omb_store::StoreError::GapFailed
        | omb_store::StoreError::HostSessionFailed => DaemonError::InternalError,
    }
}
fn ready_result<T>(deadline: Instant, result: Result<T, DaemonError>) -> Result<T, DaemonError> {
    if Instant::now() >= deadline {
        Err(DaemonError::PgStartFailed)
    } else {
        result
    }
}

pub(crate) async fn tool(binary: &Path, args: &[OsString]) -> Result<Vec<u8>, DaemonError> {
    tool_until(binary, args, Instant::now() + READY)
        .await
        .map_err(|error| {
            if error == DaemonError::PgStartFailed {
                DaemonError::PgBinariesRejected
            } else {
                error
            }
        })
}
async fn tool_until(
    binary: &Path,
    args: &[OsString],
    deadline: Instant,
) -> Result<Vec<u8>, DaemonError> {
    ready_result(deadline, Ok(()))?;
    let mut command = StdCommand::new(binary);
    command
        .args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    if binary == Path::new("/bin/ps") {
        command.env("TZ", "UTC");
    }
    ready_result(deadline, Ok(()))?;
    let child = Command::from(command)
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| DaemonError::PgBinariesRejected)?;
    run_tool_child(child, deadline).await
}
async fn run_tool_child(mut child: Child, deadline: Instant) -> Result<Vec<u8>, DaemonError> {
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(Pid::from_raw);
    let pipe = child.stdout.take();
    let mut reader = tokio::spawn(async move {
        let mut output = Vec::new();
        let pipe = pipe.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        pipe.take(8193)
            .read_to_end(&mut output)
            .await
            .map(|_| output)
    });
    let waited = timeout_at(deadline, child.wait()).await;
    let result = match waited {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(_)) => Err(DaemonError::PgBinariesRejected),
        timed_out => {
            // Keep the owned child and reader outside timeout cancellation. Cleanup has a
            // separate stop budget; it can never turn an expired readiness probe into success.
            if let Some(group) = group {
                let _ = rustix::process::kill_process_group(group, Signal::KILL);
            }
            let _ = child.start_kill();
            let reaped = timeout(STOP, child.wait()).await;
            reader.abort();
            let _ = reader.await;
            if !matches!(reaped, Ok(Ok(_))) {
                return Err(DaemonError::ShutdownFailed);
            }
            return Err(if timed_out.is_err() {
                DaemonError::PgStartFailed
            } else {
                DaemonError::PgBinariesRejected
            });
        }
    };
    let output = match timeout_at(
        deadline.min(Instant::now() + Duration::from_secs(5)),
        &mut reader,
    )
    .await
    {
        Ok(Ok(Ok(output))) => output,
        Ok(_) => return ready_result(deadline, Err(DaemonError::PgBinariesRejected)),
        Err(_) => {
            // The child is already reaped. Never signal a potentially reused group number.
            reader.abort();
            let _ = reader.await;
            return ready_result(deadline, Err(DaemonError::PgBinariesRejected));
        }
    };
    result?;
    if output.len() > 8192 {
        return Err(DaemonError::PgBinariesRejected);
    }
    ready_result(deadline, Ok(output))
}

pub(crate) async fn verify_binaries(bin: &Path) -> Result<(), DaemonError> {
    if !bin.is_absolute() {
        return Err(DaemonError::PgBinariesRejected);
    }
    for name in ["postgres", "initdb"] {
        let meta = fs::metadata(bin.join(name)).map_err(|_| DaemonError::PgBinariesRejected)?;
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            return Err(DaemonError::PgBinariesRejected);
        }
    }
    let bytes = tool(&bin.join("postgres"), &["--version".into()]).await?;
    let text = std::str::from_utf8(&bytes).map_err(|_| DaemonError::PgBinariesRejected)?;
    if !text
        .strip_prefix("postgres (PostgreSQL) ")
        .is_some_and(|v| v.trim().split('.').next() == Some("17"))
    {
        return Err(DaemonError::PgBinariesRejected);
    }
    Ok(())
}
pub(crate) fn verify_hba(root: &Path) -> Result<(), DaemonError> {
    if config::read_private(&root.join("pg/data/pg_hba.conf"), 4096)
        .map_err(|_| DaemonError::PgHbaRejected)?
        != HBA
    {
        return Err(DaemonError::PgHbaRejected);
    }
    Ok(())
}

struct Connection {
    client: Option<tokio_postgres::Client>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Connection {
    async fn close(self) -> Result<(), DaemonError> {
        self.close_until(Instant::now() + Duration::from_secs(5))
            .await
            .map_err(|_| DaemonError::ShutdownFailed)
    }
    async fn close_until(mut self, deadline: Instant) -> Result<(), DaemonError> {
        self.client.take();
        match timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(5)),
            &mut self.driver,
        )
        .await
        {
            Ok(Ok(Ok(()))) => ready_result(deadline, Ok(())),
            Ok(_) => ready_result(deadline, Err(DaemonError::ShutdownFailed)),
            Err(_) => {
                self.driver.abort();
                let _ = self.driver.await;
                ready_result(deadline, Err(DaemonError::ShutdownFailed))
            }
        }
    }
}

/// A store connection owned by the delegation authority, plus the settings to reopen it.
pub struct AuthorityConnection {
    pub config: tokio_postgres::Config,
    pub client: tokio_postgres::Client,
    pub driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}

/// The daemon's own PostgreSQL child process.
pub struct Postgres {
    child: Child,
    port: u16,
    root: PathBuf,
    password: String,
    pub(crate) version: u32,
    pid: u32,
    binary: PathBuf,
    spawned_at: SystemTime,
}
impl Postgres {
    pub(crate) fn is_alive(&mut self) -> Result<bool, DaemonError> {
        self.child
            .try_wait()
            .map(|s| s.is_none())
            .map_err(|_| DaemonError::PgStartFailed)
    }
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn database_config(&self) -> openbot_infra::db::pool::DatabaseConfig {
        openbot_infra::db::pool::DatabaseConfig::new(
            "127.0.0.1",
            self.port,
            "openmybot",
            "openmybot",
        )
        .with_password(self.password.clone())
        .with_application_name("openmybot")
    }
    pub(crate) async fn start(root: &Path, config: &Config) -> Result<Self, DaemonError> {
        verify_binaries(&config.pg_bin_dir).await?;
        verify_hba(root)?;
        let password = String::from_utf8(config::read_private(&root.join("pg/password"), 64)?)
            .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
        let deadline = Instant::now() + READY;
        for _ in 0..16 {
            if Instant::now() >= deadline {
                break;
            }
            let mut random = [0; 2];
            getrandom::fill(&mut random).map_err(|_| DaemonError::PgStartFailed)?;
            let port = 49152 + (u16::from_le_bytes(random) % 16384);
            let log_path = root.join("logs/postgres.log");
            if !log_path.exists() {
                config::write_private(&log_path, b"", true)?;
            }
            config::check(&log_path, false)?;
            let log = fs::OpenOptions::new()
                .append(true)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&log_path)
                .map_err(|_| DaemonError::PgStartFailed)?;
            let mut command = StdCommand::new(config.pg_bin_dir.join("postgres"));
            command
                .arg("-D")
                .arg(root.join("pg/data"))
                .args([
                    "-c",
                    "listen_addresses=127.0.0.1",
                    "-c",
                    &format!("port={port}"),
                    "-c",
                    "unix_socket_directories=",
                ])
                .env_clear()
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .stdin(Stdio::null())
                .stdout(Stdio::from(
                    log.try_clone().map_err(|_| DaemonError::PgStartFailed)?,
                ))
                .stderr(Stdio::from(log))
                .process_group(0);
            let spawned_at = SystemTime::now();
            let child = Command::from(command)
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| DaemonError::PgStartFailed)?;
            let pid = child.id().ok_or(DaemonError::PgStartFailed)?;
            let mut instance = Self {
                child,
                port,
                root: root.to_owned(),
                password: password.clone(),
                version: 0,
                pid,
                binary: config.pg_bin_dir.join("postgres"),
                spawned_at,
            };
            loop {
                match instance.child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => (),
                    Err(_) => {
                        instance.stop().await?;
                        return Err(DaemonError::PgStartFailed);
                    }
                }
                if Instant::now() >= deadline {
                    instance.stop().await?;
                    return Err(DaemonError::PgStartFailed);
                }
                if instance.pid_file_matches() {
                    match instance.verify_connection(deadline).await {
                        Ok(version) => match ready_result(deadline, Ok(version)) {
                            Ok(version) => {
                                instance.version = version;
                                return Ok(instance);
                            }
                            Err(error) => {
                                instance.stop().await?;
                                return Err(error);
                            }
                        },
                        Err(DaemonError::PgVersionRejected) => {
                            instance.stop().await?;
                            return Err(DaemonError::PgVersionRejected);
                        }
                        Err(_) => (),
                    }
                }
                sleep_until(deadline.min(Instant::now() + Duration::from_millis(50))).await;
            }
            // The exited child was reaped; another attempt never connects without a matching new pid file.
        }
        Err(DaemonError::PgStartFailed)
    }
    fn pid_file_matches(&self) -> bool {
        let Ok(bytes) = config::read_private(&self.root.join("pg/data/postmaster.pid"), 8192)
        else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return false;
        };
        let lines: Vec<_> = text.lines().collect();
        lines.len() >= 8
            && lines[0].parse::<u32>().ok() == Some(self.pid)
            && fs::canonicalize(lines[1]).ok() == fs::canonicalize(self.root.join("pg/data")).ok()
            && lines[3].parse::<u16>().ok() == Some(self.port)
            && lines[7].trim() == "ready"
    }
    async fn connection_identity_gate(&mut self, deadline: Instant) -> Result<(), DaemonError> {
        ready_result(deadline, Ok(()))?;
        if !self.pid_file_matches()
            || self
                .child
                .try_wait()
                .map_err(|_| DaemonError::PgStartFailed)?
                .is_some()
        {
            return Err(DaemonError::PgStartFailed);
        }
        let path = self.root.join("pg/data/postmaster.pid");
        let bytes = config::read_private(&path, 8192).map_err(|_| DaemonError::PgStartFailed)?;
        // A ready record left by a dead postmaster cannot authenticate a PID/port reused by
        // this new child. Keep that record for PG's own orphan checks, and require a new write.
        let modified = fs::symlink_metadata(&path)
            .and_then(|m| m.modified())
            .map_err(|_| DaemonError::PgStartFailed)?;
        if modified < self.spawned_at {
            return Err(DaemonError::PgStartFailed);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| DaemonError::PgStartFailed)?;
        let recorded = text
            .lines()
            .nth(2)
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|s| *s > 0)
            .ok_or(DaemonError::PgStartFailed)?;
        let identity = process_identity_until(
            self.pid,
            &self.binary,
            &self.root.join("pg/data"),
            self.port,
            deadline,
        )
        .await
        .ok_or(DaemonError::PgStartFailed)?;
        if !identity_start_matches(&identity, recorded)
            || self
                .child
                .try_wait()
                .map_err(|_| DaemonError::PgStartFailed)?
                .is_some()
            || config::read_private(&path, 8192).ok().as_ref() != Some(&bytes)
        {
            return Err(DaemonError::PgStartFailed);
        }
        ready_result(deadline, Ok(()))
    }
    fn client_config(&self, database: &str) -> tokio_postgres::Config {
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(self.port)
            .user("openmybot")
            .password(&self.password)
            .dbname(database)
            .application_name("openmybot")
            .connect_timeout(Duration::from_secs(1));
        config
    }
    async fn connect(
        &mut self,
        database: &str,
        deadline: Instant,
    ) -> Result<Connection, DaemonError> {
        self.connection_identity_gate(deadline).await?;
        let config = self.client_config(database);
        ready_result(deadline, Ok(()))?;
        let (client, connection) = timeout_at(
            deadline.min(Instant::now() + Duration::from_secs(2)),
            config.connect(tokio_postgres::NoTls),
        )
        .await
        .map_err(|_| DaemonError::PgStartFailed)?
        .map_err(|_| DaemonError::PgStartFailed)?;
        // No driver task exists yet; a late connection result drops both socket owners here.
        ready_result(deadline, Ok(()))?;
        Ok(Connection {
            client: Some(client),
            driver: tokio::spawn(connection),
        })
    }
    async fn verify_connection(&mut self, deadline: Instant) -> Result<u32, DaemonError> {
        let connection = self.connect("postgres", deadline).await?;
        let result=async {
            let client=connection.client.as_ref().ok_or(DaemonError::PgStartFailed)?;
            ready_result(deadline,Ok(()))?;
            let row=timeout_at(deadline.min(Instant::now()+Duration::from_secs(2)),client.query_one("SELECT current_setting('server_version_num'),current_setting('data_directory'),extract(epoch from pg_postmaster_start_time())::bigint",&[])).await.map_err(|_|DaemonError::PgStartFailed)?.map_err(|_|DaemonError::PgStartFailed)?;
            let version:String=row.try_get(0).map_err(|_|DaemonError::PgStartFailed)?;
            let version:u32=version.parse().map_err(|_|DaemonError::PgVersionRejected)?;
            if !(170000..180000).contains(&version) {return Err(DaemonError::PgVersionRejected);}
            let directory:String=row.try_get(1).map_err(|_|DaemonError::PgStartFailed)?;
            let start:i64=row.try_get(2).map_err(|_|DaemonError::PgStartFailed)?;
            let pid_text=String::from_utf8(config::read_private(&self.root.join("pg/data/postmaster.pid"),8192)?).map_err(|_|DaemonError::PgStartFailed)?;
            let recorded=pid_text.lines().nth(2).and_then(|s|s.parse::<i64>().ok()).ok_or(DaemonError::PgStartFailed)?;
            if !self.pid_file_matches() || self.child.try_wait().map_err(|_|DaemonError::PgStartFailed)?.is_some()
                || fs::canonicalize(directory).ok()!=fs::canonicalize(self.root.join("pg/data")).ok() || (start-recorded).abs()>1 {return Err(DaemonError::PgStartFailed);}
            Ok(version)
        }.await;
        // The query future can time out, but the Connection owner is still here. Join its
        // driver or abort+await it before deciding whether readiness is still timely.
        connection.close_until(deadline).await?;
        ready_result(deadline, result)
    }
    pub(crate) async fn migrate_store(&mut self) -> Result<(), DaemonError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut connection = self
            .connect("openmybot", deadline)
            .await
            .map_err(|_| DaemonError::OmbMigrationFailed)?;
        let result = match connection.client.as_mut() {
            Some(client) => omb_store::migrate(client, deadline)
                .await
                .map(|_| ())
                .map_err(map_store_error),
            None => Err(DaemonError::OmbMigrationFailed),
        };
        let closed = connection.close_until(deadline).await;
        result?;
        if closed.is_err() {
            return Err(DaemonError::OmbMigrationFailed);
        }
        if Instant::now() >= deadline {
            return Err(DaemonError::OmbMigrationFailed);
        }
        result
    }
    pub(crate) async fn start_control_token(
        &mut self,
        input: omb_store::ControlTokenStart<'_>,
    ) -> Result<(), DaemonError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut connection = self
            .connect("openmybot", deadline)
            .await
            .map_err(|_| DaemonError::ControlTokenFailed)?;
        let result = match connection.client.as_mut() {
            Some(client) => omb_store::start_control_token(client, input, deadline)
                .await
                .map(|_| ())
                .map_err(map_store_error),
            None => Err(DaemonError::ControlTokenFailed),
        };
        let closed = connection.close_until(deadline).await;
        if closed.is_err() || Instant::now() >= deadline {
            return Err(DaemonError::ControlTokenFailed);
        }
        result
    }
    pub(crate) async fn stop_control_token(
        &mut self,
        token_id: uuid::Uuid,
    ) -> Result<(), DaemonError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut connection = self
            .connect("openmybot", deadline)
            .await
            .map_err(|_| DaemonError::ControlTokenFailed)?;
        let result = match connection.client.as_mut() {
            Some(client) => omb_store::stop_control_token(client, token_id, deadline)
                .await
                .map_err(map_store_error),
            None => Err(DaemonError::ControlTokenFailed),
        };
        let closed = connection.close_until(deadline).await;
        if closed.is_err() || Instant::now() >= deadline {
            return Err(DaemonError::ControlTokenFailed);
        }
        result
    }
    /// Opens the delegation authority's own connection through the identity-checked path.
    pub async fn open_authority_connection(&mut self) -> Result<AuthorityConnection, DaemonError> {
        self.open_resident_connection("openmybot-delegation")
            .await
            .map_err(|_| DaemonError::BindingFailed)
    }
    /// Opens a long-lived store connection for one daemon component, through the
    /// identity-checked path, with the component's application name.
    pub async fn open_resident_connection(
        &mut self,
        application_name: &str,
    ) -> Result<AuthorityConnection, DaemonError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        self.connection_identity_gate(deadline)
            .await
            .map_err(|_| DaemonError::InternalError)?;
        let mut config = self.client_config("openmybot");
        config
            .application_name(application_name)
            .options("-c statement_timeout=2s");
        let (client, connection) = timeout(
            Duration::from_secs(2),
            config.connect(tokio_postgres::NoTls),
        )
        .await
        .map_err(|_| DaemonError::InternalError)?
        .map_err(|_| DaemonError::InternalError)?;
        Ok(AuthorityConnection {
            config,
            client,
            driver: tokio::spawn(connection),
        })
    }
    pub async fn record_startup_gaps(
        &mut self,
        token_id: uuid::Uuid,
    ) -> Result<omb_store::StartupGaps, DaemonError> {
        self.binding_call(async |client, deadline| {
            omb_store::record_startup_gaps(client, token_id, deadline).await
        })
        .await
    }
    pub async fn list_active_receivers(
        &mut self,
        channel: omb_store::Channel,
    ) -> Result<Vec<omb_store::ReceiverRow>, DaemonError> {
        self.binding_call(async |client, _| omb_store::list_active_receivers(client, channel).await)
            .await
    }
    async fn binding_call<T>(
        &mut self,
        call: impl AsyncFnOnce(&mut tokio_postgres::Client, Instant) -> Result<T, omb_store::StoreError>,
    ) -> Result<T, DaemonError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut connection = self
            .connect("openmybot", deadline)
            .await
            .map_err(|_| DaemonError::BindingFailed)?;
        let result = match connection.client.as_mut() {
            Some(client) => call(client, deadline).await.map_err(map_store_error),
            None => Err(DaemonError::BindingFailed),
        };
        let closed = connection.close_until(deadline).await;
        if closed.is_err() || Instant::now() >= deadline {
            return Err(DaemonError::BindingFailed);
        }
        result
    }
    pub(crate) async fn create_database(&mut self) -> Result<(), DaemonError> {
        let connection = self.connect("postgres", Instant::now() + READY).await?;
        let result = async {
            timeout(
                Duration::from_secs(10),
                connection
                    .client
                    .as_ref()
                    .ok_or(DaemonError::InitFailed)?
                    .batch_execute("CREATE DATABASE openmybot"),
            )
            .await
            .map_err(|_| DaemonError::InitFailed)?
            .map_err(|_| DaemonError::InitFailed)
        }
        .await;
        connection.close().await?;
        result
    }
    async fn force_reap(&mut self, pid: Pid) -> Result<(), DaemonError> {
        let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        let killed = self.child.start_kill();
        let waited = timeout(STOP, self.child.wait()).await;
        match (killed, waited) {
            (_, Ok(Ok(_))) => Ok(()),
            _ => Err(DaemonError::ShutdownFailed),
        }
    }
    pub(crate) async fn stop(&mut self) -> Result<(), DaemonError> {
        let pid = Pid::from_raw(i32::try_from(self.pid).map_err(|_| DaemonError::ShutdownFailed)?)
            .ok_or(DaemonError::ShutdownFailed)?;
        match self.child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => (),
            Err(_) => {
                self.force_reap(pid).await?;
                return Err(DaemonError::ShutdownFailed);
            }
        }
        for signal in [Signal::INT, Signal::QUIT] {
            match rustix::process::kill_process(pid, signal) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => (),
                Err(_) => {
                    self.force_reap(pid).await?;
                    return Err(DaemonError::ShutdownFailed);
                }
            }
            match timeout(STOP, self.child.wait()).await {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(_)) => {
                    self.force_reap(pid).await?;
                    return Err(DaemonError::ShutdownFailed);
                }
                Err(_) => (),
            }
        }
        // A forced kill still counts as a failed graceful shutdown; the owned child is reaped.
        self.force_reap(pid).await?;
        Err(DaemonError::ShutdownFailed)
    }
}

#[derive(PartialEq, Eq)]
struct ProcessIdentity {
    started: i64,
    arguments: String,
    device: u64,
    inode: u64,
}
fn identity_start_matches(identity: &ProcessIdentity, recorded: i64) -> bool {
    recorded > 0 && identity.started.abs_diff(recorded) <= 1
}
async fn process_identity(
    pid: u32,
    expected: &Path,
    data: &Path,
    port: u16,
) -> Option<ProcessIdentity> {
    process_identity_until(pid, expected, data, port, Instant::now() + READY).await
}
async fn process_identity_until(
    pid: u32,
    expected: &Path,
    data: &Path,
    port: u16,
    deadline: Instant,
) -> Option<ProcessIdentity> {
    ready_result(deadline, Ok(())).ok()?;
    let started = tool_until(
        Path::new("/bin/ps"),
        &[
            "-p".into(),
            pid.to_string().into(),
            "-o".into(),
            "lstart=".into(),
        ],
        deadline,
    )
    .await
    .ok()?;
    let started = std::str::from_utf8(&started).ok()?.trim();
    let started =
        chrono::DateTime::parse_from_str(&format!("{started} +0000"), "%a %b %e %H:%M:%S %Y %z")
            .ok()?
            .timestamp();
    let arguments = tool_until(
        Path::new("/bin/ps"),
        &[
            "-ww".into(),
            "-p".into(),
            pid.to_string().into(),
            "-o".into(),
            "args=".into(),
        ],
        deadline,
    )
    .await
    .ok()?;
    let arguments = std::str::from_utf8(&arguments).ok()?.trim_end().to_owned();
    // Compare the entire command we created, including the complete data path and fixed flags.
    // No whitespace tokenization: paths such as Application Support stay one exact expected value.
    let expected_arguments = format!(
        "{} -D {} -c listen_addresses=127.0.0.1 -c port={port} -c unix_socket_directories=",
        expected.to_str()?,
        data.to_str()?
    );
    if arguments != expected_arguments {
        return None;
    }
    #[cfg(target_os = "linux")]
    let executable = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    #[cfg(target_os = "macos")]
    let executable = {
        let bytes = tool_until(
            Path::new("/usr/sbin/lsof"),
            &[
                "-a".into(),
                "-p".into(),
                pid.to_string().into(),
                "-d".into(),
                "txt".into(),
                "-Fn".into(),
            ],
            deadline,
        )
        .await
        .ok()?;
        let text = std::str::from_utf8(&bytes).ok()?;
        PathBuf::from(text.lines().find_map(|line| line.strip_prefix('n'))?)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return None;
    let actual = fs::metadata(executable).ok()?;
    let desired = fs::metadata(expected).ok()?;
    if actual.dev() != desired.dev() || actual.ino() != desired.ino() {
        return None;
    }
    ready_result(deadline, Ok(())).ok()?;
    Some(ProcessIdentity {
        started,
        arguments,
        device: actual.dev(),
        inode: actual.ino(),
    })
}
pub(crate) async fn stop_stale(root: &Path, config: &Config) -> Result<(), DaemonError> {
    let path = root.join("pg/data/postmaster.pid");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(DaemonError::PostmasterPidForeign),
        Ok(_) => (),
    }
    let bytes = config::read_private(&path, 8192).map_err(|_| DaemonError::PostmasterPidForeign)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| DaemonError::PostmasterPidForeign)?;
    let lines: Vec<_> = text.lines().collect();
    let pid = lines
        .first()
        .and_then(|s| s.parse::<i32>().ok())
        .and_then(Pid::from_raw)
        .ok_or(DaemonError::PostmasterPidForeign)?;
    if rustix::process::test_kill_process(pid) == Err(rustix::io::Errno::SRCH) {
        return Ok(());
    }
    let data =
        fs::canonicalize(root.join("pg/data")).map_err(|_| DaemonError::PostmasterPidForeign)?;
    if lines.get(1).and_then(|p| fs::canonicalize(p).ok()).as_ref() != Some(&data) {
        return Err(DaemonError::PostmasterPidForeign);
    }
    let recorded_start = lines
        .get(2)
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|t| *t > 0)
        .ok_or(DaemonError::PostmasterPidForeign)?;
    let port = lines
        .get(3)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .ok_or(DaemonError::PostmasterPidForeign)?;
    let raw = pid.as_raw_pid() as u32;
    let executable = config.pg_bin_dir.join("postgres");
    let argument_data = root.join("pg/data");
    let first = process_identity(raw, &executable, &argument_data, port)
        .await
        .ok_or(DaemonError::PostmasterPidForeign)?;
    if !identity_start_matches(&first, recorded_start)
        || process_identity(raw, &executable, &argument_data, port)
            .await
            .as_ref()
            != Some(&first)
        || config::read_private(&path, 8192).ok().as_ref() != Some(&bytes)
    {
        return Err(DaemonError::PostmasterPidForeign);
    }
    match rustix::process::kill_process(pid, Signal::INT) {
        Ok(()) => (),
        Err(rustix::io::Errno::SRCH) => return Ok(()),
        Err(_) => return Err(DaemonError::StalePostgresRunning),
    }
    let deadline = Instant::now() + STOP;
    while Instant::now() < deadline {
        match rustix::process::test_kill_process(pid) {
            Ok(()) => (),
            Err(rustix::io::Errno::SRCH) if Instant::now() < deadline => return Ok(()),
            Err(_) => return Err(DaemonError::StalePostgresRunning),
        }
        // The identified process can exit while ps/lsof are observing it. Missing identity
        // is not evidence of a live replacement: confirm disappearance with a fresh kill0.
        match process_identity_until(raw, &executable, &argument_data, port, deadline).await {
            Some(identity) if identity != first => return Err(DaemonError::StalePostgresRunning),
            Some(_) => (),
            None => match rustix::process::test_kill_process(pid) {
                Err(rustix::io::Errno::SRCH) if Instant::now() < deadline => return Ok(()),
                Ok(()) => (),
                Err(_) => return Err(DaemonError::StalePostgresRunning),
            },
        }
        sleep_until(deadline.min(Instant::now() + Duration::from_millis(50))).await;
    }
    Err(DaemonError::StalePostgresRunning)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    #[tokio::test]
    async fn ready_deadline_bounds_identity_probe_and_rejects_late_success() {
        // This is the exact child/pipe owner used by ps/lsof identity probes. Earlier probe
        // time is already spent; the next helper cannot receive a fresh thirty seconds.
        let deadline = Instant::now() + Duration::from_millis(150);
        sleep(Duration::from_millis(100)).await;
        let mut command = StdCommand::new("/bin/sleep");
        command
            .arg("60")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let child = Command::from(command).kill_on_drop(true).spawn().unwrap();
        let pid = Pid::from_raw(child.id().unwrap() as i32).unwrap();
        let result = run_tool_child(child, deadline).await;
        assert_eq!(result, Err(DaemonError::PgStartFailed));
        assert!(Instant::now() >= deadline);
        assert!(Instant::now().duration_since(deadline) < Duration::from_secs(2));
        assert_eq!(
            rustix::process::test_kill_process(pid),
            Err(rustix::io::Errno::SRCH)
        );
        assert_eq!(
            rustix::process::test_kill_process_group(pid),
            Err(rustix::io::Errno::SRCH)
        );
        // No new identity tool may start after exhaustion, even when it would succeed at once.
        assert_eq!(
            tool_until(Path::new("/bin/true"), &[], deadline).await,
            Err(DaemonError::PgStartFailed)
        );
        assert_eq!(
            ready_result(deadline, Ok(170011_u32)),
            Err(DaemonError::PgStartFailed)
        );

        // An established connection driver is retained outside query timeout cancellation.
        // A private pending driver models that timeout without any database or listener.
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let destroyed = Arc::new(AtomicBool::new(false));
        let guard = Dropped(Arc::clone(&destroyed));
        let driver = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<Result<(), tokio_postgres::Error>>().await
        });
        let connection = Connection {
            client: None,
            driver,
        };
        assert_eq!(
            connection.close_until(deadline).await,
            Err(DaemonError::PgStartFailed)
        );
        assert!(
            destroyed.load(Ordering::SeqCst),
            "driver cancellation must be joined before return"
        );
        assert!(ready_result(Instant::now() + READY, Ok(170011_u32)).is_ok());
    }
    #[tokio::test]
    async fn unowned_listener_is_not_contacted_before_identity_gate() {
        // Test-only TCP placeholder: the production daemon has no bind entry.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let root = config::test_dir();
        config::make_dir(&root.join("pg")).unwrap();
        config::make_dir(&root.join("pg/data")).unwrap();
        let spawned_at = SystemTime::now();
        let child = Command::new("/bin/sleep")
            .env_clear()
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let mut instance = Postgres {
            child,
            port,
            root: root.clone(),
            password: "test-only-sentinel".into(),
            version: 0,
            pid,
            binary: PathBuf::from("/bin/sleep"),
            spawned_at,
        };
        let path = root.join("pg/data/postmaster.pid");
        let data = fs::canonicalize(root.join("pg/data")).unwrap();
        let current = chrono::Utc::now().timestamp();
        let short = format!("{pid}\n{}\n{current}\n{port}\n", data.display());
        let ready = format!("{short}\n127.0.0.1\n0 0\nready   \n");
        config::write_private(&path, short.as_bytes(), true).unwrap();
        let mut accepts = 0_u32;
        for contents in [short, ready] {
            config::write_private(&path, contents.as_bytes(), false).unwrap();
            assert!(matches!(
                instance.verify_connection(Instant::now() + READY).await,
                Err(DaemonError::PgStartFailed)
            ));
            match listener.accept() {
                Ok((_stream, _)) => accepts += 1,
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            }
            assert_eq!(
                accepts, 0,
                "a rejected identity must not contact or authenticate to the placeholder"
            );
        }
        // An old ready file carrying the newly reused PID/port cannot pass the spawn-time boundary.
        assert!(instance.pid_file_matches());
        instance.spawned_at =
            fs::metadata(&path).unwrap().modified().unwrap() + Duration::from_secs(1);
        assert!(matches!(
            instance.verify_connection(Instant::now() + READY).await,
            Err(DaemonError::PgStartFailed)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(accepts, 0); // With no accepted connection, authentication and SQL counts are also zero.
        instance.child.kill().await.unwrap();
        instance.child.wait().await.unwrap();
        // Preserve stale PG records for PostgreSQL's own orphan/shared-memory interlock.
        assert!(path.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    #[ignore = "requires explicit own PG17.11 binaries; run serially"]
    async fn identity_rejects_prefix_cluster_and_stale_start() {
        let outer = config::test_dir();
        let root = outer.join("Space Dir");
        config::make_dir(&root).unwrap();
        let pg_bin = std::env::var_os("OMB_TEST_PG_BIN_DIR")
            .map(PathBuf::from)
            .expect("explicit own PG17.11 test binary directory required");
        crate::init(crate::InitOptions {
            data_dir: root.clone(),
            pg_bin_dir: pg_bin,
        })
        .await
        .unwrap();
        let config = config::load(&root).unwrap();
        let mut postgres = Postgres::start(&root, &config).await.unwrap();
        let result: Result<(), &'static str> = async {
            let data = root.join("pg/data");
            let binary = config.pg_bin_dir.join("postgres");
            let observed = process_identity(postgres.pid, &binary, &data, postgres.port)
                .await
                .ok_or("owned PostgreSQL identity unavailable")?;
            let text = String::from_utf8(
                config::read_private(&data.join("postmaster.pid"), 8192)
                    .map_err(|_| "own pid file unavailable")?,
            )
            .map_err(|_| "own pid file UTF-8")?;
            let recorded = text
                .lines()
                .nth(2)
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or("own recorded start")?;
            if !identity_start_matches(&observed, recorded)
                || identity_start_matches(&observed, recorded - 3600)
                || identity_start_matches(&observed, recorded + 3600)
            {
                return Err("actual start freshness was not enforced");
            }
            let prefix_neighbor = PathBuf::from(format!("{}-other", data.display()));
            if process_identity(postgres.pid, &binary, &prefix_neighbor, postgres.port)
                .await
                .is_some()
                || process_identity(postgres.pid, &binary, &data, postgres.port.wrapping_add(1))
                    .await
                    .is_some()
            {
                return Err("prefix cluster or other port accepted");
            }
            let foreign_root = outer.join("Space Dir-other");
            for path in [
                &foreign_root,
                &foreign_root.join("pg"),
                &foreign_root.join("pg/data"),
            ] {
                config::make_dir(path).map_err(|_| "foreign observation fixture")?;
            }
            let foreign_data = fs::canonicalize(foreign_root.join("pg/data"))
                .map_err(|_| "foreign observation path")?;
            let foreign_record = format!(
                "{}\n{}\n{recorded}\n{}\n\n127.0.0.1\n0 0\nready   \n",
                postgres.pid,
                foreign_data.display(),
                postgres.port
            );
            config::write_private(
                &foreign_root.join("pg/data/postmaster.pid"),
                foreign_record.as_bytes(),
                true,
            )
            .map_err(|_| "foreign observation record")?;
            if stop_stale(&foreign_root, &config).await != Err(DaemonError::PostmasterPidForeign) {
                return Err("same-binary other-cluster process was not refused");
            }
            if postgres.version != 170011
                || !postgres.is_alive().map_err(|_| "owned child state")?
            {
                return Err("owned PG17.11 not alive");
            }
            Ok(())
        }
        .await;
        let stopped = postgres.stop().await;
        fs::remove_dir_all(outer).unwrap();
        stopped.unwrap();
        result.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_version_and_changed_hba() {
        let root = config::test_dir();
        config::make_dir(&root.join("pg")).unwrap();
        config::make_dir(&root.join("pg/data")).unwrap();
        config::write_private(
            &root.join("pg/data/pg_hba.conf"),
            b"host all all 0.0.0.0/0 trust",
            true,
        )
        .unwrap();
        assert_eq!(verify_hba(&root), Err(DaemonError::PgHbaRejected));
        assert_eq!(
            verify_binaries(&root).await,
            Err(DaemonError::PgBinariesRejected)
        );
        // Known disposable scripts are controlled test inputs; no unknown installation is executed.
        config::write_private(
            &root.join("postgres"),
            b"#!/bin/sh\nprintf 'postgres (PostgreSQL) 16.11\\n'\n",
            true,
        )
        .unwrap();
        config::write_private(&root.join("initdb"), b"#!/bin/sh\nexit 99\n", true).unwrap();
        for name in ["postgres", "initdb"] {
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(
            verify_binaries(&root).await,
            Err(DaemonError::PgBinariesRejected)
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn foreign_postmaster_identity_is_never_signalled() {
        let root = config::test_dir();
        config::make_dir(&root.join("pg")).unwrap();
        config::make_dir(&root.join("pg/data")).unwrap();
        let mut child = Command::new("/bin/sleep")
            .env_clear()
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let data = fs::canonicalize(root.join("pg/data")).unwrap();
        let text = format!("{}\n{}\n0\n5432\n", child.id().unwrap(), data.display());
        config::write_private(&root.join("pg/data/postmaster.pid"), text.as_bytes(), true).unwrap();
        let cfg = Config {
            deployment_id: String::new(),
            pg_bin_dir: PathBuf::from("/unavailable-pg"),
            hosts: Default::default(),
        };
        assert_eq!(
            stop_stale(&root, &cfg).await,
            Err(DaemonError::PostmasterPidForeign)
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
