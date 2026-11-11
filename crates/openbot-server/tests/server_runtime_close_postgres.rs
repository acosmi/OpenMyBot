//! V7-IMPL-046: real `wrok-bot-server` processes on an owned PostgreSQL 17.11.
//! A graceful exit writes its runtime close receipt; the next start retires
//! receipted entries, and settles killed ones only when no registered process
//! is alive (spec revision R484).

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use openbot_infra::db::pool::{self, DatabaseConfig};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const TENANT: &str = "wrok-bot-local";
/// Far below the configured 30 s convergence bound.
const PROMPT_EXIT: Duration = Duration::from_secs(10);

/// One Server site: its configuration, intent file and external control root.
struct Site {
    directory: PathBuf,
    database: DatabaseConfig,
    kek: String,
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Site {
    async fn new(database: DatabaseConfig, capacity: u64) -> Result<Self, String> {
        use base64::Engine as _;
        // A private task-owned root below the real checkout avoids the
        // intentionally world-writable system temporary ancestor.
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!(".server-close-046-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(directory.join("control")).unwrap();
        std::fs::set_permissions(
            directory.join("control"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let probe = pool::connect(&database)
            .await
            .map_err(|error| error.to_string())?;
        let row = probe
            .get()
            .await
            .map_err(|error| error.to_string())?
            .query_one(
                "SELECT pcs.system_identifier::text AS system, d.oid AS oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
        probe.close();
        let system: String = row.get("system");
        let oid: u32 = row.get("oid");
        let config = directory.join("config");
        let intent = directory.join("intent");
        let bytes = serde_json::to_vec(&json!({
            "version": 1,
            "controlRoot": directory.join("control"),
            "hostLimits": {
                "maxRequestBytes": 65536, "maxActivationBytes": 65536, "maxJournalFrameBytes": 65536,
                "maxJournalBytes": 1 << 20, "maxJournalRecords": 64, "maxRuntimeRecordBytes": 65536,
                "maxRegisteredRuntimes": capacity, "maxRetainedOperations": 8, "maxRootEntries": 64,
                "maxTempEntries": 8, "maxEvidenceRefs": 16, "maxRuntimeResourceFacts": 16,
                "maxIdBytes": 128, "maxComponentBytes": 128, "maxRelativePathBytes": 8192,
                "maxPathDepth": 128, "maxOpenFiles": 4096, "maxMetadataBytes": 1 << 24,
                "admissionNs": 30_000_000_000u64
            },
            "ordinaryStartupBounds": {"effectNs": 60_000_000_000u64, "convergenceNs": 30_000_000_000u64},
            "expectedServiceOwner": {"uid": std::fs::metadata(&directory).unwrap().uid(), "service": "openbot-test"},
            "expectedInstallationBinding": {"deploymentId": TENANT, "tenantId": TENANT,
                "datasetId": uuid::Uuid::new_v4().simple().to_string(),
                "sourceInstallationId": "server-source", "targetInstallationId": "server-target"},
            "expectedServerDatabase": {"pgSystemId": system.parse::<u64>().unwrap(), "databaseOid": oid, "pgMajor": 17},
            "optionalStartupIntent": {"mode": "fresh_init", "intentFile": intent},
        }))
        .unwrap();
        std::fs::write(&config, &bytes).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let meta = std::fs::metadata(&config).unwrap();
        let intent_bytes = serde_json::to_vec(&json!({
            "formatVersion": 1,
            "requestId": uuid::Uuid::new_v4().simple().to_string(),
            "mode": "fresh_init",
            "serviceConfig": {"file": {"device": meta.dev(), "inode": meta.ino(), "uid": meta.uid()},
                "length": meta.len(),
                "digest": format!("{:x}", Sha256::digest(&bytes))},
        }))
        .unwrap();
        std::fs::write(&intent, intent_bytes).unwrap();
        std::fs::set_permissions(&intent, std::fs::Permissions::from_mode(0o600)).unwrap();
        Ok(Self {
            directory,
            database,
            kek: base64::engine::general_purpose::STANDARD.encode(
                uuid::Uuid::new_v4()
                    .as_bytes()
                    .iter()
                    .chain(uuid::Uuid::new_v4().as_bytes())
                    .copied()
                    .collect::<Vec<u8>>(),
            ),
        })
    }

    fn runtimes(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.directory.join("control/runtimes"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect()
    }

    /// Start the real binary and wait for readiness.
    fn start(&self) -> Result<Running, String> {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let database = &self.database;
        let url = format!(
            "host={} port={} user={} password={} dbname={}",
            database.host,
            database.port,
            database.user,
            database.password.as_deref().unwrap_or_default(),
            database.dbname
        );
        let child = Command::new(env!("CARGO_BIN_EXE_wrok-bot-server"))
            .arg("--local")
            .current_dir(&self.directory)
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap())
            .env("PATH", "/usr/bin:/bin")
            .env("WROK_BOT_DATABASE_URL", url)
            .env("WROK_BOT_KEY_ENCRYPTION_KEY", &self.kek)
            .env("WROK_BOT_RECOVERY_CONFIG", self.directory.join("config"))
            .env(
                "WROK_BOT_TENANT_PACKAGE_DIR",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/wrok-bot"),
            )
            .env("WROK_BOT_PORT", port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?;
        let mut running = Running { child, port };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(60) {
            if running.ready() {
                return Ok(running);
            }
            if let Some(status) = running.child.try_wait().unwrap() {
                return Err(format!("server exited before readiness: {status}"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        running.child.kill().unwrap();
        running.child.wait().unwrap();
        Err("server never became ready".to_owned())
    }
}

struct Running {
    child: Child,
    port: u16,
}

impl Running {
    fn ready(&self) -> bool {
        let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        let request = format!(
            "GET /readiness HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            self.port
        );
        if stream.write_all(request.as_bytes()).is_err() {
            return false;
        }
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response.starts_with("HTTP/1.1 200")
    }

    /// Deliver `signal` and return the exit status and how long it took.
    fn signal(mut self, signal: &str) -> (std::process::ExitStatus, Duration) {
        let status = Command::new("/bin/kill")
            .args([signal, &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let sent = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status, sent.elapsed());
            }
            if sent.elapsed() > Duration::from_secs(60) {
                self.child.kill().unwrap();
                panic!("server did not exit after {signal}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

async fn owned<F>(tag: &str, body: F)
where
    F: AsyncFnOnce(DatabaseConfig) -> Result<(), String>,
{
    let admin = harness::admin_config(tag);
    assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
    harness::with_temp_database(&admin, tag, |config| body(config)).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
async fn t046_63_graceful_exit_writes_its_receipt_and_the_next_start_retires_it() {
    owned("t046_63", async |database| {
        let capacity = 2;
        let site = Site::new(database, capacity).await?;
        // N + 2 starts at capacity N, stopped by SIGINT and SIGTERM in turn.
        for (round, signal) in ["-INT", "-TERM", "-INT", "-TERM"].into_iter().enumerate() {
            let running = site.start()?;
            let entries = site.runtimes();
            if entries.len() != 1 {
                return Err(format!("round {round}: entries {}", entries.len()));
            }
            let (status, took) = running.signal(signal);
            if status.code() != Some(0) || took >= PROMPT_EXIT {
                return Err(format!(
                    "round {round}: {signal} gave {status} after {took:?}"
                ));
            }
            if !entries[0].join("receipt-v1").is_file() {
                return Err(format!("round {round}: no close receipt"));
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
async fn t046_64_killed_server_enrollments_settle_unless_a_registered_server_lives() {
    owned("t046_64", async |database| {
        let capacity = 3;
        let site = Site::new(database, capacity).await?;
        // N + 2 kill -9 crashes at capacity N: each start settles the last one.
        for round in 0..5 {
            let running = site.start()?;
            if site.runtimes().len() != 1 {
                return Err(format!("round {round}: the killed entry stayed"));
            }
            let (status, _) = running.signal("-KILL");
            if status.code().is_some() {
                return Err(format!("round {round}: {status} was not a kill"));
            }
        }
        // A live second Server keeps its SH: the next start cannot take EX
        // and keeps the killed entry.
        let live = site.start()?;
        let killed = site.start()?;
        let (_, _) = killed.signal("-KILL");
        let third = site.start()?;
        if site.runtimes().len() != 3 {
            return Err(format!(
                "a live runtime must keep the killed entry: {}",
                site.runtimes().len()
            ));
        }
        for running in [third, live] {
            let (status, took) = running.signal("-INT");
            if status.code() != Some(0) || took >= PROMPT_EXIT {
                return Err(format!("graceful stop gave {status} after {took:?}"));
            }
        }
        let last = site.start()?;
        let entries = site.runtimes();
        let (status, _) = last.signal("-INT");
        if entries.len() != 1 || status.code() != Some(0) {
            return Err(format!(
                "receipts retire and the killed entry settles: {}",
                entries.len()
            ));
        }
        Ok(())
    })
    .await;
}
