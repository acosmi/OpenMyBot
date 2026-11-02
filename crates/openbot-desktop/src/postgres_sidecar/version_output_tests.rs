//! macOS owned version-helper output limits and cleanup, using self-owned process fixtures.

use super::tests::{root, signing_identity, supervisor_test_paths, write_manifest};
use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::time::Instant;
use wrok_bot_macos_process::evidence_process_is_absent;

#[derive(Clone, Copy)]
enum OutputBehavior {
    ExactBytes(usize),
    Continuous,
    ReadTimeout,
    WaitTimeout,
}

struct Fixture {
    bundle_root: PathBuf,
    app_root: PathBuf,
    instance: String,
    data_dir: PathBuf,
    digest: PostgresBundleDigest,
}

impl Fixture {
    fn new(tag: &str, behavior: OutputBehavior) -> Self {
        let bundle_root = root(tag);
        fs::create_dir_all(bundle_root.join("bin")).unwrap();
        for (relative, label) in [
            (expected_program_paths()[0], "postgres"),
            (expected_program_paths()[1], "initdb"),
            (expected_program_paths()[2], "pg_ctl"),
        ] {
            let prefix = format!("{label} (PostgreSQL) {POSTGRES_VERSION}");
            let body = match behavior {
                OutputBehavior::ExactBytes(length) => format!(
                    "sys.stdout.buffer.write(prefix + b' ' * ({length} - len(prefix)))\nsys.stdout.buffer.flush()\n"
                ),
                OutputBehavior::Continuous => {
                    "while True:\n    sys.stdout.buffer.write(b'x' * 4096)\n    sys.stdout.buffer.flush()\n".to_owned()
                }
                OutputBehavior::ReadTimeout => "time.sleep(30)\n".to_owned(),
                OutputBehavior::WaitTimeout => {
                    "sys.stdout.buffer.write(prefix)\nsys.stdout.buffer.flush()\nos.close(1)\ntime.sleep(30)\n".to_owned()
                }
            };
            // An absolute shebang runs a single owned interpreter without a shell child. The
            // initial delay lets the real macOS capture/revalidation finish before a short exit.
            let script = format!(
                "#!/usr/bin/python3\nimport os, sys, time\nif sys.argv[1:] != ['--version']:\n    sys.exit(17)\ntime.sleep(0.2)\nprefix = b'{prefix}'\n{body}"
            );
            let path = bundle_root.join(relative);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let digest = write_manifest(&bundle_root);
        let (app_root, instance, data_dir) = supervisor_test_paths(tag);
        Self {
            bundle_root,
            app_root,
            instance,
            data_dir,
            digest,
        }
    }

    fn prepare(&self) -> (VerifiedPostgresBundle, PostgresStartLock, HelperJournal) {
        let bundle =
            VerifiedPostgresBundle::open(&self.bundle_root, self.digest, &signing_identity())
                .unwrap();
        let mut lock =
            PostgresStartLock::acquire(&self.app_root, &self.instance, self.digest).unwrap();
        let preparation = HelperJournalPreparation::inspect(&lock, &self.data_dir).unwrap();
        // Match the Supervisor's durable evidence policy before the first helper intent.
        lock.preserve_on_drop();
        let journal = preparation
            .begin_helper(&lock, HelperKind::VersionPostgres)
            .unwrap();
        (bundle, lock, journal)
    }

    fn journal_path(&self) -> PathBuf {
        self.app_root
            .join(format!(".postgresql-17-{}.helper-v1.json", self.instance))
    }

    fn lock_path(&self) -> PathBuf {
        self.app_root
            .join(format!(".postgresql-17-{}.start-lock-v1", self.instance))
    }

    fn record(&self) -> serde_json::Value {
        let bytes = fs::read(self.journal_path()).unwrap();
        assert!(bytes.len() <= 2048);
        assert!(
            !bytes
                .windows(b"PostgreSQL".len())
                .any(|window| window == b"PostgreSQL"),
            "version stdout must not enter the journal"
        );
        serde_json::from_slice(&bytes).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "version-output test preserved failure evidence at {} and {}",
                self.app_root.display(),
                self.bundle_root.display()
            );
            return;
        }
        let _ = fs::remove_dir_all(&self.app_root);
        let _ = fs::remove_dir_all(&self.bundle_root);
    }
}

fn child_evidence(record: &serde_json::Value) -> [u8; 32] {
    let hex = record["childObservation"].as_str().unwrap();
    assert_eq!(hex.len(), 64);
    let mut evidence = [0_u8; 32];
    for (byte, pair) in evidence
        .iter_mut()
        .zip(hex.as_bytes().as_chunks::<2>().0.iter())
    {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    evidence
}

async fn wait_for_observed_record(fixture: &Fixture) -> (serde_json::Value, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let bytes = fs::read(fixture.journal_path()).unwrap();
            let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if record["phase"] == "child_observed" {
                return (record, bytes);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("version helper did not persist child_observed")
}

async fn wait_for_exact_child_absence(evidence: &[u8; 32]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while evidence_process_is_absent(evidence).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the recorded owned helper must be absent after cleanup");
}

fn unrelated_owned_child() -> Child {
    Command::new("/bin/sleep")
        .env_clear()
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn assert_failure(behavior: OutputBehavior, tag: &str, immediate: bool) {
    let fixture = Fixture::new(tag, behavior);
    let (bundle, mut lock, mut journal) = fixture.prepare();
    let lock_bytes = fs::read(fixture.lock_path()).unwrap();
    let mut unrelated = unrelated_owned_child();
    let started = Instant::now();
    assert!(matches!(
        verify_program_versions_with_helper(&bundle, &mut lock, &mut journal, None).await,
        Err(PostgresSidecarError::VersionMismatch)
    ));
    if immediate {
        assert!(
            started.elapsed() < VERSION_DEADLINE,
            "output overflow must fail while reading, before the total timeout"
        );
    } else {
        assert!(
            started.elapsed() >= VERSION_DEADLINE,
            "the stalled helper must exercise the total timeout"
        );
    }
    assert_eq!(fs::read(fixture.lock_path()).unwrap(), lock_bytes);
    let record = fixture.record();
    assert_eq!(record["helperKind"], "version_postgres");
    assert_eq!(record["phase"], "child_observed");
    wait_for_exact_child_absence(&child_evidence(&record)).await;
    assert!(
        unrelated.try_wait().unwrap().is_none(),
        "cleanup must leave the independently owned child running"
    );
    terminate_child(&mut unrelated).await.unwrap();
}

#[tokio::test]
async fn version_output_4096_bytes_completes_all_owned_helpers() {
    let fixture = Fixture::new("version-output-4096", OutputBehavior::ExactBytes(4096));
    let (bundle, mut lock, mut journal) = fixture.prepare();
    verify_program_versions_with_helper(&bundle, &mut lock, &mut journal, None)
        .await
        .unwrap();
    let record = fixture.record();
    assert_eq!(record["helperKind"], "version_pg_ctl");
    assert_eq!(record["phase"], "exit_confirmed");
    wait_for_exact_child_absence(&child_evidence(&record)).await;
}

#[tokio::test]
async fn version_output_4097_bytes_rejects_and_cleans_exact_child() {
    assert_failure(
        OutputBehavior::ExactBytes(4097),
        "version-output-4097",
        true,
    )
    .await;
}

#[tokio::test]
async fn version_output_continuous_stream_rejects_before_timeout() {
    assert_failure(
        OutputBehavior::Continuous,
        "version-output-continuous",
        true,
    )
    .await;
}

#[tokio::test]
async fn version_output_read_timeout_cleans_exact_child_and_retains_journal() {
    assert_failure(
        OutputBehavior::ReadTimeout,
        "version-output-read-timeout",
        false,
    )
    .await;
}

#[tokio::test]
async fn version_output_eof_wait_uses_total_timeout_and_cleans_exact_child() {
    assert_failure(
        OutputBehavior::WaitTimeout,
        "version-output-wait-timeout",
        false,
    )
    .await;
}

#[tokio::test]
async fn version_output_cancellation_cleans_owned_child_and_retains_exact_evidence() {
    let fixture = Fixture::new("version-output-cancel", OutputBehavior::ReadTimeout);
    let (bundle, mut lock, mut journal) = fixture.prepare();
    let lock_bytes = fs::read(fixture.lock_path()).unwrap();
    let mut unrelated = unrelated_owned_child();
    let task = tokio::spawn(async move {
        verify_program_versions_with_helper(&bundle, &mut lock, &mut journal, None).await
    });
    let (record, journal_bytes) = wait_for_observed_record(&fixture).await;
    assert_eq!(record["helperKind"], "version_postgres");
    let evidence = child_evidence(&record);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(fs::read(fixture.lock_path()).unwrap(), lock_bytes);
    assert_eq!(fs::read(fixture.journal_path()).unwrap(), journal_bytes);
    assert_eq!(fixture.record()["phase"], "child_observed");
    wait_for_exact_child_absence(&evidence).await;
    assert!(unrelated.try_wait().unwrap().is_none());
    terminate_child(&mut unrelated).await.unwrap();
}
