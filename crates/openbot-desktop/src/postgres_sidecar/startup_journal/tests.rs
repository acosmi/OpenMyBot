use super::record::{StartupJournalPhase, StartupJournalRecord};
use super::*;
use crate::postgres_sidecar::{
    PostgresBundleDigest, PostgresSidecarError, PostgresSidecarOrigin, PostgresSidecarSupervisor,
    PostgresStartLock, ReviewedPostgresKeyStoreService, VerifiedPostgresBundle,
};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Harness {
    root: PathBuf,
    data_dir: PathBuf,
    instance: String,
    lock: Option<PostgresStartLock>,
}

impl Harness {
    fn new(tag: &str) -> Self {
        let instance = "d".repeat(64);
        let root = std::env::temp_dir().join(format!(
            "openbot-startup-journal-{tag}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let data_dir = root.join(format!("postgresql-17-{instance}"));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&data_dir).unwrap();
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock =
            PostgresStartLock::acquire(&root, &instance, PostgresBundleDigest([0x4a; 32])).unwrap();
        Self {
            root,
            data_dir,
            instance,
            lock: Some(lock),
        }
    }

    fn lock(&self) -> &PostgresStartLock {
        self.lock.as_ref().unwrap()
    }

    fn lock_mut(&mut self) -> &mut PostgresStartLock {
        self.lock.as_mut().unwrap()
    }

    fn journal_path(&self) -> PathBuf {
        self.root
            .join(format!(".postgresql-17-{}.startup-v1.json", self.instance))
    }

    fn prepare(&self) -> StartupJournalPreparation {
        StartupJournalPreparation::inspect(self.lock(), &self.data_dir).unwrap()
    }

    fn begin(&mut self) -> StartupJournal {
        let preparation = self.prepare();
        self.lock_mut().preserve_on_drop();
        preparation.begin_spawn(self.lock()).unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(lock) = self.lock.as_mut() {
                lock.preserve_on_drop();
            }
            eprintln!(
                "startup journal test preserved failure evidence at {}",
                self.root.display()
            );
            return;
        }
        drop(self.lock.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn sleeping() -> Self {
        Self(Some(
            Command::new("/bin/sleep")
                .env_clear()
                .arg("0.25")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ))
    }

    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity::capture(self.0.as_ref().unwrap().id()).unwrap()
    }

    fn wait_success(&mut self) {
        let mut child = self.0.take().unwrap();
        assert!(child.wait().unwrap().success());
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct PathCleanup(Vec<PathBuf>);

impl Drop for PathCleanup {
    fn drop(&mut self) {
        if std::thread::panicking() {
            for path in &self.0 {
                eprintln!(
                    "startup journal test preserved failure evidence at {}",
                    path.display()
                );
            }
            return;
        }
        for path in self.0.drain(..) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn decode_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}

fn decode_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

fn exited_child_observation() -> String {
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    let bytes = identity.evidence_bytes().unwrap();
    child.wait_success();
    encode_hex(&bytes)
}

fn retired_record(harness: &Harness, child_observation: &str) -> StartupJournalRecord {
    retired_record_for(
        harness.lock(),
        &harness.data_dir,
        &harness.instance,
        child_observation,
    )
}

fn retired_record_for(
    owner: &PostgresStartLock,
    data_dir: &Path,
    instance: &str,
    child_observation: &str,
) -> StartupJournalRecord {
    let preparation = StartupJournalPreparation::inspect(owner, data_dir).unwrap();
    StartupJournalRecord {
        schema: "openbot-postgres-startup".to_owned(),
        schema_version: 1,
        instance_id: instance.to_owned(),
        data_dir_name: format!("postgresql-17-{instance}"),
        data_dir_device: preparation.data_dir_device,
        data_dir_inode: preparation.data_dir_inode,
        attempt_id: "12".repeat(16),
        start_evidence_sha256: start_evidence_sha256(owner),
        owner_observation: encode_hex(&preparation.owner_observation),
        child_observation: Some(child_observation.to_owned()),
        phase: StartupJournalPhase::ExitConfirmed,
    }
}

fn write_retired(harness: &Harness, child_observation: &str) -> Vec<u8> {
    fs::write(harness.data_dir.join("PG_VERSION"), b"17\n").unwrap();
    let record = retired_record(harness, child_observation);
    let bytes = encode_record(&record).unwrap();
    write_private(&harness.journal_path(), &bytes);
    bytes
}

fn spawn_entered_record(harness: &Harness) -> StartupJournalRecord {
    let preparation = harness.prepare();
    StartupJournalRecord {
        schema: "openbot-postgres-startup".to_owned(),
        schema_version: 1,
        instance_id: harness.instance.clone(),
        data_dir_name: format!("postgresql-17-{}", harness.instance),
        data_dir_device: preparation.data_dir_device,
        data_dir_inode: preparation.data_dir_inode,
        attempt_id: "34".repeat(16),
        start_evidence_sha256: start_evidence_sha256(harness.lock()),
        owner_observation: encode_hex(&preparation.owner_observation),
        child_observation: None,
        phase: StartupJournalPhase::SpawnEntered,
    }
}

fn assert_invalid_record(mutator: impl FnOnce(&mut serde_json::Value)) {
    let harness = Harness::new("invalid-record");
    let child = exited_child_observation();
    let record = retired_record(&harness, &child);
    let mut value = serde_json::to_value(record).unwrap();
    mutator(&mut value);
    write_private(
        &harness.journal_path(),
        &serde_json::to_vec(&value).unwrap(),
    );
    assert!(matches!(
        StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(StartupJournalError::Invalid)
    ));
}

#[test]
fn process_evidence_is_canonical_and_exit_confirmation_uses_an_owned_child_wait() {
    let owner = ProcessIdentity::capture(std::process::id()).unwrap();
    let owner_bytes = owner.evidence_bytes().unwrap();
    assert_eq!(owner_bytes.len(), 32);
    assert_eq!(decode_u32(&owner_bytes[..4]), std::process::id());
    assert!(decode_u64(&owner_bytes[4..12]) > 0);
    assert!(decode_u32(&owner_bytes[12..16]) < 1_000_000);
    assert!(owner_bytes[16..].iter().any(|byte| *byte != 0));

    let mut child = OwnedChild::sleeping();
    let child_identity = child.identity();
    let child_bytes = child_identity.evidence_bytes().unwrap();
    assert_ne!(decode_u32(&child_bytes[..4]), std::process::id());
    assert_eq!(&child_bytes[16..], &owner_bytes[16..]);

    let mut harness = Harness::new("owned-child-wait");
    let mut journal = harness.begin();
    journal
        .record_child(harness.lock(), &child_identity)
        .unwrap();
    journal.mark_ready(harness.lock()).unwrap();
    journal.mark_stop(harness.lock()).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert_eq!(journal.record.phase, StartupJournalPhase::ExitConfirmed);
}

#[test]
fn phase_progression_retired_reuse_and_active_restart_are_closed() {
    let mut harness = Harness::new("phase-progression");
    let mut journal = harness.begin();
    let first_attempt = journal.record.attempt_id.clone();
    assert_eq!(journal.record.phase, StartupJournalPhase::SpawnEntered);
    assert!(journal.record.child_observation.is_none());
    assert!(matches!(
        journal.mark_ready(harness.lock()),
        Err(StartupJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.mark_stop(harness.lock()),
        Err(StartupJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.confirm_exit(harness.lock()),
        Err(StartupJournalError::ReconciliationRequired)
    ));

    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    assert_eq!(journal.record.phase, StartupJournalPhase::ChildObserved);
    assert!(matches!(
        journal.record_child(harness.lock(), &identity),
        Err(StartupJournalError::ReconciliationRequired)
    ));
    journal.mark_ready(harness.lock()).unwrap();
    assert!(matches!(
        journal.mark_ready(harness.lock()),
        Err(StartupJournalError::ReconciliationRequired)
    ));
    journal.mark_stop(harness.lock()).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();

    fs::write(harness.data_dir.join("PG_VERSION"), b"17\n").unwrap();
    let retired = StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    assert!(retired.requires_existing_data());
    let next = retired.begin_spawn(harness.lock()).unwrap();
    assert_eq!(next.record.phase, StartupJournalPhase::SpawnEntered);
    assert_ne!(next.record.attempt_id, first_attempt);
    assert!(matches!(
        StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(StartupJournalError::RecoveryRequired)
    ));
}

#[test]
fn record_is_closed_canonical_and_bounded() {
    let child = exited_child_observation();
    let harness = Harness::new("record-boundary");
    let valid = write_retired(&harness, &child);
    assert!(valid.len() < JOURNAL_MAX_BYTES);
    assert!(StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());

    let mut exact = valid.clone();
    exact.resize(JOURNAL_MAX_BYTES, b' ');
    write_private(&harness.journal_path(), &exact);
    assert_eq!(fs::metadata(harness.journal_path()).unwrap().len(), 2048);
    assert!(StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());
    exact.push(b' ');
    write_private(&harness.journal_path(), &exact);
    assert!(matches!(
        StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(StartupJournalError::Invalid)
    ));

    assert_invalid_record(|value| {
        value.as_object_mut().unwrap().remove("attemptId");
    });
    assert_invalid_record(|value| value["unknown"] = serde_json::json!(true));
    assert_invalid_record(|value| value["schemaVersion"] = serde_json::json!(2));
    assert_invalid_record(|value| value["phase"] = serde_json::json!("unknown"));
    assert_invalid_record(|value| value["attemptId"] = serde_json::json!("AA".repeat(16)));
    assert_invalid_record(|value| value["childObservation"] = serde_json::Value::Null);
    assert_invalid_record(|value| {
        value["phase"] = serde_json::json!("spawn_entered");
    });
    assert_invalid_record(|value| {
        value["childObservation"] = value["ownerObservation"].clone();
    });

    let duplicate = Harness::new("duplicate-field");
    let record = retired_record(&duplicate, &child);
    let bytes = serde_json::to_string(&record).unwrap().replacen(
        "\"schemaVersion\":1",
        "\"schemaVersion\":1,\"schemaVersion\":1",
        1,
    );
    write_private(&duplicate.journal_path(), bytes.as_bytes());
    assert!(matches!(
        StartupJournalPreparation::inspect(duplicate.lock(), &duplicate.data_dir),
        Err(StartupJournalError::Invalid)
    ));
}

#[test]
fn nullable_child_observation_is_required_even_when_spawn_entered() {
    let explicit_null = Harness::new("explicit-null-child");
    let record = spawn_entered_record(&explicit_null);
    write_private(
        &explicit_null.journal_path(),
        &serde_json::to_vec(&record).unwrap(),
    );
    assert!(matches!(
        StartupJournalPreparation::inspect(explicit_null.lock(), &explicit_null.data_dir),
        Err(StartupJournalError::RecoveryRequired)
    ));

    let missing = Harness::new("missing-nullable-child");
    let mut record = serde_json::to_value(spawn_entered_record(&missing)).unwrap();
    record.as_object_mut().unwrap().remove("childObservation");
    write_private(
        &missing.journal_path(),
        &serde_json::to_vec(&record).unwrap(),
    );
    assert!(matches!(
        StartupJournalPreparation::inspect(missing.lock(), &missing.data_dir),
        Err(StartupJournalError::Invalid)
    ));
}

#[test]
fn private_file_and_directory_identity_changes_fail_closed() {
    let child = exited_child_observation();

    let permissions = Harness::new("permissions");
    write_retired(&permissions, &child);
    fs::set_permissions(
        permissions.journal_path(),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(matches!(
        StartupJournalPreparation::inspect(permissions.lock(), &permissions.data_dir),
        Err(StartupJournalError::Invalid)
    ));

    let hardlink = Harness::new("hardlink");
    write_retired(&hardlink, &child);
    fs::hard_link(hardlink.journal_path(), hardlink.root.join("journal-alias")).unwrap();
    assert!(matches!(
        StartupJournalPreparation::inspect(hardlink.lock(), &hardlink.data_dir),
        Err(StartupJournalError::Invalid)
    ));

    let symlink = Harness::new("symlink");
    let bytes = write_retired(&symlink, &child);
    let target = symlink.root.join("journal-target");
    write_private(&target, &bytes);
    fs::remove_file(symlink.journal_path()).unwrap();
    std::os::unix::fs::symlink(&target, symlink.journal_path()).unwrap();
    assert!(matches!(
        StartupJournalPreparation::inspect(symlink.lock(), &symlink.data_dir),
        Err(StartupJournalError::Invalid)
    ));

    let replacement = Harness::new("content-replacement");
    let bytes = write_retired(&replacement, &child);
    let prepared = replacement.prepare();
    let mut changed = bytes;
    changed[0] = b'[';
    write_private(&replacement.journal_path(), &changed);
    assert!(matches!(
        prepared.revalidate(replacement.lock()),
        Err(StartupJournalError::ReconciliationRequired)
    ));

    let directory = Harness::new("directory-replacement");
    let prepared = directory.prepare();
    let old = directory.root.join("old-data-dir");
    fs::rename(&directory.data_dir, &old).unwrap();
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&directory.data_dir).unwrap();
    assert!(matches!(
        prepared.revalidate(directory.lock()),
        Err(StartupJournalError::Invalid)
    ));
}

#[test]
fn retired_record_cannot_turn_an_empty_directory_into_fresh() {
    let harness = Harness::new("retired-needs-existing");
    let child = exited_child_observation();
    let original = write_retired(&harness, &child);
    fs::remove_file(harness.data_dir.join("PG_VERSION")).unwrap();
    let preparation =
        StartupJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    assert!(preparation.requires_existing_data());
    // The same preflight would be used before any key-store call. Its refusal also preserves the
    // retired bytes, so an old record can never authorize Fresh key generation.
    let mut harness = harness;
    harness.lock_mut().preserve_on_drop();
    assert!(matches!(
        preparation.begin_spawn(harness.lock()),
        Err(StartupJournalError::RecoveryRequired)
    ));
    assert_eq!(fs::read(harness.journal_path()).unwrap(), original);
}

#[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
#[tokio::test]
async fn supervisor_preflight_rejects_retired_record_on_fresh_before_secret_write() {
    use crate::postgres_sidecar::tests::{
        MemorySecretStore, materialize_failing_initdb_bundle, signing_identity,
        supervisor_test_paths,
    };

    let (bundle_root, digest) = materialize_failing_initdb_bundle();
    let (app_root, instance, data_dir) = supervisor_test_paths("startup-retired-fresh");
    let _cleanup = PathCleanup(vec![app_root.clone(), bundle_root.clone()]);
    let journal_path = app_root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
    let dynamic_path = app_root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
    let owner = PostgresStartLock::acquire(&app_root, &instance, digest).unwrap();
    let child = exited_child_observation();
    let retired = retired_record_for(&owner, &data_dir, &instance, &child);
    let original = encode_record(&retired).unwrap();
    write_private(&journal_path, &original);
    drop(owner);
    assert!(!dynamic_path.exists());

    let store = MemorySecretStore::empty();
    let service = ReviewedPostgresKeyStoreService::from_reviewed_release(
        "com.example.review.postgresql.startup-retired-fresh",
    )
    .unwrap();
    let result = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        &store,
        &service,
    )
    .await;
    assert!(matches!(
        result,
        Err(PostgresSidecarError::StartupJournalRecoveryRequired)
    ));
    assert_eq!(store.write_count(), 0);
    assert_eq!(fs::read(&journal_path).unwrap(), original);
    assert!(!dynamic_path.exists());
}

#[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
fn materialize_sleeping_supervisor_bundle(seconds: &str) -> (PathBuf, PostgresBundleDigest) {
    use crate::postgres_sidecar::tests::{materialize_failing_initdb_bundle, write_manifest};

    let (bundle_root, _) = materialize_failing_initdb_bundle();
    let programs = [
        (
            crate::postgres_sidecar::expected_program_paths()[0],
            "postgres",
            format!("exec /bin/sleep {seconds}\n"),
        ),
        (
            crate::postgres_sidecar::expected_program_paths()[1],
            "initdb",
            "data=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--pgdata\" ]; then shift; data=$1; fi\n  shift\ndone\nIFS= read -r first\nif IFS= read -r second; then [ \"$first\" = \"$second\" ] || exit 18; fi\n[ -n \"$data\" ] && [ -n \"$first\" ] || exit 18\n/usr/bin/printf '17\\n' > \"$data/PG_VERSION\"\nexit 0\n".to_owned(),
        ),
        (
            crate::postgres_sidecar::expected_program_paths()[2],
            "pg_ctl",
            "exit 0\n".to_owned(),
        ),
    ];
    for (relative, label, body) in programs {
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"{label} (PostgreSQL) {}\"; /bin/sleep 0.2; exit 0; fi\n{body}",
            crate::postgres_sidecar::POSTGRES_VERSION
        );
        let path = bundle_root.join(relative);
        fs::write(&path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let digest = write_manifest(&bundle_root);
    (bundle_root, digest)
}

#[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
#[tokio::test]
async fn cancelled_supervisor_preserves_observed_start_until_mid_phase_child_is_absent() {
    use crate::postgres_sidecar::tests::{
        MemorySecretStore, signing_identity, supervisor_test_paths,
    };
    use crate::postgres_sidecar::{INITDB_DEADLINE, READY_DEADLINE, VERSION_DEADLINE};
    use std::sync::Arc;

    let (bundle_root, digest) = materialize_sleeping_supervisor_bundle("30");
    let (app_root, instance, data_dir) = supervisor_test_paths("startup-cancel-observed");
    let _cleanup = PathCleanup(vec![app_root.clone(), bundle_root.clone()]);
    let journal_path = app_root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
    let dynamic_path = app_root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
    let store = Arc::new(MemorySecretStore::empty());
    let task_store = Arc::clone(&store);
    let task_bundle = bundle_root.clone();
    let task_root = app_root.clone();
    let task_instance = instance.clone();
    let task_data = data_dir.clone();
    let task = tokio::spawn(async move {
        let service = ReviewedPostgresKeyStoreService::from_reviewed_release(
            "com.example.review.postgresql.startup-cancel",
        )
        .unwrap();
        PostgresSidecarSupervisor::start(
            VerifiedPostgresBundle::open(&task_bundle, digest, &signing_identity()).unwrap(),
            &task_root,
            &task_instance,
            &task_data,
            task_store.as_ref(),
            &service,
        )
        .await
    });

    let observation_budget = VERSION_DEADLINE * 3 + INITDB_DEADLINE + READY_DEADLINE;
    let observation_deadline = tokio::time::Instant::now() + observation_budget;
    let mut observed = false;
    while tokio::time::Instant::now() < observation_deadline {
        if let Ok(bytes) = fs::read(&journal_path)
            && let Ok(record) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && record["phase"] == "child_observed"
        {
            observed = true;
            break;
        }
        if task.is_finished() {
            let result = task.await;
            panic!("fake supervisor ended before child_observed: {result:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(observed, "fake supervisor did not persist child_observed");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(dynamic_path.exists());
    let retained: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(retained["phase"], "child_observed");
    assert!(retained["childObservation"].is_string());

    let writes_before = store.write_count();
    let second_service = ReviewedPostgresKeyStoreService::from_reviewed_release(
        "com.example.review.postgresql.startup-cancel",
    )
    .unwrap();
    let second = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        store.as_ref(),
        &second_service,
    )
    .await;
    // V6-PR-013: abort keeps the mid-phase journal, then kill_on_drop removes the owned
    // child. With Empty openers, controlled retirement may reclaim the start-lock so a
    // second attempt can proceed past StartLockRecoveryRequired (this fake sleeper then
    // hits ReadyTimeout). A still-live registered child must still fail closed.
    match &second {
        Err(PostgresSidecarError::StartLockRecoveryRequired) => {
            assert_eq!(store.write_count(), writes_before);
            assert!(dynamic_path.exists());
            let after: serde_json::Value =
                serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
            assert_eq!(after["phase"], "child_observed");
        }
        Err(PostgresSidecarError::ReadyTimeout) => {
            // Proof the stale lock was reclaimed and startup proceeded into readiness wait.
        }
        Ok(_) => {}
        Err(other) => panic!("unexpected second-start error: {other:?}"),
    }
}

#[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
#[tokio::test]
async fn observed_child_natural_exit_is_confirmed_before_ready_failure_releases_owner() {
    use crate::postgres_sidecar::tests::{
        MemorySecretStore, signing_identity, supervisor_test_paths,
    };

    let (bundle_root, digest) = materialize_sleeping_supervisor_bundle("0.5");
    let (app_root, instance, data_dir) = supervisor_test_paths("startup-natural-exit");
    let _cleanup = PathCleanup(vec![app_root.clone(), bundle_root.clone()]);
    let journal_path = app_root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
    let dynamic_path = app_root.join(format!(".postgresql-17-{instance}.start-lock-v1"));
    let store = MemorySecretStore::empty();
    let service = ReviewedPostgresKeyStoreService::from_reviewed_release(
        "com.example.review.postgresql.startup-natural-exit",
    )
    .unwrap();

    let result = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        &store,
        &service,
    )
    .await;
    assert!(matches!(
        result,
        Err(PostgresSidecarError::ExitedBeforeReady)
    ));
    assert_eq!(store.write_count(), 1);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(record["phase"], "exit_confirmed");
    assert!(record["childObservation"].is_string());
    assert!(!dynamic_path.exists());

    let first_attempt = record["attemptId"].as_str().unwrap().to_owned();
    let second = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        &store,
        &service,
    )
    .await;
    assert!(matches!(
        second,
        Err(PostgresSidecarError::ExitedBeforeReady)
    ));
    assert_eq!(store.write_count(), 1);
    let second_record: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(second_record["phase"], "exit_confirmed");
    assert_ne!(second_record["attemptId"], first_attempt);
    assert!(!dynamic_path.exists());
}

#[cfg(all(feature = "postgres-supervisor", target_os = "macos"))]
#[tokio::test]
#[ignore = "requires dedicated PostgreSQL 17.11 binaries via OPENBOT_TEST_POSTGRES_BIN_DIR"]
async fn real_postgres_fresh_ready_exit_and_existing_restart_use_distinct_attempts() {
    use crate::postgres_sidecar::tests::{
        MemorySecretStore, materialize_host_postgres_bundle, probe_running_sidecar, root,
        signing_identity,
    };

    let bin_dir = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").unwrap());
    let (bundle_root, digest) = materialize_host_postgres_bundle(&bin_dir);
    let app_root = root("startup-journal-real-pg");
    let _cleanup = PathCleanup(vec![app_root.clone(), bundle_root.clone()]);
    let instance = "9".repeat(64);
    let data_dir = app_root.join(format!("postgresql-17-{instance}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&app_root).unwrap();
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(&data_dir).unwrap();
    let store = MemorySecretStore::empty();
    let service = ReviewedPostgresKeyStoreService::from_reviewed_release(
        "com.example.review.postgresql.startup-journal",
    )
    .unwrap();
    let journal_path = app_root.join(format!(".postgresql-17-{instance}.startup-v1.json"));
    let dynamic_path = app_root.join(format!(".postgresql-17-{instance}.start-lock-v1"));

    let running = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        &store,
        &service,
    )
    .await
    .unwrap();
    assert_eq!(running.origin(), PostgresSidecarOrigin::Fresh);
    probe_running_sidecar(&running).await;
    let first_ready: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(first_ready["phase"], "ready");
    let first_child = first_ready["childObservation"].as_str().unwrap();
    assert!(decode_observation_hex(first_child).is_some());
    let first_attempt = first_ready["attemptId"].as_str().unwrap().to_owned();
    running.shutdown().await.unwrap();
    let first_exit: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(first_exit["phase"], "exit_confirmed");
    assert_eq!(
        first_exit["childObservation"],
        first_ready["childObservation"]
    );
    assert!(!dynamic_path.exists());

    let restarted = PostgresSidecarSupervisor::start(
        VerifiedPostgresBundle::open(&bundle_root, digest, &signing_identity()).unwrap(),
        &app_root,
        &instance,
        &data_dir,
        &store,
        &service,
    )
    .await
    .unwrap();
    assert_eq!(restarted.origin(), PostgresSidecarOrigin::Existing);
    probe_running_sidecar(&restarted).await;
    let second_ready: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(second_ready["phase"], "ready");
    assert_ne!(second_ready["attemptId"], first_attempt);
    restarted.shutdown().await.unwrap();
    let second_exit: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    assert_eq!(second_exit["phase"], "exit_confirmed");
    assert!(!dynamic_path.exists());
}
