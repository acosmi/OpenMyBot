use super::record::{HelperJournalPhase, HelperJournalRecord, HelperKind};
use super::*;
use crate::postgres_sidecar::{PostgresBundleDigest, PostgresStartLock};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use wrok_bot_macos_process::ProcessIdentity;

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
            "openbot-helper-journal-{tag}-{}-{}",
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
            .join(format!(".postgresql-17-{}.helper-v1.json", self.instance))
    }

    fn prepare(&self) -> HelperJournalPreparation {
        HelperJournalPreparation::inspect(self.lock(), &self.data_dir).unwrap()
    }

    fn begin(&mut self) -> HelperJournal {
        let preparation = self.prepare();
        self.lock_mut().preserve_on_drop();
        preparation
            .begin_helper(self.lock(), HelperKind::VersionPostgres)
            .unwrap()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(lock) = self.lock.as_mut() {
                lock.preserve_on_drop();
            }
            eprintln!(
                "helper journal test preserved failure evidence at {}",
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

fn complete_record(
    harness: &Harness,
    kind: HelperKind,
    child_observation: &str,
) -> HelperJournalRecord {
    let preparation = HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    HelperJournalRecord {
        schema: "openbot-postgres-helper".to_owned(),
        schema_version: 1,
        instance_id: harness.instance.clone(),
        data_dir_name: format!("postgresql-17-{}", harness.instance),
        data_dir_device: preparation.data_dir_device,
        data_dir_inode: preparation.data_dir_inode,
        attempt_id: "12".repeat(16),
        start_evidence_sha256: start_evidence_sha256(harness.lock()),
        owner_observation: encode_hex(&preparation.owner_observation),
        helper_kind: kind,
        child_observation: Some(child_observation.to_owned()),
        phase: HelperJournalPhase::HelpersComplete,
    }
}

fn write_complete(harness: &Harness, kind: HelperKind, child_observation: &str) -> Vec<u8> {
    let record = complete_record(harness, kind, child_observation);
    let bytes = encode_record(&record).unwrap();
    write_private(&harness.journal_path(), &bytes);
    bytes
}

fn assert_invalid_record(mutator: impl FnOnce(&mut serde_json::Value)) {
    let harness = Harness::new("invalid-record");
    let child = exited_child_observation();
    let record = complete_record(&harness, HelperKind::VersionPgCtl, &child);
    let mut value = serde_json::to_value(record).unwrap();
    mutator(&mut value);
    write_private(
        &harness.journal_path(),
        &serde_json::to_vec(&value).unwrap(),
    );
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::Invalid)
    ));
    assert!(harness.journal_path().exists());
}

#[derive(Debug, PartialEq, Eq)]
struct DispositionFileSnapshot {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
}

fn disposition_tree_snapshot(path: &Path) -> Vec<DispositionFileSnapshot> {
    let metadata = fs::symlink_metadata(path).unwrap();
    let mut snapshot = vec![DispositionFileSnapshot {
        path: path.to_owned(),
        bytes: metadata.is_file().then(|| fs::read(path).unwrap()),
        mode: metadata.mode(),
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
    }];
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            snapshot.extend(disposition_tree_snapshot(&entry));
        }
    }
    snapshot
}

#[test]
fn pg_version_disposition_preserves_trim_and_sixteen_byte_boundary() {
    let cases = [
        ("canonical", b"17\n".to_vec(), true),
        ("ascii-trim", b" \t17\r\n".to_vec(), true),
        (
            "unicode-trim",
            "\u{2002}17\u{2002}".as_bytes().to_vec(),
            true,
        ),
        (
            "boundary16",
            format!("{}17", " ".repeat(14)).into_bytes(),
            true,
        ),
        (
            "boundary17",
            format!("{}17", " ".repeat(15)).into_bytes(),
            false,
        ),
        ("empty", Vec::new(), false),
        ("wrong-version", b"18\n".to_vec(), false),
        ("invalid-utf8", vec![b'1', b'7', 0xff], false),
    ];
    for (name, bytes, expected_existing) in cases {
        let harness = Harness::new(name);
        assert_eq!(
            read_data_directory_origin(&harness.data_dir),
            Ok(DataDirOrigin::Fresh)
        );
        let version = harness.data_dir.join("PG_VERSION");
        write_private(&version, &bytes);
        let before = disposition_tree_snapshot(&harness.root);
        let result = read_data_directory_origin(&harness.data_dir);
        eprintln!(
            "069-disposition {name} bytes={} existing={}",
            bytes.len(),
            result == Ok(DataDirOrigin::Existing)
        );
        assert_eq!(
            result,
            if expected_existing {
                Ok(DataDirOrigin::Existing)
            } else {
                Err(HelperJournalError::Invalid)
            },
            "{name}"
        );
        assert_eq!(disposition_tree_snapshot(&harness.root), before, "{name}");
    }
}

#[test]
fn pg_version_disposition_keeps_existing_permissions_and_hardlink_semantics() {
    let harness = Harness::new("069-version-hardlink");
    let version = harness.data_dir.join("PG_VERSION");
    write_private(&version, b"17\n");
    fs::set_permissions(&version, fs::Permissions::from_mode(0o640)).unwrap();
    fs::hard_link(&version, harness.root.join("owned-version-alias")).unwrap();
    let before = disposition_tree_snapshot(&harness.root);
    assert_eq!(fs::symlink_metadata(&version).unwrap().nlink(), 2);
    assert_eq!(
        read_data_directory_origin(&harness.data_dir),
        Ok(DataDirOrigin::Existing)
    );
    assert_eq!(disposition_tree_snapshot(&harness.root), before);
}

#[test]
fn pg_version_disposition_rejects_directory_symlink_and_nonempty_unversioned_data() {
    for shape in ["directory", "symlink", "nonempty"] {
        let harness = Harness::new(shape);
        let version = harness.data_dir.join("PG_VERSION");
        match shape {
            "directory" => fs::create_dir(&version).unwrap(),
            "symlink" => {
                let target = harness.root.join("owned-version-target");
                write_private(&target, b"17\n");
                std::os::unix::fs::symlink(target, &version).unwrap();
            }
            "nonempty" => write_private(&harness.data_dir.join("owned-data-sentinel"), b"preserve"),
            _ => unreachable!(),
        }
        let before = disposition_tree_snapshot(&harness.root);
        assert_eq!(
            read_data_directory_origin(&harness.data_dir),
            Err(HelperJournalError::Invalid),
            "{shape}"
        );
        assert_eq!(disposition_tree_snapshot(&harness.root), before, "{shape}");
    }
}

#[test]
fn invalid_pg_version_preserves_mid_phase_journal_and_all_prior_evidence() {
    let child = exited_child_observation();
    for phase in [
        HelperJournalPhase::ChildObserved,
        HelperJournalPhase::ExitConfirmed,
    ] {
        for bytes in [
            format!("{}17", " ".repeat(15)).into_bytes(),
            Vec::new(),
            vec![b'1', b'7', 0xff],
            b"18\n".to_vec(),
        ] {
            let harness = Harness::new("069-invalid-mid-phase");
            let mut record = complete_record(&harness, HelperKind::VersionPgCtl, &child);
            record.phase = phase;
            write_private(&harness.journal_path(), &encode_record(&record).unwrap());
            write_private(&harness.data_dir.join("PG_VERSION"), &bytes);
            for (label, header) in [
                ("recovery-epoch", "openbot-postgres-recovery-epoch-v1"),
                (
                    "consumed-recovery-epoch",
                    "openbot-postgres-consumed-recovery-epoch-v1",
                ),
                (
                    "auth-invalidation-required",
                    "openbot-postgres-auth-invalidation-required-v1",
                ),
                (
                    "auth-invalidation-applied",
                    "openbot-postgres-auth-invalidation-applied-v1",
                ),
            ] {
                write_private(
                    &harness
                        .root
                        .join(format!(".postgresql-17-{}.{label}-v1", harness.instance)),
                    format!(
                        "{header}\ninstance={}\nepoch={}\n",
                        harness.instance,
                        "ab".repeat(32)
                    )
                    .as_bytes(),
                );
            }
            let wal = harness.data_dir.join("pg_wal");
            fs::create_dir(&wal).unwrap();
            fs::set_permissions(&wal, fs::Permissions::from_mode(0o700)).unwrap();
            write_private(&wal.join("owned-wal-sentinel"), b"preserve-wal");
            write_private(
                &harness.data_dir.join("owned-data-sentinel"),
                b"preserve-data",
            );
            let before = disposition_tree_snapshot(&harness.root);
            let result = recover_mid_phase(
                &harness.lock().kernel_guard,
                &harness.root,
                &harness.instance,
                &harness.data_dir,
                &format!("postgresql-17-{}", harness.instance),
            );
            assert_eq!(
                result,
                Err(HelperJournalError::Invalid),
                "phase={phase:?} len={}",
                bytes.len()
            );
            assert_eq!(
                disposition_tree_snapshot(&harness.root),
                before,
                "phase={phase:?} len={}",
                bytes.len()
            );
            let result = crate::postgres_sidecar::quiescent::recover_mid_phase_journals(
                &harness.lock().kernel_guard,
                &harness.root,
                &harness.instance,
                &harness.data_dir,
                &format!("postgresql-17-{}", harness.instance),
            );
            assert!(
                matches!(
                    result,
                    Err(crate::postgres_sidecar::PostgresSidecarError::StartLockGuardInvalid)
                ),
                "{result:?}"
            );
            assert_eq!(disposition_tree_snapshot(&harness.root), before);
        }
    }
}

#[test]
fn pg_version_opened_probe_rejects_large_same_inode_growth() {
    let harness = Harness::new("069-opened-growth");
    let version = harness.data_dir.join("PG_VERSION");
    write_private(&version, b"17\n");
    let observed = fs::symlink_metadata(&version).unwrap();
    let file = secure_open_file(&version).unwrap();
    let mut writer = OpenOptions::new().append(true).open(&version).unwrap();
    writer.write_all(&vec![b' '; 1_048_576]).unwrap();
    writer.sync_all().unwrap();
    assert_eq!(
        fs::symlink_metadata(&version).unwrap().ino(),
        observed.ino()
    );
    let before = disposition_tree_snapshot(&harness.root);
    assert_eq!(
        read_pg_version_probe(&file),
        Err(HelperJournalError::Invalid)
    );
    assert_eq!(
        read_pg_version_bytes(&version, &file, &observed),
        Err(HelperJournalError::Invalid)
    );
    assert_eq!(disposition_tree_snapshot(&harness.root), before);
}

#[test]
fn pg_version_observed_handle_rejects_replacement_and_shortening() {
    for mutation in ["path-replacement", "same-inode-shortening"] {
        let harness = Harness::new(mutation);
        let version = harness.data_dir.join("PG_VERSION");
        write_private(&version, b"17\n");
        let observed = fs::symlink_metadata(&version).unwrap();
        let file = secure_open_file(&version).unwrap();
        if mutation == "path-replacement" {
            let replacement = harness.data_dir.join("owned-replacement");
            write_private(&replacement, b"17\n");
            fs::rename(replacement, &version).unwrap();
            assert_ne!(
                fs::symlink_metadata(&version).unwrap().ino(),
                observed.ino()
            );
        } else {
            write_private(&version, b"17");
            assert_eq!(
                fs::symlink_metadata(&version).unwrap().ino(),
                observed.ino()
            );
        }
        let before = disposition_tree_snapshot(&harness.root);
        assert_eq!(
            read_pg_version_bytes(&version, &file, &observed),
            Err(HelperJournalError::Invalid),
            "{mutation}"
        );
        // A new full observation accepts the now-current legal file; only the stale one failed.
        assert_eq!(
            read_data_directory_origin(&harness.data_dir),
            Ok(DataDirOrigin::Existing)
        );
        assert_eq!(
            disposition_tree_snapshot(&harness.root),
            before,
            "{mutation}"
        );
    }
}

#[test]
fn invalid_pg_version_reclaim_keeps_public_error_and_prior_epoch() {
    let mut harness = Harness::new("069-invalid-reclaim");
    let child = exited_child_observation();
    let mut record = complete_record(&harness, HelperKind::VersionPgCtl, &child);
    record.phase = HelperJournalPhase::ExitConfirmed;
    write_private(&harness.journal_path(), &encode_record(&record).unwrap());
    write_private(
        &harness.data_dir.join("PG_VERSION"),
        format!("{}17", " ".repeat(15)).as_bytes(),
    );
    let epoch = harness.root.join(format!(
        ".postgresql-17-{}.recovery-epoch-v1",
        harness.instance
    ));
    write_private(
        &epoch,
        format!(
            "openbot-postgres-recovery-epoch-v1\ninstance={}\nepoch={}\n",
            harness.instance,
            "ab".repeat(32)
        )
        .as_bytes(),
    );
    write_private(
        &harness.data_dir.join("owned-data-sentinel"),
        b"preserve-data",
    );
    let wal = harness.data_dir.join("pg_wal");
    fs::create_dir(&wal).unwrap();
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&wal.join("owned-wal-sentinel"), b"preserve-wal");
    harness.lock_mut().preserve_on_drop();
    drop(harness.lock.take());
    let before = disposition_tree_snapshot(&harness.root);
    let acquired = PostgresStartLock::acquire_with_data_dir(
        &harness.root,
        &harness.instance,
        PostgresBundleDigest([0x4a; 32]),
        &harness.data_dir,
    );
    assert!(
        matches!(
            acquired,
            Err(crate::postgres_sidecar::PostgresSidecarError::StartLockRecoveryRequired)
        ),
        "{acquired:?}"
    );
    assert_eq!(disposition_tree_snapshot(&harness.root), before);
}

#[test]
fn owned_helper_child_is_observed_then_confirmed() {
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    let mut harness = Harness::new("owned-helper-wait");
    let mut journal = harness.begin();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert_eq!(journal.record.phase, HelperJournalPhase::ExitConfirmed);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionPostgres);
    let on_disk = fs::read(harness.journal_path()).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&on_disk).unwrap();
    assert_eq!(parsed["schema"], "openbot-postgres-helper");
    assert!(parsed.get("secret").is_none());
    assert!(parsed.get("stdout").is_none());
    assert!(parsed.as_object().unwrap().values().all(|value| {
        value
            .as_str()
            .map(|text| !text.starts_with('/'))
            .unwrap_or(true)
    }));
}

#[test]
fn kind_and_phase_gates_are_closed_and_monotonic() {
    let mut harness = Harness::new("kind-phase");
    let preparation = harness.prepare();
    harness.lock_mut().preserve_on_drop();
    assert!(matches!(
        preparation.begin_helper(harness.lock(), HelperKind::Initdb),
        Err(HelperJournalError::Invalid)
    ));

    let mut journal = harness.begin();
    let first_attempt = journal.record.attempt_id.clone();
    assert_eq!(journal.record.phase, HelperJournalPhase::SpawnEntered);
    assert!(journal.record.child_observation.is_none());
    assert!(matches!(
        journal.confirm_exit(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::VersionInitdb),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));

    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    assert!(matches!(
        journal.record_child(harness.lock(), &identity),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::VersionPgCtl),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.begin_next_helper(harness.lock(), HelperKind::Initdb),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));

    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionInitdb)
        .unwrap();
    assert_eq!(journal.record.attempt_id, first_attempt);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionInitdb);
    assert_eq!(journal.record.phase, HelperJournalPhase::SpawnEntered);
    assert!(journal.record.child_observation.is_none());

    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionPgCtl)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal.mark_complete(harness.lock()).unwrap();
    assert_eq!(journal.record.phase, HelperJournalPhase::HelpersComplete);
    assert_eq!(journal.record.helper_kind, HelperKind::VersionPgCtl);
    assert_eq!(journal.record.attempt_id, first_attempt);

    let retired = HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).unwrap();
    let next = retired
        .begin_helper(harness.lock(), HelperKind::VersionPostgres)
        .unwrap();
    assert_eq!(next.record.phase, HelperJournalPhase::SpawnEntered);
    assert_ne!(next.record.attempt_id, first_attempt);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::RecoveryRequired)
    ));
}

#[test]
fn unfinished_helper_is_recovery_required_and_does_not_rewrite() {
    let mut harness = Harness::new("unfinished");
    let journal = harness.begin();
    let original = fs::read(harness.journal_path()).unwrap();
    drop(journal);
    assert_eq!(fs::read(harness.journal_path()).unwrap(), original);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::RecoveryRequired)
    ));
    assert_eq!(fs::read(harness.journal_path()).unwrap(), original);
}

#[test]
fn record_is_closed_canonical_and_bounded() {
    let child = exited_child_observation();
    let harness = Harness::new("record-boundary");
    let valid = write_complete(&harness, HelperKind::VersionPgCtl, &child);
    assert!(valid.len() < JOURNAL_MAX_BYTES);
    assert!(HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());

    let mut exact = valid.clone();
    exact.resize(JOURNAL_MAX_BYTES, b' ');
    write_private(&harness.journal_path(), &exact);
    assert_eq!(fs::metadata(harness.journal_path()).unwrap().len(), 2048);
    assert!(HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir).is_ok());
    exact.push(b' ');
    write_private(&harness.journal_path(), &exact);
    assert!(matches!(
        HelperJournalPreparation::inspect(harness.lock(), &harness.data_dir),
        Err(HelperJournalError::Invalid)
    ));

    assert_invalid_record(|value| {
        value.as_object_mut().unwrap().remove("attemptId");
    });
    assert_invalid_record(|value| {
        value.as_object_mut().unwrap().remove("childObservation");
    });
    assert_invalid_record(|value| value["unknown"] = serde_json::json!(true));
    assert_invalid_record(|value| value["schemaVersion"] = serde_json::json!(2));
    assert_invalid_record(|value| value["phase"] = serde_json::json!("unknown"));
    assert_invalid_record(|value| value["helperKind"] = serde_json::json!("postgres"));
    assert_invalid_record(|value| value["attemptId"] = serde_json::json!("AA".repeat(16)));
    assert_invalid_record(|value| value["childObservation"] = serde_json::Value::Null);
    assert_invalid_record(|value| {
        value["phase"] = serde_json::json!("spawn_entered");
    });
}

#[test]
fn mark_complete_only_from_last_version_or_initdb_exit() {
    let mut harness = Harness::new("complete-gate");
    let mut journal = harness.begin();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionInitdb)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    assert!(matches!(
        journal.mark_complete(harness.lock()),
        Err(HelperJournalError::ReconciliationRequired)
    ));
    journal
        .begin_next_helper(harness.lock(), HelperKind::VersionPgCtl)
        .unwrap();
    let mut child = OwnedChild::sleeping();
    let identity = child.identity();
    journal.record_child(harness.lock(), &identity).unwrap();
    child.wait_success();
    journal.confirm_exit(harness.lock()).unwrap();
    journal.mark_complete(harness.lock()).unwrap();
}
