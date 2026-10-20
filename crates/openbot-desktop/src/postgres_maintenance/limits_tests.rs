use serde_json::{Value, json};

use super::MaintenanceError;
use super::clock::OperationClock;
use super::limits::{self, CapacityObservation, MaterialCounters};

// Unit inputs only. The production decoder has no default profile, and native tests require the
// separately frozen explicit profile path. This constructor never escapes cfg(test).
pub(super) fn profile_value() -> Value {
    json!({
        "effectNs":120_000_000_000_u64,"convergenceNs":30_000_000_000_u64,
        "maxSourceSecretBytes":4096,"maxSecretMemoryBytes":2_097_152,
        "maxNativeSecretCopies":32,"maxControlBytes":4224,"maxStatusBytes":1344,
        "maxStatusRecords":8,"maxStderrBytes":65536,
        "maxMaterialFiles":16384,"maxDirectories":4096,"maxPathBytes":4096,"maxDepth":64,
        "maxSingleFileBytes":268_435_456_u64,"maxMaterialPlainBytes":536_870_912_u64,
        "maxWalBytes":134_217_728_u64,"maxWalSegments":8,"maxWalSpanBytes":134_217_728_u64,
        "maxWalTimelines":1,"maxBackupManifestBytes":8_388_608_u64,
        "maxTotalCopyBlocks":65536,"copyBlockBytes":65536,
        "maxSpoolBytes":536_870_912_u64,"maxRestoreCheckBytes":536_870_912_u64,
        "maxOpenFiles":64,"maxJournalBytes":16_777_216_u64,
        "capacityReserveBytes":67_108_864_u64,"freeFloorBytes":1_073_741_824_u64
    })
}
fn parse(v: &Value) -> Result<limits::MaintenanceProfile, MaintenanceError> {
    limits::parse_profile(&serde_json::to_vec(v).expect("unit profile encoding"))
}

#[test]
fn profile_requires_single_file_wal_blocks_spool_and_reserve_bounds() {
    let value = profile_value();
    let p = parse(&value).expect("finite unit profile");
    for (source_max, copies, required) in [
        (64_u64, 12_u64, 126_727_u64),
        (4096, 32, 1_304_071),
        (64, 1024, 166_397),
        (3, 12, 108_915),
    ] {
        assert_eq!(
            super::runner::validate_secret_memory_budget(source_max, copies, required),
            Ok(())
        );
        assert_eq!(
            super::runner::validate_secret_memory_budget(source_max, copies, required - 1),
            Err(MaintenanceError::SecretInvalid)
        );
    }
    for (source_max, copies) in [
        (64_u64, 11_u64),
        (4096, u64::MAX),
        (1, u64::MAX / 2),
        (0, 12),
        (4097, 12),
    ] {
        assert_eq!(
            super::runner::validate_secret_memory_budget(source_max, copies, u64::MAX),
            Err(MaintenanceError::SecretInvalid)
        );
    }
    for key in value.as_object().expect("object").keys() {
        let mut missing = value.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert!(
            matches!(parse(&missing), Err(MaintenanceError::ProfileInvalid)),
            "missing {key}"
        );
        let mut zero = value.clone();
        zero[key] = json!(0);
        assert!(
            matches!(parse(&zero), Err(MaintenanceError::ProfileInvalid)),
            "zero {key}"
        );
    }
    let mut unknown = value.clone();
    unknown["unlimited"] = json!(true);
    assert!(matches!(
        parse(&unknown),
        Err(MaintenanceError::ProfileInvalid)
    ));
    let text = String::from_utf8(serde_json::to_vec(&value).expect("json")).expect("utf8");
    let duplicate = format!("{{\"effectNs\":1,{}", &text[1..]);
    assert!(matches!(
        limits::parse_profile(duplicate.as_bytes()),
        Err(MaintenanceError::ProfileInvalid)
    ));
    assert!(matches!(
        limits::parse_profile(b""),
        Err(MaintenanceError::ProfileMissing)
    ));
    for (key, number) in [
        ("copyBlockBytes", 4_194_305_u64),
        ("maxWalTimelines", 2),
        ("maxStatusRecords", 7),
    ] {
        let mut bad = value.clone();
        bad[key] = json!(number);
        assert!(parse(&bad).is_err());
    }
    let mut counts = MaterialCounters::default();
    assert!(matches!(
        counts.file(p.fields(), p.fields().max_single_file_bytes + 1, 0, false),
        Err(MaintenanceError::CapacityExceeded)
    ));
    let mut one = value.clone();
    one["maxTotalCopyBlocks"] = json!(1);
    let one = parse(&one).expect("bounded counter");
    assert!(counts.file(one.fields(), 65536, 65536, false).is_ok());
    assert!(matches!(
        counts.file(one.fields(), 1, 512, false),
        Err(MaintenanceError::CapacityExceeded)
    ));
    assert_eq!(
        limits::validate_wal_range(p.fields(), 1, 16_777_216, 16_777_216, 33_554_432)
            .expect("one complete segment"),
        1
    );
    assert!(matches!(
        limits::validate_wal_range(p.fields(), 1, 16_777_216, 100, 100),
        Err(MaintenanceError::WalRangeInvalid)
    ));
    let mut small = value;
    small["maxSingleFileBytes"] = json!(16_777_215);
    assert!(
        limits::validate_wal_range(
            parse(&small).expect("profile").fields(),
            1,
            16_777_216,
            1,
            2
        )
        .is_err()
    );
}

#[test]
fn checked_peak_accounting_does_not_double_count_retained_allocations() {
    let mut row = CapacityObservation {
        free_bytes: 1000,
        retained_allocated_bytes: 9000,
        remaining_source_bytes: 100,
        remaining_spool_bytes: 200,
        remaining_restore_bytes: 300,
        remaining_journal_bytes: 50,
        reserve_bytes: 50,
        free_floor_bytes: 300,
    };
    assert!(row.validate().is_ok()); // exact 700 additional + 300 floor; 9000 is already occupied.
    row.retained_allocated_bytes = u64::MAX;
    assert!(row.validate().is_ok());
    row.free_bytes = 999;
    assert_eq!(row.validate(), Err(MaintenanceError::CapacityExceeded));
    row.free_bytes = u64::MAX;
    row.remaining_restore_bytes = u64::MAX;
    assert_eq!(row.validate(), Err(MaintenanceError::CapacityExceeded));
}

#[test]
fn same_absolute_clock_deadline_is_not_replenished_on_ipc_or_phase() {
    let clock = OperationClock::from_test_observation(std::process::id(), 100, 200, 300);
    for phase_observation in [100, 150, 199, 200, 250, 299, 300] {
        assert!(
            clock
                .check_observation(std::process::id(), phase_observation)
                .is_ok()
        );
        assert_eq!(
            (clock.t0(), clock.effect(), clock.convergence()),
            (100, 200, 300)
        );
    }
    // A control message can only tighten C; a phase cannot mint another deadline.
    assert!(super::protocol::cancel_frame(&[7; 16], 250, clock.convergence()).is_ok());
    assert_eq!(
        super::protocol::cancel_frame(&[7; 16], 301, clock.convergence()),
        Err(MaintenanceError::ProtocolInvalid)
    );
    let actual = OperationClock::start(1, 1).expect("monotonic clock");
    assert!(actual.effect() > actual.t0());
    assert!(actual.convergence() > actual.effect());
}

#[test]
fn overflow_and_boot_owner_loss_never_mint_new_effect_budget() {
    assert!(matches!(
        OperationClock::start(u64::MAX, 1),
        Err(MaintenanceError::ClockOverflow)
    ));
    assert!(matches!(
        OperationClock::start(1, u64::MAX),
        Err(MaintenanceError::ClockOverflow)
    ));
    let clock = OperationClock::from_test_observation(std::process::id(), 100, 200, 300);
    assert_eq!(
        clock.check_observation(std::process::id().wrapping_add(1), 150),
        Err(MaintenanceError::ClockUnavailable)
    );
    assert_eq!(
        clock.check_observation(std::process::id(), 99),
        Err(MaintenanceError::ClockUnavailable)
    );
    // Clock capabilities have private fields and no Deserialize/Clone/restart constructor.
    let mut profile = profile_value();
    profile["effectNs"] = json!(u64::MAX);
    assert!(matches!(
        parse(&profile),
        Err(MaintenanceError::ProfileInvalid)
    ));
}
