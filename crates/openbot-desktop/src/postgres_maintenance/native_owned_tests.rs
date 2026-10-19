//! Explicit native place only. Missing or malformed frozen inputs fail; no stock/PATH fallback.
use std::path::PathBuf;

use super::{MaintenanceError, bundle, limits, runner};
use runner::{OwnedNativeTestScenario as Scenario, OwnedTestObservation};

struct Inputs {
    bundle: PathBuf,
    root: PathBuf,
    profile: PathBuf,
}
impl Inputs {
    fn frozen() -> Self {
        fn path(name: &str) -> PathBuf {
            let value = std::env::var_os(name)
                .unwrap_or_else(|| panic!("missing frozen native input {name}"));
            let path = PathBuf::from(value);
            assert!(
                path.is_absolute() && path.to_str().is_some(),
                "invalid native input {name}"
            );
            path
        }
        let inputs = Self {
            bundle: path("WROK_BOT_PG_MAINTENANCE_TEST_BUNDLE"),
            root: path("WROK_BOT_PG_MAINTENANCE_TEST_ROOT"),
            profile: path("WROK_BOT_PG_MAINTENANCE_TEST_PROFILE"),
        };
        // Trust/profile validation precedes creation. G2 freezes this exact source/build/profile
        // separately; this test has no run-time expected digest or profile defaults.
        let _bundle = bundle::verify_bundle(
            &inputs.bundle,
            bundle::reviewed_bundle_binding().expect("compiled reviewed binding"),
        )
        .expect("source-authenticated native bundle");
        let _profile = limits::parse_profile(
            &bundle::read_input_file(&inputs.profile, 64 * 1024).expect("bounded explicit profile"),
        )
        .expect("finite native profile");
        runner::prepare_owned_test_parent(&inputs.root).expect("new private-tmp namespace prefix");
        inputs
    }
    async fn run(&self, name: &str, scenario: Scenario) -> OwnedTestObservation {
        let bundle = bundle::verify_bundle(
            &self.bundle,
            bundle::reviewed_bundle_binding().expect("compiled binding"),
        )
        .expect("same closed native bundle");
        let profile = limits::parse_profile(
            &bundle::read_input_file(&self.profile, 64 * 1024).expect("frozen explicit profile"),
        )
        .expect("profile");
        assert!(
            name.len() == 2 && name.bytes().all(|b| b.is_ascii_lowercase()),
            "closed scenario suffix"
        );
        let prefix = self
            .root
            .file_name()
            .and_then(|n| n.to_str())
            .expect("frozen prefix");
        let root = self.root.with_file_name(format!("{prefix}-{name}"));
        runner::owned_test_case(bundle, root, profile, scenario)
            .await
            .expect("actual case refused or unresolved; no native pass")
    }
}
fn original_closure(o: &OwnedTestObservation) {
    assert!(
        o.native_started
            && o.original_child_wait
            && o.all_original_pipe_joins
            && o.all_original_sources_closed
    );
    if o.worker_created {
        assert!(o.worker_wait_observed);
    } else {
        assert!(!o.worker_wait_observed);
    }
    assert!(
        o.original_t0_ns < o.original_effect_ns && o.original_effect_ns < o.original_convergence_ns
    );
    assert!(
        !o.platform_signature_verified
            && !o.production_release_authorized
            && !o.existing_capture_or_ready
    );
}

#[tokio::test]
#[ignore = "Root G2: explicit owned PG17.11 v2 bundle/profile/short root and shared physical slot"]
async fn owned_v2_basebackup_streamed_wal_restores_and_restarts() {
    let i = Inputs::frozen();
    let o = i.run("ok", Scenario::Normal).await;
    original_closure(&o);
    assert_eq!(o.error, None);
    assert_eq!(o.terminal_error, Some(0));
    assert!(
        o.worker_created
            && o.native_closed_success
            && o.native_usable
            && o.restore_and_restart_checked
    );
}
#[tokio::test]
#[ignore = "Root G2: real original-worker cancel, EOF and tightened original C; roots retained"]
async fn owned_helper_cancel_eof_and_deadline_reap_original_wal_worker() {
    let i = Inputs::frozen();
    for (name, scenario) in [
        ("cn", Scenario::CancelAfterWorker),
        ("ef", Scenario::EofAfterWorker),
        ("dl", Scenario::TightDeadlineAfterWorker),
    ] {
        let o = i.run(name, scenario).await;
        original_closure(&o);
        assert!(o.worker_created && o.worker_wait_observed && o.error.is_some());
        assert!(!o.native_closed_success && !o.native_usable && !o.restore_and_restart_checked);
        if scenario == Scenario::TightDeadlineAfterWorker {
            let c = o
                .requested_tighter_c
                .expect("actual same-owner tighter C request");
            assert!(c <= o.original_convergence_ns);
            assert_eq!(
                o.terminal_error,
                Some(12),
                "actual convergence expiry must remain failure"
            );
            assert!(
                o.worker_wait_ns.is_some_and(|wait| wait >= c),
                "late original wait retained"
            );
        } else {
            assert!(matches!(o.terminal_error, Some(6 | 12)));
        }
    }
}
#[tokio::test]
#[ignore = "Root G2: own source closure before START and after real WAL-worker creation"]
async fn owned_helper_connection_copy_worker_failure_is_closed_or_honest_unknown() {
    let i = Inputs::frozen();
    for (name, scenario) in [
        ("co", Scenario::ConnectionBeforeStart),
        ("cp", Scenario::DisconnectAfterWorker),
    ] {
        let o = i.run(name, scenario).await;
        original_closure(&o);
        assert!(o.error.is_some() && !o.native_closed_success && !o.native_usable);
        assert!(matches!(o.terminal_error, Some(8..=12)));
        if scenario == Scenario::DisconnectAfterWorker {
            assert!(o.worker_created && o.worker_wait_observed);
        } else {
            assert!(!o.worker_created && !o.worker_wait_observed);
        }
    }
}
#[tokio::test]
#[ignore = "Root G2: only newly produced backup bytes tampered; no user data or expected rewrite"]
async fn owned_manifest_or_wal_tamper_fails_restore_check() {
    let i = Inputs::frozen();
    for (name, scenario) in [
        ("mf", Scenario::TamperManifest),
        ("wl", Scenario::TamperWal),
    ] {
        let o = i.run(name, scenario).await;
        original_closure(&o);
        assert!(
            o.native_closed_success,
            "helper success precedes actual stored-byte corruption"
        );
        assert!(matches!(
            o.error,
            Some(MaintenanceError::ManifestInvalid | MaintenanceError::WalRangeInvalid)
        ));
        assert!(!o.native_usable && !o.restore_and_restart_checked);
    }
}
#[tokio::test]
#[ignore = "Root G2: actual argv/env, bounded diagnostic streams and retained owned regular files"]
async fn native_secret_is_absent_from_argv_env_files_and_diagnostics() {
    let i = Inputs::frozen();
    let o = i.run("sc", Scenario::Normal).await;
    original_closure(&o);
    assert_eq!(o.error, None);
    assert!(o.native_usable);
    assert!(o.argv_env_secret_scan_pass && o.plaintext_secret_scan_pass);
}
#[tokio::test]
#[ignore = "Root G2: explicit test-only one-byte material cap passed to the real same helper"]
async fn native_capacity_exhaustion_retains_original_owners_and_evidence() {
    let i = Inputs::frozen();
    let o = i.run("ca", Scenario::Capacity).await;
    original_closure(&o);
    assert!(o.error.is_some() && !o.native_usable && !o.restore_and_restart_checked);
    assert_eq!(
        o.terminal_error,
        Some(7),
        "actual native capacity guard, not early profile refusal"
    );
}
