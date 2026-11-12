//! `openbot-migrate preflight-audit-retention` 的真实子进程/退出码/零原值投影。

use std::process::Command;

fn run(arguments: &[&str], retention: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openbot-migrate"));
    command.args(arguments).env_clear();
    if let Some(value) = retention {
        command.env("AUDIT_RETENTION_DAYS", value);
    }
    command.output().expect("migration binary 必须可执行")
}

#[test]
fn coercion_is_exit_two_with_a_secretless_canonical_replacement() {
    let raw = "+0000000000000007";
    let output = run(&["preflight-audit-retention"], Some(raw));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout 是 JSON");
    assert_eq!(body["migrationCompatible"], false);
    assert_eq!(body["findings"][0]["variable"], "AUDIT_RETENTION_DAYS");
    assert_eq!(body["findings"][0]["code"], "canonical_decimal_required");
    assert_eq!(body["findings"][0]["replacementDays"], 7);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(raw));
}

#[test]
fn compatible_and_usage_paths_have_distinct_stable_exit_codes() {
    let compatible = run(&["preflight-audit-retention"], Some("30"));
    assert_eq!(compatible.status.code(), Some(0));
    let body: serde_json::Value =
        serde_json::from_slice(&compatible.stdout).expect("stdout 是 JSON");
    assert_eq!(
        body,
        serde_json::json!({"migrationCompatible":true,"findings":[]})
    );

    let usage = run(&["unknown"], None);
    assert_eq!(usage.status.code(), Some(64));
    assert!(usage.stdout.is_empty());
    assert_eq!(
        String::from_utf8(usage.stderr).unwrap().trim(),
        r#"{"code":"migration_preflight_usage"}"#
    );

    let import_usage = run(&["intelligence-import"], None);
    assert_eq!(import_usage.status.code(), Some(64));
    assert!(import_usage.stdout.is_empty());
    assert_eq!(
        String::from_utf8(import_usage.stderr).unwrap().trim(),
        r#"{"code":"intelligence_import_usage"}"#
    );

    let finalize_without_database = run(&["intelligence-validate-tool-run-fk"], None);
    assert_eq!(finalize_without_database.status.code(), Some(69));
    assert_eq!(
        String::from_utf8(finalize_without_database.stderr)
            .unwrap()
            .trim(),
        r#"{"code":"database_url_missing"}"#
    );

    let migrate_without_database = run(&["migrate-schema"], None);
    assert_eq!(migrate_without_database.status.code(), Some(69));
    assert!(migrate_without_database.stdout.is_empty());
    assert_eq!(
        String::from_utf8(migrate_without_database.stderr)
            .unwrap()
            .trim(),
        r#"{"code":"database_url_missing"}"#
    );

    let migrate_extra = run(&["migrate-schema", "extra"], None);
    assert_eq!(migrate_extra.status.code(), Some(64));
    assert!(migrate_extra.stdout.is_empty());
    assert_eq!(
        String::from_utf8(migrate_extra.stderr).unwrap().trim(),
        r#"{"code":"migration_preflight_usage"}"#
    );
}
