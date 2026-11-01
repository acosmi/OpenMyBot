#[path = "../src/testkit.rs"]
mod testkit;
use omb_store::migrate;
use std::collections::BTreeMap;
use testkit::{Fixture, Session, deadline};
async fn setup() -> (Fixture, Session) {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    (fixture, session)
}
const RECEIVER: &str = "INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,credential_envelope,status,created_at) VALUES('00000000-0000-0000-0000-000000000001','receiver','telegram','1','envelope','active',statement_timestamp())";
const HOST: &str = "INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,workspace_dir,granted_generation,status,created_at) VALUES('00000000-0000-0000-0000-000000000002','host','host','crabcode','host:crabcode','/test-workspace',1,'active',statement_timestamp())";
const EVENT: &str = "INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,disposition) VALUES($1,'event','telegram',$2,$3,statement_timestamp(),'rejected_malformed')";

// Independent catalog oracle from the frozen column/constraint inventory; not read from migration bytes.
const EXPECTED_CHECKS: &[(&str, &[&str])] = &[
    ("omb_migrations", &["octet_length(sha256)=32"]),
    (
        "control_tokens",
        &[
            "engine_pin ~ '^[0-9a-f]{40}$'",
            "octet_length(token_sha256)=32",
            "octet_length(pg_system_identifier)<=128",
            "revoke_reason IN ('daemon_stop','daemon_restart')",
        ],
    ),
    (
        "channel_bindings",
        &[
            "run_deadline_seconds BETWEEN 1 AND 86400",
            "binding_kind <> 'receiver' OR (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host' AND credential_envelope IS NOT NULL AND sender_key IS NULL AND chat_key IS NULL AND workspace_dir IS NULL AND thread_id IS NULL AND status <> 'pending')",
            "binding_kind <> 'sender' OR (channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host' AND (status <> 'pending' OR (pairing_code_hash IS NOT NULL AND pairing_expires_at IS NOT NULL AND workspace_dir IS NOT NULL AND thread_id IS NOT NULL AND granted_generation IS NOT NULL AND sender_key IS NULL)) AND (status NOT IN ('active','suspended') OR (sender_key IS NOT NULL AND chat_key IS NOT NULL AND workspace_dir IS NOT NULL AND thread_id IS NOT NULL AND granted_generation IS NOT NULL AND pairing_code_hash IS NULL)))",
            "binding_kind <> 'host' OR (channel_kind='host' AND source_key='crabcode' AND sender_key IS NOT NULL AND sender_key='host:crabcode' AND workspace_dir IS NOT NULL AND granted_generation IS NOT NULL AND status <> 'pending')",
            "octet_length(source_key)<=128",
            "octet_length(sender_key)<=128",
            "octet_length(chat_key)<=128",
            "octet_length(thread_id)<=128",
            "octet_length(pairing_code_hash)=32",
            "binding_kind IN ('receiver','sender','host')",
            "channel_kind ~ '^[a-z][a-z0-9_]{0,31}$'",
            "status IN ('pending','active','suspended','revoked','expired')",
            "status_reason IN ('superseded','pairing_expired','owner_revoked','receiver_replaced','restore_detected','credential_rejected','webhook_conflict','grant_stale')",
        ],
    ),
    (
        "channel_events",
        &[
            "(record_kind='gap')=(disposition='gap')",
            "record_kind <> 'gap' OR (gap_started_at IS NOT NULL AND gap_reason IS NOT NULL)",
            "disposition <> 'accepted_message' OR (text IS NOT NULL AND text_sha256 IS NOT NULL AND run_id IS NOT NULL AND thread_id IS NOT NULL AND binding_id IS NOT NULL AND dispatch_status IS NOT NULL)",
            "disposition NOT IN ('dropped_unbound','dropped_not_private') OR (fingerprint IS NULL AND text IS NULL AND sender_key IS NULL AND chat_key IS NULL)",
            "disposition NOT IN ('pairing_succeeded','pairing_failed','pairing_locked') OR (sender_key IS NOT NULL AND fingerprint IS NOT NULL)",
            "disposition='accepted_message' OR text IS NULL",
            "octet_length(source_key)<=128",
            "octet_length(event_key)<=128",
            "octet_length(fingerprint)=32",
            "octet_length(sender_key)<=128",
            "octet_length(chat_key)<=128",
            "octet_length(text_sha256)=32",
            "octet_length(run_id)<=128",
            "octet_length(thread_id)<=128",
            "record_kind IN ('event','gap')",
            "channel_kind ~ '^[a-z][a-z0-9_]{0,31}$'",
            "disposition IN ('accepted_message','control_command','pairing_succeeded','pairing_failed','pairing_locked','dropped_unbound','dropped_not_private','dropped_inactive','rejected_outside_window','rejected_too_long','rejected_unsupported','rejected_malformed','rejected_queue_full','gap')",
            "command IN ('help','start','status','cancel','pair','unknown')",
            "dispatch_status IN ('pending','dispatched','conflict','expired','cancelled')",
            "terminal_kind IN ('succeeded','failed','cancelled','reconciliation_required')",
            "gap_reason IN ('daemon_down','daemon_suspended','connect_failed','stream_broken','receiver_suspended','plugin_missing')",
        ],
    ),
    (
        "host_driver_sessions",
        &[
            "record_kind <> 'session' OR (host_kind IS NOT NULL AND started_at IS NOT NULL AND workspace_dir IS NOT NULL AND num_nonnulls(permission_id,native_request_id,tool_name,input_summary,input_sha256,requested_at,expires_at,decision,decided_via,decided_at,decided_by_token,answered_at)=0)",
            "record_kind <> 'permission' OR (permission_id IS NOT NULL AND tool_name IS NOT NULL AND requested_at IS NOT NULL AND expires_at IS NOT NULL AND num_nonnulls(host_kind,host_version,args_sha256,native_session_id,resumed_from,resumable,workspace_dir,child_pid,pgid,started_at,init_at,last_event_at,last_event_seq,output_bytes,ended_at,exit_code,exit_signal,end_reason,stop_outcome,stop_confirmed_at,result_summary,artifact_paths,stderr_tail)=0)",
            "octet_length(run_id)<=128",
            "octet_length(args_sha256)=32",
            "octet_length(native_session_id)<=128",
            "octet_length(resumed_from)<=128",
            "octet_length(permission_id)<=128",
            "octet_length(native_request_id)<=128",
            "octet_length(input_sha256)=32",
            "record_kind IN ('session','permission')",
            "host_kind IN ('crabcode')",
            "end_reason IN ('result_success','result_error','stop_requested','output_limit','line_limit','stalled','protocol_error','child_exited','spawn_failed','version_rejected','init_timeout','resume_failed')",
            "stop_outcome IN ('confirmed','unknown')",
            "decision IN ('allow','deny')",
            "decided_via IN ('readonly_rule','cli','timeout','run_stopped')",
        ],
    ),
    (
        "deliveries",
        &[
            "status NOT IN ('sent','failed','unknown') OR finished_at IS NOT NULL",
            "octet_length(chat_key)<=128",
            "octet_length(idempotency_key)<=128",
            "octet_length(platform_message_id)<=128",
            "channel_kind ~ '^[a-z][a-z0-9_]{0,31}$' AND channel_kind <> 'host'",
            "kind IN ('run_result','permission_notice','control_reply','pairing_reply','reject_reply','expiry_notice')",
            "status IN ('pending','sending','sent','failed','unknown')",
        ],
    ),
];
async fn rejected(client: &tokio_postgres::Client, sql: &str) {
    let error = client.batch_execute(sql).await.unwrap_err();
    assert!(
        matches!(
            error.code().map(|c| c.code()),
            Some("23514" | "23502" | "23505" | "23503")
        ),
        "expected integrity rejection, not SQL/setup error"
    );
}

async fn i5_rejected(client: &tokio_postgres::Client, sql: &str, kind: &str) {
    let error = client.batch_execute(sql).await.unwrap_err();
    assert_eq!(error.code().unwrap().code(), "23514");
    let constraint = if kind == "session" {
        "host_driver_sessions_check_1"
    } else {
        "host_driver_sessions_check_2"
    };
    assert_eq!(error.as_db_error().unwrap().constraint(), Some(constraint));
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn catalog_matches_six_tables_all_columns_types_nullability_and_defaults() {
    let (fixture, session) = setup().await;
    let mut expected = BTreeMap::new();
    expected.insert(
        ("omb_migrations".to_owned(), "version".to_owned()),
        ("integer".to_owned(), true, None),
    );
    expected.insert(
        ("omb_migrations".to_owned(), "name".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("omb_migrations".to_owned(), "sha256".to_owned()),
        ("bytea".to_owned(), true, None),
    );
    expected.insert(
        ("omb_migrations".to_owned(), "applied_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "token_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "token_sha256".to_owned()),
        ("bytea".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "daemon_pid".to_owned()),
        ("integer".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "engine_pin".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "omb_version".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        (
            "control_tokens".to_owned(),
            "pg_system_identifier".to_owned(),
        ),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "pg_timeline_id".to_owned()),
        ("integer".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "restore_detected".to_owned()),
        ("boolean".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "created_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "last_heartbeat_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "revoked_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("control_tokens".to_owned(), "revoke_reason".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "binding_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "binding_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "channel_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "source_key".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "sender_key".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "chat_key".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "credential_envelope".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "workspace_dir".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "thread_id".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "thread_generation".to_owned(),
        ),
        ("integer".to_owned(), true, Some("0".to_owned())),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "revision".to_owned()),
        ("bigint".to_owned(), true, Some("0".to_owned())),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "granted_generation".to_owned(),
        ),
        ("bigint".to_owned(), false, None),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "run_deadline_seconds".to_owned(),
        ),
        ("integer".to_owned(), false, None),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "pairing_code_hash".to_owned(),
        ),
        ("bytea".to_owned(), false, None),
    );
    expected.insert(
        (
            "channel_bindings".to_owned(),
            "pairing_expires_at".to_owned(),
        ),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "status".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "status_reason".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "created_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "activated_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "suspended_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "reconfirmed_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_bindings".to_owned(), "ended_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "record_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "record_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "channel_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "source_key".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "event_key".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "event_type".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "occurred_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "accepted_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "fingerprint".to_owned()),
        ("bytea".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "sender_key".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "chat_key".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "binding_id".to_owned()),
        ("uuid".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "disposition".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "command".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "text".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "text_sha256".to_owned()),
        ("bytea".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "run_id".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "thread_id".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "dispatch_status".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "dispatch_attempts".to_owned()),
        ("integer".to_owned(), true, Some("0".to_owned())),
    );
    expected.insert(
        ("channel_events".to_owned(), "next_dispatch_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "dispatched_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "terminal_kind".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "terminal_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "gap_started_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "gap_ended_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "gap_reason".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("channel_events".to_owned(), "content_cleared_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "record_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "record_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "run_id".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "binding_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "host_kind".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "host_version".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "args_sha256".to_owned()),
        ("bytea".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "native_session_id".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "resumed_from".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "resumable".to_owned()),
        ("boolean".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "workspace_dir".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "child_pid".to_owned()),
        ("integer".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "pgid".to_owned()),
        ("integer".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "started_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "init_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "last_event_at".to_owned(),
        ),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "last_event_seq".to_owned(),
        ),
        ("bigint".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "output_bytes".to_owned()),
        ("bigint".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "ended_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "exit_code".to_owned()),
        ("integer".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "exit_signal".to_owned()),
        ("integer".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "end_reason".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "stop_outcome".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "stop_confirmed_at".to_owned(),
        ),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "result_summary".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "artifact_paths".to_owned(),
        ),
        ("text[]".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "stderr_tail".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "content_cleared_at".to_owned(),
        ),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "permission_id".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "native_request_id".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "tool_name".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "input_summary".to_owned(),
        ),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "input_sha256".to_owned()),
        ("bytea".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "requested_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "expires_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "decision".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "decided_via".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "decided_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        (
            "host_driver_sessions".to_owned(),
            "decided_by_token".to_owned(),
        ),
        ("uuid".to_owned(), false, None),
    );
    expected.insert(
        ("host_driver_sessions".to_owned(), "answered_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "delivery_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "binding_id".to_owned()),
        ("uuid".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "channel_kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "chat_key".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "kind".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "idempotency_key".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "body".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "status".to_owned()),
        ("text".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "attempts".to_owned()),
        ("integer".to_owned(), true, Some("0".to_owned())),
    );
    expected.insert(
        ("deliveries".to_owned(), "next_attempt_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "first_attempt_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "last_error_code".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "platform_message_id".to_owned()),
        ("text".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "created_at".to_owned()),
        ("timestamp with time zone".to_owned(), true, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "finished_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    expected.insert(
        ("deliveries".to_owned(), "content_cleared_at".to_owned()),
        ("timestamp with time zone".to_owned(), false, None),
    );
    let rows=session.client.query("SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid) FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='openmybot' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped",&[]).await.unwrap();
    let actual: BTreeMap<(String, String), (String, bool, Option<String>)> = rows
        .iter()
        .map(|r| ((r.get(0), r.get(1)), (r.get(2), r.get(3), r.get(4))))
        .collect();
    assert_eq!(actual.len(), 122);
    assert_eq!(actual, expected);
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn catalog_matches_primary_foreign_unique_and_check_constraints() {
    let (fixture, session) = setup().await;
    let rows=session.client.query("SELECT contype::text,count(*)::bigint FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='openmybot' GROUP BY contype",&[]).await.unwrap();
    let counts: BTreeMap<String, i64> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(counts.get("p"), Some(&6));
    assert_eq!(counts.get("f"), Some(&4));
    assert!(counts["c"] >= 40);
    let foreign=session.client.query("SELECT src.relname,target.relname,dst.nspname,c.confdeltype::text,c.confupdtype::text FROM pg_constraint c JOIN pg_class src ON src.oid=c.conrelid JOIN pg_class target ON target.oid=c.confrelid JOIN pg_namespace dst ON dst.oid=target.relnamespace JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='openmybot' AND c.contype='f' ORDER BY src.relname,target.relname",&[]).await.unwrap();
    let pairs: Vec<(String, String)> = foreign
        .iter()
        .map(|r| {
            assert_eq!(r.get::<_, String>(2), "openmybot");
            assert_eq!(r.get::<_, String>(3), "a");
            assert_eq!(r.get::<_, String>(4), "a");
            (r.get(0), r.get(1))
        })
        .collect();
    assert_eq!(
        pairs,
        [
            ("channel_events".into(), "channel_bindings".into()),
            ("deliveries".into(), "channel_bindings".into()),
            ("host_driver_sessions".into(), "channel_bindings".into()),
            ("host_driver_sessions".into(), "control_tokens".into())
        ]
    );
    let foreign_columns=session.client.query("SELECT s.relname,a.attname,t.relname,b.attname FROM pg_constraint c JOIN pg_class s ON s.oid=c.conrelid JOIN pg_class t ON t.oid=c.confrelid JOIN pg_namespace n ON n.oid=c.connamespace JOIN pg_attribute a ON a.attrelid=s.oid AND a.attnum=ANY(c.conkey) JOIN pg_attribute b ON b.attrelid=t.oid AND b.attnum=ANY(c.confkey) WHERE n.nspname='openmybot' AND c.contype='f'",&[]).await.unwrap();
    let actual_fk: std::collections::BTreeSet<(String, String, String, String)> = foreign_columns
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    let expected_fk: std::collections::BTreeSet<(String, String, String, String)> = [
        (
            "channel_events",
            "binding_id",
            "channel_bindings",
            "binding_id",
        ),
        (
            "host_driver_sessions",
            "binding_id",
            "channel_bindings",
            "binding_id",
        ),
        (
            "host_driver_sessions",
            "decided_by_token",
            "control_tokens",
            "token_id",
        ),
        ("deliveries", "binding_id", "channel_bindings", "binding_id"),
    ]
    .into_iter()
    .map(|(a, b, c, d)| (a.into(), b.into(), c.into(), d.into()))
    .collect();
    assert_eq!(actual_fk, expected_fk);
    let indexes=session.client.query("SELECT c.relname,pg_get_expr(i.indpred,i.indrelid),i.indnkeyatts FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='openmybot' AND i.indisunique AND NOT i.indisprimary",&[]).await.unwrap();
    assert_eq!(indexes.len(), 9);
    assert_eq!(
        indexes
            .iter()
            .filter(|r| r.get::<_, Option<String>>(1).is_some())
            .count(),
        6
    );
    let primary=session.client.query("SELECT t.relname,a.attname FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=c.connamespace JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=ANY(c.conkey) WHERE n.nspname='openmybot' AND c.contype='p'",&[]).await.unwrap();
    let actual_primary: BTreeMap<String, String> =
        primary.iter().map(|r| (r.get(0), r.get(1))).collect();
    let expected_primary: BTreeMap<String, String> = [
        ("omb_migrations", "version"),
        ("control_tokens", "token_id"),
        ("channel_bindings", "binding_id"),
        ("channel_events", "record_id"),
        ("host_driver_sessions", "record_id"),
        ("deliveries", "delivery_id"),
    ]
    .into_iter()
    .map(|(a, b)| (a.into(), b.into()))
    .collect();
    assert_eq!(actual_primary, expected_primary);
    let unique=session.client.query("SELECT c.relname,(SELECT string_agg(pg_get_indexdef(i.indexrelid,k,true),',' ORDER BY k) FROM generate_series(1,i.indnkeyatts) k),pg_get_expr(i.indpred,i.indrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='openmybot' AND i.indisunique AND NOT i.indisprimary",&[]).await.unwrap();
    let normalize = |text: String| text.replace("::text", "").replace([' ', '(', ')'], "");
    let actual: BTreeMap<(String, String), Option<String>> = unique
        .iter()
        .map(|r| {
            (
                (r.get(0), normalize(r.get(1))),
                r.get::<_, Option<String>>(2).map(&normalize),
            )
        })
        .collect();
    let expected: BTreeMap<(String, String), Option<String>> = [
        ("control_tokens", "token_sha256", None),
        ("control_tokens", "1", Some("revoked_atISNULL")),
        (
            "channel_bindings",
            "binding_kind,channel_kind",
            Some("status=ANYARRAY['pending','active','suspended']"),
        ),
        ("channel_events", "channel_kind,source_key,event_key", None),
        ("channel_events", "run_id", Some("run_idISNOTNULL")),
        (
            "host_driver_sessions",
            "run_id",
            Some("record_kind='session'"),
        ),
        (
            "host_driver_sessions",
            "permission_id",
            Some("record_kind='permission'"),
        ),
        (
            "host_driver_sessions",
            "run_id,native_request_id",
            Some("record_kind='permission'"),
        ),
        ("deliveries", "idempotency_key", None),
    ]
    .into_iter()
    .map(|(t, c, p)| ((t.into(), c.into()), p.map(str::to_owned)))
    .collect();
    assert_eq!(actual, expected);
    for (table, checks) in EXPECTED_CHECKS {
        session
            .client
            .batch_execute(&format!(
                "CREATE TEMP TABLE expected_shape (LIKE openmybot.{table})"
            ))
            .await
            .unwrap();
        for expression in *checks {
            session
                .client
                .batch_execute(&format!(
                    "ALTER TABLE pg_temp.expected_shape ADD CHECK ({expression})"
                ))
                .await
                .unwrap();
        }
        let observed:Vec<String>=session.client.query("SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid=('openmybot.'||$1)::regclass AND contype='c' ORDER BY pg_get_expr(conbin,conrelid)",&[table]).await.unwrap().iter().map(|r|r.get(0)).collect();
        let oracle:Vec<String>=session.client.query("SELECT pg_get_expr(conbin,conrelid) FROM pg_constraint WHERE conrelid='pg_temp.expected_shape'::regclass AND contype='c' ORDER BY pg_get_expr(conbin,conrelid)",&[]).await.unwrap().iter().map(|r|r.get(0)).collect();
        assert_eq!(observed, oracle, "CHECK set changed for {table}");
        session
            .client
            .batch_execute("DROP TABLE pg_temp.expected_shape")
            .await
            .unwrap();
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn b32_text_byte_lengths_and_closed_enums_are_enforced() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(RECEIVER).await.unwrap();
    for sql in [
        "UPDATE openmybot.channel_bindings SET pairing_code_hash=decode('00','hex')",
        "UPDATE openmybot.channel_bindings SET source_key=repeat('界',43)",
        "UPDATE openmybot.channel_bindings SET binding_kind='other'",
        "UPDATE openmybot.channel_bindings SET channel_kind='Other'",
        "UPDATE openmybot.channel_bindings SET channel_kind='1x'",
        "UPDATE openmybot.channel_bindings SET channel_kind='host'",
        "UPDATE openmybot.channel_bindings SET status='other'",
        "UPDATE openmybot.channel_bindings SET status_reason='other'",
        "UPDATE openmybot.channel_bindings SET run_deadline_seconds=0",
        "UPDATE openmybot.channel_bindings SET run_deadline_seconds=86401",
    ] {
        rejected(&session.client, sql).await;
    }
    session.client.batch_execute("UPDATE openmybot.channel_bindings SET source_key=repeat('x',128),pairing_code_hash=decode(repeat('ab',32),'hex'),run_deadline_seconds=86400").await.unwrap();
    let enum_fields = [
        ("channel_events", "record_kind"),
        ("channel_events", "disposition"),
        ("channel_events", "command"),
        ("channel_events", "dispatch_status"),
        ("channel_events", "terminal_kind"),
        ("channel_events", "gap_reason"),
    ];
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"x", &"event"])
        .await
        .unwrap();
    for (table, column) in enum_fields {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.{table} SET {column}='other'"),
        )
        .await;
    }
    for kind in ["Other", "1x"] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_events SET channel_kind='{kind}'"),
        )
        .await;
    }
    session.client.batch_execute(HOST).await.unwrap();
    session.client.batch_execute("INSERT INTO openmybot.control_tokens(token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier,pg_timeline_id,restore_detected,created_at,last_heartbeat_at) VALUES('00000000-0000-0000-0000-000000000099',decode(repeat('99',32),'hex'),1,repeat('a',40),'fixture','system',1,false,statement_timestamp(),statement_timestamp()); INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at) VALUES('00000000-0000-0000-0000-000000000098','session','session','00000000-0000-0000-0000-000000000002','crabcode','/fixture',statement_timestamp()); INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,tool_name,requested_at,expires_at) VALUES('00000000-0000-0000-0000-000000000097','permission','permission','00000000-0000-0000-0000-000000000002','p','Read',statement_timestamp(),statement_timestamp())").await.unwrap();
    for (table, column, condition) in [
        ("omb_migrations", "sha256", "true"),
        ("control_tokens", "token_sha256", "true"),
        (
            "host_driver_sessions",
            "args_sha256",
            "record_kind='session'",
        ),
        (
            "host_driver_sessions",
            "input_sha256",
            "record_kind='permission'",
        ),
        ("channel_events", "fingerprint", "true"),
        ("channel_events", "text_sha256", "true"),
    ] {
        for count in [0, 31, 33] {
            rejected(&session.client,&format!("UPDATE openmybot.{table} SET {column}=decode(repeat('ab',{count}),'hex') WHERE {condition}")).await;
        }
        session.client.batch_execute(&format!("UPDATE openmybot.{table} SET {column}=decode(repeat('ab',32),'hex') WHERE {condition}")).await.unwrap();
    }
    for invalid in [
        "repeat('a',39)",
        "repeat('A',40)",
        "repeat('a',41)",
        "repeat('g',40)",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.control_tokens SET engine_pin={invalid}"),
        )
        .await;
    }
    rejected(
        &session.client,
        "UPDATE openmybot.control_tokens SET revoke_reason='other'",
    )
    .await;
    for reason in ["daemon_stop", "daemon_restart"] {
        session
            .client
            .batch_execute(&format!(
                "UPDATE openmybot.control_tokens SET revoke_reason='{reason}'"
            ))
            .await
            .unwrap();
    }
    for (column, kind) in [
        ("record_kind", "session"),
        ("host_kind", "session"),
        ("end_reason", "session"),
        ("stop_outcome", "session"),
        ("decision", "permission"),
        ("decided_via", "permission"),
    ] {
        rejected(&session.client,&format!("UPDATE openmybot.host_driver_sessions SET {column}='other' WHERE record_kind='{kind}'")).await;
    }
    for reason in [
        "result_success",
        "result_error",
        "stop_requested",
        "output_limit",
        "line_limit",
        "stalled",
        "protocol_error",
        "child_exited",
        "spawn_failed",
        "version_rejected",
        "init_timeout",
        "resume_failed",
    ] {
        session.client.batch_execute(&format!("UPDATE openmybot.host_driver_sessions SET end_reason='{reason}' WHERE record_kind='session'")).await.unwrap();
    }
    for outcome in ["confirmed", "unknown"] {
        session.client.batch_execute(&format!("UPDATE openmybot.host_driver_sessions SET stop_outcome='{outcome}' WHERE record_kind='session'")).await.unwrap();
    }
    for decision in ["allow", "deny"] {
        session.client.batch_execute(&format!("UPDATE openmybot.host_driver_sessions SET decision='{decision}' WHERE record_kind='permission'")).await.unwrap();
    }
    for via in ["readonly_rule", "cli", "timeout", "run_stopped"] {
        session.client.batch_execute(&format!("UPDATE openmybot.host_driver_sessions SET decided_via='{via}' WHERE record_kind='permission'")).await.unwrap();
    }
    for (table, column, condition) in [
        ("control_tokens", "pg_system_identifier", "true"),
        ("host_driver_sessions", "run_id", "record_kind='session'"),
        (
            "host_driver_sessions",
            "native_session_id",
            "record_kind='session'",
        ),
        (
            "host_driver_sessions",
            "resumed_from",
            "record_kind='session'",
        ),
        (
            "host_driver_sessions",
            "permission_id",
            "record_kind='permission'",
        ),
        (
            "host_driver_sessions",
            "native_request_id",
            "record_kind='permission'",
        ),
        ("channel_events", "source_key", "true"),
        ("channel_events", "event_key", "true"),
        ("channel_events", "sender_key", "true"),
        ("channel_events", "chat_key", "true"),
        ("channel_events", "run_id", "true"),
        ("channel_events", "thread_id", "true"),
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.{table} SET {column}=repeat('界',43) WHERE {condition}"),
        )
        .await;
        session
            .client
            .batch_execute(&format!(
                "UPDATE openmybot.{table} SET {column}=repeat('x',128) WHERE {condition}"
            ))
            .await
            .unwrap();
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn binding_i1_i2_i3_accept_and_reject_each_shape() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(RECEIVER).await.unwrap();
    for change in [
        "channel_kind='host'",
        "credential_envelope=NULL",
        "sender_key='x'",
        "chat_key='x'",
        "workspace_dir='x'",
        "thread_id='x'",
        "status='pending'",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_bindings SET {change}"),
        )
        .await;
    }
    session.client.batch_execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,credential_envelope,status,created_at) VALUES('00000000-0000-0000-0000-000000000004','receiver','slack','1','envelope','active',statement_timestamp())").await.unwrap();
    session.client.batch_execute(HOST).await.unwrap();
    for change in [
        "channel_kind='telegram'",
        "source_key='crabcode-other'",
        "sender_key=NULL",
        "sender_key='other'",
        "workspace_dir=NULL",
        "granted_generation=NULL",
        "status='pending'",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_bindings SET {change} WHERE binding_kind='host'"),
        )
        .await;
    }
    session.client.batch_execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,pairing_code_hash,pairing_expires_at,workspace_dir,thread_id,granted_generation,status,created_at) VALUES('00000000-0000-0000-0000-000000000003','sender','telegram','1',decode(repeat('aa',32),'hex'),statement_timestamp(),'/workspace','thread',1,'pending',statement_timestamp())").await.unwrap();
    for change in [
        "pairing_code_hash=NULL",
        "pairing_expires_at=NULL",
        "workspace_dir=NULL",
        "thread_id=NULL",
        "granted_generation=NULL",
        "sender_key='x'",
        "channel_kind='host'",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_bindings SET {change} WHERE binding_kind='sender'"),
        )
        .await;
    }
    session.client.batch_execute("UPDATE openmybot.channel_bindings SET status='active',sender_key='s',chat_key='c',pairing_code_hash=NULL WHERE binding_kind='sender'").await.unwrap();
    for change in [
        "sender_key=NULL",
        "chat_key=NULL",
        "workspace_dir=NULL",
        "thread_id=NULL",
        "granted_generation=NULL",
        "pairing_code_hash=decode(repeat('aa',32),'hex')",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_bindings SET {change} WHERE binding_kind='sender'"),
        )
        .await;
    }
    session
        .client
        .batch_execute(
            "UPDATE openmybot.channel_bindings SET status='suspended' WHERE binding_kind='sender'",
        )
        .await
        .unwrap();
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn event_i4_accept_and_reject_each_disposition_shape() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(RECEIVER).await.unwrap();
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"x", &"e"])
        .await
        .unwrap();
    rejected(
        &session.client,
        "UPDATE openmybot.channel_events SET record_kind='gap'",
    )
    .await;
    rejected(
        &session.client,
        "UPDATE openmybot.channel_events SET disposition='gap'",
    )
    .await;
    session.client.batch_execute("UPDATE openmybot.channel_events SET record_kind='gap',disposition='gap',gap_started_at=statement_timestamp(),gap_reason='daemon_down'").await.unwrap();
    for change in [
        "gap_started_at=NULL",
        "gap_reason=NULL",
        "record_kind='event'",
        "text='payload'",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_events SET {change}"),
        )
        .await;
    }
    session.client.batch_execute("UPDATE openmybot.channel_events SET record_kind='event',disposition='accepted_message',text='payload',text_sha256=decode(repeat('bb',32),'hex'),run_id='run',thread_id='thread',binding_id='00000000-0000-0000-0000-000000000001',dispatch_status='pending'").await.unwrap();
    for field in [
        "text",
        "text_sha256",
        "run_id",
        "thread_id",
        "binding_id",
        "dispatch_status",
    ] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.channel_events SET {field}=NULL"),
        )
        .await;
    }
    for disposition in ["dropped_unbound", "dropped_not_private"] {
        session.client.batch_execute(&format!("UPDATE openmybot.channel_events SET disposition='{disposition}',text=NULL,fingerprint=NULL,sender_key=NULL,chat_key=NULL")).await.unwrap();
        for change in [
            "text='x'",
            "fingerprint=decode(repeat('aa',32),'hex')",
            "sender_key='x'",
            "chat_key='x'",
        ] {
            rejected(
                &session.client,
                &format!("UPDATE openmybot.channel_events SET {change}"),
            )
            .await;
        }
    }
    for disposition in ["pairing_succeeded", "pairing_failed", "pairing_locked"] {
        session.client.batch_execute(&format!("UPDATE openmybot.channel_events SET disposition='{disposition}',fingerprint=decode(repeat('aa',32),'hex'),sender_key='s'")).await.unwrap();
        rejected(
            &session.client,
            "UPDATE openmybot.channel_events SET fingerprint=NULL",
        )
        .await;
        rejected(
            &session.client,
            "UPDATE openmybot.channel_events SET sender_key=NULL",
        )
        .await;
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn session_permission_i5_common_clear_time_preserves_payload_isolation() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(HOST).await.unwrap();
    session.client.batch_execute("INSERT INTO openmybot.control_tokens(token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier,pg_timeline_id,restore_detected,created_at,last_heartbeat_at) VALUES('00000000-0000-0000-0000-000000000099',decode(repeat('99',32),'hex'),1,repeat('a',40),'fixture','fixture',1,false,statement_timestamp(),statement_timestamp())").await.unwrap();
    let binding = "00000000-0000-0000-0000-000000000002";
    for (index, clear) in ["NULL", "statement_timestamp()"].into_iter().enumerate() {
        let id = uuid::Uuid::now_v7();
        session.client.batch_execute(&format!("INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,started_at,workspace_dir,content_cleared_at) VALUES('{id}','session','session-{index}','{binding}','crabcode',statement_timestamp(),'/workspace',{clear})")).await.unwrap();
        let id = uuid::Uuid::now_v7();
        session.client.batch_execute(&format!("INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,tool_name,requested_at,expires_at,input_summary,content_cleared_at) VALUES('{id}','permission','permission-{index}','{binding}','permission-{index}','Read',statement_timestamp(),statement_timestamp(),NULL,{clear})")).await.unwrap();
    }
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET host_kind='crabcode' WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET host_version='x' WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET args_sha256=decode(repeat('aa',32),'hex') WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET native_session_id='x' WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET resumed_from='x' WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET resumable=true WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET workspace_dir='x' WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET child_pid=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET pgid=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET started_at=statement_timestamp() WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET init_at=statement_timestamp() WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET last_event_at=statement_timestamp() WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET last_event_seq=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET output_bytes=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET ended_at=statement_timestamp() WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET exit_code=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET exit_signal=1 WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET end_reason='result_success' WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET stop_outcome='confirmed' WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET stop_confirmed_at=statement_timestamp() WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET result_summary='x' WHERE record_kind='permission'","permission").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET artifact_paths=ARRAY['artifact'] WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET stderr_tail='x' WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET permission_id='x' WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET native_request_id='x' WHERE record_kind='session'","session").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET tool_name='x' WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET input_summary='x' WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET input_sha256=decode(repeat('ab',32),'hex') WHERE record_kind='session'","session").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET requested_at=statement_timestamp() WHERE record_kind='session'","session").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET expires_at=statement_timestamp() WHERE record_kind='session'","session").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET decision='allow' WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET decided_via='cli' WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET decided_at=statement_timestamp() WHERE record_kind='session'","session").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET decided_by_token='00000000-0000-0000-0000-000000000099' WHERE record_kind='session'","session").await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET answered_at=statement_timestamp() WHERE record_kind='session'","session").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET host_kind=NULL WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET started_at=NULL WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET workspace_dir=NULL WHERE record_kind='session'",
        "session",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET permission_id=NULL WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET tool_name=NULL WHERE record_kind='permission'",
        "permission",
    )
    .await;
    i5_rejected(&session.client,"UPDATE openmybot.host_driver_sessions SET requested_at=NULL WHERE record_kind='permission'","permission").await;
    i5_rejected(
        &session.client,
        "UPDATE openmybot.host_driver_sessions SET expires_at=NULL WHERE record_kind='permission'",
        "permission",
    )
    .await;
    session.client.batch_execute("UPDATE openmybot.host_driver_sessions SET input_summary=NULL,content_cleared_at=statement_timestamp() WHERE record_kind='permission'; UPDATE openmybot.host_driver_sessions SET result_summary=NULL,stderr_tail=NULL,content_cleared_at=statement_timestamp() WHERE record_kind='session'").await.unwrap();
    assert_eq!(session.client.query_one("SELECT count(*)::bigint FROM openmybot.host_driver_sessions WHERE content_cleared_at IS NOT NULL",&[]).await.unwrap().get::<_,i64>(0),4);
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn delivery_i6_terminal_rows_require_finished_at() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(RECEIVER).await.unwrap();
    session.client.batch_execute("INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,status,created_at) VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','telegram','c','control_reply','key','pending',statement_timestamp())").await.unwrap();
    for status in ["sent", "failed", "unknown"] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.deliveries SET status='{status}',finished_at=NULL"),
        )
        .await;
        session.client.batch_execute(&format!("UPDATE openmybot.deliveries SET status='{status}',finished_at=statement_timestamp()")).await.unwrap();
    }
    for field in ["kind", "status"] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.deliveries SET {field}='other'"),
        )
        .await;
    }
    for kind in ["Other", "1x", "host"] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.deliveries SET channel_kind='{kind}'"),
        )
        .await;
    }
    for column in ["chat_key", "idempotency_key", "platform_message_id"] {
        rejected(
            &session.client,
            &format!("UPDATE openmybot.deliveries SET {column}=repeat('界',43)"),
        )
        .await;
        session
            .client
            .batch_execute(&format!(
                "UPDATE openmybot.deliveries SET {column}=repeat('x',128)"
            ))
            .await
            .unwrap();
    }
    for kind in [
        "run_result",
        "permission_notice",
        "control_reply",
        "pairing_reply",
        "reject_reply",
        "expiry_notice",
    ] {
        session
            .client
            .batch_execute(&format!("UPDATE openmybot.deliveries SET kind='{kind}'"))
            .await
            .unwrap();
    }
    for channel in ["telegram", "feishu"] {
        session
            .client
            .batch_execute(&format!(
                "UPDATE openmybot.deliveries SET channel_kind='{channel}'"
            ))
            .await
            .unwrap();
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn partial_uniques_hold_for_live_bindings_sessions_permissions_and_runs() {
    let (fixture, session) = setup().await;
    session.client.batch_execute(RECEIVER).await.unwrap();
    rejected(
        &session.client,
        &RECEIVER.replace("000000000001", "000000000011"),
    )
    .await;
    session
        .client
        .batch_execute("UPDATE openmybot.channel_bindings SET status='revoked'")
        .await
        .unwrap();
    session
        .client
        .batch_execute(&RECEIVER.replace("000000000001", "000000000011"))
        .await
        .unwrap();
    session.client.batch_execute(HOST).await.unwrap();
    let base = "INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at) VALUES('00000000-0000-0000-0000-000000000010','session','run','00000000-0000-0000-0000-000000000002','crabcode','/workspace',statement_timestamp())";
    session.client.batch_execute(base).await.unwrap();
    rejected(
        &session.client,
        &base.replace("000000000010", "000000000012"),
    )
    .await;
    let permission = "INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,native_request_id,tool_name,requested_at,expires_at) VALUES('00000000-0000-0000-0000-000000000013','permission','run','00000000-0000-0000-0000-000000000002','p','request','Read',statement_timestamp(),statement_timestamp())";
    session.client.batch_execute(permission).await.unwrap();
    rejected(
        &session.client,
        &permission
            .replace("000000000013", "000000000015")
            .replace("'request'", "'request-other'"),
    )
    .await;
    rejected(
        &session.client,
        &permission.replace("000000000013", "000000000014"),
    )
    .await;
    rejected(
        &session.client,
        &permission
            .replace("000000000013", "000000000014")
            .replace("'p'", "'p2'"),
    )
    .await;
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"s", &"e1"])
        .await
        .unwrap();
    session
        .client
        .batch_execute("UPDATE openmybot.channel_events SET run_id='same'")
        .await
        .unwrap();
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"s", &"e2"])
        .await
        .unwrap();
    rejected(
        &session.client,
        "UPDATE openmybot.channel_events SET run_id='same'",
    )
    .await;
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn t01_event_dedup_key_blocks_reinsert_and_allows_distinct_identity() {
    let (fixture, session) = setup().await;
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"source", &"event"])
        .await
        .unwrap();
    let result = session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"source", &"event"])
        .await
        .unwrap_err();
    assert_eq!(result.code().unwrap().code(), "23505");
    session
        .client
        .batch_execute(
            "UPDATE openmybot.channel_events SET fingerprint=decode(repeat('aa',32),'hex')",
        )
        .await
        .unwrap();
    let different = session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"source", &"event"])
        .await
        .unwrap_err();
    assert_eq!(different.code().unwrap().code(), "23505");
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"source2", &"event"])
        .await
        .unwrap();
    session
        .client
        .execute(EVENT, &[&uuid::Uuid::now_v7(), &"source", &"event2"])
        .await
        .unwrap();
    assert_eq!(
        session
            .client
            .query_one("SELECT count(*)::bigint FROM openmybot.channel_events", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; ten fresh clusters; serial"]
async fn t01_concurrent_duplicate_event_inserts_leave_one_row() {
    for _ in 0..10 {
        let (mut fixture, a) = setup().await;
        let b = fixture.connect().await;
        let x = uuid::Uuid::now_v7();
        let y = uuid::Uuid::now_v7();
        let left: [&(dyn tokio_postgres::types::ToSql + Sync); 3] = [&x, &"s", &"e"];
        let right: [&(dyn tokio_postgres::types::ToSql + Sync); 3] = [&y, &"s", &"e"];
        let (l, r) = tokio::join!(
            a.client.execute(EVENT, &left),
            b.client.execute(EVENT, &right)
        );
        assert_eq!(usize::from(l.is_ok()) + usize::from(r.is_ok()), 1);
        let rejected = l.err().or(r.err()).unwrap();
        assert_eq!(rejected.code().unwrap().code(), "23505");
        assert_eq!(
            a.client
                .query_one("SELECT count(*)::bigint FROM openmybot.channel_events", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        a.close().await;
        b.close().await;
        fixture.stop().await;
    }
}
