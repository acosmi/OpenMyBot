//! Host driver session and permission rows, and the run lookup the host driver starts from.
use crate::{GrantKind, READ_BUDGET, StoreError, rows};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

/// UTF-8 bytes kept of a result text.
const SUMMARY_MAX: usize = 2048;
/// UTF-8 bytes kept of the end of the child's standard error.
const TAIL_MAX: usize = 2048;
const ERROR: StoreError = StoreError::HostSessionFailed;

/// The run a host driver start serves: the binding's earliest open run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunTarget {
    pub binding_id: Uuid,
    pub kind: GrantKind,
    pub run_id: String,
    pub thread_id: String,
    pub workspace_dir: String,
    pub chat_key: Option<String>,
    pub resume: Option<ResumeSession>,
}
/// The session a sender run continues: the latest resumable success in the same thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumeSession {
    pub record_id: Uuid,
    pub native_session_id: String,
}
/// Resolves the binding's earliest event with a run that is pending or dispatched and has no
/// terminal, and for a sender binding the session it resumes.
pub async fn resolve_run(
    client: &Client,
    binding_id: Uuid,
) -> Result<Option<RunTarget>, StoreError> {
    let found = rows(client, "SELECT b.binding_kind='host',e.run_id,e.thread_id,b.workspace_dir,b.chat_key,s.record_id,s.native_session_id FROM openmybot.channel_bindings b JOIN LATERAL (SELECT run_id,thread_id FROM openmybot.channel_events WHERE binding_id=b.binding_id AND run_id IS NOT NULL AND dispatch_status IN ('pending','dispatched') AND terminal_kind IS NULL ORDER BY accepted_at,record_id LIMIT 1) e ON true LEFT JOIN LATERAL (SELECT h.record_id,h.native_session_id FROM openmybot.host_driver_sessions h JOIN openmybot.channel_events r ON r.run_id=h.run_id WHERE b.binding_kind='sender' AND h.record_kind='session' AND h.binding_id=b.binding_id AND h.end_reason='result_success' AND h.resumable AND h.native_session_id IS NOT NULL AND r.thread_id=e.thread_id ORDER BY h.ended_at DESC,h.record_id DESC LIMIT 1) s ON true WHERE b.binding_id=$1 AND b.status='active' AND b.binding_kind IN ('sender','host')", &[&binding_id], Instant::now() + READ_BUDGET, ERROR).await?;
    let Some(row) = found.first() else {
        return Ok(None);
    };
    let record: Option<Uuid> = row.try_get(5).map_err(|_| ERROR)?;
    let native: Option<String> = row.try_get(6).map_err(|_| ERROR)?;
    Ok(Some(RunTarget {
        binding_id,
        kind: if row.try_get::<_, bool>(0).map_err(|_| ERROR)? {
            GrantKind::Host
        } else {
            GrantKind::Sender
        },
        run_id: row.try_get(1).map_err(|_| ERROR)?,
        thread_id: row.try_get(2).map_err(|_| ERROR)?,
        workspace_dir: row.try_get(3).map_err(|_| ERROR)?,
        chat_key: row.try_get(4).map_err(|_| ERROR)?,
        resume: record
            .zip(native)
            .map(|(record_id, native_session_id)| ResumeSession {
                record_id,
                native_session_id,
            }),
    }))
}

pub struct SessionStart<'a> {
    pub run_id: &'a str,
    pub binding_id: Uuid,
    pub workspace_dir: &'a str,
}
/// Writes the run's session row before any child exists; a repeated start of the same run
/// resets the start fields and the end columns of that one row.
pub async fn upsert_session(
    client: &Client,
    input: SessionStart<'_>,
    deadline: Instant,
) -> Result<Uuid, StoreError> {
    let written = rows(client, "INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at) VALUES ($1,'session',$2,$3,'crabcode',$4,statement_timestamp()) ON CONFLICT (run_id) WHERE record_kind='session' DO UPDATE SET binding_id=EXCLUDED.binding_id,workspace_dir=EXCLUDED.workspace_dir,started_at=EXCLUDED.started_at,host_version=NULL,args_sha256=NULL,native_session_id=NULL,resumed_from=NULL,resumable=NULL,child_pid=NULL,pgid=NULL,init_at=NULL,last_event_at=NULL,last_event_seq=NULL,output_bytes=NULL,ended_at=NULL,exit_code=NULL,exit_signal=NULL,end_reason=NULL,stop_outcome=NULL,stop_confirmed_at=NULL,result_summary=NULL,artifact_paths=NULL,stderr_tail=NULL RETURNING record_id", &[&Uuid::now_v7(), &input.run_id, &input.binding_id, &input.workspace_dir], deadline, ERROR).await?;
    written.first().ok_or(ERROR)?.try_get(0).map_err(|_| ERROR)
}
/// One changed session row, or the store error.
async fn update(
    client: &Client,
    sql: &str,
    parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    deadline: Instant,
) -> Result<(), StoreError> {
    match rows(client, sql, parameters, deadline, ERROR).await?.len() {
        1 => Ok(()),
        _ => Err(ERROR),
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn session_spawned(
    client: &Client,
    record: Uuid,
    host_version: &str,
    args_sha256: [u8; 32],
    resumed_from: Option<&str>,
    child_pid: i32,
    pgid: i32,
    deadline: Instant,
) -> Result<(), StoreError> {
    update(client, "UPDATE openmybot.host_driver_sessions SET host_version=$2,args_sha256=$3,resumed_from=$4,child_pid=$5,pgid=$6 WHERE record_id=$1 AND record_kind='session' RETURNING record_id", &[&record, &host_version, &args_sha256.as_slice(), &resumed_from, &child_pid, &pgid], deadline).await
}
pub async fn session_init(
    client: &Client,
    record: Uuid,
    native_session_id: &str,
    deadline: Instant,
) -> Result<(), StoreError> {
    update(client, "UPDATE openmybot.host_driver_sessions SET native_session_id=$2,init_at=statement_timestamp() WHERE record_id=$1 AND record_kind='session' RETURNING record_id", &[&record, &native_session_id], deadline).await
}
pub async fn session_progress(
    client: &Client,
    record: Uuid,
    last_event_seq: u64,
    output_bytes: u64,
    deadline: Instant,
) -> Result<(), StoreError> {
    let seq = i64::try_from(last_event_seq).map_err(|_| ERROR)?;
    let bytes = i64::try_from(output_bytes).map_err(|_| ERROR)?;
    update(client, "UPDATE openmybot.host_driver_sessions SET last_event_seq=$2,output_bytes=$3,last_event_at=statement_timestamp() WHERE record_id=$1 AND record_kind='session' RETURNING record_id", &[&record, &seq, &bytes], deadline).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    ResultSuccess,
    ResultError,
    StopRequested,
    OutputLimit,
    LineLimit,
    Stalled,
    ProtocolError,
    ChildExited,
    SpawnFailed,
    VersionRejected,
    InitTimeout,
    ResumeFailed,
}
impl EndReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ResultSuccess => "result_success",
            Self::ResultError => "result_error",
            Self::StopRequested => "stop_requested",
            Self::OutputLimit => "output_limit",
            Self::LineLimit => "line_limit",
            Self::Stalled => "stalled",
            Self::ProtocolError => "protocol_error",
            Self::ChildExited => "child_exited",
            Self::SpawnFailed => "spawn_failed",
            Self::VersionRejected => "version_rejected",
            Self::InitTimeout => "init_timeout",
            Self::ResumeFailed => "resume_failed",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopRecord {
    Confirmed { at: OffsetDateTime },
    Unknown,
}
pub struct SessionEnd<'a> {
    pub reason: EndReason,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub stop: Option<StopRecord>,
    /// Truncated to its first 2048 bytes on a UTF-8 boundary.
    pub result_summary: Option<&'a str>,
    pub artifact_paths: &'a [String],
    /// Truncated to its last 2048 bytes on a UTF-8 boundary.
    pub stderr_tail: &'a str,
}
/// Writes the end columns; only a successful result makes the session resumable.
pub async fn end_session(
    client: &Client,
    record: Uuid,
    end: SessionEnd<'_>,
    deadline: Instant,
) -> Result<(), StoreError> {
    let (outcome, confirmed_at) = match end.stop {
        Some(StopRecord::Confirmed { at }) => (Some("confirmed"), Some(at)),
        Some(StopRecord::Unknown) => (Some("unknown"), None),
        None => (None, None),
    };
    let resumable = (end.reason == EndReason::ResultSuccess).then_some(true);
    let summary = end.result_summary.map(|text| {
        let mut cut = text.len().min(SUMMARY_MAX);
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    });
    let mut start = end.stderr_tail.len().saturating_sub(TAIL_MAX);
    while !end.stderr_tail.is_char_boundary(start) {
        start += 1;
    }
    let stderr_tail = &end.stderr_tail[start..];
    update(client, "UPDATE openmybot.host_driver_sessions SET ended_at=statement_timestamp(),end_reason=$2,exit_code=$3,exit_signal=$4,stop_outcome=$5,stop_confirmed_at=$6,result_summary=$7,artifact_paths=$8,stderr_tail=$9,resumable=$10 WHERE record_id=$1 AND record_kind='session' RETURNING record_id", &[&record, &end.reason.as_str(), &end.exit_code, &end.exit_signal, &outcome, &confirmed_at, &summary, &end.artifact_paths, &stderr_tail, &resumable], deadline).await
}
/// The resumed session failed to continue and is not offered again.
pub async fn clear_resumable(
    client: &Client,
    record: Uuid,
    deadline: Instant,
) -> Result<(), StoreError> {
    update(client, "UPDATE openmybot.host_driver_sessions SET resumable=false WHERE record_id=$1 AND record_kind='session' RETURNING record_id", &[&record], deadline).await
}

pub struct PermissionNew<'a> {
    pub run_id: &'a str,
    pub binding_id: Uuid,
    pub permission_id: &'a str,
    pub native_request_id: &'a str,
    pub tool_name: &'a str,
    pub input_summary: &'a str,
    pub input_sha256: [u8; 32],
    pub ttl: Duration,
    /// The filled notice text; only a sender binding's run passes one.
    pub notice: Option<&'a str>,
}
/// Writes an undecided permission row and, in the same statement, its notice delivery on the
/// sender binding's chat; returns when the request expires.
pub async fn insert_permission(
    client: &Client,
    input: PermissionNew<'_>,
    deadline: Instant,
) -> Result<OffsetDateTime, StoreError> {
    let written = rows(client, "WITH p AS (INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,native_request_id,tool_name,input_summary,input_sha256,requested_at,expires_at) VALUES ($1,'permission',$2,$3,$4,$5,$6,$7,$8,statement_timestamp(),statement_timestamp()+make_interval(secs=>$9)) RETURNING binding_id,expires_at), d AS (INSERT INTO openmybot.deliveries(delivery_id,binding_id,channel_kind,chat_key,kind,idempotency_key,body,status,created_at) SELECT $10,b.binding_id,b.channel_kind,b.chat_key,'permission_notice','perm:'||$4,replace($11,'{expires}',to_char(p.expires_at,'YYYY-MM-DD HH24:MI TZ')),'pending',statement_timestamp() FROM p JOIN openmybot.channel_bindings b ON b.binding_id=p.binding_id WHERE $11::text IS NOT NULL ON CONFLICT (idempotency_key) DO NOTHING RETURNING delivery_id) SELECT expires_at FROM p", &[&Uuid::now_v7(), &input.run_id, &input.binding_id, &input.permission_id, &input.native_request_id, &input.tool_name, &input.input_summary, &input.input_sha256.as_slice(), &input.ttl.as_secs_f64(), &Uuid::now_v7(), &input.notice], deadline, ERROR).await?;
    written.first().ok_or(ERROR)?.try_get(0).map_err(|_| ERROR)
}
/// Writes a permission row already allowed by the read-only rule.
pub async fn record_readonly_allow(
    client: &Client,
    input: PermissionNew<'_>,
    deadline: Instant,
) -> Result<(), StoreError> {
    update(client, "INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,permission_id,native_request_id,tool_name,input_summary,input_sha256,requested_at,expires_at,decision,decided_via,decided_at) VALUES ($1,'permission',$2,$3,$4,$5,$6,$7,$8,statement_timestamp(),statement_timestamp()+make_interval(secs=>$9),'allow','readonly_rule',statement_timestamp()) RETURNING record_id", &[&Uuid::now_v7(), &input.run_id, &input.binding_id, &input.permission_id, &input.native_request_id, &input.tool_name, &input.input_summary, &input.input_sha256.as_slice(), &input.ttl.as_secs_f64()], deadline).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecidedVia {
    ReadonlyRule,
    Cli,
    Timeout,
    RunStopped,
}
impl DecidedVia {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadonlyRule => "readonly_rule",
            Self::Cli => "cli",
            Self::Timeout => "timeout",
            Self::RunStopped => "run_stopped",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decided {
    Decided,
    NotPending,
    Expired,
}
fn decided(row: &tokio_postgres::Row) -> Result<(Decision, DecidedVia), StoreError> {
    let decision = match row.try_get::<_, &str>(0).map_err(|_| ERROR)? {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => return Err(ERROR),
    };
    let via = match row.try_get::<_, &str>(1).map_err(|_| ERROR)? {
        "readonly_rule" => DecidedVia::ReadonlyRule,
        "cli" => DecidedVia::Cli,
        "timeout" => DecidedVia::Timeout,
        "run_stopped" => DecidedVia::RunStopped,
        _ => return Err(ERROR),
    };
    Ok((decision, via))
}
/// The owner's decision through the control interface: only an undecided, unexpired request.
pub async fn decide_permission(
    client: &Client,
    permission_id: &str,
    decision: Decision,
    token: Uuid,
    deadline: Instant,
) -> Result<Decided, StoreError> {
    let decision = match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    };
    let written = rows(client, "UPDATE openmybot.host_driver_sessions SET decision=$2,decided_via='cli',decided_at=statement_timestamp(),decided_by_token=$3 WHERE record_kind='permission' AND permission_id=$1 AND decision IS NULL AND expires_at>statement_timestamp() RETURNING record_id", &[&permission_id, &decision, &token], deadline, ERROR).await?;
    if !written.is_empty() {
        return Ok(Decided::Decided);
    }
    let found = rows(client, "SELECT decision IS NULL FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND permission_id=$1", &[&permission_id], deadline, ERROR).await?;
    match found.first() {
        Some(row) if row.try_get::<_, bool>(0).map_err(|_| ERROR)? => Ok(Decided::Expired),
        _ => Ok(Decided::NotPending),
    }
}
/// Denies a still-undecided request on expiry or run stop; otherwise returns the decision
/// already written.
pub async fn settle_permission(
    client: &Client,
    permission_id: &str,
    via: DecidedVia,
    deadline: Instant,
) -> Result<(Decision, DecidedVia), StoreError> {
    let written = rows(client, "UPDATE openmybot.host_driver_sessions SET decision='deny',decided_via=$2,decided_at=statement_timestamp() WHERE record_kind='permission' AND permission_id=$1 AND decision IS NULL RETURNING decision,decided_via", &[&permission_id, &via.as_str()], deadline, ERROR).await?;
    if let Some(row) = written.first() {
        return decided(row);
    }
    let found = rows(client, "SELECT decision,decided_via FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND permission_id=$1 AND decision IS NOT NULL", &[&permission_id], deadline, ERROR).await?;
    decided(found.first().ok_or(ERROR)?)
}
/// The decision of a request, or `None` while it is undecided.
pub async fn read_permission(
    client: &Client,
    permission_id: &str,
) -> Result<Option<(Decision, DecidedVia)>, StoreError> {
    rows(client, "SELECT decision,decided_via FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND permission_id=$1 AND decision IS NOT NULL", &[&permission_id], Instant::now() + READ_BUDGET, ERROR)
        .await?
        .first()
        .map(decided)
        .transpose()
}
/// Records that the decided response reached the child.
pub async fn answer_permission(
    client: &Client,
    permission_id: &str,
    deadline: Instant,
) -> Result<(), StoreError> {
    update(client, "UPDATE openmybot.host_driver_sessions SET answered_at=statement_timestamp() WHERE record_kind='permission' AND permission_id=$1 AND decision IS NOT NULL RETURNING record_id", &[&permission_id], deadline).await
}
