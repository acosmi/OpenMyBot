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

/// The stored facts of one dispatched or pending run, as the owner inspects it.
pub struct RunFacts {
    pub binding_id: Uuid,
    pub kind: GrantKind,
    pub thread_id: String,
    pub dispatch_status: String,
    pub terminal_kind: Option<String>,
    pub session: Option<SessionFacts>,
    /// Ordered by request time.
    pub permissions: Vec<PermissionFacts>,
}
pub struct SessionFacts {
    pub end_reason: Option<String>,
    pub stop_outcome: Option<String>,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<i32>,
    pub started_at: OffsetDateTime,
    pub ended_at: Option<OffsetDateTime>,
}
pub struct PermissionFacts {
    pub permission_id: String,
    pub tool_name: String,
    pub input_summary: Option<String>,
    pub requested_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub decision: Option<String>,
    pub decided_via: Option<String>,
}
/// The event, session and permission rows of a run; `None` when no event carries the run.
pub async fn run_facts(
    client: &Client,
    run_id: &str,
    deadline: Instant,
) -> Result<Option<RunFacts>, StoreError> {
    let event = rows(client, "SELECT e.binding_id,b.binding_kind='host',e.thread_id,e.dispatch_status,e.terminal_kind FROM openmybot.channel_events e JOIN openmybot.channel_bindings b ON b.binding_id=e.binding_id WHERE e.run_id=$1", &[&run_id], deadline, ERROR).await?;
    let Some(event) = event.first() else {
        return Ok(None);
    };
    let session = rows(client, "SELECT end_reason,stop_outcome,exit_code,exit_signal,started_at,ended_at FROM openmybot.host_driver_sessions WHERE record_kind='session' AND run_id=$1", &[&run_id], deadline, ERROR).await?;
    let permissions = rows(client, "SELECT permission_id,tool_name,input_summary,requested_at,expires_at,decision,decided_via FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND run_id=$1 ORDER BY requested_at,record_id", &[&run_id], deadline, ERROR).await?;
    Ok(Some(RunFacts {
        binding_id: event.try_get(0).map_err(|_| ERROR)?,
        kind: if event.try_get::<_, bool>(1).map_err(|_| ERROR)? {
            GrantKind::Host
        } else {
            GrantKind::Sender
        },
        thread_id: event.try_get(2).map_err(|_| ERROR)?,
        dispatch_status: event.try_get(3).map_err(|_| ERROR)?,
        terminal_kind: event.try_get(4).map_err(|_| ERROR)?,
        session: session
            .first()
            .map(|row| {
                Ok(SessionFacts {
                    end_reason: row.try_get(0).map_err(|_| ERROR)?,
                    stop_outcome: row.try_get(1).map_err(|_| ERROR)?,
                    exit_code: row.try_get(2).map_err(|_| ERROR)?,
                    exit_signal: row.try_get(3).map_err(|_| ERROR)?,
                    started_at: row.try_get(4).map_err(|_| ERROR)?,
                    ended_at: row.try_get(5).map_err(|_| ERROR)?,
                })
            })
            .transpose()?,
        permissions: permissions
            .iter()
            .map(|row| {
                Ok(PermissionFacts {
                    permission_id: row.try_get(0).map_err(|_| ERROR)?,
                    tool_name: row.try_get(1).map_err(|_| ERROR)?,
                    input_summary: row.try_get(2).map_err(|_| ERROR)?,
                    requested_at: row.try_get(3).map_err(|_| ERROR)?,
                    expires_at: row.try_get(4).map_err(|_| ERROR)?,
                    decision: row.try_get(5).map_err(|_| ERROR)?,
                    decided_via: row.try_get(6).map_err(|_| ERROR)?,
                })
            })
            .collect::<Result<_, StoreError>>()?,
    }))
}

/// A session row without an end, left by a daemon that did not stop its child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanSession {
    pub record_id: Uuid,
    pub run_id: String,
    pub pgid: Option<i32>,
}
/// Session rows not yet ended, oldest start first.
pub async fn list_orphan_sessions(
    client: &Client,
    deadline: Instant,
) -> Result<Vec<OrphanSession>, StoreError> {
    let error = StoreError::ReconcileFailed;
    rows(client, "SELECT record_id,run_id,pgid FROM openmybot.host_driver_sessions WHERE record_kind='session' AND ended_at IS NULL ORDER BY started_at,record_id", &[], deadline, error)
        .await?
        .iter()
        .map(|row| {
            Ok(OrphanSession {
                record_id: row.try_get(0).map_err(|_| error)?,
                run_id: row.try_get(1).map_err(|_| error)?,
                pgid: row.try_get(2).map_err(|_| error)?,
            })
        })
        .collect()
}
/// Denies every undecided permission request as `run_stopped`; returns how many were denied.
pub async fn deny_undecided_permissions(
    client: &Client,
    deadline: Instant,
) -> Result<u64, StoreError> {
    rows(client, "UPDATE openmybot.host_driver_sessions SET decision='deny', decided_via='run_stopped', decided_at=now() WHERE record_kind='permission' AND decision IS NULL RETURNING record_id", &[], deadline, StoreError::ReconcileFailed).await.map(|denied| denied.len() as u64)
}

/// A run's state as the host sees it, derived from its event, session and permission rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Pending,
    Running,
    AwaitingPermission,
    Succeeded,
    Failed,
    Cancelled,
    ReconciliationRequired,
}
impl RunState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::AwaitingPermission => "awaiting_permission",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::ReconciliationRequired
        )
    }
}
/// One accepted message of a binding with its run's state and stored result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunView {
    pub run_id: String,
    pub thread_id: String,
    pub state: RunState,
    /// `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC, milliseconds truncated.
    pub accepted_at: String,
    /// Undecided, unexpired requests of a dispatched run without a terminal, by request time.
    pub permission_ids: Vec<String>,
    /// The session's result text while the sweeper has not cleared it.
    pub summary: Option<String>,
    pub artifacts: Vec<String>,
}
/// The binding's accepted messages, newest first, optionally only the one carrying `run_id`.
async fn run_views(
    client: &Client,
    binding_id: Uuid,
    run_id: Option<&str>,
    limit: i64,
    deadline: Instant,
) -> Result<Vec<RunView>, StoreError> {
    rows(client, "SELECT e.run_id,e.thread_id,CASE WHEN e.terminal_kind IS NOT NULL THEN e.terminal_kind WHEN e.dispatch_status='pending' THEN 'pending' WHEN e.dispatch_status IN ('expired','cancelled') THEN 'cancelled' WHEN e.dispatch_status='conflict' THEN 'failed' WHEN p.ids IS NOT NULL THEN 'awaiting_permission' ELSE 'running' END,to_char(e.accepted_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'),COALESCE(p.ids,ARRAY[]::text[]),s.result_summary,COALESCE(s.artifact_paths,ARRAY[]::text[]) FROM openmybot.channel_events e LEFT JOIN LATERAL (SELECT array_agg(h.permission_id ORDER BY h.requested_at,h.record_id) AS ids FROM openmybot.host_driver_sessions h WHERE h.record_kind='permission' AND h.run_id=e.run_id AND h.decision IS NULL AND h.expires_at>statement_timestamp() AND e.dispatch_status='dispatched' AND e.terminal_kind IS NULL) p ON true LEFT JOIN openmybot.host_driver_sessions s ON s.record_kind='session' AND s.run_id=e.run_id WHERE e.binding_id=$1 AND e.disposition='accepted_message' AND ($2::text IS NULL OR e.run_id=$2) ORDER BY e.accepted_at DESC,e.record_id DESC LIMIT $3", &[&binding_id, &run_id, &limit], deadline, ERROR)
        .await?
        .iter()
        .map(|row| {
            Ok(RunView {
                run_id: row.try_get(0).map_err(|_| ERROR)?,
                thread_id: row.try_get(1).map_err(|_| ERROR)?,
                state: match row.try_get::<_, &str>(2).map_err(|_| ERROR)? {
                    "pending" => RunState::Pending,
                    "running" => RunState::Running,
                    "awaiting_permission" => RunState::AwaitingPermission,
                    "succeeded" => RunState::Succeeded,
                    "failed" => RunState::Failed,
                    "cancelled" => RunState::Cancelled,
                    "reconciliation_required" => RunState::ReconciliationRequired,
                    _ => return Err(ERROR),
                },
                accepted_at: row.try_get(3).map_err(|_| ERROR)?,
                permission_ids: row.try_get(4).map_err(|_| ERROR)?,
                summary: row.try_get(5).map_err(|_| ERROR)?,
                artifacts: row.try_get(6).map_err(|_| ERROR)?,
            })
        })
        .collect()
}
/// The binding's accepted message carrying `run_id`; `None` when no such message exists.
pub async fn binding_run(
    client: &Client,
    binding_id: Uuid,
    run_id: &str,
    deadline: Instant,
) -> Result<Option<RunView>, StoreError> {
    Ok(run_views(client, binding_id, Some(run_id), 1, deadline)
        .await?
        .into_iter()
        .next())
}
/// The binding's latest `limit` accepted messages, newest first.
pub async fn binding_runs(
    client: &Client,
    binding_id: Uuid,
    limit: i64,
    deadline: Instant,
) -> Result<Vec<RunView>, StoreError> {
    run_views(client, binding_id, None, limit, deadline).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_state_words_equal_the_migration_check_values() {
        let migration = include_str!("../migrations/omb_0001_initial.sql");
        let check = migration
            .lines()
            .find(|line| line.contains("CONSTRAINT channel_events_check_20"))
            .unwrap();
        let open = check.find("IN (").unwrap() + "IN (".len();
        let words: Vec<&str> = check[open..check.rfind(')').unwrap() - 1]
            .split(',')
            .map(|word| word.trim_matches('\''))
            .collect();
        let terminal = [
            RunState::Succeeded,
            RunState::Failed,
            RunState::Cancelled,
            RunState::ReconciliationRequired,
        ];
        assert_eq!(words, terminal.map(RunState::as_str));
        let all = [
            RunState::Pending,
            RunState::Running,
            RunState::AwaitingPermission,
            RunState::Succeeded,
            RunState::Failed,
            RunState::Cancelled,
            RunState::ReconciliationRequired,
        ];
        for state in all {
            assert_eq!(state.is_terminal(), terminal.contains(&state), "{state:?}");
        }
        for (index, state) in all.iter().enumerate() {
            assert!(
                !all[..index]
                    .iter()
                    .any(|earlier| earlier.as_str() == state.as_str())
            );
        }
        for state in [
            RunState::Pending,
            RunState::Running,
            RunState::AwaitingPermission,
        ] {
            assert!(!words.contains(&state.as_str()), "{state:?}");
        }
    }
}
