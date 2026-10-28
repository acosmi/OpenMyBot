//! Adapter start, the per-run session task, the stop ladder and run identification.
use crate::{
    DELIVERY_ARTIFACTS_MAX, HostDriverAdapter, STDERR_TAIL_MAX, Shared, jcs,
    mapping::{Mapped, Mapper},
    permission::{self, Pending},
    protocol::{self, Frame, LineError},
    spawn::{Slot, SpawnSpec},
    window,
};
use async_trait::async_trait;
use omb_store::{
    DecidedVia, Decision, EndReason, GrantKind, PermissionNew, RunTarget, SessionEnd, SessionStart,
    StopRecord, StoreError,
};
use openbot_application::{
    ProviderAdapter, ProviderEvent, ProviderFailure, ProviderMessage, ProviderMessageRole,
    ProviderPortError, ProviderRequest, ProviderSession, StopOutcome,
};
use rustix::process::{Pid, Signal};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout},
    sync::{mpsc, oneshot},
    time::{Instant, MissedTickBehavior, interval, sleep, sleep_until},
};
use uuid::Uuid;

/// Deadline of one store write.
const STORE_BUDGET: Duration = Duration::from_secs(2);
/// Interval of the liveness probes while a stop step waits.
const PROBE: Duration = Duration::from_millis(10);
const READ_CHUNK: usize = 8192;

fn deadline() -> Instant {
    Instant::now() + STORE_BUDGET
}

/// The engine-facing failure of a session row's end reason; `None` where no `Failed` is sent.
pub(crate) fn failure(reason: EndReason) -> Option<ProviderFailure> {
    match reason {
        EndReason::ResultSuccess
        | EndReason::StopRequested
        | EndReason::SpawnFailed
        | EndReason::VersionRejected => None,
        EndReason::ResultError | EndReason::ResumeFailed => Some(ProviderFailure::GenerationFailed),
        EndReason::OutputLimit
        | EndReason::LineLimit
        | EndReason::ProtocolError
        | EndReason::InitTimeout => Some(ProviderFailure::InvalidResponse),
        EndReason::Stalled => Some(ProviderFailure::StreamStalled),
        EndReason::ChildExited => Some(ProviderFailure::Transport),
    }
}

/// Stop step 7: confirmed only when the child was reaped and its process group is empty.
pub(crate) fn confirm(reaped: bool, group_empty: bool, at: SystemTime) -> StopOutcome {
    if reaped && group_empty {
        StopOutcome::Confirmed { at }
    } else {
        StopOutcome::Unknown
    }
}

/// The binding named by the marker line of the first user message after the last assistant
/// message, and the text sent to CrabCode: those user messages without the marker line, joined
/// by a blank line.
pub(crate) fn run_marker(
    messages: &[ProviderMessage],
) -> Result<(Uuid, String), ProviderPortError> {
    let invalid = ProviderPortError::InvalidRequest {
        field: "omb_binding",
    };
    let start = messages
        .iter()
        .rposition(|message| message.role == ProviderMessageRole::Assistant)
        .map_or(0, |index| index + 1);
    let users: Vec<&str> = messages[start..]
        .iter()
        .filter(|message| message.role == ProviderMessageRole::User)
        .map(|message| message.content.as_str())
        .collect();
    let (first, rest) = users.split_first().ok_or(invalid)?;
    let (marker, body) = first.split_once('\n').unwrap_or((first, ""));
    let binding = marker
        .strip_prefix("[omb-binding ")
        .and_then(|id| id.strip_suffix(']'))
        .and_then(|id| Uuid::try_parse(id).ok())
        .ok_or(invalid)?;
    let prompt = std::iter::once(body)
        .chain(rest.iter().copied())
        .collect::<Vec<_>>()
        .join("\n\n");
    Ok((binding, prompt))
}

/// `file_path` values of the owner-allowed inputs, relative to the workspace: real paths, or
/// the parent's real path plus the name for a file not yet written; inside the workspace only,
/// first occurrence kept, at most `DELIVERY_ARTIFACTS_MAX`.
pub(crate) fn artifact_paths(inputs: &[Value], workspace: &Path) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for input in inputs {
        if paths.len() == DELIVERY_ARTIFACTS_MAX {
            break;
        }
        let Some(path) = input["file_path"].as_str() else {
            continue;
        };
        let path = workspace.join(path);
        let real = std::fs::canonicalize(&path).ok().or_else(|| {
            Some(
                std::fs::canonicalize(path.parent()?)
                    .ok()?
                    .join(path.file_name()?),
            )
        });
        let Some(relative) = real
            .as_deref()
            .and_then(|real| real.strip_prefix(workspace).ok())
            .and_then(Path::to_str)
            .filter(|relative| !relative.is_empty())
        else {
            continue;
        };
        if !paths.iter().any(|known| known == relative) {
            paths.push(relative.to_owned());
        }
    }
    paths
}

enum Command {
    Stop(oneshot::Sender<StopOutcome>),
}

/// One run's provider stream; a background task owns the child and every store write.
pub struct HostDriverSession {
    events: mpsc::UnboundedReceiver<Result<ProviderEvent, ProviderPortError>>,
    commands: mpsc::Sender<Command>,
    finished: Arc<OnceLock<StopOutcome>>,
}
#[async_trait]
impl ProviderSession for HostDriverSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        self.events.recv().await.transpose()
    }
    async fn request_stop(&mut self) -> Result<StopOutcome, ProviderPortError> {
        let (reply, answer) = oneshot::channel();
        if self.commands.send(Command::Stop(reply)).await.is_ok()
            && let Ok(outcome) = answer.await
        {
            return Ok(outcome);
        }
        // The task already ended; its last ladder decided the outcome.
        Ok(self.finished.get().copied().unwrap_or(StopOutcome::Unknown))
    }
}

struct Spawned {
    child: Child,
    slot: Slot,
    workspace: PathBuf,
    version: String,
    args_sha256: [u8; 32],
}
impl HostDriverAdapter {
    async fn spawn(&self, target: &RunTarget) -> Result<Spawned, EndReason> {
        let config = &self.shared.config;
        let binary = config.binary.as_deref().ok_or(EndReason::SpawnFailed)?;
        let workspace = config
            .roots
            .resolve(Path::new(&target.workspace_dir))
            .ok_or(EndReason::SpawnFailed)?;
        let slot = Slot::reserve(&self.shared.children, config.limits.max_children)
            .ok_or(EndReason::SpawnFailed)?;
        let (none_args, none_env) = (Vec::new(), BTreeMap::new());
        let probe = config.window.first();
        let accepted = window::verify(
            &SpawnSpec {
                binary,
                cwd: &workspace,
                home: &config.home,
                tmp_dir: &config.tmp_dir,
                extra_args: probe.map_or(&none_args, |entry| &entry.extra_args),
                extra_env: probe.map_or(&none_env, |entry| &entry.extra_env),
                resume: None,
            },
            &config.window,
            config.limits.version_timeout,
        )
        .await?;
        let spec = SpawnSpec {
            binary,
            cwd: &workspace,
            home: &config.home,
            tmp_dir: &config.tmp_dir,
            extra_args: &accepted.extra_args,
            extra_env: &accepted.extra_env,
            resume: target
                .resume
                .as_ref()
                .map(|resume| resume.native_session_id.as_str()),
        };
        if spec.refused() {
            return Err(EndReason::SpawnFailed);
        }
        let child = spec
            .command(false)
            .spawn()
            .map_err(|_| EndReason::SpawnFailed)?;
        Ok(Spawned {
            args_sha256: spec.args_sha256(),
            child,
            slot,
            workspace,
            version: accepted.version.clone(),
        })
    }
}
#[async_trait]
impl ProviderAdapter for HostDriverAdapter {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let store = &*self.shared.store;
        let (binding, prompt) = run_marker(&request.messages)?;
        let target = omb_store::resolve_run(store, binding)
            .await
            .map_err(|_| ProviderPortError::Unavailable)?
            .ok_or(ProviderPortError::InvalidRequest {
                field: "omb_binding",
            })?;
        let record = omb_store::upsert_session(
            store,
            SessionStart {
                run_id: &target.run_id,
                binding_id: binding,
                workspace_dir: &target.workspace_dir,
            },
            deadline(),
        )
        .await
        .map_err(|_| ProviderPortError::Unavailable)?;
        let spawned = match self.spawn(&target).await {
            Ok(spawned) => spawned,
            Err(reason) => {
                let _ = omb_store::end_session(
                    store,
                    record,
                    SessionEnd {
                        reason,
                        exit_code: None,
                        exit_signal: None,
                        stop: None,
                        result_summary: None,
                        artifact_paths: &[],
                        stderr_tail: "",
                    },
                    deadline(),
                )
                .await;
                return Err(ProviderPortError::Unavailable);
            }
        };
        let Spawned {
            mut child,
            slot,
            workspace,
            version,
            args_sha256,
        } = spawned;
        let pid = child.id().expect("a just-spawned child has an id") as i32;
        let (events_tx, events) = mpsc::unbounded_channel();
        let (commands, commands_rx) = mpsc::channel(4);
        let finished = Arc::new(OnceLock::new());
        let run = Run {
            shared: Arc::clone(&self.shared),
            record,
            target,
            workspace,
            version,
            args_sha256,
            pid,
            pgid: Pid::from_raw(pid).expect("a child pid is positive"),
            stdin: child.stdin.take(),
            stdout: child.stdout.take().expect("piped stdout"),
            stderr: child.stderr.take().expect("piped stderr"),
            child,
            stdout_open: true,
            stderr_open: true,
            status: None,
            events: events_tx,
            commands: commands_rx,
            finished: Arc::clone(&finished),
            mapper: Mapper::default(),
            line: Vec::new(),
            output: 0,
            tail: Vec::new(),
            pending: Vec::new(),
            allowed: Vec::new(),
            result_seen: false,
            write_stalled: false,
            slot: Some(slot),
        };
        {
            let mut tasks = self.shared.tasks.lock().unwrap();
            while tasks.try_join_next().is_some() {}
            tasks.spawn(run.run(prompt));
        }
        Ok(Box::new(HostDriverSession {
            events,
            commands,
            finished,
        }))
    }
}

/// How the session's main loop ended.
enum End {
    Reason(EndReason),
    Success {
        summary: Option<String>,
    },
    Stop(oneshot::Sender<StopOutcome>),
    Dropped,
    Shutdown,
    /// A session-row write failed: the daemon's store is gone.
    Store,
}

struct Run {
    shared: Arc<Shared>,
    record: Uuid,
    target: RunTarget,
    workspace: PathBuf,
    version: String,
    args_sha256: [u8; 32],
    pid: i32,
    pgid: Pid,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
    stdout_open: bool,
    stderr_open: bool,
    status: Option<ExitStatus>,
    events: mpsc::UnboundedSender<Result<ProviderEvent, ProviderPortError>>,
    commands: mpsc::Receiver<Command>,
    finished: Arc<OnceLock<StopOutcome>>,
    mapper: Mapper,
    line: Vec<u8>,
    output: u64,
    tail: Vec<u8>,
    pending: Vec<Pending>,
    /// Inputs the owner allowed, in order; the source of the row's artifact paths.
    allowed: Vec<Value>,
    result_seen: bool,
    /// A stdin write outlasted the stall budget.
    write_stalled: bool,
    /// Released once the ladder has run, so a reaped child frees its place at once.
    slot: Option<Slot>,
}
impl Run {
    async fn run(mut self, prompt: String) {
        let end = self.drive(prompt).await;
        let outcome = match end {
            End::Stop(reply) => {
                let settled = self.stop_pending().await;
                self.write(&protocol::interrupt()).await;
                let outcome = self.ladder().await;
                if settled {
                    let _ = self
                        .close(EndReason::StopRequested, Some(outcome), None)
                        .await;
                }
                let _ = reply.send(outcome);
                outcome
            }
            End::Shutdown => {
                let outcome = self.ladder().await;
                let _ = self
                    .close(EndReason::StopRequested, Some(outcome), None)
                    .await;
                outcome
            }
            End::Dropped => {
                let outcome = self.ladder().await;
                let _ = self.close(EndReason::StopRequested, None, None).await;
                outcome
            }
            End::Store => {
                let outcome = self.ladder().await;
                self.emit([ProviderEvent::Failed(ProviderFailure::Transport)]);
                outcome
            }
            End::Success { summary } => {
                let outcome = self.ladder().await;
                let terminal = match self.close(EndReason::ResultSuccess, None, summary).await {
                    Ok(()) => ProviderEvent::Completed,
                    Err(_) => ProviderEvent::Failed(ProviderFailure::Transport),
                };
                self.emit([terminal]);
                outcome
            }
            End::Reason(reason) => {
                let outcome = self.ladder().await;
                let failed = match self.close(reason, None, None).await {
                    Ok(()) => failure(reason).unwrap_or(ProviderFailure::Transport),
                    Err(_) => ProviderFailure::Transport,
                };
                self.emit([ProviderEvent::Failed(failed)]);
                outcome
            }
        };
        let _ = self.finished.set(outcome);
    }

    async fn drive(&mut self, prompt: String) -> End {
        let limits = self.shared.config.limits;
        let resumed_from = self
            .target
            .resume
            .as_ref()
            .map(|resume| resume.native_session_id.clone());
        if omb_store::session_spawned(
            &self.shared.store,
            self.record,
            &self.version,
            self.args_sha256,
            resumed_from.as_deref(),
            self.pid,
            self.pid,
            deadline(),
        )
        .await
        .is_err()
        {
            return End::Store;
        }
        self.write(&protocol::initialize()).await;
        self.write(&protocol::user(&prompt)).await;
        let init_deadline = Instant::now() + limits.init_timeout;
        let mut last_output = Instant::now();
        let mut shutdown = self.shared.shutdown.subscribe();
        let mut poll = interval(limits.permission_poll);
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut out = vec![0; READ_CHUNK];
        let mut err = vec![0; READ_CHUNK];
        loop {
            if self.write_stalled {
                return End::Reason(EndReason::Stalled);
            }
            let stall = self.pending.is_empty().then(|| last_output + limits.stall);
            tokio::select! {
                read = self.stdout.read(&mut out), if self.stdout_open => match read {
                    Ok(0) | Err(_) => {
                        self.stdout_open = false;
                        return End::Reason(if self.target.resume.is_some() && !self.mapper.init {
                            EndReason::ResumeFailed
                        } else {
                            EndReason::ChildExited
                        });
                    }
                    Ok(count) => {
                        last_output = Instant::now();
                        if let Some(end) = self.stdout_bytes(&out[..count]).await {
                            return end;
                        }
                    }
                },
                read = self.stderr.read(&mut err), if self.stderr_open => match read {
                    Ok(0) | Err(_) => self.stderr_open = false,
                    Ok(count) => {
                        last_output = Instant::now();
                        self.keep_tail(&err[..count]);
                        if self.count(count) {
                            return End::Reason(EndReason::OutputLimit);
                        }
                    }
                },
                command = self.commands.recv() => return match command {
                    Some(Command::Stop(reply)) => End::Stop(reply),
                    None => End::Dropped,
                },
                () = async { drop(shutdown.wait_for(|stopping| *stopping).await) } => return End::Shutdown,
                () = sleep_until(stall.unwrap_or(init_deadline)), if stall.is_some() => {
                    return End::Reason(EndReason::Stalled);
                }
                () = sleep_until(init_deadline), if !self.mapper.init => {
                    return End::Reason(EndReason::InitTimeout);
                }
                _ = poll.tick(), if !self.pending.is_empty() => {
                    if self.poll().await.is_err() {
                        return End::Store;
                    }
                    if self.pending.is_empty() {
                        // The stall budget restarts once no request waits for the owner.
                        last_output = Instant::now();
                    }
                }
            }
        }
    }

    /// Counts output bytes against the run's cap; true once it is exceeded.
    fn count(&mut self, bytes: usize) -> bool {
        self.output += bytes as u64;
        self.output > self.shared.config.limits.output_max
    }
    /// PostgreSQL text holds no NUL, so NUL bytes never enter the tail.
    fn keep_tail(&mut self, bytes: &[u8]) {
        self.tail.extend(bytes.iter().filter(|byte| **byte != 0));
        let excess = self.tail.len().saturating_sub(STDERR_TAIL_MAX);
        self.tail.drain(..excess);
    }
    fn emit<const N: usize>(&self, events: [ProviderEvent; N]) {
        for event in events {
            let _ = self.events.send(Ok(event));
        }
    }
    /// Writes one frame to the child; false when stdin is closed or the write failed. A child that
    /// does not read its stdin within the stall budget, or a driver shutdown during the write,
    /// closes stdin; the main loop then ends the run as stalled or shut down.
    async fn write(&mut self, frame: &[u8]) -> bool {
        let Some(stdin) = self.stdin.as_mut() else {
            return false;
        };
        let mut shutdown = self.shared.shutdown.subscribe();
        let written = tokio::select! {
            written = tokio::time::timeout(self.shared.config.limits.stall, stdin.write_all(frame)) => match written {
                Ok(result) => return result.is_ok(),
                Err(_) => {
                    self.write_stalled = true;
                    false
                }
            },
            () = async { drop(shutdown.wait_for(|stopping| *stopping).await) } => false,
        };
        self.stdin = None;
        written
    }

    async fn stdout_bytes(&mut self, bytes: &[u8]) -> Option<End> {
        if self.count(bytes.len()) {
            return Some(End::Reason(EndReason::OutputLimit));
        }
        let line_max = self.shared.config.limits.line_max;
        self.line.extend_from_slice(bytes);
        while let Some(at) = self.line.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.line.drain(..=at).collect();
            let frame = match protocol::parse_line(&line[..at], line_max) {
                Ok(frame) => frame,
                Err(LineError::LineLimit) => return Some(End::Reason(EndReason::LineLimit)),
                Err(LineError::Protocol) => return Some(End::Reason(EndReason::ProtocolError)),
            };
            if let Some(end) = self.frame(frame).await {
                return Some(end);
            }
        }
        (self.line.len() > line_max).then_some(End::Reason(EndReason::LineLimit))
    }

    async fn frame(&mut self, frame: Frame) -> Option<End> {
        match self.mapper.map(frame) {
            Mapped::Events(events) => {
                for event in events {
                    let _ = self.events.send(Ok(event));
                }
                None
            }
            Mapped::Init { session_id, event } => {
                let store = Arc::clone(&self.shared.store);
                if omb_store::session_init(&store, self.record, &session_id, deadline())
                    .await
                    .is_err()
                    || self.progress().await.is_err()
                {
                    return Some(End::Store);
                }
                self.emit([event]);
                None
            }
            Mapped::Permission {
                request_id,
                tool_name,
                input,
            } => self
                .permission(request_id, tool_name, input)
                .await
                .err()
                .map(|_| End::Store),
            Mapped::Refuse { request_id, code } => {
                self.write(&protocol::refuse(&request_id, code)).await;
                None
            }
            Mapped::Success {
                events,
                mut summary,
            } => {
                // PostgreSQL text holds no NUL.
                if let Some(text) = summary.as_mut() {
                    text.retain(|c| c != '\0');
                }
                self.result_seen = true;
                for event in events {
                    let _ = self.events.send(Ok(event));
                }
                Some(End::Success { summary })
            }
            Mapped::ResultError => {
                self.result_seen = true;
                Some(End::Reason(if self.target.resume.is_some() {
                    EndReason::ResumeFailed
                } else {
                    EndReason::ResultError
                }))
            }
            Mapped::Violation => Some(End::Reason(EndReason::ProtocolError)),
        }
    }

    async fn progress(&self) -> Result<(), StoreError> {
        omb_store::session_progress(
            &self.shared.store,
            self.record,
            self.mapper.seq,
            self.output,
            deadline(),
        )
        .await
    }

    /// Persists a `can_use_tool` request: the read-only rule answers at once, anything else
    /// waits for the owner.
    async fn permission(
        &mut self,
        request_id: String,
        tool_name: String,
        input: Value,
    ) -> Result<(), StoreError> {
        self.progress().await?;
        let store = Arc::clone(&self.shared.store);
        let ttl = self.shared.config.limits.permission_ttl;
        let permission_id = permission::permission_id();
        let bytes = jcs::jcs(&input);
        let summary = jcs::summary(&bytes);
        let readonly = permission::readonly(&tool_name, &input, &self.workspace);
        let notice = (self.target.kind == GrantKind::Sender && !readonly)
            .then(|| permission::notice(&self.target.run_id, &tool_name, &permission_id));
        let row = PermissionNew {
            run_id: &self.target.run_id,
            binding_id: self.target.binding_id,
            permission_id: &permission_id,
            native_request_id: &request_id,
            tool_name: &tool_name,
            input_summary: &summary,
            input_sha256: jcs::input_sha256(&bytes),
            ttl,
            notice: notice.as_deref(),
        };
        if readonly {
            omb_store::record_readonly_allow(&store, row, deadline()).await?;
            return self
                .answer(
                    &permission_id,
                    &request_id,
                    Decision::Allow,
                    DecidedVia::ReadonlyRule,
                    input,
                )
                .await;
        }
        omb_store::insert_permission(&store, row, deadline()).await?;
        self.pending.push(Pending {
            permission_id,
            request_id,
            input,
            expires: Instant::now() + ttl,
        });
        Ok(())
    }
    /// Sends the persisted decision to the child, then records the answer.
    async fn answer(
        &mut self,
        permission_id: &str,
        request_id: &str,
        decision: Decision,
        via: DecidedVia,
        input: Value,
    ) -> Result<(), StoreError> {
        let response = permission::response(request_id, decision, via, &input);
        if (decision, via) == (Decision::Allow, DecidedVia::Cli) {
            self.allowed.push(input);
        }
        if self.write(&response).await {
            omb_store::answer_permission(&self.shared.store, permission_id, deadline()).await?;
        }
        Ok(())
    }
    async fn poll(&mut self) -> Result<(), StoreError> {
        let store = Arc::clone(&self.shared.store);
        let mut index = 0;
        while index < self.pending.len() {
            match permission::poll(&store, &self.pending[index], deadline()).await? {
                Some((decision, via)) => {
                    let pending = self.pending.remove(index);
                    self.answer(
                        &pending.permission_id,
                        &pending.request_id,
                        decision,
                        via,
                        pending.input,
                    )
                    .await?;
                }
                None => index += 1,
            }
        }
        Ok(())
    }
    /// Stop step 1: every waiting request is denied with `run_stopped` before the interrupt;
    /// false when a store write failed.
    async fn stop_pending(&mut self) -> bool {
        let store = Arc::clone(&self.shared.store);
        let mut settled = true;
        for pending in std::mem::take(&mut self.pending) {
            settled &= match omb_store::settle_permission(
                &store,
                &pending.permission_id,
                DecidedVia::RunStopped,
                deadline(),
            )
            .await
            {
                Ok((decision, via)) => self
                    .answer(
                        &pending.permission_id,
                        &pending.request_id,
                        decision,
                        via,
                        pending.input,
                    )
                    .await
                    .is_ok(),
                Err(_) => false,
            };
        }
        settled
    }

    fn group_alive(&self) -> bool {
        rustix::process::test_kill_process_group(self.pgid) != Err(rustix::io::Errno::SRCH)
    }
    /// Not yet reaped, or another member of its process group remains.
    fn alive(&mut self) -> bool {
        if self.status.is_none() {
            self.status = self.child.try_wait().ok().flatten();
        }
        self.status.is_none() || self.group_alive()
    }
    async fn settle(&mut self, grace: Duration) {
        let until = Instant::now() + grace;
        while Instant::now() < until {
            if !self.alive() {
                return;
            }
            sleep(PROBE).await;
        }
    }
    /// While stopping, output is drained and only watched for a result frame.
    fn drain(&mut self, bytes: &[u8]) {
        self.line.extend_from_slice(bytes);
        while let Some(at) = self.line.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.line.drain(..=at).collect();
            if let Ok(Frame::Result(_)) = protocol::parse_line(&line[..at], usize::MAX) {
                self.result_seen = true;
            }
        }
        if self.line.len() > self.shared.config.limits.line_max {
            self.line.clear();
        }
    }
    /// Stop steps 3–6, then the step 7 judgement.
    async fn ladder(&mut self) -> StopOutcome {
        let limits = self.shared.config.limits;
        let until = Instant::now() + limits.stop_grace;
        let mut out = vec![0; READ_CHUNK];
        let mut err = vec![0; READ_CHUNK];
        while !self.result_seen && self.status.is_none() {
            tokio::select! {
                read = self.stdout.read(&mut out), if self.stdout_open => match read {
                    Ok(0) | Err(_) => self.stdout_open = false,
                    Ok(count) => self.drain(&out[..count]),
                },
                read = self.stderr.read(&mut err), if self.stderr_open => match read {
                    Ok(0) | Err(_) => self.stderr_open = false,
                    Ok(count) => self.keep_tail(&err[..count]),
                },
                status = self.child.wait() => self.status = status.ok(),
                () = sleep_until(until) => break,
            }
        }
        drop(self.stdin.take());
        if self.alive() {
            let _ = rustix::process::kill_process_group(self.pgid, Signal::TERM);
            self.settle(limits.term_grace).await;
        }
        if self.alive() {
            let _ = rustix::process::kill_process_group(self.pgid, Signal::KILL);
            self.settle(limits.kill_grace).await;
        }
        self.slot = None;
        if limits.kill_grace.is_zero() {
            return StopOutcome::Unknown;
        }
        let reaped = self.status.is_some();
        confirm(reaped, reaped && !self.group_alive(), SystemTime::now())
    }

    /// Writes the end columns; a failed resume also withdraws the resumed session.
    async fn close(
        &mut self,
        reason: EndReason,
        stop: Option<StopOutcome>,
        summary: Option<String>,
    ) -> Result<(), StoreError> {
        let store = Arc::clone(&self.shared.store);
        self.progress().await?;
        let artifacts = artifact_paths(&self.allowed, &self.workspace);
        let tail = String::from_utf8_lossy(&self.tail).into_owned();
        omb_store::end_session(
            &store,
            self.record,
            SessionEnd {
                reason,
                exit_code: self.status.and_then(|status| status.code()),
                exit_signal: self.status.and_then(|status| status.signal()),
                stop: stop.map(|outcome| match outcome {
                    StopOutcome::Confirmed { at } => StopRecord::Confirmed { at: at.into() },
                    StopOutcome::Unknown | StopOutcome::Unsupported => StopRecord::Unknown,
                }),
                result_summary: summary.as_deref(),
                artifact_paths: &artifacts,
                stderr_tail: &tail,
            },
            deadline(),
        )
        .await?;
        if reason == EndReason::ResumeFailed
            && let Some(resume) = &self.target.resume
        {
            omb_store::clear_resumable(&store, resume.record_id, deadline()).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::tests::temp;
    use serde_json::json;

    fn message(role: ProviderMessageRole, content: &str) -> ProviderMessage {
        ProviderMessage {
            role,
            content: content.into(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }
    }

    #[test]
    fn marker_line_selects_binding_and_missing_marker_is_invalid_request() {
        let id = Uuid::now_v7();
        let other = Uuid::now_v7();
        let invalid = ProviderPortError::InvalidRequest {
            field: "omb_binding",
        };
        let messages = vec![
            message(ProviderMessageRole::System, "system"),
            message(
                ProviderMessageRole::User,
                &format!("[omb-binding {other}]\nold"),
            ),
            message(ProviderMessageRole::Assistant, "earlier answer"),
            message(
                ProviderMessageRole::User,
                &format!("[omb-binding {id}]\nnew"),
            ),
            message(ProviderMessageRole::User, "material"),
        ];
        assert_eq!(run_marker(&messages).unwrap().0, id);
        let mut first_only = messages[..2].to_vec();
        assert_eq!(run_marker(&first_only).unwrap().0, other);
        first_only.push(message(ProviderMessageRole::Assistant, "done"));
        assert_eq!(run_marker(&first_only), Err(invalid));
        for content in [
            "no marker\n[omb-binding x]".to_owned(),
            format!(" [omb-binding {id}]\nx"),
            "[omb-binding not-a-uuid]\nx".to_owned(),
            format!("text\n[omb-binding {id}]"),
        ] {
            assert_eq!(
                run_marker(&[message(ProviderMessageRole::User, &content)]),
                Err(invalid),
                "{content}"
            );
        }
        assert_eq!(
            run_marker(&[
                message(ProviderMessageRole::User, "material first"),
                message(ProviderMessageRole::User, &format!("[omb-binding {id}]\nx")),
            ]),
            Err(invalid)
        );
    }

    #[test]
    fn prompt_drops_marker_line_and_joins_with_blank_line() {
        let id = Uuid::now_v7();
        let messages = [
            message(
                ProviderMessageRole::User,
                &format!("[omb-binding {id}]\nTemplate line\nsecond"),
            ),
            message(ProviderMessageRole::User, "Untrusted material\nbody"),
        ];
        assert_eq!(
            run_marker(&messages).unwrap(),
            (
                id,
                "Template line\nsecond\n\nUntrusted material\nbody".into()
            )
        );
        assert_eq!(
            run_marker(&[message(
                ProviderMessageRole::User,
                &format!("[omb-binding {id}]")
            )])
            .unwrap(),
            (id, String::new())
        );
    }

    #[test]
    fn artifact_paths_are_inside_workspace_deduplicated_ordered_and_capped() {
        let root = temp("artifacts");
        let outside = temp("artifacts-out");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let workspace = std::fs::canonicalize(&root).unwrap();
        let inputs = vec![
            json!({"file_path": workspace.join("src/a.rs")}),
            json!({"file_path": "src/new.rs"}),
            json!({"file_path": "src/a.rs"}),
            json!({"file_path": outside.join("x.txt")}),
            json!({"file_path": "escape/y.txt"}),
            json!({"file_path": "missing-dir/z.txt"}),
            json!({"command": "ls"}),
            json!({"file_path": "src/../src/b.rs"}),
        ];
        assert_eq!(
            artifact_paths(&inputs, &workspace),
            ["src/a.rs", "src/new.rs", "src/b.rs"]
        );
        let many: Vec<Value> = (0..30)
            .map(|n| json!({"file_path": format!("f{n}.txt")}))
            .collect();
        let capped = artifact_paths(&many, &workspace);
        assert_eq!(capped.len(), 20);
        assert_eq!(capped[0], "f0.txt");
        assert_eq!(capped[19], "f19.txt");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn confirm_decision_table() {
        let at = SystemTime::now();
        assert_eq!(confirm(true, true, at), StopOutcome::Confirmed { at });
        assert_eq!(confirm(true, false, at), StopOutcome::Unknown);
        assert_eq!(confirm(false, true, at), StopOutcome::Unknown);
        assert_eq!(confirm(false, false, at), StopOutcome::Unknown);
    }

    #[test]
    fn end_reason_maps_to_provider_failure_per_table() {
        use EndReason::*;
        for (reason, expected) in [
            (ResultSuccess, None),
            (ResultError, Some(ProviderFailure::GenerationFailed)),
            (StopRequested, None),
            (OutputLimit, Some(ProviderFailure::InvalidResponse)),
            (LineLimit, Some(ProviderFailure::InvalidResponse)),
            (Stalled, Some(ProviderFailure::StreamStalled)),
            (ProtocolError, Some(ProviderFailure::InvalidResponse)),
            (ChildExited, Some(ProviderFailure::Transport)),
            (InitTimeout, Some(ProviderFailure::InvalidResponse)),
            (ResumeFailed, Some(ProviderFailure::GenerationFailed)),
            (VersionRejected, None),
            (SpawnFailed, None),
        ] {
            assert_eq!(failure(reason), expected, "{reason:?}");
        }
    }
}
