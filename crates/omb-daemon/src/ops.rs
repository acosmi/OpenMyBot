//! The owner's non-model control operations, executed under the local context.
use crate::{
    DaemonError,
    channels::rfc3339_utc,
    pairing::{self, PairRequest},
    pg::{self, AuthorityConnection},
};
use omb_channels::{CredentialProblem, TelegramEndpoint, verify_credentials};
use omb_hostdriver::WorkspaceRoots;
use omb_store::{
    Channel, Decided, Decision, GrantKind, HostBinding, IdentityKey, KEY_MAX, NewReceiver, OpenRun,
    ReceiverRow, RunDeadline, StoreError,
};
use openbot_application::ApplicationService;
use openbot_contracts::{
    command::{
        AppCommand, AppReply, CancelThreadRun, ThreadForegroundRunState, ThreadRunCancellationState,
    },
    error::AppError,
    ids::{ActorId, RunId, ThreadId},
};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::SingleUserAuthResolver;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{fmt, path::PathBuf, sync::Arc};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use uuid::Uuid;

/// The control operations besides `status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    StatusRun,
    PairStart,
    BindingsList,
    BindingsRevoke,
    BindingsReconfirm,
    BindingsResetThread,
    BindingsReceiver,
    BindingsHost,
    Approve,
    Deny,
    Cancel,
}
impl Op {
    pub(crate) fn parse(name: &str) -> Option<Op> {
        Some(match name {
            "status_run" => Self::StatusRun,
            "pair_start" => Self::PairStart,
            "bindings_list" => Self::BindingsList,
            "bindings_revoke" => Self::BindingsRevoke,
            "bindings_reconfirm" => Self::BindingsReconfirm,
            "bindings_reset_thread" => Self::BindingsResetThread,
            "bindings_receiver" => Self::BindingsReceiver,
            "bindings_host" => Self::BindingsHost,
            "approve" => Self::Approve,
            "deny" => Self::Deny,
            "cancel" => Self::Cancel,
            _ => return None,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    run_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairArgs {
    channel: String,
    workspace: PathBuf,
    run_deadline: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingArgs {
    binding_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetArgs {
    binding_id: String,
    ack_unknown: String,
}
#[derive(Deserialize)]
#[serde(tag = "channel", rename_all = "lowercase", deny_unknown_fields)]
enum ReceiverArgs {
    Telegram {
        token: String,
    },
    #[allow(
        dead_code,
        reason = "accepted for its syntax until the Feishu receiver exists"
    )]
    Feishu {
        app_id: String,
        app_secret: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostArgs {
    workspace: PathBuf,
    run_deadline: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionArgs {
    permission_id: String,
}

/// One request after its single boundary parse.
enum Request {
    StatusRun(IdentityKey),
    PairStart(PairRequest),
    BindingsList,
    BindingsRevoke(Uuid),
    BindingsReconfirm(Uuid),
    BindingsResetThread(Uuid, IdentityKey),
    BindingsReceiver(ChannelSecret),
    BindingsHost(PathBuf, Option<RunDeadline>),
    Decide(IdentityKey, Decision),
    Cancel(IdentityKey),
}
fn decode<T: DeserializeOwned>(args: Value) -> Result<T, DaemonError> {
    serde_json::from_value(args).map_err(|_| DaemonError::InvalidRequest)
}
fn uuid(text: &str) -> Result<Uuid, DaemonError> {
    Uuid::parse_str(text).map_err(|_| DaemonError::InvalidRequest)
}
fn key(text: &str) -> Result<IdentityKey, DaemonError> {
    IdentityKey::parse(text).ok_or(DaemonError::InvalidRequest)
}
fn run_deadline(seconds: Option<u32>) -> Result<Option<RunDeadline>, DaemonError> {
    seconds
        .map(|seconds| RunDeadline::parse(seconds).ok_or(DaemonError::InvalidRequest))
        .transpose()
}
fn parse(op: Op, args: Value) -> Result<Request, DaemonError> {
    Ok(match op {
        Op::StatusRun => Request::StatusRun(key(&decode::<RunArgs>(args)?.run_id)?),
        Op::PairStart => {
            let args: PairArgs = decode(args)?;
            Request::PairStart(PairRequest {
                channel: match args.channel.as_str() {
                    "telegram" => Channel::Telegram,
                    "feishu" => Channel::Feishu,
                    _ => return Err(DaemonError::InvalidRequest),
                },
                workspace: args.workspace,
                run_deadline: run_deadline(args.run_deadline)?,
            })
        }
        Op::BindingsList => {
            decode::<NoArgs>(args)?;
            Request::BindingsList
        }
        Op::BindingsRevoke => {
            Request::BindingsRevoke(uuid(&decode::<BindingArgs>(args)?.binding_id)?)
        }
        Op::BindingsReconfirm => {
            Request::BindingsReconfirm(uuid(&decode::<BindingArgs>(args)?.binding_id)?)
        }
        Op::BindingsResetThread => {
            let args: ResetArgs = decode(args)?;
            Request::BindingsResetThread(uuid(&args.binding_id)?, key(&args.ack_unknown)?)
        }
        Op::BindingsReceiver => match decode::<ReceiverArgs>(args)? {
            ReceiverArgs::Telegram { token } => Request::BindingsReceiver(
                ChannelSecret::telegram(token).ok_or(DaemonError::InvalidRequest)?,
            ),
            // The Feishu receiver arrives with a later task; its syntax is accepted and refused.
            ReceiverArgs::Feishu { .. } => return Err(DaemonError::ChannelNotSupported),
        },
        Op::BindingsHost => {
            let args: HostArgs = decode(args)?;
            Request::BindingsHost(args.workspace, run_deadline(args.run_deadline)?)
        }
        Op::Approve => Request::Decide(
            key(&decode::<PermissionArgs>(args)?.permission_id)?,
            Decision::Allow,
        ),
        Op::Deny => Request::Decide(
            key(&decode::<PermissionArgs>(args)?.permission_id)?,
            Decision::Deny,
        ),
        Op::Cancel => Request::Cancel(key(&decode::<RunArgs>(args)?.run_id)?),
    })
}

/// A Bot token parsed once at the boundary: `<decimal bot_id>:<non-empty rest>`.
pub(crate) struct ChannelSecret {
    bot_id: String,
    token: SecretBytes,
}
impl fmt::Debug for ChannelSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl ChannelSecret {
    pub(crate) fn telegram(token: String) -> Option<ChannelSecret> {
        let (bot_id, rest) = token.split_once(':')?;
        let valid = !bot_id.is_empty()
            && bot_id.len() <= KEY_MAX
            && bot_id.bytes().all(|b| b.is_ascii_digit())
            && !rest.is_empty();
        let bot_id = valid.then(|| bot_id.to_owned())?;
        Some(ChannelSecret {
            bot_id,
            token: SecretBytes::new(token.into_bytes()),
        })
    }
    pub(crate) fn bot_id(&self) -> &str {
        &self.bot_id
    }
    pub(crate) fn token(&self) -> &SecretBytes {
        &self.token
    }
}

/// A runtime receiver change the daemon's main loop performs; each carries its receipt.
pub(crate) enum ReceiverCommand {
    Start(ReceiverRow, oneshot::Sender<Result<(), DaemonError>>),
    Stop(Uuid, oneshot::Sender<()>),
}

/// A store failure after the operation's deadline is the request timeout.
pub(crate) fn store_error(error: StoreError, deadline: Instant) -> DaemonError {
    match error {
        StoreError::BindingFailed | StoreError::EventFailed | StoreError::HostSessionFailed
            if Instant::now() >= deadline =>
        {
            DaemonError::RequestTimeout
        }
        other => pg::map_store_error(other),
    }
}
async fn execute(
    application: &dyn ApplicationService,
    resolver: &SingleUserAuthResolver,
    command: AppCommand,
) -> Result<AppReply, AppError> {
    application
        .execute(resolver.local_context()?, command)
        .await
}
async fn cancel_run(
    application: &dyn ApplicationService,
    resolver: &SingleUserAuthResolver,
    thread_id: &str,
    run_id: &str,
) -> Result<&'static str, DaemonError> {
    let command = AppCommand::CancelThreadRun(CancelThreadRun {
        thread_id: ThreadId::new(thread_id),
        run_id: RunId::new(run_id),
    });
    match execute(application, resolver, command).await {
        Ok(AppReply::ThreadRunCancellation(cancellation)) => Ok(match cancellation.state {
            ThreadRunCancellationState::Requested => "requested",
            ThreadRunCancellationState::AlreadyRequested => "already_requested",
            ThreadRunCancellationState::AlreadyTerminal => "already_terminal",
        }),
        _ => Err(DaemonError::InternalError),
    }
}
fn optional_time(unix_nanos: Option<i128>) -> Result<Option<String>, DaemonError> {
    unix_nanos.map(rfc3339_utc).transpose()
}

/// The resources the control operations run on; operations are serialized by the connection lock.
pub(crate) struct Ops {
    pub(crate) control: Mutex<tokio_postgres::Client>,
    pub(crate) application: Arc<dyn ApplicationService>,
    pub(crate) resolver: SingleUserAuthResolver,
    pub(crate) vault: CredentialRecordVault,
    pub(crate) owner: ActorId,
    pub(crate) roots: WorkspaceRoots,
    pub(crate) endpoint: TelegramEndpoint,
    pub(crate) receiver: mpsc::Sender<ReceiverCommand>,
}
impl Ops {
    pub(crate) async fn run(
        &self,
        op: Op,
        args: Value,
        deadline: Instant,
        token_id: Uuid,
    ) -> Result<Value, DaemonError> {
        let failed = |error| store_error(error, deadline);
        match parse(op, args)? {
            Request::StatusRun(run_id) => self.status_run(&run_id, deadline).await,
            Request::PairStart(request) => {
                let mut client = self.control.lock().await;
                let started = pairing::pair(
                    &mut client,
                    self.application.as_ref(),
                    &self.resolver,
                    &self.roots,
                    request,
                    deadline,
                )
                .await?;
                Ok(
                    json!({"binding_id": started.binding_id.to_string(), "code": started.code.display(), "expires_at": rfc3339_utc(started.expires_at.unix_timestamp_nanos())?}),
                )
            }
            Request::BindingsList => {
                let views = omb_store::list_bindings(&*self.control.lock().await, deadline)
                    .await
                    .map_err(failed)?;
                let bindings = views
                    .into_iter()
                    .map(|view| {
                        Ok(json!({
                            "binding_id": view.binding_id.to_string(),
                            "binding_kind": view.binding_kind,
                            "channel_kind": view.channel_kind,
                            "source_key": view.source_key,
                            "sender_key": view.sender_key,
                            "status": view.status,
                            "status_reason": view.status_reason,
                            "revision": view.revision,
                            "thread_generation": view.thread_generation,
                            "workspace_dir": view.workspace_dir,
                            "thread_id": view.thread_id,
                            "run_deadline_seconds": view.run_deadline_seconds,
                            "created_at": rfc3339_utc(view.created_at.unix_timestamp_nanos())?,
                            "activated_at": optional_time(view.activated_at.map(|at| at.unix_timestamp_nanos()))?,
                            "suspended_at": optional_time(view.suspended_at.map(|at| at.unix_timestamp_nanos()))?,
                            "reconfirmed_at": optional_time(view.reconfirmed_at.map(|at| at.unix_timestamp_nanos()))?,
                        }))
                    })
                    .collect::<Result<Vec<_>, DaemonError>>()?;
                Ok(json!({ "bindings": bindings }))
            }
            Request::BindingsRevoke(binding_id) => {
                let runs = {
                    let mut client = self.control.lock().await;
                    let runs = omb_store::revoke_binding(&mut client, binding_id, deadline)
                        .await
                        .map_err(failed)?;
                    self.command(|done| ReceiverCommand::Stop(binding_id, done), deadline)
                        .await?;
                    runs
                };
                self.cancel_all(&runs).await?;
                Ok(json!({"binding_id": binding_id.to_string(), "cancelled_runs": runs.len()}))
            }
            Request::BindingsReconfirm(binding_id) => {
                let receiver =
                    omb_store::receiver_row(&*self.control.lock().await, binding_id, deadline)
                        .await
                        .map_err(failed)?;
                let revision = match receiver {
                    Some(row) => {
                        let token = self
                            .vault
                            .open(
                                &row.binding_id,
                                SecretKind::Connector,
                                SecretPrincipal::Actor(self.owner.clone()),
                                SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                                &row.credential_envelope,
                            )
                            .map_err(|_| DaemonError::CredentialRejected)?
                            .into_secret();
                        self.verify(&token, &row.source_key, deadline).await?;
                        let generation = self.generation()?;
                        let mut client = self.control.lock().await;
                        let revision = omb_store::reconfirm_binding(
                            &mut client,
                            binding_id,
                            generation,
                            deadline,
                        )
                        .await
                        .map_err(failed)?;
                        self.command(|done| ReceiverCommand::Start(row, done), deadline)
                            .await??;
                        revision
                    }
                    None => {
                        let generation = self.generation()?;
                        omb_store::reconfirm_binding(
                            &mut *self.control.lock().await,
                            binding_id,
                            generation,
                            deadline,
                        )
                        .await
                        .map_err(failed)?
                    }
                };
                Ok(json!({"binding_id": binding_id.to_string(), "revision": revision}))
            }
            Request::BindingsResetThread(binding_id, ack) => {
                let AppReply::ThreadMinted(minted) = execute(
                    self.application.as_ref(),
                    &self.resolver,
                    AppCommand::MintThreadId,
                )
                .await
                .map_err(|_| DaemonError::InternalError)?
                else {
                    return Err(DaemonError::InternalError);
                };
                let done = omb_store::reset_thread(
                    &mut *self.control.lock().await,
                    binding_id,
                    ack.as_str(),
                    minted.thread_id.as_str(),
                    deadline,
                )
                .await
                .map_err(failed)?;
                Ok(
                    json!({"binding_id": binding_id.to_string(), "thread_generation": done.thread_generation, "revision": done.revision}),
                )
            }
            Request::BindingsReceiver(secret) => {
                self.verify(secret.token(), secret.bot_id(), deadline)
                    .await?;
                let binding_id = Uuid::now_v7();
                let envelope = self
                    .vault
                    .seal(
                        &binding_id,
                        SecretKind::Connector,
                        SecretPrincipal::Actor(self.owner.clone()),
                        SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                        secret.token(),
                    )
                    .map_err(|_| DaemonError::InternalError)?;
                let runs = {
                    let mut client = self.control.lock().await;
                    let runs = omb_store::activate_receiver(
                        &mut client,
                        NewReceiver {
                            binding_id,
                            channel: Channel::Telegram,
                            source_key: secret.bot_id(),
                            credential_envelope: &envelope,
                        },
                        deadline,
                    )
                    .await
                    .map_err(failed)?;
                    let row = ReceiverRow {
                        binding_id,
                        source_key: secret.bot_id().to_owned(),
                        credential_envelope: envelope,
                    };
                    self.command(|done| ReceiverCommand::Start(row, done), deadline)
                        .await??;
                    runs
                };
                self.cancel_all(&runs).await?;
                Ok(json!({"binding_id": binding_id.to_string(), "source_key": secret.bot_id()}))
            }
            Request::BindingsHost(workspace, run_deadline) => {
                let workspace = self
                    .roots
                    .resolve(&workspace)
                    .filter(|workspace| workspace.is_dir())
                    .ok_or(DaemonError::WorkspaceInvalid)?;
                let workspace_dir = workspace.to_str().ok_or(DaemonError::WorkspaceInvalid)?;
                let granted_generation = self.generation()?;
                let binding_id = omb_store::activate_host(
                    &mut *self.control.lock().await,
                    HostBinding {
                        workspace_dir,
                        granted_generation,
                        run_deadline,
                    },
                    deadline,
                )
                .await
                .map_err(failed)?;
                Ok(json!({"binding_id": binding_id.to_string()}))
            }
            Request::Decide(permission_id, decision) => {
                let decided = omb_store::decide_permission(
                    &*self.control.lock().await,
                    permission_id.as_str(),
                    decision,
                    token_id,
                    deadline,
                )
                .await
                .map_err(failed)?;
                match decided {
                    Decided::Decided => Ok(json!({
                        "permission_id": permission_id.as_str(),
                        "decision": match decision {
                            Decision::Allow => "allow",
                            Decision::Deny => "deny",
                        },
                    })),
                    Decided::NotPending => Err(DaemonError::PermissionNotPending),
                    Decided::Expired => Err(DaemonError::PermissionExpired),
                }
            }
            Request::Cancel(run_id) => {
                let facts =
                    omb_store::run_facts(&*self.control.lock().await, run_id.as_str(), deadline)
                        .await
                        .map_err(failed)?
                        .filter(|facts| facts.dispatch_status == "dispatched")
                        .ok_or(DaemonError::RunNotFound)?;
                let state = cancel_run(
                    self.application.as_ref(),
                    &self.resolver,
                    &facts.thread_id,
                    run_id.as_str(),
                )
                .await?;
                Ok(json!({"run_id": run_id.as_str(), "state": state}))
            }
        }
    }
    async fn status_run(
        &self,
        run_id: &IdentityKey,
        deadline: Instant,
    ) -> Result<Value, DaemonError> {
        let facts = omb_store::run_facts(&*self.control.lock().await, run_id.as_str(), deadline)
            .await
            .map_err(|error| store_error(error, deadline))?
            .ok_or(DaemonError::RunNotFound)?;
        let (known, state) = if facts.dispatch_status == "dispatched" {
            let thread_id = ThreadId::new(&facts.thread_id);
            let status = AppCommand::GetThreadStatus {
                thread_id: thread_id.clone(),
            };
            let known = match execute(self.application.as_ref(), &self.resolver, status).await {
                Ok(AppReply::ThreadStatus(status)) => status.known,
                Err(AppError::DependencyUnavailable { .. }) => false,
                _ => return Err(DaemonError::InternalError),
            };
            let conversation = AppCommand::GetThreadConversation { thread_id };
            let state = match execute(self.application.as_ref(), &self.resolver, conversation).await
            {
                Ok(AppReply::ThreadConversation(snapshot)) => {
                    match (snapshot.active_run_id, snapshot.active_run_state) {
                        (Some(active), Some(state)) if active.as_str() == run_id.as_str() => {
                            match state {
                                ThreadForegroundRunState::Queued => "queued",
                                ThreadForegroundRunState::Running => "running",
                                ThreadForegroundRunState::Cancelling => "cancelling",
                                ThreadForegroundRunState::ReconciliationRequired => {
                                    "reconciliation_required"
                                }
                            }
                        }
                        _ => "none",
                    }
                }
                Err(AppError::DependencyUnavailable { .. }) => "unavailable",
                _ => return Err(DaemonError::InternalError),
            };
            (known, state)
        } else {
            (false, "none")
        };
        let session = facts
            .session
            .map(|session| {
                Ok(json!({
                    "end_reason": session.end_reason,
                    "stop_outcome": session.stop_outcome,
                    "exit_code": session.exit_code,
                    "exit_signal": session.exit_signal,
                    "started_at": rfc3339_utc(session.started_at.unix_timestamp_nanos())?,
                    "ended_at": optional_time(session.ended_at.map(|at| at.unix_timestamp_nanos()))?,
                }))
            })
            .transpose()?;
        let permissions = facts
            .permissions
            .into_iter()
            .map(|permission| {
                Ok(json!({
                    "permission_id": permission.permission_id,
                    "tool_name": permission.tool_name,
                    "input_summary": permission.input_summary,
                    "requested_at": rfc3339_utc(permission.requested_at.unix_timestamp_nanos())?,
                    "expires_at": rfc3339_utc(permission.expires_at.unix_timestamp_nanos())?,
                    "decision": permission.decision,
                    "decided_via": permission.decided_via,
                }))
            })
            .collect::<Result<Vec<_>, DaemonError>>()?;
        Ok(json!({
            "run_id": run_id.as_str(),
            "binding_id": facts.binding_id.to_string(),
            "binding_kind": match facts.kind {
                GrantKind::Sender => "sender",
                GrantKind::Host => "host",
            },
            "thread_id": facts.thread_id,
            "dispatch_status": facts.dispatch_status,
            "terminal_kind": facts.terminal_kind,
            "engine": {"known": known, "state": state},
            "session": session,
            "permissions": permissions,
        }))
    }
    fn generation(&self) -> Result<u64, DaemonError> {
        Ok(self
            .resolver
            .local_context()
            .map_err(|_| DaemonError::InternalError)?
            .auth_generation()
            .get())
    }
    /// Bind-time credential check within the operation's deadline.
    async fn verify(
        &self,
        token: &SecretBytes,
        bot_id: &str,
        deadline: Instant,
    ) -> Result<(), DaemonError> {
        match timeout_at(deadline, verify_credentials(&self.endpoint, token, bot_id)).await {
            Err(_) => Err(DaemonError::RequestTimeout),
            Ok(Ok(())) => Ok(()),
            Ok(Err(CredentialProblem::CredentialRejected)) => Err(DaemonError::CredentialRejected),
            Ok(Err(CredentialProblem::WebhookConflict)) => Err(DaemonError::WebhookConflict),
            Ok(Err(CredentialProblem::Unreachable)) => Err(DaemonError::ChannelUnreachable),
        }
    }
    /// Hands a receiver change to the main loop and waits for its receipt within the deadline.
    async fn command<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> ReceiverCommand,
        deadline: Instant,
    ) -> Result<T, DaemonError> {
        let (done, receipt) = oneshot::channel();
        timeout_at(deadline, async {
            self.receiver
                .send(command(done))
                .await
                .map_err(|_| DaemonError::InternalError)?;
            receipt.await.map_err(|_| DaemonError::InternalError)
        })
        .await
        .map_err(|_| DaemonError::RequestTimeout)?
    }
    /// Cancels the runs of bindings that already ended; the first engine refusal is reported.
    async fn cancel_all(&self, runs: &[OpenRun]) -> Result<(), DaemonError> {
        for run in runs {
            cancel_run(
                self.application.as_ref(),
                &self.resolver,
                &run.thread_id,
                &run.run_id,
            )
            .await?;
        }
        Ok(())
    }
}

/// The narrow handle behind channel `/cancel`: cancels only the named binding's own open run.
pub(crate) struct BindingRunCanceller {
    task: JoinHandle<()>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl BindingRunCanceller {
    pub(crate) fn start(
        application: Arc<dyn ApplicationService>,
        resolver: SingleUserAuthResolver,
        connection: AuthorityConnection,
        mut requests: mpsc::Receiver<Uuid>,
    ) -> Self {
        let client = connection.client;
        let task = tokio::spawn(async move {
            while let Some(binding_id) = requests.recv().await {
                // Any failure drops this request; the owner can send `/cancel` again.
                if let Ok(Some(run)) = omb_store::open_run(&client, binding_id).await {
                    let _ =
                        cancel_run(application.as_ref(), &resolver, &run.thread_id, &run.run_id)
                            .await;
                }
            }
        });
        Self {
            task,
            driver: connection.driver,
        }
    }
    /// Joins the task once every request sender is gone, then the connection it owned.
    pub(crate) async fn stop(self) {
        let _ = self.task.await;
        let _ = self.driver.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent::{
            AgentRuntime,
            tests::{self as agent, Run},
        },
        channels::Channels,
        delegation::{
            BOT_ID,
            fixture::{self, Fixture},
        },
    };
    use omb_channels::{CANCEL_QUEUE, Timings, testkit::FakeTelegram};
    use omb_hostdriver::{HostDriverConfig, Limits, OMB_NOTICE_PERMISSION_V1};
    use omb_store::{Claim, Suspension, testkit};
    use openbot_application::{BeginDelegatedThreadRun, DelegatedUntrustedMaterial};
    use openbot_contracts::{
        auth::DelegationSource,
        command::{AppEvent, SubscriptionRequest, ThreadRunEventKind},
        ids::{BotId, thread::ThreadIdentity},
        reconciliation::RunReconciliationStatus,
    };
    use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
    use std::{path::Path, time::Duration};
    use tokio_postgres::Client;

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn invalid(op: &str, args: Value) -> bool {
        matches!(
            parse(Op::parse(op).unwrap(), args),
            Err(DaemonError::InvalidRequest)
        )
    }

    #[test]
    fn args_types_reject_unknown_fields_missing_fields_and_wrong_types() {
        let id = Uuid::now_v7().to_string();
        for (op, valid, rejected) in [
            (
                "status_run",
                json!({"run_id": "r1"}),
                vec![
                    json!({}),
                    json!({"run_id": "r1", "x": 1}),
                    json!({"run_id": 1}),
                ],
            ),
            (
                "pair_start",
                json!({"channel": "telegram", "workspace": "/ws", "run_deadline": 60}),
                vec![
                    json!({"workspace": "/ws"}),
                    json!({"channel": "telegram"}),
                    json!({"channel": "telegram", "workspace": "/ws", "x": 1}),
                    json!({"channel": 1, "workspace": "/ws"}),
                    json!({"channel": "telegram", "workspace": "/ws", "run_deadline": "60"}),
                    json!({"channel": "slack", "workspace": "/ws"}),
                ],
            ),
            (
                "bindings_list",
                json!({}),
                vec![json!({"x": 1}), json!("x"), json!(null)],
            ),
            (
                "bindings_revoke",
                json!({"binding_id": id}),
                vec![
                    json!({}),
                    json!({"binding_id": 1}),
                    json!({"binding_id": id, "x": 1}),
                ],
            ),
            (
                "bindings_reconfirm",
                json!({"binding_id": id}),
                vec![
                    json!({}),
                    json!({"binding_id": true}),
                    json!({"binding_id": id, "x": 1}),
                ],
            ),
            (
                "bindings_reset_thread",
                json!({"binding_id": id, "ack_unknown": "r1"}),
                vec![
                    json!({"binding_id": id}),
                    json!({"ack_unknown": "r1"}),
                    json!({"binding_id": id, "ack_unknown": 1}),
                    json!({"binding_id": id, "ack_unknown": "r1", "x": 1}),
                ],
            ),
            (
                "bindings_receiver",
                json!({"channel": "telegram", "token": "1:x"}),
                vec![
                    json!({}),
                    json!({"token": "1:x"}),
                    json!({"channel": "telegram"}),
                    json!({"channel": "telegram", "token": 1}),
                    json!({"channel": "telegram", "token": "1:x", "x": 1}),
                    json!({"channel": "slack", "token": "1:x"}),
                    json!({"channel": "feishu", "app_id": "a"}),
                ],
            ),
            (
                "bindings_host",
                json!({"workspace": "/ws"}),
                vec![
                    json!({}),
                    json!({"workspace": 1}),
                    json!({"workspace": "/ws", "run_deadline": -1}),
                    json!({"workspace": "/ws", "x": 1}),
                ],
            ),
            (
                "approve",
                json!({"permission_id": "hp1"}),
                vec![
                    json!({}),
                    json!({"permission_id": 1}),
                    json!({"permission_id": "hp1", "x": 1}),
                ],
            ),
            (
                "deny",
                json!({"permission_id": "hp1"}),
                vec![
                    json!({}),
                    json!({"permission_id": null}),
                    json!({"permission_id": "hp1", "x": 1}),
                ],
            ),
            (
                "cancel",
                json!({"run_id": "r1"}),
                vec![
                    json!({}),
                    json!({"run_id": []}),
                    json!({"run_id": "r1", "x": 1}),
                ],
            ),
        ] {
            assert!(parse(Op::parse(op).unwrap(), valid).is_ok(), "{op}");
            for args in rejected {
                assert!(invalid(op, args.clone()), "{op} {args}");
            }
        }
        // Feishu's syntax is accepted and refused as unsupported.
        assert!(matches!(
            parse(
                Op::BindingsReceiver,
                json!({"channel": "feishu", "app_id": "a", "app_secret": "s"})
            ),
            Err(DaemonError::ChannelNotSupported)
        ));
    }

    #[test]
    fn ids_parse_once_at_the_boundary() {
        let id = Uuid::now_v7().to_string();
        for op in ["bindings_revoke", "bindings_reconfirm"] {
            for text in ["not-a-uuid", "", "1234"] {
                assert!(invalid(op, json!({"binding_id": text})), "{op} {text}");
            }
        }
        assert!(invalid(
            "bindings_reset_thread",
            json!({"binding_id": "x", "ack_unknown": "r1"})
        ));
        let long = "x".repeat(129);
        for text in ["", "é", "run\u{7f}", long.as_str()] {
            assert!(invalid("approve", json!({"permission_id": text})), "{text}");
            assert!(invalid("deny", json!({"permission_id": text})), "{text}");
            assert!(invalid("status_run", json!({"run_id": text})), "{text}");
            assert!(invalid("cancel", json!({"run_id": text})), "{text}");
            assert!(
                invalid(
                    "bindings_reset_thread",
                    json!({"binding_id": id, "ack_unknown": text})
                ),
                "{text}"
            );
        }
        let max = "x".repeat(128);
        assert!(matches!(
            parse(Op::Approve, json!({"permission_id": max})),
            Ok(Request::Decide(..))
        ));
    }

    #[test]
    fn channel_secret_debug_is_redacted() {
        let secret = ChannelSecret::telegram("123456:SENTINEL-debug".into()).unwrap();
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret:#?}"), "[REDACTED]");
        assert_eq!(secret.bot_id(), "123456");
        assert_eq!(secret.token().expose(), b"123456:SENTINEL-debug");
    }

    #[test]
    fn bot_token_requires_decimal_bot_id_non_empty_rest_and_bot_id_within_key_max() {
        let long = format!("{}:rest", "1".repeat(129));
        for token in [
            "123456",
            "abc:rest",
            "12a:rest",
            ":rest",
            "123456:",
            "-1:rest",
            long.as_str(),
        ] {
            assert!(ChannelSecret::telegram(token.into()).is_none(), "{token}");
        }
        let max = format!("{}:rest", "1".repeat(128));
        assert_eq!(
            ChannelSecret::telegram(max).unwrap().bot_id(),
            "1".repeat(128)
        );
        assert_eq!(
            ChannelSecret::telegram("42:a:b".into()).unwrap().bot_id(),
            "42"
        );
    }

    #[test]
    fn past_deadline_store_failures_map_to_request_timeout_and_refusals_pass_through() {
        let past = Instant::now() - Duration::from_millis(1);
        for error in [
            StoreError::BindingFailed,
            StoreError::EventFailed,
            StoreError::HostSessionFailed,
        ] {
            assert_eq!(store_error(error, past), DaemonError::RequestTimeout);
        }
        for (error, mapped) in [
            (StoreError::BindingFailed, DaemonError::BindingFailed),
            (StoreError::EventFailed, DaemonError::InternalError),
            (StoreError::HostSessionFailed, DaemonError::InternalError),
        ] {
            assert_eq!(store_error(error, later()), mapped);
        }
        for (error, mapped) in [
            (StoreError::BindingNotFound, DaemonError::BindingNotFound),
            (
                StoreError::BindingStateInvalid,
                DaemonError::BindingStateInvalid,
            ),
            (
                StoreError::ChannelAlreadyBound,
                DaemonError::ChannelAlreadyBound,
            ),
            (
                StoreError::ReceiverNotActive,
                DaemonError::ReceiverNotActive,
            ),
        ] {
            assert_eq!(store_error(error, past), mapped);
            assert_eq!(store_error(error, later()), mapped);
        }
    }

    #[test]
    fn permission_notice_names_the_cli_commands() {
        for prefix in ["openmybot approve ", "openmybot deny "] {
            let at = OMB_NOTICE_PERMISSION_V1.find(prefix).unwrap();
            let word = prefix.trim_start_matches("openmybot ").trim_end();
            assert!(Op::parse(word).is_some(), "{word}");
            assert!(OMB_NOTICE_PERMISSION_V1[at + prefix.len()..].starts_with("{id}"));
        }
    }

    // ---- Real PostgreSQL cases --------------------------------------------------------------

    const TEXT: &str = "test message";
    fn quick_channels() -> Timings {
        Timings {
            heartbeat: Duration::from_millis(100),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            dispatch_retry: Duration::from_millis(100),
            ..Timings::default()
        }
    }
    /// A host on the root's `home/ws` whose fake asks one `Write` permission for `approved.txt`.
    fn asking(root: &Path) -> HostDriverConfig {
        agent::host(
            root,
            "permission",
            agent::quick(),
            &[(
                "FAKE_CRABCODE_INPUT",
                r#"{"file_path":"approved.txt","content":"data"}"#,
            )],
        )
    }
    fn expiring(root: &Path) -> HostDriverConfig {
        agent::host(
            root,
            "permission",
            Limits {
                permission_ttl: Duration::from_secs(1),
                ..agent::quick()
            },
            &[(
                "FAKE_CRABCODE_INPUT",
                r#"{"file_path":"approved.txt","content":"data"}"#,
            )],
        )
    }
    fn happy(root: &Path) -> HostDriverConfig {
        agent::host(root, "happy", agent::quick(), &[])
    }

    /// `Ops` over the fixture's engine, a `FakeTelegram` endpoint and a temporary `HOME` with one
    /// workspace root `home/ws` under it; the test serves the receiver commands itself.
    struct Env {
        fixture: Fixture,
        ops: Ops,
        commands: mpsc::Receiver<ReceiverCommand>,
        channels: Option<Channels>,
        runtime: Option<AgentRuntime>,
        control_link: JoinHandle<Result<(), tokio_postgres::Error>>,
        client: Client,
        token: Uuid,
        fake: FakeTelegram,
    }
    impl Env {
        async fn new(mut fixture: Fixture) -> Self {
            let home = fixture.root.join("home");
            let workspace = home.join("ws");
            std::fs::create_dir_all(&workspace).unwrap();
            let token = Uuid::now_v7();
            let mut digest = [0; 32];
            digest[..16].copy_from_slice(token.as_bytes());
            fixture
                .pg
                .start_control_token(omb_store::ControlTokenStart {
                    token_id: token,
                    token_sha256: digest,
                    daemon_pid: 1,
                    engine_pin: "0123456789abcdef0123456789abcdef01234567",
                    omb_version: "0.0.0",
                })
                .await
                .unwrap();
            let control = fixture
                .pg
                .open_resident_connection("openmybot-control")
                .await
                .unwrap();
            let client = fixture.client().await;
            let fake = FakeTelegram::start().await;
            let (receiver, commands) = mpsc::channel(8);
            let engine = fixture.engine();
            let ops = Ops {
                control: Mutex::new(control.client),
                application: engine.assembly.application.clone(),
                resolver: engine.resolver.clone(),
                vault: engine.vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                roots: WorkspaceRoots::parse(&home, &[workspace]).unwrap(),
                endpoint: fake.endpoint(),
                receiver,
            };
            Self {
                fixture,
                ops,
                commands,
                channels: None,
                runtime: None,
                control_link: control.driver,
                client,
                token,
                fake,
            }
        }
        async fn start() -> Self {
            Self::new(Fixture::start().await).await
        }
        /// Like `new`, with the fixture's Agent runtime executing delegated runs.
        async fn running(fixture: Fixture) -> Self {
            let mut env = Self::new(fixture).await;
            env.runtime = Some(
                AgentRuntime::start(env.fixture.engine(), env.fixture.pg.database_config())
                    .unwrap(),
            );
            env
        }
        /// Like `start`, with the daemon's channel tasks serving the receiver commands.
        async fn with_channels() -> Self {
            let mut env = Self::start().await;
            let (cancel, _) = mpsc::channel(CANCEL_QUEUE);
            env.channels = Some(
                Channels::start(
                    &mut env.fixture.pg,
                    env.fixture.engine.as_ref().unwrap(),
                    env.token,
                    quick_channels(),
                    env.fake.endpoint(),
                    cancel,
                )
                .await
                .unwrap(),
            );
            env
        }
        fn workspace(&self) -> String {
            self.fixture
                .root
                .join("home/ws")
                .to_str()
                .unwrap()
                .to_owned()
        }
        /// Runs one operation, serving the receiver commands it sends meanwhile.
        async fn call_until(
            &mut self,
            op: &str,
            args: Value,
            deadline: Instant,
        ) -> Result<Value, DaemonError> {
            let run = self
                .ops
                .run(Op::parse(op).unwrap(), args, deadline, self.token);
            tokio::pin!(run);
            loop {
                tokio::select! {
                    result = &mut run => return result,
                    Some(command) = self.commands.recv() => match command {
                        ReceiverCommand::Start(row, done) => {
                            let started = match self.channels.as_mut() {
                                Some(channels) => channels.start_receiver(&mut self.fixture.pg, row).await,
                                None => Ok(()),
                            };
                            let _ = done.send(started);
                        }
                        ReceiverCommand::Stop(binding_id, done) => {
                            if let Some(channels) = self.channels.as_mut() {
                                channels.stop_receiver(binding_id).await;
                            }
                            let _ = done.send(());
                        }
                    },
                }
            }
        }
        async fn call(&mut self, op: &str, args: Value) -> Result<Value, DaemonError> {
            self.call_until(op, args, later()).await
        }
        fn generation(&self) -> u64 {
            self.ops.generation().unwrap()
        }
        async fn minted(&self) -> ThreadId {
            let AppReply::ThreadMinted(minted) = execute(
                self.ops.application.as_ref(),
                &self.ops.resolver,
                AppCommand::MintThreadId,
            )
            .await
            .unwrap() else {
                panic!("mint reply");
            };
            minted.thread_id
        }
        /// An active Telegram sender on receiver source `1001` with a freshly minted thread.
        async fn sender(&self) -> (Uuid, ThreadId) {
            self.sender_on("telegram").await
        }
        /// Like `sender`, on `channel` (one live sender per channel).
        async fn sender_on(&self, channel: &str) -> (Uuid, ThreadId) {
            let thread = self.minted().await;
            let binding = Uuid::now_v7();
            let generation = i64::try_from(self.generation()).unwrap();
            self.client.execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,chat_key,workspace_dir,thread_id,granted_generation,revision,status,created_at,activated_at) VALUES ($1,'sender',$5,'1001','telegram:42','telegram:42',$2,$3,$4,1,'active',statement_timestamp(),statement_timestamp())", &[&binding, &self.workspace(), &thread.as_str(), &generation, &channel]).await.unwrap();
            (binding, thread)
        }
        /// A dispatched accepted message of the binding, begun through the delegated entry.
        async fn begun(&self, binding: Uuid, thread: &ThreadId) -> Run {
            let run = format!("run-{}", Uuid::now_v7());
            let record = dispatched(&self.client, binding, &run, thread.as_str()).await;
            self.fixture
                .engine()
                .assembly
                .delegated_entry
                .clone()
                .unwrap()
                .begin(BeginDelegatedThreadRun {
                    source: DelegationSource::ExternalBinding {
                        binding_id: binding.to_string(),
                    },
                    revision: 1,
                    trigger_id: record.to_string(),
                    thread_id: thread.clone(),
                    run_id: RunId::new(&run),
                    bot_id: BotId::new(BOT_ID),
                    untrusted_material: Some(DelegatedUntrustedMaterial {
                        source_ref: format!("omb:channel_events:{record}"),
                        text: TEXT.into(),
                    }),
                })
                .await
                .unwrap();
            Run {
                thread: thread.clone(),
                run: RunId::new(&run),
            }
        }
        /// The engine's answer to cancelling `run` directly under the local context.
        async fn cancel_state(&self, run: &Run) -> &'static str {
            cancel_run(
                self.ops.application.as_ref(),
                &self.ops.resolver,
                run.thread.as_str(),
                run.run.as_str(),
            )
            .await
            .unwrap()
        }
        async fn binding(&self, id: Uuid) -> Value {
            testkit::read_row(&self.client, "channel_bindings", "binding_id", id).await
        }
        /// Every channel and host-session row as one sorted JSON text.
        async fn rows(&self) -> String {
            let mut all = String::new();
            for table in ["channel_bindings", "channel_events", "host_driver_sessions"] {
                let text: String = self
                    .client
                    .query_one(
                        &format!("SELECT coalesce(string_agg(row_to_json(x)::text, ',' ORDER BY row_to_json(x)::text), '') FROM openmybot.{table} x"),
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                all.push_str(&text);
            }
            all
        }
        async fn permission_of(&self, run: &RunId) -> String {
            let limit = Instant::now() + Duration::from_secs(90);
            loop {
                let found = self.client.query("SELECT permission_id FROM openmybot.host_driver_sessions WHERE record_kind='permission' AND run_id=$1", &[&run.as_str()]).await.unwrap();
                if let Some(row) = found.first() {
                    return row.get(0);
                }
                assert!(Instant::now() < limit, "permission request deadline");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        /// Scripts a successful bind-time check for bot `bot_id`.
        fn verified(&self, bot_id: u64) {
            self.fake.script(
                "getMe",
                200,
                serde_json::to_vec(&json!({"ok": true, "result": {"id": bot_id, "is_bot": true, "first_name": "Bot", "username": "bot"}})).unwrap(),
            );
            self.fake.script(
                "getWebhookInfo",
                200,
                br#"{"ok":true,"result":{"url":"","pending_update_count":0}}"#.to_vec(),
            );
        }
        async fn stop(self) {
            if let Some(channels) = self.channels {
                channels.stop().await;
            }
            if let Some(runtime) = self.runtime {
                runtime.stop().await;
            }
            drop(self.ops);
            self.control_link.abort();
            let _ = self.control_link.await;
            drop(self.client);
            self.fixture.stop().await;
        }
    }
    async fn dispatched(client: &Client, binding: Uuid, run: &str, thread: &str) -> Uuid {
        let record =
            testkit::insert_event_for_run(client, binding, run, thread, "dispatched").await;
        testkit::shift_event(client, record, "dispatched_at", 0.0).await;
        record
    }
    async fn permission(client: &Client, permission_id: &str) -> Value {
        testkit::permission_row_json(client, permission_id).await
    }
    fn rfc3339(value: &Value) -> bool {
        value.as_str().is_some_and(|text| {
            text.len() >= 20 && text.as_bytes()[10] == b'T' && text.ends_with('Z')
        })
    }
    async fn polls_with(fake: &FakeTelegram, token: &str) {
        let path = format!("/bot{token}/getUpdates");
        let limit = Instant::now() + Duration::from_secs(10);
        while !fake
            .calls("getUpdates")
            .iter()
            .any(|request| request.path == path)
        {
            assert!(Instant::now() < limit, "no poll with {token}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn host_binding(env: &Env) -> Uuid {
        testkit::insert_host_binding(&env.client, &env.workspace()).await
    }
    async fn run_events_terminal(env: &Env, run: &Run) -> Option<ThreadRunEventKind> {
        let local = env.ops.resolver.local_context().unwrap();
        let mut events = env
            .ops
            .application
            .subscribe(
                local,
                SubscriptionRequest::ThreadEvents {
                    thread_id: run.thread.clone(),
                    after_event_sequence: None,
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match std::future::poll_fn(|cx| events.as_mut().poll_next(cx)).await {
                    Some(AppEvent::ThreadRunEvent(event))
                        if event.run_id == run.run && event.terminal =>
                    {
                        return Some(event.event_type);
                    }
                    Some(_) => (),
                    None => return None,
                }
            }
        })
        .await
        .unwrap()
    }
    async fn reconciliation_required(env: &Env, run: &Run) {
        let limit = Instant::now() + Duration::from_secs(90);
        loop {
            let reply = execute(
                env.ops.application.as_ref(),
                &env.ops.resolver,
                AppCommand::GetRunReconciliation {
                    thread_id: run.thread.clone(),
                    run_id: run.run.clone(),
                    after: None,
                    limit: None,
                },
            )
            .await;
            if let Ok(AppReply::RunReconciliation(snapshot)) = reply {
                assert_eq!(
                    snapshot.status,
                    RunReconciliationStatus::ReconciliationRequired
                );
                return;
            }
            assert!(Instant::now() < limit, "reconciliation deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn stop_settled(client: &Client, run: &RunId) -> Value {
        let limit = Instant::now() + Duration::from_secs(90);
        loop {
            let row = agent::session(client, run).await;
            if !row["stop_outcome"].is_null() {
                return row;
            }
            assert!(Instant::now() < limit, "stop outcome deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    fn kill_group(row: &Value) {
        let pgid = rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap();
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn approve_writes_allow_cli_with_the_control_token_id() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        testkit::insert_permission_row(&env.client, binding, "run-88", "hp-88", 600.0).await;
        assert_eq!(
            env.call("approve", json!({"permission_id": "hp-88"}))
                .await
                .unwrap(),
            json!({"permission_id": "hp-88", "decision": "allow"})
        );
        let row = permission(&env.client, "hp-88").await;
        assert_eq!(row["decision"], "allow");
        assert_eq!(row["decided_via"], "cli");
        assert_eq!(row["decided_by_token"], env.token.to_string());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn deny_writes_deny_cli_with_the_control_token_id() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        testkit::insert_permission_row(&env.client, binding, "run-89", "hp-89", 600.0).await;
        assert_eq!(
            env.call("deny", json!({"permission_id": "hp-89"}))
                .await
                .unwrap(),
            json!({"permission_id": "hp-89", "decision": "deny"})
        );
        let row = permission(&env.client, "hp-89").await;
        assert_eq!(row["decision"], "deny");
        assert_eq!(row["decided_via"], "cli");
        assert_eq!(row["decided_by_token"], env.token.to_string());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn approve_expired_undecided_permission_is_permission_expired_and_row_unchanged() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        testkit::insert_permission_row(&env.client, binding, "run-90", "hp-90", -1.0).await;
        let before = permission(&env.client, "hp-90").await;
        for op in ["approve", "deny"] {
            assert_eq!(
                env.call(op, json!({"permission_id": "hp-90"})).await,
                Err(DaemonError::PermissionExpired)
            );
        }
        assert_eq!(permission(&env.client, "hp-90").await, before);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn approve_or_deny_decided_or_unknown_permission_is_permission_not_pending() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        testkit::insert_permission_row(&env.client, binding, "run-91", "hp-91", 600.0).await;
        env.call("deny", json!({"permission_id": "hp-91"}))
            .await
            .unwrap();
        let decided = permission(&env.client, "hp-91").await;
        for op in ["approve", "deny"] {
            for id in ["hp-91", "hp-unknown"] {
                assert_eq!(
                    env.call(op, json!({"permission_id": id})).await,
                    Err(DaemonError::PermissionNotPending),
                    "{op} {id}"
                );
            }
        }
        assert_eq!(permission(&env.client, "hp-91").await, decided);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn approve_with_invalid_permission_id_is_invalid_request() {
        let mut env = Env::start().await;
        for args in [
            json!({"permission_id": ""}),
            json!({"permission_id": "é"}),
            json!({"permission_id": "x".repeat(129)}),
            json!({}),
        ] {
            assert_eq!(
                env.call("approve", args.clone()).await,
                Err(DaemonError::InvalidRequest),
                "{args}"
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn approve_unblocks_fake_crabcode_write_and_run_ends_result_success() {
        let mut env = Env::running(Fixture::start_with_host(asking).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let id = env.permission_of(&run.run).await;
        assert_eq!(
            env.call("approve", json!({"permission_id": id}))
                .await
                .unwrap()["decision"],
            "allow"
        );
        let snapshot = agent::settled(&env.fixture, &run.thread).await;
        assert!(
            snapshot.messages.iter().any(|m| m.content == "allowed"),
            "{snapshot:?}"
        );
        assert_eq!(
            std::fs::read_to_string(env.fixture.root.join("home/ws/approved.txt")).unwrap(),
            "data"
        );
        assert_eq!(
            agent::session(&client, &run.run).await["end_reason"],
            "result_success"
        );
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn deny_gives_owner_denied_and_no_file_is_written() {
        let mut env = Env::running(Fixture::start_with_host(asking).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let id = env.permission_of(&run.run).await;
        assert_eq!(
            env.call("deny", json!({"permission_id": id}))
                .await
                .unwrap()["decision"],
            "deny"
        );
        let snapshot = agent::settled(&env.fixture, &run.thread).await;
        assert!(
            snapshot.messages.iter().any(|m| m.content == "denied"),
            "{snapshot:?}"
        );
        assert!(!env.fixture.root.join("home/ws/approved.txt").exists());
        let row = permission(&client, &id).await;
        assert_eq!(row["decision"], "deny");
        assert_eq!(row["decided_via"], "cli");
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn undecided_permission_times_out_to_deny_timeout_and_later_approve_is_not_pending() {
        let mut env = Env::running(Fixture::start_with_host(expiring).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let id = env.permission_of(&run.run).await;
        let limit = Instant::now() + Duration::from_secs(60);
        let row = loop {
            let row = permission(&client, &id).await;
            if !row["decision"].is_null() {
                break row;
            }
            assert!(Instant::now() < limit, "permission timeout deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(row["decision"], "deny");
        assert_eq!(row["decided_via"], "timeout");
        assert_eq!(
            env.call("approve", json!({"permission_id": id})).await,
            Err(DaemonError::PermissionNotPending)
        );
        agent::settled(&env.fixture, &run.thread).await;
        assert!(!env.fixture.root.join("home/ws/approved.txt").exists());
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn concurrent_approve_and_deny_have_exactly_one_winner() {
        let env = Env::start().await;
        let binding = host_binding(&env).await;
        for round in 0..10 {
            let id = format!("hp-race-{round}");
            testkit::insert_permission_row(&env.client, binding, "run-96", &id, 600.0).await;
            let (approved, denied) = tokio::join!(
                env.ops.run(
                    Op::Approve,
                    json!({"permission_id": id}),
                    later(),
                    env.token
                ),
                env.ops
                    .run(Op::Deny, json!({"permission_id": id}), later(), env.token),
            );
            let row = permission(&env.client, &id).await;
            match (approved, denied) {
                (Ok(_), Err(DaemonError::PermissionNotPending)) => {
                    assert_eq!(row["decision"], "allow")
                }
                (Err(DaemonError::PermissionNotPending), Ok(_)) => {
                    assert_eq!(row["decision"], "deny")
                }
                other => panic!("round {round}: {other:?}"),
            }
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_reports_event_session_and_pending_permission_summary() {
        let mut env = Env::running(Fixture::start_with_host(asking).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let id = env.permission_of(&run.run).await;
        let status = env
            .call("status_run", json!({"run_id": run.run.as_str()}))
            .await
            .unwrap();
        assert_eq!(status["run_id"], run.run.as_str());
        assert_eq!(status["binding_kind"], "host");
        assert_eq!(status["thread_id"], run.thread.as_str());
        assert_eq!(status["dispatch_status"], "dispatched");
        assert!(status["terminal_kind"].is_null());
        assert!(Uuid::parse_str(status["binding_id"].as_str().unwrap()).is_ok());
        let session = &status["session"];
        assert!(rfc3339(&session["started_at"]));
        assert!(session["ended_at"].is_null());
        assert!(session["end_reason"].is_null());
        let permissions = status["permissions"].as_array().unwrap();
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0]["permission_id"], id.as_str());
        assert_eq!(permissions[0]["tool_name"], "Write");
        assert!(
            permissions[0]["input_summary"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert!(rfc3339(&permissions[0]["requested_at"]));
        assert!(rfc3339(&permissions[0]["expires_at"]));
        assert!(permissions[0]["decision"].is_null());
        assert!(permissions[0]["decided_via"].is_null());
        let keys: Vec<&String> = status.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 9, "{keys:?}");
        env.call("deny", json!({"permission_id": id}))
            .await
            .unwrap();
        agent::settled(&env.fixture, &run.thread).await;
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_reports_running_state_for_the_active_run() {
        let mut env = Env::running(Fixture::start_with_host(asking).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let id = env.permission_of(&run.run).await;
        let status = env
            .call("status_run", json!({"run_id": run.run.as_str()}))
            .await
            .unwrap();
        assert_eq!(status["engine"], json!({"known": true, "state": "running"}));
        env.call("deny", json!({"permission_id": id}))
            .await
            .unwrap();
        agent::settled(&env.fixture, &run.thread).await;
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_unknown_run_is_run_not_found() {
        let mut env = Env::start().await;
        assert_eq!(
            env.call("status_run", json!({"run_id": "run-unknown"}))
                .await,
            Err(DaemonError::RunNotFound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_maps_unavailable_conversation_to_unavailable_state() {
        let mut env = Env::running(Fixture::start_with_host(agent::unconfirmable).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        agent::initialized(&client, &run.run).await;
        assert_eq!(
            env.call("cancel", json!({"run_id": run.run.as_str()}))
                .await
                .unwrap()["state"],
            "requested"
        );
        reconciliation_required(&env, &run).await;
        let status = env
            .call("status_run", json!({"run_id": run.run.as_str()}))
            .await
            .unwrap();
        assert_eq!(status["engine"]["state"], "unavailable");
        assert_eq!(status["dispatch_status"], "dispatched");
        kill_group(&agent::session(&client, &run.run).await);
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_for_pending_event_makes_no_engine_call() {
        let mut env = Env::start().await;
        let binding = testkit::insert_sender(
            &env.client,
            "telegram",
            "1001",
            "telegram:42",
            "thread-unminted",
        )
        .await;
        testkit::insert_event_for_run(
            &env.client,
            binding,
            "run-pending",
            "thread-unminted",
            "pending",
        )
        .await;
        let status = env
            .call("status_run", json!({"run_id": "run-pending"}))
            .await
            .unwrap();
        assert_eq!(status["engine"], json!({"known": false, "state": "none"}));
        assert_eq!(status["dispatch_status"], "pending");
        assert_eq!(status["binding_kind"], "sender");
        assert_eq!(status["binding_id"], binding.to_string());
        assert!(status["session"].is_null());
        assert_eq!(status["permissions"], json!([]));
        // The same thread through the engine is refused, so a call would have failed the op.
        assert!(
            execute(
                env.ops.application.as_ref(),
                &env.ops.resolver,
                AppCommand::GetThreadConversation {
                    thread_id: ThreadId::new("thread-unminted")
                }
            )
            .await
            .is_err()
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_run_output_carries_no_result_summary_stderr_tail_or_event_text() {
        let mut env = Env::running(Fixture::start_with_host(happy).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        agent::settled(&env.fixture, &run.thread).await;
        let limit = Instant::now() + Duration::from_secs(30);
        let session = loop {
            let row = agent::session(&client, &run.run).await;
            if !row["end_reason"].is_null() {
                break row;
            }
            assert!(Instant::now() < limit, "session end deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let rendered = env
            .call("status_run", json!({"run_id": run.run.as_str()}))
            .await
            .unwrap()
            .to_string();
        assert!(rendered.contains("result_success"));
        for absent in [
            "result_summary",
            "stderr_tail",
            "do the work",
            "hello from fake",
        ] {
            assert!(!rendered.contains(absent), "{absent}");
        }
        for column in ["result_summary", "stderr_tail"] {
            if let Some(text) = session[column].as_str().filter(|text| !text.is_empty()) {
                assert!(!rendered.contains(text), "{column}");
            }
        }
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_requested_then_already_requested_then_already_terminal() {
        let mut env = Env::new(Fixture::start_with_host(agent::cooperative).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        let args = json!({"run_id": run.run.as_str()});
        // No runtime yet: the cancellation stays requested until one serves it.
        assert_eq!(
            env.call("cancel", args.clone()).await.unwrap(),
            json!({"run_id": run.run.as_str(), "state": "requested"})
        );
        assert_eq!(
            env.call("cancel", args.clone()).await.unwrap()["state"],
            "already_requested"
        );
        env.runtime = Some(
            AgentRuntime::start(env.fixture.engine(), env.fixture.pg.database_config()).unwrap(),
        );
        agent::settled(&env.fixture, &run.thread).await;
        let limit = Instant::now() + Duration::from_secs(60);
        loop {
            match env.call("cancel", args.clone()).await {
                Ok(value) if value["state"] == "already_terminal" => break,
                other => assert!(Instant::now() < limit, "terminal deadline: {other:?}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_pending_or_unknown_run_is_run_not_found() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        for (run, status) in [
            ("run-pending", "pending"),
            ("run-conflict", "conflict"),
            ("run-cancelled", "cancelled"),
        ] {
            testkit::insert_event_for_run(&env.client, binding, run, "thread-x", status).await;
            assert_eq!(
                env.call("cancel", json!({"run_id": run})).await,
                Err(DaemonError::RunNotFound),
                "{status}"
            );
        }
        assert_eq!(
            env.call("cancel", json!({"run_id": "run-unknown"})).await,
            Err(DaemonError::RunNotFound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_works_for_host_binding_runs() {
        let mut env = Env::new(Fixture::start_with_host(agent::cooperative).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        assert_eq!(
            env.call("cancel", json!({"run_id": run.run.as_str()}))
                .await
                .unwrap()["state"],
            "requested"
        );
        assert_eq!(env.cancel_state(&run).await, "already_requested");
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_engine_refusal_is_internal_error() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        dispatched(&env.client, binding, "run-foreign", "thread-not-minted").await;
        assert_eq!(
            env.call("cancel", json!({"run_id": "run-foreign"})).await,
            Err(DaemonError::InternalError)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_with_confirmed_stop_ends_cancelled() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        agent::initialized(&client, &run.run).await;
        assert_eq!(
            env.call("cancel", json!({"run_id": run.run.as_str()}))
                .await
                .unwrap()["state"],
            "requested"
        );
        agent::settled(&env.fixture, &run.thread).await;
        assert_eq!(
            run_events_terminal(&env, &run).await,
            Some(ThreadRunEventKind::Cancelled)
        );
        let row = stop_settled(&client, &run.run).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "confirmed");
        assert!(agent::group_gone(&row));
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_with_unknown_stop_ends_reconciliation_required() {
        let mut env = Env::running(Fixture::start_with_host(agent::unconfirmable).await).await;
        let (run, client) = agent::begin(&mut env.fixture).await;
        agent::initialized(&client, &run.run).await;
        assert_eq!(
            env.call("cancel", json!({"run_id": run.run.as_str()}))
                .await
                .unwrap()["state"],
            "requested"
        );
        reconciliation_required(&env, &run).await;
        let row = stop_settled(&client, &run.run).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "unknown");
        kill_group(&row);
        drop(client);
        env.stop().await;
    }

    /// A sender whose latest dispatched run on its thread ended in reconciliation, plus one later
    /// pending message.
    async fn paused(env: &Env) -> (Uuid, String, Uuid, Uuid) {
        let (binding, thread) = env.sender().await;
        let run = format!("run-{}", Uuid::now_v7());
        let old = dispatched(&env.client, binding, &run, thread.as_str()).await;
        testkit::set_terminal(&env.client, old, "reconciliation_required").await;
        let next = testkit::insert_event_for_run(
            &env.client,
            binding,
            &format!("run-{}", Uuid::now_v7()),
            thread.as_str(),
            "pending",
        )
        .await;
        (binding, run, old, next)
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn unknown_stop_pauses_later_events_until_reset_thread() {
        let env = Env::start().await;
        let (_, _, _, next) = paused(&env).await;
        assert!(matches!(
            omb_store::claim_dispatch(&env.client).await.unwrap(),
            Claim::Idle { .. }
        ));
        let row = testkit::read_row(&env.client, "channel_events", "record_id", next).await;
        assert_eq!(row["dispatch_status"], "pending");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reset_thread_without_or_with_wrong_ack_is_binding_state_invalid() {
        let mut env = Env::start().await;
        let (binding, run, _, _) = paused(&env).await;
        let before = env.binding(binding).await;
        // An empty acknowledgement fails the boundary parse; another run id fails the reset.
        assert_eq!(
            env.call(
                "bindings_reset_thread",
                json!({"binding_id": binding.to_string(), "ack_unknown": ""})
            )
            .await,
            Err(DaemonError::InvalidRequest)
        );
        assert_eq!(
            env.call(
                "bindings_reset_thread",
                json!({"binding_id": binding.to_string(), "ack_unknown": "run-other"})
            )
            .await,
            Err(DaemonError::BindingStateInvalid)
        );
        assert_eq!(env.binding(binding).await, before);
        // Without a reconciliation the acknowledgement of the latest run is refused too.
        let (fresh, thread) = env.sender_on("feishu").await;
        let fresh_run = format!("run-{}", Uuid::now_v7());
        dispatched(&env.client, fresh, &fresh_run, thread.as_str()).await;
        assert_eq!(
            env.call(
                "bindings_reset_thread",
                json!({"binding_id": fresh.to_string(), "ack_unknown": fresh_run})
            )
            .await,
            Err(DaemonError::BindingStateInvalid)
        );
        assert!(!run.is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reset_thread_with_ack_mints_new_thread_and_next_event_is_claimed_on_it() {
        let mut env = Env::start().await;
        let (binding, run, old, next) = paused(&env).await;
        let before = env.binding(binding).await;
        let old_row = testkit::read_row(&env.client, "channel_events", "record_id", old).await;
        let reset = env
            .call(
                "bindings_reset_thread",
                json!({"binding_id": binding.to_string(), "ack_unknown": run}),
            )
            .await
            .unwrap();
        let after = env.binding(binding).await;
        assert_eq!(
            reset,
            json!({
                "binding_id": binding.to_string(),
                "thread_generation": before["thread_generation"].as_i64().unwrap() + 1,
                "revision": before["revision"].as_i64().unwrap() + 1,
            })
        );
        assert_eq!(after["granted_generation"], before["granted_generation"]);
        let thread = after["thread_id"].as_str().unwrap();
        assert_ne!(thread, before["thread_id"].as_str().unwrap());
        assert!(ThreadIdentity::new(&env.fixture.engine().deployment).owns(&ThreadId::new(thread)));
        assert_eq!(
            testkit::read_row(&env.client, "channel_events", "record_id", old).await,
            old_row
        );
        let Claim::Item(item) = omb_store::claim_dispatch(&env.client).await.unwrap() else {
            panic!("next event is claimed");
        };
        assert_eq!(item.record_id, next);
        assert_eq!(item.thread_id, thread);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reset_thread_for_unknown_binding_is_binding_not_found() {
        let mut env = Env::start().await;
        assert_eq!(
            env.call(
                "bindings_reset_thread",
                json!({"binding_id": Uuid::now_v7().to_string(), "ack_unknown": "run-1"})
            )
            .await,
            Err(DaemonError::BindingNotFound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_start_returns_code_once_and_row_holds_only_the_hash() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        let started = env
            .call(
                "pair_start",
                json!({"channel": "telegram", "workspace": env.workspace()}),
            )
            .await
            .unwrap();
        let code = started["code"].as_str().unwrap().to_owned();
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
        assert!(rfc3339(&started["expires_at"]));
        let binding = Uuid::parse_str(started["binding_id"].as_str().unwrap()).unwrap();
        let row = env.binding(binding).await;
        assert_eq!(row["status"], "pending");
        assert_eq!(row["granted_generation"], env.generation());
        assert!(!row["pairing_code_hash"].is_null());
        let listed = env
            .call("bindings_list", json!({}))
            .await
            .unwrap()
            .to_string();
        for text in [row.to_string(), listed] {
            assert!(!text.contains(&code));
            assert!(!text.contains(&code.replace('-', "")));
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_start_outside_roots_is_workspace_invalid() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        let link = env.fixture.root.join("home/ws/escape");
        std::os::unix::fs::symlink(&env.fixture.root, &link).unwrap();
        for workspace in [
            env.fixture.root.clone(),
            env.fixture.root.join("home/ws/missing"),
            link,
        ] {
            assert_eq!(
                env.call(
                    "pair_start",
                    json!({"channel": "telegram", "workspace": workspace})
                )
                .await,
                Err(DaemonError::WorkspaceInvalid),
                "{workspace:?}"
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_start_with_live_sender_is_channel_already_bound() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        env.sender().await;
        assert_eq!(
            env.call(
                "pair_start",
                json!({"channel": "telegram", "workspace": env.workspace()})
            )
            .await,
            Err(DaemonError::ChannelAlreadyBound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_start_without_active_receiver_is_receiver_not_active() {
        let mut env = Env::start().await;
        let workspace = env.workspace();
        assert_eq!(
            env.call(
                "pair_start",
                json!({"channel": "telegram", "workspace": workspace})
            )
            .await,
            Err(DaemonError::ReceiverNotActive)
        );
        fixture::receiver(&env.client, "telegram").await;
        assert_eq!(
            env.call(
                "pair_start",
                json!({"channel": "feishu", "workspace": workspace})
            )
            .await,
            Err(DaemonError::ReceiverNotActive)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn pair_start_run_deadline_outside_1_to_86400_is_invalid_request() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        let workspace = env.workspace();
        for seconds in [0, 86401] {
            assert_eq!(
                env.call(
                    "pair_start",
                    json!({"channel": "telegram", "workspace": workspace, "run_deadline": seconds})
                )
                .await,
                Err(DaemonError::InvalidRequest)
            );
        }
        for seconds in [1, 86400] {
            let started = env
                .call(
                    "pair_start",
                    json!({"channel": "telegram", "workspace": workspace, "run_deadline": seconds}),
                )
                .await
                .unwrap();
            let binding = Uuid::parse_str(started["binding_id"].as_str().unwrap()).unwrap();
            assert_eq!(env.binding(binding).await["run_deadline_seconds"], seconds);
            env.call(
                "bindings_revoke",
                json!({"binding_id": binding.to_string()}),
            )
            .await
            .unwrap();
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_host_activates_with_current_generation() {
        let mut env = Env::start().await;
        let workspace = env.workspace();
        let activated = env
            .call(
                "bindings_host",
                json!({"workspace": workspace, "run_deadline": 900}),
            )
            .await
            .unwrap();
        let binding = Uuid::parse_str(activated["binding_id"].as_str().unwrap()).unwrap();
        let row = env.binding(binding).await;
        assert_eq!(row["binding_kind"], "host");
        assert_eq!(row["status"], "active");
        assert_eq!(row["revision"], 1);
        assert_eq!(row["granted_generation"], env.generation());
        assert_eq!(row["run_deadline_seconds"], 900);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_host_twice_is_channel_already_bound() {
        let mut env = Env::start().await;
        let workspace = env.workspace();
        env.call("bindings_host", json!({"workspace": workspace}))
            .await
            .unwrap();
        assert_eq!(
            env.call("bindings_host", json!({"workspace": workspace}))
                .await,
            Err(DaemonError::ChannelAlreadyBound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_host_outside_roots_is_workspace_invalid() {
        let mut env = Env::start().await;
        for workspace in [
            env.fixture.root.clone(),
            env.fixture.root.join("home/ws/missing"),
        ] {
            assert_eq!(
                env.call("bindings_host", json!({"workspace": workspace}))
                    .await,
                Err(DaemonError::WorkspaceInvalid)
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_verifies_seals_activates_and_starts_the_poller() {
        let mut env = Env::with_channels().await;
        env.verified(1001);
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": "1001:receiver-token"}),
            )
            .await
            .unwrap();
        assert_eq!(bound["source_key"], "1001");
        let binding = Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap();
        let row = env.binding(binding).await;
        assert_eq!(row["binding_kind"], "receiver");
        assert_eq!(row["status"], "active");
        assert_eq!(row["revision"], 1);
        assert_eq!(row["source_key"], "1001");
        polls_with(&env.fake, "1001:receiver-token").await;
        let methods: Vec<String> = env.fake.requests().into_iter().map(|r| r.method).collect();
        assert_eq!(&methods[..2], ["getMe", "getWebhookInfo"]);
        assert!(methods[2..].iter().all(|method| method == "getUpdates"));
        env.stop().await;
    }

    async fn refused_receiver(env: &mut Env, token: &str, expected: DaemonError) {
        let before = env.rows().await;
        assert_eq!(
            env.call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": token})
            )
            .await,
            Err(expected)
        );
        assert_eq!(env.rows().await, before);
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_with_other_bot_id_is_credential_rejected_and_writes_nothing() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        env.verified(2002);
        refused_receiver(&mut env, "1001:token", DaemonError::CredentialRejected).await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_with_webhook_set_is_webhook_conflict_and_writes_nothing() {
        let mut env = Env::start().await;
        env.fake.script(
            "getMe",
            200,
            br#"{"ok":true,"result":{"id":1001,"is_bot":true,"first_name":"Bot"}}"#.to_vec(),
        );
        env.fake.script(
            "getWebhookInfo",
            200,
            br#"{"ok":true,"result":{"url":"https://example.invalid/hook"}}"#.to_vec(),
        );
        refused_receiver(&mut env, "1001:token", DaemonError::WebhookConflict).await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_unreachable_is_channel_unreachable_and_writes_nothing() {
        let mut env = Env::start().await;
        env.ops.endpoint = FakeTelegram::endpoint_at(FakeTelegram::unused_port());
        refused_receiver(&mut env, "1001:token", DaemonError::ChannelUnreachable).await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_with_malformed_token_is_invalid_request_without_network_call() {
        let mut env = Env::start().await;
        for token in ["no-colon", "abc:rest", "1001:"] {
            refused_receiver(&mut env, token, DaemonError::InvalidRequest).await;
        }
        assert!(env.fake.requests().is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_feishu_is_channel_not_supported_and_writes_nothing() {
        let mut env = Env::start().await;
        let before = env.rows().await;
        assert_eq!(
            env.call(
                "bindings_receiver",
                json!({"channel": "feishu", "app_id": "cli_a", "app_secret": "secret"})
            )
            .await,
            Err(DaemonError::ChannelNotSupported)
        );
        assert_eq!(
            env.call(
                "pair_start",
                json!({"channel": "feishu", "workspace": env.workspace()})
            )
            .await,
            Err(DaemonError::ReceiverNotActive)
        );
        assert_eq!(env.rows().await, before);
        assert!(env.fake.requests().is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_replacement_stops_old_poller_before_new_starts() {
        let mut env = Env::with_channels().await;
        let sampler = std::sync::Arc::new(env.fixture.client().await);
        for round in 0..10 {
            let token = format!("1001:token-{round}");
            let watch = std::sync::Arc::clone(&sampler);
            let (stop, mut stopped) = oneshot::channel::<()>();
            let most = tokio::spawn(async move {
                let mut most = 0;
                loop {
                    let count: i64 = watch
                        .query_one("SELECT count(*) FROM pg_stat_activity WHERE application_name='openmybot-receiver'", &[])
                        .await
                        .unwrap()
                        .get(0);
                    most = most.max(count);
                    if stopped.try_recv().is_ok() {
                        return most;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            });
            env.verified(1001);
            env.call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": token}),
            )
            .await
            .unwrap();
            polls_with(&env.fake, &token).await;
            stop.send(()).unwrap();
            assert!(most.await.unwrap() <= 1, "round {round}");
            if round > 0 {
                let requests = env.fake.requests();
                let old = format!("/bot1001:token-{}/", round - 1);
                let new = format!("/bot{token}/");
                let last_old = requests
                    .iter()
                    .filter(|r| r.path.starts_with(&old))
                    .map(|r| r.at)
                    .max()
                    .unwrap();
                let first_new = requests
                    .iter()
                    .filter(|r| r.path.starts_with(&new) && r.method == "getUpdates")
                    .map(|r| r.at)
                    .min()
                    .unwrap();
                assert!(last_old < first_new, "round {round}");
            }
        }
        let live: i64 = env.client.query_one("SELECT count(*) FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND status='active'", &[]).await.unwrap().get(0);
        assert_eq!(live, 1);
        drop(sampler);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_replacement_cancels_sender_run_and_denies_its_permissions() {
        let mut env = Env::start().await;
        let old = fixture::receiver(&env.client, "telegram").await;
        let (sender, thread) = env.sender().await;
        let run = env.begun(sender, &thread).await;
        testkit::insert_permission_row(&env.client, sender, run.run.as_str(), "hp-128", 600.0)
            .await;
        env.verified(1001);
        env.call(
            "bindings_receiver",
            json!({"channel": "telegram", "token": "1001:new-token"}),
        )
        .await
        .unwrap();
        let receiver = env.binding(old).await;
        assert_eq!(receiver["status"], "revoked");
        assert_eq!(receiver["status_reason"], "receiver_replaced");
        assert_eq!(receiver["credential_envelope"], "");
        let row = env.binding(sender).await;
        assert_eq!(row["status"], "revoked");
        assert_eq!(row["status_reason"], "receiver_replaced");
        let decided = permission(&env.client, "hp-128").await;
        assert_eq!(decided["decision"], "deny");
        assert_eq!(decided["decided_via"], "run_stopped");
        assert_eq!(env.cancel_state(&run).await, "already_requested");
        // The owner pairs again against the new receiver.
        let started = env
            .call(
                "pair_start",
                json!({"channel": "telegram", "workspace": env.workspace()}),
            )
            .await
            .unwrap();
        assert!(started["code"].is_string());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sealed_envelope_opens_with_the_receivers_principals() {
        let mut env = Env::start().await;
        env.verified(1001);
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": "1001:sealed-token"}),
            )
            .await
            .unwrap();
        let binding = Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap();
        let envelope = env.binding(binding).await["credential_envelope"]
            .as_str()
            .unwrap()
            .to_owned();
        let owner = SecretPrincipal::Actor(env.ops.owner.clone());
        let service = SecretPrincipal::Service(ServiceId::new("openmybot.telegram"));
        let opened = env
            .ops
            .vault
            .open(
                &binding,
                SecretKind::Connector,
                owner.clone(),
                service.clone(),
                &envelope,
            )
            .unwrap()
            .into_secret();
        assert_eq!(opened.expose(), b"1001:sealed-token");
        let other = Uuid::now_v7();
        for (id, kind, owner, consumer) in [
            (
                &other,
                SecretKind::Connector,
                owner.clone(),
                service.clone(),
            ),
            (&binding, SecretKind::Model, owner.clone(), service.clone()),
            (
                &binding,
                SecretKind::Connector,
                SecretPrincipal::Actor(ActorId::new("someone-else")),
                service.clone(),
            ),
            (
                &binding,
                SecretKind::Connector,
                owner.clone(),
                SecretPrincipal::Service(ServiceId::new("openmybot.feishu")),
            ),
        ] {
            assert!(
                env.ops
                    .vault
                    .open(id, kind, owner, consumer, &envelope)
                    .is_err()
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn receiver_secret_is_absent_from_responses_errors_rows_debug_and_process_output() {
        const SENTINEL: &str = "123456:SENTINEL-ops-secret";
        let mut env = Env::start().await;
        let mut seen = Vec::new();
        env.fake.script(
            "getMe",
            200,
            br#"{"ok":true,"result":{"id":999,"is_bot":true,"first_name":"Bot"}}"#.to_vec(),
        );
        let refused = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": SENTINEL}),
            )
            .await
            .unwrap_err();
        seen.push(format!("{refused} {refused:?} {}", refused.code()));
        env.verified(123456);
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": SENTINEL}),
            )
            .await
            .unwrap();
        seen.push(bound.to_string());
        seen.push(
            env.call("bindings_list", json!({}))
                .await
                .unwrap()
                .to_string(),
        );
        let binding = bound["binding_id"].as_str().unwrap().to_owned();
        seen.push(
            env.call("bindings_reconfirm", json!({"binding_id": binding}))
                .await
                .map_or_else(|error| error.code().to_owned(), |value| value.to_string()),
        );
        seen.push(format!(
            "{:?}",
            ChannelSecret::telegram(SENTINEL.into()).unwrap()
        ));
        let rows: String = env
            .client
            .query_one("SELECT coalesce(json_agg(b),'[]')::text FROM (SELECT binding_id,binding_kind,channel_kind,source_key,sender_key,chat_key,status,status_reason,workspace_dir,thread_id FROM openmybot.channel_bindings) b", &[])
            .await
            .unwrap()
            .get(0);
        seen.push(rows);
        seen.push(
            env.rows().await.replace(
                env.binding(Uuid::parse_str(&binding).unwrap()).await["credential_envelope"]
                    .as_str()
                    .unwrap(),
                "",
            ),
        );
        for text in &seen {
            assert!(!text.contains("SENTINEL"), "{text}");
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_sender_uses_current_generation_and_bumps_revision() {
        let mut env = Env::start().await;
        let (sender, _) = env.sender().await;
        env.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='grant_stale',suspended_at=statement_timestamp(),granted_generation=0 WHERE binding_id=$1", &[&sender]).await.unwrap();
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": sender.to_string()})
            )
            .await
            .unwrap(),
            json!({"binding_id": sender.to_string(), "revision": 2})
        );
        let row = env.binding(sender).await;
        assert_eq!(row["status"], "active");
        assert_eq!(row["revision"], 2);
        assert_eq!(row["granted_generation"], env.generation());
        assert!(!row["reconfirmed_at"].is_null());
        env.stop().await;
    }

    /// A receiver row whose envelope seals `token`, suspended with its gap open.
    async fn suspended_receiver(env: &mut Env, token: &str) -> Uuid {
        let binding = Uuid::now_v7();
        let envelope = env
            .ops
            .vault
            .seal(
                &binding,
                SecretKind::Connector,
                SecretPrincipal::Actor(env.ops.owner.clone()),
                SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
                &SecretBytes::new(token.as_bytes().to_vec()),
            )
            .unwrap();
        testkit::insert_receiver_with(&env.client, binding, "telegram", "1001", &envelope).await;
        let mut client = env
            .fixture
            .pg
            .open_authority_connection()
            .await
            .unwrap()
            .client;
        omb_store::suspend_receiver(
            &mut client,
            binding,
            Suspension::CredentialRejected,
            later(),
        )
        .await
        .unwrap();
        binding
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_receiver_verifies_first_and_stays_suspended_on_failure() {
        let mut env = Env::start().await;
        let binding = suspended_receiver(&mut env, "1001:reconfirm-token").await;
        let before = env.rows().await;
        // A refused bot id ends the check before getWebhookInfo, so only getMe is scripted.
        env.fake.script(
            "getMe",
            200,
            br#"{"ok":true,"result":{"id":2002,"is_bot":true,"first_name":"Bot"}}"#.to_vec(),
        );
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()})
            )
            .await,
            Err(DaemonError::CredentialRejected)
        );
        assert_eq!(env.rows().await, before);
        env.fake.script(
            "getMe",
            200,
            br#"{"ok":true,"result":{"id":1001,"is_bot":true,"first_name":"Bot"}}"#.to_vec(),
        );
        env.fake.script(
            "getWebhookInfo",
            200,
            br#"{"ok":true,"result":{"url":"https://example.invalid/hook"}}"#.to_vec(),
        );
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()})
            )
            .await,
            Err(DaemonError::WebhookConflict)
        );
        assert_eq!(env.rows().await, before);
        assert_eq!(env.binding(binding).await["status"], "suspended");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_receiver_success_restarts_the_poller_and_closes_the_gap() {
        let mut env = Env::with_channels().await;
        let binding = suspended_receiver(&mut env, "1001:reconfirm-token").await;
        env.verified(1001);
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()})
            )
            .await
            .unwrap(),
            json!({"binding_id": binding.to_string(), "revision": 2})
        );
        let row = env.binding(binding).await;
        assert_eq!(row["status"], "active");
        let open: i64 = env.client.query_one("SELECT count(*) FROM openmybot.channel_events WHERE binding_id=$1 AND record_kind='gap' AND gap_reason='receiver_suspended' AND gap_ended_at IS NULL", &[&binding]).await.unwrap().get(0);
        assert_eq!(open, 0);
        polls_with(&env.fake, "1001:reconfirm-token").await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_unknown_or_active_binding_is_binding_not_found_or_state_invalid() {
        let mut env = Env::start().await;
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": Uuid::now_v7().to_string()})
            )
            .await,
            Err(DaemonError::BindingNotFound)
        );
        let (sender, _) = env.sender().await;
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": sender.to_string()})
            )
            .await,
            Err(DaemonError::BindingStateInvalid)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_sender_cancels_open_run_and_denies_permissions() {
        let mut env = Env::start().await;
        let (sender, thread) = env.sender().await;
        let run = env.begun(sender, &thread).await;
        testkit::insert_permission_row(&env.client, sender, run.run.as_str(), "hp-135", 600.0)
            .await;
        assert_eq!(
            env.call("bindings_revoke", json!({"binding_id": sender.to_string()}))
                .await
                .unwrap(),
            json!({"binding_id": sender.to_string(), "cancelled_runs": 1})
        );
        let row = env.binding(sender).await;
        assert_eq!(row["status"], "revoked");
        assert_eq!(row["status_reason"], "owner_revoked");
        let decided = permission(&env.client, "hp-135").await;
        assert_eq!(decided["decision"], "deny");
        assert_eq!(decided["decided_via"], "run_stopped");
        assert!(decided["decided_by_token"].is_null());
        assert_eq!(env.cancel_state(&run).await, "already_requested");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_receiver_stops_the_poller_and_cascades_to_the_sender() {
        let mut env = Env::with_channels().await;
        env.verified(1001);
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "token": "1001:revoked-token"}),
            )
            .await
            .unwrap();
        polls_with(&env.fake, "1001:revoked-token").await;
        let (sender, _) = env.sender().await;
        env.call(
            "bindings_revoke",
            json!({"binding_id": bound["binding_id"]}),
        )
        .await
        .unwrap();
        let seen = env.fake.requests().len();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(env.fake.requests().len(), seen);
        let row = env.binding(sender).await;
        assert_eq!(row["status"], "revoked");
        assert_eq!(row["status_reason"], "owner_revoked");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_unknown_binding_is_binding_not_found() {
        let mut env = Env::start().await;
        assert_eq!(
            env.call(
                "bindings_revoke",
                json!({"binding_id": Uuid::now_v7().to_string()})
            )
            .await,
            Err(DaemonError::BindingNotFound)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_list_has_no_secret_fields_and_rfc3339_times() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        let workspace = env.workspace();
        env.call(
            "pair_start",
            json!({"channel": "telegram", "workspace": workspace}),
        )
        .await
        .unwrap();
        env.call("bindings_host", json!({"workspace": workspace}))
            .await
            .unwrap();
        let listed = env.call("bindings_list", json!({})).await.unwrap();
        let bindings = listed["bindings"].as_array().unwrap();
        assert_eq!(bindings.len(), 3);
        let kinds: Vec<&str> = bindings
            .iter()
            .map(|b| b["binding_kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["host", "receiver", "sender"]);
        let mut expected = vec![
            "binding_id",
            "binding_kind",
            "channel_kind",
            "source_key",
            "sender_key",
            "status",
            "status_reason",
            "revision",
            "thread_generation",
            "workspace_dir",
            "thread_id",
            "run_deadline_seconds",
            "created_at",
            "activated_at",
            "suspended_at",
            "reconfirmed_at",
        ];
        expected.sort_unstable();
        for binding in bindings {
            let mut keys: Vec<&str> = binding
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, expected);
            assert!(rfc3339(&binding["created_at"]));
            for key in ["activated_at", "suspended_at", "reconfirmed_at"] {
                assert!(binding[key].is_null() || rfc3339(&binding[key]), "{key}");
            }
        }
        let rendered = listed.to_string();
        for absent in [
            "credential_envelope",
            "pairing_code_hash",
            "chat_key",
            "test-envelope",
        ] {
            assert!(!rendered.contains(absent), "{absent}");
        }
        env.stop().await;
    }

    async fn canceller(env: &mut Env) -> (BindingRunCanceller, mpsc::Sender<Uuid>) {
        let connection = env
            .fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let (cancel, requests) = mpsc::channel(CANCEL_QUEUE);
        (
            BindingRunCanceller::start(
                env.ops.application.clone(),
                env.ops.resolver.clone(),
                connection,
                requests,
            ),
            cancel,
        )
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn channel_cancel_cancels_only_the_own_bindings_open_run() {
        let mut env = Env::start().await;
        let (sender, thread) = env.sender().await;
        let own = env.begun(sender, &thread).await;
        let (other, client) = agent::begin(&mut env.fixture).await;
        let (task, cancel) = canceller(&mut env).await;
        cancel.send(sender).await.unwrap();
        drop(cancel);
        task.stop().await;
        assert_eq!(env.cancel_state(&own).await, "already_requested");
        assert_eq!(env.cancel_state(&other).await, "requested");
        drop(client);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn channel_cancel_without_open_run_does_nothing_and_survives_engine_failure() {
        let mut env = Env::start().await;
        let refused = host_binding(&env).await;
        dispatched(&env.client, refused, "run-refused", "thread-not-minted").await;
        let (idle, idle_thread) = env.sender().await;
        let (sender, thread) = env.sender_on("feishu").await;
        let own = env.begun(sender, &thread).await;
        let (task, cancel) = canceller(&mut env).await;
        for binding in [refused, idle, Uuid::now_v7(), sender] {
            cancel.send(binding).await.unwrap();
        }
        drop(cancel);
        task.stop().await;
        assert_eq!(env.cancel_state(&own).await, "already_requested");
        // The idle sender's thread has no run at all.
        assert_eq!(omb_store::open_run(&env.client, idle).await.unwrap(), None);
        assert!(!idle_thread.as_str().is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn op_past_its_deadline_returns_request_timeout_and_leaves_the_connection_usable() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        testkit::insert_permission_row(&env.client, binding, "run-143", "hp-143", 600.0).await;
        let past = Instant::now() - Duration::from_millis(1);
        let args = json!({"binding_id": binding.to_string()});
        assert_eq!(
            env.call_until("bindings_revoke", args.clone(), past).await,
            Err(DaemonError::RequestTimeout)
        );
        assert_eq!(
            env.call_until("approve", json!({"permission_id": "hp-143"}), past)
                .await,
            Err(DaemonError::RequestTimeout)
        );
        assert_eq!(env.binding(binding).await["status"], "active");
        assert_eq!(
            env.call("approve", json!({"permission_id": "hp-143"}))
                .await
                .unwrap()["decision"],
            "allow"
        );
        env.call("bindings_revoke", args).await.unwrap();
        assert_eq!(env.binding(binding).await["status"], "revoked");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn op_blocked_on_a_row_lock_times_out_without_leaving_an_open_transaction() {
        let mut env = Env::start().await;
        let binding = host_binding(&env).await;
        let mut holder = env.fixture.client().await;
        let lock = holder.transaction().await.unwrap();
        lock.execute(
            "SELECT 1 FROM openmybot.channel_bindings WHERE binding_id=$1 FOR UPDATE",
            &[&binding],
        )
        .await
        .unwrap();
        let args = json!({"binding_id": binding.to_string()});
        assert_eq!(
            env.call_until(
                "bindings_revoke",
                args.clone(),
                Instant::now() + Duration::from_secs(1)
            )
            .await,
            Err(DaemonError::RequestTimeout)
        );
        let states: Vec<String> = env
            .client
            .query(
                "SELECT coalesce(state,'') FROM pg_stat_activity WHERE application_name='openmybot-control'",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(states.len(), 1);
        assert_ne!(states[0], "idle in transaction");
        assert_ne!(states[0], "idle in transaction (aborted)");
        lock.commit().await.unwrap();
        env.call("bindings_revoke", args).await.unwrap();
        assert_eq!(env.binding(binding).await["status"], "revoked");
        drop(holder);
        env.stop().await;
    }
}
