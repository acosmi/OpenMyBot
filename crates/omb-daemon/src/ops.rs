//! The owner's non-model control operations, executed under the local context.
use crate::{
    Counters, DaemonError,
    channels::rfc3339_utc,
    control::REQUEST_TIMEOUT,
    pairing::{self, PairRequest},
    pg,
    plugins::Plugins,
};
use omb_channel_sdk::protocol::VerifyFailure;
use omb_hostdriver::WorkspaceRoots;
use omb_store::{
    ChannelKind, Decided, Decision, EventCancel, GrantKind, HostAccept, HostBinding,
    HostBindingState, HostMessage, IdentityKey, MCP_LIST_MAX, NewReceiver, OperationId,
    ReceiverRow, RunDeadline, Settled, StoreError, accept_host_begin, binding_run, binding_runs,
    cancel_pending, cancel_state, host_binding_state,
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
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use tokio::{
    sync::{Mutex, Notify, mpsc, oneshot},
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
    PluginsList,
    PluginsAdd,
    PluginsRemove,
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
            "plugins_list" => Self::PluginsList,
            "plugins_add" => Self::PluginsAdd,
            "plugins_remove" => Self::PluginsRemove,
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
/// One value per credential field the channel's plugin declares.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverArgs {
    channel: String,
    fields: BTreeMap<String, String>,
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsAddArgs {
    dir: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginsRemoveArgs {
    name: String,
}

/// One request after its single boundary parse.
enum Request {
    StatusRun(IdentityKey),
    PairStart(PairRequest),
    BindingsList,
    BindingsRevoke(Uuid),
    BindingsReconfirm(Uuid),
    BindingsResetThread(Uuid, IdentityKey),
    BindingsReceiver(ChannelKind, BTreeMap<String, String>),
    BindingsHost(PathBuf, Option<RunDeadline>),
    Decide(IdentityKey, Decision),
    Cancel(IdentityKey),
    PluginsList,
    PluginsAdd(PathBuf),
    PluginsRemove(String),
}
fn decode<T: DeserializeOwned>(args: Value) -> Result<T, DaemonError> {
    // A struct also deserializes from a JSON array, so anything but an object is refused here.
    if !args.is_object() {
        return Err(DaemonError::InvalidRequest);
    }
    serde_json::from_value(args).map_err(|_| DaemonError::InvalidRequest)
}
fn uuid(text: &str) -> Result<Uuid, DaemonError> {
    Uuid::parse_str(text).map_err(|_| DaemonError::InvalidRequest)
}
fn key(text: &str) -> Result<IdentityKey, DaemonError> {
    IdentityKey::parse(text).ok_or(DaemonError::InvalidRequest)
}
fn kind(text: &str) -> Result<ChannelKind, DaemonError> {
    ChannelKind::parse(text).ok_or(DaemonError::InvalidRequest)
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
                channel: kind(&args.channel)?,
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
        Op::BindingsReceiver => {
            let args: ReceiverArgs = decode(args)?;
            Request::BindingsReceiver(kind(&args.channel)?, args.fields)
        }
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
        Op::PluginsList => {
            decode::<NoArgs>(args)?;
            Request::PluginsList
        }
        Op::PluginsAdd => {
            let dir = decode::<PluginsAddArgs>(args)?.dir;
            if !dir.is_absolute() {
                return Err(DaemonError::InvalidRequest);
            }
            Request::PluginsAdd(dir)
        }
        Op::PluginsRemove => Request::PluginsRemove(decode::<PluginsRemoveArgs>(args)?.name),
    })
}

/// The vault consumer of a channel's receiver credential.
pub(crate) fn service(kind: &ChannelKind) -> ServiceId {
    ServiceId::new(format!("openmybot.{}", kind.as_str()))
}

/// A runtime receiver change or credential check the daemon's main loop hands to the channel's
/// plugin; each carries its receipt.
pub(crate) enum ReceiverCommand {
    Start(ReceiverRow, oneshot::Sender<Result<(), DaemonError>>),
    Stop(Uuid, oneshot::Sender<()>),
    /// Ends the processes of these channels before their package is removed or replaced.
    Retire(Vec<String>, oneshot::Sender<()>),
    /// The reply is dropped when the plugin cannot be started or breaks off.
    Verify {
        kind: ChannelKind,
        credential: String,
        source_key: Option<String>,
        reply: oneshot::Sender<Result<String, VerifyFailure>>,
    },
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
/// The engine's word for cancelling the run; `None` when the engine has no such run.
async fn cancel_run(
    application: &dyn ApplicationService,
    resolver: &SingleUserAuthResolver,
    thread_id: &str,
    run_id: &str,
) -> Result<Option<&'static str>, DaemonError> {
    let command = AppCommand::CancelThreadRun(CancelThreadRun {
        thread_id: ThreadId::new(thread_id),
        run_id: RunId::new(run_id),
    });
    match execute(application, resolver, command).await {
        Ok(AppReply::ThreadRunCancellation(cancellation)) => Ok(Some(match cancellation.state {
            ThreadRunCancellationState::Requested => "requested",
            ThreadRunCancellationState::AlreadyRequested => "already_requested",
            ThreadRunCancellationState::AlreadyTerminal => "already_terminal",
        })),
        Err(AppError::NotVisible) => Ok(None),
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
    pub(crate) plugins: Plugins,
    pub(crate) receiver: mpsc::Sender<ReceiverCommand>,
    pub(crate) wake: Arc<Notify>,
    pub(crate) minter: ThreadMinter,
    pub(crate) canceller: BindingRunCanceller,
    /// The receivers' counters: a host operation conflict counts as an event conflict.
    pub(crate) counters: Arc<Counters>,
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
                self.plugins
                    .provider(&request.channel)
                    .ok_or(DaemonError::PluginNotInstalled)?;
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
                let (settled, stopped) = {
                    let mut client = self.control.lock().await;
                    let settled = {
                        // No dispatch is between its event lock and its receipt while the binding
                        // ends.
                        let _gate = timeout_at(deadline, self.canceller.gate.lock())
                            .await
                            .map_err(|_| DaemonError::RequestTimeout)?;
                        omb_store::revoke_binding(&mut client, binding_id, deadline)
                            .await
                            .map_err(failed)?
                    };
                    let stopped = self
                        .command(|done| ReceiverCommand::Stop(binding_id, done), deadline)
                        .await;
                    (settled, stopped)
                };
                // Asked after the commit, also when the receiver command failed: a run that lands
                // later fails its delegation check.
                let cancelled = self.cancel_all(&settled).await?;
                stopped?;
                Ok(json!({"binding_id": binding_id.to_string(), "cancelled_runs": cancelled}))
            }
            Request::BindingsReconfirm(binding_id) => {
                let receiver =
                    omb_store::receiver_row(&*self.control.lock().await, binding_id, deadline)
                        .await
                        .map_err(failed)?;
                let revision = match receiver {
                    Some(row) => {
                        self.plugins
                            .provider(&row.channel)
                            .ok_or(DaemonError::PluginNotInstalled)?;
                        let secret = self
                            .vault
                            .open(
                                &row.binding_id,
                                SecretKind::Connector,
                                SecretPrincipal::Actor(self.owner.clone()),
                                SecretPrincipal::Service(service(&row.channel)),
                                &row.credential_envelope,
                            )
                            .map_err(|_| DaemonError::CredentialRejected)?
                            .into_secret();
                        let credential = String::from_utf8(secret.expose().to_vec())
                            .map_err(|_| DaemonError::CredentialRejected)?;
                        let verified = self
                            .verify(
                                row.channel.clone(),
                                credential,
                                Some(row.source_key.clone()),
                                deadline,
                            )
                            .await?;
                        // The stored credential must still belong to the receiver's account.
                        if verified != row.source_key {
                            return Err(DaemonError::CredentialRejected);
                        }
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
                self.wake.notify_one();
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
                self.wake.notify_one();
                Ok(
                    json!({"binding_id": binding_id.to_string(), "thread_generation": done.thread_generation, "revision": done.revision}),
                )
            }
            Request::BindingsReceiver(kind, fields) => {
                let plugin = self
                    .plugins
                    .provider(&kind)
                    .ok_or(DaemonError::PluginNotInstalled)?;
                let declared = &plugin.channels[kind.as_str()].credential_fields;
                if !fields.keys().map(String::as_str).eq(declared
                    .iter()
                    .map(|field| field.name.as_str())
                    .collect::<BTreeSet<_>>())
                {
                    return Err(DaemonError::InvalidRequest);
                }
                // The only plain field is the source key candidate; one secret is sealed as its
                // value, several as a JSON object in name order.
                let (secrets, plain): (Vec<_>, Vec<_>) =
                    declared.iter().partition(|field| field.secret);
                let source_key = match plain.as_slice() {
                    [field] => Some(fields[&field.name].clone()),
                    _ => None,
                };
                let credential = match secrets.as_slice() {
                    [field] => fields[&field.name].clone(),
                    _ => serde_json::to_string(
                        &secrets
                            .iter()
                            .map(|field| (&field.name, &fields[&field.name]))
                            .collect::<BTreeMap<_, _>>(),
                    )
                    .map_err(|_| DaemonError::InternalError)?,
                };
                let source_key = self
                    .verify(kind.clone(), credential.clone(), source_key, deadline)
                    .await?;
                let binding_id = Uuid::now_v7();
                let envelope = self
                    .vault
                    .seal(
                        &binding_id,
                        SecretKind::Connector,
                        SecretPrincipal::Actor(self.owner.clone()),
                        SecretPrincipal::Service(service(&kind)),
                        &SecretBytes::new(credential.into_bytes()),
                    )
                    .map_err(|_| DaemonError::InternalError)?;
                let (settled, started) = {
                    let mut client = self.control.lock().await;
                    let settled = {
                        // No dispatch is between its event lock and its receipt while the replaced
                        // bindings end.
                        let _gate = timeout_at(deadline, self.canceller.gate.lock())
                            .await
                            .map_err(|_| DaemonError::RequestTimeout)?;
                        omb_store::activate_receiver(
                            &mut client,
                            NewReceiver {
                                binding_id,
                                channel: kind.clone(),
                                source_key: &source_key,
                                credential_envelope: &envelope,
                            },
                            deadline,
                        )
                        .await
                        .map_err(failed)?
                    };
                    let row = ReceiverRow {
                        binding_id,
                        channel: kind,
                        source_key: source_key.clone(),
                        credential_envelope: envelope,
                    };
                    let started = self
                        .command(|done| ReceiverCommand::Start(row, done), deadline)
                        .await;
                    (settled, started)
                };
                // The replaced bindings' runs are asked to stop even when the new receiver did not
                // start.
                self.cancel_all(&settled).await?;
                started??;
                Ok(json!({"binding_id": binding_id.to_string(), "source_key": source_key}))
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
                .await?
                .ok_or(DaemonError::InternalError)?;
                Ok(json!({"run_id": run_id.as_str(), "state": state}))
            }
            Request::PluginsList => {
                let plugins = self
                    .plugins
                    .list()
                    .into_iter()
                    .map(|plugin| {
                        let (process, last_exit_code) = self.plugins.process(&plugin);
                        let channels: Vec<Value> = plugin
                            .channels
                            .iter()
                            .map(|(kind, channel)| {
                                json!({
                                    "channel_kind": kind,
                                    "credential_fields": channel.credential_fields,
                                    "status_note": channel.status_note,
                                })
                            })
                            .collect();
                        json!({
                            "name": plugin.name,
                            "version": plugin.version,
                            "channels": channels,
                            "process": process,
                            "last_exit_code": last_exit_code,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({ "plugins": plugins }))
            }
            Request::PluginsAdd(dir) => {
                let client = self.control.lock().await;
                let staged = self
                    .plugins
                    .stage(&dir, &self.live(&client, deadline).await?)?;
                let replaces = staged.replaces.clone();
                self.command(|done| ReceiverCommand::Retire(replaces, done), deadline)
                    .await?;
                let installed = self.plugins.commit(staged)?;
                let channels: Vec<&String> = installed.channels.keys().collect();
                Ok(
                    json!({"name": installed.name, "version": installed.version, "channels": channels}),
                )
            }
            Request::PluginsRemove(name) => {
                let client = self.control.lock().await;
                let kinds = self
                    .plugins
                    .removable(&name, &self.live(&client, deadline).await?)?;
                self.command(|done| ReceiverCommand::Retire(kinds, done), deadline)
                    .await?;
                self.plugins.remove(&name)?;
                Ok(json!({ "name": name }))
            }
        }
    }
    /// The channels with a pending, active or suspended binding.
    async fn live(
        &self,
        client: &tokio_postgres::Client,
        deadline: Instant,
    ) -> Result<HashSet<String>, DaemonError> {
        Ok(omb_store::list_bindings(client, deadline)
            .await
            .map_err(|error| store_error(error, deadline))?
            .into_iter()
            .map(|view| view.channel_kind)
            .collect())
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
    /// Bind-time credential check by the channel's plugin within the operation's deadline; returns
    /// the source key the credential belongs to.
    async fn verify(
        &self,
        kind: ChannelKind,
        credential: String,
        source_key: Option<String>,
        deadline: Instant,
    ) -> Result<String, DaemonError> {
        let (reply, receipt) = oneshot::channel();
        let verified = timeout_at(deadline, async {
            self.receiver
                .send(ReceiverCommand::Verify {
                    kind,
                    credential,
                    source_key,
                    reply,
                })
                .await
                .map_err(|_| DaemonError::InternalError)?;
            receipt.await.map_err(|_| DaemonError::PluginUnavailable)
        })
        .await
        .map_err(|_| DaemonError::RequestTimeout)??;
        verified.map_err(|failure| match failure {
            VerifyFailure::CredentialRejected => DaemonError::CredentialRejected,
            VerifyFailure::WebhookConflict => DaemonError::WebhookConflict,
            VerifyFailure::Unreachable => DaemonError::ChannelUnreachable,
            VerifyFailure::Malformed => DaemonError::InvalidRequest,
        })
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
    /// Cancels the runs of bindings that already ended and counts them: every dispatched run,
    /// where the first engine refusal is reported, and every run the engine has for a cancelled
    /// pending message, which an earlier begin attempt started.
    async fn cancel_all(&self, settled: &Settled) -> Result<usize, DaemonError> {
        for run in &settled.dispatched {
            cancel_run(
                self.application.as_ref(),
                &self.resolver,
                &run.thread_id,
                &run.run_id,
            )
            .await?
            .ok_or(DaemonError::InternalError)?;
        }
        let mut cancelled = settled.dispatched.len();
        for run in &settled.pending {
            if cancel_run(
                self.application.as_ref(),
                &self.resolver,
                &run.thread_id,
                &run.run_id,
            )
            .await?
            .is_some()
            {
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }
}

/// The MCP control operations, accepted only from an MCP client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum McpOp {
    RunBegin,
    RunStatus,
    RunCancel,
    RunResult,
    ThreadList,
}
impl McpOp {
    pub(crate) fn parse(name: &str) -> Option<McpOp> {
        Some(match name {
            "mcp_run_begin" => Self::RunBegin,
            "mcp_run_status" => Self::RunStatus,
            "mcp_run_cancel" => Self::RunCancel,
            "mcp_run_result" => Self::RunResult,
            "mcp_thread_list" => Self::ThreadList,
            _ => return None,
        })
    }
}

/// The engine handle that only mints thread ids; a host run's thread is minted before its
/// acceptance transaction.
#[derive(Clone)]
pub(crate) struct ThreadMinter {
    application: Arc<dyn ApplicationService>,
    resolver: SingleUserAuthResolver,
}
impl ThreadMinter {
    pub(crate) fn new(
        application: Arc<dyn ApplicationService>,
        resolver: SingleUserAuthResolver,
    ) -> Self {
        Self {
            application,
            resolver,
        }
    }
    pub(crate) async fn mint(&self) -> Result<ThreadId, DaemonError> {
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
        Ok(minted.thread_id)
    }
}

/// The narrow handle that cancels one run of one binding, behind channel `/cancel` and
/// `wrok_run_cancel`; it runs on the canceller's own connection, not under the control lock, and
/// under the dispatch gate it shares with the dispatcher. The gate holds the run ids whose begin
/// outcome is unknown.
#[derive(Clone)]
pub(crate) struct BindingRunCanceller {
    application: Arc<dyn ApplicationService>,
    resolver: SingleUserAuthResolver,
    client: Arc<tokio_postgres::Client>,
    gate: Arc<Mutex<HashSet<String>>>,
}
impl BindingRunCanceller {
    pub(crate) fn new(
        application: Arc<dyn ApplicationService>,
        resolver: SingleUserAuthResolver,
        client: Arc<tokio_postgres::Client>,
        gate: Arc<Mutex<HashSet<String>>>,
    ) -> Self {
        Self {
            application,
            resolver,
            client,
            gate,
        }
    }
    /// Holds the dispatch gate for the whole cancel, so no dispatch is between its event lock and
    /// its receipt. A pending message may have a run from an earlier begin attempt, so the engine
    /// cancels the run it has, and the message is cancelled only when the engine has none and no
    /// begin of it has an unknown outcome; while one has, the cancel is a request timeout. A
    /// dispatched run without a terminal is cancelled in the engine; a run of another binding is
    /// not found.
    pub(crate) async fn cancel(
        &self,
        binding_id: Uuid,
        run_id: &str,
        deadline: Instant,
    ) -> Result<&'static str, DaemonError> {
        let unknown = timeout_at(deadline, self.gate.lock())
            .await
            .map_err(|_| DaemonError::RequestTimeout)?;
        let mut found = cancel_state(&self.client, binding_id, run_id)
            .await
            .map_err(pg::map_store_error)?;
        if let EventCancel::Pending { thread_id } = &found {
            if let Some(state) =
                cancel_run(self.application.as_ref(), &self.resolver, thread_id, run_id).await?
            {
                return Ok(state);
            }
            // The engine has no run yet, but a begin of it whose COMMIT outcome is unknown may
            // still land; the next dispatch attempt settles it.
            if unknown.contains(run_id) {
                return Err(DaemonError::RequestTimeout);
            }
            if cancel_pending(&self.client, binding_id, run_id)
                .await
                .map_err(pg::map_store_error)?
            {
                return Ok("requested");
            }
            found = cancel_state(&self.client, binding_id, run_id)
                .await
                .map_err(pg::map_store_error)?;
        }
        match found {
            EventCancel::NotFound => Err(DaemonError::RunNotFound),
            EventCancel::Ended => Ok("already_terminal"),
            EventCancel::Open { thread_id } => cancel_run(
                self.application.as_ref(),
                &self.resolver,
                &thread_id,
                run_id,
            )
            .await?
            .ok_or(DaemonError::InternalError),
            // A message returns to pending only when a dispatch receipt rolls back, which the gate
            // excludes.
            EventCancel::Pending { .. } => Err(DaemonError::InternalError),
        }
    }
}

/// The `/cancel` queue of the channel receivers: each binding id cancels that binding's open run.
pub(crate) struct CancelQueue {
    task: JoinHandle<()>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl CancelQueue {
    pub(crate) fn start(
        canceller: BindingRunCanceller,
        driver: JoinHandle<Result<(), tokio_postgres::Error>>,
        mut requests: mpsc::Receiver<Uuid>,
    ) -> Self {
        let task = tokio::spawn(async move {
            while let Some(binding_id) = requests.recv().await {
                // Any failure drops this request; the owner can send `/cancel` again.
                if let Ok(Some(run)) = omb_store::open_run(&canceller.client, binding_id).await {
                    let _ = canceller
                        .cancel(binding_id, &run.run_id, Instant::now() + REQUEST_TIMEOUT)
                        .await;
                }
            }
        });
        Self { task, driver }
    }
    /// Joins the task once every request sender is gone, then ends the connection's driver:
    /// clones of the handle still hold its client, so the connection does not end by itself.
    pub(crate) async fn stop(self) {
        let _ = self.task.await;
        self.driver.abort();
        let _ = self.driver.await;
    }
}

mod mcp {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BeginArgs {
        operation_id: String,
        message: String,
    }
    /// One MCP request after its single boundary parse.
    pub(super) enum McpRequest {
        Begin(OperationId, HostMessage),
        Status(IdentityKey),
        Cancel(IdentityKey),
        Result(IdentityKey),
        List,
    }
    pub(super) fn parse(op: McpOp, args: Value) -> Result<McpRequest, DaemonError> {
        Ok(match op {
            McpOp::RunBegin => {
                let args: BeginArgs = decode(args)?;
                McpRequest::Begin(
                    OperationId::parse(&args.operation_id).ok_or(DaemonError::InvalidRequest)?,
                    HostMessage::parse(&args.message).ok_or(DaemonError::InvalidRequest)?,
                )
            }
            McpOp::RunStatus => McpRequest::Status(key(&decode::<RunArgs>(args)?.run_id)?),
            McpOp::RunCancel => McpRequest::Cancel(key(&decode::<RunArgs>(args)?.run_id)?),
            McpOp::RunResult => McpRequest::Result(key(&decode::<RunArgs>(args)?.run_id)?),
            McpOp::ThreadList => {
                decode::<NoArgs>(args)?;
                McpRequest::List
            }
        })
    }

    impl Ops {
        /// The live host binding, checked by every operation but `RunBegin`, whose acceptance
        /// transaction checks it.
        async fn host_binding(&self, deadline: Instant) -> Result<Uuid, DaemonError> {
            match host_binding_state(&*self.control.lock().await, deadline)
                .await
                .map_err(|error| store_error(error, deadline))?
            {
                HostBindingState::Active(binding_id) => Ok(binding_id),
                HostBindingState::Suspended => Err(DaemonError::HostBindingSuspended),
                HostBindingState::NotBound => Err(DaemonError::HostNotBound),
            }
        }
        pub(crate) async fn run_mcp(
            &self,
            op: McpOp,
            args: Value,
            deadline: Instant,
        ) -> Result<Value, DaemonError> {
            let failed = |error| store_error(error, deadline);
            match parse(op, args)? {
                McpRequest::Begin(operation, message) => {
                    let thread = self.minter.mint().await?;
                    let accepted = accept_host_begin(
                        &mut *self.control.lock().await,
                        &operation,
                        &message,
                        thread.as_str(),
                        deadline,
                    )
                    .await;
                    // Every outcome wakes, an error too: its commit may have landed.
                    self.wake.notify_one();
                    match accepted.map_err(failed)? {
                        HostAccept::Accepted(run) => Ok(
                            json!({"run_id": run.run_id, "thread_id": run.thread_id, "state": "accepted"}),
                        ),
                        HostAccept::Replayed(run) => Ok(
                            json!({"run_id": run.run_id, "thread_id": run.thread_id, "state": "replayed"}),
                        ),
                        HostAccept::Conflict => {
                            self.counters.event_conflict.fetch_add(1, Ordering::Relaxed);
                            Err(DaemonError::OperationConflict)
                        }
                        HostAccept::NotBound => Err(DaemonError::HostNotBound),
                        HostAccept::Suspended => Err(DaemonError::HostBindingSuspended),
                        HostAccept::QueueFull => Err(DaemonError::DispatchQueueFull),
                    }
                }
                McpRequest::Status(run_id) => {
                    let binding_id = self.host_binding(deadline).await?;
                    let view = binding_run(
                        &*self.control.lock().await,
                        binding_id,
                        run_id.as_str(),
                        deadline,
                    )
                    .await
                    .map_err(failed)?
                    .ok_or(DaemonError::RunNotFound)?;
                    Ok(
                        json!({"run_id": view.run_id, "state": view.state.as_str(), "permission_ids": view.permission_ids}),
                    )
                }
                McpRequest::Result(run_id) => {
                    let binding_id = self.host_binding(deadline).await?;
                    let view = binding_run(
                        &*self.control.lock().await,
                        binding_id,
                        run_id.as_str(),
                        deadline,
                    )
                    .await
                    .map_err(failed)?
                    .ok_or(DaemonError::RunNotFound)?;
                    if !view.state.is_terminal() {
                        return Err(DaemonError::RunNotTerminal);
                    }
                    Ok(json!({
                        "run_id": view.run_id,
                        "terminal_kind": view.state.as_str(),
                        "summary": view.summary,
                        "artifacts": view.artifacts,
                    }))
                }
                McpRequest::List => {
                    let binding_id = self.host_binding(deadline).await?;
                    let runs: Vec<Value> = binding_runs(
                        &*self.control.lock().await,
                        binding_id,
                        MCP_LIST_MAX,
                        deadline,
                    )
                    .await
                    .map_err(failed)?
                    .into_iter()
                    .map(|view| {
                        json!({
                            "run_id": view.run_id,
                            "thread_id": view.thread_id,
                            "state": view.state.as_str(),
                            "accepted_at": view.accepted_at,
                        })
                    })
                    .collect();
                    Ok(json!({ "runs": runs }))
                }
                McpRequest::Cancel(run_id) => {
                    let binding_id = self.host_binding(deadline).await?;
                    let state = self
                        .canceller
                        .cancel(binding_id, run_id.as_str(), deadline)
                        .await?;
                    Ok(json!({"run_id": run_id.as_str(), "state": state}))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CANCEL_QUEUE, ChannelError, Connection, Timings,
        agent::{
            AgentRuntime,
            tests::{self as agent, Run},
        },
        channels::{Channels, Outbound},
        delegation::{
            BOT_ID,
            fixture::{self, Fixture},
        },
        dispatch::start_dispatcher,
        plugins::tests::{Logs, fake_channel, package},
        supervisor::{Context, PluginProcess},
    };
    use omb_channel_sdk::PLUGIN_MAX;
    use omb_hostdriver::{HostDriverConfig, Limits, OMB_NOTICE_PERMISSION_V1};
    use omb_store::{
        Claim, DispatchOutcome, Suspension, TerminalKind, lock_dispatch, record_dispatch,
        record_terminal, testkit,
    };
    use openbot_application::{
        BeginDelegatedThreadRun, DelegatedUntrustedMaterial, RunTerminalKind,
    };
    use openbot_contracts::{
        auth::DelegationSource,
        command::{AppEvent, SubscriptionRequest, ThreadRunEventKind},
        ids::{BotId, thread::ThreadIdentity},
        reconciliation::RunReconciliationStatus,
    };
    use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
    use std::{collections::HashMap, path::Path, time::Duration};
    use tokio::{sync::Semaphore, task::JoinSet};
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
                    json!(["r1"]),
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
                    json!({"channel": "Slack", "workspace": "/ws"}),
                    json!({"channel": "host", "workspace": "/ws"}),
                    json!({"channel": "", "workspace": "/ws"}),
                ],
            ),
            (
                "bindings_list",
                json!({}),
                vec![json!({"x": 1}), json!("x"), json!(null), json!([])],
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
                json!({"channel": "telegram", "fields": {"token": "1:x"}}),
                vec![
                    json!({}),
                    json!({"fields": {"token": "1:x"}}),
                    json!({"channel": "telegram"}),
                    json!({"channel": "telegram", "token": "1:x"}),
                    json!({"channel": "telegram", "fields": {"token": 1}}),
                    json!({"channel": "telegram", "fields": ["1:x"]}),
                    json!({"channel": "telegram", "fields": {"token": "1:x"}, "x": 1}),
                    json!({"channel": "Telegram", "fields": {"token": "1:x"}}),
                    json!({"channel": "host", "fields": {}}),
                ],
            ),
            (
                "plugins_list",
                json!({}),
                vec![json!({"x": 1}), json!(null)],
            ),
            (
                "plugins_add",
                json!({"dir": "/pkg"}),
                vec![
                    json!({}),
                    json!({"dir": "pkg"}),
                    json!({"dir": 1}),
                    json!({"dir": "/pkg", "built_in": "telegram"}),
                ],
            ),
            (
                "plugins_remove",
                json!({"name": "fake"}),
                vec![
                    json!({}),
                    json!({"name": 1}),
                    json!({"name": "fake", "x": 1}),
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
        let Ok(Request::BindingsReceiver(kind, fields)) = parse(
            Op::BindingsReceiver,
            json!({"channel": "feishu", "fields": {"app_id": "a", "app_secret": "s"}}),
        ) else {
            panic!("not a receiver request");
        };
        assert_eq!(kind.as_str(), "feishu");
        assert_eq!(fields["app_id"], "a");
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

    /// `Ops` over the fixture's engine, the fake plugin installed for `telegram` and `feishu` under
    /// the fixture's data directory, and a temporary `HOME` with one workspace root `home/ws` under
    /// it; the test serves the receiver commands itself.
    struct Env {
        fixture: Fixture,
        ops: Ops,
        commands: mpsc::Receiver<ReceiverCommand>,
        channels: Option<Channels>,
        runtime: Option<AgentRuntime>,
        control_link: JoinHandle<Result<(), tokio_postgres::Error>>,
        canceller_link: JoinHandle<Result<(), tokio_postgres::Error>>,
        client: Client,
        token: Uuid,
        telegram: Logs,
        feishu: Logs,
        /// Without the channel tasks: the supervisors that answer the credential checks.
        context: Arc<Context>,
        processes: HashMap<ChannelKind, PluginProcess>,
        supervisors: JoinSet<Result<(), ChannelError>>,
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
            let canceller = fixture
                .pg
                .open_resident_connection("openmybot-canceller")
                .await
                .unwrap();
            let client = fixture.client().await;
            let (receiver, commands) = mpsc::channel(8);
            let engine = fixture.engine();
            let ops = Ops {
                control: Mutex::new(control.client),
                application: engine.assembly.application.clone(),
                resolver: engine.resolver.clone(),
                vault: engine.vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                roots: WorkspaceRoots::parse(&home, &[workspace]).unwrap(),
                plugins: Plugins::load(&fixture.root, Vec::new(), fixture.root.clone()).unwrap(),
                receiver,
                wake: Arc::new(Notify::new()),
                minter: ThreadMinter::new(
                    engine.assembly.application.clone(),
                    engine.resolver.clone(),
                ),
                canceller: BindingRunCanceller::new(
                    engine.assembly.application.clone(),
                    engine.resolver.clone(),
                    Arc::new(canceller.client),
                    Arc::default(),
                ),
                counters: Arc::new(Counters::default()),
            };
            let context = Arc::new(Context {
                plugins: ops.plugins.clone(),
                vault: engine.vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                timings: quick_channels(),
                counters: Arc::clone(&ops.counters),
                wake: Arc::clone(&ops.wake),
                cancel: mpsc::channel(CANCEL_QUEUE).0,
                slots: Arc::new(Semaphore::new(PLUGIN_MAX)),
            });
            let env = Self {
                fixture,
                ops,
                commands,
                channels: None,
                runtime: None,
                control_link: control.driver,
                canceller_link: canceller.driver,
                client,
                token,
                telegram: Logs::new(),
                feishu: Logs::new(),
                context,
                processes: HashMap::new(),
                supervisors: JoinSet::new(),
            };
            env.install("telegram", "normal", "1001");
            env.install("feishu", "normal", "cli_a");
            env
        }
        /// Installs the fake as plugin `fake-<kind>` with `scenario`, its credential check
        /// answering `source_key`, in place of an earlier installation; `telegram` declares one
        /// secret `token`, `feishu` a plain `app_id` and a secret `app_secret`.
        fn install(&self, kind: &str, scenario: &str, source_key: &str) {
            let (logs, fields) = match kind {
                "telegram" => (&self.telegram, json!([{"name": "token", "secret": true}])),
                _ => (
                    &self.feishu,
                    json!([{"name": "app_id", "secret": false}, {"name": "app_secret", "secret": true}]),
                ),
            };
            let mut channel = fake_channel(kind, logs, scenario, fields);
            channel["args"]
                .as_array_mut()
                .unwrap()
                .extend([json!("--source-key"), json!(source_key)]);
            let dir = package(&format!("fake-{kind}"), json!({ kind: channel }));
            self.ops.plugins.install(&dir, &HashSet::new()).unwrap();
            std::fs::remove_dir_all(dir).unwrap();
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
            env.serve().await;
            env
        }
        /// Starts the daemon's channel tasks; the dispatcher takes over the wake-up.
        async fn serve(&mut self) {
            let (cancel, _) = mpsc::channel(CANCEL_QUEUE);
            let terminals = self.fixture.take_terminals();
            let channels = Channels::start(
                &mut self.fixture.pg,
                self.fixture.engine.as_ref().unwrap(),
                self.token,
                quick_channels(),
                self.ops.plugins.clone(),
                cancel,
                Outbound {
                    terminals,
                    crabcode: None,
                },
                Arc::clone(&self.ops.canceller.gate),
            )
            .await
            .unwrap();
            self.ops.wake = channels.wake();
            self.channels = Some(channels);
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
                        ReceiverCommand::Start(row, done) => match self.channels.as_mut() {
                            Some(channels) => {
                                channels.start_receiver(&mut self.fixture.pg, row, done).await
                            }
                            None => {
                                let _ = done.send(Ok(()));
                            }
                        },
                        ReceiverCommand::Stop(binding_id, done) => match self.channels.as_mut() {
                            Some(channels) => channels.stop_receiver(binding_id, done).await,
                            None => {
                                let _ = done.send(());
                            }
                        },
                        ReceiverCommand::Retire(kinds, done) => match self.channels.as_mut() {
                            Some(channels) => channels.retire(kinds, done).await,
                            None => {
                                let _ = done.send(());
                            }
                        },
                        ReceiverCommand::Verify { kind, credential, source_key, reply } => {
                            match self.channels.as_mut() {
                                Some(channels) => {
                                    channels.verify(kind, credential, source_key, reply).await
                                }
                                None => {
                                    self.processes
                                        .entry(kind.clone())
                                        .or_insert_with(|| {
                                            PluginProcess::spawn(
                                                kind,
                                                Arc::clone(&self.context),
                                                &mut self.supervisors,
                                            )
                                        })
                                        .verify(credential, source_key, reply)
                                        .await
                                }
                            }
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
        async fn stop(mut self) {
            if let Some(channels) = self.channels {
                channels.stop().await;
            }
            for process in self.processes.values() {
                process.terminate().await;
            }
            while self.supervisors.join_next().await.is_some() {}
            if let Some(runtime) = self.runtime {
                runtime.stop().await;
            }
            drop(self.ops);
            self.canceller_link.abort();
            let _ = self.canceller_link.await;
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
    /// Polls `probe`, usually over a fake plugin's frame log, until it holds.
    async fn waits_for(what: &str, probe: impl Fn() -> bool) {
        let limit = Instant::now() + Duration::from_secs(20);
        while !probe() {
            assert!(Instant::now() < limit, "{what} deadline");
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
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": "1001:receiver-token"}}),
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
        waits_for("start", || !env.telegram.received_of("start").is_empty()).await;
        // The plugin checked the token before it started receiving with it.
        let frames: Vec<Value> = env
            .telegram
            .received()
            .into_iter()
            .map(|frame| json!([frame["type"], frame["credential"], frame["source_key"]]))
            .collect();
        assert_eq!(
            frames,
            [
                json!(["hello", null, null]),
                json!(["verify", "1001:receiver-token", null]),
                json!(["start", "1001:receiver-token", "1001"]),
            ]
        );
        env.stop().await;
    }

    /// Binding `fields` on `channel` is refused with `expected` and leaves every row unchanged.
    async fn refused(env: &mut Env, channel: &str, fields: Value, expected: DaemonError) {
        let before = env.rows().await;
        assert_eq!(
            env.call(
                "bindings_receiver",
                json!({"channel": channel, "fields": fields})
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
        env.install("telegram", "verify_fail:credential_rejected", "1001");
        refused(
            &mut env,
            "telegram",
            json!({"token": "1001:token"}),
            DaemonError::CredentialRejected,
        )
        .await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_with_webhook_set_is_webhook_conflict_and_writes_nothing() {
        let mut env = Env::start().await;
        env.install("telegram", "verify_fail:webhook_conflict", "1001");
        refused(
            &mut env,
            "telegram",
            json!({"token": "1001:token"}),
            DaemonError::WebhookConflict,
        )
        .await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_unreachable_is_channel_unreachable_and_writes_nothing() {
        let mut env = Env::start().await;
        env.install("telegram", "verify_fail:unreachable", "1001");
        refused(
            &mut env,
            "telegram",
            json!({"token": "1001:token"}),
            DaemonError::ChannelUnreachable,
        )
        .await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_with_malformed_token_is_invalid_request_without_network_call() {
        let mut env = Env::start().await;
        // Fields other than the declared ones are refused before the plugin sees them.
        for fields in [
            json!({}),
            json!({"bot_token": "1001:token"}),
            json!({"token": "1001:token", "app_id": "1001"}),
        ] {
            refused(&mut env, "telegram", fields, DaemonError::InvalidRequest).await;
        }
        assert!(env.telegram.received_of("verify").is_empty());
        // The plugin judges the token's shape.
        env.install("telegram", "verify_fail:malformed", "1001");
        refused(
            &mut env,
            "telegram",
            json!({"token": "no-colon"}),
            DaemonError::InvalidRequest,
        )
        .await;
        assert_eq!(env.telegram.received_of("verify").len(), 1);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_feishu_verifies_the_token_seals_activates_and_connects() {
        let mut env = Env::with_channels().await;
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "feishu", "fields": {"app_id": "cli_a", "app_secret": "secret"}}),
            )
            .await
            .unwrap();
        assert_eq!(bound["source_key"], "cli_a");
        let binding = Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap();
        // The only secret field is the credential; the plain one is the source key candidate.
        let verify = env.feishu.received_of("verify");
        assert_eq!(verify.len(), 1);
        assert_eq!(
            (&verify[0]["credential"], &verify[0]["source_key"]),
            (&json!("secret"), &json!("cli_a"))
        );
        let row = env.binding(binding).await;
        assert_eq!(
            [
                &row["binding_kind"],
                &row["channel_kind"],
                &row["source_key"],
                &row["status"],
            ],
            ["receiver", "feishu", "cli_a", "active"]
        );
        assert_eq!(row["revision"], 1);
        let envelope = row["credential_envelope"].as_str().unwrap();
        let open = |service: &str| {
            env.ops.vault.open(
                &binding,
                SecretKind::Connector,
                SecretPrincipal::Actor(env.ops.owner.clone()),
                SecretPrincipal::Service(ServiceId::new(service)),
                envelope,
            )
        };
        assert_eq!(
            open("openmybot.feishu").unwrap().into_secret().expose(),
            b"secret"
        );
        assert!(open("openmybot.telegram").is_err());
        waits_for("start", || !env.feishu.received_of("start").is_empty()).await;
        let start = env.feishu.received_of("start");
        assert_eq!(
            (&start[0]["credential"], &start[0]["source_key"]),
            (&json!("secret"), &json!("cli_a"))
        );
        let paired = env
            .call(
                "pair_start",
                json!({"channel": "feishu", "workspace": env.workspace()}),
            )
            .await
            .unwrap();
        assert!(paired["code"].is_string());
        assert!(env.telegram.received().is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_feishu_rejected_token_is_credential_rejected_and_leaks_nothing() {
        let mut env = Env::start().await;
        env.install("feishu", "verify_fail:credential_rejected", "cli_a");
        let before = env.rows().await;
        let refused = env
            .call(
                "bindings_receiver",
                json!({"channel": "feishu", "fields": {"app_id": "cli_a", "app_secret": "SENTINEL-feishu-ops"}}),
            )
            .await
            .unwrap_err();
        assert_eq!(refused, DaemonError::CredentialRejected);
        assert_eq!(env.rows().await, before);
        let listed = env.call("bindings_list", json!({})).await.unwrap();
        let bindings: String = env
            .client
            .query_one(
                "SELECT coalesce(string_agg(row_to_json(b)::text, ','), '') FROM openmybot.channel_bindings b",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let rendered = format!(
            "{refused} {refused:?} {} {listed} {bindings}",
            refused.code()
        );
        assert_eq!(rendered.matches("SENTINEL").count(), 0);
        // One check reached the plugin, and nothing started receiving.
        assert_eq!(env.feishu.received_of("verify").len(), 1);
        assert!(env.feishu.received_of("start").is_empty());
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_feishu_unreachable_or_server_error_is_channel_unreachable() {
        let mut env = Env::start().await;
        env.install("feishu", "verify_fail:unreachable", "cli_a");
        refused(
            &mut env,
            "feishu",
            json!({"app_id": "cli_a", "app_secret": "secret"}),
            DaemonError::ChannelUnreachable,
        )
        .await;
        assert_eq!(env.feishu.received_of("verify").len(), 1);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_feishu_malformed_args_are_invalid_request_without_network_call() {
        let mut env = Env::start().await;
        // Fields other than the declared ones are refused before the plugin sees them.
        for fields in [
            json!({"app_id": "cli_a"}),
            json!({"app_secret": "secret"}),
            json!({"app_id": "cli_a", "app_secret": "secret", "token": "x"}),
        ] {
            refused(&mut env, "feishu", fields, DaemonError::InvalidRequest).await;
        }
        assert!(env.feishu.received_of("verify").is_empty());
        // The plugin judges the values.
        env.install("feishu", "verify_fail:malformed", "cli_a");
        let long = "x".repeat(129);
        for (app_id, app_secret) in [
            ("", "secret"),
            ("é", "secret"),
            (long.as_str(), "secret"),
            ("cli_a", ""),
        ] {
            refused(
                &mut env,
                "feishu",
                json!({"app_id": app_id, "app_secret": app_secret}),
                DaemonError::InvalidRequest,
            )
            .await;
        }
        assert_eq!(env.feishu.received_of("verify").len(), 4);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_feishu_receiver_rechecks_the_token_and_restarts_it() {
        let mut env = Env::with_channels().await;
        // The platform refuses the credential once receiving started.
        env.install("feishu", "suspend:credential_rejected", "cli_a");
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "feishu", "fields": {"app_id": "cli_a", "app_secret": "secret"}}),
            )
            .await
            .unwrap();
        let binding = Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap();
        let limit = Instant::now() + Duration::from_secs(10);
        while env.binding(binding).await["status"] != "suspended" {
            assert!(Instant::now() < limit, "receiver did not suspend");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            env.binding(binding).await["status_reason"],
            "credential_rejected"
        );
        env.install("feishu", "verify_fail:credential_rejected", "cli_a");
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()})
            )
            .await,
            Err(DaemonError::CredentialRejected)
        );
        let row = env.binding(binding).await;
        assert_eq!(row["status"], "suspended");
        assert_eq!(row["revision"], 1);
        env.install("feishu", "normal", "cli_a");
        let starts = env.feishu.received_of("start").len();
        let reconfirmed = env
            .call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()}),
            )
            .await
            .unwrap();
        assert_eq!(reconfirmed["revision"], 2);
        assert_eq!(env.binding(binding).await["status"], "active");
        waits_for("restart", || env.feishu.received_of("start").len() > starts).await;
        // Every check carried the stored secret and the receiver's app id.
        let verify = env.feishu.received_of("verify");
        assert_eq!(verify.len(), 3);
        for frame in &verify {
            assert_eq!(
                (&frame["credential"], &frame["source_key"]),
                (&json!("secret"), &json!("cli_a"))
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn bindings_receiver_replacement_stops_old_poller_before_new_starts() {
        let mut env = Env::with_channels().await;
        for round in 0..10 {
            env.call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": format!("1001:token-{round}")}}),
            )
            .await
            .unwrap();
            waits_for("start", || {
                env.telegram.received_of("start").len() == round + 1
            })
            .await;
            // Each replacement ends the old process before a new one starts with the new token.
            let frames: Vec<Value> = env
                .telegram
                .received()
                .into_iter()
                .filter(|frame| frame["type"] == "start" || frame["type"] == "hello")
                .map(|frame| json!([frame["type"], frame["credential"]]))
                .collect();
            let expected: Vec<Value> = (0..=round)
                .flat_map(|at| {
                    [
                        json!(["hello", null]),
                        json!(["start", format!("1001:token-{at}")]),
                    ]
                })
                .collect();
            assert_eq!(frames, expected, "round {round}");
            // The replaced receiver's store connection is closed.
            until(
                &env.client,
                "one receiver connection",
                "SELECT count(*)=1 FROM pg_stat_activity WHERE application_name='openmybot-receiver'",
            )
            .await;
        }
        let live: i64 = env.client.query_one("SELECT count(*) FROM openmybot.channel_bindings WHERE binding_kind='receiver' AND status='active'", &[]).await.unwrap().get(0);
        assert_eq!(live, 1);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn plugins_add_and_remove_end_the_running_process_and_free_its_slot() {
        let mut env = Env::with_channels().await;
        let telegram = ChannelKind::from_static("telegram");
        // A refused credential check leaves the plugin running without a binding.
        env.install("telegram", "verify_fail:credential_rejected", "1001");
        for op in ["plugins_add", "plugins_remove"] {
            assert_eq!(
                env.call(
                    "bindings_receiver",
                    json!({"channel": "telegram", "fields": {"token": "1001:token"}}),
                )
                .await,
                Err(DaemonError::CredentialRejected)
            );
            let plugin = env.ops.plugins.provider(&telegram).unwrap();
            let slots = |env: &Env| {
                env.channels
                    .as_ref()
                    .unwrap()
                    .context
                    .slots
                    .available_permits()
            };
            assert_eq!(
                env.ops.plugins.process(&plugin).0,
                crate::ProcessState::Running
            );
            assert_eq!(slots(&env), PLUGIN_MAX - 1);
            let replacement = (op == "plugins_add").then(|| {
                let mut channel = fake_channel(
                    "telegram",
                    &env.telegram,
                    "verify_fail:credential_rejected",
                    json!([{"name": "token", "secret": true}]),
                );
                channel["args"]
                    .as_array_mut()
                    .unwrap()
                    .extend([json!("--source-key"), json!("1001")]);
                package("fake-telegram", json!({ "telegram": channel }))
            });
            let args = match &replacement {
                Some(dir) => json!({ "dir": dir }),
                None => json!({"name": "fake-telegram"}),
            };
            env.call(op, args).await.unwrap();
            // The process went through the stop ladder before the package changed.
            assert_eq!(
                env.ops.plugins.process(&plugin).0,
                crate::ProcessState::Stopped
            );
            assert_eq!(slots(&env), PLUGIN_MAX);
            if let Some(dir) = replacement {
                std::fs::remove_dir_all(dir).unwrap();
            }
        }
        assert!(env.ops.plugins.provider(&telegram).is_none());
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
        env.call(
            "bindings_receiver",
            json!({"channel": "telegram", "fields": {"token": "1001:new-token"}}),
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
    async fn receiver_replacement_cancels_the_run_even_when_the_start_command_fails() {
        let mut env = Env::start().await;
        fixture::receiver(&env.client, "telegram").await;
        let (sender, thread) = env.sender().await;
        let run = env.begun(sender, &thread).await;
        let answer = {
            let replaced = env.ops.run(
                Op::BindingsReceiver,
                json!({"channel": "telegram", "fields": {"token": "1001:new-token"}}),
                later(),
                env.token,
            );
            tokio::pin!(replaced);
            loop {
                tokio::select! {
                    answer = &mut replaced => break answer,
                    Some(command) = env.commands.recv() => match command {
                        ReceiverCommand::Verify { reply, .. } => {
                            let _ = reply.send(Ok("1001".to_owned()));
                        }
                        // The start receipt is dropped unanswered after the replacement
                        // committed.
                        ReceiverCommand::Start(..)
                        | ReceiverCommand::Stop(..)
                        | ReceiverCommand::Retire(..) => {}
                    },
                }
            }
        };
        assert_eq!(answer, Err(DaemonError::InternalError));
        assert_eq!(env.cancel_state(&run).await, "already_requested");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn sealed_envelope_opens_with_the_receivers_principals() {
        let mut env = Env::start().await;
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": "1001:sealed-token"}}),
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
        env.install("telegram", "verify_fail:credential_rejected", "123456");
        let refused = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": SENTINEL}}),
            )
            .await
            .unwrap_err();
        seen.push(format!("{refused} {refused:?} {}", refused.code()));
        env.install("telegram", "normal", "123456");
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": SENTINEL}}),
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
        // The stored token now belongs to another bot.
        env.install("telegram", "normal", "2002");
        assert_eq!(
            env.call(
                "bindings_reconfirm",
                json!({"binding_id": binding.to_string()})
            )
            .await,
            Err(DaemonError::CredentialRejected)
        );
        assert_eq!(env.rows().await, before);
        env.install("telegram", "verify_fail:webhook_conflict", "1001");
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
        // Both checks carried the stored token and the receiver's source key.
        let verify = env.telegram.received_of("verify");
        assert_eq!(verify.len(), 2);
        for frame in &verify {
            assert_eq!(
                (&frame["credential"], &frame["source_key"]),
                (&json!("1001:reconfirm-token"), &json!("1001"))
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_receiver_success_restarts_the_poller_and_closes_the_gap() {
        let mut env = Env::with_channels().await;
        let binding = suspended_receiver(&mut env, "1001:reconfirm-token").await;
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
        waits_for("start", || !env.telegram.received_of("start").is_empty()).await;
        let start = env.telegram.received_of("start");
        assert_eq!(
            (&start[0]["credential"], &start[0]["source_key"]),
            (&json!("1001:reconfirm-token"), &json!("1001"))
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn reconfirm_wakes_dispatcher_for_pending_events_of_the_reactivated_binding() {
        let mut env = Env::with_channels().await;
        let (sender, thread) = env.sender().await;
        env.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='grant_stale',suspended_at=statement_timestamp(),granted_generation=0 WHERE binding_id=$1", &[&sender]).await.unwrap();
        let event = testkit::insert_event_for_run(
            &env.client,
            sender,
            &format!("run-{}", Uuid::now_v7()),
            thread.as_str(),
            "pending",
        )
        .await;
        // On the suspended binding a wake-up leaves the event pending.
        env.ops.wake.notify_one();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            testkit::read_row(&env.client, "channel_events", "record_id", event).await["dispatch_status"],
            "pending"
        );
        // No inbound message follows the reconfirm.
        env.call(
            "bindings_reconfirm",
            json!({"binding_id": sender.to_string()}),
        )
        .await
        .unwrap();
        let limit = Instant::now() + Duration::from_secs(10);
        loop {
            let row = testkit::read_row(&env.client, "channel_events", "record_id", event).await;
            if row["dispatch_status"] == "dispatched" {
                break;
            }
            assert!(Instant::now() < limit, "{row}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
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
    async fn revoke_cancels_the_run_even_when_the_stop_command_fails() {
        let mut env = Env::start().await;
        let (sender, thread) = env.sender().await;
        let run = env.begun(sender, &thread).await;
        // Nothing receives the command, so sending it fails after the revoke committed.
        env.commands.close();
        assert_eq!(
            env.call("bindings_revoke", json!({"binding_id": sender.to_string()}))
                .await,
            Err(DaemonError::InternalError)
        );
        assert_eq!(env.cancel_state(&run).await, "already_requested");
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_receiver_stops_the_poller_and_cascades_to_the_sender() {
        let mut env = Env::with_channels().await;
        let bound = env
            .call(
                "bindings_receiver",
                json!({"channel": "telegram", "fields": {"token": "1001:revoked-token"}}),
            )
            .await
            .unwrap();
        waits_for("start", || !env.telegram.received_of("start").is_empty()).await;
        let (sender, _) = env.sender().await;
        env.call(
            "bindings_revoke",
            json!({"binding_id": bound["binding_id"]}),
        )
        .await
        .unwrap();
        waits_for("stop", || !env.telegram.received_of("stop").is_empty()).await;
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

    async fn canceller(env: &mut Env) -> (CancelQueue, mpsc::Sender<Uuid>) {
        let connection = env
            .fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let (cancel, requests) = mpsc::channel(CANCEL_QUEUE);
        (
            CancelQueue::start(
                BindingRunCanceller::new(
                    env.ops.application.clone(),
                    env.ops.resolver.clone(),
                    Arc::new(connection.client),
                    Arc::default(),
                ),
                connection.driver,
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

    #[test]
    fn mcp_op_names_are_exactly_the_five_spec_names() {
        for (name, op) in [
            ("mcp_run_begin", McpOp::RunBegin),
            ("mcp_run_status", McpOp::RunStatus),
            ("mcp_run_cancel", McpOp::RunCancel),
            ("mcp_run_result", McpOp::RunResult),
            ("mcp_thread_list", McpOp::ThreadList),
        ] {
            assert_eq!(McpOp::parse(name), Some(op));
            assert_eq!(Op::parse(name), None);
        }
        for name in [
            "",
            "mcp_run_events",
            "mcp_run_begin ",
            "MCP_RUN_BEGIN",
            "wrok_run_begin",
            "status",
            "status_run",
            "pair_start",
            "bindings_list",
            "bindings_revoke",
            "bindings_reconfirm",
            "bindings_reset_thread",
            "bindings_receiver",
            "bindings_host",
            "approve",
            "deny",
            "cancel",
            "plugins_list",
            "plugins_add",
            "plugins_remove",
        ] {
            assert_eq!(McpOp::parse(name), None, "{name:?}");
        }
    }

    #[test]
    fn mcp_arguments_parse_once_into_narrow_types() {
        let invalid = |op, args| matches!(mcp::parse(op, args), Err(DaemonError::InvalidRequest));
        assert!(matches!(
            mcp::parse(McpOp::RunBegin, json!({"operation_id": "a", "message": ""})),
            Ok(mcp::McpRequest::Begin(operation, message))
                if operation.as_str() == "a" && message.as_str().is_empty()
        ));
        let longest = "a".repeat(125);
        assert!(matches!(
            mcp::parse(McpOp::RunBegin, json!({"operation_id": longest, "message": "m"})),
            Ok(mcp::McpRequest::Begin(operation, _)) if operation.as_str() == longest
        ));
        for args in [
            json!({"operation_id": "a".repeat(126), "message": "m"}),
            json!({"operation_id": "", "message": "m"}),
            json!({"operation_id": "a b", "message": "m"}),
            json!({"operation_id": "a/b", "message": "m"}),
            json!({"operation_id": "a", "message": "x".repeat(4097)}),
            json!({"operation_id": "a", "message": "a\u{0}b"}),
            json!({"operation_id": "a"}),
            json!({"operation_id": "a", "message": "m", "x": 1}),
            json!({"operation_id": 1, "message": "m"}),
            json!({"operation_id": "a", "message": 5}),
        ] {
            assert!(invalid(McpOp::RunBegin, args.clone()), "{args}");
        }
        for op in [McpOp::RunStatus, McpOp::RunCancel, McpOp::RunResult] {
            let key = match mcp::parse(op, json!({"run_id": "r1"})) {
                Ok(
                    mcp::McpRequest::Status(key)
                    | mcp::McpRequest::Cancel(key)
                    | mcp::McpRequest::Result(key),
                ) => key,
                _ => panic!("{op:?}"),
            };
            assert_eq!(key, IdentityKey::parse("r1").unwrap());
            for args in [
                json!({"run_id": ""}),
                json!({"run_id": "r".repeat(129)}),
                json!({"run_id": "r\u{1}1"}),
                json!({}),
                json!({"run_id": "r1", "x": 1}),
                json!({"run_id": 5}),
            ] {
                assert!(invalid(op, args.clone()), "{op:?} {args}");
            }
        }
        assert!(matches!(
            mcp::parse(McpOp::ThreadList, json!({})),
            Ok(mcp::McpRequest::List)
        ));
        assert!(invalid(McpOp::ThreadList, json!({"x": 1})));
        for op in [
            McpOp::RunBegin,
            McpOp::RunStatus,
            McpOp::RunCancel,
            McpOp::RunResult,
            McpOp::ThreadList,
        ] {
            for args in [json!([]), json!("x"), json!(5), Value::Null] {
                assert!(invalid(op, args.clone()), "{op:?} {args}");
            }
        }
    }

    async fn mcp_call(env: &Env, op: McpOp, args: Value) -> Result<Value, DaemonError> {
        env.ops.run_mcp(op, args, later()).await
    }
    fn begin(operation_id: &str, message: &str) -> Value {
        json!({"operation_id": operation_id, "message": message})
    }
    /// Takes the dispatcher wake-up a host acceptance leaves behind.
    async fn woken(env: &Env) -> bool {
        tokio::time::timeout(Duration::from_millis(100), env.ops.wake.notified())
            .await
            .is_ok()
    }
    async fn events(env: &Env) -> i64 {
        env.client
            .query_one("SELECT count(*) FROM openmybot.channel_events", &[])
            .await
            .unwrap()
            .get(0)
    }
    async fn host_event(env: &Env, operation_id: &str) -> Value {
        env.client
            .query_one(
                "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE event_key=$1",
                &[&format!("op:{operation_id}")],
            )
            .await
            .unwrap()
            .get(0)
    }
    /// Binds the host on the workspace through the owner's `bindings host` operation.
    async fn bound(env: &mut Env) -> Uuid {
        let workspace = env.workspace();
        let bound = env
            .call("bindings_host", json!({"workspace": workspace}))
            .await
            .unwrap();
        Uuid::parse_str(bound["binding_id"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn begin_accepts_then_replays_and_every_acceptance_call_wakes() {
        let env = Env::start().await;
        let host = host_binding(&env).await;
        let accepted = mcp_call(&env, McpOp::RunBegin, begin("op-1", "hello"))
            .await
            .unwrap();
        let keys: Vec<&String> = accepted.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["run_id", "state", "thread_id"]);
        assert_eq!(accepted["state"], "accepted");
        let run_id = accepted["run_id"].as_str().unwrap();
        assert_eq!(run_id.len(), 36);
        assert!(Uuid::parse_str(run_id).is_ok());
        let row = host_event(&env, "op-1").await;
        assert_eq!(row["binding_id"], host.to_string());
        assert_eq!(row["run_id"], accepted["run_id"]);
        assert_eq!(row["thread_id"], accepted["thread_id"]);
        assert_eq!(row["text"], "hello");
        assert_eq!(row["dispatch_status"], "pending");
        assert!(woken(&env).await);
        let replayed = mcp_call(&env, McpOp::RunBegin, begin("op-1", "hello"))
            .await
            .unwrap();
        assert_eq!(replayed["state"], "replayed");
        assert_eq!(replayed["run_id"], accepted["run_id"]);
        assert_eq!(replayed["thread_id"], accepted["thread_id"]);
        assert_eq!(events(&env).await, 1);
        assert!(woken(&env).await);
        let longest = mcp_call(&env, McpOp::RunBegin, begin(&"a".repeat(125), "m"))
            .await
            .unwrap();
        assert_eq!(longest["state"], "accepted");
        assert!(woken(&env).await);
        for args in [
            begin(&"a".repeat(126), "m"),
            begin("op-2", &"x".repeat(4097)),
            begin("op-2", "a\u{0}b"),
        ] {
            assert_eq!(
                mcp_call(&env, McpOp::RunBegin, args).await,
                Err(DaemonError::InvalidRequest)
            );
        }
        // Refused at the boundary: no acceptance call, no wake-up.
        assert_eq!(events(&env).await, 2);
        assert!(!woken(&env).await);
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-3", ""))
                .await
                .unwrap()["state"],
            "accepted"
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn conflicting_begin_counts_one_conflict_and_writes_nothing() {
        let env = Env::start().await;
        host_binding(&env).await;
        mcp_call(&env, McpOp::RunBegin, begin("op-1", "a"))
            .await
            .unwrap();
        assert!(woken(&env).await);
        let conflicts = || env.ops.counters.event_conflict.load(Ordering::Relaxed);
        assert_eq!(conflicts(), 0);
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-1", "b")).await,
            Err(DaemonError::OperationConflict)
        );
        assert_eq!(conflicts(), 1);
        assert_eq!(events(&env).await, 1);
        assert_eq!(host_event(&env, "op-1").await["text"], "a");
        assert!(woken(&env).await);
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-1", "b")).await,
            Err(DaemonError::OperationConflict)
        );
        assert_eq!(conflicts(), 2);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn every_mcp_op_checks_the_host_binding_first() {
        let mut env = Env::start().await;
        let calls = || {
            [
                (McpOp::RunBegin, begin("o", "m")),
                (McpOp::RunStatus, json!({"run_id": "r1"})),
                (McpOp::RunCancel, json!({"run_id": "r1"})),
                (McpOp::RunResult, json!({"run_id": "r1"})),
                (McpOp::ThreadList, json!({})),
            ]
        };
        for (op, args) in calls() {
            assert_eq!(
                mcp_call(&env, op, args).await,
                Err(DaemonError::HostNotBound)
            );
        }
        let host = host_binding(&env).await;
        testkit::suspend_binding(&env.client, host).await;
        for (op, args) in calls() {
            assert_eq!(
                mcp_call(&env, op, args).await,
                Err(DaemonError::HostBindingSuspended)
            );
        }
        omb_store::revoke_binding(&mut env.client, host, later())
            .await
            .unwrap();
        for (op, args) in calls() {
            assert_eq!(
                mcp_call(&env, op, args).await,
                Err(DaemonError::HostNotBound)
            );
        }
        assert_eq!(events(&env).await, 0);
        host_binding(&env).await;
        let [begun, status, cancel, result, list] = calls();
        let accepted = mcp_call(&env, begun.0, begun.1).await.unwrap();
        assert_eq!(accepted["state"], "accepted");
        for (op, args) in [status, cancel, result] {
            assert_eq!(
                mcp_call(&env, op, args).await,
                Err(DaemonError::RunNotFound)
            );
        }
        let runs = mcp_call(&env, list.0, list.1).await.unwrap();
        assert_eq!(runs["runs"][0]["run_id"], accepted["run_id"]);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn begin_refuses_the_twenty_first_pending_run() {
        let env = Env::start().await;
        host_binding(&env).await;
        let mut runs = Vec::new();
        for index in 1..=20 {
            let accepted = mcp_call(&env, McpOp::RunBegin, begin(&format!("op-{index}"), "m"))
                .await
                .unwrap();
            assert_eq!(accepted["state"], "accepted");
            runs.push(accepted["run_id"].clone());
        }
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-21", "m")).await,
            Err(DaemonError::DispatchQueueFull)
        );
        assert_eq!(events(&env).await, 20);
        let replayed = mcp_call(&env, McpOp::RunBegin, begin("op-4", "m"))
            .await
            .unwrap();
        assert_eq!(replayed["state"], "replayed");
        assert_eq!(replayed["run_id"], runs[3]);
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-4", "other")).await,
            Err(DaemonError::OperationConflict)
        );
        assert_eq!(
            mcp_call(&env, McpOp::RunCancel, json!({"run_id": runs[0]}))
                .await
                .unwrap()["state"],
            "requested"
        );
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-21", "m"))
                .await
                .unwrap()["state"],
            "accepted"
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_words_come_from_store_rows_without_an_engine_call() {
        let env = Env::start().await;
        let host = host_binding(&env).await;
        let client = &env.client;
        let event = async |run: &str, status: &str| {
            testkit::insert_event_for_run(client, host, run, &format!("thread-{run}"), status).await
        };
        event("pending", "pending").await;
        event("running", "dispatched").await;
        event("asking", "dispatched").await;
        testkit::insert_permission_row(client, host, "asking", "p-1", 600.0).await;
        for (run, kind) in [
            ("ok", "succeeded"),
            ("bad", "failed"),
            ("stopped", "cancelled"),
            ("unknown", "reconciliation_required"),
        ] {
            let record = event(run, "dispatched").await;
            testkit::set_terminal(client, record, kind).await;
        }
        event("expired", "expired").await;
        event("cancelled", "cancelled").await;
        event("conflict", "conflict").await;
        for (run, state, permissions) in [
            ("pending", "pending", vec![]),
            ("running", "running", vec![]),
            ("asking", "awaiting_permission", vec!["p-1"]),
            ("ok", "succeeded", vec![]),
            ("bad", "failed", vec![]),
            ("stopped", "cancelled", vec![]),
            ("unknown", "reconciliation_required", vec![]),
            ("expired", "cancelled", vec![]),
            ("cancelled", "cancelled", vec![]),
            ("conflict", "failed", vec![]),
        ] {
            assert_eq!(
                mcp_call(&env, McpOp::RunStatus, json!({"run_id": run}))
                    .await
                    .unwrap(),
                json!({"run_id": run, "state": state, "permission_ids": permissions}),
                "{run}"
            );
        }
        let (sender, thread) = env.sender().await;
        testkit::insert_event_for_run(client, sender, "sender-run", thread.as_str(), "pending")
            .await;
        for run in ["sender-run", "no-such-run"] {
            assert_eq!(
                mcp_call(&env, McpOp::RunStatus, json!({"run_id": run})).await,
                Err(DaemonError::RunNotFound)
            );
        }
        for run in [String::new(), "r".repeat(129), "r\u{1}1".to_owned()] {
            assert_eq!(
                mcp_call(&env, McpOp::RunStatus, json!({"run_id": run})).await,
                Err(DaemonError::InvalidRequest)
            );
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn result_returns_the_terminal_facts_or_run_not_terminal() {
        let env = Env::start().await;
        let host = host_binding(&env).await;
        let client = &env.client;
        let event = async |run: &str, status: &str| {
            testkit::insert_event_for_run(client, host, run, &format!("thread-{run}"), status).await
        };
        let result =
            async |run: &str| mcp_call(&env, McpOp::RunResult, json!({"run_id": run})).await;
        event("pending", "pending").await;
        event("running", "dispatched").await;
        for run in ["pending", "running"] {
            assert_eq!(result(run).await, Err(DaemonError::RunNotTerminal));
        }
        let record = event("ok", "dispatched").await;
        testkit::set_terminal(client, record, "succeeded").await;
        let workspace = env.workspace();
        let session = omb_store::upsert_session(
            client,
            omb_store::SessionStart {
                run_id: "ok",
                binding_id: host,
                workspace_dir: &workspace,
            },
            later(),
        )
        .await
        .unwrap();
        omb_store::end_session(
            client,
            session,
            omb_store::SessionEnd {
                reason: omb_store::EndReason::ResultSuccess,
                exit_code: Some(0),
                exit_signal: None,
                stop: None,
                result_summary: Some("done"),
                artifact_paths: &["a.txt".to_owned()],
                stderr_tail: "",
            },
            later(),
        )
        .await
        .unwrap();
        assert_eq!(
            result("ok").await.unwrap(),
            json!({"run_id": "ok", "terminal_kind": "succeeded", "summary": "done", "artifacts": ["a.txt"]})
        );
        let record = event("bad", "dispatched").await;
        testkit::set_terminal(client, record, "failed").await;
        assert_eq!(
            result("bad").await.unwrap(),
            json!({"run_id": "bad", "terminal_kind": "failed", "summary": null, "artifacts": []})
        );
        client
            .execute(
                "UPDATE openmybot.host_driver_sessions SET result_summary=NULL WHERE record_id=$1",
                &[&session],
            )
            .await
            .unwrap();
        assert_eq!(result("ok").await.unwrap()["summary"], Value::Null);
        for (run, status, kind) in [
            ("expired", "expired", "cancelled"),
            ("cancelled", "cancelled", "cancelled"),
            ("conflict", "conflict", "failed"),
        ] {
            event(run, status).await;
            assert_eq!(
                result(run).await.unwrap(),
                json!({"run_id": run, "terminal_kind": kind, "summary": null, "artifacts": []})
            );
        }
        assert_eq!(result("no-such-run").await, Err(DaemonError::RunNotFound));
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn thread_list_is_newest_first_and_capped_at_fifty() {
        let env = Env::start().await;
        let host = host_binding(&env).await;
        assert_eq!(
            mcp_call(&env, McpOp::ThreadList, json!({})).await.unwrap(),
            json!({"runs": []})
        );
        for index in 0..55 {
            let record = testkit::insert_event_for_run(
                &env.client,
                host,
                &format!("run-{index:02}"),
                &format!("thread-{index:02}"),
                "pending",
            )
            .await;
            testkit::shift_event(&env.client, record, "accepted_at", f64::from(index) - 100.0)
                .await;
        }
        let (sender, thread) = env.sender().await;
        testkit::insert_event_for_run(
            &env.client,
            sender,
            "sender-run",
            thread.as_str(),
            "pending",
        )
        .await;
        let listed = mcp_call(&env, McpOp::ThreadList, json!({})).await.unwrap();
        let runs = listed["runs"].as_array().unwrap();
        let expected: Vec<String> = (5..55)
            .rev()
            .map(|index| format!("run-{index:02}"))
            .collect();
        let ids: Vec<&str> = runs
            .iter()
            .map(|run| run["run_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, expected);
        for run in runs {
            let keys: Vec<&String> = run.as_object().unwrap().keys().collect();
            assert_eq!(keys, ["accepted_at", "run_id", "state", "thread_id"]);
            let accepted_at = run["accepted_at"].as_str().unwrap().as_bytes();
            assert_eq!(accepted_at.len(), 24);
            assert_eq!(accepted_at[10], b'T');
            assert_eq!(accepted_at[19], b'.');
            assert_eq!(accepted_at[23], b'Z');
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_answers_every_branch_of_the_run_lifecycle() {
        let mut env = Env::new(Fixture::start_with_host(agent::cooperative).await).await;
        let host = bound(&mut env).await;
        let cancel = async |env: &Env, run: &str| {
            mcp_call(env, McpOp::RunCancel, json!({"run_id": run})).await
        };
        let queued = mcp_call(&env, McpOp::RunBegin, begin("c-1", "queued"))
            .await
            .unwrap();
        let queued = queued["run_id"].as_str().unwrap();
        assert_eq!(
            cancel(&env, queued).await.unwrap(),
            json!({"run_id": queued, "state": "requested"})
        );
        assert_eq!(
            host_event(&env, "c-1").await["dispatch_status"],
            "cancelled"
        );
        assert_eq!(
            mcp_call(&env, McpOp::RunStatus, json!({"run_id": queued}))
                .await
                .unwrap()["state"],
            "cancelled"
        );
        assert_eq!(
            cancel(&env, queued).await.unwrap()["state"],
            "already_terminal"
        );
        let thread = env.minted().await;
        let run = env.begun(host, &thread).await;
        for state in ["requested", "already_requested"] {
            assert_eq!(
                cancel(&env, run.run.as_str()).await.unwrap()["state"],
                state
            );
        }
        env.runtime = Some(
            AgentRuntime::start(env.fixture.engine(), env.fixture.pg.database_config()).unwrap(),
        );
        agent::settled(&env.fixture, &run.thread).await;
        assert_eq!(
            cancel(&env, run.run.as_str()).await.unwrap()["state"],
            "already_terminal"
        );
        // Neither the engine nor the store knows this thread; the terminal alone answers.
        let ended = dispatched(&env.client, host, "run-ended", "thread-ended").await;
        testkit::set_terminal(&env.client, ended, "succeeded").await;
        assert_eq!(
            cancel(&env, "run-ended").await.unwrap()["state"],
            "already_terminal"
        );
        let (sender, sender_thread) = env.sender().await;
        let foreign = testkit::insert_event_for_run(
            &env.client,
            sender,
            "run-foreign",
            sender_thread.as_str(),
            "pending",
        )
        .await;
        for run in ["run-foreign", "no-such-run"] {
            assert_eq!(cancel(&env, run).await, Err(DaemonError::RunNotFound));
        }
        assert_eq!(
            testkit::read_row(&env.client, "channel_events", "record_id", foreign).await["dispatch_status"],
            "pending"
        );
        dispatched(&env.client, host, "run-refused", "thread-not-minted").await;
        assert_eq!(
            cancel(&env, "run-refused").await,
            Err(DaemonError::InternalError)
        );
        assert_eq!(
            mcp_call(&env, McpOp::RunStatus, json!({"run_id": queued}))
                .await
                .unwrap()["state"],
            "cancelled"
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn host_run_flows_from_begin_through_the_dispatcher_to_the_result() {
        let mut env = Env::running(Fixture::start_with_host(happy).await).await;
        let (cancel, _) = mpsc::channel(CANCEL_QUEUE);
        let terminals = env.fixture.take_terminals();
        let channels = Channels::start(
            &mut env.fixture.pg,
            env.fixture.engine.as_ref().unwrap(),
            env.token,
            quick_channels(),
            env.ops.plugins.clone(),
            cancel,
            Outbound {
                terminals,
                crabcode: None,
            },
            Arc::default(),
        )
        .await
        .unwrap();
        env.channels = Some(channels);
        env.ops.wake = env.channels.as_ref().unwrap().wake();
        let host = bound(&mut env).await;
        let accepted = mcp_call(&env, McpOp::RunBegin, begin("e2e-1", "do the work"))
            .await
            .unwrap();
        assert_eq!(accepted["state"], "accepted");
        let run_id = accepted["run_id"].as_str().unwrap();
        let order = ["pending", "running", "awaiting_permission", "succeeded"];
        let mut reached = 0;
        let limit = Instant::now() + Duration::from_secs(60);
        loop {
            let status = mcp_call(&env, McpOp::RunStatus, json!({"run_id": run_id}))
                .await
                .unwrap();
            let state = status["state"].as_str().unwrap();
            let at = order
                .iter()
                .position(|word| *word == state)
                .unwrap_or_else(|| panic!("{state}"));
            assert!(at >= reached, "{state} after {}", order[reached]);
            reached = at;
            if state == "succeeded" {
                break;
            }
            assert!(Instant::now() < limit, "host run deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            mcp_call(&env, McpOp::RunResult, json!({"run_id": run_id}))
                .await
                .unwrap(),
            json!({"run_id": run_id, "terminal_kind": "succeeded", "summary": "hello from fake", "artifacts": []})
        );
        let listed = mcp_call(&env, McpOp::ThreadList, json!({})).await.unwrap();
        assert!(
            listed["runs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|run| run["run_id"] == run_id && run["state"] == "succeeded"),
            "{listed}"
        );
        let replayed = mcp_call(&env, McpOp::RunBegin, begin("e2e-1", "do the work"))
            .await
            .unwrap();
        assert_eq!(replayed["state"], "replayed");
        assert_eq!(replayed["run_id"], run_id);
        let deliveries: i64 = env
            .client
            .query_one(
                "SELECT count(*) FROM openmybot.deliveries WHERE binding_id=$1",
                &[&host],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(deliveries, 0);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn thread_minter_mints_distinct_ids_and_writes_no_row() {
        let env = Env::start().await;
        let minter = ThreadMinter::new(env.ops.application.clone(), env.ops.resolver.clone());
        let before = env.rows().await;
        let first = minter.mint().await.unwrap();
        let second = minter.mint().await.unwrap();
        assert_ne!(first.as_str(), second.as_str());
        for thread in [&first, &second] {
            assert!((1..=128).contains(&thread.as_str().len()), "{thread:?}");
        }
        assert_eq!(env.rows().await, before);
        host_binding(&env).await;
        mcp_call(&env, McpOp::RunBegin, begin("op-1", "m"))
            .await
            .unwrap();
        let accepted = env.rows().await;
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("op-1", "m"))
                .await
                .unwrap()["state"],
            "replayed"
        );
        assert_eq!(env.rows().await, accepted);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn host_event_expiry_does_not_end_the_dispatcher() {
        let mut env = Env::with_channels().await;
        let host = bound(&mut env).await;
        let thread = env.minted().await;
        let aged = accept_host_begin(
            &mut env.client,
            &OperationId::parse("aged-1").unwrap(),
            &HostMessage::parse("old").unwrap(),
            thread.as_str(),
            later(),
        )
        .await
        .unwrap();
        assert!(matches!(aged, HostAccept::Accepted(_)));
        let record = host_event(&env, "aged-1").await["record_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        testkit::shift_event(&env.client, record, "accepted_at", -100_000.0).await;
        env.ops.wake.notify_one();
        let limit = Instant::now() + Duration::from_secs(30);
        while host_event(&env, "aged-1").await["dispatch_status"] != "expired" {
            assert!(Instant::now() < limit, "expiry deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let deliveries: i64 = env
            .client
            .query_one(
                "SELECT count(*) FROM openmybot.deliveries WHERE binding_id=$1",
                &[&host],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(deliveries, 0);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                env.channels.as_mut().unwrap().finished()
            )
            .await
            .is_err()
        );
        let fresh = mcp_call(&env, McpOp::RunBegin, begin("fresh-1", "new"))
            .await
            .unwrap();
        assert_eq!(fresh["state"], "accepted");
        let limit = Instant::now() + Duration::from_secs(30);
        while mcp_call(&env, McpOp::RunStatus, json!({"run_id": fresh["run_id"]}))
            .await
            .unwrap()["state"]
            != "running"
        {
            assert!(Instant::now() < limit, "dispatch deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_queue_stop_returns_while_a_handle_clone_is_alive() {
        let mut env = Env::start().await;
        let connection = env
            .fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let (cancel, requests) = mpsc::channel(CANCEL_QUEUE);
        let handle = BindingRunCanceller::new(
            env.ops.application.clone(),
            env.ops.resolver.clone(),
            Arc::new(connection.client),
            Arc::default(),
        );
        let queue = CancelQueue::start(handle.clone(), connection.driver, requests);
        drop(cancel);
        tokio::time::timeout(Duration::from_secs(5), queue.stop())
            .await
            .unwrap();
        assert_eq!(
            handle.cancel(Uuid::now_v7(), "r", later()).await,
            Err(DaemonError::InternalError)
        );
        env.stop().await;
    }

    /// Polls `sql`, one boolean, until it holds.
    async fn until(client: &Client, what: &str, sql: &str) {
        let limit = Instant::now() + Duration::from_secs(20);
        while !client.query_one(sql, &[]).await.unwrap().get::<_, bool>(0) {
            assert!(Instant::now() < limit, "{what} deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    /// Whether operation `next` was dispatched no earlier than operation `ended` reached its terminal.
    async fn dispatched_after_terminal(env: &Env, ended: &str, next: &str) -> bool {
        env.client
            .query_one(
                "SELECT n.dispatched_at>=e.terminal_at FROM openmybot.channel_events e, openmybot.channel_events n WHERE e.event_key=$1 AND n.event_key=$2",
                &[&format!("op:{ended}"), &format!("op:{next}")],
            )
            .await
            .unwrap()
            .get(0)
    }
    /// Cancels the dispatched run of `operation_id` and waits for its terminal.
    async fn cancelled_after_dispatch(env: &Env, operation_id: &str) {
        let key = format!("op:{operation_id}");
        until(
            &env.client,
            "dispatch",
            &format!("SELECT dispatch_status='dispatched' FROM openmybot.channel_events WHERE event_key='{key}'"),
        )
        .await;
        let run = host_event(env, operation_id).await["run_id"].clone();
        assert_eq!(
            mcp_call(env, McpOp::RunCancel, json!({"run_id": run}))
                .await
                .unwrap()["state"],
            "requested"
        );
        until(
            &env.client,
            "terminal",
            &format!("SELECT terminal_kind IS NOT NULL FROM openmybot.channel_events WHERE event_key='{key}'"),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_during_the_dispatch_begin_stops_the_run_before_the_next_event() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        env.serve().await;
        bound(&mut env).await;
        let gate = env.fixture.client().await;
        for round in 0..10 {
            let (first, second) = (format!("a-{round}"), format!("b-{round}"));
            let thread = env.minted().await;
            // The engine's begin takes this thread's transaction lock first; holding it parks the
            // dispatcher inside the begin with the event locked.
            gate.execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            for (operation, on) in [(&first, thread.clone()), (&second, env.minted().await)] {
                let accepted = accept_host_begin(
                    &mut env.client,
                    &OperationId::parse(operation).unwrap(),
                    &HostMessage::parse("work").unwrap(),
                    on.as_str(),
                    later(),
                )
                .await
                .unwrap();
                assert!(matches!(accepted, HostAccept::Accepted(_)), "round {round}");
            }
            env.ops.wake.notify_one();
            until(
                &gate,
                "begin parked",
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
            )
            .await;
            let run = host_event(&env, &first).await["run_id"].clone();
            let cancelled = mcp_call(&env, McpOp::RunCancel, json!({"run_id": run}));
            tokio::pin!(cancelled);
            // The dispatch holds the gate inside its begin: the cancel waits for it.
            assert!(
                tokio::time::timeout(Duration::from_millis(300), &mut cancelled)
                    .await
                    .is_err(),
                "round {round}"
            );
            gate.execute(
                "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            assert_eq!(
                cancelled.await.unwrap()["state"],
                "requested",
                "round {round}"
            );
            let key = format!("op:{first}");
            until(
                &env.client,
                "first terminal",
                &format!("SELECT terminal_kind IS NOT NULL FROM openmybot.channel_events WHERE event_key='{key}'"),
            )
            .await;
            let ended = host_event(&env, &first).await;
            assert_eq!(ended["dispatch_status"], "dispatched", "round {round}");
            assert_eq!(ended["terminal_kind"], "cancelled", "round {round}");
            cancelled_after_dispatch(&env, &second).await;
            assert!(
                dispatched_after_terminal(&env, &first, &second).await,
                "round {round}"
            );
        }
        drop(gate);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_in_the_reconciliation_backoff_stops_the_begun_run_before_the_next_event() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        let host = bound(&mut env).await;
        for (operation, message) in [("a-1", "first"), ("b-1", "second")] {
            mcp_call(&env, McpOp::RunBegin, begin(operation, message))
                .await
                .unwrap();
        }
        // The dispatcher's begin committed the run, yet its receipt was an accepted
        // reconciliation: the run executes while the event waits for its retry.
        let row = host_event(&env, "a-1").await;
        let record: Uuid = row["record_id"].as_str().unwrap().parse().unwrap();
        let run = row["run_id"].as_str().unwrap();
        env.fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap()
            .begin(BeginDelegatedThreadRun {
                source: DelegationSource::ExternalBinding {
                    binding_id: host.to_string(),
                },
                revision: env.binding(host).await["revision"].as_u64().unwrap(),
                trigger_id: record.to_string(),
                thread_id: ThreadId::new(row["thread_id"].as_str().unwrap()),
                run_id: RunId::new(run),
                bot_id: BotId::new(BOT_ID),
                untrusted_material: Some(DelegatedUntrustedMaterial {
                    source_ref: format!("omb:channel_events:{record}"),
                    text: "first".into(),
                }),
            })
            .await
            .unwrap();
        let dispatch = lock_dispatch(&mut env.client, record, later())
            .await
            .unwrap()
            .unwrap();
        record_dispatch(
            dispatch,
            record,
            DispatchOutcome::RetryAfter(Duration::from_secs(5)),
            later(),
        )
        .await
        .unwrap();
        env.serve().await;
        assert_eq!(
            mcp_call(&env, McpOp::RunCancel, json!({"run_id": run}))
                .await
                .unwrap()["state"],
            "requested"
        );
        // The cancel landed inside the backoff: the event still waits for its retry.
        let waiting = host_event(&env, "a-1").await;
        assert_eq!(
            (&waiting["dispatch_status"], &waiting["dispatch_attempts"]),
            (&json!("pending"), &json!(1))
        );
        assert_eq!(host_event(&env, "b-1").await["dispatch_status"], "pending");
        until(
            &env.client,
            "first terminal",
            "SELECT terminal_kind IS NOT NULL FROM openmybot.channel_events WHERE event_key='op:a-1'",
        )
        .await;
        let ended = host_event(&env, "a-1").await;
        assert_eq!(ended["terminal_kind"], "cancelled");
        cancelled_after_dispatch(&env, "b-1").await;
        assert!(dispatched_after_terminal(&env, "a-1", "b-1").await);
        assert_eq!(
            host_event(&env, "a-1").await["dispatch_status"],
            "dispatched"
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_before_the_claim_never_starts_the_run_and_the_next_event_proceeds() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        bound(&mut env).await;
        for (operation, message) in [("a-1", "first"), ("b-1", "second")] {
            mcp_call(&env, McpOp::RunBegin, begin(operation, message))
                .await
                .unwrap();
        }
        let first = host_event(&env, "a-1").await;
        assert_eq!(
            mcp_call(&env, McpOp::RunCancel, json!({"run_id": first["run_id"]}))
                .await
                .unwrap()["state"],
            "requested"
        );
        env.serve().await;
        cancelled_after_dispatch(&env, "b-1").await;
        let first = host_event(&env, "a-1").await;
        assert_eq!(first["dispatch_status"], "cancelled");
        assert_eq!(first["dispatch_attempts"], 0);
        assert!(first["terminal_kind"].is_null());
        let run = first["run_id"].as_str().unwrap();
        assert_eq!(
            cancel_run(
                env.ops.application.as_ref(),
                &env.ops.resolver,
                first["thread_id"].as_str().unwrap(),
                run,
            )
            .await,
            Ok(None)
        );
        let sessions: i64 = env
            .client
            .query_one(
                "SELECT count(*) FROM openmybot.host_driver_sessions WHERE run_id=$1",
                &[&run],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(sessions, 0);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn begin_whose_commit_ends_past_the_deadline_still_wakes_the_dispatcher() {
        let mut env = Env::with_channels().await;
        bound(&mut env).await;
        env.client.batch_execute("CREATE FUNCTION openmybot.fixture_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1.5); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER fixture_commit_delay AFTER INSERT ON openmybot.channel_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openmybot.fixture_commit_delay()").await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let accepted = env
            .ops
            .run_mcp(McpOp::RunBegin, begin("late-1", "m"), deadline)
            .await
            .unwrap();
        assert!(Instant::now() >= deadline);
        assert_eq!(accepted["state"], "accepted");
        until(
            &env.client,
            "dispatch",
            "SELECT dispatch_status='dispatched' FROM openmybot.channel_events WHERE event_key='op:late-1'",
        )
        .await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_in_a_backoff_without_an_engine_run_cancels_the_event_and_the_retry_skips_it() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        bound(&mut env).await;
        for (operation, message) in [("a-1", "first"), ("b-1", "second")] {
            mcp_call(&env, McpOp::RunBegin, begin(operation, message))
                .await
                .unwrap();
        }
        // The begin created no run, as on a lease conflict or an unavailable dependency, and its
        // receipt scheduled a retry.
        let first = host_event(&env, "a-1").await;
        let record: Uuid = first["record_id"].as_str().unwrap().parse().unwrap();
        let dispatch = lock_dispatch(&mut env.client, record, later())
            .await
            .unwrap()
            .unwrap();
        record_dispatch(
            dispatch,
            record,
            DispatchOutcome::RetryAfter(Duration::from_millis(100)),
            later(),
        )
        .await
        .unwrap();
        assert_eq!(
            mcp_call(&env, McpOp::RunCancel, json!({"run_id": first["run_id"]}))
                .await
                .unwrap()["state"],
            "requested"
        );
        let cancelled = host_event(&env, "a-1").await;
        assert_eq!(
            (
                &cancelled["dispatch_status"],
                &cancelled["dispatch_attempts"]
            ),
            (&json!("cancelled"), &json!(1))
        );
        // The retry is due when the dispatcher starts; it passes the cancelled event by.
        tokio::time::sleep(Duration::from_millis(200)).await;
        env.serve().await;
        cancelled_after_dispatch(&env, "b-1").await;
        let skipped = host_event(&env, "a-1").await;
        assert_eq!(
            (&skipped["dispatch_status"], &skipped["dispatch_attempts"]),
            (&json!("cancelled"), &json!(1))
        );
        assert!(skipped["dispatched_at"].is_null());
        assert_eq!(
            cancel_run(
                env.ops.application.as_ref(),
                &env.ops.resolver,
                first["thread_id"].as_str().unwrap(),
                first["run_id"].as_str().unwrap(),
            )
            .await,
            Ok(None)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_waits_for_a_dispatch_whose_session_ends_mid_begin_and_stops_the_begun_run() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        bound(&mut env).await;
        let mut terminals = env.fixture.take_terminals();
        let entry = env
            .fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap();
        let gate = env.fixture.client().await;
        let mut previous: Option<String> = None;
        for round in 0..10 {
            let operation = format!("lost-{round}");
            let thread = env.minted().await;
            // The engine's begin takes this thread's lock first; holding it parks the begin.
            gate.execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            let HostAccept::Accepted(run) = accept_host_begin(
                &mut env.client,
                &OperationId::parse(&operation).unwrap(),
                &HostMessage::parse("work").unwrap(),
                thread.as_str(),
                later(),
            )
            .await
            .unwrap() else {
                panic!("round {round}: not accepted");
            };
            let opened = env
                .fixture
                .pg
                .open_resident_connection("openmybot-dispatcher")
                .await
                .unwrap();
            let wake = Arc::new(Notify::new());
            let mut dispatcher = start_dispatcher(
                Connection {
                    client: opened.client,
                    driver: opened.driver,
                },
                entry.clone(),
                quick_channels(),
                Arc::clone(&wake),
                Arc::clone(&env.ops.canceller.gate),
            );
            wake.notify_one();
            until(
                &gate,
                "begin parked",
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
            )
            .await;
            let parked = Instant::now();
            // The event the previous round left pending was replayed to dispatched first.
            if let Some(previous) = &previous {
                assert_eq!(
                    host_event(&env, previous).await["dispatch_status"],
                    "dispatched",
                    "round {round}"
                );
            }
            // The server ends the dispatcher's session between its begin and its commit.
            let ended: bool = gate
                .query_one(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='openmybot-dispatcher'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert!(ended, "round {round}");
            let cancelled = {
                let cancelled = mcp_call(&env, McpOp::RunCancel, json!({"run_id": run.run_id}));
                tokio::pin!(cancelled);
                assert!(
                    tokio::time::timeout_at(parked + Duration::from_secs(3), &mut cancelled)
                        .await
                        .is_err(),
                    "round {round}: the cancel waits for the gate"
                );
                gate.execute(
                    "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                    &[&thread.as_str()],
                )
                .await
                .unwrap();
                // The begin commits the run; its receipt finds the session gone.
                assert_eq!(
                    dispatcher.finished().await,
                    Err(ChannelError::StoreFailed),
                    "round {round}"
                );
                cancelled.await.unwrap()
            };
            assert_eq!(cancelled["state"], "requested", "round {round}");
            let waiting = host_event(&env, &operation).await;
            assert_eq!(
                (&waiting["dispatch_status"], &waiting["dispatch_attempts"]),
                (&json!("pending"), &json!(0)),
                "round {round}"
            );
            let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (notice.run_id.as_str(), notice.terminal),
                (run.run_id.as_str(), RunTerminalKind::Cancelled),
                "round {round}"
            );
            assert_eq!(
                host_event(&env, &operation).await["dispatch_status"],
                "pending",
                "round {round}"
            );
            // Recorded as the sender records a notice, so the next dispatch can replay the event.
            record_terminal(
                &mut env.client,
                &run.run_id,
                TerminalKind::Cancelled,
                later(),
            )
            .await
            .unwrap();
            dispatcher.stop().await;
            previous = Some(operation);
        }
        drop(gate);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn replayed_begin_wakes_the_dispatcher_for_an_event_whose_wake_was_lost() {
        let mut env = Env::with_channels().await;
        bound(&mut env).await;
        until(
            &env.client,
            "dispatcher idle",
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name='openmybot-dispatcher' AND state='idle' AND query LIKE 'SELECT e.record_id,%')",
        )
        .await;
        // Written without a wake-up, as when the commit outlives the caller's wait.
        let thread = env.minted().await;
        let accepted = accept_host_begin(
            &mut env.client,
            &OperationId::parse("lost-1").unwrap(),
            &HostMessage::parse("m").unwrap(),
            thread.as_str(),
            later(),
        )
        .await
        .unwrap();
        assert!(matches!(accepted, HostAccept::Accepted(_)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            host_event(&env, "lost-1").await["dispatch_status"],
            "pending"
        );
        assert_eq!(
            mcp_call(&env, McpOp::RunBegin, begin("lost-1", "m"))
                .await
                .unwrap()["state"],
            "replayed"
        );
        until(
            &env.client,
            "dispatch",
            "SELECT dispatch_status='dispatched' FROM openmybot.channel_events WHERE event_key='op:lost-1'",
        )
        .await;
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancel_while_a_begin_commit_is_unknown_answers_request_timeout_until_the_replay() {
        let mut env = Env::running(Fixture::start_through_proxy(agent::cooperative).await).await;
        bound(&mut env).await;
        let mut terminals = env.fixture.take_terminals();
        let entry = env
            .fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap();
        let gate = env.fixture.client().await;
        let opened = env
            .fixture
            .pg
            .open_resident_connection("openmybot-dispatcher")
            .await
            .unwrap();
        let wake = Arc::new(Notify::new());
        // A retry of a withheld begin is rare inside the window, and harmless: it waits for the
        // thread lock, gets an unavailable dependency and keeps the mark.
        let dispatcher = start_dispatcher(
            Connection {
                client: opened.client,
                driver: opened.driver,
            },
            entry,
            Timings {
                backoff_min: Duration::from_secs(3600),
                backoff_max: Duration::from_secs(3600),
                ..quick_channels()
            },
            Arc::clone(&wake),
            Arc::clone(&env.ops.canceller.gate),
        );
        for round in 0..10 {
            let operation = format!("u-{round}");
            let key = format!("op:{operation}");
            let thread = env.minted().await;
            // The engine's begin takes this thread's lock first; holding it parks the begin.
            gate.execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            let HostAccept::Accepted(run) = accept_host_begin(
                &mut env.client,
                &OperationId::parse(&operation).unwrap(),
                &HostMessage::parse("work").unwrap(),
                thread.as_str(),
                later(),
            )
            .await
            .unwrap() else {
                panic!("round {round}: not accepted");
            };
            wake.notify_one();
            until(
                &gate,
                "begin parked",
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
            )
            .await;
            let pid: i32 = gate
                .query_one(
                    "SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            let proxy = env.fixture.proxy.as_ref().unwrap();
            proxy.hold_commit_of(pid);
            gate.execute(
                "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            // The begin's COMMIT is withheld: its client loses the connection, so the receipt is
            // an accepted reconciliation, and the run lands only on release.
            until(
                &env.client,
                "unknown receipt",
                &format!("SELECT dispatch_status='pending' AND dispatch_attempts>=1 FROM openmybot.channel_events WHERE event_key='{key}'"),
            )
            .await;
            assert!(proxy.holding(), "round {round}");
            assert_eq!(
                mcp_call(&env, McpOp::RunCancel, json!({"run_id": run.run_id})).await,
                Err(DaemonError::RequestTimeout),
                "round {round}"
            );
            let waiting = host_event(&env, &operation).await;
            assert_eq!(waiting["dispatch_status"], "pending", "round {round}");
            assert!(
                waiting["dispatch_attempts"].as_i64().unwrap() >= 1,
                "round {round}"
            );
            proxy.release().await;
            // The next attempt replays the landed run.
            let record: Uuid = waiting["record_id"].as_str().unwrap().parse().unwrap();
            testkit::shift_event(&env.client, record, "next_dispatch_at", 0.0).await;
            wake.notify_one();
            until(
                &env.client,
                "replay",
                &format!("SELECT dispatch_status='dispatched' FROM openmybot.channel_events WHERE event_key='{key}'"),
            )
            .await;
            assert_eq!(
                mcp_call(&env, McpOp::RunCancel, json!({"run_id": run.run_id}))
                    .await
                    .unwrap()["state"],
                "requested",
                "round {round}"
            );
            let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (notice.run_id.as_str(), notice.terminal),
                (run.run_id.as_str(), RunTerminalKind::Cancelled),
                "round {round}"
            );
            // Recorded as the sender records a notice, so the next event can be claimed.
            record_terminal(
                &mut env.client,
                &run.run_id,
                TerminalKind::Cancelled,
                later(),
            )
            .await
            .unwrap();
        }
        dispatcher.stop().await;
        drop(gate);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_waits_for_a_dispatch_in_flight_and_stops_the_run_it_began() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        let mut terminals = env.fixture.take_terminals();
        let entry = env
            .fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap();
        let gate = env.fixture.client().await;
        for round in 0..10 {
            // Each round binds anew: the previous binding is revoked.
            let host = bound(&mut env).await;
            let operation = format!("r-{round}");
            let thread = env.minted().await;
            // The engine's begin takes this thread's lock first; holding it parks the begin.
            gate.execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            let HostAccept::Accepted(run) = accept_host_begin(
                &mut env.client,
                &OperationId::parse(&operation).unwrap(),
                &HostMessage::parse("work").unwrap(),
                thread.as_str(),
                later(),
            )
            .await
            .unwrap() else {
                panic!("round {round}: not accepted");
            };
            let opened = env
                .fixture
                .pg
                .open_resident_connection("openmybot-dispatcher")
                .await
                .unwrap();
            let wake = Arc::new(Notify::new());
            let mut dispatcher = start_dispatcher(
                Connection {
                    client: opened.client,
                    driver: opened.driver,
                },
                entry.clone(),
                quick_channels(),
                Arc::clone(&wake),
                Arc::clone(&env.ops.canceller.gate),
            );
            wake.notify_one();
            until(
                &gate,
                "begin parked",
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
            )
            .await;
            let parked = Instant::now();
            // Even rounds: the server ends the dispatcher's session between its begin and its
            // receipt, so the begun run's event stays pending.
            let lost = round % 2 == 0;
            if lost {
                let ended: bool = gate
                    .query_one(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='openmybot-dispatcher'",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                assert!(ended, "round {round}");
            }
            let revoked = env.ops.run(
                Op::BindingsRevoke,
                json!({"binding_id": host.to_string()}),
                later(),
                env.token,
            );
            tokio::pin!(revoked);
            // Answer the receiver commands while asserting, as `call_until` does: a revoke
            // that is not held by the gate would otherwise also stall on the missing answer.
            loop {
                tokio::select! {
                    answer = &mut revoked => {
                        panic!("round {round}: the revoke waits for the gate, but answered {answer:?}")
                    }
                    Some(command) = env.commands.recv() => {
                        if let ReceiverCommand::Stop(_, done) = command {
                            let _ = done.send(());
                        }
                    }
                    () = tokio::time::sleep_until(parked + Duration::from_secs(3)) => break,
                }
            }
            gate.execute(
                "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            if lost {
                // The begin commits the run; its receipt finds the session gone.
                assert_eq!(
                    dispatcher.finished().await,
                    Err(ChannelError::StoreFailed),
                    "round {round}"
                );
            }
            let answer = loop {
                tokio::select! {
                    answer = &mut revoked => break answer,
                    Some(command) = env.commands.recv() => {
                        if let ReceiverCommand::Stop(_, done) = command {
                            let _ = done.send(());
                        }
                    }
                }
            };
            assert_eq!(
                answer,
                Ok(json!({"binding_id": host.to_string(), "cancelled_runs": 1})),
                "round {round}"
            );
            assert_eq!(
                host_event(&env, &operation).await["dispatch_status"],
                if lost { "cancelled" } else { "dispatched" },
                "round {round}"
            );
            // The stop request races the run's delegation check at its first sampling.
            let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(notice.run_id.as_str(), run.run_id, "round {round}");
            assert!(
                matches!(
                    notice.terminal,
                    RunTerminalKind::Cancelled | RunTerminalKind::Failed
                ),
                "round {round}"
            );
            assert_eq!(
                cancel_run(
                    env.ops.application.as_ref(),
                    &env.ops.resolver,
                    &run.thread_id,
                    &run.run_id,
                )
                .await,
                Ok(Some("already_terminal")),
                "round {round}"
            );
            dispatcher.stop().await;
        }
        drop(gate);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_stops_the_running_run_of_a_pending_event_and_counts_only_engine_runs() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        let mut terminals = env.fixture.take_terminals();
        let host = bound(&mut env).await;
        for (operation, message) in [("a-1", "first"), ("b-1", "second")] {
            mcp_call(&env, McpOp::RunBegin, begin(operation, message))
                .await
                .unwrap();
        }
        // An earlier begin committed the run, yet its receipt was an accepted reconciliation:
        // the run executes while the event waits for its retry.
        let row = host_event(&env, "a-1").await;
        let record: Uuid = row["record_id"].as_str().unwrap().parse().unwrap();
        let run = row["run_id"].as_str().unwrap();
        env.fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap()
            .begin(BeginDelegatedThreadRun {
                source: DelegationSource::ExternalBinding {
                    binding_id: host.to_string(),
                },
                revision: env.binding(host).await["revision"].as_u64().unwrap(),
                trigger_id: record.to_string(),
                thread_id: ThreadId::new(row["thread_id"].as_str().unwrap()),
                run_id: RunId::new(run),
                bot_id: BotId::new(BOT_ID),
                untrusted_material: Some(DelegatedUntrustedMaterial {
                    source_ref: format!("omb:channel_events:{record}"),
                    text: "first".into(),
                }),
            })
            .await
            .unwrap();
        let dispatch = lock_dispatch(&mut env.client, record, later())
            .await
            .unwrap()
            .unwrap();
        record_dispatch(
            dispatch,
            record,
            DispatchOutcome::RetryAfter(Duration::from_secs(5)),
            later(),
        )
        .await
        .unwrap();
        // With its session row the run is past its first sampling: only the cancel ends it.
        until(
            &env.client,
            "host session",
            &format!(
                "SELECT EXISTS (SELECT 1 FROM openmybot.host_driver_sessions WHERE run_id='{run}')"
            ),
        )
        .await;
        // `b-1` has no engine run: it is neither counted nor an error.
        assert_eq!(
            env.call("bindings_revoke", json!({"binding_id": host.to_string()}))
                .await,
            Ok(json!({"binding_id": host.to_string(), "cancelled_runs": 1}))
        );
        for operation in ["a-1", "b-1"] {
            assert_eq!(
                host_event(&env, operation).await["dispatch_status"],
                "cancelled",
                "{operation}"
            );
        }
        let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (notice.run_id.as_str(), notice.terminal),
            (run, RunTerminalKind::Cancelled)
        );
        let second = host_event(&env, "b-1").await;
        assert_eq!(
            cancel_run(
                env.ops.application.as_ref(),
                &env.ops.resolver,
                second["thread_id"].as_str().unwrap(),
                second["run_id"].as_str().unwrap(),
            )
            .await,
            Ok(None)
        );
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoke_during_an_unknown_begin_lets_the_landed_run_fail_its_delegation_check() {
        let mut env = Env::running(Fixture::start_through_proxy(agent::cooperative).await).await;
        let host = bound(&mut env).await;
        let mut terminals = env.fixture.take_terminals();
        let entry = env
            .fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap();
        let gate = env.fixture.client().await;
        let thread = env.minted().await;
        gate.execute(
            "SELECT pg_advisory_lock(hashtextextended($1,0))",
            &[&thread.as_str()],
        )
        .await
        .unwrap();
        let HostAccept::Accepted(run) = accept_host_begin(
            &mut env.client,
            &OperationId::parse("unknown-1").unwrap(),
            &HostMessage::parse("work").unwrap(),
            thread.as_str(),
            later(),
        )
        .await
        .unwrap() else {
            panic!("not accepted");
        };
        let opened = env
            .fixture
            .pg
            .open_resident_connection("openmybot-dispatcher")
            .await
            .unwrap();
        let wake = Arc::new(Notify::new());
        let dispatcher = start_dispatcher(
            Connection {
                client: opened.client,
                driver: opened.driver,
            },
            entry,
            Timings {
                backoff_min: Duration::from_secs(3600),
                backoff_max: Duration::from_secs(3600),
                ..quick_channels()
            },
            Arc::clone(&wake),
            Arc::clone(&env.ops.canceller.gate),
        );
        wake.notify_one();
        until(
            &gate,
            "begin parked",
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
        )
        .await;
        let pid: i32 = gate
            .query_one(
                "SELECT pid FROM pg_locks WHERE locktype='advisory' AND NOT granted",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        env.fixture.proxy.as_ref().unwrap().hold_commit_of(pid);
        gate.execute(
            "SELECT pg_advisory_unlock(hashtextextended($1,0))",
            &[&thread.as_str()],
        )
        .await
        .unwrap();
        until(
            &env.client,
            "unknown receipt",
            "SELECT dispatch_status='pending' AND dispatch_attempts>=1 FROM openmybot.channel_events WHERE event_key='op:unknown-1'",
        )
        .await;
        assert!(env.fixture.proxy.as_ref().unwrap().holding());
        // The engine does not see the withheld run yet, so the revoke counts none.
        assert_eq!(
            env.call("bindings_revoke", json!({"binding_id": host.to_string()}))
                .await,
            Ok(json!({"binding_id": host.to_string(), "cancelled_runs": 0}))
        );
        assert_eq!(
            host_event(&env, "unknown-1").await["dispatch_status"],
            "cancelled"
        );
        env.fixture.proxy.as_ref().unwrap().release().await;
        // The run lands after the revoke committed and fails before its first sampling.
        let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (notice.run_id.as_str(), notice.terminal),
            (run.run_id.as_str(), RunTerminalKind::Failed)
        );
        let sessions: i64 = env
            .client
            .query_one(
                "SELECT count(*) FROM openmybot.host_driver_sessions WHERE run_id=$1",
                &[&run.run_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(sessions, 0);
        dispatcher.stop().await;
        drop(gate);
        env.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn receiver_replacement_waits_for_a_dispatch_in_flight_instead_of_failing() {
        let mut env = Env::running(Fixture::start_with_host(agent::cooperative).await).await;
        let mut terminals = env.fixture.take_terminals();
        let entry = env
            .fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap();
        let gate = env.fixture.client().await;
        let mut receiver = fixture::receiver(&env.client, "telegram").await;
        for round in 0..10 {
            // Each round replaces the receiver, which ends the round's sender.
            let (sender, thread) = env.sender().await;
            let run = format!("run-{}", Uuid::now_v7());
            let record = testkit::insert_event_for_run(
                &env.client,
                sender,
                &run,
                thread.as_str(),
                "pending",
            )
            .await;
            // The engine's begin takes this thread's lock first; holding it parks the begin.
            gate.execute(
                "SELECT pg_advisory_lock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            let opened = env
                .fixture
                .pg
                .open_resident_connection("openmybot-dispatcher")
                .await
                .unwrap();
            let wake = Arc::new(Notify::new());
            let mut dispatcher = start_dispatcher(
                Connection {
                    client: opened.client,
                    driver: opened.driver,
                },
                entry.clone(),
                quick_channels(),
                Arc::clone(&wake),
                Arc::clone(&env.ops.canceller.gate),
            );
            wake.notify_one();
            until(
                &gate,
                "begin parked",
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted)",
            )
            .await;
            let parked = Instant::now();
            // Even rounds: the server ends the dispatcher's session between its begin and its
            // receipt, so the begun run's event stays pending.
            let lost = round % 2 == 0;
            if lost {
                let ended: bool = gate
                    .query_one(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='openmybot-dispatcher'",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get(0);
                assert!(ended, "round {round}");
            }
            let replaced = env.ops.run(
                Op::BindingsReceiver,
                json!({"channel": "telegram", "fields": {"token": format!("1001:token-{round}")}}),
                later(),
                env.token,
            );
            tokio::pin!(replaced);
            // Answer the receiver commands while asserting, as `call_until` does: a replacement
            // that is not held by the gate would otherwise also stall on the missing answer. The
            // credential check answers for source `1001` at once.
            loop {
                tokio::select! {
                    answer = &mut replaced => {
                        panic!("round {round}: the replacement waits for the gate, but answered {answer:?}")
                    }
                    Some(command) = env.commands.recv() => match command {
                        ReceiverCommand::Start(_, done) => {
                            let _ = done.send(Ok(()));
                        }
                        ReceiverCommand::Stop(_, done) | ReceiverCommand::Retire(_, done) => {
                            let _ = done.send(());
                        }
                        ReceiverCommand::Verify { reply, .. } => {
                            let _ = reply.send(Ok("1001".to_owned()));
                        }
                    },
                    () = tokio::time::sleep_until(parked + Duration::from_secs(3)) => break,
                }
            }
            gate.execute(
                "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                &[&thread.as_str()],
            )
            .await
            .unwrap();
            if lost {
                // The begin commits the run; its receipt finds the session gone.
                assert_eq!(
                    dispatcher.finished().await,
                    Err(ChannelError::StoreFailed),
                    "round {round}"
                );
            }
            let answer = loop {
                tokio::select! {
                    answer = &mut replaced => break answer,
                    Some(command) = env.commands.recv() => match command {
                        ReceiverCommand::Start(_, done) => {
                            let _ = done.send(Ok(()));
                        }
                        ReceiverCommand::Stop(_, done) | ReceiverCommand::Retire(_, done) => {
                            let _ = done.send(());
                        }
                        ReceiverCommand::Verify { reply, .. } => {
                            let _ = reply.send(Ok("1001".to_owned()));
                        }
                    },
                }
            };
            let answer = answer.unwrap();
            assert_eq!(answer["source_key"], "1001", "round {round}");
            for (binding, kind) in [(receiver, "receiver"), (sender, "sender")] {
                let row = env.binding(binding).await;
                assert_eq!(
                    (&row["status"], &row["status_reason"]),
                    (&json!("revoked"), &json!("receiver_replaced")),
                    "round {round}: {kind}"
                );
            }
            assert_eq!(
                testkit::read_row(&env.client, "channel_events", "record_id", record).await["dispatch_status"],
                if lost { "cancelled" } else { "dispatched" },
                "round {round}"
            );
            // The stop request races the run's delegation check at its first sampling.
            let notice = tokio::time::timeout(Duration::from_secs(30), terminals.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(notice.run_id.as_str(), run, "round {round}");
            assert!(
                matches!(
                    notice.terminal,
                    RunTerminalKind::Cancelled | RunTerminalKind::Failed
                ),
                "round {round}"
            );
            assert_eq!(
                cancel_run(
                    env.ops.application.as_ref(),
                    &env.ops.resolver,
                    thread.as_str(),
                    &run,
                )
                .await,
                Ok(Some("already_terminal")),
                "round {round}"
            );
            dispatcher.stop().await;
            receiver = answer["binding_id"].as_str().unwrap().parse().unwrap();
        }
        drop(gate);
        env.stop().await;
    }
}
