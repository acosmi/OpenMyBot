//! Original existing Agents edit/Save through one actual Application/Session/PG assembly.
//! IPC can only observe, bind a real saved Agent, and acquire/release its own row lock; it cannot Save, Begin or forge a verdict.
use std::collections::BTreeSet;
use std::future::Future;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use openbot_agent::{
    AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime, ProviderRouter,
    RemoteAguiProvider, RetryingProvider, RetryingProviderConfig,
};
use openbot_application::provider::{
    RemoteAguiEventStream, RemoteAguiTransport, RemoteAguiTransportError,
};
use openbot_application::{
    ProviderAdapter, ProviderPortError, ProviderRequest, ProviderSession, remember_provider_tool,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::policy::{ActionPolicy, PolicyMode};
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::agent_audit::PostgresAgentAudit;
use openbot_infra::agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence};
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssemblyInput, assemble_postgres_application,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::pool::DatabasePool as Pool;
use openbot_infra::db::{fresh, pool};
use openbot_infra::net::safe_http::{SafeHttpBudget, SchemePolicy};
use openbot_infra::policy::PolicyStore;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::custom::PostgresCustomModelProvider;
use openbot_infra::provider::openai::{
    OpenAiApiKey, OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig,
};
use openbot_infra::remote_agui::SafeRemoteAguiTransport;
use openbot_infra::run_runtime::RunRelay;
use openbot_infra::ui_preferences::PostgresUiPreferenceAdministration;
use openbot_infra::vault::CredentialRecordVault;
use openbot_server::config::{EnvMap, ServerConfig};
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder, StaticApp,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::{Mutex, mpsc, oneshot};
use url::Url;
use uuid::Uuid;

use super::agent_editor_edit_save_owned_tls_fixture::{
    AUTH_LATE, CASES, ERROR_CODE, ERROR_MESSAGE, OwnedWire, ProbeObservations, SAVE_UPDATE,
    WireRecord, WireView, late, metadata,
};
const DEPLOYMENT: &str = "owned-agent-edit-save-client-deployment";
const TENANT: &str = "owned-agent-edit-save-client-tenant";
const SESSION_KEY: &[u8] = b"owned-agent-edit-save-client-session-key-at-least-32-bytes";
const MANAGED_KEY: &str = "owned-c5e-unused-managed-key";
const APPLICATION_NAME: &str = "owned-agent-edit-save-client-application";
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);
const PG_BUDGET: Duration = Duration::from_secs(6);
// Existing non-production idp.test test CA/leaf/key; no system trust or vendor key is used.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default)]
struct Counters {
    custom: AtomicU64,
    package: AtomicU64,
    managed: AtomicU64,
    business_remote: AtomicU64,
    probe_validate: AtomicU64,
    probe_start: AtomicU64,
    api_ingress: AtomicU64,
    agent_post: AtomicU64,
    agent_put: AtomicU64,
    agent_delete: AtomicU64,
    model_post: AtomicU64,
    model_put: AtomicU64,
    model_delete: AtomicU64,
    credential: AtomicU64,
    callback: AtomicU64,
    mint_post: AtomicU64,
    begin_post: AtomicU64,
    cap_get: AtomicU64,
    probe_post: AtomicU64,
    served_index: AtomicU64,
    sequence: AtomicU64,
    collection_failed: AtomicBool,
}
struct CountingCustom {
    inner: Arc<PostgresCustomModelProvider>,
    counters: Arc<Counters>,
}
#[async_trait]
impl ProviderAdapter for CountingCustom {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.counters.custom.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}
struct CountingProvider {
    inner: Arc<dyn ProviderAdapter>,
    counters: Arc<Counters>,
    kind: u8,
}
#[async_trait]
impl ProviderAdapter for CountingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let counter = match self.kind {
            1 => &self.counters.managed,
            2 => &self.counters.business_remote,
            _ => &self.counters.package,
        };
        counter.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}
fn transport_error(error: RemoteAguiTransportError) -> &'static str {
    match error {
        RemoteAguiTransportError::DestinationRejected => "destination_rejected",
        RemoteAguiTransportError::Unavailable => "unavailable",
        RemoteAguiTransportError::CommitUnknown => "commit_unknown",
        RemoteAguiTransportError::Authentication => "authentication",
        RemoteAguiTransportError::RateLimited => "rate_limited",
        RemoteAguiTransportError::ServerUnavailable => "server_unavailable",
        RemoteAguiTransportError::InvalidResponse => "invalid_response",
        RemoteAguiTransportError::StreamStalled => "stream_stalled",
    }
}
fn observed_set(
    rows: &ProbeObservations,
    counters: &Counters,
    index: usize,
    key: &str,
    value: Value,
) {
    match rows.lock() {
        Ok(mut rows) => match rows.get_mut(index) {
            Some(row) => row[key] = value,
            None => counters.collection_failed.store(true, Ordering::SeqCst),
        },
        Err(_) => counters.collection_failed.store(true, Ordering::SeqCst),
    }
}
struct StartGuard {
    rows: ProbeObservations,
    counters: Arc<Counters>,
    index: usize,
    returned: bool,
}
impl Drop for StartGuard {
    fn drop(&mut self) {
        if !self.returned {
            observed_set(
                &self.rows,
                &self.counters,
                self.index,
                "startFutureDropObserved",
                json!(true),
            );
        }
    }
}
struct ObservedStream {
    inner: Box<dyn RemoteAguiEventStream>,
    rows: ProbeObservations,
    counters: Arc<Counters>,
    index: usize,
}
#[async_trait]
impl RemoteAguiEventStream for ObservedStream {
    async fn next_data(&mut self) -> Result<Option<String>, RemoteAguiTransportError> {
        if let Ok(mut rows) = self.rows.lock() {
            let row = &mut rows[self.index];
            let n = row["nextDataCalls"].as_u64().unwrap_or(0);
            row["nextDataCalls"] = json!(n + 1);
        } else {
            self.counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
        let value = self.inner.next_data().await;
        match &value {
            Ok(Some(data)) => {
                let kind = serde_json::from_str::<Value>(data)
                    .ok()
                    .and_then(|v| v.get("type").and_then(Value::as_str).map(str::to_owned));
                if let Ok(mut rows) = self.rows.lock() {
                    if rows[self.index]["firstEventType"].is_null() {
                        rows[self.index]["firstEventType"] = json!(match kind.as_deref() {
                            Some("RUN_STARTED") => "RUN_STARTED",
                            Some("RUN_ERROR") => "RUN_ERROR",
                            Some("run_started") => "run_started",
                            _ => "other",
                        });
                    }
                } else {
                    self.counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                }
            }
            Ok(None) => observed_set(
                &self.rows,
                &self.counters,
                self.index,
                "eofObserved",
                json!(true),
            ),
            Err(_) => {}
        }
        value
    }
}
impl Drop for ObservedStream {
    fn drop(&mut self) {
        observed_set(
            &self.rows,
            &self.counters,
            self.index,
            "wrapperStreamDropObserved",
            json!(true),
        );
    }
}
struct CountingRemote {
    inner: Arc<SafeRemoteAguiTransport>,
    counters: Arc<Counters>,
    rows: ProbeObservations,
}
#[async_trait]
impl RemoteAguiTransport for CountingRemote {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.counters.probe_validate.fetch_add(1, Ordering::SeqCst);
        let index = match self.rows.lock() {
            Ok(mut rows) => {
                let index = rows.len();
                rows.push(json!({"ordinal":index+1,"endpoint":endpoint,"threadId":null,"runId":null,"messageId":null,
                "validateCalled":true,"validateReturn":null,"validateElapsedMicros":null,"startCalled":false,"startReturn":null,"startElapsedMicros":null,
                "startFutureDropObserved":false,"firstEventType":null,"nextDataCalls":0,"eofObserved":false,"wrapperStreamDropObserved":false}));
                Some(index)
            }
            Err(_) => {
                self.counters
                    .collection_failed
                    .store(true, Ordering::SeqCst);
                None
            }
        };
        let started = std::time::Instant::now();
        let result = self.inner.validate_endpoint(endpoint).await;
        if let Some(index) = index {
            observed_set(
                &self.rows,
                &self.counters,
                index,
                "validateReturn",
                json!(match result {
                    Ok(()) => "ok",
                    Err(error) => transport_error(error),
                }),
            );
            observed_set(
                &self.rows,
                &self.counters,
                index,
                "validateElapsedMicros",
                json!(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
            );
        }
        result
    }
    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.counters.probe_start.fetch_add(1, Ordering::SeqCst);
        let parsed = serde_json::from_slice::<Value>(&body).ok();
        let index = match self.rows.lock() {
            Ok(mut rows) => {
                let found = rows
                    .iter()
                    .rposition(|r| r["endpoint"] == endpoint && r["startCalled"] == false);
                if let Some(index) = found {
                    rows[index]["startCalled"] = json!(true);
                    if let Some(value) = &parsed {
                        for key in ["threadId", "runId"] {
                            rows[index][key] = value[key].clone();
                        }
                        rows[index]["messageId"] = value["messages"][0]["id"].clone();
                    }
                } else {
                    self.counters
                        .collection_failed
                        .store(true, Ordering::SeqCst);
                }
                found
            }
            Err(_) => {
                self.counters
                    .collection_failed
                    .store(true, Ordering::SeqCst);
                None
            }
        };
        let mut guard = index.map(|index| StartGuard {
            rows: self.rows.clone(),
            counters: self.counters.clone(),
            index,
            returned: false,
        });
        let started = std::time::Instant::now();
        let result = self.inner.start(endpoint, authorization, body).await;
        if let Some(ref mut guard) = guard {
            guard.returned = true;
            observed_set(
                &self.rows,
                &self.counters,
                guard.index,
                "startElapsedMicros",
                json!(u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)),
            );
            observed_set(
                &self.rows,
                &self.counters,
                guard.index,
                "startReturn",
                json!(match &result {
                    Ok(_) => "stream",
                    Err(error) => transport_error(*error),
                }),
            );
        }
        match (result, index) {
            (Ok(inner), Some(index)) => Ok(Box::new(ObservedStream {
                inner,
                rows: self.rows.clone(),
                counters: self.counters.clone(),
                index,
            })),
            (value, _) => value,
        }
    }
}
// Preserve ownership after a budget breach; the observed overrun stays RED.
async fn bounded_completion<F: Future>(future: F, budget: Duration) -> (F::Output, bool) {
    tokio::pin!(future);
    match tokio::time::timeout(budget, &mut future).await {
        Ok(value) => (value, false),
        Err(_) => (future.await, true),
    }
}
#[derive(Clone)]
struct Case {
    actor: String,
    session: String,
}
struct State {
    observer: Pool,
    counters: Arc<Counters>,
    case: Mutex<Option<Case>>,
    requests: Mutex<Vec<Value>>,
    case_id: String,
    observations: ProbeObservations,
    // Complete original rows, including sensitive columns, stay exclusively in memory.
    baseline: Mutex<Option<Value>>,
    bound: Mutex<Option<(String, Value)>>,
    vault: CredentialRecordVault,
    save_lock: SaveController,
}
const ORIGINAL_SAVE_SELECT: &str = "SELECT id FROM public.agents WHERE id=$1 FOR UPDATE";
const SAVE_CONTROLLER_NAME: &str = "owned-agent-edit-save-client-controller";
struct SaveController {
    pool: Pool,
    facts: Arc<Mutex<Value>>,
    task: Mutex<Option<tokio::task::JoinHandle<Result<(), String>>>>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    released: AtomicBool,
}
impl SaveController {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            facts: Arc::new(Mutex::new(
                json!({"armed":false,"agentId":null,"transactionStarted":false,"lockAcquired":false,"active":false,"controller":null,"blockedQuery":null,"saveRequest":null,"rollbackAttempted":false,"rollbackReturned":false,"stopSent":false,"taskJoined":false,"remainingBlockedQueries":null,"remainingControllerLocks":null,"originalTargetSettled":false,"error":null}),
            )),
            task: Mutex::new(None),
            stop: Mutex::new(None),
            released: AtomicBool::new(false),
        }
    }
    async fn snapshot(&self) -> Value {
        self.facts.lock().await.clone()
    }
    async fn fail(&self, code: &str) {
        let mut facts = self.facts.lock().await;
        if facts["error"].is_null() {
            facts["error"] = json!(code);
        }
    }
    async fn admission(&self, sequence: u64, path: &str) {
        let mut facts = self.facts.lock().await;
        if facts["saveRequest"].is_null() {
            facts["saveRequest"] = json!({"sequence":sequence,"method":"PATCH","path":path,"responseStatus":null,"originalHandlerReturned":false});
        } else if facts["error"].is_null() {
            facts["error"] = json!("original_save_admission_repeated");
        }
    }
    async fn response(&self, status: u16) {
        let mut facts = self.facts.lock().await;
        if !facts["saveRequest"].is_null() {
            facts["saveRequest"]["responseStatus"] = json!(status);
            facts["saveRequest"]["originalHandlerReturned"] = json!(true);
        } else if facts["error"].is_null() {
            facts["error"] = json!("original_save_response_without_admission");
        }
    }
    async fn arm(&self, id: &str) -> Result<(), String> {
        let mut slot = self.task.lock().await;
        if slot.is_some() || self.facts.lock().await["armed"] == true {
            return Err("save_lock_reused".to_owned());
        }
        {
            let mut f = self.facts.lock().await;
            f["armed"] = json!(true);
            f["agentId"] = json!(id);
        }
        let (stop, stopped) = oneshot::channel();
        *self.stop.lock().await = Some(stop);
        let (send, ready) = oneshot::channel();
        let pool = self.pool.clone();
        let facts = self.facts.clone();
        let agent = id.to_owned();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        *slot = Some(tokio::spawn(async move {
            let connection = tokio::time::timeout_at(deadline, pool.get()).await;
            let mut client = match connection {
                Ok(Ok(c)) => c,
                _ => {
                    facts.lock().await["error"] = json!("save_lock_connection");
                    return Err("save_lock_connection".to_owned());
                }
            };
            let tx = match tokio::time::timeout_at(deadline, client.transaction()).await {
                Ok(Ok(tx)) => tx,
                _ => {
                    facts.lock().await["error"] = json!("save_lock_begin");
                    return Err("save_lock_begin".to_owned());
                }
            };
            facts.lock().await["transactionStarted"] = json!(true);
            let setup=async {
                tokio::time::timeout_at(deadline,tx.query_one("SELECT set_config('application_name',$1,true),set_config('statement_timeout','6000',true),set_config('lock_timeout','6000',true)",&[&SAVE_CONTROLLER_NAME])).await.map_err(|_|"save_lock_setup_deadline")?.map_err(|_|"save_lock_setup")?;
                let matched=tokio::time::timeout_at(deadline,tx.query_opt(ORIGINAL_SAVE_SELECT,&[&agent])).await.map_err(|_|"save_lock_acquire_deadline")?.map_err(|_|"save_lock_acquire")?.ok_or("save_lock_target_missing")?;
                let target:String=matched.try_get(0).map_err(|_|"save_lock_target_shape")?;
                if target!=agent{return Err("save_lock_target_mismatch".to_owned());}
                let row=tokio::time::timeout_at(deadline,tx.query_one("SELECT jsonb_build_object('pid',a.pid,'backendStart',a.backend_start::text,'xactStart',a.xact_start::text,'database',a.datname,'user',a.usename,'applicationName',a.application_name,'relationOid','public.agents'::regclass::bigint) FROM pg_stat_activity a WHERE a.pid=pg_backend_pid() AND a.application_name=$1 AND a.xact_start IS NOT NULL",&[&SAVE_CONTROLLER_NAME])).await.map_err(|_|"save_lock_identity_deadline")?.map_err(|_|"save_lock_identity")?;
                let mut controller:Value=row.try_get(0).map_err(|_|"save_lock_identity_shape")?;
                if controller["pid"].as_i64().is_none_or(|p|p<=0)||controller["backendStart"].as_str().is_none()||controller["xactStart"].as_str().is_none(){return Err("save_lock_identity_invalid".to_owned());}
                controller["rowMatched"]=json!(true);controller["lockQuerySha256"]=json!(Sha256Digest::of(ORIGINAL_SAVE_SELECT.as_bytes()).to_hex());
                let mut f=facts.lock().await;f["lockAcquired"]=json!(true);f["active"]=json!(true);f["controller"]=controller;
                Ok::<(),String>(())
            }.await;
            let mut error = setup.err();
            let notice = error.as_ref().map_or(Ok(()), |e| Err(e.clone()));
            if send.send(notice).is_err() && error.is_none() {
                error = Some("save_lock_ready_receiver_closed".to_owned());
            }
            if error.is_none() {
                match tokio::time::timeout_at(deadline, stopped).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => error = Some("save_lock_stop_sender_closed".to_owned()),
                    Err(_) => error = Some("save_lock_hold_deadline".to_owned()),
                }
            }
            facts.lock().await["rollbackAttempted"] = json!(true);
            let (rolled, over) = bounded_completion(tx.rollback(), PG_BUDGET).await;
            if over && error.is_none() {
                error = Some("save_lock_rollback_deadline".to_owned());
            }
            if rolled.is_ok() {
                let mut f = facts.lock().await;
                f["rollbackReturned"] = json!(true);
                f["active"] = json!(false);
            } else if error.is_none() {
                error = Some("save_lock_rollback_error".to_owned());
            }
            if let Some(code) = error {
                let mut f = facts.lock().await;
                if f["error"].is_null() {
                    f["error"] = json!(code);
                }
                Err(code)
            } else {
                Ok(())
            }
        }));
        drop(slot);
        match tokio::time::timeout(PG_BUDGET, ready).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(e))) => {
                self.fail(&e).await;
                Err(e)
            }
            _ => {
                self.fail("save_lock_ready_deadline").await;
                Err("save_lock_ready_deadline".to_owned())
            }
        }
    }
    async fn observe(&self, budget: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + budget;
        let f = self.snapshot().await;
        if f["active"] != true || f["controller"]["rowMatched"] != true {
            return Err("save_lock_not_actually_active".to_owned());
        }
        let pid = i32::try_from(
            f["controller"]["pid"]
                .as_i64()
                .ok_or("save_controller_pid")?,
        )
        .map_err(|_| "save_controller_pid")?;
        let database = text(&f["controller"], "database")?;
        let user = text(&f["controller"], "user")?;
        let birth = text(&f["controller"], "backendStart")?;
        let xact = text(&f["controller"], "xactStart")?;
        loop {
            let current = self.snapshot().await;
            if current["active"] != true || !current["error"].is_null() {
                return Err("save_lock_lost_before_original_wait".to_owned());
            }
            let mut client = tokio::time::timeout_at(deadline, self.pool.get())
                .await
                .map_err(|_| "save_observer_connection_deadline")?
                .map_err(|_| "save_observer_connection")?;
            let tx = client
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(|_| "save_observer_begin")?;
            let records=tokio::time::timeout_at(deadline,tx.query("SELECT jsonb_build_object('pid',a.pid,'backendStart',a.backend_start::text,'xactStart',a.xact_start::text,'queryStart',a.query_start::text,'database',a.datname,'user',a.usename,'applicationName',a.application_name,'state',a.state,'waitEventType',a.wait_event_type,'waitEvent',a.wait_event,'queryText',a.query,'queryUtf8Bytes',octet_length(a.query),'blockingPids',to_jsonb(pg_blocking_pids(a.pid)),'controllerBlocking',($1=ANY(pg_blocking_pids(a.pid)))) FROM pg_stat_activity a WHERE a.datname=$2 AND a.usename=$3 AND a.application_name=$4 AND a.state='active' AND a.wait_event_type='Lock' AND a.query=$5 AND $1=ANY(pg_blocking_pids(a.pid)) AND EXISTS(SELECT 1 FROM pg_stat_activity c WHERE c.pid=$1 AND c.backend_start::text=$6 AND c.xact_start::text=$7 AND c.application_name=$8)",&[&pid,&database,&user,&APPLICATION_NAME,&ORIGINAL_SAVE_SELECT,&birth,&xact,&SAVE_CONTROLLER_NAME])).await.map_err(|_|"save_observer_query_deadline")?.map_err(|_|"save_observer_query")?;
            tx.commit().await.map_err(|_| "save_observer_commit")?;
            drop(client);
            if records.len() > 1 {
                return Err("save_observer_nonunique_original_wait".to_owned());
            }
            if let Some(row) = records.first() {
                let mut witness: Value = row.try_get(0).map_err(|_| "save_blocked_shape")?;
                if witness["queryText"] != ORIGINAL_SAVE_SELECT
                    || witness["queryUtf8Bytes"] != json!(ORIGINAL_SAVE_SELECT.len())
                    || witness["controllerBlocking"] != true
                {
                    return Err("save_original_query_identity_mismatch".to_owned());
                }
                let mut current = self.facts.lock().await;
                let known = current["agentId"].as_str().ok_or("save_bound_id_missing")?;
                if current["saveRequest"]["method"] != "PATCH"
                    || current["saveRequest"]["path"] != format!("/api/agents/{known}")
                    || current["saveRequest"]["originalHandlerReturned"] != false
                {
                    return Err("save_original_HTTP_pending_not_observed".to_owned());
                }
                witness["querySha256"] =
                    json!(Sha256Digest::of(ORIGINAL_SAVE_SELECT.as_bytes()).to_hex());
                // This boolean joins an exact own target row lock with the original same-ID
                // PATCH admission; PostgreSQL bind-parameter values are not observed.
                witness["agentIdMatches"] = json!(true);
                current["blockedQuery"] = witness;
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("save_original_wait_unobserved".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn settle(&self) -> Result<(), String> {
        let f = self.snapshot().await;
        if f["controller"].is_null() {
            return Ok(());
        }
        let controller = i32::try_from(
            f["controller"]["pid"]
                .as_i64()
                .ok_or("save_settle_controller_pid")?,
        )
        .map_err(|_| "save_settle_controller_pid")?;
        let database = text(&f["controller"], "database")?;
        let user = text(&f["controller"], "user")?;
        let birth = text(&f["controller"], "backendStart")?;
        let controller_xact = text(&f["controller"], "xactStart")?;
        let target = f["blockedQuery"]["pid"]
            .as_i64()
            .map(i32::try_from)
            .transpose()
            .map_err(|_| "save_settle_target_pid")?;
        let target_birth = f["blockedQuery"]["backendStart"].as_str();
        let target_xact = f["blockedQuery"]["xactStart"].as_str();
        let deadline = tokio::time::Instant::now() + PG_BUDGET;
        loop {
            let mut client = tokio::time::timeout_at(deadline, self.pool.get())
                .await
                .map_err(|_| "save_settle_connection_deadline")?
                .map_err(|_| "save_settle_connection")?;
            let tx = client
                .build_transaction()
                .read_only(true)
                .start()
                .await
                .map_err(|_| "save_settle_begin")?;
            let row=tokio::time::timeout_at(deadline,tx.query_one("SELECT (SELECT count(*) FROM pg_stat_activity a WHERE a.datname=$1 AND a.usename=$2 AND a.application_name=$3 AND a.query=$4 AND a.wait_event_type='Lock' AND $5=ANY(pg_blocking_pids(a.pid))),(SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.pid=$5 AND a.backend_start::text=$6 AND a.xact_start::text=$7 AND a.application_name=$8 AND l.relation='public.agents'::regclass AND l.granted)",&[&database,&user,&APPLICATION_NAME,&ORIGINAL_SAVE_SELECT,&controller,&birth,&controller_xact,&SAVE_CONTROLLER_NAME])).await.map_err(|_|"save_settle_query_deadline")?.map_err(|_|"save_settle_query")?;
            let blocked: i64 = row.try_get(0).map_err(|_| "save_settle_blocked_shape")?;
            let locks: i64 = row.try_get(1).map_err(|_| "save_settle_lock_shape")?;
            // The exact old transaction must end. A pooled backend may already serve a new readonly request.
            let settled = if let (Some(pid), Some(birth), Some(xact)) =
                (target, target_birth, target_xact)
            {
                match tokio::time::timeout_at(deadline,tx.query_opt("SELECT (a.xact_start IS NULL OR a.xact_start::text<>$4) AND a.query<>$3 FROM pg_stat_activity a WHERE a.pid=$1 AND a.backend_start::text=$2",&[&pid,&birth,&ORIGINAL_SAVE_SELECT,&xact])).await.map_err(|_|"save_settle_target_deadline")?.map_err(|_|"save_settle_target")?{None=>true,Some(row)=>row.try_get::<_,bool>(0).map_err(|_|"save_settle_target_shape")?}
            } else {
                false
            };
            tx.commit().await.map_err(|_| "save_settle_commit")?;
            {
                let mut facts = self.facts.lock().await;
                facts["remainingBlockedQueries"] = json!(blocked);
                facts["remainingControllerLocks"] = json!(locks);
                facts["originalTargetSettled"] = json!(settled);
            }
            if blocked == 0 && locks == 0 && (target.is_none() || settled) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("save_lock_original_target_settle_deadline".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn release(&self, shutdown: bool) -> Result<(), String> {
        if self.snapshot().await["armed"] != true {
            return if shutdown {
                Ok(())
            } else {
                Err("save_lock_not_armed".to_owned())
            };
        }
        if !self.released.swap(true, Ordering::SeqCst) {
            if let Some(stop) = self.stop.lock().await.take() {
                self.facts.lock().await["stopSent"] = json!(true);
                if stop.send(()).is_err() {
                    self.fail("save_lock_stop_receiver_closed").await;
                }
            }
            if let Some(task) = self.task.lock().await.take() {
                let (value, over) = bounded_completion(task, CLOSE_TIMEOUT).await;
                self.facts.lock().await["taskJoined"] = json!(true);
                if over {
                    self.fail("save_lock_join_deadline").await;
                }
                match value {
                    Ok(Ok(())) => {}
                    Ok(Err(code)) => self.fail(&code).await,
                    Err(_) => self.fail("save_lock_join_error").await,
                }
            }
            if let Err(code) = self.settle().await {
                self.fail(&code).await;
            }
        } else if !shutdown {
            return Err("save_lock_release_reused".to_owned());
        }
        let f = self.snapshot().await;
        if !f["error"].is_null()
            || f["active"] != false
            || f["rollbackReturned"] != true
            || f["taskJoined"] != true
        {
            return Err("save_lock_actual_close_failed".to_owned());
        }
        Ok(())
    }
}

fn item_path(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}
fn begin_path(path: &str) -> bool {
    path.starts_with("/api/threads/") && path.ends_with("/runs") && path.split('/').count() == 5
}
async fn observe_http(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/") {
        state.counters.api_ingress.fetch_add(1, Ordering::SeqCst);
    }
    let admission = match (method.as_str(), path.as_str()) {
        ("POST", "/api/agents/test-connection") => Some(&state.counters.probe_post),
        ("POST", "/api/agents") => Some(&state.counters.agent_post),
        ("PATCH", p) if item_path(p, "/api/agents/") => Some(&state.counters.agent_put),
        ("DELETE", p) if item_path(p, "/api/agents/") => Some(&state.counters.agent_delete),
        ("POST", "/api/me/model-connections") => Some(&state.counters.model_post),
        ("PUT", p) if item_path(p, "/api/me/model-connections/") => Some(&state.counters.model_put),
        ("DELETE", p) if item_path(p, "/api/me/model-connections/") => {
            Some(&state.counters.model_delete)
        }
        ("POST", "/api/threads/mint") => Some(&state.counters.mint_post),
        ("POST", p) if begin_path(p) => Some(&state.counters.begin_post),
        ("GET", "/api/me/capabilities") => Some(&state.counters.cap_get),
        (_, p)
            if (method != "GET"
                && (p == "/api/admin/credentials" || p.starts_with("/api/admin/credentials/")))
                || ((method == "POST" || method == "DELETE")
                    && p.starts_with("/api/agents/")
                    && p.ends_with("/callback-token")
                    && p.split('/').count() == 5) =>
        {
            Some(&state.counters.credential)
        }
        ("POST", "/api/agent-tools/call") => Some(&state.counters.callback),
        _ => None,
    };
    if let Some(counter) = admission {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let sequence = state.counters.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    let is_bound_save = method == "PATCH"
        && state.case_id == SAVE_UPDATE
        && state
            .bound
            .lock()
            .await
            .as_ref()
            .is_some_and(|(id, _)| path == format!("/api/agents/{id}"));
    if is_bound_save {
        state.save_lock.admission(sequence, &path).await;
    }
    let response = next.run(request).await;
    if is_bound_save {
        state.save_lock.response(response.status().as_u16()).await;
    }
    if response.status().is_success()
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/html"))
    {
        state.counters.served_index.fetch_add(1, Ordering::SeqCst);
    }
    let mut records = state.requests.lock().await;
    if records.len() >= 4096 || path.len() > 2048 {
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
    } else {
        records.push(json!({"sequence":sequence,"method":method,"path":path,"status":response.status().as_u16()}));
    }
    response
}
fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC5E_HOST {text}").map_err(|_| "protocol_write")?;
    output.flush().map_err(|_| "protocol_flush".to_owned())
}

fn stdin_owner() -> (
    mpsc::Receiver<Result<Value, String>>,
    std::thread::JoinHandle<()>,
) {
    let (sender, receiver) = mpsc::channel(8);
    let thread = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let mut bytes = Vec::new();
            let message = loop {
                let available = match input.fill_buf() {
                    Ok(value) => value,
                    Err(_) => break Err("protocol_read".to_owned()),
                };
                if available.is_empty() {
                    if bytes.is_empty() {
                        return;
                    }
                    break Err("protocol_partial_eof".to_owned());
                }
                let length = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(available.len(), |index| index + 1);
                if bytes.len() + length > 65_536 {
                    break Err("protocol_line_limit".to_owned());
                }
                let newline = available[length - 1] == b'\n';
                bytes.extend_from_slice(&available[..length]);
                input.consume(length);
                if newline {
                    break serde_json::from_slice(&bytes)
                        .map_err(|_| "protocol_invalid_json_or_utf8".to_owned());
                }
            };
            let invalid = message.is_err();
            if sender.blocking_send(message).is_err() || invalid {
                return;
            }
        }
    });
    (receiver, thread)
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("protocol_invalid_{field}"))
}

fn fields(value: &Value, extra: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("protocol_object_required")?;
    if value["schemaVersion"] != 1
        || object.keys().any(|key| {
            !["schemaVersion", "id", "command"].contains(&key.as_str())
                && !extra.contains(&key.as_str())
        })
    {
        return Err("protocol_unknown_field_or_version".to_owned());
    }
    Ok(())
}

// Whole owned rows are read only into internal memory. No secret/cipher/config digest is emitted.
const SNAPSHOT: &str = "SELECT jsonb_build_object(
 'model_connections',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM public.model_connections m),
 'model_connection_secrets',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets s),
 'credentials',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]'::jsonb) FROM public.credentials c),
 'action_policy',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM public.action_policy p),
 'agents',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.agents a),
 'agent_profiles',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY agent_id),'[]'::jsonb) FROM public.agent_profiles p),
 'channels',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY id),'[]'::jsonb) FROM public.channels c),
 'channel_memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY channel_id,user_id),'[]'::jsonb) FROM public.channel_memberships m),
 'threads',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY thread_id),'[]'::jsonb) FROM public.threads t),
 'thread_leases',(SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY thread_id),'[]'::jsonb) FROM public.thread_leases l),
 'thread_memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY thread_id,user_id),'[]'::jsonb) FROM public.thread_memberships m),
 'messages',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY message_id),'[]'::jsonb) FROM public.messages m),
 'runs',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY run_id),'[]'::jsonb) FROM public.runs r),
 'run_model_selections',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY run_id),'[]'::jsonb) FROM public.run_model_selections s),
 'run_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY run_id,event_seq),'[]'::jsonb) FROM public.run_events e),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY outbox_id),'[]'::jsonb) FROM public.outbox o),
 'tool_calls',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY tool_call_id),'[]'::jsonb) FROM public.tool_calls c),
 'tool_attempts',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY tool_call_id,attempt_seq),'[]'::jsonb) FROM public.tool_attempts a),
 'remember_effect_receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY receipt_id),'[]'::jsonb) FROM public.remember_effect_receipts r),
 'memories',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY memory_id),'[]'::jsonb) FROM public.memories m),
 'memory_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY memory_id,seq),'[]'::jsonb) FROM public.memory_events e),
 'audit_events',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.audit_events a),
 'audit_checkpoints',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY sequence),'[]'::jsonb) FROM public.audit_checkpoints c))";

async fn snapshot(state: &State) -> Result<Value, String> {
    let mut client = tokio::time::timeout(PG_BUDGET, state.observer.get())
        .await
        .map_err(|_| "snapshot_connection_deadline")?
        .map_err(|_| "snapshot_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "snapshot_begin")?;
    let full: Value = tokio::time::timeout(PG_BUDGET, tx.query_one(SNAPSHOT, &[]))
        .await
        .map_err(|_| "snapshot_query_deadline")?
        .map_err(|_| "snapshot_query")?
        .try_get(0)
        .map_err(|_| "snapshot_shape")?;
    tx.commit().await.map_err(|_| "snapshot_commit")?;
    if serde_json::to_vec(&full)
        .map_err(|_| "snapshot_size_encode")?
        .len()
        > 262144
    {
        return Err("snapshot_limit".to_owned());
    }
    Ok(full)
}
fn rows<'a>(full: &'a Value, relation: &str) -> Result<&'a Vec<Value>, String> {
    full[relation]
        .as_array()
        .ok_or_else(|| format!("snapshot_relation_shape_{relation}"))
}
fn row<'a>(
    full: &'a Value,
    relation: &str,
    column: &str,
    id: &str,
) -> Result<Option<&'a Value>, String> {
    Ok(rows(full, relation)?.iter().find(|v| v[column] == id))
}
fn difference(
    before: &Value,
    after: &Value,
    relation: &str,
    key: &str,
) -> Result<(usize, usize, usize), String> {
    let old = rows(before, relation)?;
    let new = rows(after, relation)?;
    let added = new
        .iter()
        .filter(|r| !old.iter().any(|o| o[key] == r[key]))
        .count();
    let removed = old
        .iter()
        .filter(|r| !new.iter().any(|o| o[key] == r[key]))
        .count();
    let changed = new
        .iter()
        .filter(|r| {
            old.iter()
                .find(|o| o[key] == r[key])
                .is_some_and(|o| o != *r)
        })
        .count();
    Ok((added, removed, changed))
}
fn target_only(
    before: &Value,
    after: &Value,
    relation: &str,
    key: &str,
    id: &str,
) -> Result<bool, String> {
    let old: Vec<&Value> = rows(before, relation)?
        .iter()
        .filter(|r| r[key] != id)
        .collect();
    let new: Vec<&Value> = rows(after, relation)?
        .iter()
        .filter(|r| r[key] != id)
        .collect();
    Ok(old == new)
}
fn reference(agent: Option<&Value>) -> Option<&str> {
    agent.and_then(|r| r["configuration"]["auth"]["credentialId"].as_str())
}
fn safe_agent_state(
    full: &Value,
    initial: &Value,
    bound: Option<&(String, Value)>,
    current: &Case,
    vault: &CredentialRecordVault,
    wire: &WireView,
) -> Result<Value, String> {
    let before = bound.map_or(initial, |(_, base)| base);
    let mut agents = Vec::new();
    let mut profiles = Vec::new();
    let mut credentials = Vec::new();
    let (key_a, key_b) = wire.keys();
    for r in rows(full, "agents")? {
        let id = text(r, "id")?;
        let configuration = &r["configuration"];
        let profile =
            row(full, "agent_profiles", "agent_id", id)?.ok_or("agent_profile_missing")?;
        let serialized =
            serde_json::to_string(configuration).map_err(|_| "configuration_internal_encode")?;
        let contains_secret = serialized.contains(&key_a) || serialized.contains(&key_b);
        // A malformed producer must fail without serializing the offending secret/config.
        if contains_secret {
            return Err("secret_in_agent_configuration".to_owned());
        }
        let keys: Vec<&str> = configuration
            .as_object()
            .ok_or("configuration_shape")?
            .keys()
            .map(String::as_str)
            .collect();
        if keys
            .iter()
            .any(|k| !["endpoint", "auth", "systemPrompt", "providerSource"].contains(k))
        {
            return Err("agent_configuration_unregistered_key".to_owned());
        }
        if let Some(auth) = configuration.get("auth") {
            let object = auth.as_object().ok_or("credential_reference_shape")?;
            if object.len() != 2
                || auth["header"] != "Authorization"
                || auth["credentialId"]
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .is_none()
            {
                return Err("credential_reference_invalid".to_owned());
            }
        }
        agents.push(json!({"id":id,"name":r["name"],"type":r["type"],"packageId":r["package_id"],"createdAt":r["created_at"],"updatedAt":r["updated_at"],
            "endpoint":configuration.get("endpoint"),"providerSource":configuration.get("providerSource"),
            "systemPromptMatchesRole":configuration.get("systemPrompt").map(|s|s==&profile["role_description"]),
            "configurationKeys":keys,"authCredentialId":reference(Some(r)),"authHeader":configuration["auth"].get("header"),"secretInConfiguration":false}));
    }
    for r in rows(full, "agent_profiles")? {
        profiles.push(json!({"agentId":r["agent_id"],"ownerUserId":r["owner_user_id"],"title":r["title"],"roleDescription":r["role_description"],"avatarSeed":r["avatar_seed"],"visibility":r["visibility"],
            "deletedAt":r["deleted_at"],"createdAt":r["created_at"],"updatedAt":r["updated_at"],"hasCallbackToken":!r["callback_token_hash"].is_null(),"callbackTokenIssuedAt":r["callback_token_issued_at"],"mine":r["owner_user_id"]==current.actor}));
    }
    for r in rows(full, "credentials")? {
        let encrypted = text(r, "encrypted_value")?;
        if r["metadata"] != json!({"header":"Authorization"}) {
            return Err("credential_metadata_outside_registered_shape".to_owned());
        }
        credentials.push(json!({"id":r["id"],"kind":r["kind"],"provider":r["provider"],"keyId":r["key_id"],"metadataHeader":r["metadata"]["header"],"revokedAt":r["revoked_at"],"createdAt":r["created_at"],"updatedAt":r["updated_at"],"envelopeV2":encrypted.starts_with("{\"version\":2")}));
    }
    let mut audits = Vec::new();
    for r in rows(full, "audit_events")? {
        let payload = r["payload"].as_object().ok_or("audit_payload_shape")?;
        if payload.keys().any(|k| {
            ![
                "bot",
                "agent_endpoint_origin",
                "credential_owner",
                "revocation_reason",
            ]
            .contains(&k.as_str())
        }) {
            return Err("audit_payload_outside_registered_safe_facts".to_owned());
        }
        let encoded =
            serde_json::to_string(&r["payload"]).map_err(|_| "audit_payload_internal_encode")?;
        if encoded.contains(&key_a) || encoded.contains(&key_b) {
            return Err("audit_payload_secret_rejected".to_owned());
        }
        audits.push(json!({"id":r["id"],"actor_user_id":r["actor_user_id"],"event_type":r["event_type"],"target_type":r["target_type"],"target_id":r["target_id"],"payload":r["payload"],"prev_hash":r["prev_hash"],"row_hash":r["row_hash"],"created_at":r["created_at"]}));
    }
    let checkpoints:Vec<Value>=rows(full,"audit_checkpoints")?.iter().map(|r|json!({"sequence":r["sequence"],"eventCount":r["event_count"],"lastEventId":r["last_event_id"],"lastRowHash":r["last_row_hash"],"createdAt":r["created_at"]})).collect();
    let a = difference(before, full, "agents", "id")?;
    let p = difference(before, full, "agent_profiles", "agent_id")?;
    let c = difference(before, full, "credentials", "id")?;
    let old_agent = bound.and_then(|(id, base)| {
        base["agents"]
            .as_array()
            .and_then(|rs| rs.iter().find(|r| r["id"] == *id))
    });
    let new_agent = bound.and_then(|(id, _)| {
        full["agents"]
            .as_array()
            .and_then(|rs| rs.iter().find(|r| r["id"] == *id))
    });
    let old_ref = reference(old_agent);
    let new_ref = reference(new_agent);
    let retained_ref = bound.map(|_| old_ref.is_some() && old_ref == new_ref);
    let retained_envelope = if let (Some((_, base)), Some(id)) = (bound, new_ref) {
        let old = row(base, "credentials", "id", id)?;
        let new = row(full, "credentials", "id", id)?;
        Some(
            old.is_some()
                && new.is_some()
                && old.map(|r| &r["encrypted_value"]) == new.map(|r| &r["encrypted_value"]),
        )
    } else {
        None
    };
    let all_other = full
        .as_object()
        .ok_or("snapshot_shape")?
        .iter()
        .filter(|(k, _)| {
            ![
                "agents",
                "agent_profiles",
                "credentials",
                "audit_events",
                "audit_checkpoints",
            ]
            .contains(&k.as_str())
        })
        .all(|(k, v)| before[k] == *v);
    let mutation = json!({"agentsAdded":a.0,"agentsRemoved":a.1,"agentsChanged":a.2,"profilesAdded":p.0,"profilesRemoved":p.1,"profilesChanged":p.2,"credentialsAdded":c.0,"credentialsRemoved":c.1,"credentialsChanged":c.2,
        "auditsAdded":rows(full,"audit_events")?.len().checked_sub(rows(before,"audit_events")?.len()),"checkpointsAdded":rows(full,"audit_checkpoints")?.len().checked_sub(rows(before,"audit_checkpoints")?.len()),
        "onlyBoundAgentChanged":bound.map(|(id,_)|target_only(before,full,"agents","id",id)).transpose()?,"onlyBoundProfileChanged":bound.map(|(id,_)|target_only(before,full,"agent_profiles","agent_id",id)).transpose()?,
        "allOtherRelationsEqual":all_other,"credentialReferenceRetained":retained_ref,"credentialEnvelopeRetained":retained_envelope});
    let mut proof = Value::Null;
    for r in rows(full, "credentials")? {
        if !proof.is_null() {
            return Err("multiple_credentials_outside_finite_calibration".to_owned());
        }
        let id = Uuid::parse_str(text(r, "id")?).map_err(|_| "credential_id_shape")?;
        let consumer = text(r, "provider")?;
        let owner = text(r, "key_id")?;
        let stored = text(r, "encrypted_value")?;
        let agent = row(full, "agents", "id", consumer)?.ok_or("credential_consumer_missing")?;
        let opened = vault
            .open(
                &id,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new(owner)),
                SecretPrincipal::Service(ServiceId::new(consumer)),
                stored,
            )
            .map_err(|_| "actual_vault_open_rejected")?;
        let needs_migration = opened.needs_migration();
        let secret = opened.into_secret();
        let wrong_owner = vault
            .open(
                &id,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new("owned-wrong-actor")),
                SecretPrincipal::Service(ServiceId::new(consumer)),
                stored,
            )
            .is_err();
        let wrong_consumer = vault
            .open(
                &id,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new(owner)),
                SecretPrincipal::Service(ServiceId::new("owned-wrong-agent")),
                stored,
            )
            .is_err();
        let wrong_vault = CredentialRecordVault::single_key(
            TenantId::new("owned-wrong-tenant"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "wrong_tenant_test_key")?,
        );
        let wrong_tenant = wrong_vault
            .open(
                &id,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new(owner)),
                SecretPrincipal::Service(ServiceId::new(consumer)),
                stored,
            )
            .is_err();
        proof = json!({"credentialId":r["id"],"kindMatches":r["kind"]=="agent","ownerMatches":owner==current.actor,"consumerMatches":agent["id"]==consumer,"referenceMatches":reference(Some(agent))==r["id"].as_str(),
            "envelopeV2":stored.starts_with("{\"version\":2"),"opened":true,"secretMatches":secret.expose()==key_a.as_bytes(),"needsMigration":needs_migration,"wrongOwnerRejected":wrong_owner,"wrongConsumerRejected":wrong_consumer,"wrongTenantRejected":wrong_tenant,
            "retainedReference":retained_ref,"retainedEnvelope":retained_envelope,"physicalSealCalls":null,"physicalMigrationCalls":null});
    }
    Ok(
        json!({"boundAgentId":bound.map(|(id,_)|id),"agents":agents,"profiles":profiles,"credentials":credentials,"audits":audits,"checkpoints":checkpoints,"mutation":mutation,"vault":proof}),
    )
}
async fn bind_agent(state: &State, wire: &WireView, id: &str) -> Result<Value, String> {
    if state.case_id != SAVE_UPDATE || state.bound.lock().await.is_some() {
        return Err("bind_agent_not_registered_or_reused".to_owned());
    }
    if !id
        .strip_prefix("agent_")
        .is_some_and(|s| Uuid::parse_str(s).is_ok())
    {
        return Err("bind_agent_id_shape".to_owned());
    }
    if state.counters.agent_post.load(Ordering::SeqCst) != 1
        || !state
            .requests
            .lock()
            .await
            .iter()
            .any(|r| r["method"] == "POST" && r["path"] == "/api/agents" && r["status"] == 201)
    {
        return Err("bind_agent_original_POST201_not_observed".to_owned());
    }
    let full = snapshot(state).await?;
    let current = case(state).await?;
    let agent = row(&full, "agents", "id", id)?.ok_or("bind_agent_actual_row_missing")?;
    let profile =
        row(&full, "agent_profiles", "agent_id", id)?.ok_or("bind_agent_actual_profile_missing")?;
    if rows(&full, "agents")?.len() != 1
        || profile["owner_user_id"] != current.actor
        || profile["deleted_at"] != Value::Null
        || agent["type"] != "remote_ag_ui"
        || reference(Some(agent)).is_none()
    {
        return Err("bind_agent_original_owned_remote_credential_missing".to_owned());
    }
    *state.bound.lock().await = Some((id.to_owned(), full));
    Ok(json!({"caseId":state.case_id,"agentId":id,"probe":probe(state,wire).await?}))
}

async fn case(state: &State) -> Result<Case, String> {
    state
        .case
        .lock()
        .await
        .clone()
        .ok_or_else(|| "case_not_prepared".to_owned())
}
async fn prepare(state: &State, wire: &WireView) -> Result<Value, String> {
    let mut slot = state.case.lock().await;
    if slot.is_some() {
        return Err("case_already_prepared".to_owned());
    }
    let actor = format!("owned-c5e-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C5E_SESSION_{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let tx = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c5.test");
    tx.execute(
        "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
        &[&actor, &email],
    )
    .await
    .map_err(|_| "prepare_user")?;
    tx.execute(
        "INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')",
        &[&actor],
    )
    .await
    .map_err(|_| "prepare_role")?;
    let now = OffsetDateTime::now_utc();
    let token_hash = SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    tx.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",&[&session,&actor,&token_hash,&(now+time::Duration::hours(2)),&now]).await.map_err(|_|"prepare_session")?;
    tx.commit().await.map_err(|_| "prepare_commit")?;
    *slot = Some(Case {
        actor: actor.clone(),
        session: session.clone(),
    });
    drop(slot);
    // Prerequisite identity/policy writes precede the measured baseline.
    let baseline = snapshot(state).await?;
    *state.baseline.lock().await = Some(baseline);
    let (a, b) = wire.keys();
    let first = format!("{}/ag-ui/a", wire.origin());
    let second =
        if state.case_id == AUTH_LATE || metadata(&state.case_id) || state.case_id == SAVE_UPDATE {
            first.clone()
        } else {
            format!("{}/ag-ui/b", wire.origin())
        };
    Ok(
        json!({"caseId":state.case_id,"actor":actor,"session":{"id":session,"userId":actor,"cookieName":"openbot_session","token":token},
        "endpoints":{"first":first,"second":second},"secrets":{"apiKeyA":a,"apiKeyB":b},"canaries":{"runErrorMessage":ERROR_MESSAGE,"runErrorCode":ERROR_CODE},
        "budgets":{"responseBytes":64*1024*1024,"connectHeadersMs":30000,"bodyStallMs":null,"resolverBoundary":"owned pinned resolver separately observed; not execute_stream budget","ownedIoMs":12000,"ownedRowLockMs":12000,"selectedJsonMs":35000,"wholeCaseMs":180000}}),
    )
}
async fn live_counters(state: &State, wire: &WireView) -> Value {
    let records = state.requests.lock().await;
    let c = &state.counters;
    let wire = wire.counts();
    json!({"agentSavePost":c.agent_post.load(Ordering::SeqCst),"agentSavePatch":c.agent_put.load(Ordering::SeqCst),"agentDelete":c.agent_delete.load(Ordering::SeqCst),
        "modelSavePost":c.model_post.load(Ordering::SeqCst),"modelSavePut":c.model_put.load(Ordering::SeqCst),"modelDelete":c.model_delete.load(Ordering::SeqCst),
        "credentialMutation":c.credential.load(Ordering::SeqCst),"callbackPost":c.callback.load(Ordering::SeqCst),"threadMintPost":c.mint_post.load(Ordering::SeqCst),"beginPost":c.begin_post.load(Ordering::SeqCst),"capabilityGet":c.cap_get.load(Ordering::SeqCst),
        "probePost":c.probe_post.load(Ordering::SeqCst),"probe200":records.iter().filter(|r|r["method"]=="POST" && r["path"]=="/api/agents/test-connection" && r["status"]==200).count(),
        "probeValidate":c.probe_validate.load(Ordering::SeqCst),"probeStart":c.probe_start.load(Ordering::SeqCst),
        "customStart":c.custom.load(Ordering::SeqCst),"packageStart":c.package.load(Ordering::SeqCst),"managedStart":c.managed.load(Ordering::SeqCst),"businessRemoteStart":c.business_remote.load(Ordering::SeqCst),
        "dns":wire["dns"],"tcp":wire["tcp"],"http":wire["http"],"apiIngressCount":c.api_ingress.load(Ordering::SeqCst),"servedIndex":c.served_index.load(Ordering::SeqCst),"collectionFailed":c.collection_failed.load(Ordering::SeqCst)})
}
async fn probe(state: &State, wire: &WireView) -> Result<Value, String> {
    let current = case(state).await?;
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "observer_connection")?;
    let tx = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "observer_begin")?;
    let pid: i32 = tx
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|_| "observer_pid")?
        .get(0);
    let full: Value = tx
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "observer_snapshot")?
        .get(0);
    if serde_json::to_vec(&full)
        .map_err(|_| "observer_encode")?
        .len()
        > 262144
    {
        return Err("observer_snapshot_limit".to_owned());
    }
    let session: Value = tx
        .query_one(
            "SELECT to_jsonb(s)-'token' FROM public.sessions s WHERE id=$1 AND user_id=$2",
            &[&current.session, &current.actor],
        )
        .await
        .map_err(|_| "observer_session")?
        .get(0);
    let observations = state
        .observations
        .lock()
        .map_err(|_| "probe_observation_lock")?
        .clone();
    let ids: Vec<String> = observations
        .iter()
        .flat_map(|v| {
            ["threadId", "runId", "messageId"]
                .iter()
                .filter_map(|key| v[*key].as_str().map(str::to_owned))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let absent=tx.query_one("SELECT (SELECT count(*) FROM public.runs WHERE run_id=ANY($1::text[])),(SELECT count(*) FROM public.threads WHERE thread_id=ANY($1::text[])),(SELECT count(*) FROM public.messages WHERE message_id=ANY($1::text[]) OR run_id=ANY($1::text[])),(SELECT count(*) FROM public.outbox o WHERE o.outbox_id=ANY($1::text[]) OR o.aggregate_id=ANY($1::text[]) OR EXISTS(SELECT 1 FROM unnest($1::text[]) AS probe_id(value) WHERE strpos(o.payload::text,probe_id.value)>0))",&[&ids]).await.map_err(|_|"observer_ephemeral_ids")?;
    let totals: [i64; 4] = [absent.get(0), absent.get(1), absent.get(2), absent.get(3)];
    let readonly: String = tx
        .query_one("SHOW transaction_read_only", &[])
        .await
        .map_err(|_| "observer_readonly")?
        .get(0);
    tx.commit().await.map_err(|_| "observer_commit")?;
    let object = full.as_object().ok_or("observer_snapshot_shape")?;
    let initial_guard = state.baseline.lock().await;
    let initial = initial_guard
        .as_ref()
        .ok_or("observer_initial_baseline_missing")?;
    let bound_guard = state.bound.lock().await;
    let mut business = serde_json::Map::new();
    let mut counts = serde_json::Map::new();
    for (name, rows) in object {
        let count = rows.as_array().ok_or("observer_relation_shape")?.len();
        counts.insert(name.clone(), json!(count));
        business.insert(
            name.clone(),
            json!({"count":count,"unchangedFromInitial":initial[name] == *rows,
            "unchangedFromBound":bound_guard.as_ref().map(|(_,baseline)|baseline[name] == *rows)}),
        );
    }
    let agent_state = safe_agent_state(
        &full,
        initial,
        bound_guard.as_ref(),
        &current,
        &state.vault,
        wire,
    )?;
    drop(bound_guard);
    drop(initial_guard);
    Ok(
        json!({"caseId":state.case_id,"session":session,"policy":full["action_policy"],"business":business,"counts":counts,
        "counters":live_counters(state,wire).await,"requests":state.requests.lock().await.clone(),"wireRequests":wire.requests()?,"wireCounts":wire.counts(),"probeObservations":observations,
        "probeIdsAbsent":{"checkedIds":ids,"runs":totals[0],"threads":totals[1],"messages":totals[2],"outbox":totals[3],"allAbsent":totals.iter().all(|n|*n==0)},
        "observer":{"backendPid":pid,"transactionReadOnly":readonly=="on","sameApplicationPool":true,"allOwnedRelations":object.len(),"resolverObservations":wire.resolver()?,
            "physicalVaultSealCalls":null,"physicalVaultMigrationCalls":null,"physicalVaultObservationBoundary":"concrete same-Arc-key Vault; internal physical calls unobserved",
            "sourcePathInference":{"TestTraversesVault":false,"boundary":"static original Test authorize_scope -> commit -> SafeRemote, separate from Save/Vault calibration"}},
        "agentState":agent_state,"saveLock":state.save_lock.snapshot().await}),
    )
}
async fn execute(state: &State, wire: &WireView, value: &Value) -> Result<Value, String> {
    let command = text(value, "command")?;
    let extra = match command {
        "prepare" | "probe" | "release_probe" | "release_save_lock" => &["caseId"][..],
        "bind_agent" | "arm_save_lock" => &["caseId", "agentId"][..],
        "observe_save_lock" => &["caseId", "timeoutMs"][..],
        "shutdown" => &[][..],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    fields(value, extra)?;
    if command != "shutdown" && text(value, "caseId")? != state.case_id {
        return Err("protocol_case_mismatch".to_owned());
    }
    match command {
        "prepare" => prepare(state, wire).await,
        "probe" => tokio::time::timeout(PG_BUDGET, probe(state, wire))
            .await
            .map_err(|_| "observer_deadline".to_owned())?,
        "bind_agent" => bind_agent(state, wire, text(value, "agentId")?).await,
        "arm_save_lock" => {
            let id = text(value, "agentId")?;
            if state.case_id != SAVE_UPDATE
                || state
                    .bound
                    .lock()
                    .await
                    .as_ref()
                    .map(|(known, _)| known.as_str())
                    != Some(id)
            {
                return Err("save_lock_requires_original_bound_agent".to_owned());
            }
            state.save_lock.arm(id).await?;
            Ok(json!({"caseId":state.case_id,"saveLock":state.save_lock.snapshot().await}))
        }
        "observe_save_lock" => {
            let timeout = value["timeoutMs"]
                .as_u64()
                .filter(|n| *n > 0 && *n <= 4000)
                .ok_or("save_lock_observer_budget")?;
            state
                .save_lock
                .observe(Duration::from_millis(timeout))
                .await?;
            Ok(json!({"caseId":state.case_id,"saveLock":state.save_lock.snapshot().await}))
        }
        "release_save_lock" => {
            if state.case_id != SAVE_UPDATE {
                return Err("save_lock_not_registered".to_owned());
            }
            state.save_lock.release(false).await?;
            Ok(json!({"caseId":state.case_id,"saveLock":state.save_lock.snapshot().await}))
        }
        "release_probe" => {
            if !late(&state.case_id) {
                return Err("release_probe_not_late_case".to_owned());
            }
            let actual = tokio::time::timeout(PG_BUDGET, probe(state, wire))
                .await
                .map_err(|_| "release_observer_deadline")??;
            if actual["probeIdsAbsent"]["allAbsent"] != true
                || actual["agentState"]["mutation"]["allOtherRelationsEqual"] != true
            {
                return Err("held_probe_unrelated_durable_effect_changed".to_owned());
            }
            if state.case_id == SAVE_UPDATE {
                let lock = state.save_lock.snapshot().await;
                if lock["active"] != true
                    || lock["blockedQuery"].is_null()
                    || lock["saveRequest"]["originalHandlerReturned"] != false
                {
                    return Err("held_probe_save_not_actually_pending".to_owned());
                }
            } else {
                let expected = if metadata(&state.case_id) { 3 } else { 2 };
                let requests = wire.requests()?;
                if requests.len() != expected
                    || requests[expected - 1]["intendedStatus"] != 401
                    || requests[expected - 1]["headersWriteReturned"] != true
                    || requests[expected - 1]["bodyWriteReturned"] != true
                    || requests[expected - 1]["flushReturned"] != true
                    || !actual["probeObservations"].as_array().is_some_and(|rows| {
                        rows.iter()
                            .any(|row| row["startReturn"] == "authentication")
                    })
                {
                    return Err(
                        "held_probe_current_B_original_authentication_not_observed".to_owned()
                    );
                }
            }
            let release = wire.release()?;
            Ok(
                json!({"caseId":state.case_id,"released":release["released"],"requestOrdinal":release["requestOrdinal"]}),
            )
        }
        "shutdown" => Ok(json!({"stopping":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }
}
pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C5E_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C5E_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C5E_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C5E_CASE_ID").map_err(|_| "missing_case_id")?;
    if !CASES.contains(&case_id.as_str())
        || source.len() != 40
        || spec.len() != 64
        || !source.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !spec.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !std::path::Path::new(&dist).is_absolute()
    {
        return Err("invalid_outer_identity".to_owned());
    }
    let static_app = StaticApp::open(&dist).map_err(|_| "invalid_owned_dist")?;
    let mut application_config = config.clone();
    application_config.max_pool_size = 8;
    application_config.application_name = Some(APPLICATION_NAME.to_owned());
    let application_pool = pool::connect(&application_config)
        .await
        .map_err(|_| "application_pool")?;
    // Observation uses the SAME original ApplicationPool instance, never a parallel authority.
    let observer_pool = application_pool.clone();
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    drop(client);
    let observations: ProbeObservations = Arc::new(StdMutex::new(Vec::new()));
    let wire = OwnedWire::new(
        &case_id,
        [TEST_CA, TEST_LEAF, TEST_KEY],
        observations.clone(),
    )
    .await?;
    let view = wire.view();
    let counters = Arc::new(Counters::default());
    let tenant = TenantId::new(TENANT);
    let deployment = DeploymentId::new(DEPLOYMENT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "owned_vault_key")?,
    );
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
        observations: observations.clone(),
        baseline: Mutex::new(None),
        bound: Mutex::new(None),
        vault: vault.clone(),
        save_lock: SaveController::new(application_pool.clone()),
    });
    let mut assembly = None;
    let mut auth_owner = None;
    let mut agent = None;
    let mut relay = None;
    let mut listener_task = None;
    let mut stop_sender = None;
    let mut stdin_thread = None;
    let result=async {
        let policies=PolicyStore::postgres(application_pool.clone(),None);
        policies.set(ActionPolicy{mode:PolicyMode::Enforce,deny:vec!["true".to_owned()],allow:Vec::new()},None)
            .await.map_err(|_|"owned_deny_all_policy")?;
        policies.load().await.map_err(|_|"owned_policy_load")?;
        let assertions=Arc::new(RemoteRunAssertionSigner::new(vec![0x83;32]).map_err(|_|"owned_assertion_key")?);
        let auth=Arc::new(PostgresSessionAuthResolver::new(application_pool.clone(),SESSION_KEY,default_session_lifetime(),deployment.clone(),tenant.clone())
            .map_err(|_|"owned_session_resolver")?);
        auth_owner=Some(auth.clone());
        let budget=SafeHttpBudget::new(64*1024*1024,Duration::from_secs(30)).map_err(|_|"owned_http_budget")?;
        let remote:Arc<dyn RemoteAguiTransport>=Arc::new(CountingRemote{inner:Arc::new(SafeRemoteAguiTransport::new(view.dialer()?,budget,None,SchemePolicy::HttpsOnly)
            .map_err(|_|"owned_actual_remote")?),counters:counters.clone(),rows:observations.clone()});
        // This actual adapter is a legal CreateAgent prerequisite. Its key remains only in memory.
        let managed_inner:Option<Arc<dyn ProviderAdapter>>=Some(Arc::new(OpenAiProvider::new(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/chat/completions",view.origin())).map_err(|_|"owned_managed_endpoint")?,
            "owned-managed-model".to_owned(),OpenAiProtocol::ChatCompletions,budget,None)
            .map_err(|_|"owned_managed_config")?,OpenAiApiKey::from_bytes(MANAGED_KEY.as_bytes().to_vec()).map_err(|_|"owned_managed_key")?,view.dialer()?)));
        let managed_slot_available=managed_inner.is_some();
        let managed=managed_inner.map(|inner|Arc::new(CountingProvider{inner,counters:counters.clone(),kind:1}) as Arc<dyn ProviderAdapter>);
        assembly=Some(assemble_postgres_application(PostgresApplicationAssemblyInput{
            recovery_gate:openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&application_pool,&deployment,&tenant),
            pool:application_pool.clone(),listener_database:application_config.clone().into(),deployment:deployment.clone(),tenant:tenant.clone(),single_user:false,admin_floor:None,
            model:"unused-default-model".to_owned(),credential_key_id:"unused-default-model-key".to_owned(),credential_vault:vault.clone(),audit_key:SecretBytes::new(vec![0x82;32]),
            remote_assertions:assertions.clone(),mcp_oauth_state_key:SecretBytes::new(vec![0x84;32]),policy_store:policies,
            ui_preferences:Arc::new(PostgresUiPreferenceAdministration::new(application_pool.clone(),deployment.clone(),tenant.clone(),SecretBytes::new(vec![0x82;32])).map_err(|_|"owned_preferences")?),
            screen_sessions:Arc::new(openbot_application::NoScreenSessionAdministration),artifacts:None,
            runtime_capabilities:Some(auth.runtime_capability_factory(None).map_err(|_|"owned_actual_capability_factory")?),
            remote_agent_probe:remote.clone(),managed_slot_available,
            channel_routing_provider:ChannelRoutingProviderInput{endpoint:Url::parse(&format!("{}/v1/chat/completions",view.origin())).map_err(|_|"owned_channel_endpoint")?,environment_api_key:None,egress_allow_cidrs:vec!["127.0.0.1/32".to_owned()],allow_http:false},
            stall_timeout:None,oauth_public_url:None,app_url:None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        }).await.map_err(|_|"owned_production_assembly")?);
        let assembled=assembly.as_ref().ok_or("assembly_missing")?;
        let package_credentials=Arc::new(PostgresOpenAiCredentialSource::new(application_pool.clone(),vault.clone(),"unused-default-model-key".to_owned(),None).map_err(|_|"owned_default_source")?);
        let package:Arc<dyn ProviderAdapter>=Arc::new(CountingProvider{inner:Arc::new(OpenAiProvider::new_with_credential_source(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/responses",view.origin())).map_err(|_|"owned_package_endpoint")?,"unused-default-model".to_owned(),OpenAiProtocol::Responses,budget,None)
            .map_err(|_|"owned_package_config")?,package_credentials,view.dialer()?)),counters:counters.clone(),kind:0});
        let custom:Arc<dyn ProviderAdapter>=Arc::new(CountingCustom{inner:Arc::new(PostgresCustomModelProvider::new(application_pool.clone(),vault.clone(),deployment.clone(),tenant.clone(),view.dialer()?,budget,None)
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(CountingProvider{inner:Arc::new(RemoteAguiProvider::new(remote)),counters:counters.clone(),kind:2}))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
        let context=Arc::new(PostgresAgentContextSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),Some(32)).map_err(|_|"owned_context")?
            .with_tools(vec![remember_provider_tool()]).with_remote_assertions(assertions).with_mcp_catalog(assembled.mcp_catalog.clone())
            .with_components(assembled.components.clone()).with_sandboxed_components(assembled.sandboxed_components.clone()).with_agent_credential_vault(vault.clone()));
        let tools=Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(assembled.application.clone(),Arc::new(PostgresAgentAuthorizationSource::new(application_pool.clone(),deployment.clone(),tenant.clone(),false)),
            Arc::new(PostgresAgentToolSequence::new(application_pool.clone())),assembled.tool_cancellations.clone()));
        let audit=Arc::new(PostgresAgentAudit::new(application_pool.clone(),vec![0x82;32]).map_err(|_|"owned_agent_audit")?);
        agent=Some(BuiltInAgentRuntime::start_with_remote_interrupts(assembled.run_runtime.clone(),context,provider,tools,audit,assembled.remote_interrupts.clone(),
            BuiltInAgentConfig::default()).map_err(|_|"owned_actual_agent")?);
        relay=Some(RunRelay::start_with_database(assembled.run_runtime.clone(),agent.as_ref().ok_or("agent_missing")?.consumer(),application_config.clone()));
        let listener=tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await.map_err(|_|"owned_http_bind")?;
        let origin=format!("http://{}",listener.local_addr().map_err(|_|"owned_http_address")?);
        let transport=ServerConfig::from_env_map(&EnvMap::new()).map_err(|_|"owned_transport_config")?.transport_policy(true);
        let router=ServerBuilder::new(assembled.application.clone(),auth).with_transport_policy(transport)
            .with_sensitive_write_security(SensitiveWriteSecurity::new(default_session_lifetime(),TrustedOrigins::from_configured([origin.as_str()]).map_err(|_|"owned_origin")?))
            .with_static_app(static_app).into_router().layer(axum::middleware::from_fn_with_state(state.clone(),observe_http));
        let (stop,stopped)=oneshot::channel();stop_sender=Some(stop);
        listener_task=Some(tokio::spawn(async move {axum::serve(listener,router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async {let _=stopped.await;}).await}));
        let (mut input,thread)=stdin_owner();stdin_thread=Some(thread);
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":view.origin(),"dist":dist,
            "sourceHead":source,"specSha256":spec,"producer":"same-Pool SessionAuthResolver/CapabilityFactory/SameApplicationPool/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/PassiveOriginalSafeRemote/StrictOwnedFiniteTLS/MutationAware23InternalRowEqualities/SameConcreteVault/OriginalSaveRowLock","caseEvidence":"none"}))?;
        let mut ids=BTreeSet::new();
        loop {
            let value=tokio::time::timeout(Duration::from_secs(90),input.recv()).await.map_err(|_|"protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id=text(&value,"id")?.to_owned();
            if id.len()>64 || !id.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"._-".contains(&byte)) || !ids.insert(id.clone()) || ids.len()>4096{return Err("protocol_invalid_or_reused_id".to_owned());}
            let reply=execute(&state,&view,&value).await;
            let shutdown=reply.is_ok() && text(&value,"command")?=="shutdown";
            let frame=match reply {Ok(result)=>json!({"schemaVersion":1,"id":id,"ok":true,"result":result}),Err(error)=>json!({"schemaVersion":1,"id":id,"ok":false,"error":error})};
            emit(&frame)?;
            if shutdown{return Ok::<(),String>(());}
        }
    }.await;
    let mut close_errors = Vec::new();
    if let Some(auth) = auth_owner {
        auth.close_request_bindings();
    }
    if let Some(assembled) = &assembly
        && let Some(facts) = &assembled.runtime_capability_facts
    {
        facts.close();
    }
    // Release and join our transaction before graceful HTTP join; never strand an original Save.
    if state.save_lock.release(true).await.is_err() {
        close_errors.push("save_lock_controller_close");
    }
    if let Some(stop) = stop_sender
        && stop.send(()).is_err()
    {
        close_errors.push("http_listener_stop_send");
    }
    // Closing an unreleased owned gate is recorded; it cannot become a positive probe.
    // Do this before App graceful join so an early browser failure cannot strand A.
    if view.close_held().is_err() {
        close_errors.push("owned_held_gate_close");
    }
    let listener_joined = if let Some(task) = listener_task {
        let (outcome, over_budget) = bounded_completion(task, CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("http_listener_join_deadline");
        }
        match outcome {
            Ok(Ok(())) => true,
            Ok(Err(_)) => {
                close_errors.push("http_listener_return_error");
                false
            }
            Err(_) => {
                close_errors.push("http_listener_join_error");
                false
            }
        }
    } else {
        false
    };
    let facts_drained = if let Some(assembled) = &assembly {
        if let Some(facts) = &assembled.runtime_capability_facts {
            let ((), over_budget) = bounded_completion(facts.drain(), CLOSE_TIMEOUT).await;
            if over_budget {
                close_errors.push("capability_worker_drain_deadline");
            }
            true
        } else {
            false
        }
    } else {
        false
    };
    let relay_stopped = if let Some(relay) = relay {
        let ((), over_budget) = bounded_completion(relay.stop(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("relay_stop_deadline");
        }
        true
    } else {
        false
    };
    let agent_stopped = if let Some(agent) = agent {
        let ((), over_budget) = bounded_completion(agent.stop(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("agent_stop_deadline");
        }
        true
    } else {
        false
    };
    let assembly_closed = if let Some(assembled) = assembly {
        let ((), over_budget) = bounded_completion(assembled.shutdown(), CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("assembly_shutdown_deadline");
        }
        true
    } else {
        false
    };
    // Always await our actual listener and every TLS child. Errors stay visible.
    let wire_task = tokio::spawn(wire.finish());
    let (outcome, over_budget) = bounded_completion(wire_task, CLOSE_TIMEOUT).await;
    if over_budget {
        close_errors.push("owned_wire_finish_deadline");
    }
    let wire_record: Option<WireRecord> = match outcome {
        Ok(Ok(record)) => Some(record),
        Ok(Err(_)) => {
            close_errors.push("owned_wire_finish_error");
            None
        }
        Err(_) => {
            close_errors.push("owned_wire_finish_join_error");
            None
        }
    };
    if let Some(record) = &wire_record {
        if record.failed != 0
            || record.summary["unexpectedErrors"]
                .as_array()
                .is_none_or(|v| !v.is_empty())
            || record.summary["remainingChildren"] != 0
            || record.summary["remainingReplies"] != 0
            || record.summary["remainingGates"] != 0
            || record.summary["childrenSpawned"].as_u64() != Some(record.joined as u64)
        {
            close_errors.push("owned_wire_actual_closure_or_IO_failure");
            counters.collection_failed.store(true, Ordering::SeqCst);
        }
        if record.requests.len() as u64 != record.counts["http"].as_u64().unwrap_or(u64::MAX) {
            close_errors.push("owned_wire_capture_incomplete");
        }
    } else {
        counters.collection_failed.store(true, Ordering::SeqCst);
    }
    let final_counters = live_counters(&state, &view).await;
    observer_pool.close();
    application_pool.close();
    let stdin_joined = if let Some(thread) = stdin_thread {
        let join = tokio::task::spawn_blocking(move || thread.join());
        let (outcome, over_budget) = bounded_completion(join, CLOSE_TIMEOUT).await;
        if over_budget {
            close_errors.push("stdin_eof_join_deadline");
        }
        match outcome {
            Ok(Ok(())) => true,
            _ => {
                close_errors.push("stdin_eof_join_error");
                false
            }
        }
    } else {
        false
    };
    let collection_failed = counters.collection_failed.load(Ordering::SeqCst);
    let wire_finish_returned = wire_record.is_some();
    emit(
        &json!({"schemaVersion":1,"event":"closed","caseId":case_id,"sourceHead":source,"specSha256":spec,
        "listenerJoined":listener_joined,"factsDrained":facts_drained,"relayStopReturned":relay_stopped,
        "agentStopReturned":agent_stopped,"assemblyShutdownReturned":assembly_closed,
        "wireFinishReturned":wire_finish_returned,"wireJoined":wire_record.as_ref().map(|record|record.joined),
        "wireFailed":wire_record.as_ref().map(|record|record.failed),
        "wireCounts":wire_record.as_ref().map(|record|record.counts.clone()),
        "wireRequests":wire_record.as_ref().map(|record|record.requests.clone()),
        "wireSummary":wire_record.as_ref().map(|record|record.summary.clone()),"saveLock":state.save_lock.snapshot().await,"stdinJoined":stdin_joined,"observerPoolCloseCalled":true,
        "applicationPoolCloseCalled":true,"counters":final_counters,"collectionFailed":collection_failed,"closeErrors":close_errors}),
    )?;
    if !listener_joined
        || !facts_drained
        || !relay_stopped
        || !agent_stopped
        || !assembly_closed
        || !wire_finish_returned
        || !stdin_joined
        || collection_failed
        || !close_errors.is_empty()
    {
        return Err("owned_close_incomplete".to_owned());
    }
    result
}
