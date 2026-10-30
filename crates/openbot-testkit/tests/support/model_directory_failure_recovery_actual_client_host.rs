//! Actual assembled host. IPC can prepare identities and observe; it cannot execute a model/run.

use std::collections::BTreeSet;
use std::future::Future;
use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

use super::provider_target_fixture::{Counts, OwnedWire, WireRecord};

const REFRESH: &str = "C4.normal-models-refresh-fault-and-recovery";
const SELECTED: &str = "C4.same-composer-stale-begin-directory-fault";
const DEPLOYMENT: &str = "owned-model-directory-client-deployment";
const TENANT: &str = "owned-model-directory-client-tenant";
const SESSION_KEY: &[u8] = b"owned-model-directory-client-session-key-at-least-32-bytes";
const MODEL_KEY: &str = "owned-c4-model-key";
const MANAGED_KEY: &str = "owned-c4-managed-key";
const MODEL: &str = "owned-c4-model";
const INPUT: &str = "owned C4 stale selection must not begin";
const RENAMED: &str = "Owned C4 model revised";
const APPLICATION_NAME: &str = "owned-model-directory-client-application";
const CONTROLLER_NAME: &str = "owned-model-directory-client-controller";
const PG_BUDGET: Duration = Duration::from_secs(6);
const DIRECTORY_PATH: &str = "/api/me/model-connections";
const CLOSE_TIMEOUT: Duration = Duration::from_secs(12);

// Existing non-production idp.test test CA/leaf/key; no system trust or vendor key is used.
const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

#[derive(Default)]
struct Counters {
    custom: AtomicU64,
    package: AtomicU64,
    managed: AtomicU64,
    remote_validate: AtomicU64,
    remote_start: AtomicU64,
    api_ingress: AtomicU64,
    model_post: AtomicU64,
    model_put: AtomicU64,
    model_list: AtomicU64,
    agent_post: AtomicU64,
    mint_post: AtomicU64,
    begin_post: AtomicU64,
    cap_get: AtomicU64,
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
    managed: bool,
}

#[async_trait]
impl ProviderAdapter for CountingProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        let counter = if self.managed {
            &self.counters.managed
        } else {
            &self.counters.package
        };
        counter.fetch_add(1, Ordering::SeqCst);
        self.inner.start(request).await
    }
}

struct CountingRemote {
    inner: Arc<SafeRemoteAguiTransport>,
    counters: Arc<Counters>,
}

#[async_trait]
impl RemoteAguiTransport for CountingRemote {
    async fn validate_endpoint(&self, endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        self.counters.remote_validate.fetch_add(1, Ordering::SeqCst);
        self.inner.validate_endpoint(endpoint).await
    }

    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&openbot_application::RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        self.counters.remote_start.fetch_add(1, Ordering::SeqCst);
        self.inner.start(endpoint, authorization, body).await
    }
}

// A budget breach stays RED, but ownership is retained until the actual future
// returns. Cleanup never aborts a task or turns dropping a future into a join.
async fn bounded_completion<F: Future>(future: F, budget: Duration) -> (F::Output, bool) {
    tokio::pin!(future);
    match tokio::time::timeout(budget, &mut future).await {
        Ok(value) => (value, false),
        Err(_) => (future.await, true),
    }
}

// These are exact issued statements, not a shortened suffix or a manufactured error.
const ORIGINAL_LIST_SELECT: &str = "SELECT c.id,c.name,c.protocol,c.endpoint,c.model,c.enabled,c.revision,c.current_secret_id,c.created_at,c.updated_at,EXISTS(SELECT 1 FROM public.model_connection_secrets s WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.retired_at IS NULL) AS has_credential FROM public.model_connections c WHERE c.deployment_id=$1 AND c.tenant_id=$2 AND c.owner_user_id=$3 AND c.deleted_at IS NULL AND ($4::uuid IS NULL OR c.id>$4) ORDER BY c.id LIMIT $5";
const ORIGINAL_LIST_SHA: &str = "f89837200b8e120ae539bb839481955fb8362b72b916a75140800d5e0040c9f1";
const OWN_DIRECTORY_LOCK: &str = "LOCK TABLE public.model_connections IN ACCESS EXCLUSIVE MODE";

struct DirectoryController {
    pool: Pool,
    facts: Arc<Mutex<Value>>,
    task: Mutex<Option<tokio::task::JoinHandle<Result<(), String>>>>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    armed: AtomicBool,
    next_list: AtomicBool,
    claimed: AtomicBool,
    cancel_claimed: AtomicBool,
    released: AtomicBool,
    closing: AtomicBool,
}

impl DirectoryController {
    fn new(pool: Pool, mode: String) -> Self {
        Self {
            pool,
            facts: Arc::new(Mutex::new(json!({
                "mode":mode,"phase":"idle","armed":false,"requestSequence":null,
                "lock":{"transactionStarted":false,"lockAcquired":false,"active":false,
                    "controllerPid":null,"controllerBackendStart":null,"controllerXactStart":null,
                    "database":null,"user":null,"applicationName":null,"relationOid":null,
                    "lockMode":null,"lockQuerySha256":null},
                "blockedQuery":null,
                "cancel":{"attempted":false,"guardMatched":false,"signalSent":false,
                    "targetPid":null,"targetBackendStart":null,"targetQueryStart":null,"pgCancelReturned":null},
                "response":{"sequence":null,"status":null,"cacheControl":null,"originalHandlerReturned":false},
                "closure":{"rollbackAttempted":false,"rollbackReturned":false,"stopSent":false,
                    "taskJoined":false,"remainingBlockedQueries":null,"remainingControllerLocks":null,
                    "originalTargetSettled":false},
                "error":null
            }))),
            task: Mutex::new(None),
            stop: Mutex::new(None),
            armed: AtomicBool::new(false),
            next_list: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
            cancel_claimed: AtomicBool::new(false),
            released: AtomicBool::new(false),
            closing: AtomicBool::new(false),
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
        facts["phase"] = json!("failed");
    }

    async fn probe_allowed(&self) -> Result<(), String> {
        // An armed future GET can acquire the lock concurrently with a probe. Reject the
        // entire arm-to-release interval before obtaining any connection/model snapshot.
        if self.armed.load(Ordering::SeqCst) && !self.released.load(Ordering::SeqCst) {
            return Err("directory_probe_disallowed_while_armed".to_owned());
        }
        Ok(())
    }

    async fn arm(&self, next_list: bool, deadline: tokio::time::Instant) -> Result<(), String> {
        if self.closing.load(Ordering::SeqCst) || self.armed.swap(true, Ordering::SeqCst) {
            return Err("directory_arm_reused_or_closed".to_owned());
        }
        self.next_list.store(next_list, Ordering::SeqCst);
        {
            let mut facts = self.facts.lock().await;
            facts["armed"] = json!(true);
            facts["phase"] = json!("armed");
        }
        if next_list {
            Ok(())
        } else {
            self.acquire(deadline).await
        }
    }

    async fn acquire(&self, deadline: tokio::time::Instant) -> Result<(), String> {
        let mut slot = self.task.lock().await;
        if slot.is_some() || self.closing.load(Ordering::SeqCst) {
            return Err("directory_lock_reused_or_closed".to_owned());
        }
        let (stop, stopped) = oneshot::channel();
        *self.stop.lock().await = Some(stop);
        let (ready, prepared) = oneshot::channel();
        let pool = self.pool.clone();
        let facts = self.facts.clone();
        *slot = Some(tokio::spawn(async move {
            let mut client = tokio::time::timeout_at(deadline, pool.get())
                .await
                .map_err(|_| "directory_lock_connection_deadline")?
                .map_err(|_| "directory_lock_connection")?;
            let tx = tokio::time::timeout_at(deadline, client.transaction())
                .await
                .map_err(|_| "directory_lock_begin_deadline")?
                .map_err(|_| "directory_lock_begin")?;
            facts.lock().await["lock"]["transactionStarted"] = json!(true);
            let setup = async {
                tokio::time::timeout_at(deadline, tx.query_one(
                    "SELECT set_config('application_name',$1,true),set_config('statement_timeout','6000',true),set_config('lock_timeout','6000',true)",
                    &[&CONTROLLER_NAME])).await.map_err(|_| "directory_lock_setup_deadline")?
                    .map_err(|_| "directory_lock_setup")?;
                tokio::time::timeout_at(deadline, tx.batch_execute(OWN_DIRECTORY_LOCK)).await
                    .map_err(|_| "directory_lock_acquire_deadline")?.map_err(|_| "directory_lock_acquire")?;
                let row = tokio::time::timeout_at(deadline, tx.query_one(
                    "SELECT jsonb_build_object('transactionStarted',true,'lockAcquired',true,'active',true,
                     'controllerPid',a.pid,'controllerBackendStart',a.backend_start::text,
                     'controllerXactStart',a.xact_start::text,'database',a.datname,'user',a.usename,
                     'applicationName',a.application_name,'relationOid',l.relation::bigint,'lockMode',l.mode,
                     'lockQuerySha256',NULL)
                     FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
                     WHERE a.pid=pg_backend_pid() AND a.application_name=$1 AND l.locktype='relation'
                       AND l.relation='public.model_connections'::regclass AND l.mode='AccessExclusiveLock' AND l.granted",
                    &[&CONTROLLER_NAME])).await.map_err(|_| "directory_lock_identity_deadline")?
                    .map_err(|_| "directory_lock_identity")?;
                let mut witness:Value = row.try_get(0).map_err(|_| "directory_lock_identity_shape")?;
                if witness["controllerPid"].as_i64().is_none_or(|pid|pid<=0)
                    || witness["controllerXactStart"].as_str().is_none()
                    || witness["relationOid"].as_i64().is_none_or(|oid|oid<=0) {
                    return Err("directory_lock_identity_invalid".to_owned());
                }
                witness["lockQuerySha256"] = json!(Sha256Digest::of(OWN_DIRECTORY_LOCK.as_bytes()).to_hex());
                let mut record = facts.lock().await;
                record["lock"] = witness; record["phase"] = json!("locked");
                Ok::<(),String>(())
            }.await;
            let mut error = setup.err();
            let notice = error.as_ref().map_or(Ok(()), |code| Err(code.clone()));
            if ready.send(notice).is_err() && error.is_none() {
                error = Some("directory_lock_ready_receiver".to_owned());
            }
            if error.is_none() && stopped.await.is_err() {
                error = Some("directory_lock_stop_receiver".to_owned());
            }
            facts.lock().await["closure"]["rollbackAttempted"] = json!(true);
            let (rolled_back, over_budget) = bounded_completion(tx.rollback(), PG_BUDGET).await;
            if over_budget && error.is_none() {
                error = Some("directory_lock_rollback_deadline".to_owned());
            }
            match rolled_back {
                Ok(()) => {
                    let mut record = facts.lock().await;
                    record["closure"]["rollbackReturned"] = json!(true);
                    record["lock"]["active"] = json!(false);
                }
                _ => {
                    if error.is_none() {
                        error = Some("directory_lock_rollback".to_owned());
                    }
                }
            }
            if let Some(code) = error {
                let mut record = facts.lock().await;
                if record["error"].is_null() {
                    record["error"] = json!(code);
                }
                record["phase"] = json!("failed");
                Err(code)
            } else {
                Ok(())
            }
        }));
        drop(slot);
        match tokio::time::timeout_at(deadline, prepared).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(code))) => {
                self.fail(&code).await;
                Err(code)
            }
            _ => {
                self.fail("directory_lock_ready_deadline").await;
                Err("directory_lock_ready_deadline".to_owned())
            }
        }
    }

    async fn admit(&self, sequence: u64) -> Result<(), String> {
        if self.claimed.swap(true, Ordering::SeqCst) || self.closing.load(Ordering::SeqCst) {
            return Err("directory_original_get_reused_or_closed".to_owned());
        }
        self.facts.lock().await["requestSequence"] = json!(sequence);
        if self.next_list.load(Ordering::SeqCst) {
            self.acquire(tokio::time::Instant::now() + PG_BUDGET)
                .await?;
        }
        if self.facts.lock().await["lock"]["active"] != true {
            return Err("directory_original_get_without_actual_lock".to_owned());
        }
        Ok(())
    }

    async fn response(&self, sequence: u64, status: u16, cache: Option<String>) {
        let mut facts = self.facts.lock().await;
        if facts["requestSequence"] == sequence {
            facts["response"] = json!({"sequence":sequence,"status":status,"cacheControl":cache,"originalHandlerReturned":true});
            if facts["error"].is_null() {
                facts["phase"] = json!("response_observed");
            }
            if status != 503 || facts["response"]["cacheControl"] != "no-store" {
                if facts["error"].is_null() {
                    facts["error"] = json!("directory_original_response_mismatch");
                }
                facts["phase"] = json!("failed");
            }
        }
    }

    async fn blocked(&self, deadline: tokio::time::Instant) -> Result<Option<Value>, String> {
        let record = self.snapshot().await;
        if let Some(code) = record["error"].as_str() {
            return Err(code.to_owned());
        }
        let lock = record["lock"].clone();
        if lock["controllerPid"].is_null() {
            if self.armed.load(Ordering::SeqCst) && !self.released.load(Ordering::SeqCst) {
                return Ok(None);
            }
            return Err("directory_controller_pid_missing".to_owned());
        }
        let controller = i32::try_from(
            lock["controllerPid"]
                .as_i64()
                .ok_or("directory_controller_pid_missing")?,
        )
        .map_err(|_| "directory_controller_pid_invalid")?;
        let oid = lock["relationOid"]
            .as_i64()
            .ok_or("directory_controller_relation_missing")?;
        let database = text(&lock, "database")?;
        let user = text(&lock, "user")?;
        let birth = text(&lock, "controllerBackendStart")?;
        let xact = text(&lock, "controllerXactStart")?;
        let mut client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| "directory_watch_connection_deadline")?
            .map_err(|_| "directory_watch_connection")?;
        let tx =
            tokio::time::timeout_at(deadline, client.build_transaction().read_only(true).start())
                .await
                .map_err(|_| "directory_watch_begin_deadline")?
                .map_err(|_| "directory_watch_begin")?;
        let result=async {
            let remaining=deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis().clamp(1,4000).to_string();
            tokio::time::timeout_at(deadline,tx.query_one("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)", &[&remaining]))
                .await.map_err(|_|"directory_watch_setup_deadline")?.map_err(|_|"directory_watch_setup")?;
            let rows=tokio::time::timeout_at(deadline,tx.query(
                "SELECT jsonb_build_object('pid',a.pid,'backendStart',a.backend_start::text,'xactStart',a.xact_start::text,
                 'queryStart',a.query_start::text,'database',a.datname,'user',a.usename,'applicationName',a.application_name,
                 'state',a.state,'waitEventType',a.wait_event_type,'waitEvent',a.wait_event,'queryText',a.query,
                 'queryUtf8Bytes',octet_length(a.query),'querySha256',NULL,'relationOid',l.relation::bigint,
                 'lockMode',l.mode,'lockGranted',l.granted,'blockingPids',to_jsonb(pg_blocking_pids(a.pid)),
                 'controllerBlocking',($1=ANY(pg_blocking_pids(a.pid))))
                 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid AND l.locktype='relation'
                   AND l.relation::bigint=$2 AND l.mode='AccessShareLock' AND NOT l.granted
                 WHERE a.datname=$3 AND a.usename=$4 AND a.application_name=$5 AND a.state='active'
                   AND a.wait_event_type='Lock' AND a.query=$6 AND $1=ANY(pg_blocking_pids(a.pid))
                   AND EXISTS(SELECT 1 FROM pg_stat_activity c JOIN pg_locks cl ON cl.pid=c.pid
                     WHERE c.pid=$1 AND c.backend_start::text=$7 AND c.xact_start::text=$8 AND c.datname=$3
                       AND c.usename=$4 AND c.application_name=$9 AND cl.locktype='relation' AND cl.relation::bigint=$2
                       AND cl.mode='AccessExclusiveLock' AND cl.granted)",
                &[&controller,&oid,&database,&user,&APPLICATION_NAME,&ORIGINAL_LIST_SELECT,&birth,&xact,&CONTROLLER_NAME]))
                .await.map_err(|_|"directory_watch_query_deadline")?.map_err(|_|"directory_watch_query")?;
            if rows.len()>1 { return Err("directory_multiple_original_queries".to_owned()); }
            if let Some(row)=rows.first() {
                let mut witness:Value=row.try_get(0).map_err(|_|"directory_watch_shape")?;
                let actual=text(&witness,"queryText")?;
                let digest=Sha256Digest::of(actual.as_bytes()).to_hex();
                if actual!=ORIGINAL_LIST_SELECT || actual.len()!=551 || digest!=ORIGINAL_LIST_SHA
                    || witness["queryUtf8Bytes"]!=551 || witness["controllerBlocking"]!=true {
                    return Err("directory_complete_query_mismatch".to_owned());
                }
                witness["querySha256"]=json!(digest);
                Ok(Some(witness))
            } else { Ok(None) }
        }.await;
        let (rolled_back, over_budget) = bounded_completion(tx.rollback(), PG_BUDGET).await;
        if over_budget {
            return Err("directory_watch_rollback_deadline".to_owned());
        }
        match rolled_back {
            Ok(()) => result,
            Err(_) => Err("directory_watch_rollback".to_owned()),
        }
    }

    async fn cancel(&self, current: Case, budget: Duration) -> Result<(), String> {
        if !self.armed.load(Ordering::SeqCst)
            || self.closing.load(Ordering::SeqCst)
            || self.cancel_claimed.swap(true, Ordering::SeqCst)
            || self.released.load(Ordering::SeqCst)
        {
            return Err("directory_cancel_reused_or_released".to_owned());
        }
        let deadline = tokio::time::Instant::now() + budget;
        let witness = loop {
            if let Some(value) = self.blocked(deadline).await? {
                break value;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("directory_original_query_not_observed".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let pid = i32::try_from(
            witness["pid"]
                .as_i64()
                .ok_or("directory_target_pid_missing")?,
        )
        .map_err(|_| "directory_target_pid_invalid")?;
        let birth = text(&witness, "backendStart")?;
        let xact = text(&witness, "xactStart")?;
        let query_start = text(&witness, "queryStart")?;
        let lock = self.facts.lock().await["lock"].clone();
        let controller = i32::try_from(
            lock["controllerPid"]
                .as_i64()
                .ok_or("directory_controller_pid_missing")?,
        )
        .map_err(|_| "directory_controller_pid_invalid")?;
        let oid = lock["relationOid"]
            .as_i64()
            .ok_or("directory_controller_relation_missing")?;
        let database = text(&lock, "database")?;
        let user = text(&lock, "user")?;
        let control_birth = text(&lock, "controllerBackendStart")?;
        let control_xact = text(&lock, "controllerXactStart")?;
        let hash = SessionTokenHash::compute(
            SessionToken::new(current.cookie_token.as_bytes()),
            SessionHashKey::new(SESSION_KEY),
        )
        .to_column_value();
        {
            let mut facts = self.facts.lock().await;
            facts["blockedQuery"] = witness.clone();
            facts["phase"] = json!("blocked");
            facts["cancel"]["targetPid"] = json!(pid);
            facts["cancel"]["targetBackendStart"] = json!(birth);
            facts["cancel"]["targetQueryStart"] = json!(query_start);
        }
        let mut client = tokio::time::timeout_at(deadline, self.pool.get())
            .await
            .map_err(|_| "directory_cancel_connection_deadline")?
            .map_err(|_| "directory_cancel_connection")?;
        let tx = tokio::time::timeout_at(deadline, client.transaction())
            .await
            .map_err(|_| "directory_cancel_begin_deadline")?
            .map_err(|_| "directory_cancel_begin")?;
        let result=async {
            let remaining=deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis().clamp(1,4000).to_string();
            tokio::time::timeout_at(deadline,tx.query_one("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining]))
                .await.map_err(|_|"directory_cancel_setup_deadline")?.map_err(|_|"directory_cancel_setup")?;
            self.facts.lock().await["cancel"]["attempted"]=json!(true);
            // The exact identity, current complete query, own relation lock/blocker and
            // unaffected original session/actor facts are rechecked in this one statement.
            let rows=tokio::time::timeout_at(deadline,tx.query(
                "SELECT pg_cancel_backend(a.pid) FROM pg_stat_activity a
                 WHERE a.pid=$1 AND a.backend_start::text=$2 AND a.xact_start::text=$3 AND a.query_start::text=$4
                   AND a.datname=$5 AND a.usename=$6 AND a.application_name=$7 AND a.state='active'
                   AND a.wait_event_type='Lock' AND a.query=$8 AND octet_length(a.query)=551
                   AND $9=ANY(pg_blocking_pids(a.pid))
                   AND EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='relation'
                     AND l.relation::bigint=$10 AND l.mode='AccessShareLock' AND NOT l.granted)
                   AND EXISTS(SELECT 1 FROM pg_stat_activity c JOIN pg_locks l ON l.pid=c.pid
                     WHERE c.pid=$9 AND c.backend_start::text=$11 AND c.xact_start::text=$12 AND c.datname=$5
                       AND c.usename=$6 AND c.application_name=$13 AND l.locktype='relation' AND l.relation::bigint=$10
                       AND l.mode='AccessExclusiveLock' AND l.granted)
                   AND EXISTS(SELECT 1 FROM public.sessions s JOIN public.users u ON u.id=s.user_id
                     WHERE s.id=$14 AND s.user_id=$15 AND s.token=$16 AND s.auth_generation=0
                       AND coalesce(u.auth_generation,0)=0 AND s.expires_at>clock_timestamp()
                       AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role IN ('user','admin'))
                       AND NOT EXISTS(SELECT 1 FROM public.revoked_access r WHERE r.email=lower(u.email)))",
                &[&pid,&birth,&xact,&query_start,&database,&user,&APPLICATION_NAME,&ORIGINAL_LIST_SELECT,
                  &controller,&oid,&control_birth,&control_xact,&CONTROLLER_NAME,&current.session,&current.actor,&hash]))
                .await.map_err(|_|"directory_cancel_query_deadline")?.map_err(|_|"directory_cancel_query")?;
            if rows.len()!=1 { return Err("directory_cancel_joint_guard_failed".to_owned()); }
            let sent:bool=rows[0].try_get(0).map_err(|_|"directory_cancel_shape")?;
            let mut facts=self.facts.lock().await;
            facts["cancel"]["guardMatched"]=json!(true);facts["cancel"]["pgCancelReturned"]=json!(sent);
            facts["cancel"]["signalSent"]=json!(sent);
            if facts["error"].is_null() { facts["phase"]=json!("cancel_sent"); }
            if !sent { return Err("directory_cancel_signal_false".to_owned()); }
            Ok::<(),String>(())
        }.await;
        let (rolled_back, over_budget) = bounded_completion(tx.rollback(), PG_BUDGET).await;
        if over_budget {
            return Err("directory_cancel_observer_rollback_deadline".to_owned());
        }
        if rolled_back.is_err() {
            return Err("directory_cancel_observer_rollback".to_owned());
        }
        result?;
        loop {
            let facts = self.snapshot().await;
            if facts["response"]["originalHandlerReturned"] == true {
                if facts["response"]["status"] != 503
                    || facts["response"]["cacheControl"] != "no-store"
                    || !facts["error"].is_null()
                {
                    return Err("directory_original_response_failed".to_owned());
                }
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("directory_original_response_deadline".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn settle(&self) -> Result<(), String> {
        let facts = self.snapshot().await;
        let lock = facts["lock"].clone();
        let Some(controller) = lock["controllerPid"].as_i64() else {
            return Ok(());
        };
        let controller =
            i32::try_from(controller).map_err(|_| "directory_settle_controller_pid")?;
        let oid = lock["relationOid"]
            .as_i64()
            .ok_or("directory_settle_relation")?;
        let database = text(&lock, "database")?;
        let user = text(&lock, "user")?;
        let deadline = tokio::time::Instant::now() + PG_BUDGET;
        loop {
            let mut client = tokio::time::timeout_at(deadline, self.pool.get())
                .await
                .map_err(|_| "directory_settle_connection_deadline")?
                .map_err(|_| "directory_settle_connection")?;
            let tx = tokio::time::timeout_at(
                deadline,
                client.build_transaction().read_only(true).start(),
            )
            .await
            .map_err(|_| "directory_settle_begin_deadline")?
            .map_err(|_| "directory_settle_begin")?;
            let result=async {
                let remaining=deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis().clamp(1,6000).to_string();
                tokio::time::timeout_at(deadline,tx.query_one("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$1,true)",&[&remaining]))
                    .await.map_err(|_|"directory_settle_setup_deadline")?.map_err(|_|"directory_settle_setup")?;
                let row=tokio::time::timeout_at(deadline,tx.query_one(
                    "SELECT (SELECT count(*) FROM pg_stat_activity a WHERE a.datname=$1 AND a.usename=$2
                       AND a.application_name=$3 AND a.query=$4 AND a.state='active'),
                     (SELECT count(*) FROM pg_locks l WHERE l.pid=$5 AND l.relation::bigint=$6
                       AND l.locktype='relation' AND l.mode='AccessExclusiveLock' AND l.granted)",
                    &[&database,&user,&APPLICATION_NAME,&ORIGINAL_LIST_SELECT,&controller,&oid]))
                    .await.map_err(|_|"directory_settle_query_deadline")?.map_err(|_|"directory_settle_query")?;
                let pending:i64=row.try_get(0).map_err(|_|"directory_settle_shape")?;
                let locks:i64=row.try_get(1).map_err(|_|"directory_settle_shape")?;
                let target=if let Some(pid)=facts["blockedQuery"]["pid"].as_i64() {
                    let pid=i32::try_from(pid).map_err(|_|"directory_settle_target_pid")?;
                    let birth=text(&facts["blockedQuery"],"backendStart")?;
                    let row=tokio::time::timeout_at(deadline,tx.query_opt(
                        "SELECT a.state,a.xact_start IS NULL,a.query<>$3 FROM pg_stat_activity a WHERE a.pid=$1 AND a.backend_start::text=$2",
                        &[&pid,&birth,&ORIGINAL_LIST_SELECT])).await.map_err(|_|"directory_target_settle_deadline")?
                        .map_err(|_|"directory_target_settle_query")?;
                    if let Some(row)=row {
                        let state:String=row.try_get(0).map_err(|_|"directory_target_settle_shape")?;
                        let no_xact:bool=row.try_get(1).map_err(|_|"directory_target_settle_shape")?;
                        let not_source:bool=row.try_get(2).map_err(|_|"directory_target_settle_shape")?;
                        state=="idle" && no_xact && not_source
                    } else { true }
                } else { false };
                Ok::<_,String>((pending,locks,target))
            }.await;
            let (rolled_back, over_budget) = bounded_completion(tx.rollback(), PG_BUDGET).await;
            if over_budget {
                return Err("directory_settle_rollback_deadline".to_owned());
            }
            if rolled_back.is_err() {
                return Err("directory_settle_rollback".to_owned());
            }
            let (pending, locks, target) = result?;
            {
                let mut record = self.facts.lock().await;
                record["closure"]["remainingBlockedQueries"] = json!(pending);
                record["closure"]["remainingControllerLocks"] = json!(locks);
                record["closure"]["originalTargetSettled"] = json!(target);
            }
            if pending == 0 && locks == 0 && target {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("directory_actual_settle_deadline".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn release(&self, finally: bool) -> bool {
        if finally {
            self.closing.store(true, Ordering::SeqCst);
        }
        if self.released.load(Ordering::SeqCst) {
            return self.facts.lock().await["error"].is_null();
        }
        if !self.armed.load(Ordering::SeqCst) {
            return finally;
        }
        if !finally && self.facts.lock().await["response"]["originalHandlerReturned"] != true {
            self.fail("directory_release_before_original_response")
                .await;
            return false;
        }
        if let Some(stop) = self.stop.lock().await.take() {
            let sent = stop.send(()).is_ok();
            self.facts.lock().await["closure"]["stopSent"] = json!(sent);
            if !sent {
                self.fail("directory_stop_send").await;
            }
        }
        if let Some(mut task) = self.task.lock().await.take() {
            let outcome = match tokio::time::timeout(CLOSE_TIMEOUT, &mut task).await {
                Ok(value) => value,
                Err(_) => {
                    self.fail("directory_controller_join_deadline").await;
                    task.await
                }
            };
            // An actual handle was awaited to completion. Error is retained separately.
            self.facts.lock().await["closure"]["taskJoined"] = json!(true);
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(code)) => self.fail(&code).await,
                Err(_) => self.fail("directory_controller_join_error").await,
            }
        }
        if let Err(code) = self.settle().await {
            self.fail(&code).await;
        }
        self.released.store(true, Ordering::SeqCst);
        let mut facts = self.facts.lock().await;
        if facts["error"].is_null() {
            facts["phase"] = json!(if finally { "closed" } else { "rolled_back" });
        }
        facts["error"].is_null()
    }
}

async fn validate_fault_source(state: &State, current: &Case) -> Result<(), String> {
    let id = current.model_id.ok_or("directory_model_not_bound")?;
    let base = current
        .bound_revision
        .ok_or("directory_created_revision_missing")?;
    let revision = if state.case_id == SELECTED {
        base.checked_add(1).ok_or("directory_revision_overflow")?
    } else {
        base
    };
    let name = if state.case_id == SELECTED {
        RENAMED
    } else {
        "Owned C4 model"
    };
    let secret = current
        .bound_secret_id
        .ok_or("directory_created_secret_missing")?;
    let endpoint = current
        .bound_endpoint
        .as_deref()
        .ok_or("directory_created_endpoint_missing")?;
    let hash = SessionTokenHash::compute(
        SessionToken::new(current.cookie_token.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    let client = state
        .observer
        .get()
        .await
        .map_err(|_| "directory_source_connection")?;
    let row=client.query_opt(
        "SELECT c.id FROM public.model_connections c JOIN public.model_connection_secrets k ON k.id=c.current_secret_id
         AND k.connection_id=c.id AND k.owner_user_id=c.owner_user_id AND k.deployment_id=c.deployment_id AND k.tenant_id=c.tenant_id
         JOIN public.sessions s ON s.id=$2 AND s.user_id=c.owner_user_id JOIN public.users u ON u.id=s.user_id
         WHERE c.id=$1 AND c.owner_user_id=$3 AND c.deployment_id=$4 AND c.tenant_id=$5 AND c.deleted_at IS NULL
           AND c.enabled AND c.name=$6 AND c.model=$7 AND c.revision=$8 AND c.current_secret_id=$9 AND c.endpoint=$10
           AND c.protocol='openai_chat_completions' AND k.retired_at IS NULL AND s.token=$11
           AND s.auth_generation=0 AND coalesce(u.auth_generation,0)=0 AND s.expires_at>clock_timestamp()
           AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role IN ('user','admin'))
           AND NOT EXISTS(SELECT 1 FROM public.revoked_access r WHERE r.email=lower(u.email))",
        &[&id,&current.session,&current.actor,&DEPLOYMENT,&TENANT,&name,&MODEL,&revision,&secret,&endpoint,&hash])
        .await.map_err(|_|"directory_source_query")?;
    if row.is_none() {
        return Err("directory_original_fixture_source_changed".to_owned());
    }
    Ok(())
}

#[derive(Clone)]
struct Case {
    actor: String,
    session: String,
    model_id: Option<Uuid>,
    bound_revision: Option<i64>,
    bound_secret_id: Option<Uuid>,
    bound_endpoint: Option<String>,
    cookie_token: String,
}

struct State {
    observer: Pool,
    vault: CredentialRecordVault,
    counters: Arc<Counters>,
    case: Mutex<Option<Case>>,
    requests: Mutex<Vec<Value>>,
    case_id: String,
    directory: Arc<DirectoryController>,
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
        ("POST", DIRECTORY_PATH) => Some(&state.counters.model_post),
        ("PUT", path) if model_path(path) => Some(&state.counters.model_put),
        ("GET", DIRECTORY_PATH) => Some(&state.counters.model_list),
        ("POST", "/api/agents") => Some(&state.counters.agent_post),
        ("POST", "/api/threads/mint") => Some(&state.counters.mint_post),
        ("GET", "/api/me/capabilities") => Some(&state.counters.cap_get),
        ("POST", path) if begin_path(path) => Some(&state.counters.begin_post),
        _ => None,
    };
    if let Some(counter) = admission {
        counter.fetch_add(1, Ordering::SeqCst);
    }
    let sequence = state.counters.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    if method == "GET"
        && path == DIRECTORY_PATH
        && state.directory.armed.load(Ordering::SeqCst)
        && !state.directory.released.load(Ordering::SeqCst)
    {
        let request_has_query = request.uri().query().is_some();
        let request_cookies = (|| {
            let mut found = Vec::new();
            for header in request.headers().get_all(axum::http::header::COOKIE) {
                let header = header
                    .to_str()
                    .map_err(|_| "directory_original_cookie_invalid".to_owned())?;
                for value in header.split(';') {
                    if let Some((name, value)) = value.trim().split_once('=')
                        && name == "openbot_session"
                    {
                        found.push(value.to_owned());
                    }
                }
            }
            Ok::<Vec<String>, String>(found)
        })();
        let gate = async {
            if request_has_query {
                return Err("directory_original_get_query_changed".to_owned());
            }
            let current = case(&state).await?;
            let found = request_cookies?;
            if found.len() != 1 || found[0] != current.cookie_token {
                return Err("directory_original_get_session_mismatch".to_owned());
            }
            if state.case_id == SELECTED
                && !state.requests.lock().await.iter().any(|record| {
                    record["method"] == "POST"
                        && record["status"] == 409
                        && record["path"].as_str().is_some_and(begin_path)
                        && record["sequence"]
                            .as_u64()
                            .is_some_and(|earlier| earlier < sequence)
                })
            {
                return Err("directory_next_get_before_real_begin409".to_owned());
            }
            state.directory.admit(sequence).await
        }
        .await;
        if let Err(code) = gate {
            state.directory.fail(&code).await;
            state
                .counters
                .collection_failed
                .store(true, Ordering::SeqCst);
        }
    }
    // Gate errors never manufacture a response. The original router, resolver,
    // authorization, application and database handler still receive this request.
    let response = next.run(request).await;
    let cache = response
        .headers()
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .map(str::to_owned);
    state
        .directory
        .response(sequence, response.status().as_u16(), cache)
        .await;
    if response.status().is_success()
        && response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/html"))
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
        records.push(json!({"sequence":sequence,"method":method,"path":path,
            "status":response.status().as_u16()}));
    }
    response
}

fn begin_path(path: &str) -> bool {
    path.starts_with("/api/threads/") && path.ends_with("/runs") && path.split('/').count() == 5
}

fn model_path(path: &str) -> bool {
    path.strip_prefix("/api/me/model-connections/")
        .is_some_and(|id| !id.contains('/') && Uuid::parse_str(id).is_ok())
}

fn emit(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string(value).map_err(|_| "protocol_encode")?;
    if text.len() > 1_048_576 {
        return Err("protocol_reply_limit".to_owned());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "\nC4_HOST {text}").map_err(|_| "protocol_write")?;
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

async fn case(state: &State) -> Result<Case, String> {
    state
        .case
        .lock()
        .await
        .clone()
        .ok_or_else(|| "case_not_prepared".to_owned())
}

async fn prepare(state: &State, wire: &OwnedWire) -> Result<Value, String> {
    let mut slot = state.case.lock().await;
    if slot.is_some() {
        return Err("case_already_prepared".to_owned());
    }
    let actor = format!("owned-c4-user-{}", Uuid::new_v4());
    let session = Uuid::new_v4().to_string();
    let token = format!("OWNED_C4_SESSION_{}", Uuid::new_v4());
    let channel = format!("owned-c4-channel-{}", Uuid::new_v4());
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "prepare_connection")?;
    let transaction = client.transaction().await.map_err(|_| "prepare_begin")?;
    let email = format!("{actor}@owned-c4.test");
    transaction
        .execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES($1,$2,0)",
            &[&actor, &email],
        )
        .await
        .map_err(|_| "prepare_user")?;
    transaction
        .execute(
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
    transaction
        .execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,0)",
            &[&session,&actor,&token_hash,&(now+time::Duration::hours(2)),&now])
        .await.map_err(|_| "prepare_session")?;
    transaction
        .execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned C4 channel','',ARRAY[]::text[],ARRAY[]::text[])", &[&channel])
        .await.map_err(|_| "prepare_channel")?;
    transaction
        .execute(
            "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,$2)",
            &[&channel, &actor],
        )
        .await
        .map_err(|_| "prepare_membership")?;
    transaction.commit().await.map_err(|_| "prepare_commit")?;
    *slot = Some(Case {
        actor: actor.clone(),
        session: session.clone(),
        model_id: None,
        bound_revision: None,
        bound_secret_id: None,
        bound_endpoint: None,
        cookie_token: token.clone(),
    });
    Ok(json!({"caseId":state.case_id,"actor":actor,
        "session":{"id":session,"userId":actor,"token":token,"cookieName":"openbot_session"},
        "model":{"name":"Owned C4 model","protocol":"openai_chat_completions",
            "endpoint":format!("{}/v1",wire.origin()),"model":MODEL,"enabled":true,"apiKey":MODEL_KEY},
        "agent":{"name":"Owned C4 Bot","title":"Owned C4 Bot","roleDescription":"Return the owned canary text without tools.","visibility":"public"},
        "channelId":channel,"intents":{"input":INPUT,"renamedModelName":RENAMED}}))
}

fn fingerprint(value: &Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "observer_hash_encode")?;
    Ok(
        json!({"count":value.as_array().map_or(0,Vec::len),"sha256":Sha256Digest::of(&bytes).to_hex()}),
    )
}

// Only owned relations. Cipher/signature columns never leave SQL as their original value.
const SNAPSHOT: &str = "SELECT jsonb_build_object(
 'model_connections',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY id),'[]'::jsonb) FROM public.model_connections m),
 'model_connection_secrets',(SELECT coalesce(jsonb_agg((to_jsonb(s)-'encrypted_value') || jsonb_build_object('encrypted_value_sql_md5',md5(encrypted_value)) ORDER BY id),'[]'::jsonb) FROM public.model_connection_secrets s),
 'credentials',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'encrypted_value') || jsonb_build_object('encrypted_value_sql_md5',md5(encrypted_value)) ORDER BY id),'[]'::jsonb) FROM public.credentials c),
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
 'audit_checkpoints',(SELECT coalesce(jsonb_agg((to_jsonb(c)-'signature') || jsonb_build_object('signature_sql_md5',md5(signature)) ORDER BY sequence),'[]'::jsonb) FROM public.audit_checkpoints c))";

async fn live_counters(state: &State, counts: Option<Counts>) -> Value {
    let records = state.requests.lock().await;
    let matching = |method: &str, path: &str, status: Option<u64>| -> usize {
        records
            .iter()
            .filter(|record| {
                record["method"] == method
                    && record["path"] == path
                    && status.is_none_or(|status| record["status"].as_u64() == Some(status))
            })
            .count()
    };
    let begin = |status: Option<u64>| -> usize {
        records
            .iter()
            .filter(|record| {
                record["method"] == "POST"
                    && record["path"].as_str().is_some_and(begin_path)
                    && status.is_none_or(|status| record["status"].as_u64() == Some(status))
            })
            .count()
    };
    json!({"modelPost":state.counters.model_post.load(Ordering::SeqCst),
        "model201":matching("POST",DIRECTORY_PATH,Some(201)),
        "modelPut":state.counters.model_put.load(Ordering::SeqCst),
        "modelPut200":records.iter().filter(|record|record["method"]=="PUT" && record["status"]==200
            && record["path"].as_str().is_some_and(model_path)).count(),
        "modelListGet":state.counters.model_list.load(Ordering::SeqCst),
        "modelList200":matching("GET",DIRECTORY_PATH,Some(200)),
        "modelList503":matching("GET",DIRECTORY_PATH,Some(503)),
        "agentPost":state.counters.agent_post.load(Ordering::SeqCst),"agent201":matching("POST","/api/agents",Some(201)),
        "mintPost":state.counters.mint_post.load(Ordering::SeqCst),"beginPost":state.counters.begin_post.load(Ordering::SeqCst),"begin201":begin(Some(201)),"begin409":begin(Some(409)),
        "capGet":state.counters.cap_get.load(Ordering::SeqCst),"cap200":matching("GET","/api/me/capabilities",Some(200)),
        "customStart":state.counters.custom.load(Ordering::SeqCst),"packageStart":state.counters.package.load(Ordering::SeqCst),
        "managedStart":state.counters.managed.load(Ordering::SeqCst),
        "remoteValidate":state.counters.remote_validate.load(Ordering::SeqCst),"remoteStart":state.counters.remote_start.load(Ordering::SeqCst),
        "dns":counts.map(|value|value.dns),"tcp":counts.map(|value|value.tcp),"http":counts.map(|value|value.http),
        "apiIngressCount":state.counters.api_ingress.load(Ordering::SeqCst),
        "servedIndex":state.counters.served_index.load(Ordering::SeqCst),
        "collectionFailed":state.counters.collection_failed.load(Ordering::SeqCst)})
}

fn wire_requests(wire: &OwnedWire) -> Result<Value, String> {
    let mut records = Vec::new();
    for request in wire.requests() {
        let body: Value = serde_json::from_slice(&request.body).map_err(|_| "owned_wire_json")?;
        records.push(json!({"method":request.method,"target":request.target,"model":body.get("model"),"stream":body.get("stream"),
            "authorizationMatches":request.headers.get("authorization").is_some_and(|header|header==&format!("Bearer {MODEL_KEY}")),
            "authorizationHeaderCount":request.header_counts.get("authorization").copied().unwrap_or(0),
            "secretInBody":request.body.windows(MODEL_KEY.len()).any(|bytes|bytes==MODEL_KEY.as_bytes()),
            "bodySha256":Sha256Digest::of(&request.body).to_hex()}));
    }
    Ok(json!(records))
}

async fn probe(state: &State, wire: &OwnedWire) -> Result<Value, String> {
    state.directory.probe_allowed().await?;
    let current = case(state).await?;
    let mut client = state
        .observer
        .get()
        .await
        .map_err(|_| "observer_connection")?;
    let transaction = client
        .build_transaction()
        .read_only(true)
        .start()
        .await
        .map_err(|_| "observer_begin")?;
    let pid: i32 = transaction
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|_| "observer_pid")?
        .get(0);
    let full: Value = transaction
        .query_one(SNAPSHOT, &[])
        .await
        .map_err(|_| "observer_snapshot")?
        .get(0);
    if serde_json::to_vec(&full)
        .map_err(|_| "observer_encode")?
        .len()
        > 262_144
    {
        return Err("observer_snapshot_limit".to_owned());
    }
    let session: Value = transaction
        .query_one(
            "SELECT to_jsonb(s)-'token' FROM public.sessions s WHERE id=$1 AND user_id=$2",
            &[&current.session, &current.actor],
        )
        .await
        .map_err(|_| "observer_session")?
        .get(0);
    let mut row = Value::Null;
    let mut secret = Value::Null;
    let mut vault = Value::Null;
    if let Some(id) = current.model_id {
        let record=transaction.query_one("SELECT to_jsonb(m),to_jsonb(s)-'encrypted_value',s.encrypted_value,s.id FROM public.model_connections m JOIN public.model_connection_secrets s ON s.id=m.current_secret_id AND s.connection_id=m.id AND s.deployment_id=m.deployment_id AND s.tenant_id=m.tenant_id AND s.owner_user_id=m.owner_user_id WHERE m.id=$1 AND m.deployment_id=$2 AND m.tenant_id=$3 AND m.owner_user_id=$4",
            &[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"observer_current_model_secret")?;
        row = record.get(0);
        secret = record.get(1);
        let encrypted: String = record.get(2);
        let secret_id: Uuid = record.get(3);
        secret["encrypted_value_sha256"] = json!(Sha256Digest::of(encrypted.as_bytes()).to_hex());
        let owner = SecretPrincipal::Actor(ActorId::new(current.actor.clone()));
        let service = SecretPrincipal::Service(ServiceId::new(id.to_string()));
        let opened = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                owner.clone(),
                service.clone(),
                &encrypted,
            )
            .map_err(|_| "observer_vault_open")?;
        let migration = opened.needs_migration();
        let plaintext = opened.into_secret();
        let wrong_owner = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("owned-c4-wrong-owner")),
                service.clone(),
                &encrypted,
            )
            .is_err();
        let wrong_service = state
            .vault
            .open(
                &secret_id,
                SecretKind::Model,
                owner.clone(),
                SecretPrincipal::Service(ServiceId::new("owned-c4-wrong-service")),
                &encrypted,
            )
            .is_err();
        let wrong_tenant = CredentialRecordVault::single_key(
            TenantId::new("owned-c4-wrong-tenant"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "observer_wrong_tenant_key")?,
        );
        vault = json!({"canaryMatches":plaintext.expose()==MODEL_KEY.as_bytes(),"needsMigration":migration,
            "wrongOwnerRejected":wrong_owner,"wrongServiceRejected":wrong_service,
            "wrongTenantRejected":wrong_tenant.open(&secret_id,SecretKind::Model,owner,service,&encrypted).is_err()});
    }
    transaction.rollback().await.map_err(|_| "observer_end")?;
    let array = |name: &str| -> Result<&Vec<Value>, String> {
        full.get(name)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("observer_relation_{name}"))
    };
    let model_creates: Vec<Value> = array("audit_events")?
        .iter()
        .filter(|value| {
            value["event_type"] == "configuration.changed"
                && value["target_type"] == "model_connection"
                && value["payload"]["change"] == "model_connection_created"
        })
        .cloned()
        .collect();
    let mut business = serde_json::Map::new();
    let mut audit = serde_json::Map::new();
    for (name, value) in full.as_object().ok_or("observer_snapshot_shape")? {
        if name.starts_with("audit_") {
            audit.insert(name.clone(), fingerprint(value)?);
        } else {
            business.insert(name.clone(), fingerprint(value)?);
        }
    }
    audit.insert("modelCreates".to_owned(), json!(model_creates));
    let model_updates: Vec<Value> = array("audit_events")?
        .iter()
        .filter(|value| {
            value["event_type"] == "configuration.changed"
                && value["target_type"] == "model_connection"
                && value["payload"]["change"] == "model_connection_updated"
        })
        .cloned()
        .collect();
    audit.insert("modelUpdates".to_owned(), json!(model_updates));
    let policy = array("action_policy")?
        .first()
        .cloned()
        .unwrap_or(Value::Null);
    let counts = json!({"modelConnections":array("model_connections")?.len(),"modelConnectionSecrets":array("model_connection_secrets")?.len(),
        "activeModelSecrets":array("model_connection_secrets")?.iter().filter(|value|value["retired_at"].is_null()).count(),
        "runs":array("runs")?.len(),"dispatch":array("outbox")?.iter().filter(|value|value["destination"]=="agent_run_dispatch").count(),
        "toolEffects":array("tool_calls")?.len()+array("tool_attempts")?.len()+array("remember_effect_receipts")?.len()
            +array("memories")?.len()+array("memory_events")?.len()
            +array("messages")?.iter().filter(|value|value["role"]=="tool").count(),"modelCreateAudits":model_creates.len(),"modelUpdateAudits":model_updates.len()});
    Ok(
        json!({"caseId":state.case_id,"boundModelId":current.model_id,"row":row,"currentSecret":secret,"vault":vault,
        "counts":counts,"business":business,"audit":audit,"session":session,"policy":policy,
        "counters":live_counters(state,Some(wire.counts())).await,"requests":state.requests.lock().await.clone(),
        "wireRequests":wire_requests(wire)?,"observer":{"backendPid":pid,"readOnly":true,"isolation":"read committed"},"directoryFault":state.directory.snapshot().await}),
    )
}

async fn bind_model(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let id = Uuid::parse_str(text(value, "modelId")?).map_err(|_| "model_id_invalid")?;
    let mut slot = state.case.lock().await;
    let current = slot.as_mut().ok_or("case_not_prepared")?;
    if current.model_id.is_some() {
        return Err("model_already_bound".to_owned());
    }
    let client = state.observer.get().await.map_err(|_| "bind_connection")?;
    let row:Value=client.query_one("SELECT to_jsonb(m) FROM public.model_connections m WHERE id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4 AND deleted_at IS NULL",
        &[&id,&DEPLOYMENT,&TENANT,&current.actor]).await.map_err(|_|"bind_original_model")?.get(0);
    current.model_id = Some(id);
    current.bound_revision = row["revision"].as_i64();
    current.bound_secret_id = row["current_secret_id"]
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok());
    current.bound_endpoint = row["endpoint"].as_str().map(str::to_owned);
    drop(slot);
    Ok(
        json!({"caseId":state.case_id,"modelId":id,"revision":row["revision"],"probe":probe(state,wire).await?}),
    )
}

async fn execute(state: &State, wire: &OwnedWire, value: &Value) -> Result<Value, String> {
    let command = text(value, "command")?;
    let extra: &[&str] = match command {
        "prepare" | "probe" | "arm_directory_fault" | "release_directory_fault" => &["caseId"],
        "bind_model" => &["caseId", "modelId"],
        "cancel_directory_fault" => &["caseId", "timeoutMs"],
        "shutdown" => &[],
        _ => return Err("protocol_unknown_command".to_owned()),
    };
    fields(value, extra)?;
    if command != "shutdown" && text(value, "caseId")? != state.case_id {
        return Err("protocol_case_mismatch".to_owned());
    }
    let outcome = async { match command {
        "prepare" => prepare(state, wire).await,
        "bind_model" => bind_model(state, wire, value).await,
        "probe" => probe(state, wire).await,
        "arm_directory_fault" => {
            let deadline = tokio::time::Instant::now() + PG_BUDGET;
            let current = case(state).await?;
            tokio::time::timeout_at(deadline, validate_fault_source(state, &current)).await
                .map_err(|_| "directory_source_deadline")??;
            state.directory.arm(state.case_id == SELECTED, deadline).await?;
            Ok(json!({"caseId":state.case_id,"directoryFault":state.directory.snapshot().await}))
        }
        "cancel_directory_fault" => {
            let millis = value["timeoutMs"].as_u64().filter(|n| *n>0 && *n<=4000)
                .ok_or("directory_cancel_timeout_invalid")?;
            state.directory.cancel(case(state).await?, Duration::from_millis(millis)).await?;
            Ok(json!({"caseId":state.case_id,"directoryFault":state.directory.snapshot().await}))
        }
        "release_directory_fault" => {
            if !state.directory.release(false).await {
                return Err("directory_release_incomplete".to_owned());
            }
            Ok(json!({"caseId":state.case_id,"directoryFault":state.directory.snapshot().await}))
        }
        "shutdown" => Ok(json!({"stopping":true})),
        _ => Err("protocol_unknown_command".to_owned()),
    }}.await;
    if let Err(code) = &outcome
        && [
            "arm_directory_fault",
            "cancel_directory_fault",
            "release_directory_fault",
        ]
        .contains(&command)
    {
        state.directory.fail(code).await;
        state
            .counters
            .collection_failed
            .store(true, Ordering::SeqCst);
    }
    outcome
}

pub(super) async fn run(config: pool::DatabaseConfig) -> Result<(), String> {
    let dist = std::env::var("C4_CLIENT_DIST").map_err(|_| "missing_owned_dist")?;
    let source = std::env::var("C4_SOURCE_HEAD").map_err(|_| "missing_source_head")?;
    let spec = std::env::var("C4_SPEC_SHA256").map_err(|_| "missing_spec_sha")?;
    let case_id = std::env::var("C4_CASE_ID").map_err(|_| "missing_case_id")?;
    if ![REFRESH, SELECTED].contains(&case_id.as_str())
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
    let mut observer_config = config.clone();
    observer_config.max_pool_size = 4;
    observer_config.application_name = Some("owned-model-directory-client-observer".to_owned());
    let observer_pool = pool::connect(&observer_config)
        .await
        .map_err(|_| "observer_pool")?;
    let mut client = application_pool
        .get()
        .await
        .map_err(|_| "migration_connection")?;
    fresh::apply(&mut client)
        .await
        .map_err(|_| "fresh_owned_migration")?;
    drop(client);
    // The immutable carrier has no allowed reply or business waveform in C4.
    // Any DNS, connection, HTTP request or child is a failure, even if that child joins.
    let wire = OwnedWire::new(Vec::new(), [TEST_CA, TEST_LEAF, TEST_KEY]).await;
    let counters = Arc::new(Counters::default());
    let tenant = TenantId::new(TENANT);
    let deployment = DeploymentId::new(DEPLOYMENT);
    let vault = CredentialRecordVault::single_key(
        tenant.clone(),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x81; 32]).map_err(|_| "owned_vault_key")?,
    );
    let directory = Arc::new(DirectoryController::new(
        observer_pool.clone(),
        case_id.clone(),
    ));
    let state = Arc::new(State {
        observer: observer_pool.clone(),
        vault: vault.clone(),
        counters: counters.clone(),
        case: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
        case_id: case_id.clone(),
        directory: directory.clone(),
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
        let budget=SafeHttpBudget::new(64*1024*1024,Duration::from_secs(6)).map_err(|_|"owned_http_budget")?;
        let remote:Arc<dyn RemoteAguiTransport>=Arc::new(CountingRemote{inner:Arc::new(SafeRemoteAguiTransport::new(wire.dialer(),budget,Some(Duration::from_secs(2)),SchemePolicy::HttpsOnly)
            .map_err(|_|"owned_actual_remote")?),counters:counters.clone()});
        // This actual adapter is a legal CreateAgent prerequisite. Its key remains only in memory.
        let managed_inner:Option<Arc<dyn ProviderAdapter>>=Some(Arc::new(OpenAiProvider::new(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/chat/completions",wire.origin())).map_err(|_|"owned_managed_endpoint")?,
            "owned-managed-model".to_owned(),OpenAiProtocol::ChatCompletions,budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_managed_config")?,OpenAiApiKey::from_bytes(MANAGED_KEY.as_bytes().to_vec()).map_err(|_|"owned_managed_key")?,wire.dialer())));
        let managed_slot_available=managed_inner.is_some();
        let managed=managed_inner.map(|inner|Arc::new(CountingProvider{inner,counters:counters.clone(),managed:true}) as Arc<dyn ProviderAdapter>);
        assembly=Some(assemble_postgres_application(PostgresApplicationAssemblyInput{
            pool:application_pool.clone(),listener_database:application_config.clone().into(),deployment:deployment.clone(),tenant:tenant.clone(),single_user:false,admin_floor:None,
            model:"unused-default-model".to_owned(),credential_key_id:"unused-default-model-key".to_owned(),credential_vault:vault.clone(),audit_key:SecretBytes::new(vec![0x82;32]),
            remote_assertions:assertions.clone(),mcp_oauth_state_key:SecretBytes::new(vec![0x84;32]),policy_store:policies,
            ui_preferences:Arc::new(PostgresUiPreferenceAdministration::new(application_pool.clone(),deployment.clone(),tenant.clone(),SecretBytes::new(vec![0x82;32])).map_err(|_|"owned_preferences")?),
            screen_sessions:Arc::new(openbot_application::NoScreenSessionAdministration),artifacts:None,
            runtime_capabilities:Some(auth.runtime_capability_factory(None).map_err(|_|"owned_actual_capability_factory")?),
            remote_agent_probe:remote.clone(),managed_slot_available,
            channel_routing_provider:ChannelRoutingProviderInput{endpoint:Url::parse(&format!("{}/v1/chat/completions",wire.origin())).map_err(|_|"owned_channel_endpoint")?,environment_api_key:None,egress_allow_cidrs:vec!["127.0.0.1/32".to_owned()],allow_http:false},
            stall_timeout:Some(Duration::from_secs(2)),oauth_public_url:None,app_url:None,
            extra_provider_adapters: Vec::new(),
            run_event_subscriber: None,
            delegation_authority: None,
        }).await.map_err(|_|"owned_production_assembly")?);
        let assembled=assembly.as_ref().ok_or("assembly_missing")?;
        let package_credentials=Arc::new(PostgresOpenAiCredentialSource::new(application_pool.clone(),vault.clone(),"unused-default-model-key".to_owned(),None).map_err(|_|"owned_default_source")?);
        let package:Arc<dyn ProviderAdapter>=Arc::new(CountingProvider{inner:Arc::new(OpenAiProvider::new_with_credential_source(OpenAiProviderConfig::new(
            Url::parse(&format!("{}/v1/responses",wire.origin())).map_err(|_|"owned_package_endpoint")?,"unused-default-model".to_owned(),OpenAiProtocol::Responses,budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_package_config")?,package_credentials,wire.dialer())),counters:counters.clone(),managed:false});
        let custom:Arc<dyn ProviderAdapter>=Arc::new(CountingCustom{inner:Arc::new(PostgresCustomModelProvider::new(application_pool.clone(),vault.clone(),deployment.clone(),tenant.clone(),wire.dialer(),budget,Some(Duration::from_secs(2)))
            .map_err(|_|"owned_actual_custom")?),counters:counters.clone()});
        let provider=Arc::new(RetryingProvider::new(Arc::new(ProviderRouter::new(package,managed).with_custom(custom)
            .with_remote_agui(Arc::new(RemoteAguiProvider::new(remote)))),RetryingProviderConfig::default()).map_err(|_|"owned_retry_provider")?);
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
        emit(&json!({"schemaVersion":1,"event":"ready","caseId":case_id,"origin":origin,"providerOrigin":wire.origin(),"dist":dist,
            "sourceHead":source,"specSha256":spec,"producer":"same-Pool SessionAuthResolver/CapabilityFactory/PostgresApplicationAssembly/ApplicationService/ServerBuilder.StaticApp/ActualCustom/Agent/RunRelay/OwnedRelationLock/FullOriginalQueryGuardedCancel/ZeroPlanOwnedTLS","caseEvidence":"none"}))?;
        let mut ids=BTreeSet::new();
        loop {
            let value=tokio::time::timeout(Duration::from_secs(90),input.recv()).await.map_err(|_|"protocol_idle_timeout")?.ok_or("protocol_unexpected_eof")??;
            let id=text(&value,"id")?.to_owned();
            if id.len()>64 || !id.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"._-".contains(&byte)) || !ids.insert(id.clone()) || ids.len()>4096{return Err("protocol_invalid_or_reused_id".to_owned());}
            let reply=execute(&state,&wire,&value).await;
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
    if let Some(stop) = stop_sender
        && stop.send(()).is_err()
    {
        close_errors.push("http_listener_stop_send");
    }
    // Release our own actual lock before joining the original server. Otherwise
    // an early browser failure could leave graceful shutdown waiting on the List.
    if !directory.release(true).await {
        close_errors.push("directory_controller_close");
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
    // Even business failure must run finish and await the genuine listener/child
    // ownership. C4 permits no wire activity, so no child shutdown claim is made.
    let wire_task = tokio::spawn(wire.finish());
    let (wire_outcome, wire_over_budget) = bounded_completion(wire_task, CLOSE_TIMEOUT).await;
    if wire_over_budget {
        close_errors.push("owned_zero_wire_finish_deadline");
    }
    let wire_record: Option<WireRecord> = match wire_outcome {
        Ok(record) => Some(record),
        Err(_) => {
            close_errors.push("owned_zero_wire_finish_join_error");
            None
        }
    };
    if let Some(record) = &wire_record {
        if record.counts.dns != 0
            || record.counts.tcp != 0
            || record.counts.http != 0
            || !record.requests.is_empty()
            || record.joined != 0
            || record.failed != 0
        {
            close_errors.push("owned_zero_wire_activity_or_child");
            counters.collection_failed.store(true, Ordering::SeqCst);
        }
        if record.requests.len() != record.counts.http {
            close_errors.push("owned_zero_wire_capture_incomplete");
        }
    } else {
        counters.collection_failed.store(true, Ordering::SeqCst);
    }
    let final_counters =
        live_counters(&state, wire_record.as_ref().map(|record| record.counts)).await;
    let directory_fault = directory.snapshot().await;
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
        "wireCounts":{"dns":wire_record.as_ref().map(|record|record.counts.dns),
            "tcp":wire_record.as_ref().map(|record|record.counts.tcp),"http":wire_record.as_ref().map(|record|record.counts.http)},
        "directoryFault":directory_fault,"stdinJoined":stdin_joined,"observerPoolCloseCalled":true,
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
