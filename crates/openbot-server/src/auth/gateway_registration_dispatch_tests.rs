//! New finite registration POST regression cases. All data and peers are owned synthetic fixtures.
use super::*;
use openbot_infra::db::pool::ConnectionObservation;
use openbot_infra::db::tables::gateway_authorization_attempts::Row;
use openbot_infra::gateway_transport::GatewayFailure as DispatchTransportFailure;
use openbot_infra::{
    GatewayAuthorizationCancellationToken as CancellationToken, GatewayAuthorizationJournal,
    GatewayAuthorizationJournalAck as DispatchAck, GatewayAuthorizationJournalRuntimeOwner,
    RegisteredAttemptOwner, RegistrationAdmissionReceipt, RegistrationDispatchError,
    RegistrationDispatchKind as DispatchKind,
};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use fixture::{
    ACTOR, COOKIE, DEP, Fixture, INSTALLATION, PgTerminalAckGate, REDIRECT, TENANT, TerminalStage,
    harness,
};

fn check(value: bool, message: &str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}
fn refused(
    result: Result<RegisteredAttemptOwner, RegistrationDispatchError>,
) -> Result<RegistrationDispatchError, String> {
    match result {
        Err(error) => Ok(error),
        Ok(_) => Err("registration unexpectedly returned a success owner".into()),
    }
}
fn kind(error: &RegistrationDispatchError, expected: DispatchKind) -> Result<(), String> {
    check(
        error.kind() == expected,
        &format!("closed dispatch kind expected {expected:?}, got {error:?}"),
    )
}
fn ack(
    error: &RegistrationDispatchError,
    send: DispatchAck,
    write: DispatchAck,
    read: DispatchAck,
) -> Result<(), String> {
    for (field, actual, expected) in [
        ("send_guard_rollback", error.send_guard_rollback_ack(), send),
        ("registered_write", error.registered_write_ack(), write),
        ("registered_readback", error.registered_readback_ack(), read),
    ] {
        check(
            actual == expected,
            &format!("original {field} must remain {expected:?}: {error:?}"),
        )?;
    }
    Ok(())
}
fn sent_facts(
    error: &RegistrationDispatchError,
    may_send: bool,
    status: Option<u16>,
    released: bool,
) -> Result<(), String> {
    let facts = error
        .transport_snapshot()
        .ok_or_else(|| "actual transport snapshot is absent".to_owned())?;
    check(
        facts.may_have_sent() == may_send,
        "actual transport entry fact",
    )?;
    check(
        facts.response_status() == status,
        "actual numeric response fact",
    )?;
    check(
        facts.permit_released() == released,
        "actual transport permit release fact",
    )
}
// These facts are minted by the original transport, separate from the journal ACKs.
fn body_facts(
    error: &RegistrationDispatchError,
    complete: bool,
    failure: Option<DispatchTransportFailure>,
) -> Result<(), String> {
    let facts = error
        .transport_snapshot()
        .ok_or_else(|| "actual transport snapshot is absent".to_owned())?;
    check(
        facts.complete() == complete,
        "actual transport EOF completion fact",
    )?;
    check(
        facts.failure() == failure,
        "actual transport failure history excludes unrelated body/network failure",
    )
}
async fn owned_response(f: &Fixture, configuration: &Value, full_body: bool) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if f.response_finished()? {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "owned response did not finish within its finite proof budget")??;
    let events = f.events()?;
    check(
        events
            .iter()
            .all(|v| v["event"] != "unexpected_handler_error"),
        "owned handler failure cannot earn rejection credit",
    )?;
    let raw = configuration
        .get("raw")
        .and_then(Value::as_str)
        .unwrap_or("{\"client_id\":\"owned-registration-client\"}");
    let headers = configuration
        .get("headers")
        .cloned()
        .unwrap_or_else(|| json!([["Content-Type", "application/json"]]));
    let sent: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "headers_sent" && v["method"] == "POST")
        .collect();
    check(
        sent.len() == 1,
        "one actual owned POST response header write",
    )?;
    check(
        sent[0]["status"] == 200
            && sent[0]["headers"] == headers
            && sent[0]["body_bytes"].as_u64() == Some(raw.len() as u64)
            && sent[0]["content_length"] == raw.len().to_string(),
        "actual owned response status/configured headers/declared exact body size",
    )?;
    let tail: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "response_finished" && v["method"] == "POST")
        .collect();
    check(tail.len() == 1, "one normal owned response completion")?;
    let bodies: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "body_sent" && v["method"] == "POST")
        .collect();
    let closed: Vec<_> = events
        .iter()
        .filter(|v| v["event"] == "peer_closed" && v["method"] == "POST")
        .collect();
    if tail[0]["outcome"] == "body_sent" {
        check(
            bodies.len() == 1 && closed.is_empty(),
            "owned body completed without peer close",
        )?;
        let hex: String = raw
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        check(
            bodies[0]["bytes"].as_u64() == Some(raw.len() as u64) && bodies[0]["body_hex"] == hex,
            "owned peer actually wrote and flushed all exact configured response bytes",
        )?;
    } else {
        check(
            !full_body
                && tail[0]["outcome"] == "peer_closed"
                && bodies.is_empty()
                && closed.len() == 1,
            "only causally allowed early peer close, never missing full-body/EOF proof",
        )?;
        check(
            matches!(
                closed[0]["kind"].as_str(),
                Some("BrokenPipeError" | "ConnectionResetError" | "SSLEOFError")
            ),
            "peer-close evidence has an explicitly allowed closed kind",
        )?;
    }
    Ok(())
}
async fn admit_on(
    f: &Fixture,
    journal: &Arc<GatewayAuthorizationJournal>,
    auth: &AuthContext,
    parent: CancellationToken,
    budget: Duration,
) -> Result<RegistrationAdmissionReceipt, String> {
    let metadata = f.metadata(parent.clone()).await?;
    let original = journal
        .create_attempt(
            auth,
            metadata,
            Zeroizing::new(REDIRECT.into()),
            parent,
            Instant::now() + budget,
        )
        .await
        .map_err(|e| e.to_string())?;
    journal
        .admit_registration(auth, original)
        .await
        .map_err(|e| e.to_string())
}
async fn admitted(f: &Fixture, auth: &AuthContext) -> Result<RegistrationAdmissionReceipt, String> {
    admit_on(
        f,
        &f.journal,
        auth,
        CancellationToken::new(),
        Duration::from_secs(60),
    )
    .await
}
async fn execute(f: &Fixture, sql: &str) -> Result<(), String> {
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    client.batch_execute(sql).await.map_err(|e| e.to_string())
}
fn wire(capture: &Value) -> Result<(), String> {
    check(
        capture["method"] == "POST" && capture["path"] == "/oauth/desktop/register",
        "actual registration POST target",
    )?;
    check(
        capture["authorization"] == Value::Null,
        "actual POST has no bearer",
    )?;
    let headers = capture["headers"]
        .as_array()
        .ok_or("actual wire headers missing")?;
    let mut types = 0;
    let mut accepts = 0;
    for header in headers {
        let name = header[0]
            .as_str()
            .ok_or("actual header name")?
            .to_ascii_lowercase();
        check(
            name != "authorization",
            "original SDK request carries no Authorization",
        )?;
        if name == "accept" {
            accepts += 1;
            check(
                header[1] == "application/json",
                "unchanged SafeHttp JSON framing Accept",
            )?;
        }
        if name == "content-type" {
            types += 1;
            check(header[1] == "application/json", "original JSON header")?;
        }
        check(
            [
                "content-type",
                "accept",
                "content-length",
                "host",
                "connection",
            ]
            .contains(&name.as_str()),
            "wire only carries original SDK header and required SafeHttp JSON framing",
        )?;
    }
    check(
        types == 1 && accepts == 1,
        "one actual Content-Type and one original SafeHttp Accept",
    )?;
    let raw = capture["body"].as_str().ok_or("actual body missing")?;
    let body: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    check(
        body == json!({"client_name":"Wrok Bot","redirect_uris":[REDIRECT],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}),
        "original SDK registration body exact grammar",
    )
}
fn registered(old: &Row, next: &Row, f: &Fixture, actor: &str) -> Result<(), String> {
    let mut expected = old.clone();
    expected.phase = "registered".into();
    expected.client_id = Some("owned-registration-client".into());
    expected.enrollment_id = next.enrollment_id;
    expected.updated_at = next.updated_at;
    check(
        next == &expected,
        "registered successor changes exactly four of original twenty columns",
    )?;
    check(
        next.enrollment_id
            .is_some_and(|id| id.get_version_num() == 7),
        "one actual private v7 reservation",
    )?;
    check(
        next.deployment_id == DEP
            && next.tenant_id == TENANT
            && next.owner_user_id == actor
            && next.auth_generation == 7,
        "current actual scope/actor",
    )?;
    check(
        next.installation_id == INSTALLATION
            && next.runtime_epoch.len() == 64
            && next.issuer == f.issuer()
            && next.redirect_uri == REDIRECT,
        "original runtime/issuer/redirect",
    )?;
    check(
        next.updated_at >= old.updated_at
            && next.updated_at < next.expires_at
            && next.updated_at.nanosecond() % 1000 == 0,
        "original-clock PG microsecond floor",
    )?;
    check(
        next.registration_admitted_at == old.registration_admitted_at
            && next.code_admitted_at.is_none()
            && next.finished_at.is_none()
            && next.outcome_code.is_none(),
        "admission timestamp and NULL history preserved",
    )
}
async fn registered_audit(f: &Fixture, id: uuid::Uuid) -> Result<(), String> {
    let audits = f.audits().await?;
    check(
        audits.len() == 3,
        "exact created/admitted/registered typed events",
    )?;
    check(
        audits[2]
            == json!({"journal_schema":1,"attempt_id":id.to_string(),"phase":"registered","outcome_code":null}),
        "exact registered four typed facts",
    )?;
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    let labels:Vec<String>=client.query("SELECT event_type FROM public.audit_events WHERE event_type LIKE 'gateway_authorization_%' ORDER BY created_at,id",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect();
    check(
        labels
            == [
                "gateway_authorization_attempt_created",
                "gateway_authorization_registration_admitted",
                "gateway_authorization_registered",
            ],
        "exact current typed label order",
    )
}
async fn no_second_post(f: &Fixture, count: usize) -> Result<(), String> {
    check(
        f.posts()?.len() == count,
        "one actual POST per consumed original owner; no resend",
    )
}
async fn retired(f: &Fixture, original: &ConnectionObservation, pid: i32) -> Result<(), String> {
    original
        .wait_for_destruction_before(Instant::now() + Duration::from_secs(5))
        .await
        .map_err(|e| e.to_string())?;
    let observed = original.snapshot();
    check(
        observed.retirement_requested && observed.connection_destroyed,
        "actual original guarded connection retired/destroyed",
    )?;
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    let next: i32 = client
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    check(next != pid, "original uncertain backend not recycled")?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let absent: bool = client
            .query_one(
                "SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                &[&pid],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        if absent {
            break;
        }
        if Instant::now() >= until {
            return Err("original backend still present".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    eprintln!(
        "GATEWAY_REGISTRATION_ORIGINAL_BACKEND backend_pid={pid} retired=true destroyed=true absent_observed=true individual_production_driver_join=UNPROVEN"
    );
    Ok(())
}

mod fixture {
    //! New owned registration POST/TLS/PG fixture; setup discovery GET is counted separately.
    use super::super::*;
    use super::{GatewayAuthorizationJournal, GatewayAuthorizationJournalRuntimeOwner};
    use openbot_domain::vault::SecretBytes;
    use openbot_infra::GatewayAuthorizationCancellationToken as CancellationToken;
    use openbot_infra::db::tables::gateway_authorization_attempts::Row as AttemptRow;
    use openbot_infra::db::{
        fresh,
        pool::{self, DatabaseConfig},
    };
    use openbot_infra::gateway_account::{GatewayAccountClient, GatewayDesktopMetadata};
    use openbot_infra::gateway_transport::*;
    use openbot_infra::net::safe_http::{
        CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
    };
    use serde_json::Value;
    use std::{
        io::{BufRead as _, Read as _, Write as _},
        net::SocketAddr,
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, oneshot},
        task::{JoinHandle, JoinSet},
    };

    pub(super) mod harness {
        use std::future::Future;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/postgres_harness.rs"
        ));
    }
    pub(super) const DEP: &str = "owned-journal-deployment";
    pub(super) const TENANT: &str = "owned-journal-tenant";
    pub(super) const ACTOR: &str = "owned-journal-owner";
    pub(super) const COOKIE: &str = "owned-journal-cookie-00000000000001";
    pub(super) const NEXT_COOKIE: &str = "owned-journal-cookie-00000000000002";
    pub(super) const INSTALLATION: &str =
        "2828282828282828282828282828282828282828282828282828282828282828";
    pub(super) const REDIRECT: &str = "http://127.0.0.1:48281/callback";
    const SESSION_KEY: &[u8] = b"owned-journal-session-hash-key";

    pub(super) struct Fixture {
        pub(super) config: DatabaseConfig,
        pub(super) pool: pool::DatabasePool,
        pub(super) runtime: Option<Arc<GatewayAuthorizationJournalRuntimeOwner>>,
        pub(super) journal: Arc<GatewayAuthorizationJournal>,
        pub(super) resolver: Arc<PostgresSessionAuthResolver>,
        tls: Option<OwnedTls>,
    }
    impl Fixture {
        pub(super) async fn new(config: DatabaseConfig, size: usize) -> Result<Self, String> {
            let config = config.with_max_pool_size(size);
            let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            fresh::apply(&mut client).await.map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('owned-journal-owner','journal@example.test',7),('owned-journal-other','other@example.test',7),('dev-local-user','dev@openbot.local',7); INSERT INTO public.user_roles(user_id,role) VALUES('owned-journal-owner','user'),('owned-journal-other','user'),('dev-local-user','admin');").await.map_err(|e|e.to_string())?;
            let now = OffsetDateTime::now_utc();
            for (id, cookie) in [
                ("owned-journal-session", COOKIE),
                ("owned-journal-next-session", NEXT_COOKIE),
            ] {
                let hash = SessionTokenHash::compute(
                    SessionToken::new(cookie.as_bytes()),
                    SessionHashKey::new(SESSION_KEY),
                )
                .to_column_value();
                client.execute("INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) VALUES($1,$2,$3,$4,$5,$5,7)",&[&id,&ACTOR,&hash,&(now+time::Duration::hours(1)),&(now-time::Duration::minutes(1))]).await.map_err(|e|e.to_string())?;
            }
            drop(client);
            let env = crate::config::EnvMap::from([(
                "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
                INSTALLATION.to_owned(),
            )]);
            let config_value =
                crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
            let (runtime, journal) = assemble_gateway_authorization_journal(
                &config_value,
                pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(vec![0x28; 32]),
            )
            .map_err(|e| e.to_string())?
            .ok_or("configured journal missing")?;
            let resolver = Arc::new(
                PostgresSessionAuthResolver::new(
                    pool.clone(),
                    SESSION_KEY,
                    openbot_infra::auth::config::default_session_lifetime(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )
                .map_err(|e| e.to_string())?,
            );
            resolver
                .install_gateway_authorization_journal(&journal)
                .map_err(|e| format!("{e:?}"))?;
            Ok(Self {
                config,
                pool,
                runtime: Some(runtime),
                journal,
                resolver,
                tls: Some(OwnedTls::new("journal")?),
            })
        }
        pub(super) async fn auth(&self) -> Result<AuthContext, String> {
            self.auth_cookie(COOKIE).await
        }
        pub(super) async fn auth_cookie(&self, cookie: &str) -> Result<AuthContext, String> {
            self.resolver
                .resolve(
                    &http::Request::builder()
                        .uri("/owned-journal")
                        .header("cookie", format!("openbot_session={cookie}"))
                        .body(())
                        .map_err(|e| e.to_string())?
                        .into_parts()
                        .0,
                )
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn fresh_pair(
            &self,
        ) -> Result<
            (
                Arc<GatewayAuthorizationJournalRuntimeOwner>,
                Arc<GatewayAuthorizationJournal>,
            ),
            String,
        > {
            fresh_pair(
                self.pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
        }
        pub(super) async fn single(
            &self,
            journal: &Arc<GatewayAuthorizationJournal>,
        ) -> Result<SingleUserAuthResolver, String> {
            let principal = openbot_infra::auth::single_user::load_single_user_principal(
                &self.pool,
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
            )
            .await
            .map_err(|e| e.to_string())?;
            let resolver = SingleUserAuthResolver::from_verified_principal(
                principal,
                openbot_infra::auth::config::default_session_lifetime(),
            );
            resolver
                .install_gateway_authorization_journal(journal, &self.pool)
                .map_err(|e| format!("{e:?}"))?;
            Ok(resolver)
        }
        pub(super) fn factory(
            &self,
            registration: Option<&str>,
        ) -> Result<GatewayTransportFactory, String> {
            let tls = self.tls.as_ref().ok_or("owned TLS closed")?;
            let origin = tls.endpoint();
            let oauth = registration
                .map(|path| {
                    GatewayOAuthEndpoints::new(
                        GatewayOAuthProfile::Desktop,
                        &format!("{origin}{path}"),
                        &format!("{origin}/oauth/desktop/token"),
                        Some(&format!("{origin}/oauth/desktop/revoke")),
                    )
                })
                .transpose()
                .map_err(|e| e.to_string())?;
            Ok(GatewayTransportFactory::new(
                tls.dialer()?,
                VerifiedGatewayEndpoints::new(&origin, None, oauth).map_err(|e| e.to_string())?,
                GatewayTransportLimits::new(Duration::from_secs(10), 65536)
                    .map_err(|e| e.to_string())?,
            ))
        }
        pub(super) fn configure(&self, value: &Value) -> Result<(), String> {
            let tls = self.tls.as_ref().ok_or("owned TLS absent")?;
            let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
            if bytes.len() > 131072 {
                return Err("owned TLS settings exceeded budget".into());
            }
            let temp = tls.root.join("settings.tmp");
            std::fs::write(&temp, bytes).map_err(|e| e.to_string())?;
            std::fs::rename(temp, tls.root.join("settings.json")).map_err(|e| e.to_string())
        }
        pub(super) fn release_headers(&self) -> Result<(), String> {
            std::fs::write(
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .root
                    .join("release_headers"),
                b"owned",
            )
            .map_err(|e| e.to_string())
        }
        pub(super) fn release_body(&self) -> Result<(), String> {
            std::fs::write(
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .root
                    .join("release_body"),
                b"owned",
            )
            .map_err(|e| e.to_string())
        }
        fn records(&self, file: &str) -> Result<Vec<Value>, String> {
            let path = self.tls.as_ref().ok_or("owned TLS absent")?.root.join(file);
            if !path.exists() {
                return Ok(Vec::new());
            }
            if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1048576 {
                return Err("owned peer records exceeded budget".into());
            }
            let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let values = text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<Vec<Value>, _>>()
                .map_err(|e| e.to_string())?;
            if values.len() > 256 {
                return Err("owned peer record count exceeded budget".into());
            }
            Ok(values)
        }
        pub(super) fn response_finished(&self) -> Result<bool, String> {
            let root = &self.tls.as_ref().ok_or("owned TLS absent")?.root;
            if root.join("unexpected-handler-error").exists() {
                return Err("owned handler failed before response proof".into());
            }
            // Published only after complete event writes, so a partial JSON append cannot pass.
            Ok(root.join("response-finished").exists())
        }
        pub(super) fn events(&self) -> Result<Vec<Value>, String> {
            self.records("events.jsonl")
        }
        pub(super) fn posts(&self) -> Result<Vec<Value>, String> {
            Ok(self
                .captures()?
                .into_iter()
                .filter(|v| v["method"] == "POST")
                .collect())
        }
        pub(super) fn network_point(&self) -> Result<(usize, usize, usize), String> {
            Ok((
                self.tls
                    .as_ref()
                    .ok_or("owned TLS absent")?
                    .dns_count
                    .load(Ordering::SeqCst),
                self.records("connections.jsonl")?.len(),
                self.posts()?.len(),
            ))
        }
        pub(super) async fn wait_posts(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if self.posts().unwrap().len() >= count {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("owned POST was not observed");
        }
        pub(super) async fn metadata(
            &self,
            parent: CancellationToken,
        ) -> Result<GatewayDesktopMetadata, String> {
            let factory = self.factory(Some("/oauth/desktop/register"))?;
            let transport = factory
                .for_operation(
                    Arc::new(DiscoveryOnly),
                    Arc::new(DiscoveryObserved),
                    tokio::time::Instant::now() + Duration::from_secs(15),
                    Duration::from_secs(2),
                )
                .map_err(|e| e.to_string())?;
            let origin = self.issuer();
            let client =
                GatewayAccountClient::new(&origin, transport).map_err(|e| e.to_string())?;
            client
                .fetch_metadata(parent)
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn issuer(&self) -> String {
            self.tls.as_ref().unwrap().endpoint()
        }
        pub(super) async fn rows(&self) -> Result<Vec<AttemptRow>, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            client.query("SELECT * FROM openbot_internal.gateway_authorization_attempts ORDER BY created_at,attempt_id",&[]).await.map_err(|e|e.to_string())?.iter().map(|row|AttemptRow::try_from(row).map_err(|e|e.to_string())).collect()
        }
        pub(super) async fn row(&self, id: uuid::Uuid) -> Result<AttemptRow, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            let row = client
            .query_one(
                "SELECT * FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1",
                &[&id],
            )
            .await
            .map_err(|e| e.to_string())?;
            AttemptRow::try_from(&row).map_err(|e| e.to_string())
        }
        pub(super) async fn audits(&self) -> Result<Vec<Value>, String> {
            let client = self.pool.get().await.map_err(|e| e.to_string())?;
            Ok(client.query("SELECT payload FROM public.audit_events WHERE event_type LIKE 'gateway_authorization_%' ORDER BY created_at,id",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect())
        }
        pub(super) async fn direct(&self) -> Result<pool::DatabasePool, String> {
            pool::connect(&self.config.clone().with_max_pool_size(2))
                .await
                .map_err(|e| e.to_string())
        }
        pub(super) fn disarm_host(&self) {
            self.resolver.close_request_bindings();
        }
        pub(super) fn captures(&self) -> Result<Vec<Value>, String> {
            self.tls.as_ref().ok_or("owned TLS absent")?.captures()
        }
        pub(super) async fn finish(mut self) -> Result<(), String> {
            self.resolver.close_request_bindings();
            if let Some(runtime) = self.runtime.take() {
                runtime.close();
            }
            let tls = self.tls.take().ok_or("owned TLS absent")?;
            let captures = tls.captures()?;
            if captures.iter().any(|x| {
                !matches!(x["method"].as_str(), Some("GET" | "POST"))
                    || x["authorization"] != Value::Null
                    || (x["method"] == "POST" && x["path"] != "/oauth/desktop/register")
            }) {
                return Err("unexpected journal TLS dispatch".into());
            }
            let closed = tls.finish();
            self.pool.close();
            eprintln!(
                "GATEWAY_REGISTRATION_FIXTURE setup_discovery_gets={} registration_posts={} token_posts=0 pool_closed={} individual_production_driver_join=UNPROVEN",
                captures.iter().filter(|v| v["method"] == "GET").count(),
                captures.iter().filter(|v| v["method"] == "POST").count(),
                self.pool.is_closed()
            );
            closed
        }
    }
    pub(super) fn fresh_pair(
        pool: pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<
        (
            Arc<GatewayAuthorizationJournalRuntimeOwner>,
            Arc<GatewayAuthorizationJournal>,
        ),
        String,
    > {
        let env = crate::config::EnvMap::from([(
            "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID".to_owned(),
            INSTALLATION.to_owned(),
        )]);
        let config = crate::config::ServerConfig::from_env_map(&env).map_err(|e| e.to_string())?;
        assemble_gateway_authorization_journal(
            &config,
            pool,
            deployment,
            tenant,
            SecretBytes::new(vec![0x28; 32]),
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "configured journal missing".to_owned())
    }
    pub(super) fn session_resolver(
        pool: pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
    ) -> Result<Arc<PostgresSessionAuthResolver>, String> {
        Ok(Arc::new(
            PostgresSessionAuthResolver::new(
                pool,
                SESSION_KEY,
                openbot_infra::auth::config::default_session_lifetime(),
                deployment,
                tenant,
            )
            .map_err(|e| e.to_string())?,
        ))
    }
    struct DiscoveryOnly;
    struct DiscoveryPermit;
    struct DiscoveryObserved;
    #[async_trait::async_trait]
    impl GatewayHttpAuthority for DiscoveryOnly {
        async fn before_request(
            &self,
            request: GatewayRequestDescriptor,
            cancel: CancellationToken,
        ) -> Result<Box<dyn GatewayHttpPermit>, GatewayFenceError> {
            if request.kind() != GatewayRequestKind::OAuthDiscovery || cancel.is_cancelled() {
                return Err(GatewayFenceError::Refused);
            }
            Ok(Box::new(DiscoveryPermit))
        }
    }
    #[async_trait::async_trait]
    impl GatewayHttpPermit for DiscoveryPermit {
        async fn release_after_headers(self: Box<Self>) -> Result<(), GatewayFenceError> {
            Ok(())
        }
    }
    impl GatewayHttpOutcomes for DiscoveryObserved {
        fn started(&self, _: GatewayAttempt) {}
    }

    // The Python interpreter is an explicit Root-frozen test input. It only owns this fixture's
    // random temporary directory, listener and child process; it never changes system trust.
    struct OwnedTls {
        root: PathBuf,
        child: Option<Child>,
        address: SocketAddr,
        ca: Vec<u8>,
        stdout_reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
        root_removed: bool,
        dns_count: Arc<AtomicUsize>,
    }

    impl OwnedTls {
        fn new(label: &str) -> Result<Self, String> {
            let interpreter = PathBuf::from(
                std::env::var_os("OPENBOT_TEST_TLS_PYTHON")
                    .ok_or("Root-pinned Python TLS interpreter missing")?,
            );
            if !interpreter.is_absolute() {
                return Err("TLS interpreter must be an absolute pinned input".to_owned());
            }
            let root = std::env::temp_dir().join(format!(
                "openbot-registration-owned-tls-{label}-{}",
                uuid::Uuid::now_v7()
            ));
            std::fs::create_dir(&root).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| e.to_string())?;
            }
            let child = Command::new(interpreter)
                .args(["-I", "-u", "-c", PYTHON_TLS])
                .arg(&root)
                .args([TEST_CA, TEST_LEAF, TEST_KEY])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| e.to_string())?;
            let mut fixture = Self {
                root,
                child: Some(child),
                address: "127.0.0.1:0".parse().unwrap(),
                ca: Vec::new(),
                stdout_reader: None,
                root_removed: false,
                dns_count: Arc::new(AtomicUsize::new(0)),
            };
            let stdout = fixture
                .child
                .as_mut()
                .unwrap()
                .stdout
                .take()
                .ok_or("owned TLS stdout missing")?;
            let (ready_send, ready_receive) = std::sync::mpsc::sync_channel(1);
            fixture.stdout_reader = Some(std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stdout);
                let mut line = String::new();
                let bytes = reader
                    .by_ref()
                    .take(8193)
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?;
                if bytes == 0 || bytes > 8192 {
                    return Err("owned TLS startup output missing or unbounded".to_owned());
                }
                ready_send.send(line).map_err(|e| e.to_string())?;
                let mut tail = Vec::new();
                reader
                    .take(65537)
                    .read_to_end(&mut tail)
                    .map_err(|e| e.to_string())?;
                if tail.len() > 65536 {
                    return Err("owned TLS stdout tail exceeded budget".to_owned());
                }
                Ok(tail)
            }));
            let line = ready_receive
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| format!("owned TLS startup not acknowledged: {e}"))?;
            let ready: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            let port = ready["port"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("owned TLS port invalid")?;
            if port == 0 || [39025, 39027].contains(&port) {
                return Err("owned TLS port is outside fixture policy".to_owned());
            }
            fixture.address = SocketAddr::from(([127, 0, 0, 1], port));
            fixture.ca = serde_json::from_value(ready["ca"].clone()).map_err(|e| e.to_string())?;
            eprintln!(
                "GATEWAY_REGISTRATION_OWNED_TLS_START original_child_pid={} owned_root={} loopback_port={port}",
                fixture.child.as_ref().unwrap().id(),
                fixture.root.display()
            );
            Ok(fixture)
        }
        fn endpoint(&self) -> String {
            format!("https://idp.test:{}", self.address.port())
        }
        fn dialer(&self) -> Result<SafeDialer, String> {
            SafeDialer::with_extra_roots(
                EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"]).map_err(|e| e.to_string())?,
                ),
                Arc::new(OwnedDns {
                    address: self.address,
                    count: self.dns_count.clone(),
                }),
                [self.ca.clone().into()],
            )
            .map_err(|e| e.to_string())
        }
        fn release(&self) -> Result<(), String> {
            std::fs::write(self.root.join("release_headers"), b"owned")
                .map_err(|e| e.to_string())?;
            std::fs::write(self.root.join("release_body"), b"owned").map_err(|e| e.to_string())
        }
        fn captures(&self) -> Result<Vec<Value>, String> {
            let path = self.root.join("captures.jsonl");
            if !path.exists() {
                return Ok(Vec::new());
            }
            if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
                return Err("owned TLS captures exceeded budget".to_owned());
            }
            let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let captures: Vec<Value> = contents
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            if captures.len() > 64 {
                return Err("owned TLS capture count exceeded budget".to_owned());
            }
            Ok(captures)
        }
        fn finish(mut self) -> Result<(), String> {
            self.release()?;
            let child = self.child.as_mut().ok_or("owned TLS child absent")?;
            child
                .stdin
                .as_mut()
                .ok_or("owned TLS stop channel absent")?
                .write_all(b"x")
                .map_err(|e| e.to_string())?;
            drop(child.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    if !status.success() {
                        return Err("owned TLS child did not exit naturally with zero".to_owned());
                    }
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("owned TLS child did not acknowledge stop".to_owned());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid = child.id();
            drop(self.child.take());
            let tail = self
                .stdout_reader
                .take()
                .ok_or("owned TLS stdout reader absent")?
                .join()
                .map_err(|_| "owned TLS stdout reader panicked")??;
            let stopped: Value = serde_json::from_slice(&tail).map_err(|e| e.to_string())?;
            if stopped["stopped"] != true || stopped["fatal"] != false {
                return Err("owned TLS stop output missing".to_owned());
            }
            let count = self.captures()?.len();
            std::fs::remove_dir_all(&self.root).map_err(|e| e.to_string())?;
            if self.root.exists() {
                return Err("owned TLS root survived cleanup".to_owned());
            }
            self.root_removed = true;
            eprintln!(
                "GATEWAY_REGISTRATION_OWNED_TLS original_child_pid={pid} child_wait_zero=true listener_closed=true stdout_reader_joined=true captured_requests={count} owned_root={} root_removed=true root_absent=true",
                self.root.display()
            );
            Ok(())
        }
    }
    impl Drop for OwnedTls {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!(
                    "GATEWAY_REGISTRATION_OWNED_TLS fallback_kill=true natural_stop_unproven=true"
                );
            }
            if let Some(reader) = self.stdout_reader.take() {
                let _ = reader.join();
            }
            if !self.root_removed {
                eprintln!(
                    "GATEWAY_REGISTRATION_OWNED_TLS retained_unproven_cleanup=true owned_root={}",
                    self.root.display()
                );
            }
        }
    }
    struct OwnedDns {
        address: SocketAddr,
        count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl DnsResolver for OwnedDns {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if host == "idp.test" && port == self.address.port() {
                Ok(vec![self.address])
            } else {
                Err(DnsUnavailable)
            }
        }
    }

    const PYTHON_TLS: &str = r#"
import base64,http.server,json,os,pathlib,ssl,sys,threading,time
root=pathlib.Path(sys.argv[1]); os.umask(0o077)
ca,leaf,key=[base64.b64decode(x,validate=True) for x in sys.argv[2:5]]
def pem(kind,data): return ('-----BEGIN '+kind+'-----\n'+base64.encodebytes(data).decode()+'-----END '+kind+'-----\n')
(root/'leaf.pem').write_text(pem('CERTIFICATE',leaf)); (root/'key.pem').write_text(pem('PRIVATE KEY',key))
stop=threading.Event(); fatal=threading.Event(); count=0; connections=0
def record(file,data):
    path=root/file
    if path.exists() and path.stat().st_size>1048576: raise RuntimeError('owned capture byte budget')
    with path.open('a') as f: f.write(json.dumps(data,separators=(',',':'))+'\n'); f.flush()
def stopping(): sys.stdin.buffer.read(1); stop.set()
thread=threading.Thread(target=stopping); thread.start()
def wait_owned(name):
    deadline=time.monotonic()+6
    while not (root/name).exists() and not stop.is_set():
        if time.monotonic()>=deadline: raise RuntimeError('owned release deadline')
        time.sleep(.005)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def capture(self,body):
        global count
        if count>=64: raise RuntimeError('owned request count budget')
        count+=1
        record('captures.jsonl',{'method':self.command,'path':self.path,'authorization':self.headers.get('Authorization'),'headers':list(self.headers.raw_items()),'body':body.decode('utf8')})
    def send_owned(self,status,headers,data):
        self.send_response(status)
        for name,value in headers: self.send_header(name,value)
        self.send_header('Content-Length',str(len(data))); self.send_header('Connection','close'); self.end_headers(); self.wfile.flush()
        record('events.jsonl',{'event':'headers_sent','method':self.command,'status':status,'headers':headers,'body_bytes':len(data),'content_length':str(len(data))})
        return data
    def do_GET(self):
        self.connection.settimeout(6)
        if self.path!='/.well-known/oauth-authorization-server/desktop': raise RuntimeError('owned discovery path')
        if self.headers.get('Authorization') is not None: raise RuntimeError('owned discovery carried bearer')
        origin='https://idp.test:'+str(self.server.server_port)
        data=json.dumps({'issuer':origin,'authorization_endpoint':origin+'/oauth/desktop/authorize','token_endpoint':origin+'/oauth/desktop/token','registration_endpoint':origin+'/oauth/desktop/register','revocation_endpoint':origin+'/oauth/desktop/revoke','scopes_supported':['ai','account'],'response_types_supported':['code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],'grant_types_supported':['authorization_code','refresh_token'],'crabcode_auth_contract_version':2,'gateway_error_contract_version':1},separators=(',',':')).encode()
        self.capture(b''); self.send_owned(200,[['Content-Type','application/json']],data); self.wfile.write(data); self.wfile.flush(); self.close_connection=True
    def do_POST(self):
        self.connection.settimeout(6)
        if self.path!='/oauth/desktop/register': raise RuntimeError('owned POST path denies tokens/other endpoints')
        length=int(self.headers.get('Content-Length','-1'))
        if not 0<=length<=65536: raise RuntimeError('owned request byte bound')
        body=self.rfile.read(length)
        if len(body)!=length: raise RuntimeError('owned request EOF')
        self.capture(body)
        settings=root/'settings.json'
        if settings.exists() and settings.stat().st_size>131072: raise RuntimeError('owned settings bound')
        config=json.loads(settings.read_text()) if settings.exists() else {}
        if config.get('close_before_headers'): self.close_connection=True; return
        if config.get('hold_headers'): wait_owned('release_headers')
        if stop.is_set(): self.close_connection=True; return
        data=config.get('raw','{"client_id":"owned-registration-client"}').encode('utf8')
        if len(data)>131072: raise RuntimeError('owned response byte bound')
        headers=config.get('headers',[['Content-Type','application/json']])
        if len(headers)>128 or any(len(n)+len(v)>16384 for n,v in headers): raise RuntimeError('owned header budget')
        outcome='stopped'
        try:
            self.send_owned(config.get('status',200),headers,data)
            if config.get('hold_body'): wait_owned('release_body')
            if not stop.is_set():
                self.wfile.write(data); self.wfile.flush(); record('events.jsonl',{'event':'body_sent','method':'POST','bytes':len(data),'body_hex':data.hex()}); outcome='body_sent'
        except (BrokenPipeError,ConnectionResetError,ssl.SSLEOFError) as closed:
            record('events.jsonl',{'event':'peer_closed','method':'POST','kind':type(closed).__name__}); outcome='peer_closed'
        self.close_connection=True
        record('events.jsonl',{'event':'response_finished','method':'POST','outcome':outcome})
        (root/'response-finished').write_bytes(b'owned')
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(root/'leaf.pem',root/'key.pem')
class Server(http.server.HTTPServer):
    def handle_error(self,request,client_address):
        # BaseServer must not swallow an unexpected owned handler failure into exit zero.
        fatal.set(); stop.set()
        (root/'unexpected-handler-error').write_bytes(b'UnexpectedHandler')
        record('events.jsonl',{'event':'unexpected_handler_error','failure':'UnexpectedHandler'})
    def get_request(self):
        global connections
        raw,address=self.socket.accept(); raw.settimeout(3); connections+=1
        if connections>64: raw.close(); raise RuntimeError('owned socket count budget')
        record('connections.jsonl',{'accepted':connections})
        try: return context.wrap_socket(raw,server_side=True),address
        except BaseException: raw.close(); raise
server=Server(('127.0.0.1',0),Handler); server.timeout=.2
print(json.dumps({'port':server.server_port,'ca':list(ca)}),flush=True)
try:
    while not stop.is_set(): server.handle_request()
finally: server.server_close(); stop.set(); thread.join(timeout=2)
print(json.dumps({'stopped':not fatal.is_set(),'fatal':fatal.is_set(),'requests':count,'connections':connections}),flush=True)
if thread.is_alive(): raise RuntimeError('owned stop reader did not join')
if fatal.is_set(): raise RuntimeError('owned handler failed')
"#;

    // Existing repository non-production W7 CA/leaf/key, SAN=idp.test. Never installed in OS trust.
    const TEST_CA: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
    const TEST_LEAF: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
    const TEST_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";

    // Select only the original journal transaction on its real backend, never a v2 classifier.
    #[derive(Clone, Copy, Debug)]
    pub(super) enum TerminalStage {
        SendGuardRollback,
        RegisteredCommit,
        RegisteredReadbackRollback,
    }
    impl TerminalStage {
        fn command(self) -> &'static [u8] {
            if matches!(self, Self::RegisteredCommit) {
                b"COMMIT\0"
            } else {
                b"ROLLBACK\0"
            }
        }
        fn sql_bits(self, sql: &[u8]) -> u8 {
            let Ok(sql) = std::str::from_utf8(sql) else {
                return 0;
            };
            let canonical = sql
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase();
            let (marker, body) = if let Some(comment) = canonical.strip_prefix("/* ") {
                let Some((marker, body)) = comment.split_once(" */") else {
                    return 0;
                };
                (Some(marker), body.trim_start())
            } else {
                (None, canonical.as_str())
            };
            let assignments = body.split(" where ").next().unwrap_or(body);
            let journal = match self {
                Self::SendGuardRollback => {
                    marker == Some("gateway_authorization_attempt_lock")
                        && body.starts_with("select ")
                        && body.contains("from openbot_internal.gateway_authorization_attempts")
                        && body.contains("for update")
                }
                Self::RegisteredCommit => {
                    marker == Some("gateway_authorization_registered")
                        && assignments
                            .starts_with("update openbot_internal.gateway_authorization_attempts")
                        && assignments.contains("client_id")
                        && assignments.contains("enrollment_id")
                }
                Self::RegisteredReadbackRollback => {
                    marker == Some("gateway_authorization_exact_readback")
                        && body.starts_with("select ")
                        && body.contains("from openbot_internal.gateway_authorization_attempts")
                        && !body.contains("for update")
                }
            };
            let audit = body.starts_with("insert into public.audit_events");
            u8::from(journal) | (u8::from(audit) << 1)
        }
        fn complete_bits(self) -> u8 {
            if matches!(self, Self::RegisteredCommit) {
                3
            } else {
                1
            }
        }
    }

    struct TerminalGateState {
        stage: TerminalStage,
        discard: bool,
        armed: std::sync::atomic::AtomicBool,
        claimed: std::sync::atomic::AtomicBool,
        original_backend_pid: AtomicUsize,
        selected_backend_pid: AtomicUsize,
        stage_seen: AtomicUsize,
        begins: AtomicUsize,
        all_begins_after_arm: AtomicUsize,
        commits: AtomicUsize,
        rollbacks: AtomicUsize,
        command_acks: AtomicUsize,
        ready_acks: AtomicUsize,
        forwarded_acks: AtomicUsize,
        accepted: AtomicUsize,
        joined: AtomicUsize,
        held: Semaphore,
        release: Semaphore,
        forwarded: Semaphore,
    }
    pub(super) struct PgTerminalAckGate {
        pub(super) config: DatabaseConfig,
        state: Arc<TerminalGateState>,
        stop: Option<oneshot::Sender<()>>,
        task: Option<JoinHandle<Result<(), String>>>,
    }
    impl PgTerminalAckGate {
        pub(super) async fn new(
            config: &DatabaseConfig,
            stage: TerminalStage,
            discard: bool,
        ) -> Self {
            assert_eq!(config.host, "127.0.0.1");
            let upstream = SocketAddr::from(([127, 0, 0, 1], config.port));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut routed = config.clone();
            routed.port = listener.local_addr().unwrap().port();
            assert!(![39025, 39027].contains(&routed.port));
            let state = Arc::new(TerminalGateState {
                stage,
                discard,
                armed: std::sync::atomic::AtomicBool::new(false),
                claimed: std::sync::atomic::AtomicBool::new(false),
                original_backend_pid: AtomicUsize::new(0),
                selected_backend_pid: AtomicUsize::new(0),
                stage_seen: AtomicUsize::new(0),
                begins: AtomicUsize::new(0),
                all_begins_after_arm: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                rollbacks: AtomicUsize::new(0),
                command_acks: AtomicUsize::new(0),
                ready_acks: AtomicUsize::new(0),
                forwarded_acks: AtomicUsize::new(0),
                accepted: AtomicUsize::new(0),
                joined: AtomicUsize::new(0),
                held: Semaphore::new(0),
                release: Semaphore::new(0),
                forwarded: Semaphore::new(0),
            });
            eprintln!(
                "GATEWAY_REGISTRATION_TERMINAL_RELAY_START owned_process_pid={} stage={stage:?} relay_port={} upstream_port={}",
                std::process::id(),
                routed.port,
                config.port
            );
            let shared = state.clone();
            let (stop, mut stopped) = oneshot::channel();
            let task = tokio::spawn(async move {
                let mut children = JoinSet::new();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        accepted = listener.accept() => {
                            let (downstream, _) = accepted.map_err(|_| "terminal relay accept")?;
                            let count = shared.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                            if count > 64 || children.len() >= 32 {
                                return Err("terminal relay bounded connection limit".into());
                            }
                            children.spawn(terminal_relay_connection(downstream, upstream, shared.clone()));
                        },
                        Some(child) = children.join_next(), if !children.is_empty() => {
                            child.map_err(|_| "terminal relay child join")??;
                            shared.joined.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                drop(listener);
                // The Pool/assembly are closed before stop. Normal success must reap
                // every owned relay child, without abort_all or a synthetic join ACK.
                tokio::time::timeout(Duration::from_secs(8), async {
                    while let Some(child) = children.join_next().await {
                        child.map_err(|_| "terminal relay tail child join")??;
                        shared.joined.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok::<(), String>(())
                })
                .await
                .map_err(|_| "terminal relay normal tail deadline")??;
                Ok(())
            });
            Self {
                config: routed,
                state,
                stop: Some(stop),
                task: Some(task),
            }
        }
        pub(super) async fn arm_original(&self, f: &Fixture) -> pool::ConnectionObservation {
            assert_eq!(f.pool.status().max_size, 1);
            let client = f.pool.get().await.unwrap();
            let backend: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            assert!(backend > 0);
            let original = client.observation();
            assert!(!original.snapshot().retirement_requested);
            assert!(!original.snapshot().connection_destroyed);
            self.state
                .original_backend_pid
                .store(backend as usize, Ordering::SeqCst);
            drop(client);
            self.state.armed.store(true, Ordering::SeqCst);
            original
        }
        pub(super) async fn held(&self) {
            tokio::time::timeout(Duration::from_secs(6), self.state.held.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        pub(super) fn original_pid(&self) -> i32 {
            i32::try_from(self.state.original_backend_pid.load(Ordering::SeqCst)).unwrap()
        }
        pub(super) async fn release_original_ack(&self) {
            assert!(!self.state.discard);
            self.state.release.add_permits(1);
            tokio::time::timeout(Duration::from_secs(2), self.state.forwarded.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
            // A successful socket write is not driver receipt or join. Allow the
            // real driver to run while the original business future stays unpolled;
            // only its later real owner result can establish known-late state.
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        pub(super) fn assert_idle(&self) {
            assert_eq!(self.state.all_begins_after_arm.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 0);
            eprintln!(
                "GATEWAY_REGISTRATION_IDLE_SEND original_backend={} actual_BEGIN_after_arm=0 target_terminal_ACK=0",
                self.original_pid()
            );
        }
        pub(super) fn assert_target(&self, expected_forwarded: usize) {
            assert_eq!(
                self.state.selected_backend_pid.load(Ordering::SeqCst),
                self.state.original_backend_pid.load(Ordering::SeqCst)
            );
            assert_ne!(self.state.selected_backend_pid.load(Ordering::SeqCst), 0);
            assert_eq!(self.state.stage_seen.load(Ordering::SeqCst), 1);
            assert_eq!(self.state.command_acks.load(Ordering::SeqCst), 1);
            assert_eq!(self.state.ready_acks.load(Ordering::SeqCst), 1);
            assert_eq!(
                self.state.forwarded_acks.load(Ordering::SeqCst),
                expected_forwarded
            );
            assert_eq!(self.state.begins.load(Ordering::SeqCst), 1);
            match self.state.stage {
                TerminalStage::RegisteredCommit => {
                    assert_eq!(self.state.commits.load(Ordering::SeqCst), 1);
                    assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 0);
                }
                _ => {
                    assert_eq!(self.state.commits.load(Ordering::SeqCst), 0);
                    assert_eq!(self.state.rollbacks.load(Ordering::SeqCst), 1);
                }
            }
        }
        pub(super) async fn stop(mut self) {
            self.state.armed.store(false, Ordering::SeqCst);
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            let mut task = self.task.take().unwrap();
            match tokio::time::timeout(Duration::from_secs(10), &mut task).await {
                Ok(result) => result.unwrap().unwrap(),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    panic!("terminal relay did not naturally join");
                }
            }
            let accepted = self.state.accepted.load(Ordering::SeqCst);
            let joined = self.state.joined.load(Ordering::SeqCst);
            assert_eq!(accepted, joined);
            eprintln!(
                "GATEWAY_REGISTRATION_TERMINAL_RELAY stage={:?} backend_pid={} accepted={} naturally_joined={} command_ack={} ready_ack={} forwarded_ack={} listener_closed=true",
                self.state.stage,
                self.state.selected_backend_pid.load(Ordering::SeqCst),
                accepted,
                joined,
                self.state.command_acks.load(Ordering::SeqCst),
                self.state.ready_acks.load(Ordering::SeqCst),
                self.state.forwarded_acks.load(Ordering::SeqCst)
            );
        }
    }
    impl Drop for PgTerminalAckGate {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(task) = self.task.take() {
                eprintln!(
                    "GATEWAY_REGISTRATION_TERMINAL_RELAY fallback_abort=true normal_join_unproven=true"
                );
                task.abort();
            }
        }
    }
    fn pg_statement(tag: u8, bytes: &[u8]) -> Option<&[u8]> {
        let sql = match tag {
            b'Q' => bytes,
            b'P' => &bytes[bytes.iter().position(|b| *b == 0)? + 1..],
            _ => return None,
        };
        Some(&sql[..sql.iter().position(|b| *b == 0)?])
    }
    async fn terminal_relay_connection(
        mut downstream: TcpStream,
        upstream_address: SocketAddr,
        state: Arc<TerminalGateState>,
    ) -> Result<(), String> {
        let mut upstream = TcpStream::connect(upstream_address)
            .await
            .map_err(|_| "terminal upstream connect")?;
        let len = downstream
            .read_u32()
            .await
            .map_err(|_| "terminal startup length")?;
        if !(8..=65536).contains(&len) {
            return Err("terminal startup bound".into());
        }
        let mut startup = vec![0; len as usize - 4];
        downstream
            .read_exact(&mut startup)
            .await
            .map_err(|_| "terminal startup read")?;
        upstream
            .write_u32(len)
            .await
            .map_err(|_| "terminal startup header")?;
        upstream
            .write_all(&startup)
            .await
            .map_err(|_| "terminal startup forwarding")?;
        if len == 16 && startup[..4] == 80877102_u32.to_be_bytes() {
            // Forward the actual cancellation packet without inventing a terminal ACK.
            upstream
                .shutdown()
                .await
                .map_err(|_| "terminal cancel forwarding shutdown")?;
            return Ok(());
        }
        if startup[..4] != 196608_u32.to_be_bytes() {
            return Err("terminal relay requires original NoTls protocol3 startup".into());
        }
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();
        let backend = Arc::new(AtomicUsize::new(0));
        let selected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let client_state = state.clone();
        let client_backend = backend.clone();
        let client_selected = selected.clone();
        let client = async move {
            let mut stage_bits = 0;
            let mut seen_stage = false;
            let mut original_begin = false;
            let mut original_read_only = false;
            while let Some((tag, bytes)) = terminal_frame(&mut down_read).await? {
                if client_state.armed.load(Ordering::SeqCst)
                    && client_backend.load(Ordering::SeqCst)
                        == client_state.original_backend_pid.load(Ordering::SeqCst)
                    && client_backend.load(Ordering::SeqCst) != 0
                {
                    if tag == b'Q'
                        && (bytes.starts_with(b"START TRANSACTION") || bytes.starts_with(b"BEGIN"))
                    {
                        client_state
                            .all_begins_after_arm
                            .fetch_add(1, Ordering::SeqCst);
                        stage_bits = 0;
                        seen_stage = false;
                        let query =
                            std::str::from_utf8(&bytes).map_err(|_| "terminal BEGIN UTF8")?;
                        original_begin = query.contains("ISOLATION LEVEL READ COMMITTED");
                        original_read_only = query.contains("READ ONLY");
                    }
                    if let Some(sql) = pg_statement(tag, &bytes) {
                        stage_bits |= client_state.stage.sql_bits(sql);
                        if stage_bits == client_state.stage.complete_bits() && !seen_stage {
                            if !original_begin
                                || original_read_only
                                    != matches!(
                                        client_state.stage,
                                        TerminalStage::RegisteredReadbackRollback
                                    )
                            {
                                return Err(
                                    "terminal original business RC/read-only mode mismatch".into(),
                                );
                            }
                            seen_stage = true;
                            client_state.begins.fetch_add(1, Ordering::SeqCst);
                            client_state.stage_seen.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    if tag == b'Q' && seen_stage {
                        if bytes.eq_ignore_ascii_case(b"COMMIT\0") {
                            client_state.commits.fetch_add(1, Ordering::SeqCst);
                        }
                        if bytes.eq_ignore_ascii_case(b"ROLLBACK\0") {
                            client_state.rollbacks.fetch_add(1, Ordering::SeqCst);
                        }
                        if seen_stage
                            && bytes.eq_ignore_ascii_case(client_state.stage.command())
                            && client_state
                                .claimed
                                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                        {
                            client_state
                                .selected_backend_pid
                                .store(client_backend.load(Ordering::SeqCst), Ordering::SeqCst);
                            client_selected.store(true, Ordering::SeqCst);
                        }
                    }
                }
                up_write
                    .write_u8(tag)
                    .await
                    .map_err(|_| "terminal frontend tag write")?;
                up_write
                    .write_u32(bytes.len() as u32 + 4)
                    .await
                    .map_err(|_| "terminal frontend length write")?;
                up_write
                    .write_all(&bytes)
                    .await
                    .map_err(|_| "terminal frontend body write")?;
                if tag == b'Q'
                    && (bytes.eq_ignore_ascii_case(b"COMMIT\0")
                        || bytes.eq_ignore_ascii_case(b"ROLLBACK\0"))
                {
                    stage_bits = 0;
                    seen_stage = false;
                    original_begin = false;
                    original_read_only = false;
                }
            }
            Ok::<(), String>(())
        };
        let server = async move {
            let mut command_complete = None;
            while let Some((tag, bytes)) = terminal_frame(&mut up_read).await? {
                if tag == b'K' {
                    if bytes.len() != 8 {
                        return Err("terminal BackendKeyData shape".into());
                    }
                    backend.store(
                        u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
                        Ordering::SeqCst,
                    );
                }
                if selected.load(Ordering::SeqCst) {
                    if tag == b'C' && bytes == state.stage.command() {
                        if command_complete.is_some() {
                            return Err("terminal original CommandComplete mismatch".into());
                        }
                        state.command_acks.fetch_add(1, Ordering::SeqCst);
                        command_complete = Some(bytes);
                        continue;
                    }
                    if tag == b'Z' && command_complete.is_some() {
                        let completion = command_complete
                            .take()
                            .ok_or("terminal ReadyForQuery without original C")?;
                        if bytes != b"I" {
                            return Err("terminal original ACK did not leave idle".into());
                        }
                        state.ready_acks.fetch_add(1, Ordering::SeqCst);
                        state.held.add_permits(1);
                        if state.discard {
                            return Ok(());
                        }
                        tokio::time::timeout(Duration::from_secs(8), state.release.acquire())
                            .await
                            .map_err(|_| "terminal original ACK release deadline")?
                            .map_err(|_| "terminal original ACK release closed")?
                            .forget();
                        down_write
                            .write_u8(b'C')
                            .await
                            .map_err(|_| "terminal C write")?;
                        down_write
                            .write_u32(completion.len() as u32 + 4)
                            .await
                            .map_err(|_| "terminal C length")?;
                        down_write
                            .write_all(&completion)
                            .await
                            .map_err(|_| "terminal C body")?;
                        down_write
                            .write_u8(b'Z')
                            .await
                            .map_err(|_| "terminal Z write")?;
                        down_write
                            .write_u32(bytes.len() as u32 + 4)
                            .await
                            .map_err(|_| "terminal Z length")?;
                        down_write
                            .write_all(&bytes)
                            .await
                            .map_err(|_| "terminal Z body")?;
                        state.forwarded_acks.fetch_add(1, Ordering::SeqCst);
                        state.forwarded.add_permits(1);
                        state.armed.store(false, Ordering::SeqCst);
                        selected.store(false, Ordering::SeqCst);
                        continue;
                    }
                    // An earlier prepared Statement Drop can still have CloseComplete/
                    // ReadyForQuery on this same socket. Forward those until the exact
                    // target C is seen; they never count as the target terminal ACK.
                    if tag == b'E' || (command_complete.is_some() && tag != b'N') {
                        return Err("terminal unexpected backend frame around original ACK".into());
                    }
                }
                down_write
                    .write_u8(tag)
                    .await
                    .map_err(|_| "terminal backend tag write")?;
                down_write
                    .write_u32(bytes.len() as u32 + 4)
                    .await
                    .map_err(|_| "terminal backend length write")?;
                down_write
                    .write_all(&bytes)
                    .await
                    .map_err(|_| "terminal backend body write")?;
            }
            Ok::<(), String>(())
        };
        tokio::select! { result = client => result, result = server => result }
    }
    async fn terminal_frame<R: AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Option<(u8, Vec<u8>)>, String> {
        let tag = match reader.read_u8().await {
            Ok(tag) => tag,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(_) => return Err("terminal frame tag IO".into()),
        };
        let len = reader
            .read_u32()
            .await
            .map_err(|_| "terminal partial frame length")?;
        if !(4..=8 * 1024 * 1024).contains(&len) {
            return Err("terminal frame bound".into());
        }
        let mut bytes = vec![0; len as usize - 4];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "terminal partial frame body")?;
        Ok(Some((tag, bytes)))
    }
}

#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r01_actual_session_200_registered_original_ack_readback() {
    let admin = harness::admin_config("registration-r01");
    harness::with_temp_database(&admin, "gr_r01", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = f
            .journal
            .register_admitted(&auth, receipt, &factory)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let next = f.row(old.attempt_id).await?;
        registered(&old, &next, &f, ACTOR)?;
        registered_audit(&f, old.attempt_id).await?;
        no_second_post(&f, 1).await?;
        wire(&f.posts()?[0])?;
        let debug = format!("{owner:?}");
        check(
            debug.contains("RegisteredAttemptOwner"),
            "opaque original registered owner",
        )?;
        for secret in [ACTOR, REDIRECT, "owned-registration-client", &f.issuer()] {
            check(
                !debug.contains(secret),
                "opaque registered owner is redacted",
            )?;
        }
        drop(owner);
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r02_actual_singleuser_201_registered_original_ack_readback() {
    let admin = harness::admin_config("registration-r02");
    harness::with_temp_database(&admin, "gr_r02", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        f.configure(&json!({"status":201}))?;
        let (runtime, journal) = f.fresh_pair()?;
        let single = f.single(&journal).await?;
        let auth = single
            .resolve(
                &http::Request::builder()
                    .uri("/owned-registration")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())?;
        let receipt = admit_on(
            &f,
            &journal,
            &auth,
            CancellationToken::new(),
            Duration::from_secs(60),
        )
        .await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = journal
            .register_admitted(&auth, receipt, &factory)
            .await
            .map_err(|e| format!("{e:?}"))?;
        registered(&old, &f.row(old.attempt_id).await?, &f, "dev-local-user")?;
        registered_audit(&f, old.attempt_id).await?;
        wire(&f.posts()?[0])?;
        no_second_post(&f, 1).await?;
        drop(owner);
        single.close_request_bindings();
        runtime.close();
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r03_actual_sdk_whole_request_drop_child_original_parent() {
    let admin = harness::admin_config("registration-r03");
    harness::with_temp_database(&admin,"gr_r03",|cfg|async move {
        let f=Fixture::new(cfg,2).await?;f.configure(&json!({"hold_headers":true}))?;let auth=f.auth().await?;let parent=CancellationToken::new();
        let receipt=admit_on(&f,&f.journal,&auth,parent.clone(),Duration::from_secs(60)).await?;check(!parent.is_cancelled(),"real SDK helper exits without cancelling original parent")?;
        let old=f.rows().await?.remove(0);let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=f.wait_posts(1)=>{}, result=&mut call=>return Err(format!("dispatch ended before owned headers hold: {result:?}")) }
        wire(&f.posts()?[0])?;parent.cancel();let error=refused(call.await)?;kind(&error,DispatchKind::Cancelled)?;ack(&error,DispatchAck::Unknown,DispatchAck::NotAttempted,DispatchAck::NotAttempted)?;sent_facts(&error,true,None,false)?;
        check(f.row(old.attempt_id).await?==old,"cancelled original parent cannot yield registered successor")?;no_second_post(&f,1).await?;f.finish().await
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r04_bad_registration_shape_endpoint_headers_zero_connection() {
    let admin = harness::admin_config("registration-r04");
    harness::with_temp_database(&admin, "gr_r04", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::SendGuardRollback, false).await;
        let f = Fixture::new(relay.config.clone(), 1).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let original = relay.arm_original(&f).await;
        let baseline = f.network_point()?;
        let factory = f.factory(None)?;
        let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
        kind(&error, DispatchKind::FramingInvalid)?;
        ack(
            &error,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
        )?;
        sent_facts(&error, false, None, false)?;
        check(
            f.network_point()? == baseline,
            "registration DNS/socket/POST remain zero beyond setup GET",
        )?;
        relay.assert_idle();
        check(
            !original.snapshot().retirement_requested,
            "idle framing refusal does not retire an unstarted send Tx",
        )?;
        check(
            f.row(old.attempt_id).await? == old,
            "idle refusal preserves admitted history",
        )?;
        f.finish().await?;
        relay.stop().await;
        Ok(())
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r05_original_metadata_factory_drift_zero_connection() {
    let admin = harness::admin_config("registration-r05");
    harness::with_temp_database(&admin, "gr_r05", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let baseline = f.network_point()?;
        let factory = f.factory(Some("/oauth/desktop/changed-register"))?;
        let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
        kind(&error, DispatchKind::FramingInvalid)?;
        ack(
            &error,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
        )?;
        sent_facts(&error, false, None, false)?;
        check(
            f.network_point()? == baseline,
            "used registration target/context drift refuses before DNS/socket/POST",
        )?;
        check(
            f.row(old.attempt_id).await? == old,
            "factory drift preserves admitted history",
        )?;
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r06_current_actor_host_revoked_before_dispatch_zero_send() {
    let admin = harness::admin_config("registration-r06");
    for vector in 0..5 {
        harness::with_temp_database(&admin, &format!("gr_r06_{vector}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let auth = f.auth().await?;
            let receipt = admitted(&f, &auth).await?;
            let old = f.rows().await?.remove(0);
            let baseline = f.network_point()?;
            match vector {
                0 => {
                    execute(
                        &f,
                        "DELETE FROM public.user_roles WHERE user_id='owned-journal-owner'",
                    )
                    .await?
                }
                1 => {
                    execute(
                        &f,
                        "UPDATE public.users SET auth_generation=8 WHERE id='owned-journal-owner'",
                    )
                    .await?
                }
                2 => {
                    execute(
                        &f,
                        "DELETE FROM public.sessions WHERE id='owned-journal-session'",
                    )
                    .await?
                }
                3 => f.disarm_host(),
                _ => f.runtime.as_ref().unwrap().close(),
            }
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
            kind(
                &error,
                if vector == 4 {
                    DispatchKind::Unavailable
                } else {
                    DispatchKind::BeforeDispatchRefused
                },
            )?;
            ack(
                &error,
                if vector < 3 {
                    DispatchAck::Timely
                } else {
                    DispatchAck::NotAttempted
                },
                DispatchAck::NotAttempted,
                DispatchAck::NotAttempted,
            )?;
            check(
                f.network_point()? == baseline,
                "current actor/Host revocation suppresses registration DNS/socket/POST",
            )?;
            check(
                f.row(old.attempt_id).await? == old,
                "revocation leaves original admitted history",
            )?;
            f.finish().await
        })
        .await;
    }
    // Existing default guards and a synthetic Desktop lease cannot replace the
    // genuine original Server binding. This is a negative vector, not Desktop assembly.
    harness::with_temp_database(&admin, "gr_r06_default", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let baseline = f.network_point()?;
        use openbot_contracts::request_binding::{
            HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
            RequestBindingOwnerLease,
        };
        struct DefaultGuard;
        impl HostRequestBindingGuard for DefaultGuard {
            fn verify_current<'a>(
                &'a self,
                _: &'a AuthContext,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Result<(), HostRequestBindingError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(async { Ok(()) })
            }
        }
        let (lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::DesktopWindow);
        let binding = issuer
            .bind_desktop_window(
                &auth,
                "owned-registration-default-desktop-negative".into(),
                1,
                Arc::new(DefaultGuard),
            )
            .map_err(|e| format!("{e:?}"))?;
        let replacement = auth
            .clone()
            .with_verified_request_binding(binding)
            .map_err(|e| format!("{e:?}"))?;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let error = refused(
            f.journal
                .register_admitted(&replacement, receipt, &factory)
                .await,
        )?;
        kind(&error, DispatchKind::BeforeDispatchRefused)?;
        check(
            f.network_point()? == baseline,
            "default/synthetic Desktop binding cannot send original Server receipt",
        )?;
        drop(lease);
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r07_actor_share_then_attempt_update_actual_blockers() {
    let admin = harness::admin_config("registration-r07");
    for actor_blocked in [true, false] {
        harness::with_temp_database(&admin,if actor_blocked {"gr_r07_actor"} else {"gr_r07_attempt"},|cfg|async move {
            let f=Fixture::new(cfg,4).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);let direct=f.direct().await?;let blocker=direct.get().await.map_err(|e|e.to_string())?;blocker.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
            let blocker_pid:i32=blocker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            if actor_blocked { blocker.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE",&[&ACTOR]).await.map_err(|e|e.to_string())?; } else { blocker.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE",&[&old.attempt_id]).await.map_err(|e|e.to_string())?; }
            let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));let observe=async {
                let observer=f.pool.get().await.map_err(|e|e.to_string())?;let until=Instant::now()+Duration::from_secs(5);
                loop {let rows=observer.query("SELECT pid,query FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid))",&[&blocker_pid]).await.map_err(|e|e.to_string())?;
                    if let Some(row)=rows.iter().find(|r| {let sql:String=r.get(1);if actor_blocked {sql.to_ascii_lowercase().contains("for share")} else {sql.contains("gateway_authorization_attempt_lock")}}) {return Ok::<i32,String>(row.get(0));}
                    if Instant::now()>=until {return Err("actual registration lock waiter not observed".into());}tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let waiter=tokio::select! { result=observe=>result?, result=&mut call=>return Err(format!("registration escaped actual blocker: {result:?}")) };
            check(f.posts()?.is_empty(),"no socket POST before actual authority lock order")?;
            let probe=f.pool.get().await.map_err(|e|e.to_string())?;probe.batch_execute("BEGIN").await.map_err(|e|e.to_string())?;
            if actor_blocked {probe.query_one("SELECT attempt_id FROM openbot_internal.gateway_authorization_attempts WHERE attempt_id=$1 FOR UPDATE NOWAIT",&[&old.attempt_id]).await.map_err(|e|e.to_string())?;} else {let failure=probe.query_one("SELECT id FROM public.users WHERE id=$1 FOR UPDATE NOWAIT",&[&ACTOR]).await.err().ok_or("actor SHARE was not held before attempt UPDATE waiter")?;check(failure.as_db_error().is_some_and(|e|e.code().code()=="55P03"),"actual independent NOWAIT confirms actor SHARE")?;}
            probe.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;drop(probe);blocker.batch_execute("ROLLBACK").await.map_err(|e|e.to_string())?;drop(blocker);
            let owner=call.await.map_err(|e|format!("{e:?}"))?;registered(&old,&f.row(old.attempt_id).await?,&f,ACTOR)?;drop(owner);direct.close();
            eprintln!("GATEWAY_REGISTRATION_LOCK_ORDER actual_waiter={waiter} original_blocker={blocker_pid} actor_blocked={actor_blocked} target_query_observed=true independent_NOWAIT_checked=true");f.finish().await
        }).await;
    }
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r08_revocation_while_headers_pending_suppresses_handoff() {
    let admin = harness::admin_config("registration-r08");
    for runtime in [false, true] {
        harness::with_temp_database(&admin,if runtime {"gr_r08_runtime"} else {"gr_r08_lease"},|cfg|async move {
            let f=Fixture::new(cfg,2).await?;f.configure(&json!({"hold_headers":true}))?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
            tokio::select! { ()=f.wait_posts(1)=>{}, result=&mut call=>return Err(format!("ended before headers hold: {result:?}")) }
            if runtime {f.runtime.as_ref().unwrap().close();} else {f.disarm_host();}f.release_headers()?;let error=refused(call.await)?;check(error.registered_write_ack()==DispatchAck::NotAttempted,"revoked current Host suppresses registered write")?;check(f.row(old.attempt_id).await?==old,"revoked held send cannot handoff owner")?;no_second_post(&f,1).await?;f.finish().await
        }).await;
    }
    harness::with_temp_database(&admin,"gr_r08_db_tail",|cfg|async move {
        let relay=PgTerminalAckGate::new(&cfg,TerminalStage::SendGuardRollback,false).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("missing original send ACK hold: {result:?}")) }
        let direct=f.direct().await?;let client=direct.get().await.map_err(|e|e.to_string())?;client.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='owned-journal-owner'").await.map_err(|e|e.to_string())?;drop(client);relay.release_original_ack().await;
        let error=refused(call.await)?;kind(&error,DispatchKind::RegistrationUnknown)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,DispatchAck::NotAttempted)?;check(f.row(old.attempt_id).await?==old,"post-release DB revocation refuses successor")?;relay.assert_target(1);direct.close();f.finish().await?;relay.stop().await;Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r09_permit_timely_original_rollback_before_reply_visible() {
    let admin = harness::admin_config("registration-r09");
    harness::with_temp_database(&admin,"gr_r09",|cfg|async move {
        let relay=PgTerminalAckGate::new(&cfg,TerminalStage::SendGuardRollback,false).await;let f=Fixture::new(relay.config.clone(),1).await?;f.configure(&json!({"hold_body":true}))?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("missing actual original rollback hold: {result:?}")) }
        check(f.events()?.iter().all(|e|e["event"]!="body_sent"),"owned peer body remains unavailable before original release ACK")?;
        relay.release_original_ack().await;check(tokio::time::timeout(Duration::from_millis(100),&mut call).await.is_err(),"caller remains pending on owned body after actual permit rollback ACK")?;f.release_body()?;
        let owner=call.await.map_err(|e|format!("{e:?}"))?;registered(&old,&f.row(old.attempt_id).await?,&f,ACTOR)?;relay.assert_target(1);wire(&f.posts()?[0])?;drop(owner);f.finish().await?;relay.stop().await;Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r10_permit_late_or_lost_rollback_unknown_no_reply() {
    let admin = harness::admin_config("registration-r10");
    for discard in [false, true] {
        harness::with_temp_database(&admin,if discard {"gr_r10_loss"} else {"gr_r10_late"},|cfg|async move {
            let relay=PgTerminalAckGate::new(&cfg,TerminalStage::SendGuardRollback,discard).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admit_on(&f,&f.journal,&auth,CancellationToken::new(),Duration::from_secs(3)).await?;let old=f.rows().await?.remove(0);let original=relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
            tokio::select! { biased; ()=relay.held()=>{}, result=&mut call=>return Err(format!("original rollback ACK never held: {result:?}")) }
            if !discard {tokio::time::sleep(Duration::from_millis(3200)).await;relay.release_original_ack().await;}
            let error=refused(call.await)?;kind(&error,if discard {DispatchKind::CleanupUnknown} else {DispatchKind::RollbackAcknowledgedAfterDeadline})?;ack(&error,if discard {DispatchAck::Unknown} else {DispatchAck::Late},DispatchAck::NotAttempted,DispatchAck::NotAttempted)?;sent_facts(&error,true,Some(200),false)?;
            check(f.row(old.attempt_id).await?==old,"late/lost original rollback ACK does not expose reply or register")?;no_second_post(&f,1).await?;relay.assert_target(usize::from(!discard));retired(&f,&original,relay.original_pid()).await?;f.finish().await?;relay.stop().await;Ok(())
        }).await;
    }
    harness::with_temp_database(&admin, "gr_r10_request_end", |cfg| async move {
        let f = Fixture::new(cfg, 1).await?;
        f.configure(&json!({"close_before_headers":true}))?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let error = refused(
            tokio::time::timeout(
                Duration::from_secs(5),
                f.journal.register_admitted(&auth, receipt, &factory),
            )
            .await
            .map_err(|_| "local runner orphan after real request end/permit Drop")?,
        )?;
        ack(
            &error,
            DispatchAck::Timely,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
        )?;
        sent_facts(&error, true, None, false)?;
        check(
            f.row(old.attempt_id).await? == old,
            "request ended without headers keeps admitted history",
        )?;
        no_second_post(&f, 1).await?;
        f.finish().await
    })
    .await;
    harness::with_temp_database(&admin,"gr_r10_caller_drop",|cfg|async move {
        let f=Fixture::new(cfg,1).await?;f.configure(&json!({"hold_headers":true}))?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);let client=f.pool.get().await.map_err(|e|e.to_string())?;let original=client.observation();let pid:i32=client.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);drop(client);
        let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));tokio::select! { ()=f.wait_posts(1)=>{}, result=&mut call=>return Err(format!("caller escaped owned headers wait: {result:?}")) }
        drop(call);retired(&f,&original,pid).await?;check(f.row(old.attempt_id).await?==old,"whole caller Drop cannot manufacture registered owner/restore receipt")?;no_second_post(&f,1).await?;
        eprintln!("GATEWAY_REGISTRATION_WHOLE_CALLER_DROP result_owner=NONE terminal_ACK=UNKNOWN local_runner_async_join=UNPROVEN receipt_restore=false");f.finish().await
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r11_same_parent_caps_during_send_release_body_no_retry() {
    let admin = harness::admin_config("registration-r11");
    for cancel in [false, true] {
        harness::with_temp_database(&admin,if cancel {"gr_r11_parent_body"} else {"gr_r11_caller_body"},|cfg|async move {
            let relay=PgTerminalAckGate::new(&cfg,TerminalStage::SendGuardRollback,false).await;let f=Fixture::new(relay.config.clone(),1).await?;f.configure(&json!({"hold_body":true}))?;let auth=f.auth().await?;let parent=CancellationToken::new();let receipt=admit_on(&f,&f.journal,&auth,parent.clone(),Duration::from_secs(3)).await?;let old=f.rows().await?.remove(0);relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
            tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("body scenario missed original send rollback: {result:?}")) }
            relay.release_original_ack().await;check(tokio::time::timeout(Duration::from_millis(100),&mut call).await.is_err(),"actual reader remains pending after true release ACK")?;
            if cancel {parent.cancel();}
            let error=refused(call.await)?;kind(&error,if cancel {DispatchKind::Cancelled} else {DispatchKind::Deadline})?;ack(&error,DispatchAck::Timely,DispatchAck::NotAttempted,DispatchAck::NotAttempted)?;sent_facts(&error,true,Some(200),true)?;
            check(f.row(old.attempt_id).await?==old,"original parent/caller cap does not renew during body")?;no_second_post(&f,1).await?;relay.assert_target(1);f.finish().await?;relay.stop().await;Ok(())
        }).await;
    }
    harness::with_temp_database(&admin, "gr_r11_capture_expired", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let baseline = f.network_point()?;
        tokio::time::sleep(Duration::from_millis(10200)).await;
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
        kind(&error, DispatchKind::Deadline)?;
        ack(
            &error,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
            DispatchAck::NotAttempted,
        )?;
        check(
            f.network_point()? == baseline,
            "original captured ten-second ceiling never restarts at dispatch",
        )?;
        check(
            f.row(old.attempt_id).await? == old,
            "expired capture is not a new receipt",
        )?;
        f.finish().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r12_non_success_or_invalid_success_reply_no_sdk_decode() {
    let admin = harness::admin_config("registration-r12");
    for status in [400_u16, 429, 500] {
        harness::with_temp_database(&admin,&format!("gr_r12_{status}"),|cfg|async move {
            let f=Fixture::new(cfg,2).await?;f.configure(&json!({"status":status,"hold_body":true,"raw":"{\"vendor_secret\":\"owned-error-body-must-not-be-decoded\"}"}))?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);let factory=f.factory(Some("/oauth/desktop/register"))?;
            let error=refused(tokio::time::timeout(Duration::from_secs(3),f.journal.register_admitted(&auth,receipt,&factory)).await.map_err(|_|"non-success response incorrectly waited for owned error body")?)?;
            kind(&error,DispatchKind::HttpStatus(status))?;ack(&error,DispatchAck::Timely,DispatchAck::NotAttempted,DispatchAck::NotAttempted)?;sent_facts(&error,true,Some(status),true)?;check(!format!("{error:?}").contains("vendor_secret"),"numeric failure contains no vendor body")?;
            check(f.events()?.iter().all(|v|v["event"]!="body_sent"),"caller returns while peer error body is still withheld")?;check(f.row(old.attempt_id).await?==old,"non-success keeps admitted uncertainty")?;no_second_post(&f,1).await?;f.finish().await
        }).await;
    }
    for raw in [
        "not-json",
        "{}",
        "{\"client_id\":7}",
        "{\"client_id\":\"a\",\"client_id\":\"b\"}",
    ] {
        harness::with_temp_database(&admin, "gr_r12_invalid200", |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            let configuration = json!({"raw":raw});
            f.configure(&configuration)?;
            let auth = f.auth().await?;
            let receipt = admitted(&f, &auth).await?;
            let old = f.rows().await?.remove(0);
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
            kind(&error, DispatchKind::RegistrationUnknown)?;
            ack(
                &error,
                DispatchAck::Timely,
                DispatchAck::NotAttempted,
                DispatchAck::NotAttempted,
            )?;
            sent_facts(&error, true, Some(200), true)?;
            body_facts(&error, true, None)?;
            owned_response(&f, &configuration, true).await?;
            check(
                f.row(old.attempt_id).await? == old,
                "invalid success bytes do not run SDK decoder or register",
            )?;
            no_second_post(&f, 1).await?;
            f.finish().await
        })
        .await;
    }
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r13_header_body_limits_secret_keys_and_owner_drop() {
    let admin = harness::admin_config("registration-r13");
    let mut vectors = vec![
        json!({"headers":[["Content-Type","text/plain"]]}),
        json!({"headers":[["Content-Type","application/json"],["Content-Type","application/json"]]}),
        json!({"headers":[["Content-Type","application/json"],["X-Large","x".repeat(8193)]]}),
        json!({"raw":" ".repeat(65537)}),
        json!({"raw":"{\"client_id\":\"owned-registration-client\",\"client_secret\":\"owned-secret\"}"}),
        json!({"raw":"{\"client_id\":\"owned-registration-client\",\"access_token\":\"owned-secret\"}"}),
        json!({"raw":"{\"client_id\":\"owned-registration-client\",\"refresh_token\":\"owned-secret\"}"}),
        json!({"raw":"{\"client_id\":\"owned-registration-client\",\"id_token\":\"owned-secret\"}"}),
    ];
    let mut many = vec![json!(["Content-Type", "application/json"])];
    for index in 0..65 {
        many.push(json!([format!("X-{index}"), "x"]));
    }
    vectors.push(json!({"headers":many}));
    let mut total = vec![json!(["Content-Type", "application/json"])];
    for index in 0..14 {
        total.push(json!([format!("X-{index}"), "x".repeat(5000)]));
    }
    vectors.push(json!({"headers":total}));
    for (index, configuration) in vectors.into_iter().enumerate() {
        harness::with_temp_database(&admin, &format!("gr_r13_{index}"), |cfg| async move {
            let f = Fixture::new(cfg, 2).await?;
            f.configure(&configuration)?;
            let auth = f.auth().await?;
            let receipt = admitted(&f, &auth).await?;
            let old = f.rows().await?.remove(0);
            let factory = f.factory(Some("/oauth/desktop/register"))?;
            let error = refused(f.journal.register_admitted(&auth, receipt, &factory).await)?;
            kind(&error, DispatchKind::RegistrationUnknown)?;
            ack(
                &error,
                DispatchAck::Timely,
                DispatchAck::NotAttempted,
                DispatchAck::NotAttempted,
            )?;
            if index == 3 {
                // The original SafeHttp rejects known Content-Length=65537 before it returns
                // headers to GatewayTransport. This proves its existing 64KiB pre-return cap,
                // without claiming that the reply cursor consumed an oversized body.
                sent_facts(&error, true, None, false)?;
                body_facts(&error, false, Some(DispatchTransportFailure::Body))?;
            } else {
                sent_facts(&error, true, Some(200), true)?;
                match index {
                    0 | 1 => body_facts(&error, false, Some(DispatchTransportFailure::Cancelled))?,
                    2 | 8 | 9 => {
                        body_facts(&error, false, Some(DispatchTransportFailure::Rejected))?
                    }
                    4..=7 => body_facts(&error, true, None)?,
                    _ => return Err("unregistered owned response vector".into()),
                }
            }
            owned_response(&f, &configuration, matches!(index, 4..=7)).await?;
            check(
                !format!("{error:?}").contains("owned-secret"),
                "bounded failure does not retain secret body values",
            )?;
            check(
                f.row(old.attempt_id).await? == old,
                "multiheader/media/body/secret refusal cannot return registered owner",
            )?;
            no_second_post(&f, 1).await?;
            f.finish().await
        })
        .await;
    }
    eprintln!(
        "GATEWAY_REGISTRATION_RESOURCE_DROP original_owned_response_dropped=true immutable_SDK_Bytes_and_allocator_erasure=UNPROVEN no_enrollment_or_tokens=true"
    );
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r14_registered_original_reservation_fullrow_cas() {
    let admin = harness::admin_config("registration-r14");
    harness::with_temp_database(&admin, "gr_r14_success", |cfg| async move {
        let f = Fixture::new(cfg, 2).await?;
        let auth = f.auth().await?;
        let receipt = admitted(&f, &auth).await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = f
            .journal
            .register_admitted(&auth, receipt, &factory)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let next = f.row(old.attempt_id).await?;
        registered(&old, &next, &f, ACTOR)?;
        registered_audit(&f, old.attempt_id).await?;
        let id = next
            .enrollment_id
            .ok_or("registered reservation pair absent")?;
        check(
            id != next.attempt_id,
            "one reserved future ID is distinct from original attempt ID",
        )?;
        check(
            f.rows().await?.len() == 1,
            "reservation does not create an enrollment or another attempt",
        )?;
        no_second_post(&f, 1).await?;
        drop(owner);
        f.finish().await
    })
    .await;
    harness::with_temp_database(&admin,"gr_r14_drift",|cfg|async move {
        let relay=PgTerminalAckGate::new(&cfg,TerminalStage::SendGuardRollback,false).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("fullrow drift missed original send ACK hold: {result:?}")) }
        let direct=f.direct().await?;let client=direct.get().await.map_err(|e|e.to_string())?;let changed=client.execute("UPDATE openbot_internal.gateway_authorization_attempts SET updated_at=updated_at+interval '1 microsecond' WHERE attempt_id=$1",&[&old.attempt_id]).await.map_err(|e|e.to_string())?;check(changed==1,"actual owned admitted-row drift committed after send lock release")?;drop(client);relay.release_original_ack().await;
        let error=refused(call.await)?;kind(&error,DispatchKind::RegistrationUnknown)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,DispatchAck::NotAttempted)?;let observed=f.row(old.attempt_id).await?;check(observed.phase=="registration_admitted" && observed.client_id.is_none() && observed.enrollment_id.is_none() && observed.updated_at==old.updated_at+time::Duration::microseconds(1),"full20 comparison refuses to overwrite drift or mint a durable reservation")?;no_second_post(&f,1).await?;relay.assert_target(1);direct.close();f.finish().await?;relay.stop().await;Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r15_registered_audit_failure_rolls_back_without_resend() {
    let admin = harness::admin_config("registration-r15");
    harness::with_temp_database(&admin,"gr_r15",|cfg|async move {
        let f=Fixture::new(cfg,2).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);execute(&f,"ALTER TABLE public.audit_events ADD CONSTRAINT owned_registration_audit_reject CHECK(event_type <> 'gateway_authorization_registered')").await?;let factory=f.factory(Some("/oauth/desktop/register"))?;
        let error=refused(f.journal.register_admitted(&auth,receipt,&factory).await)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,DispatchAck::NotAttempted)?;sent_facts(&error,true,Some(200),true)?;check(f.row(old.attempt_id).await?==old,"real registered audit failure rolls back successor")?;check(f.audits().await?.len()==2,"actual failed registered audit does not persist")?;check(!format!("{error:?}").contains("owned_registration_audit_reject"),"raw SQL/PG error not exposed")?;no_second_post(&f,1).await?;f.finish().await
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r16_registered_commit_late_or_lost_preserves_send_unknown() {
    let admin = harness::admin_config("registration-r16");
    for discard in [false, true] {
        harness::with_temp_database(&admin,if discard {"gr_r16_loss"} else {"gr_r16_late"},|cfg|async move {
            let relay=PgTerminalAckGate::new(&cfg,TerminalStage::RegisteredCommit,discard).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admit_on(&f,&f.journal,&auth,CancellationToken::new(),Duration::from_secs(3)).await?;let old=f.rows().await?.remove(0);let original=relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
            tokio::select! { biased; ()=relay.held()=>{}, result=&mut call=>return Err(format!("registered original commit ACK was not held: {result:?}")) }
            if !discard {tokio::time::sleep(Duration::from_millis(3200)).await;relay.release_original_ack().await;}
            let error=refused(call.await)?;kind(&error,if discard {DispatchKind::CommitUnknown} else {DispatchKind::CommitAcknowledgedAfterDeadline})?;ack(&error,DispatchAck::Timely,if discard {DispatchAck::Unknown} else {DispatchAck::Late},DispatchAck::NotAttempted)?;sent_facts(&error,true,Some(200),true)?;
            let next=f.row(old.attempt_id).await?;registered(&old,&next,&f,ACTOR)?;registered_audit(&f,old.attempt_id).await?;ack(&error,DispatchAck::Timely,if discard {DispatchAck::Unknown} else {DispatchAck::Late},DispatchAck::NotAttempted)?;no_second_post(&f,1).await?;relay.assert_target(usize::from(!discard));retired(&f,&original,relay.original_pid()).await?;f.finish().await?;relay.stop().await;Ok(())
        }).await;
    }
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r17_registered_readback_tail_rollback_unknown_no_owner() {
    let admin = harness::admin_config("registration-r17");
    for discard in [false, true] {
        harness::with_temp_database(&admin,if discard {"gr_r17_loss"} else {"gr_r17_late"},|cfg|async move {
            let relay=PgTerminalAckGate::new(&cfg,TerminalStage::RegisteredReadbackRollback,discard).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admit_on(&f,&f.journal,&auth,CancellationToken::new(),Duration::from_secs(3)).await?;let old=f.rows().await?.remove(0);let original=relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
            tokio::select! { biased; ()=relay.held()=>{}, result=&mut call=>return Err(format!("registered original RO rollback ACK not held: {result:?}")) }
            if !discard {tokio::time::sleep(Duration::from_millis(3200)).await;relay.release_original_ack().await;}
            let error=refused(call.await)?;kind(&error,if discard {DispatchKind::ReadbackUnproven} else {DispatchKind::RollbackAcknowledgedAfterDeadline})?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,if discard {DispatchAck::Unknown} else {DispatchAck::Late})?;sent_facts(&error,true,Some(200),true)?;
            registered(&old,&f.row(old.attempt_id).await?,&f,ACTOR)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,if discard {DispatchAck::Unknown} else {DispatchAck::Late})?;no_second_post(&f,1).await?;relay.assert_target(usize::from(!discard));retired(&f,&original,relay.original_pid()).await?;f.finish().await?;relay.stop().await;Ok(())
        }).await;
    }
    harness::with_temp_database(&admin,"gr_r17_full20_readback",|cfg|async move {
        let relay=PgTerminalAckGate::new(&cfg,TerminalStage::RegisteredCommit,false).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;let old=f.rows().await?.remove(0);relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("readback drift missed registered COMMIT ACK: {result:?}")) }
        let direct=f.direct().await?;let client=direct.get().await.map_err(|e|e.to_string())?;client.execute("UPDATE openbot_internal.gateway_authorization_attempts SET updated_at=updated_at+interval '1 microsecond' WHERE attempt_id=$1",&[&old.attempt_id]).await.map_err(|e|e.to_string())?;drop(client);relay.release_original_ack().await;
        let error=refused(call.await)?;kind(&error,DispatchKind::ReadbackUnproven)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,DispatchAck::Timely)?;no_second_post(&f,1).await?;relay.assert_target(1);direct.close();f.finish().await?;relay.stop().await;Ok(())
    }).await;
    harness::with_temp_database(&admin,"gr_r17_host_tail",|cfg|async move {
        let relay=PgTerminalAckGate::new(&cfg,TerminalStage::RegisteredReadbackRollback,false).await;let f=Fixture::new(relay.config.clone(),1).await?;let auth=f.auth().await?;let receipt=admitted(&f,&auth).await?;relay.arm_original(&f).await;let factory=f.factory(Some("/oauth/desktop/register"))?;let mut call=Box::pin(f.journal.register_admitted(&auth,receipt,&factory));
        tokio::select! { ()=relay.held()=>{}, result=&mut call=>return Err(format!("host tail missed original readback ACK: {result:?}")) }
        f.disarm_host();relay.release_original_ack().await;let error=refused(call.await)?;ack(&error,DispatchAck::Timely,DispatchAck::Timely,DispatchAck::Timely)?;no_second_post(&f,1).await?;relay.assert_target(1);f.finish().await?;relay.stop().await;Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires the Root-frozen owned PostgreSQL and TLS runtime"]
async fn r18_two_operations_drop_old_runtime_no_resume_or_resend() {
    let admin = harness::admin_config("registration-r18");
    let facts = Arc::new(std::sync::Mutex::new(Vec::<Row>::new()));
    for drop_runtime in [false, true] {
        let facts = facts.clone();
        harness::with_temp_database(
            &admin,
            if drop_runtime {
                "gr_r18_drop"
            } else {
                "gr_r18_close"
            },
            |cfg| async move {
                let mut f = Fixture::new(cfg, 2).await?;
                let old_auth = f.auth().await?;
                let parent = CancellationToken::new();
                let old_receipt = admit_on(
                    &f,
                    &f.journal,
                    &old_auth,
                    parent.clone(),
                    Duration::from_secs(60),
                )
                .await?;
                let old = f.rows().await?.remove(0);
                let baseline = f.network_point()?;
                if drop_runtime {
                    drop(f.runtime.take());
                } else {
                    f.runtime.as_ref().unwrap().close();
                }
                let factory = f.factory(Some("/oauth/desktop/register"))?;
                let error = refused(
                    f.journal
                        .register_admitted(&old_auth, old_receipt, &factory)
                        .await,
                )?;
                kind(&error, DispatchKind::Unavailable)?;
                ack(
                    &error,
                    DispatchAck::NotAttempted,
                    DispatchAck::NotAttempted,
                    DispatchAck::NotAttempted,
                )?;
                check(
                    f.network_point()? == baseline,
                    "old runtime Weak cannot dispatch or replay consumed receipt",
                )?;
                let (runtime, journal) = f.fresh_pair()?;
                let resolver = fixture::session_resolver(
                    f.pool.clone(),
                    DeploymentId::new(DEP),
                    TenantId::new(TENANT),
                )?;
                resolver
                    .install_gateway_authorization_journal(&journal)
                    .map_err(|e| format!("{e:?}"))?;
                let fresh_auth = resolver
                    .resolve(
                        &http::Request::builder()
                            .uri("/owned-registration")
                            .header("cookie", format!("openbot_session={COOKIE}"))
                            .body(())
                            .unwrap()
                            .into_parts()
                            .0,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                let receipt = admit_on(
                    &f,
                    &journal,
                    &fresh_auth,
                    CancellationToken::new(),
                    Duration::from_secs(60),
                )
                .await?;
                parent.cancel();
                let owner = journal
                    .register_admitted(&fresh_auth, receipt, &factory)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                let rows = f.rows().await?;
                check(rows.len() == 2, "only independent original attempts remain")?;
                check(
                    f.row(old.attempt_id).await? == old,
                    "old admitted history is neither resumed nor rewritten",
                )?;
                let next = rows
                    .into_iter()
                    .find(|r| r.attempt_id != old.attempt_id)
                    .ok_or("new runtime operation row absent")?;
                check(
                    next.phase == "registered"
                        && next.client_id.as_deref() == Some("owned-registration-client")
                        && next
                            .enrollment_id
                            .is_some_and(|id| id.get_version_num() == 7)
                        && next.runtime_epoch != old.runtime_epoch,
                    "new valid independent runtime has its own reservation and parent",
                )?;
                facts.lock().unwrap().push(next);
                no_second_post(&f, 1).await?;
                wire(&f.posts()?[0])?;
                drop(owner);
                resolver.close_request_bindings();
                runtime.close();
                f.finish().await
            },
        )
        .await;
    }
    let facts = facts.lock().unwrap();
    check(
        facts.len() == 2
            && facts[0].attempt_id != facts[1].attempt_id
            && facts[0].runtime_epoch != facts[1].runtime_epoch
            && facts[0].issuer != facts[1].issuer,
        "two independently owned PG/TLS operations do not share identity/endpoint/outcomes",
    )
    .unwrap();
}
