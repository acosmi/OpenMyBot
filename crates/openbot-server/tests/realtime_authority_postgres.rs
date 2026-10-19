//! Real session/people transactions and real TCP/SSE/WebSocket delivery. Membership stays intact.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}
#[path = "support/transport_fixture.rs"]
mod transport_fixture;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, OpenBotApplication, PeopleAdministration, RunRuntime,
    RunSemanticChannel, RunTerminal, ThreadDirectory,
};
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId, ThreadId};
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::ChannelRepo;
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const KEY: &[u8] = b"isolated-realtime-session-hash-key";
const ORIGIN: &str = "https://app.example.test";
const WRITER_TOKEN: &str = "isolated-realtime-writer-session-token";

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn require(value: bool, message: &str) -> Result<(), String> {
    value.then_some(()).ok_or_else(|| message.to_owned())
}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Sse,
    ThreadWs,
    ChannelWs,
}

enum Client {
    Sse(TcpStream),
    Ws(Box<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>>),
}
impl Client {
    async fn connect(
        address: SocketAddr,
        protocol: Protocol,
        thread: &ThreadId,
        token: &str,
    ) -> Result<Self, String> {
        let (path, subprotocol) = match protocol {
            Protocol::Sse => (format!("/api/threads/{}/events", thread.as_str()), ""),
            Protocol::ThreadWs => (
                format!("/api/threads/{}/ws", thread.as_str()),
                "openbot.thread-events.v1",
            ),
            Protocol::ChannelWs => ("/api/channels/events".into(), "openbot.channel-activity.v1"),
        };
        if matches!(protocol, Protocol::Sse) {
            let mut socket = TcpStream::connect(address).await.map_err(text)?;
            socket.write_all(format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nCookie: openbot_session={token}\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(text)?;
            // Read exactly through the headers; do not consume or discard an initial event.
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                require(header.len() < 16_384, "unbounded SSE response header")?;
                header.push(socket.read_u8().await.map_err(text)?);
            }
            require(
                header.starts_with(b"HTTP/1.1 200"),
                "SSE admission was not 200",
            )?;
            Ok(Self::Sse(socket))
        } else {
            let mut request = format!("ws://{address}{path}")
                .into_client_request()
                .map_err(text)?;
            request.headers_mut().insert(
                "cookie",
                format!("openbot_session={token}").parse().map_err(text)?,
            );
            request
                .headers_mut()
                .insert("origin", ORIGIN.parse().map_err(text)?);
            request
                .headers_mut()
                .insert("sec-websocket-protocol", subprotocol.parse().map_err(text)?);
            let (socket, response) = tokio_tungstenite::connect_async(request)
                .await
                .map_err(text)?;
            require(
                response.status() == http::StatusCode::SWITCHING_PROTOCOLS,
                "WS admission was not 101",
            )?;
            Ok(Self::Ws(Box::new(socket)))
        }
    }

    async fn next(&mut self) -> Result<Option<String>, String> {
        match self {
            Self::Sse(socket) => {
                let mut bytes = [0_u8; 8192];
                let n = socket.read(&mut bytes).await.map_err(text)?;
                Ok((n > 0).then(|| String::from_utf8_lossy(&bytes[..n]).into_owned()))
            }
            Self::Ws(socket) => loop {
                match socket.next().await {
                    Some(Ok(Message::Text(body))) => return Ok(Some(body.to_string())),
                    Some(Ok(Message::Close(_))) | None => return Ok(None),
                    Some(Err(
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed
                        | tokio_tungstenite::tungstenite::Error::AlreadyClosed,
                    )) => return Ok(None),
                    // An invalidated pending send must drop the socket without flushing
                    // its old write buffer just to complete a WebSocket close handshake.
                    Some(Err(tokio_tungstenite::tungstenite::Error::Protocol(
                        tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                    ))) => return Ok(None),
                    Some(Err(error)) => return Err(text(error)),
                    Some(Ok(_)) => {}
                }
            },
        }
    }

    async fn contains(&mut self, marker: &str) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut body = String::new();
            while let Some(next) = self.next().await? {
                body.push_str(&next);
                require(body.len() <= 128 * 1024, "unbounded positive stream")?;
                if body.contains(marker) {
                    return Ok(());
                }
            }
            Err("valid session closed before receiving the new body".into())
        })
        .await
        .map_err(text)?
    }

    async fn closed_without(&mut self, marker: &str) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut body = String::new();
            while let Some(next) = self.next().await? {
                body.push_str(&next);
                require(body.len() <= 128 * 1024, "unbounded invalid stream")?;
                require(
                    !body.contains(marker),
                    "invalidated session received a new body",
                )?;
            }
            Ok(())
        })
        .await
        .map_err(text)?
    }
}

async fn seed_session(
    pool: &pool::DatabasePool,
    id: &str,
    user: &str,
    token: &str,
) -> Result<(), String> {
    let hash = SessionTokenHash::compute(
        SessionToken::new(token.as_bytes()),
        SessionHashKey::new(KEY),
    )
    .to_column_value();
    pool.get().await.map_err(text)?.execute(
        "INSERT INTO public.sessions(id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
         VALUES($1,$2,$3,clock_timestamp()+interval '1 hour',clock_timestamp()-interval '12 hours',clock_timestamp(),0)",
        &[&id,&user,&hash],
    ).await.map_err(text)?;
    Ok(())
}

async fn sign_out(address: SocketAddr, token: &str) -> Result<(), String> {
    let mut socket = TcpStream::connect(address).await.map_err(text)?;
    socket.write_all(format!("POST /api/auth/sign-out HTTP/1.1\r\nHost: {address}\r\nOrigin: {ORIGIN}\r\nCookie: openbot_session={token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(text)?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        require(header.len() < 16_384, "unbounded sign-out response header")?;
        header.push(socket.read_u8().await.map_err(text)?);
    }
    require(
        header.starts_with(b"HTTP/1.1 204"),
        "real HTTP sign-out was not 204",
    )
}

async fn listener_count(pool: &pool::DatabasePool, expected: i64) -> Result<(), String> {
    for _ in 0..100 {
        let actual: i64 = pool.get().await.map_err(text)?
            .query_one("SELECT count(*)::bigint FROM pg_stat_activity WHERE application_name='audit-realtime-listener'", &[])
            .await.map_err(text)?.get(0);
        if actual == expected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(format!(
        "original LISTEN connections did not converge to {expected}"
    ))
}

async fn matrix(protocol: Protocol) {
    let admin = admin_config("realtime_authority_postgres");
    with_temp_database(&admin, "realtime_authority", |config| async move {
        let pool = pool::connect(&config.clone().with_max_pool_size(8)).await.map_err(text)?;
        let result = async {
            let mut db = pool.get().await.map_err(text)?;
            baseline::apply(&db).await.map_err(text)?;
            native::apply(&mut db).await.map_err(text)?;
            db.batch_execute(
                "INSERT INTO public.users(id,email) VALUES('writer','writer@example.test');
                 INSERT INTO public.user_roles(user_id,role) VALUES('writer','admin');
                 INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Bot','built_in','{}');
                 INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                   VALUES('bot',NULL,'Bot','test','seed','public');
                 INSERT INTO public.channels(id,name,description) VALUES('channel','Channel','isolated authorization test');
                 INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','writer');
                 INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');"
            ).await.map_err(text)?;
            drop(db);
            seed_session(&pool,"writer-session","writer",WRITER_TOKEN).await?;
            let directory = PostgresThreadDirectory::with_runtime(pool.clone(), config.clone().with_application_name("audit-realtime-listener"), "realtime-writer".into(), DEFAULT_THREAD_LEASE_DURATION).map_err(text)?;
            let runtime = PostgresRunRuntime::new(pool.clone(), "realtime-writer".into(), DEFAULT_THREAD_LEASE_DURATION, DEFAULT_DISPATCH_CLAIM_DURATION).map_err(text)?;
            let resolver = Arc::new(PostgresSessionAuthResolver::new(pool.clone(),KEY,default_session_lifetime(),DeploymentId::new("dep"),TenantId::new("tenant")).map_err(text)?);
            let people = PostgresPeopleAdministration::new(pool.clone(),None,b"realtime-audit-key".to_vec()).map_err(text)?;
            let app = Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())).with_threads(directory.clone()));
            let state = ServerBuilder::new(app,resolver.clone())
                .with_transport_policy(transport_fixture::loopback_policy())
                .with_sensitive_write_security(SensitiveWriteSecurity::new(default_session_lifetime(),TrustedOrigins::from_configured([ORIGIN]).map_err(text)?))
                .build();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
            let address = listener.local_addr().map_err(text)?;
            let server = tokio::spawn(async move {
                axum::serve(listener,openbot_server::router(state).into_make_service_with_connect_info::<SocketAddr>()).await
            });
            let cases = async {
                for (index, change) in ["revoke","role","signout","expiry","idle","session_null","database"].into_iter().enumerate() {
                    let reader = format!("reader-{index}");
                    let token = format!("isolated-realtime-reader-session-token-{index}");
                    let other_token = format!("isolated-realtime-second-session-token-{index}");
                    let db = pool.get().await.map_err(text)?;
                    db.execute("INSERT INTO public.users(id,email) VALUES($1,$2)", &[&reader,&format!("{reader}@example.test")]).await.map_err(text)?;
                    db.execute("INSERT INTO public.user_roles(user_id,role) VALUES($1,'user')", &[&reader]).await.map_err(text)?;
                    db.execute("INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel',$1)", &[&reader]).await.map_err(text)?;
                    drop(db);
                    seed_session(&pool,&format!("session-{index}"),&reader,&token).await?;
                    seed_session(&pool,&format!("second-{index}"),&reader,&other_token).await?;
                    let thread = ThreadIdentity::new(&DeploymentId::new("dep")).mint_from_entropy([index as u8+1;16]);
                    directory.begin_thread_run(BeginThreadRunRequest {
                        deployment:DeploymentId::new("dep"),tenant:TenantId::new("tenant"),actor:ActorId::new("writer"),auth_generation:AuthGeneration::new(0),
                        command:BeginThreadRun { thread_id:thread.clone(),run_id:RunId::new(format!("run-{index}")),bot_id:BotId::new("bot"),anchor:ThreadRunAnchor::Channel{channel_id:ChannelId::new("channel")},message:"before invalidation".into(),model_selection:None,selected_skill_slugs:Vec::new(),artifact_refs:Vec::new() },
                    }).await.map_err(text)?;
                    let mut revoked = Client::connect(address,protocol,&thread,&token).await?;
                    let valid_token = if change=="signout" { other_token.as_str() } else { WRITER_TOKEN };
                    let mut valid = Client::connect(address,protocol,&thread,valid_token).await?;
                    if !matches!(protocol,Protocol::ChannelWs) {
                        revoked.contains("thread_run_event").await?;
                        valid.contains("thread_run_event").await?;
                    }
                    match change {
                        "revoke" => { people.change_access(&ActorId::new("writer"),&ActorId::new(&reader),true).await.map_err(text)?; }
                        "role" => { people.change_role(&ActorId::new("writer"),&ActorId::new(&reader),Role::Admin).await.map_err(text)?; }
                        "signout" => {
                            sign_out(address,&token).await?;
                        }
                        "expiry" => {
                            pool.get().await.map_err(text)?.execute("UPDATE public.sessions SET expires_at=clock_timestamp()+interval '100 milliseconds' WHERE id=$1",&[&format!("session-{index}")]).await.map_err(text)?;
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                        "idle" => {
                            pool.get().await.map_err(text)?.execute("UPDATE public.sessions SET updated_at=clock_timestamp()-interval '9 hours' WHERE id=$1",&[&format!("session-{index}")]).await.map_err(text)?;
                        }
                        "session_null" => {
                            pool.get().await.map_err(text)?.execute("UPDATE public.sessions SET auth_generation=NULL WHERE id=$1",&[&format!("session-{index}")]).await.map_err(text)?;
                        }
                        "database" => {}
                        _ => unreachable!(),
                    }
                    let mut blocked_client = if change=="database" { Some(pool.get().await.map_err(text)?) } else { None };
                    let blocked_tx = if let Some(client) = blocked_client.as_mut() {
                        let tx=client.transaction().await.map_err(text)?;
                        tx.batch_execute("LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE").await.map_err(text)?;
                        Some(tx)
                    } else { None };
                    let member:bool = pool.get().await.map_err(text)?.query_one("SELECT EXISTS(SELECT 1 FROM public.channel_memberships WHERE channel_id='channel' AND user_id=$1)",&[&reader]).await.map_err(text)?.get(0);
                    require(member,"test removed membership instead of exercising real session authorization")?;
                    let claim=runtime.claim_dispatch().await.map_err(text)?.ok_or("missing original dispatch")?;
                    let lease=runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
                    let marker=format!("private-after-{change}-{index}");
                    runtime.append_semantic_chunk(&lease,1,RunSemanticChannel::Text,&marker).await.map_err(text)?;
                    runtime.finish_run(&lease,2,RunTerminal::Completed).await.map_err(text)?;
                    if change=="database" { valid.closed_without(&marker).await?; }
                    else { valid.contains(&marker).await?; }
                    revoked.closed_without(&marker).await?;
                    listener_count(&pool,if change=="database" { 0 } else { 1 }).await?;
                    if let Some(tx)=blocked_tx {
                        tx.rollback().await.map_err(text)?;
                        let mut reconnected=Client::connect(address,protocol,&thread,valid_token).await?;
                        if !matches!(protocol,Protocol::ChannelWs) { reconnected.contains(&marker).await?; }
                        println!("{protocol:?}/{change}: both streams closed without a body; original valid session reconnects after the real rollback");
                        continue;
                    }
                    println!("{protocol:?}/{change}: original stream closed; membership retained; valid session received the new body");
                }
                Ok(())
            }.await;
            resolver.close_request_bindings();
            server.abort();
            let _=server.await;
            if cases.is_ok() {
                listener_count(&pool,0).await?;
            }
            cases
        }.await;
        pool.close();
        result
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL instance"]
async fn thread_sse_rechecks_real_revocation_role_single_logout_and_expiry() {
    matrix(Protocol::Sse).await;
}
#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL instance"]
async fn thread_ws_rechecks_real_revocation_role_single_logout_and_expiry() {
    matrix(Protocol::ThreadWs).await;
}
#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL instance"]
async fn channel_ws_rechecks_real_revocation_role_single_logout_and_expiry() {
    matrix(Protocol::ChannelWs).await;
}
