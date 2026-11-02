//! Real PostgreSQL/Vault/admin transactions and fresh model-credential consumption.

mod harness;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::routing::post;
use openbot_application::credential_admin::{
    CredentialAdministration, CredentialAdministrationError,
};
use openbot_application::{
    ProviderAdapter, ProviderMessage, ProviderMessageRole, ProviderRequest, ProviderRoute,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::credential_admin::{
    CredentialExternalRevocation, CredentialPageRequest, CredentialWrite, ManualCredentialKind,
};
use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
use openbot_domain::vault::{KeyVersion, SecretBytes, SecretKind, SecretPrincipal, WrappingKey};
use openbot_infra::credential_admin::PostgresCredentialAdministration;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::mcp::SafeRmcpClient;
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::mcp_connections::PostgresMcpConnections;
use openbot_infra::mcp_credentials::{McpCredentialError, PostgresMcpCredentialBroker};
use openbot_infra::mcp_oauth::McpOAuthClient;
use openbot_infra::net::safe_http::{
    CidrAllowlist, EgressPolicy, SafeDialer, SafeHttpBudget, SchemePolicy,
};
use openbot_infra::provider::credential::PostgresOpenAiCredentialSource;
use openbot_infra::provider::openai::{OpenAiProtocol, OpenAiProvider, OpenAiProviderConfig};
use openbot_infra::vault::CredentialRecordVault;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

const DEPLOYMENT: &str = "credential-admin-deployment";
const TENANT: &str = "credential-admin-tenant";
const ACTOR: &str = "credential-admin";
const AUDIT_KEY: &[u8] = b"credential-admin-test-key-at-least-32-bytes";

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(ACTOR),
        AuthGeneration::new(0),
        false,
    )
    .with_roles([Role::Admin])
    .build()
}

fn write(
    kind: ManualCredentialKind,
    provider: &str,
    key_id: &str,
    plaintext: &str,
) -> CredentialWrite {
    CredentialWrite::new(
        kind,
        provider.to_owned(),
        key_id.to_owned(),
        json!({"label":"Test label","revocation_status":"caller_metadata_is_not_authority"}),
        Zeroizing::new(plaintext.to_owned()),
    )
    .unwrap()
}

async fn setup(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<(PostgresCredentialAdministration, CredentialRecordVault), String> {
    let mut client = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&client).await.map_err(|e| e.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|e| e.to_string())?;
    client.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('credential-admin','credential-admin@example.test',0); INSERT INTO public.user_roles(user_id,role) VALUES('credential-admin','admin');").await.map_err(|e| e.to_string())?;
    drop(client);
    let vault = CredentialRecordVault::single_key(
        TenantId::new(TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x76; 32]).map_err(|e| e.to_string())?,
    );
    let catalog = Arc::new(
        PostgresMcpCatalog::new(
            pool.clone(),
            SafeRmcpClient::new(
                SafeDialer::new(EgressPolicy::default()),
                SchemePolicy::HttpsOnly,
                Some(Duration::from_secs(2)),
            ),
            AUDIT_KEY.to_vec(),
        )
        .map_err(|e| e.to_string())?,
    );
    let mcp = Arc::new(
        PostgresMcpConnections::new(
            pool.clone(),
            vault.clone(),
            McpOAuthClient::new(
                SafeDialer::new(EgressPolicy::default()),
                SchemePolicy::HttpsOnly,
            ),
            catalog,
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            vec![0x77; 32],
            AUDIT_KEY.to_vec(),
            None,
            None,
            SchemePolicy::HttpsOnly,
            openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                &pool,
                &openbot_contracts::ids::DeploymentId::new("outside"),
                &openbot_contracts::ids::TenantId::new("outside"),
            ),
        )
        .map_err(|e| e.to_string())?,
    );
    let admin = PostgresCredentialAdministration::new(
        pool.clone(),
        vault.clone(),
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        SecretBytes::new(AUDIT_KEY.to_vec()),
        mcp,
    )
    .map_err(|e| e.to_string())?;
    Ok((admin, vault))
}

fn request() -> ProviderRequest {
    ProviderRequest {
        route: ProviderRoute::PackageOpenAi,
        messages: vec![ProviderMessage {
            role: ProviderMessageRole::User,
            content: "test".to_owned(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: Vec::new(),
        }],
        tools: Vec::new(),
        max_output_tokens: Some(8),
        rate_card: None,
        cost_cap: None,
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and loopback sockets; set OPENBOT_TEST_DATABASE_URL"]
async fn model_create_rotate_revoke_are_atomic_and_the_running_provider_reads_the_current_key() {
    let config = harness::admin_config("credential_admin_model");
    harness::with_temp_database(&config, "credmodel", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let (admin, vault) = setup(&pool).await?;
        let outcome = async {
            let seen = Arc::new(Mutex::new(Vec::<String>::new()));
            let capture = seen.clone();
            let router = axum::Router::new().route("/v1/responses", post(move |headers: HeaderMap| {
                let capture = capture.clone(); async move {
                    capture.lock().unwrap().push(headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned());
                    ([("content-type","text/event-stream")], "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_admin\"},\"sequence_number\":0}\n\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"delta\":\"ok\",\"sequence_number\":1}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}},\"sequence_number\":2}\n\n")
                }
            }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
            let address = listener.local_addr().map_err(|e| e.to_string())?;
            let server = tokio::spawn(async move { axum::serve(listener, router).await });
            let provider = OpenAiProvider::new_with_credential_source(
                OpenAiProviderConfig::new_with_transport_policy(url::Url::parse(&format!("http://{address}/v1/responses")).unwrap(), "test".to_owned(), OpenAiProtocol::Responses, SafeHttpBudget::new(64*1024,Duration::from_secs(2)).unwrap(), Some(Duration::from_secs(1)), SchemePolicy::HttpOrHttps).unwrap(),
                Arc::new(PostgresOpenAiCredentialSource::new(pool.clone(), vault.clone(), "primary".to_owned(), None).unwrap()),
                SafeDialer::new(EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap())),
            );
            let created = admin.create(&auth(), &write(ManualCredentialKind::Model, "openai", "primary", "OLD_MODEL_CANARY")).await.map_err(|e| e.to_string())?;
            let mut session = provider.start(request()).await.map_err(|e| e.to_string())?;
            while session.next_event().await.map_err(|e| e.to_string())?.is_some() {}
            let replaced = admin.rotate(&auth(), &created.credential.id, &write(ManualCredentialKind::Model, "openai", "primary", "NEW_MODEL_CANARY")).await.map_err(|e| e.to_string())?;
            let mut session = provider.start(request()).await.map_err(|e| e.to_string())?;
            while session.next_event().await.map_err(|e| e.to_string())?.is_some() {}
            assert_eq!(*seen.lock().unwrap(), ["Bearer OLD_MODEL_CANARY", "Bearer NEW_MODEL_CANARY"]);
            let pg = pool.get().await.map_err(|e| e.to_string())?;
            pg.batch_execute("CREATE FUNCTION reject_credential_rotation_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.event_type='credential.rotated' THEN RAISE EXCEPTION 'audit fault'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_credential_rotation_audit BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION reject_credential_rotation_audit();").await.map_err(|e| e.to_string())?;
            drop(pg);
            assert!(admin.rotate(&auth(), &replaced.credential.id, &write(ManualCredentialKind::Model, "openai", "primary", "ROLLBACK_CANARY")).await.is_err());
            let pg = pool.get().await.map_err(|e| e.to_string())?;
            let rows = pg.query("SELECT id,encrypted_value,revoked_at FROM public.credentials ORDER BY created_at,id", &[]).await.map_err(|e| e.to_string())?;
            assert_eq!(rows.len(),2);
            assert!(rows[0].get::<_,Option<time::OffsetDateTime>>("revoked_at").is_some());
            assert!(rows[1].get::<_,Option<time::OffsetDateTime>>("revoked_at").is_none());
            let id = rows[1].get::<_,Uuid>("id");
            let encrypted = rows[1].get::<_,String>("encrypted_value");
            assert!(!encrypted.contains("CANARY"));
            assert_eq!(vault.open(&id, SecretKind::Model, SecretPrincipal::Deployment, SecretPrincipal::Deployment, &encrypted).unwrap().into_secret().expose(), b"NEW_MODEL_CANARY");
            drop(pg);
            let page = admin.list(&auth(), &CredentialPageRequest::default()).await.map_err(|e| e.to_string())?;
            assert!(!serde_json::to_string(&page).unwrap().contains("CANARY"));
            assert_eq!(page.credentials[1].metadata["revocation_status"], "caller_metadata_is_not_authority");
            let retired = admin.revoke(&auth(), &replaced.credential.id).await.map_err(|e| e.to_string())?;
            assert_eq!(retired.external_revocation, CredentialExternalRevocation::OperatorRequired);
            assert_eq!(admin.revoke(&auth(), &replaced.credential.id).await.unwrap(), retired);
            let mut rejected = provider.start(request()).await.map_err(|e| e.to_string())?;
            assert!(matches!(rejected.next_event().await.unwrap(), Some(openbot_application::ProviderEvent::Failed(openbot_application::ProviderFailure::Authentication))));
            assert_eq!(seen.lock().unwrap().len(), 2);
            server.abort();
            Ok(())
        }.await;
        pool.close(); outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn mcp_reference_and_grants_move_atomically_and_revocation_cannot_enable_anonymous_access() {
    let config = harness::admin_config("credential_admin_mcp");
    harness::with_temp_database(&config,"credmcp",|config| async move {
        let pool = pool::connect(&config).await.map_err(|e| format!("{e:?}"))?;
        let (admin,vault) = setup(&pool).await?;
        let outcome = async {
            let first=admin.create(&auth(),&write(ManualCredentialKind::Mcp,"notes","first","OLD_MCP_CANARY")).await.map_err(|e| format!("{e:?}"))?;
            let id=Uuid::parse_str(&first.credential.id).unwrap();
            let pg=pool.get().await.map_err(|e| format!("{e:?}"))?;
            pg.execute("INSERT INTO public.mcp_servers(id,title,vendor,url,provenance,credential_id,transport,credential_generation,catalog_generation,catalog_hash,catalog_transport_fingerprint) VALUES('notes','Notes','notes.example.test','https://notes.example.test/mcp','custom',$1,'mcp',0,1,repeat('a',64),repeat('b',64))",&[&id]).await.map_err(|e| format!("{e:?}"))?;
            pg.batch_execute("INSERT INTO public.agents(id,name,type,configuration) VALUES('holder','Holder','remote_ag_ui','{}'); INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by,state,catalog_generation,schema_hash,effect,transport_fingerprint,credential_generation) VALUES('mcp','notes/search','holder','credential-admin','active',1,repeat('a',64),'read',repeat('b',64),0);").await.map_err(|e| format!("{e:?}"))?;
            drop(pg);
            let broker=PostgresMcpCredentialBroker::new(pool.clone(),vault, openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")));
            assert!(broker.bearer_for("notes",auth().actor()).await.unwrap().is_some());
            let replaced=admin.rotate(&auth(),&first.credential.id,&write(ManualCredentialKind::Mcp,"notes","second","NEW_MCP_CANARY")).await.map_err(|e| format!("{e:?}"))?;
            let pg=pool.get().await.map_err(|e| format!("{e:?}"))?;
            let row=pg.query_one("SELECT credential_id,credential_generation FROM public.mcp_servers WHERE id='notes'",&[]).await.map_err(|e| format!("{e:?}"))?;
            assert_eq!(row.get::<_,Uuid>(0).to_string(),replaced.credential.id);
            assert_eq!(row.get::<_,i64>(1),1);
            assert_eq!(pg.query_one("SELECT state FROM public.plugin_grants WHERE ref='notes/search'",&[]).await.map_err(|e| format!("{e:?}"))?.get::<_,String>(0),"suspended_missing");
            drop(pg);
            admin.revoke(&auth(),&replaced.credential.id).await.map_err(|e| format!("{e:?}"))?;
            assert!(matches!(broker.bearer_for("notes",auth().actor()).await,Err(McpCredentialError::AuthRequired)));
            let pg=pool.get().await.map_err(|e| format!("{e:?}"))?;
            assert!(pg.query_one("SELECT credential_id IS NOT NULL FROM public.mcp_servers WHERE id='notes'",&[]).await.map_err(|e| format!("{e:?}"))?.get::<_,bool>(0));
            Ok(())
        }.await;
        pool.close();outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn inventory_is_bounded_and_current_scope_and_role_are_rechecked() {
    let config = harness::admin_config("credential_admin_inventory");
    harness::with_temp_database(&config,"credpage",|config| async move {
        let pool=pool::connect(&config).await.map_err(|e| e.to_string())?;
        let (admin,_)=setup(&pool).await?;
        let outcome=async {
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            pg.batch_execute("INSERT INTO public.credentials(kind,provider,key_id,encrypted_value,metadata) SELECT 'model','openai',i::text,'CIPHERTEXT_MUST_NOT_BE_READ','{}' FROM generate_series(1,101) i;").await.map_err(|e| e.to_string())?;
            drop(pg);
            let first=admin.list(&auth(),&CredentialPageRequest::default()).await.map_err(|e| e.to_string())?;
            assert_eq!(first.credentials.len(),100);assert!(first.next_cursor.is_some());
            let second=admin.list(&auth(),&CredentialPageRequest{cursor:first.next_cursor}).await.map_err(|e| e.to_string())?;
            assert_eq!(second.credentials.len(),1);assert!(second.next_cursor.is_none());
            assert!(!first.credentials.iter().any(|r|r.id==second.credentials[0].id));
            let other=AuthContextBuilder::from_verified_session(DeploymentId::new(DEPLOYMENT),TenantId::new("other"),ActorId::new(ACTOR),AuthGeneration::new(0),false).with_roles([Role::Admin]).build();
            assert_eq!(admin.list(&other,&CredentialPageRequest::default()).await.unwrap_err(),CredentialAdministrationError::NotVisible);
            let pg=pool.get().await.map_err(|e| e.to_string())?;
            pg.execute("UPDATE public.users SET auth_generation=1 WHERE id=$1",&[&ACTOR]).await.map_err(|e| e.to_string())?;drop(pg);
            assert_eq!(admin.create(&auth(),&write(ManualCredentialKind::Model,"openai","new","STALE_CANARY")).await.unwrap_err(),CredentialAdministrationError::NotVisible);
            Ok(())
        }.await;
        pool.close();outcome
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn failed_readback_is_invisible_and_concurrent_rotations_have_one_winner() {
    let config = harness::admin_config("credential_admin_atomic_faults");
    harness::with_temp_database(&config,"credfault",|config|async move{
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let (admin,_)=setup(&pool).await?;
        let outcome=async{
            let pg=pool.get().await.map_err(|e|e.to_string())?;
            pg.batch_execute("CREATE FUNCTION corrupt_credential_write() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.encrypted_value='invalid-envelope';RETURN NEW;END$$;CREATE TRIGGER corrupt_credential_write BEFORE INSERT ON public.credentials FOR EACH ROW EXECUTE FUNCTION corrupt_credential_write();").await.map_err(|e|e.to_string())?;drop(pg);
            assert!(admin.create(&auth(),&write(ManualCredentialKind::Model,"openai","fault","READBACK_CANARY")).await.is_err());
            let pg=pool.get().await.map_err(|e|e.to_string())?;
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.credentials",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),0);
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.audit_events",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),0);
            pg.batch_execute("DROP TRIGGER corrupt_credential_write ON public.credentials; DROP FUNCTION corrupt_credential_write();").await.map_err(|e|e.to_string())?;drop(pg);
            let first=admin.create(&auth(),&write(ManualCredentialKind::Model,"openai","race","FIRST_CANARY")).await.map_err(|e|e.to_string())?;
            let actor=auth();let a=write(ManualCredentialKind::Model,"openai","race","A_CANARY");let b=write(ManualCredentialKind::Model,"openai","race","B_CANARY");
            let (a,b)=tokio::join!(admin.rotate(&actor,&first.credential.id,&a),admin.rotate(&actor,&first.credential.id,&b));
            assert_eq!(usize::from(a.is_ok())+usize::from(b.is_ok()),1);
            assert_eq!(usize::from(matches!(a,Err(CredentialAdministrationError::Conflict)))+usize::from(matches!(b,Err(CredentialAdministrationError::Conflict))),1);
            let pg=pool.get().await.map_err(|e|e.to_string())?;
            let row=pg.query_one("SELECT count(*)::bigint,count(*) FILTER(WHERE revoked_at IS NULL)::bigint FROM public.credentials",&[]).await.map_err(|e|e.to_string())?;
            assert_eq!((row.get::<_,i64>(0),row.get::<_,i64>(1)),(2,1));
            assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.audit_events WHERE event_type='credential.rotated'",&[]).await.map_err(|e|e.to_string())?.get::<_,i64>(0),1);
            Ok(())
        }.await;pool.close();outcome
    }).await;
}
