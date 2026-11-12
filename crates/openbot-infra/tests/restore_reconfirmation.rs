//! V7-IMPL-046 retirement, consumer-gate and reconfirmation cases on explicitly
//! owned PostgreSQL 17.11 (spec revision R484, task card section 5.1, INF-R).
#![cfg(feature = "server-runtime")]
#[cfg(not(all(feature = "desktop-local", feature = "server-sso", target_os = "macos")))]
mod harness;
#[cfg(all(feature = "desktop-local", feature = "server-sso", target_os = "macos"))]
use sso_fixture::harness;

// Reuse the existing owned TLS/SAML fixtures and their regressions. Their
// nested tests remain in the reported target denominator.
#[cfg(all(feature = "desktop-local", feature = "server-sso", target_os = "macos"))]
#[path = "dynamic_sso.rs"]
mod sso_fixture;

mod retirement {
    // T046-24 and T046-26 land with the retirement producer batch.
}

mod reconfirm {
    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    mod current_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/restore_current_fixture.rs"
        ));
    }

    #[cfg(all(feature = "desktop-local", feature = "server-sso", target_os = "macos"))]
    mod sso_current {
        use super::current_fixture::CurrentFixture;
        use crate::sso_fixture;
        use openbot_contracts::ids::ActorId;
        use openbot_infra::auth::oidc::{ProviderId, session_issuer::OriginalLoginRequest};
        use openbot_infra::auth::sso::{
            DynamicSsoService, DynamicSsoStart, RegisterIdentityProviderInput,
        };
        use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;
        use uuid::Uuid;

        // An owned wire fault changes the row in the original transaction
        // only at its post-response SELECT. This avoids inventing a natural
        // concurrent UPDATE that could bypass the real FOR UPDATE lock.
        struct RecheckRelay {
            port: u16,
            task: tokio::task::JoinHandle<()>,
        }
        impl RecheckRelay {
            async fn start(port: u16, armed: Arc<AtomicBool>, rewrites: Arc<AtomicUsize>) -> Self {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let exposed = listener.local_addr().unwrap().port();
                let task = tokio::spawn(async move {
                    let mut children = tokio::task::JoinSet::new();
                    loop {
                        let (client, _) = listener.accept().await.unwrap();
                        let server = tokio::net::TcpStream::connect(("127.0.0.1", port))
                            .await
                            .unwrap();
                        let (armed, rewrites) = (armed.clone(), rewrites.clone());
                        children.spawn(async move {
                            let (mut cr,mut cw)=client.into_split();let (mut sr,mut sw)=server.into_split();
                            let frontend=async {
                                loop {
                                    let length=cr.read_u32().await?;
                                    if !(4..=16*1024*1024).contains(&length) {return Err::<(),_>(std::io::Error::other("owned startup frame"));}
                                    let mut payload=vec![0;(length-4) as usize];cr.read_exact(&mut payload).await?;
                                    sw.write_u32(length).await?;sw.write_all(&payload).await?;
                                    if !(length==8 && payload==80877103u32.to_be_bytes()) {break;}
                                }
                                loop {
                                    let kind=cr.read_u8().await?;let length=cr.read_u32().await?;
                                    if !(4..=16*1024*1024).contains(&length) {return Err::<(),_>(std::io::Error::other("owned query frame"));}
                                    let mut payload=vec![0;(length-4) as usize];cr.read_exact(&mut payload).await?;
                                    if kind==b'P' {
                                        let start=payload.iter().position(|b|*b==0).unwrap()+1;
                                        let end=start+payload[start..].iter().position(|b|*b==0).unwrap();
                                        if &payload[start..end]==b"SELECT id FROM public.sso_providers WHERE provider_id=$1" && armed.swap(false,Ordering::SeqCst) {
                                            let sql=format!("WITH changed AS (UPDATE public.sso_providers SET id='{}' WHERE provider_id=$1 RETURNING id) SELECT id FROM changed",Uuid::now_v7());
                                            payload.splice(start..end,sql.bytes());
                                            rewrites.fetch_add(1,Ordering::SeqCst);
                                        }
                                    }
                                    sw.write_u8(kind).await?;sw.write_u32(u32::try_from(payload.len()+4).unwrap()).await?;sw.write_all(&payload).await?;
                                }
                            };
                            let backend=tokio::io::copy(&mut sr,&mut cw);
                            tokio::select! {_=frontend=>(),_=backend=>()}
                        });
                    }
                });
                Self {
                    port: exposed,
                    task,
                }
            }
        }
        impl Drop for RecheckRelay {
            fn drop(&mut self) {
                self.task.abort();
            }
        }

        async fn count(f: &CurrentFixture, table: &str) -> i64 {
            f.pool
                .get()
                .await
                .unwrap()
                .query_one(&format!("SELECT count(*)::bigint FROM {table}"), &[])
                .await
                .unwrap()
                .get(0)
        }
        async fn confirm_fixture(f: &CurrentFixture, id: Uuid) {
            f.pool.get().await.unwrap().execute("INSERT INTO openbot_internal.restore_reconfirm_receipts(operation_id,epoch,requirement_id,confirmation_id,proof_ref,confirmed_by,proof_kind) VALUES($1,$2,$3,$4,$5,'admin','fresh_actor')",
                &[&Uuid::from_bytes(f.cohort.operation_id),&f.cohort.epoch.as_slice(),&id,&Uuid::now_v7(),&Uuid::now_v7()]).await.unwrap();
        }
        async fn oidc_attempt(
            service: &DynamicSsoService,
            params: &Arc<Mutex<Option<sso_fixture::OidcAuthorizationParams>>>,
            now: time::OffsetDateTime,
        ) -> String {
            let route = service
                .route_email("person@oidc.example", "203.0.113.7", now)
                .await
                .unwrap();
            let DynamicSsoStart::Oidc(url) = service
                .continue_route(route.ticket(), "203.0.113.7", now)
                .await
                .unwrap()
            else {
                panic!("OIDC start");
            };
            let query: std::collections::BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            *params.lock().unwrap() = Some(sso_fixture::OidcAuthorizationParams {
                nonce: query["nonce"].clone(),
                challenge: query["code_challenge"].clone(),
            });
            query["state"].clone()
        }
        fn login() -> OriginalLoginRequest {
            OriginalLoginRequest::new(
                Instant::now() + Duration::from_secs(20),
                CancellationToken::new(),
            )
        }

        pub(super) async fn run() {
            let (armed, rewrites) = (
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicUsize::new(0)),
            );
            let mut relay = None;
            let fixture=CurrentFixture::with_port("INSERT INTO public.users(id,email,email_verified,auth_generation) VALUES('admin','admin@example.com',true,1); INSERT INTO public.user_roles(user_id,role) VALUES('admin','admin');",
                async |port| {let proxy=RecheckRelay::start(port,armed.clone(),rewrites.clone()).await;let exposed=proxy.port;relay=Some(proxy);exposed}).await;
            let now = time::OffsetDateTime::from_unix_timestamp(sso_fixture::NOW).unwrap();
            let client = fixture.pool.get().await.unwrap();
            let old = Uuid::now_v7().to_string();
            let legacy=serde_json::json!({"entryPoint":"https://idp.example/sso","idpMetadata":{"metadata":sso_fixture::metadata()},"emailAttribute":"email","groupAttribute":"groups","groupNormalization":"trim_lowercase"}).to_string();
            client.execute("INSERT INTO public.sso_providers(id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) VALUES($1,'urn:example:idp:directory',NULL,$2,'admin','legacy-saml',NULL,'legacy.example')",&[&old,&legacy]).await.unwrap();
            let requirement = fixture.requirement("sso_provider", &old).await;
            let service = sso_fixture::service_with_gate(
                &fixture.pool,
                SafeDialer::new(EgressPolicy::default()),
                fixture.runtime.as_ref().unwrap().read_gate(),
            );
            let denied = service.preflight_all(now).await.unwrap_err();
            assert!(denied.to_string().contains("dependency_unavailable"));
            assert_eq!(
                client
                    .query_one(
                        "SELECT saml_config FROM public.sso_providers WHERE id=$1",
                        &[&old]
                    )
                    .await
                    .unwrap()
                    .get::<_, String>(0),
                legacy,
                "unconfirmed root never reaches migration/open"
            );
            assert_eq!(count(&fixture, "public.sessions").await, 0);
            confirm_fixture(&fixture, requirement).await;
            service.preflight_all(now).await.unwrap();
            service.preflight_all(now).await.unwrap();
            let row=client.query_one("SELECT id,saml_config FROM public.sso_providers WHERE provider_id='legacy-saml'",&[]).await.unwrap();
            assert_eq!(row.get::<_, String>(0), old);
            assert!(row.get::<_, String>(1).starts_with("{\"version\":2"));
            assert_eq!(
                count(&fixture, "openbot_internal.restore_reconfirm_requirements").await,
                1
            );
            let route = service
                .route_email("person@legacy.example", "203.0.113.8", now)
                .await
                .unwrap();
            let (_, saml) = sso_fixture::start(&service, "person@legacy.example", now)
                .await
                .unwrap();
            service
                .update(
                    sso_fixture::registration("legacy-saml", "changed.example"),
                    &ActorId::new("admin"),
                    now,
                )
                .await
                .unwrap();
            let changed: String = client
                .query_one(
                    "SELECT id FROM public.sso_providers WHERE provider_id='legacy-saml'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_ne!(changed, old);
            client.batch_execute("UPDATE public.sso_providers SET saml_config='not-a-vault' WHERE provider_id='legacy-saml'").await.unwrap();
            assert!(
                service
                    .continue_route(route.ticket(), "203.0.113.8", now)
                    .await
                    .err()
                    .expect("old route is unavailable")
                    .to_string()
                    .contains("provider_unknown")
            );
            assert!(
                service
                    .continue_route(route.ticket(), "203.0.113.8", now)
                    .await
                    .is_err(),
                "old route was burned"
            );
            let provider = ProviderId::parse("legacy-saml").unwrap();
            assert!(
                service
                    .saml_callback(
                        &provider,
                        &saml,
                        "not-a-saml-response",
                        now,
                        "203.0.113.9",
                        None
                    )
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("provider_unknown"),
                "SAML compares before loading corrupt configuration"
            );
            assert!(
                service
                    .saml_callback(
                        &provider,
                        &saml,
                        "not-a-saml-response",
                        now,
                        "203.0.113.9",
                        None
                    )
                    .await
                    .is_err(),
                "old SAML state was burned"
            );
            assert_eq!(count(&fixture, "public.sessions").await, 0);

            let params = Arc::new(Mutex::new(None));
            let calls = Arc::new(AtomicUsize::new(0));
            let (address, root, server) =
                sso_fixture::spawn_oidc_idp_requests(params.clone(), calls.clone(), 20)
                    .await
                    .unwrap();
            let dialer = SafeDialer::with_extra_roots(
                EgressPolicy::new(CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap()),
                Arc::new(sso_fixture::LocalResolver(address)),
                [root],
            )
            .unwrap();
            let oidc = sso_fixture::service_with_gate(
                &fixture.pool,
                dialer,
                fixture.runtime.as_ref().unwrap().read_gate(),
            );
            let origin = format!("https://idp.test:{}", address.port());
            let input = |domain: &str| -> RegisterIdentityProviderInput {
                serde_json::from_value(serde_json::json!({"providerId":"acme-oidc","issuer":origin,"domain":domain,
                "oidcConfig":{"clientId":"acme-client","clientSecret":"acme-secret","discoveryEndpoint":format!("{origin}/.well-known/openid-configuration"),"groupClaimPath":"groups","groupNormalization":"trim_lowercase"}})).unwrap()
            };
            oidc.register(input("oidc.example"), &ActorId::new("admin"), now)
                .await
                .unwrap();
            let id: String = client
                .query_one(
                    "SELECT id FROM public.sso_providers WHERE provider_id='acme-oidc'",
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            confirm_fixture(&fixture, fixture.requirement("sso_provider", &id).await).await;
            let provider = ProviderId::parse("acme-oidc").unwrap();
            let state = oidc_attempt(&oidc, &params, now).await;
            oidc.oidc_callback(
                &provider,
                &state,
                "valid-code",
                now,
                "203.0.113.7",
                None,
                login(),
            )
            .await
            .unwrap();
            assert_eq!(count(&fixture, "public.sessions").await, 1);
            assert_eq!(
                client
                    .query_one(
                        "SELECT id FROM public.sso_providers WHERE provider_id='acme-oidc'",
                        &[]
                    )
                    .await
                    .unwrap()
                    .get::<_, String>(0),
                id
            );
            assert_eq!(
                count(&fixture, "openbot_internal.restore_reconfirm_requirements").await,
                2,
                "normal discovery/JWKS refresh preserves the root"
            );
            let state = oidc_attempt(&oidc, &params, now).await;
            armed.store(true, Ordering::SeqCst);
            let error = oidc
                .oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    None,
                    login(),
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("provider_mismatch"),
                "post-response row replacement: {error}"
            );
            assert_eq!(rewrites.load(Ordering::SeqCst), 1);
            assert_eq!(count(&fixture, "public.sessions").await, 1);
            let before = calls.load(Ordering::SeqCst);
            assert!(
                oidc.oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    None,
                    login()
                )
                .await
                .is_err()
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                before,
                "burned attempt sends nothing again"
            );
            let state = oidc_attempt(&oidc, &params, now).await;
            oidc.update(input("oidc.changed"), &ActorId::new("admin"), now)
                .await
                .unwrap();
            assert_ne!(
                client
                    .query_one(
                        "SELECT id FROM public.sso_providers WHERE provider_id='acme-oidc'",
                        &[]
                    )
                    .await
                    .unwrap()
                    .get::<_, String>(0),
                id
            );
            assert_eq!(
                count(&fixture, "public.sessions").await,
                0,
                "semantic update retires the old linked session"
            );
            let before = calls.load(Ordering::SeqCst);
            assert!(
                oidc.oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    None,
                    login()
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("provider_unknown")
            );
            assert!(
                oidc.oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    None,
                    login()
                )
                .await
                .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), before);
            assert_eq!(count(&fixture, "public.sessions").await, 0);
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            drop(client);
            drop(oidc);
            drop(service);
            drop(fixture);
            drop(relay);
        }
    }

    #[cfg(all(feature = "desktop-local", feature = "server-sso", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 and TLS; actual Current SSO incarnation checks"]
    async fn t046_33_sso_semantic_update_rotates_id_rewrap_and_refresh_do_not() {
        sso_current::run().await;
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    mod sdk_current {
        use super::current_fixture::{AUDIT_KEY, CurrentFixture, DEP, TENANT};
        use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
        use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
        use openbot_contracts::recovery::RecoveryAdmissionLease;
        use openbot_contracts::request_binding::{
            HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
            RequestBindingOwnerLease, ServerSessionBindingIdentity, VerifiedHostRequestBinding,
        };
        use openbot_domain::vault::{
            KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
        };
        use openbot_infra::db::pool::DatabasePool;
        use openbot_infra::recovery_control::RecoveryReadGate;
        use openbot_infra::restore_reconfirmation::{
            CancellationToken, OriginalReconfirmationRequest, RestoreReconfirmation,
        };
        use openbot_infra::vault::CredentialRecordVault;
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use uuid::Uuid;

        struct SessionGuard {
            pool: DatabasePool,
            gate: RecoveryReadGate,
            auth: AuthContext,
            id: String,
            token: String,
            _owner: RequestBindingOwnerLease,
        }
        impl SessionGuard {
            async fn current(
                &self,
                auth: &AuthContext,
                deadline: Instant,
            ) -> Result<(), HostRequestBindingError> {
                if auth != &self.auth || Instant::now() >= deadline {
                    return Err(HostRequestBindingError::NotCurrent);
                }
                let client = self
                    .pool
                    .get()
                    .await
                    .map_err(|_| HostRequestBindingError::Unavailable)?;
                let current:bool=client.query_one("SELECT EXISTS(SELECT 1 FROM public.sessions s JOIN public.users u ON u.id=s.user_id WHERE s.id=$1 AND s.token=$2 AND s.user_id=$3 AND s.auth_generation=1 AND u.auth_generation=1 AND s.expires_at>clock_timestamp())",&[&self.id,&self.token,&auth.actor().as_str()])
                    .await.map_err(|_|HostRequestBindingError::Unavailable)?.get(0);
                if current && Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(HostRequestBindingError::NotCurrent)
                }
            }
        }
        impl HostRequestBindingGuard for SessionGuard {
            fn verify_current<'a>(
                &'a self,
                auth: &'a AuthContext,
            ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
            {
                Box::pin(self.current(auth, Instant::now() + Duration::from_secs(5)))
            }
            fn verify_current_before<'a>(
                &'a self,
                auth: &'a AuthContext,
                deadline: Instant,
            ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
            {
                Box::pin(self.current(auth, deadline))
            }
            fn borrow_restore_reconfirmation_before<'a>(
                &'a self,
                binding: &'a VerifiedHostRequestBinding,
                auth: &'a AuthContext,
                deadline: Instant,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<RecoveryAdmissionLease<'a>, HostRequestBindingError>>
                        + Send
                        + 'a,
                >,
            > {
                Box::pin(
                    self.gate
                        .borrow_reconfirmation_before(binding, auth, deadline),
                )
            }
        }

        async fn snapshot(pool: &DatabasePool, id: Uuid) -> serde_json::Value {
            pool.get().await.unwrap().query_one("SELECT jsonb_build_object(
                'connection',(SELECT to_jsonb(c) FROM public.sdk_gateway_connections c WHERE id=$1),
                'secrets',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM public.sdk_gateway_secrets s WHERE connection_id=$1),
                'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY id),'[]'::jsonb) FROM public.sdk_gateway_operations o WHERE connection_id=$1),
                'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY requirement_id),'[]'::jsonb) FROM openbot_internal.restore_reconfirm_receipts r),
                'audits',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM public.audit_events a))",&[&id]).await.unwrap().get(0)
        }

        pub(super) async fn run() {
            let fixture=CurrentFixture::new("INSERT INTO public.users(id,email,email_verified,auth_generation) VALUES('sdk-restored-owner','sdk-restored-owner@example.test',true,1); INSERT INTO public.user_roles(user_id,role) VALUES('sdk-restored-owner','admin');").await;
            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
            );
            let gate = fixture.runtime.as_ref().unwrap().read_gate();
            let adapter = RestoreReconfirmation::new(
                fixture.pool.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                openbot_infra::auth::config::default_session_lifetime(),
                SecretBytes::new(AUDIT_KEY.to_vec()),
                vault.clone(),
                &gate,
            )
            .unwrap();
            let auth = AuthContextBuilder::from_verified_session(
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                ActorId::new("sdk-restored-owner"),
                AuthGeneration::new(1),
                false,
            )
            .with_role(Role::Admin)
            .build();
            let (owner, issuer) =
                RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
            adapter.enroll_host_issuer(&issuer).unwrap();
            let session = Uuid::now_v7().to_string();
            let token = "owned-current-sdk-session-column".to_owned();
            let client = fixture.pool.get().await.unwrap();
            let created=client.query_one("INSERT INTO public.sessions(id,token,user_id,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,'sdk-restored-owner',clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '1 hour',1) RETURNING created_at",&[&session,&token]).await.unwrap().get(0);
            let identity = ServerSessionBindingIdentity::from_verified_row(
                session.clone(),
                auth.actor().clone(),
                token.clone(),
                created,
                auth.auth_generation(),
            );
            let guard = Arc::new(SessionGuard {
                pool: fixture.pool.clone(),
                gate,
                auth: auth.clone(),
                id: session,
                token,
                _owner: owner,
            });
            let binding = issuer.bind_server_session(&auth, identity, guard).unwrap();
            let auth = auth.with_verified_request_binding(binding).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!(
                "https://127.0.0.1:{}",
                listener.local_addr().unwrap().port()
            );
            for state in ["pending", "staged", "unknown", "ready"] {
                let (id, secret, operation, candidate) = (
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                );
                let tokens = serde_json::json!({"access_token":"RESTORED_ACCESS_CANARY","refresh_token":"RESTORED_REFRESH_CANARY","expires_at":"2028-01-01T00:00:00Z","scope":"ai account","client_id":"restored-client","server_url":endpoint});
                let envelope = serde_json::json!({"schemaVersion":1,"connectionId":id,"credentialGeneration":1,"authGeneration":0,"issuer":endpoint,"accountId":"restored-account","organizationId":null,"clientId":"restored-client","tokens":tokens});
                let sealed = vault
                    .seal(
                        &secret,
                        SecretKind::Model,
                        SecretPrincipal::Actor(auth.actor().clone()),
                        SecretPrincipal::Service(ServiceId::new(id.to_string())),
                        &SecretBytes::new(serde_json::to_vec(&envelope).unwrap()),
                    )
                    .unwrap();
                let mut c = fixture.pool.get().await.unwrap();
                let tx = c.transaction().await.unwrap();
                tx.execute("INSERT INTO public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id,name,issuer,client_id,account_id,organization_id,auth_contract_version,error_contract_version,enabled,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id,created_at,updated_at) VALUES($1,$2,$3,$4,'Restored SDK',$5,'restored-client','restored-account',NULL,2,1,true,1,1,0,$6,$7,$8,clock_timestamp(),clock_timestamp())",
                    &[&id,&DEP,&TENANT,&auth.actor().as_str(),&endpoint,&if state=="ready"{"ready"}else{"rotation_pending"},&secret,&(state!="ready").then_some(operation)]).await.unwrap();
                tx.execute("INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,1,$6,clock_timestamp())",&[&secret,&id,&DEP,&TENANT,&auth.actor().as_str(),&sealed]).await.unwrap();
                if state == "staged" {
                    tx.execute("INSERT INTO public.sdk_gateway_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,credential_generation,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,2,$6,clock_timestamp())",&[&candidate,&id,&DEP,&TENANT,&auth.actor().as_str(),&sealed]).await.unwrap();
                }
                if state != "ready" {
                    tx.execute("INSERT INTO public.sdk_gateway_operations(id,connection_id,deployment_id,tenant_id,owner_user_id,expected_revision,auth_generation,from_generation,to_generation,state,candidate_secret_id,token_admitted_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,0,1,2,$6,$7,CASE WHEN $8 THEN clock_timestamp() ELSE NULL END,clock_timestamp(),clock_timestamp())",
                        &[&operation,&id,&DEP,&TENANT,&auth.actor().as_str(),&if state=="staged"{"staged"}else{"pending"},&(state=="staged").then_some(candidate),&matches!(state,"staged"|"unknown")]).await.unwrap();
                }
                tx.commit().await.unwrap();
                drop(c);
                let requirement = fixture.requirement("sdk_secret", &id.to_string()).await;
                let before = snapshot(&fixture.pool, id).await;
                if state == "ready" {
                    client.batch_execute("CREATE FUNCTION public.reject_owned_sdk_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned_receipt_commit_refused'; END $$; CREATE CONSTRAINT TRIGGER reject_owned_sdk_receipt AFTER INSERT ON openbot_internal.restore_reconfirm_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.reject_owned_sdk_receipt()").await.unwrap();
                }
                let due = Instant::now() + Duration::from_secs(20);
                let confirmation = adapter
                    .prepare_server_confirmation(&auth, requirement, due)
                    .await
                    .unwrap();
                assert!(
                    adapter
                        .confirm_current_binding(
                            confirmation,
                            OriginalReconfirmationRequest::new(due, CancellationToken::new())
                        )
                        .await
                        .is_err(),
                    "{state}"
                );
                assert_eq!(
                    snapshot(&fixture.pool, id).await,
                    before,
                    "failed confirmation is atomic: {state}"
                );
                if state == "ready" {
                    client.batch_execute("DROP TRIGGER reject_owned_sdk_receipt ON openbot_internal.restore_reconfirm_receipts; DROP FUNCTION public.reject_owned_sdk_receipt()").await.unwrap();
                    let due = Instant::now() + Duration::from_secs(20);
                    let confirmation = adapter
                        .prepare_server_confirmation(&auth, requirement, due)
                        .await
                        .unwrap();
                    let fact = adapter
                        .confirm_current_binding(
                            confirmation,
                            OriginalReconfirmationRequest::new(due, CancellationToken::new()),
                        )
                        .await
                        .unwrap();
                    assert_eq!(fact.requirement_id(), requirement);
                    let row=client.query_one("SELECT c.auth_generation,c.credential_generation,c.current_secret_id,c.pending_operation_id,s.encrypted_value,c.xmin::text=r.xact_id::text,a.xmin::text=r.xact_id::text FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id JOIN openbot_internal.restore_reconfirm_receipts r ON r.requirement_id=$2 JOIN public.audit_events a ON a.target_id=c.id::text AND a.target_type='sdk_gateway_connection' WHERE c.id=$1",&[&id,&requirement]).await.unwrap();
                    assert_eq!(row.get::<_, i64>(0), 1);
                    assert_eq!(row.get::<_, i64>(1), 1);
                    assert_eq!(row.get::<_, Uuid>(2), secret);
                    assert!(row.get::<_, Option<Uuid>>(3).is_none());
                    assert!(
                        row.get::<_, bool>(5) && row.get::<_, bool>(6),
                        "connection, receipt and audit share the real transaction"
                    );
                    let after: String = row.get(4);
                    assert_ne!(after, sealed);
                    let opened = vault
                        .open(
                            &secret,
                            SecretKind::Model,
                            SecretPrincipal::Actor(auth.actor().clone()),
                            SecretPrincipal::Service(ServiceId::new(id.to_string())),
                            &after,
                        )
                        .unwrap()
                        .into_secret();
                    let actual: serde_json::Value =
                        serde_json::from_slice(opened.expose()).unwrap();
                    assert_eq!(actual["authGeneration"], 1);
                    assert_eq!(actual["tokens"], tokens);
                }
                assert!(
                    tokio::time::timeout(Duration::from_millis(25), listener.accept())
                        .await
                        .is_err(),
                    "reconfirmation sent an SDK request: {state}"
                );
            }
            drop(client);
        }
    }

    #[cfg(all(feature = "desktop-local", target_os = "macos"))]
    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 tools; actual Current and atomic READY reconfirmation"]
    async fn t046_34_sdk_ready_reconfirmation_updates_authgen_receipt_audit_in_one_transaction() {
        sdk_current::run().await;
    }
}

mod consumers {
    use super::harness;
    use openbot_application::model_connections::{
        ModelConnectionAdministration, ModelConnectionError,
    };
    use openbot_application::{McpConnectionAdministration, McpConnectionError};
    use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use openbot_contracts::mcp::McpOAuthReturnTo;
    use openbot_contracts::model_connections::{
        CreateModelConnection, CustomModelProtocol, ModelApiKey, UpdateModelConnection,
    };
    use openbot_contracts::recovery::{
        RecoveryAdmissionLease, RecoveryAdmissionPurpose, RecoveryAdmissionWitness,
        RestoreCohortRef,
    };
    use openbot_contracts::request_binding::{
        HostRequestBindingError, HostRequestBindingGuard, HostRequestBindingKind,
        RequestBindingOwnerLease, ServerSessionBindingIdentity, VerifiedHostRequestBinding,
    };
    use openbot_domain::vault::{
        KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
    };
    use openbot_infra::db::{fresh, pool};
    use openbot_infra::mcp::SafeRmcpClient;
    use openbot_infra::mcp_catalog::PostgresMcpCatalog;
    use openbot_infra::mcp_connections::PostgresMcpConnections;
    use openbot_infra::mcp_oauth::McpOAuthClient;
    use openbot_infra::model_connections::PostgresModelConnections;
    use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer, SchemePolicy};
    use openbot_infra::recovery_control::RecoveryReadGate;
    use openbot_infra::vault::CredentialRecordVault;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use uuid::Uuid;
    use zeroize::Zeroizing;

    type TestResult<T = ()> = Result<T, String>;
    const DEP: &str = "restore-consumer-deployment";
    const TENANT: &str = "restore-consumer-tenant";
    const ACTOR: &str = "restore-consumer-actor";
    const SERVER: &str = "restore-consumer-notes";
    const AUDIT_KEY: &[u8] = b"restore-consumer-audit-key-at-least-32-bytes";

    fn text(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }

    fn require(value: bool, reason: &'static str) -> TestResult {
        if value {
            Ok(())
        } else {
            Err(reason.to_owned())
        }
    }

    /// A synthetic host whose Normal admission carries `cohort`, exactly as a
    /// lease borrowed under a published RestoreCurrent (`Some`) or an ordinary
    /// / outside-domain runtime (`None`) would. It grants nothing else.
    fn admitted(cohort: Option<RestoreCohortRef>) -> AuthContext {
        let auth = AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            ActorId::new(ACTOR),
            AuthGeneration::new(0),
            false,
        )
        .with_roles([Role::User, Role::Admin])
        .build();
        let (owner, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        let identity = ServerSessionBindingIdentity::from_verified_row(
            "restore-consumer-session".into(),
            auth.actor().clone(),
            "restore-consumer-column".into(),
            time::OffsetDateTime::UNIX_EPOCH,
            auth.auth_generation(),
        );
        let guard = Arc::new(CohortGuard {
            auth: auth.clone(),
            cohort,
            _owner: owner,
        });
        let binding = issuer
            .bind_server_session(&auth, identity, guard)
            .expect("the synthetic session matches its own context");
        auth.with_verified_request_binding(binding)
            .expect("the synthetic binding matches its own context")
    }

    struct CohortGuard {
        auth: AuthContext,
        cohort: Option<RestoreCohortRef>,
        _owner: RequestBindingOwnerLease,
    }

    struct CohortAdmission {
        auth: AuthContext,
        cohort: Option<RestoreCohortRef>,
    }

    impl RecoveryAdmissionWitness for CohortAdmission {
        fn purpose(&self) -> RecoveryAdmissionPurpose {
            RecoveryAdmissionPurpose::Normal
        }

        fn verify_current_before(
            &self,
            _binding: &VerifiedHostRequestBinding,
            auth: &AuthContext,
            deadline: Instant,
        ) -> Result<(), HostRequestBindingError> {
            if Instant::now() >= deadline {
                Err(HostRequestBindingError::Unavailable)
            } else if auth == &self.auth {
                Ok(())
            } else {
                Err(HostRequestBindingError::NotCurrent)
            }
        }

        fn restore_cohort(&self) -> Option<RestoreCohortRef> {
            self.cohort
        }
    }

    impl HostRequestBindingGuard for CohortGuard {
        fn verify_current<'a>(
            &'a self,
            auth: &'a AuthContext,
        ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>>
        {
            Box::pin(async move {
                if auth == &self.auth {
                    Ok(())
                } else {
                    Err(HostRequestBindingError::NotCurrent)
                }
            })
        }

        fn borrow_recovery_admission_before<'a>(
            &'a self,
            _binding: &'a VerifiedHostRequestBinding,
            auth: &'a AuthContext,
            deadline: Instant,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<RecoveryAdmissionLease<'a>, HostRequestBindingError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let admission = CohortAdmission {
                    auth: self.auth.clone(),
                    cohort: self.cohort,
                };
                admission.verify_current_before(_binding, auth, deadline)?;
                Ok(Box::new(admission) as RecoveryAdmissionLease<'a>)
            })
        }
    }

    async fn owned<F, Fut>(tag: &str, body: F)
    where
        F: FnOnce(pool::DatabasePool) -> Fut,
        Fut: Future<Output = TestResult>,
    {
        let admin = harness::admin_config(tag);
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        harness::with_temp_database(&admin, tag, |config| async move {
            let p = pool::connect(&config.with_max_pool_size(4))
                .await
                .map_err(text)?;
            let result = async {
                let mut c = p.get().await.map_err(text)?;
                fresh::apply(&mut c).await.map_err(text)?;
                c.execute(
                    "INSERT INTO public.users(id,email,auth_generation) VALUES($1,'restore-consumer@example.test',0)",
                    &[&ACTOR],
                )
                .await
                .map_err(text)?;
                c.batch_execute(&format!(
                    "INSERT INTO public.user_roles(user_id,role) VALUES('{ACTOR}','user'),('{ACTOR}','admin')"
                ))
                .await
                .map_err(text)?;
                drop(c);
                body(p.clone()).await
            }
            .await;
            p.close();
            result
        })
        .await;
    }

    /// One restore operation row of this very database, the cohort's anchor.
    async fn operation(p: &pool::DatabasePool, epoch_byte: u8) -> TestResult<RestoreCohortRef> {
        let cohort = RestoreCohortRef {
            operation_id: *Uuid::now_v7().as_bytes(),
            epoch: [epoch_byte; 32],
        };
        p.get().await.map_err(text)?.execute(
            "INSERT INTO openbot_internal.restore_pg_operations(operation_id,epoch,candidate_generation,source_bundle_id,
               deployment_id,tenant_id,dataset_id,source_installation_id,target_installation_id,candidate_database_oid,
               pg_system_identifier,profile_binding,max_batches,max_requirements)
             SELECT $1,$2,$3,$4,$5,$6,'0123456789abcdef0123456789abcdef','source','target',
               (SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
               (SELECT system_identifier::text FROM pg_catalog.pg_control_system()),$7,64,64",
            &[
                &Uuid::from_bytes(cohort.operation_id),
                &cohort.epoch.as_slice(),
                &Uuid::now_v7(),
                &Uuid::now_v7(),
                &DEP,
                &TENANT,
                &[7u8; 32].as_slice(),
            ],
        )
        .await
        .map_err(text)?;
        Ok(cohort)
    }

    /// An unconfirmed latest generation for one source. The binding producer
    /// (the candidate retirement transaction) is not this test's subject, so
    /// the fixture writes the row with that producer's insert check suspended;
    /// with no receipt the readback is "not confirmed" whatever the binding.
    async fn unconfirmed(
        p: &pool::DatabasePool,
        cohort: RestoreCohortRef,
        seq: i64,
        kind: &str,
        source: &str,
        owner_kind: &str,
        owner: &str,
    ) -> TestResult {
        let c = p.get().await.map_err(text)?;
        c.batch_execute("ALTER TABLE openbot_internal.restore_reconfirm_requirements DISABLE TRIGGER restore_reconfirm_requirements_insert")
            .await
            .map_err(text)?;
        let inserted = c.execute(
            "INSERT INTO openbot_internal.restore_reconfirm_requirements(operation_id,epoch,requirement_id,requirement_seq,
               source_kind,source_ref,binding_generation,public_binding,owner_kind,owner_id)
             VALUES($1,$2,$3,$4,$5,$6,0,$7,$8,$9)",
            &[
                &Uuid::from_bytes(cohort.operation_id),
                &cohort.epoch.as_slice(),
                &Uuid::now_v7(),
                &seq,
                &kind,
                &source,
                &[9u8; 32].as_slice(),
                &owner_kind,
                &owner,
            ],
        )
        .await
        .map_err(text);
        c.batch_execute("ALTER TABLE openbot_internal.restore_reconfirm_requirements ENABLE TRIGGER restore_reconfirm_requirements_insert")
            .await
            .map_err(text)?;
        require(inserted? == 1, "requirement fixture row missing")
    }

    /// Loopback endpoint that only counts actual TCP accepts.
    async fn counting_listener() -> TestResult<(u16, Arc<AtomicUsize>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(text)?;
        let port = listener.local_addr().map_err(text)?.port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = accepts.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Ok((port, accepts))
    }

    async fn accepts_after(accepts: &AtomicUsize, before: usize) -> usize {
        let until = Instant::now() + Duration::from_secs(3);
        while accepts.load(Ordering::SeqCst) == before && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        accepts.load(Ordering::SeqCst)
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_32_unconfirmed_credentials_open_no_vault_and_send_nothing() {
        owned("t046_32_unconfirmed", |p| async move {
            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x46; 32]).map_err(text)?,
            );
            // Credential: the MCP OAuth client opened by begin_oauth before discovery.
            let (port, accepts) = counting_listener().await?;
            let client_id = Uuid::now_v7();
            let body = serde_json::to_vec(&serde_json::json!({"clientId":"restore-client","clientSecret":"restore-secret",
                "issuer":format!("http://127.0.0.1:{port}"),"tokenEndpointAuthMethod":"client_secret_basic"}))
                .map_err(text)?;
            let cipher = vault
                .seal(
                    &client_id,
                    SecretKind::McpOauthClient,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Service(ServiceId::new(SERVER)),
                    &SecretBytes::new(body),
                )
                .map_err(text)?;
            let c = p.get().await.map_err(text)?;
            c.execute("INSERT INTO public.credentials(id,kind,provider,key_id,encrypted_value,metadata) VALUES($1,'mcp_oauth_client',$2,'oauth-client',$3,'{}')",
                &[&client_id, &SERVER, &cipher]).await.map_err(text)?;
            c.execute("INSERT INTO public.mcp_servers(id,title,vendor,url,provenance,transport,credential_id,credential_generation,egress_allow_cidrs)
                VALUES($1,'Restore Notes','test',$2,'custom','mcp',$3,0,ARRAY['127.0.0.1/32'])",
                &[&SERVER, &format!("http://127.0.0.1:{port}/mcp"), &client_id]).await.map_err(text)?;
            drop(c);
            let gate = RecoveryReadGate::outside_recovery_domain(
                &p,
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            );
            let catalog = Arc::new(
                PostgresMcpCatalog::new(
                    p.clone(),
                    SafeRmcpClient::new(
                        SafeDialer::new(EgressPolicy::default()),
                        SchemePolicy::HttpOrHttps,
                        Some(Duration::from_secs(2)),
                    ),
                    AUDIT_KEY.to_vec(),
                )
                .map_err(text)?,
            );
            let connections = PostgresMcpConnections::new(
                p.clone(),
                vault.clone(),
                McpOAuthClient::new(
                    SafeDialer::new(EgressPolicy::default()),
                    SchemePolicy::HttpOrHttps,
                ),
                catalog,
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                vec![0x66; 32],
                AUDIT_KEY.to_vec(),
                Some("http://127.0.0.1:9"),
                Some("http://app.example.test"),
                SchemePolicy::HttpOrHttps,
                gate,
            )
            .map_err(text)?;
            let restored = operation(&p, 0x31).await?;
            let unrelated = operation(&p, 0x32).await?;
            unconfirmed(&p, restored, 1, "credential", &client_id.to_string(), "service", DEP).await?;

            // (1) Cohort None: the original open and discovery send happen.
            let before = accepts.load(Ordering::SeqCst);
            let _ = connections
                .begin_oauth(&admitted(None), SERVER, McpOAuthReturnTo::Settings)
                .await;
            require(accepts_after(&accepts, before).await > before, "no-cohort open never reached the network")?;
            // (2) Some cohort whose operation has no row for this source passes too.
            let before = accepts.load(Ordering::SeqCst);
            let _ = connections
                .begin_oauth(&admitted(Some(unrelated)), SERVER, McpOAuthReturnTo::Settings)
                .await;
            require(accepts_after(&accepts, before).await > before, "absent source was refused")?;
            // (3) Latest in-cohort generation without receipt: closed "not confirmed",
            // before the Vault-open (a decrypt would answer differently) and before any send.
            let before = accepts.load(Ordering::SeqCst);
            let refused = connections
                .begin_oauth(&admitted(Some(restored)), SERVER, McpOAuthReturnTo::Settings)
                .await;
            require(refused == Err(McpConnectionError::NotVisible), "unconfirmed credential not refused as not confirmed")?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            require(accepts.load(Ordering::SeqCst) == before, "unconfirmed credential reached the network")?;
            require(
                p.get().await.map_err(text)?.query_one("SELECT count(*)::bigint FROM public.verifications", &[]).await.map_err(text)?.get::<_, i64>(0) == 0,
                "refused open wrote an OAuth attempt",
            )?;

            // Model secret: the writer requirement gate on the restored logical connection.
            let models = PostgresModelConnections::new(
                p.clone(),
                vault.clone(),
                DeploymentId::new(DEP),
                TenantId::new(TENANT),
                SecretBytes::new(AUDIT_KEY.to_vec()),
            )
            .map_err(text)?;
            let key = |value: &str| ModelApiKey::new(Zeroizing::new(value.to_owned())).map_err(text);
            let created = models
                .create(
                    &admitted(None),
                    &CreateModelConnection {
                        name: "Restore model".to_owned(),
                        protocol: CustomModelProtocol::OpenaiChatCompletions,
                        endpoint: "https://provider.example.test/v1".to_owned(),
                        model: "restore-model".to_owned(),
                        enabled: true,
                        api_key: key("MODEL_FAKE_RESTORE_ONE")?,
                    },
                )
                .await
                .map_err(text)?;
            unconfirmed(&p, restored, 2, "model_secret", &created.id, "actor", ACTOR).await?;
            let update = |revision: i64, value: &str| -> TestResult<UpdateModelConnection> {
                Ok(UpdateModelConnection {
                    expected_revision: revision,
                    name: "Restore model".to_owned(),
                    protocol: CustomModelProtocol::OpenaiChatCompletions,
                    endpoint: "https://provider.example.test/v1".to_owned(),
                    model: "restore-model".to_owned(),
                    enabled: true,
                    api_key: Some(key(value)?),
                })
            };
            let secrets = || async {
                p.get().await.map_err(text)?
                    .query_one("SELECT count(*)::bigint FROM public.model_connection_secrets", &[])
                    .await
                    .map_err(text)
                    .map(|row| row.get::<_, i64>(0))
            };
            let updated = models
                .update(&admitted(Some(unrelated)), &created.id, &update(created.revision, "MODEL_FAKE_RESTORE_TWO")?)
                .await
                .map_err(text)?;
            let before = secrets().await?;
            require(
                models
                    .update(&admitted(Some(restored)), &created.id, &update(updated.revision, "MODEL_FAKE_RESTORE_THREE")?)
                    .await
                    == Err(ModelConnectionError::NotVisible),
                "unconfirmed model secret not refused as not confirmed",
            )?;
            require(secrets().await? == before, "refused model secret sealed a new key")?;
            require(
                models.get(&admitted(None), &created.id).await.map_err(text)?.revision == updated.revision,
                "refused model update changed the connection",
            )?;
            models
                .update(&admitted(None), &created.id, &update(updated.revision, "MODEL_FAKE_RESTORE_FOUR")?)
                .await
                .map_err(text)?;
            Ok(())
        })
        .await;
    }
}
