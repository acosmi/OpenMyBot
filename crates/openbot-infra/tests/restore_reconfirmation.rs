//! V7-IMPL-046 retirement, consumer-gate and reconfirmation cases on explicitly
//! owned PostgreSQL 17.11 (spec revision R484, task card section 5.1, INF-R).
#![cfg(feature = "server-runtime")]
mod harness;

mod retirement {
    // T046-24 and T046-26 land with the retirement producer batch.
}

mod reconfirm {
    // T046-25, T046-33 and T046-34 land with the reconfirmation batch.
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
