// Preauthor synthetic fixtures copied from the delivered actual-main origin suite.
// Expected schema is frozen independently; no candidate observation generates it.
fn require(value: bool, reason: &'static str) -> TestResult {
    if value {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}

// This fixture observes the original application's normalized request, forwards every
// real store operation, and never supplies schema expected facts or a production grant.
struct RecordingImport {
    store: PostgresIntelligenceImportStore,
    request: std::sync::Mutex<Option<IntelligenceThreadImportRequest>>,
}
#[async_trait]
impl IntelligenceImportStore for RecordingImport {
    async fn load_progress(
        &self,
        b: &str,
        d: &str,
        h: &str,
    ) -> Result<Option<IntelligenceImportProgress>, IntelligenceImportError> {
        self.store.load_progress(b, d, h).await
    }
    async fn import_thread(
        &self,
        r: IntelligenceThreadImportRequest,
    ) -> Result<IntelligenceThreadImportReceipt, IntelligenceImportError> {
        *self.request.lock().expect("owned recording mutex") = Some(r.clone());
        self.store.import_thread(r).await
    }
    async fn verify_thread(
        &self,
        id: &str,
    ) -> Result<IntelligenceThreadChecksum, IntelligenceImportError> {
        self.store.verify_thread(id).await
    }
    async fn complete_bundle(
        &self,
        b: &str,
        d: &str,
        h: &str,
        p: &IntelligenceImportProgress,
    ) -> Result<(), IntelligenceImportError> {
        self.store.complete_bundle(b, d, h, p).await
    }
    async fn mark_failed(&self, b: &str, d: &str, h: &str) -> Result<(), IntelligenceImportError> {
        self.store.mark_failed(b, d, h).await
    }
    async fn validate_tool_run_fk(
        &self,
    ) -> Result<IntelligenceToolRunFkReport, IntelligenceImportError> {
        self.store.validate_tool_run_fk().await
    }
}
fn import_fixture(
    index: u64,
) -> TestResult<(
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    IntelligenceThreadExport,
)> {
    let mut empty = IntelligenceThreadChecksum {
        projection_hash: "0".repeat(64),
        message_count: 0,
        message_hash: "0".repeat(64),
        event_count: 0,
        event_hash: "0".repeat(64),
        terminal_state_hash: "0".repeat(64),
        memory_count: 0,
        memory_hash: "0".repeat(64),
        sample_render_hash: "0".repeat(64),
    };
    let id = request("origin-a", index)
        .command
        .thread_id
        .as_str()
        .to_owned();
    let mut source = IntelligenceThreadExport {
        thread_id: id,
        created_by: "legacy-creator".into(),
        members: vec!["legacy-creator".into()],
        title: Some("Owned maintenance provenance".into()),
        anchor: IntelligenceThreadAnchor::DirectBot {
            bot_id: "legacy-bot".into(),
        },
        status: IntelligenceThreadStatus::Active,
        messages: vec![],
        runs: vec![],
        memories: vec![],
        checksum: empty.clone(),
        created_at: datetime!(2026-09-01 00:00 UTC),
        updated_at: datetime!(2026-09-01 00:00 UTC),
        deleted_at: None,
    };
    source.checksum = compute_intelligence_thread_checksum(&source).map_err(|e| e.to_string())?;
    let mut normalized = source.clone();
    normalized.created_by = "origin-a".into();
    normalized.members = vec!["origin-a".into()];
    normalized.anchor = IntelligenceThreadAnchor::DirectBot {
        bot_id: "origin-bot".into(),
    };
    empty = compute_intelligence_thread_checksum(&normalized).map_err(|e| e.to_string())?;
    normalized.checksum = empty;
    let payload = IntelligenceBundlePayload {
        schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
        bundle_id: format!("owned-origin-bundle-{index}"),
        source_deployment_id: "owned-legacy-source-deployment".into(),
        exported_at: datetime!(2026-09-01 01:00 UTC),
        provenance: IntelligenceBundleProvenance {
            upstream_commit: INTELLIGENCE_SOURCE_COMMIT.into(),
            exporter_version: "owned-origin-exporter-v1".into(),
            project_id: "owned-origin-project".into(),
        },
        threads: vec![source],
    };
    let verified = VerifiedIntelligenceBundle::new(
        payload,
        "c".repeat(64),
        "owned-origin-maintenance-key".into(),
    )
    .map_err(|e| e.to_string())?;
    let mapping = IntelligenceImportMapping {
        target_deployment_id: DEP.into(),
        target_tenant_id: TENANT.into(),
        users: [("legacy-creator".into(), "origin-a".into())]
            .into_iter()
            .collect(),
        bots: [("legacy-bot".into(), "origin-bot".into())]
            .into_iter()
            .collect(),
        channels: Default::default(),
        claimed_thread_ids: Default::default(),
    };
    Ok((verified, mapping, normalized))
}
async fn close_pool(p: pool::DatabasePool) -> TestResult {
    let observations = p.connection_observations();
    p.close();
    let deadline = Instant::now() + Duration::from_secs(10);
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|e| e.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "owned connection destruction unobserved",
        )?;
    }
    Ok(())
}
async fn owned<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(pool::DatabasePool, pool::DatabaseConfig) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let admin = harness::admin_config(tag);
    require(
        matches!(admin.host.as_str(), "127.0.0.1" | "::1"),
        "literal loopback required",
    )
    .expect("owned fixture prerequisite");
    harness::with_temp_database(&admin,tag,|config|async move{
        require(config.dbname.starts_with("openbot_it_"),"owned database name missing")?;
        let config=config.with_max_pool_size(4);
        let p=pool::connect(&config).await.map_err(|e|e.to_string())?;
        let prerequisite=async{
            let c=p.get().await.map_err(|e|e.to_string())?;
            let r=c.query_one("SELECT current_setting('server_version_num')::int,current_setting('server_encoding'),current_setting('block_size')::int",&[]).await.map_err(|e|e.to_string())?;
            require(r.try_get::<_,i32>(0).map_err(|e|e.to_string())?==170011
                &&r.try_get::<_,String>(1).map_err(|e|e.to_string())?=="UTF8"
                &&r.try_get::<_,i32>(2).map_err(|e|e.to_string())?==8192,"frozen PG17.11 prerequisites differ")
        }.await;
        let result=match prerequisite{Ok(())=>body(p.clone(),config).await,Err(e)=>Err(e)};
        result.and(close_pool(p).await)
    }).await;
}
async fn initialize(p: &pool::DatabasePool, version: i32) -> TestResult {
    let mut c = p.get().await.map_err(|e| e.to_string())?;
    if version == 52 {
        require(
            fresh::apply(&mut c).await.map_err(|e| e.to_string())?
                == fresh::FreshApplyOutcome::Applied(native::ApplyOutcome::Applied),
            "fresh52 not applied",
        )?;
    } else {
        require(
            matches!(version, 47..=51),
            "unregistered historical fixture",
        )?;
        baseline::apply(&c).await.map_err(|e| e.to_string())?;
        require(
            native::apply_through(&mut c, version)
                .await
                .map_err(|e| e.to_string())?
                == native::ApplyOutcome::Applied,
            "explicit historical fixture not applied",
        )?;
    }
    Ok(())
}
async fn provision(p: &pool::DatabasePool) -> TestResult {
    initialize(p, 52).await?;
    let c = p.get().await.map_err(|e| e.to_string())?;
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES
        ('origin-a','origin-a@example.test',7),('origin-b','origin-b@example.test',7),
        ('origin-admin','origin-admin@example.test',7),('origin-roleless','origin-roleless@example.test',7),
        ('origin-denied','origin-denied@example.test',7);
        INSERT INTO public.user_roles(user_id,role) VALUES('origin-a','user'),('origin-b','user'),('origin-admin','admin'),('origin-denied','user');
        INSERT INTO public.revoked_access(email,revoked_by) VALUES('origin-denied@example.test','origin-admin');
        INSERT INTO public.agents(id,name,type,configuration) VALUES('origin-bot','Owned origin bot','built_in','{\"systemPrompt\":\"Owned origin prompt\",\"providerSource\":\"managed\"}');
        INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('origin-bot','origin-a','Owned origin bot','','owned-origin','public');")
        .await.map_err(|e|e.to_string())?;
    Ok(())
}
fn request(actor: &str, index: u64) -> BeginThreadRunRequest {
    let deployment = DeploymentId::new(DEP);
    let mut entropy = [0u8; 16];
    entropy[8..].copy_from_slice(&index.to_be_bytes());
    BeginThreadRunRequest {
        deployment: deployment.clone(),
        tenant: TenantId::new(TENANT),
        actor: ActorId::new(actor),
        auth_generation: AuthGeneration::new(7),
        command: BeginThreadRun {
            artifact_refs: Vec::new(),
            thread_id: ThreadIdentity::new(&deployment).mint_from_entropy(entropy),
            run_id: RunId::new(format!("owned-origin-run-{index}")),
            bot_id: BotId::new("origin-bot"),
            anchor: ThreadRunAnchor::DirectBot,
            message: "Owned finite origin words".to_owned(),
            selected_skill_slugs: vec![],
            model_selection: None,
        },
    }
}
fn directory(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
) -> TestResult<PostgresThreadDirectory> {
    PostgresThreadDirectory::with_runtime(
        p.clone(),
        config.clone(),
        PROCESS.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .map_err(|e| e.to_string())
}
async fn current_owned_auth(p: &pool::DatabasePool, actor: &str) -> TestResult<AuthContext> {
    let c = p.get().await.map_err(|e| e.to_string())?;
    let generation: i64 = c
        .query_one(
            "SELECT coalesce(auth_generation,0) FROM public.users WHERE id=$1",
            &[&actor],
        )
        .await
        .map_err(|e| e.to_string())?
        .try_get(0)
        .map_err(|e| e.to_string())?;
    let mut roles = vec![];
    for row in c
        .query(
            "SELECT role::text FROM public.user_roles WHERE user_id=$1 ORDER BY role",
            &[&actor],
        )
        .await
        .map_err(|e| e.to_string())?
    {
        let role: String = row.try_get(0).map_err(|e| e.to_string())?;
        roles.push(match role.as_str() {
            "user" => Role::User,
            "admin" => Role::Admin,
            _ => return Err("owned role outside enum".into()),
        });
    }
    Ok(AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new(actor),
        AuthGeneration::new(u64::try_from(generation).map_err(|e| e.to_string())?),
        false,
    )
    .with_roles(roles)
    .build())
}
struct ClosedProbe;
#[async_trait]
impl RemoteAguiTransport for ClosedProbe {
    async fn start(
        &self,
        _: &str,
        _: Option<&openbot_application::RemoteAguiAuthorization>,
        _: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }
}

fn auth() -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        ActorId::new("alice"),
        AuthGeneration::new(7),
        false,
    )
    .with_roles([Role::User])
    .build()
}
struct ModelFixture {
    assembly: PostgresApplicationAssembly,
    registry: Option<Arc<ArtifactDatasetRegistry>>,
    binding: Arc<PostgresModelDatasetBinding>,
    directory: PostgresThreadDirectory,
    models: PostgresModelConnections,
}
impl ModelFixture {
    async fn new(p: pool::DatabasePool, config: pool::DatabaseConfig) -> Self {
        let c = p.get().await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','owned-v2-alice@example.test',7),('bob','owned-v2-bob@example.test',7);
            INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');
            INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Owned bot','built_in','{\"systemPrompt\":\"Owned prompt\",\"providerSource\":\"managed\"}');
            INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot','alice','Owned bot','','owned','public');
            INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES('channel','Owned channel','',ARRAY[]::text[],ARRAY[]::text[]);
            INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','alice');
            INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot');").await.unwrap();
        drop(c);
        let vault = CredentialRecordVault::single_key(
            TenantId::new(TENANT),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x61; 32]).unwrap(),
        );
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(
                p.clone(),
                &DeploymentId::new(DEP),
                &TenantId::new(TENANT),
            )
            .await
            .unwrap(),
        );
        let policy_store = PolicyStore::postgres(p.clone(), None);
        policy_store.load().await.unwrap();
        let assembly = assemble_postgres_application(PostgresApplicationAssemblyInput {
            pool: p.clone(),
            listener_database: config.clone().into(),
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            single_user: false,
            admin_floor: None,
            model: "owned-model".into(),
            credential_key_id: "owned-key-ref".into(),
            credential_vault: vault.clone(),
            audit_key: SecretBytes::new(vec![0x62; 32]),
            remote_assertions: Arc::new(RemoteRunAssertionSigner::new(vec![0x63; 32]).unwrap()),
            mcp_oauth_state_key: SecretBytes::new(vec![0x64; 32]),
            policy_store,
            ui_preferences: Arc::new(openbot_application::NoUiPreferenceAdministration),
            screen_sessions: Arc::new(openbot_application::NoScreenSessionAdministration),
            artifacts: None,
            runtime_capabilities: None,
            remote_agent_probe: Arc::new(ClosedProbe),
            managed_slot_available: false,
            channel_routing_provider: ChannelRoutingProviderInput {
                endpoint: url::Url::parse("http://127.0.0.1:9/v1/chat/completions").unwrap(),
                environment_api_key: None,
                egress_allow_cidrs: vec!["127.0.0.1/32".into()],
                allow_http: true,
            },
            stall_timeout: Some(Duration::from_secs(2)),
            oauth_public_url: None,
            app_url: None,
        })
        .await
        .unwrap();
        let binding = assembly.model_dataset_binding.clone();
        binding.enroll_original_registry(&registry).unwrap();
        let directory = PostgresThreadDirectory::with_runtime(
            p.clone(),
            config.clone(),
            PROCESS.into(),
            time::Duration::seconds(30),
        )
        .unwrap()
        .with_model_dataset_binding(binding.clone())
        .unwrap();
        let models = PostgresModelConnections::new(
            p.clone(),
            vault,
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            SecretBytes::new(vec![0x62; 32]),
        )
        .unwrap();
        Self {
            assembly,
            registry: Some(registry),
            binding,
            directory,
            models,
        }
    }
    async fn model(&self, protocol: CustomModelProtocol) -> ModelConnection {
        self.models
            .create(
                &auth(),
                &CreateModelConnection {
                    name: "Owned choice".into(),
                    protocol,
                    endpoint: "https://owned-v2.example.test/v1".into(),
                    model: "owned-selected-model".into(),
                    enabled: true,
                    api_key: ModelApiKey::new(Zeroizing::new("OWNED_V2_SYNTHETIC_KEY".into()))
                        .unwrap(),
                },
            )
            .await
            .unwrap()
    }
    fn request(
        &self,
        index: u64,
        channel: bool,
        model: &ModelConnection,
    ) -> BeginThreadRunV2Request {
        let mut entropy = [0u8; 16];
        entropy[8..].copy_from_slice(&index.to_be_bytes());
        BeginThreadRunV2Request {
            deployment: DeploymentId::new(DEP),
            tenant: TenantId::new(TENANT),
            actor: ActorId::new("alice"),
            auth_generation: AuthGeneration::new(7),
            command: BeginThreadRunV2 {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEP)).mint_from_entropy(entropy),
                run_id: RunId::new(format!("owned-v2-run-{index}")),
                bot_id: BotId::new("bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: "Exact owned words".into(),
                selected_skill_slugs: vec![],
                model_selection: RunModelSelectionV2::new(
                    ModelSelectionIntentSource::Custom,
                    model.id.clone(),
                    model.revision,
                    format!("custom:{}", model.id),
                    1,
                )
                .unwrap(),
            },
        }
    }
    async fn finish(self) {
        self.assembly.shutdown().await;
        drop(self.directory);
        drop(self.models);
        drop(self.binding);
        drop(self.registry);
    }
}
