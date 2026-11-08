//! V7-IMPL-046 ordinary Server initialization and legacy adoption on explicitly
//! owned PostgreSQL 17.11 (spec revision R484, task card section 5.1, INF-W).
#![cfg(feature = "server-runtime")]
mod harness;

mod control {
    // T046 control-root cases live in the recovery_control unit tests.
}

mod input {
    // T046-13/15/16/18 stay in the backup library tests (crate-private access).
}

mod candidate {
    // T046-21a/22/23 land with the candidate PG batch.
}

mod ordinary {
    use super::harness;
    use openbot_contracts::ids::{DeploymentId, TenantId};
    use openbot_domain::vault::{
        KeyVersion, RecordBinding, SecretBytes, SecretId, SecretKind, SecretPrincipal, ServiceId,
        WrappingKey, seal_v2,
    };
    use openbot_infra::auth::config::{EnvMap, ExampleKeyPolicy, KeyEncryptionKey};
    use openbot_infra::db::pool::{self, DatabaseConfig, DatabasePool};
    use openbot_infra::db::{baseline, fresh, native};
    use openbot_infra::recovery_control::{
        RecoveryControl, RecoveryControlConfig, RecoveryControlError, RecoveryControlFault,
        RecoveryRuntimeOwner, RuntimeOwner, load_service_recovery_host_from_config,
    };
    use openbot_infra::vault::CredentialRecordVault;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    type TestResult<T = ()> = Result<T, String>;
    const DEP: &str = "ordinary-site-deployment";
    const TENANT: &str = "ordinary-site-tenant";
    const DATASET: &str = "0123456789abcdef0123456789abcdef";
    const KEK: [u8; 32] = [0x42; 32];
    const OTHER_KEK: [u8; 32] = [0x24; 32];
    const OWNERS: [RuntimeOwner; 4] = [
        RuntimeOwner::RunRelay,
        RuntimeOwner::McpRevocationReconciler,
        RuntimeOwner::ScreenHub,
        RuntimeOwner::SqlDriver,
    ];

    fn text(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }

    fn require(value: bool, reason: &str) -> TestResult {
        if value {
            Ok(())
        } else {
            Err(reason.to_owned())
        }
    }

    fn kek(bytes: [u8; 32]) -> KeyEncryptionKey {
        use base64::Engine as _;
        let env: EnvMap = [(
            "KEY_ENCRYPTION_KEY".to_owned(),
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )]
        .into_iter()
        .collect();
        KeyEncryptionKey::from_env_map(&env, ExampleKeyPolicy::Reject).unwrap()
    }

    /// One Server site: a private directory holding its configuration, the
    /// optional startup intent and the external control root.
    struct ServerSite {
        directory: PathBuf,
    }

    impl Drop for ServerSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    impl ServerSite {
        fn new() -> Self {
            // A private task-owned root below the real checkout avoids the
            // intentionally world-writable system temporary ancestor.
            let directory = std::env::current_dir()
                .unwrap()
                .join(format!(".ordinary-046-{}", Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory }
        }

        fn control_root(&self) -> PathBuf {
            self.directory.join("control")
        }

        fn write_private(path: &Path, bytes: &[u8]) {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        /// Write the service configuration and, for `mode`, its intent file
        /// with a fresh request ID.
        async fn configure(&self, database: &DatabasePool, mode: Option<&str>) -> TestResult {
            let client = database.get().await.map_err(text)?;
            let row = client
                .query_one(
                    "SELECT pcs.system_identifier::text AS system, d.oid AS oid FROM pg_control_system() pcs JOIN pg_database d ON d.datname=current_database()",
                    &[],
                )
                .await
                .map_err(text)?;
            let system: String = row.get("system");
            let oid: u32 = row.get("oid");
            let intent = self.directory.join("intent");
            let config = self.directory.join("config");
            let _ = std::fs::remove_file(&intent);
            let _ = std::fs::remove_file(&config);
            let configuration = json!({
                "version": 1,
                "controlRoot": self.control_root(),
                "hostLimits": {
                    "maxRequestBytes": 65536, "maxActivationBytes": 65536, "maxJournalFrameBytes": 65536,
                    "maxJournalBytes": 1 << 20, "maxJournalRecords": 64, "maxRuntimeRecordBytes": 65536,
                    "maxRegisteredRuntimes": 8, "maxRetainedOperations": 8, "maxRootEntries": 64,
                    "maxTempEntries": 8, "maxEvidenceRefs": 16, "maxRuntimeResourceFacts": 16,
                    "maxIdBytes": 128, "maxComponentBytes": 128, "maxRelativePathBytes": 8192,
                    "maxPathDepth": 128, "maxOpenFiles": 4096, "maxMetadataBytes": 1 << 24,
                    "admissionNs": 30_000_000_000u64
                },
                "ordinaryStartupBounds": {"effectNs": 60_000_000_000u64, "convergenceNs": 30_000_000_000u64},
                "expectedServiceOwner": {"uid": rustix::process::getuid().as_raw(), "service": "openbot-test"},
                "expectedInstallationBinding": {"deploymentId": DEP, "tenantId": TENANT, "datasetId": DATASET,
                    "sourceInstallationId": "server-source", "targetInstallationId": "server-target"},
                "expectedServerDatabase": {"pgSystemId": system.parse::<u64>().map_err(text)?, "databaseOid": oid, "pgMajor": 17},
                "optionalStartupIntent": mode.map(|mode| json!({"mode": mode, "intentFile": intent})),
            });
            let bytes = serde_json::to_vec(&configuration).map_err(text)?;
            Self::write_private(&config, &bytes);
            if let Some(mode) = mode {
                let meta = std::fs::metadata(&config).map_err(text)?;
                let mut id = [0u8; 16];
                getrandom::fill(&mut id).map_err(text)?;
                let intent_bytes = serde_json::to_vec(&json!({
                    "formatVersion": 1,
                    "requestId": id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "mode": mode,
                    "serviceConfig": {"file": {"device": meta.dev(), "inode": meta.ino(), "uid": meta.uid()},
                        "length": meta.len(),
                        "digest": Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()},
                }))
                .map_err(text)?;
                Self::write_private(&intent, &intent_bytes);
            }
            Ok(())
        }

        async fn start(
            &self,
            database: &DatabaseConfig,
            key: &KeyEncryptionKey,
        ) -> Result<(DatabasePool, RecoveryRuntimeOwner), RecoveryControlError> {
            let host = load_service_recovery_host_from_config(&self.directory.join("config"))?;
            let limits = host.host_limits().clone();
            let mut control = RecoveryControl::open(RecoveryControlConfig::server(host, limits)?)?;
            control
                .open_server_before(
                    database,
                    key,
                    &DeploymentId::new(DEP),
                    &TenantId::new(TENANT),
                    &OWNERS,
                )
                .await
        }

        fn head(&self) -> Option<Value> {
            std::fs::read(self.control_root().join("activation-v1"))
                .ok()
                .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        }

        fn operations(&self) -> Vec<String> {
            match std::fs::read_dir(self.control_root().join("operations")) {
                Ok(entries) => entries
                    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                    .collect(),
                Err(_) => Vec::new(),
            }
        }

        /// Every journal record body of one operation, in order.
        fn journal(&self, operation: &str) -> Vec<Value> {
            let raw = std::fs::read(
                self.control_root()
                    .join("operations")
                    .join(operation)
                    .join("journal-v1"),
            )
            .unwrap();
            let mut records = Vec::new();
            let mut offset = 0;
            while offset < raw.len() {
                let length =
                    u32::from_be_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) as usize;
                records
                    .push(serde_json::from_slice(&raw[offset + 12..offset + 12 + length]).unwrap());
                offset += 12 + length + 32;
            }
            records
        }
    }

    /// The fault of a refused start; a success is an error of the test.
    fn refused(
        result: Result<(DatabasePool, RecoveryRuntimeOwner), RecoveryControlError>,
    ) -> TestResult<RecoveryControlFault> {
        match result {
            Ok(_) => Err("startup unexpectedly succeeded".to_owned()),
            Err(error) => Ok(error.fault()),
        }
    }

    async fn owned<F, Fut>(tag: &str, body: F)
    where
        F: FnOnce(DatabaseConfig, DatabasePool) -> Fut,
        Fut: std::future::Future<Output = TestResult>,
    {
        let admin = harness::admin_config(tag);
        assert!(matches!(admin.host.as_str(), "127.0.0.1" | "::1"));
        harness::with_temp_database(&admin, tag, |config| async move {
            let p = pool::connect(&config.clone().with_max_pool_size(4))
                .await
                .map_err(text)?;
            let result = body(config.with_max_pool_size(4), p.clone()).await;
            p.close();
            result
        })
        .await;
    }

    async fn latest_schema(p: &DatabasePool) -> TestResult {
        let mut c = p.get().await.map_err(text)?;
        fresh::apply(&mut c).await.map_err(text)?;
        Ok(())
    }

    async fn ledger_head(p: &DatabasePool) -> TestResult<(i32, String)> {
        let c = p.get().await.map_err(text)?;
        let row = c
            .query_one("SELECT version, checksum FROM openbot_internal.schema_migrations ORDER BY version DESC LIMIT 1", &[])
            .await
            .map_err(text)?;
        Ok((row.get(0), row.get(1)))
    }

    async fn canaries(p: &DatabasePool) -> TestResult<Vec<String>> {
        let c = p.get().await.map_err(text)?;
        Ok(c.query(
            "SELECT key_id FROM openbot_internal.server_kek_canaries",
            &[],
        )
        .await
        .map_err(text)?
        .iter()
        .map(|row| row.get(0))
        .collect())
    }

    /// The disposition kinds of the stages a published Active names as evidence.
    fn evidence_stages(site: &ServerSite, head: &Value) -> Vec<String> {
        head["data"]["initializationEvidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|reference| {
                let journal = site.journal(reference["contextId"].as_str().unwrap());
                let observed = &journal[reference["sequence"].as_u64().unwrap() as usize - 1];
                let intent =
                    &journal[observed["data"]["intentSequence"].as_u64().unwrap() as usize - 1];
                intent["data"]["stage"].as_str().unwrap().to_owned()
            })
            .collect()
    }

    fn has_resource_close(site: &ServerSite, operation: &str) -> bool {
        site.journal(operation).iter().any(|record| {
            record["kind"] == "StageIntent" && record["data"]["stage"] == "resource_close"
        })
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_07_server_fresh_proof_publishes_ordinary_active() {
        owned("t046_07a", |config, p| async move {
            let site = ServerSite::new();
            site.configure(&p, Some("fresh_init")).await?;
            let (pool, runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            let head = site.head().ok_or("no head")?;
            require(
                head["phase"] == "OrdinaryActive" && head["revision"] == 2,
                "Initializing then Active",
            )?;
            let (version, checksum) = ledger_head(&p).await?;
            require(
                version == native::NATIVE_LATEST_VERSION,
                "fresh schema is the latest",
            )?;
            let binding = &head["data"]["binding"];
            require(
                binding["nativeVersion"] == version
                    && binding["migrationDigest"] == checksum.as_str(),
                "binding is the ledger",
            )?;
            require(
                evidence_stages(&site, &head) == ["ordinary_initialize"],
                "evidence is the ordinary_initialize observation",
            )?;
            let operations = site.operations();
            require(
                operations.len() == 1 && has_resource_close(&site, &operations[0]),
                "one operation with resource_close",
            )?;
            let keys = canaries(&p).await?;
            require(
                keys.len() == 1 && binding["keyRefs"][0]["keyId"] == keys[0].as_str(),
                "canary key is keyRefs[0]",
            )?;
            pool.close();
            drop(runtime);
            // Restart: the latest head enrolls under SH; the intent is not consumed twice.
            let (pool, _runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            require(site.operations() == operations, "no second operation")?;
            require(site.head().as_ref() == Some(&head), "the head is unchanged")
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_08_server_legacy_needs_positive_intent_and_rejects_known_restore() {
        owned("t046_08a", |config, p| async move {
            latest_schema(&p).await?;
            let site = ServerSite::new();
            site.configure(&p, None).await?;
            require(
                refused(site.start(&config, &kek(KEK)).await)?
                    == RecoveryControlFault::InitializationRequired,
                "null intent",
            )?;
            require(
                site.head().is_none() && site.operations().is_empty(),
                "nothing written",
            )?;
            site.configure(&p, Some("legacy_adoption")).await?;
            let (pool, _runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            let head = site.head().ok_or("no head")?;
            require(
                head["phase"] == "OrdinaryActive",
                "legacy adoption publishes Active",
            )?;
            require(
                evidence_stages(&site, &head) == ["ordinary_verify", "key_slot"],
                "zero protected values: first canary",
            )?;
            Ok(())
        })
        .await;
        owned("t046_08a_restore", |config, p| async move {
            latest_schema(&p).await?;
            let c = p.get().await.map_err(text)?;
            c.batch_execute(
                "SET session_replication_role = replica;
                 INSERT INTO openbot_internal.restore_pg_operations(operation_id,epoch,candidate_generation,source_bundle_id,
                   deployment_id,tenant_id,dataset_id,source_installation_id,target_installation_id,candidate_database_oid,
                   pg_system_identifier,profile_binding,max_batches,max_requirements)
                 VALUES(gen_random_uuid(),'\\x1111111111111111111111111111111111111111111111111111111111111111'::bytea,
                   gen_random_uuid(),gen_random_uuid(),'d','t','0123456789abcdef0123456789abcdef','s','t',1,'1',
                   '\\x2222222222222222222222222222222222222222222222222222222222222222'::bytea,1,1);
                 SET session_replication_role = origin;",
            )
            .await
            .map_err(text)?;
            drop(c);
            let site = ServerSite::new();
            site.configure(&p, Some("legacy_adoption")).await?;
            require(refused(site.start(&config, &kek(KEK)).await)? == RecoveryControlFault::ControlInvalid, "known restore is refused")?;
            require(site.head().is_none() && site.operations().is_empty(), "nothing written")
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_42_server_legacy_requires_current_schema_then_adopts_after_migrate() {
        owned("t046_42", |config, p| async move {
            let mut c = p.get().await.map_err(text)?;
            baseline::apply(&c).await.map_err(text)?;
            native::apply_through(&mut c, native::NATIVE_0052_VERSION)
                .await
                .map_err(text)?;
            drop(c);
            let site = ServerSite::new();
            site.configure(&p, Some("legacy_adoption")).await?;
            require(
                refused(site.start(&config, &kek(KEK)).await)?
                    == RecoveryControlFault::ControlInvalid,
                "strict-prior schema",
            )?;
            require(
                site.head().is_none() && site.operations().is_empty(),
                "no head and no operation",
            )?;
            require(
                ledger_head(&p).await?.0 == native::NATIVE_0052_VERSION,
                "no DDL",
            )?;
            // The operator migrates with the same native entry, then retries the same intent.
            let mut c = p.get().await.map_err(text)?;
            native::apply(&mut c).await.map_err(text)?;
            drop(c);
            let (pool, runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            let head = site.head().ok_or("no head")?;
            require(
                head["phase"] == "OrdinaryActive"
                    && head["data"]["binding"]["nativeVersion"] == native::NATIVE_LATEST_VERSION,
                "latest Active",
            )?;
            require(
                evidence_stages(&site, &head) == ["ordinary_verify", "key_slot"],
                "verify then key slot",
            )?;
            let keys = canaries(&p).await?;
            require(
                keys.len() == 1
                    && head["data"]["binding"]["keyRefs"][0]["keyId"] == keys[0].as_str(),
                "one canary named by keyRefs[0]",
            )?;
            let operations = site.operations();
            require(operations.len() == 1, "one legacy operation")?;
            require(
                site.journal(&operations[0])[0]["data"]["mode"] == "legacy_adoption",
                "no other mode",
            )?;
            drop(runtime);
            let (pool, _runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            require(
                site.head().as_ref() == Some(&head),
                "restart enrolls the same head",
            )
        })
        .await;
    }

    /// One protected value per KEK-protected column, sealed the way its
    /// consumer writes it, plus enough credential rows to cross one keyset page.
    struct Protected {
        sdk: Uuid,
        credential: Uuid,
    }

    async fn protect(p: &DatabasePool, key: [u8; 32], foreign_sdk: bool) -> TestResult<Protected> {
        let vault = |bytes| {
            CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(Vec::from(bytes)).unwrap(),
            )
        };
        let ours = vault(key);
        let secret = SecretBytes::new(b"protected-secret".to_vec());
        let c = p.get().await.map_err(text)?;
        c.batch_execute("SET session_replication_role = replica")
            .await
            .map_err(text)?;
        let deployment = SecretPrincipal::Deployment;
        let service = |name: &str| SecretPrincipal::Service(ServiceId::new(name));
        let actor = |name: &str| SecretPrincipal::Actor(openbot_contracts::ids::ActorId::new(name));
        let kinds: [(&str, SecretKind, SecretPrincipal, SecretPrincipal); 6] = [
            (
                "model",
                SecretKind::Model,
                deployment.clone(),
                deployment.clone(),
            ),
            (
                "connector",
                SecretKind::Connector,
                deployment.clone(),
                deployment.clone(),
            ),
            (
                "mcp",
                SecretKind::Mcp,
                deployment.clone(),
                service("provider"),
            ),
            (
                "agent",
                SecretKind::Agent,
                actor("owner"),
                service("provider"),
            ),
            (
                "mcp_oauth_client",
                SecretKind::McpOauthClient,
                deployment.clone(),
                service("provider"),
            ),
            (
                "mcp_user_token",
                SecretKind::McpUserToken,
                actor("owner"),
                service("provider"),
            ),
        ];
        let mut credential = Uuid::nil();
        for index in 0..40 {
            let (kind, secret_kind, owner, consumer) = &kinds[index % kinds.len()];
            let id = Uuid::new_v4();
            let value = ours
                .seal(&id, *secret_kind, owner.clone(), consumer.clone(), &secret)
                .map_err(text)?;
            let revoked = index % 7 == 0;
            c.execute(
                "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata,revoked_at) VALUES($1,$2::text::public.credential_kind,'provider',$3,'owner','{}'::jsonb,CASE WHEN $4 THEN now() END)",
                &[&id, kind, &value, &revoked],
            )
            .await
            .map_err(text)?;
            credential = id;
        }
        // An upstream V1 credential (no AAD).
        {
            use aes_gcm::aead::{Aead, KeyInit};
            use base64::Engine as _;
            let iv = [7u8; 12];
            let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(text)?;
            let ciphertext = cipher
                .encrypt(aes_gcm::Nonce::from_slice(&iv), b"v1-secret".as_slice())
                .map_err(text)?;
            let b64 = base64::engine::general_purpose::STANDARD;
            // The upstream column text starts with the version key.
            let value = format!(
                "{{\"version\":1,\"iv\":\"{}\",\"ciphertext\":\"{}\"}}",
                b64.encode(iv),
                b64.encode(ciphertext)
            );
            c.execute(
                "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata) VALUES(gen_random_uuid(),'model','provider',$1,'owner','{}'::jsonb)",
                &[&value],
            )
            .await
            .map_err(text)?;
        }
        let sdk = Uuid::new_v4();
        for (table, id, retired, sealer) in [
            ("model_connection_secrets", Uuid::new_v4(), true, &ours),
            (
                "sdk_gateway_secrets",
                sdk,
                false,
                &if foreign_sdk {
                    vault(OTHER_KEK)
                } else {
                    vault(key)
                },
            ),
        ] {
            let connection = Uuid::new_v4();
            let value = sealer
                .seal(
                    &id,
                    SecretKind::Model,
                    actor("owner"),
                    service(&connection.to_string()),
                    &secret,
                )
                .map_err(text)?;
            let generation = if table == "sdk_gateway_secrets" {
                ",credential_generation"
            } else {
                ""
            };
            let generation_value = if table == "sdk_gateway_secrets" {
                ",1"
            } else {
                ""
            };
            c.execute(
                &format!("INSERT INTO public.{table}(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at,retired_at{generation}) VALUES($1,$2,$3,$4,'owner',$5,now(),CASE WHEN $6 THEN now() END{generation_value})"),
                &[&id, &connection, &DEP, &TENANT, &value, &retired],
            )
            .await
            .map_err(text)?;
        }
        // SSO: one sealed OIDC config, one plaintext SAML config (not a KEK value).
        let sso = WrappingKey::from_bytes(Vec::from(key)).unwrap();
        let binding = RecordBinding::new(
            TenantId::new(TENANT),
            SecretId::new("sso-provider/provider-a/oidc_config"),
            SecretKind::Connector,
            SecretPrincipal::Deployment,
            SecretPrincipal::Deployment,
            KeyVersion::new(1),
        );
        let mut dek = [0u8; 32];
        getrandom::fill(&mut dek).map_err(text)?;
        let oidc = seal_v2(
            &sso,
            &openbot_domain::vault::DataKey::from_bytes(dek.to_vec()).map_err(text)?,
            &binding,
            openbot_domain::vault::Nonce::from_slice(&[1u8; 12]).map_err(text)?,
            openbot_domain::vault::Nonce::from_slice(&[2u8; 12]).map_err(text)?,
            b"{\"clientId\":\"a\"}",
        )
        .map_err(text)?
        .to_column_value();
        c.execute(
            "INSERT INTO public.sso_providers(id,issuer,oidc_config,saml_config,provider_id,domain) VALUES($1,'https://issuer.example',$2,'<saml/>','provider-a','example.test')",
            &[&Uuid::new_v4().to_string(), &oidc],
        )
        .await
        .map_err(text)?;
        c.batch_execute("SET session_replication_role = origin")
            .await
            .map_err(text)?;
        Ok(Protected { sdk, credential })
    }

    async fn protected_bytes(p: &DatabasePool) -> TestResult<Vec<String>> {
        let c = p.get().await.map_err(text)?;
        let mut values = Vec::new();
        for sql in [
            "SELECT encrypted_value FROM public.credentials ORDER BY id",
            "SELECT encrypted_value FROM public.model_connection_secrets ORDER BY id",
            "SELECT encrypted_value FROM public.sdk_gateway_secrets ORDER BY id",
            "SELECT coalesce(oidc_config,'') || coalesce(saml_config,'') FROM public.sso_providers ORDER BY id",
        ] {
            for row in c.query(sql, &[]).await.map_err(text)? {
                values.push(row.get(0));
            }
        }
        Ok(values)
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_44_server_legacy_without_canary_opens_every_kek_value_then_writes_canary() {
        owned("t046_44", |config, p| async move {
            latest_schema(&p).await?;
            protect(&p, KEK, false).await?;
            let site = ServerSite::new();
            site.configure(&p, Some("legacy_adoption")).await?;
            let (pool, _runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            let head = site.head().ok_or("no head")?;
            let keys = canaries(&p).await?;
            require(
                keys.len() == 1
                    && head["data"]["binding"]["keyRefs"][0]["keyId"] == keys[0].as_str(),
                "first canary after every value opened",
            )?;
            require(
                evidence_stages(&site, &head) == ["ordinary_verify", "key_slot"],
                "key slot written",
            )
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_45_server_legacy_unopenable_value_refuses_and_leaves_no_head() {
        owned("t046_45", |config, p| async move {
            latest_schema(&p).await?;
            let protected = protect(&p, KEK, true).await?;
            let before = protected_bytes(&p).await?;
            let site = ServerSite::new();
            site.configure(&p, Some("legacy_adoption")).await?;
            require(
                refused(site.start(&config, &kek(KEK)).await)?
                    == RecoveryControlFault::KeyUnverified,
                "a value under another KEK",
            )?;
            require(
                site.head().is_none() && site.operations().is_empty(),
                "no head, intent not consumed",
            )?;
            require(canaries(&p).await?.is_empty(), "no canary")?;
            require(
                protected_bytes(&p).await? == before,
                "protected rows unchanged",
            )?;
            let _ = protected.sdk;
            Ok(())
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires owned PostgreSQL 17.11 through OPENBOT_TEST_DATABASE_URL"]
    async fn t046_46_server_legacy_authentication_failure_refuses_then_retry_succeeds() {
        owned("t046_46", |config, p| async move {
            latest_schema(&p).await?;
            let protected = protect(&p, KEK, false).await?;
            let c = p.get().await.map_err(text)?;
            let original: String = c
                .query_one("SELECT encrypted_value FROM public.credentials WHERE id=$1", &[&protected.credential])
                .await
                .map_err(text)?
                .get(0);
            // Move the ciphertext under another record's binding: AAD authentication fails.
            c.execute(
                r#"UPDATE public.credentials SET encrypted_value=(SELECT encrypted_value FROM public.credentials WHERE id<>$1 AND encrypted_value LIKE '{"version":2%' ORDER BY id LIMIT 1) WHERE id=$1"#,
                &[&protected.credential],
            )
            .await
            .map_err(text)?;
            drop(c);
            let site = ServerSite::new();
            site.configure(&p, Some("legacy_adoption")).await?;
            require(refused(site.start(&config, &kek(KEK)).await)? == RecoveryControlFault::KeyUnverified, "authentication failure")?;
            require(site.head().is_none() && site.operations().is_empty() && canaries(&p).await?.is_empty(), "nothing written")?;
            let c = p.get().await.map_err(text)?;
            c.execute("UPDATE public.credentials SET encrypted_value=$2 WHERE id=$1", &[&protected.credential, &original])
                .await
                .map_err(text)?;
            drop(c);
            let (pool, _runtime) = site.start(&config, &kek(KEK)).await.map_err(text)?;
            pool.close();
            require(site.head().is_some_and(|head| head["phase"] == "OrdinaryActive"), "the same intent then adopts")
        })
        .await;
    }
}
