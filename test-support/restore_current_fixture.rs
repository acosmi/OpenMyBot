// Consumer fixtures use a real isolated PG, its canary and the production
// Current reader. The serialized journal is fixture DATA, not evidence of a
// restore producer; the Desktop end-to-end cases exercise that producer.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use openbot_contracts::recovery::RestoreCohortRef;
use openbot_domain::vault::{DesktopVaultCanaryBinding, KeyVersion, Nonce, SecretBytes, seal_desktop_vault_canary};
use openbot_infra::auth::single_user::desktop_local::{CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore};
use openbot_infra::db::{baseline, desktop_local, desktop_vault_canary, native, pool};
use openbot_infra::recovery_control::{ActivationBinding, RecoveryControl, RecoveryControlConfig, RecoveryFileIdentity,
    RecoveryRuntimeOwner, RestoreOperationProfile, RuntimeOwner, TrustedHostRecoveryLimits};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEP: &str = "dep-1";
pub const TENANT: &str = "tenant-1";
pub const AUDIT_KEY: &[u8] = b"owned-current-audit-key-at-least-32-bytes";

pub struct CurrentFixture {
    pub runtime: Option<RecoveryRuntimeOwner>,
    pub pool: pool::DatabasePool,
    pub cohort: RestoreCohortRef,
    database: Option<desktop_local::DesktopLocalDatabase>,
    _pg: OwnedPg,
}

struct OwnedPg { child: Child, root: PathBuf }

impl Drop for OwnedPg {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let reaped = self.child.wait().is_ok();
        if reaped && !std::thread::panicking() { let _ = fs::remove_dir_all(&self.root); }
        else { eprintln!("retained Current consumer fixture: {}", self.root.display()); }
    }
}

fn encoded(value: impl Serialize) -> String { serde_json::to_string(&value).unwrap() }

// The reader requires the declared field order, including nested records.
fn object(fields: &[(&str, String)]) -> String {
    format!("{{{}}}", fields.iter().map(|(key, value)| format!("{}:{value}", encoded(key))).collect::<Vec<_>>().join(","))
}

fn identity(path: &Path) -> RecoveryFileIdentity {
    let m = fs::metadata(path).unwrap();
    RecoveryFileIdentity { device: m.dev(), inode: m.ino(), uid: m.uid() }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}

fn append_frame(journal: &mut Vec<u8>, previous: &mut [u8; 32], context: (&str,&str,&str),
    sequence: u64, kind: &str, data: String) -> String
{
    let (control,operation,epoch)=context;
    let body = object(&[("recordType", encoded("wrokbot-recovery-journal")), ("version", encoded(1)),
        ("controlId", encoded(control)), ("operationId", encoded(operation)), ("epoch", encoded(epoch)),
        ("sequence", encoded(sequence)), ("previousDigest", encoded(hex(previous))), ("kind", encoded(kind)), ("data", data)]);
    let mut frame = b"WBRCJ001".to_vec();
    frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(body.as_bytes());
    *previous = Sha256::new().chain_update(b"wrokbot.restore.journal.v1\0").chain_update(&frame).finalize().into();
    frame.extend_from_slice(previous);
    journal.extend(frame);
    object(&[("contextId", encoded(operation)), ("sequence", encoded(sequence)), ("digest", encoded(hex(previous)))])
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

impl CurrentFixture {
    pub async fn requirement(&self, kind: &str, source: &str) -> Uuid {
        let requirement = Uuid::now_v7();
        let mut client = self.pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        // This test supplies the inventory; all original insert guards stay
        // enabled and verify it against this actual database and source row.
        let inserted = tx.execute(
            "WITH inventory(kind,ref,birth,revision,owner_kind,owner_id,owner_birth,public_fields) AS (
             SELECT 'subject',u.id,u.created_at,NULL::bigint,'actor',u.id,u.created_at,
              jsonb_build_array(u.id,to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')) FROM public.users u
             UNION ALL SELECT 'sdk_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
              jsonb_build_array(c.id,to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.issuer,c.client_id,c.account_id,c.organization_id)
              FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
             UNION ALL SELECT 'sso_provider',s.id,NULL::timestamptz,NULL::bigint,
              CASE WHEN s.user_id IS NULL THEN 'service' ELSE 'actor' END,coalesce(s.user_id,$6),u.created_at,
              jsonb_build_array(s.id,s.provider_id,s.issuer,s.organization_id,s.domain,s.user_id)
              FROM public.sso_providers s LEFT JOIN public.users u ON u.id=s.user_id)
             INSERT INTO openbot_internal.restore_reconfirm_requirements(operation_id,epoch,requirement_id,requirement_seq,
              source_kind,source_ref,binding_generation,source_created_at,source_revision,public_binding,owner_kind,owner_id,owner_created_at)
             SELECT $1,$2,$5,(SELECT coalesce(max(requirement_seq),0)+1 FROM openbot_internal.restore_reconfirm_requirements WHERE operation_id=$1),
              i.kind,i.ref,0,i.birth,i.revision,sha256(convert_to('wrokbot.restore.public-binding.v1'||chr(10)||jsonb_build_array(i.kind,i.public_fields)::text,'UTF8')),
              i.owner_kind,i.owner_id,i.owner_birth FROM inventory i WHERE i.kind=$3 AND i.ref=$4",
            &[&Uuid::from_bytes(self.cohort.operation_id),&self.cohort.epoch.as_slice(),&kind,&source,&requirement,&DEP],
        ).await.unwrap();
        assert_eq!(inserted,1);
        tx.commit().await.unwrap();
        requirement
    }

    pub async fn new(seed: &str) -> Self {
        Self::with_port(seed, async |port| port).await
    }

    pub async fn with_port(seed: &str, connect_port: impl AsyncFnOnce(u16) -> u16) -> Self {
        let root = std::env::current_dir().unwrap().canonicalize().unwrap()
            .join(format!(".restore-current-consumer-{}", Uuid::now_v7()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let generation = root.join("generation");
        fs::DirBuilder::new().mode(0o700).create(&generation).unwrap();
        let data = generation.join("data");
        let binary = PathBuf::from(std::env::var_os("OPENBOT_TEST_POSTGRES_BIN_DIR").expect("explicit owned PostgreSQL 17.11 tools"));
        let password = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        write_private(&root.join("pwfile"), password.as_bytes());
        let output = OpenOptions::new().create_new(true).write(true).mode(0o600).open(root.join("postgres.log")).unwrap();
        let initialized = Command::new(binary.join("initdb")).args(["--username=desktop_admin", "--auth=scram-sha-256", "--encoding=UTF8", "--locale=C"])
            .arg("-D").arg(&data).arg(format!("--pwfile={}", root.join("pwfile").display()))
            .stdin(Stdio::null()).stdout(output.try_clone().unwrap()).stderr(output.try_clone().unwrap()).status().unwrap();
        assert!(initialized.success(), "owned initdb failed; retain its private log");
        let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
        let child = Command::new(binary.join("postgres")).arg("-D").arg(&data).arg("-p").arg(port.to_string())
            .args(["-c", "listen_addresses=127.0.0.1", "-c", "unix_socket_directories=", "-c", "password_encryption=scram-sha-256"])
            .stdin(Stdio::null()).stdout(output.try_clone().unwrap()).stderr(output).spawn().unwrap();
        let pg = OwnedPg { child, root: root.clone() };
        let mut config = tokio_postgres::Config::new();
        config.host("127.0.0.1").port(port).user("desktop_admin").password(&password).dbname("postgres");
        let end = Instant::now() + Duration::from_secs(30);
        let (admin, driver) = loop {
            match config.connect(tokio_postgres::NoTls).await {
                Ok(connected) => break connected,
                Err(_) if Instant::now() < end => tokio::time::sleep(Duration::from_millis(25)).await,
                Err(_) => panic!("owned PG did not become ready"),
            }
        };
        let driver = tokio::spawn(driver);
        admin.batch_execute("CREATE DATABASE openbot WITH OWNER=desktop_admin TEMPLATE=template0 ENCODING='UTF8' LC_COLLATE='C' LC_CTYPE='C'").await.unwrap();
        drop(admin);
        driver.await.unwrap().unwrap();
        let source = pool::connect(&pool::DatabaseConfig {
            host:"127.0.0.1".into(),port,user:"desktop_admin".into(),password:Some(password.clone()),dbname:"openbot".into(),
            application_name:Some("owned-current-source".into()),max_pool_size:4,connect_timeout:Duration::from_secs(10),
        }).await.unwrap();
        let mut client = source.get().await.unwrap();
        baseline::apply(&client).await.unwrap();
        native::apply(&mut client).await.unwrap();
        client.batch_execute(seed).await.unwrap();
        let row = client.query_one("SELECT (SELECT system_identifier FROM pg_control_system()),(SELECT oid FROM pg_database WHERE datname=current_database()),checksum FROM openbot_internal.schema_migrations WHERE version=$1",
            &[&native::NATIVE_LATEST_VERSION]).await.unwrap();
        let system = u64::try_from(row.get::<_, i64>(0)).unwrap();
        let oid: u32 = row.get(1);
        let migration: String = row.get(2);
        let (control_id, operation, generation_id, dataset, key_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let epoch = Sha256::digest(Uuid::new_v4().as_bytes());
        let cohort = RestoreCohortRef { operation_id: *operation.as_bytes(), epoch: epoch.into() };
        let (control_id, operation, generation_id, dataset, key_id) = (control_id.simple().to_string(), operation.simple().to_string(), generation_id.simple().to_string(), dataset.simple().to_string(), key_id.simple().to_string());
        let installation = "22".repeat(32);
        let master = SecretBytes::new(vec![0x41; 32]);
        let canary_binding = DesktopVaultCanaryBinding::new(&dataset, DEP, TENANT, &key_id, KeyVersion::new(1)).unwrap();
        let canary = seal_desktop_vault_canary(&master, &canary_binding, Nonce::from_slice(&Uuid::new_v4().as_bytes()[..12]).unwrap()).unwrap();
        client.execute("INSERT INTO openbot_internal.desktop_vault_canaries(dataset_id,deployment_id,tenant_id,key_id,key_version,canary_schema,encrypted_canary) VALUES($1,$2,$3,$4,1,1,$5)",
            &[&dataset,&DEP,&TENANT,&key_id,&canary.to_column_value()]).await.unwrap();
        client.execute("INSERT INTO openbot_internal.restore_pg_operations(operation_id,epoch,candidate_generation,source_bundle_id,deployment_id,tenant_id,dataset_id,source_installation_id,target_installation_id,candidate_database_oid,pg_system_identifier,profile_binding,max_batches,max_requirements) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11,64,4096)",
            &[&Uuid::from_bytes(cohort.operation_id),&cohort.epoch.as_slice(),&Uuid::parse_str(&generation_id).unwrap(),&Uuid::now_v7(),&DEP,&TENANT,&dataset,&installation,&oid,&system.to_string(),&[7u8;32].as_slice()]).await.unwrap();
        drop(client);
        source.close();
        drop(source);

        let limits: TrustedHostRecoveryLimits = serde_json::from_value(json!({
            "maxRequestBytes":65536,"maxActivationBytes":262144,"maxJournalFrameBytes":65536,"maxJournalBytes":1048576,"maxJournalRecords":128,
            "maxRuntimeRecordBytes":65536,"maxRegisteredRuntimes":16,"maxRetainedOperations":16,"maxRootEntries":64,"maxTempEntries":16,
            "maxEvidenceRefs":32,"maxRuntimeResourceFacts":32,"maxIdBytes":128,"maxComponentBytes":255,"maxRelativePathBytes":8192,
            "maxPathDepth":64,"maxOpenFiles":4096,"maxMetadataBytes":201326592,"admissionNs":30000000000u64
        })).unwrap();
        let profile: RestoreOperationProfile = serde_json::from_value(json!({"effectNs":120000000000u64,"convergenceNs":30000000000u64,"capacity":{
            "maxInputWireBytes":67108864,"maxManifestBytes":4194304,"maxMaterialFiles":4096,"maxMaterialDirectories":512,"maxSingleMaterialBytes":33554432,
            "maxMaterialPlainBytes":67108864,"maxPathBytes":8192,"maxPathDepth":64,"maxCandidateDataBytes":67108864,"maxCandidateWalBytes":67108864,
            "maxCandidateTempBytes":16777216,"maxSpoolBytes":67108864,"maxRetainedPriorBytes":67108864,"maxJournalBytes":1048576,"maxJournalRecords":128,
            "maxMetadataBytes":201326592,"maxOpenFiles":4096,"maxNativeTasks":32,"maxPgConnections":64,"maxPgTransactions":64,"maxPgRows":65536,
            "maxReconfirmRequirements":4096,"maxSecretMemoryBytes":8388608,"maxSecretStructureBytes":65536,"maxTotalAllocationBytes":4294967296u64,
            "reserveBytes":1,"freeFloorBytes":1,"maxKeyMediumAllocationBytes":1073741824,"keyMediumReserveBytes":1,"keyMediumFreeFloorBytes":1
        }})).unwrap();
        let app = CurrentOsUserAppDataRoot::from_current_os_user_app_data(root.join("original-app")).unwrap();
        let control = RecoveryControl::open(RecoveryControlConfig::local(app.clone(), limits.clone()).unwrap()).unwrap();
        let control_root = root.join("com.acosmi.wrokbot.restore-control");
        let op_dir = control_root.join("operations").join(&operation);
        fs::DirBuilder::new().mode(0o700).create(&op_dir).unwrap();
        let account = format!("{installation}-r-{operation}");
        let key = |kind, service, account: String, id: String| json!({"kind":kind,"reviewedService":service,"account":account,"keyId":id,"keyVersion":1,"targetInstallationId":installation,"operationId":operation});
        let binding: ActivationBinding = serde_json::from_value(json!({"siteKind":"local_physical","datasetId":dataset,"deploymentId":DEP,"tenantId":TENANT,
            "sourceInstallationId":installation,"targetInstallationId":installation,"generationId":generation_id,"generationRoot":identity(&generation),
            "pgSystemId":system,"databaseOid":oid,"pgMajor":17,"nativeVersion":native::NATIVE_LATEST_VERSION,"migrationDigest":migration,"authorizationEpoch":hex(&cohort.epoch),
            "keyRefs":[key("historical_master","test.vault",format!("desktop-vault-master-v1-{account}"),key_id.clone()),key("postgres_scram","test.postgres",format!("postgresql-17-{account}"),format!("postgresql-17-{account}"))]})).unwrap();
        let original_file = object(&[("file",encoded(identity(&generation))),("length",encoded(104))]);
        let plan = object(&[("siteKind",encoded("local_physical")),("trustedParent",encoded(identity(&root))),
            ("entryComponent",encoded("generation")),("installationId",encoded(&installation)),("generationId",encoded(&generation_id))]);
        let clock = object(&[("clockKind",encoded("CLOCK_MONOTONIC")),("bootIdentity",encoded("consumer-fixture")),("pid",encoded(1)),
            ("processStart",object(&[("seconds",encoded(1)),("nanos",encoded(0))])),("ownerNonce",encoded(&control_id)),
            ("t0Ns",encoded(1)),("effectDeadlineNs",encoded(2)),("convergenceDeadlineNs",encoded(3))]);
        let intent = object(&[("mode",encoded("restore")),("profile",encoded(profile)),
            ("inputIdentities",object(&[("carrier",original_file.clone()),("keyMedium",original_file)])),
            ("business",object(&[("deploymentId",encoded(DEP)),("tenantId",encoded(TENANT)),("datasetId",encoded(&dataset))])),
            ("sourceInstallationId",encoded(&installation)),("targetInstallationId",encoded(&installation)),("candidatePlan",plan),("ownerClock",clock)]);
        let mut journal = Vec::new();
        let mut previous = [0u8;32];
        let epoch = hex(&cohort.epoch);
        append_frame(&mut journal,&mut previous,(&control_id,&operation,&epoch),1,"OperationIntent",intent);
        append_frame(&mut journal,&mut previous,(&control_id,&operation,&epoch),2,"StageIntent",object(&[
            ("stage",encoded("switch")),("originalEffectId",encoded(&control_id)),("expectedBinding",encoded(Option::<u8>::None))]));
        let observed = append_frame(&mut journal,&mut previous,(&control_id,&operation,&epoch),3,"StageObserved",object(&[
            ("intentSequence",encoded(2)),("typedDisposition",object(&[("kind",encoded("PgCommit")),("data",encoded("TimelyAck"))])),
            ("actualBinding",encoded(Option::<u8>::None)),("receiptRefs",encoded(Vec::<u8>::new()))]));
        let data = object(&[("operationId",encoded(&operation)),("epoch",encoded(&epoch)),("profileDigest",encoded("07".repeat(32))),
            ("binding",encoded(binding)),("closureEvidence",format!("[{observed}]")),("switchReadback",observed),
            ("publishIntent",object(&[("contextId",encoded(&operation)),("sequence",encoded(4))]))]);
        let activation = object(&[("recordType",encoded("wrokbot-recovery-activation")),("version",encoded(1)),("controlId",encoded(&control_id)),
            ("revision",encoded(1)),("previousDigest",encoded(Option::<u8>::None)),("phase",encoded("RestoreCurrent")),("data",data)]);
        let digest = hex(&Sha256::new().chain_update(b"wrokbot.restore.activation.v1\0").chain_update(activation.as_bytes()).finalize());
        append_frame(&mut journal,&mut previous,(&control_id,&operation,&epoch),4,"PublishIntent",object(&[
            ("expectedPhase",encoded("RestoreCurrent")),("descriptorDigest",encoded(&digest)),("receiptRefs",encoded(Vec::<u8>::new()))]));
        write_private(&control_root.join("activation-v1"),activation.as_bytes());
        append_frame(&mut journal,&mut previous,(&control_id,&operation,&epoch),5,"PublishObserved",object(&[
            ("intentSequence",encoded(4)),("descriptorDigest",encoded(&digest)),("actualFileIdentity",encoded(identity(&control_root.join("activation-v1")))),
            ("disposition",encoded("FileAndParentSyncedReadback"))]));
        write_private(&op_dir.join("journal-v1"),&journal);
        drop(control);
        let control = RecoveryControl::open(RecoveryControlConfig::local(app.clone(), limits).unwrap()).unwrap();
        let mut runtime = control.open_local_before(&DesktopLocalAuthorityStore::new(app.clone()),[0x11;32],["test.vault","test.postgres"],
            serde_json::from_value(json!({"effectNs":120000000000u64,"convergenceNs":30000000000u64})).unwrap(),
            &[RuntimeOwner::PostgresSidecar,RuntimeOwner::SqlDriver,RuntimeOwner::ApplicationAssembly,RuntimeOwner::DesktopAgentRelay,RuntimeOwner::DesktopAgent]).unwrap();
        let site = runtime.restored_local_site(&app).unwrap().unwrap();
        let port = connect_port(port).await;
        let admin = desktop_local::connect_for_attestation(port,SecretBytes::new(password.into_bytes())).await.unwrap();
        let database = site.attest_postgres_admin(admin).await.unwrap().connect_application(false).await.unwrap();
        let canary = desktop_vault_canary::verify_persisted(&database,&master,&dataset,DEP,TENANT,&key_id).await.unwrap();
        runtime.verify_restored_local_before(&database,&canary,["test.vault","test.postgres"],&site).await.unwrap();
        let pool = database.clone_pool();
        assert!(runtime.read_gate().matches_server_scope(&pool,DEP,TENANT));
        Self { runtime:Some(runtime),pool,cohort,database:Some(database),_pg:pg }
    }
}

impl Drop for CurrentFixture {
    fn drop(&mut self) {
        self.runtime.take();
        self.pool.close();
        if let Some(database) = self.database.take() { database.close(); }
    }
}
