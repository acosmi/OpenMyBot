//! Real owned-PG/Begin/Save/FD tests through the new CORE consumer.
//! The Session host issuer below is a test seam; real Server/Desktop acceptance is separate.
//! Static phases and gate ACK are not substitutes for actual PG Lock/PID/COMMIT evidence.

use std::fs::{self, File, Permissions};
use std::future::Future;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use openbot_application::ArtifactAdministration;
use openbot_application::{BeginThreadRunRequest, ThreadDirectory};
use openbot_contracts::artifacts::{ArtifactGoneStatus, SaveRunMessageTextArtifact};
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_contracts::request_binding::{
    HostRequestBindingGuard, RequestBindingIssuer, RequestBindingOwnerLease,
    ServerSessionBindingIdentity,
};
use openbot_domain::artifact::ArtifactQuotaPolicy;
use openbot_domain::vault::SecretBytes;
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::artifact_bytes::{ArtifactByteError, MAX_ARTIFACT_READ_CHUNK_BYTES};
use crate::artifact_registry::ArtifactDatasetRegistry;
use crate::artifact_store::{
    ArtifactReadBridgeError, DatasetBoundArtifactStore, StoreBoundArtifactReader,
};
use crate::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthorityStore,
};
use crate::db::pool::DatabaseConfig;
use crate::db::{baseline, native, pool};
use crate::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};

mod harness {
    use crate as openbot_infra;
    include!("../../../../test-support/postgres_harness.rs");
}

const DEPLOYMENT: &str = "artifact-read-owned-deployment";
const TENANT: &str = "artifact-read-owned-tenant";
const OWNER: &str = "read-owner";
const OTHER: &str = "read-other";
const EXACT: &str = "  PRIVATE_READ_SOURCE_CANARY\n成果 café 🦀\t  ";

#[cfg(target_os = "macos")]
fn shared_pg_owned_fds(path: &std::path::Path) -> Result<std::collections::BTreeSet<u32>, String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        metadata.is_file() && metadata.nlink() == 1,
        "owned FD oracle requires original regular inode",
    )?;
    let device = metadata.dev() & u64::from(u32::MAX);
    let inode = metadata.ino();
    let sample = || -> Result<std::collections::BTreeSet<u32>, String> {
        let pid = std::process::id();
        let mut child = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", "-p", &pid.to_string(), "-FfDi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "own-PID lsof is unavailable (Unproven)".to_owned())?;
        let stdout = child.stdout.take().ok_or("lsof stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("lsof stderr unavailable")?;
        let output = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(65_537).read_to_end(&mut bytes).map(|_| bytes)
        });
        let errors = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.take(8_193).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output.join();
                let _ = errors.join();
                return Err("own-PID lsof exceeded original five seconds (Unproven)".to_owned());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let output = output
            .join()
            .map_err(|_| "lsof output worker panicked")?
            .map_err(|error| error.to_string())?;
        let errors = errors
            .join()
            .map_err(|_| "lsof error worker panicked")?
            .map_err(|error| error.to_string())?;
        require(
            status.success()
                && output.len() <= 65_536
                && errors.len() <= 8_192
                && output.ends_with(b"\n"),
            "lsof incomplete/failed/truncated (Unproven)",
        )?;
        let text = std::str::from_utf8(&output).map_err(|_| "lsof output invalid (Unproven)")?;
        let mut self_pid = false;
        let mut fd = None;
        let mut dev = None;
        let mut ino = None;
        let mut found = std::collections::BTreeSet::new();
        for line in text.lines().chain(std::iter::once("f")) {
            let (kind, value) = line
                .split_at_checked(1)
                .ok_or("lsof empty field (Unproven)")?;
            match kind {
                "p" => {
                    require(
                        value.parse::<u32>().ok() == Some(pid),
                        "lsof observed another PID",
                    )?;
                    self_pid = true;
                }
                "f" => {
                    if dev == Some(device) && ino == Some(inode) {
                        found.insert(
                            fd.ok_or("original inode has an ambiguous nonnumeric FD (Unproven)")?,
                        );
                    }
                    fd = value.parse::<u32>().ok();
                    dev = None;
                    ino = None;
                }
                "D" => {
                    dev = Some(
                        if let Some(hex) = value.strip_prefix("0x") {
                            u64::from_str_radix(hex, 16)
                        } else {
                            value.parse::<u64>()
                        }
                        .map_err(|_| "lsof device invalid (Unproven)")?,
                    );
                }
                "i" => {
                    ino = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| "lsof inode invalid (Unproven)")?,
                    );
                }
                _ => return Err("lsof unexpected field (Unproven)".to_owned()),
            }
        }
        require(self_pid, "lsof self-PID field missing (Unproven)")?;
        Ok(found)
    };
    let first = sample()?;
    let second = sample()?;
    require(
        first == second,
        "own original FD inventory was unstable (Unproven)",
    )?;
    Ok(first)
}

// Controlled fences below are database inputs to the actual reader. They do not constitute
// cleanup authorization, physical deletion, directory sync, refund or producer acceptance.
const CLEANUP_CONSUMER_FACTS: &str = "SELECT jsonb_build_object( \
 'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY to_jsonb(o)::text),'[]') FROM openbot_internal.artifact_save_operations o), \
 'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_records r), \
 'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM openbot_internal.artifact_saved_receipts r), \
 'stores',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]') FROM openbot_internal.artifact_store_bindings s), \
 'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q), \
 'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q), \
 'fences',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]') FROM openbot_internal.artifact_cleanup_fences f), \
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))";

async fn cleanup_consumer_facts_on(client: &tokio_postgres::Client) -> Result<Value, String> {
    client
        .query_one(CLEANUP_CONSUMER_FACTS, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

async fn cleanup_consumer_facts(f: &Fixture) -> Result<Value, String> {
    let client = f.pool.get().await.map_err(|error| error.to_string())?;
    cleanup_consumer_facts_on(&client).await
}

async fn arm_original_cleanup(f: &Fixture, id: &str, terminal: &str) -> Result<(), String> {
    let client = f.pool.get().await.map_err(|error| error.to_string())?;
    let changed = client
        .execute(
            "INSERT INTO openbot_internal.artifact_cleanup_fences \
         (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
         SELECT deployment_id,tenant_id,dataset_id,operation_id,artifact_id,$4,'armed' \
         FROM openbot_internal.artifact_records \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$5",
            &[
                &DEPLOYMENT,
                &TENANT,
                &f.registry.binding().dataset_id(),
                &terminal,
                &id,
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
    require(
        changed == 1,
        "controlled fence did not bind exactly the original saved row",
    )
}

async fn complete_original_cleanup_fixture(
    f: &Fixture,
    id: &str,
    terminal: &str,
) -> Result<(), String> {
    let mut client = f.pool.get().await.map_err(|error| error.to_string())?;
    let transaction = client
        .transaction()
        .await
        .map_err(|error| error.to_string())?;
    let parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 5] = [
        &DEPLOYMENT,
        &TENANT,
        &f.registry.binding().dataset_id(),
        &id,
        &terminal,
    ];
    let records = transaction.execute(
        "UPDATE openbot_internal.artifact_records SET status=$5,workspace_kind=NULL,workspace_id=NULL, \
         media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4", &parameters,
    ).await.map_err(|error| error.to_string())?;
    let operations = transaction.execute(
        "UPDATE openbot_internal.artifact_save_operations SET state=$5,store_id=NULL,workspace_kind=NULL,workspace_id=NULL, \
         expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL, \
         actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4", &parameters,
    ).await.map_err(|error| error.to_string())?;
    require(
        records == 1 && operations == 1,
        "controlled terminal pair was not the original pair",
    )?;
    let completed = transaction.execute(
        "UPDATE openbot_internal.artifact_cleanup_fences SET phase='completed' \
         WHERE deployment_id=$1 AND tenant_id=$2 AND dataset_id=$3 AND artifact_id=$4 AND terminal_status=$5", &parameters,
    ).await.map_err(|error| error.to_string())?;
    require(
        completed == 1,
        "real fence guard did not complete exactly the controlled terminal pair",
    )?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())
}

async fn close_cleanup_fixture(f: &Fixture) -> Result<(), String> {
    let lifecycle = f.administration.read_authority().read_lifecycle();
    lifecycle.close();
    lifecycle
        .drain_before(Instant::now() + Duration::from_secs(3))
        .await
        .map_err(|error| format!("{error:?}"))?;
    let observations = f.pool.connection_observations();
    f.pool.close();
    let cleanup_deadline = Instant::now() + Duration::from_secs(3);
    for observation in observations {
        require(
            observation
                .wait_for_destruction_before(cleanup_deadline)
                .await
                .map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "original reader fixture connection did not actually destruct",
        )?;
    }
    Ok(())
}

#[derive(Default)]
struct CleanupPreparationObserver {
    completion: std::sync::Mutex<
        Option<
            Arc<dyn openbot_application::artifact_read_protocol::ArtifactReadOperationCompletion>,
        >,
    >,
}
impl openbot_application::artifact_read_protocol::ArtifactReadPreparationObserver
    for CleanupPreparationObserver
{
    fn enrolled(
        &self,
        completion: Arc<
            dyn openbot_application::artifact_read_protocol::ArtifactReadOperationCompletion,
        >,
    ) -> Result<(), AppError> {
        let mut slot = self
            .completion
            .lock()
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "artifacts",
            })?;
        if slot.is_some() {
            return Err(AppError::DependencyUnavailable {
                dependency: "artifacts",
            });
        }
        *slot = Some(completion);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and actual Save/store/current-reader observations"]
async fn cleanup_fence_initial_and_final_classification_are_read_only() {
    for (status, armed, host_current, source_visible) in [
        ("available", false, true, true),
        ("available", true, true, true),
        ("available", true, false, true),
        ("available", true, true, false),
        ("available", true, false, false),
        ("deleted", true, true, true),
        ("expired", true, true, true),
        ("deleted", true, false, true),
        ("deleted", true, true, false),
    ] {
        with_fixture("cleanup_reader_classes", false, |f| async move {
            let saved = f.save().await?;
            if armed {
                arm_original_cleanup(
                    &f,
                    &saved.artifact_id,
                    if status == "expired" {
                        "expired"
                    } else {
                        "deleted"
                    },
                )
                .await?;
            }
            if status != "available" {
                complete_original_cleanup_fixture(&f, &saved.artifact_id, status).await?;
            }
            let initial = f.observe(&saved.artifact_id).await;
            require(
                match status {
                    "deleted" => matches!(
                        initial,
                        Err(ArtifactAdministrationError::Gone {
                            status: ArtifactGoneStatus::Deleted
                        })
                    ),
                    "expired" => matches!(
                        initial,
                        Err(ArtifactAdministrationError::Gone {
                            status: ArtifactGoneStatus::Expired
                        })
                    ),
                    _ if armed => matches!(initial, Err(ArtifactAdministrationError::Unavailable)),
                    _ => initial.is_ok(),
                },
                "initial actual fence observation classified the original row incorrectly",
            )?;
            if !host_current {
                f.sql("DELETE FROM public.sessions WHERE id='core-read-session-a'")
                    .await?;
            }
            if !source_visible {
                f.sql("DELETE FROM public.thread_memberships WHERE user_id='read-owner'")
                    .await?;
            }
            let before = cleanup_consumer_facts(&f).await?;
            let auth = f.auth();
            let result = f
                .administration
                .read_host_bound_chunk(&auth, &saved.artifact_id)
                .await;
            require(
                if !host_current {
                    matches!(result, Err(AppError::Unauthenticated))
                } else if !source_visible {
                    matches!(result, Err(AppError::NotVisible))
                } else if status == "deleted" {
                    matches!(
                        result,
                        Err(AppError::ArtifactGone {
                            status: ArtifactGoneStatus::Deleted
                        })
                    )
                } else if status == "expired" {
                    matches!(
                        result,
                        Err(AppError::ArtifactGone {
                            status: ArtifactGoneStatus::Expired
                        })
                    )
                } else if armed {
                    matches!(
                        result,
                        Err(AppError::DependencyUnavailable {
                            dependency: "artifacts"
                        })
                    )
                } else {
                    result
                        .map_err(|error| error.to_string())?
                        .handoff(&auth)
                        .map_err(|error| error.to_string())?
                        == EXACT.as_bytes()
                },
                "actual final host/source/terminal/armed classification changed or released bytes",
            )?;
            let after = cleanup_consumer_facts(&f).await?;
            require(
                before == after,
                "actual initial/final consumer changed business or fence rows",
            )?;
            require(
                f.object(&saved.artifact_id).is_file(),
                "controlled tombstone was mistaken for actual deletion",
            )?;
            close_cleanup_fixture(&f).await
        })
        .await;
    }
    for drift in ["ledger_checksum", "guard_disabled", "extra_catalog_column"] {
        with_fixture("cleanup_reader_schema_drift", false, |f| async move {
            let saved = f.save().await?;
            f.sql(match drift {
                "ledger_checksum" => "UPDATE openbot_internal.schema_migrations SET checksum=repeat('0',64) WHERE version=44",
                "guard_disabled" => "ALTER TABLE openbot_internal.artifact_cleanup_fences DISABLE TRIGGER artifact_cleanup_fences_identity_guard",
                _ => "ALTER TABLE openbot_internal.artifact_cleanup_fences ADD COLUMN controlled_drift integer",
            }).await?;
            let client = f.pool.get().await.map_err(|error| error.to_string())?;
            let schema_before = crate::db::artifact_cleanup_schema::capture(&client).await.map_err(|error| error.to_string())?;
            drop(client);
            let before = cleanup_consumer_facts(&f).await?;
            require(f.observe(&saved.artifact_id).await.is_err(), "initial reader accepted actual schema drift")?;
            let auth = f.auth();
            require(f.administration.read_host_bound_chunk(&auth, &saved.artifact_id).await.is_err(), "final reader accepted actual schema drift")?;
            let probe = public_read_prepare::PublicPrepareProbe::new();
            *f.administration.read_authority().public_prepare_probe.lock().map_err(|_| "probe slot poisoned")? = Some(Arc::clone(&probe));
            let observer = Arc::new(CleanupPreparationObserver::default());
            let prepared = f.administration.prepare_host_bound_artifact_read(
                &auth, &saved.artifact_id, Instant::now() + Duration::from_secs(5), observer.clone(),
            ).await;
            require(prepared.is_err(), "public prepare accepted actual schema drift")?;
            require(probe.sha_segments.load(Ordering::SeqCst) == 0 && probe.prefix.lock().map_err(|_| "prefix probe poisoned")?.is_none(), "schema drift caused extra actual SHA or prefix IO")?;
            let original_state = probe.state.lock().map_err(|_| "probe state poisoned")?.upgrade();
            if let Some(state) = original_state {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while state.actual_jobs() != 0 { tokio::time::sleep(Duration::from_millis(1)).await; }
                }).await.map_err(|_| "original schema rejection collector did not finish".to_owned())?;
                let data = state.data.lock().map_err(|_| "read state poisoned")?;
                require(state.actual_jobs() == 0 && data.reader.is_none() && data.resource.is_none(), "schema rejection retained physical reader work")?;
            }
            drop(prepared);
            drop(observer);
            let after = cleanup_consumer_facts(&f).await?;
            require(before == after, "schema rejection repaired or changed business/fence rows")?;
            let client = f.pool.get().await.map_err(|error| error.to_string())?;
            require(schema_before == crate::db::artifact_cleanup_schema::capture(&client).await.map_err(|error| error.to_string())?, "reader repaired actual ledger/catalog/guard drift")?;
            drop(client);
            close_cleanup_fixture(&f).await
        }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL, actual A Save/store and legal controlled B rows"]
async fn cleanup_fence_exact_five_key_scope_ignores_other_original_record() {
    with_fixture("cleanup_reader_exact_scope", false, |f| async move {
        let saved = f.save().await?;
        let dataset = f.registry.binding().dataset_id().to_owned();
        // These legal terminal B pairs have no producer receipt or physical object. They are
        // controlled inputs only. A below remains the actual saved-and-readable artifact.
        for (deployment, tenant, other_dataset, artifact) in [
            ("other-deployment".to_owned(), TENANT.to_owned(), dataset.clone(), saved.artifact_id.clone()),
            (DEPLOYMENT.to_owned(), "other-tenant".to_owned(), dataset.clone(), saved.artifact_id.clone()),
            (DEPLOYMENT.to_owned(), TENANT.to_owned(), "other-dataset".to_owned(), saved.artifact_id.clone()),
            (DEPLOYMENT.to_owned(), TENANT.to_owned(), dataset.clone(), Uuid::now_v7().to_string()),
        ] {
            let operation = Uuid::now_v7().to_string();
            let request = Uuid::now_v7().to_string();
            let mut client = f.pool.get().await.map_err(|error| error.to_string())?;
            let transaction = client.transaction().await.map_err(|error| error.to_string())?;
            let parameters: [&(dyn tokio_postgres::types::ToSql + Sync); 10] = [
                &deployment, &tenant, &other_dataset, &operation, &request, &artifact,
                &DEPLOYMENT, &TENANT, &dataset, &saved.artifact_id,
            ];
            let operations = transaction.execute(
                "INSERT INTO openbot_internal.artifact_save_operations \
                 (deployment_id,tenant_id,dataset_id,operation_id,request_id,artifact_id,owner_actor_id, \
                  source_thread_id,source_run_id,source_message_id,source_call_seq,source_attempt_seq,state) \
                 SELECT $1,$2,$3,$4,$5,$6,owner_actor_id,source_thread_id,source_run_id,source_message_id, \
                        source_call_seq,source_attempt_seq,'deleted' FROM openbot_internal.artifact_records \
                 WHERE deployment_id=$7 AND tenant_id=$8 AND dataset_id=$9 AND artifact_id=$10", &parameters,
            ).await.map_err(|error| error.to_string())?;
            let records = transaction.execute(
                "INSERT INTO openbot_internal.artifact_records \
                 (deployment_id,tenant_id,dataset_id,operation_id,request_id,artifact_id,owner_actor_id, \
                  source_thread_id,source_run_id,source_message_id,source_call_seq,source_attempt_seq,status) \
                 SELECT $1,$2,$3,$4,$5,$6,owner_actor_id,source_thread_id,source_run_id,source_message_id, \
                        source_call_seq,source_attempt_seq,'deleted' FROM openbot_internal.artifact_records \
                 WHERE deployment_id=$7 AND tenant_id=$8 AND dataset_id=$9 AND artifact_id=$10", &parameters,
            ).await.map_err(|error| error.to_string())?;
            require(operations == 1 && records == 1, "controlled legal B pair did not satisfy the original 0042 relation")?;
            let fences = transaction.execute(
                "INSERT INTO openbot_internal.artifact_cleanup_fences \
                 (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
                 VALUES($1,$2,$3,$4,$5,'deleted','armed')", &[&deployment, &tenant, &other_dataset, &operation, &artifact],
            ).await.map_err(|error| error.to_string())?;
            require(fences == 1, "controlled B fence failed the original five-key FK")?;
            transaction.commit().await.map_err(|error| error.to_string())?;
            drop(client);
            let before = cleanup_consumer_facts(&f).await?;
            let auth = f.auth();
            let body = f.administration.read_host_bound_chunk(&auth, &saved.artifact_id).await
                .map_err(|error| error.to_string())?.handoff(&auth).map_err(|error| error.to_string())?;
            require(body == EXACT.as_bytes(), "another legal namespace/dataset/artifact fence blocked actual A bytes")?;
            require(before == cleanup_consumer_facts(&f).await?, "isolated A read changed controlled B rows")?;
        }
        let client = f.pool.get().await.map_err(|error| error.to_string())?;
        let before = cleanup_consumer_facts_on(&client).await?;
        let wrong_operation = Uuid::now_v7().to_string();
        let refused = client.execute(
            "INSERT INTO openbot_internal.artifact_cleanup_fences \
             (deployment_id,tenant_id,dataset_id,operation_id,artifact_id,terminal_status,phase) \
             VALUES($1,$2,$3,$4,$5,'deleted','armed')", &[&DEPLOYMENT, &TENANT, &dataset, &wrong_operation, &saved.artifact_id],
        ).await.err().ok_or("original five-key FK accepted a nonexistent wrong operation")?;
        require(refused.code() == Some(&tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION), "wrong-operation input was not rejected by the actual FK")?;
        require(before == cleanup_consumer_facts_on(&client).await?, "refused wrong-operation input changed business rows")?;

        // These SELECT rows are pure decoder inputs, not legal stored wrong-operation fences.
        let base = [
            Some("strict-deployment café".to_owned()), Some("strict-tenant".to_owned()),
            Some("strict-dataset".to_owned()), Some("0199b000-aaaa-7aaa-8aaa-aaaaaaaaaaaa".to_owned()),
            Some("0199b001-bbbb-7bbb-9bbb-bbbbbbbbbbbb".to_owned()), Some("deleted".to_owned()), Some("armed".to_owned()),
        ];
        let expected = openbot_domain::artifact_cleanup::ArtifactCleanupFenceKey::from_stored(
            DeploymentId::new(base[0].as_deref().unwrap()), TenantId::new(base[1].as_deref().unwrap()),
            base[2].as_deref().unwrap(), base[3].as_deref().unwrap(), base[4].as_deref().unwrap(),
        ).map_err(|error| error.to_string())?;
        const ROW_SQL: &str = "SELECT $1::text AS cleanup_deployment_id,$2::text AS cleanup_tenant_id, \
            $3::text AS cleanup_dataset_id,$4::text AS cleanup_operation_id,$5::text AS cleanup_artifact_id, \
            $6::text AS cleanup_terminal_status,$7::text AS cleanup_phase";
        let row = client.query_one(ROW_SQL, &[&base[0], &base[1], &base[2], &base[3], &base[4], &base[5], &base[6]])
            .await.map_err(|error| error.to_string())?;
        require(super::super::decode_read_cleanup_fence(&row, &expected).map_err(|error| error.to_string())?.is_some(), "valid pure decoder fence disappeared")?;
        let absent: Option<String> = None;
        let row = client.query_one(ROW_SQL, &[&absent, &absent, &absent, &absent, &absent, &absent, &absent])
            .await.map_err(|error| error.to_string())?;
        require(super::super::decode_read_cleanup_fence(&row, &expected).map_err(|error| error.to_string())?.is_none(), "all-seven-NULL was not the only absent shape")?;
        let mut inputs = Vec::new();
        for index in 0..7 { let mut partial = base.clone(); partial[index] = None; inputs.push(partial); }
        for (index, value) in [
            (0, "different-deployment"), (1, "different-tenant"), (2, "different-dataset"),
            (3, "0199b002-cccc-7ccc-accc-cccccccccccc"), (4, "0199b003-dddd-7ddd-bddd-dddddddddddd"),
            (0, "bad\u{0085}deployment"), (2, ""), (3, "0199B000-AAAA-7AAA-8AAA-AAAAAAAAAAAA"),
            (4, "0199B001-BBBB-7BBB-9BBB-BBBBBBBBBBBB"), (3, "bad-uuid"), (5, "available"), (6, "rearmed"),
        ] { let mut invalid = base.clone(); invalid[index] = Some(value.to_owned()); inputs.push(invalid); }
        for input in inputs {
            let row = client.query_one(ROW_SQL, &[&input[0], &input[1], &input[2], &input[3], &input[4], &input[5], &input[6]])
                .await.map_err(|error| error.to_string())?;
            require(matches!(super::super::decode_read_cleanup_fence(&row, &expected), Err(ArtifactAdministrationError::Corrupt { field: "read_cleanup_fence" })), "partial/invalid/five-key pure row was accepted or exposed a dynamic error")?;
        }
        let row = client.query_one("SELECT 1::integer AS cleanup_deployment_id,NULL::text AS cleanup_tenant_id,NULL::text AS cleanup_dataset_id,NULL::text AS cleanup_operation_id,NULL::text AS cleanup_artifact_id,NULL::text AS cleanup_terminal_status,NULL::text AS cleanup_phase", &[])
            .await.map_err(|error| error.to_string())?;
        require(matches!(super::super::decode_read_cleanup_fence(&row, &expected), Err(ArtifactAdministrationError::Corrupt { field: "read_cleanup_fence" })), "wrong PostgreSQL decoder type was accepted")?;
        drop(client);
        arm_original_cleanup(&f, &saved.artifact_id, "deleted").await?;
        require(matches!(f.observe(&saved.artifact_id).await, Err(ArtifactAdministrationError::Unavailable)), "exact original A armed fence failed to block A")?;
        close_cleanup_fixture(&f).await
    }).await;
}

async fn wait_original_cleanup_schema_lock(
    observer: &tokio_postgres::Client,
    controller_pid: i32,
    original_pid: i32,
    deadline: Instant,
) -> Result<(), String> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        loop {
            let rows = observer.query(
                "SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() \
                 AND a.pid<>pg_backend_pid() AND a.state='active' AND a.wait_event_type='Lock' \
                 AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)) \
                 AND a.query='SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=$1'", &[&controller_pid],
            ).await.map_err(|error| error.to_string())?;
            if !rows.is_empty() {
                require(rows.len() == 1 && rows[0].get::<_, i32>(0) == original_pid, "schema Lock waiter did not uniquely belong to the original saved observation")?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| "original pre-BEGIN native schema Lock waiter was not observed".to_owned())?
}

async fn wait_original_cleanup_backend_gone(
    observer: &tokio_postgres::Client,
    original_pid: i32,
    cleanup_deadline: Instant,
) -> Result<(), String> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(cleanup_deadline), async {
        loop {
            let present: bool = observer.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid=$1)", &[&original_pid],
            ).await.map_err(|error| error.to_string())?.get(0);
            if !present { return Ok(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| "same original reader backend remained after actual local destruction".to_owned())?
}

async fn cleanup_schema_original_owner_control(
    config: DatabaseConfig,
    cancel: bool,
) -> Result<(), String> {
    let external = pool::connect(&config.clone().with_max_pool_size(2))
        .await
        .map_err(|error| error.to_string())?;
    let f = Fixture::new(config, false).await?;
    let saved = f.save().await?;
    let mut controller = external.get().await.map_err(|error| error.to_string())?;
    let observer = external.get().await.map_err(|error| error.to_string())?;
    let controller_pid: i32 = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let observer_pid: i32 = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        controller_pid != observer_pid,
        "original controller and observer did not have distinct actual PIDs",
    )?;
    let before = cleanup_consumer_facts_on(&observer).await?;
    let setup_deadline = Instant::now() + Duration::from_secs(5);
    let mut held = tokio::time::timeout_at(tokio::time::Instant::from_std(setup_deadline), async {
        let mut clients = Vec::new();
        for _ in 0..8 {
            let client = f.pool.get().await.map_err(|error| error.to_string())?;
            let pid: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|error| error.to_string())?
                .get(0);
            let observation = client.observation();
            require(
                observation.snapshot().connection_started
                    && !observation.snapshot().retirement_requested,
                "original probe was not a live actually started Connection",
            )?;
            clients.push((client, pid, observation));
        }
        Ok::<_, String>(clients)
    })
    .await
    .map_err(|_| "actual max8 original Pool checkout setup did not complete".to_owned())??;
    let pids: std::collections::BTreeSet<_> = held.iter().map(|(_, pid, _)| *pid).collect();
    require(
        pids.len() == 8 && !pids.contains(&controller_pid) && !pids.contains(&observer_pid),
        "reader Pool or independent controllers did not have distinct actual PIDs",
    )?;
    require(
        f.pool.status().available == 0 && f.pool.connection_observations().len() == 8,
        "original Pool did not have exactly eight exclusively held connections",
    )?;
    let (probe, original_pid, original_observation) =
        held.pop().ok_or("original eighth probe missing")?;
    // Registered test-only setting on this exact probe while all eight leases are held. It
    // makes the backend's disconnected-client observation finite during its lock wait.
    probe
        .batch_execute("SET client_connection_check_interval='10ms'")
        .await
        .map_err(|error| error.to_string())?;
    let connection_check: String = probe
        .query_one(
            "SELECT current_setting('client_connection_check_interval')",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        connection_check == "10ms",
        "original probe did not actually use its registered 10ms client-disconnect check",
    )?;
    let mut transaction = Some(
        controller
            .transaction()
            .await
            .map_err(|error| error.to_string())?,
    );
    transaction.as_ref().unwrap().batch_execute(
        "SET LOCAL lock_timeout='1s'; LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE",
    ).await.map_err(|error| error.to_string())?;
    drop(probe); // Only this exact actual object can be recycled by the original reader.
    let original_deadline = Instant::now() + Duration::from_secs(if cancel { 5 } else { 3 });
    let administration = Arc::clone(&f.administration);
    let auth = f.auth();
    let id = saved.artifact_id.clone();
    let mut original_task = Some(tokio::spawn(async move {
        administration
            .observe_read_record_before_inner(&auth, &id, original_deadline)
            .await
    }));
    let attempted = async {
        wait_original_cleanup_schema_lock(&observer, controller_pid, original_pid,
            original_deadline.min(Instant::now() + Duration::from_secs(2))).await?;
        require(Instant::now() < original_deadline && !original_task.as_ref().unwrap().is_finished(), "original deadline expired or task ended before actual schema wait control")?;
        if cancel {
            original_task.as_ref().unwrap().abort();
            let cancelled = tokio::time::timeout(Duration::from_secs(2), original_task.as_mut().unwrap()).await
                .map_err(|_| "original schema reader cancellation was not reaped".to_owned())?;
            drop(original_task.take());
            require(matches!(cancelled, Err(error) if error.is_cancelled()), "original schema reader did not reap as the exact cancelled task")?;
        } else {
            // This outer bound only supervises the JoinHandle. The operation retains its one
            // original 3s absolute deadline; no fresh deadline is passed to product code.
            let result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(original_deadline + Duration::from_secs(2)), original_task.as_mut().unwrap(),
            ).await.map_err(|_| "original schema deadline task failed to reap".to_owned())?
                .map_err(|_| "original schema deadline task did not finish normally with refusal".to_owned())?;
            drop(original_task.take());
            require(Instant::now() >= original_deadline, "schema reader returned before the controlled original deadline")?;
            require(matches!(result, Err(super::super::PublicReadRecordFailure {
                error: ArtifactAdministrationError::Unavailable, rollback_unproven: true,
            })), "expired original schema reader produced a record or reusable/ACKed outcome")?;
        }
        // A separate finite cleanup budget witnesses destruction only. It cannot produce an
        // original record, normal witness, rollback ACK or successful deadline result.
        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        require(original_observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?
            == pool::ConnectionDestruction::ConnectionDestroyed, "exact original schema Connection was not actually destroyed")?;
        require(original_observation.snapshot().retirement_requested && original_observation.snapshot().connection_destroyed, "original schema Connection became reusable instead of permanently retired")?;
        wait_original_cleanup_backend_gone(&observer, original_pid, cleanup_deadline).await?;
        require(transaction.is_some(), "controller lock was released before original destruction/PID-gone proof")?;
        eprintln!("ARTIFACT_CLEANUP_SCHEMA_OWNER cancel={cancel} original_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_schema_lock=true original_connection_destroyed=true original_backend_gone=true original_success=false");
        Ok::<(), String>(())
    }.await;
    let rescue = if let Some(mut task) = original_task.take() {
        task.abort();
        match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            Ok(_) => Ok(()),
            Err(_) => {
                // Keep the exact handle until it really reaps; a timeout cannot detach it.
                task.abort();
                let _ = task.await;
                Err(
                    "original failed-control task cancellation exceeded its cleanup bound"
                        .to_owned(),
                )
            }
        }
    } else {
        Ok(())
    };
    let rollback = match transaction.take() {
        Some(transaction) => tokio::time::timeout(Duration::from_secs(2), transaction.rollback())
            .await
            .map_err(|_| "original controller rollback did not finish".to_owned())?
            .map_err(|error| error.to_string()),
        None => Err("original controller transaction was lost before rollback ACK".to_owned()),
    };
    drop(transaction);
    let after = cleanup_consumer_facts_on(&observer).await;
    drop(held); // All seven still-held original leases finish before Pool close.
    let closed = close_cleanup_fixture(&f).await;
    let external_observations = external.connection_observations();
    drop(observer);
    drop(controller);
    external.close();
    let cleanup_deadline = Instant::now() + Duration::from_secs(3);
    let mut external_closed = Ok(());
    for observation in external_observations {
        if let Err(error) = observation
            .wait_for_destruction_before(cleanup_deadline)
            .await
        {
            external_closed = Err(error.to_string());
        }
    }
    attempted?;
    rescue?;
    rollback?;
    require(
        before == after?,
        "schema wait refusal changed original business/charge/receipt/fence/audit rows",
    )?;
    closed?;
    external_closed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and true original schema Lock/PID/Connection destruction"]
async fn reader_cleanup_schema_wait_cancellation_retires_original_connection() {
    let tag = "cleanup_schema_cancel";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        cleanup_schema_original_owner_control(config, true).await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL and true original deadline/schema Connection destruction"]
async fn reader_cleanup_schema_original_deadline_wait_does_not_become_reusable() {
    let tag = "cleanup_schema_deadline";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        cleanup_schema_original_owner_control(config, false).await
    })
    .await;
}

// These counters observe actual producer traces. PG waiting and ACK are proved separately
// by the exact original connection, Lock/PID, controller and selected backend ROLLBACK frame.
#[derive(Default)]
struct SharedPgReadPhases {
    io: AtomicUsize,
    joint: AtomicUsize,
    segments: AtomicUsize,
    // R432 control-before observes through the same final statement path before any IO.
    // The single-shot test gate is armed only by the actual after-IO trace, so it still
    // selects the final joint rather than the earlier control query.
    final_gate_after_io: std::sync::Mutex<
        Option<(
            std::sync::Weak<PostgresArtifactReadAuthority>,
            FinalQueryGate,
        )>,
    >,
}
type FinalQueryGate = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);
impl SharedPgReadPhases {
    fn after_io(authority: &Arc<PostgresArtifactReadAuthority>, gate: FinalQueryGate) -> Arc<Self> {
        let phases = Self::default();
        *phases.final_gate_after_io.lock().unwrap() = Some((Arc::downgrade(authority), gate));
        Arc::new(phases)
    }
    fn arm_final_gate(&self) {
        let armed = self
            .final_gate_after_io
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some((authority, gate)) = armed
            && let Some(authority) = authority.upgrade()
            && let Ok(mut slot) = authority.final_query_gate.lock()
        {
            *slot = Some(gate);
        }
    }
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.io.load(Ordering::SeqCst),
            self.joint.load(Ordering::SeqCst),
            self.segments.load(Ordering::SeqCst),
        )
    }
}
struct SharedPgPhaseVisitor {
    io: bool,
    joint: bool,
    segment: bool,
}
impl tracing::field::Visit for SharedPgPhaseVisitor {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match (field.name(), value) {
            ("artifact_read_phase", "actual_io_completed_before_joint") => self.io = true,
            ("artifact_read_phase", "joint_statement_ready") => self.joint = true,
            ("artifact_read_lifecycle_phase", "physical_segment_completed_before_more_io") => {
                self.segment = true
            }
            _ => {}
        }
    }
}
struct SharedPgPhaseSubscriber(Arc<SharedPgReadPhases>);
impl tracing::Subscriber for SharedPgPhaseSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = SharedPgPhaseVisitor {
            io: false,
            joint: false,
            segment: false,
        };
        event.record(&mut visitor);
        if visitor.io {
            self.0.io.fetch_add(1, Ordering::SeqCst);
            self.0.arm_final_gate();
        }
        if visitor.joint {
            self.0.joint.fetch_add(1, Ordering::SeqCst);
        }
        if visitor.segment {
            self.0.segments.fetch_add(1, Ordering::SeqCst);
        }
    }
}

async fn shared_pg_original_probe(
    f: &Fixture,
    controller_pid: i32,
    observer_pid: i32,
) -> Result<
    (
        Vec<pool::PooledClient>,
        pool::PooledClient,
        i32,
        pool::ConnectionObservation,
    ),
    String,
> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut held = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(f.pool.get().await.map_err(|error| error.to_string())?);
        }
        Ok::<_, String>(held)
    })
    .await
    .map_err(|_| "shared original max8 checkout did not finish")??;
    let mut pids = std::collections::BTreeSet::new();
    for client in &held {
        let pid: i32 = client
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|error| error.to_string())?
            .get(0);
        pids.insert(pid);
    }
    require(
        pids.len() == 8
            && !pids.contains(&controller_pid)
            && !pids.contains(&observer_pid)
            && controller_pid != observer_pid
            && f.pool.status().available == 0
            && f.pool.connection_observations().len() == 8,
        "shared original reader leases and independent controllers were not exclusive actual owners",
    )?;
    let probe = held.pop().ok_or("original eighth shared probe missing")?;
    let pid = probe
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let observation = probe.observation();
    require(
        observation.snapshot().connection_started && !observation.snapshot().retirement_requested,
        "shared original probe did not retain a started original connection",
    )?;
    // Reuse the registered Task016 exact-probe disconnect control; no production setting.
    probe
        .batch_execute("SET client_connection_check_interval='10ms'")
        .await
        .map_err(|error| error.to_string())?;
    let actual: String = probe
        .query_one(
            "SELECT current_setting('client_connection_check_interval')",
            &[],
        )
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    require(
        actual == "10ms",
        "shared original probe disconnect control was not actually set",
    )?;
    Ok((held, probe, pid, observation))
}

async fn shared_pg_final_lock(
    observer: &tokio_postgres::Client,
    controller_pid: i32,
    original_pid: i32,
    deadline: Instant,
) -> Result<(), String> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        loop {
            let rows = observer.query(
                "SELECT a.pid FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database() \
                 AND a.state='active' AND a.wait_event_type='Lock' AND a.pid<>pg_backend_pid() \
                 AND $1=ANY(pg_catalog.pg_blocking_pids(a.pid)) \
                 AND a.query LIKE '/* artifact_current_host_joint_read_after_io */ %'", &[&controller_pid],
            ).await.map_err(|error| error.to_string())?;
            if !rows.is_empty() {
                require(rows.len() == 1 && rows[0].get::<_, i32>(0) == original_pid,
                    "actual shared final Lock/PID did not uniquely belong to the original held connection")?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| "actual shared final statement Lock/PID was not observed".to_owned())?
}

async fn shared_pg_destroy_pool(pool: &Pool) -> Result<(), String> {
    let observations = pool.connection_observations();
    pool.close();
    let deadline = Instant::now() + Duration::from_secs(3);
    for original in observations {
        require(
            original
                .wait_for_destruction_before(deadline)
                .await
                .map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed,
            "shared PG original connection did not actually destruct",
        )?;
    }
    Ok(())
}

async fn shared_pg_other_key_remains_readable(f: &Fixture, id: &str) -> Result<(), String> {
    let auth = f.auth();
    let bytes = f
        .administration
        .read_host_bound_chunk(&auth, id)
        .await
        .map_err(|error| error.to_string())?
        .handoff(&auth)
        .map_err(|error| error.to_string())?;
    require(
        bytes == EXACT.as_bytes(),
        "original unproved key polluted a different actual Save",
    )?;
    drop(bytes); // This already transferred legacy Vec is outside controlled allocation scope.
    Ok(())
}

async fn shared_pg_closed_read_is_denied(
    f: &Fixture,
    id: &str,
    phases: &Arc<SharedPgReadPhases>,
) -> Result<(), String> {
    let before = phases.counts();
    let dispatch = tracing::Dispatch::new(SharedPgPhaseSubscriber(phases.clone()));
    let denied = f
        .administration
        .read_host_bound_chunk(&f.auth(), id)
        .with_subscriber(dispatch)
        .await
        .is_err();
    require(
        denied && phases.counts().0 == before.0 && phases.counts().2 == before.2,
        "closed original shared key delivered bytes or admitted another actual body IO",
    )
}

#[derive(Clone, Copy, Debug)]
enum SharedPgFinalLeg {
    ReleasedAck,
    DroppedAck,
    OriginalDeadline,
}

#[cfg(target_os = "macos")]
async fn shared_pg_final_leg(config: DatabaseConfig, leg: SharedPgFinalLeg) -> Result<(), String> {
    let external = pool::connect(&config.clone().with_max_pool_size(2))
        .await
        .map_err(|error| error.to_string())?;
    let mut proxy = RollbackAckProxy::start(config.host.clone(), config.port).await?;
    let mut proxied = config;
    proxied.host = "127.0.0.1".to_owned();
    proxied.port = proxy.port;
    let f = Fixture::new(proxied, false).await?;
    let saved = f.save().await?;
    let saved_b = f.save().await?;
    require(
        saved.artifact_id != saved_b.artifact_id && saved.operation_id != saved_b.operation_id,
        "shared PG other key was not a different actual Save",
    )?;
    let record = f
        .observe(&saved.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let path = f.root.0.join("objects").join(&saved.artifact_id);
    let mut controller = external.get().await.map_err(|error| error.to_string())?;
    let observer = external.get().await.map_err(|error| error.to_string())?;
    let controller_pid: i32 = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let observer_pid: i32 = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let before = cleanup_consumer_facts_on(&observer).await?;
    let (held, probe, original_pid, original_observation) =
        shared_pg_original_probe(&f, controller_pid, observer_pid).await?;
    drop(probe); // With seven original leases held, only this exact connection can serve the read.
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (proceed, proceed_rx) = tokio::sync::oneshot::channel();
    let phases =
        SharedPgReadPhases::after_io(&f.administration.read_authority(), (reached, proceed_rx));
    let dispatch = tracing::Dispatch::new(SharedPgPhaseSubscriber(phases.clone()));
    let administration = f.administration.clone();
    let auth = f.auth();
    let id = saved.artifact_id.clone();
    let mut task = Some(tokio::spawn(
        async move { administration.read_host_bound_chunk(&auth, &id).await }
            .with_subscriber(dispatch),
    ));
    let mut proceed = Some(proceed);
    let mut transaction = Some(
        controller
            .transaction()
            .await
            .map_err(|error| error.to_string())?,
    );
    let mut held_ack = None;
    let attempted = async {
        tokio::time::timeout(Duration::from_secs(2), reached_rx).await.map_err(|_| "shared original after-IO gate timed out")?
            .map_err(|_| "shared original after-IO gate closed")?;
        let phases_after_io = phases.counts();
        require(phases_after_io.0 == 1 && phases_after_io.2 == 0 && shared_pg_owned_fds(&path)?.len() == 1,
            "shared final fixture did not complete its actual original IO/full allocation and retain the FD")?;
        transaction.as_ref().unwrap().batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE")
            .await.map_err(|error| error.to_string())?;
        match leg {
            SharedPgFinalLeg::ReleasedAck => held_ack = Some(proxy.hold(1).await?),
            SharedPgFinalLeg::DroppedAck => proxy.remaining.store(1, Ordering::SeqCst),
            SharedPgFinalLeg::OriginalDeadline => {}
        }
        let original_phase_started = Instant::now();
        proceed.take().unwrap().send(()).map_err(|_| "shared original final gate release closed")?;
        shared_pg_final_lock(&observer, controller_pid, original_pid, Instant::now() + Duration::from_secs(2)).await?;
        require(!task.as_ref().unwrap().is_finished(), "original final read ended before its actual Lock proof")?;
        let barrier = f.administration.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
            Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)),
            "shared close did not keep the actual original final PG/FD owner accounted")?;
        shared_pg_final_lock(&observer, controller_pid, original_pid, Instant::now() + Duration::from_millis(250)).await?;
        if !matches!(leg, SharedPgFinalLeg::OriginalDeadline) {
            require(original_phase_started.elapsed() < Duration::from_secs(3), "controlled release exceeded the original final five-second budget")?;
            tokio::time::timeout(Duration::from_secs(2), transaction.take().unwrap().commit()).await
                .map_err(|_| "actual shared final controller COMMIT ACK timed out")?.map_err(|error| error.to_string())?;
            if let Some(ack) = held_ack.as_mut() {
                ack.wait().await?;
                require(proxy.held.load(Ordering::SeqCst) == 1 && proxy.dropped.load(Ordering::SeqCst) == 0
                    && !task.as_ref().unwrap().is_finished(),
                    "selected actual original ROLLBACK CommandComplete was not held")?;
                require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
                    Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)),
                    "controller COMMIT or backend-side rollback substituted for the original client ACK")?;
                require(original_phase_started.elapsed() < Duration::from_secs(3),
                    "original ACK release renewed or exceeded the original read phase")?;
                held_ack.take().unwrap().release()?;
            }
        }
        let result = tokio::time::timeout(Duration::from_secs(7), task.as_mut().unwrap()).await
            .map_err(|_| "original shared final reader did not finish within its unchanged phase")?
            .map_err(|error| error.to_string())?;
        drop(task.take());
        require(result.is_err(), "permanently closed shared key released a final body")?;
        drop(result);
        if matches!(leg, SharedPgFinalLeg::ReleasedAck) {
            let ack = barrier.drain_before(Instant::now() + Duration::from_secs(3)).await.map_err(|error| format!("{error:?}"))?;
            require(!original_observation.snapshot().retirement_requested,
                "positive actual rollback ACK was replaced with original connection retirement")?;
            require(shared_pg_owned_fds(&path)?.is_empty(), "positive shared ACK retained the original FD/full allocation")?;
            drop(ack);
        } else {
            if matches!(leg, SharedPgFinalLeg::DroppedAck) {
                require(proxy.dropped.load(Ordering::SeqCst) == 1 && proxy.held.load(Ordering::SeqCst) == 0,
                    "unacknowledged case did not actually drop the selected original backend ROLLBACK frame")?;
            } else {
                require(original_phase_started.elapsed() >= Duration::from_secs(4),
                    "original five-second final deadline was silently replaced with an early rejection")?;
            }
            let cleanup_deadline = Instant::now() + Duration::from_secs(3);
            require(original_observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?
                == pool::ConnectionDestruction::ConnectionDestroyed && original_observation.snapshot().retirement_requested,
                "original unacknowledged final connection did not actually retire")?;
            wait_original_cleanup_backend_gone(&observer, original_pid, cleanup_deadline).await?;
            require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(100)).await,
                Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)),
                "later original driver/backend destruction cleared permanent final unproven")?;
            require(shared_pg_owned_fds(&path)?.is_empty(), "unproved final query left an actual original FD after all actual jobs ended")?;
            if let Some(tx) = transaction.take() {
                tokio::time::timeout(Duration::from_secs(2), tx.rollback()).await
                    .map_err(|_| "actual shared final controller ROLLBACK ACK timed out")?.map_err(|error| error.to_string())?;
            }
        }
        require(phases.counts().0 == phases_after_io.0 && phases.counts().2 == phases_after_io.2 && path.is_file(),
            "final shared PG drain reread/rehashed the original body or deleted the object")?;
        drop(barrier);
        eprintln!("ARTIFACT_SHARED_PG leg={leg:?} original_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_final_lock=true original_io=true legacy_total_deadline=None original_fd_absent=true deletion=false");
        Ok::<_, String>(())
    }.await;
    // Cleanup is distinct from any original operation success or rollback proof.
    drop(held_ack.take());
    drop(proceed.take());
    if let Some(mut original) = task.take() {
        original.abort();
        let _ = (&mut original).await;
    }
    let rollback = if let Some(tx) = transaction.take() {
        tokio::time::timeout(Duration::from_secs(2), tx.rollback())
            .await
            .map_err(|_| "shared final cleanup controller ACK timed out".to_owned())
            .and_then(|result| result.map_err(|error| error.to_string()))
    } else {
        Ok(())
    };
    drop(transaction);
    drop(held);
    let denied = if attempted.is_ok() {
        shared_pg_closed_read_is_denied(&f, &saved.artifact_id, &phases).await
    } else {
        Ok(())
    };
    let other = if attempted.is_ok() {
        shared_pg_other_key_remains_readable(&f, &saved_b.artifact_id).await
    } else {
        Ok(())
    };
    let still_closed = if attempted.is_ok() {
        let barrier = f
            .administration
            .close_observed_artifact_reads(&record)
            .map_err(|error| error.to_string())?;
        if matches!(leg, SharedPgFinalLeg::ReleasedAck) {
            barrier
                .drain_before(Instant::now() + Duration::from_secs(3))
                .await
                .map(|_| ())
                .map_err(|error| format!("{error:?}"))
        } else {
            require(
                matches!(
                    barrier
                        .drain_before(Instant::now() + Duration::from_millis(100))
                        .await,
                    Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)
                ),
                "another actual client/key or a fresh drain budget cleared original final poison",
            )
        }
    } else {
        Ok(())
    };
    let after = cleanup_consumer_facts_on(&observer).await;
    f.administration.read_authority().read_lifecycle().close();
    let closed = shared_pg_destroy_pool(&f.pool).await;
    drop(observer);
    drop(controller);
    let external_closed = shared_pg_destroy_pool(&external).await;
    proxy.task.abort();
    let _ = (&mut proxy.task).await;
    drop(proxy);
    attempted?;
    rollback?;
    denied?;
    other?;
    still_closed?;
    require(
        before == after?,
        "actual shared final query changed original business/charge/receipt/fence/audit facts",
    )?;
    closed?;
    external_closed
}

#[cfg(target_os = "macos")]
async fn shared_pg_initial_cancel_leg(config: DatabaseConfig) -> Result<(), String> {
    let external = pool::connect(&config.clone().with_max_pool_size(2))
        .await
        .map_err(|error| error.to_string())?;
    let f = Fixture::new(config, false).await?;
    let saved = f.save().await?;
    let saved_b = f.save().await?;
    let record = f
        .observe(&saved.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let path = f.root.0.join("objects").join(&saved.artifact_id);
    let mut controller = external.get().await.map_err(|error| error.to_string())?;
    let observer = external.get().await.map_err(|error| error.to_string())?;
    let controller_pid = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let observer_pid = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let before = cleanup_consumer_facts_on(&observer).await?;
    let (held, probe, original_pid, original_observation) =
        shared_pg_original_probe(&f, controller_pid, observer_pid).await?;
    let mut transaction = Some(
        controller
            .transaction()
            .await
            .map_err(|error| error.to_string())?,
    );
    transaction.as_ref().unwrap().batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE openbot_internal.schema_migrations IN ACCESS EXCLUSIVE MODE")
        .await.map_err(|error| error.to_string())?;
    drop(probe);
    let authority = f.administration.read_authority();
    // Call the actual original producer with precisely its legacy State/job enrollment. This
    // cancels that producer future, rather than only detaching a caller from its spawned job.
    let state = ReadOperationState::new(authority.clone(), f.auth(), saved.artifact_id.clone());
    require(
        state.original_deadline.is_none(),
        "initial legacy fixture silently acquired a public total deadline",
    )?;
    state
        .enroll_store(f.store.clone(), None)
        .map_err(|error| format!("{error:?}"))?;
    authority
        .lifecycle
        .register(&state)
        .map_err(|error| format!("{error:?}"))?;
    let job = authority
        .lifecycle
        .admit_operation(&state)
        .map_err(|error| format!("{error:?}"))?;
    state.begin().map_err(|error| format!("{error:?}"))?;
    let phases = Arc::new(SharedPgReadPhases::default());
    let dispatch = tracing::Dispatch::new(SharedPgPhaseSubscriber(phases.clone()));
    let original_state = state.clone();
    let original_authority = authority.clone();
    let mut task = Some(tokio::spawn(async move {
        let _original_job = job;
        original_authority
            .read_first_chunk_collected(&original_state, dispatch)
            .await
    }));
    let attempted = async {
        wait_original_cleanup_schema_lock(&observer, controller_pid, original_pid, Instant::now() + Duration::from_secs(2)).await?;
        require(!task.as_ref().unwrap().is_finished() && phases.counts() == (0, 0, 0)
            && shared_pg_owned_fds(&path)?.is_empty(), "original initial schema query was replaced with body IO or an already-finished future")?;
        let barrier = f.administration.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
            Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)),
            "shared initial pre-record reservation disappeared while its actual original query waited")?;
        task.as_ref().unwrap().abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(2), task.as_mut().unwrap()).await.map_err(|_| "actual original initial producer cancel did not reap")?;
        drop(task.take());
        require(matches!(cancelled, Err(error) if error.is_cancelled()), "initial original producer was not actually reaped as cancelled")?;
        let cleanup_deadline = Instant::now() + Duration::from_secs(3);
        require(original_observation.wait_for_destruction_before(cleanup_deadline).await.map_err(|error| error.to_string())?
            == pool::ConnectionDestruction::ConnectionDestroyed && original_observation.snapshot().retirement_requested,
            "initial cancelled original connection did not actually retire")?;
        wait_original_cleanup_backend_gone(&observer, original_pid, cleanup_deadline).await?;
        require(transaction.is_some() && phases.counts() == (0, 0, 0) && shared_pg_owned_fds(&path)?.is_empty(),
            "initial original proof released its lock, renewed IO or replaced actual destruction with counter zero")?;
        require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(100)).await,
            Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)),
            "initial cancellation before a minted record yielded ACK after actual backend destruction")?;
        tokio::time::timeout(Duration::from_secs(2), transaction.take().unwrap().rollback()).await
            .map_err(|_| "actual shared initial controller ROLLBACK ACK timed out")?.map_err(|error| error.to_string())?;
        drop(barrier);
        eprintln!("ARTIFACT_SHARED_PG leg=initial_cancel original_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_schema_lock=true original_producer_cancel_reaped=true original_connection_destroyed=true original_backend_gone=true legacy_total_deadline=None permanent_unproven=true original_io=false");
        Ok::<_, String>(())
    }.await;
    if let Some(mut original) = task.take() {
        original.abort();
        let _ = (&mut original).await;
    }
    let rollback = if let Some(tx) = transaction.take() {
        tokio::time::timeout(Duration::from_secs(2), tx.rollback())
            .await
            .map_err(|_| "shared initial cleanup controller ACK timed out".to_owned())
            .and_then(|result| result.map_err(|error| error.to_string()))
    } else {
        Ok(())
    };
    drop(transaction);
    drop(held);
    let denied = if attempted.is_ok() {
        shared_pg_closed_read_is_denied(&f, &saved.artifact_id, &phases).await
    } else {
        Ok(())
    };
    let other = if attempted.is_ok() {
        shared_pg_other_key_remains_readable(&f, &saved_b.artifact_id).await
    } else {
        Ok(())
    };
    let still_unproven = if attempted.is_ok() {
        let barrier = f
            .administration
            .close_observed_artifact_reads(&record)
            .map_err(|error| error.to_string())?;
        require(
            matches!(
                barrier
                    .drain_before(Instant::now() + Duration::from_millis(100))
                    .await,
                Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Unavailable)
            ),
            "new client or fresh wait budget cleared the original initial cancellation",
        )
    } else {
        Ok(())
    };
    let after = cleanup_consumer_facts_on(&observer).await;
    state.close();
    drop(state);
    drop(authority);
    f.administration.read_authority().read_lifecycle().close();
    let closed = shared_pg_destroy_pool(&f.pool).await;
    drop(observer);
    drop(controller);
    let external_closed = shared_pg_destroy_pool(&external).await;
    attempted?;
    rollback?;
    denied?;
    other?;
    still_unproven?;
    require(
        before == after? && path.is_file(),
        "initial cancelled producer changed original business facts or deleted the object",
    )?;
    closed?;
    external_closed
}

#[cfg(target_os = "macos")]
async fn shared_pg_control_tail_leg(config: DatabaseConfig) -> Result<(), String> {
    use openbot_application::ApplicationService as _;
    use openbot_contracts::artifact_read_protocol::{
        AcknowledgeArtifactReadBlock, CloseArtifactRead, OpenArtifactRead, ReadArtifactReadBlock,
    };
    use openbot_contracts::command::{AppCommand, AppReply};
    let external = pool::connect(&config.clone().with_max_pool_size(2))
        .await
        .map_err(|error| error.to_string())?;
    let f = Fixture::new(config, false).await?;
    let saved = f.save().await?;
    let record = f
        .observe(&saved.artifact_id)
        .await
        .map_err(|error| error.to_string())?;
    let path = f.root.0.join("objects").join(&saved.artifact_id);
    let mut controller = external.get().await.map_err(|error| error.to_string())?;
    let observer = external.get().await.map_err(|error| error.to_string())?;
    let controller_pid = controller
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let observer_pid = observer
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|error| error.to_string())?
        .get(0);
    let before = cleanup_consumer_facts_on(&observer).await?;
    let (held, probe, original_pid, original_observation) =
        shared_pg_original_probe(&f, controller_pid, observer_pid).await?;
    drop(probe);
    let auth = f.auth();
    let application = Arc::new(
        openbot_application::OpenBotApplication::new(crate::repo::channels::ChannelRepo::new(
            f.pool.clone(),
        ))
        .with_artifacts(f.administration.clone()),
    );
    let phases = Arc::new(SharedPgReadPhases::default());
    let dispatch = tracing::Dispatch::new(SharedPgPhaseSubscriber(phases.clone()));
    let reply = application
        .execute(
            auth.clone(),
            AppCommand::OpenArtifactRead(OpenArtifactRead {
                artifact_id: saved.artifact_id.clone(),
            }),
        )
        .with_subscriber(dispatch.clone())
        .await
        .map_err(|error| format!("control_tail_phase=open_execute original_error={error}"))?;
    let opened = match &reply {
        AppReply::ArtifactReadOpened(value) => value.clone(),
        _ => return Err("real control-tail Open returned another reply".to_owned()),
    };
    let control = application
        .take_artifact_read_control_delivery(auth.clone(), reply)
        .map_err(|error| format!("control_tail_phase=open_take_control original_error={error}"))?;
    control
        .verify_current_tail(&auth)
        .map_err(|error| format!("control_tail_phase=open_verify_tail original_error={error}"))?;
    drop(control);
    let input = ReadArtifactReadBlock {
        handle_id: opened.handle_id.clone(),
        sequence: 0,
    };
    application
        .execute(
            auth.clone(),
            AppCommand::ReadArtifactReadBlock(input.clone()),
        )
        .with_subscriber(dispatch.clone())
        .await
        .map_err(|error| format!("control_tail_phase=next_execute original_error={error}"))?;
    let delivery = application
        .take_artifact_read_delivery(auth.clone(), input)
        .map_err(|error| format!("control_tail_phase=next_take_delivery original_error={error}"))?;
    let block = delivery
        .handoff(&auth)
        .map_err(|error| format!("control_tail_phase=next_handoff original_error={error}"))?
        .ok_or("actual nonempty control-tail transport block missing")?;
    require(
        block.as_ref() == EXACT.as_bytes(),
        "real control-tail preparation handed off another body",
    )?;
    drop(block);
    let reply = application
        .execute(
            auth.clone(),
            AppCommand::AcknowledgeArtifactReadBlock(AcknowledgeArtifactReadBlock {
                handle_id: opened.handle_id.clone(),
                sequence: 0,
            }),
        )
        .with_subscriber(dispatch.clone())
        .await
        .map_err(|error| format!("control_tail_phase=ack_execute original_error={error}"))?;
    require(
        matches!(&reply, AppReply::ArtifactReadAcknowledged(_)),
        "original normal ACK did not end its real registry/transport allocation",
    )?;
    let control = application
        .take_artifact_read_control_delivery(auth.clone(), reply)
        .map_err(|error| format!("control_tail_phase=ack_take_control original_error={error}"))?;
    control
        .verify_current_tail(&auth)
        .map_err(|error| format!("control_tail_phase=ack_verify_tail original_error={error}"))?;
    drop(control);
    let counts = phases.counts();
    require(
        counts.0 == 1 && counts.2 == 0 && shared_pg_owned_fds(&path)?.len() == 1,
        "control-tail fixture did not retain its original idle reader after real normal data ACK",
    )?;
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (proceed, proceed_rx) = tokio::sync::oneshot::channel();
    *f.administration
        .read_authority()
        .final_query_gate
        .lock()
        .map_err(|_| "control-tail final gate poisoned")? = Some((reached, proceed_rx));
    let original_application = application.clone();
    let original_auth = auth.clone();
    let id = opened.handle_id.clone();
    let mut task = Some(tokio::spawn(
        async move {
            original_application
                .execute(
                    original_auth,
                    AppCommand::CloseArtifactRead(CloseArtifactRead { handle_id: id }),
                )
                .await
        }
        .with_subscriber(dispatch),
    ));
    let mut proceed = Some(proceed);
    let mut transaction = Some(
        controller
            .transaction()
            .await
            .map_err(|error| error.to_string())?,
    );
    let attempted = async {
        tokio::time::timeout(Duration::from_secs(2), reached_rx).await.map_err(|_| "actual Close control-tail final gate timed out")?
            .map_err(|_| "actual Close control-tail final gate closed")?;
        transaction.as_ref().unwrap().batch_execute("SET LOCAL lock_timeout='1s'; LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE")
            .await.map_err(|error| error.to_string())?;
        let original_phase_started = Instant::now();
        proceed.take().unwrap().send(()).map_err(|_| "actual Close control-tail gate release closed")?;
        shared_pg_final_lock(&observer, controller_pid, original_pid, Instant::now() + Duration::from_secs(2)).await?;
        let barrier = f.administration.close_observed_artifact_reads(&record).map_err(|error| error.to_string())?;
        // Actual normal ACK already dropped the entire registry allocation. Shared close now
        // closes its original idle FD; only the real no-byte control query remains in flight.
        require(shared_pg_owned_fds(&path)?.is_empty() && !task.as_ref().unwrap().is_finished(),
            "no-carrier Close control tail did not release its actual FD while its original PG query waited")?;
        require(matches!(barrier.drain_before(Instant::now() + Duration::from_millis(25)).await,
            Err(crate::artifact_read_lifecycle::ArtifactReadDrainError::Elapsed)),
            "zero data-carrier/FD owners substituted for the real Close control-tail PG ACK")?;
        shared_pg_final_lock(&observer, controller_pid, original_pid, Instant::now() + Duration::from_millis(250)).await?;
        require(original_phase_started.elapsed() < Duration::from_secs(3), "Close control-tail release exceeded its original five-second budget")?;
        tokio::time::timeout(Duration::from_secs(2), transaction.take().unwrap().commit()).await
            .map_err(|_| "actual Close control-tail controller COMMIT ACK timed out")?.map_err(|error| error.to_string())?;
        let result = tokio::time::timeout(Duration::from_secs(3), task.as_mut().unwrap()).await
            .map_err(|_| "actual original Close control query did not finish after release")?.map_err(|error| error.to_string())?;
        drop(task.take());
        require(result.is_err(), "shared permanent stop accepted a late Close control success")?;
        drop(result);
        let ack = barrier.drain_before(Instant::now() + Duration::from_secs(3)).await.map_err(|error| format!("{error:?}"))?;
        require(!original_observation.snapshot().retirement_requested && shared_pg_owned_fds(&path)?.is_empty(),
            "normal control-tail rollback ACK was replaced with retirement or left the original FD")?;
        require(phases.counts().0 == counts.0 && phases.counts().2 == counts.2 && path.is_file(),
            "real no-byte control query reran body IO or deleted the original artifact")?;
        drop(ack); drop(barrier);
        eprintln!("ARTIFACT_SHARED_PG leg=actual_close_control_tail original_pid={original_pid} controller_pid={controller_pid} observer_pid={observer_pid} actual_final_lock=true no_data_carrier=true original_fd_absent_while_waiting=true wait_no_ack=true controller_commit_ack=true original_rollback_ack=true controlled_ack=true");
        Ok::<_, String>(())
    }.await;
    drop(proceed.take());
    if let Some(mut original) = task.take() {
        original.abort();
        let _ = (&mut original).await;
    }
    let rollback = if let Some(tx) = transaction.take() {
        tokio::time::timeout(Duration::from_secs(2), tx.rollback())
            .await
            .map_err(|_| "control-tail cleanup controller ACK timed out".to_owned())
            .and_then(|result| result.map_err(|error| error.to_string()))
    } else {
        Ok(())
    };
    drop(transaction);
    let stopped = application
        .close_public_artifact_reads()
        .map_err(|error| error.to_string());
    drop(application);
    drop(auth);
    drop(held);
    let after = cleanup_consumer_facts_on(&observer).await;
    f.administration.read_authority().read_lifecycle().close();
    let closed = shared_pg_destroy_pool(&f.pool).await;
    drop(observer);
    drop(controller);
    let external_closed = shared_pg_destroy_pool(&external).await;
    attempted?;
    rollback?;
    stopped?;
    require(
        before == after?,
        "actual Close control-tail shared wait changed original business/charge/receipt/fence/audit facts",
    )?;
    closed?;
    external_closed
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL; original query Lock/PID/ROLLBACK ACK and permanent exact-key unproven"]
async fn shared_read_barrier_final_pg_wait_requires_original_rollback_ack() {
    for leg in [
        SharedPgFinalLeg::ReleasedAck,
        SharedPgFinalLeg::DroppedAck,
        SharedPgFinalLeg::OriginalDeadline,
    ] {
        let tag = "shared-original-final-pg";
        harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
            shared_pg_final_leg(config, leg).await
        })
        .await;
    }
    let tag = "shared-original-initial-cancel";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        shared_pg_initial_cancel_leg(config).await
    })
    .await;
    let tag = "shared-original-control-tail";
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        shared_pg_control_tail_leg(config).await
    })
    .await;
}

fn require(ok: bool, message: &'static str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

fn mutate_owned_read_only_file<M, E>(
    path: &std::path::Path,
    mutation: M,
    expected: E,
) -> Result<(), String>
where
    M: FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    E: FnOnce(&[u8], &[u8]) -> bool,
{
    let original = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        original.is_file() && original.mode() & 0o7777 == 0o400 && original.nlink() == 1,
        "owned mutation requires the original regular0400 single-link file",
    )?;
    let anchor = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let anchored = anchor.metadata().map_err(|error| error.to_string())?;
    require(
        anchored.is_file()
            && anchored.dev() == original.dev()
            && anchored.ino() == original.ino()
            && anchored.uid() == original.uid()
            && anchored.mode() & 0o7777 == 0o400
            && anchored.nlink() == 1,
        "owned mutation read FD is not the original0400 inode",
    )?;
    let mut before = Vec::new();
    (&anchor)
        .read_to_end(&mut before)
        .map_err(|error| error.to_string())?;
    struct RestoreReadOnly<'a> {
        file: &'a std::fs::File,
        armed: bool,
    }
    impl Drop for RestoreReadOnly<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = self
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(0o400));
                let _ = self.file.sync_all();
            }
        }
    }
    let mut restore = RestoreReadOnly {
        file: &anchor,
        armed: true,
    };
    anchor
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    let writable = writer.metadata().map_err(|error| error.to_string())?;
    require(
        writable.is_file()
            && writable.dev() == original.dev()
            && writable.ino() == original.ino()
            && writable.uid() == original.uid()
            && writable.mode() & 0o7777 == 0o600
            && writable.nlink() == 1,
        "owned mutation write FD is not the original temporary0600 inode",
    )?;
    let mutation_result = mutation(&mut writer, &before);
    let mutation_sync = writer.sync_all();
    // Restore even when mutation or its sync failed; the anchored guard also covers early errors.
    let restored = writer.set_permissions(std::fs::Permissions::from_mode(0o400));
    let restore_sync = writer.sync_all();
    if restored.is_ok() && restore_sync.is_ok() {
        restore.armed = false;
    }
    restored.map_err(|error| error.to_string())?;
    restore_sync.map_err(|error| error.to_string())?;
    let actual = writer.metadata().map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    require(
        actual.is_file()
            && installed.is_file()
            && actual.dev() == original.dev()
            && actual.ino() == original.ino()
            && actual.uid() == original.uid()
            && installed.dev() == original.dev()
            && installed.ino() == original.ino()
            && actual.mode() & 0o7777 == 0o400
            && installed.mode() & 0o7777 == 0o400
            && actual.nlink() == 1
            && installed.nlink() == 1,
        "owned mutation did not restore original inode and0400 permissions",
    )?;
    mutation_result.map_err(|error| error.to_string())?;
    mutation_sync.map_err(|error| error.to_string())?;
    (&anchor)
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut after = Vec::new();
    (&anchor)
        .read_to_end(&mut after)
        .map_err(|error| error.to_string())?;
    require(
        before != after && expected(&before, &after),
        "owned mutation did not cause exact real byte drift",
    )
}

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("openbot-read-bridge-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self(fs::canonicalize(path).map_err(|e| e.to_string())?))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let removed = fs::remove_dir_all(&self.0).is_ok();
        let absent = !self.0.exists();
        eprintln!("ARTIFACT_READ_BRIDGE_ROOT_CLEANUP removed={removed} absent={absent}");
        if !std::thread::panicking() {
            assert!(removed && absent, "owned read-root cleanup failed");
        }
    }
}

struct Fixture {
    pool: Pool,
    registry: Arc<ArtifactDatasetRegistry>,
    store: Arc<DatasetBoundArtifactStore>,
    administration: Arc<PostgresArtifactAdministration>,
    _lease: RequestBindingOwnerLease,
    issuer: RequestBindingIssuer,
    created: OffsetDateTime,
    begin: BeginThreadRunRequest,
    root: OwnedRoot,
}
impl Fixture {
    async fn new(config: DatabaseConfig, channel: bool) -> Result<Self, String> {
        let config = config.with_max_pool_size(8);
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        {
            let mut client = pool.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|e| e.to_string())?;
            client.batch_execute("INSERT INTO public.users(id,email,auth_generation,groups) VALUES
              ('read-owner','read-owner@example.test',0,ARRAY['read-fixture']),
              ('read-other','read-other@example.test',0,ARRAY['read-fixture']);
              INSERT INTO public.user_roles(user_id,role) VALUES('read-owner','user'),('read-other','admin');
              INSERT INTO public.agents(id,name,type,configuration) VALUES('read-bot','Read fixture','built_in','{}');
              INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                VALUES('read-bot','read-owner','Read fixture','fixture','fixture','public');
              INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                VALUES('00000000-0000-4000-8000-000000000051','artifact-read-owned-tenant','fixture','fixture');
              INSERT INTO public.channels(id,name,description,allowed_groups)
                VALUES('read-channel','Read fixture','fixture',ARRAY['read-fixture']);
              INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('read-channel','read-owner'),('read-channel','read-other');
              INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('read-channel','read-bot');")
                .await.map_err(|e| e.to_string())?;
        }
        let deployment = DeploymentId::new(DEPLOYMENT);
        let tenant = TenantId::new(TENANT);
        let registry = Arc::new(
            ArtifactDatasetRegistry::from_server(pool.clone(), &deployment, &tenant)
                .await
                .map_err(|e| e.to_string())?,
        );
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment,
            tenant,
            actor: ActorId::new(OWNER),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&DeploymentId::new(DEPLOYMENT))
                    .mint_from_entropy([9; 16]),
                run_id: RunId::new("read/source%成果"),
                bot_id: BotId::new("read-bot"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("read-channel"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: EXACT.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "read-bridge-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|e| e.to_string())?;
        let root = OwnedRoot::new()?;
        let policy = ArtifactQuotaPolicy::default();
        let store = Arc::new(
            DatasetBoundArtifactStore::bind_host_root(
                File::open(&root.0).map_err(|e| e.to_string())?,
                Arc::clone(&registry),
                policy,
            )
            .await
            .map_err(|e| e.to_string())?,
        );
        let administration = Arc::new(
            PostgresArtifactAdministration::new(
                Arc::clone(&registry),
                Arc::clone(&store),
                policy,
                SecretBytes::new(vec![0x83; 32]),
            )
            .map_err(|e| e.to_string())?,
        );
        let created = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let expires = created + time::Duration::hours(1);
        pool.get().await.map_err(|e| e.to_string())?.execute(
            "INSERT INTO public.sessions(id,user_id,token,created_at,updated_at,expires_at,auth_generation) VALUES($1,$2,$3,$4,$4,$5,0),($6,$2,$7,$4,$4,$5,0)",
            &[&"core-read-session-a", &OWNER, &"owned-test-session-column-a", &created, &expires, &"core-read-session-b", &"owned-test-session-column-b"],
        ).await.map_err(|e| e.to_string())?;
        // PostgreSQL stores microseconds. The immutable epoch is copied from the actual row,
        // rather than comparing a pre-insert nanosecond clock value against that row.
        let created: OffsetDateTime = pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT created_at FROM public.sessions WHERE id='core-read-session-a'",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let (_lease, issuer) =
            RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
        administration.read_authority();
        Ok(Self {
            pool,
            registry,
            store,
            administration,
            _lease,
            issuer,
            created,
            begin,
            root,
        })
    }

    fn auth_as(&self, actor: &str, generation: u64) -> AuthContext {
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEPLOYMENT),
            TenantId::new(TENANT),
            ActorId::new(actor),
            AuthGeneration::new(generation),
            false,
        )
        .with_role(if actor == OTHER {
            Role::Admin
        } else {
            Role::User
        })
        .build()
    }
    fn auth(&self) -> AuthContext {
        self.session_auth("core-read-session-a", "owned-test-session-column-a")
    }
    fn session_auth(&self, id: &str, token: &str) -> AuthContext {
        let auth = self.auth_as(OWNER, 0);
        let guard = CoreSessionGuard {
            issuer: self.issuer.clone(),
            authority: Arc::downgrade(&self.administration.read_authority()),
            lifetime: lifetime(),
        };
        let epoch = ServerSessionBindingIdentity::from_verified_row(
            id.into(),
            auth.actor().clone(),
            token.into(),
            self.created,
            auth.auth_generation(),
        );
        let binding = self
            .issuer
            .bind_server_session(&auth, epoch, Arc::new(guard))
            .expect("owned real-row epoch");
        auth.with_verified_request_binding(binding)
            .expect("owned attachment")
    }
    fn message_id(&self) -> String {
        format!("{}:input", self.begin.command.run_id.as_str())
    }
    async fn save(&self) -> Result<ArtifactRegistrationReceipt, String> {
        self.administration
            .save_run_message_text(
                &self.auth(),
                SaveRunMessageTextArtifact {
                    request_id: Uuid::now_v7().to_string(),
                    source_thread_id: self.begin.command.thread_id.clone(),
                    source_run_id: self.begin.command.run_id.clone(),
                    source_message_id: self.message_id(),
                    expected_sha256: Sha256Digest::of(EXACT.as_bytes()).to_hex(),
                },
            )
            .await
            .map_err(|e| e.to_string())
    }
    async fn observe(
        &self,
        id: &str,
    ) -> Result<ObservedArtifactReadRecord, ArtifactAdministrationError> {
        self.administration
            .observe_read_record(&self.auth(), id)
            .await
    }
    fn object(&self, id: &str) -> PathBuf {
        self.root.0.join("objects").join(id)
    }
    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|e| e.to_string())
    }
    async fn facts(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|e| e.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'operations',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_save_operations o),
              'records',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY artifact_id),'[]') FROM openbot_internal.artifact_records r),
              'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY operation_id),'[]') FROM openbot_internal.artifact_saved_receipts r),
              'workspace',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_workspace_quotas q),
              'runquota',(SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY to_jsonb(q)::text),'[]') FROM openbot_internal.artifact_run_quotas q),
              'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM public.audit_events e))", &[])
            .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())
    }
    async fn reader(&self, id: &str) -> Result<StoreBoundArtifactReader, String> {
        let record = self.observe(id).await.map_err(|e| e.to_string())?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.open_observed_record(record))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())
    }
    async fn read_all(&self, id: &str) -> Result<Vec<u8>, String> {
        let mut reader = self.reader(id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = Vec::new();
            let mut chunk = [0; 11];
            loop {
                let n = reader
                    .read_observed_chunk(&mut chunk)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(bytes);
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

async fn with_fixture<F, Fut>(tag: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        body(Fixture::new(config, channel).await?).await
    })
    .await;
}

fn lifetime() -> SessionLifetimePolicy {
    SessionLifetimePolicy::new(
        time::Duration::minutes(30),
        time::Duration::hours(1),
        time::Duration::seconds(1),
    )
    .unwrap()
}
struct CoreSessionGuard {
    issuer: RequestBindingIssuer,
    authority: Weak<PostgresArtifactReadAuthority>,
    lifetime: SessionLifetimePolicy,
}
impl HostRequestBindingGuard for CoreSessionGuard {
    fn verify_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(HostRequestBindingError::Unavailable)?;
            let authority = self
                .authority
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let administration = authority
                .administration
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let binding = auth
                .request_binding()
                .ok_or(HostRequestBindingError::Missing)?;
            let epoch = self
                .issuer
                .borrow_server_session_epoch(binding.identity())?;
            let mut client = administration
                .registry
                .pool()
                .get_guarded(deadline)
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let original_transaction = client
                .begin_read_committed_read_only()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let outcome = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                async {
                    let tx = original_transaction.as_transaction();
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .filter(|remaining| !remaining.is_zero())
                        .ok_or(HostRequestBindingError::Unavailable)?;
                    let millis = remaining.as_millis().clamp(1, 5000);
                    tx.batch_execute(&format!("SET LOCAL statement_timeout='{millis}ms'; SET LOCAL lock_timeout='{millis}ms'"))
                        .await.map_err(|_| HostRequestBindingError::Unavailable)?;
                    let row = tx.query_one(
                        "SELECT u.id AS read_host_user,u.auth_generation AS read_host_generation, \
                          u.email AS read_host_email,EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked, \
                          ARRAY(SELECT role::text FROM public.user_roles WHERE user_id=u.id ORDER BY role::text) AS read_host_roles, \
                          s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token, \
                          s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,s.auth_generation AS read_session_generation \
                         FROM (SELECT 1) a LEFT JOIN public.users u ON u.id=$1 LEFT JOIN public.sessions s ON s.id=$2 AND s.user_id=u.id",
                        &[&auth.actor().as_str(), &epoch.lookup_id()],
                    ).await.map_err(|_| HostRequestBindingError::Unavailable)?;
                    decode_host(&administration, auth, &row, &CurrentHost::Session { epoch, lifetime: self.lifetime })
                        .map_err(|error| match error {
                            ArtifactReadCurrentError::Host(error) => error,
                            _ => HostRequestBindingError::Unavailable,
                        })
                },
            ).await.map_err(|_| HostRequestBindingError::Unavailable);
            // Only the actual original ACK can reuse this lease. Cancellation or any
            // unacknowledged exit retires the original guarded client under its deadline.
            original_transaction
                .rollback()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let witness = outcome??;
            witness
                .verify_current(auth, deadline)
                .map_err(|error| match error {
                    ArtifactReadCurrentError::Host(error) => error,
                    _ => HostRequestBindingError::Unavailable,
                })
        })
    }
    fn verify_current<'a>(
        &'a self,
        auth: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async move {
            let authority = self
                .authority
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let administration = authority
                .administration
                .upgrade()
                .ok_or(HostRequestBindingError::Unavailable)?;
            let identity = auth
                .request_binding()
                .ok_or(HostRequestBindingError::Missing)?
                .identity();
            let epoch = self.issuer.borrow_server_session_epoch(identity)?;
            let client = administration
                .registry
                .pool()
                .get()
                .await
                .map_err(|_| HostRequestBindingError::Unavailable)?;
            let row = client.query_one(
                "SELECT u.id AS read_host_user,u.auth_generation AS read_host_generation, \
                  u.email AS read_host_email,EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) AS read_host_revoked, \
                  ARRAY(SELECT role::text FROM public.user_roles WHERE user_id=u.id ORDER BY role::text) AS read_host_roles, \
                  s.id AS read_session_id,s.user_id AS read_session_user,s.token AS read_session_token, \
                  s.created_at AS read_session_created,s.updated_at AS read_session_updated,s.expires_at AS read_session_expires,s.auth_generation AS read_session_generation \
                 FROM (SELECT 1) a LEFT JOIN public.users u ON u.id=$1 LEFT JOIN public.sessions s ON s.id=$2 AND s.user_id=u.id",
                &[&auth.actor().as_str(), &epoch.lookup_id()],
            ).await.map_err(|_| HostRequestBindingError::Unavailable)?;
            let result = decode_host(
                &administration,
                auth,
                &row,
                &CurrentHost::Session {
                    epoch,
                    lifetime: self.lifetime,
                },
            );
            match result {
                Ok(tail) => tail
                    .verify_current(auth, Instant::now() + Duration::from_secs(5))
                    .map_err(|error| match error {
                        ArtifactReadCurrentError::Host(error) => error,
                        _ => HostRequestBindingError::Unavailable,
                    }),
                Err(ArtifactReadCurrentError::Host(error)) => Err(error),
                Err(_) => Err(HostRequestBindingError::Unavailable),
            }
        })
    }
    fn verify_artifact_read_current_before<'a>(
        &'a self,
        auth: &'a AuthContext,
        target: &'a dyn ArtifactReadCurrentTarget,
        deadline: Instant,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn ArtifactReadTailWitness>, ArtifactReadCurrentError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let authority = self.authority.upgrade().ok_or_else(host_unavailable)?;
            let identity = auth
                .request_binding()
                .ok_or_else(host_unavailable)?
                .identity();
            let epoch = self
                .issuer
                .borrow_server_session_epoch(identity)
                .map_err(ArtifactReadCurrentError::Host)?;
            authority
                .observe_server_session(auth, target, epoch, self.lifetime, deadline)
                .await
        })
    }
}

#[test]
fn joint_sql_keeps_original_source_cte_and_host_anchor() {
    for desktop in [false, true] {
        let sql = current_read_sql(desktop);
        assert!(
            sql.strip_prefix("/* artifact_current_host_joint_read_after_io */ ")
                .unwrap()
                .starts_with(crate::thread_directory::reconciliation_visibility::VISIBLE_RUN)
        );
        assert!(
            sql.contains(
                super::super::observed_read_sql()
                    .strip_prefix(crate::thread_directory::reconciliation_visibility::VISIBLE_RUN)
                    .unwrap()
            )
        );
        assert!(sql.contains("FROM (SELECT 1) anchor LEFT JOIN public.users"));
        assert!(sql.contains("LEFT JOIN current_artifact a ON true"));
        assert!(sql.contains("u.auth_generation AS read_host_generation"));
        assert!(!sql.contains("coalesce(u.auth_generation,0) AS read_host_generation"));
        assert!(sql.contains("artifact_current_host_joint_read_after_io"));
        assert_eq!(sql.contains("pg_control_system()"), desktop);
    }
}

struct CarrierGuard;
impl HostRequestBindingGuard for CarrierGuard {
    fn verify_current<'a>(
        &'a self,
        _: &'a AuthContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), HostRequestBindingError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
fn carrier_auth() -> (RequestBindingOwnerLease, AuthContext) {
    let (lease, issuer) =
        RequestBindingOwnerLease::for_trusted_host(HostRequestBindingKind::ServerSession);
    let auth = AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(OWNER),
        AuthGeneration::new(0),
        false,
    )
    .with_role(Role::User)
    .build();
    let epoch = ServerSessionBindingIdentity::from_verified_row(
        "clock-seam".into(),
        auth.actor().clone(),
        "clock-test-column".into(),
        OffsetDateTime::UNIX_EPOCH,
        auth.auth_generation(),
    );
    let binding = issuer
        .bind_server_session(&auth, epoch, Arc::new(CarrierGuard))
        .unwrap();
    (lease, auth.with_verified_request_binding(binding).unwrap())
}

#[test]
fn current_tail_rejects_expiry_clock_reversal_and_binding_swap() {
    let (_a_lease, auth) = carrier_auth();
    let (_b_lease, other_binding) = carrier_auth();
    let now = OffsetDateTime::now_utc();
    let mut tail = CurrentReadTail {
        auth: auth.clone(),
        identity: auth.request_binding().unwrap().identity().clone(),
        observed_wall: now,
        observed_monotonic: Instant::now(),
        session: Some((
            now - time::Duration::seconds(2),
            now - time::Duration::seconds(1),
            now + time::Duration::hours(1),
            lifetime(),
        )),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    assert_eq!(tail.verify_current(&auth, deadline), Ok(()));
    assert_eq!(
        tail.verify_current(&other_binding, deadline),
        Err(host_not_current())
    );
    tail.observed_wall = now + time::Duration::hours(1);
    assert_eq!(
        tail.verify_current(&auth, deadline),
        Err(host_not_current())
    );
    tail.observed_wall = now;
    tail.session.as_mut().unwrap().2 = now - time::Duration::seconds(1);
    assert_eq!(
        tail.verify_current(&auth, deadline),
        Err(host_not_current())
    );
    assert_eq!(
        tail.verify_current(&auth, Instant::now()),
        Err(host_unavailable())
    );
}

async fn wait_final_lock(pool: &Pool, blocker: i32) -> Result<i32, String> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let client = pool.get().await.map_err(|e| e.to_string())?;
            let rows = client.query("SELECT pid,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND wait_event_type='Lock' AND query LIKE '%artifact_current_host_joint_read_after_io%' AND pid<>pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?;
            for row in rows {
                let blockers: Vec<i32> = row.get("blockers");
                if blockers.contains(&blocker) { return Ok(row.get("pid")); }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_| "actual final statement Lock/PID was not observed".to_owned())?
}

// `after_io=false` gates the first statement, which for host-first source errors is the
// R432 control-before itself; those reads have no body IO or later final joint.
async fn start_after_io(
    f: &Fixture,
    id: &str,
    after_io: bool,
) -> Result<
    (
        tokio::task::JoinHandle<Result<CurrentArtifactReadChunk, AppError>>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    String,
> {
    let (reached, acknowledged) = tokio::sync::oneshot::channel();
    let (proceed, release) = tokio::sync::oneshot::channel();
    let authority = f.administration.read_authority();
    let phases = if after_io {
        SharedPgReadPhases::after_io(&authority, (reached, release))
    } else {
        *authority
            .final_query_gate
            .lock()
            .map_err(|_| "gate poisoned".to_owned())? = Some((reached, release));
        Arc::new(SharedPgReadPhases::default())
    };
    let dispatch = tracing::Dispatch::new(SharedPgPhaseSubscriber(phases));
    let administration = Arc::clone(&f.administration);
    let auth = f.auth();
    let id = id.to_owned();
    let worker = tokio::spawn(
        async move { administration.read_host_bound_chunk(&auth, &id).await }
            .with_subscriber(dispatch),
    );
    Ok((worker, acknowledged, proceed))
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_current_read_and_sync_fd_tail() {
    with_fixture("arc_positive", false, |f| async move {
        let saved = f.save().await?;
        let before = f.facts().await?;
        let authority = f.administration.read_authority();
        require(
            authority.matches_pool_scope(
                &f.pool,
                &DeploymentId::new(DEPLOYMENT),
                &TenantId::new(TENANT),
            ),
            "actual pool enrollment refused",
        )?;
        require(
            Arc::ptr_eq(&f.registry, &f.administration.registry),
            "registry owner changed",
        )?;
        let auth = f.auth();
        let chunk = f
            .administration
            .read_host_bound_chunk(&auth, &saved.artifact_id)
            .await
            .map_err(|e| e.to_string())?;
        require(
            chunk.handoff(&auth).map_err(|e| e.to_string())? == EXACT.as_bytes(),
            "real first-chunk bytes differed",
        )?;
        require(
            f.read_all(&saved.artifact_id).await? == EXACT.as_bytes(),
            "retained original snapshot differed",
        )?;
        let mut reader = f.reader(&saved.artifact_id).await?;
        tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES];
            let length = reader
                .read_observed_chunk(&mut bytes)
                .map_err(|e| e.to_string())?;
            require(
                length == EXACT.len() && &bytes[..length] == EXACT.as_bytes(),
                "real full-capacity reader refused first chunk",
            )?;
            let mut oversized = vec![0xa5; MAX_ARTIFACT_READ_CHUNK_BYTES + 1];
            require(
                matches!(
                    reader.read_observed_chunk(&mut oversized),
                    Err(ArtifactReadBridgeError::Bytes(
                        ArtifactByteError::InvalidChunk
                    ))
                ) && oversized.iter().all(|byte| *byte == 0),
                "actual >4MiB buffer was not refused and wholly wiped",
            )
        })
        .await
        .map_err(|e| e.to_string())??;
        require(
            f.facts().await? == before,
            "read mutated registration, quotas, audit or receipts",
        )?;
        let chunk = f
            .administration
            .read_host_bound_chunk(&auth, &saved.artifact_id)
            .await
            .map_err(|e| e.to_string())?;
        mutate_owned_read_only_file(
            &f.object(&saved.artifact_id),
            |object, _| {
                object.seek(std::io::SeekFrom::End(0))?;
                object.write_all(b"changed")
            },
            |before, after| {
                after.len() == before.len() + b"changed".len()
                    && after.starts_with(before)
                    && after.ends_with(b"changed")
            },
        )?;
        require(
            matches!(
                chunk.handoff(&auth),
                Err(AppError::DependencyUnavailable {
                    dependency: "artifacts"
                })
            ),
            "original FD drift survived sync handoff",
        )
    })
    .await;
}

// Privileged corruption control is confined to this owned disposable test DB.
// Probe the real guard for every change/restore and re-enable it in the same transaction.

// Finite privileged joint corruption in this disposable test DB. Ordinary
// open direct-source metadata changes stay ordinary DML; missing actual Run or
// referenced canonical mutations first prove their precise new55000 refusal.
async fn tamper_owned_message_joint(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const GUARDS: [&str; 3] = [
        "messages_history_body_before",
        "messages_history_canonical_before",
        "messages_history_source_final",
    ];
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!("owned message guard {guard} was not enabled"));
        }
    }
    tx.batch_execute("SAVEPOINT owned_message_joint_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    if matches!(&ordinary,Ok(n) if *n>0) {
        tx.batch_execute("RELEASE SAVEPOINT owned_message_joint_probe")
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_message_joint_probe; RELEASE SAVEPOINT owned_message_joint_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err(
            "message joint control did not encounter its explicit registered refusal".into(),
        );
    }
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    let n = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    for guard in GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.messages ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in GUARDS {
        let state:String=tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.messages'::regclass AND tgname=$1 AND NOT tgisinternal",&[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "message guard {guard} was not restored before natural COMMIT/product reader"
            ));
        }
    }
    if n == 0 {
        return Err("owned message corruption changed no row".into());
    }
    Ok(())
}
async fn tamper_owned_thread_identity(
    tx: &tokio_postgres::Transaction<'_>,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<(), String> {
    const NEW_GUARDS: [&str; 3] = [
        "threads_history_body_before_update",
        "threads_history_canonical_before",
        "threads_history_source_final",
    ];
    const OLD: &str = "threads_history_protect_identity_update";
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned registered Thread guard {guard} was not normally enabled"
            ));
        }
    }
    tx.batch_execute("SAVEPOINT owned_current_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let ordinary = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_current_identity_probe; RELEASE SAVEPOINT owned_current_identity_probe").await.map_err(|e|e.to_string())?;
    if !ordinary
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000"
                && matches!(
                    e.message(),
                    "thread_history_state_binding_invalid"
                        | "thread_history_writer_binding_invalid"
                        | "thread_history_writer_source_mutation_refused"
                )
        })
    {
        return Err("ordinary current Thread identity DML was not explicitly refused".into());
    }
    // Suppress only these owned fixture events BEFORE corrupting DML. Re-enabling
    // at COMMIT cannot remove an already queued deferred event; none is bypassed.
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads DISABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.batch_execute("SAVEPOINT owned_original50_identity_probe")
        .await
        .map_err(|e| e.to_string())?;
    let original = tx.execute(sql, params).await;
    tx.batch_execute("ROLLBACK TO SAVEPOINT owned_original50_identity_probe; RELEASE SAVEPOINT owned_original50_identity_probe").await.map_err(|e|e.to_string())?;
    if !original
        .as_ref()
        .err()
        .and_then(|e| e.as_db_error())
        .is_some_and(|e| {
            e.code().code() == "55000" && e.message() == "thread_history_state_binding_invalid"
        })
    {
        return Err("original0050 single identity guard control lost its exact refusal".into());
    }
    tx.batch_execute(
        "ALTER TABLE public.threads DISABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    let changed = tx.execute(sql, params).await.map_err(|e| e.to_string())?;
    tx.batch_execute(
        "ALTER TABLE public.threads ENABLE TRIGGER threads_history_protect_identity_update",
    )
    .await
    .map_err(|e| e.to_string())?;
    for guard in NEW_GUARDS {
        tx.batch_execute(&format!(
            "ALTER TABLE public.threads ENABLE TRIGGER {guard}"
        ))
        .await
        .map_err(|e| e.to_string())?;
    }
    for guard in NEW_GUARDS.into_iter().chain([OLD]) {
        let state: String = tx.query_one("SELECT tgenabled::text FROM pg_catalog.pg_trigger WHERE tgrelid='public.threads'::regclass AND tgname=$1 AND NOT tgisinternal", &[&guard]).await.map_err(|e|e.to_string())?.get(0);
        if state != "O" {
            return Err(format!(
                "owned Thread guard {guard} was not restored before product entry"
            ));
        }
    }
    if changed == 0 {
        return Err("owned identity control changed no row".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SourceMutation {
    DirectMembership,
    ThreadTenant,
    ProfileVisibility,
    ChannelMembership,
    ChannelAssignment,
    PackageTenant,
    MessageRole,
    MessageActor,
    MessageRun,
    MessageDelete,
    OperationPayload,
    DatasetTuple,
    StoreTuple,
    OriginalFd,
    RootMode,
    Marker,
}
impl SourceMutation {
    fn identity(self) -> &'static str {
        match self {
            Self::DirectMembership => "direct_membership",
            Self::ThreadTenant => "thread_tenant",
            Self::ProfileVisibility => "profile_visibility",
            Self::ChannelMembership => "channel_membership",
            Self::ChannelAssignment => "channel_assignment",
            Self::PackageTenant => "package_tenant",
            Self::MessageRole => "message_role",
            Self::MessageActor => "message_actor",
            Self::MessageRun => "message_run",
            Self::MessageDelete => "message_delete",
            Self::OperationPayload => "operation_payload",
            Self::DatasetTuple => "dataset_tuple",
            Self::StoreTuple => "store_tuple",
            Self::OriginalFd => "original_fd",
            Self::RootMode => "root_mode",
            Self::Marker => "marker",
        }
    }
    fn channel(self) -> bool {
        matches!(
            self,
            Self::ChannelMembership | Self::ChannelAssignment | Self::PackageTenant
        )
    }
    fn lock_sql(self) -> &'static str {
        match self {
            // Acquire the ALTER TRIGGER table lock before releasing the real final query.
            Self::ThreadTenant => {
                "LOCK TABLE public.sessions,public.threads IN ACCESS EXCLUSIVE MODE"
            }
            Self::MessageRole | Self::MessageActor | Self::MessageRun => {
                "LOCK TABLE public.sessions,public.messages IN ACCESS EXCLUSIVE MODE"
            }
            Self::OperationPayload => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_save_operations IN ACCESS EXCLUSIVE MODE"
            }
            Self::DatasetTuple => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_dataset_bindings IN ACCESS EXCLUSIVE MODE"
            }
            Self::StoreTuple => {
                "LOCK TABLE public.sessions,openbot_internal.artifact_store_bindings IN ACCESS EXCLUSIVE MODE"
            }
            _ => "LOCK TABLE public.sessions IN ACCESS EXCLUSIVE MODE",
        }
    }
    async fn apply(self, f: &Fixture, tx: &tokio_postgres::Transaction<'_>) -> Result<(), String> {
        match self {
            Self::DirectMembership => tx.batch_execute("DELETE FROM public.thread_memberships WHERE user_id='read-owner'").await.map_err(|e| e.to_string()),
            Self::ThreadTenant => tamper_owned_thread_identity(tx, "UPDATE public.threads SET tenant_id='foreign'", &[]).await,
            Self::ProfileVisibility => tx.batch_execute("UPDATE public.agent_profiles SET visibility='private',owner_user_id='read-other'").await.map_err(|e| e.to_string()),
            Self::ChannelMembership => tx.batch_execute("DELETE FROM public.channel_memberships WHERE user_id='read-owner'").await.map_err(|e| e.to_string()),
            Self::ChannelAssignment => tx.batch_execute("DELETE FROM public.channel_agents WHERE channel_id='read-channel'").await.map_err(|e| e.to_string()),
            Self::PackageTenant => tx.batch_execute("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000051'; UPDATE public.deployment_packages SET tenant_id='foreign'").await.map_err(|e| e.to_string()),
            Self::MessageRole => tamper_owned_message_joint(tx, "UPDATE public.messages SET role='assistant'", &[]).await,
            Self::MessageActor => tamper_owned_message_joint(tx, "UPDATE public.messages SET actor_id='read-other'", &[]).await,
            Self::MessageRun => tamper_owned_message_joint(tx, "UPDATE public.messages SET run_id='another-run'", &[]).await,
            Self::MessageDelete => tx.batch_execute("DELETE FROM public.messages").await.map_err(|e| e.to_string()),
            // Closed corruption controls only in this disposable DB. Restore the registered
            // trigger in the same transaction before the real controller COMMIT ACK.
            Self::OperationPayload => tx.batch_execute("ALTER TABLE openbot_internal.artifact_save_operations DISABLE TRIGGER artifact_save_operations_identity_guard; UPDATE openbot_internal.artifact_save_operations SET actual_sha256=repeat('0',64); ALTER TABLE openbot_internal.artifact_save_operations ENABLE TRIGGER artifact_save_operations_identity_guard").await.map_err(|e| e.to_string()),
            Self::DatasetTuple => tx.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only; UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary'; ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|e| e.to_string()),
            Self::StoreTuple => tx.batch_execute("ALTER TABLE openbot_internal.artifact_store_bindings DISABLE TRIGGER artifact_store_bindings_append_only; UPDATE openbot_internal.artifact_store_bindings SET root_inode='0'; ALTER TABLE openbot_internal.artifact_store_bindings ENABLE TRIGGER artifact_store_bindings_append_only").await.map_err(|e| e.to_string()),
            Self::OriginalFd => {
                mutate_owned_read_only_file(
                    &f.object(&f.saved_id().await?),
                    |object, _| object.set_len(1),
                    |before, after| before.len() > 1 && after.len() == 1
                        && after == &before[..1],
                )
            }
            Self::RootMode => fs::set_permissions(&f.root.0, Permissions::from_mode(0o755)).map_err(|e| e.to_string()),
            Self::Marker => mutate_owned_read_only_file(
                &f.root.0.join(".artifact-store-v1"),
                |marker, _| {
                    marker.set_len(0)?;
                    marker.write_all(b"changed-owned-marker")
                },
                |_, after| after == b"changed-owned-marker",
            ),
        }
    }
    fn expected(self, error: &AppError) -> bool {
        if matches!(
            self,
            Self::OperationPayload
                | Self::DatasetTuple
                | Self::StoreTuple
                | Self::OriginalFd
                | Self::RootMode
                | Self::Marker
        ) {
            matches!(
                error,
                AppError::DependencyUnavailable {
                    dependency: "artifacts"
                }
            )
        } else {
            matches!(error, AppError::NotVisible)
        }
    }
}
impl Fixture {
    async fn saved_id(&self) -> Result<String, String> {
        self.pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT artifact_id FROM openbot_internal.artifact_records",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .try_get(0)
            .map_err(|e| e.to_string())
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_post_io_source_and_physical_mutation_matrix() {
    for mutation in [
        SourceMutation::DirectMembership,
        SourceMutation::ThreadTenant,
        SourceMutation::ProfileVisibility,
        SourceMutation::ChannelMembership,
        SourceMutation::ChannelAssignment,
        SourceMutation::PackageTenant,
        SourceMutation::MessageRole,
        SourceMutation::MessageActor,
        SourceMutation::MessageRun,
        SourceMutation::MessageDelete,
        SourceMutation::OperationPayload,
        SourceMutation::DatasetTuple,
        SourceMutation::StoreTuple,
        SourceMutation::OriginalFd,
        SourceMutation::RootMode,
        SourceMutation::Marker,
    ] {
        with_fixture("arc_source", mutation.channel(), |f| async move {
            let saved = f.save().await?;
            let (worker, reached, proceed) = start_after_io(&f, &saved.artifact_id, true).await?;
            tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "post-IO gate timed out".to_owned())?.map_err(|_| "post-IO gate sender gone".to_owned())?;
            let mut controller = f.pool.get().await.map_err(|e| e.to_string())?;
            let controller_pid: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            let tx = controller.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute(mutation.lock_sql()).await.map_err(|e| e.to_string())?;
            proceed.send(()).map_err(|_| "post-IO gate release gone".to_owned())?;
            let reader_pid = wait_final_lock(&f.pool, controller_pid).await?;
            mutation.apply(&f, &tx).await?;
            tx.commit().await.map_err(|e| e.to_string())?;
            let error = worker.await.map_err(|e| e.to_string())?.err().ok_or_else(|| "post-IO mutation released bytes".to_owned())?;
            require(mutation.expected(&error), "post-IO mutation returned wrong closed failure")?;
            eprintln!("ARTIFACT_CURRENT_CORE_SOURCE case={} final_lock_pid={reader_pid} blocker_pid={controller_pid} controller_commit_ack=true denied=true", mutation.identity());
            Ok(())
        }).await;
    }
}

#[derive(Clone, Copy)]
enum SessionMutation {
    DeleteOriginal,
    Token,
    Created,
    Issued,
    CurrentNull,
    CurrentNegative,
    IssuedNull,
    IssuedNegative,
    Roles,
    Revoked,
    Expires,
    Idle,
}
impl SessionMutation {
    fn identity(self) -> &'static str {
        match self {
            Self::DeleteOriginal => "delete_original",
            Self::Token => "same_id_token",
            Self::Created => "same_id_created",
            Self::Issued => "same_id_issued",
            Self::CurrentNull => "current_null",
            Self::CurrentNegative => "current_negative",
            Self::IssuedNull => "issued_null",
            Self::IssuedNegative => "issued_negative",
            Self::Roles => "roles",
            Self::Revoked => "revoked",
            Self::Expires => "expires",
            Self::Idle => "idle",
        }
    }
    fn sql(self) -> &'static str {
        match self {
            Self::DeleteOriginal => "DELETE FROM public.sessions WHERE id='core-read-session-a'",
            Self::Token => {
                "UPDATE public.sessions SET token='changed-owned-test-column' WHERE id='core-read-session-a'"
            }
            Self::Created => {
                "UPDATE public.sessions SET created_at=created_at-interval '1 second' WHERE id='core-read-session-a'"
            }
            Self::Issued => {
                "UPDATE public.sessions SET auth_generation=1 WHERE id='core-read-session-a'"
            }
            Self::CurrentNull => {
                "UPDATE public.users SET auth_generation=NULL WHERE id='read-owner'"
            }
            Self::CurrentNegative => {
                "ALTER TABLE public.users DROP CONSTRAINT users_auth_generation_nonnegative; UPDATE public.users SET auth_generation=-1 WHERE id='read-owner'"
            }
            Self::IssuedNull => {
                "UPDATE public.sessions SET auth_generation=NULL WHERE id='core-read-session-a'"
            }
            Self::IssuedNegative => {
                "ALTER TABLE public.sessions DROP CONSTRAINT sessions_auth_generation_nonnegative; UPDATE public.sessions SET auth_generation=-1 WHERE id='core-read-session-a'"
            }
            Self::Roles => "DELETE FROM public.user_roles WHERE user_id='read-owner'",
            Self::Revoked => {
                "INSERT INTO public.revoked_access(email,revoked_by) VALUES('read-owner@example.test','read-owner')"
            }
            Self::Expires => {
                "UPDATE public.sessions SET expires_at=now()-interval '1 second' WHERE id='core-read-session-a'"
            }
            Self::Idle => {
                "UPDATE public.sessions SET updated_at=now()-interval '31 minutes' WHERE id='core-read-session-a'"
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_post_io_session_epoch_and_generation_matrix() {
    for mutation in [
        SessionMutation::DeleteOriginal,
        SessionMutation::Token,
        SessionMutation::Created,
        SessionMutation::Issued,
        SessionMutation::CurrentNull,
        SessionMutation::CurrentNegative,
        SessionMutation::IssuedNull,
        SessionMutation::IssuedNegative,
        SessionMutation::Roles,
        SessionMutation::Revoked,
        SessionMutation::Expires,
        SessionMutation::Idle,
    ] {
        with_fixture("arc_session", false, |f| async move {
            let mut f = f;
            if matches!(mutation, SessionMutation::Idle) {
                f.sql("UPDATE public.sessions SET created_at=now()-interval '59 minutes' WHERE id='core-read-session-a'").await?;
                f.created = f.pool.get().await.map_err(|e| e.to_string())?.query_one("SELECT created_at FROM public.sessions WHERE id='core-read-session-a'", &[]).await.map_err(|e| e.to_string())?.get(0);
            }
            let saved = f.save().await?;
            let (worker, reached, proceed) = start_after_io(&f, &saved.artifact_id, true).await?;
            tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "post-IO session gate timed out".to_owned())?.map_err(|_| "post-IO session gate gone".to_owned())?;
            let mut controller = f.pool.get().await.map_err(|e| e.to_string())?;
            let blocker: i32 = controller.query_one("SELECT pg_backend_pid()", &[]).await.map_err(|e| e.to_string())?.get(0);
            let tx = controller.transaction().await.map_err(|e| e.to_string())?;
            tx.batch_execute("LOCK TABLE public.sessions,public.users IN ACCESS EXCLUSIVE MODE").await.map_err(|e| e.to_string())?;
            proceed.send(()).map_err(|_| "post-IO session release gone".to_owned())?;
            let pid = wait_final_lock(&f.pool, blocker).await?;
            tx.batch_execute(mutation.sql()).await.map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            require(matches!(worker.await.map_err(|e| e.to_string())?, Err(AppError::Unauthenticated)), "post-IO original Session mutation was accepted")?;
            if matches!(mutation, SessionMutation::DeleteOriginal | SessionMutation::Token | SessionMutation::Created | SessionMutation::Issued | SessionMutation::IssuedNull) {
                let b = f.session_auth("core-read-session-b", "owned-test-session-column-b");
                let chunk = f.administration.read_host_bound_chunk(&b, &saved.artifact_id).await.map_err(|e| e.to_string())?;
                require(chunk.handoff(&b).map_err(|e| e.to_string())? == EXACT.as_bytes(), "unchanged same-actor/generation Session B lost its own read")?;
            }
            eprintln!("ARTIFACT_CURRENT_CORE_SESSION case={} final_lock_pid={pid} blocker_pid={blocker} controller_commit_ack=true denied=true", mutation.identity());
            Ok(())
        }).await;
    }
}

/// Only the owned test PostgreSQL TCP leg is proxied. Drop or hold the selected backend ROLLBACK
/// CommandComplete after the server actually rolled back; SQL and durable effects remain real.
struct RollbackAckProxy {
    port: u16,
    remaining: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    held: Arc<AtomicUsize>,
    hold_at_rollback: Arc<tokio::sync::Mutex<Option<RollbackHold>>>,
    task: tokio::task::JoinHandle<()>,
}

struct RollbackHold {
    arrived: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

struct HeldRollbackAck {
    arrived: tokio::sync::oneshot::Receiver<()>,
    release: tokio::sync::oneshot::Sender<()>,
}

impl HeldRollbackAck {
    async fn wait(&mut self) -> Result<(), String> {
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.arrived)
            .await
            .map_err(|_| "owned proxy did not observe the selected rolled back ACK".to_owned())?
            .map_err(|_| "owned proxy ACK arrival controller closed".to_owned())
    }

    fn release(self) -> Result<(), String> {
        self.release
            .send(())
            .map_err(|()| "owned proxy ACK release receiver closed".to_owned())
    }
}

impl RollbackAckProxy {
    async fn start(host: String, port: u16) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|error| error.to_string())?;
        let proxy_port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let remaining = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicUsize::new(0));
        let hold_at_rollback = Arc::new(tokio::sync::Mutex::new(None::<RollbackHold>));
        let countdown = Arc::clone(&remaining);
        let count = Arc::clone(&dropped);
        let held_count = Arc::clone(&held);
        let hold_controller = Arc::clone(&hold_at_rollback);
        let task = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let Ok(server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                    break;
                };
                let countdown = Arc::clone(&countdown);
                let count = Arc::clone(&count);
                let held_count = Arc::clone(&held_count);
                let hold_controller = Arc::clone(&hold_controller);
                children.spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    let backend = async {
                        loop {
                            let kind = server_read.read_u8().await?;
                            let length = server_read.read_u32().await?;
                            if !(4..=16 * 1024 * 1024).contains(&length) {
                                return Err(std::io::Error::other("invalid owned proxy frame"));
                            }
                            let mut payload = vec![0; (length - 4) as usize];
                            server_read.read_exact(&mut payload).await?;
                            if kind == b'C' && payload == b"ROLLBACK\0" {
                                let previous = countdown.fetch_update(
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                    |value| value.checked_sub(1),
                                );
                                if previous == Ok(1) {
                                    let hold = hold_controller.lock().await.take();
                                    if let Some(hold) = hold {
                                        held_count.fetch_add(1, Ordering::SeqCst);
                                        hold.arrived.send(()).map_err(|()| {
                                            std::io::Error::other("owned ACK controller closed")
                                        })?;
                                        tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            hold.release,
                                        )
                                        .await
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK hold timed out")
                                        })?
                                        .map_err(|_| {
                                            std::io::Error::other("owned ACK release closed")
                                        })?;
                                        // Forward this exact successful backend frame only after
                                        // the direct observer's real rolled back mutation.
                                    } else {
                                        count.fetch_add(1, Ordering::SeqCst);
                                        return Ok::<(), std::io::Error>(());
                                    }
                                }
                            }
                            client_write.write_u8(kind).await?;
                            client_write.write_u32(length).await?;
                            client_write.write_all(&payload).await?;
                        }
                    };
                    tokio::select! {
                        _ = tokio::io::copy(&mut client_read, &mut server_write) => {},
                        _ = backend => {},
                    }
                });
            }
        });
        Ok(Self {
            port: proxy_port,
            remaining,
            dropped,
            held,
            hold_at_rollback,
            task,
        })
    }

    async fn hold(&self, ordinal: usize) -> Result<HeldRollbackAck, String> {
        require(ordinal > 0, "owned ACK ordinal must be positive")?;
        let (arrived_sender, arrived) = tokio::sync::oneshot::channel();
        let (release, release_receiver) = tokio::sync::oneshot::channel();
        let mut controller = self.hold_at_rollback.lock().await;
        require(controller.is_none(), "owned ACK hold already armed")?;
        *controller = Some(RollbackHold {
            arrived: arrived_sender,
            release: release_receiver,
        });
        self.remaining.store(ordinal, Ordering::SeqCst);
        Ok(HeldRollbackAck { arrived, release })
    }
}

impl Drop for RollbackAckProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn with_rollback_ack<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(Fixture, RollbackAckProxy) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(tag), tag, |config| async move {
        let proxy = RollbackAckProxy::start(config.host.clone(), config.port).await?;
        let mut proxied = config;
        proxied.host = "127.0.0.1".to_owned();
        proxied.port = proxy.port;
        body(Fixture::new(proxied, false).await?, proxy).await
    })
    .await;
}

#[derive(Clone, Copy)]
enum SourceOutcome {
    Missing,
    Invisible,
    Deleted,
    Expired,
}
impl SourceOutcome {
    fn identity(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invisible => "invisible",
            Self::Deleted => "deleted",
            Self::Expired => "expired",
        }
    }
    async fn prepare(self, f: &Fixture) -> Result<String, String> {
        if matches!(self, Self::Missing) {
            return Ok(Uuid::now_v7().to_string());
        }
        let saved = f.save().await?;
        match self {
            Self::Invisible => {
                f.sql("DELETE FROM public.thread_memberships WHERE user_id='read-owner'")
                    .await?
            }
            Self::Deleted | Self::Expired => {
                let status = if matches!(self, Self::Deleted) {
                    "deleted"
                } else {
                    "expired"
                };
                let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
                let tx = client.transaction().await.map_err(|e| e.to_string())?;
                tx.execute("UPDATE openbot_internal.artifact_records SET status=$1,workspace_kind=NULL,workspace_id=NULL,media_type=NULL,byte_length=NULL,sha256=NULL,retention_class=NULL,saved_by=NULL,saved_at=NULL", &[&status]).await.map_err(|e| e.to_string())?;
                tx.execute("UPDATE openbot_internal.artifact_save_operations SET state=$1,store_id=NULL,workspace_kind=NULL,workspace_id=NULL,expected_sha256=NULL,expected_bytes=NULL,charged_bytes=NULL,actual_absent=NULL,actual_byte_length=NULL,actual_sha256=NULL,actual_location=NULL,observation_phase=NULL,created_at=NULL", &[&status]).await.map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
            Self::Missing => {}
        }
        Ok(saved.artifact_id)
    }
    fn expected(self, error: &AppError) -> bool {
        match self {
            Self::Missing | Self::Invisible => matches!(error, AppError::NotVisible),
            Self::Deleted => matches!(
                error,
                AppError::ArtifactGone {
                    status: ArtifactGoneStatus::Deleted
                }
            ),
            Self::Expired => matches!(
                error,
                AppError::ArtifactGone {
                    status: ArtifactGoneStatus::Expired
                }
            ),
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_host_first_missing_invisible_gone_and_final_clock() {
    for outcome in [
        SourceOutcome::Missing,
        SourceOutcome::Invisible,
        SourceOutcome::Deleted,
        SourceOutcome::Expired,
    ] {
        for failure in [
            "none",
            "session_delete_before_statement",
            "owner_close_during_rollback_ack",
            "session_expiry_during_rollback_ack",
        ] {
            with_rollback_ack("arc_error_tail", |f, proxy| async move {
                let id = outcome.prepare(&f).await?;
                let (worker, reached, proceed) = start_after_io(&f, &id, false).await?;
                tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "source outcome final gate timed out".to_owned())?.map_err(|_| "source outcome final gate closed".to_owned())?;
                // This source-error path intentionally had no byte worker. The gate proves real
                // final own-Pool setup/seed, not IO completion or SQL Lock/PID observation.
                let mut held = proxy.hold(1).await?;
                if failure == "session_delete_before_statement" {
                    f.sql("DELETE FROM public.sessions WHERE id='core-read-session-a'").await?;
                }
                if failure == "session_expiry_during_rollback_ack" {
                    f.sql("UPDATE public.sessions SET expires_at=now()+interval '300 milliseconds' WHERE id='core-read-session-a'").await?;
                }
                proceed.send(()).map_err(|_| "source outcome gate release closed".to_owned())?;
                held.wait().await?;
                require(proxy.held.load(Ordering::SeqCst) == 1 && proxy.dropped.load(Ordering::SeqCst) == 0, "real rollback ACK was not held")?;
                if failure == "owner_close_during_rollback_ack" { f._lease.close(); }
                if failure == "session_expiry_during_rollback_ack" {
                    let expires: OffsetDateTime = f.pool.get().await.map_err(|e| e.to_string())?.query_one(
                        "SELECT expires_at FROM public.sessions WHERE id='core-read-session-a'", &[],
                    ).await.map_err(|e| e.to_string())?.get(0);
                    let now = OffsetDateTime::now_utc();
                    require(now < expires, "session was already expired before actual rollback ACK hold")?;
                    let wait = std::time::Duration::try_from(expires - now).map_err(|_| "expiry interval was invalid".to_owned())? + Duration::from_millis(30);
                    tokio::time::sleep(wait).await;
                    require(OffsetDateTime::now_utc() >= expires, "held rollback ACK did not cross real expiry")?;
                }
                held.release()?;
                let error = worker.await.map_err(|e| e.to_string())?.err().ok_or_else(|| "source error released a chunk".to_owned())?;
                require(if failure == "none" { outcome.expected(&error) } else { matches!(error, AppError::Unauthenticated) }, "host/clock precedence lost across real explicit rollback ACK")?;
                eprintln!("ARTIFACT_CURRENT_CORE_ERROR_TAIL source={} failure={failure} actual_rollback_ack_held=true ack_released=true no_body=true", outcome.identity());
                Ok(())
            }).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_pg_cancelled_waiter_retains_worker_fd_and_raii_result() {
    with_fixture("arc_cancel", false, |f| async move {
        let saved = f.save().await?;
        // R430: the cancelled original final query keeps `saved`'s exact key permanently
        // unproven, so the assembled worker below consumes a second real saved record.
        let wrapped = f.save().await?;
        // Cancel the actual production consumer at its registered common final gate after
        // real snapshot/worker ACK. Dropping this future owns the pending buffer's Drop path;
        // it does not certify an acknowledged PostgreSQL rollback or inspect freed memory.
        let (production, reached, proceed) = start_after_io(&f, &saved.artifact_id, true).await?;
        tokio::time::timeout(Duration::from_secs(3), reached).await.map_err(|_| "actual production cancel gate timed out".to_owned())?.map_err(|_| "actual production cancel gate closed".to_owned())?;
        production.abort();
        require(production.await.is_err(), "actual production pending waiter was not cancelled")?;
        drop(proceed);
        let cancelled = f.observe(&saved.artifact_id).await.map_err(|e| e.to_string())?;
        require(f.store.open_observed_record(cancelled).is_err(), "cancelled original key admitted another body FD")?;
        let snapshot = f.observe(&wrapped.artifact_id).await.map_err(|e| e.to_string())?;
        let authority = f.administration.read_authority();
        let identity = Arc::clone(&authority.identity);
        let store = Arc::clone(&f.store);
        let store_weak = Arc::downgrade(&store);
        let (release_worker, worker_release) = std::sync::mpsc::channel();
        let (io_done, observed_io) = tokio::sync::oneshot::channel();
        let (completed, worker_completed) = tokio::sync::oneshot::channel();
        // The same real snapshot/open/chunk/RAII target composition as the registered producer.
        // A test-only wrapper holds this real result after IO, making waiter cancellation
        // deterministic. The wrapper is not a fake current-host or production timing grant.
        let physical = tokio::task::spawn_blocking(move || {
            let mut pending = PendingArtifactReadBuffer::new_initialized().map_err(|_| "RAII allocation failed".to_owned())?;
            let mut reader = store.open_observed_record(snapshot).map_err(|e| e.to_string())?;
            let length = reader.read_observed_chunk(pending.initialized_mut()).map_err(|e| e.to_string())?;
            pending.record_actual_length(length).map_err(|_| "actual length failed".to_owned())?;
            let target = Arc::new(ActualArtifactReadTarget::from_reader(identity, reader));
            let result = ArtifactReadWorkerResult { pending, target };
            io_done.send(()).map_err(|_| "IO observer gone".to_owned())?;
            worker_release.recv_timeout(Duration::from_secs(5)).map_err(|_| "bounded worker hold was not released".to_owned())?;
            result.pending.actual_length().ok_or_else(|| "RAII result was lost before completion".to_owned())?;
            completed.send(()).map_err(|_| "completion observer gone".to_owned())?;
            Ok::<_, String>(result)
        });
        let waiter = tokio::spawn(physical);
        observed_io.await.map_err(|_| "real IO did not finish before barrier".to_owned())?;
        waiter.abort();
        require(waiter.await.is_err(), "waiter was not cancelled")?;
        let administration_weak = Arc::downgrade(&f.administration);
        let Fixture { pool, registry, store, administration, _lease, root, .. } = f;
        drop(administration);
        drop(registry);
        drop(store);
        require(administration_weak.upgrade().is_none(), "worker prolonged actual administration")?;
        require(store_weak.upgrade().is_some(), "cancelled waiter dropped worker's store Arc after all composition owners dropped")?;
        _lease.close();
        drop(_lease);
        // Cancellation of the JoinHandle neither stops this actual worker nor acknowledges it.
        release_worker.send(()).map_err(|_| "actual worker release receiver gone".to_owned())?;
        worker_completed.await.map_err(|_| "actual worker completion ACK was absent".to_owned())?;
        // This assembled worker wrapper measures a real JoinHandle/RAII completion and store
        // Arc reclamation; Weak<Store> is not a kernel FD census. Production physical-worker
        // cancellation and continuous original-FD kernel occupancy remain lifecycle follow-up.
        // The abandoned result is dropped by Tokio, with its whole initialized pending buffer
        // still owned by Zeroizing. No body extraction or freed-memory inspection is used.
        tokio::time::timeout(Duration::from_secs(2), async {
            while store_weak.upgrade().is_some() { tokio::task::yield_now().await; }
        }).await.map_err(|_| "abandoned RAII result retained store Arc after worker completion".to_owned())?;
        drop(pool);
        drop(root);
        eprintln!("ARTIFACT_CURRENT_CORE_CANCEL cancelled_waiter=true actual_io_ack=true actual_worker_completion_ack=true store_arc_owners_absent=true owned_root_cleanup=true body_handoff=false");
        Ok(())
    }).await;
}

async fn actual_pool(config: &pool::DatabaseConfig) -> Result<pool::DatabasePool, String> {
    let pool = pool::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    drop(client);
    Ok(pool)
}

#[tokio::test]
#[ignore = "requires owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn actual_owned_server_registry_cannot_mint_desktop_read_provenance() {
    harness::with_temp_database(&harness::admin_config("arc_desktop_provenance"), "arc_desktop_provenance", |config| async move {
        let pool = actual_pool(&config).await?;
        let installation_root = OwnedRoot::new()?;
        let installation = DesktopLocalAuthorityStore::new(CurrentOsUserAppDataRoot::from_current_os_user_app_data(&installation_root.0).map_err(|error| error.to_string())?).load_or_create().map_err(|error| error.to_string())?;
        let scope = installation.auth_context();
        let registry = ArtifactDatasetRegistry::from_server(pool.clone(), scope.deployment(), scope.tenant()).await.map_err(|error| error.to_string())?;
        assert!(registry.matches_pool_scope(&pool, scope.deployment(), scope.tenant()));
        assert_eq!(registry.binding().initial_origin(), "server_first_adoption");
        assert!(!registry.matches_desktop_read_installation(&installation));
        // Neither the exact same Pool/namespace nor changing immutable history can manufacture
        // Some(sealed VerifiedCanary provenance). The mutation is test-owned corruption only.
        pool.get().await.map_err(|error| error.to_string())?.batch_execute("ALTER TABLE openbot_internal.artifact_dataset_bindings DISABLE TRIGGER artifact_dataset_bindings_append_only; UPDATE openbot_internal.artifact_dataset_bindings SET initial_origin='desktop_canary'; ALTER TABLE openbot_internal.artifact_dataset_bindings ENABLE TRIGGER artifact_dataset_bindings_append_only").await.map_err(|error| error.to_string())?;
        assert!(!registry.matches_desktop_read_installation(&installation));
        drop(registry);
        pool.close();
        drop(installation_root);
        Ok(())
    }).await;
}
