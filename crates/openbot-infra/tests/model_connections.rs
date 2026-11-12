//! Isolated real PostgreSQL/Vault personal model-connection transactions.
mod harness;
#[path = "support/recovery_admission.rs"]
mod recovery_admission;

use openbot_application::model_connections::{
    ModelConnectionAdministration, ModelConnectionError as Error,
};
use openbot_contracts::{
    auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role},
    ids::{ActorId, DeploymentId, TenantId},
    model_connections::*,
};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::{
    db::{baseline, native, pool},
    model_connections::PostgresModelConnections,
    vault::CredentialRecordVault,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const DEP: &str = "model-deployment";
const TENANT: &str = "model-tenant";
const AUDIT: &[u8] = b"model-connection-test-audit-key-32-bytes";
fn auth(actor: &str, generation: u64, role: Role) -> AuthContext {
    // This owned database is outside every recovery domain.
    recovery_admission::outside_domain(
        AuthContextBuilder::from_verified_session(
            DeploymentId::new(DEP),
            TenantId::new(TENANT),
            ActorId::new(actor),
            AuthGeneration::new(generation),
            false,
        )
        .with_roles([role])
        .build(),
    )
}
fn owner() -> AuthContext {
    auth("alice", 7, Role::User)
}
fn input() -> CreateModelConnection {
    CreateModelConnection {
        name: "Owner model".to_owned(),
        protocol: CustomModelProtocol::OpenaiChatCompletions,
        endpoint: "https://provider.example.test/v1".to_owned(),
        model: "model-1".to_owned(),
        enabled: true,
        api_key: ModelApiKey::new(Zeroizing::new("MODEL_FAKE_CANARY_ONE".to_owned())).unwrap(),
    }
}
fn update(row: &ModelConnection) -> UpdateModelConnection {
    UpdateModelConnection {
        expected_revision: row.revision,
        name: row.name.clone(),
        protocol: row.protocol,
        endpoint: row.endpoint.clone(),
        model: row.model.clone(),
        enabled: row.enabled,
        api_key: None,
    }
}
async fn setup(
    pool: &openbot_infra::db::pool::DatabasePool,
) -> Result<(PostgresModelConnections, CredentialRecordVault), String> {
    let mut c = pool.get().await.map_err(|e| e.to_string())?;
    baseline::apply(&c).await.map_err(|e| e.to_string())?;
    native::apply(&mut c).await.map_err(|e| e.to_string())?;
    c.batch_execute("INSERT INTO public.users(id,email,auth_generation) VALUES('alice','alice@example.test',7),('bob','bob@example.test',3); INSERT INTO public.user_roles(user_id,role) VALUES('alice','user'),('bob','admin');").await.map_err(|e|e.to_string())?;
    drop(c);
    let vault = CredentialRecordVault::single_key(
        TenantId::new(TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x31; 32]).unwrap(),
    );
    let port = PostgresModelConnections::new(
        pool.clone(),
        vault.clone(),
        DeploymentId::new(DEP),
        TenantId::new(TENANT),
        SecretBytes::new(AUDIT.to_vec()),
    )
    .unwrap();
    Ok((port, vault))
}
async fn current_secret(pool: &openbot_infra::db::pool::DatabasePool, id: &str) -> (Uuid, String) {
    let c = pool.get().await.unwrap();
    let id = Uuid::parse_str(id).unwrap();
    let row=c.query_one("SELECT s.id,s.encrypted_value FROM public.model_connections c JOIN public.model_connection_secrets s ON s.id=c.current_secret_id WHERE c.id=$1",&[&id]).await.unwrap();
    (row.get(0), row.get(1))
}

#[tokio::test]
#[ignore = "requires an isolated loopback PostgreSQL; explicit include-ignored only"]
async fn personal_crud_rotates_bound_keys_and_retires_atomically() {
    let config = harness::admin_config("model_connections_crud");
    harness::with_temp_database(&config,"modelcrud",|config|async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;let (port,vault)=setup(&pool).await?;
        let created=port.create(&owner(),&input()).await.unwrap();assert_eq!(created.source,ModelConnectionSource::Custom);assert_eq!(created.revision,1);assert_eq!(created.endpoint,"https://provider.example.test/v1/chat/completions");
        let serialized=serde_json::to_string(&created).unwrap();assert!(!serialized.contains("MODEL_FAKE_CANARY"));assert!(!serialized.contains("apiKey"));
        let (first,encrypted)=current_secret(&pool,&created.id).await;assert!(!encrypted.contains("MODEL_FAKE_CANARY"));
        let consumer=SecretPrincipal::Service(ServiceId::new(created.id.clone()));
        let secret=vault.open(&first,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("alice")),consumer.clone(),&encrypted).unwrap().into_secret();assert_eq!(secret.expose(),b"MODEL_FAKE_CANARY_ONE");
        assert!(vault.open(&first,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("bob")),consumer,&encrypted).is_err());
        assert!(vault.open(&first,SecretKind::Model,SecretPrincipal::Actor(ActorId::new("alice")),SecretPrincipal::Service(ServiceId::new("other-connection")),&encrypted).is_err());
        let mut replace=update(&created);replace.model="model-2".to_owned();replace.enabled=false;
        let changed=port.update(&owner(),&created.id,&replace).await.unwrap();assert_eq!(changed.revision,2);assert!(!changed.enabled);assert_eq!(current_secret(&pool,&created.id).await.0,first);
        assert_eq!(port.update(&owner(),&created.id,&replace).await.unwrap_err(),Error::StaleSnapshot(openbot_contracts::revision::RevisionSnapshot::from_public(changed.revision,changed.updated_at,&changed).unwrap()));
        let mut replace=update(&changed);replace.endpoint="https://other.example.test/v1".to_owned();
        assert!(matches!(port.update(&owner(),&created.id,&replace).await,Err(Error::InvalidInput {field:"apiKey"})));
        replace.api_key=Some(ModelApiKey::new(Zeroizing::new("MODEL_FAKE_CANARY_TWO".to_owned())).unwrap());replace.enabled=true;
        let rotated=port.update(&owner(),&created.id,&replace).await.unwrap();assert_eq!(rotated.revision,3);assert!(rotated.enabled);
        let (second,_)=current_secret(&pool,&created.id).await;assert_ne!(second,first);
        let c=pool.get().await.unwrap();let retired:bool=c.query_one("SELECT retired_at IS NOT NULL FROM public.model_connection_secrets WHERE id=$1",&[&first]).await.unwrap().get(0);assert!(retired);drop(c);
        let deleted=port.delete(&owner(),&created.id,&DeleteModelConnection {expected_revision:3}).await.unwrap();assert_eq!(deleted.revision,4);
        assert_eq!(port.get(&owner(),&created.id).await.unwrap_err(),Error::NotVisible);
        assert!(port.list(&owner(),&ModelConnectionPageRequest::default()).await.unwrap().connections.is_empty());
        let c=pool.get().await.unwrap();let active:i64=c.query_one("SELECT count(*) FROM public.model_connection_secrets WHERE retired_at IS NULL",&[]).await.unwrap().get(0);assert_eq!(active,0);
        let audit:String=c.query_one("SELECT string_agg(payload::text,' ') FROM public.audit_events WHERE target_type='model_connection'",&[]).await.unwrap().get(0);assert!(!audit.contains("MODEL_FAKE_CANARY"));assert!(!audit.contains("provider.example"));drop(c);pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback PostgreSQL; explicit include-ignored only"]
async fn current_actor_generation_roles_deny_and_all_scopes_are_enforced() {
    let config = harness::admin_config("model_connections_auth");
    harness::with_temp_database(&config,"modelauth",|config|async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;let (port,vault)=setup(&pool).await?;
        let row=port.create(&owner(),&input()).await.unwrap();let admin=auth("bob",3,Role::Admin);
        let advanced=port.update(&owner(),&row.id,&update(&row)).await.unwrap();assert_eq!(advanced.revision,2);
        assert_eq!(port.get(&admin,&row.id).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.update(&admin,&row.id,&update(&row)).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.delete(&admin,&row.id,&DeleteModelConnection {expected_revision:1}).await.unwrap_err(),Error::NotVisible);
        assert!(port.list(&admin,&ModelConnectionPageRequest::default()).await.unwrap().connections.is_empty());
        assert!(port.create(&admin,&input()).await.is_ok());
        for (dep,tenant) in [("other-deployment",TENANT),(DEP,"other-tenant")] {
            let scoped=AuthContextBuilder::from_verified_session(DeploymentId::new(dep),TenantId::new(tenant),ActorId::new("alice"),AuthGeneration::new(7),false).with_roles([Role::User]).build();
            assert_eq!(port.get(&scoped,&row.id).await.unwrap_err(),Error::NotVisible);
            let other=PostgresModelConnections::new(pool.clone(),vault.clone(),DeploymentId::new(dep),TenantId::new(tenant),SecretBytes::new(AUDIT.to_vec())).unwrap();
            assert_eq!(other.get(&scoped,&row.id).await.unwrap_err(),Error::NotVisible);
            assert!(other.list(&scoped,&ModelConnectionPageRequest::default()).await.unwrap().connections.is_empty());
        }
        let missing=auth("missing",7,Role::User);assert_eq!(port.create(&missing,&input()).await.unwrap_err(),Error::NotVisible);
        let c=pool.get().await.unwrap();c.batch_execute("UPDATE public.users SET auth_generation=8 WHERE id='alice'").await.unwrap();drop(c);
        assert_eq!(port.get(&owner(),&row.id).await.unwrap_err(),Error::NotVisible);assert_eq!(port.create(&owner(),&input()).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.update(&owner(),&row.id,&update(&row)).await.unwrap_err(),Error::NotVisible);
        assert_eq!(port.delete(&owner(),&row.id,&DeleteModelConnection {expected_revision:1}).await.unwrap_err(),Error::NotVisible);
        let fresh=auth("alice",8,Role::User);assert!(port.get(&fresh,&row.id).await.is_ok());
        let c=pool.get().await.unwrap();c.batch_execute("DELETE FROM public.user_roles WHERE user_id='alice'").await.unwrap();drop(c);
        assert_eq!(port.list(&fresh,&ModelConnectionPageRequest::default()).await.unwrap_err(),Error::NotVisible);
        let c=pool.get().await.unwrap();c.batch_execute("INSERT INTO public.user_roles(user_id,role) VALUES('alice','user');INSERT INTO public.revoked_access(email,revoked_by) VALUES('alice@example.test','bob')").await.unwrap();drop(c);
        assert_eq!(port.get(&fresh,&row.id).await.unwrap_err(),Error::NotVisible);assert_eq!(port.delete(&fresh,&row.id,&DeleteModelConnection {expected_revision:1}).await.unwrap_err(),Error::NotVisible);
        pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback PostgreSQL; explicit include-ignored only"]
async fn audit_or_ciphertext_failures_roll_back_metadata_and_key_references() {
    let config = harness::admin_config("model_connections_rollback");
    harness::with_temp_database(&config,"modelrollback",|config|async move {
        let pool=pool::connect(&config).await.map_err(|e|e.to_string())?;let (port,_)=setup(&pool).await?;
        let original=port.create(&owner(),&input()).await.unwrap();let first=current_secret(&pool,&original.id).await.0;
        let c=pool.get().await.unwrap();c.batch_execute("CREATE FUNCTION model_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.target_type='model_connection' THEN RAISE EXCEPTION 'qa fault';END IF;RETURN NEW;END$$;CREATE TRIGGER model_audit_fault BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION model_audit_fault();").await.unwrap();drop(c);
        let mut replace=update(&original);replace.api_key=Some(ModelApiKey::new(Zeroizing::new("SECOND_CANARY".to_owned())).unwrap());
        assert_eq!(port.update(&owner(),&original.id,&replace).await.unwrap_err(),Error::Unavailable);
        assert_eq!(port.get(&owner(),&original.id).await.unwrap(),original);assert_eq!(current_secret(&pool,&original.id).await.0,first);
        assert_eq!(port.delete(&owner(),&original.id,&DeleteModelConnection {expected_revision:1}).await.unwrap_err(),Error::Unavailable);
        let c=pool.get().await.unwrap();let secrets:i64=c.query_one("SELECT count(*) FROM public.model_connection_secrets",&[]).await.unwrap().get(0);assert_eq!(secrets,1);
        c.batch_execute("DROP TRIGGER model_audit_fault ON public.audit_events;DROP FUNCTION model_audit_fault();CREATE FUNCTION model_ciphertext_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.encrypted_value='invalid-envelope';RETURN NEW;END$$;CREATE TRIGGER model_ciphertext_fault BEFORE INSERT ON public.model_connection_secrets FOR EACH ROW EXECUTE FUNCTION model_ciphertext_fault();").await.unwrap();drop(c);
        assert_eq!(port.create(&owner(),&input()).await.unwrap_err(),Error::Corrupt);
        assert_eq!(port.update(&owner(),&original.id,&replace).await.unwrap_err(),Error::Corrupt);
        assert_eq!(port.get(&owner(),&original.id).await.unwrap(),original);
        let c=pool.get().await.unwrap();let secrets:i64=c.query_one("SELECT count(*) FROM public.model_connection_secrets",&[]).await.unwrap().get(0);assert_eq!(secrets,1);drop(c);pool.close();Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback PostgreSQL; explicit include-ignored only"]
async fn inventory_page_is_stable_bounded_and_actor_scoped() {
    let config = harness::admin_config("model_connections_page");
    harness::with_temp_database(&config, "modelpage", |config| async move {
        let pool = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let (port, _) = setup(&pool).await?;
        for _ in 0..101 {
            port.create(&owner(), &input()).await.unwrap();
        }
        port.create(&auth("bob", 3, Role::Admin), &input())
            .await
            .unwrap();
        let first = port
            .list(&owner(), &ModelConnectionPageRequest::default())
            .await
            .unwrap();
        assert_eq!(first.connections.len(), 100);
        assert!(first.next_cursor.is_some());
        let last = port
            .list(
                &owner(),
                &ModelConnectionPageRequest {
                    cursor: first.next_cursor,
                },
            )
            .await
            .unwrap();
        assert_eq!(last.connections.len(), 1);
        assert!(last.next_cursor.is_none());
        assert!(first.connections.last().unwrap().id < last.connections[0].id);
        pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an isolated loopback PostgreSQL; explicit include-ignored only"]
async fn concurrent_metadata_replacements_commit_exactly_one_revision() {
    let config = harness::admin_config("model_connections_concurrent");
    harness::with_temp_database(&config, "modelcas", |config| async move {
        let config = config.with_max_pool_size(2);
        let pool = pool::connect(&config)
            .await
            .map_err(|e| e.to_string())?;
        let (port, _) = setup(&pool).await?;
        let created = port.create(&owner(), &input()).await.unwrap();
        // A stronger session default must not turn a stale edit into a serialization error.
        // Hold both pool connections while configuring them, so both writers inherit it.
        let first = pool.get().await.unwrap();
        let second = pool.get().await.unwrap();
        for client in [&first, &second] {
            client
                .batch_execute("SET default_transaction_isolation = 'repeatable read'")
                .await
                .unwrap();
            let isolation: String = client
                .query_one("SHOW default_transaction_isolation", &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(isolation, "repeatable read");
        }
        drop(first);
        drop(second);
        // Lock with a third owned connection and observe both writers waiting before release.
        // Both transactions have therefore taken a snapshot before either can commit.
        let (mut barrier, connection) = config.to_pg_config().connect(tokio_postgres::NoTls).await.unwrap();
        let connection_task = tokio::spawn(async move { connection.await.unwrap() });
        let barrier_tx = barrier.transaction().await.unwrap();
        barrier_tx.query_one("SELECT id FROM public.model_connections WHERE id=$1 FOR UPDATE", &[&Uuid::parse_str(&created.id).unwrap()]).await.unwrap();
        let mut left = update(&created);
        let mut right = left.clone();
        left.name = "left".to_owned();
        right.name = "right".to_owned();
        let auth = owner();
        let (left, right, ()) = tokio::join!(
            port.update(&auth, &created.id, &left),
            port.update(&auth, &created.id, &right),
            async {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    loop {
                        let waiting: i64 = barrier_tx.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND cardinality(pg_blocking_pids(pid))>0", &[]).await.unwrap().get(0);
                        if waiting == 2 { break; }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }).await.expect("both real writers must reach the lock barrier");
                barrier_tx.commit().await.unwrap();
            }
        );
        drop(barrier);
        connection_task.await.unwrap();
        let (winner, snapshot) = match (left, right) {
            (Ok(row), Err(Error::StaleSnapshot(snapshot)))
            | (Err(Error::StaleSnapshot(snapshot)), Ok(row)) => (row, snapshot),
            other => panic!("one revision must win: {other:?}"),
        };
        assert_eq!(winner.revision, 2);
        assert_eq!(
            snapshot,
            openbot_contracts::revision::RevisionSnapshot::from_public(
                winner.revision,
                winner.updated_at,
                &winner
            )
            .unwrap()
        );
        assert_eq!(port.get(&auth, &created.id).await.unwrap(), winner);
        let client = pool.get().await.unwrap();
        let count: i64 = client
            .query_one("SELECT count(*) FROM public.model_connection_secrets", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1);
        let audit_count: i64 = client
            .query_one(
                "SELECT count(*) FROM public.audit_events WHERE target_type='model_connection'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(audit_count, 2);
        drop(client);
        pool.close();
        Ok(())
    })
    .await;
}
