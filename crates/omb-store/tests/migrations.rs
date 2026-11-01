#[path = "../src/testkit.rs"]
mod testkit;
use omb_store::{StoreError, migrate};
use sha2::{Digest, Sha256};
use testkit::{Fixture, deadline};
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn bootstrap_and_initial_migration_create_exact_version_record() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    let result = migrate(&mut session.client, deadline()).await.unwrap();
    assert_eq!(result.applied_count, 2);
    assert_eq!(result.current_version, 2);
    let rows=session.client.query("SELECT version,name,sha256,applied_at<=statement_timestamp() FROM openmybot.omb_migrations ORDER BY version",&[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    for (row, (version, name, sql)) in rows.iter().zip([
        (
            1,
            "omb_0001_initial.sql",
            &include_bytes!("../migrations/omb_0001_initial.sql")[..],
        ),
        (
            2,
            "omb_0002_open_channel_kind.sql",
            &include_bytes!("../migrations/omb_0002_open_channel_kind.sql")[..],
        ),
    ]) {
        assert_eq!(row.get::<_, i32>(0), version);
        assert_eq!(row.get::<_, String>(1), name);
        assert_eq!(row.get::<_, Vec<u8>>(2), Sha256::digest(sql).to_vec());
        assert!(row.get::<_, bool>(3));
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn second_start_is_idempotent_without_new_migration_rows() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    let before = session
        .client
        .query_one(
            "SELECT json_agg(m ORDER BY m.version)::text FROM openmybot.omb_migrations m",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(
        migrate(&mut session.client, deadline())
            .await
            .unwrap()
            .applied_count,
        0
    );
    let after = session
        .client
        .query_one(
            "SELECT json_agg(m ORDER BY m.version)::text FROM openmybot.omb_migrations m",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(before, after);
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn modified_applied_digest_is_rejected_without_mutation() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    session
        .client
        .batch_execute("UPDATE openmybot.omb_migrations SET sha256=decode(repeat('00',32),'hex')")
        .await
        .unwrap();
    let before = session
        .client
        .query_one(
            "SELECT json_agg(m ORDER BY m.version)::text FROM openmybot.omb_migrations m",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(
        migrate(&mut session.client, deadline()).await.unwrap_err(),
        StoreError::MigrationDrift
    );
    let after = session
        .client
        .query_one(
            "SELECT json_agg(m ORDER BY m.version)::text FROM openmybot.omb_migrations m",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(before, after);
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn unknown_database_version_is_rejected_without_mutation() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    session.client.batch_execute("INSERT INTO openmybot.omb_migrations VALUES(3,'fixture-newer',decode(repeat('11',32),'hex'),statement_timestamp())").await.unwrap();
    assert_eq!(
        migrate(&mut session.client, deadline()).await.unwrap_err(),
        StoreError::SchemaNewer
    );
    assert_eq!(
        session
            .client
            .query_one("SELECT count(*)::bigint FROM openmybot.omb_migrations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn failed_migration_rolls_back_ddl_and_version_record() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    session
        .client
        .batch_execute(
            "CREATE SCHEMA openmybot; CREATE TABLE openmybot.channel_bindings(sentinel text)",
        )
        .await
        .unwrap();
    assert_eq!(
        migrate(&mut session.client, deadline()).await.unwrap_err(),
        StoreError::MigrationFailed
    );
    let names: Vec<String> = session
        .client
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname='openmybot' ORDER BY tablename",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(names, ["channel_bindings", "omb_migrations"]);
    assert_eq!(
        session
            .client
            .query_one("SELECT count(*)::bigint FROM openmybot.omb_migrations", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    session
        .client
        .batch_execute("DROP TABLE openmybot.channel_bindings")
        .await
        .unwrap();
    assert_eq!(
        migrate(&mut session.client, deadline())
            .await
            .unwrap()
            .applied_count,
        2
    );
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; ten fresh clusters; serial"]
async fn concurrent_migrators_apply_once_under_transaction_lock() {
    let mut blocked = Fixture::new().await;
    let mut candidate = blocked.connect().await;
    let holder = blocked.connect().await;
    holder.client.batch_execute("BEGIN").await.unwrap();
    holder
        .client
        .query_one("SELECT pg_advisory_xact_lock(8752007243381909980)", &[])
        .await
        .unwrap();
    let limit = tokio::time::Instant::now() + std::time::Duration::from_millis(50);
    assert_eq!(
        migrate(&mut candidate.client, limit).await.unwrap_err(),
        StoreError::MigrationFailed
    );
    holder.client.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        candidate
            .client
            .query_one(
                "SELECT count(*)::bigint FROM pg_tables WHERE schemaname='openmybot'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        migrate(&mut candidate.client, deadline())
            .await
            .unwrap()
            .applied_count,
        2
    );
    candidate.close().await;
    holder.close().await;
    blocked.stop().await;

    for _ in 0..10 {
        let mut fixture = Fixture::new().await;
        let mut a = fixture.connect().await;
        let mut b = fixture.connect().await;
        let (x, y) = tokio::join!(
            migrate(&mut a.client, deadline()),
            migrate(&mut b.client, deadline())
        );
        assert_eq!(x.unwrap().applied_count + y.unwrap().applied_count, 2);
        assert_eq!(
            a.client
                .query_one("SELECT count(*)::bigint FROM openmybot.omb_migrations", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            2
        );
        a.close().await;
        b.close().await;
        fixture.stop().await;
    }
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn upgrade_from_version_one_applies_only_the_second_migration() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    let initial = include_bytes!("../migrations/omb_0001_initial.sql");
    session.client.batch_execute("CREATE SCHEMA openmybot; CREATE TABLE openmybot.omb_migrations(version integer PRIMARY KEY,name text NOT NULL,sha256 bytea NOT NULL CHECK(octet_length(sha256)=32),applied_at timestamptz NOT NULL)").await.unwrap();
    session
        .client
        .batch_execute(std::str::from_utf8(initial).unwrap())
        .await
        .unwrap();
    session.client.execute("INSERT INTO openmybot.omb_migrations VALUES(1,'omb_0001_initial.sql',$1,statement_timestamp())", &[&Sha256::digest(initial).to_vec()]).await.unwrap();
    let result = migrate(&mut session.client, deadline()).await.unwrap();
    assert_eq!(result.applied_count, 1);
    assert_eq!(result.current_version, 2);
    let versions: Vec<i32> = session
        .client
        .query(
            "SELECT version FROM openmybot.omb_migrations ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(versions, [1, 2]);
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn migration_preserves_all_non_openmybot_catalog_objects() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    session.client.batch_execute("CREATE SCHEMA engine_sentinel; CREATE TABLE engine_sentinel.keep(id integer PRIMARY KEY, payload text); INSERT INTO engine_sentinel.keep VALUES(1,'unchanged')").await.unwrap();
    let query = "SELECT c.oid::bigint,row_to_json(x)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL (SELECT c.relname,c.relkind,n.nspname,CASE WHEN c.relkind='i' THEN pg_get_indexdef(c.oid) ELSE NULL END AS index_definition) x ORDER BY c.oid";
    let before: std::collections::BTreeMap<i64, String> = session
        .client
        .query(query, &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    migrate(&mut session.client, deadline()).await.unwrap();
    let after: std::collections::BTreeMap<i64, String> = session
        .client
        .query(query, &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    for (oid, definition) in &before {
        assert_eq!(
            after.get(oid),
            Some(definition),
            "original catalog relation changed"
        );
    }
    for oid in after.keys().filter(|id| !before.contains_key(*id)) {
        let permitted:bool=session.client.query_one("SELECT n.nspname='openmybot' OR (n.nspname='pg_toast' AND (c.oid IN (SELECT b.reltoastrelid FROM pg_class b JOIN pg_namespace bn ON bn.oid=b.relnamespace WHERE bn.nspname='openmybot') OR c.oid IN (SELECT i.indexrelid FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid JOIN pg_class b ON b.reltoastrelid=t.oid JOIN pg_namespace bn ON bn.oid=b.relnamespace WHERE bn.nspname='openmybot'))) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=$1::bigint::oid",&[oid]).await.unwrap().get(0);
        assert!(permitted, "unrelated new catalog relation");
    }
    assert_eq!(
        session
            .client
            .query_one("SELECT payload FROM engine_sentinel.keep WHERE id=1", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "unchanged"
    );
    session.close().await;
    fixture.stop().await;
}
