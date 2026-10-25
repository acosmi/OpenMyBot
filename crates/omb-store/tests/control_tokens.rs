#[path = "../src/testkit.rs"]
mod testkit;
use omb_store::{ControlTokenStart, StoreError, migrate, start_control_token, stop_control_token};
use testkit::{Fixture, Session, deadline};
use uuid::Uuid;
async fn setup() -> (Fixture, Session) {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    (fixture, session)
}
fn input(id: Uuid, hash: u8) -> ControlTokenStart<'static> {
    ControlTokenStart {
        token_id: id,
        token_sha256: [hash; 32],
        daemon_pid: 1234,
        engine_pin: "0123456789abcdef0123456789abcdef01234567",
        omb_version: "0.0.0",
    }
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn token_start_persists_digest_metadata_and_one_live_row() {
    let (fixture, mut session) = setup().await;
    let id = Uuid::now_v7();
    let record = start_control_token(&mut session.client, input(id, 1), deadline())
        .await
        .unwrap();
    assert_eq!(record.token_id, id);
    assert!(!record.restore_detected);
    let row=session.client.query_one("SELECT token_id,token_sha256,daemon_pid,engine_pin,omb_version,pg_system_identifier=(pg_control_system()).system_identifier::text,pg_timeline_id=(pg_control_checkpoint()).timeline_id,restore_detected,created_at=last_heartbeat_at,revoked_at IS NULL,revoke_reason IS NULL FROM openmybot.control_tokens",&[]).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), id);
    assert_eq!(row.get::<_, Vec<u8>>(1), vec![1; 32]);
    assert_eq!(row.get::<_, i32>(2), 1234);
    assert_eq!(row.get::<_, String>(3), input(id, 1).engine_pin);
    assert_eq!(row.get::<_, String>(4), "0.0.0");
    for index in [5, 6, 8, 9, 10] {
        assert!(row.get::<_, bool>(index));
    }
    assert!(!row.get::<_, bool>(7));
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn restart_revokes_only_previous_live_token_atomically() {
    let (fixture, mut session) = setup().await;
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let c = Uuid::now_v7();
    start_control_token(&mut session.client, input(a, 1), deadline())
        .await
        .unwrap();
    stop_control_token(&mut session.client, a, deadline())
        .await
        .unwrap();
    start_control_token(&mut session.client, input(b, 2), deadline())
        .await
        .unwrap();
    start_control_token(&mut session.client, input(c, 3), deadline())
        .await
        .unwrap();
    let rows=session.client.query("SELECT token_id,revoke_reason,revoked_at IS NOT NULL FROM openmybot.control_tokens ORDER BY created_at,token_id",&[]).await.unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let id: Uuid = row.get(0);
        let reason: Option<String> = row.get(1);
        if id == a {
            assert_eq!(reason.as_deref(), Some("daemon_stop"));
        } else if id == b {
            assert_eq!(reason.as_deref(), Some("daemon_restart"));
            assert!(row.get::<_, bool>(2));
        } else {
            assert_eq!(id, c);
            assert!(reason.is_none());
            assert!(!row.get::<_, bool>(2));
        }
    }
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn normal_stop_revokes_only_current_token_with_daemon_stop() {
    let (fixture, mut session) = setup().await;
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    start_control_token(&mut session.client, input(a, 1), deadline())
        .await
        .unwrap();
    start_control_token(&mut session.client, input(b, 2), deadline())
        .await
        .unwrap();
    stop_control_token(&mut session.client, b, deadline())
        .await
        .unwrap();
    stop_control_token(&mut session.client, b, deadline())
        .await
        .unwrap();
    assert_eq!(
        session
            .client
            .query_one(
                "SELECT revoke_reason FROM openmybot.control_tokens WHERE token_id=$1",
                &[&a]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "daemon_restart"
    );
    assert_eq!(
        session
            .client
            .query_one(
                "SELECT revoke_reason FROM openmybot.control_tokens WHERE token_id=$1",
                &[&b]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        "daemon_stop"
    );
    assert_eq!(
        session
            .client
            .query_one(
                "SELECT count(*)::bigint FROM openmybot.control_tokens WHERE revoked_at IS NULL",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn failed_token_insert_rolls_back_prior_revocation() {
    let (mut fixture, mut session) = setup().await;
    let id = Uuid::now_v7();
    start_control_token(&mut session.client, input(id, 1), deadline())
        .await
        .unwrap();
    let before = session
        .client
        .query_one(
            "SELECT row_to_json(t)::text FROM openmybot.control_tokens t",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    assert_eq!(
        start_control_token(&mut session.client, input(id, 2), deadline())
            .await
            .unwrap_err(),
        StoreError::ControlTokenFailed
    );
    assert_eq!(
        session
            .client
            .query_one(
                "SELECT row_to_json(t)::text FROM openmybot.control_tokens t",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        before
    );
    let holder = fixture.connect().await;
    holder
        .client
        .batch_execute("BEGIN; LOCK TABLE openmybot.control_tokens IN EXCLUSIVE MODE")
        .await
        .unwrap();
    assert_eq!(
        start_control_token(
            &mut session.client,
            input(Uuid::now_v7(), 3),
            tokio::time::Instant::now() + std::time::Duration::from_millis(50)
        )
        .await
        .unwrap_err(),
        StoreError::ControlTokenFailed
    );
    holder.client.batch_execute("ROLLBACK").await.unwrap();
    assert_eq!(
        session
            .client
            .query_one(
                "SELECT row_to_json(t)::text FROM openmybot.control_tokens t",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        before
    );
    holder.close().await;
    session.close().await;
    fixture.stop().await;
}
#[tokio::test]
#[ignore = "own PG17.11; ten fresh clusters; serial"]
async fn concurrent_token_starts_never_leave_two_live_rows() {
    for _ in 0..10 {
        let (mut fixture, mut a) = setup().await;
        let mut b = fixture.connect().await;
        let (x, y) = tokio::join!(
            start_control_token(&mut a.client, input(Uuid::now_v7(), 1), deadline()),
            start_control_token(&mut b.client, input(Uuid::now_v7(), 2), deadline())
        );
        assert!(x.is_ok());
        assert!(y.is_ok());
        assert_eq!(a.client.query_one("SELECT count(*)::bigint FROM openmybot.control_tokens WHERE revoked_at IS NULL",&[]).await.unwrap().get::<_,i64>(0),1);
        assert_eq!(a.client.query_one("SELECT count(*)::bigint FROM openmybot.control_tokens WHERE revoke_reason='daemon_restart'",&[]).await.unwrap().get::<_,i64>(0),1);
        a.close().await;
        b.close().await;
        fixture.stop().await;
    }
}
#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn token_metadata_comparison_records_restore_fact_without_binding_mutation() {
    let (fixture, mut session) = setup().await;
    session.client.batch_execute("INSERT INTO openmybot.channel_bindings(binding_id,binding_kind,channel_kind,source_key,sender_key,workspace_dir,granted_generation,status,created_at) VALUES('00000000-0000-0000-0000-000000000002','host','host','crabcode','host:crabcode','/fixture',1,'active',statement_timestamp()); INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,disposition) VALUES('00000000-0000-0000-0000-000000000003','event','host','crabcode','e',statement_timestamp(),'rejected_malformed'); INSERT INTO openmybot.host_driver_sessions(record_id,record_kind,run_id,binding_id,host_kind,workspace_dir,started_at) VALUES('00000000-0000-0000-0000-000000000004','session','run','00000000-0000-0000-0000-000000000002','crabcode','/fixture',statement_timestamp())").await.unwrap();
    let snapshot = "SELECT (SELECT json_agg(b)::text FROM openmybot.channel_bindings b),(SELECT json_agg(e)::text FROM openmybot.channel_events e),(SELECT json_agg(s)::text FROM openmybot.host_driver_sessions s)";
    let before = session.client.query_one(snapshot, &[]).await.unwrap();
    let before: Vec<String> = (0..3).map(|i| before.get(i)).collect();
    for (index, mutation, expected, stop_latest) in [
        (0, "", false, false),
        (1, "", false, false),
        (2, "pg_system_identifier='different'", true, false),
        (3, "pg_timeline_id=pg_timeline_id+1", true, false),
        (
            4,
            "pg_system_identifier='different',pg_timeline_id=pg_timeline_id+1",
            true,
            false,
        ),
        (5, "pg_system_identifier='different'", true, true),
    ] {
        if !mutation.is_empty() {
            session.client.batch_execute(&format!("UPDATE openmybot.control_tokens SET {mutation} WHERE token_id=(SELECT token_id FROM openmybot.control_tokens ORDER BY created_at DESC,token_id DESC LIMIT 1)")).await.unwrap();
        }
        if stop_latest {
            let id:Uuid=session.client.query_one("SELECT token_id FROM openmybot.control_tokens ORDER BY created_at DESC,token_id DESC LIMIT 1",&[]).await.unwrap().get(0);
            stop_control_token(&mut session.client, id, deadline())
                .await
                .unwrap();
        }
        let record = start_control_token(
            &mut session.client,
            input(Uuid::now_v7(), (index + 1) as u8),
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(record.restore_detected, expected);
        let after = session.client.query_one(snapshot, &[]).await.unwrap();
        let after: Vec<String> = (0..3).map(|i| after.get(i)).collect();
        assert_eq!(before, after);
    }
    session.close().await;
    fixture.stop().await;
}
