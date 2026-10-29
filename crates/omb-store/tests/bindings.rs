#[path = "../src/testkit.rs"]
mod testkit;
use omb_store::{
    AcceptedEvent, AuthorityRow, Channel, GrantKind, HostBinding, IdentityKey, PairAttempt,
    PairOutcome, PairStart, RunDeadline, StoreError, activate_host, authority_row, migrate,
    pair_attempt, pair_start, reconfirm_binding, revoke_binding,
};
use testkit::{Fixture, Session, deadline, insert_receiver};
use tokio_postgres::Client;
use uuid::Uuid;

async fn setup() -> (Fixture, Session) {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    (fixture, session)
}
async fn host(client: &mut Client) -> Result<Uuid, StoreError> {
    activate_host(
        client,
        HostBinding {
            workspace_dir: "/workspaces/host",
            granted_generation: 3,
            run_deadline: RunDeadline::parse(900),
        },
        deadline(),
    )
    .await
}
async fn pending_sender(client: &mut Client) -> Uuid {
    pair_start(
        client,
        PairStart {
            channel: Channel::Telegram,
            workspace_dir: "/workspaces/project",
            thread_id: "thread-1",
            granted_generation: 4,
            run_deadline: None,
        },
        deadline(),
    )
    .await
    .unwrap()
    .binding_id
}
/// Pairs a sender through the real store path and returns the active binding.
async fn active_sender(client: &mut Client) -> Uuid {
    let started = pair_start(
        client,
        PairStart {
            channel: Channel::Telegram,
            workspace_dir: "/workspaces/project",
            thread_id: "thread-1",
            granted_generation: 4,
            run_deadline: None,
        },
        deadline(),
    )
    .await
    .unwrap();
    let sender = IdentityKey::parse("telegram:1").unwrap();
    let chat = IdentityKey::parse("telegram:1").unwrap();
    let tx = client.transaction().await.unwrap();
    let outcome = pair_attempt(
        &tx,
        PairAttempt {
            channel: Channel::Telegram,
            receiver_source_key: "1001",
            sender_key: &sender,
            chat_key: &chat,
            code_text: &started.code.display(),
            event: AcceptedEvent {
                event_key: "pair",
                source_key: "1001",
                fingerprint: [1; 32],
                occurred_at: None,
                event_type: None,
            },
        },
        deadline(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        outcome,
        PairOutcome::Succeeded {
            binding_id: started.binding_id
        }
    );
    started.binding_id
}
async fn suspend(client: &Client, id: Uuid) {
    assert_eq!(client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&id]).await.unwrap(), 1);
}
async fn pending_event(client: &Client, binding: Uuid, key: &str) -> Uuid {
    let id = Uuid::now_v7();
    client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,fingerprint,sender_key,chat_key,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) VALUES ($1,'event','telegram','1001',$2,statement_timestamp(),$3,'telegram:1','telegram:1',$4,'accepted_message','hello',$3,$2,'thread-1','pending')", &[&id, &key, &vec![2_u8; 32], &binding]).await.unwrap();
    id
}
async fn row(client: &Client, id: Uuid) -> String {
    client
        .query_one(
            "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn activate_host_writes_active_row_with_revision_1() {
    let (fixture, mut session) = setup().await;
    let id = host(&mut session.client).await.unwrap();
    let row = session.client.query_one("SELECT binding_kind,channel_kind,source_key,sender_key,workspace_dir,granted_generation,run_deadline_seconds,revision,status,activated_at IS NOT NULL,thread_id IS NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "host");
    assert_eq!(row.get::<_, String>(1), "host");
    assert_eq!(row.get::<_, String>(2), "crabcode");
    assert_eq!(row.get::<_, String>(3), "host:crabcode");
    assert_eq!(row.get::<_, String>(4), "/workspaces/host");
    assert_eq!(row.get::<_, i64>(5), 3);
    assert_eq!(row.get::<_, i32>(6), 900);
    assert_eq!(row.get::<_, i64>(7), 1);
    assert_eq!(row.get::<_, String>(8), "active");
    assert!(row.get::<_, bool>(9) && row.get::<_, bool>(10));
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn host_binding_is_unique_per_kind_and_channel() {
    let (fixture, mut session) = setup().await;
    let first = host(&mut session.client).await.unwrap();
    assert_eq!(
        host(&mut session.client).await.unwrap_err(),
        StoreError::ChannelAlreadyBound
    );
    suspend(&session.client, first).await;
    assert_eq!(
        host(&mut session.client).await.unwrap_err(),
        StoreError::ChannelAlreadyBound
    );
    let count: i64 = session
        .client
        .query_one("SELECT count(*) FROM openmybot.channel_bindings", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reconfirm_increments_revision_and_replaces_granted_generation() {
    let (fixture, mut session) = setup().await;
    let id = host(&mut session.client).await.unwrap();
    suspend(&session.client, id).await;
    assert_eq!(
        reconfirm_binding(&mut session.client, id, 9, deadline())
            .await
            .unwrap(),
        2
    );
    let row = session.client.query_one("SELECT status,status_reason IS NULL,revision,granted_generation,reconfirmed_at IS NOT NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, i64>(2), 2);
    assert_eq!(row.get::<_, i64>(3), 9);
    assert!(row.get::<_, bool>(4));
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn reconfirm_refuses_non_suspended_rows() {
    let (fixture, mut session) = setup().await;
    insert_receiver(&session.client, "telegram", "1001").await;
    let revoked = host(&mut session.client).await.unwrap();
    revoke_binding(&mut session.client, revoked, deadline())
        .await
        .unwrap();
    let active = host(&mut session.client).await.unwrap();
    let expired = pending_sender(&mut session.client).await;
    let pending = pending_sender(&mut session.client).await;
    for id in [active, pending, revoked, expired] {
        let before = row(&session.client, id).await;
        assert_eq!(
            reconfirm_binding(&mut session.client, id, 9, deadline())
                .await
                .unwrap_err(),
            StoreError::BindingStateInvalid
        );
        assert_eq!(row(&session.client, id).await, before);
    }
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_is_terminal_clears_secrets_and_cancels_pending_events() {
    let (fixture, mut session) = setup().await;
    let receiver = insert_receiver(&session.client, "telegram", "1001").await;
    let pending = pending_sender(&mut session.client).await;
    revoke_binding(&mut session.client, pending, deadline())
        .await
        .unwrap();
    let sender = active_sender(&mut session.client).await;
    let other = host(&mut session.client).await.unwrap();
    let mine = pending_event(&session.client, sender, "run-1").await;
    let theirs = pending_event(&session.client, other, "run-2").await;
    revoke_binding(&mut session.client, sender, deadline())
        .await
        .unwrap();
    revoke_binding(&mut session.client, receiver, deadline())
        .await
        .unwrap();
    for id in [pending, sender, receiver] {
        let row = session.client.query_one("SELECT status,status_reason,ended_at IS NOT NULL,pairing_code_hash IS NULL,coalesce(credential_envelope,'') FROM openmybot.channel_bindings WHERE binding_id=$1", &[&id]).await.unwrap();
        assert_eq!(row.get::<_, String>(0), "revoked");
        assert_eq!(row.get::<_, String>(1), "owner_revoked");
        assert!(row.get::<_, bool>(2) && row.get::<_, bool>(3));
        assert_eq!(row.get::<_, String>(4), "");
    }
    for (event, expected) in [(mine, "cancelled"), (theirs, "pending")] {
        let status: String = session
            .client
            .query_one(
                "SELECT dispatch_status FROM openmybot.channel_events WHERE record_id=$1",
                &[&event],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(status, expected);
    }
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn revoke_and_reconfirm_refuse_ended_rows() {
    let (fixture, mut session) = setup().await;
    insert_receiver(&session.client, "telegram", "1001").await;
    let revoked = host(&mut session.client).await.unwrap();
    revoke_binding(&mut session.client, revoked, deadline())
        .await
        .unwrap();
    let expired = pending_sender(&mut session.client).await;
    pending_sender(&mut session.client).await;
    for id in [revoked, expired] {
        let before = row(&session.client, id).await;
        assert_eq!(
            revoke_binding(&mut session.client, id, deadline())
                .await
                .unwrap_err(),
            StoreError::BindingStateInvalid
        );
        assert_eq!(
            reconfirm_binding(&mut session.client, id, 1, deadline())
                .await
                .unwrap_err(),
            StoreError::BindingStateInvalid
        );
        assert_eq!(row(&session.client, id).await, before);
    }
    let missing = Uuid::now_v7();
    assert_eq!(
        revoke_binding(&mut session.client, missing, deadline())
            .await
            .unwrap_err(),
        StoreError::BindingNotFound
    );
    assert_eq!(
        reconfirm_binding(&mut session.client, missing, 1, deadline())
            .await
            .unwrap_err(),
        StoreError::BindingNotFound
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn authority_row_returns_only_active_sender_or_host() {
    let (fixture, mut session) = setup().await;
    let receiver = insert_receiver(&session.client, "telegram", "1001").await;
    let expired = pending_sender(&mut session.client).await;
    let pending = pending_sender(&mut session.client).await;
    let host_id = host(&mut session.client).await.unwrap();
    assert_eq!(
        authority_row(&session.client, host_id).await.unwrap(),
        Some(AuthorityRow {
            kind: GrantKind::Host,
            revision: 1,
            granted_generation: 3,
            run_deadline_seconds: Some(900)
        })
    );
    for id in [pending, expired, receiver, Uuid::now_v7()] {
        assert_eq!(authority_row(&session.client, id).await.unwrap(), None);
    }
    revoke_binding(&mut session.client, pending, deadline())
        .await
        .unwrap();
    let sender = active_sender(&mut session.client).await;
    assert_eq!(
        authority_row(&session.client, sender).await.unwrap(),
        Some(AuthorityRow {
            kind: GrantKind::Sender,
            revision: 1,
            granted_generation: 4,
            run_deadline_seconds: None
        })
    );
    suspend(&session.client, sender).await;
    assert_eq!(authority_row(&session.client, sender).await.unwrap(), None);
    revoke_binding(&mut session.client, host_id, deadline())
        .await
        .unwrap();
    for id in [sender, host_id, pending] {
        assert_eq!(authority_row(&session.client, id).await.unwrap(), None);
    }
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn authority_row_conversion_failure_returns_none() {
    let (fixture, mut session) = setup().await;
    let id = host(&mut session.client).await.unwrap();
    for (mutation, restore) in [
        ("revision=-1", "revision=1"),
        ("granted_generation=-5", "granted_generation=3"),
    ] {
        session
            .client
            .execute(
                &format!("UPDATE openmybot.channel_bindings SET {mutation} WHERE binding_id=$1"),
                &[&id],
            )
            .await
            .unwrap();
        assert_eq!(authority_row(&session.client, id).await.unwrap(), None);
        session
            .client
            .execute(
                &format!("UPDATE openmybot.channel_bindings SET {restore} WHERE binding_id=$1"),
                &[&id],
            )
            .await
            .unwrap();
        assert!(authority_row(&session.client, id).await.unwrap().is_some());
    }
    session.close().await;
    fixture.stop().await;
}
