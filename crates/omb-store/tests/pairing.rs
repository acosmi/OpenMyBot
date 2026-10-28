#[path = "../src/testkit.rs"]
mod testkit;
use omb_store::{
    AcceptedEvent, Channel, IdentityKey, PairAttempt, PairOutcome, PairStart, PairStarted,
    RunDeadline, StoreError, migrate, pair_attempt, pair_start, revoke_binding,
};
use sha2::{Digest, Sha256};
use testkit::{
    Fixture, Session, deadline, insert_receiver, set_accepted_at, set_pairing_expires_at,
};
use tokio_postgres::Client;
use uuid::Uuid;

async fn setup() -> (Fixture, Session, Uuid) {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    let receiver = insert_receiver(&session.client, "telegram", "1001").await;
    (fixture, session, receiver)
}
async fn start(client: &mut Client, channel: Channel) -> Result<PairStarted, StoreError> {
    pair_start(
        client,
        PairStart {
            channel,
            workspace_dir: "/workspaces/project",
            thread_id: "thread-1",
            granted_generation: 7,
            run_deadline: RunDeadline::parse(120),
        },
        deadline(),
    )
    .await
}
async fn attempt(
    client: &mut Client,
    channel: Channel,
    receiver: Uuid,
    sender: &str,
    code: &str,
    event_key: &str,
) -> PairOutcome {
    let source_key = if channel == Channel::Telegram {
        "1001"
    } else {
        "cli_app"
    };
    let sender = IdentityKey::parse(sender).unwrap();
    let chat = IdentityKey::parse(&format!("{}:chat", sender.as_str())).unwrap();
    pair_attempt(
        client,
        PairAttempt {
            channel,
            receiver_binding_id: receiver,
            sender_key: &sender,
            chat_key: &chat,
            code_text: code,
            event: AcceptedEvent {
                event_key,
                source_key,
                fingerprint: [7; 32],
            },
        },
        deadline(),
    )
    .await
    .unwrap()
}
async fn scalar<T: for<'a> tokio_postgres::types::FromSql<'a>>(client: &Client, sql: &str) -> T {
    client.query_one(sql, &[]).await.unwrap().get(0)
}
async fn binding(client: &Client, id: Uuid) -> String {
    client
        .query_one(
            "SELECT row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0)
}
async fn snapshot(client: &Client) -> Vec<Option<String>> {
    let row = client.query_one("SELECT (SELECT json_agg(b ORDER BY binding_id)::text FROM openmybot.channel_bindings b),(SELECT json_agg(e ORDER BY record_id)::text FROM openmybot.channel_events e),(SELECT json_agg(d ORDER BY delivery_id)::text FROM openmybot.deliveries d)", &[]).await.unwrap();
    (0..3).map(|i| row.get(i)).collect()
}
async fn dispositions(client: &Client) -> Vec<String> {
    client
        .query(
            "SELECT disposition FROM openmybot.channel_events ORDER BY accepted_at,record_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}
async fn status(client: &Client, id: Uuid) -> (String, Option<String>) {
    let row = client
        .query_one(
            "SELECT status,status_reason FROM openmybot.channel_bindings WHERE binding_id=$1",
            &[&id],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1))
}
async fn fail_five(client: &mut Client, receiver: Uuid, sender: &str, prefix: &str) {
    for index in 1..=5 {
        assert_eq!(
            attempt(
                client,
                Channel::Telegram,
                receiver,
                sender,
                "WRONG000",
                &format!("{prefix}{index}")
            )
            .await,
            PairOutcome::Failed
        );
    }
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_start_writes_pending_row_with_hash_expiry_and_grant_fields() {
    let (fixture, mut session, _) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    let row = session.client.query_one("SELECT binding_kind,channel_kind,source_key,workspace_dir,thread_id,granted_generation,run_deadline_seconds,status,sender_key IS NULL,revision,pairing_code_hash,extract(epoch FROM pairing_expires_at-created_at)::float8,pairing_expires_at,row_to_json(b)::text FROM openmybot.channel_bindings b WHERE binding_id=$1", &[&started.binding_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "sender");
    assert_eq!(row.get::<_, String>(1), "telegram");
    assert_eq!(row.get::<_, String>(2), "1001");
    assert_eq!(row.get::<_, String>(3), "/workspaces/project");
    assert_eq!(row.get::<_, String>(4), "thread-1");
    assert_eq!(row.get::<_, i64>(5), 7);
    assert_eq!(row.get::<_, i32>(6), 120);
    assert_eq!(row.get::<_, String>(7), "pending");
    assert!(row.get::<_, bool>(8));
    assert_eq!(row.get::<_, i64>(9), 0);
    let display = started.code.display();
    let plain = display.replace('-', "");
    let mut digest = Sha256::new();
    digest.update(started.binding_id.as_bytes());
    digest.update(plain.as_bytes());
    assert_eq!(row.get::<_, Vec<u8>>(10), digest.finalize().to_vec());
    assert_eq!(row.get::<_, f64>(11), 600.0);
    assert_eq!(row.get::<_, time::OffsetDateTime>(12), started.expires_at);
    let text: String = row.get(13);
    assert!(!text.contains(&plain) && !text.contains(&display));
    assert!(!format!("{started:?}").contains(&plain));
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_start_requires_active_receiver() {
    let mut fixture = Fixture::new().await;
    let mut session = fixture.connect().await;
    migrate(&mut session.client, deadline()).await.unwrap();
    assert_eq!(
        start(&mut session.client, Channel::Telegram)
            .await
            .unwrap_err(),
        StoreError::ReceiverNotActive
    );
    let receiver = insert_receiver(&session.client, "feishu", "cli_app").await;
    assert_eq!(
        start(&mut session.client, Channel::Telegram)
            .await
            .unwrap_err(),
        StoreError::ReceiverNotActive
    );
    session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&receiver]).await.unwrap();
    assert_eq!(
        start(&mut session.client, Channel::Feishu)
            .await
            .unwrap_err(),
        StoreError::ReceiverNotActive
    );
    assert_eq!(
        scalar::<i64>(
            &session.client,
            "SELECT count(*) FROM openmybot.channel_bindings WHERE binding_kind='sender'"
        )
        .await,
        0
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_start_refuses_active_or_suspended_sender() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    let code = started.code.display();
    assert!(matches!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &code,
            "1"
        )
        .await,
        PairOutcome::Succeeded { .. }
    ));
    let before = snapshot(&session.client).await;
    assert_eq!(
        start(&mut session.client, Channel::Telegram)
            .await
            .unwrap_err(),
        StoreError::ChannelAlreadyBound
    );
    assert_eq!(snapshot(&session.client).await, before);
    session.client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='restore_detected',suspended_at=statement_timestamp() WHERE binding_id=$1", &[&started.binding_id]).await.unwrap();
    let before = snapshot(&session.client).await;
    assert_eq!(
        start(&mut session.client, Channel::Telegram)
            .await
            .unwrap_err(),
        StoreError::ChannelAlreadyBound
    );
    assert_eq!(snapshot(&session.client).await, before);
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_start_supersedes_existing_pending_row() {
    let (fixture, mut session, _) = setup().await;
    let first = start(&mut session.client, Channel::Telegram).await.unwrap();
    let second = start(&mut session.client, Channel::Telegram).await.unwrap();
    let row = session.client.query_one("SELECT status,status_reason,pairing_code_hash IS NULL,ended_at IS NOT NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&first.binding_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "expired");
    assert_eq!(row.get::<_, String>(1), "superseded");
    assert!(row.get::<_, bool>(2) && row.get::<_, bool>(3));
    assert_eq!(
        status(&session.client, second.binding_id).await,
        ("pending".into(), None)
    );
    assert_eq!(scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.channel_bindings WHERE binding_kind='sender' AND status IN ('pending','active','suspended')").await, 1);
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_attempt_success_activates_with_revision_1_and_reply_delivery() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    let typed = started.code.display().to_lowercase().replace('-', " - ");
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:42",
            &typed,
            "100"
        )
        .await,
        PairOutcome::Succeeded {
            binding_id: started.binding_id
        }
    );
    let row = session.client.query_one("SELECT status,revision,sender_key,chat_key,activated_at IS NOT NULL,pairing_code_hash IS NULL,status_reason IS NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&started.binding_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, String>(2), "telegram:42");
    assert_eq!(row.get::<_, String>(3), "telegram:42:chat");
    assert!(row.get::<_, bool>(4) && row.get::<_, bool>(5) && row.get::<_, bool>(6));
    let event = session.client.query_one("SELECT disposition,binding_id,command,fingerprint,text IS NULL,sender_key,source_key,event_key FROM openmybot.channel_events", &[]).await.unwrap();
    assert_eq!(event.get::<_, String>(0), "pairing_succeeded");
    assert_eq!(event.get::<_, Uuid>(1), started.binding_id);
    assert_eq!(event.get::<_, String>(2), "pair");
    assert_eq!(event.get::<_, Vec<u8>>(3), vec![7; 32]);
    assert!(event.get::<_, bool>(4));
    assert_eq!(event.get::<_, String>(5), "telegram:42");
    assert_eq!(event.get::<_, String>(6), "1001");
    assert_eq!(event.get::<_, String>(7), "100");
    let delivery = session.client.query_one("SELECT binding_id,channel_kind,chat_key,kind,idempotency_key,body,status FROM openmybot.deliveries", &[]).await.unwrap();
    assert_eq!(delivery.get::<_, Uuid>(0), started.binding_id);
    assert_eq!(delivery.get::<_, String>(1), "telegram");
    assert_eq!(delivery.get::<_, String>(2), "telegram:42:chat");
    assert_eq!(delivery.get::<_, String>(3), "pairing_reply");
    assert_eq!(
        delivery.get::<_, String>(4),
        format!("pair:{}", started.binding_id)
    );
    assert_eq!(
        delivery.get::<_, String>(5),
        "绑定成功，工作区 project；发送 /help 查看命令"
    );
    assert_eq!(delivery.get::<_, String>(6), "pending");
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pair_code_is_single_use() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    let code = started.code.display();
    assert!(matches!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &code,
            "1"
        )
        .await,
        PairOutcome::Succeeded { .. }
    ));
    let before = binding(&session.client, started.binding_id).await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:2",
            &code,
            "2"
        )
        .await,
        PairOutcome::Failed
    );
    assert_eq!(binding(&session.client, started.binding_id).await, before);
    assert_eq!(
        dispositions(&session.client).await,
        ["pairing_succeeded", "pairing_failed"]
    );
    assert_eq!(
        scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.deliveries").await,
        1
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn wrong_code_records_pairing_failed_without_reply() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    let before = binding(&session.client, started.binding_id).await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            "WRONG000",
            "1"
        )
        .await,
        PairOutcome::Failed
    );
    assert_eq!(binding(&session.client, started.binding_id).await, before);
    let event = session
        .client
        .query_one(
            "SELECT disposition,binding_id,text IS NULL FROM openmybot.channel_events",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(event.get::<_, String>(0), "pairing_failed");
    assert_eq!(event.get::<_, Option<Uuid>>(1), Some(started.binding_id));
    assert!(event.get::<_, bool>(2));
    assert_eq!(
        scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn no_pending_row_records_pairing_failed() {
    let (fixture, mut session, receiver) = setup().await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            "ABCD2345",
            "1"
        )
        .await,
        PairOutcome::Failed
    );
    let event = session
        .client
        .query_one(
            "SELECT disposition,binding_id FROM openmybot.channel_events",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(event.get::<_, String>(0), "pairing_failed");
    assert_eq!(event.get::<_, Option<Uuid>>(1), None);
    assert_eq!(
        scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn expired_pending_row_fails_and_becomes_expired_in_same_transaction() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    set_pairing_expires_at(&session.client, started.binding_id, -1.0).await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &started.code.display(),
            "1"
        )
        .await,
        PairOutcome::Failed
    );
    let row = session.client.query_one("SELECT status,status_reason,pairing_code_hash IS NULL,ended_at IS NOT NULL,sender_key IS NULL FROM openmybot.channel_bindings WHERE binding_id=$1", &[&started.binding_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "expired");
    assert_eq!(row.get::<_, String>(1), "pairing_expired");
    assert!(row.get::<_, bool>(2) && row.get::<_, bool>(3) && row.get::<_, bool>(4));
    assert_eq!(dispositions(&session.client).await, ["pairing_failed"]);
    assert_eq!(
        scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn five_failures_lock_for_60_minutes_after_the_fifth_without_comparing_code() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    fail_five(&mut session.client, receiver, "telegram:1", "f").await;
    // The newest failure is 59 minutes old: still inside the lock.
    for (index, key) in ["f1", "f2", "f3", "f4", "f5"].into_iter().enumerate() {
        set_accepted_at(&session.client, key, -3580.0 + 10.0 * index as f64).await;
    }
    for (index, key) in ["2", "3"].into_iter().enumerate() {
        assert_eq!(
            attempt(
                &mut session.client,
                Channel::Telegram,
                receiver,
                "telegram:1",
                &started.code.display(),
                key
            )
            .await,
            PairOutcome::Locked,
            "attempt {index}"
        );
    }
    assert_eq!(
        status(&session.client, started.binding_id).await,
        ("pending".into(), None)
    );
    let locked = session.client.query("SELECT binding_id IS NULL,sender_key FROM openmybot.channel_events WHERE disposition='pairing_locked'", &[]).await.unwrap();
    assert_eq!(locked.len(), 2);
    assert!(locked.iter().all(|r| r.get::<_, bool>(0)));
    assert_eq!(
        scalar::<i64>(&session.client, "SELECT count(*) FROM openmybot.deliveries").await,
        0
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn lock_lifts_after_60_minutes_even_if_five_failures_remain_in_rolling_window() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    fail_five(&mut session.client, receiver, "telegram:1", "f").await;
    for (key, offset) in [
        ("f1", -6900.0),
        ("f2", -6000.0),
        ("f3", -5000.0),
        ("f4", -4000.0),
        ("f5", -3660.0),
    ] {
        set_accepted_at(&session.client, key, offset).await;
    }
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &started.code.display(),
            "ok"
        )
        .await,
        PairOutcome::Succeeded {
            binding_id: started.binding_id
        }
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn spread_failures_and_locked_rows_do_not_trigger_lock() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    fail_five(&mut session.client, receiver, "telegram:1", "f").await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &started.code.display(),
            "locked"
        )
        .await,
        PairOutcome::Locked
    );
    // The five failures now span more than 60 minutes. The newer locked row must not
    // replace the oldest failure in the counted five.
    set_accepted_at(&session.client, "f1", -3700.0).await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &started.code.display(),
            "ok"
        )
        .await,
        PairOutcome::Succeeded {
            binding_id: started.binding_id
        }
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn pending_row_is_selected_by_arriving_channel() {
    let (fixture, mut session, telegram) = setup().await;
    let feishu = insert_receiver(&session.client, "feishu", "cli_app").await;
    let on_telegram = start(&mut session.client, Channel::Telegram).await.unwrap();
    let on_feishu = start(&mut session.client, Channel::Feishu).await.unwrap();
    let feishu_code = on_feishu.code.display();
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            telegram,
            "telegram:1",
            &feishu_code,
            "1"
        )
        .await,
        PairOutcome::Failed
    );
    assert_eq!(
        status(&session.client, on_feishu.binding_id).await,
        ("pending".into(), None)
    );
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Feishu,
            feishu,
            "feishu:ou_1",
            &feishu_code,
            "1"
        )
        .await,
        PairOutcome::Succeeded {
            binding_id: on_feishu.binding_id
        }
    );
    assert_eq!(
        status(&session.client, on_telegram.binding_id).await,
        ("pending".into(), None)
    );
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn duplicate_event_key_changes_nothing() {
    let (fixture, mut session, receiver) = setup().await;
    let started = start(&mut session.client, Channel::Telegram).await.unwrap();
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            "WRONG000",
            "same"
        )
        .await,
        PairOutcome::Failed
    );
    let before = snapshot(&session.client).await;
    assert_eq!(
        attempt(
            &mut session.client,
            Channel::Telegram,
            receiver,
            "telegram:1",
            &started.code.display(),
            "same"
        )
        .await,
        PairOutcome::Duplicate
    );
    assert_eq!(snapshot(&session.client).await, before);
    session.close().await;
    fixture.stop().await;
}

#[tokio::test]
#[ignore = "own PG17.11; explicit binary directory; serial"]
async fn concurrent_pair_attempts_with_same_code_succeed_once() {
    let (mut fixture, mut session, receiver) = setup().await;
    let mut a = fixture.connect().await;
    let mut b = fixture.connect().await;
    let mut c = fixture.connect().await;
    let mut d = fixture.connect().await;
    let mut previous = None;
    for round in 0..10 {
        if let Some(id) = previous {
            revoke_binding(&mut session.client, id, deadline())
                .await
                .unwrap();
        }
        let started = start(&mut session.client, Channel::Telegram).await.unwrap();
        let code = started.code.display();
        let keys: Vec<String> = (0..4).map(|i| format!("r{round}-{i}")).collect();
        let senders: Vec<String> = (0..4).map(|i| format!("telegram:{round}{i}")).collect();
        let outcomes = tokio::join!(
            attempt(
                &mut a.client,
                Channel::Telegram,
                receiver,
                &senders[0],
                &code,
                &keys[0]
            ),
            attempt(
                &mut b.client,
                Channel::Telegram,
                receiver,
                &senders[1],
                &code,
                &keys[1]
            ),
            attempt(
                &mut c.client,
                Channel::Telegram,
                receiver,
                &senders[2],
                &code,
                &keys[2]
            ),
            attempt(
                &mut d.client,
                Channel::Telegram,
                receiver,
                &senders[3],
                &code,
                &keys[3]
            ),
        );
        let outcomes = [outcomes.0, outcomes.1, outcomes.2, outcomes.3];
        let won = outcomes
            .iter()
            .filter(|o| {
                **o == PairOutcome::Succeeded {
                    binding_id: started.binding_id,
                }
            })
            .count();
        let lost = outcomes
            .iter()
            .filter(|o| **o == PairOutcome::Failed)
            .count();
        assert_eq!((won, lost), (1, 3), "round {round}");
        let replies: i64 = session.client.query_one("SELECT count(*) FROM openmybot.deliveries WHERE kind='pairing_reply' AND binding_id=$1", &[&started.binding_id]).await.unwrap().get(0);
        assert_eq!(replies, 1, "round {round}");
        previous = Some(started.binding_id);
    }
    for owned in [a, b, c, d] {
        owned.close().await;
    }
    session.close().await;
    fixture.stop().await;
}
