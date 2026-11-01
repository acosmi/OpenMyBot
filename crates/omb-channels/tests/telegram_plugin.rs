//! The Telegram plugin binary against the in-process fake Bot API, driven through the SDK's test
//! host.
use omb_channel_sdk::protocol::{
    EventKind, FailureClass, FromPlugin, SendErrorCode, SkipCounter, SuspendReason, ToPlugin,
    VerifyFailure,
};
use omb_channel_sdk::testkit::Host;
use omb_channels::testkit::FakeTelegram;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::time::Instant;

const PLUGIN: &str = env!("CARGO_BIN_EXE_openmybot-channel-telegram");
const WAIT: Duration = Duration::from_secs(10);
const TOKEN: &str = "1001:plugin-test-token";

async fn spawn(fake: &FakeTelegram) -> Host {
    let base = fake.endpoint().api_base;
    let mut host = Host::spawn(Path::new(PLUGIN), &["--api-base", base.as_str()], &[])
        .await
        .unwrap();
    host.hello("telegram").await.unwrap();
    host
}
async fn next(host: &mut Host) -> FromPlugin {
    host.recv(WAIT).await.unwrap().expect("a frame")
}
async fn verify(host: &mut Host, credential: &str, source_key: Option<&str>) -> FromPlugin {
    host.send(&ToPlugin::Verify {
        credential: credential.to_owned(),
        source_key: source_key.map(str::to_owned),
    })
    .await
    .unwrap();
    next(host).await
}
async fn start(host: &mut Host, cursor: Option<&str>) {
    host.send(&ToPlugin::Start {
        source_key: "1001".to_owned(),
        credential: TOKEN.to_owned(),
        last_event_key: cursor.map(str::to_owned),
        last_accepted_at: cursor.map(|_| OffsetDateTime::now_utc().format(&Rfc3339).unwrap()),
    })
    .await
    .unwrap();
}
async fn accept(host: &mut Host, key: &str) {
    host.send(&ToPlugin::Accepted {
        event_key: key.to_owned(),
    })
    .await
    .unwrap();
}
fn update(id: u64, text: &str) -> Value {
    json!({"update_id": id, "message": {
        "message_id": id * 10,
        "date": OffsetDateTime::now_utc().unix_timestamp(),
        "from": {"id": 42},
        "chat": {"id": 42, "type": "private"},
        "text": text,
    }})
}
/// The `offset` of every `getUpdates` call so far.
fn offsets(fake: &FakeTelegram) -> Vec<Option<String>> {
    fake.calls("getUpdates")
        .iter()
        .map(|call| call.param("offset").map(str::to_owned))
        .collect()
}
async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "waited for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn telegram_verify_returns_bot_id_and_rejects_mismatch() {
    let fake = FakeTelegram::start().await;
    let mut host = spawn(&fake).await;
    assert_eq!(
        verify(&mut host, TOKEN, None).await,
        FromPlugin::Verified {
            source_key: "1001".into()
        }
    );
    assert_eq!(
        verify(&mut host, TOKEN, Some("1001")).await,
        FromPlugin::Verified {
            source_key: "1001".into()
        }
    );
    let failed = |code| FromPlugin::VerifyFailed { code };
    assert_eq!(
        verify(&mut host, TOKEN, Some("1002")).await,
        failed(VerifyFailure::CredentialRejected)
    );
    for malformed in ["no-colon", ":secret", "10x1:secret"] {
        assert_eq!(
            verify(&mut host, malformed, None).await,
            failed(VerifyFailure::Malformed),
            "{malformed}"
        );
    }
    fake.script(
        "getWebhookInfo",
        200,
        br#"{"ok":true,"result":{"url":"https://hook.example.test/"}}"#.to_vec(),
    );
    assert_eq!(
        verify(&mut host, TOKEN, None).await,
        failed(VerifyFailure::WebhookConflict)
    );
    fake.script("getMe", 401, b"{}".to_vec());
    assert_eq!(
        verify(&mut host, TOKEN, None).await,
        failed(VerifyFailure::CredentialRejected)
    );
    fake.script("getMe", 503, b"{}".to_vec());
    assert_eq!(
        verify(&mut host, TOKEN, None).await,
        failed(VerifyFailure::Unreachable)
    );
    // The token travels only in the request path, never in a frame back.
    assert!(
        fake.calls("getMe")
            .iter()
            .all(|call| call.path == format!("/bot{TOKEN}/getMe"))
    );
    host.kill().await;
}

#[tokio::test]
async fn telegram_start_emits_event_and_advances_offset_only_after_accepted() {
    let fake = FakeTelegram::start().await;
    let mut host = spawn(&fake).await;
    fake.push_update(update(5, "hello"));
    start(&mut host, Some("4")).await;
    let FromPlugin::Event(event) = next(&mut host).await else {
        panic!("not an event");
    };
    assert_eq!(event.event_key, "5");
    assert_eq!(event.event_type, "telegram.message");
    assert_eq!(
        (
            event.kind,
            event.text.as_str(),
            event.sender_key.as_deref(),
            event.chat_key.as_deref(),
            event.private
        ),
        (
            EventKind::Text,
            "hello",
            Some("telegram:42"),
            Some("telegram:42"),
            true
        )
    );
    assert_eq!(
        event.data.keys().collect::<Vec<_>>(),
        ["chatId", "fromId", "messageId", "messageKind", "text"]
    );
    assert!(event.occurred_at.unwrap().ends_with('Z'));
    // Waiting for the receipt, the plugin polls no further.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(offsets(&fake), [Some("5".to_owned())]);
    accept(&mut host, "5").await;
    until("the offset past 5", || {
        offsets(&fake).contains(&Some("6".to_owned()))
    })
    .await;
    // An update without a message is skipped and passed without a receipt.
    fake.push_update(json!({"update_id": 6, "edited_message": {"text": "x"}}));
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Skipped {
            counter: SkipCounter::UnsupportedUpdate
        }
    );
    until("the offset past 6", || {
        offsets(&fake).contains(&Some("7".to_owned()))
    })
    .await;
    host.kill().await;
}

#[tokio::test]
async fn telegram_ack_timeout_refetches_same_offset() {
    let fake = FakeTelegram::start().await;
    let mut host = spawn(&fake).await;
    fake.push_update(update(2, "first"));
    start(&mut host, Some("1")).await;
    let FromPlugin::Event(first) = next(&mut host).await else {
        panic!("not an event");
    };
    assert_eq!(first.event_key, "2");
    // No receipt within the 3 s ack window: the same update comes again from the same offset.
    let FromPlugin::Event(again) = next(&mut host).await else {
        panic!("not an event");
    };
    assert_eq!(again, first);
    assert!(
        offsets(&fake)
            .iter()
            .all(|offset| offset.as_deref() == Some("2"))
    );
    accept(&mut host, "2").await;
    until("the offset past 2", || {
        offsets(&fake).contains(&Some("3".to_owned()))
    })
    .await;
    host.kill().await;
}

#[tokio::test]
async fn telegram_401_suspends_credential_rejected() {
    let fake = FakeTelegram::start().await;
    let mut host = spawn(&fake).await;
    fake.script("getUpdates", 401, b"{}".to_vec());
    start(&mut host, None).await;
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Suspend {
            reason: SuspendReason::CredentialRejected
        }
    );
    // Receiving ended: no further poll.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(fake.calls("getUpdates").len(), 1);
    host.kill().await;
}

#[tokio::test]
async fn telegram_send_maps_verdicts() {
    let fake = FakeTelegram::start().await;
    let mut host = spawn(&fake).await;
    let send = async |host: &mut Host, id: &str| {
        host.send(&ToPlugin::Send {
            delivery_id: id.to_owned(),
            chat_key: "telegram:42".to_owned(),
            body: format!("reply {id}"),
            idempotency_key: format!("control_reply:{id}"),
        })
        .await
        .unwrap();
        next(host).await
    };
    let failed = |id: &str, class, code, retry_after_ms| FromPlugin::SendFailed {
        delivery_id: id.to_owned(),
        class,
        code,
        retry_after_ms,
    };
    // Before any start there is no token to send with.
    assert_eq!(
        send(&mut host, "d0").await,
        failed(
            "d0",
            FailureClass::Final,
            SendErrorCode::ReceiverInactive,
            None
        )
    );
    start(&mut host, None).await;
    assert_eq!(
        send(&mut host, "d1").await,
        FromPlugin::Sent {
            delivery_id: "d1".into(),
            platform_message_id: Some("1".into())
        }
    );
    fake.script(
        "sendMessage",
        429,
        br#"{"ok":false,"error_code":429,"parameters":{"retry_after":7}}"#.to_vec(),
    );
    assert_eq!(
        send(&mut host, "d2").await,
        failed(
            "d2",
            FailureClass::Retryable,
            SendErrorCode::RateLimited,
            Some(7000)
        )
    );
    fake.script("sendMessage", 400, b"{}".to_vec());
    assert_eq!(
        send(&mut host, "d3").await,
        failed("d3", FailureClass::Final, SendErrorCode::ClientError, None)
    );
    fake.script("sendMessage", 200, br#"{"ok":false}"#.to_vec());
    assert_eq!(
        send(&mut host, "d4").await,
        failed(
            "d4",
            FailureClass::Unknown,
            SendErrorCode::ServerError,
            None
        )
    );
    // Sending keeps working after stop, with the token of the start.
    host.send(&ToPlugin::Stop {}).await.unwrap();
    assert!(matches!(
        send(&mut host, "d5").await,
        FromPlugin::Sent { .. }
    ));
    let sent = fake.sent_messages();
    assert_eq!(sent.len(), 5);
    assert!(sent.iter().all(|sent| sent.chat_id == 42
        && !sent.has_parse_mode
        && sent.path == format!("/bot{TOKEN}/sendMessage")));
    assert_eq!(sent[0].text, "reply d1");
    host.kill().await;
}
