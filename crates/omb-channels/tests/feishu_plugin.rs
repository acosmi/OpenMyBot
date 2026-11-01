//! The Feishu plugin binary against the in-process fake open platform, driven through the SDK's
//! test host.
use omb_channel_sdk::protocol::{
    EventKind, FailureClass, FromPlugin, GapReason, SendErrorCode, SkipCounter, ToPlugin,
    VerifyFailure,
};
use omb_channel_sdk::testkit::Host;
use omb_channels::{fake_feishu::FakeFeishu, testkit::Reply};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use time::OffsetDateTime;
use tokio::time::Instant;

const PLUGIN: &str = env!("CARGO_BIN_EXE_openmybot-channel-feishu");
const WAIT: Duration = Duration::from_secs(10);
const TOKEN_PATH: &str = "/open-apis/auth/v3/tenant_access_token/internal";

async fn spawn(fake: &FakeFeishu) -> Host {
    let base = fake.endpoint().api_base;
    let mut host = Host::spawn(Path::new(PLUGIN), &["--api-base", base.as_str()], &[])
        .await
        .unwrap();
    host.hello("feishu").await.unwrap();
    host
}
async fn next(host: &mut Host) -> FromPlugin {
    host.recv(WAIT).await.unwrap().expect("a frame")
}
async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "waited for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
/// Starts receiving and waits for the long connection.
async fn started(fake: &FakeFeishu) -> Host {
    let mut host = spawn(fake).await;
    host.send(&ToPlugin::Start {
        source_key: "cli_test".to_owned(),
        credential: "app-secret".to_owned(),
        last_event_key: None,
        last_accepted_at: None,
    })
    .await
    .unwrap();
    until("the long connection", || fake.connected()).await;
    host
}
fn envelope(event_id: &str, text: &str) -> Value {
    json!({
        "schema": "2.0",
        "header": {
            "event_id": event_id,
            "event_type": "im.message.receive_v1",
            "create_time": (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).to_string(),
            "app_id": "cli_test",
        },
        "event": {
            "sender": {"sender_id": {"open_id": "ou_user"}, "sender_type": "user"},
            "message": {
                "message_id": format!("om_{event_id}"),
                "chat_id": "oc_chat",
                "chat_type": "p2p",
                "message_type": "text",
                "content": json!({"text": text}).to_string(),
            },
        },
    })
}

#[tokio::test]
async fn feishu_verify_maps_token_reply() {
    let fake = FakeFeishu::start().await;
    let mut host = spawn(&fake).await;
    let mut verify = async |source_key: Option<&str>| {
        host.send(&ToPlugin::Verify {
            credential: "app-secret".to_owned(),
            source_key: source_key.map(str::to_owned),
        })
        .await
        .unwrap();
        next(&mut host).await
    };
    assert_eq!(
        verify(Some("cli_test")).await,
        FromPlugin::Verified {
            source_key: "cli_test".into()
        }
    );
    let failed = |code| FromPlugin::VerifyFailed { code };
    assert_eq!(verify(None).await, failed(VerifyFailure::Malformed));
    fake.script(
        TOKEN_PATH,
        Reply::Respond {
            status: 200,
            body: br#"{"code":10014}"#.to_vec(),
        },
    );
    assert_eq!(
        verify(Some("cli_test")).await,
        failed(VerifyFailure::CredentialRejected)
    );
    fake.script(
        TOKEN_PATH,
        Reply::Respond {
            status: 503,
            body: Vec::new(),
        },
    );
    assert_eq!(
        verify(Some("cli_test")).await,
        failed(VerifyFailure::Unreachable)
    );
    let bodies: Vec<Value> = fake
        .calls(TOKEN_PATH)
        .iter()
        .map(|call| serde_json::from_slice(&call.body).unwrap())
        .collect();
    assert_eq!(bodies.len(), 3);
    assert!(
        bodies
            .iter()
            .all(|body| *body == json!({"app_id": "cli_test", "app_secret": "app-secret"}))
    );
    host.kill().await;
}

#[tokio::test]
async fn feishu_event_is_acked_only_after_accepted() {
    let fake = FakeFeishu::start().await;
    let mut host = started(&fake).await;
    assert!(fake.push_event(&envelope("ev_1", "hello")));
    let FromPlugin::Event(event) = next(&mut host).await else {
        panic!("not an event");
    };
    assert_eq!(
        (
            event.event_key.as_str(),
            event.event_type.as_str(),
            event.kind,
            event.text.as_str()
        ),
        (
            "ev_1",
            "feishu.im.message.receive_v1",
            EventKind::Text,
            "hello"
        )
    );
    assert_eq!(
        (event.sender_key.as_deref(), event.chat_key.as_deref()),
        (Some("feishu:ou_user"), Some("feishu:oc_chat"))
    );
    assert_eq!(
        event.data.keys().collect::<Vec<_>>(),
        ["chatId", "content", "messageId", "messageType", "openId"]
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(fake.acks().is_empty());
    host.send(&ToPlugin::Accepted {
        event_key: "ev_1".to_owned(),
    })
    .await
    .unwrap();
    until("one acknowledgement", || fake.acks().len() == 1).await;
    let ack = &fake.acks()[0];
    assert!(ack.valid);
    assert_eq!(ack.message_id, "ev_1");
    // An event without a receipt in the ack window is not acknowledged.
    assert!(fake.push_event(&envelope("ev_2", "again")));
    assert!(matches!(next(&mut host).await, FromPlugin::Event(event) if event.event_key == "ev_2"));
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(fake.acks().len(), 1);
    host.kill().await;
}

#[tokio::test]
async fn feishu_unparseable_payload_is_skipped_and_acked() {
    let fake = FakeFeishu::start().await;
    let mut host = started(&fake).await;
    assert!(fake.push_event(&json!({"schema": "1.0", "header": {"event_id": "ev_bad"}})));
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Skipped {
            counter: SkipCounter::PlatformPayloadUnparseable
        }
    );
    until("the acknowledgement", || fake.acks().len() == 1).await;
    let mut unsupported = envelope("ev_read", "x");
    unsupported["header"]["event_type"] = json!("im.message.message_read_v1");
    assert!(fake.push_event(&unsupported));
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Skipped {
            counter: SkipCounter::UnsupportedUpdate
        }
    );
    until("both acknowledgements", || fake.acks().len() == 2).await;
    assert!(fake.acks().iter().all(|ack| ack.valid));
    host.kill().await;
}

#[tokio::test]
async fn feishu_stream_break_opens_and_closes_gap() {
    let fake = FakeFeishu::start().await;
    let mut host = started(&fake).await;
    fake.disconnect();
    assert_eq!(
        next(&mut host).await,
        FromPlugin::Gap {
            reason: GapReason::StreamBroken
        }
    );
    assert_eq!(next(&mut host).await, FromPlugin::GapClosed {});
    until("the second connection", || fake.handshakes().len() == 2).await;
    host.kill().await;
}

#[tokio::test]
async fn feishu_send_uses_cached_token_and_idempotency_uuid() {
    let fake = FakeFeishu::start().await;
    let mut host = spawn(&fake).await;
    let send = async |host: &mut Host, id: &str, key: &str| {
        host.send(&ToPlugin::Send {
            delivery_id: id.to_owned(),
            chat_key: "feishu:oc_chat".to_owned(),
            body: format!("reply {id}"),
            idempotency_key: key.to_owned(),
        })
        .await
        .unwrap();
        next(host).await
    };
    assert_eq!(
        send(&mut host, "d0", "control_reply:f0").await,
        FromPlugin::SendFailed {
            delivery_id: "d0".into(),
            class: FailureClass::Final,
            code: SendErrorCode::ReceiverInactive,
            retry_after_ms: None,
        }
    );
    host.send(&ToPlugin::Start {
        source_key: "cli_test".to_owned(),
        credential: "app-secret".to_owned(),
        last_event_key: None,
        last_accepted_at: None,
    })
    .await
    .unwrap();
    for (id, key, message) in [
        ("d1", "control_reply:f1", "om_1"),
        ("d2", "result:run-9", "om_2"),
    ] {
        assert_eq!(
            send(&mut host, id, key).await,
            FromPlugin::Sent {
                delivery_id: id.into(),
                platform_message_id: Some(message.into())
            }
        );
    }
    // One tenant token served both sends.
    assert_eq!(fake.calls(TOKEN_PATH).len(), 1);
    let sent = fake.sent_messages();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(
        |sent| sent.authorization.as_deref() == Some("Bearer t-fake-1")
            && sent.receive_id == "oc_chat"
            && sent.msg_type == "text"
            && sent.keys == 4
            && sent.query == [("receive_id_type".to_owned(), "chat_id".to_owned())]
    ));
    assert_eq!(
        [sent[0].uuid.as_str(), sent[1].uuid.as_str()],
        [
            "95f12bd8e78f5b6e7d886b7f16c05d03",
            "10587490d704f9cc303b3c5e1ad34e44"
        ]
    );
    assert_eq!(sent[0].content, json!({"text": "reply d1"}).to_string());
    host.kill().await;
}
