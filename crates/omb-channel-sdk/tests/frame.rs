use std::collections::BTreeMap;
use std::io::Cursor;

use omb_channel_sdk::FRAME_MAX;
use omb_channel_sdk::frame::{FrameError, decode, encode, read_frame, write_frame};
use omb_channel_sdk::protocol::{
    EventFrame, EventKind, FailureClass, FromPlugin, GapReason, Limits, SendErrorCode, SkipCounter,
    SuspendReason, ToPlugin, VerifyFailure,
};
use serde_json::{Value, json};

fn event(occurred_at: Option<&str>) -> EventFrame {
    EventFrame {
        event_key: "101".to_owned(),
        event_type: "fake.message".to_owned(),
        occurred_at: occurred_at.map(str::to_owned),
        private: true,
        sender_key: Some("fake:7".to_owned()),
        chat_key: Some("fake:9".to_owned()),
        kind: EventKind::Text,
        text: "hello".to_owned(),
        data: BTreeMap::from([("messageId".to_owned(), "5".to_owned())]),
    }
}

/// Encodes `message`, compares the wire JSON with `wire` and decodes it back unchanged.
fn assert_wire<T>(message: T, wire: Value)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let payload = encode(&message).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&payload).unwrap(), wire);
    assert_eq!(decode::<T>(&payload).unwrap(), message);
}

#[tokio::test]
async fn frame_round_trip() {
    let payload = encode(&FromPlugin::GapClosed {}).unwrap();
    let mut wire = Vec::new();
    write_frame(&mut wire, &payload).await.unwrap();
    assert_eq!(&wire[..4], &(payload.len() as u32).to_be_bytes());
    let mut reader = Cursor::new(wire);
    let read = read_frame(&mut reader).await.unwrap().unwrap();
    assert_eq!(
        decode::<FromPlugin>(&read).unwrap(),
        FromPlugin::GapClosed {}
    );
    assert!(read_frame(&mut reader).await.unwrap().is_none());
}

#[tokio::test]
async fn frame_exactly_max_is_accepted() {
    let mut wire = (FRAME_MAX as u32).to_be_bytes().to_vec();
    wire.resize(4 + FRAME_MAX, b' ');
    let read = read_frame(&mut Cursor::new(wire)).await.unwrap().unwrap();
    assert_eq!(read.len(), FRAME_MAX);
}

#[tokio::test]
async fn frame_zero_length_is_rejected() {
    let error = read_frame(&mut Cursor::new(vec![0, 0, 0, 0]))
        .await
        .unwrap_err();
    assert!(matches!(error, FrameError::ZeroLength));
}

#[tokio::test]
async fn frame_over_max_is_rejected_before_reading_the_body() {
    // Only the length prefix exists: a body read would fail with an I/O error instead.
    let header = ((FRAME_MAX + 1) as u32).to_be_bytes().to_vec();
    let error = read_frame(&mut Cursor::new(header)).await.unwrap_err();
    assert!(matches!(error, FrameError::TooLarge(length) if length == FRAME_MAX + 1));

    let mut sink = Vec::new();
    let error = write_frame(&mut sink, &vec![b' '; FRAME_MAX + 1])
        .await
        .unwrap_err();
    assert!(matches!(error, FrameError::TooLarge(length) if length == FRAME_MAX + 1));
    assert!(sink.is_empty());
}

#[tokio::test]
async fn frame_truncated_is_an_io_error() {
    let error = read_frame(&mut Cursor::new(vec![0, 0])).await.unwrap_err();
    assert!(matches!(error, FrameError::Io(_)));
    let error = read_frame(&mut Cursor::new(vec![0, 0, 0, 5, b'{']))
        .await
        .unwrap_err();
    assert!(matches!(error, FrameError::Io(_)));
}

#[test]
fn decode_rejects_duplicate_keys_at_any_depth() {
    let top = br#"{"type":"gap","reason":"stream_broken","reason":"connect_failed"}"#;
    assert!(matches!(
        decode::<FromPlugin>(top),
        Err(FrameError::DuplicateKey)
    ));
    let nested = br#"{"type":"event","event_key":"1","event_type":"fake.message","occurred_at":null,"private":true,"sender_key":null,"chat_key":null,"kind":"text","text":"","data":{"a":"1","a":"2"}}"#;
    assert!(matches!(
        decode::<FromPlugin>(nested),
        Err(FrameError::DuplicateKey)
    ));
}

#[test]
fn decode_rejects_unknown_fields() {
    let gap = br#"{"type":"gap","reason":"stream_broken","extra":1}"#;
    assert!(matches!(decode::<FromPlugin>(gap), Err(FrameError::Json)));
    let mut event = serde_json::to_value(FromPlugin::Event(event(None))).unwrap();
    event["extra"] = json!(1);
    let payload = serde_json::to_vec(&event).unwrap();
    assert!(matches!(
        decode::<FromPlugin>(&payload),
        Err(FrameError::Json)
    ));
    let limits = br#"{"type":"hello","protocol":"openmybot-channel/1","channel_kind":"fake","limits":{"send_timeout_ms":1,"ack_timeout_ms":1,"extra":1}}"#;
    assert!(matches!(decode::<ToPlugin>(limits), Err(FrameError::Json)));
    let stop = br#"{"type":"stop","extra":1}"#;
    assert!(matches!(decode::<ToPlugin>(stop), Err(FrameError::Json)));
    let unknown_type = br#"{"type":"approve"}"#;
    assert!(matches!(
        decode::<ToPlugin>(unknown_type),
        Err(FrameError::Json)
    ));
}

#[test]
fn decode_rejects_invalid_utf8_and_json() {
    assert!(matches!(
        decode::<ToPlugin>(b"{\"type\":\"\xff\"}"),
        Err(FrameError::Utf8)
    ));
    assert!(matches!(
        decode::<ToPlugin>(b"{\"type\":"),
        Err(FrameError::Json)
    ));
}

#[test]
fn to_plugin_wire_format() {
    assert_wire(
        ToPlugin::Hello {
            protocol: "openmybot-channel/1".to_owned(),
            channel_kind: "fake".to_owned(),
            limits: Limits {
                send_timeout_ms: 35_000,
                ack_timeout_ms: 3_000,
            },
        },
        json!({"type": "hello", "protocol": "openmybot-channel/1", "channel_kind": "fake",
               "limits": {"send_timeout_ms": 35_000, "ack_timeout_ms": 3_000}}),
    );
    assert_wire(
        ToPlugin::Verify {
            credential: "secret".to_owned(),
            source_key: Some("42".to_owned()),
        },
        json!({"type": "verify", "credential": "secret", "source_key": "42"}),
    );
    assert_wire(
        ToPlugin::Start {
            source_key: "42".to_owned(),
            credential: "secret".to_owned(),
            last_event_key: Some("100".to_owned()),
            last_accepted_at: Some("2026-10-31T08:00:00.000Z".to_owned()),
        },
        json!({"type": "start", "source_key": "42", "credential": "secret",
               "last_event_key": "100", "last_accepted_at": "2026-10-31T08:00:00.000Z"}),
    );
    assert_wire(ToPlugin::Stop {}, json!({"type": "stop"}));
    assert_wire(
        ToPlugin::Send {
            delivery_id: "d1".to_owned(),
            chat_key: "fake:9".to_owned(),
            body: "hi".to_owned(),
            idempotency_key: "k1".to_owned(),
        },
        json!({"type": "send", "delivery_id": "d1", "chat_key": "fake:9", "body": "hi",
               "idempotency_key": "k1"}),
    );
    assert_wire(
        ToPlugin::Accepted {
            event_key: "101".to_owned(),
        },
        json!({"type": "accepted", "event_key": "101"}),
    );
    // Optional fields may be left out on the wire.
    assert_eq!(
        decode::<ToPlugin>(br#"{"type":"verify","credential":"secret"}"#).unwrap(),
        ToPlugin::Verify {
            credential: "secret".to_owned(),
            source_key: None,
        }
    );
}

#[test]
fn from_plugin_wire_format() {
    assert_wire(
        FromPlugin::HelloOk {
            plugin_name: "fake-channel-plugin".to_owned(),
            plugin_version: "0.0.0".to_owned(),
            channel_kind: "fake".to_owned(),
        },
        json!({"type": "hello_ok", "plugin_name": "fake-channel-plugin", "plugin_version": "0.0.0",
               "channel_kind": "fake"}),
    );
    assert_wire(
        FromPlugin::Verified {
            source_key: "42".to_owned(),
        },
        json!({"type": "verified", "source_key": "42"}),
    );
    for (code, wire) in [
        (VerifyFailure::CredentialRejected, "credential_rejected"),
        (VerifyFailure::WebhookConflict, "webhook_conflict"),
        (VerifyFailure::Unreachable, "unreachable"),
        (VerifyFailure::Malformed, "malformed"),
    ] {
        assert_wire(
            FromPlugin::VerifyFailed { code },
            json!({"type": "verify_failed", "code": wire}),
        );
    }
    for (kind, wire) in [
        (EventKind::Text, "text"),
        (EventKind::Other, "other"),
        (EventKind::Malformed, "malformed"),
    ] {
        assert_wire(
            FromPlugin::Event(EventFrame {
                kind,
                ..event(Some("2026-10-31T08:00:00.123Z"))
            }),
            json!({"type": "event", "event_key": "101", "event_type": "fake.message",
                   "occurred_at": "2026-10-31T08:00:00.123Z", "private": true,
                   "sender_key": "fake:7", "chat_key": "fake:9", "kind": wire, "text": "hello",
                   "data": {"messageId": "5"}}),
        );
    }
    for (counter, wire) in [
        (
            SkipCounter::PlatformPayloadUnparseable,
            "platform_payload_unparseable",
        ),
        (SkipCounter::UnsupportedUpdate, "unsupported_update"),
    ] {
        assert_wire(
            FromPlugin::Skipped { counter },
            json!({"type": "skipped", "counter": wire}),
        );
    }
    for (reason, wire) in [
        (GapReason::ConnectFailed, "connect_failed"),
        (GapReason::StreamBroken, "stream_broken"),
    ] {
        assert_wire(
            FromPlugin::Gap { reason },
            json!({"type": "gap", "reason": wire}),
        );
    }
    assert_wire(FromPlugin::GapClosed {}, json!({"type": "gap_closed"}));
    for (reason, wire) in [
        (SuspendReason::CredentialRejected, "credential_rejected"),
        (SuspendReason::WebhookConflict, "webhook_conflict"),
    ] {
        assert_wire(
            FromPlugin::Suspend { reason },
            json!({"type": "suspend", "reason": wire}),
        );
    }
    assert_wire(
        FromPlugin::Sent {
            delivery_id: "d1".to_owned(),
            platform_message_id: Some("m1".to_owned()),
        },
        json!({"type": "sent", "delivery_id": "d1", "platform_message_id": "m1"}),
    );
    for (class, class_wire) in [
        (FailureClass::Retryable, "retryable"),
        (FailureClass::Final, "final"),
        (FailureClass::Unknown, "unknown"),
    ] {
        for (code, code_wire) in [
            (SendErrorCode::Unreachable, "unreachable"),
            (SendErrorCode::RateLimited, "rate_limited"),
            (SendErrorCode::ServerError, "server_error"),
            (SendErrorCode::ClientError, "client_error"),
            (SendErrorCode::ReceiverInactive, "receiver_inactive"),
        ] {
            assert_wire(
                FromPlugin::SendFailed {
                    delivery_id: "d1".to_owned(),
                    class: class.clone(),
                    code,
                    retry_after_ms: Some(1_500),
                },
                json!({"type": "send_failed", "delivery_id": "d1", "class": class_wire,
                       "code": code_wire, "retry_after_ms": 1_500}),
            );
        }
    }
}

#[test]
fn occurred_at_passes_through_unchanged() {
    for occurred_at in [None, Some("2026-10-31T08:00:00.123Z"), Some("1730361600")] {
        let payload = encode(&FromPlugin::Event(event(occurred_at))).unwrap();
        let FromPlugin::Event(decoded) = decode(&payload).unwrap() else {
            panic!("not an event");
        };
        assert_eq!(decoded.occurred_at.as_deref(), occurred_at);
    }
}
