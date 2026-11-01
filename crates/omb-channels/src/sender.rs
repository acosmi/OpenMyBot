//! Telegram and Feishu send requests and the classification of their responses.
use omb_store::ErrorCode;
use openbot_infra::net::safe_http::SafeHttpError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Bytes read of one `sendMessage` response.
pub(crate) const SEND_RESPONSE_MAX: usize = 64 * 1024;

/// The decimal chat id after the `telegram:` prefix.
pub(crate) fn chat_id(chat_key: &str) -> Option<i64> {
    chat_key
        .strip_prefix("telegram:")
        .filter(|digits| !digits.starts_with('+'))?
        .parse()
        .ok()
}
/// `{"chat_id": <integer>, "text": <text>}` and no other key: the text is sent as plain text.
pub(crate) fn request_body(chat_id: i64, text: &str) -> Vec<u8> {
    serde_json::json!({"chat_id": chat_id, "text": text})
        .to_string()
        .into_bytes()
}
/// The chat id after the `feishu:` prefix, kept as the platform's text.
pub(crate) fn feishu_chat_id(chat_key: &str) -> Option<&str> {
    chat_key
        .strip_prefix("feishu:")
        .filter(|chat_id| !chat_id.is_empty())
}
/// `receive_id`, `msg_type`, `content` and `uuid` and no other key: `content` is the JSON text of
/// `{"text": <text>}`, and `uuid` the first 16 bytes of the idempotency key's SHA-256 in lower-case
/// hex, so a resent row is deduplicated by the platform.
pub(crate) fn feishu_body(chat_id: &str, text: &str, idempotency_key: &str) -> Vec<u8> {
    let uuid: String = Sha256::digest(idempotency_key.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({
        "receive_id": chat_id,
        "msg_type": "text",
        "content": json!({"text": text}).to_string(),
        "uuid": uuid,
    })
    .to_string()
    .into_bytes()
}

/// What one `sendMessage` outcome means for the row.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Sent {
        message_id: String,
    },
    /// A definite failure that takes a retry slot.
    Retry {
        code: ErrorCode,
        retry_after: Option<Duration>,
    },
    Failed {
        code: ErrorCode,
    },
    /// The request may have reached the platform; never resent.
    Unknown,
}
pub(crate) fn classify(result: Result<(u16, &[u8]), SafeHttpError>) -> Verdict {
    match result {
        Err(
            SafeHttpError::DnsUnavailable
            | SafeHttpError::DestinationDenied
            | SafeHttpError::ConnectFailed
            | SafeHttpError::PeerMismatch
            | SafeHttpError::TlsFailed
            | SafeHttpError::InvalidUrl
            | SafeHttpError::SchemeRejected
            | SafeHttpError::InvalidBudget
            | SafeHttpError::InvalidHeader
            | SafeHttpError::InvalidAllowlist,
        ) => Verdict::Retry {
            code: ErrorCode::Unreachable,
            retry_after: None,
        },
        Err(
            SafeHttpError::DeadlineExceeded
            | SafeHttpError::ProtocolFailed
            | SafeHttpError::ResponseTooLarge
            | SafeHttpError::StreamStalled
            | SafeHttpError::RedirectInvalid
            | SafeHttpError::RedirectLimit
            | SafeHttpError::RedirectMethodRejected
            | SafeHttpError::SensitiveRedirectRejected,
        ) => Verdict::Unknown,
        Ok((429, body)) => Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: serde_json::from_slice::<Value>(body)
                .ok()
                .and_then(|body| {
                    body.pointer("/parameters/retry_after")
                        .and_then(Value::as_u64)
                })
                .map(Duration::from_secs),
        },
        Ok((500..=599, _)) => Verdict::Retry {
            code: ErrorCode::ServerError,
            retry_after: None,
        },
        Ok((200..=299, body)) => serde_json::from_slice::<Value>(body)
            .ok()
            .filter(|body| body.get("ok") == Some(&Value::Bool(true)))
            .and_then(|body| body.pointer("/result/message_id").and_then(Value::as_i64))
            .map_or(Verdict::Unknown, |id| Verdict::Sent {
                message_id: id.to_string(),
            }),
        Ok(_) => Verdict::Failed {
            code: ErrorCode::ClientError,
        },
    }
}
/// The Feishu send outcome: the rate-limit codes 230020 and 99991400 count as 429 whatever the
/// status, and only code 0 with a message id is sent.
pub(crate) fn classify_feishu(result: Result<(u16, &[u8]), SafeHttpError>) -> Verdict {
    let (status, body) = match result {
        Err(
            SafeHttpError::DnsUnavailable
            | SafeHttpError::DestinationDenied
            | SafeHttpError::ConnectFailed
            | SafeHttpError::PeerMismatch
            | SafeHttpError::TlsFailed
            | SafeHttpError::InvalidUrl
            | SafeHttpError::SchemeRejected
            | SafeHttpError::InvalidBudget
            | SafeHttpError::InvalidHeader
            | SafeHttpError::InvalidAllowlist,
        ) => {
            return Verdict::Retry {
                code: ErrorCode::Unreachable,
                retry_after: None,
            };
        }
        Err(
            SafeHttpError::DeadlineExceeded
            | SafeHttpError::ProtocolFailed
            | SafeHttpError::ResponseTooLarge
            | SafeHttpError::StreamStalled
            | SafeHttpError::RedirectInvalid
            | SafeHttpError::RedirectLimit
            | SafeHttpError::RedirectMethodRejected
            | SafeHttpError::SensitiveRedirectRejected,
        ) => return Verdict::Unknown,
        Ok((429, _)) => {
            return Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: None,
            };
        }
        Ok((500..=599, _)) => {
            return Verdict::Retry {
                code: ErrorCode::ServerError,
                retry_after: None,
            };
        }
        Ok(reply) => reply,
    };
    let body = serde_json::from_slice::<Value>(body).ok();
    match (
        status,
        body.as_ref()
            .and_then(|body| body.get("code"))
            .and_then(Value::as_i64),
    ) {
        (_, Some(230_020 | 99_991_400)) => Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: None,
        },
        (200..=299, Some(0)) => body
            .as_ref()
            .and_then(|body| body.pointer("/data/message_id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map_or(Verdict::Unknown, |id| Verdict::Sent {
                message_id: id.to_owned(),
            }),
        (200..=299, None) => Verdict::Unknown,
        _ => Verdict::Failed {
            code: ErrorCode::ClientError,
        },
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_id_is_the_decimal_after_the_telegram_prefix() {
        assert_eq!(chat_id("telegram:42"), Some(42));
        assert_eq!(chat_id("telegram:-100123"), Some(-100_123));
        for key in [
            "42",
            "feishu:42",
            "telegram:",
            "telegram:4x2",
            "telegram:+42",
            "telegram:0x2a",
            "telegram:99999999999999999999",
        ] {
            assert_eq!(chat_id(key), None, "{key}");
        }
    }
    #[test]
    fn request_body_has_exactly_chat_id_and_text() {
        let body: Value = serde_json::from_slice(&request_body(-42, "你好 \"x\"\n")).unwrap();
        let object = body.as_object().unwrap();
        // Exactly these two keys: no formatting mode is ever requested.
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["chat_id", "text"]);
        assert_eq!(object["chat_id"], Value::from(-42));
        assert!(object["chat_id"].is_i64());
        assert_eq!(object["text"], "你好 \"x\"\n");
    }
    #[test]
    fn classify_2xx_ok_true_is_sent_with_decimal_message_id() {
        assert_eq!(
            classify(Ok((
                200,
                br#"{"ok":true,"result":{"message_id":123,"text":"x"}}"#
            ))),
            Verdict::Sent {
                message_id: "123".into()
            }
        );
    }
    #[test]
    fn classify_2xx_ok_false_unparseable_or_without_message_id_is_unknown() {
        for body in [
            br#"{"ok":false,"result":{"message_id":1}}"#.as_slice(),
            b"not json",
            br#"{"ok":true,"result":{}}"#,
            br#"{"ok":true}"#,
        ] {
            assert_eq!(classify(Ok((200, body))), Verdict::Unknown);
        }
    }
    #[test]
    fn classify_429_is_rate_limited_and_reads_retry_after() {
        assert_eq!(
            classify(Ok((
                429,
                br#"{"ok":false,"error_code":429,"parameters":{"retry_after":7}}"#
            ))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: Some(Duration::from_secs(7)),
            }
        );
        assert_eq!(
            classify(Ok((429, br#"{"ok":false,"error_code":429}"#))),
            Verdict::Retry {
                code: ErrorCode::RateLimited,
                retry_after: None,
            }
        );
    }
    #[test]
    fn classify_5xx_is_server_error_retry() {
        for status in [500, 502, 503] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Retry {
                    code: ErrorCode::ServerError,
                    retry_after: None,
                }
            );
        }
    }
    #[test]
    fn classify_other_4xx_and_leftover_3xx_are_client_error_failed() {
        for status in [400, 401, 403, 404, 302] {
            assert_eq!(
                classify(Ok((status, b"{}"))),
                Verdict::Failed {
                    code: ErrorCode::ClientError
                },
                "{status}"
            );
        }
    }
    #[test]
    fn classify_errors_before_the_request_is_sent_are_unreachable_retry() {
        for error in [
            SafeHttpError::DnsUnavailable,
            SafeHttpError::DestinationDenied,
            SafeHttpError::ConnectFailed,
            SafeHttpError::PeerMismatch,
            SafeHttpError::TlsFailed,
            SafeHttpError::InvalidUrl,
            SafeHttpError::SchemeRejected,
            SafeHttpError::InvalidBudget,
            SafeHttpError::InvalidHeader,
            SafeHttpError::InvalidAllowlist,
        ] {
            assert_eq!(
                classify(Err(error)),
                Verdict::Retry {
                    code: ErrorCode::Unreachable,
                    retry_after: None,
                },
                "{error:?}"
            );
        }
    }
    #[test]
    fn classify_errors_after_the_request_is_sent_are_unknown() {
        for error in [
            SafeHttpError::DeadlineExceeded,
            SafeHttpError::ProtocolFailed,
            SafeHttpError::ResponseTooLarge,
            SafeHttpError::StreamStalled,
            SafeHttpError::RedirectInvalid,
            SafeHttpError::RedirectLimit,
            SafeHttpError::RedirectMethodRejected,
            SafeHttpError::SensitiveRedirectRejected,
        ] {
            assert_eq!(classify(Err(error)), Verdict::Unknown, "{error:?}");
        }
    }
    #[test]
    fn feishu_chat_id_is_the_raw_text_after_the_feishu_prefix() {
        assert_eq!(feishu_chat_id("feishu:oc_1"), Some("oc_1"));
        assert_eq!(feishu_chat_id("feishu:ou 1"), Some("ou 1"));
        for key in ["feishu:", "telegram:42", "oc_1"] {
            assert_eq!(feishu_chat_id(key), None, "{key}");
        }
        assert_eq!(chat_id("feishu:42"), None);
    }
    #[test]
    fn feishu_body_has_four_keys_and_uuid_is_the_sha256_prefix() {
        let body: Value =
            serde_json::from_slice(&feishu_body("oc_1", "你好 \"x\"\n", "control_reply:f1"))
                .unwrap();
        let object = body.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["content", "msg_type", "receive_id", "uuid"]);
        assert_eq!(object["receive_id"], "oc_1");
        assert_eq!(object["msg_type"], "text");
        let content: Value = serde_json::from_str(object["content"].as_str().unwrap()).unwrap();
        assert_eq!(content["text"], "你好 \"x\"\n");
        for (key, uuid) in [
            ("control_reply:f1", "95f12bd8e78f5b6e7d886b7f16c05d03"),
            ("result:run-9", "10587490d704f9cc303b3c5e1ad34e44"),
        ] {
            let body: Value = serde_json::from_slice(&feishu_body("oc_1", "x", key)).unwrap();
            assert_eq!(body["uuid"], uuid);
            assert_eq!(uuid.len(), 32);
            assert!(
                uuid.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
        }
    }
    #[test]
    fn classify_feishu_follows_the_closed_classification() {
        for error in [
            SafeHttpError::DnsUnavailable,
            SafeHttpError::DestinationDenied,
            SafeHttpError::ConnectFailed,
            SafeHttpError::PeerMismatch,
            SafeHttpError::TlsFailed,
            SafeHttpError::InvalidUrl,
            SafeHttpError::SchemeRejected,
            SafeHttpError::InvalidBudget,
            SafeHttpError::InvalidHeader,
            SafeHttpError::InvalidAllowlist,
        ] {
            assert_eq!(
                classify_feishu(Err(error)),
                Verdict::Retry {
                    code: ErrorCode::Unreachable,
                    retry_after: None,
                },
                "{error:?}"
            );
        }
        for error in [
            SafeHttpError::DeadlineExceeded,
            SafeHttpError::ProtocolFailed,
            SafeHttpError::ResponseTooLarge,
            SafeHttpError::StreamStalled,
            SafeHttpError::RedirectInvalid,
            SafeHttpError::RedirectLimit,
            SafeHttpError::RedirectMethodRejected,
            SafeHttpError::SensitiveRedirectRejected,
        ] {
            assert_eq!(classify_feishu(Err(error)), Verdict::Unknown, "{error:?}");
        }
        let rate_limited = Verdict::Retry {
            code: ErrorCode::RateLimited,
            retry_after: None,
        };
        for (status, body) in [
            (429, r#"{"parameters":{"retry_after":9}}"#),
            (400, r#"{"code":230020}"#),
            (400, r#"{"code":99991400}"#),
            (200, r#"{"code":230020}"#),
        ] {
            assert_eq!(
                classify_feishu(Ok((status, body.as_bytes()))),
                rate_limited,
                "{status} {body}"
            );
        }
        for status in [500, 502] {
            assert_eq!(
                classify_feishu(Ok((status, b""))),
                Verdict::Retry {
                    code: ErrorCode::ServerError,
                    retry_after: None,
                }
            );
        }
        assert_eq!(
            classify_feishu(Ok((200, br#"{"code":0,"data":{"message_id":"om_1"}}"#))),
            Verdict::Sent {
                message_id: "om_1".into()
            }
        );
        for body in [
            r#"{"code":0}"#,
            r#"{"code":0,"data":{"message_id":""}}"#,
            "x",
            r#"{"code":"0"}"#,
        ] {
            assert_eq!(
                classify_feishu(Ok((200, body.as_bytes()))),
                Verdict::Unknown,
                "{body}"
            );
        }
        for (status, body) in [
            (200, r#"{"code":230001}"#),
            (400, r#"{"code":230002}"#),
            (404, ""),
            (403, r#"{"code":99991672}"#),
            (302, ""),
        ] {
            assert_eq!(
                classify_feishu(Ok((status, body.as_bytes()))),
                Verdict::Failed {
                    code: ErrorCode::ClientError
                },
                "{status} {body}"
            );
        }
    }
}
