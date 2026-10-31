//! Telegram Bot API long polling: boundary parsing, fingerprints, offsets and the receive loop.
use crate::{
    CancelRequests, ChannelError, Connection, Counters, Endpoints, OMB_REPLY_TEXTS_V1,
    STORE_BUDGET, TELEGRAM, TG_HTTP_MARGIN, TG_OFFSET_STALE, TG_POLL_LIMIT, TG_RESPONSE_MAX, Task,
    TelegramEndpoint, Timings,
};
use omb_store::{
    ACCEPT_TX_BUDGET, AcceptOutcome, Command, Content, IdentityKey, NormalizedEvent, PollGapReason,
    ReceiverRow, StoreError, Suspension, accept_event, close_poll_gaps, latest_event,
    open_poll_gap, suspend_receiver,
};
use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use openbot_infra::{
    net::safe_http::{SafeHttpBudget, SafeHttpError, SafeHttpRequest},
    vault::CredentialRecordVault,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::{
    sync::{Notify, oneshot},
    time::Instant,
};
use url::Url;

/// One `getUpdates` element after boundary parsing.
#[derive(Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one value per update, consumed at once; the event is not boxed"
)]
pub enum Normalized {
    Event(NormalizedEvent),
    /// The update carries no `message`.
    Unsupported,
    /// `update_id` is missing or not an integer.
    Unparseable,
}

/// Parses one update into the closed event shape; malformed messages keep obtainable identity.
pub fn normalize(update: &Value, source_key: &str) -> Normalized {
    let Some(update_id) = update.get("update_id").and_then(Value::as_u64) else {
        return Normalized::Unparseable;
    };
    let Some(message) = update.get("message") else {
        return Normalized::Unsupported;
    };
    let from_id = message.pointer("/from/id").and_then(Value::as_i64);
    let chat_id = message.pointer("/chat/id").and_then(Value::as_i64);
    let occurred_at = message
        .get("date")
        .and_then(Value::as_i64)
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok());
    let message_id = message.get("message_id").and_then(Value::as_i64);
    let text = message.get("text").and_then(Value::as_str);
    let fingerprint = match (from_id, chat_id, occurred_at, message_id) {
        (Some(from_id), Some(chat_id), Some(occurred_at), Some(message_id)) => {
            Some(fingerprint(&FingerprintInput {
                occurred_at,
                chat_id: &chat_id.to_string(),
                from_id: &from_id.to_string(),
                message_id: &message_id.to_string(),
                message_kind: if text.is_some() { "text" } else { "other" },
                text: text.unwrap_or_default(),
            }))
        }
        _ => None,
    };
    let content = match (fingerprint, text) {
        (None, _) => Content::Malformed,
        (Some(_), Some(text)) if text.contains('\0') => Content::Malformed,
        (Some(_), Some(text)) => {
            let (command, pair_code) = classify(text);
            Content::Text {
                text: text.to_owned(),
                command,
                pair_code,
            }
        }
        (Some(_), None) => Content::Other,
    };
    Normalized::Event(NormalizedEvent {
        channel: TELEGRAM,
        source_key: source_key.to_owned(),
        event_key: update_id.to_string(),
        event_type: "telegram.message".to_owned(),
        occurred_at,
        private: message.pointer("/chat/type").and_then(Value::as_str) == Some("private"),
        sender: from_id.and_then(|id| IdentityKey::parse(&format!("telegram:{id}"))),
        chat: chat_id.and_then(|id| IdentityKey::parse(&format!("telegram:{id}"))),
        fingerprint,
        content,
    })
}

/// Control command of the first word, and the `/pair` code when the whole text is `/pair <code>`.
pub fn classify(text: &str) -> (Option<Command>, Option<String>) {
    let pair_code = text.strip_prefix("/pair").and_then(|rest| {
        let code = rest.trim_start();
        (code.len() < rest.len() && !code.is_empty() && !code.contains(char::is_whitespace))
            .then(|| code.to_owned())
    });
    let word = text.split_whitespace().next().unwrap_or_default();
    let command = word.starts_with('/').then(|| {
        let name = word.split('@').next().unwrap_or_default().to_lowercase();
        match name.as_str() {
            "/help" => Command::Help,
            "/start" => Command::Start,
            "/status" => Command::Status,
            "/cancel" => Command::Cancel,
            "/pair" => Command::Pair,
            _ => Command::Unknown,
        }
    });
    (command, pair_code)
}

pub struct FingerprintInput<'a> {
    pub occurred_at: OffsetDateTime,
    pub chat_id: &'a str,
    pub from_id: &'a str,
    pub message_id: &'a str,
    pub message_kind: &'a str,
    pub text: &'a str,
}
/// RFC 8785 form of the fingerprint object: every key is ASCII and written in byte order, and
/// every value is a string escaped the way JCS requires.
pub fn canonical_json(input: &FingerprintInput<'_>) -> String {
    let string = |value: &str| serde_json::to_string(value).unwrap_or_default();
    let occurred_at = input
        .occurred_at
        .to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_default();
    format!(
        r#"{{"data":{{"chatId":{},"fromId":{},"messageId":{},"messageKind":{},"text":{}}},"eventType":"telegram.message","occurredAt":{}}}"#,
        string(input.chat_id),
        string(input.from_id),
        string(input.message_id),
        string(input.message_kind),
        string(input.text),
        string(&occurred_at),
    )
}
pub fn fingerprint(input: &FingerprintInput<'_>) -> [u8; 32] {
    Sha256::digest(canonical_json(input).as_bytes()).into()
}

/// Next `getUpdates` offset: one past the larger of the stored and in-memory update ids; a stored
/// row older than `TG_OFFSET_STALE` does not count.
pub fn next_offset(
    stored: Option<(u64, OffsetDateTime)>,
    memory: Option<u64>,
    now: OffsetDateTime,
) -> Option<u64> {
    let stored = stored
        .filter(|(_, accepted_at)| now - *accepted_at <= TG_OFFSET_STALE)
        .map(|(update_id, _)| update_id);
    stored.max(memory).map(|update_id| update_id + 1)
}
/// `min` doubled per attempt, capped at `max`.
pub fn backoff_ceiling(attempt: u32, min: Duration, max: Duration) -> Duration {
    min.checked_mul(2u32.saturating_pow(attempt))
        .unwrap_or(max)
        .min(max)
}
/// Full jitter: uniform in `[0, backoff_ceiling]`.
pub fn backoff(attempt: u32, min: Duration, max: Duration) -> Duration {
    let ceiling = backoff_ceiling(attempt, min, max);
    let nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
    getrandom::u64().map_or(ceiling, |random| {
        Duration::from_nanos(random % nanos.saturating_add(1))
    })
}

fn method_url(endpoint: &TelegramEndpoint, token: &str, method: &str) -> Url {
    let mut url = endpoint.api_base.clone();
    url.set_path(&format!("/bot{token}/{method}"));
    url
}
fn updates_url(
    endpoint: &TelegramEndpoint,
    token: &str,
    offset: Option<u64>,
    poll_timeout: Duration,
) -> Url {
    let mut url = method_url(endpoint, token, "getUpdates");
    {
        let mut query = url.query_pairs_mut();
        if let Some(offset) = offset {
            query.append_pair("offset", &offset.to_string());
        }
        query
            .append_pair("timeout", &poll_timeout.as_secs().to_string())
            .append_pair("limit", &TG_POLL_LIMIT.to_string())
            .append_pair("allowed_updates", r#"["message"]"#);
    }
    url
}

/// What one `getUpdates` response means for the receiver.
#[derive(Debug, PartialEq)]
enum Verdict {
    Updates(Vec<Value>),
    Suspend(Suspension),
    /// Rate limited with a platform wait.
    Wait(Duration),
    Backoff,
}
fn verdict(status: u16, body: &[u8]) -> Verdict {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    match status {
        200 => match parsed {
            Some(Value::Object(mut object)) if object.get("ok") == Some(&Value::Bool(true)) => {
                match object.remove("result") {
                    Some(Value::Array(updates)) => Verdict::Updates(updates),
                    _ => Verdict::Backoff,
                }
            }
            _ => Verdict::Backoff,
        },
        401 | 404 => Verdict::Suspend(Suspension::CredentialRejected),
        409 => Verdict::Suspend(Suspension::WebhookConflict),
        429 => parsed
            .and_then(|body| {
                body.pointer("/parameters/retry_after")
                    .and_then(Value::as_u64)
            })
            .map_or(Verdict::Backoff, |seconds| {
                Verdict::Wait(Duration::from_secs(seconds))
            }),
        _ => Verdict::Backoff,
    }
}

#[derive(Clone)]
pub struct ReceiverContext {
    pub vault: CredentialRecordVault,
    pub owner: ActorId,
    pub endpoints: Endpoints,
    pub timings: Timings,
    pub counters: Arc<Counters>,
    pub wake: Arc<Notify>,
    pub cancel: CancelRequests,
}

/// Starts the long-poll loop of one active receiver.
pub(crate) fn start_receiver(
    connection: Connection,
    receiver: ReceiverRow,
    context: ReceiverContext,
) -> Task {
    Task::spawn(connection, move |client, stop| {
        receive(client, receiver, context, stop)
    })
}
async fn receive(
    mut client: tokio_postgres::Client,
    receiver: ReceiverRow,
    context: ReceiverContext,
    mut stop: oneshot::Receiver<()>,
) -> Result<(), ChannelError> {
    let store = |_: StoreError| ChannelError::StoreFailed;
    let secret = context
        .vault
        .open(
            &receiver.binding_id,
            SecretKind::Connector,
            SecretPrincipal::Actor(context.owner.clone()),
            SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
            &receiver.credential_envelope,
        )
        .map(|opened| opened.into_secret());
    let token = secret
        .as_ref()
        .ok()
        .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
        .filter(|token| {
            token
                .split_once(':')
                .is_some_and(|(bot_id, _)| bot_id == receiver.source_key)
        });
    let Some(token) = token else {
        suspend_receiver(
            &mut client,
            receiver.binding_id,
            Suspension::CredentialRejected,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(store)?;
        return Ok(());
    };
    let timings = context.timings;
    let mut memory: Option<u64> = None;
    let mut failures = 0u32;
    loop {
        let stored = latest_event(&client, &TELEGRAM, &receiver.source_key)
            .await
            .map_err(store)?
            .map(|(key, at)| Ok((key.parse().map_err(|_| ChannelError::StoreFailed)?, at)))
            .transpose()?;
        let url = updates_url(
            &context.endpoints.telegram,
            token,
            next_offset(stored, memory, OffsetDateTime::now_utc()),
            timings.poll_timeout,
        );
        let response = tokio::select! {
            _ = &mut stop => return Ok(()),
            response = async {
                let budget = SafeHttpBudget::new(TG_RESPONSE_MAX, timings.poll_timeout + TG_HTTP_MARGIN)?;
                context.endpoints.telegram.dialer.execute(SafeHttpRequest::get(url, context.endpoints.telegram.scheme, budget)?).await
            } => response,
        };
        let (reason, delay) = match response.map(|r| verdict(r.status().as_u16(), r.body())) {
            Err(
                SafeHttpError::InvalidUrl
                | SafeHttpError::SchemeRejected
                | SafeHttpError::InvalidBudget
                | SafeHttpError::DnsUnavailable
                | SafeHttpError::DestinationDenied
                | SafeHttpError::ConnectFailed
                | SafeHttpError::PeerMismatch
                | SafeHttpError::TlsFailed,
            ) => (PollGapReason::ConnectFailed, None),
            Err(_) | Ok(Verdict::Backoff) => (PollGapReason::StreamBroken, None),
            Ok(Verdict::Wait(delay)) => (PollGapReason::StreamBroken, Some(delay)),
            Ok(Verdict::Suspend(why)) => {
                suspend_receiver(
                    &mut client,
                    receiver.binding_id,
                    why,
                    Instant::now() + STORE_BUDGET,
                )
                .await
                .map_err(store)?;
                return Ok(());
            }
            Ok(Verdict::Updates(mut updates)) => {
                close_poll_gaps(
                    &mut client,
                    receiver.binding_id,
                    Instant::now() + STORE_BUDGET,
                )
                .await
                .map_err(store)?;
                failures = 0;
                updates.sort_by_key(|update| update.get("update_id").and_then(Value::as_u64));
                for update in &updates {
                    let committed = match normalize(update, &receiver.source_key) {
                        Normalized::Unparseable => {
                            context
                                .counters
                                .platform_payload_unparseable
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        Normalized::Unsupported => {
                            context
                                .counters
                                .unsupported_update
                                .fetch_add(1, Ordering::Relaxed);
                            true
                        }
                        Normalized::Event(event) => {
                            let accepted = accept_event(
                                &mut client,
                                receiver.binding_id,
                                &event,
                                &OMB_REPLY_TEXTS_V1,
                                Instant::now() + ACCEPT_TX_BUDGET,
                            )
                            .await;
                            // Every outcome wakes, an error too: its commit may have landed.
                            context.wake.notify_one();
                            match accepted {
                                Ok(AcceptOutcome::Conflict) => {
                                    context
                                        .counters
                                        .event_conflict
                                        .fetch_add(1, Ordering::Relaxed);
                                    true
                                }
                                // Sent only after commit; a closed channel means the daemon is stopping.
                                Ok(AcceptOutcome::Cancel(binding)) => {
                                    let _ = context.cancel.send(binding).await;
                                    true
                                }
                                Ok(_) => true,
                                Err(StoreError::ReceiverNotActive) => return Ok(()),
                                // Not committed: the rest of the batch is fetched again from here.
                                Err(_) => false,
                            }
                        }
                    };
                    if !committed {
                        break;
                    }
                    memory = memory.max(update.get("update_id").and_then(Value::as_u64));
                }
                continue;
            }
        };
        open_poll_gap(
            &mut client,
            receiver.binding_id,
            reason,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(store)?;
        let delay =
            delay.unwrap_or_else(|| backoff(failures, timings.backoff_min, timings.backoff_max));
        failures = failures.saturating_add(1);
        tokio::select! {
            _ = &mut stop => return Ok(()),
            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialProblem {
    CredentialRejected,
    WebhookConflict,
    Unreachable,
}
async fn call(
    endpoint: &TelegramEndpoint,
    token: &str,
    method: &str,
) -> Result<Value, CredentialProblem> {
    let budget = SafeHttpBudget::new(TG_RESPONSE_MAX, TG_HTTP_MARGIN)
        .map_err(|_| CredentialProblem::Unreachable)?;
    let request =
        SafeHttpRequest::get(method_url(endpoint, token, method), endpoint.scheme, budget)
            .map_err(|_| CredentialProblem::Unreachable)?;
    let response = endpoint
        .dialer
        .execute(request)
        .await
        .map_err(|_| CredentialProblem::Unreachable)?;
    match response.status().as_u16() {
        200 => serde_json::from_slice::<Value>(response.body())
            .ok()
            .and_then(|mut body| body.get_mut("result").map(Value::take))
            .ok_or(CredentialProblem::Unreachable),
        401 | 404 => Err(CredentialProblem::CredentialRejected),
        _ => Err(CredentialProblem::Unreachable),
    }
}
/// Bind-time check: `getMe` must report `bot_id` and `getWebhookInfo` no webhook. Never changes
/// any Bot setting.
pub async fn verify_credentials(
    endpoint: &TelegramEndpoint,
    token: &SecretBytes,
    bot_id: &str,
) -> Result<(), CredentialProblem> {
    let token =
        std::str::from_utf8(token.expose()).map_err(|_| CredentialProblem::CredentialRejected)?;
    let me = call(endpoint, token, "getMe").await?;
    if me
        .get("id")
        .and_then(Value::as_i64)
        .map(|id| id.to_string())
        .as_deref()
        != Some(bot_id)
    {
        return Err(CredentialProblem::CredentialRejected);
    }
    let webhook = call(endpoint, token, "getWebhookInfo").await?;
    if webhook
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(|url| !url.is_empty())
    {
        return Err(CredentialProblem::WebhookConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer, SchemePolicy};
    use serde_json::json;

    const DATE: i64 = 1_793_202_187; // 2026-10-28T15:43:07Z
    fn update(message: Value) -> Value {
        json!({"update_id": 500, "message": message})
    }
    fn private_text(text: &str) -> Value {
        update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 42, "is_bot": false}, "chat": {"id": 42, "type": "private"}, "text": text}),
        )
    }
    fn event(value: &Value) -> NormalizedEvent {
        match normalize(value, "1001") {
            Normalized::Event(event) => event,
            other => panic!("not an event: {other:?}"),
        }
    }
    fn input<'a>(chat_id: &'a str, kind: &'a str, text: &'a str) -> FingerprintInput<'a> {
        FingerprintInput {
            occurred_at: OffsetDateTime::from_unix_timestamp(DATE).unwrap(),
            chat_id,
            from_id: "42",
            message_id: "77",
            message_kind: kind,
            text,
        }
    }
    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    // The canonical text and digests below were produced independently with Python's
    // `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` and `hashlib`.
    const ESCAPES: &str = "hi \"you\"\\ \u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f} é 中";
    const ESCAPED_JCS: &str = "{\"data\":{\"chatId\":\"-1001\",\"fromId\":\"42\",\"messageId\":\"77\",\"messageKind\":\"text\",\"text\":\"hi \\\"you\\\"\\\\ \\b\\f\\n\\r\\t\\u0001\\u001f\u{7f} é 中\"},\"eventType\":\"telegram.message\",\"occurredAt\":\"2026-10-28T15:43:07.000Z\"}";
    const ESCAPED_SHA256: &str = "578ed2e26fd764a1ba54a491b575af6f1d28b5216e1e76ae4ecbe3f6c4dd5174";
    const OTHER_SHA256: &str = "62f5ad742ffd8c7b994acd6c19dcc4d5da5ce88d9013ff254de1985ecc1a95d5";

    #[test]
    fn fingerprint_is_sha256_of_jcs_with_sorted_keys() {
        let value = input("-1001", "text", ESCAPES);
        let text = canonical_json(&value);
        assert_eq!(text, ESCAPED_JCS);
        let keys: Vec<_> = serde_json::from_str::<serde_json::Map<String, Value>>(&text)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["data", "eventType", "occurredAt"]);
        assert!(text.find("\"data\"") < text.find("\"eventType\""));
        assert!(text.find("\"eventType\"") < text.find("\"occurredAt\""));
        assert_eq!(hex(fingerprint(&value)), ESCAPED_SHA256);
        assert_eq!(
            fingerprint(&value),
            <[u8; 32]>::from(Sha256::digest(text.as_bytes()))
        );
    }
    #[test]
    fn fingerprint_data_holds_only_the_five_string_fields() {
        let parsed: Value =
            serde_json::from_str(&canonical_json(&input("42", "text", "x"))).unwrap();
        let data = parsed["data"].as_object().unwrap();
        assert_eq!(
            data.keys().collect::<Vec<_>>(),
            ["chatId", "fromId", "messageId", "messageKind", "text"]
        );
        assert!(data.values().all(Value::is_string));
        assert_eq!(parsed["eventType"], "telegram.message");
        assert_eq!(parsed.as_object().unwrap().len(), 3);
    }
    #[test]
    fn fingerprint_non_text_uses_kind_other_and_empty_text() {
        let normalized = event(&update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42, "type": "private"}, "sticker": {"file_id": "x"}}),
        ));
        assert_eq!(hex(normalized.fingerprint.unwrap()), OTHER_SHA256);
        assert!(
            canonical_json(&input("42", "other", ""))
                .contains("\"messageKind\":\"other\",\"text\":\"\"")
        );
    }
    #[test]
    fn jcs_string_escapes_follow_rfc8785_vectors() {
        for (raw, escaped) in [
            ("\"", "\\\""),
            ("\\", "\\\\"),
            ("\u{8}", "\\b"),
            ("\u{c}", "\\f"),
            ("\n", "\\n"),
            ("\r", "\\r"),
            ("\t", "\\t"),
            ("\u{0}", "\\u0000"),
            ("\u{1b}", "\\u001b"),
            ("\u{1f}", "\\u001f"),
            ("\u{7f}", "\u{7f}"),
            ("/", "/"),
            ("é中😀", "é中😀"),
        ] {
            let text = canonical_json(&input("42", "text", raw));
            assert!(
                text.contains(&format!("\"text\":\"{escaped}\"}}")),
                "{raw:?} -> {text}"
            );
        }
    }
    #[test]
    fn occurred_at_is_millisecond_rfc3339_utc_from_unix_seconds() {
        let normalized = event(&private_text("hello"));
        assert_eq!(
            normalized.occurred_at,
            Some(OffsetDateTime::from_unix_timestamp(DATE).unwrap())
        );
        let shifted = FingerprintInput {
            occurred_at: OffsetDateTime::from_unix_timestamp(DATE)
                .unwrap()
                .to_offset(UtcOffset::from_hms(8, 0, 0).unwrap()),
            ..input("42", "text", "hello")
        };
        let text = canonical_json(&shifted);
        assert!(
            text.ends_with("\"occurredAt\":\"2026-10-28T15:43:07.000Z\"}"),
            "{text}"
        );
        assert_eq!(
            canonical_json(&shifted),
            canonical_json(&input("42", "text", "hello"))
        );
    }
    #[test]
    fn normalizes_private_text_update() {
        let normalized = event(&private_text("hello"));
        assert_eq!(
            normalized,
            NormalizedEvent {
                channel: TELEGRAM,
                source_key: "1001".into(),
                event_key: "500".into(),
                event_type: "telegram.message".into(),
                occurred_at: Some(OffsetDateTime::from_unix_timestamp(DATE).unwrap()),
                private: true,
                sender: IdentityKey::parse("telegram:42"),
                chat: IdentityKey::parse("telegram:42"),
                fingerprint: Some(fingerprint(&input("42", "text", "hello"))),
                content: Content::Text {
                    text: "hello".into(),
                    command: None,
                    pair_code: None
                },
            }
        );
    }
    #[test]
    fn normalizes_non_text_message_as_other() {
        let normalized = event(&update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42, "type": "private"}, "photo": []}),
        ));
        assert_eq!(normalized.content, Content::Other);
        assert!(normalized.private && normalized.fingerprint.is_some());
    }
    #[test]
    fn group_update_normalizes_as_not_private() {
        for kind in ["group", "supergroup", "channel"] {
            let normalized = event(&update(
                json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": -100, "type": kind}, "text": "hi"}),
            ));
            assert!(!normalized.private);
            assert!(matches!(normalized.content, Content::Text { .. }));
        }
        let normalized = event(&update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42}, "text": "hi"}),
        ));
        assert!(!normalized.private);
    }
    #[test]
    fn identity_keys_are_telegram_prefixed_decimal() {
        let normalized = event(&update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 9_007_199_254_740_991_i64}, "chat": {"id": -1_001_234_567_890_i64, "type": "private"}, "text": "hi"}),
        ));
        assert_eq!(
            normalized.sender.unwrap().as_str(),
            "telegram:9007199254740991"
        );
        assert_eq!(normalized.chat.unwrap().as_str(), "telegram:-1001234567890");
        assert!(IdentityKey::parse("telegram:-1001234567890").is_some());
    }
    #[test]
    fn missing_or_non_integer_update_id_is_unparseable() {
        for value in [
            json!({"message": {}}),
            json!({"update_id": "500", "message": {}}),
            json!({"update_id": 1.5, "message": {}}),
            json!({"update_id": -1, "message": {}}),
            json!({"update_id": null}),
            json!([]),
        ] {
            assert_eq!(
                normalize(&value, "1001"),
                Normalized::Unparseable,
                "{value}"
            );
        }
    }
    #[test]
    fn update_without_message_is_unsupported() {
        for value in [
            json!({"update_id": 5}),
            json!({"update_id": 5, "edited_message": {"text": "x"}}),
            json!({"update_id": 5, "callback_query": {}}),
        ] {
            assert_eq!(normalize(&value, "1001"), Normalized::Unsupported);
        }
    }
    #[test]
    fn message_without_from_date_or_message_id_is_malformed() {
        let full = json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42, "type": "private"}, "text": "hi"});
        for missing in ["from", "date", "message_id"] {
            let mut message = full.clone();
            message.as_object_mut().unwrap().remove(missing);
            let normalized = event(&update(message));
            assert_eq!(normalized.content, Content::Malformed, "{missing}");
            assert_eq!(normalized.fingerprint, None, "{missing}");
        }
    }
    #[test]
    fn non_integer_from_id_or_chat_id_is_malformed() {
        for message in [
            json!({"message_id": 77, "date": DATE, "from": {"id": "42"}, "chat": {"id": 42, "type": "private"}, "text": "hi"}),
            json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 4.2, "type": "private"}, "text": "hi"}),
            json!({"message_id": 77, "date": DATE, "from": {}, "chat": {"id": 42, "type": "private"}, "text": "hi"}),
        ] {
            let normalized = event(&update(message));
            assert_eq!(normalized.content, Content::Malformed);
            assert_eq!(normalized.fingerprint, None);
        }
    }
    #[test]
    fn malformed_event_has_no_fingerprint_and_keeps_obtainable_identity() {
        let normalized = event(&update(
            json!({"date": DATE, "from": {"id": 42}, "chat": {"id": 43, "type": "private"}, "text": "hi"}),
        ));
        assert_eq!(normalized.content, Content::Malformed);
        assert_eq!(normalized.fingerprint, None);
        assert_eq!(normalized.sender, IdentityKey::parse("telegram:42"));
        assert_eq!(normalized.chat, IdentityKey::parse("telegram:43"));
        assert_eq!(normalized.event_key, "500");
        assert!(normalized.occurred_at.is_some());
        let normalized = event(&update(
            json!({"message_id": 1, "date": DATE, "chat": {"id": 43, "type": "private"}}),
        ));
        assert_eq!(
            (normalized.sender, normalized.chat),
            (None, IdentityKey::parse("telegram:43"))
        );
    }
    #[test]
    fn bot_sender_is_normalized_like_any_sender() {
        let human = event(&private_text("hi"));
        let mut value = private_text("hi");
        value["message"]["from"]["is_bot"] = json!(true);
        assert_eq!(event(&value), human);
    }
    #[test]
    fn text_containing_nul_is_malformed() {
        let normalized = event(&private_text("a\u{0}b"));
        assert_eq!(normalized.content, Content::Malformed);
        assert_eq!(
            normalized.fingerprint,
            Some(fingerprint(&input("42", "text", "a\u{0}b")))
        );
        assert_eq!(normalized.sender, IdentityKey::parse("telegram:42"));
        assert_eq!(normalized.chat, IdentityKey::parse("telegram:42"));
    }
    #[test]
    fn pair_pattern_requires_exactly_one_argument() {
        assert_eq!(classify("/pair X").1.as_deref(), Some("X"));
        assert_eq!(classify("/pair  ab-CD 12").1, None);
        assert_eq!(classify("/pair\tABCD-2345").1.as_deref(), Some("ABCD-2345"));
        for text in [
            "/pair",
            "/pair X Y",
            "/pair X ",
            "/pairX",
            "/PAIR X",
            "/pair@bot X",
            " /pair X",
            "/pair ",
        ] {
            assert_eq!(classify(text).1, None, "{text:?}");
        }
        assert_eq!(classify("/pair X").0, Some(Command::Pair));
        assert_eq!(classify("/pair").0, Some(Command::Pair));
    }
    #[test]
    fn classify_cancel_is_cancel_command() {
        assert_eq!(classify("/cancel"), (Some(Command::Cancel), None));
        assert_eq!(classify("/cancel now").0, Some(Command::Cancel));
    }
    #[test]
    fn classify_uses_first_word_after_leading_whitespace_trim() {
        assert_eq!(classify("  \n/help me").0, Some(Command::Help));
        assert_eq!(classify("/status\tnow").0, Some(Command::Status));
        assert_eq!(classify("hello /help").0, None);
    }
    #[test]
    fn classify_strips_at_suffix_and_everything_after() {
        assert_eq!(classify("/help@bot").0, Some(Command::Help));
        assert_eq!(classify("/status@a@b").0, Some(Command::Status));
        assert_eq!(classify("/foo@help").0, Some(Command::Unknown));
    }
    #[test]
    fn classify_start_payload_is_discarded() {
        assert_eq!(
            classify("/start deep-link-payload"),
            (Some(Command::Start), None)
        );
        assert_eq!(classify("/start@bot x").0, Some(Command::Start));
    }
    #[test]
    fn classify_is_case_insensitive() {
        for (text, command) in [
            ("/HELP", Command::Help),
            ("/Start", Command::Start),
            ("/STATUS", Command::Status),
            ("/Cancel", Command::Cancel),
            ("/PAIR", Command::Pair),
        ] {
            assert_eq!(classify(text).0, Some(command));
        }
    }
    #[test]
    fn classify_non_slash_text_is_not_a_command() {
        for text in ["hello", "help", "", "   ", "yes approve 1", "\\help"] {
            assert_eq!(classify(text), (None, None), "{text:?}");
        }
    }
    #[test]
    fn classify_unknown_slash_word_is_unknown() {
        for text in ["/foo", "/", "/helpme", "/approve 1"] {
            assert_eq!(classify(text).0, Some(Command::Unknown), "{text:?}");
        }
    }
    fn production() -> TelegramEndpoint {
        TelegramEndpoint::production(SafeDialer::new(EgressPolicy::default()))
    }
    #[test]
    fn getupdates_url_carries_closed_parameters() {
        let url = updates_url(
            &production(),
            "1001:secret",
            Some(501),
            Duration::from_secs(50),
        );
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.telegram.org"));
        assert_eq!(url.path(), "/bot1001:secret/getUpdates");
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let expected: Vec<(String, String)> = [
            ("offset", "501"),
            ("timeout", "50"),
            ("limit", "100"),
            ("allowed_updates", "[\"message\"]"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .to_vec();
        assert_eq!(pairs, expected);
        let first = updates_url(&production(), "1001:secret", None, Duration::from_secs(50));
        assert_eq!(first.query_pairs().count(), 3);
        assert!(first.query_pairs().all(|(k, _)| k != "offset"));
    }
    #[test]
    fn offset_is_max_of_stored_and_memory_plus_one() {
        let now = OffsetDateTime::now_utc();
        let recent = now - time::Duration::minutes(5);
        assert_eq!(next_offset(Some((10, recent)), Some(7), now), Some(11));
        assert_eq!(next_offset(Some((10, recent)), Some(12), now), Some(13));
        assert_eq!(next_offset(None, Some(12), now), Some(13));
        assert_eq!(next_offset(Some((10, recent)), None, now), Some(11));
        assert_eq!(next_offset(None, None, now), None);
    }
    #[test]
    fn offset_is_omitted_when_stored_row_older_than_six_days() {
        let now = OffsetDateTime::now_utc();
        let stale = now - time::Duration::days(6) - time::Duration::seconds(1);
        let edge = now - time::Duration::days(6);
        assert_eq!(next_offset(Some((10, stale)), None, now), None);
        assert_eq!(next_offset(Some((10, edge)), None, now), Some(11));
        assert_eq!(next_offset(Some((10, stale)), Some(3), now), Some(4));
    }
    #[test]
    fn status_codes_map_to_suspension_wait_or_backoff() {
        let ok = br#"{"ok":true,"result":[{"update_id":1}]}"#;
        assert_eq!(
            verdict(200, ok),
            Verdict::Updates(vec![json!({"update_id": 1})])
        );
        assert_eq!(
            verdict(200, br#"{"ok":true,"result":[]}"#),
            Verdict::Updates(Vec::new())
        );
        assert_eq!(
            verdict(401, b"{}"),
            Verdict::Suspend(Suspension::CredentialRejected)
        );
        assert_eq!(
            verdict(404, b""),
            Verdict::Suspend(Suspension::CredentialRejected)
        );
        assert_eq!(
            verdict(409, b"{}"),
            Verdict::Suspend(Suspension::WebhookConflict)
        );
        assert_eq!(
            verdict(429, br#"{"ok":false,"parameters":{"retry_after":7}}"#),
            Verdict::Wait(Duration::from_secs(7))
        );
        assert_eq!(verdict(429, b"{}"), Verdict::Backoff);
        for (status, body) in [
            (500, &b"{}"[..]),
            (502, b""),
            (400, b"{}"),
            (403, b"{}"),
            (200, b"not json"),
            (200, br#"{"ok":false}"#),
            (200, br#"{"ok":true,"result":{}}"#),
        ] {
            assert_eq!(verdict(status, body), Verdict::Backoff, "{status}");
        }
    }
    #[test]
    fn backoff_ceiling_doubles_from_one_to_sixty_seconds() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        let ceilings: Vec<u64> = (0..8)
            .map(|a| backoff_ceiling(a, min, max).as_secs())
            .collect();
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(backoff_ceiling(u32::MAX, min, max), max);
        assert_eq!(backoff_ceiling(40, min, max), max);
    }
    #[test]
    fn backoff_is_drawn_within_zero_and_ceiling() {
        let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
        for attempt in 0..10 {
            let ceiling = backoff_ceiling(attempt, min, max);
            let draws: Vec<Duration> = (0..200).map(|_| backoff(attempt, min, max)).collect();
            assert!(draws.iter().all(|d| *d <= ceiling));
            assert!(draws.iter().any(|d| *d < ceiling / 2), "attempt {attempt}");
        }
    }
    #[test]
    fn token_never_appears_in_debug_display_or_error() {
        let sentinel = "1001:token-sentinel-ZXCV";
        let secret = SecretBytes::new(sentinel.as_bytes().to_vec());
        let request = SafeHttpRequest::get(
            updates_url(&production(), sentinel, Some(1), Duration::from_secs(50)),
            SchemePolicy::HttpsOnly,
            SafeHttpBudget::new(TG_RESPONSE_MAX, Duration::from_secs(65)).unwrap(),
        )
        .unwrap();
        let row = ReceiverRow {
            binding_id: uuid::Uuid::now_v7(),
            channel: TELEGRAM,
            source_key: "1001".into(),
            credential_envelope: sentinel.into(),
        };
        let rendered = format!(
            "{secret:?} {request:?} {row:?} {:?} {} {:?} {:?} {:?}",
            ChannelError::StoreFailed,
            ChannelError::StoreFailed,
            CredentialProblem::CredentialRejected,
            Verdict::Suspend(Suspension::CredentialRejected),
            production().dialer
        );
        assert!(!rendered.contains("token-sentinel"), "{rendered}");
        for error in [
            CredentialProblem::CredentialRejected,
            CredentialProblem::WebhookConflict,
            CredentialProblem::Unreachable,
        ] {
            assert!(!format!("{error:?}").contains("sentinel"));
        }
    }
}
