//! Telegram Bot API plugin: boundary parsing, offsets, the long-poll receive loop and sending.
//! Nothing is logged: every request URL carries the bot token.
use crate::{
    BACKOFF_MAX, BACKOFF_MIN, HTTP_SEND_TIMEOUT, TG_HTTP_MARGIN, TG_OFFSET_STALE, TG_POLL_LIMIT,
    TG_POLL_TIMEOUT, TG_RESPONSE_MAX, TelegramEndpoint,
    sender::{SEND_RESPONSE_MAX, chat_id, classify, request_body},
    utc_millis,
};
use omb_channel_sdk::{
    plugin::{ChannelPlugin, HelloInfo, Outbox, SendArgs, SendOutcome, StartArgs},
    protocol::{
        EventFrame, EventKind, FailureClass, GapReason, SendErrorCode, SkipCounter, SuspendReason,
        VerifyFailure,
    },
};
use openbot_infra::net::safe_http::{SafeHttpBudget, SafeHttpRequest};
use serde_json::Value;
use std::{collections::BTreeMap, hash::BuildHasher, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::task::JoinHandle;
use url::Url;

/// One `getUpdates` element (or Feishu event payload) after boundary parsing.
#[derive(Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one value per update, consumed at once; the event is not boxed"
)]
pub(crate) enum Normalized {
    Event(EventFrame),
    /// The update carries no `message`.
    Unsupported,
    /// `update_id` is missing or not an integer.
    Unparseable,
}

/// Parses one update into an event frame; a message without sender, chat, date or message id, or
/// with a text holding NUL, is malformed and keeps the identity it has.
pub(crate) fn normalize(update: &Value) -> Normalized {
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
    let (kind, data) = match (from_id, chat_id, occurred_at, message_id) {
        (Some(from_id), Some(chat_id), Some(_), Some(message_id)) => (
            match text {
                Some(text) if text.contains('\0') => EventKind::Malformed,
                Some(_) => EventKind::Text,
                None => EventKind::Other,
            },
            BTreeMap::from(
                [
                    ("chatId", chat_id.to_string()),
                    ("fromId", from_id.to_string()),
                    ("messageId", message_id.to_string()),
                    (
                        "messageKind",
                        if text.is_some() { "text" } else { "other" }.to_owned(),
                    ),
                    ("text", text.unwrap_or_default().to_owned()),
                ]
                .map(|(key, value)| (key.to_owned(), value)),
            ),
        ),
        _ => (EventKind::Malformed, BTreeMap::new()),
    };
    Normalized::Event(EventFrame {
        event_key: update_id.to_string(),
        event_type: "telegram.message".to_owned(),
        occurred_at: occurred_at.map(utc_millis),
        private: message.pointer("/chat/type").and_then(Value::as_str) == Some("private"),
        sender_key: from_id.map(|id| format!("telegram:{id}")),
        chat_key: chat_id.map(|id| format!("telegram:{id}")),
        kind,
        text: text.unwrap_or_default().to_owned(),
        data,
    })
}

/// Next `getUpdates` offset: one past the larger of the stored and in-memory update ids; a stored
/// cursor older than `TG_OFFSET_STALE` does not count.
pub(crate) fn next_offset(
    stored: Option<(u64, OffsetDateTime)>,
    memory: Option<u64>,
    now: OffsetDateTime,
) -> Option<u64> {
    let stored = stored
        .filter(|(_, accepted_at)| now - *accepted_at <= TG_OFFSET_STALE)
        .map(|(update_id, _)| update_id);
    stored.max(memory).map(|update_id| update_id + 1)
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
    Suspend(SuspendReason),
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
        401 | 404 => Verdict::Suspend(SuspendReason::CredentialRejected),
        409 => Verdict::Suspend(SuspendReason::WebhookConflict),
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

/// One read-only Bot API call; 401 and 404 refuse the token, anything else but a result is
/// unreachable.
async fn call(
    endpoint: &TelegramEndpoint,
    token: &str,
    method: &str,
) -> Result<Value, VerifyFailure> {
    let response = async {
        let budget = SafeHttpBudget::new(TG_RESPONSE_MAX, TG_HTTP_MARGIN)?;
        endpoint
            .dialer
            .execute(SafeHttpRequest::get(
                method_url(endpoint, token, method),
                endpoint.scheme,
                budget,
            )?)
            .await
    }
    .await
    .map_err(|_| VerifyFailure::Unreachable)?;
    match response.status().as_u16() {
        200 => serde_json::from_slice::<Value>(response.body())
            .ok()
            .and_then(|mut body| body.get_mut("result").map(Value::take))
            .ok_or(VerifyFailure::Unreachable),
        401 | 404 => Err(VerifyFailure::CredentialRejected),
        _ => Err(VerifyFailure::Unreachable),
    }
}

/// The Telegram plugin. The token of the latest `start` stays in memory for sending after `stop`.
pub struct TelegramPlugin {
    endpoint: TelegramEndpoint,
    credential: Option<String>,
    task: Option<JoinHandle<()>>,
}
impl TelegramPlugin {
    pub fn new(endpoint: TelegramEndpoint) -> Self {
        Self {
            endpoint,
            credential: None,
            task: None,
        }
    }
}
impl ChannelPlugin for TelegramPlugin {
    fn hello_ok(&self) -> HelloInfo {
        HelloInfo {
            plugin_name: "openmybot-channel-telegram".to_owned(),
            plugin_version: env!("CARGO_PKG_VERSION").to_owned(),
            channel_kind: "telegram".to_owned(),
        }
    }

    /// `getMe` must answer the bot id (and match `source_key` when one is given) and
    /// `getWebhookInfo` no webhook. Never changes any Bot setting.
    async fn verify(
        &mut self,
        credential: String,
        source_key: Option<String>,
    ) -> Result<String, VerifyFailure> {
        let shaped = credential.split_once(':').is_some_and(|(bot_id, _)| {
            !bot_id.is_empty() && bot_id.bytes().all(|b| b.is_ascii_digit())
        });
        if !shaped {
            return Err(VerifyFailure::Malformed);
        }
        let id = call(&self.endpoint, &credential, "getMe")
            .await?
            .get("id")
            .and_then(Value::as_i64)
            .map(|id| id.to_string())
            .filter(|id| source_key.as_ref().is_none_or(|key| key == id))
            .ok_or(VerifyFailure::CredentialRejected)?;
        let webhook = call(&self.endpoint, &credential, "getWebhookInfo").await?;
        if webhook
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.is_empty())
        {
            return Err(VerifyFailure::WebhookConflict);
        }
        Ok(id)
    }

    async fn start(&mut self, start: StartArgs, outbox: Outbox) {
        self.credential = Some(start.credential.clone());
        let endpoint = self.endpoint.clone();
        let token = start.credential;
        // A cursor that does not parse counts as none.
        let stored = start
            .last_event_key
            .and_then(|key| key.parse::<u64>().ok())
            .zip(
                start
                    .last_accepted_at
                    .and_then(|at| OffsetDateTime::parse(&at, &Rfc3339).ok()),
            );
        self.task = Some(tokio::spawn(async move {
            let mut memory: Option<u64> = None;
            let mut failures = 0u32;
            let mut gap_open = false;
            loop {
                let url = updates_url(
                    &endpoint,
                    &token,
                    next_offset(stored, memory, OffsetDateTime::now_utc()),
                    TG_POLL_TIMEOUT,
                );
                let response = async {
                    let budget =
                        SafeHttpBudget::new(TG_RESPONSE_MAX, TG_POLL_TIMEOUT + TG_HTTP_MARGIN)?;
                    endpoint
                        .dialer
                        .execute(SafeHttpRequest::get(url, endpoint.scheme, budget)?)
                        .await
                }
                .await;
                match response.map(|response| verdict(response.status().as_u16(), response.body()))
                {
                    Ok(Verdict::Updates(mut updates)) => {
                        if gap_open {
                            outbox.gap_closed().await;
                            gap_open = false;
                        }
                        failures = 0;
                        updates
                            .sort_by_key(|update| update.get("update_id").and_then(Value::as_u64));
                        for update in &updates {
                            match normalize(update) {
                                Normalized::Unparseable => {
                                    outbox
                                        .skipped(SkipCounter::PlatformPayloadUnparseable)
                                        .await;
                                }
                                Normalized::Unsupported => {
                                    outbox.skipped(SkipCounter::UnsupportedUpdate).await;
                                }
                                // Not confirmed: the rest of the batch is fetched again from here.
                                Normalized::Event(event) => {
                                    if outbox.emit(event).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            memory = memory.max(update.get("update_id").and_then(Value::as_u64));
                        }
                    }
                    Ok(Verdict::Suspend(reason)) => {
                        outbox.suspend(reason).await;
                        return;
                    }
                    Ok(Verdict::Wait(delay)) => tokio::time::sleep(delay).await,
                    Err(_) | Ok(Verdict::Backoff) => {
                        if !gap_open {
                            outbox.gap(GapReason::ConnectFailed).await;
                            gap_open = true;
                        }
                        // Full jitter: uniform below `BACKOFF_MIN` doubled per failure, capped.
                        let ceiling = BACKOFF_MIN
                            .checked_mul(2u32.saturating_pow(failures))
                            .unwrap_or(BACKOFF_MAX)
                            .min(BACKOFF_MAX);
                        let random =
                            std::collections::hash_map::RandomState::new().hash_one(failures);
                        tokio::time::sleep(Duration::from_nanos(
                            random % (ceiling.as_nanos() as u64 + 1),
                        ))
                        .await;
                        failures = failures.saturating_add(1);
                    }
                }
            }
        }));
    }

    async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }

    async fn send(&mut self, send: SendArgs) -> SendOutcome {
        let failed = |class, code| SendOutcome::Failed {
            class,
            code,
            retry_after_ms: None,
        };
        let Some(token) = &self.credential else {
            return failed(FailureClass::Final, SendErrorCode::ReceiverInactive);
        };
        let Some(chat) = chat_id(&send.chat_key) else {
            return failed(FailureClass::Final, SendErrorCode::ClientError);
        };
        let url = method_url(&self.endpoint, token, "sendMessage");
        let response = async {
            let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, HTTP_SEND_TIMEOUT)?;
            self.endpoint
                .dialer
                .execute(SafeHttpRequest::post_json_with_scheme(
                    url,
                    self.endpoint.scheme,
                    request_body(chat, &send.body),
                    None,
                    budget,
                )?)
                .await
        }
        .await;
        classify(
            response
                .as_ref()
                .map(|response| (response.status().as_u16(), response.body()))
                .map_err(|error| *error),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_domain::vault::SecretBytes;
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
    fn event(value: &Value) -> EventFrame {
        match normalize(value) {
            Normalized::Event(event) => event,
            other => panic!("not an event: {other:?}"),
        }
    }
    fn data(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn occurred_at_is_millisecond_rfc3339_utc_from_unix_seconds() {
        assert_eq!(
            event(&private_text("hello")).occurred_at.as_deref(),
            Some("2026-10-28T15:43:07.000Z")
        );
    }
    #[test]
    fn normalizes_private_text_update() {
        assert_eq!(
            event(&private_text("hello")),
            EventFrame {
                event_key: "500".into(),
                event_type: "telegram.message".into(),
                occurred_at: Some("2026-10-28T15:43:07.000Z".into()),
                private: true,
                sender_key: Some("telegram:42".into()),
                chat_key: Some("telegram:42".into()),
                kind: EventKind::Text,
                text: "hello".into(),
                data: data(&[
                    ("chatId", "42"),
                    ("fromId", "42"),
                    ("messageId", "77"),
                    ("messageKind", "text"),
                    ("text", "hello"),
                ]),
            }
        );
    }
    #[test]
    fn normalizes_non_text_message_as_other() {
        let normalized = event(&update(
            json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42, "type": "private"}, "photo": []}),
        ));
        assert_eq!(normalized.kind, EventKind::Other);
        assert!(normalized.private);
        assert_eq!(normalized.data["messageKind"], "other");
        assert_eq!(normalized.data["text"], "");
        assert_eq!(normalized.text, "");
    }
    #[test]
    fn group_update_normalizes_as_not_private() {
        for kind in ["group", "supergroup", "channel"] {
            let normalized = event(&update(
                json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": -100, "type": kind}, "text": "hi"}),
            ));
            assert!(!normalized.private);
            assert_eq!(normalized.kind, EventKind::Text);
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
            normalized.sender_key.as_deref(),
            Some("telegram:9007199254740991")
        );
        assert_eq!(
            normalized.chat_key.as_deref(),
            Some("telegram:-1001234567890")
        );
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
            assert_eq!(normalize(&value), Normalized::Unparseable, "{value}");
        }
    }
    #[test]
    fn update_without_message_is_unsupported() {
        for value in [
            json!({"update_id": 5}),
            json!({"update_id": 5, "edited_message": {"text": "x"}}),
            json!({"update_id": 5, "callback_query": {}}),
        ] {
            assert_eq!(normalize(&value), Normalized::Unsupported);
        }
    }
    #[test]
    fn message_without_from_date_or_message_id_is_malformed() {
        let full = json!({"message_id": 77, "date": DATE, "from": {"id": 42}, "chat": {"id": 42, "type": "private"}, "text": "hi"});
        for missing in ["from", "date", "message_id"] {
            let mut message = full.clone();
            message.as_object_mut().unwrap().remove(missing);
            let normalized = event(&update(message));
            assert_eq!(normalized.kind, EventKind::Malformed, "{missing}");
            assert!(normalized.data.is_empty(), "{missing}");
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
            assert_eq!(normalized.kind, EventKind::Malformed);
            assert!(normalized.data.is_empty());
        }
    }
    #[test]
    fn malformed_event_keeps_obtainable_identity() {
        let normalized = event(&update(
            json!({"date": DATE, "from": {"id": 42}, "chat": {"id": 43, "type": "private"}, "text": "hi"}),
        ));
        assert_eq!(normalized.kind, EventKind::Malformed);
        assert_eq!(normalized.sender_key.as_deref(), Some("telegram:42"));
        assert_eq!(normalized.chat_key.as_deref(), Some("telegram:43"));
        assert_eq!(normalized.event_key, "500");
        assert!(normalized.occurred_at.is_some());
        let normalized = event(&update(
            json!({"message_id": 1, "date": DATE, "chat": {"id": 43, "type": "private"}}),
        ));
        assert_eq!(
            (normalized.sender_key, normalized.chat_key.as_deref()),
            (None, Some("telegram:43"))
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
        assert_eq!(normalized.kind, EventKind::Malformed);
        assert_eq!(normalized.data["text"], "a\u{0}b");
        assert_eq!(normalized.sender_key.as_deref(), Some("telegram:42"));
        assert_eq!(normalized.chat_key.as_deref(), Some("telegram:42"));
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
            Verdict::Suspend(SuspendReason::CredentialRejected)
        );
        assert_eq!(
            verdict(404, b""),
            Verdict::Suspend(SuspendReason::CredentialRejected)
        );
        assert_eq!(
            verdict(409, b"{}"),
            Verdict::Suspend(SuspendReason::WebhookConflict)
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
    fn token_never_appears_in_debug_display_or_error() {
        let sentinel = "1001:token-sentinel-ZXCV";
        let secret = SecretBytes::new(sentinel.as_bytes().to_vec());
        let request = SafeHttpRequest::get(
            updates_url(&production(), sentinel, Some(1), Duration::from_secs(50)),
            SchemePolicy::HttpsOnly,
            SafeHttpBudget::new(TG_RESPONSE_MAX, Duration::from_secs(65)).unwrap(),
        )
        .unwrap();
        let rendered = format!(
            "{secret:?} {request:?} {:?} {:?} {:?}",
            VerifyFailure::CredentialRejected,
            Verdict::Suspend(SuspendReason::CredentialRejected),
            production().dialer
        );
        assert!(!rendered.contains("token-sentinel"), "{rendered}");
    }
}
