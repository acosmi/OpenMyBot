//! Feishu long connection: frame codec, endpoint and handshake verdicts, event parsing, tenant
//! tokens and the receive loop. Nothing is logged: the connection URL carries a ticket and the
//! endpoint request the app secret.
use crate::{
    ChannelError, Connection, CredentialProblem, FS_FRAME_MAX, FS_WRITE_TIMEOUT, FeishuEndpoint,
    HTTP_SEND_TIMEOUT, Normalized, OMB_REPLY_TEXTS_V1, ReceiverContext, STORE_BUDGET, Task,
    backoff, classify, sender::SEND_RESPONSE_MAX,
};
use futures_util::{SinkExt, StreamExt};
use omb_store::{
    ACCEPT_TX_BUDGET, AcceptOutcome, Channel, Content, ErrorCode, IdentityKey, NormalizedEvent,
    PollGapReason, ReceiverRow, StoreError, Suspension, accept_event, close_poll_gaps,
    open_poll_gap, suspend_receiver,
};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use openbot_infra::net::safe_http::{SafeHttpBudget, SafeHttpError, SafeHttpRequest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::Ordering,
    time::Duration,
};
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use tokio::{sync::oneshot, time::Instant};
use tokio_tungstenite::tungstenite::{self, Message, protocol::WebSocketConfig};
use url::Url;

/// One `pbbp2.Frame` of the long connection (proto2), parsed once at the boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FeishuFrame {
    pub(crate) seq_id: u64,
    pub(crate) log_id: u64,
    pub(crate) service: i32,
    /// 0 is a control frame, 1 a data frame.
    pub(crate) method: i32,
    /// `Header { key = 1, value = 2 }` in arrival order, repeated keys kept.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) payload_encoding: String,
    pub(crate) payload_type: String,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) log_id_new: String,
}
impl FeishuFrame {
    /// Fields 1 to 9 in ascending order; 6, 7 and 9 are always written, 8 only when present.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in [
            (0x08, self.seq_id),
            (0x10, self.log_id),
            // A negative int32 is written sign-extended to 64 bits, ten bytes.
            (0x18, i64::from(self.service) as u64),
            (0x20, i64::from(self.method) as u64),
        ] {
            out.push(tag);
            put_varint(&mut out, value);
        }
        for (key, value) in &self.headers {
            let mut header = Vec::new();
            put_bytes(&mut header, 0x0a, key.as_bytes());
            put_bytes(&mut header, 0x12, value.as_bytes());
            put_bytes(&mut out, 0x2a, &header);
        }
        put_bytes(&mut out, 0x32, self.payload_encoding.as_bytes());
        put_bytes(&mut out, 0x3a, self.payload_type.as_bytes());
        if let Some(payload) = &self.payload {
            put_bytes(&mut out, 0x42, payload);
        }
        put_bytes(&mut out, 0x4a, self.log_id_new.as_bytes());
        out
    }
    /// Missing fields take their zero value and unknown fields are skipped; a truncated record,
    /// a length past the end, a known field of another wire type, a group, a varint over ten
    /// bytes or a string that is not UTF-8 refuses the whole frame.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let text = |bytes: &[u8]| std::str::from_utf8(bytes).ok().map(str::to_owned);
        let mut frame = FeishuFrame {
            seq_id: 0,
            log_id: 0,
            service: 0,
            method: 0,
            headers: Vec::new(),
            payload_encoding: String::new(),
            payload_type: String::new(),
            payload: None,
            log_id_new: String::new(),
        };
        let mut rest = bytes;
        while !rest.is_empty() {
            let key = take_varint(&mut rest)?;
            match (key >> 3, key & 7) {
                (1, 0) => frame.seq_id = take_varint(&mut rest)?,
                (2, 0) => frame.log_id = take_varint(&mut rest)?,
                (3, 0) => frame.service = take_varint(&mut rest)? as i32,
                (4, 0) => frame.method = take_varint(&mut rest)? as i32,
                (5, 2) => {
                    let mut header = take_bytes(&mut rest)?;
                    let (mut key, mut value) = (String::new(), String::new());
                    while !header.is_empty() {
                        let tag = take_varint(&mut header)?;
                        match (tag >> 3, tag & 7) {
                            (1, 2) => key = text(take_bytes(&mut header)?)?,
                            (2, 2) => value = text(take_bytes(&mut header)?)?,
                            (1 | 2, _) => return None,
                            (_, wire) => skip(&mut header, wire)?,
                        }
                    }
                    frame.headers.push((key, value));
                }
                (6, 2) => frame.payload_encoding = text(take_bytes(&mut rest)?)?,
                (7, 2) => frame.payload_type = text(take_bytes(&mut rest)?)?,
                (8, 2) => frame.payload = Some(take_bytes(&mut rest)?.to_vec()),
                (9, 2) => frame.log_id_new = text(take_bytes(&mut rest)?)?,
                (1..=9, _) => return None,
                (_, wire) => skip(&mut rest, wire)?,
            }
        }
        Some(frame)
    }
    /// The first header named `key`.
    pub(crate) fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
fn put_bytes(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}
fn take_varint(rest: &mut &[u8]) -> Option<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let (&byte, tail) = rest.split_first()?;
        *rest = tail;
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Some(value);
        }
    }
    None
}
fn take_bytes<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = usize::try_from(take_varint(rest)?).ok()?;
    let (bytes, tail) = rest.split_at_checked(length)?;
    *rest = tail;
    Some(bytes)
}
/// Skips an unknown field of a varint, 64-bit, length-delimited or 32-bit wire type.
fn skip(rest: &mut &[u8], wire: u64) -> Option<()> {
    match wire {
        0 => take_varint(rest).map(drop),
        1 => rest.split_off(..8).map(drop),
        2 => take_bytes(rest).map(drop),
        5 => rest.split_off(..4).map(drop),
        _ => None,
    }
}

/// The client's heartbeat on the connection's service.
pub(crate) fn ping_frame(service: i32) -> FeishuFrame {
    FeishuFrame {
        seq_id: 0,
        log_id: 0,
        service,
        method: 0,
        headers: vec![("type".to_owned(), "ping".to_owned())],
        payload_encoding: String::new(),
        payload_type: String::new(),
        payload: None,
        log_id_new: String::new(),
    }
}
/// The success response the acknowledgement carries.
pub(crate) const ACK_RESPONSE: &[u8] = br#"{"code":200,"headers":null,"data":null}"#;
/// The inbound frame written back with a `biz_rt` header of the handling milliseconds and the
/// success response as its payload.
pub(crate) fn ack_frame(inbound: &FeishuFrame, biz_rt_ms: u128) -> FeishuFrame {
    let mut ack = inbound.clone();
    ack.headers
        .push(("biz_rt".to_owned(), biz_rt_ms.to_string()));
    ack.payload = Some(ACK_RESPONSE.to_vec());
    ack
}

/// What one endpoint request means for the receiver; no variant renders the connection URL.
pub(crate) enum EndpointReply {
    Connect {
        url: Url,
        service: i32,
        ping: Option<Duration>,
    },
    ConnectFailed,
    Rejected,
}
/// Codes 1 and 1000040343 are the platform's own failures; any other non-zero code refuses the
/// credential.
pub(crate) fn endpoint_reply(result: Result<(u16, &[u8]), SafeHttpError>) -> EndpointReply {
    let Ok((200, body)) = result else {
        return EndpointReply::ConnectFailed;
    };
    let Some(body) = serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)
    else {
        return EndpointReply::ConnectFailed;
    };
    match body.get("code").and_then(Value::as_i64) {
        Some(0) => {}
        None | Some(1 | 1_000_040_343) => return EndpointReply::ConnectFailed,
        Some(_) => return EndpointReply::Rejected,
    }
    let Some(url) = body
        .pointer("/data/URL")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .and_then(|url| Url::parse(url).ok())
    else {
        return EndpointReply::ConnectFailed;
    };
    let service = url
        .query_pairs()
        .find(|(key, _)| key == "service_id")
        .and_then(|(_, value)| value.parse::<i32>().ok())
        .unwrap_or(0);
    let ping = body
        .pointer("/data/ClientConfig")
        .filter(|config| config.is_object())
        .and_then(ping_interval);
    EndpointReply::Connect { url, service, ping }
}
/// `PingInterval` seconds when it is an integer in `1..=u32::MAX`; the reconnect keys are not read.
pub(crate) fn ping_interval(config: &Value) -> Option<Duration> {
    config
        .get("PingInterval")
        .and_then(Value::as_u64)
        .filter(|seconds| (1..=u64::from(u32::MAX)).contains(seconds))
        .map(Duration::from_secs)
}
pub(crate) enum HandshakeReply {
    Rejected,
    ConnectFailed,
}
/// `Handshake-Status` decides, or the HTTP status when it is missing, unparsable or 0; only 403
/// refuses the credential.
pub(crate) fn handshake_reply(response: &http::Response<Option<Vec<u8>>>) -> HandshakeReply {
    let code = response
        .headers()
        .get("handshake-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|code| *code != 0)
        .unwrap_or_else(|| i64::from(response.status().as_u16()));
    match code {
        403 => HandshakeReply::Rejected,
        _ => HandshakeReply::ConnectFailed,
    }
}

/// Parses one event payload into the closed event shape; malformed messages keep obtainable
/// identity.
pub(crate) fn normalize(payload: &[u8], source_key: &str) -> Normalized {
    let Some(value) = serde_json::from_slice::<Value>(payload)
        .ok()
        .filter(Value::is_object)
    else {
        return Normalized::Unparseable;
    };
    if value.get("schema").and_then(Value::as_str) != Some("2.0") {
        return Normalized::Unparseable;
    }
    let Some(event_id) = value
        .pointer("/header/event_id")
        .and_then(Value::as_str)
        .filter(|id| IdentityKey::parse(id).is_some())
    else {
        return Normalized::Unparseable;
    };
    if value.pointer("/header/event_type").and_then(Value::as_str) != Some("im.message.receive_v1")
    {
        return Normalized::Unsupported;
    }
    let text = |pointer: &str| value.pointer(pointer).and_then(Value::as_str);
    let open_id = text("/event/sender/sender_id/open_id");
    let chat_id = text("/event/message/chat_id");
    let message_id = text("/event/message/message_id");
    let message_type = text("/event/message/message_type");
    let content = text("/event/message/content");
    let occurred_at = match value.pointer("/header/create_time") {
        Some(Value::String(millis))
            if (1..=19).contains(&millis.len()) && millis.bytes().all(|b| b.is_ascii_digit()) =>
        {
            millis.parse::<u64>().ok()
        }
        Some(millis) => millis.as_u64(),
        None => None,
    }
    .and_then(|millis| {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000).ok()
    });
    let fingerprint = match (
        occurred_at,
        chat_id,
        open_id,
        message_id,
        message_type,
        content,
    ) {
        (
            Some(occurred_at),
            Some(chat_id),
            Some(open_id),
            Some(message_id),
            Some(message_type),
            Some(content),
        ) => Some(fingerprint(&FeishuFingerprint {
            occurred_at,
            chat_id,
            open_id,
            message_id,
            message_type,
            content,
        })),
        _ => None,
    };
    let content = match (fingerprint, message_type, content) {
        (None, ..) => Content::Malformed,
        (Some(_), Some("text"), Some(content)) => {
            match serde_json::from_str::<Value>(content)
                .ok()
                .and_then(|content| content.get("text")?.as_str().map(str::to_owned))
            {
                Some(text) if text.contains('\0') => Content::Malformed,
                Some(text) => {
                    let (command, pair_code) = classify(&text);
                    Content::Text {
                        text,
                        command,
                        pair_code,
                    }
                }
                None => Content::Malformed,
            }
        }
        (Some(_), ..) => Content::Other,
    };
    Normalized::Event(NormalizedEvent {
        channel: Channel::Feishu,
        source_key: source_key.to_owned(),
        event_key: event_id.to_owned(),
        event_type: "feishu.im.message.receive_v1".to_owned(),
        occurred_at,
        private: text("/event/message/chat_type") == Some("p2p"),
        sender: open_id.and_then(|id| IdentityKey::parse(&format!("feishu:{id}"))),
        chat: chat_id.and_then(|id| IdentityKey::parse(&format!("feishu:{id}"))),
        fingerprint,
        content,
    })
}

pub(crate) struct FeishuFingerprint<'a> {
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) chat_id: &'a str,
    pub(crate) open_id: &'a str,
    pub(crate) message_id: &'a str,
    pub(crate) message_type: &'a str,
    /// The platform's content string as received.
    pub(crate) content: &'a str,
}
/// RFC 8785 form of the fingerprint object: every key is ASCII and written in byte order, and
/// every value is a string escaped the way JCS requires.
pub(crate) fn canonical_json(input: &FeishuFingerprint<'_>) -> String {
    let string = |value: &str| serde_json::to_string(value).unwrap_or_default();
    let occurred_at = input
        .occurred_at
        .to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_default();
    format!(
        r#"{{"data":{{"chatId":{},"content":{},"messageId":{},"messageType":{},"openId":{}}},"eventType":"feishu.im.message.receive_v1","occurredAt":{}}}"#,
        string(input.chat_id),
        string(input.content),
        string(input.message_id),
        string(input.message_type),
        string(input.open_id),
        string(&occurred_at),
    )
}
pub(crate) fn fingerprint(input: &FeishuFingerprint<'_>) -> [u8; 32] {
    Sha256::digest(canonical_json(input).as_bytes()).into()
}

/// What one tenant token request means; no variant renders the token.
pub(crate) enum TokenReply {
    Granted { token: String, expire: Duration },
    Retry(ErrorCode),
    Rejected,
}
/// Transport failures, 429, 5xx and the rate-limit code 99991400 are retried; anything else but
/// a granted token refuses the credential.
pub(crate) fn token_reply(result: Result<(u16, &[u8]), SafeHttpError>) -> TokenReply {
    let (status, body) = match result {
        Err(_) => return TokenReply::Retry(ErrorCode::Unreachable),
        Ok((429, _)) => return TokenReply::Retry(ErrorCode::RateLimited),
        Ok((500..=599, _)) => return TokenReply::Retry(ErrorCode::ServerError),
        Ok(reply) => reply,
    };
    let body = serde_json::from_slice::<Value>(body).ok();
    let field = |name: &str| body.as_ref().and_then(|body| body.get(name));
    match field("code").and_then(Value::as_i64) {
        Some(99_991_400) => TokenReply::Retry(ErrorCode::RateLimited),
        Some(0) if status == 200 => {
            let token = field("tenant_access_token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty());
            let expire = field("expire")
                .and_then(Value::as_u64)
                .filter(|seconds| *seconds > 0);
            match (token, expire) {
                (Some(token), Some(expire)) => TokenReply::Granted {
                    token: token.to_owned(),
                    expire: Duration::from_secs(expire),
                },
                _ => TokenReply::Rejected,
            }
        }
        _ => TokenReply::Rejected,
    }
}
/// One tenant token request with the app's credential.
pub(crate) async fn tenant_token(
    endpoint: &FeishuEndpoint,
    app_id: &str,
    app_secret: &str,
    timeout: Duration,
) -> TokenReply {
    let mut url = endpoint.api_base.clone();
    url.set_path("/open-apis/auth/v3/tenant_access_token/internal");
    let body = json!({"app_id": app_id, "app_secret": app_secret})
        .to_string()
        .into_bytes();
    let response = async {
        let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, timeout)?;
        endpoint
            .dialer
            .execute(SafeHttpRequest::post_json_with_scheme(
                url,
                endpoint.scheme,
                body,
                None,
                budget,
            )?)
            .await
    }
    .await;
    token_reply(
        response
            .as_ref()
            .map(|response| (response.status().as_u16(), response.body()))
            .map_err(|error| *error),
    )
}
/// Bind-time check: the app's credential must be granted a tenant token. Never changes any
/// platform setting.
pub async fn verify_feishu_credentials(
    endpoint: &FeishuEndpoint,
    app_id: &str,
    app_secret: &SecretBytes,
) -> Result<(), CredentialProblem> {
    let app_secret = std::str::from_utf8(app_secret.expose())
        .map_err(|_| CredentialProblem::CredentialRejected)?;
    match tenant_token(endpoint, app_id, app_secret, HTTP_SEND_TIMEOUT).await {
        TokenReply::Granted { .. } => Ok(()),
        TokenReply::Rejected => Err(CredentialProblem::CredentialRejected),
        TokenReply::Retry(_) => Err(CredentialProblem::Unreachable),
    }
}

/// Starts the long-connection loop of one active receiver.
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
            SecretPrincipal::Service(ServiceId::new("openmybot.feishu")),
            &receiver.credential_envelope,
        )
        .map(|opened| opened.into_secret());
    let app_secret = secret
        .as_ref()
        .ok()
        .and_then(|secret| std::str::from_utf8(secret.expose()).ok())
        .filter(|secret| !secret.is_empty());
    let Some(app_secret) = app_secret else {
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
    let endpoint = &context.endpoints.feishu;
    let timings = context.timings;
    let config = WebSocketConfig::default()
        .max_message_size(Some(FS_FRAME_MAX))
        .max_frame_size(Some(FS_FRAME_MAX));
    let mut ping = timings.fs_ping_interval;
    let mut failures = 0u32;
    loop {
        // `None` suspends the receiver; otherwise the reason of the gap before the next attempt.
        let reason = 'attempt: {
            let mut url = endpoint.api_base.clone();
            url.set_path("/callback/ws/endpoint");
            let body = json!({"AppID": receiver.source_key, "AppSecret": app_secret})
                .to_string()
                .into_bytes();
            let reply = tokio::select! {
                _ = &mut stop => return Ok(()),
                response = async {
                    let budget = SafeHttpBudget::new(SEND_RESPONSE_MAX, timings.http_send_timeout)?;
                    endpoint.dialer.execute(SafeHttpRequest::post_json_with_scheme(url, endpoint.scheme, body, None, budget)?).await
                } => endpoint_reply(response.as_ref().map(|response| (response.status().as_u16(), response.body())).map_err(|error| *error)),
            };
            let (url, service) = match reply {
                EndpointReply::Rejected => break 'attempt None,
                EndpointReply::ConnectFailed => break 'attempt Some(PollGapReason::ConnectFailed),
                EndpointReply::Connect {
                    url,
                    service,
                    ping: adopted,
                } => {
                    ping = adopted.unwrap_or(ping);
                    (url, service)
                }
            };
            // Connect, TLS and the upgrade share one deadline.
            let connected = tokio::select! {
                _ = &mut stop => return Ok(()),
                connected = tokio::time::timeout(timings.http_send_timeout, async {
                    let stream = endpoint.dialer.connect_websocket_stream(&url, endpoint.scheme, timings.http_send_timeout).await.map_err(|_| HandshakeReply::ConnectFailed)?;
                    tokio_tungstenite::client_async_with_config(url.as_str(), stream, Some(config)).await.map_err(|error| match error {
                        tungstenite::Error::Http(response) => handshake_reply(&response),
                        _ => HandshakeReply::ConnectFailed,
                    })
                }) => connected.unwrap_or(Err(HandshakeReply::ConnectFailed)),
            };
            let socket = match connected {
                Ok((socket, _)) => socket,
                Err(HandshakeReply::Rejected) => break 'attempt None,
                Err(HandshakeReply::ConnectFailed) => {
                    break 'attempt Some(PollGapReason::ConnectFailed);
                }
            };
            close_poll_gaps(
                &mut client,
                receiver.binding_id,
                Instant::now() + STORE_BUDGET,
            )
            .await
            .map_err(store)?;
            failures = 0;
            let (mut write, mut read) = socket.split();
            let mut fragments: HashMap<String, (BTreeMap<usize, Vec<u8>>, Instant)> =
                HashMap::new();
            let mut last_read = Instant::now();
            let mut last_ping = Instant::now();
            let sent = tokio::select! {
                _ = &mut stop => return Ok(()),
                sent = tokio::time::timeout(FS_WRITE_TIMEOUT, write.send(Message::binary(ping_frame(service).encode()))) => sent,
            };
            if !matches!(sent, Ok(Ok(()))) {
                break 'attempt Some(PollGapReason::StreamBroken);
            }
            loop {
                let message = tokio::select! {
                    _ = &mut stop => return Ok(()),
                    () = tokio::time::sleep_until(last_read + 2 * ping + timings.fs_read_grace) => {
                        break 'attempt Some(PollGapReason::StreamBroken);
                    }
                    () = tokio::time::sleep_until(last_ping + ping) => {
                        last_ping = Instant::now();
                        let sent = tokio::select! {
                            _ = &mut stop => return Ok(()),
                            sent = tokio::time::timeout(FS_WRITE_TIMEOUT, write.send(Message::binary(ping_frame(service).encode()))) => sent,
                        };
                        if !matches!(sent, Ok(Ok(()))) {
                            break 'attempt Some(PollGapReason::StreamBroken);
                        }
                        continue;
                    }
                    message = read.next() => message,
                };
                // Any message extends the read deadline; a Ping is answered by the library.
                let received = Instant::now();
                last_read = received;
                let frame = match message {
                    Some(Ok(Message::Binary(bytes))) => FeishuFrame::decode(&bytes),
                    Some(Ok(Message::Close(_)) | Err(_)) | None => {
                        break 'attempt Some(PollGapReason::StreamBroken);
                    }
                    Some(Ok(_)) => continue,
                };
                let Some(mut frame) = frame else {
                    context
                        .counters
                        .platform_payload_unparseable
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                match frame.method {
                    0 => {
                        if frame.header("type") == Some("pong")
                            && let Some(adopted) = frame
                                .payload
                                .as_deref()
                                .filter(|payload| !payload.is_empty())
                                .and_then(|payload| serde_json::from_slice::<Value>(payload).ok())
                                .and_then(|config| ping_interval(&config))
                        {
                            ping = adopted;
                        }
                        continue;
                    }
                    1 => {}
                    _ => continue,
                }
                fragments.retain(|_, (_, expires)| *expires > received);
                if frame.header("type") != Some("event") {
                    continue;
                }
                let sum = frame
                    .header("sum")
                    .and_then(|sum| sum.parse::<usize>().ok())
                    .unwrap_or(1);
                let payload = if sum <= 1 {
                    frame.payload.take().unwrap_or_default()
                } else {
                    let Some(seq) = frame
                        .header("seq")
                        .and_then(|seq| seq.parse::<usize>().ok())
                        .filter(|seq| *seq < sum)
                    else {
                        continue;
                    };
                    let key = frame.header("message_id").unwrap_or_default().to_owned();
                    let (parts, expires) = fragments
                        .entry(key.clone())
                        .or_insert_with(|| (BTreeMap::new(), received));
                    parts.insert(seq, frame.payload.take().unwrap_or_default());
                    *expires = received + timings.fs_fragment_ttl;
                    if parts.values().map(Vec::len).sum::<usize>() > FS_FRAME_MAX {
                        break 'attempt Some(PollGapReason::StreamBroken);
                    }
                    if parts.len() < sum {
                        continue;
                    }
                    fragments
                        .remove(&key)
                        .map(|(parts, _)| parts.into_values().flatten().collect())
                        .unwrap_or_default()
                };
                let committed = match normalize(&payload, &receiver.source_key) {
                    Normalized::Unparseable => {
                        context
                            .counters
                            .platform_payload_unparseable
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Normalized::Unsupported => {
                        context
                            .counters
                            .unsupported_update
                            .fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Normalized::Event(event) => {
                        // Dropped on stop, the acceptance has rolled back or committed; either way
                        // the redelivery is deduplicated.
                        // When both are ready, the acceptance and its post-commit steps win.
                        let accepted = tokio::select! {
                            biased;
                            accepted = accept_event(&mut client, receiver.binding_id, &event, &OMB_REPLY_TEXTS_V1, Instant::now() + ACCEPT_TX_BUDGET) => accepted,
                            _ = &mut stop => return Ok(()),
                        };
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
                            // Not committed: no acknowledgement, the platform delivers it again.
                            Err(_) => false,
                        }
                    }
                };
                // Past the budget the platform redelivers; deduplication absorbs it.
                let elapsed = received.elapsed();
                if committed && elapsed <= timings.fs_ack_budget {
                    let sent = tokio::select! {
                        _ = &mut stop => return Ok(()),
                        sent = tokio::time::timeout(FS_WRITE_TIMEOUT, write.send(Message::binary(ack_frame(&frame, elapsed.as_millis()).encode()))) => sent,
                    };
                    if !matches!(sent, Ok(Ok(()))) {
                        break 'attempt Some(PollGapReason::StreamBroken);
                    }
                }
            }
        };
        let Some(reason) = reason else {
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
        open_poll_gap(
            &mut client,
            receiver.binding_id,
            reason,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(store)?;
        let delay = backoff(failures, timings.backoff_min, timings.backoff_max);
        failures = failures.saturating_add(1);
        tokio::select! {
            _ = &mut stop => return Ok(()),
            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omb_store::Command;
    use time::macros::datetime;

    // Vectors hand-encoded from the proto2 wire format of `pbbp2.Frame`.
    const V1: &str = "08001000180720002a0c0a0474797065120470696e6732003a004a00";
    const V2: &str = "08ac021001180720012a0d0a047479706512056576656e742a100a0a6d6573736167655f696412026d312a080a0373756d1201312a080a037365711201302a0e0a0874726163655f69641202743142027b7d";
    const V3: &str = "08ac021001180720012a0d0a047479706512056576656e742a100a0a6d6573736167655f696412026d312a080a0373756d1201312a080a037365711201302a0e0a0874726163655f6964120274312a0b0a0662697a5f727412013332003a0042277b22636f6465223a3230302c2268656164657273223a6e756c6c2c2264617461223a6e756c6c7d4a00";
    const V4: &str = "780508ac021001180720012a0d0a047479706512056576656e742a100a0a6d6573736167655f696412026d312a080a0373756d1201312a080a037365711201302a0e0a0874726163655f69641202743142027b7d820101008d010102030491010102030405060708";
    const V5: &str = "0800100018ffffffffffffffffff01200032003a004a00";
    const V6: &str = "080010001800200132003a0042004a00";
    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn pairs(headers: &[(&str, &str)]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }
    fn frame(method: i32, payload: Option<Vec<u8>>) -> FeishuFrame {
        FeishuFrame {
            seq_id: 0,
            log_id: 0,
            service: 0,
            method,
            headers: Vec::new(),
            payload_encoding: String::new(),
            payload_type: String::new(),
            payload,
            log_id_new: String::new(),
        }
    }
    fn endpoint(status: u16, body: &str) -> EndpointReply {
        endpoint_reply(Ok((status, body.as_bytes())))
    }
    fn connect_failed(reply: &EndpointReply) -> bool {
        matches!(reply, EndpointReply::ConnectFailed)
    }
    fn service_of(url: &str) -> i32 {
        match endpoint(200, &json!({"code": 0, "data": {"URL": url}}).to_string()) {
            EndpointReply::Connect { service, .. } => service,
            _ => panic!("not a connect"),
        }
    }
    fn handshake(status: u16, headers: &[(&str, &str)]) -> HandshakeReply {
        let mut response = http::Response::builder().status(status);
        for (name, value) in headers {
            response = response.header(*name, *value);
        }
        handshake_reply(&response.body(None).unwrap())
    }
    fn envelope() -> Value {
        json!({
            "schema": "2.0",
            "header": {"event_id": "ev_1", "event_type": "im.message.receive_v1", "create_time": "1793260800123", "app_id": "cli_test"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_user"}, "sender_type": "user"},
                "message": {"message_id": "om_1", "chat_id": "oc_chat", "chat_type": "p2p", "message_type": "text", "content": "{\"text\":\"/status\"}"}
            }
        })
    }
    fn normalized(value: &Value) -> Normalized {
        normalize(&serde_json::to_vec(value).unwrap(), "cli_test")
    }
    fn event(value: &Value) -> NormalizedEvent {
        match normalized(value) {
            Normalized::Event(event) => event,
            other => panic!("not an event: {other:?}"),
        }
    }
    fn with(pointer: &str, value: Value) -> Value {
        let mut envelope = envelope();
        *envelope.pointer_mut(pointer).unwrap() = value;
        envelope
    }
    fn without(parent: &str, key: &str) -> Value {
        let mut envelope = envelope();
        envelope
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        envelope
    }
    fn token(status: u16, body: &str) -> TokenReply {
        token_reply(Ok((status, body.as_bytes())))
    }
    const AT: OffsetDateTime = datetime!(2026-10-29 08:00:00.123 UTC);

    #[test]
    fn ping_frame_encodes_to_vector_v1() {
        assert_eq!(hex(&ping_frame(7).encode()), V1);
        assert_eq!(FeishuFrame::decode(&bytes(V1)), Some(ping_frame(7)));
    }
    #[test]
    fn data_frame_decodes_from_vector_v2() {
        assert_eq!(bytes(V2).len(), 82);
        let frame = FeishuFrame::decode(&bytes(V2)).unwrap();
        assert_eq!(
            frame,
            FeishuFrame {
                seq_id: 300,
                log_id: 1,
                service: 7,
                method: 1,
                headers: pairs(&[
                    ("type", "event"),
                    ("message_id", "m1"),
                    ("sum", "1"),
                    ("seq", "0"),
                    ("trace_id", "t1"),
                ]),
                payload_encoding: String::new(),
                payload_type: String::new(),
                payload: Some(b"{}".to_vec()),
                log_id_new: String::new(),
            }
        );
        assert_eq!(frame.header("message_id"), Some("m1"));
        assert_eq!(frame.header("absent"), None);
    }
    #[test]
    fn ack_of_vector_v2_with_biz_rt_3_encodes_to_vector_v3() {
        let inbound = FeishuFrame::decode(&bytes(V2)).unwrap();
        let ack = ack_frame(&inbound, 3);
        assert_eq!(hex(&ack.encode()), V3);
        assert_eq!(bytes(V3).len(), 138);
        assert_eq!(ack.payload, Some(ACK_RESPONSE.to_vec()));
        assert_eq!(ACK_RESPONSE.len(), 39);
        assert_eq!(
            (ack.seq_id, ack.log_id, ack.service, ack.method),
            (300, 1, 7, 1)
        );
        let mut headers = inbound.headers.clone();
        headers.push(("biz_rt".to_owned(), "3".to_owned()));
        assert_eq!(ack.headers, headers);
    }
    #[test]
    fn decode_skips_unknown_fields_of_vector_v4() {
        assert_eq!(bytes(V4).len(), 104);
        assert_eq!(
            FeishuFrame::decode(&bytes(V4)),
            FeishuFrame::decode(&bytes(V2))
        );
        assert!(FeishuFrame::decode(&bytes(V4)).is_some());
    }
    #[test]
    fn negative_service_round_trips_as_vector_v5() {
        let frame = FeishuFrame::decode(&bytes(V5)).unwrap();
        assert_eq!(frame.service, -1);
        assert_eq!(hex(&frame.encode()), V5);
        assert_eq!(frame.encode().len(), 23);
    }
    #[test]
    fn empty_payload_is_written_as_vector_v6_and_absent_payload_is_omitted() {
        let empty = frame(1, Some(Vec::new()));
        assert_eq!(hex(&empty.encode()), V6);
        assert_eq!(empty.encode().len(), 16);
        let absent = frame(1, None);
        assert_eq!(hex(&absent.encode()), "080010001800200132003a004a00");
        assert_eq!(absent.encode().len(), 14);
        assert_eq!(FeishuFrame::decode(&empty.encode()), Some(empty));
        assert_eq!(FeishuFrame::decode(&absent.encode()), Some(absent));
    }
    #[test]
    fn decode_refuses_vectors_r1_to_r7() {
        for vector in [
            "08001000180720002a0c0a0474797065120470696e6732003a004a",
            "08002a050a",
            "0a00",
            "5b5c",
            "08ffffffffffffffffffff01",
            "2a050a01ff1200",
            "2a020800",
        ] {
            assert_eq!(FeishuFrame::decode(&bytes(vector)), None, "{vector}");
        }
    }
    #[test]
    fn decode_of_encode_keeps_header_order_and_duplicate_keys() {
        let frame = FeishuFrame {
            seq_id: 9,
            log_id: 1 << 40,
            service: 3,
            method: 1,
            headers: pairs(&[("a", "1"), ("b", "2"), ("a", "3")]),
            payload_encoding: "gzip".to_owned(),
            payload_type: "json".to_owned(),
            payload: Some(vec![0x00, 0xff, 0x7b]),
            log_id_new: "log-9".to_owned(),
        };
        assert_eq!(FeishuFrame::decode(&frame.encode()), Some(frame.clone()));
        assert_eq!(frame.header("a"), Some("1"));
    }
    #[test]
    fn endpoint_reply_maps_status_code_and_url() {
        let url = "wss://msg.example.test/ws?device_id=d&service_id=12";
        let ok = json!({"code": 0, "data": {"URL": url}}).to_string();
        assert!(connect_failed(&endpoint_reply(Err(
            SafeHttpError::ConnectFailed
        ))));
        assert!(connect_failed(&endpoint_reply(Err(
            SafeHttpError::DeadlineExceeded
        ))));
        for reply in [
            endpoint(503, &ok),
            endpoint(401, &ok),
            endpoint(200, "not json"),
            endpoint(200, r#"{"code":"0"}"#),
            endpoint(200, r#"{"code":1}"#),
            endpoint(200, r#"{"code":1000040343}"#),
            endpoint(200, r#"{"code":0}"#),
            endpoint(200, r#"{"code":0,"data":null}"#),
            endpoint(200, r#"{"code":0,"data":{"URL":""}}"#),
            endpoint(200, r#"{"code":0,"data":{"URL":"::"}}"#),
        ] {
            assert!(connect_failed(&reply));
        }
        for body in [
            r#"{"code":10003}"#,
            r#"{"code":1000040350}"#,
            r#"{"code":-1}"#,
        ] {
            assert!(
                matches!(endpoint(200, body), EndpointReply::Rejected),
                "{body}"
            );
        }
        match endpoint(200, &ok) {
            EndpointReply::Connect {
                url: connect,
                service,
                ping,
            } => {
                assert_eq!(connect.as_str(), url);
                assert_eq!(service, 12);
                assert_eq!(ping, None);
            }
            _ => panic!("not a connect"),
        }
    }
    #[test]
    fn endpoint_reply_reads_service_id_from_the_url_query() {
        let base = "wss://msg.example.test/ws?device_id=d";
        for (query, service) in [
            ("&service_id=7", 7),
            ("", 0),
            ("&service_id=x", 0),
            ("&service_id=2147483648", 0),
            ("&service_id=-3", -3),
            ("&service_id=+5", 0),
            ("&service_id=1&service_id=2", 1),
        ] {
            assert_eq!(service_of(&format!("{base}{query}")), service, "{query}");
        }
    }
    #[test]
    fn ping_interval_is_adopted_only_from_a_positive_integer() {
        assert_eq!(
            ping_interval(&json!({"PingInterval": 30})),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            ping_interval(&json!({"PingInterval": 1})),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            ping_interval(&json!({"PingInterval": 4_294_967_295u64})),
            Some(Duration::from_secs(4_294_967_295))
        );
        for config in [
            json!({"PingInterval": 4_294_967_296u64}),
            json!({"PingInterval": 0}),
            json!({"PingInterval": -5}),
            json!({"PingInterval": 1.5}),
            json!({"PingInterval": "30"}),
            json!({"PingInterval": null}),
            json!({}),
            json!({"ReconnectInterval": 5, "ReconnectNonce": 1, "ReconnectCount": 0}),
        ] {
            assert_eq!(ping_interval(&config), None, "{config}");
        }
        let url = "wss://msg.example.test/ws?device_id=d&service_id=12";
        for (config, ping) in [
            (json!({"PingInterval": 30}), Some(Duration::from_secs(30))),
            (json!(5), None),
        ] {
            let body = json!({"code": 0, "data": {"URL": url, "ClientConfig": config}});
            match endpoint(200, &body.to_string()) {
                EndpointReply::Connect { ping: adopted, .. } => assert_eq!(adopted, ping),
                _ => panic!("not a connect"),
            }
        }
    }
    #[test]
    fn handshake_reply_maps_403_to_rejected_and_the_rest_to_connect_failed() {
        for reply in [
            handshake(403, &[]),
            handshake(400, &[("Handshake-Status", "403")]),
            handshake(403, &[("Handshake-Status", "0")]),
            handshake(403, &[("Handshake-Status", "x")]),
        ] {
            assert!(matches!(reply, HandshakeReply::Rejected));
        }
        for reply in [
            handshake(
                200,
                &[
                    ("Handshake-Status", "514"),
                    ("Handshake-Autherrcode", "1000040350"),
                ],
            ),
            handshake(
                200,
                &[("Handshake-Status", "514"), ("Handshake-Autherrcode", "1")],
            ),
            handshake(500, &[]),
            handshake(401, &[]),
        ] {
            assert!(matches!(reply, HandshakeReply::ConnectFailed));
        }
    }
    #[test]
    fn private_text_event_normalizes_every_field() {
        let expected = NormalizedEvent {
            channel: Channel::Feishu,
            source_key: "cli_test".to_owned(),
            event_key: "ev_1".to_owned(),
            event_type: "feishu.im.message.receive_v1".to_owned(),
            occurred_at: Some(AT),
            private: true,
            sender: IdentityKey::parse("feishu:ou_user"),
            chat: IdentityKey::parse("feishu:oc_chat"),
            fingerprint: Some(fingerprint(&FeishuFingerprint {
                occurred_at: AT,
                chat_id: "oc_chat",
                open_id: "ou_user",
                message_id: "om_1",
                message_type: "text",
                content: "{\"text\":\"/status\"}",
            })),
            content: Content::Text {
                text: "/status".to_owned(),
                command: Some(Command::Status),
                pair_code: None,
            },
        };
        assert_eq!(normalized(&envelope()), Normalized::Event(expected.clone()));
        assert_eq!(
            normalized(&with("/header/create_time", json!(1_793_260_800_123u64))),
            Normalized::Event(expected)
        );
        let pair = event(&with(
            "/event/message/content",
            json!("{\"text\":\"/pair ABCD\"}"),
        ));
        assert!(matches!(
            pair.content,
            Content::Text { pair_code: Some(code), .. } if code == "ABCD"
        ));
    }
    #[test]
    fn schema_event_id_and_event_type_decide_unparseable_and_unsupported() {
        for payload in [b"not json".as_slice(), b"[]", b"\"x\"", b"{}"] {
            assert_eq!(normalize(payload, "cli_test"), Normalized::Unparseable);
        }
        for envelope in [
            with("/schema", json!("1.0")),
            without("", "schema"),
            with("/schema", json!(2.0)),
            without("/header", "event_id"),
            with("/header/event_id", json!("")),
            with("/header/event_id", json!("e".repeat(129))),
            with("/header/event_id", json!("ev\u{7f}1")),
            with("/header/event_id", json!(1)),
        ] {
            assert_eq!(normalized(&envelope), Normalized::Unparseable, "{envelope}");
        }
        assert_eq!(
            event(&with("/header/event_id", json!("e".repeat(128)))).event_key,
            "e".repeat(128)
        );
        for envelope in [
            with("/header/event_type", json!("im.message.message_read_v1")),
            without("/header", "event_type"),
        ] {
            assert_eq!(normalized(&envelope), Normalized::Unsupported);
        }
    }
    #[test]
    fn missing_identity_or_non_integer_create_time_is_malformed_without_fingerprint() {
        let mut envelopes = vec![
            without("/event/sender/sender_id", "open_id"),
            without("/event/message", "chat_id"),
            without("/event/message", "message_id"),
            without("/event/message", "message_type"),
            without("/event/message", "content"),
        ];
        for create_time in [
            json!("1.5"),
            json!("abc"),
            json!(""),
            json!("-1"),
            json!("12345678901234567890"),
            json!(1.5),
            json!(-1),
        ] {
            envelopes.push(with("/header/create_time", create_time));
        }
        for envelope in envelopes {
            let event = event(&envelope);
            assert_eq!(event.content, Content::Malformed, "{envelope}");
            assert_eq!(event.fingerprint, None, "{envelope}");
            assert_eq!(event.event_key, "ev_1");
        }
    }
    #[test]
    fn text_content_needs_json_with_a_string_text_without_nul() {
        for content in [
            "plain",
            r#"{"text":1}"#,
            "{}",
            r#"["x"]"#,
            r#"{"text":"a\u0000b"}"#,
        ] {
            let event = event(&with("/event/message/content", json!(content)));
            assert_eq!(event.content, Content::Malformed, "{content}");
            assert!(event.fingerprint.is_some(), "{content}");
        }
        let extra = event(&with(
            "/event/message/content",
            json!(r#"{"text":"hi","extra":1}"#),
        ));
        assert!(matches!(extra.content, Content::Text { text, .. } if text == "hi"));
    }
    #[test]
    fn non_text_group_chat_and_bot_sender_follow_the_closed_set() {
        let image = event(&with("/event/message/message_type", json!("image")));
        assert_eq!(image.content, Content::Other);
        assert!(image.fingerprint.is_some());
        assert!(!event(&with("/event/message/chat_type", json!("group"))).private);
        assert!(!event(&without("/event/message", "chat_type")).private);
        let bot = event(&with("/event/sender/sender_type", json!("bot")));
        assert_eq!(bot.sender, IdentityKey::parse("feishu:ou_user"));
        assert!(matches!(bot.content, Content::Text { .. }));
    }
    #[test]
    fn identity_keys_over_key_max_are_absent() {
        let open_id = "u".repeat(121);
        let at_max = event(&with("/event/sender/sender_id/open_id", json!(open_id)));
        assert_eq!(
            at_max.sender.as_ref().map(|key| key.as_str().len()),
            Some(128)
        );
        assert!(at_max.fingerprint.is_some());
        for (pointer, value) in [
            ("/event/sender/sender_id/open_id", "u".repeat(122)),
            ("/event/sender/sender_id/open_id", "ou\u{7f}".to_owned()),
        ] {
            let event = event(&with(pointer, json!(value)));
            assert_eq!(event.sender, None);
            assert!(event.fingerprint.is_some());
        }
        let chat = event(&with("/event/message/chat_id", json!("c".repeat(122))));
        assert_eq!(chat.chat, None);
        assert!(chat.fingerprint.is_some());
    }
    #[test]
    fn canonical_json_and_fingerprint_match_the_fixed_vector() {
        let input = FeishuFingerprint {
            occurred_at: AT,
            chat_id: "oc_chat",
            open_id: "ou_user",
            message_id: "om_1",
            message_type: "text",
            content: "{\"text\":\"你好\"}",
        };
        assert_eq!(
            canonical_json(&input),
            r#"{"data":{"chatId":"oc_chat","content":"{\"text\":\"你好\"}","messageId":"om_1","messageType":"text","openId":"ou_user"},"eventType":"feishu.im.message.receive_v1","occurredAt":"2026-10-29T08:00:00.123Z"}"#
        );
        assert_eq!(
            hex(&fingerprint(&input)),
            "dcbcf8f503062bdc046eba31fc043dad5489983c3aa6088f686f49feb91c8a21"
        );
    }
    #[test]
    fn token_reply_maps_transport_rate_limit_server_and_rejection() {
        for error in [
            SafeHttpError::ConnectFailed,
            SafeHttpError::DeadlineExceeded,
        ] {
            assert!(matches!(
                token_reply(Err(error)),
                TokenReply::Retry(ErrorCode::Unreachable)
            ));
        }
        for reply in [
            token(429, ""),
            token(400, r#"{"code":99991400}"#),
            token(200, r#"{"code":99991400}"#),
        ] {
            assert!(matches!(reply, TokenReply::Retry(ErrorCode::RateLimited)));
        }
        for status in [500, 503] {
            assert!(matches!(
                token(status, ""),
                TokenReply::Retry(ErrorCode::ServerError)
            ));
        }
        match token(
            200,
            r#"{"code":0,"tenant_access_token":"t-1","expire":7200}"#,
        ) {
            TokenReply::Granted { token, expire } => {
                assert_eq!(token, "t-1");
                assert_eq!(expire, Duration::from_secs(7200));
            }
            _ => panic!("not granted"),
        }
        for (status, body) in [
            (200, r#"{"code":10014}"#),
            (400, r#"{"code":10003}"#),
            (401, ""),
            (200, "not json"),
            (200, r#"{"code":0,"tenant_access_token":"","expire":7200}"#),
            (200, r#"{"code":0,"tenant_access_token":"t-1"}"#),
            (200, r#"{"code":0,"tenant_access_token":"t-1","expire":0}"#),
        ] {
            assert!(
                matches!(token(status, body), TokenReply::Rejected),
                "{status} {body}"
            );
        }
    }
}
