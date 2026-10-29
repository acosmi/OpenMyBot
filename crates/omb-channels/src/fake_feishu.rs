//! Loopback fake of the Feishu open platform, for tests only.
use crate::{
    FeishuEndpoint,
    feishu::{ACK_RESPONSE, FeishuFrame, ping_frame},
    testkit::{Reply, Request},
};
use futures_util::{SinkExt, StreamExt};
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::Instant,
};
use tokio_tungstenite::tungstenite::{
    Message,
    handshake::server::{ErrorResponse, Request as Upgrade, Response},
};
use url::Url;

const TOKEN_PATH: &str = "/open-apis/auth/v3/tenant_access_token/internal";
const ENDPOINT_PATH: &str = "/callback/ws/endpoint";
const MESSAGES_PATH: &str = "/open-apis/im/v1/messages";

/// How the WebSocket listener answers one upgrade request.
#[derive(Clone, Debug)]
pub enum Handshake {
    Accept,
    /// Answers with `status`, the given handshake headers and `Handshake-Msg: fake`.
    Reject {
        status: u16,
        handshake_status: Option<String>,
        autherrcode: Option<String>,
    },
    /// Accepts the TCP connection and never answers.
    Hang,
}
/// One `im/v1/messages` request as the fake parsed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeishuSent {
    pub query: Vec<(String, String)>,
    pub authorization: Option<String>,
    pub receive_id: String,
    pub msg_type: String,
    pub content: String,
    pub uuid: String,
    /// Keys of the body object.
    pub keys: usize,
}
/// One data frame written back by the client; `valid` when it is a pushed frame with exactly one
/// trailing decimal `biz_rt` header and the success response as payload.
#[derive(Clone, Debug)]
pub struct Ack {
    pub message_id: String,
    pub seq: Option<String>,
    pub valid: bool,
    pub at: Instant,
}
/// One client ping; `valid` when every field but `service` has its ping value.
#[derive(Clone, Debug)]
pub struct Ping {
    pub service: i32,
    pub valid: bool,
    pub at: Instant,
}
#[derive(Default)]
struct State {
    ws_port: u16,
    log: Mutex<Vec<(Request, Option<String>)>>,
    scripted: Mutex<VecDeque<(String, Reply)>>,
    handshake_script: Mutex<VecDeque<Handshake>>,
    client_config: Mutex<Option<Value>>,
    ws_url: Mutex<Option<String>>,
    pong_config: Mutex<Option<Value>>,
    silent: Mutex<bool>,
    handshakes: Mutex<Vec<String>>,
    acks: Mutex<Vec<Ack>>,
    pings: Mutex<Vec<Ping>>,
    dropped: Mutex<usize>,
    /// Every frame written to a connection, for checking acknowledgements.
    pushed: Mutex<Vec<FeishuFrame>>,
    /// The current connection's id and its outgoing queue.
    connection: Mutex<Option<(u64, mpsc::UnboundedSender<Message>)>>,
    connections: Mutex<u64>,
    tokens: Mutex<u64>,
    messages: Mutex<u64>,
    frames: Mutex<u64>,
}
/// Loopback fake of the Feishu open platform: hand-written HTTP/1 for the token, endpoint and
/// message paths and a WebSocket listener speaking the pbbp2 frames of `crate::feishu` (the same
/// codec, no second implementation). One connection at a time; a new one replaces the old.
pub struct FakeFeishu {
    http_port: u16,
    state: Arc<State>,
    http: JoinHandle<()>,
    ws: JoinHandle<()>,
}
impl FakeFeishu {
    pub async fn start() -> Self {
        let http = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let ws = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let http_port = http.local_addr().unwrap().port();
        let state = Arc::new(State {
            ws_port: ws.local_addr().unwrap().port(),
            ..State::default()
        });
        let shared = Arc::clone(&state);
        let http = tokio::spawn(async move {
            while let Ok((stream, _)) = http.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&shared)));
            }
        });
        let shared = Arc::clone(&state);
        let ws = tokio::spawn(async move {
            while let Ok((stream, _)) = ws.accept().await {
                tokio::spawn(connect(stream, Arc::clone(&shared)));
            }
        });
        Self {
            http_port,
            state,
            http,
            ws,
        }
    }
    pub fn endpoint_at(port: u16) -> FeishuEndpoint {
        FeishuEndpoint {
            api_base: Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            dialer: SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
            scheme: SchemePolicy::HttpOrHttps,
        }
    }
    pub fn endpoint(&self) -> FeishuEndpoint {
        Self::endpoint_at(self.http_port)
    }
    /// Queued per path; each POST of that path takes one before the default answer.
    pub fn script(&self, path: &str, reply: Reply) {
        self.state
            .scripted
            .lock()
            .unwrap()
            .push_back((path.to_owned(), reply));
    }
    /// Queued; each upgrade request takes one, and an empty queue accepts.
    pub fn script_handshake(&self, handshake: Handshake) {
        self.state
            .handshake_script
            .lock()
            .unwrap()
            .push_back(handshake);
    }
    pub fn set_client_config(&self, config: Option<Value>) {
        *self.state.client_config.lock().unwrap() = config;
    }
    pub fn set_ws_url(&self, url: Option<String>) {
        *self.state.ws_url.lock().unwrap() = url;
    }
    pub fn set_pong_config(&self, config: Option<Value>) {
        *self.state.pong_config.lock().unwrap() = config;
    }
    /// While silent, pings are recorded and never answered.
    pub fn set_silent(&self, silent: bool) {
        *self.state.silent.lock().unwrap() = silent;
    }
    /// One encoded single-fragment data frame of type `kind`.
    pub fn data_frame(&self, kind: &str, payload: &Value) -> Vec<u8> {
        let seq_id = self.next_frame();
        let message_id = message_id(payload, seq_id);
        frame(
            seq_id,
            kind,
            &message_id,
            1,
            0,
            serde_json::to_vec(payload).unwrap(),
        )
        .encode()
    }
    pub fn event_frame(&self, payload: &Value) -> Vec<u8> {
        self.data_frame("event", payload)
    }
    /// The payload cut into `parts` fragments of one message id: each but the last holds
    /// `len / parts` bytes.
    pub fn fragment_frames(&self, payload: &Value, parts: usize) -> Vec<Vec<u8>> {
        let bytes = serde_json::to_vec(payload).unwrap();
        let size = bytes.len() / parts;
        let mut message = None;
        (0..parts)
            .map(|seq| {
                let seq_id = self.next_frame();
                let message_id = message
                    .get_or_insert_with(|| message_id(payload, seq_id))
                    .clone();
                let end = if seq + 1 == parts {
                    bytes.len()
                } else {
                    (seq + 1) * size
                };
                frame(
                    seq_id,
                    "event",
                    &message_id,
                    parts,
                    seq,
                    bytes[seq * size..end].to_vec(),
                )
                .encode()
            })
            .collect()
    }
    /// Writes a Binary message to the current connection; without one the frame is dropped.
    pub fn push_frame(&self, frame: Vec<u8>) -> bool {
        // Recorded first: an acknowledgement may come back before this returns.
        self.state
            .pushed
            .lock()
            .unwrap()
            .extend(FeishuFrame::decode(&frame));
        self.push(Message::binary(frame))
    }
    pub fn push_event(&self, payload: &Value) -> bool {
        self.push_frame(self.event_frame(payload))
    }
    pub fn push_text(&self, text: &str) -> bool {
        self.push(Message::text(text))
    }
    /// Closes the current connection with a Close message.
    pub fn disconnect(&self) {
        if let Some((_, connection)) = self.state.connection.lock().unwrap().take() {
            let _ = connection.send(Message::Close(None));
        }
    }
    pub fn connected(&self) -> bool {
        self.state.connection.lock().unwrap().is_some()
    }
    /// Path and query of every accepted upgrade.
    pub fn handshakes(&self) -> Vec<String> {
        self.state.handshakes.lock().unwrap().clone()
    }
    pub fn acks(&self) -> Vec<Ack> {
        self.state.acks.lock().unwrap().clone()
    }
    pub fn pings(&self) -> Vec<Ping> {
        self.state.pings.lock().unwrap().clone()
    }
    pub fn dropped(&self) -> usize {
        *self.state.dropped.lock().unwrap()
    }
    /// Every HTTP request with its body, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.state
            .log
            .lock()
            .unwrap()
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }
    pub fn calls(&self, path: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|request| request.path == path)
            .collect()
    }
    /// Every message request whose body parsed, in arrival order.
    pub fn sent_messages(&self) -> Vec<FeishuSent> {
        self.state
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|(request, _)| request.path == MESSAGES_PATH)
            .filter_map(|(request, authorization)| {
                let body: Value = serde_json::from_slice(&request.body).ok()?;
                let text = |key: &str| Some(body.get(key)?.as_str()?.to_owned());
                Some(FeishuSent {
                    query: request.query.clone(),
                    authorization: authorization.clone(),
                    receive_id: text("receive_id")?,
                    msg_type: text("msg_type")?,
                    content: text("content")?,
                    uuid: text("uuid")?,
                    keys: body.as_object()?.len(),
                })
            })
            .collect()
    }
    fn push(&self, message: Message) -> bool {
        let sent = self
            .state
            .connection
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(_, connection)| connection.send(message).is_ok());
        if !sent {
            *self.state.dropped.lock().unwrap() += 1;
        }
        sent
    }
    fn next_frame(&self) -> u64 {
        let mut frames = self.state.frames.lock().unwrap();
        *frames += 1;
        *frames
    }
}
impl Drop for FakeFeishu {
    fn drop(&mut self) {
        self.http.abort();
        self.ws.abort();
    }
}

/// The payload's `header.event_id`, or `m-<seq_id>` without one.
fn message_id(payload: &Value, seq_id: u64) -> String {
    payload
        .pointer("/header/event_id")
        .and_then(Value::as_str)
        .map_or_else(|| format!("m-{seq_id}"), str::to_owned)
}
fn frame(
    seq_id: u64,
    kind: &str,
    message_id: &str,
    sum: usize,
    seq: usize,
    payload: Vec<u8>,
) -> FeishuFrame {
    FeishuFrame {
        seq_id,
        log_id: seq_id,
        service: 7,
        method: 1,
        headers: [
            ("type", kind.to_owned()),
            ("message_id", message_id.to_owned()),
            ("sum", sum.to_string()),
            ("seq", seq.to_string()),
            ("trace_id", format!("trace-{seq_id}")),
        ]
        .map(|(key, value)| (key.to_owned(), value))
        .to_vec(),
        payload_encoding: String::new(),
        payload_type: String::new(),
        payload: Some(payload),
        log_id_new: String::new(),
    }
}

async fn serve(mut stream: TcpStream, state: Arc<State>) {
    let mut received = Vec::new();
    let mut buffer = [0; 4096];
    let end = loop {
        if let Some(at) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
    };
    let text = String::from_utf8_lossy(&received[..end]).into_owned();
    let header = |wanted: &str| {
        text.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.trim().to_owned())
    };
    let length: usize = header("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    while received.len() < end + length {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
    }
    let mut line = text.split(' ');
    let verb = line.next().unwrap_or_default().to_owned();
    let target = line.next().unwrap_or_default().to_owned();
    let url = Url::parse(&format!("http://fake{target}")).unwrap();
    let request = Request {
        method: verb,
        path: url.path().to_owned(),
        query: url.query_pairs().into_owned().collect(),
        at: Instant::now(),
        body: received[end..end + length].to_vec(),
    };
    state
        .log
        .lock()
        .unwrap()
        .push((request.clone(), header("authorization")));
    // Every path is a POST; any other verb is refused without using a scripted answer.
    let refused = request.method != "POST";
    let scripted = {
        let mut scripted = state.scripted.lock().unwrap();
        let index = scripted
            .iter()
            .position(|(path, _)| !refused && *path == request.path);
        index.and_then(|index| scripted.remove(index))
    };
    let next = |counter: &Mutex<u64>| {
        let mut counter = counter.lock().unwrap();
        *counter += 1;
        *counter
    };
    let (status, body) = match scripted {
        None if refused => (405, json!({"code": 405, "msg": "method not allowed"}).to_string().into_bytes()),
        Some((_, Reply::Respond { status, body })) => (status, body),
        Some((
            _,
            Reply::Delayed {
                delay,
                status,
                body,
            },
        )) => {
            tokio::time::sleep(delay).await;
            (status, body)
        }
        Some((_, Reply::Hang)) => std::future::pending().await,
        Some((_, Reply::Disconnect)) => return,
        None if request.path == TOKEN_PATH => (
            200,
            json!({"code": 0, "msg": "ok", "tenant_access_token": format!("t-fake-{}", next(&state.tokens)), "expire": 7200}).to_string().into_bytes(),
        ),
        None if request.path == ENDPOINT_PATH => {
            let url = state.ws_url.lock().unwrap().clone().unwrap_or_else(|| {
                format!(
                    "ws://127.0.0.1:{}/ws?device_id=fake-device&service_id=7",
                    state.ws_port
                )
            });
            let mut data = json!({"URL": url});
            if let Some(config) = state.client_config.lock().unwrap().clone() {
                data["ClientConfig"] = config;
            }
            (200, json!({"code": 0, "msg": "ok", "data": data}).to_string().into_bytes())
        }
        None if request.path == MESSAGES_PATH => (
            200,
            json!({"code": 0, "msg": "success", "data": {"message_id": format!("om_{}", next(&state.messages))}}).to_string().into_bytes(),
        ),
        None => (404, json!({"code": 404, "msg": "not found"}).to_string().into_bytes()),
    };
    let head = format!(
        "HTTP/1.1 {status} Fake\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).await.is_ok() {
        let _ = stream.write_all(&body).await;
    }
    let _ = stream.shutdown().await;
}

#[allow(
    clippy::result_large_err,
    reason = "the upgrade callback's error type is tungstenite's own response"
)]
async fn connect(mut stream: TcpStream, state: Arc<State>) {
    let handshake = state
        .handshake_script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(Handshake::Accept);
    if let Handshake::Hang = handshake {
        let mut buffer = [0; 1024];
        while matches!(stream.read(&mut buffer).await, Ok(read) if read > 0) {}
        return;
    }
    let mut target = String::new();
    let upgraded =
        tokio_tungstenite::accept_hdr_async(stream, |request: &Upgrade, response: Response| {
            match handshake {
                Handshake::Reject {
                    status,
                    handshake_status,
                    autherrcode,
                } => {
                    let mut rejection = http::Response::builder()
                        .status(status)
                        .header("Handshake-Msg", "fake");
                    for (name, value) in [
                        ("Handshake-Status", handshake_status),
                        ("Handshake-Autherrcode", autherrcode),
                    ] {
                        if let Some(value) = value {
                            rejection = rejection.header(name, value);
                        }
                    }
                    Err::<Response, ErrorResponse>(rejection.body(None).unwrap())
                }
                _ => {
                    target = request
                        .uri()
                        .path_and_query()
                        .map(|target| target.as_str().to_owned())
                        .unwrap_or_default();
                    Ok(response)
                }
            }
        })
        .await;
    let Ok(socket) = upgraded else {
        return;
    };
    let (mut write, mut read) = socket.split();
    let (sender, mut outgoing) = mpsc::unbounded_channel();
    let id = {
        let mut connections = state.connections.lock().unwrap();
        *connections += 1;
        *connections
    };
    // The replaced connection is closed; the handshake is listed only once pushes reach this one.
    if let Some((_, previous)) = state.connection.lock().unwrap().replace((id, sender)) {
        let _ = previous.send(Message::Close(None));
    }
    state.handshakes.lock().unwrap().push(target);
    loop {
        tokio::select! {
            message = outgoing.recv() => match message {
                Some(Message::Close(frame)) => {
                    let _ = write.send(Message::Close(frame)).await;
                    break;
                }
                Some(message) => {
                    if write.send(message).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            incoming = read.next() => {
                let bytes = match incoming {
                    Some(Ok(Message::Binary(bytes))) => bytes,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) | None => break,
                };
                let Some(frame) = FeishuFrame::decode(&bytes) else {
                    continue;
                };
                let at = Instant::now();
                if frame.method == 0 && frame.header("type") == Some("ping") {
                    state.pings.lock().unwrap().push(Ping {
                        service: frame.service,
                        valid: frame == ping_frame(frame.service),
                        at,
                    });
                    if *state.silent.lock().unwrap() {
                        continue;
                    }
                    let mut pong = ping_frame(frame.service);
                    pong.headers = vec![("type".to_owned(), "pong".to_owned())];
                    pong.payload = state
                        .pong_config
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map(|config| serde_json::to_vec(config).unwrap());
                    if write.send(Message::binary(pong.encode())).await.is_err() {
                        break;
                    }
                } else if frame.method == 1 {
                    let valid = match frame.headers.split_last() {
                        Some(((key, value), headers))
                            if key == "biz_rt"
                                && !value.is_empty()
                                && value.bytes().all(|b| b.is_ascii_digit()) =>
                        {
                            let echoed = FeishuFrame {
                                headers: headers.to_vec(),
                                payload: None,
                                ..frame.clone()
                            };
                            frame.payload.as_deref() == Some(ACK_RESPONSE)
                                && state.pushed.lock().unwrap().iter().any(|pushed| {
                                    FeishuFrame {
                                        payload: None,
                                        ..pushed.clone()
                                    } == echoed
                                })
                        }
                        _ => false,
                    };
                    state.acks.lock().unwrap().push(Ack {
                        message_id: frame.header("message_id").unwrap_or_default().to_owned(),
                        seq: frame.header("seq").map(str::to_owned),
                        valid,
                        at,
                    });
                }
            }
        }
    }
    let mut connection = state.connection.lock().unwrap();
    if connection
        .as_ref()
        .is_some_and(|(current, _)| *current == id)
    {
        *connection = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feishu::ack_frame;
    use openbot_infra::net::safe_http::{
        AuthorizationValue, SafeHttpBudget, SafeHttpRequest, SafeStream,
    };
    use std::time::Duration;
    use tokio_tungstenite::{WebSocketStream, tungstenite};

    fn budget() -> SafeHttpBudget {
        SafeHttpBudget::new(64 * 1024, Duration::from_secs(5)).unwrap()
    }
    fn url(fake: &FakeFeishu, path: &str) -> Url {
        let mut url = fake.endpoint().api_base;
        url.set_path(path);
        url
    }
    async fn post(
        fake: &FakeFeishu,
        url: Url,
        body: &Value,
        authorization: Option<&str>,
    ) -> (u16, Value) {
        let endpoint = fake.endpoint();
        let response = endpoint
            .dialer
            .execute(
                SafeHttpRequest::post_json_with_scheme(
                    url,
                    endpoint.scheme,
                    body.to_string().into_bytes(),
                    authorization.map(|value| AuthorizationValue::parse(value).unwrap()),
                    budget(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        (
            response.status().as_u16(),
            serde_json::from_slice(response.body()).unwrap(),
        )
    }
    fn ws_url(fake: &FakeFeishu) -> Url {
        Url::parse(&format!(
            "ws://127.0.0.1:{}/ws?device_id=fake-device&service_id=7",
            fake.state.ws_port
        ))
        .unwrap()
    }
    async fn upgrade(fake: &FakeFeishu) -> Result<WebSocketStream<SafeStream>, tungstenite::Error> {
        let endpoint = fake.endpoint();
        let url = ws_url(fake);
        let stream = endpoint
            .dialer
            .connect_websocket_stream(&url, endpoint.scheme, Duration::from_secs(5))
            .await
            .unwrap();
        tokio_tungstenite::client_async_with_config(url.as_str(), stream, None)
            .await
            .map(|(socket, _)| socket)
    }
    async fn until(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn next_frame(socket: &mut WebSocketStream<SafeStream>) -> FeishuFrame {
        match socket.next().await {
            Some(Ok(Message::Binary(bytes))) => FeishuFrame::decode(&bytes).unwrap(),
            other => panic!("not a binary frame: {other:?}"),
        }
    }
    fn event(event_id: &str) -> Value {
        json!({"schema": "2.0", "header": {"event_id": event_id}, "event": {"text": "x".repeat(50)}})
    }

    #[tokio::test]
    async fn fake_http_defaults_answer_token_endpoint_and_messages() {
        let fake = FakeFeishu::start().await;
        let credential = json!({"app_id": "cli_test", "app_secret": "s"});
        for expected in ["t-fake-1", "t-fake-2"] {
            let (status, body) = post(&fake, url(&fake, TOKEN_PATH), &credential, None).await;
            assert_eq!(status, 200);
            assert_eq!(body["tenant_access_token"], expected);
            assert_eq!(body["expire"], 7200);
        }
        let (status, body) = post(&fake, url(&fake, ENDPOINT_PATH), &json!({}), None).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"]["URL"], ws_url(&fake).as_str());
        assert!(body["data"].get("ClientConfig").is_none());
        fake.set_client_config(Some(json!({"PingInterval": 3})));
        let (_, body) = post(&fake, url(&fake, ENDPOINT_PATH), &json!({}), None).await;
        assert_eq!(body["data"]["ClientConfig"], json!({"PingInterval": 3}));
        fake.set_ws_url(Some("ws://127.0.0.1:9/elsewhere".to_owned()));
        let (_, body) = post(&fake, url(&fake, ENDPOINT_PATH), &json!({}), None).await;
        assert_eq!(body["data"]["URL"], "ws://127.0.0.1:9/elsewhere");
        let mut messages = url(&fake, MESSAGES_PATH);
        messages.set_query(Some("receive_id_type=chat_id"));
        let message = json!({"receive_id": "oc_1", "msg_type": "text", "content": "{\"text\":\"hi\"}", "uuid": "u-1"});
        let (status, body) = post(&fake, messages, &message, Some("Bearer t-fake-1")).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"]["message_id"], "om_1");
        assert_eq!(
            fake.sent_messages()[0],
            FeishuSent {
                query: vec![("receive_id_type".to_owned(), "chat_id".to_owned())],
                authorization: Some("Bearer t-fake-1".to_owned()),
                receive_id: "oc_1".to_owned(),
                msg_type: "text".to_owned(),
                content: "{\"text\":\"hi\"}".to_owned(),
                uuid: "u-1".to_owned(),
                keys: 4,
            }
        );
        let (status, _) = post(&fake, url(&fake, "/unknown"), &json!({}), None).await;
        assert_eq!(status, 404);
        fake.script(
            TOKEN_PATH,
            Reply::Respond {
                status: 400,
                body: br#"{"code":10014}"#.to_vec(),
            },
        );
        let endpoint = fake.endpoint();
        let response = endpoint
            .dialer
            .execute(
                SafeHttpRequest::get(url(&fake, TOKEN_PATH), endpoint.scheme, budget()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 405);
        assert_eq!(fake.calls(TOKEN_PATH).last().unwrap().method, "GET");
        let (status, body) = post(&fake, url(&fake, TOKEN_PATH), &credential, None).await;
        assert_eq!((status, &body["code"]), (400, &json!(10014)));
        let (status, body) = post(&fake, url(&fake, TOKEN_PATH), &credential, None).await;
        assert_eq!(
            (status, &body["tenant_access_token"]),
            (200, &json!("t-fake-3"))
        );
        assert_eq!(
            fake.calls(TOKEN_PATH)[0].body,
            credential.to_string().into_bytes()
        );
    }

    #[tokio::test]
    async fn fake_answers_pings_with_pongs_and_validates_acks() {
        let fake = FakeFeishu::start().await;
        let mut socket = upgrade(&fake).await.unwrap();
        until("the connection", || fake.connected()).await;
        assert_eq!(
            fake.handshakes(),
            ["/ws?device_id=fake-device&service_id=7"]
        );
        socket
            .send(Message::binary(ping_frame(7).encode()))
            .await
            .unwrap();
        let pong = next_frame(&mut socket).await;
        assert_eq!(
            (
                pong.method,
                pong.service,
                pong.header("type"),
                pong.payload.as_deref()
            ),
            (0, 7, Some("pong"), None)
        );
        assert!(fake.pings()[0].valid);
        assert_eq!(fake.pings()[0].service, 7);
        fake.set_pong_config(Some(json!({"PingInterval": 9})));
        socket
            .send(Message::binary(ping_frame(7).encode()))
            .await
            .unwrap();
        assert_eq!(
            next_frame(&mut socket).await.payload,
            Some(serde_json::to_vec(&json!({"PingInterval": 9})).unwrap())
        );
        fake.set_silent(true);
        socket
            .send(Message::binary(ping_frame(7).encode()))
            .await
            .unwrap();
        until("the third ping", || fake.pings().len() == 3).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.next())
                .await
                .is_err()
        );
        assert!(fake.push_event(&event("ev_1")));
        let pushed = next_frame(&mut socket).await;
        assert_eq!(
            (
                pushed.header("type"),
                pushed.header("sum"),
                pushed.header("seq"),
                pushed.header("message_id"),
            ),
            (Some("event"), Some("1"), Some("0"), Some("ev_1"))
        );
        socket
            .send(Message::binary(ack_frame(&pushed, 5).encode()))
            .await
            .unwrap();
        until("the ack", || fake.acks().len() == 1).await;
        assert!(fake.acks()[0].valid);
        assert_eq!(fake.acks()[0].message_id, "ev_1");
        let mut wrong = ack_frame(&pushed, 5);
        wrong.payload = Some(br#"{"code":200}"#.to_vec());
        socket.send(Message::binary(wrong.encode())).await.unwrap();
        until("the second ack", || fake.acks().len() == 2).await;
        assert!(!fake.acks()[1].valid);
    }

    #[tokio::test]
    async fn fake_scripted_handshakes_reject_hang_and_then_accept() {
        let fake = FakeFeishu::start().await;
        fake.script_handshake(Handshake::Reject {
            status: 403,
            handshake_status: Some("403".to_owned()),
            autherrcode: None,
        });
        fake.script_handshake(Handshake::Reject {
            status: 500,
            handshake_status: Some("514".to_owned()),
            autherrcode: Some("1000040350".to_owned()),
        });
        fake.script_handshake(Handshake::Hang);
        let header = |response: &http::Response<Option<Vec<u8>>>, name: &str| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        match upgrade(&fake).await {
            Err(tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 403);
                assert_eq!(
                    header(&response, "Handshake-Status").as_deref(),
                    Some("403")
                );
            }
            other => panic!("not a rejection: {:?}", other.map(|_| ())),
        }
        match upgrade(&fake).await {
            Err(tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 500);
                assert_eq!(
                    header(&response, "Handshake-Status").as_deref(),
                    Some("514")
                );
                assert_eq!(
                    header(&response, "Handshake-Autherrcode").as_deref(),
                    Some("1000040350")
                );
                assert_eq!(header(&response, "Handshake-Msg").as_deref(), Some("fake"));
            }
            other => panic!("not a rejection: {:?}", other.map(|_| ())),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(300), upgrade(&fake))
                .await
                .is_err()
        );
        assert!(fake.handshakes().is_empty());
        let mut first = upgrade(&fake).await.unwrap();
        until("the first connection", || fake.handshakes().len() == 1).await;
        assert!(fake.connected());
        let _second = upgrade(&fake).await.unwrap();
        until("the second connection", || fake.handshakes().len() == 2).await;
        assert!(matches!(
            first.next().await,
            Some(Ok(Message::Close(_))) | None
        ));
        assert!(fake.connected());
    }

    #[tokio::test]
    async fn fake_drops_frames_pushed_without_a_connection() {
        let fake = FakeFeishu::start().await;
        assert!(!fake.push_event(&event("ev_lost")));
        assert_eq!(fake.dropped(), 1);
        let mut socket = upgrade(&fake).await.unwrap();
        until("the connection", || fake.connected()).await;
        assert!(fake.push_event(&event("ev_kept")));
        assert_eq!(
            next_frame(&mut socket).await.header("message_id"),
            Some("ev_kept")
        );
        fake.disconnect();
        assert!(!fake.connected());
        assert!(!fake.push_event(&event("ev_after")));
        assert_eq!(fake.dropped(), 2);
        let payload = event("ev_frag");
        let frames: Vec<FeishuFrame> = fake
            .fragment_frames(&payload, 3)
            .iter()
            .map(|bytes| FeishuFrame::decode(bytes).unwrap())
            .collect();
        assert_eq!(frames.len(), 3);
        for (seq, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header("message_id"), Some("ev_frag"));
            assert_eq!(frame.header("sum"), Some("3"));
            assert_eq!(frame.header("seq"), Some(seq.to_string().as_str()));
        }
        let joined: Vec<u8> = frames
            .into_iter()
            .flat_map(|frame| frame.payload.unwrap())
            .collect();
        assert_eq!(joined, serde_json::to_vec(&payload).unwrap());
    }
}
