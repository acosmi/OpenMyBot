//! Hand-written HTTP/1 fake of the Telegram Bot API on a loopback listener, for tests only.
use crate::TelegramEndpoint;
use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
    time::Instant,
};
use url::Url;

/// One request as the fake received it, with the body read to its `Content-Length`.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub at: Instant,
    pub body: Vec<u8>,
}
impl Request {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}
/// A scripted answer to one call of a method.
#[derive(Clone, Debug)]
pub enum Reply {
    Respond {
        status: u16,
        body: Vec<u8>,
    },
    Delayed {
        delay: Duration,
        status: u16,
        body: Vec<u8>,
    },
    /// Reads the request and never answers.
    Hang,
    /// Reads the request, then closes the connection without an answer.
    Disconnect,
}
/// One `sendMessage` request body as the fake parsed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub path: String,
    pub chat_id: i64,
    pub text: String,
    pub has_parse_mode: bool,
}
#[derive(Default)]
struct State {
    log: Mutex<Vec<Request>>,
    scripted: Mutex<VecDeque<(String, Reply)>>,
    updates: Mutex<Vec<Value>>,
    pushed: Notify,
    /// The last `message_id` an unscripted `sendMessage` answered with.
    message_id: Mutex<i64>,
}
/// `getUpdates` answers from a queue of pushed updates with Bot API offset semantics and an
/// unscripted `sendMessage` succeeds with the next `message_id`; scripted answers take
/// precedence, one per call of their method.
pub struct FakeTelegram {
    port: u16,
    state: Arc<State>,
    task: JoinHandle<()>,
}
impl FakeTelegram {
    pub async fn start() -> Self {
        Self::start_at(0).await
    }
    pub async fn start_at(port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State::default());
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&shared)));
            }
        });
        Self { port, state, task }
    }
    /// A loopback port with no listener behind it.
    pub fn unused_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    pub fn endpoint_at(port: u16) -> TelegramEndpoint {
        TelegramEndpoint {
            api_base: Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            dialer: SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
            scheme: SchemePolicy::HttpOrHttps,
        }
    }
    pub fn endpoint(&self) -> TelegramEndpoint {
        Self::endpoint_at(self.port)
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn push_update(&self, update: Value) {
        self.state.updates.lock().unwrap().push(update);
        self.state.pushed.notify_waiters();
    }
    /// Shorthand for a scripted [`Reply::Respond`].
    pub fn script(&self, method: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.script_reply(
            method,
            Reply::Respond {
                status,
                body: body.into(),
            },
        );
    }
    pub fn script_reply(&self, method: &str, reply: Reply) {
        self.state
            .scripted
            .lock()
            .unwrap()
            .push_back((method.to_owned(), reply));
    }
    /// Every `sendMessage` request whose body parsed, in arrival order.
    pub fn sent_messages(&self) -> Vec<Sent> {
        self.calls("sendMessage")
            .into_iter()
            .filter_map(|request| {
                let body: Value = serde_json::from_slice(&request.body).ok()?;
                Some(Sent {
                    path: request.path,
                    chat_id: body.get("chat_id")?.as_i64()?,
                    text: body.get("text")?.as_str()?.to_owned(),
                    has_parse_mode: body.get("parse_mode").is_some(),
                })
            })
            .collect()
    }
    pub fn requests(&self) -> Vec<Request> {
        self.state.log.lock().unwrap().clone()
    }
    pub fn calls(&self, method: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|request| request.method == method)
            .collect()
    }
}
impl Drop for FakeTelegram {
    fn drop(&mut self) {
        self.task.abort();
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
    let length: usize = text
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0);
    while received.len() < end + length {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => received.extend_from_slice(&buffer[..read]),
        }
    }
    let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
    let url = Url::parse(&format!("http://fake{target}")).unwrap();
    let request = Request {
        method: url.path().rsplit('/').next().unwrap_or_default().to_owned(),
        path: url.path().to_owned(),
        query: url.query_pairs().into_owned().collect(),
        at: Instant::now(),
        body: received[end..end + length].to_vec(),
    };
    state.log.lock().unwrap().push(request.clone());
    let scripted = {
        let mut scripted = state.scripted.lock().unwrap();
        let index = scripted
            .iter()
            .position(|(method, _)| *method == request.method);
        index.and_then(|index| scripted.remove(index))
    };
    let (status, body) = match scripted {
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
        None if request.method == "sendMessage" => {
            let id = {
                let mut last = state.message_id.lock().unwrap();
                *last += 1;
                *last
            };
            (
                200,
                serde_json::to_vec(&json!({"ok": true, "result": {"message_id": id}})).unwrap(),
            )
        }
        None if request.method == "getUpdates" => {
            let offset: Option<u64> = request.param("offset").and_then(|v| v.parse().ok());
            let pending = |state: &State| {
                let mut updates = state.updates.lock().unwrap();
                if let Some(offset) = offset {
                    updates.retain(|update| {
                        update
                            .get("update_id")
                            .and_then(Value::as_u64)
                            .is_none_or(|id| id >= offset)
                    });
                }
                updates.clone()
            };
            let mut result = pending(&state);
            if result.is_empty() {
                let _ =
                    tokio::time::timeout(Duration::from_millis(100), state.pushed.notified()).await;
                result = pending(&state);
            }
            // Updates without an id cannot be confirmed by an offset; deliver them once.
            state
                .updates
                .lock()
                .unwrap()
                .retain(|update| update.get("update_id").is_some_and(Value::is_u64));
            (
                200,
                serde_json::to_vec(&json!({"ok": true, "result": result})).unwrap(),
            )
        }
        None => (
            404,
            br#"{"ok":false,"error_code":404,"description":"Not Found"}"#.to_vec(),
        ),
    };
    let header = format!(
        "HTTP/1.1 {status} Fake\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(header.as_bytes()).await.is_ok() {
        let _ = stream.write_all(&body).await;
    }
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sends `head` and `body` in several writes and reads the whole answer, if any.
    async fn exchange(port: u16, path: &str, body: &[u8]) -> Option<(u16, Vec<u8>)> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let head = format!(
            "POST {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let (first, second) = head.as_bytes().split_at(10);
        for chunk in [
            first,
            second,
            &body[..body.len() / 2],
            &body[body.len() / 2..],
        ] {
            stream.write_all(chunk).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.ok()?;
        let end = answer.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
        let status = String::from_utf8_lossy(&answer[..end])
            .split(' ')
            .nth(1)?
            .parse()
            .ok()?;
        Some((status, answer[end..].to_vec()))
    }
    fn message(chat_id: i64, text: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"chat_id": chat_id, "text": text})).unwrap()
    }

    #[tokio::test]
    async fn fake_records_post_body_with_chat_id_and_text() {
        let fake = FakeTelegram::start().await;
        let mut ids = Vec::new();
        for text in ["第一条消息", "second"] {
            let (status, body) = exchange(fake.port(), "/bot1:t/sendMessage", &message(42, text))
                .await
                .unwrap();
            assert_eq!(status, 200);
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["ok"], true);
            ids.push(body["result"]["message_id"].as_i64().unwrap());
        }
        assert_eq!(ids[1], ids[0] + 1);
        assert_eq!(
            fake.sent_messages(),
            [
                Sent {
                    path: "/bot1:t/sendMessage".into(),
                    chat_id: 42,
                    text: "第一条消息".into(),
                    has_parse_mode: false,
                },
                Sent {
                    path: "/bot1:t/sendMessage".into(),
                    chat_id: 42,
                    text: "second".into(),
                    has_parse_mode: false,
                },
            ]
        );
        assert_eq!(fake.calls("sendMessage")[0].body, message(42, "第一条消息"));
    }

    #[tokio::test]
    async fn fake_scripted_reply_variants_respond_delay_hang_and_disconnect() {
        let fake = FakeTelegram::start().await;
        let path = "/bot1:t/sendMessage";
        fake.script_reply(
            "sendMessage",
            Reply::Respond {
                status: 500,
                body: b"respond".to_vec(),
            },
        );
        assert_eq!(
            exchange(fake.port(), path, &message(1, "a")).await,
            Some((500, b"respond".to_vec()))
        );
        fake.script_reply(
            "sendMessage",
            Reply::Delayed {
                delay: Duration::from_millis(300),
                status: 429,
                body: b"delayed".to_vec(),
            },
        );
        let started = Instant::now();
        assert_eq!(
            exchange(fake.port(), path, &message(1, "b")).await,
            Some((429, b"delayed".to_vec()))
        );
        assert!(started.elapsed() >= Duration::from_millis(300));
        fake.script_reply("sendMessage", Reply::Hang);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(400),
                exchange(fake.port(), path, &message(1, "c"))
            )
            .await
            .is_err()
        );
        fake.script_reply("sendMessage", Reply::Disconnect);
        assert_eq!(exchange(fake.port(), path, &message(1, "d")).await, None);
        // Every scripted call was read in full before its answer.
        let texts: Vec<_> = fake
            .sent_messages()
            .into_iter()
            .map(|sent| sent.text)
            .collect();
        assert_eq!(texts, ["a", "b", "c", "d"]);
        fake.script("getMe", 401, b"unauthorized".to_vec());
        assert_eq!(
            exchange(fake.port(), "/bot1:t/getMe", b"").await,
            Some((401, b"unauthorized".to_vec()))
        );
        assert_eq!(
            exchange(fake.port(), "/bot1:t/getMe", b"").await.unwrap().0,
            404
        );
    }
}
