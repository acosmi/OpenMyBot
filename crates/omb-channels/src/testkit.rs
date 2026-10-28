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

/// One request line as the fake received it.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub at: Instant,
}
impl Request {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}
#[derive(Default)]
struct State {
    log: Mutex<Vec<Request>>,
    scripted: Mutex<VecDeque<(String, u16, Vec<u8>)>>,
    updates: Mutex<Vec<Value>>,
    pushed: Notify,
}
/// `getUpdates` answers from a queue of pushed updates with Bot API offset semantics; scripted
/// answers take precedence, one per call of their method.
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
    pub fn script(&self, method: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.state
            .scripted
            .lock()
            .unwrap()
            .push_back((method.to_owned(), status, body.into()));
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
    let mut head = Vec::new();
    let mut buffer = [0; 4096];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
    let url = Url::parse(&format!("http://fake{target}")).unwrap();
    let request = Request {
        method: url.path().rsplit('/').next().unwrap_or_default().to_owned(),
        path: url.path().to_owned(),
        query: url.query_pairs().into_owned().collect(),
        at: Instant::now(),
    };
    state.log.lock().unwrap().push(request.clone());
    let scripted = {
        let mut scripted = state.scripted.lock().unwrap();
        let index = scripted
            .iter()
            .position(|(method, _, _)| *method == request.method);
        index.and_then(|index| scripted.remove(index))
    };
    let (status, body) = match scripted {
        Some((_, status, body)) => (status, body),
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
