use crate::{DaemonError, StatusOptions, StatusSnapshot, config};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use std::{
    collections::HashSet,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
const FRAME_MAX: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const ENGINE_PIN: &str = env!("OMB_ENGINE_PIN");

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Client {
    Cli,
    Mcp,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    r#type: String,
    token: String,
    client: Client,
    client_version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HelloOk {
    r#type: String,
    daemon_version: String,
    engine_pin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    r#type: String,
    op: String,
    args: serde_json::Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    r#type: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    data: Option<StatusSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    code: Option<String>,
}

// Validate every JSON object before typed decoding: serde_json::Value alone would collapse duplicate keys.
struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                while seq.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ()> {
    serde_json::from_slice::<UniqueJson>(bytes).map_err(|_| ())?;
    serde_json::from_slice(bytes).map_err(|_| ())
}
async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ()> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > FRAME_MAX {
        return Err(());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.map_err(|_| ())?;
    Ok(bytes)
}
async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), ()> {
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    if bytes.len() > FRAME_MAX {
        return Err(());
    }
    timeout(REQUEST_TIMEOUT, async {
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

pub(crate) struct ControlState {
    token: String,
    snapshot: StatusSnapshot,
    failures: AtomicU64,
}
impl fmt::Debug for ControlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlState")
            .field("snapshot", &self.snapshot)
            .field("token", &"[REDACTED]")
            .finish()
    }
}
impl ControlState {
    pub(crate) fn new(token: String, snapshot: StatusSnapshot) -> Arc<Self> {
        Arc::new(Self {
            token,
            snapshot,
            failures: AtomicU64::new(0),
        })
    }
    fn snapshot(&self) -> StatusSnapshot {
        let mut data = self.snapshot.clone();
        data.authentication_failures = self.failures.load(Ordering::Relaxed);
        data
    }
}
fn reject(state: &ControlState) {
    state.failures.fetch_add(1, Ordering::Relaxed);
}
pub(crate) async fn handle(mut stream: UnixStream, state: Arc<ControlState>) {
    let uid = match stream.peer_cred() {
        Ok(credentials) => credentials.uid(),
        Err(_) => {
            reject(&state);
            return;
        }
    };
    handle_with_uid(&mut stream, state, uid).await;
}
async fn handle_with_uid(stream: &mut UnixStream, state: Arc<ControlState>, observed_uid: u32) {
    if observed_uid != config::uid() {
        reject(&state);
        return;
    }
    let hello = match timeout(REQUEST_TIMEOUT, read_frame(stream)).await {
        Ok(Ok(bytes)) => decode::<Hello>(&bytes),
        _ => Err(()),
    };
    let hello = match hello {
        Ok(hello)
            if hello.r#type == "hello"
                && config::is_hex(&hello.token, 64)
                && hello.client_version.len() <= 128
                && semver::Version::parse(&hello.client_version).is_ok()
                && bool::from(hello.token.as_bytes().ct_eq(state.token.as_bytes())) =>
        {
            hello
        }
        _ => {
            reject(&state);
            return;
        }
    };
    if write_frame(
        stream,
        &HelloOk {
            r#type: "hello_ok".into(),
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            engine_pin: ENGINE_PIN.into(),
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let response = match timeout(REQUEST_TIMEOUT, read_frame(stream)).await {
        Err(_) => error_response(DaemonError::RequestTimeout),
        Ok(Err(_)) => error_response(DaemonError::InvalidRequest),
        Ok(Ok(bytes)) => match decode::<Request>(&bytes) {
            Err(_) => error_response(DaemonError::InvalidRequest),
            Ok(request) if request.r#type != "request" => {
                error_response(DaemonError::InvalidRequest)
            }
            Ok(request) if hello.client != Client::Cli || request.op != "status" => {
                error_response(DaemonError::OpNotAllowed)
            }
            Ok(request) if !request.args.as_object().is_some_and(|a| a.is_empty()) => {
                error_response(DaemonError::InvalidRequest)
            }
            Ok(_) => Response {
                r#type: "response".into(),
                ok: true,
                data: Some(state.snapshot()),
                code: None,
            },
        },
    };
    let _ = write_frame(stream, &response).await;
}
fn error_response(error: DaemonError) -> Response {
    Response {
        r#type: "response".into(),
        ok: false,
        data: None,
        code: Some(error.code().into()),
    }
}

pub async fn status(options: StatusOptions) -> Result<StatusSnapshot, DaemonError> {
    let root = &options.data_dir;
    config::validate_path(root)?;
    let token_path = root.join("run/control.token");
    match std::fs::symlink_metadata(&token_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DaemonError::DaemonNotRunning);
        }
        Err(_) => return Err(DaemonError::DataDirPermissionsInvalid),
        Ok(_) => (),
    }
    config::check(root, true)?;
    config::check(&root.join("run"), true)?;
    let token = String::from_utf8(config::read_private(&token_path, 64)?)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !config::is_hex(&token, 64) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    match std::fs::symlink_metadata(root.join("run/control.sock")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DaemonError::DaemonNotRunning);
        }
        Err(_) => return Err(DaemonError::DataDirPermissionsInvalid),
        Ok(_) => (),
    }
    config::check(&root.join("run/control.sock"), false)?;
    let mut stream = timeout(
        REQUEST_TIMEOUT,
        UnixStream::connect(root.join("run/control.sock")),
    )
    .await
    .map_err(|_| DaemonError::RequestTimeout)?
    .map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            DaemonError::DaemonNotRunning
        }
        _ => DaemonError::InternalError,
    })?;
    if stream
        .peer_cred()
        .map_err(|_| DaemonError::InternalError)?
        .uid()
        != config::uid()
    {
        return Err(DaemonError::InternalError);
    }
    write_frame(
        &mut stream,
        &Hello {
            r#type: "hello".into(),
            token,
            client: Client::Cli,
            client_version: env!("CARGO_PKG_VERSION").into(),
        },
    )
    .await
    .map_err(|_| DaemonError::InternalError)?;
    let hello: HelloOk = decode(
        &timeout(REQUEST_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| DaemonError::RequestTimeout)?
            .map_err(|_| DaemonError::InternalError)?,
    )
    .map_err(|_| DaemonError::InternalError)?;
    if hello.r#type != "hello_ok"
        || !config::is_hex(&hello.engine_pin, 40)
        || semver::Version::parse(&hello.daemon_version).is_err()
    {
        return Err(DaemonError::InternalError);
    }
    write_frame(
        &mut stream,
        &serde_json::json!({"type":"request","op":"status","args":{}}),
    )
    .await
    .map_err(|_| DaemonError::InternalError)?;
    let response: Response = decode(
        &timeout(REQUEST_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| DaemonError::RequestTimeout)?
            .map_err(|_| DaemonError::InternalError)?,
    )
    .map_err(|_| DaemonError::InternalError)?;
    if response.r#type != "response" {
        return Err(DaemonError::InternalError);
    }
    match (response.ok, response.data, response.code) {
        (true, Some(data), None)
            if data.engine_pin == hello.engine_pin
                && data.daemon_version == hello.daemon_version =>
        {
            Ok(data)
        }
        (false, None, Some(code)) => match code.as_str() {
            "request_timeout" => Err(DaemonError::RequestTimeout),
            "op_not_allowed" => Err(DaemonError::OpNotAllowed),
            "invalid_request" => Err(DaemonError::InvalidRequest),
            _ => Err(DaemonError::InternalError),
        },
        _ => Err(DaemonError::InternalError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;
    fn state() -> Arc<ControlState> {
        ControlState::new(
            "a".repeat(64),
            StatusSnapshot {
                deployment_id: "omb-local-test".into(),
                daemon_pid: std::process::id(),
                pg_pid: 123,
                pg_server_version_num: 170011,
                daemon_version: env!("CARGO_PKG_VERSION").into(),
                engine_pin: ENGINE_PIN.into(),
                authentication_failures: 0,
            },
        )
    }
    fn hello(token: &str, client: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"type":"hello","token":token,"client":client,"client_version":"0.0.0"})).unwrap()
    }
    async fn raw(stream: &mut UnixStream, bytes: &[u8]) {
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(bytes).await.unwrap();
    }
    async fn rejected(bytes: &[u8], uid: Option<u32>) -> Arc<ControlState> {
        let state = state();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            if let Some(uid) = uid {
                handle_with_uid(&mut server, shared, uid).await;
            } else {
                handle(server, shared).await;
            }
        });
        // Write before the synthetic uid rejection can close the socket.
        let _ = client.write_all(&(bytes.len() as u32).to_be_bytes()).await;
        let _ = client.write_all(bytes).await;
        let mut response = Vec::new();
        let read = timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap();
        assert!(read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
        assert!(response.is_empty());
        task.await.unwrap();
        assert_eq!(state.failures.load(Ordering::Relaxed), 1);
        state
    }
    async fn authenticated(client_kind: &str) -> (UnixStream, tokio::task::JoinHandle<()>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(handle(server, state()));
        raw(&mut client, &hello(&"a".repeat(64), client_kind)).await;
        let ack: HelloOk = decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert_eq!(ack.r#type, "hello_ok");
        (client, task)
    }
    #[tokio::test]
    async fn t10_wrong_token_returns_zero_bytes() {
        rejected(&hello(&"b".repeat(64), "cli"), None).await;
    }
    #[tokio::test]
    async fn t10_wrong_uid_is_rejected_before_hello() {
        for _ in 0..10 {
            rejected(
                &hello(&"a".repeat(64), "cli"),
                Some(config::uid().wrapping_add(1)),
            )
            .await;
        }
    }
    #[tokio::test]
    async fn t10_missing_token_file_prevents_connection() {
        let root = config::test_dir();
        config::make_dir(&root.join("run")).unwrap();
        let listener = UnixListener::bind(root.join("run/control.sock")).unwrap();
        assert_eq!(
            status(StatusOptions {
                data_dir: root.clone()
            })
            .await
            .unwrap_err(),
            DaemonError::DaemonNotRunning
        );
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        drop(listener);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn accepts_same_uid_current_token_and_one_status_request() {
        let root = config::test_dir();
        let listener = UnixListener::bind(root.join("socket")).unwrap();
        let path = root.join("socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.peer_cred().unwrap().uid(), config::uid());
            handle(stream, state()).await;
        });
        let mut client = UnixStream::connect(path).await.unwrap();
        raw(&mut client, &hello(&"a".repeat(64), "cli")).await;
        read_frame(&mut client).await.unwrap();
        let request = br#"{"type":"request","op":"status","args":{}}"#;
        raw(&mut client, request).await;
        let response: Response = decode(&read_frame(&mut client).await.unwrap()).unwrap();
        assert!(response.ok);
        assert_eq!(response.data.unwrap().authentication_failures, 0);
        let _ = client.write_all(&[0, 0, 0, 2, b'{', b'}']).await;
        let mut remaining = Vec::new();
        let _ = client.read_to_end(&mut remaining).await;
        assert!(remaining.is_empty());
        server.await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn rejects_malformed_duplicate_and_unknown_hello_fields() {
        let valid = String::from_utf8(hello(&"a".repeat(64), "cli")).unwrap();
        for text in [
            valid.replace(
                "\"type\":\"hello\"",
                "\"type\":\"hello\",\"type\":\"hello\"",
            ),
            valid.replace("\"type\":\"hello\"", "\"extra\":1,\"type\":\"hello\""),
            valid.replace("hello", "request"),
            valid.replace("\"cli\"", "\"other\""),
            valid.replace("0.0.0", "not-semver"),
            valid.replace(&"a".repeat(64), "short"),
        ] {
            rejected(text.as_bytes(), None).await;
        }
        rejected(&[0xff], None).await;
    }
    #[tokio::test]
    async fn rejects_oversized_and_truncated_frames() {
        for bytes in [
            vec![0, 0],
            vec![0, 0, 0, 3, b'{'],
            ((FRAME_MAX + 1) as u32).to_be_bytes().to_vec(),
            vec![0; 4],
        ] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            writer.write_all(&bytes).await.unwrap();
            writer.shutdown().await.unwrap();
            assert!(read_frame(&mut reader).await.is_err());
        }
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let payload = vec![b' '; FRAME_MAX];
        let task = tokio::spawn(async move {
            raw(&mut writer, &payload).await;
        });
        assert_eq!(read_frame(&mut reader).await.unwrap().len(), FRAME_MAX);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn rejects_unknown_status_arguments_and_disallowed_ops() {
        for (client, request, code) in [
            (
                "cli",
                r#"{"type":"request","op":"status","args":{"run":"x"}}"#,
                "invalid_request",
            ),
            (
                "cli",
                r#"{"type":"request","op":"status","args":{"x":1,"x":2}}"#,
                "invalid_request",
            ),
            (
                "cli",
                r#"{"type":"request","op":"pair_start","args":{}}"#,
                "op_not_allowed",
            ),
            (
                "mcp",
                r#"{"type":"request","op":"status","args":{}}"#,
                "op_not_allowed",
            ),
            (
                "mcp",
                r#"{"type":"request","op":"mcp_run_begin","args":{}}"#,
                "op_not_allowed",
            ),
        ] {
            let (mut stream, task) = authenticated(client).await;
            raw(&mut stream, request.as_bytes()).await;
            let response: Response = decode(&read_frame(&mut stream).await.unwrap()).unwrap();
            assert!(!response.ok);
            assert_eq!(response.code.as_deref(), Some(code));
            task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn authenticated_request_timeout_is_bounded() {
        let (mut stream, task) = authenticated("cli").await;
        let started = tokio::time::Instant::now();
        let response: Response = decode(
            &timeout(Duration::from_secs(12), read_frame(&mut stream))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.code.as_deref(), Some("request_timeout"));
        assert!(started.elapsed() >= REQUEST_TIMEOUT);
        task.await.unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let shared = state();
        let task = tokio::spawn(handle(server, shared.clone()));
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(12), client.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.is_empty());
        task.await.unwrap();
        assert_eq!(shared.failures.load(Ordering::Relaxed), 1);
    }
    #[tokio::test]
    async fn secrets_are_absent_from_status_errors_and_debug() {
        let shared = state();
        let rendered = format!(
            "{:?} {} {:?}",
            shared,
            serde_json::to_string(&shared.snapshot()).unwrap(),
            DaemonError::InternalError
        );
        for secret in [
            &"a".repeat(64),
            "master-secret-sentinel",
            "pg-password-sentinel",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(!rendered.contains("data_dir"));
    }
}
