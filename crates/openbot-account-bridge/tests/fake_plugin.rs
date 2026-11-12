use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Stdio;
use std::thread;

use openbot_account_bridge::error::ErrorCode;
use openbot_account_bridge::fake_plugin;
use openbot_account_bridge::frame::{decode, encode, read_frame, write_frame};
use openbot_account_bridge::protocol::{
    Connector, EgressProxy, HostFrame, InferOutcome, PluginFrame, ProtocolName, ProxyCredential,
};
use openbot_account_bridge::{HELLO_TIMEOUT, PROTOCOL};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, duplex};
use tokio::process::Command;
use tokio::time::timeout;

async fn next<R: AsyncRead + Unpin>(stdout: &mut R) -> PluginFrame {
    let payload = read_frame(stdout).await.unwrap().expect("plugin frame");
    decode(&payload).unwrap()
}

#[tokio::test]
async fn fake_plugin_completes_hello_infer_and_shutdown() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fake-account-bridge-plugin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let connectors = vec![Connector::Openai, Connector::Kimi];
    let hello = HostFrame::Hello {
        protocol: ProtocolName,
        plugin_version: "0.0.0-fixture.1".to_owned(),
        connectors: connectors.clone(),
        egress_proxy: EgressProxy {
            url: "http://127.0.0.1:43129".to_owned(),
            credential: ProxyCredential("fixture-proxy-password".to_owned()),
        },
    };
    write_frame(&mut stdin, &encode(&hello).unwrap())
        .await
        .unwrap();
    let hello_ok = timeout(HELLO_TIMEOUT, next(&mut stdout)).await.unwrap();
    assert_eq!(
        hello_ok,
        PluginFrame::HelloOk {
            protocol: ProtocolName,
            plugin_version: "0.0.0-fixture.1".to_owned(),
            connectors,
        }
    );
    assert_eq!(
        serde_json::to_value(&hello_ok).unwrap()["protocol"],
        PROTOCOL
    );

    let Value::Object(body) = json!({
        "model": "fixture-model",
        "max_tokens": 64,
        "stream": true,
        "messages": [{ "role": "user", "content": "Hello" }],
    }) else {
        unreachable!()
    };
    let infer = HostFrame::Infer {
        request_id: "req-run-7".to_owned(),
        connection_id: "00000000-0000-4000-8000-00000000c001".to_owned(),
        credential_generation: 3,
        body,
    };
    write_frame(&mut stdin, &encode(&infer).unwrap())
        .await
        .unwrap();

    let mut event_types = Vec::new();
    let outcome = loop {
        match next(&mut stdout).await {
            PluginFrame::InferEvent { request_id, event } => {
                assert_eq!(request_id, "req-run-7");
                event_types.push(event["type"].as_str().unwrap().to_owned());
            }
            PluginFrame::InferEnd {
                request_id,
                outcome,
            } => {
                assert_eq!(request_id, "req-run-7");
                break outcome;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    };
    assert_eq!(
        event_types,
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop",
        ]
    );
    assert!(matches!(
        outcome,
        InferOutcome::Completed { usage } if usage.input_tokens == 9 && usage.output_tokens == 2
    ));

    write_frame(&mut stdin, &encode(&HostFrame::Shutdown {}).unwrap())
        .await
        .unwrap();
    assert!(child.wait().await.unwrap().success());
    assert!(read_frame(&mut stdout).await.unwrap().is_none());
}

/// A one-shot proxy on loopback that answers `status_line` and returns the request head it saw.
fn proxy(status_line: &'static str) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            head.push(line.trim_end().to_owned());
        }
        write!(&stream, "{status_line}\r\n\r\n").unwrap();
        head
    });
    (url, handle)
}

/// Drives the library entry through `hello` and `models` with the egress probe aimed at a vendor.
async fn models_through_proxy(url: String) -> PluginFrame {
    let (mut host, plugin) = duplex(64 * 1024);
    let (mut plugin_in, mut plugin_out) = tokio::io::split(plugin);
    let task = tokio::spawn(async move {
        fake_plugin::run(
            &mut plugin_in,
            &mut plugin_out,
            Some("vendor.example.invalid:443"),
        )
        .await
    });
    let hello = HostFrame::Hello {
        protocol: ProtocolName,
        plugin_version: "0.0.0-fixture.1".to_owned(),
        connectors: vec![Connector::Openai],
        egress_proxy: EgressProxy {
            url,
            credential: ProxyCredential("fixture-proxy-password".to_owned()),
        },
    };
    write_frame(&mut host, &encode(&hello).unwrap())
        .await
        .unwrap();
    assert!(matches!(next(&mut host).await, PluginFrame::HelloOk { .. }));
    let models = HostFrame::Models {
        request_id: "req-models-1".to_owned(),
        connection_id: "00000000-0000-4000-8000-00000000c001".to_owned(),
        credential_generation: 3,
    };
    write_frame(&mut host, &encode(&models).unwrap())
        .await
        .unwrap();
    let reply = next(&mut host).await;
    write_frame(&mut host, &encode(&HostFrame::Shutdown {}).unwrap())
        .await
        .unwrap();
    task.await.unwrap().unwrap();
    reply
}

const EXPECTED_HEAD: [&str; 3] = [
    "CONNECT vendor.example.invalid:443 HTTP/1.1",
    "Host: vendor.example.invalid:443",
    // Basic base64("account-bridge:fixture-proxy-password")
    "Proxy-Authorization: Basic YWNjb3VudC1icmlkZ2U6Zml4dHVyZS1wcm94eS1wYXNzd29yZA==",
];

#[tokio::test]
async fn egress_probe_tunnels_through_the_hello_proxy() {
    let (url, seen) = proxy("HTTP/1.1 200 Connection established");
    let reply = models_through_proxy(url).await;
    assert_eq!(seen.join().unwrap(), EXPECTED_HEAD);
    assert!(matches!(
        reply,
        PluginFrame::ModelsResult { request_id, models } if request_id == "req-models-1" && models.len() == 2
    ));
}

#[tokio::test]
async fn egress_probe_reports_the_proxy_refusal() {
    let (url, seen) = proxy("HTTP/1.1 407 Proxy Authentication Required");
    let reply = models_through_proxy(url).await;
    assert_eq!(seen.join().unwrap(), EXPECTED_HEAD);
    assert_eq!(
        reply,
        PluginFrame::Error {
            request_id: Some("req-models-1".to_owned()),
            code: ErrorCode::UpstreamUnavailable,
            message: "egress refused: HTTP/1.1 407 Proxy Authentication Required".to_owned(),
        }
    );
}
