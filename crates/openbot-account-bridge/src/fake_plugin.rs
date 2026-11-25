//! Fake account bridge plugin for tests. [`run`] answers every request with the matching reply
//! fixture of `fixtures/account-bridge/protocol-1/`, its `requestId` (and `connectionId`, where the
//! reply has one) replaced by the request's:
//!   hello           -> hello_ok echoing the protocol, plugin version and connectors
//!   login_start     -> login_progress (browser)
//!   login_poll      -> login_result
//!   refresh         -> refresh_result
//!   revoke          -> revoke_result (revoked)
//!   models          -> models_result, after the egress probe when one is configured
//!   usage           -> usage_result
//!   infer           -> the six infer_event fixtures in order, then infer_end (completed)
//!   login_cancel, credential_load, infer_cancel -> no reply
//!   shutdown        -> return
//! A frame that fails to decode is answered by an unattributed `error` and returned as the error.
//!
//! Egress probe: with `egress_probe = Some("host:port")`, each `models` request first opens one
//! HTTP CONNECT tunnel to that target through `hello.egressProxy`, authorized as Basic
//! [`EGRESS_PROXY_USER`]:credential. A `200` answer leads to the normal `models_result`; any other
//! answer, or a failed connection, to `error{code: upstream_unavailable}` whose message carries the
//! proxy's status line.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::EGRESS_PROXY_USER;
use crate::frame::{FrameError, decode, encode, read_frame, write_frame};
use crate::protocol::{EgressProxy, HostFrame, PluginFrame};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            "../../../fixtures/account-bridge/protocol-1/plugin-to-host/",
            $name
        ))
    };
}

const INFER_EVENTS: [&str; 6] = [
    fixture!("infer_event-1-message_start.json"),
    fixture!("infer_event-2-content_block_start.json"),
    fixture!("infer_event-3-content_block_delta.json"),
    fixture!("infer_event-4-content_block_stop.json"),
    fixture!("infer_event-5-message_delta.json"),
    fixture!("infer_event-6-message_stop.json"),
];

/// The fixture as JSON with `requestId`, and `connectionId` when given, set to the request's.
fn reply(fixture: &str, request_id: &str, connection_id: Option<&str>) -> Vec<u8> {
    let mut value: Value = serde_json::from_str(fixture).expect("fixture is JSON");
    value["requestId"] = Value::from(request_id);
    if let Some(connection_id) = connection_id {
        value["connectionId"] = Value::from(connection_id);
    }
    serde_json::to_vec(&value).expect("fixture encodes")
}

/// Runs the fake plugin loop until `shutdown` or the end of `input`.
pub async fn run<R, W>(
    input: &mut R,
    output: &mut W,
    egress_probe: Option<&str>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut proxy: Option<EgressProxy> = None;
    while let Some(payload) = read_frame(input).await? {
        let frame = match decode::<HostFrame>(&payload) {
            Ok(frame) => frame,
            Err(error) => {
                let refusal = json!({
                    "type": "error",
                    "code": "invalid_request",
                    "message": error.to_string(),
                });
                write_frame(output, &encode(&refusal)?).await?;
                return Err(error);
            }
        };
        let replies = match frame {
            HostFrame::Hello {
                protocol,
                plugin_version,
                connectors,
                egress_proxy,
            } => {
                proxy = Some(egress_proxy);
                vec![encode(&PluginFrame::HelloOk {
                    protocol,
                    plugin_version,
                    connectors,
                })?]
            }
            HostFrame::LoginStart { request_id, .. } => {
                vec![reply(
                    fixture!("login_progress-browser.json"),
                    &request_id,
                    None,
                )]
            }
            HostFrame::LoginPoll { request_id, .. } => {
                vec![reply(fixture!("login_result.json"), &request_id, None)]
            }
            HostFrame::Refresh {
                request_id,
                connection_id,
                ..
            } => vec![reply(
                fixture!("refresh_result.json"),
                &request_id,
                Some(&connection_id),
            )],
            HostFrame::Revoke {
                request_id,
                connection_id,
                ..
            } => vec![reply(
                fixture!("revoke_result-revoked.json"),
                &request_id,
                Some(&connection_id),
            )],
            HostFrame::Models { request_id, .. } => {
                let refused = match (egress_probe, &proxy) {
                    (Some(target), Some(proxy)) => {
                        let target = target.to_owned();
                        let proxy = proxy.clone();
                        tokio::task::spawn_blocking(move || connect_probe(&proxy, &target))
                            .await
                            .expect("probe task")
                            .err()
                    }
                    _ => None,
                };
                match refused {
                    None => vec![reply(fixture!("models_result.json"), &request_id, None)],
                    Some(status) => vec![encode(&json!({
                        "type": "error",
                        "requestId": request_id,
                        "code": "upstream_unavailable",
                        "message": format!("egress refused: {status}"),
                    }))?],
                }
            }
            HostFrame::Usage { request_id, .. } => {
                vec![reply(fixture!("usage_result.json"), &request_id, None)]
            }
            HostFrame::Infer { request_id, .. } => INFER_EVENTS
                .into_iter()
                .chain([fixture!("infer_end-completed.json")])
                .map(|fixture| reply(fixture, &request_id, None))
                .collect(),
            HostFrame::LoginCancel { .. }
            | HostFrame::CredentialLoad { .. }
            | HostFrame::InferCancel { .. } => Vec::new(),
            HostFrame::Shutdown {} => return Ok(()),
        };
        for payload in replies {
            write_frame(output, &payload).await?;
        }
    }
    Ok(())
}

/// One CONNECT through the proxy; `Err` carries the proxy's status line or the I/O failure.
fn connect_probe(proxy: &EgressProxy, target: &str) -> Result<(), String> {
    let address = proxy.url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
    let authorization = base64(format!("{EGRESS_PROXY_USER}:{}", proxy.credential.0).as_bytes());
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {authorization}\r\n\r\n"
    )
    .map_err(|error| error.to_string())?;
    let mut status = String::new();
    BufReader::new(stream)
        .read_line(&mut status)
        .map_err(|error| error.to_string())?;
    let status = status.trim_end().to_owned();
    if status.split(' ').nth(1) == Some("200") {
        Ok(())
    } else {
        Err(status)
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let group = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[((group >> (18 - 6 * index)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
