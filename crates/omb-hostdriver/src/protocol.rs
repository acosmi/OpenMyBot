//! The CrabCode stdio control protocol subset: bounded line parsing and the four outgoing frames.
//! Nothing here leaves the crate; `mapping` alone turns these frames into engine events and rows.
use omb_store::KEY_MAX;
use serde_json::{Value, json};

pub(crate) const HOOK_CALLBACK_REFUSED: &str = "hook_callback_refused";
pub(crate) const ELICITATION_REFUSED: &str = "elicitation_refused";
pub(crate) const SDK_MCP_REFUSED: &str = "sdk_mcp_refused";
pub(crate) const SUBTYPE_UNSUPPORTED: &str = "subtype_unsupported";

/// One child output line after closed, bounded parsing.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Frame {
    Init {
        session_id: String,
    },
    System,
    Assistant(Vec<Block>),
    User {
        tool_results: u64,
    },
    Result(Outcome),
    CanUseTool {
        request_id: String,
        tool_name: String,
        input: Value,
    },
    /// A child request this driver answers with an error code.
    Refuse {
        request_id: String,
        code: &'static str,
    },
    ControlResponse,
    Unknown,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Block {
    Text(String),
    ToolUse(String),
    Other,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Outcome {
    pub(crate) success: bool,
    pub(crate) text: Option<String>,
    pub(crate) usage: Option<(u64, u64)>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineError {
    LineLimit,
    Protocol,
}

fn bounded(value: &Value) -> Result<String, LineError> {
    value
        .as_str()
        .filter(|text| text.len() <= KEY_MAX)
        .map(str::to_owned)
        .ok_or(LineError::Protocol)
}
fn blocks(message: &Value) -> Result<&Vec<Value>, LineError> {
    message["content"].as_array().ok_or(LineError::Protocol)
}

/// Parses one stdout line, excluding its newline.
pub(crate) fn parse_line(line: &[u8], line_max: usize) -> Result<Frame, LineError> {
    if line.len() > line_max {
        return Err(LineError::LineLimit);
    }
    let value: Value = serde_json::from_slice(line).map_err(|_| LineError::Protocol)?;
    let kind = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(LineError::Protocol)?;
    Ok(match kind {
        "system" if value["subtype"] == "init" => Frame::Init {
            session_id: bounded(&value["session_id"])?,
        },
        "system" => Frame::System,
        "assistant" => Frame::Assistant(
            blocks(&value["message"])?
                .iter()
                .map(|block| match block["type"].as_str() {
                    Some("text") => block["text"]
                        .as_str()
                        .map(|text| Block::Text(text.to_owned()))
                        .ok_or(LineError::Protocol),
                    Some("tool_use") => Ok(Block::ToolUse(
                        block["name"].as_str().unwrap_or_default().to_owned(),
                    )),
                    _ => Ok(Block::Other),
                })
                .collect::<Result<_, _>>()?,
        ),
        "user" => Frame::User {
            tool_results: value["message"]["content"].as_array().map_or(0, |content| {
                content
                    .iter()
                    .filter(|block| block["type"] == "tool_result")
                    .count() as u64
            }),
        },
        "result" => Frame::Result(Outcome {
            success: value["subtype"] == "success" && value["is_error"] != true,
            text: value["result"].as_str().map(str::to_owned),
            usage: value["usage"]["input_tokens"]
                .as_u64()
                .zip(value["usage"]["output_tokens"].as_u64()),
        }),
        "control_request" => {
            let request_id = bounded(&value["request_id"])?;
            let request = &value["request"];
            match request["subtype"].as_str() {
                Some("can_use_tool") => Frame::CanUseTool {
                    request_id,
                    tool_name: request["tool_name"]
                        .as_str()
                        .filter(|name| !name.is_empty())
                        .ok_or(LineError::Protocol)?
                        .to_owned(),
                    input: request["input"]
                        .as_object()
                        .map(|input| Value::Object(input.clone()))
                        .ok_or(LineError::Protocol)?,
                },
                Some("hook_callback") => Frame::Refuse {
                    request_id,
                    code: HOOK_CALLBACK_REFUSED,
                },
                Some("elicitation") => Frame::Refuse {
                    request_id,
                    code: ELICITATION_REFUSED,
                },
                Some("mcp_message") => Frame::Refuse {
                    request_id,
                    code: SDK_MCP_REFUSED,
                },
                _ => Frame::Refuse {
                    request_id,
                    code: SUBTYPE_UNSUPPORTED,
                },
            }
        }
        "control_response" => Frame::ControlResponse,
        _ => Frame::Unknown,
    })
}

fn line(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}
/// The session handshake; it declares neither hooks nor SDK MCP servers.
pub(crate) fn initialize() -> Vec<u8> {
    line(
        json!({"type":"control_request","request_id":"omb-initialize","request":{"subtype":"initialize"}}),
    )
}
pub(crate) fn user(text: &str) -> Vec<u8> {
    line(json!({"type":"user","message":{"role":"user","content":text}}))
}
pub(crate) fn interrupt() -> Vec<u8> {
    line(
        json!({"type":"control_request","request_id":"omb-interrupt","request":{"subtype":"interrupt"}}),
    )
}
/// Allows a tool request with its original input.
pub(crate) fn allow(request_id: &str, input: &Value) -> Vec<u8> {
    line(
        json!({"type":"control_response","response":{"subtype":"success","request_id":request_id,"response":{"behavior":"allow","updatedInput":input}}}),
    )
}
pub(crate) fn deny(request_id: &str, code: &str) -> Vec<u8> {
    line(
        json!({"type":"control_response","response":{"subtype":"success","request_id":request_id,"response":{"behavior":"deny","message":code}}}),
    )
}
/// Answers a refused child request with an error response.
pub(crate) fn refuse(request_id: &str, code: &str) -> Vec<u8> {
    line(
        json!({"type":"control_response","response":{"subtype":"error","request_id":request_id,"error":code}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(text: &str) -> Result<Frame, LineError> {
        parse_line(text.as_bytes(), crate::CC_LINE_MAX)
    }
    fn decoded(bytes: Vec<u8>) -> Value {
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn oversize_line_is_line_limit() {
        let padding = |total: usize| {
            let frame = r#"{"type":"system","subtype":"status","pad":""}"#;
            frame.replace(
                r#""pad":"""#,
                &format!(r#""pad":"{}""#, "x".repeat(total - frame.len())),
            )
        };
        let exact = padding(crate::CC_LINE_MAX);
        assert_eq!(exact.len(), crate::CC_LINE_MAX);
        assert_eq!(parse(&exact), Ok(Frame::System));
        assert_eq!(
            parse(&padding(crate::CC_LINE_MAX + 1)),
            Err(LineError::LineLimit)
        );
    }

    #[test]
    fn non_json_and_non_object_lines_are_protocol_errors() {
        for text in [
            "not json",
            "",
            "[1,2]",
            "\"system\"",
            "42",
            "{\"subtype\":\"init\"}",
            "{\"type\":7}",
            "{\"type\":\"system\"",
            "{\"type\":\"assistant\",\"message\":{}}",
        ] {
            assert_eq!(parse(text), Err(LineError::Protocol), "{text}");
        }
        assert_eq!(parse_line(&[0xff, 0xfe], 10), Err(LineError::Protocol));
    }

    #[test]
    fn unknown_type_is_counted_and_ignored() {
        assert_eq!(
            parse(r#"{"type":"stream_event","event":{}}"#),
            Ok(Frame::Unknown)
        );
        assert_eq!(
            parse(r#"{"type":"control_response","response":{}}"#),
            Ok(Frame::ControlResponse)
        );
        assert_eq!(
            parse(r#"{"type":"system","subtype":"compact_boundary"}"#),
            Ok(Frame::System)
        );
    }

    #[test]
    fn control_request_refusal_codes() {
        for (subtype, code) in [
            ("hook_callback", "hook_callback_refused"),
            ("elicitation", "elicitation_refused"),
            ("mcp_message", "sdk_mcp_refused"),
            ("set_model", "subtype_unsupported"),
        ] {
            let text = format!(
                r#"{{"type":"control_request","request_id":"r1","request":{{"subtype":"{subtype}"}}}}"#
            );
            assert_eq!(
                parse(&text),
                Ok(Frame::Refuse {
                    request_id: "r1".into(),
                    code
                }),
                "{subtype}"
            );
        }
        assert_eq!(
            parse(
                r#"{"type":"control_request","request_id":"r2","request":{"subtype":"can_use_tool","tool_name":"Write","input":{"file_path":"a"},"tool_use_id":"t"}}"#
            ),
            Ok(Frame::CanUseTool {
                request_id: "r2".into(),
                tool_name: "Write".into(),
                input: json!({"file_path":"a"})
            })
        );
        assert_eq!(
            decoded(refuse("r1", "elicitation_refused")),
            json!({"type":"control_response","response":{"subtype":"error","request_id":"r1","error":"elicitation_refused"}})
        );
    }

    #[test]
    fn session_id_and_native_request_id_over_128_bytes_are_protocol_errors() {
        let ok = "s".repeat(128);
        let long = "s".repeat(129);
        assert_eq!(
            parse(&format!(
                r#"{{"type":"system","subtype":"init","session_id":"{ok}"}}"#
            )),
            Ok(Frame::Init {
                session_id: ok.clone()
            })
        );
        assert_eq!(
            parse(&format!(
                r#"{{"type":"system","subtype":"init","session_id":"{long}"}}"#
            )),
            Err(LineError::Protocol)
        );
        let request = |id: &str| {
            format!(
                r#"{{"type":"control_request","request_id":"{id}","request":{{"subtype":"can_use_tool","tool_name":"Read","input":{{}}}}}}"#
            )
        };
        assert!(parse(&request(&ok)).is_ok());
        assert_eq!(parse(&request(&long)), Err(LineError::Protocol));
    }

    #[test]
    fn outgoing_frames_have_the_four_closed_shapes() {
        let init = decoded(initialize());
        assert_eq!(
            init,
            json!({"type":"control_request","request_id":"omb-initialize","request":{"subtype":"initialize"}})
        );
        assert!(
            init["request"].get("hooks").is_none()
                && init["request"].get("sdkMcpServers").is_none()
        );
        assert_eq!(
            decoded(user("line one\n\nline two")),
            json!({"type":"user","message":{"role":"user","content":"line one\n\nline two"}})
        );
        assert_eq!(
            decoded(interrupt()),
            json!({"type":"control_request","request_id":"omb-interrupt","request":{"subtype":"interrupt"}})
        );
        let input = json!({"file_path":"a.txt","content":"x"});
        assert_eq!(
            decoded(allow("r1", &input)),
            json!({"type":"control_response","response":{"subtype":"success","request_id":"r1","response":{"behavior":"allow","updatedInput":input}}})
        );
        assert_eq!(
            decoded(deny("r1", "owner_denied")),
            json!({"type":"control_response","response":{"subtype":"success","request_id":"r1","response":{"behavior":"deny","message":"owner_denied"}}})
        );
    }
}
