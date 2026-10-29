//! The `openmybot mcp` stdio server: five tools, each call forwarded once to the local daemon.
mod tools;

use omb_daemon::{CallOptions, DaemonError};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
        ToolsCapability,
    },
    service::{QuitReason, RequestContext, ServerInitializeError},
};
use serde_json::Value;
use std::{borrow::Cow, path::PathBuf, time::Duration};

/// The two revisions this server speaks and no other: the current CrabCode client negotiates
/// the older one through `initialize`; a client of the stateless revision uses
/// `server/discover`.
const SUPPORTED_VERSIONS: &[ProtocolVersion] =
    &[ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25];
/// Whole-call bound of one tool call.
pub const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct McpOptions {
    pub data_dir: PathBuf,
    /// The process runs as a host-driver child; the caller reads this once at start.
    pub nested: bool,
}

/// Serves MCP on stdin and stdout until stdin closes.
pub async fn serve(options: McpOptions) -> Result<(), DaemonError> {
    let bridge = Bridge {
        data_dir: options.data_dir,
        nested: options.nested,
    };
    match bridge.serve(rmcp::transport::stdio()).await {
        Ok(running) => match running.waiting().await {
            Ok(QuitReason::JoinError(_)) | Err(_) => Err(DaemonError::InternalError),
            Ok(_) => Ok(()),
        },
        Err(ServerInitializeError::ConnectionClosed(_)) => Ok(()),
        Err(_) => Err(DaemonError::InternalError),
    }
}

struct Bridge {
    data_dir: PathBuf,
    nested: bool,
}
impl ServerHandler for Bridge {
    /// Its protocol version answers an `initialize` that asks for a revision outside the two.
    fn get_info(&self) -> ServerInfo {
        let mut tools = ToolsCapability::default();
        tools.list_changed = Some(false);
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools_with(tools)
                .build(),
        )
        .with_server_info(Implementation::new("openmybot", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_VERSIONS)
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(tools::list()))
    }
    /// A nested call is refused first, then an unknown tool; arguments go to the daemon as sent.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if self.nested {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "nested_delegation_refused",
            )])
            .into());
        }
        let Some(def) = tools::DEFS.iter().find(|def| def.name == request.name) else {
            return Err(McpError::invalid_params("unknown tool", None));
        };
        let called = tokio::time::timeout(
            MCP_CALL_TIMEOUT,
            omb_daemon::call_mcp(CallOptions {
                data_dir: self.data_dir.clone(),
                op: def.op.into(),
                args: Value::Object(request.arguments.unwrap_or_default()),
            }),
        )
        .await
        .unwrap_or(Err(DaemonError::RequestTimeout));
        Ok(outcome(called).into())
    }
}

/// Maps one daemon outcome to a tool result.
fn outcome(called: Result<Value, DaemonError>) -> CallToolResult {
    match called {
        Ok(data) => CallToolResult::structured(data),
        Err(DaemonError::DaemonNotRunning) => {
            CallToolResult::error(vec![ContentBlock::text("wrok_not_running")])
        }
        Err(error) => CallToolResult::error(vec![ContentBlock::text(error.code())]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};

    /// One client end of an in-memory connection to a served `Bridge`.
    struct Peer {
        writer: DuplexStream,
        lines: Lines<BufReader<DuplexStream>>,
    }
    impl Peer {
        async fn send(&mut self, message: &Value) {
            let mut line = message.to_string();
            line.push('\n');
            self.writer.write_all(line.as_bytes()).await.unwrap();
        }
        async fn recv(&mut self) -> Value {
            let line = tokio::time::timeout(Duration::from_secs(5), self.lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            serde_json::from_str(&line).unwrap()
        }
    }
    fn start(nested: bool, data_dir: &Path) -> Peer {
        let (writer, server_reader) = tokio::io::duplex(65536);
        let (server_writer, reader) = tokio::io::duplex(65536);
        let bridge = Bridge {
            data_dir: data_dir.to_path_buf(),
            nested,
        };
        tokio::spawn(async move {
            if let Ok(running) = bridge.serve((server_reader, server_writer)).await {
                let _ = running.waiting().await;
            }
        });
        Peer {
            writer,
            lines: BufReader::new(reader).lines(),
        }
    }
    /// A data directory that does not exist: any daemon call answers `wrok_not_running`.
    fn missing(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("omb-mcp-{}-{name}", std::process::id()));
        assert!(!dir.exists());
        dir
    }
    /// A request of the stateless revision: every request carries its version in `_meta`.
    fn request(id: u64, method: &str, mut params: Value) -> Value {
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }
    /// A request of a session negotiated through `initialize`.
    fn legacy(id: u64, method: &str, params: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    }
    fn initialize(version: &str) -> Value {
        legacy(
            1,
            "initialize",
            json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"}
            }),
        )
    }
    fn call(id: u64, name: &str) -> Value {
        request(id, "tools/call", json!({"name": name, "arguments": {}}))
    }
    fn refused(answer: &Value, text: &str) {
        assert_eq!(answer["result"]["isError"], true, "{answer}");
        assert_eq!(
            answer["result"]["content"],
            json!([{"type": "text", "text": text}]),
            "{answer}"
        );
        assert!(
            answer["result"].get("structuredContent").is_none(),
            "{answer}"
        );
    }
    const NAMES: [&str; 5] = [
        "wrok_run_begin",
        "wrok_run_status",
        "wrok_run_cancel",
        "wrok_run_result",
        "wrok_thread_list",
    ];

    #[tokio::test]
    async fn discover_and_tools_list_answer_without_touching_the_daemon() {
        let dir = missing("discover");
        let mut peer = start(false, &dir);
        peer.send(&request(1, "server/discover", json!({}))).await;
        let discovered = peer.recv().await;
        let result = &discovered["result"];
        assert_eq!(
            result["supportedVersions"],
            json!(["2026-07-28", "2025-11-25"])
        );
        assert_eq!(
            result["capabilities"],
            json!({"tools": {"listChanged": false}})
        );
        assert_eq!(result["ttlMs"], 0);
        assert_eq!(result["cacheScope"], "private");
        assert_eq!(result["resultType"], "complete");
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/serverInfo"],
            json!({"name": "openmybot", "version": env!("CARGO_PKG_VERSION")})
        );
        peer.send(&request(2, "tools/list", json!({}))).await;
        let listed = peer.recv().await;
        let tools = listed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
        assert_eq!(
            listed["result"]["tools"],
            serde_json::to_value(tools::list()).unwrap()
        );
        for (tool, name) in tools.iter().zip(NAMES) {
            let mut keys: Vec<&String> = tool.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, ["description", "inputSchema", "name", "outputSchema"]);
            assert_eq!(tool["name"], name);
        }
        assert!(listed["result"].get("nextCursor").is_none());
        assert_eq!(listed["result"]["resultType"], "complete");
        peer.send(&call(3, "wrok_thread_list")).await;
        let called = peer.recv().await;
        refused(&called, "wrok_not_running");
        assert_eq!(called["result"]["resultType"], "complete");
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn initialize_flow_of_2025_11_25_serves_tools_list_and_tools_call() {
        let dir = missing("initialize");
        let mut peer = start(false, &dir);
        peer.send(&initialize("2025-11-25")).await;
        let initialized = peer.recv().await;
        let result = &initialized["result"];
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert_eq!(
            result["capabilities"],
            json!({"tools": {"listChanged": false}})
        );
        assert_eq!(result["serverInfo"]["name"], "openmybot");
        assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
        peer.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        peer.send(&legacy(2, "tools/list", json!({}))).await;
        let listed = peer.recv().await;
        assert_eq!(
            listed["result"]["tools"],
            serde_json::to_value(tools::list()).unwrap()
        );
        assert!(listed["result"].get("resultType").is_none(), "{listed}");
        peer.send(&legacy(
            3,
            "tools/call",
            json!({"name": "wrok_thread_list", "arguments": {}}),
        ))
        .await;
        let called = peer.recv().await;
        refused(&called, "wrok_not_running");
        assert!(called["result"].get("resultType").is_none(), "{called}");
        peer.send(&legacy(
            4,
            "tools/call",
            json!({"name": "wrok_unknown", "arguments": {}}),
        ))
        .await;
        assert_eq!(peer.recv().await["error"]["code"], -32602);
        let mut latest = start(false, &dir);
        latest.send(&initialize("2026-07-28")).await;
        assert_eq!(
            latest.recv().await["result"]["protocolVersion"],
            "2026-07-28"
        );
        let bridge = Bridge {
            data_dir: dir,
            nested: false,
        };
        assert_eq!(
            bridge.supported_protocol_versions().as_ref(),
            [ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25]
        );
    }

    #[test]
    fn outcome_maps_every_daemon_outcome() {
        let texts = |result: &CallToolResult| -> Vec<String> {
            result
                .content
                .iter()
                .map(|block| block.as_text().unwrap().text.clone())
                .collect()
        };
        let data = json!({"run_id": "r1", "state": "running", "permission_ids": []});
        let done = outcome(Ok(data.clone()));
        assert_eq!(done.structured_content, Some(data.clone()));
        assert_ne!(done.is_error, Some(true));
        assert_eq!(texts(&done), [data.to_string()]);
        let down = outcome(Err(DaemonError::DaemonNotRunning));
        assert_eq!(down.is_error, Some(true));
        assert_eq!(texts(&down), ["wrok_not_running"]);
        assert_eq!(down.structured_content, None);
        for error in DaemonError::ALL {
            if *error == DaemonError::DaemonNotRunning {
                continue;
            }
            let failed = outcome(Err(*error));
            assert_eq!(failed.is_error, Some(true), "{error:?}");
            assert_eq!(texts(&failed), [error.code()]);
            assert_eq!(failed.structured_content, None);
        }
        assert_eq!(DaemonError::ALL.len(), 47);
    }

    #[tokio::test]
    async fn call_tool_order_is_nested_then_unknown_tool_then_the_daemon() {
        let dir = missing("order");
        let mut nested = start(true, &dir);
        for (id, name) in (1..).zip(NAMES.iter().chain(&["wrok_unknown"])) {
            nested.send(&call(id, name)).await;
            refused(&nested.recv().await, "nested_delegation_refused");
        }
        let mut plain = start(false, &dir);
        plain.send(&call(1, "wrok_unknown")).await;
        let unknown = plain.recv().await;
        assert_eq!(unknown["error"]["code"], -32602);
        assert_eq!(unknown["id"], 1);
        for (id, name) in (2..).zip(NAMES) {
            plain.send(&call(id, name)).await;
            refused(&plain.recv().await, "wrok_not_running");
        }
        plain
            .send(&request(
                7,
                "tools/call",
                json!({"name": "wrok_thread_list"}),
            ))
            .await;
        refused(&plain.recv().await, "wrok_not_running");
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn no_revision_outside_the_two_is_ever_negotiated() {
        let dir = missing("revisions");
        for version in ["2025-06-18", "2025-03-26", "2024-11-05"] {
            let mut peer = start(false, &dir);
            peer.send(&initialize(version)).await;
            let answer = peer.recv().await;
            assert_ne!(answer["result"]["protocolVersion"], version);
            assert_eq!(answer["result"]["protocolVersion"], "2026-07-28");
        }
        let mut peer = start(false, &dir);
        let mut stale = request(1, "server/discover", json!({}));
        stale["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2025-06-18");
        peer.send(&stale).await;
        let refused = peer.recv().await;
        assert_eq!(refused["error"]["code"], -32022, "{refused}");
        assert_eq!(refused["error"]["data"]["requested"], "2025-06-18");
        assert_eq!(
            refused["error"]["data"]["supported"],
            json!(["2026-07-28", "2025-11-25"])
        );
        peer.send(&request(2, "server/discover", json!({}))).await;
        assert_eq!(
            peer.recv().await["result"]["supportedVersions"],
            json!(["2026-07-28", "2025-11-25"])
        );
    }
}
