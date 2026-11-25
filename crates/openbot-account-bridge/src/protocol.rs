//! Frames of the `wrokbot-account-bridge/1` protocol. Each enum is tagged by its `type` field;
//! variant names are snake_case and field names camelCase on the wire.

use std::fmt;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::PROTOCOL;
use crate::error::ErrorCode;

/// A JSON object the host does not interpret at this layer.
pub type JsonObject = Map<String, Value>;

/// Host to plugin, over the plugin's stdin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostFrame {
    /// Always the first frame. The plugin may use only the listed connectors and only this proxy.
    Hello {
        protocol: ProtocolName,
        plugin_version: String,
        connectors: Vec<Connector>,
        egress_proxy: EgressProxy,
    },
    /// Answered by `login_progress` or `error`. The host has persisted the attempt before sending.
    LoginStart {
        request_id: String,
        attempt_id: String,
        connector: Connector,
    },
    /// Answered by `login_progress` while the vendor has not confirmed yet, `login_result` or `error`.
    LoginPoll {
        request_id: String,
        attempt_id: String,
    },
    /// No reply; the plugin closes the attempt's callback listener and drops any later callback.
    LoginCancel {
        request_id: String,
        attempt_id: String,
    },
    /// Replaces the connection's in-memory token set. No reply on success; `credential_rejected`
    /// otherwise. Frames are handled in order, so a following request sees the outcome.
    CredentialLoad {
        request_id: String,
        connection_id: String,
        connector: Connector,
        credential_generation: u64,
        token_set: TokenSet,
    },
    /// Answered by `refresh_result` or `error`. The plugin keeps using the loaded generation until
    /// the host loads the refreshed set as a new generation.
    Refresh {
        request_id: String,
        connection_id: String,
        credential_generation: u64,
    },
    /// Answered by `models_result` or `error`.
    Models {
        request_id: String,
        connection_id: String,
        credential_generation: u64,
    },
    /// Answered by `usage_result` or `error`.
    Usage {
        request_id: String,
        connection_id: String,
        credential_generation: u64,
    },
    /// One Anthropic Messages request body. Answered by zero or more `infer_event` and exactly one
    /// `infer_end`, or by `error` when the request is refused before any event.
    Infer {
        request_id: String,
        connection_id: String,
        credential_generation: u64,
        body: JsonObject,
    },
    /// No reply of its own; the target `infer` ends with `infer_end` and code `cancelled`.
    InferCancel {
        request_id: String,
        target_request_id: String,
    },
    /// Sent once, without retry, after the host has completed the local disconnect; the token set
    /// is the one the host held before deleting it. Answered by `revoke_result`.
    Revoke {
        request_id: String,
        connection_id: String,
        connector: Connector,
        token_set: TokenSet,
    },
    /// No reply; the plugin exits.
    Shutdown {},
}

/// Plugin to host, over the plugin's stdout.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PluginFrame {
    HelloOk {
        protocol: ProtocolName,
        plugin_version: String,
        connectors: Vec<Connector>,
    },
    LoginProgress {
        request_id: String,
        attempt_id: String,
        challenge: LoginChallenge,
    },
    /// The token set is stored sealed by the host and handed back verbatim by `credential_load`.
    LoginResult {
        request_id: String,
        attempt_id: String,
        account_id: String,
        token_set: TokenSet,
        expires_at: u64,
    },
    RefreshResult {
        request_id: String,
        connection_id: String,
        token_set: TokenSet,
        expires_at: u64,
    },
    RevokeResult {
        request_id: String,
        connection_id: String,
        outcome: RevokeOutcome,
    },
    CredentialRejected {
        request_id: String,
        connection_id: String,
        credential_generation: u64,
        code: ErrorCode,
    },
    ModelsResult {
        request_id: String,
        models: Vec<Model>,
    },
    /// The vendor's account usage report, not interpreted at this layer.
    UsageResult {
        request_id: String,
        usage: JsonObject,
    },
    /// One server-sent event of the Anthropic Messages stream, as its JSON data.
    InferEvent {
        request_id: String,
        event: JsonObject,
    },
    InferEnd {
        request_id: String,
        outcome: InferOutcome,
    },
    /// `requestId` is absent only when the failure cannot be attributed to a request.
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        code: ErrorCode,
        message: String,
    },
}

/// The connectors of spec revision R486; any other value fails decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Connector {
    Openai,
    Anthropic,
    Xai,
    Qwen,
    Kimi,
    Zai,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressProxy {
    /// Loopback proxy address assigned to this plugin instance.
    pub url: String,
    pub credential: ProxyCredential,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LoginChallenge {
    /// The host opens this URL in the system browser; the plugin receives the callback.
    Browser { authorization_url: String },
    /// The host shows the user code next to the verification URL.
    DeviceCode {
        verification_url: String,
        user_code: String,
    },
}

/// Result of the vendor-side revocation only; it never changes the local disconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeOutcome {
    Revoked,
    /// The connector has no vendor revocation endpoint.
    NotSupported,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Model {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum InferOutcome {
    Completed { usage: Usage },
    Failed { code: ErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

/// The exact protocol name; decoding any other string fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolName;

impl Serialize for ProtocolName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(PROTOCOL)
    }
}

impl<'de> Deserialize<'de> for ProtocolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name != PROTOCOL {
            return Err(de::Error::custom("unsupported protocol"));
        }
        Ok(ProtocolName)
    }
}

/// Plugin-owned token set. The host reads nothing inside it; `Debug` never shows its content.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenSet(pub JsonObject);

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSet(..)")
    }
}

/// Per-instance proxy password. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProxyCredential(pub String);

impl fmt::Debug for ProxyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredential(..)")
    }
}
