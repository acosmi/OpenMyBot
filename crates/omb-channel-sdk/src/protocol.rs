//! Messages of the `openmybot-channel/1` protocol. Each enum is tagged by its `type` field.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Daemon to plugin, over the plugin's stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToPlugin {
    Hello {
        protocol: String,
        channel_kind: String,
        limits: Limits,
    },
    /// May arrive in any state after `hello`.
    Verify {
        credential: String,
        source_key: Option<String>,
    },
    Start {
        source_key: String,
        credential: String,
        last_event_key: Option<String>,
        last_accepted_at: Option<String>,
    },
    /// Stops receiving only; the daemon ends the process afterwards.
    Stop {},
    Send {
        delivery_id: String,
        chat_key: String,
        body: String,
        idempotency_key: String,
    },
    /// Sent after the acceptance transaction for `event_key` committed, whatever its result.
    Accepted { event_key: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub send_timeout_ms: u64,
    pub ack_timeout_ms: u64,
}

/// Plugin to daemon, over the plugin's stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromPlugin {
    HelloOk {
        plugin_name: String,
        plugin_version: String,
        channel_kind: String,
    },
    Verified {
        source_key: String,
    },
    VerifyFailed {
        code: VerifyFailure,
    },
    /// The event's fields sit next to `type` on the wire.
    Event(EventFrame),
    /// No receipt follows; the plugin may move its cursor past the update.
    Skipped {
        counter: SkipCounter,
    },
    Gap {
        reason: GapReason,
    },
    GapClosed {},
    Suspend {
        reason: SuspendReason,
    },
    Sent {
        delivery_id: String,
        platform_message_id: Option<String>,
    },
    SendFailed {
        delivery_id: String,
        class: FailureClass,
        code: SendErrorCode,
        retry_after_ms: Option<u64>,
    },
}

/// One platform update. `occurred_at` is RFC 3339 UTC with milliseconds when the platform has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventFrame {
    pub event_key: String,
    pub event_type: String,
    pub occurred_at: Option<String>,
    pub private: bool,
    pub sender_key: Option<String>,
    pub chat_key: Option<String>,
    pub kind: EventKind,
    pub text: String,
    pub data: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Text,
    Other,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipCounter {
    PlatformPayloadUnparseable,
    UnsupportedUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    ConnectFailed,
    StreamBroken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendReason {
    CredentialRejected,
    WebhookConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFailure {
    CredentialRejected,
    WebhookConflict,
    Unreachable,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Retryable,
    Final,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendErrorCode {
    Unreachable,
    RateLimited,
    ServerError,
    ClientError,
    ReceiverInactive,
}
