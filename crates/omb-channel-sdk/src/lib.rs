//! Channel plugin SDK for the `openmybot-channel/1` protocol.
//!
//! A channel plugin is a child process of the OpenMyBot daemon. Every frame is a 4-byte big-endian
//! length followed by UTF-8 JSON of at most [`FRAME_MAX`] bytes; duplicate keys and unknown fields
//! are rejected. The daemon writes [`protocol::ToPlugin`] frames to the plugin's stdin and reads
//! [`protocol::FromPlugin`] frames from its stdout. The daemon keeps only a bounded tail of stderr.
//!
//! The first frame is always `hello`; the plugin answers `hello_ok` with the same `channel_kind`.
//! The receive cursor advances only after `accepted{event_key}` or `skipped`; an event without a
//! receipt inside `limits.ack_timeout_ms` counts as not accepted. `accepted` is sent for every
//! committed acceptance result, duplicates and conflicts included.
//!
//! Credentials arrive as plain strings in `verify` and `start`. A plugin must not persist them and
//! must not print them to stdout, stderr or any log.
//!
//! Plugins implement [`plugin::ChannelPlugin`] and call [`plugin::run_channel_plugin`] from `main`.

use std::time::Duration;

pub mod frame;
pub mod plugin;
pub mod protocol;
#[cfg(feature = "testkit")]
pub mod testkit;

/// Protocol name carried in `hello`.
pub const PROTOCOL: &str = "openmybot-channel/1";
/// Largest frame payload in bytes, excluding the 4-byte length prefix.
pub const FRAME_MAX: usize = 1 << 20;
/// How long the daemon waits for `hello_ok`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a plugin waits for `accepted` after emitting an event.
pub const ACK_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the daemon waits for `sent` or `send_failed`.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(35);
/// Most plugin processes the daemon runs at once.
pub const PLUGIN_MAX: usize = 8;
