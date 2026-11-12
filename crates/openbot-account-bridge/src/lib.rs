//! Host side of the `wrokbot-account-bridge/1` protocol (spec revision R486).
//!
//! The account bridge plugin is a child process. The host writes [`protocol::HostFrame`] frames to
//! the plugin's stdin and reads [`protocol::PluginFrame`] frames from its stdout. Every frame is a
//! 4-byte big-endian length followed by UTF-8 JSON of at most [`FRAME_MAX`] bytes; duplicate keys
//! and unknown fields are rejected. The first host frame is `hello`; the plugin answers `hello_ok`
//! within [`HELLO_TIMEOUT`]. Every other request except `shutdown` carries a host-generated
//! `requestId`, and replies are attributed by that `requestId` only.
//!
//! Frame shapes are frozen by `fixtures/account-bridge/protocol-1/`. [`PROTOCOL_FIXTURE_DIGEST`] is
//! the SHA-256 of that directory's canonical listing: one line `<sha256-hex>  <relative/path>\n`
//! per regular file, sorted by path bytes, hashed as one byte string. It is the same value as
//! `find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256` run in
//! that directory. Any shape change bumps the protocol number and moves to a new directory.

use std::time::Duration;

pub mod error;
#[cfg(feature = "fake-plugin")]
pub mod fake_plugin;
pub mod frame;
pub mod protocol;

/// Protocol name carried in `hello` and `hello_ok`.
pub const PROTOCOL: &str = "wrokbot-account-bridge/1";
/// Directory digest of `fixtures/account-bridge/protocol-1/`, pinned together with [`PROTOCOL`].
pub const PROTOCOL_FIXTURE_DIGEST: &str =
    "dc7ad9a3d8bc9283b76a58339b58e8ffe6ca22acb6b3bf318f4c0a1a89589988";
/// User name of the proxy Basic authorization; the password is `hello.egressProxy.credential`.
pub const EGRESS_PROXY_USER: &str = "account-bridge";
/// Largest frame payload in bytes, excluding the 4-byte length prefix.
pub const FRAME_MAX: usize = 1 << 20;
/// How long the host waits for `hello_ok`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
