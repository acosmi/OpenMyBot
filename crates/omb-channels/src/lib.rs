//! Telegram and Feishu channel plugins of the `openmybot-channel/1` protocol: boundary parsing,
//! the receive loops and the send requests. Each `openmybot-channel-<kind>` binary runs one plugin.
#[cfg(feature = "testkit")]
pub mod fake_feishu;
mod feishu;
mod sender;
mod telegram;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use feishu::FeishuPlugin;
pub use telegram::TelegramPlugin;

use openbot_infra::net::safe_http::{SafeDialer, SchemePolicy};
use std::time::Duration;
use time::{OffsetDateTime, UtcOffset, macros::format_description};
use url::Url;

pub const TG_POLL_TIMEOUT: Duration = Duration::from_secs(50);
/// The HTTP deadline of one long poll is the poll timeout plus this margin.
pub const TG_HTTP_MARGIN: Duration = Duration::from_secs(15);
pub const TG_POLL_LIMIT: u32 = 100;
pub const TG_OFFSET_STALE: Duration = Duration::from_secs(6 * 24 * 3600);
/// Larger `getUpdates` bodies are refused as a broken stream and fetched again.
pub const TG_RESPONSE_MAX: usize = 8 * 1024 * 1024;
pub const HTTP_SEND_TIMEOUT: Duration = Duration::from_secs(15);
/// A failed poll or connection is retried after a uniform wait below this bound, doubled per
/// failure up to `BACKOFF_MAX`.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A cached tenant token with less validity left is fetched again.
pub const FS_TOKEN_MARGIN: Duration = Duration::from_secs(30 * 60);
/// The long connection's ping interval until the platform's `PingInterval` replaces it.
pub const FS_PING_INTERVAL: Duration = Duration::from_secs(120);
/// The read deadline is twice the ping interval plus this grace after the last message.
pub const FS_READ_GRACE: Duration = Duration::from_secs(5);
pub const FS_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Fragments of an event not completed within this time after the latest one are dropped.
pub const FS_FRAGMENT_TTL: Duration = Duration::from_secs(5);
/// Bytes of one WebSocket message or frame, and of one event reassembled from its fragments.
pub const FS_FRAME_MAX: usize = 1024 * 1024;
/// Where the Bot API is reached; production is HTTPS to the public endpoint only.
#[derive(Clone)]
pub struct TelegramEndpoint {
    pub api_base: Url,
    pub dialer: SafeDialer,
    pub scheme: SchemePolicy,
}
impl TelegramEndpoint {
    pub fn production(dialer: SafeDialer) -> Self {
        Self {
            api_base: Url::parse("https://api.telegram.org/").expect("static Bot API origin"),
            dialer,
            scheme: SchemePolicy::HttpsOnly,
        }
    }
}
/// Where the Feishu open platform is reached; production is HTTPS to the public endpoint only.
#[derive(Clone)]
pub struct FeishuEndpoint {
    pub api_base: Url,
    pub dialer: SafeDialer,
    pub scheme: SchemePolicy,
}
impl FeishuEndpoint {
    pub fn production(dialer: SafeDialer) -> Self {
        Self {
            api_base: Url::parse("https://open.feishu.cn/").expect("static open platform origin"),
            dialer,
            scheme: SchemePolicy::HttpsOnly,
        }
    }
}
/// RFC 3339 in UTC with milliseconds, the `occurred_at` form of an event frame.
fn utc_millis(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .expect("a UTC time formats")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timings_default_equals_spec_constants() {
        assert_eq!(TG_POLL_LIMIT, 100);
        assert_eq!(TG_OFFSET_STALE, Duration::from_secs(6 * 24 * 3600));
        assert_eq!(TG_RESPONSE_MAX, 8 * 1024 * 1024);
        assert_eq!(BACKOFF_MIN, Duration::from_secs(1));
        assert_eq!(BACKOFF_MAX, Duration::from_secs(60));
    }
    #[test]
    fn production_endpoint_is_https_only() {
        use openbot_infra::net::safe_http::{EgressPolicy, SafeHttpBudget, SafeHttpRequest};
        let endpoint = TelegramEndpoint::production(SafeDialer::new(EgressPolicy::default()));
        assert_eq!(endpoint.api_base.as_str(), "https://api.telegram.org/");
        // The endpoint's scheme policy admits the HTTPS base and refuses the same URL over HTTP.
        let request = |url: &str| {
            SafeHttpRequest::get(
                Url::parse(url).unwrap(),
                endpoint.scheme,
                SafeHttpBudget::new(1024, Duration::from_secs(1)).unwrap(),
            )
        };
        assert!(request("https://api.telegram.org/").is_ok());
        assert_eq!(
            request("http://api.telegram.org/").err(),
            Some(openbot_infra::net::safe_http::SafeHttpError::SchemeRejected)
        );
    }
    #[test]
    fn feishu_constants_are_fixed() {
        assert_eq!(FS_TOKEN_MARGIN, Duration::from_secs(1800));
        assert_eq!(FS_PING_INTERVAL, Duration::from_secs(120));
        assert_eq!(FS_READ_GRACE, Duration::from_secs(5));
        assert_eq!(FS_WRITE_TIMEOUT, Duration::from_secs(10));
        assert_eq!(FS_FRAGMENT_TTL, Duration::from_secs(5));
        assert_eq!(FS_FRAME_MAX, 1_048_576);
        assert_eq!(HTTP_SEND_TIMEOUT, Duration::from_secs(15));
    }
    #[tokio::test]
    async fn feishu_production_endpoint_is_https_only() {
        use openbot_infra::net::safe_http::{
            EgressPolicy, SafeHttpBudget, SafeHttpError, SafeHttpRequest,
        };
        let endpoint = FeishuEndpoint::production(SafeDialer::new(EgressPolicy::default()));
        assert_eq!(endpoint.api_base.as_str(), "https://open.feishu.cn/");
        let request = |url: &str| {
            SafeHttpRequest::get(
                Url::parse(url).unwrap(),
                endpoint.scheme,
                SafeHttpBudget::new(1024, Duration::from_secs(1)).unwrap(),
            )
        };
        assert!(request("https://open.feishu.cn/").is_ok());
        assert_eq!(
            request("http://open.feishu.cn/").err(),
            Some(SafeHttpError::SchemeRejected)
        );
        // The scheme is refused before any name is resolved.
        assert_eq!(
            endpoint
                .dialer
                .connect_websocket_stream(
                    &Url::parse("ws://open.feishu.cn/ws").unwrap(),
                    endpoint.scheme,
                    Duration::from_secs(1),
                )
                .await
                .err(),
            Some(SafeHttpError::SchemeRejected)
        );
    }
}
