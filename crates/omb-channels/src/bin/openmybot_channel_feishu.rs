//! The Feishu channel plugin: speaks `openmybot-channel/1` on standard input and output. The
//! app secret arrives only in `verify` and `start` frames and the app id as their source key; no
//! argument or environment variable carries them. Test builds also take `--api-base <loopback url>`.
use omb_channel_sdk::plugin::run_channel_plugin;
use omb_channels::{FeishuEndpoint, FeishuPlugin};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    #[cfg_attr(not(feature = "testkit"), allow(unused_mut))]
    let mut endpoint = FeishuEndpoint::production(SafeDialer::new(EgressPolicy::default()));
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            #[cfg(feature = "testkit")]
            ("--api-base", Some(base)) => {
                let Some(port) = url::Url::parse(&base).ok().and_then(|url| url.port()) else {
                    eprintln!("usage: openmybot-channel-feishu [--api-base <loopback url>]");
                    return ExitCode::from(2);
                };
                endpoint = omb_channels::fake_feishu::FakeFeishu::endpoint_at(port);
            }
            _ => {
                eprintln!("usage: openmybot-channel-feishu");
                return ExitCode::from(2);
            }
        }
    }
    match run_channel_plugin(FeishuPlugin::new(endpoint)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
