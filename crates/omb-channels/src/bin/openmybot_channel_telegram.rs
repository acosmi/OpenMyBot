//! The Telegram channel plugin: speaks `openmybot-channel/1` on standard input and output. The
//! token arrives only in `verify` and `start` frames; no argument or environment variable carries
//! it. Test builds also take `--api-base <loopback url>`.
use omb_channel_sdk::plugin::run_channel_plugin;
use omb_channels::{TelegramEndpoint, TelegramPlugin};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    #[cfg_attr(not(feature = "testkit"), allow(unused_mut))]
    let mut endpoint = TelegramEndpoint::production(SafeDialer::new(EgressPolicy::default()));
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match (flag.as_str(), args.next()) {
            #[cfg(feature = "testkit")]
            ("--api-base", Some(base)) => {
                let Some(port) = url::Url::parse(&base).ok().and_then(|url| url.port()) else {
                    eprintln!("usage: openmybot-channel-telegram [--api-base <loopback url>]");
                    return ExitCode::from(2);
                };
                endpoint = omb_channels::testkit::FakeTelegram::endpoint_at(port);
            }
            _ => {
                eprintln!("usage: openmybot-channel-telegram");
                return ExitCode::from(2);
            }
        }
    }
    match run_channel_plugin(TelegramPlugin::new(endpoint)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
