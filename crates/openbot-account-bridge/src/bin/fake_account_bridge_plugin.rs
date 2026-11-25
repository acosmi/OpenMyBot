//! Fake account bridge plugin process for tests; see `openbot_account_bridge::fake_plugin`.
//! Arguments: `[--egress-probe <host:port>]`.

use std::process::ExitCode;

use openbot_account_bridge::fake_plugin;
use tokio::io::{stdin, stdout};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let egress_probe = match args.as_slice() {
        [] => None,
        [flag, target] if flag == "--egress-probe" => Some(target.as_str()),
        _ => {
            eprintln!("usage: fake-account-bridge-plugin [--egress-probe <host:port>]");
            return ExitCode::from(2);
        }
    };
    match fake_plugin::run(&mut stdin(), &mut stdout(), egress_probe).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
