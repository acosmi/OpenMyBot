//! Minimal daemon-side driver for plugin tests: spawns a plugin process and exchanges frames with it.

use std::io;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Instant, sleep, timeout, timeout_at};

use crate::frame::{FrameError, decode, encode, read_frame, write_frame};
use crate::protocol::{FromPlugin, Limits, ToPlugin};
use crate::{ACK_TIMEOUT, HELLO_TIMEOUT, PROTOCOL, SEND_TIMEOUT};

/// Bytes of stderr kept, matching the daemon's `STDERR_TAIL_MAX`.
const STDERR_TAIL: usize = 2048;
/// Matches the daemon's `CC_TERM_GRACE`.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// A running plugin. Fields are public so tests can close stdin and wait for the exit themselves.
pub struct Host {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: ChildStdout,
    /// The last stderr bytes, filled by a background task until the plugin closes stderr.
    pub stderr_tail: Arc<Mutex<Vec<u8>>>,
}

impl Host {
    /// Spawns `command` with exactly `env`, in its own process group, with all three stdio piped.
    pub async fn spawn(command: &Path, args: &[&str], env: &[(&str, &str)]) -> io::Result<Host> {
        let mut child = Command::new(command)
            .args(args)
            .env_clear()
            .envs(env.iter().copied())
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (Some(stdin), Some(stdout), Some(mut stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            unreachable!("all three stdio streams are piped");
        };
        let stderr_tail = Arc::new(Mutex::new(Vec::new()));
        let tail = stderr_tail.clone();
        tokio::spawn(async move {
            let mut chunk = [0; 4096];
            while let Ok(read @ 1..) = stderr.read(&mut chunk).await {
                let mut tail = tail.lock().unwrap();
                tail.extend_from_slice(&chunk[..read]);
                let excess = tail.len().saturating_sub(STDERR_TAIL);
                tail.drain(..excess);
            }
        });
        Ok(Host {
            child,
            stdin,
            stdout,
            stderr_tail,
        })
    }

    /// Sends `hello` with the default limits and returns `(plugin_name, plugin_version)` from
    /// `hello_ok`. No `hello_ok` within [`HELLO_TIMEOUT`] is a `TimedOut` I/O error; any other reply
    /// is [`FrameError::Json`].
    pub async fn hello(&mut self, channel_kind: &str) -> Result<(String, String), FrameError> {
        self.send(&ToPlugin::Hello {
            protocol: PROTOCOL.to_owned(),
            channel_kind: channel_kind.to_owned(),
            limits: Limits {
                send_timeout_ms: SEND_TIMEOUT.as_millis() as u64,
                ack_timeout_ms: ACK_TIMEOUT.as_millis() as u64,
            },
        })
        .await?;
        match self.recv(HELLO_TIMEOUT).await? {
            Some(FromPlugin::HelloOk {
                plugin_name,
                plugin_version,
                ..
            }) => Ok((plugin_name, plugin_version)),
            Some(_) => Err(FrameError::Json),
            None => Err(io::Error::from(io::ErrorKind::TimedOut).into()),
        }
    }

    pub async fn send(&mut self, msg: &ToPlugin) -> Result<(), FrameError> {
        write_frame(&mut self.stdin, &encode(msg)?).await
    }

    /// Returns the next frame, or `None` when `timeout` passes or stdout ends first.
    pub async fn recv(
        &mut self,
        timeout_after: Duration,
    ) -> Result<Option<FromPlugin>, FrameError> {
        let Ok(read) = timeout(timeout_after, read_frame(&mut self.stdout)).await else {
            return Ok(None);
        };
        read?.map(|payload| decode(&payload)).transpose()
    }

    /// Sends TERM to the process group, sends KILL once the grace period passes, waits until the
    /// group is empty and returns the plugin's exit code (`None` when a signal ended it).
    pub async fn kill(mut self) -> Option<i32> {
        let group = format!("-{}", self.child.id()?);
        let deadline = Instant::now() + TERM_GRACE;
        signal(&group, "TERM").await;
        let status = match timeout_at(deadline, self.child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                signal(&group, "KILL").await;
                self.child.wait().await
            }
        };
        // Other members of the group can outlive the plugin itself.
        while signal(&group, "0").await {
            if Instant::now() >= deadline {
                signal(&group, "KILL").await;
            }
            sleep(Duration::from_millis(10)).await;
        }
        status.ok()?.code()
    }
}

/// Sends `-<name>` to the process group through `/bin/kill`; `false` once the group is gone.
async fn signal(group: &str, name: &str) -> bool {
    Command::new("/bin/kill")
        .args([&format!("-{name}"), "--", group])
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}
