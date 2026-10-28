//! CrabCode host driver: one stdio child per run behind the engine's provider ports.
mod jcs;
mod mapping;
mod permission;
mod protocol;
mod session;
mod spawn;
mod window;
mod workspace;

pub use session::HostDriverSession;
pub use window::{AcceptedVersion, VersionWindow, WindowError};
pub use workspace::{WorkspaceRootError, WorkspaceRoots};

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicUsize},
    time::Duration,
};
use tokio::{sync::watch, task::JoinSet};

pub const CC_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
pub const CC_INIT_TIMEOUT: Duration = Duration::from_secs(10);
pub const CC_STALL: Duration = Duration::from_secs(600);
pub const CC_PERMISSION_TTL: Duration = Duration::from_secs(600);
pub const CC_STOP_GRACE: Duration = Duration::from_secs(20);
pub const CC_TERM_GRACE: Duration = Duration::from_secs(5);
pub const CC_KILL_GRACE: Duration = Duration::from_secs(3);
pub const CC_OUTPUT_MAX: u64 = 1024 * 1024;
pub const CC_LINE_MAX: usize = 256 * 1024;
pub const HOST_MAX_CHILDREN: usize = 3;
pub const PERMISSION_SUMMARY_MAX: usize = 512;
pub const STDERR_TAIL_MAX: usize = 2048;
pub const DELIVERY_SUMMARY_MAX: usize = 2048;
pub const DELIVERY_ARTIFACTS_MAX: usize = 20;
pub const CC_READONLY_TOOLS: [&str; 4] = ["Read", "Grep", "Glob", "LS"];
/// How often a waiting permission request reads its row for the owner's decision.
pub const PERMISSION_POLL: Duration = Duration::from_millis(250);
pub const OMB_NOTICE_PERMISSION_V1: &str = "CrabCode 请求使用工具 {tool}。在本机执行 openmybot approve {id} 放行，或 openmybot deny {id} 拒绝。";

/// Per-driver budgets; the default is the specification's constants.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub version_timeout: Duration,
    pub init_timeout: Duration,
    pub stall: Duration,
    pub output_max: u64,
    pub line_max: usize,
    pub permission_ttl: Duration,
    pub permission_poll: Duration,
    pub stop_grace: Duration,
    pub term_grace: Duration,
    /// Zero means no confirmation budget: the stop ladder ends `Unknown` without probing.
    pub kill_grace: Duration,
    pub max_children: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            version_timeout: CC_VERSION_TIMEOUT,
            init_timeout: CC_INIT_TIMEOUT,
            stall: CC_STALL,
            output_max: CC_OUTPUT_MAX,
            line_max: CC_LINE_MAX,
            permission_ttl: CC_PERMISSION_TTL,
            permission_poll: PERMISSION_POLL,
            stop_grace: CC_STOP_GRACE,
            term_grace: CC_TERM_GRACE,
            kill_grace: CC_KILL_GRACE,
            max_children: HOST_MAX_CHILDREN,
        }
    }
}

pub struct HostDriverConfig {
    /// `None` refuses every start with `spawn_failed`.
    pub binary: Option<PathBuf>,
    pub home: PathBuf,
    /// `<data>/hosts/crabcode/tmp`.
    pub tmp_dir: PathBuf,
    pub roots: WorkspaceRoots,
    pub window: VersionWindow,
    pub limits: Limits,
}

/// State shared by the driver, its adapter and every session task.
pub(crate) struct Shared {
    pub(crate) config: HostDriverConfig,
    pub(crate) store: Arc<tokio_postgres::Client>,
    pub(crate) children: Arc<AtomicUsize>,
    pub(crate) shutdown: watch::Sender<bool>,
    pub(crate) tasks: Mutex<JoinSet<()>>,
}

/// The driver: owns the adapter registered under the `crabcode` extension and every live session.
pub struct HostDriver {
    shared: Arc<Shared>,
}
impl HostDriver {
    pub fn new(config: HostDriverConfig, store: Arc<tokio_postgres::Client>) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                store,
                children: Arc::new(AtomicUsize::new(0)),
                shutdown: watch::Sender::new(false),
                tasks: Mutex::new(JoinSet::new()),
            }),
        }
    }
    pub fn adapter(&self) -> Arc<HostDriverAdapter> {
        Arc::new(HostDriverAdapter {
            shared: Arc::clone(&self.shared),
        })
    }
    /// Runs stop steps 3–6 and the step 7 judgement for every live session and returns once
    /// all of them have finished.
    pub async fn shutdown(&self) {
        self.shared.shutdown.send_replace(true);
        let mut tasks = std::mem::take(&mut *self.shared.tasks.lock().unwrap());
        while tasks.join_next().await.is_some() {}
    }
}

/// `ProviderAdapter` for the `crabcode` extension key.
pub struct HostDriverAdapter {
    pub(crate) shared: Arc<Shared>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_default_equals_spec_constants() {
        let limits = Limits::default();
        assert_eq!(limits.version_timeout, Duration::from_secs(5));
        assert_eq!(limits.init_timeout, Duration::from_secs(10));
        assert_eq!(limits.stall, Duration::from_secs(600));
        assert_eq!(limits.output_max, 1_048_576);
        assert_eq!(limits.line_max, 262_144);
        assert_eq!(limits.permission_ttl, Duration::from_secs(600));
        assert_eq!(limits.permission_poll, Duration::from_millis(250));
        assert_eq!(limits.stop_grace, Duration::from_secs(20));
        assert_eq!(limits.term_grace, Duration::from_secs(5));
        assert_eq!(limits.kill_grace, Duration::from_secs(3));
        assert_eq!(limits.max_children, 3);
        assert_eq!(
            (
                PERMISSION_SUMMARY_MAX,
                STDERR_TAIL_MAX,
                DELIVERY_SUMMARY_MAX
            ),
            (512, 2048, 2048)
        );
        assert_eq!(DELIVERY_ARTIFACTS_MAX, 20);
        assert_eq!(CC_READONLY_TOOLS, ["Read", "Grep", "Glob", "LS"]);
        // The engine waits at most 30 s for a provider stop (its private PROVIDER_STOP_TIMEOUT).
        assert!(
            limits.stop_grace + limits.term_grace + limits.kill_grace < Duration::from_secs(30)
        );
    }
}
