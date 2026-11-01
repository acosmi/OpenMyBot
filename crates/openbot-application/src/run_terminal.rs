//! Process-local wakeup contract after a durable Run terminal commit.

use openbot_contracts::ids::{DeploymentId, RunId, TenantId, ThreadId};

/// Receives an optional wakeup; implementations must enqueue without blocking the caller.
///
/// Notices are at most once in this process, are not durable, and are not replayed after restart.
/// Consumers must read the authoritative Run status and result through the application boundary.
pub trait RunTerminalSubscriber: Send + Sync {
    /// Accept a terminal wakeup without performing blocking work.
    fn on_run_terminal(&self, notice: RunTerminalNotice);
}

/// Body-free identity and terminal kind of a durably committed Run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunTerminalNotice {
    /// Authoritative deployment of the Run.
    pub deployment: DeploymentId,
    /// Authoritative tenant of the Run.
    pub tenant: TenantId,
    /// Thread containing the Run.
    pub thread_id: ThreadId,
    /// Run whose terminal event was committed.
    pub run_id: RunId,
    /// Closed terminal outcome, without result content or error details.
    pub terminal: RunTerminalKind,
}

/// Closed outcome carried by a terminal wakeup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunTerminalKind {
    /// Run completed successfully.
    Succeeded,
    /// Run failed with a definite outcome.
    Failed,
    /// Run cancellation was confirmed.
    Cancelled,
    /// An uncertain outcome requires reconciliation.
    ReconciliationRequired,
}
