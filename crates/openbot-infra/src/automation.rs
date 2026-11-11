//! PostgreSQL automation definition facts and cumulative-budget storage.

pub mod schema;

mod time;

#[cfg(feature = "server-runtime")]
pub(crate) mod store;
#[cfg(feature = "server-runtime")]
pub use store::PostgresAutomations;

#[cfg(feature = "server-runtime")]
mod authority;
#[cfg(feature = "server-runtime")]
pub use authority::PostgresAutomationAuthority;
#[cfg(feature = "server-runtime")]
pub(crate) mod dispatch;

#[cfg(feature = "server-runtime")]
mod queue;

#[cfg(feature = "server-runtime")]
mod ingress;
