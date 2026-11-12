//! Stable error codes carried by `error`, `credential_rejected` and a failed `infer_end`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request names an unknown attempt or connection, or its body cannot be used.
    InvalidRequest,
    /// The connector is not listed in `hello`.
    ConnectorUnavailable,
    /// No token set of the requested credential generation is loaded for the connection.
    CredentialMissing,
    /// The loaded access token is no longer accepted, or the vendor path produced a new token set
    /// outside `refresh`; the host refreshes under its own authority before trying again.
    CredentialExpired,
    /// The vendor refused the token set or the refresh token; only a new login helps.
    CredentialInvalid,
    /// The login attempt ran out of time before the vendor confirmed it.
    LoginExpired,
    /// The request was cancelled by `login_cancel` or `infer_cancel`.
    Cancelled,
    RateLimited,
    /// The vendor refused the request for a reason other than the credential.
    UpstreamRejected,
    /// The vendor could not be reached or failed.
    UpstreamUnavailable,
    Internal,
}
