//! Independently reviewed PostgreSQL maintenance tools, separate from Desktop Local startup.
//!
//! The compiled outer binding authenticates a source toolchain. It is not a platform signature,
//! production release authorization, an Existing source capability, or a capture receipt.
pub(crate) mod bundle;
#[cfg(feature = "desktop-launcher")]
pub(crate) mod capture;
pub(crate) mod clock;
pub(crate) mod limits;
mod protocol;
mod runner;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod native_owned_tests;
#[cfg(test)]
mod protocol_tests;
#[cfg(test)]
mod tests;

/// Run the closed maintenance consumer CLI; arguments exclude argv0.
///
/// Only verify and selftest-owned are accepted. The latter creates a new fixture and never opens
/// an existing application installation, a supplied database URL, or an OS secret store.
pub async fn run_maintenance_toolchain_cli(args: &[OsString]) -> ExitCode {
    let result = match parse_cli(args) {
        Ok(Cli::Verify { bundle }) => bundle::reviewed_bundle_binding()
            .and_then(|expected| bundle::verify_bundle(&bundle, expected))
            .and_then(|verified| {
                let receipt = verified.verification_receipt();
                serde_json::to_writer(std::io::stdout().lock(), &receipt)
                    .map_err(|_| MaintenanceError::IoFailure)
            }),
        Ok(Cli::Selftest {
            bundle,
            root,
            profile,
        }) => {
            match bundle::read_input_file(&profile, 64 * 1024)
                .and_then(|bytes| limits::parse_profile(&bytes))
                .and_then(|profile| {
                    let expected = bundle::reviewed_bundle_binding()?;
                    let bundle = bundle::verify_bundle(&bundle, expected)?;
                    Ok((bundle, profile))
                }) {
                Ok((bundle, profile)) => {
                    // This private resident task owns every original handle. Dropping the public
                    // CLI future detaches its join handle rather than dropping a live Child/driver.
                    // Process/runtime shutdown is still an external loss, never a closure receipt.
                    let owner = tokio::spawn(async move {
                        match runner::run_owned_selftest(bundle, root, profile).await {
                            Ok(receipt) => Ok(receipt),
                            Err(failure) => Err(failure.retain_until_original_owners_close().await),
                        }
                    });
                    match owner.await {
                        Ok(Ok(receipt)) => {
                            serde_json::to_writer(std::io::stdout().lock(), &receipt)
                                .map_err(|_| MaintenanceError::IoFailure)
                        }
                        Ok(Err(error)) => Err(error),
                        Err(_) => Err(MaintenanceError::ClosingPending),
                    }
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

enum Cli {
    Verify {
        bundle: PathBuf,
    },
    Selftest {
        bundle: PathBuf,
        root: PathBuf,
        profile: PathBuf,
    },
}

fn parse_cli(args: &[OsString]) -> Result<Cli, MaintenanceError> {
    let values = args
        .iter()
        .map(|v| v.to_str().ok_or(MaintenanceError::InvalidArguments))
        .collect::<Result<Vec<_>, _>>()?;
    let path = |s: &str| -> Result<PathBuf, MaintenanceError> {
        if s.is_empty() || s.len() > 4096 || s.contains('\0') {
            return Err(MaintenanceError::InvalidArguments);
        }
        let p = PathBuf::from(s);
        if !p.is_absolute() {
            return Err(MaintenanceError::InvalidArguments);
        }
        Ok(p)
    };
    match values.as_slice() {
        ["verify", "--bundle", root] => Ok(Cli::Verify {
            bundle: path(root)?,
        }),
        [
            "selftest-owned",
            "--bundle",
            bundle,
            "--new-owned-root",
            root,
            "--profile",
            profile,
        ] => Ok(Cli::Selftest {
            bundle: path(bundle)?,
            root: path(root)?,
            profile: path(profile)?,
        }),
        _ => Err(MaintenanceError::InvalidArguments),
    }
}

/// Closed diagnostic codes: never retain a path, server response or secret as an error payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum MaintenanceError {
    UnsupportedPlatform,
    InvalidArguments,
    TrustMissing,
    SourcePinMismatch,
    PatchMismatch,
    PatchScopeInvalid,
    DerivedTreeMismatch,
    BuildToolUnavailable,
    BuildFailed,
    BundleInvalid,
    LibraryClosureInvalid,
    ProfileMissing,
    ProfileInvalid,
    CapacityExceeded,
    ClockUnavailable,
    ClockOverflow,
    DeadlineExpired,
    Cancelled,
    SecretInvalid,
    ProtocolInvalid,
    ConnectionFailed,
    BackupFailed,
    WalRangeInvalid,
    WalWorkerFailed,
    WalWorkerWaitUnknown,
    HelperWaitUnknown,
    PipeJoinUnknown,
    SourceWaitUnknown,
    ManifestInvalid,
    RestoreCheckFailed,
    IoFailure,
    ClosingPending,
}
impl fmt::Display for MaintenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MaintenanceError {}
impl From<std::io::Error> for MaintenanceError {
    fn from(_: std::io::Error) -> Self {
        Self::IoFailure
    }
}
