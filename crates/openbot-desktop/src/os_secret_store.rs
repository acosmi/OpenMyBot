//! Shared current-user OS generic-secret adapter for supported Desktop platforms.
//!
//! Product-specific modules own service/account validation and stored-byte formats. This module is
//! deliberately narrower: read/write one opaque byte string through macOS Keychain or the sole
//! audited Windows Credential Manager boundary, immediately transferring reads into
//! [`SecretBytes`]. Platform calls are blocking and must run off the Tauri UI thread.

use openbot_domain::vault::SecretBytes;

#[cfg(target_os = "macos")]
mod macos_interaction;

/// Stable platform-store failures with no service, account, path, or secret payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OsSecretStoreError {
    /// The current process is not permitted to access the requested store operation.
    #[error("desktop_os_secret_store_access_denied")]
    AccessDenied,
    /// The platform rejected authentication or authorization material.
    #[error("desktop_os_secret_store_auth_failed")]
    AuthFailed,
    /// The operation requires user interaction that daily startup deliberately disables.
    #[error("desktop_os_secret_store_interaction_required")]
    InteractionRequired,
    /// The current-user platform store or its backing service is unavailable.
    #[error("desktop_os_secret_store_unavailable")]
    StoreUnavailable,
    /// The platform returned a failure outside the reviewed closed mapping.
    #[error("desktop_os_secret_store_unknown")]
    Unknown,
}

/// Opaque current-user generic-secret port. Reads transfer their unique allocation directly into
/// zeroizing ownership; implementations never log caller-supplied identifiers or bytes.
pub trait OsSecretStore: Send + Sync {
    /// Read one exact service/account pair; an absent item is `None`.
    fn read(&self, service: &str, account: &str)
    -> Result<Option<SecretBytes>, OsSecretStoreError>;

    /// Create or replace one exact service/account pair.
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError>;

    /// Read one exact pair whose value is at most `max_bytes`; a longer value
    /// is `Unknown` and is not copied into this process. Adapters that cannot
    /// see the length before their own copy check it right after.
    fn read_bounded(
        &self,
        service: &str,
        account: &str,
        max_bytes: usize,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        match self.read(service, account)? {
            Some(secret) if secret.expose().len() > max_bytes => Err(OsSecretStoreError::Unknown),
            read => Ok(read),
        }
    }
}

/// Current-user macOS Keychain generic-password adapter.
#[cfg(target_os = "macos")]
pub struct MacOsKeychainSecretStore {
    keychain: security_framework::os::macos::keychain::SecKeychain,
}

#[cfg(target_os = "macos")]
impl MacOsKeychainSecretStore {
    /// Open the current OS user's default Keychain.
    pub fn current_user_default() -> Result<Self, OsSecretStoreError> {
        macos_interaction::non_interactive(|| {
            security_framework::os::macos::keychain::SecKeychain::default()
                .map(|keychain| Self { keychain })
                .map_err(|error| macos_interaction::platform_error(error.code()))
        })
    }

    #[cfg(test)]
    pub(crate) fn from_keychain(
        keychain: security_framework::os::macos::keychain::SecKeychain,
    ) -> Self {
        Self { keychain }
    }
}

#[cfg(target_os = "macos")]
impl OsSecretStore for MacOsKeychainSecretStore {
    fn read(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        macos_interaction::non_interactive(|| {
            macos_interaction::lookup(
                self.keychain
                    .find_generic_password(service, account)
                    .map_err(|error| error.code()),
            )
            .map(|entry| {
                entry.map(|(password, _item)| SecretBytes::new(password.as_ref().to_vec()))
            })
        })
    }

    // Security.framework allocates its own password buffer before returning;
    // that buffer is outside this boundary. The length is checked on it before
    // the only copy into Rust-owned memory.
    fn read_bounded(
        &self,
        service: &str,
        account: &str,
        max_bytes: usize,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        macos_interaction::non_interactive(|| {
            match macos_interaction::lookup(
                self.keychain
                    .find_generic_password(service, account)
                    .map_err(|error| error.code()),
            )? {
                Some((password, _item)) if password.as_ref().len() > max_bytes => {
                    Err(OsSecretStoreError::Unknown)
                }
                entry => {
                    Ok(entry.map(|(password, _item)| SecretBytes::new(password.as_ref().to_vec())))
                }
            }
        })
    }

    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        macos_interaction::non_interactive(|| {
            macos_interaction::write_after_lookup(
                || {
                    macos_interaction::lookup(
                        self.keychain
                            .find_generic_password(service, account)
                            .map_err(|error| error.code()),
                    )
                    .map(|entry| entry.map(|(_password, item)| item))
                },
                |mut item| {
                    item.set_password(secret)
                        .map_err(|error| macos_interaction::platform_error(error.code()))
                },
                || {
                    self.keychain
                        .add_generic_password(service, account, secret)
                        .map_err(|error| macos_interaction::platform_error(error.code()))
                },
            )
        })
    }
}

/// Current-user Windows Credential Manager generic-credential adapter.
#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsCredentialSecretStore;

#[cfg(target_os = "windows")]
impl OsSecretStore for WindowsCredentialSecretStore {
    fn read(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        let target = format!("{service}:{account}");
        openbot_windows_sandbox::read_generic_credential(&target)
            .map(|secret| secret.map(|secret| SecretBytes::new(secret.into_bytes())))
            .map_err(|error| {
                tracing::warn!(?error, "Windows Credential Manager read failed");
                OsSecretStoreError::StoreUnavailable
            })
    }

    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        let target = format!("{service}:{account}");
        openbot_windows_sandbox::write_generic_credential(&target, secret).map_err(|error| {
            tracing::warn!(?error, "Windows Credential Manager write failed");
            OsSecretStoreError::StoreUnavailable
        })
    }
}
