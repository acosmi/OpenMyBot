//! Desktop Local background composition from Tauri's current-user app-data authority.
//!
//! The event loop starts with no window. `setup` resolves `AppHandle::path().app_data_dir()`, then
//! a Tauri runtime worker performs the complete authority → PostgreSQL sidecar → fixed database →
//! application key material → shared `ApplicationService` sequence. The custom protocol remains
//! unavailable until that sequence succeeds, and the first window is created last.

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use openbot_application::tenant::package::{LoadedTenantPackage, TenantPackageError};
use openbot_computer::screen::{
    DEFAULT_SCREEN_VIEWERS_PER_STREAM, ScreenHub, ScreenSessionService,
};
use openbot_contracts::auth::AuthContext;
use openbot_infra::application_assembly::{
    ChannelRoutingProviderInput, PostgresApplicationAssembly, PostgresApplicationAssemblyInput,
    assemble_postgres_application,
};
use openbot_infra::auth::single_user::desktop_local::{
    CurrentOsUserAppDataRoot, DesktopLocalAuthority, DesktopLocalAuthorityStore,
};
use openbot_infra::db::desktop_local::DesktopLocalDatabaseError;
use openbot_infra::policy::PolicyStore;
use tauri::{App, Builder, Context, Manager, RunEvent, Runtime, Wry};

use crate::desktop_agent_runtime::{
    DesktopAgentHost, DesktopAgentHostInput, start_desktop_agent_host,
};
use crate::desktop_local_bootstrap::{
    DesktopLocalCompositionError, RunningDesktopLocalDataPlane, prepare_running_sidecar,
};
use crate::desktop_vault::{DesktopVaultKeyError, ReviewedDesktopVaultKeyStoreService};
use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};
use crate::postgres_sidecar::{
    PostgresSecretStoreError, PostgresSidecarError, PostgresSidecarSupervisor,
    ReviewedPostgresKeyStoreService, VerifiedPostgresBundle,
};
use crate::tauri_host::{
    DesktopTauriProtocol, DesktopTauriProtocolSlot, register_tauri_protocol_slot, valid_scheme,
};
use crate::{
    DesktopAgentBudgets, DesktopOpenAiProviderInput, DesktopUiPreferenceAdministration,
    DesktopUiPreferenceStore, DesktopWindowLifecycle, InProcessTransport,
    VerifiedDesktopWindowAuthority,
};

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
pub(crate) mod capture;


// This fixed fixture is a debug-only original launcher input, not a configurable source.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_FIXTURE: &str = "/Users/wrok/Desktop/wrokbot/.local-private/v7-implementation/qa/task044-maintenance-v2-registration-20261019-01/SelfOwned-normal-fixture-02";
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_OUTER: &str = "f9ee6d061d6202b15edd9de72a1560212ccc70e1438625a2559025b21edaaaf6";
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_RELEASE: &str = "/Users/wrok/Desktop/wrokbot/.local-private/v7-implementation/qa/task044-maintenance-v2-registration-20261019-01/SelfOwned-normal-fixture-02/release";
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_APP_DATA: &str = "/Users/wrok/Desktop/wrokbot/.local-private/v7-implementation/qa/task044-maintenance-v2-registration-20261019-01/SelfOwned-normal-fixture-02/app-data";
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_OUTPUT: &str = "/Users/wrok/Desktop/wrokbot/.local-private/v7-implementation/qa/task044-maintenance-v2-registration-20261019-01/SelfOwned-normal-fixture-02/capture-output";
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
const SELF_OWNED_CAPTURE_KEY: &str = "/Users/wrok/Desktop/wrokbot/.local-private/v7-implementation/qa/task044-maintenance-v2-registration-20261019-01/SelfOwned-normal-fixture-02/independent-key-medium";

// There is no public constructor, Clone, Deserialize, caller flag, path or secret injection.
#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) struct SelfOwnedCaptureFixtureBinding {
    #[cfg(feature = "postgres-maintenance")]
    store: Option<std::sync::Weak<SelfOwnedFixtureSecretStore>>,
    #[cfg(feature = "postgres-maintenance")]
    held_parent: Option<std::fs::File>,
    #[cfg(feature = "postgres-maintenance")]
    new_root: Option<std::fs::File>,
    #[cfg(feature = "postgres-maintenance")]
    original_root: Option<(u64, u64, u32, u32)>,
    #[cfg(feature = "postgres-maintenance")]
    original_verified: bool,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
#[derive(Default)]
struct SelfOwnedFixtureEntries {
    instance: Option<[u8; 64]>,
    master: Option<[u8; 33]>,
    scram: Option<[u8; 64]>,
    master_reads: u8,
    scram_reads: u8,
}
#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl Drop for SelfOwnedFixtureEntries {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(bytes) = self.master.as_mut() { bytes.zeroize(); }
        if let Some(bytes) = self.scram.as_mut() { bytes.zeroize(); }
    }
}
#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
#[derive(Default)]
struct SelfOwnedFixtureSecretStore {
    entries: Mutex<SelfOwnedFixtureEntries>,
    original_book: std::sync::OnceLock<Arc<Mutex<capture::CaptureResourceTotals>>>,
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl SelfOwnedFixtureSecretStore {
    fn original_slot(
        entries: &mut SelfOwnedFixtureEntries, service: &str, account: &str,
    ) -> Result<bool, OsSecretStoreError> {
        let (master, suffix) = match service {
            "com.acosmi.wrokbot.vault" => (true, account.strip_prefix("desktop-vault-master-v1-")),
            "com.acosmi.wrokbot.postgresql" => (false, account.strip_prefix("postgresql-17-")),
            _ => return Err(OsSecretStoreError::AccessDenied),
        };
        let bytes = suffix.ok_or(OsSecretStoreError::AccessDenied)?.as_bytes();
        if bytes.len() != 64 || !bytes.iter().all(|n| n.is_ascii_digit() || (b'a'..=b'f').contains(n)) {
            return Err(OsSecretStoreError::AccessDenied);
        }
        let instance: [u8; 64] = bytes.try_into().map_err(|_| OsSecretStoreError::AccessDenied)?;
        match entries.instance {
            Some(original) if original != instance => return Err(OsSecretStoreError::AccessDenied),
            None => entries.instance = Some(instance),
            _ => {}
        }
        Ok(master)
    }
    fn require_original_book(&self) -> Result<(), OsSecretStoreError> {
        if self.original_book.get().is_none() { return Err(OsSecretStoreError::AccessDenied); }
        Ok(())
    }
}
#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
impl OsSecretStore for SelfOwnedFixtureSecretStore {
    fn read(&self, service: &str, account: &str)
        -> Result<Option<openbot_domain::vault::SecretBytes>, OsSecretStoreError>
    {
        self.require_original_book()?;
        let mut entries = self.entries.lock().map_err(|_| OsSecretStoreError::StoreUnavailable)?;
        let master = Self::original_slot(&mut entries, service, account)?;
        // The sole New initializer reads absence, writes once, then reads back once.
        // This cannot become an unlimited allocator or a reusable OS-secret replacement.
        let reads = if master { entries.master_reads } else { entries.scram_reads };
        if reads >= 2 { return Err(OsSecretStoreError::AccessDenied); }
        let bytes: Option<&[u8]> = if master { entries.master.as_ref().map(|n| n.as_slice()) }
            else { entries.scram.as_ref().map(|n| n.as_slice()) };
        if (reads == 0) != bytes.is_none() { return Err(OsSecretStoreError::AccessDenied); }
        // Payload/class and these two exact read-result/header slots were admitted before Arc::new
        // and adopted once by the same original book before any initializer can call read/write.
        let result = bytes.map(|n| openbot_domain::vault::SecretBytes::new(n.to_vec()));
        // This fixed New fixture permits only its one real readback. Wipe the RAM
        // slot before the original consumer can allocate its decoded master copy;
        // never call the linear move of that consumer's SCRAM source a wipe.
        if result.is_some() {
            use zeroize::Zeroize;
            if master {
                if let Some(bytes) = entries.master.as_mut() { bytes.zeroize(); }
                entries.master = None;
            } else {
                if let Some(bytes) = entries.scram.as_mut() { bytes.zeroize(); }
                entries.scram = None;
            }
        }
        if master { entries.master_reads += 1; } else { entries.scram_reads += 1; }
        Ok(result)
    }
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        self.require_original_book()?;
        let mut entries = self.entries.lock().map_err(|_| OsSecretStoreError::StoreUnavailable)?;
        if Self::original_slot(&mut entries, service, account)? {
            if entries.master.is_some() || entries.master_reads != 1 || secret.len() != 33 || secret[0] != 1 {
                return Err(OsSecretStoreError::AccessDenied);
            }
            entries.master = Some([0; 33]);
            entries.master.as_mut().ok_or(OsSecretStoreError::AccessDenied)?.copy_from_slice(secret);
        } else {
            if entries.scram.is_some() || entries.scram_reads != 1 || secret.len() != 64
                || !secret.iter().all(|n| n.is_ascii_digit() || (b'a'..=b'f').contains(n)) {
                return Err(OsSecretStoreError::AccessDenied);
            }
            entries.scram = Some([0; 64]);
            entries.scram.as_mut().ok_or(OsSecretStoreError::AccessDenied)?.copy_from_slice(secret);
        }
        Ok(())
    }
}

#[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
pub(crate) fn checked_self_owned_fixture_metadata_bytes() -> Result<u64, DesktopLocalRuntimeError> {
    use std::mem::size_of;
    use openbot_domain::vault::SecretBytes;
    let arc = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
        .align_to(2).map_err(|_| DesktopLocalRuntimeError::Configuration)?
        .extend(std::alloc::Layout::new::<SelfOwnedFixtureSecretStore>())
        .map_err(|_| DesktopLocalRuntimeError::Configuration)?.0.pad_to_align().size();
    // 97 resident secret bytes belong to original master_source / scram_source, not metadata.
    let arc_metadata = arc.checked_sub(97).ok_or(DesktopLocalRuntimeError::Configuration)?;
    let mut total = 0usize;
    for n in [
        arc_metadata, size_of::<SelfOwnedFixtureSecretStore>(),
        size_of::<SelfOwnedFixtureEntries>(), size_of::<SelfOwnedCaptureFixtureBinding>(),
        size_of::<Option<SelfOwnedCaptureFixtureBinding>>(),
        size_of::<Arc<dyn OsSecretStore>>(), size_of::<Arc<SelfOwnedFixtureSecretStore>>(),
        size_of::<std::sync::Weak<SelfOwnedFixtureSecretStore>>() * 2,
        size_of::<Option<Arc<SelfOwnedFixtureSecretStore>>>(),
        size_of::<Arc<Mutex<capture::CaptureResourceTotals>>>() * 2,
        size_of::<std::sync::MutexGuard<'static, SelfOwnedFixtureEntries>>() * 4,
        size_of::<std::sync::LockResult<std::sync::MutexGuard<'static, SelfOwnedFixtureEntries>>>() * 4,
        size_of::<Result<Option<SecretBytes>, OsSecretStoreError>>() * 2,
        size_of::<SecretBytes>() * 2, size_of::<Result<(), OsSecretStoreError>>() * 2,
        size_of::<std::fs::Metadata>() * 5, size_of::<std::io::Result<std::fs::Metadata>>() * 5,
        size_of::<std::fs::File>() * 2, size_of::<Result<std::fs::File, std::io::Error>>() * 2,
        size_of::<Option<(u64, u64, u32, u32)>>(), size_of::<[u8; 64]>(),
        size_of::<Option<&[u8]>>(), size_of::<Option<[u8; 33]>>(), size_of::<Option<[u8; 64]>>(),
        size_of::<Result<bool, OsSecretStoreError>>(), size_of::<Result<(), DesktopLocalRuntimeError>>() * 4,
        size_of::<rustix::fs::Stat>(), size_of::<Result<rustix::fs::Stat, rustix::io::Errno>>(),
    ] { total = total.checked_add(n).ok_or(DesktopLocalRuntimeError::Configuration)?; }
    // Fixed app-data PathBuf backing plus original trusted-directory getpath request; the
    // existing path parser's allocator internals retain their original unproven boundary.
    // rustix1.1.4 getpath uses locked macOS libc PATH_MAX=1024, then shrink
    // and CString NUL growth; count both old/new requests before linear into_vec.
    total = total.checked_add(SELF_OWNED_CAPTURE_APP_DATA.len())
        .and_then(|n| n.checked_add(1024))
        .and_then(|n| n.checked_add(SELF_OWNED_CAPTURE_FIXTURE.len().checked_mul(2)?))
        .and_then(|n| n.checked_add(1))
        .ok_or(DesktopLocalRuntimeError::Configuration)?;
    u64::try_from(total).map_err(|_| DesktopLocalRuntimeError::Configuration)
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
pub(crate) fn bind_self_owned_capture_fixture(
    request: Option<&crate::desktop_release::ReviewedNormalCaptureRequest>,
) -> Result<Option<(SelfOwnedCaptureFixtureBinding, Arc<dyn OsSecretStore>)>, DesktopLocalRuntimeError> {
    // Retired fixed fixture pins must fail before any current-user secret-store fallback.
    if option_env!("WROK_BOT_DESKTOP_RELEASE_SHA256")
        == Some("64428c91f9123a42a1220a6cfb0b78dd6f1082a928827b230fca66e1640b4dc1")
        || option_env!("WROK_BOT_DESKTOP_RELEASE_SHA256")
            == Some("77ea40dfc06352b5161317beae22a325cfb2b0ef827575d37d5bfef8895ceae2")
    {
        return Err(DesktopLocalRuntimeError::Configuration);
    }
    if option_env!("WROK_BOT_DESKTOP_RELEASE_SHA256") != Some(SELF_OWNED_CAPTURE_OUTER) {
        return Ok(None);
    }
    #[cfg(not(all(feature = "postgres-maintenance", debug_assertions)))]
    { let _ = request; return Err(DesktopLocalRuntimeError::Configuration); }
    #[cfg(all(feature = "postgres-maintenance", debug_assertions))]
    {
        use std::os::unix::fs::MetadataExt;
        let request = request.ok_or(DesktopLocalRuntimeError::Configuration)?;
        let expected = [0xf9,0xee,0x6d,0x06,0x1d,0x62,0x02,0xb1,0x5e,0xdd,0x9d,0xe7,0x2a,0x15,0x60,0x21,0x2c,0xcc,0x70,0xe1,0x43,0x86,0x25,0xa2,0x55,0x90,0x25,0xb2,0x1e,0xda,0xaa,0xf6];
        let known = checked_self_owned_fixture_metadata_bytes()?;
        request.profile.validate_self_owned_fixture_retention(known)
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let fixed = std::path::Path::new(SELF_OWNED_CAPTURE_FIXTURE);
        let release = std::path::Path::new(SELF_OWNED_CAPTURE_RELEASE);
        let held = request.release_root.metadata().map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let named = std::fs::symlink_metadata(release).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let parent = std::fs::symlink_metadata(fixed).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        if request.release_digest != expected
            || request.request_id != "ba037759c50383b4cdd3769d0159fbe2daebee1d15629682f8c20b1d90fb28d7"
            || request.release_path != release
            || !held.is_dir() || !named.is_dir() || named.file_type().is_symlink()
            || (held.dev(), held.ino(), held.uid(), held.mode() & 0o7777) != (16777232,111166603,501,0o700)
            || (named.dev(), named.ino(), named.uid(), named.mode()) != (held.dev(),held.ino(),held.uid(),held.mode())
            || !parent.is_dir() || parent.file_type().is_symlink()
            || (parent.dev(),parent.ino(),parent.uid(),parent.mode() & 0o7777) != (16777232,111166602,501,0o700)
        { return Err(DesktopLocalRuntimeError::Configuration); }
        for (destination, leaf, inode) in [(&request.output, "capture-output", 111166604u64), (&request.key_medium, "independent-key-medium",111166605u64)] {
            let fixed_destination = if leaf == "capture-output" { SELF_OWNED_CAPTURE_OUTPUT } else { SELF_OWNED_CAPTURE_KEY };
            if destination.absolute_path != std::path::Path::new(fixed_destination)
                || (destination.device,destination.inode,destination.uid) != (16777232,inode,501) {
                return Err(DesktopLocalRuntimeError::Configuration);
            }
            let m = std::fs::symlink_metadata(&destination.absolute_path).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
            if !m.is_dir() || m.file_type().is_symlink() || (m.dev(),m.ino(),m.uid(),m.mode() & 0o7777) != (16777232,inode,501,0o700) {
                return Err(DesktopLocalRuntimeError::Configuration);
            }
        }
        match std::fs::symlink_metadata(SELF_OWNED_CAPTURE_APP_DATA) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(DesktopLocalRuntimeError::Configuration),
        }
        request.original_compatibility_metadata_bytes().map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let store = Arc::new(SelfOwnedFixtureSecretStore::default());
        let binding = SelfOwnedCaptureFixtureBinding { store: Some(Arc::downgrade(&store)), held_parent: None, new_root: None, original_root: None, original_verified: false };
        Ok(Some((binding, store)))
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl SelfOwnedCaptureFixtureBinding {
    fn app_data_root(&self) -> Result<CurrentOsUserAppDataRoot, DesktopLocalRuntimeError> {
        CurrentOsUserAppDataRoot::from_current_os_user_app_data(
            std::path::Path::new(SELF_OWNED_CAPTURE_APP_DATA).to_path_buf(),
        ).map_err(|_| DesktopLocalRuntimeError::Configuration)
    }
    #[cfg(feature = "postgres-maintenance")]
    fn prepare_new_root_before_startup(&mut self, book: &Arc<Mutex<capture::CaptureResourceTotals>>)
        -> Result<(), DesktopLocalRuntimeError>
    {
        use std::os::unix::fs::MetadataExt;
        use rustix::fs::{OFlags, Mode};
        if self.held_parent.is_some() || self.new_root.is_some() { return Err(DesktopLocalRuntimeError::Configuration); }
        capture::reserve_capture_resources(book, 2, checked_self_owned_fixture_metadata_bytes()?)
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        self.held_parent = Some(capture::control::open_trusted_directory(std::path::Path::new(SELF_OWNED_CAPTURE_FIXTURE), true)
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?);
        let parent = self.held_parent.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?;
        let m = parent.metadata().map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        if (m.dev(),m.ino(),m.uid(),m.mode() & 0o7777) != (16777232,111166602,501,0o700) {
            return Err(DesktopLocalRuntimeError::Configuration);
        }
        // mkdirat has no EEXIST adoption. The original New initializer follows only this root.
        rustix::fs::mkdirat(parent, "app-data", Mode::RWXU).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        self.new_root = Some(std::fs::File::from(rustix::fs::openat(parent,"app-data",OFlags::RDONLY|OFlags::DIRECTORY|OFlags::NOFOLLOW|OFlags::CLOEXEC,Mode::empty())
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?));
        let root = self.new_root.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?;
        let m = root.metadata().map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        if !m.is_dir() || m.uid()!=501 || m.mode() & 0o7777 != 0o700 { return Err(DesktopLocalRuntimeError::Configuration); }
        self.original_root=Some((m.dev(),m.ino(),m.uid(),m.mode() & 0o7777));
        rustix::fs::fsync(parent).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let store = self.store.as_ref().and_then(std::sync::Weak::upgrade).ok_or(DesktopLocalRuntimeError::Configuration)?;
        store.original_book.set(Arc::clone(book)).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        drop(store);
        Ok(())
    }
    #[cfg(feature = "postgres-maintenance")]
    fn verify_original_root(&mut self, installation: &openbot_infra::auth::single_user::desktop_local::RetainedInstallationCapture)
        -> Result<(), DesktopLocalRuntimeError>
    {
        use std::os::unix::fs::MetadataExt;
        let expected=self.original_root.ok_or(DesktopLocalRuntimeError::Configuration)?;
        let m=installation.original_root().metadata().map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        let named=rustix::fs::statat(self.held_parent.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?, "app-data", rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        if !m.is_dir() || (m.dev(),m.ino(),m.uid(),m.mode() & 0o7777)!=expected
            || (named.st_dev as u64,named.st_ino,named.st_uid,u32::from(named.st_mode) & 0o7777)!=expected {
            return Err(DesktopLocalRuntimeError::Configuration);
        }
        self.original_verified=true;
        Ok(())
    }
    #[cfg(feature = "postgres-maintenance")]
    fn require_original_store_dropped(&self) -> Result<(), DesktopLocalRuntimeError> {
        if !self.original_verified || self.store.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?.upgrade().is_some() {
            return Err(DesktopLocalRuntimeError::Configuration);
        }
        Ok(())
    }
    #[cfg(feature = "postgres-maintenance")]
    pub(crate) fn require_window_witness(&self) -> Result<(), DesktopLocalRuntimeError> {
        self.require_original_store_dropped()
    }
    #[cfg(feature = "postgres-maintenance")]
    fn retire_before_window_ready(mut self) -> Result<(), DesktopLocalRuntimeError> {
        self.require_original_store_dropped()?;
        drop(self.store.take()); // the last Weak allocation header is gone before mark_ready
        drop(self.new_root.take());
        drop(self.held_parent.take());
        Ok(())
    }
}

type PackageFactory = Box<
    dyn FnOnce(&DesktopLocalAuthority) -> Result<LoadedTenantPackage, TenantPackageError>
        + Send
        + 'static,
>;

const DESKTOP_UI_PREFERENCES_FILE: &str = "ui-preferences-v1";
const STARTUP_DIAGNOSTIC_MAX_BYTES: usize = 256;

/// Stable startup/shutdown failures with no path, secret, package prose, or platform diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum DesktopLocalRuntimeError {
    /// Caller-supplied scheme, window label, or Desktop network policy was outside the closed shape.
    #[error("desktop_local_runtime_configuration_invalid")]
    Configuration,
    /// Tauri could not resolve the current user's application-data directory.
    #[error("desktop_local_runtime_app_data_unavailable")]
    AppData,
    /// App-instance identity or its private PostgreSQL directory could not be loaded.
    #[error("desktop_local_runtime_authority_failed")]
    Authority,
    /// The release-attested PostgreSQL child did not reach SCRAM readiness.
    #[error("desktop_local_runtime_sidecar_failed")]
    Sidecar,
    /// The release package factory did not return a valid exact-instance package.
    #[error("desktop_local_runtime_package_failed")]
    Package,
    /// Fixed database, migration, principal, or package bootstrap failed.
    #[error("desktop_local_runtime_data_plane_failed")]
    DataPlane,
    /// Per-instance application key material could not be loaded from the OS store.
    #[error("desktop_local_runtime_vault_failed")]
    Vault,
    /// The OS denied the signed process access to a required startup secret.
    #[error("desktop_local_runtime_os_secret_store_access_denied")]
    OsSecretStoreAccessDenied(#[source] OsSecretStoreError),
    /// The OS rejected authentication or authorization for a required startup secret.
    #[error("desktop_local_runtime_os_secret_store_auth_failed")]
    OsSecretStoreAuthFailed(#[source] OsSecretStoreError),
    /// A required startup secret needs interaction while daily startup is noninteractive.
    #[error("desktop_local_runtime_os_secret_store_interaction_required")]
    OsSecretStoreInteractionRequired(#[source] OsSecretStoreError),
    /// The current-user OS secret store or backing service is unavailable.
    #[error("desktop_local_runtime_os_secret_store_unavailable")]
    OsSecretStoreUnavailable(#[source] OsSecretStoreError),
    /// The OS secret store returned an unclassified, payload-free startup failure.
    #[error("desktop_local_runtime_os_secret_store_unknown")]
    OsSecretStoreUnknown(#[source] OsSecretStoreError),
    /// A key-store call failed after startup entered a secret write/read-back phase.
    #[error("desktop_local_runtime_os_secret_store_reconciliation_required")]
    OsSecretStoreReconciliationRequired(#[source] OsSecretStoreError),
    /// Another verified process currently owns this instance's startup guard.
    #[error("desktop_local_runtime_startup_busy")]
    StartupBusy,
    /// Existing instance evidence requires an explicit, separately authorized recovery flow.
    #[error("desktop_local_runtime_recovery_required")]
    RecoveryRequired,
    /// Persistent initialization evidence was corrupt, inconsistent, or no longer authoritative.
    #[error("desktop_local_runtime_initialization_evidence_invalid")]
    InitializationEvidenceInvalid,
    /// A payload-free initialization write/read-back result requires reconciliation.
    #[error("desktop_local_runtime_initialization_reconciliation_required")]
    InitializationReconciliationRequired,
    /// The authoritative action-policy snapshot could not be loaded.
    #[error("desktop_local_runtime_policy_failed")]
    Policy,
    /// Shared PostgreSQL application adapter assembly failed.
    #[error("desktop_local_runtime_application_failed")]
    Application,
    /// Built-in/remote Agent runtime or durable run relay could not start.
    #[error("desktop_local_runtime_agent_failed")]
    Agent,
    /// Local bundle/protocol/window construction failed after application assembly.
    #[error("desktop_local_runtime_host_failed")]
    Host,
    /// Startup failed after a child existed and verified cleanup could not complete.
    #[error("desktop_local_runtime_failure_cleanup_failed")]
    FailureCleanup,
    /// The process-wide background state was poisoned or made an impossible transition.
    #[error("desktop_local_runtime_state_failed")]
    State,
    /// Final authority/transport/reconciler/sidecar shutdown did not fully complete.
    #[error("desktop_local_runtime_shutdown_failed")]
    Shutdown,
    /// Tauri application construction failed before the event loop started.
    #[error("desktop_local_runtime_build_failed")]
    Build,
}

impl DesktopLocalRuntimeError {
    fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "desktop_local_runtime_configuration_invalid",
            Self::AppData => "desktop_local_runtime_app_data_unavailable",
            Self::Authority => "desktop_local_runtime_authority_failed",
            Self::Sidecar => "desktop_local_runtime_sidecar_failed",
            Self::Package => "desktop_local_runtime_package_failed",
            Self::DataPlane => "desktop_local_runtime_data_plane_failed",
            Self::Vault => "desktop_local_runtime_vault_failed",
            Self::OsSecretStoreAccessDenied(_) => {
                "desktop_local_runtime_os_secret_store_access_denied"
            }
            Self::OsSecretStoreAuthFailed(_) => "desktop_local_runtime_os_secret_store_auth_failed",
            Self::OsSecretStoreInteractionRequired(_) => {
                "desktop_local_runtime_os_secret_store_interaction_required"
            }
            Self::OsSecretStoreUnavailable(_) => {
                "desktop_local_runtime_os_secret_store_unavailable"
            }
            Self::OsSecretStoreUnknown(_) => "desktop_local_runtime_os_secret_store_unknown",
            Self::OsSecretStoreReconciliationRequired(_) => {
                "desktop_local_runtime_os_secret_store_reconciliation_required"
            }
            Self::StartupBusy => "desktop_local_runtime_startup_busy",
            Self::RecoveryRequired => "desktop_local_runtime_recovery_required",
            Self::InitializationEvidenceInvalid => {
                "desktop_local_runtime_initialization_evidence_invalid"
            }
            Self::InitializationReconciliationRequired => {
                "desktop_local_runtime_initialization_reconciliation_required"
            }
            Self::Policy => "desktop_local_runtime_policy_failed",
            Self::Application => "desktop_local_runtime_application_failed",
            Self::Agent => "desktop_local_runtime_agent_failed",
            Self::Host => "desktop_local_runtime_host_failed",
            Self::FailureCleanup => "desktop_local_runtime_failure_cleanup_failed",
            Self::State => "desktop_local_runtime_state_failed",
            Self::Shutdown => "desktop_local_runtime_shutdown_failed",
            Self::Build => "desktop_local_runtime_build_failed",
        }
    }

    fn os_code(&self) -> Option<&'static str> {
        let source = match self {
            Self::OsSecretStoreAccessDenied(source)
            | Self::OsSecretStoreAuthFailed(source)
            | Self::OsSecretStoreInteractionRequired(source)
            | Self::OsSecretStoreUnavailable(source)
            | Self::OsSecretStoreUnknown(source)
            | Self::OsSecretStoreReconciliationRequired(source) => source,
            _ => return None,
        };
        Some(match source {
            OsSecretStoreError::AccessDenied => "desktop_os_secret_store_access_denied",
            OsSecretStoreError::AuthFailed => "desktop_os_secret_store_auth_failed",
            OsSecretStoreError::InteractionRequired => {
                "desktop_os_secret_store_interaction_required"
            }
            OsSecretStoreError::StoreUnavailable => "desktop_os_secret_store_unavailable",
            OsSecretStoreError::Unknown => "desktop_os_secret_store_unknown",
        })
    }
}

fn startup_failure_diagnostic(error: &DesktopLocalRuntimeError) -> String {
    let mut diagnostic = format!("wrok_bot_desktop_startup_failed code={}", error.code());
    if let Some(os_code) = error.os_code() {
        diagnostic.push_str(" os_code=");
        diagnostic.push_str(os_code);
    }
    diagnostic.push('\n');
    debug_assert!(diagnostic.len() <= STARTUP_DIAGNOSTIC_MAX_BYTES);
    diagnostic
}

fn report_startup_failure_to<W: Write + ?Sized>(error: &DesktopLocalRuntimeError, sink: &mut W) {
    let diagnostic = startup_failure_diagnostic(error);
    if diagnostic.len() <= STARTUP_DIAGNOSTIC_MAX_BYTES {
        // One write attempt only. A partial or broken stderr must not retry, panic, or replace the
        // startup failure that has already completed its unique-owner cleanup.
        if let Ok(written) = sink.write(diagnostic.as_bytes()) {
            debug_assert!(written <= diagnostic.len());
        }
    }
}

fn report_preparation_result_to<T, W: Write + ?Sized>(
    result: Result<T, DesktopLocalRuntimeError>,
    sink: &mut W,
) -> Result<T, DesktopLocalRuntimeError> {
    result.inspect_err(|error| report_startup_failure_to(error, sink))
}

fn report_preparation_result<T>(
    result: Result<T, DesktopLocalRuntimeError>,
) -> Result<T, DesktopLocalRuntimeError> {
    let result = {
        let stderr = std::io::stderr();
        let mut sink = stderr.lock();
        report_preparation_result_to(result, &mut sink)
    };
    result.inspect_err(|error| {
        tracing::error!(code = error.code(), "Desktop Local startup failed");
    })
}

/// Reviewed release resources that remain independent from the current user's app-data path.
pub(crate) enum DesktopUiResource {
    Path(PathBuf),
    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    Verified(crate::tauri_host::VerifiedUiAssets),
}

/// Reviewed release resources independent from current-user app data. Product builds consume the
/// immutable verified UI variant; the path constructor remains an explicit host/development lane.
pub struct DesktopLocalReleaseInput {
    ui: DesktopUiResource,
    scheme: String,
    window_label: String,
    postgres_bundle: VerifiedPostgresBundle,
    postgres_key_store_service: ReviewedPostgresKeyStoreService,
    vault_key_store_service: ReviewedDesktopVaultKeyStoreService,
    secret_store: Arc<dyn OsSecretStore>,
}

impl DesktopLocalReleaseInput {
    /// Bind verified release assets and reviewed platform key-store identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dist: impl Into<PathBuf>,
        scheme: impl Into<String>,
        window_label: impl Into<String>,
        postgres_bundle: VerifiedPostgresBundle,
        postgres_key_store_service: ReviewedPostgresKeyStoreService,
        vault_key_store_service: ReviewedDesktopVaultKeyStoreService,
        secret_store: Arc<dyn OsSecretStore>,
    ) -> Result<Self, DesktopLocalRuntimeError> {
        Self::new_with_ui(
            DesktopUiResource::Path(dist.into()),
            scheme,
            window_label,
            postgres_bundle,
            postgres_key_store_service,
            vault_key_store_service,
            secret_store,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_ui(
        ui: DesktopUiResource,
        scheme: impl Into<String>,
        window_label: impl Into<String>,
        postgres_bundle: VerifiedPostgresBundle,
        postgres_key_store_service: ReviewedPostgresKeyStoreService,
        vault_key_store_service: ReviewedDesktopVaultKeyStoreService,
        secret_store: Arc<dyn OsSecretStore>,
    ) -> Result<Self, DesktopLocalRuntimeError> {
        let scheme = scheme.into();
        let window_label = window_label.into();
        if !valid_scheme(&scheme) || !valid_window_label(&window_label) {
            return Err(DesktopLocalRuntimeError::Configuration);
        }
        Ok(Self {
            ui,
            scheme,
            window_label,
            postgres_bundle,
            postgres_key_store_service,
            vault_key_store_service,
            secret_store,
        })
    }
}

impl core::fmt::Debug for DesktopLocalReleaseInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopLocalReleaseInput")
            .field("ui", &"<reviewed-resource>")
            .field("scheme", &"<reviewed>")
            .field("window_label", &self.window_label)
            .field("postgres_bundle", &self.postgres_bundle)
            .field(
                "postgres_key_store_service",
                &self.postgres_key_store_service,
            )
            .field("vault_key_store_service", &self.vault_key_store_service)
            .field("secret_store", &"current-user OS store")
            .finish()
    }
}

/// Desktop-specific, environment-free inputs to the shared application composition root.
pub struct DesktopLocalApplicationInput {
    provider: DesktopOpenAiProviderInput,
    budgets: DesktopAgentBudgets,
}

impl DesktopLocalApplicationInput {
    /// Bind already-validated environment-free provider and Agent budget inputs.
    pub fn new(
        provider: DesktopOpenAiProviderInput,
        budgets: DesktopAgentBudgets,
    ) -> Result<Self, DesktopLocalRuntimeError> {
        provider
            .remote_transport(budgets.stall_timeout)
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
        Ok(Self { provider, budgets })
    }
}

impl core::fmt::Debug for DesktopLocalApplicationInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopLocalApplicationInput")
            .field("provider", &self.provider)
            .field("budgets", &self.budgets)
            .finish()
    }
}

/// One-shot setup plan. The package factory receives the elected app-instance authority, so a
/// release template cannot guess or hard-code the per-installation tenant.
pub struct DesktopLocalRuntimeConfig {
    release: DesktopLocalReleaseInput,
    application: DesktopLocalApplicationInput,
    package_factory: PackageFactory,
    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    self_owned_capture_fixture: Option<SelfOwnedCaptureFixtureBinding>,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture_request: Option<crate::desktop_release::ReviewedNormalCaptureRequest>,
}

impl DesktopLocalRuntimeConfig {
    /// Construct a one-shot plan from reviewed release inputs and an exact-instance package source.
    #[must_use]
    pub fn new<F>(
        release: DesktopLocalReleaseInput,
        application: DesktopLocalApplicationInput,
        package_factory: F,
    ) -> Self
    where
        F: FnOnce(&DesktopLocalAuthority) -> Result<LoadedTenantPackage, TenantPackageError>
            + Send
            + 'static,
    {
        Self {
            release,
            application,
            package_factory: Box::new(package_factory),
            #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
            self_owned_capture_fixture: None,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            capture_request: None,
        }
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn with_reviewed_normal_capture(
        mut self,
        request: Option<crate::desktop_release::ReviewedNormalCaptureRequest>,
    ) -> Self {
        self.capture_request = request;
        self
    }
}

#[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
impl DesktopLocalRuntimeConfig {
    pub(crate) fn with_self_owned_capture_fixture(mut self, binding: SelfOwnedCaptureFixtureBinding) -> Self {
        self.self_owned_capture_fixture = Some(binding);
        self
    }
}

impl core::fmt::Debug for DesktopLocalRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopLocalRuntimeConfig")
            .field("release", &self.release)
            .field("application", &self.application)
            .field("package_factory", &"<one-shot>")
            .finish()
    }
}

/// Observable lifecycle phase used by the event-loop exit fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopLocalRuntimePhase {
    /// `setup` returned with no window and background initialization is running.
    Initializing,
    /// All background owners exist and the first verified window is being created.
    StartingWindow,
    /// At least one verified native window is active.
    Ready,
    /// New work is fenced and shutdown is running.
    Stopping,
    /// Ordered shutdown completed; the next exit request may terminate the process.
    Stopped,
    /// Startup or shutdown failed; the process exits non-zero.
    Failed,
}

struct RuntimeStateInner {
    phase: DesktopLocalRuntimePhase,
    exit_requested: bool,
    terminal_exit: bool,
    startup_complete: bool,
    lifecycle: Option<Arc<DesktopWindowLifecycle>>,
    owner: Option<Box<dyn RuntimeShutdownOwner>>,
    closing_observation: Option<Arc<DesktopLocalClosingObservation>>,
}

/// Managed state shared by Tauri setup, window callbacks, commands, and the run-loop exit fence.
pub struct DesktopLocalRuntimeState {
    inner: Mutex<RuntimeStateInner>,
    changed: tokio::sync::watch::Sender<()>,
}

impl DesktopLocalRuntimeState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(RuntimeStateInner {
                phase: DesktopLocalRuntimePhase::Initializing,
                exit_requested: false,
                terminal_exit: false,
                startup_complete: false,
                lifecycle: None,
                owner: None,
                closing_observation: None,
            }),
            changed: tokio::sync::watch::channel(()).0,
        })
    }

    /// Read the current closed lifecycle phase without exposing paths or errors.
    #[must_use]
    pub fn phase(&self) -> DesktopLocalRuntimePhase {
        self.inner
            .lock()
            .map(|inner| inner.phase)
            .unwrap_or(DesktopLocalRuntimePhase::Failed)
    }

    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn closing_acknowledgements_for_reviewed_test(
        &self,
    ) -> Option<(
        Option<Instant>,
        Option<Instant>,
        Option<Instant>,
        Option<bool>,
    )> {
        let observation = self.inner.lock().ok()?.closing_observation.clone()?;
        let facts = observation.facts.lock().ok()?;
        Some((
            facts.drain_ack_at,
            facts.postgres_ack_at,
            facts.job_finished_at,
            match facts.outcome {
                Some(DesktopLocalClosingOutcome::Succeeded) => Some(true),
                Some(DesktopLocalClosingOutcome::Failed) => Some(false),
                Some(DesktopLocalClosingOutcome::Unknown) | None => None,
            },
        ))
    }

    fn note_exit_requested(&self) -> Result<bool, DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        inner.exit_requested = true;
        Ok(inner.phase == DesktopLocalRuntimePhase::Ready)
    }

    fn exit_requested(&self) -> Result<bool, DesktopLocalRuntimeError> {
        self.inner
            .lock()
            .map(|inner| inner.exit_requested)
            .map_err(|_| DesktopLocalRuntimeError::State)
    }

    fn install_owner(
        &self,
        owner: &mut Option<Box<dyn RuntimeShutdownOwner>>,
        lifecycle: Arc<DesktopWindowLifecycle>,
    ) -> Result<bool, DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        if inner.phase != DesktopLocalRuntimePhase::Initializing || inner.owner.is_some() {
            return Err(DesktopLocalRuntimeError::State);
        }
        if owner.is_none() {
            return Err(DesktopLocalRuntimeError::State);
        }
        inner.phase = DesktopLocalRuntimePhase::StartingWindow;
        inner.lifecycle = Some(lifecycle);
        inner.owner = owner.take();
        self.changed.send_replace(());
        Ok(inner.exit_requested)
    }

    fn mark_ready(&self) -> Result<bool, DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        if inner.phase != DesktopLocalRuntimePhase::StartingWindow {
            return Err(DesktopLocalRuntimeError::State);
        }
        inner.phase = DesktopLocalRuntimePhase::Ready;
        self.changed.send_replace(());
        Ok(inner.exit_requested)
    }

    fn lifecycle(&self) -> Option<Arc<DesktopWindowLifecycle>> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.lifecycle.clone())
    }

    fn begin_shutdown(
        &self,
    ) -> Result<Option<Box<dyn RuntimeShutdownOwner>>, DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        match inner.phase {
            DesktopLocalRuntimePhase::StartingWindow | DesktopLocalRuntimePhase::Ready => {
                let owner = inner.owner.take().ok_or(DesktopLocalRuntimeError::State)?;
                inner.phase = DesktopLocalRuntimePhase::Stopping;
                inner.lifecycle = None;
                self.changed.send_replace(());
                Ok(Some(owner))
            }
            DesktopLocalRuntimePhase::Stopping
            | DesktopLocalRuntimePhase::Stopped
            | DesktopLocalRuntimePhase::Failed
            | DesktopLocalRuntimePhase::Initializing => Ok(None),
        }
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    fn begin_native_exit_shutdown(
        &self,
        requested_code: Option<i32>,
    ) -> Result<
        Option<(
            Box<dyn RuntimeShutdownOwner>,
            Option<capture::NormalReadyExitToken>,
        )>,
        DesktopLocalRuntimeError,
    > {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        match inner.phase {
            DesktopLocalRuntimePhase::StartingWindow | DesktopLocalRuntimePhase::Ready => {
                let ready = if inner.phase == DesktopLocalRuntimePhase::Ready
                    && (requested_code == Some(0)
                        || requested_code.is_none() && inner.terminal_exit)
                {
                    Some(capture::NormalReadyExitToken::from_original_native_ready(
                        &inner,
                    )?)
                } else {
                    None
                };
                let owner = inner.owner.take().ok_or(DesktopLocalRuntimeError::State)?;
                inner.phase = DesktopLocalRuntimePhase::Stopping;
                inner.lifecycle = None;
                self.changed.send_replace(());
                Ok(Some((owner, ready)))
            }
            _ => Ok(None),
        }
    }

    fn finish_shutdown(&self, succeeded: bool) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = if succeeded {
                DesktopLocalRuntimePhase::Stopped
            } else {
                DesktopLocalRuntimePhase::Failed
            };
            inner.lifecycle = None;
            inner.owner = None;
        }
        self.changed.send_replace(());
    }

    fn install_closing_observation(
        &self,
        observation: Arc<DesktopLocalClosingObservation>,
    ) -> Result<(), DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        if inner.closing_observation.is_some() || inner.phase != DesktopLocalRuntimePhase::Stopping
        {
            return Err(DesktopLocalRuntimeError::State);
        }
        inner.closing_observation = Some(observation);
        Ok(())
    }

    fn fail_startup(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = DesktopLocalRuntimePhase::Failed;
            inner.lifecycle = None;
            inner.owner = None;
        }
        self.changed.send_replace(());
    }

    fn finish_startup(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.startup_complete = true;
            // A dropped/panicking startup must not leave terminal Exit waiting on a notification
            // that can no longer arrive. Explicit acquisition failures already cleaned up below.
            if inner.phase == DesktopLocalRuntimePhase::Initializing {
                inner.phase = DesktopLocalRuntimePhase::Failed;
            }
        }
        self.changed.send_replace(());
    }

    fn stop_before_startup(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return true;
        };
        if inner.exit_requested && inner.phase == DesktopLocalRuntimePhase::Initializing {
            inner.phase = DesktopLocalRuntimePhase::Stopped;
            self.changed.send_replace(());
            true
        } else {
            false
        }
    }

    fn can_create_window(&self) -> bool {
        self.inner.lock().is_ok_and(|inner| {
            inner.phase == DesktopLocalRuntimePhase::StartingWindow
                && !inner.exit_requested
                && !inner.terminal_exit
        })
    }

    fn is_terminal_exit(&self) -> bool {
        self.inner.lock().map_or(true, |inner| inner.terminal_exit)
    }

    fn note_terminal_exit(&self) -> Result<(), DesktopLocalRuntimeError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| DesktopLocalRuntimeError::State)?;
        inner.terminal_exit = true;
        inner.exit_requested = true;
        self.changed.send_replace(());
        Ok(())
    }

    async fn join_terminal_exit(self: &Arc<Self>) -> Result<(), DesktopLocalRuntimeError> {
        let mut changed = self.changed.subscribe();
        self.note_terminal_exit()?;
        loop {
            let (phase, startup_complete) = {
                let inner = self
                    .inner
                    .lock()
                    .map_err(|_| DesktopLocalRuntimeError::State)?;
                (inner.phase, inner.startup_complete)
            };
            match phase {
                DesktopLocalRuntimePhase::StartingWindow | DesktopLocalRuntimePhase::Ready => {
                    start_shutdown(Arc::clone(self), None);
                }
                DesktopLocalRuntimePhase::Stopped if startup_complete => return Ok(()),
                DesktopLocalRuntimePhase::Failed if startup_complete => {
                    return Err(DesktopLocalRuntimeError::Shutdown);
                }
                _ => {}
            }
            changed
                .changed()
                .await
                .map_err(|_| DesktopLocalRuntimeError::State)?;
        }
    }
}

// Completion belongs to the one startup task, including failure returns. Terminal Exit waits for
// this notification as well as the unique shutdown completion; no startup task is detached at exit.
struct StartupCompletion(Arc<DesktopLocalRuntimeState>);
impl Drop for StartupCompletion {
    fn drop(&mut self) {
        self.0.finish_startup();
    }
}

struct DesktopLocalClosingCompletion {
    state: Arc<DesktopLocalRuntimeState>,
    exit: Option<(tauri::AppHandle<Wry>, i32)>,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    normal_ready: Option<capture::NormalReadyExitToken>,
}

struct DesktopLocalClosingObservation {
    facts: Mutex<DesktopLocalClosingFacts>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DesktopLocalClosingOutcome {
    Succeeded,
    Failed,
    Unknown,
}

// Private observations are deliberately not a public teardown-ack API.
#[allow(dead_code)]
struct DesktopLocalClosingFacts {
    started: Instant,
    deadline: Instant,
    job_spawned_at: Option<Instant>,
    job_entered_at: Option<Instant>,
    drain_ack_at: Option<Instant>,
    postgres_ack_at: Option<Instant>,
    job_finished_at: Option<Instant>,
    waiter_ack_observed_at: Option<Instant>,
    waiter_detached_at: Option<Instant>,
    outcome: Option<DesktopLocalClosingOutcome>,
}

impl DesktopLocalClosingObservation {
    fn update(&self, update: impl FnOnce(&mut DesktopLocalClosingFacts)) -> bool {
        match self.facts.lock() {
            Ok(mut facts) => {
                update(&mut facts);
                true
            }
            Err(_) => false,
        }
    }
}

// This guard belongs to the actual job. An observer disappearing cannot run native completion.
struct ShutdownCompletion {
    completion: Option<DesktopLocalClosingCompletion>,
    observation: Arc<DesktopLocalClosingObservation>,
    completed: bool,
}

impl ShutdownCompletion {
    fn finish(&mut self, succeeded: bool) -> bool {
        let observed = self.observation.update(|facts| {
            facts.job_finished_at = Some(Instant::now());
            facts.outcome = Some(if succeeded {
                DesktopLocalClosingOutcome::Succeeded
            } else {
                DesktopLocalClosingOutcome::Failed
            });
        });
        let succeeded = succeeded && observed;
        if let Some(completion) = self.completion.take() {
            completion.state.finish_shutdown(succeeded);
            observe_exit("shutdown", if succeeded { "ok" } else { "failed" });
            if let Some((app_handle, requested_exit_code)) = completion.exit {
                exit_if_live(
                    &completion.state,
                    &app_handle,
                    if succeeded { requested_exit_code } else { 1 },
                );
            }
        }
        self.completed = true;
        succeeded
    }
}

impl Drop for ShutdownCompletion {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.observation
            .update(|facts| facts.outcome = Some(DesktopLocalClosingOutcome::Unknown));
        if let Some(completion) = &self.completion
            && completion.state.phase() == DesktopLocalRuntimePhase::Stopping
        {
            completion.state.finish_shutdown(false);
            observe_exit("shutdown_task", "unknown");
        }
    }
}

pub(crate) struct DesktopLocalShutdownWaiter {
    reply: tokio::sync::oneshot::Receiver<Result<(), DesktopLocalRuntimeError>>,
    observation: Arc<DesktopLocalClosingObservation>,
    reply_observed: bool,
}

impl Future for DesktopLocalShutdownWaiter {
    type Output = Result<(), DesktopLocalRuntimeError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.reply).poll(context) {
            Poll::Ready(Ok(result)) => {
                self.reply_observed = true;
                self.observation
                    .update(|facts| facts.waiter_ack_observed_at = Some(Instant::now()));
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(DesktopLocalRuntimeError::Shutdown)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DesktopLocalShutdownWaiter {
    fn drop(&mut self) {
        if !self.reply_observed {
            self.observation
                .update(|facts| facts.waiter_detached_at = Some(Instant::now()));
        }
    }
}

trait RuntimeShutdownOwner: Send {
    fn start_closing(
        self: Box<Self>,
        completion: Option<DesktopLocalClosingCompletion>,
    ) -> DesktopLocalShutdownWaiter;
}

struct DesktopLocalBackgroundOwner {
    lifecycle: Arc<DesktopWindowLifecycle>,
    transport: Arc<InProcessTransport>,
    agent_host: Option<DesktopAgentHost>,
    assembly: Option<PostgresApplicationAssembly>,
    data_plane: Option<RunningDesktopLocalDataPlane>,
    _remember_preference_repository:
        Arc<openbot_infra::approval_preferences::PostgresRememberPreferenceRepository>,
    read_lifecycle: Arc<openbot_infra::artifact_read_lifecycle::ArtifactReadLifecycle>,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture_armed: Option<capture::ArmedNormalCapture>,
}

impl Drop for DesktopLocalBackgroundOwner {
    fn drop(&mut self) {
        let _ = self.lifecycle.shutdown_authority();
    }
}

impl RuntimeShutdownOwner for DesktopLocalBackgroundOwner {
    fn start_closing(
        self: Box<Self>,
        completion: Option<DesktopLocalClosingCompletion>,
    ) -> DesktopLocalShutdownWaiter {
        start_owned_local_closing_job(self, completion)
    }
}

struct DesktopLocalClosingJob {
    owner: Option<Box<DesktopLocalBackgroundOwner>>,
    deadline: Instant,
    tracker: Arc<openbot_infra::artifact_read_lifecycle::ArtifactReadLifecycle>,
    reply: Option<tokio::sync::oneshot::Sender<Result<(), DesktopLocalRuntimeError>>>,
    observation: Arc<DesktopLocalClosingObservation>,
    completion: ShutdownCompletion,
    startup_ok: bool,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    normal_ready: Option<capture::NormalReadyExitToken>,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    capture: Option<capture::CaptureJobCustody>,
}

fn start_owned_local_closing_job(
    owner: Box<DesktopLocalBackgroundOwner>,
    completion: Option<DesktopLocalClosingCompletion>,
) -> DesktopLocalShutdownWaiter {
    let started = Instant::now();
    let deadline = started + crate::cancel::SHUTDOWN_DEADLINE;
    let observation = Arc::new(DesktopLocalClosingObservation {
        facts: Mutex::new(DesktopLocalClosingFacts {
            started,
            deadline,
            job_spawned_at: None,
            job_entered_at: None,
            drain_ack_at: None,
            postgres_ack_at: None,
            job_finished_at: None,
            waiter_ack_observed_at: None,
            waiter_detached_at: None,
            outcome: None,
        }),
    });
    let mut completion = completion;
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let normal_ready = completion
        .as_mut()
        .and_then(|completion| completion.normal_ready.take());
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let capturing = normal_ready.is_some() && owner.capture_armed.is_some();
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let capturing = false;
    // The original ordinary path keeps its exact ordering. Armed close first persists Intent.
    let authority_ok = capturing || owner.lifecycle.shutdown_authority().is_ok();
    let tracker = Arc::clone(&owner.read_lifecycle);
    if !capturing {
        tracker.close();
    }
    let state_install_ok = match &completion {
        Some(completion) => completion
            .state
            .install_closing_observation(Arc::clone(&observation))
            .is_ok(),
        None => true,
    };
    let (reply, receiver) = tokio::sync::oneshot::channel();
    let job = DesktopLocalClosingJob {
        owner: Some(owner),
        deadline,
        tracker,
        reply: Some(reply),
        observation: Arc::clone(&observation),
        completion: ShutdownCompletion {
            completion,
            observation: Arc::clone(&observation),
            completed: false,
        },
        startup_ok: authority_ok && state_install_ok,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        normal_ready: if capturing { normal_ready } else { None },
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        capture: None,
    };
    // The actual owner and data plane belong to this job before the observer can be returned.
    tauri::async_runtime::spawn(run_owned_local_closing_job(job));
    observation.update(|facts| facts.job_spawned_at = Some(Instant::now()));
    DesktopLocalShutdownWaiter {
        reply: receiver,
        observation,
        reply_observed: false,
    }
}

async fn run_owned_local_closing_job(mut job: DesktopLocalClosingJob) {
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    if let Some(ready) = job.normal_ready.take() {
        job.observation
            .update(|facts| facts.job_entered_at = Some(Instant::now()));
        let result = capture::run_normal_exit_capture(&mut job, ready).await;
        if result.is_err() {
            // A capture refusal does not complete the original shutdown while live/unknown
            // resources remain resident. Keep Stopping: finish(false) would schedule native
            // exit(1) and destroy this very custody through process termination.
            job.observation
                .update(|facts| facts.outcome = Some(DesktopLocalClosingOutcome::Unknown));
            observe_exit("capture", "closing_pending");
            if let Some(reply) = job.reply.take() {
                let _observed = reply.send(Err(DesktopLocalRuntimeError::Shutdown));
            }
            std::future::pending::<()>().await;
            return;
        }
        let succeeded = job.completion.finish(true);
        if let Some(reply) = job.reply.take() {
            let _observed = reply.send(if succeeded {
                Ok(())
            } else {
                Err(DesktopLocalRuntimeError::Shutdown)
            });
        }
        return;
    }
    let DesktopLocalClosingJob {
        mut owner,
        deadline,
        tracker,
        reply,
        observation,
        mut completion,
        startup_ok,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
            normal_ready: _,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
            capture: _,
    } = job;
    let mut owner = owner.take().expect("original ordinary closing owner");
    let reply = reply.expect("original ordinary closing observer");
    let mut observations_ok =
        observation.update(|facts| facts.job_entered_at = Some(Instant::now()));
    let agent_host = owner.agent_host.take();
    let assembly = owner.assembly.take();
    // The data plane stays in owner, outside all deadline-limited subfutures.
    let non_database = async {
        let (transport, (), (), ()) = tokio::join!(
            owner.transport.shutdown(),
            async {
                if let Some(host) = agent_host {
                    host.stop().await;
                }
            },
            async {
                if let Some(assembly) = assembly {
                    assembly.shutdown().await;
                }
            },
            owner.lifecycle.wait_local_confirmation_stopped(),
        );
        transport.within_deadline
    };
    let (non_database, drain) = tokio::join!(
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), non_database),
        tracker.drain_before(deadline),
    );
    let non_database_ok = match non_database {
        Ok(true) => {
            observe_exit("non_database", "ok");
            true
        }
        Ok(false) => {
            observe_exit("non_database", "failed");
            false
        }
        Err(_) => {
            observe_exit("non_database", "timed_out");
            false
        }
    };
    // This result is latched. Late drain can clean up but cannot renew the original budget.
    let drain_in_deadline = drain.is_ok();
    if !drain_in_deadline {
        let _late_cleanup_ack = tracker.drain().await;
    }
    observations_ok &= observation.update(|facts| facts.drain_ack_at = Some(Instant::now()));
    let database_ok = match owner.data_plane.take() {
        Some(data_plane) => data_plane.shutdown().await.is_ok(),
        None => false,
    };
    if database_ok {
        observations_ok &= observation.update(|facts| facts.postgres_ack_at = Some(Instant::now()));
    }
    observe_exit("postgresql", if database_ok { "ok" } else { "failed" });
    let succeeded = completion.finish(
        startup_ok && observations_ok && non_database_ok && drain_in_deadline && database_ok,
    );
    let _observer_received = reply.send(if succeeded {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    });
}

pub(crate) struct PreparedDesktopLocalRuntime {
    auth: AuthContext,
    protocol: Arc<DesktopTauriProtocol>,
    lifecycle: Arc<DesktopWindowLifecycle>,
    owner: Box<dyn RuntimeShutdownOwner>,
    #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
    self_owned_capture_fixture: Option<SelfOwnedCaptureFixtureBinding>,
    #[cfg(target_os = "macos")]
    confirmation: crate::local_confirmation_native::PreparedMacLocalConfirmation,
    #[cfg(test)]
    application: Arc<dyn openbot_application::ApplicationService>,
    #[cfg(test)]
    pool: openbot_infra::db::pool::DatabasePool,
    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    pub(crate) artifact_administration:
        Arc<openbot_infra::artifact_administration::PostgresArtifactAdministration>,
}

#[cfg(test)]
impl PreparedDesktopLocalRuntime {
    pub(crate) fn auth_context(&self) -> &AuthContext {
        &self.auth
    }

    pub(crate) fn application(&self) -> &Arc<dyn openbot_application::ApplicationService> {
        &self.application
    }

    pub(crate) fn active_window_count(&self) -> usize {
        self.lifecycle.active_window_count()
    }

    pub(crate) fn pool(&self) -> &openbot_infra::db::pool::DatabasePool {
        &self.pool
    }

    pub(crate) fn protocol(&self) -> &Arc<DesktopTauriProtocol> {
        &self.protocol
    }

    pub(crate) fn shutdown(self) -> DesktopLocalShutdownWaiter {
        self.owner.start_closing(None)
    }

    pub(crate) fn start_closing_for_reviewed_test(
        self,
    ) -> Result<(Arc<DesktopLocalRuntimeState>, DesktopLocalShutdownWaiter), DesktopLocalRuntimeError>
    {
        let state = DesktopLocalRuntimeState::new();
        let mut owner = Some(self.owner);
        if let Err(error) = state.install_owner(&mut owner, self.lifecycle) {
            if let Some(owner) = owner {
                drop(owner.start_closing(None));
            }
            return Err(error);
        }
        state.mark_ready()?;
        let owner = state
            .begin_shutdown()?
            .ok_or(DesktopLocalRuntimeError::State)?;
        let waiter = owner.start_closing(Some(DesktopLocalClosingCompletion {
            state: Arc::clone(&state),
            exit: None,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            normal_ready: None,
        }));
        Ok((state, waiter))
    }
}

/// Builder wrapper that makes the exit-fencing run callback non-optional.
pub struct DesktopLocalTauriBuilder {
    builder: Builder<Wry>,
}

impl DesktopLocalTauriBuilder {
    /// Build with the caller's reviewed external Tauri context, then run with ordered exit fencing.
    pub fn run(self, context: Context<Wry>) -> Result<(), DesktopLocalRuntimeError> {
        validate_tauri_context(&context)?;
        let app = self
            .builder
            .build(context)
            .map_err(|_| DesktopLocalRuntimeError::Build)?;
        run_desktop_local_app(app);
        Ok(())
    }
}

fn validate_tauri_context<R: Runtime>(
    context: &Context<R>,
) -> Result<(), DesktopLocalRuntimeError> {
    if context
        .config()
        .app
        .windows
        .iter()
        .any(|window| window.create)
    {
        return Err(DesktopLocalRuntimeError::Configuration);
    }
    Ok(())
}

/// Register deferred custom-protocol framing and the one authoritative Desktop Local setup.
pub fn register_desktop_local_runtime(
    builder: Builder<Wry>,
    config: DesktopLocalRuntimeConfig,
) -> Result<DesktopLocalTauriBuilder, DesktopLocalRuntimeError> {
    let scheme = config.release.scheme.clone();
    let window_label = config.release.window_label.clone();
    let protocol_slot = DesktopTauriProtocolSlot::pending();
    let runtime_state = DesktopLocalRuntimeState::new();

    let setup_state = Arc::clone(&runtime_state);
    let setup_slot = Arc::clone(&protocol_slot);
    let builder = register_tauri_protocol_slot(builder, &scheme, protocol_slot)
        .map_err(|_| DesktopLocalRuntimeError::Configuration)?
        .manage(Arc::clone(&runtime_state))
        .setup(move |app| {
            let app_handle = app.handle().clone();
            #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
            let selected_app_data = match config.self_owned_capture_fixture.as_ref() {
                Some(binding) => binding.app_data_root(),
                None => resolve_current_user_app_data_root(app),
            };
            #[cfg(not(all(feature = "desktop-launcher", target_os = "macos")))]
            let selected_app_data = resolve_current_user_app_data_root(app);
            let app_data_root = match selected_app_data {
                Ok(root) => root,
                Err(_) => {
                    setup_state.fail_startup();
                    setup_state.finish_startup();
                    app_handle.exit(1);
                    return Ok(());
                }
            };
            tauri::async_runtime::spawn(async move {
                let _startup_completion = StartupCompletion(Arc::clone(&setup_state));
                if setup_state.stop_before_startup() {
                    exit_if_live(&setup_state, &app_handle, 0);
                    return;
                }
                let prepared = report_preparation_result(
                    prepare_desktop_local_runtime(app_data_root, config).await,
                );
                let prepared = match prepared {
                    Ok(prepared) => prepared,
                    Err(_) => {
                        setup_state.fail_startup();
                        exit_if_live(&setup_state, &app_handle, 1);
                        return;
                    }
                };
                if setup_slot.install(Arc::clone(&prepared.protocol)).is_err() {
                    let _ = prepared.owner.start_closing(None).await;
                    setup_state.fail_startup();
                    exit_if_live(&setup_state, &app_handle, 1);
                    return;
                }
                let lifecycle = Arc::clone(&prepared.lifecycle);
                let auth = prepared.auth.clone();
                #[cfg(target_os = "macos")]
                let confirmation = prepared.confirmation;
                #[cfg(target_os = "macos")]
                let confirmation_protocol = Arc::clone(&prepared.protocol);
                #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
                let mut self_owned_capture_fixture = prepared.self_owned_capture_fixture;
                let mut owner = Some(prepared.owner);
                if setup_state
                    .install_owner(&mut owner, Arc::clone(&lifecycle))
                    .is_err()
                {
                    if let Some(owner) = owner {
                        let _ = owner.start_closing(None).await;
                    }
                    setup_state.fail_startup();
                    exit_if_live(&setup_state, &app_handle, 1);
                    return;
                }
                if setup_state.exit_requested().unwrap_or(true) {
                    request_shutdown(Arc::clone(&setup_state), app_handle, 0);
                    return;
                }
                // Never block a startup worker on Wry while terminal Exit blocks the native
                // thread joining that worker. State already owns PostgreSQL; this queued closure
                // owns only window authority and may safely arrive after shutdown has begun.
                let window_state = Arc::clone(&setup_state);
                let window_handle = app_handle.clone();
                let queued = app_handle.run_on_main_thread(move || {
                    if !window_state.can_create_window() {
                        request_shutdown(Arc::clone(&window_state), window_handle, 0);
                        return;
                    }
                    #[cfg(target_os = "macos")]
                    if confirmation
                        .install(window_handle.clone(), &confirmation_protocol)
                        .is_err()
                    {
                        request_shutdown(Arc::clone(&window_state), window_handle, 1);
                        return;
                    }
                    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos", debug_assertions))]
                    let self_owned_exit = self_owned_capture_fixture.is_some();
                    #[cfg(not(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos", debug_assertions)))]
                    let self_owned_exit = false;
                    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos", debug_assertions))]
                    let authority = match self_owned_capture_fixture.as_ref() {
                        Some(binding) => match VerifiedDesktopWindowAuthority::from_self_owned_fixture(auth, binding) {
                            Ok(authority) => authority,
                            Err(_) => { request_shutdown(Arc::clone(&window_state), window_handle, 1); return; }
                        },
                        None => VerifiedDesktopWindowAuthority::from_verified_session(auth, None),
                    };
                    #[cfg(not(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos", debug_assertions)))]
                    let authority = VerifiedDesktopWindowAuthority::from_verified_session(auth, None);
                    let window = lifecycle.create_verified_window(&window_handle, window_label, authority);
                    if window.is_err() {
                        request_shutdown(Arc::clone(&window_state), window_handle, 1);
                        return;
                    }
                    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
                    if let Some(binding) = self_owned_capture_fixture.take() {
                        if binding.retire_before_window_ready().is_err() {
                            request_shutdown(Arc::clone(&window_state), window_handle, 1);
                            return;
                        }
                    }
                    let ready = window_state.mark_ready();
                    let exit_requested = if self_owned_exit {
                        match ready {
                            Ok(exit_requested) => exit_requested,
                            Err(_) => { request_shutdown(Arc::clone(&window_state), window_handle, 1); return; }
                        }
                    } else { ready.unwrap_or(true) };
                    if self_owned_exit || exit_requested || lifecycle.active_window_count() == 0 {
                        request_shutdown(Arc::clone(&window_state), window_handle, 0);
                    }
                });
                if queued.is_err() {
                    request_shutdown(Arc::clone(&setup_state), app_handle, 1);
                }
            });
            Ok(())
        });

    let window_state = Arc::clone(&runtime_state);
    let builder = builder.on_window_event(move |window, event| {
        let Some(lifecycle) = window_state.lifecycle() else {
            return;
        };
        match lifecycle.handle_window_event(window.label(), event) {
            Ok(true) if lifecycle.active_window_count() == 0 => {
                request_shutdown(Arc::clone(&window_state), window.app_handle().clone(), 0)
            }
            Ok(_) => {}
            Err(_) => request_shutdown(Arc::clone(&window_state), window.app_handle().clone(), 1),
        }
    });
    Ok(DesktopLocalTauriBuilder { builder })
}

fn resolve_current_user_app_data_root<R, M>(
    manager: &M,
) -> Result<CurrentOsUserAppDataRoot, DesktopLocalRuntimeError>
where
    R: Runtime,
    M: Manager<R>,
{
    let path = manager
        .path()
        .app_data_dir()
        .map_err(|_| DesktopLocalRuntimeError::AppData)?;
    CurrentOsUserAppDataRoot::from_current_os_user_app_data(path)
        .map_err(|_| DesktopLocalRuntimeError::AppData)
}

fn run_desktop_local_app(app: App<Wry>) {
    app.run(|app_handle, event| {
        match event {
            RunEvent::ExitRequested { api, code, .. } => {
                let state = app_handle.state::<Arc<DesktopLocalRuntimeState>>();
                observe_exit("exit_requested", phase_code(state.phase()));
                match state.phase() {
                    DesktopLocalRuntimePhase::Initializing
                    | DesktopLocalRuntimePhase::StartingWindow => {
                        api.prevent_exit();
                        if state.note_exit_requested().is_err() {
                            app_handle.exit(1);
                        }
                    }
                    DesktopLocalRuntimePhase::Ready => {
                        api.prevent_exit();
                        let _ = state.note_exit_requested();
                        // The original native request code distinguishes normal exit from failure/restart.
                        request_shutdown(
                            Arc::clone(state.inner()),
                            app_handle.clone(),
                            code.unwrap_or(0),
                        );
                    }
                    DesktopLocalRuntimePhase::Stopping => api.prevent_exit(),
                    DesktopLocalRuntimePhase::Stopped | DesktopLocalRuntimePhase::Failed => {}
                }
            }
            RunEvent::Exit => {
                let state = app_handle.state::<Arc<DesktopLocalRuntimeState>>();
                observe_exit("terminal_exit", phase_code(state.phase()));
                // The state may already have moved its lifecycle into the shutdown owner.
                // The process protocol slot remains the exact current owner. Observer removal
                // runs here on the real native thread before joining any worker shutdown.
                #[cfg(target_os = "macos")]
                let monitor_cleanup = app_handle
                    .try_state::<Arc<DesktopTauriProtocolSlot>>()
                    .and_then(|slot| slot.get().ok())
                    .map(|protocol| protocol.cleanup_local_confirmation_on_main_thread())
                    .transpose();
                #[cfg(not(target_os = "macos"))]
                let monitor_cleanup = Ok::<(), ()>(());
                // macOS terminate: can deliver Exit without ExitRequested. This runs on the
                // ordinary fn-main native thread, outside Tokio. The existing Tauri worker runtime
                // keeps executing startup/shutdown while this thread waits only on notifications.
                // No state lock is held, and shutdown does not require a native window callback.
                let result = tauri::async_runtime::block_on(state.join_terminal_exit());
                observe_exit(
                    "terminal_join",
                    if result.is_ok() { "ok" } else { "failed" },
                );
                if result.is_err() || monitor_cleanup.is_err() {
                    // Native terminate: has no ExitRequested code to change. The joined failure
                    // must not recursively enqueue app.exit or let the platform's default zero
                    // status disguise failed cleanup; an unconfirmed PG stop retains its marker.
                    std::process::exit(1);
                }
            }
            _ => {}
        }
    });
}

fn exit_if_live(
    state: &DesktopLocalRuntimeState,
    app_handle: &tauri::AppHandle<Wry>,
    exit_code: i32,
) {
    if !state.is_terminal_exit() {
        app_handle.exit(exit_code);
    }
}

fn request_shutdown(
    state: Arc<DesktopLocalRuntimeState>,
    app_handle: tauri::AppHandle<Wry>,
    requested_exit_code: i32,
) {
    start_shutdown(state, Some((app_handle, requested_exit_code)));
}

fn start_shutdown(
    state: Arc<DesktopLocalRuntimeState>,
    exit: Option<(tauri::AppHandle<Wry>, i32)>,
) {
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let (owner, normal_ready) =
        match state.begin_native_exit_shutdown(exit.as_ref().map(|(_, code)| *code)) {
            Ok(Some(pair)) => pair,
            Ok(None) => return,
            Err(_) => {
                state.finish_shutdown(false);
                if let Some((app_handle, _)) = exit {
                    exit_if_live(&state, &app_handle, 1);
                }
                return;
            }
        };
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let owner = match state.begin_shutdown() {
        Ok(Some(owner)) => owner,
        Ok(None) => return,
        Err(_) => {
            state.finish_shutdown(false);
            if let Some((app_handle, _)) = exit {
                exit_if_live(&state, &app_handle, 1);
            }
            return;
        }
    };
    observe_exit("shutdown", "begin");
    drop(owner.start_closing(Some(DesktopLocalClosingCompletion {
        state,
        exit,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        normal_ready,
    })));
}

async fn finish_shutdown_stages(
    non_database: impl Future<Output = bool>,
    database: impl Future<Output = bool>,
    non_database_window: Duration,
) -> Result<(), DesktopLocalRuntimeError> {
    // The database future retains the exact data-plane/child owner outside this timeout. A slow
    // Agent/relay/reconciler cannot skip PostgreSQL cleanup by dropping the whole shutdown future.
    let non_database_ok = match tokio::time::timeout(non_database_window, non_database).await {
        Ok(true) => {
            observe_exit("non_database", "ok");
            true
        }
        Ok(false) => {
            observe_exit("non_database", "failed");
            false
        }
        Err(_) => {
            observe_exit("non_database", "timed_out");
            false
        }
    };
    let database_ok = database.await;
    observe_exit("postgresql", if database_ok { "ok" } else { "failed" });
    if non_database_ok && database_ok {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    }
}

fn observe_exit(stage: &'static str, outcome: &'static str) {
    // Closed lifecycle facts remain available before a tracing subscriber is configured. Never
    // include a request, URI, SQL error, user value, secret, or resource path in this boundary.
    eprintln!("wrok_bot_desktop_exit stage={stage} outcome={outcome}");
}

const fn phase_code(phase: DesktopLocalRuntimePhase) -> &'static str {
    match phase {
        DesktopLocalRuntimePhase::Initializing => "initializing",
        DesktopLocalRuntimePhase::StartingWindow => "starting_window",
        DesktopLocalRuntimePhase::Ready => "ready",
        DesktopLocalRuntimePhase::Stopping => "stopping",
        DesktopLocalRuntimePhase::Stopped => "stopped",
        DesktopLocalRuntimePhase::Failed => "failed",
    }
}

pub(crate) async fn prepare_desktop_local_runtime(
    app_data_root: CurrentOsUserAppDataRoot,
    config: DesktopLocalRuntimeConfig,
) -> Result<PreparedDesktopLocalRuntime, DesktopLocalRuntimeError> {
    let DesktopLocalRuntimeConfig {
        release,
        application,
        package_factory,
        #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
        mut self_owned_capture_fixture,
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        mut capture_request,
    } = config;
    let DesktopLocalReleaseInput {
        ui,
        scheme,
        window_label: _,
        postgres_bundle,
        postgres_key_store_service,
        vault_key_store_service,
        secret_store,
    } = release;
    let DesktopLocalApplicationInput { provider, budgets } = application;
    let remote_agent_probe = provider
        .remote_transport(budgets.stall_timeout)
        .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
    let channel_routing_provider = ChannelRoutingProviderInput {
        endpoint: provider
            .channel_endpoint()
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?,
        environment_api_key: None,
        egress_allow_cidrs: provider.egress_allow_cidrs(),
        allow_http: false,
    };

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_resources = match capture_request.as_ref() {
        Some(request) => Some(capture::prepare_original_capture_resources(
            &request.profile.carrier_bounds().map_err(|_| DesktopLocalRuntimeError::Configuration)?,
        ).map_err(|_| DesktopLocalRuntimeError::Configuration)?),
        None => None,
    };
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    if let Some(binding) = self_owned_capture_fixture.as_mut() {
        binding.prepare_new_root_before_startup(capture_resources.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?)?;
    }
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    let mut capture_control_footprint = None;
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    let mut closed_history_profile = None;
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    if let Some(app) = capture::open_app_data_read_only(app_data_root.as_path())
        .map_err(|_| DesktopLocalRuntimeError::Authority)?
    {
        let observed = capture::control::inspect_startup_control_for_capture(
            &app,
            capture_request.as_ref().map(|request| &request.profile),
            capture_request.as_ref().map(|request| request.request_id.as_str()),
            capture_resources.as_ref(),
        )
        .map_err(|_| DesktopLocalRuntimeError::Authority)?;
        let completed_request = match capture_request.as_ref() {
            Some(request) => observed.completed_request(&request.request_id),
            None => false,
        };
        if completed_request {
            // Full original Closed history consumes this reviewed request. Do
            // not arm or retain capture-only secrets again on ordinary startup.
            if let Some(request) = capture_request.take() {
                closed_history_profile = Some(request.profile);
            }
            capture_resources = None;
        } else if capture_resources.is_some() {
            capture_control_footprint = Some(observed);
        }
    }

    let authority_store = DesktopLocalAuthorityStore::new(app_data_root.clone());
    let installation = authority_store
        .load_or_create_installation()
        .map_err(|_| DesktopLocalRuntimeError::Authority)?;
    let package =
        package_factory(installation.authority()).map_err(|_| DesktopLocalRuntimeError::Package)?;
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_installation = match capture_request.as_ref() {
        Some(_) => Some(
            installation
                .retain_capture_installation()
                .map_err(|_| DesktopLocalRuntimeError::Authority)?,
        ),
        None => None,
    };
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_control = {
        if let Some(binding) = self_owned_capture_fixture.as_mut() {
            binding.verify_original_root(capture_installation.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?)?;
        }
        match capture_request.as_ref() {
        Some(request) => {
            request
                .profile
                .validate_master_retention()
                .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
            let app = capture::open_app_data_read_only(app_data_root.as_path())
                .map_err(|_| DesktopLocalRuntimeError::Authority)?
                .ok_or(DesktopLocalRuntimeError::Authority)?;
            Some(
                capture::CaptureControlOwner::prepare(
                    &app, request,
                    Arc::clone(capture_resources.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?),
                    capture_control_footprint.take()
                        .unwrap_or_else(capture::control::OriginalControlHistoryFootprint::unobserved),
                )
                    .map_err(|_| DesktopLocalRuntimeError::Configuration)?,
            )
        }
        None => None,
    }};
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_decode = match capture_request.as_ref() {
        Some(request) => {
            let (known, _) = request.profile.checked_original_decode_structure_bytes()
                .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
            capture::reserve_capture_resources(
                capture_resources.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?, 0, known,
            ).map_err(|_| DesktopLocalRuntimeError::Configuration)?;
            let class = &request.profile.secrets.classes.decode_crypto_temporary;
            Some(openbot_infra::db::capture_materials::CaptureDecodeBudget::checked(
                class.max_count, class.max_one_bytes,
            ).map_err(|_| DesktopLocalRuntimeError::Configuration)?)
        }
        None => None,
    };
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    let capture_custody = match capture_request.as_ref() {
        Some(request) => {
            use openbot_infra::db::desktop_local::{
                DesktopLocalDriverCustody, DesktopPoolJoinBounds,
            };
            let p = &request.profile.drivers;
            let bounds = DesktopPoolJoinBounds::checked(
                p.max_live_original_tasks,
                p.max_unjoined_original_tasks,
                p.max_pending_connects,
                p.max_live_proxies,
                p.max_owner_metadata_bytes,
            )
            .map_err(|_| DesktopLocalRuntimeError::Configuration)?;
            Some(
                DesktopLocalDriverCustody::prepare(
                    bounds,
                    Arc::clone(capture_decode.as_ref().ok_or(DesktopLocalRuntimeError::Configuration)?),
                )
                    .map_err(|_| DesktopLocalRuntimeError::Configuration)?,
            )
        }
        None => None,
    };
    let start = async {
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let profile = match capture_request.as_ref() {
            Some(request) => Some(&request.profile),
            None => closed_history_profile.as_ref(),
        };
        #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
        if let Some(profile) = profile {
            return PostgresSidecarSupervisor::start_with_capture_profile(
                postgres_bundle,
                app_data_root.as_path(),
                installation.authority().instance_id(),
                installation.sidecar_data_dir(),
                secret_store.as_ref(),
                &postgres_key_store_service,
                profile,
            )
            .await;
        }
        PostgresSidecarSupervisor::start(
            postgres_bundle,
            app_data_root.as_path(),
            installation.authority().instance_id(),
            installation.sidecar_data_dir(),
            secret_store.as_ref(),
            &postgres_key_store_service,
        )
        .await
    };
    let sidecar = start.await.map_err(map_sidecar_error)?;
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    drop(closed_history_profile);
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let prepared_data_plane = match capture_custody {
        Some(custody) => {
            crate::desktop_local_bootstrap::prepare_running_sidecar_retained(
                installation,
                sidecar,
                &package,
                custody,
            )
            .await
        }
        None => prepare_running_sidecar(installation, sidecar, &package).await,
    }
    .map_err(map_data_plane_error)?;
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let prepared_data_plane = prepare_running_sidecar(installation, sidecar, &package)
        .await
        .map_err(map_data_plane_error)?;
    let verify_vault = async {
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(request) = capture_request.as_ref() {
            return prepared_data_plane
                .verify_application_key_material_for_capture(
                    secret_store.as_ref(),
                    &vault_key_store_service,
                    &package,
                    request,
                )
                .await;
        }
        prepared_data_plane
            .verify_application_key_material(
                secret_store.as_ref(),
                &vault_key_store_service,
                &package,
            )
            .await
    };
    let vault_ready = match verify_vault.await {
        Ok(material) => material,
        Err(error) => {
            let original = map_vault_error(error);
            return Err(if prepared_data_plane.shutdown().await.is_ok() {
                original
            } else {
                DesktopLocalRuntimeError::FailureCleanup
            });
        }
    };
    #[cfg(all(feature = "desktop-launcher", feature = "postgres-maintenance", target_os = "macos"))]
    if let Some(binding) = self_owned_capture_fixture.as_ref() {
        drop(secret_store);
        if binding.require_original_store_dropped().is_err() {
            return Err(if prepared_data_plane.shutdown().await.is_ok() {
                DesktopLocalRuntimeError::Configuration
            } else { DesktopLocalRuntimeError::FailureCleanup });
        }
    }
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let (key_material, proof, database_origin, mut capture_vault) =
        vault_ready.into_capture_parts();
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let (key_material, proof, database_origin) = vault_ready.into_parts();
    // Copy sealed provenance while the real verified canary and its actual database
    // owner are both live. Namespace strings cannot construct this proof.
    let remember_preference_provenance =
        match proof.remember_preference_provenance(prepared_data_plane.database()) {
            Some(provenance) => provenance,
            None => {
                return Err(if prepared_data_plane.shutdown().await.is_ok() {
                    DesktopLocalRuntimeError::DataPlane
                } else {
                    DesktopLocalRuntimeError::FailureCleanup
                });
            }
        };
    let custom_model_catalog_provenance =
        match proof.custom_model_catalog_provenance(prepared_data_plane.database()) {
            Some(provenance) => provenance,
            None => {
                return Err(if prepared_data_plane.shutdown().await.is_ok() {
                    DesktopLocalRuntimeError::DataPlane
                } else {
                    DesktopLocalRuntimeError::FailureCleanup
                });
            }
        };
    let data_plane = prepared_data_plane
        .complete_after_vault(
            &package,
            database_origin,
            &proof,
            key_material.expose_audit_key(),
        )
        .await
        .map_err(map_data_plane_error)?;

    let listener_database = match data_plane.thread_listener_database() {
        Ok(listener) => listener,
        Err(_) => {
            return Err(cleanup_data_plane(data_plane, DesktopLocalRuntimeError::DataPlane).await);
        }
    };
    let pool = data_plane.pool().clone();
    #[cfg(target_os = "macos")]
    let confirmation = crate::local_confirmation_native::PreparedMacLocalConfirmation::new(
        data_plane.authority(),
        pool.clone(),
    );
    #[cfg(test)]
    let test_pool = pool.clone();
    let policy_store = PolicyStore::postgres(pool.clone(), None);
    if policy_store.load().await.is_err() {
        return Err(cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Policy).await);
    }
    // Bind the existing Computer screen-session port to one bounded Rust hub. This local
    // assembly has no Engine/source or viewer transport; absent targets still fail closed.
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let (screen_sessions, mut capture_screen_seal): (
        Arc<dyn openbot_application::ScreenSessionAdministration>,
        Option<capture::materials::CaptureScreenAssemblySeal>,
    ) = match capture_request.as_ref() {
        Some(_) => match capture::materials::capture_screen_sessions_from_startup() {
            Ok((service, seal)) => (service, Some(seal)),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        },
        None => match ScreenHub::new(DEFAULT_SCREEN_VIEWERS_PER_STREAM) {
            Ok(hub) => (Arc::new(ScreenSessionService::new(hub)), None),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        },
    };
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    let screen_sessions: Arc<dyn openbot_application::ScreenSessionAdministration> =
        match ScreenHub::new(DEFAULT_SCREEN_VIEWERS_PER_STREAM) {
            Ok(hub) => Arc::new(ScreenSessionService::new(hub)),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        };
    let auth = data_plane.auth_context().clone();
    let (credential_vault, audit_key, remote_assertions, mcp_oauth_state_key) =
        key_material.into_assembly_parts();
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_audit_key = capture_request
        .as_ref()
        .map(|_| openbot_domain::vault::SecretBytes::new(audit_key.expose().to_vec()));
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let mut capture_artifact_store = None;
    let remember_preference_repository =
        match openbot_infra::approval_preferences::PostgresRememberPreferenceRepository::new(
            pool.clone(),
            auth.deployment().clone(),
            auth.tenant().clone(),
            openbot_domain::vault::SecretBytes::new(audit_key.expose().to_vec()),
        ) {
            Ok(repository) => Arc::new(repository),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        };
    if remember_preference_repository
        .adopt_desktop_provenance(remember_preference_provenance)
        .is_err()
    {
        return Err(cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await);
    }
    let agent_credential_vault = credential_vault.clone();
    let agent_audit_key = audit_key.expose().to_vec();
    let agent_remote_assertions = Arc::clone(&remote_assertions);
    let agent_listener_database = listener_database.clone();
    let preference_authority =
        match openbot_infra::ui_preferences::PostgresUiPreferenceAdministration::new(
            pool.clone(),
            auth.deployment().clone(),
            auth.tenant().clone(),
            openbot_domain::vault::SecretBytes::new(audit_key.expose().to_vec()),
        ) {
            Ok(port) => Arc::new(port),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let artifact_administration = {
        let artifact_policy = openbot_domain::artifact::ArtifactQuotaPolicy::default();
        let artifact_store = match data_plane.open_artifact_store(artifact_policy).await {
            Ok(store) => store,
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        };
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let Some(request) = capture_request.as_ref() {
            if artifact_store
                .arm_capture_barrier(request.profile.drivers.max_live_original_tasks)
                .is_err()
            {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
            capture_artifact_store = Some(Arc::clone(&artifact_store));
        }
        match openbot_infra::artifact_administration::PostgresArtifactAdministration::new(
            data_plane.artifact_dataset_owner(),
            artifact_store,
            artifact_policy,
            openbot_domain::vault::SecretBytes::new(audit_key.expose().to_vec()),
        ) {
            Ok(port) => Arc::new(port),
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        }
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let artifacts: Option<Arc<dyn openbot_application::artifacts::ArtifactAdministration>> =
        Some(artifact_administration.clone());
    #[cfg(target_os = "macos")]
    let artifact_read_authority = artifact_administration.read_authority();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let artifacts: Option<Arc<dyn openbot_application::artifacts::ArtifactAdministration>> = None;
    #[cfg(target_os = "macos")]
    let capability_factory =
        match crate::tauri_host::runtime_capabilities::DesktopRuntimeCapabilityFactory::new(
            pool.clone(),
            data_plane.authority().clone(),
        ) {
            Ok(factory) => factory,
            Err(_) => {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
        };
    let ui_preferences = Arc::new(DesktopUiPreferenceAdministration::new(
        preference_authority,
        app_data_root.as_path().join(DESKTOP_UI_PREFERENCES_FILE),
    ));
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let (ui_preferences, mut capture_preferences, mut capture_resources) = match capture_request.as_ref() {
        Some(request) => {
            // One original pre-t0 book is shared by both components and carried into Armed.
            // The local bounds remain ceilings; every actual component admission debits this
            // same book. Other owners and opaque peaks still require original global closure.
            let bounds = match request.profile.carrier_bounds() {
                Ok(bounds) => bounds,
                Err(_) => {
                    return Err(
                        cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                    );
                }
            };
            let resources = match capture_resources.take() {
                Some(resources) => resources,
                None => {
                    return Err(
                        cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                    );
                }
            };
            if ui_preferences
                .bind_original_capture_resources(Arc::clone(&resources))
                .is_err()
            {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
            let (adapter, mut preferences) = match ui_preferences
                .prepare_capture_projection(bounds)
            {
                Ok(prepared) => prepared,
                Err(_) => {
                    return Err(
                        cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                    );
                }
            };
            let original_installation = match capture_installation.as_ref() {
                Some(original) => original,
                None => {
                    return Err(
                        cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                    );
                }
            };
            if preferences
                .verify_original_installation_root(original_installation.original_root())
                .is_err()
            {
                return Err(
                    cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
                );
            }
            // This exact passive owner stays in the startup future across assembly and
            // cleanup awaits, then moves into the original materials before publication.
            (adapter, Some(preferences), Some(resources))
        }
        None => (ui_preferences, None, None),
    };
    let assembly = match assemble_postgres_application(PostgresApplicationAssemblyInput {
        pool: pool.clone(),
        listener_database: listener_database.clone(),
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        single_user: true,
        admin_floor: None,
        model: package.package.model.default_model.clone(),
        credential_key_id: package.package.model.credential_secret_ref.clone(),
        credential_vault,
        audit_key,
        remote_assertions,
        mcp_oauth_state_key,
        policy_store,
        ui_preferences,
        screen_sessions,
        artifacts,
        #[cfg(target_os = "macos")]
        runtime_capabilities: Some(capability_factory.clone()),
        #[cfg(not(target_os = "macos"))]
        runtime_capabilities: None,
        remote_agent_probe: remote_agent_probe.clone(),
        managed_slot_available: false,
        channel_routing_provider,
        stall_timeout: budgets.stall_timeout,
        oauth_public_url: None,
        app_url: None,
    })
    .await
    {
        Ok(assembly) => assembly,
        Err(_) => {
            return Err(
                cleanup_data_plane(data_plane, DesktopLocalRuntimeError::Application).await,
            );
        }
    };
    if assembly
        .model_dataset_binding
        .enroll_original_registry(&data_plane.artifact_dataset_owner())
        .is_err()
    {
        return Err(
            cleanup_assembly(data_plane, assembly, DesktopLocalRuntimeError::Application).await,
        );
    }
    if assembly
        .thread_history_authority
        .enroll_original_registry(&data_plane.artifact_dataset_owner())
        .is_err()
    {
        return Err(
            cleanup_assembly(data_plane, assembly, DesktopLocalRuntimeError::Application).await,
        );
    }
    if !custom_model_catalog_provenance.matches_installation(data_plane.authority())
        || assembly
            .custom_model_catalog_inventory
            .adopt_desktop_provenance(custom_model_catalog_provenance)
            .is_err()
    {
        return Err(
            cleanup_assembly(data_plane, assembly, DesktopLocalRuntimeError::Application).await,
        );
    }
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    if capture_request.is_some() {
        let bound = match (capture_screen_seal.as_mut(), capture_resources.as_ref()) {
            (Some(seal), Some(resources)) => {
                // The original seal was one Weak screen field. Charge only the added
                // requested static layout in the same pre-t0 book, once before binding.
                let added_metadata =
                    core::mem::size_of::<capture::materials::CaptureScreenAssemblySeal>()
                        .checked_sub(core::mem::size_of::<
                            std::sync::Weak<dyn openbot_application::ScreenSessionAdministration>,
                        >())
                        .and_then(|bytes| u64::try_from(bytes).ok());
                match added_metadata {
                    Some(bytes) => capture::reserve_capture_resources(resources, 0, bytes)
                        .and_then(|()| seal.bind_original_desktop_assembly(&assembly)),
                    None => Err(
                        openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::BoundsOverflow,
                    ),
                }
            }
            _ => Err(
                openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::MaterialMissing,
            ),
        };
        if bound.is_err() {
            return Err(
                cleanup_assembly(data_plane, assembly, DesktopLocalRuntimeError::Application).await,
            );
        }
    }
    let agent_host = match start_desktop_agent_host(DesktopAgentHostInput {
        pool,
        model_dataset_binding: Arc::clone(&assembly.model_dataset_binding),
        listener_database: agent_listener_database,
        deployment: auth.deployment().clone(),
        tenant: auth.tenant().clone(),
        package: package.clone(),
        application: Arc::clone(&assembly.application),
        tool_cancellations: Arc::clone(&assembly.tool_cancellations),
        runtime: Arc::clone(&assembly.run_runtime),
        remote_interrupts: assembly.remote_interrupts.clone(),
        credential_vault: agent_credential_vault,
        audit_key: agent_audit_key,
        remote_assertions: agent_remote_assertions,
        mcp_catalog: Arc::clone(&assembly.mcp_catalog),
        components: Arc::clone(&assembly.components),
        sandboxed_components: Arc::clone(&assembly.sandboxed_components),
        provider,
        remote_transport: remote_agent_probe,
        budgets,
    }) {
        Ok(host) => host,
        Err(_) => {
            return Err(
                cleanup_assembly(data_plane, assembly, DesktopLocalRuntimeError::Agent).await,
            );
        }
    };
    let transport = Arc::new(InProcessTransport::new(Arc::clone(&assembly.application)));
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    if let Some(request) = capture_request.as_ref() {
        // The fresh original transport has not been given to any consumer yet. Bind the
        // exact same pre-t0 book; no replacement identity, allowance or clock is created.
        let resources = match capture_resources.as_ref() {
            Some(resources) => resources,
            None => {
                return Err(cleanup_agent_host(
                    data_plane,
                    assembly,
                    agent_host,
                    DesktopLocalRuntimeError::Application,
                )
                .await);
            }
        };
        let bounds = match request.profile.carrier_bounds() {
            Ok(bounds) => bounds,
            Err(_) => {
                return Err(cleanup_agent_host(
                    data_plane,
                    assembly,
                    agent_host,
                    DesktopLocalRuntimeError::Application,
                )
                .await);
            }
        };
        if transport
            .bind_original_capture_resources(Arc::clone(resources))
            .and_then(|()| transport.arm_capture_retention(&bounds))
            .is_err()
        {
            return Err(cleanup_agent_host(
                data_plane,
                assembly,
                agent_host,
                DesktopLocalRuntimeError::Application,
            )
            .await);
        }
    }
    let opened_protocol = match ui {
        DesktopUiResource::Path(dist) => DesktopTauriProtocol::open(dist, Arc::clone(&transport)),
        #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
        DesktopUiResource::Verified(assets) => Ok(DesktopTauriProtocol::from_verified_assets(
            assets,
            Arc::clone(&transport),
        )),
    };
    #[cfg(target_os = "macos")]
    let current_identity_source = Arc::new(
        crate::local_confirmation_authority::PostgresLocalConfirmationAuthority::new(
            data_plane.authority().clone(),
            data_plane.pool().clone(),
        ),
    );
    #[cfg(target_os = "macos")]
    if current_identity_source
        .install_artifact_read_authority(&artifact_read_authority)
        .is_err()
    {
        return Err(cleanup_agent_host(
            data_plane,
            assembly,
            agent_host,
            DesktopLocalRuntimeError::Host,
        )
        .await);
    }
    #[cfg(target_os = "macos")]
    if current_identity_source
        .install_remember_preference_repository(&remember_preference_repository)
        .is_err()
    {
        return Err(cleanup_agent_host(
            data_plane,
            assembly,
            agent_host,
            DesktopLocalRuntimeError::Host,
        )
        .await);
    }
    #[cfg(target_os = "macos")]
    if current_identity_source
        .install_thread_history_authority(&assembly.thread_history_authority)
        .is_err()
    {
        return Err(cleanup_agent_host(
            data_plane,
            assembly,
            agent_host,
            DesktopLocalRuntimeError::Host,
        )
        .await);
    }
    #[cfg(target_os = "macos")]
    if current_identity_source
        .install_custom_model_catalog_inventory(&assembly.custom_model_catalog_inventory)
        .is_err()
    {
        return Err(cleanup_agent_host(
            data_plane,
            assembly,
            agent_host,
            DesktopLocalRuntimeError::Host,
        )
        .await);
    }
    let protocol = match opened_protocol {
        Ok(protocol) => {
            #[cfg(target_os = "macos")]
            let protocol = match protocol
                .with_remember_preference_identity_source(current_identity_source.clone())
            {
                Ok(protocol) => protocol,
                Err(_) => {
                    return Err(cleanup_agent_host(
                        data_plane,
                        assembly,
                        agent_host,
                        DesktopLocalRuntimeError::Host,
                    )
                    .await);
                }
            };
            #[cfg(target_os = "macos")]
            let protocol = match protocol
                .with_custom_model_catalog_identity_source(current_identity_source.clone())
            {
                Ok(protocol) => protocol,
                Err(_) => {
                    return Err(cleanup_agent_host(
                        data_plane,
                        assembly,
                        agent_host,
                        DesktopLocalRuntimeError::Host,
                    )
                    .await);
                }
            };
            #[cfg(target_os = "macos")]
            let protocol =
                match protocol.with_thread_history_identity_source(current_identity_source) {
                    Ok(protocol) => protocol,
                    Err(_) => {
                        return Err(cleanup_agent_host(
                            data_plane,
                            assembly,
                            agent_host,
                            DesktopLocalRuntimeError::Host,
                        )
                        .await);
                    }
                };
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            let first_frame_projection = if capture_request.is_some() {
                match capture_preferences.as_ref() {
                    Some(preferences) => preferences.original_store().clone(),
                    None => {
                        protocol.close_request_bindings();
                        return Err(cleanup_agent_host(
                            data_plane,
                            assembly,
                            agent_host,
                            DesktopLocalRuntimeError::Application,
                        )
                        .await);
                    }
                }
            } else {
                DesktopUiPreferenceStore::new(
                    app_data_root.as_path().join(DESKTOP_UI_PREFERENCES_FILE),
                )
            };
            #[cfg(not(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            )))]
            let first_frame_projection = DesktopUiPreferenceStore::new(
                app_data_root.as_path().join(DESKTOP_UI_PREFERENCES_FILE),
            );
            Arc::new(protocol.with_first_frame_projection(first_frame_projection))
        }
        Err(_) => {
            return Err(cleanup_agent_host(
                data_plane,
                assembly,
                agent_host,
                DesktopLocalRuntimeError::Host,
            )
            .await);
        }
    };
    #[cfg(target_os = "macos")]
    if capability_factory.install(&protocol).is_err() {
        protocol.close_request_bindings();
        return Err(cleanup_agent_host(
            data_plane,
            assembly,
            agent_host,
            DesktopLocalRuntimeError::Host,
        )
        .await);
    }
    let lifecycle = match DesktopWindowLifecycle::new(&scheme, Arc::clone(&protocol)) {
        Ok(lifecycle) => Arc::new(lifecycle),
        Err(_) => {
            protocol.close_request_bindings();
            return Err(cleanup_agent_host(
                data_plane,
                assembly,
                agent_host,
                DesktopLocalRuntimeError::Host,
            )
            .await);
        }
    };
    #[cfg(test)]
    let application = Arc::clone(&assembly.application);
    #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
    let artifact_administration_for_tests = Arc::clone(&artifact_administration);
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    let capture_armed = if let Some(request) = capture_request {
        let capture = match (
            capture_control.take(),
            capture_vault.take(),
            capture_artifact_store.take(),
            capture_audit_key.take(),
            capture_installation.take(),
            capture_screen_seal.take(),
            capture_preferences.take(),
            capture_resources.take(),
            capture_decode.take(),
        ) {
            (
                Some(control),
                Some(vault),
                Some(store),
                Some(audit_key),
                Some(installation),
                Some(screen),
                Some(preferences),
                Some(resources),
                Some(decode),
            ) => capture::ArmedNormalCapture::from_original_startup(
                request,
                control,
                vault,
                store,
                openbot_infra::repo::audit::AuditEventRepo::new(data_plane.pool().clone()),
                audit_key,
                capture::NormalCaptureMaterials::from_original_installation(
                    installation,
                    screen,
                    preferences,
                    decode,
                ),
                resources,
            ),
            _ => {
                Err(openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault::MaterialMissing)
            }
        };
        match capture {
            Ok(capture) => Some(capture),
            Err(_) => {
                protocol.close_request_bindings();
                return Err(cleanup_agent_host(
                    data_plane,
                    assembly,
                    agent_host,
                    DesktopLocalRuntimeError::Application,
                )
                .await);
            }
        }
    } else {
        None
    };
    let owner: Box<dyn RuntimeShutdownOwner> = Box::new(DesktopLocalBackgroundOwner {
        lifecycle: Arc::clone(&lifecycle),
        transport,
        agent_host: Some(agent_host),
        assembly: Some(assembly),
        data_plane: Some(data_plane),
        _remember_preference_repository: remember_preference_repository,
        read_lifecycle: artifact_administration.read_authority().read_lifecycle(),
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        capture_armed,
    });
    Ok(PreparedDesktopLocalRuntime {
        auth,
        protocol,
        lifecycle,
        owner,
        #[cfg(all(feature = "desktop-launcher", target_os = "macos"))]
        self_owned_capture_fixture,
        #[cfg(target_os = "macos")]
        confirmation,
        #[cfg(test)]
        application,
        #[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
        artifact_administration: artifact_administration_for_tests,
        #[cfg(test)]
        pool: test_pool,
    })
}

async fn cleanup_data_plane(
    data_plane: RunningDesktopLocalDataPlane,
    original: DesktopLocalRuntimeError,
) -> DesktopLocalRuntimeError {
    match data_plane.shutdown().await {
        Ok(()) => original,
        Err(_) => DesktopLocalRuntimeError::FailureCleanup,
    }
}

async fn cleanup_assembly(
    data_plane: RunningDesktopLocalDataPlane,
    assembly: PostgresApplicationAssembly,
    original: DesktopLocalRuntimeError,
) -> DesktopLocalRuntimeError {
    let result = finish_shutdown_stages(
        async {
            assembly.shutdown().await;
            true
        },
        async { data_plane.shutdown().await.is_ok() },
        crate::cancel::SHUTDOWN_DEADLINE,
    )
    .await;
    if result.is_ok() {
        original
    } else {
        DesktopLocalRuntimeError::FailureCleanup
    }
}

async fn cleanup_agent_host(
    data_plane: RunningDesktopLocalDataPlane,
    assembly: PostgresApplicationAssembly,
    agent_host: DesktopAgentHost,
    original: DesktopLocalRuntimeError,
) -> DesktopLocalRuntimeError {
    let result = finish_shutdown_stages(
        async {
            tokio::join!(agent_host.stop(), assembly.shutdown());
            true
        },
        async { data_plane.shutdown().await.is_ok() },
        crate::cancel::SHUTDOWN_DEADLINE,
    )
    .await;
    if result.is_ok() {
        original
    } else {
        DesktopLocalRuntimeError::FailureCleanup
    }
}

fn map_sidecar_error(error: PostgresSidecarError) -> DesktopLocalRuntimeError {
    #[cfg(test)]
    {
        let diagnostic: Option<&'static [u8]> = match &error {
            PostgresSidecarError::StartLockGuardInvalid => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=start_lock_guard_invalid\n",
            ),
            PostgresSidecarError::ProcessIdentityInvalid => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=process_identity_invalid\n",
            ),
            PostgresSidecarError::StartupJournalInvalid => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=startup_journal_invalid\n",
            ),
            PostgresSidecarError::HelperJournalInvalid => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=helper_journal_invalid\n",
            ),
            PostgresSidecarError::Secret(PostgresSecretStoreError::Corrupt) => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=secret_corrupt\n",
            ),
            PostgresSidecarError::Secret(PostgresSecretStoreError::DispositionInvalid) => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=sidecar variant=secret_disposition_invalid\n",
            ),
            _ => None,
        };
        if let Some(diagnostic) = diagnostic {
            let stderr = std::io::stderr();
            let mut sink = stderr.lock();
            let _ = sink.write(diagnostic);
        }
    }
    match error {
        PostgresSidecarError::StartLockHeld => DesktopLocalRuntimeError::StartupBusy,
        PostgresSidecarError::StartLockRecoveryRequired => {
            DesktopLocalRuntimeError::RecoveryRequired
        }
        PostgresSidecarError::StartupJournalRecoveryRequired
        | PostgresSidecarError::HelperJournalRecoveryRequired => {
            DesktopLocalRuntimeError::RecoveryRequired
        }
        PostgresSidecarError::StartLockGuardInvalid
        | PostgresSidecarError::ProcessIdentityInvalid
        | PostgresSidecarError::StartupJournalInvalid
        | PostgresSidecarError::HelperJournalInvalid => {
            DesktopLocalRuntimeError::InitializationEvidenceInvalid
        }
        PostgresSidecarError::StartupJournalReconciliationRequired
        | PostgresSidecarError::HelperJournalReconciliationRequired => {
            DesktopLocalRuntimeError::InitializationReconciliationRequired
        }
        PostgresSidecarError::ShutdownFailed => DesktopLocalRuntimeError::FailureCleanup,
        PostgresSidecarError::Secret(PostgresSecretStoreError::OsStore(error)) => {
            map_os_secret_store_error(error)
        }
        PostgresSidecarError::Secret(PostgresSecretStoreError::OsStoreReconciliationRequired(
            error,
        )) => DesktopLocalRuntimeError::OsSecretStoreReconciliationRequired(error),
        PostgresSidecarError::Secret(PostgresSecretStoreError::Missing) => {
            DesktopLocalRuntimeError::RecoveryRequired
        }
        PostgresSidecarError::Secret(
            PostgresSecretStoreError::Corrupt | PostgresSecretStoreError::DispositionInvalid,
        ) => DesktopLocalRuntimeError::InitializationEvidenceInvalid,
        PostgresSidecarError::Secret(PostgresSecretStoreError::ReconciliationRequired) => {
            DesktopLocalRuntimeError::InitializationReconciliationRequired
        }
        _ => DesktopLocalRuntimeError::Sidecar,
    }
}

fn map_vault_error(error: DesktopVaultKeyError) -> DesktopLocalRuntimeError {
    #[cfg(test)]
    {
        let diagnostic: Option<&'static [u8]> = match &error {
            DesktopVaultKeyError::Corrupt => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=vault variant=master_key_corrupt\n",
            ),
            DesktopVaultKeyError::MaterialInvalid => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=vault variant=application_material_invalid\n",
            ),
            DesktopVaultKeyError::DataPlaneNotRunning => Some(
                b"ARTIFACT_LIFECYCLE_LOCAL_INITIALIZER_INVALID stage=vault variant=data_plane_not_running\n",
            ),
            _ => None,
        };
        if let Some(diagnostic) = diagnostic {
            let stderr = std::io::stderr();
            let mut sink = stderr.lock();
            let _ = sink.write(diagnostic);
        }
    }
    match error {
        DesktopVaultKeyError::OsStore(error) => map_os_secret_store_error(error),
        DesktopVaultKeyError::OsStoreReconciliationRequired(error) => {
            DesktopLocalRuntimeError::OsSecretStoreReconciliationRequired(error)
        }
        DesktopVaultKeyError::Missing => DesktopLocalRuntimeError::RecoveryRequired,
        DesktopVaultKeyError::Corrupt
        | DesktopVaultKeyError::MaterialInvalid
        | DesktopVaultKeyError::DataPlaneNotRunning => {
            DesktopLocalRuntimeError::InitializationEvidenceInvalid
        }
        DesktopVaultKeyError::ReconciliationRequired => {
            DesktopLocalRuntimeError::InitializationReconciliationRequired
        }
        _ => DesktopLocalRuntimeError::Vault,
    }
}

fn map_os_secret_store_error(error: OsSecretStoreError) -> DesktopLocalRuntimeError {
    match error {
        OsSecretStoreError::AccessDenied => {
            DesktopLocalRuntimeError::OsSecretStoreAccessDenied(error)
        }
        OsSecretStoreError::AuthFailed => DesktopLocalRuntimeError::OsSecretStoreAuthFailed(error),
        OsSecretStoreError::InteractionRequired => {
            DesktopLocalRuntimeError::OsSecretStoreInteractionRequired(error)
        }
        OsSecretStoreError::StoreUnavailable => {
            DesktopLocalRuntimeError::OsSecretStoreUnavailable(error)
        }
        OsSecretStoreError::Unknown => DesktopLocalRuntimeError::OsSecretStoreUnknown(error),
    }
}

fn map_data_plane_error(error: DesktopLocalCompositionError) -> DesktopLocalRuntimeError {
    match error {
        DesktopLocalCompositionError::FailureCleanup
        | DesktopLocalCompositionError::SidecarShutdown => DesktopLocalRuntimeError::FailureCleanup,
        DesktopLocalCompositionError::Database(DesktopLocalDatabaseError::Missing) => {
            DesktopLocalRuntimeError::RecoveryRequired
        }
        _ => DesktopLocalRuntimeError::DataPlane,
    }
}

fn valid_window_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;
    use core::task::{Context as TaskContext, Poll};
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use openbot_application::{AppEventStream, ApplicationService};
    use openbot_contracts::command::{
        AppCommand, AppEvent, AppReply, HealthReport, SubscriptionRequest,
    };
    use openbot_contracts::error::AppError;
    use tauri::WindowEvent;

    use super::*;
    use crate::testing::auth_for;

    static TEST_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct EmptyStream(VecDeque<AppEvent>);

    impl futures_core::Stream for EmptyStream {
        type Item = AppEvent;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut TaskContext<'_>,
        ) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    struct NoopService;

    #[async_trait]
    impl ApplicationService for NoopService {
        async fn execute(
            &self,
            _auth: AuthContext,
            _command: AppCommand,
        ) -> Result<AppReply, AppError> {
            Ok(AppReply::Health(HealthReport { ok: true }))
        }

        async fn subscribe(
            &self,
            _auth: AuthContext,
            _request: SubscriptionRequest,
        ) -> Result<AppEventStream, AppError> {
            Ok(Box::pin(EmptyStream(VecDeque::new())))
        }
    }

    struct CountingOwner(Arc<AtomicUsize>);

    impl RuntimeShutdownOwner for CountingOwner {
        fn start_closing(
            self: Box<Self>,
            completion: Option<DesktopLocalClosingCompletion>,
        ) -> DesktopLocalShutdownWaiter {
            start_mock_closing_job(completion, async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn start_mock_closing_job(
        completion: Option<DesktopLocalClosingCompletion>,
        work: impl Future<Output = Result<(), DesktopLocalRuntimeError>> + Send + 'static,
    ) -> DesktopLocalShutdownWaiter {
        let started = Instant::now();
        let observation = Arc::new(DesktopLocalClosingObservation {
            facts: Mutex::new(DesktopLocalClosingFacts {
                started,
                deadline: started + crate::cancel::SHUTDOWN_DEADLINE,
                job_spawned_at: None,
                job_entered_at: None,
                drain_ack_at: None,
                postgres_ack_at: None,
                job_finished_at: None,
                waiter_ack_observed_at: None,
                waiter_detached_at: None,
                outcome: None,
            }),
        });
        let state_ok = match &completion {
            Some(completion) => completion
                .state
                .install_closing_observation(observation.clone())
                .is_ok(),
            None => true,
        };
        let mut completion = ShutdownCompletion {
            completion,
            observation: observation.clone(),
            completed: false,
        };
        let (reply, receiver) = tokio::sync::oneshot::channel();
        let job_observation = observation.clone();
        tauri::async_runtime::spawn(async move {
            job_observation.update(|facts| facts.job_entered_at = Some(Instant::now()));
            let succeeded = work.await.is_ok();
            let succeeded = completion.finish(state_ok && succeeded);
            let _received = reply.send(if succeeded {
                Ok(())
            } else {
                Err(DesktopLocalRuntimeError::Shutdown)
            });
        });
        observation.update(|facts| facts.job_spawned_at = Some(Instant::now()));
        DesktopLocalShutdownWaiter {
            reply: receiver,
            observation,
            reply_observed: false,
        }
    }

    fn protocol_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "openbot-tauri-background-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("index.html"),
            "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>",
        )
        .unwrap();
        fs::write(root.join("openbot-bootstrap.mjs"), "export {};").unwrap();
        root
    }

    fn lifecycle() -> (
        Arc<DesktopWindowLifecycle>,
        Arc<DesktopTauriProtocol>,
        PathBuf,
    ) {
        let root = protocol_root();
        let transport = Arc::new(InProcessTransport::new(Arc::new(NoopService)));
        let protocol = Arc::new(DesktopTauriProtocol::open(&root, transport).unwrap());
        (
            Arc::new(DesktopWindowLifecycle::new("openbot", Arc::clone(&protocol)).unwrap()),
            protocol,
            root,
        )
    }

    #[test]
    fn phase_fences_exit_until_background_is_terminal() {
        let state = DesktopLocalRuntimeState::new();
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Initializing);
        assert!(!state.note_exit_requested().unwrap());
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Initializing);
        state.fail_startup();
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Failed);
    }

    #[test]
    fn release_label_and_application_network_policy_are_closed() {
        assert!(valid_window_label("main"));
        assert!(!valid_window_label(""));
        assert!(!valid_window_label("main/window"));
        assert!(!valid_window_label(&"a".repeat(65)));

        assert!(
            DesktopLocalApplicationInput::new(
                DesktopOpenAiProviderInput::new(
                    "https://api.example.test/v1",
                    vec!["203.0.113.0/24".to_owned()],
                )
                .unwrap(),
                DesktopAgentBudgets::new(
                    Some(Duration::from_secs(2)),
                    Some(Duration::from_secs(1_800)),
                    16_384,
                )
                .unwrap(),
            )
            .is_ok()
        );
    }

    #[test]
    fn os_store_categories_survive_scram_and_vault_startup_mapping() {
        for (store_error, expected_code) in [
            (
                crate::os_secret_store::OsSecretStoreError::AccessDenied,
                "desktop_local_runtime_os_secret_store_access_denied",
            ),
            (
                crate::os_secret_store::OsSecretStoreError::AuthFailed,
                "desktop_local_runtime_os_secret_store_auth_failed",
            ),
            (
                crate::os_secret_store::OsSecretStoreError::InteractionRequired,
                "desktop_local_runtime_os_secret_store_interaction_required",
            ),
            (
                crate::os_secret_store::OsSecretStoreError::StoreUnavailable,
                "desktop_local_runtime_os_secret_store_unavailable",
            ),
            (
                crate::os_secret_store::OsSecretStoreError::Unknown,
                "desktop_local_runtime_os_secret_store_unknown",
            ),
        ] {
            let scram = map_sidecar_error(PostgresSidecarError::Secret(
                crate::postgres_sidecar::PostgresSecretStoreError::OsStore(store_error),
            ));
            let vault = map_vault_error(crate::desktop_vault::DesktopVaultKeyError::OsStore(
                store_error,
            ));
            assert_eq!(scram.code(), expected_code);
            assert_eq!(vault.code(), expected_code);
            assert_eq!(scram.to_string(), expected_code);
            assert_eq!(vault.to_string(), expected_code);
            let os_code = store_error.to_string();
            assert_eq!(scram.os_code(), Some(os_code.as_str()));
            assert_eq!(vault.os_code(), Some(os_code.as_str()));
            assert!(startup_failure_diagnostic(&scram).contains(&format!(" os_code={os_code}\n")));
            assert!(startup_failure_diagnostic(&vault).contains(&format!(" os_code={os_code}\n")));
        }

        let source = crate::os_secret_store::OsSecretStoreError::AuthFailed;
        for startup in [
            map_sidecar_error(PostgresSidecarError::Secret(
                crate::postgres_sidecar::PostgresSecretStoreError::OsStoreReconciliationRequired(
                    source,
                ),
            )),
            map_vault_error(
                crate::desktop_vault::DesktopVaultKeyError::OsStoreReconciliationRequired(source),
            ),
        ] {
            assert_eq!(
                startup.code(),
                "desktop_local_runtime_os_secret_store_reconciliation_required"
            );
            assert_eq!(
                std::error::Error::source(&startup).map(|source| source.to_string()),
                Some("desktop_os_secret_store_auth_failed".to_owned())
            );
            let rendered = format!("{startup:?} {startup}");
            assert!(!rendered.contains("-25293"));
            assert!(!rendered.to_ascii_lowercase().contains("locked"));
        }
    }

    #[test]
    fn r274_runtime_codes_and_display_are_identical() {
        for (error, expected) in [
            (
                DesktopLocalRuntimeError::StartupBusy,
                "desktop_local_runtime_startup_busy",
            ),
            (
                DesktopLocalRuntimeError::RecoveryRequired,
                "desktop_local_runtime_recovery_required",
            ),
            (
                DesktopLocalRuntimeError::InitializationEvidenceInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                DesktopLocalRuntimeError::InitializationReconciliationRequired,
                "desktop_local_runtime_initialization_reconciliation_required",
            ),
        ] {
            assert_eq!(error.code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn r279_data_plane_errors_preserve_cleanup_and_missing_database_classes() {
        for error in [
            DesktopLocalCompositionError::FailureCleanup,
            DesktopLocalCompositionError::SidecarShutdown,
        ] {
            let mapped = map_data_plane_error(error);
            assert!(matches!(mapped, DesktopLocalRuntimeError::FailureCleanup));
            assert_eq!(
                mapped.code(),
                "desktop_local_runtime_failure_cleanup_failed"
            );
            assert_eq!(
                startup_failure_diagnostic(&mapped),
                "wrok_bot_desktop_startup_failed code=desktop_local_runtime_failure_cleanup_failed\n"
            );
        }

        let missing = map_data_plane_error(DesktopLocalCompositionError::Database(
            DesktopLocalDatabaseError::Missing,
        ));
        assert!(matches!(
            missing,
            DesktopLocalRuntimeError::RecoveryRequired
        ));
        assert_eq!(missing.code(), "desktop_local_runtime_recovery_required");
        assert_eq!(
            startup_failure_diagnostic(&missing),
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_recovery_required\n"
        );

        let fallback = map_data_plane_error(DesktopLocalCompositionError::InstallationMismatch);
        assert!(matches!(fallback, DesktopLocalRuntimeError::DataPlane));
        assert_eq!(fallback.code(), "desktop_local_runtime_data_plane_failed");
        assert_eq!(
            startup_failure_diagnostic(&fallback),
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_data_plane_failed\n"
        );
    }

    #[test]
    fn r274_sidecar_and_master_failures_map_to_the_frozen_runtime_classes() {
        for (error, expected) in [
            (
                PostgresSidecarError::StartLockHeld,
                "desktop_local_runtime_startup_busy",
            ),
            (
                PostgresSidecarError::StartLockRecoveryRequired,
                "desktop_local_runtime_recovery_required",
            ),
            (
                PostgresSidecarError::StartLockGuardInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::ProcessIdentityInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::StartupJournalRecoveryRequired,
                "desktop_local_runtime_recovery_required",
            ),
            (
                PostgresSidecarError::StartupJournalInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::StartupJournalReconciliationRequired,
                "desktop_local_runtime_initialization_reconciliation_required",
            ),
            (
                PostgresSidecarError::HelperJournalRecoveryRequired,
                "desktop_local_runtime_recovery_required",
            ),
            (
                PostgresSidecarError::HelperJournalInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::HelperJournalReconciliationRequired,
                "desktop_local_runtime_initialization_reconciliation_required",
            ),
            (
                PostgresSidecarError::Secret(PostgresSecretStoreError::Missing),
                "desktop_local_runtime_recovery_required",
            ),
            (
                PostgresSidecarError::Secret(PostgresSecretStoreError::Corrupt),
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::Secret(PostgresSecretStoreError::DispositionInvalid),
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                PostgresSidecarError::Secret(PostgresSecretStoreError::ReconciliationRequired),
                "desktop_local_runtime_initialization_reconciliation_required",
            ),
            (
                PostgresSidecarError::ShutdownFailed,
                "desktop_local_runtime_failure_cleanup_failed",
            ),
        ] {
            let mapped = map_sidecar_error(error);
            assert_eq!(mapped.code(), expected);
            assert_eq!(mapped.to_string(), expected);
        }

        for (error, expected) in [
            (
                DesktopVaultKeyError::Missing,
                "desktop_local_runtime_recovery_required",
            ),
            (
                DesktopVaultKeyError::Corrupt,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                DesktopVaultKeyError::MaterialInvalid,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                DesktopVaultKeyError::DataPlaneNotRunning,
                "desktop_local_runtime_initialization_evidence_invalid",
            ),
            (
                DesktopVaultKeyError::ReconciliationRequired,
                "desktop_local_runtime_initialization_reconciliation_required",
            ),
        ] {
            let mapped = map_vault_error(error);
            assert_eq!(mapped.code(), expected);
            assert_eq!(mapped.to_string(), expected);
        }

        assert!(matches!(
            map_sidecar_error(PostgresSidecarError::Secret(
                PostgresSecretStoreError::IdentityInvalid
            )),
            DesktopLocalRuntimeError::Sidecar
        ));
        assert!(matches!(
            map_vault_error(DesktopVaultKeyError::IdentityInvalid),
            DesktopLocalRuntimeError::Vault
        ));
    }

    #[test]
    fn startup_diagnostic_is_closed_bounded_and_preserves_only_os_category() {
        let ordinary = startup_failure_diagnostic(&DesktopLocalRuntimeError::RecoveryRequired);
        assert_eq!(
            ordinary,
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_recovery_required\n"
        );
        assert!(
            !startup_failure_diagnostic(
                &DesktopLocalRuntimeError::InitializationReconciliationRequired
            )
            .contains(" os_code=")
        );

        let with_os_source = startup_failure_diagnostic(
            &DesktopLocalRuntimeError::OsSecretStoreReconciliationRequired(
                OsSecretStoreError::AuthFailed,
            ),
        );
        assert_eq!(
            with_os_source,
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_os_secret_store_reconciliation_required os_code=desktop_os_secret_store_auth_failed\n"
        );
        for diagnostic in [ordinary, with_os_source] {
            assert!(diagnostic.len() <= STARTUP_DIAGNOSTIC_MAX_BYTES);
            assert_eq!(diagnostic.bytes().filter(|byte| *byte == b'\n').count(), 1);
            assert!(diagnostic.ends_with('\n'));
        }

        let source_canary = "SECRET=/Users/alice/private/account-token";
        let mapped = map_sidecar_error(PostgresSidecarError::Io(std::io::Error::other(
            source_canary,
        )));
        let diagnostic = startup_failure_diagnostic(&mapped);
        assert!(!diagnostic.contains(source_canary));
        assert!(!diagnostic.contains("/Users/alice"));
        assert_eq!(
            diagnostic,
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_sidecar_failed\n"
        );
    }

    struct BrokenDiagnosticSink {
        writes: usize,
    }

    impl std::io::Write for BrokenDiagnosticSink {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test-only broken diagnostic sink",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn async_prepare_result_uses_one_non_masking_diagnostic_write() {
        let mut captured = Vec::new();
        let result: Result<(), DesktopLocalRuntimeError> = report_preparation_result_to(
            Err(DesktopLocalRuntimeError::RecoveryRequired),
            &mut captured,
        );
        assert!(matches!(
            result,
            Err(DesktopLocalRuntimeError::RecoveryRequired)
        ));
        assert_eq!(
            captured,
            b"wrok_bot_desktop_startup_failed code=desktop_local_runtime_recovery_required\n"
        );

        let mut sink = BrokenDiagnosticSink { writes: 0 };
        let result: Result<(), DesktopLocalRuntimeError> =
            report_preparation_result_to(Err(DesktopLocalRuntimeError::FailureCleanup), &mut sink);
        assert!(matches!(
            result,
            Err(DesktopLocalRuntimeError::FailureCleanup)
        ));
        assert_eq!(sink.writes, 1);

        let result = report_preparation_result_to(Ok(17_u8), &mut sink);
        assert_eq!(result.unwrap(), 17);
        assert_eq!(sink.writes, 1);
    }

    #[test]
    fn cleanup_failure_replaces_the_original_startup_class() {
        let failed = map_sidecar_error(PostgresSidecarError::ShutdownFailed);
        assert!(matches!(failed, DesktopLocalRuntimeError::FailureCleanup));
        assert_eq!(
            startup_failure_diagnostic(&failed),
            "wrok_bot_desktop_startup_failed code=desktop_local_runtime_failure_cleanup_failed\n"
        );
    }

    #[test]
    fn app_data_authority_is_exactly_tauri_path_resolver_output() {
        let app = tauri::test::mock_app();
        let expected = app.path().app_data_dir().unwrap();
        let actual = resolve_current_user_app_data_root(&app).unwrap();
        assert_eq!(actual.as_path(), expected);
    }

    #[test]
    fn external_tauri_context_cannot_precreate_a_window_before_setup() {
        let mut context: Context<tauri::test::MockRuntime> =
            tauri::test::mock_context(tauri::test::noop_assets());
        assert!(validate_tauri_context(&context).is_ok());
        context.config_mut().app.windows.push(Default::default());
        assert!(matches!(
            validate_tauri_context(&context),
            Err(DesktopLocalRuntimeError::Configuration)
        ));
        context.config_mut().app.windows[0].create = false;
        assert!(validate_tauri_context(&context).is_ok());
    }

    #[tokio::test]
    async fn destroyed_last_window_releases_the_single_background_owner() {
        let (lifecycle, protocol, root) = lifecycle();
        let app = tauri::test::mock_app();
        lifecycle
            .create_verified_window(
                &app,
                "main",
                VerifiedDesktopWindowAuthority::from_verified_session(auth_for("actor-1"), None),
            )
            .unwrap();
        assert_eq!(lifecycle.active_window_count(), 1);
        assert!(protocol.is_window_bound("main").unwrap());

        let state = DesktopLocalRuntimeState::new();
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let mut owner: Option<Box<dyn RuntimeShutdownOwner>> =
            Some(Box::new(CountingOwner(Arc::clone(&shutdowns))));
        assert!(
            !state
                .install_owner(&mut owner, Arc::clone(&lifecycle))
                .unwrap()
        );
        assert!(owner.is_none());
        assert!(!state.mark_ready().unwrap());
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Ready);

        assert!(
            lifecycle
                .handle_window_event("main", &WindowEvent::Destroyed)
                .unwrap()
        );
        assert_eq!(lifecycle.active_window_count(), 0);
        assert!(!protocol.is_window_bound("main").unwrap());
        let owner = state.begin_shutdown().unwrap().unwrap();
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Stopping);
        owner.start_closing(None).await.unwrap();
        state.finish_shutdown(true);
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Stopped);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    struct PausedOwner {
        calls: Arc<AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        succeeds: bool,
    }

    impl RuntimeShutdownOwner for PausedOwner {
        fn start_closing(
            self: Box<Self>,
            completion: Option<DesktopLocalClosingCompletion>,
        ) -> DesktopLocalShutdownWaiter {
            start_mock_closing_job(completion, async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                self.release.notified().await;
                if self.succeeds {
                    Ok(())
                } else {
                    Err(DesktopLocalRuntimeError::Shutdown)
                }
            })
        }
    }

    fn install_test_owner(
        state: &DesktopLocalRuntimeState,
        owner: Box<dyn RuntimeShutdownOwner>,
    ) -> PathBuf {
        let (lifecycle, _, root) = lifecycle();
        let mut owner = Some(owner);
        state.install_owner(&mut owner, lifecycle).unwrap();
        root
    }

    async fn phase_reached(state: &DesktopLocalRuntimeState, phase: DesktopLocalRuntimePhase) {
        let mut changed = state.changed.subscribe();
        while state.phase() != phase {
            changed.changed().await.unwrap();
        }
    }

    #[test]
    fn terminal_exit_on_native_thread_joins_ready_owner_once_using_existing_runtime() {
        let state = DesktopLocalRuntimeState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let root = install_test_owner(&state, Box::new(CountingOwner(calls.clone())));
        state.mark_ready().unwrap();
        state.finish_startup();
        tauri::async_runtime::block_on(state.join_terminal_exit()).unwrap();
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Stopped);
        assert!(state.is_terminal_exit());
        tauri::async_runtime::block_on(state.join_terminal_exit()).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn terminal_exit_during_stopping_joins_existing_cleanup_without_replaying_owner() {
        for succeeds in [true, false] {
            let state = DesktopLocalRuntimeState::new();
            let calls = Arc::new(AtomicUsize::new(0));
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let root = install_test_owner(
                &state,
                Box::new(PausedOwner {
                    calls: calls.clone(),
                    entered: entered.clone(),
                    release: release.clone(),
                    succeeds,
                }),
            );
            state.mark_ready().unwrap();
            state.finish_startup();
            start_shutdown(state.clone(), None);
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            assert_eq!(state.phase(), DesktopLocalRuntimePhase::Stopping);
            let waiting_state = state.clone();
            let mut joined = tokio::spawn(async move { waiting_state.join_terminal_exit().await });
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut joined)
                    .await
                    .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            release.notify_one();
            let result = tokio::time::timeout(Duration::from_secs(2), joined)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(state.join_terminal_exit().await.is_ok(), succeeds);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn terminal_exit_waits_for_initializing_owner_handoff_and_cleanup() {
        let state = DesktopLocalRuntimeState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let (lifecycle, _, root) = lifecycle();
        let startup_entered = Arc::new(tokio::sync::Notify::new());
        let startup_release = Arc::new(tokio::sync::Notify::new());
        let startup_state = state.clone();
        let entered = startup_entered.clone();
        let release = startup_release.clone();
        let owner_calls = calls.clone();
        let startup = tokio::spawn(async move {
            let _completion = StartupCompletion(startup_state.clone());
            assert!(!startup_state.stop_before_startup());
            entered.notify_one();
            release.notified().await;
            let mut owner: Option<Box<dyn RuntimeShutdownOwner>> =
                Some(Box::new(CountingOwner(owner_calls)));
            assert!(startup_state.install_owner(&mut owner, lifecycle).unwrap());
            assert!(!startup_state.can_create_window());
        });
        startup_entered.notified().await;
        let waiting_state = state.clone();
        let mut joined = tokio::spawn(async move { waiting_state.join_terminal_exit().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut joined)
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        startup_release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), joined)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        startup.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn terminal_exit_before_startup_does_not_acquire_an_owner() {
        let state = DesktopLocalRuntimeState::new();
        state.note_terminal_exit().unwrap();
        {
            let _completion = StartupCompletion(state.clone());
            assert!(state.stop_before_startup());
        }
        state.join_terminal_exit().await.unwrap();
        assert!(state.inner.lock().unwrap().owner.is_none());
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::Stopped);
    }

    #[tokio::test]
    async fn queued_window_creation_is_rejected_after_terminal_exit_and_owner_is_released() {
        let state = DesktopLocalRuntimeState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let root = install_test_owner(&state, Box::new(CountingOwner(calls.clone())));
        assert!(state.can_create_window());
        state.finish_startup();
        // The production native closure uses this same gate before touching Wry. Queue delivery
        // is intentionally late here; the queued closure never owned the PostgreSQL lifecycle.
        state.join_terminal_exit().await.unwrap();
        let built_windows = AtomicUsize::new(0);
        if state.can_create_window() {
            built_windows.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(built_windows.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Failed queue delivery also uses the unique start_shutdown path, including duplicates.
        start_shutdown(state.clone(), None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn completed_owner_cleanup_still_waits_for_startup_task_completion() {
        let state = DesktopLocalRuntimeState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let root = install_test_owner(&state, Box::new(CountingOwner(calls.clone())));
        let startup_completion = StartupCompletion(state.clone());
        let waiting_state = state.clone();
        let mut joined = tokio::spawn(async move { waiting_state.join_terminal_exit().await });
        tokio::time::timeout(
            Duration::from_secs(2),
            phase_reached(&state, DesktopLocalRuntimePhase::Stopped),
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut joined)
                .await
                .is_err()
        );
        drop(startup_completion);
        tokio::time::timeout(Duration::from_secs(2), joined)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn startup_failure_completion_wakes_terminal_exit_with_failure() {
        let state = DesktopLocalRuntimeState::new();
        let completion = StartupCompletion(state.clone());
        state.note_terminal_exit().unwrap();
        state.fail_startup();
        drop(completion);
        assert!(matches!(
            state.join_terminal_exit().await,
            Err(DesktopLocalRuntimeError::Shutdown)
        ));
    }

    #[tokio::test]
    async fn slow_or_failed_non_database_shutdown_still_completes_database_cleanup() {
        for slow in [true, false] {
            let database_calls = AtomicUsize::new(0);
            let cleanup_completed = AtomicUsize::new(0);
            let result = finish_shutdown_stages(
                async {
                    if slow {
                        std::future::pending::<()>().await;
                    }
                    false
                },
                async {
                    database_calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    cleanup_completed.fetch_add(1, Ordering::SeqCst);
                    true
                },
                Duration::from_millis(10),
            )
            .await;
            assert!(matches!(result, Err(DesktopLocalRuntimeError::Shutdown)));
            assert_eq!(database_calls.load(Ordering::SeqCst), 1);
            assert_eq!(cleanup_completed.load(Ordering::SeqCst), 1);
        }
        assert!(
            finish_shutdown_stages(async { true }, async { false }, Duration::from_millis(10))
                .await
                .is_err()
        );
        assert!(
            finish_shutdown_stages(async { true }, async { true }, Duration::from_millis(10))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn failed_window_queue_delivery_stops_starting_owner_and_late_callback_cannot_build() {
        let state = DesktopLocalRuntimeState::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let root = install_test_owner(&state, Box::new(CountingOwner(calls.clone())));
        assert_eq!(state.phase(), DesktopLocalRuntimePhase::StartingWindow);
        state.finish_startup();
        // Production run_on_main_thread Err uses request_shutdown -> start_shutdown. Model that
        // outcome before any native callback was delivered; no real GUI queue is claimed here.
        start_shutdown(state.clone(), None);
        state.join_terminal_exit().await.unwrap();
        assert!(!state.can_create_window());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
