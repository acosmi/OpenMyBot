//! Per-instance Desktop application master key and derived cryptographic material.
//!
//! v4 §6.4 requires the Desktop master key to live in Keychain / Credential Manager / Secret
//! Service, never an environment variable or app-data file. The only production entry point is a
//! [`PreparedDesktopLocalDataPlane`] that still owns the single-instance PostgreSQL start lock and
//! asynchronously verifies the durable master journal plus PG canary before it can become Running.
//! Platform calls are blocking; the Desktop runtime calls this module from its Tauri runtime worker
//! before creating any window.

use std::sync::Arc;

use openbot_contracts::ids::TenantId;
use openbot_domain::remote_callback::RemoteRunAssertionSigner;
use openbot_domain::vault::{
    ApplicationKeyPurpose, DesktopVaultCanaryBinding, KeyVersion, NONCE_BYTES, Nonce, SecretBytes,
    WrappingKey, derive_application_key, seal_desktop_vault_canary,
};
use openbot_infra::db::desktop_local::DesktopLocalDatabaseOrigin;
use openbot_infra::db::desktop_vault_canary::{
    self, DesktopVaultCanaryRow, VerifiedDesktopVaultCanary,
};
use openbot_infra::db::initialization::DatabaseOrigin;
use openbot_infra::vault::CredentialRecordVault;

use crate::desktop_local_bootstrap::PreparedDesktopLocalDataPlane;
use crate::os_secret_store::{OsSecretStore, OsSecretStoreError};

mod initialization_journal;
use initialization_journal::{JournalError, MasterInitializationJournal, MasterJournalPhase};

const STORED_FORMAT_VERSION: u8 = 1;
const MASTER_KEY_BYTES: usize = 32;
const STORED_BYTES: usize = 1 + MASTER_KEY_BYTES;
const ACCOUNT_PREFIX: &str = "desktop-vault-master-v1-";

/// Stable master-key failures; service/account/key bytes and platform prose never enter the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DesktopVaultKeyError {
    /// Reviewed external key-store service identity was malformed or prohibited.
    #[error("desktop_vault_key_store_identity_invalid")]
    IdentityInvalid,
    /// CSPRNG generation was unavailable before any store write.
    #[error("desktop_vault_key_store_unavailable")]
    Unavailable,
    /// OS key-store access failed with one of the frozen, payload-free platform categories.
    #[error(transparent)]
    OsStore(#[from] OsSecretStoreError),
    /// A platform failure after entering the write phase left persistence unknown.
    #[error("desktop_vault_master_key_reconciliation_required")]
    OsStoreReconciliationRequired(#[source] OsSecretStoreError),
    /// Existing bytes did not match the exact versioned 256-bit format.
    #[error("desktop_vault_master_key_corrupt")]
    Corrupt,
    /// Existing instance data was present but master key was missing from the OS key store.
    #[error("desktop_vault_master_key_missing")]
    Missing,
    /// Write succeeded ambiguously or immediate read-back differed.
    #[error("desktop_vault_master_key_reconciliation_required")]
    ReconciliationRequired,
    /// Domain key/signer construction rejected material that had already passed the closed shape.
    #[error("desktop_vault_application_material_invalid")]
    MaterialInvalid,
    /// The data-plane owner no longer has a live sidecar/start-lock capability.
    #[error("desktop_vault_data_plane_not_running")]
    DataPlaneNotRunning,
}

/// Host assertion that this external Keychain/Credential Manager service ID passed release review.
#[derive(Clone, PartialEq, Eq)]
pub struct ReviewedDesktopVaultKeyStoreService(Arc<str>);

impl ReviewedDesktopVaultKeyStoreService {
    /// Accept one canonical lowercase service ID without source-project marks.
    pub fn from_reviewed_release(value: impl Into<String>) -> Result<Self, DesktopVaultKeyError> {
        let value = value.into();
        let lower = value.to_ascii_lowercase();
        if value.len() < 3
            || value.len() > 128
            || value != lower
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
            || ["openbot", "copilotkit", "codex", "openai", "grok", "xai"]
                .iter()
                .any(|mark| lower.contains(mark))
        {
            return Err(DesktopVaultKeyError::IdentityInvalid);
        }
        Ok(Self(Arc::from(value)))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ReviewedDesktopVaultKeyStoreService {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ReviewedDesktopVaultKeyStoreService(<reviewed>)")
    }
}

/// Unique current-version Desktop master key. It is neither Clone nor serializable.
struct DesktopVaultMasterKey(SecretBytes);

impl core::fmt::Debug for DesktopVaultMasterKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DesktopVaultMasterKey([REDACTED])")
    }
}

/// Material needed by the next production ApplicationService assembly step.
pub struct DesktopApplicationKeyMaterial {
    credential_vault: CredentialRecordVault,
    audit_key: SecretBytes,
    remote_assertions: Arc<RemoteRunAssertionSigner>,
    mcp_oauth_state_key: SecretBytes,
}

impl DesktopApplicationKeyMaterial {
    /// Borrow the v2 credential record vault bound to this app-instance tenant.
    #[must_use]
    pub const fn credential_vault(&self) -> &CredentialRecordVault {
        &self.credential_vault
    }

    /// Explicitly expose the domain-separated audit checkpoint key to an audit adapter.
    #[must_use]
    pub fn expose_audit_key(&self) -> &[u8] {
        self.audit_key.expose()
    }

    /// Share the run-assertion signer, which holds only its derived key.
    #[must_use]
    pub fn remote_assertions(&self) -> Arc<RemoteRunAssertionSigner> {
        self.remote_assertions.clone()
    }

    /// Explicitly expose the domain-separated MCP OAuth state key to its coordinator.
    #[must_use]
    pub fn expose_mcp_oauth_state_key(&self) -> &[u8] {
        self.mcp_oauth_state_key.expose()
    }

    #[cfg(feature = "desktop-local-runtime")]
    pub(crate) fn into_assembly_parts(
        self,
    ) -> (
        CredentialRecordVault,
        SecretBytes,
        Arc<RemoteRunAssertionSigner>,
        SecretBytes,
    ) {
        (
            self.credential_vault,
            self.audit_key,
            self.remote_assertions,
            self.mcp_oauth_state_key,
        )
    }
}

impl core::fmt::Debug for DesktopApplicationKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DesktopApplicationKeyMaterial")
            .field("credential_vault", &self.credential_vault)
            .field("audit_key", &"[REDACTED]")
            .field("remote_assertions", &self.remote_assertions)
            .field("mcp_oauth_state_key", &"[REDACTED]")
            .finish()
    }
}

/// Private proof bundle consumed by the bootstrap completion typestate.
pub(crate) struct VaultReadyDesktopMaterial {
    material: DesktopApplicationKeyMaterial,
    proof: VerifiedDesktopVaultCanary,
    database_origin: DatabaseOrigin,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    retained_capture: Option<ArmedCaptureVault>,
}

/// The original master and its original confirmed journal, retained only for an armed request.
/// This owner has no public constructor and never reads a second master from the OS store.
#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
pub(crate) struct ArmedCaptureVault {
    master: DesktopVaultMasterKey,
    journal: MasterInitializationJournal,
    dataset_id: String,
    deployment_id: String,
    tenant_id: String,
    key_id: String,
    key_version: i32,
}

#[cfg(all(
    feature = "desktop-launcher",
    feature = "postgres-maintenance",
    target_os = "macos"
))]
impl ArmedCaptureVault {
    pub(crate) fn revalidate(&self) -> Result<(), DesktopVaultKeyError> {
        self.journal.revalidate_retained().map_err(map_journal)?;
        if self.journal.dataset_id() != self.dataset_id
            || self.journal.deployment_id() != self.deployment_id
            || self.journal.tenant_id() != self.tenant_id
            || self.journal.key_id() != self.key_id
            || self.key_version != 1
            || self.master.0.expose().len() != MASTER_KEY_BYTES
        {
            return Err(DesktopVaultKeyError::ReconciliationRequired);
        }
        Ok(())
    }

    pub(crate) fn revalidate_before(
        &self,
        clock: &dyn openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        clock.require_effect()?;
        self.journal.revalidate_retained_before(clock)?;
        if self.journal.dataset_id() != self.dataset_id
            || self.journal.deployment_id() != self.deployment_id
            || self.journal.tenant_id() != self.tenant_id
            || self.journal.key_id() != self.key_id || self.key_version != 1
        {
            return Err(Fault::SourceChanged);
        }
        if self.master.0.expose().len() != MASTER_KEY_BYTES {
            return Err(Fault::SecretInvalid);
        }
        clock.require_effect()
    }

    pub(crate) fn verify_capture_canary_before(
        &self,
        row: &DesktopVaultCanaryRow,
        clock: &dyn openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(), openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault> {
        use openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault as Fault;
        self.revalidate_before(clock)?;
        if row.dataset_id() != self.dataset_id
            || row.deployment_id() != self.deployment_id
            || row.tenant_id() != self.tenant_id
            || row.key_id() != self.key_id
            || row.key_version() != self.key_version || row.canary_schema() != 1
        {
            return Err(Fault::SourceChanged);
        }
        clock.require_effect()?;
        let observed_binding = DesktopVaultCanaryBinding::new(
            self.dataset_id.clone(), self.deployment_id.clone(), self.tenant_id.clone(),
            self.key_id.clone(), KeyVersion::new(1),
        );
        clock.require_effect()?;
        let binding = observed_binding.map_err(|_| Fault::SecretInvalid)?;
        let observed_envelope =
            openbot_domain::vault::DesktopVaultCanaryEnvelope::parse(row.encrypted_canary());
        clock.require_effect()?;
        let envelope = observed_envelope.map_err(|_| Fault::SecretInvalid)?;
        let observed_canary =
            openbot_domain::vault::open_desktop_vault_canary(&self.master.0, &binding, &envelope);
        clock.require_effect()?;
        observed_canary.map_err(|_| Fault::SecretInvalid)?;
        self.revalidate_before(clock)
    }

    pub(crate) fn journal_material(
        &self,
    ) -> Result<(std::fs::File, Vec<u8>), DesktopVaultKeyError> {
        self.revalidate()?;
        self.journal.retained_material().map_err(map_journal)
    }

    pub(crate) fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    pub(crate) fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    pub(crate) fn key_version(&self) -> i32 {
        self.key_version
    }

    /// Move the original secret, keeping the original journal owner separately resident.
    pub(crate) fn into_original_master_before(
        self,
        clock: &dyn openbot_infra::backup::whole_pg_capture_stream::CaptureClockCheck,
    ) -> Result<(SecretBytes, std::fs::File, Vec<u8>),
                (Self, openbot_domain::backup::whole_pg_carrier::WholePgCarrierFault)> {
        if let Err(error) = self.revalidate_before(clock) {
            return Err((self, error));
        }
        let (file, bytes) = self.journal.into_retained_material();
        Ok((self.master.0, file, bytes))
    }
}

enum MasterRetention<'a> {
    Ordinary,
    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    Armed(&'a crate::desktop_release::ReviewedNormalCaptureRequest),
    #[cfg(not(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    )))]
    _Lifetime(std::marker::PhantomData<&'a ()>),
}

impl VaultReadyDesktopMaterial {
    pub(crate) fn into_parts(
        self,
    ) -> (
        DesktopApplicationKeyMaterial,
        VerifiedDesktopVaultCanary,
        DatabaseOrigin,
    ) {
        (self.material, self.proof, self.database_origin)
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) fn into_capture_parts(
        self,
    ) -> (
        DesktopApplicationKeyMaterial,
        VerifiedDesktopVaultCanary,
        DatabaseOrigin,
        Option<ArmedCaptureVault>,
    ) {
        (
            self.material,
            self.proof,
            self.database_origin,
            self.retained_capture,
        )
    }
}

impl PreparedDesktopLocalDataPlane {
    /// Establish or verify the durable master+dataset canary before business bootstrap.
    pub(crate) async fn verify_application_key_material<S: OsSecretStore + ?Sized>(
        &self,
        store: &S,
        service: &ReviewedDesktopVaultKeyStoreService,
        package: &openbot_application::tenant::package::LoadedTenantPackage,
    ) -> Result<VaultReadyDesktopMaterial, DesktopVaultKeyError> {
        self.verify_application_key_material_inner(
            store,
            service,
            package,
            MasterRetention::Ordinary,
        )
        .await
    }

    #[cfg(all(
        feature = "desktop-launcher",
        feature = "postgres-maintenance",
        target_os = "macos"
    ))]
    pub(crate) async fn verify_application_key_material_for_capture<S: OsSecretStore + ?Sized>(
        &self,
        store: &S,
        service: &ReviewedDesktopVaultKeyStoreService,
        package: &openbot_application::tenant::package::LoadedTenantPackage,
        request: &crate::desktop_release::ReviewedNormalCaptureRequest,
    ) -> Result<VaultReadyDesktopMaterial, DesktopVaultKeyError> {
        self.verify_application_key_material_inner(
            store,
            service,
            package,
            MasterRetention::Armed(request),
        )
        .await
    }

    async fn verify_application_key_material_inner<S: OsSecretStore + ?Sized>(
        &self,
        store: &S,
        service: &ReviewedDesktopVaultKeyStoreService,
        package: &openbot_application::tenant::package::LoadedTenantPackage,
        retention: MasterRetention<'_>,
    ) -> Result<VaultReadyDesktopMaterial, DesktopVaultKeyError> {
        // Validate the full finite secret profile before the original master is acquired.
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        if let MasterRetention::Armed(request) = &retention {
            request
                .profile
                .validate_master_retention()
                .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?;
        }
        self.ensure_owner_current()
            .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
        let mut journal = MasterInitializationJournal::load(self).map_err(map_journal)?;
        let created_database = self.database_origin() == DesktopLocalDatabaseOrigin::Created;
        let fresh = created_database
            && self.sidecar_origin() == Some(crate::postgres_sidecar::PostgresSidecarOrigin::Fresh);
        let database_origin = if fresh {
            if journal.is_some() {
                return Err(DesktopVaultKeyError::ReconciliationRequired);
            }
            let origin = self
                .initialize_fresh_schema(package)
                .await
                .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?;
            desktop_vault_canary::verify_current_layout(self.pool())
                .await
                .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?;
            self.ensure_owner_current()
                .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
            MasterInitializationJournal::revalidate_absent(self).map_err(map_journal)?;
            origin
        } else {
            let phase = journal
                .as_ref()
                .map(MasterInitializationJournal::phase)
                .ok_or(DesktopVaultKeyError::ReconciliationRequired)?;
            match phase {
                MasterJournalPhase::Prepared | MasterJournalPhase::ReadbackConfirmed => {
                    desktop_vault_canary::verify_empty_initializing(self.pool())
                        .await
                        .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?;
                }
                MasterJournalPhase::WriteEntered => {
                    return Err(DesktopVaultKeyError::ReconciliationRequired);
                }
                MasterJournalPhase::CanaryWriteEntered | MasterJournalPhase::CanaryConfirmed => {
                    desktop_vault_canary::verify_pre_upgrade_layout(self.pool())
                        .await
                        .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?;
                }
            }
            DatabaseOrigin::RustManaged
        };

        if journal
            .as_ref()
            .is_some_and(|value| value.phase() == MasterJournalPhase::WriteEntered)
        {
            return Err(DesktopVaultKeyError::ReconciliationRequired);
        }
        self.ensure_owner_current()
            .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
        match journal.as_ref() {
            Some(value) => value.revalidate(self).map_err(map_journal)?,
            None => MasterInitializationJournal::revalidate_absent(self).map_err(map_journal)?,
        }
        let account = format!("{ACCOUNT_PREFIX}{}", self.authority().instance_id());
        let stored = store.read(service.as_str(), &account)?;
        match journal.as_ref() {
            Some(value) => value.revalidate(self).map_err(map_journal)?,
            None => MasterInitializationJournal::revalidate_absent(self).map_err(map_journal)?,
        }

        let master = match journal.as_ref().map(MasterInitializationJournal::phase) {
            None => {
                if stored.is_some() || !fresh {
                    return Err(DesktopVaultKeyError::ReconciliationRequired);
                }
                if self
                    .vault_creation_attempted
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(DesktopVaultKeyError::ReconciliationRequired);
                }
                journal = Some(MasterInitializationJournal::prepare(self).map_err(map_journal)?);
                create_master(store, service, &account, self, journal.as_mut().unwrap())?
            }
            Some(MasterJournalPhase::Prepared) => {
                if stored.is_some()
                    || self
                        .vault_creation_attempted
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(DesktopVaultKeyError::ReconciliationRequired);
                }
                create_master(store, service, &account, self, journal.as_mut().unwrap())?
            }
            Some(MasterJournalPhase::ReadbackConfirmed)
            | Some(MasterJournalPhase::CanaryWriteEntered)
            | Some(MasterJournalPhase::CanaryConfirmed) => {
                decode_stored(stored.ok_or(DesktopVaultKeyError::Missing)?)?
            }
            Some(MasterJournalPhase::WriteEntered) => unreachable!(),
        };

        let confirmed_journal = journal
            .as_mut()
            .ok_or(DesktopVaultKeyError::ReconciliationRequired)?;
        confirmed_journal.revalidate(self).map_err(map_journal)?;
        let proof = match confirmed_journal.phase() {
            MasterJournalPhase::ReadbackConfirmed => {
                if desktop_vault_canary::read(
                    self.pool(),
                    confirmed_journal.deployment_id(),
                    confirmed_journal.tenant_id(),
                )
                .await
                .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?
                .is_some()
                {
                    return Err(DesktopVaultKeyError::ReconciliationRequired);
                }
                confirmed_journal
                    .enter_canary_write(self)
                    .map_err(map_journal)?;
                self.ensure_owner_current()
                    .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
                let row = new_canary_row(&master, confirmed_journal)?;
                desktop_vault_canary::insert_once(self.pool(), &row)
                    .await
                    .map_err(|_| DesktopVaultKeyError::ReconciliationRequired)?;
                let proof = verify_canary(self, confirmed_journal, &master).await?;
                confirmed_journal
                    .confirm_canary(self)
                    .map_err(map_journal)?;
                proof
            }
            MasterJournalPhase::CanaryWriteEntered => {
                let proof = verify_canary(self, confirmed_journal, &master).await?;
                confirmed_journal
                    .confirm_canary(self)
                    .map_err(map_journal)?;
                proof
            }
            MasterJournalPhase::CanaryConfirmed => {
                verify_canary(self, confirmed_journal, &master).await?
            }
            _ => return Err(DesktopVaultKeyError::ReconciliationRequired),
        };
        confirmed_journal.revalidate(self).map_err(map_journal)?;
        let material =
            derive_application_material(self.authority().auth_context().tenant().clone(), &master)?;
        #[cfg(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        ))]
        let retained_capture = match retention {
            MasterRetention::Armed(_) => Some(ArmedCaptureVault {
                dataset_id: proof.dataset_id().to_owned(),
                deployment_id: proof.deployment_id().to_owned(),
                tenant_id: proof.tenant_id().to_owned(),
                key_id: proof.key_id().to_owned(),
                key_version: proof.key_version(),
                master,
                journal: journal
                    .take()
                    .ok_or(DesktopVaultKeyError::ReconciliationRequired)?,
            }),
            MasterRetention::Ordinary => {
                drop(master);
                None
            }
        };
        #[cfg(not(all(
            feature = "desktop-launcher",
            feature = "postgres-maintenance",
            target_os = "macos"
        )))]
        {
            let _ = retention;
            drop(master);
        }
        Ok(VaultReadyDesktopMaterial {
            material,
            proof,
            database_origin,
            #[cfg(all(
                feature = "desktop-launcher",
                feature = "postgres-maintenance",
                target_os = "macos"
            ))]
            retained_capture,
        })
    }
}

fn create_master<S: OsSecretStore + ?Sized>(
    store: &S,
    service: &ReviewedDesktopVaultKeyStoreService,
    account: &str,
    owner: &PreparedDesktopLocalDataPlane,
    journal: &mut MasterInitializationJournal,
) -> Result<DesktopVaultMasterKey, DesktopVaultKeyError> {
    let mut bytes = vec![0_u8; MASTER_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| DesktopVaultKeyError::Unavailable)?;
    let generated = DesktopVaultMasterKey(SecretBytes::new(bytes));
    journal.enter_write(owner).map_err(map_journal)?;
    owner
        .ensure_owner_current()
        .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
    journal.revalidate(owner).map_err(map_journal)?;
    let mut framed = Vec::with_capacity(STORED_BYTES);
    framed.push(STORED_FORMAT_VERSION);
    framed.extend_from_slice(generated.0.expose());
    let framed = SecretBytes::new(framed);
    store
        .write(service.as_str(), account, framed.expose())
        .map_err(DesktopVaultKeyError::OsStoreReconciliationRequired)?;
    owner
        .ensure_owner_current()
        .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
    journal.revalidate(owner).map_err(map_journal)?;
    let persisted = store
        .read(service.as_str(), account)
        .map_err(DesktopVaultKeyError::OsStoreReconciliationRequired)?
        .ok_or(DesktopVaultKeyError::ReconciliationRequired)
        .and_then(decode_stored)?;
    owner
        .ensure_owner_current()
        .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
    journal.revalidate(owner).map_err(map_journal)?;
    if !generated.0.ct_eq(&persisted.0) {
        return Err(DesktopVaultKeyError::ReconciliationRequired);
    }
    journal.confirm_readback(owner).map_err(map_journal)?;
    Ok(persisted)
}

fn new_canary_row(
    master: &DesktopVaultMasterKey,
    journal: &MasterInitializationJournal,
) -> Result<DesktopVaultCanaryRow, DesktopVaultKeyError> {
    let binding = DesktopVaultCanaryBinding::new(
        journal.dataset_id(),
        journal.deployment_id(),
        journal.tenant_id(),
        journal.key_id(),
        KeyVersion::new(1),
    )
    .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| DesktopVaultKeyError::Unavailable)?;
    let envelope = seal_desktop_vault_canary(&master.0, &binding, Nonce::from_array(nonce))
        .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?;
    DesktopVaultCanaryRow::new(
        journal.dataset_id(),
        journal.deployment_id(),
        journal.tenant_id(),
        journal.key_id(),
        envelope.to_column_value(),
    )
    .map_err(|_| DesktopVaultKeyError::MaterialInvalid)
}

async fn verify_canary(
    owner: &PreparedDesktopLocalDataPlane,
    journal: &MasterInitializationJournal,
    master: &DesktopVaultMasterKey,
) -> Result<VerifiedDesktopVaultCanary, DesktopVaultKeyError> {
    owner
        .ensure_owner_current()
        .map_err(|_| DesktopVaultKeyError::DataPlaneNotRunning)?;
    let proof = desktop_vault_canary::verify_persisted(
        owner.database(),
        &master.0,
        journal.dataset_id(),
        journal.deployment_id(),
        journal.tenant_id(),
        journal.key_id(),
    )
    .await
    .map_err(|error| match error {
        desktop_vault_canary::DesktopVaultCanaryError::MaterialInvalid => {
            DesktopVaultKeyError::MaterialInvalid
        }
        _ => DesktopVaultKeyError::ReconciliationRequired,
    })?;
    journal.revalidate(owner).map_err(map_journal)?;
    Ok(proof)
}

fn map_journal(error: JournalError) -> DesktopVaultKeyError {
    match error {
        JournalError::Unavailable => DesktopVaultKeyError::Unavailable,
        JournalError::ReconciliationRequired => DesktopVaultKeyError::ReconciliationRequired,
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct DesktopVaultKeyDisposition {
    is_existing: bool,
}

#[cfg(test)]
impl DesktopVaultKeyDisposition {
    const fn existing() -> Self {
        Self { is_existing: true }
    }
    const fn fresh() -> Self {
        Self { is_existing: false }
    }
    const fn is_existing(&self) -> bool {
        self.is_existing
    }
}

#[cfg(test)]
fn load_or_create_master_key<S: OsSecretStore + ?Sized>(
    store: &S,
    service: &ReviewedDesktopVaultKeyStoreService,
    instance_id: &str,
    disposition: DesktopVaultKeyDisposition,
) -> Result<DesktopVaultMasterKey, DesktopVaultKeyError> {
    if !valid_instance_id(instance_id) {
        return Err(DesktopVaultKeyError::Corrupt);
    }
    let account = format!("{ACCOUNT_PREFIX}{instance_id}");
    if let Some(stored) = store.read(service.as_str(), &account)? {
        return decode_stored(stored);
    }
    if disposition.is_existing() {
        return Err(DesktopVaultKeyError::Missing);
    }

    let mut bytes = vec![0_u8; MASTER_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| DesktopVaultKeyError::Unavailable)?;
    let generated = DesktopVaultMasterKey(SecretBytes::new(bytes));
    let mut framed = Vec::with_capacity(STORED_BYTES);
    framed.push(STORED_FORMAT_VERSION);
    framed.extend_from_slice(generated.0.expose());
    let framed = SecretBytes::new(framed);
    store
        .write(service.as_str(), &account, framed.expose())
        .map_err(DesktopVaultKeyError::OsStoreReconciliationRequired)?;
    let persisted = store
        .read(service.as_str(), &account)
        .map_err(DesktopVaultKeyError::OsStoreReconciliationRequired)?
        .ok_or(DesktopVaultKeyError::ReconciliationRequired)
        .and_then(decode_stored)?;
    if !generated.0.ct_eq(&persisted.0) {
        return Err(DesktopVaultKeyError::ReconciliationRequired);
    }
    Ok(persisted)
}

fn decode_stored(stored: SecretBytes) -> Result<DesktopVaultMasterKey, DesktopVaultKeyError> {
    let bytes = stored.expose();
    if bytes.len() != STORED_BYTES || bytes[0] != STORED_FORMAT_VERSION {
        return Err(DesktopVaultKeyError::Corrupt);
    }
    let key = bytes[1..].to_vec();
    drop(stored);
    Ok(DesktopVaultMasterKey(SecretBytes::new(key)))
}

fn derive_application_material(
    tenant: TenantId,
    master: &DesktopVaultMasterKey,
) -> Result<DesktopApplicationKeyMaterial, DesktopVaultKeyError> {
    let credential_vault = CredentialRecordVault::single_key(
        tenant,
        KeyVersion::new(1),
        WrappingKey::from_bytes(master.0.expose().to_vec())
            .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?,
    );
    let remote_assertions = Arc::new(
        RemoteRunAssertionSigner::new(master.0.expose().to_vec())
            .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?,
    );
    let audit_key = derive_application_key(&master.0, ApplicationKeyPurpose::AuditCheckpoint)
        .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?;
    let mcp_oauth_state_key =
        derive_application_key(&master.0, ApplicationKeyPurpose::McpOauthState)
            .map_err(|_| DesktopVaultKeyError::MaterialInvalid)?;
    Ok(DesktopApplicationKeyMaterial {
        credential_vault,
        audit_key,
        remote_assertions,
        mcp_oauth_state_key,
    })
}

#[cfg(test)]
fn valid_instance_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use openbot_domain::vault::{SecretKind, SecretPrincipal};
    use uuid::Uuid;

    use super::*;

    #[cfg(target_os = "macos")]
    static KEYCHAIN_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct MemoryStore {
        value: Mutex<Option<Vec<u8>>>,
        writes: AtomicUsize,
        replace_on_write: bool,
    }

    struct FailingOsStore {
        error: crate::os_secret_store::OsSecretStoreError,
        writes: AtomicUsize,
    }

    impl OsSecretStore for FailingOsStore {
        fn read(
            &self,
            _service: &str,
            _account: &str,
        ) -> Result<Option<SecretBytes>, crate::os_secret_store::OsSecretStoreError> {
            Err(self.error)
        }

        fn write(
            &self,
            _service: &str,
            _account: &str,
            _secret: &[u8],
        ) -> Result<(), crate::os_secret_store::OsSecretStoreError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            panic!("a failed key-store read must not enter the write path")
        }
    }

    impl MemoryStore {
        fn empty() -> Self {
            Self {
                value: Mutex::new(None),
                writes: AtomicUsize::new(0),
                replace_on_write: false,
            }
        }
    }

    impl OsSecretStore for MemoryStore {
        fn read(
            &self,
            _service: &str,
            _account: &str,
        ) -> Result<Option<SecretBytes>, crate::os_secret_store::OsSecretStoreError> {
            Ok(self.value.lock().unwrap().clone().map(SecretBytes::new))
        }

        fn write(
            &self,
            _service: &str,
            _account: &str,
            secret: &[u8],
        ) -> Result<(), crate::os_secret_store::OsSecretStoreError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            let mut value = secret.to_vec();
            if self.replace_on_write {
                value[1] ^= 1;
            }
            *self.value.lock().unwrap() = Some(value);
            Ok(())
        }
    }

    fn service() -> ReviewedDesktopVaultKeyStoreService {
        ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
            "com.example.product.desktop-vault.test",
        )
        .unwrap()
    }

    #[test]
    fn first_restart_corrupt_reconciliation_and_material_are_closed() {
        let instance = "a".repeat(64);
        let store = MemoryStore::empty();
        let first = load_or_create_master_key(
            &store,
            &service(),
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let first_material =
            derive_application_material(TenantId::new("tenant-a"), &first).unwrap();
        assert_eq!(store.writes.load(Ordering::Relaxed), 1);
        let secret_id = Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let plaintext = SecretBytes::new(b"vault-canary".to_vec());
        let sealed = first_material
            .credential_vault()
            .seal(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &plaintext,
            )
            .unwrap();
        let second = load_or_create_master_key(
            &store,
            &service(),
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let second_material =
            derive_application_material(TenantId::new("tenant-a"), &second).unwrap();
        let opened = second_material
            .credential_vault()
            .open(
                &secret_id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &sealed,
            )
            .unwrap()
            .into_secret();
        assert_eq!(opened.expose(), plaintext.expose());
        assert_eq!(store.writes.load(Ordering::Relaxed), 1);
        assert_ne!(
            first_material.expose_audit_key(),
            first_material.expose_mcp_oauth_state_key()
        );
        let rendered = format!("{first_material:?}");
        assert!(!rendered.contains("vault-canary"));

        let corrupt = MemoryStore {
            value: Mutex::new(Some(vec![STORED_FORMAT_VERSION, 1, 2, 3])),
            writes: AtomicUsize::new(0),
            replace_on_write: false,
        };
        assert!(matches!(
            load_or_create_master_key(
                &corrupt,
                &service(),
                &instance,
                DesktopVaultKeyDisposition::fresh()
            ),
            Err(DesktopVaultKeyError::Corrupt)
        ));
        assert_eq!(corrupt.writes.load(Ordering::Relaxed), 0);

        let mismatch = MemoryStore {
            value: Mutex::new(None),
            writes: AtomicUsize::new(0),
            replace_on_write: true,
        };
        assert!(matches!(
            load_or_create_master_key(
                &mismatch,
                &service(),
                &instance,
                DesktopVaultKeyDisposition::fresh()
            ),
            Err(DesktopVaultKeyError::ReconciliationRequired)
        ));
    }

    #[test]
    fn service_instance_and_stored_version_are_closed() {
        for rejected in [
            "",
            "ab",
            "Com.Example.Product.Vault",
            "com.example.openbot.vault",
            "spaces invalid",
        ] {
            assert!(ReviewedDesktopVaultKeyStoreService::from_reviewed_release(rejected).is_err());
        }
        assert!(matches!(
            load_or_create_master_key(
                &MemoryStore::empty(),
                &service(),
                "wrong",
                DesktopVaultKeyDisposition::fresh()
            ),
            Err(DesktopVaultKeyError::Corrupt)
        ));
        let bad_version = MemoryStore {
            value: Mutex::new(Some([vec![2], vec![0; MASTER_KEY_BYTES]].concat())),
            writes: AtomicUsize::new(0),
            replace_on_write: false,
        };
        assert!(matches!(
            load_or_create_master_key(
                &bad_version,
                &service(),
                &"b".repeat(64),
                DesktopVaultKeyDisposition::fresh()
            ),
            Err(DesktopVaultKeyError::Corrupt)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_keychain_persists_master_and_cross_restart_vault_open() {
        use security_framework::os::macos::keychain::CreateOptions;

        let root = std::env::temp_dir().join(format!(
            "openbot-desktop-vault-keychain-{}-{}",
            std::process::id(),
            KEYCHAIN_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("vault-test.keychain-db");
        let mut options = CreateOptions::new();
        options
            .password("test-only-private-keychain-password")
            .prompt_user(false);
        let keychain = options.create(&path).unwrap();
        let cleanup_keychain = keychain.clone();
        let store = crate::os_secret_store::MacOsKeychainSecretStore::from_keychain(keychain);
        let instance = "c".repeat(64);
        let service = service();
        let first = load_or_create_master_key(
            &store,
            &service,
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let first = derive_application_material(TenantId::new("tenant-keychain"), &first).unwrap();
        let id = Uuid::from_u128(0xfedc_ba09_8765_4321_fedc_ba09_8765_4321);
        let plaintext = SecretBytes::new(b"private-keychain-canary".to_vec());
        let sealed = first
            .credential_vault()
            .seal(
                &id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &plaintext,
            )
            .unwrap();
        let second = load_or_create_master_key(
            &store,
            &service,
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let second =
            derive_application_material(TenantId::new("tenant-keychain"), &second).unwrap();
        assert_eq!(
            second
                .credential_vault()
                .open(
                    &id,
                    SecretKind::Model,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Deployment,
                    &sealed,
                )
                .unwrap()
                .into_secret()
                .expose(),
            plaintext.expose()
        );
        let account = format!("{ACCOUNT_PREFIX}{instance}");
        let (_password, item) = cleanup_keychain
            .find_generic_password(service.as_str(), &account)
            .unwrap();
        item.delete();
        drop(first);
        drop(second);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "需要Windows当前用户Credential Manager真机读写"]
    fn windows_credential_manager_persists_master_and_cross_restart_vault_open() {
        let store = crate::os_secret_store::WindowsCredentialSecretStore;
        let instance = "d".repeat(64);
        let service = service();
        let account = format!("{ACCOUNT_PREFIX}{instance}");
        let target = format!("{}:{account}", service.as_str());
        let _ = openbot_windows_sandbox::delete_generic_credential(&target);

        let first = load_or_create_master_key(
            &store,
            &service,
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let first = derive_application_material(TenantId::new("tenant-windows"), &first).unwrap();
        let id = Uuid::from_u128(0xaaaa_bbbb_cccc_dddd_eeee_ffff_0000_1111);
        let plaintext = SecretBytes::new(b"windows-credential-canary".to_vec());
        let sealed = first
            .credential_vault()
            .seal(
                &id,
                SecretKind::Model,
                SecretPrincipal::Deployment,
                SecretPrincipal::Deployment,
                &plaintext,
            )
            .unwrap();
        let second = load_or_create_master_key(
            &store,
            &service,
            &instance,
            DesktopVaultKeyDisposition::fresh(),
        )
        .unwrap();
        let second = derive_application_material(TenantId::new("tenant-windows"), &second).unwrap();
        assert_eq!(
            second
                .credential_vault()
                .open(
                    &id,
                    SecretKind::Model,
                    SecretPrincipal::Deployment,
                    SecretPrincipal::Deployment,
                    &sealed,
                )
                .unwrap()
                .into_secret()
                .expose(),
            plaintext.expose()
        );
        assert!(openbot_windows_sandbox::delete_generic_credential(&target).unwrap());
    }

    #[test]
    fn existing_master_key_missing_refuses_to_generate_and_keeps_writes_zero() {
        let instance = "e".repeat(64);
        let store = MemoryStore::empty();
        let result = load_or_create_master_key(
            &store,
            &service(),
            &instance,
            DesktopVaultKeyDisposition::existing(),
        );
        assert!(matches!(result, Err(DesktopVaultKeyError::Missing)));
        assert_eq!(store.writes.load(Ordering::Relaxed), 0);

        // Pre-populated store returns existing key without writes
        let valid = MemoryStore {
            value: Mutex::new(Some(
                [vec![STORED_FORMAT_VERSION], vec![7_u8; MASTER_KEY_BYTES]].concat(),
            )),
            writes: AtomicUsize::new(0),
            replace_on_write: false,
        };
        let loaded = load_or_create_master_key(
            &valid,
            &service(),
            &instance,
            DesktopVaultKeyDisposition::existing(),
        )
        .unwrap();
        assert_eq!(loaded.0.expose(), &[7_u8; MASTER_KEY_BYTES]);
        assert_eq!(valid.writes.load(Ordering::Relaxed), 0);

        // Corrupt key under existing disposition errors closed without writes
        let corrupt = MemoryStore {
            value: Mutex::new(Some(vec![STORED_FORMAT_VERSION, 0x99])),
            writes: AtomicUsize::new(0),
            replace_on_write: false,
        };
        assert!(matches!(
            load_or_create_master_key(
                &corrupt,
                &service(),
                &instance,
                DesktopVaultKeyDisposition::existing()
            ),
            Err(DesktopVaultKeyError::Corrupt)
        ));
        assert_eq!(corrupt.writes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn os_store_error_categories_reach_vault_callers_without_writes() {
        let instance = "f".repeat(64);
        for error in [
            crate::os_secret_store::OsSecretStoreError::AccessDenied,
            crate::os_secret_store::OsSecretStoreError::AuthFailed,
            crate::os_secret_store::OsSecretStoreError::InteractionRequired,
            crate::os_secret_store::OsSecretStoreError::StoreUnavailable,
            crate::os_secret_store::OsSecretStoreError::Unknown,
        ] {
            let store = FailingOsStore {
                error,
                writes: AtomicUsize::new(0),
            };
            assert!(matches!(
                load_or_create_master_key(
                    &store,
                    &service(),
                    &instance,
                    DesktopVaultKeyDisposition::existing()
                ),
                Err(DesktopVaultKeyError::OsStore(actual)) if actual == error
            ));
            assert_eq!(store.writes.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn vault_os_failure_after_write_entry_requires_reconciliation() {
        struct AmbiguousOsStore {
            fail_write: bool,
            reads: AtomicUsize,
            writes: AtomicUsize,
        }
        impl OsSecretStore for AmbiguousOsStore {
            fn read(
                &self,
                _service: &str,
                _account: &str,
            ) -> Result<Option<SecretBytes>, crate::os_secret_store::OsSecretStoreError>
            {
                if self.reads.fetch_add(1, Ordering::Relaxed) == 0 {
                    Ok(None)
                } else {
                    Err(crate::os_secret_store::OsSecretStoreError::StoreUnavailable)
                }
            }

            fn write(
                &self,
                _service: &str,
                _account: &str,
                _secret: &[u8],
            ) -> Result<(), crate::os_secret_store::OsSecretStoreError> {
                self.writes.fetch_add(1, Ordering::Relaxed);
                if self.fail_write {
                    Err(crate::os_secret_store::OsSecretStoreError::StoreUnavailable)
                } else {
                    Ok(())
                }
            }
        }

        for fail_write in [true, false] {
            let store = AmbiguousOsStore {
                fail_write,
                reads: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
            };
            assert!(matches!(
                load_or_create_master_key(
                    &store,
                    &service(),
                    &"1".repeat(64),
                    DesktopVaultKeyDisposition::fresh()
                ),
                Err(DesktopVaultKeyError::OsStoreReconciliationRequired(
                    crate::os_secret_store::OsSecretStoreError::StoreUnavailable
                ))
            ));
            assert_eq!(store.writes.load(Ordering::Relaxed), 1);
            assert_eq!(
                store.reads.load(Ordering::Relaxed),
                usize::from(!fail_write) + 1
            );
        }
    }
}
