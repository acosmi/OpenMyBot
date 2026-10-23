//! Closed, release-bound inputs for the macOS product launcher.
//!
//! The expected outer manifest digest is supplied to the reviewed core build. Reading a manifest
//! and hashing it at launch does not establish trust. This module verifies that binding and all
//! declared resources before any OS secret access or child process creation. Native signing and
//! notarization remain release gates; a matching digest is not a claim that those gates passed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use openbot_application::tenant::package::{
    LoadedTenantPackage, TENANT_PACKAGE_FILENAMES, TenantPackageError, TenantPackageFiles,
    validate_tenant_package,
};
use openbot_contracts::engine::ENGINE_RELEASE_EPOCH;
use openbot_domain::vault::SecretBytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::postgres_sidecar::{
    PostgresBundleDigest, ReviewedPostgresKeyStoreService, ReviewedPostgresSigningIdentity,
    VerifiedPostgresBundle,
};
use crate::tauri_background::DesktopUiResource;
use crate::tauri_host::{VerifiedUiAssets, static_asset_max_bytes};
use crate::{
    DesktopAgentBudgets, DesktopLocalApplicationInput, DesktopLocalReleaseInput,
    DesktopLocalRuntimeConfig, DesktopOpenAiProviderInput, MacOsKeychainSecretStore, OsSecretStore,
    OsSecretStoreError, ReviewedDesktopVaultKeyStoreService,
};

/// Reviewed external product name; internal crate/protocol compatibility names are unchanged.
pub const PRODUCT_NAME: &str = "Wrok Bot";
/// Independent product bundle identity. This constant is not an Apple signing attestation.
pub const BUNDLE_IDENTIFIER: &str = "com.acosmi.wrokbot";
/// Only local application protocol installed by the product launcher.
pub const PROTOCOL_SCHEME: &str = "wrokbot";
/// Only window created by the verified background assembly.
pub const MAIN_WINDOW: &str = "main";
/// Independent current-user PostgreSQL Keychain service.
pub const POSTGRES_KEY_STORE_SERVICE: &str = "com.acosmi.wrokbot.postgresql";
/// Independent current-user application Vault Keychain service.
pub const VAULT_KEY_STORE_SERVICE: &str = "com.acosmi.wrokbot.vault";
/// Fixed outer manifest name beneath the release resource root.
pub const RELEASE_MANIFEST_FILE: &str = "wrok-bot-release.json";
/// The sole installation-bound variable in the release's first-party brand template.
pub const INSTANCE_BRAND_TEMPLATE: &str =
    "tenant:\n  id: ${WROK_BOT_INSTANCE_TENANT}\n  product_name: Wrok Bot\n";

mod capture_request;
use capture_request::CaptureField;
pub(crate) use capture_request::{CaptureProfile, ReviewedNormalCaptureRequest};

const MANIFEST_MAX_BYTES: u64 = 1024 * 1024;
const TENANT_FILE_MAX_BYTES: u64 = 1024 * 1024;
const TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const TREE_MAX_ENTRIES: usize = 8192;
// Darwin fcntl.h: prevents following a final-component symlink during the actual open.
const O_NOFOLLOW: i32 = 0x100;
// A raced FIFO must not block before the opened-file type check below.
const O_NONBLOCK: i32 = 0x4;

/// Stable launcher failures. No resource path, release payload, URL, signer or secret is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DesktopReleaseError {
    /// The reviewed core build did not supply a valid outer manifest binding.
    #[error("wrok_bot_release_trust_missing_or_invalid")]
    Trust,
    /// The resource bytes do not match the reviewed core's outer manifest binding.
    #[error("wrok_bot_release_digest_mismatch")]
    Digest,
    /// Closed schema, product, version, platform or resource metadata is invalid.
    #[error("wrok_bot_release_manifest_invalid")]
    Manifest,
    /// A file is missing, unbounded, linked, changed or outside the exact resource inventory.
    #[error("wrok_bot_release_resource_invalid")]
    Resource,
    /// The existing PostgreSQL bundle verifier rejected the release inputs.
    #[error("wrok_bot_release_postgres_invalid")]
    Postgres,
    /// The first-party package is not a valid installation-bound template.
    #[error("wrok_bot_release_tenant_invalid")]
    Tenant,
    /// The existing provider/budget/host configuration rejected the release inputs.
    #[error("wrok_bot_release_application_invalid")]
    Application,
    /// The compiled Tauri context differs from the reviewed product configuration.
    #[error("wrok_bot_release_context_invalid")]
    Context,
}

/// An opaque expected digest provided by reviewed build metadata, never inferred from disk.
#[derive(Clone, Copy)]
pub struct TrustedDesktopReleaseDigest([u8; 32]);

impl TrustedDesktopReleaseDigest {
    /// Decode the outer manifest hash supplied to the core build by the release process.
    pub fn from_reviewed_build(value: Option<&str>) -> Result<Self, DesktopReleaseError> {
        value
            .and_then(decode_digest)
            .map(Self)
            .ok_or(DesktopReleaseError::Trust)
    }
}

impl core::fmt::Debug for TrustedDesktopReleaseDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TrustedDesktopReleaseDigest(<reviewed-build-binding>)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema: String,
    schema_version: u32,
    product_name: String,
    bundle_identifier: String,
    scheme: String,
    window_label: String,
    core_version: String,
    release_epoch: u64,
    platform: String,
    arch: String,
    ui: ResourceTree,
    tenant: ResourceTree,
    postgres: PostgresResource,
    vault_key_store_service: String,
    provider: ProviderInput,
    agent_budgets: AgentBudgets,
    #[serde(default)]
    normal_capture: CaptureField,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceTree {
    root: String,
    files: Vec<ResourceFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceFile {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresResource {
    root: String,
    manifest_sha256: String,
    signing_identity: String,
    key_store_service: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderInput {
    base_url: String,
    egress_allow_cidrs: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentBudgets {
    stall_timeout_ms: Option<u64>,
    run_deadline_ms: Option<u64>,
    max_output_tokens: u32,
}

impl ReleaseManifest {
    fn parse(bytes: &[u8]) -> Result<Self, DesktopReleaseError> {
        if bytes.len() as u64 > MANIFEST_MAX_BYTES {
            return Err(DesktopReleaseError::Manifest);
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|_| DesktopReleaseError::Manifest)?;
        if manifest.schema != "wrok-bot-desktop-release"
            || !matches!(
                (&manifest.schema_version, &manifest.normal_capture),
                (1, CaptureField::Missing) | (2, CaptureField::Null | CaptureField::Request(_))
            )
            || manifest.product_name != PRODUCT_NAME
            || manifest.bundle_identifier != BUNDLE_IDENTIFIER
            || manifest.scheme != PROTOCOL_SCHEME
            || manifest.window_label != MAIN_WINDOW
            || manifest.core_version != env!("CARGO_PKG_VERSION")
            || manifest.release_epoch != ENGINE_RELEASE_EPOCH
            || manifest.platform != "macos"
            || manifest.arch != std::env::consts::ARCH
            || manifest.ui.root != "ui"
            || manifest.tenant.root != "tenant"
            || manifest.postgres.root != "postgres"
            || manifest.postgres.key_store_service != POSTGRES_KEY_STORE_SERVICE
            || manifest.vault_key_store_service != VAULT_KEY_STORE_SERVICE
            || decode_digest(&manifest.postgres.manifest_sha256).is_none()
        {
            return Err(DesktopReleaseError::Manifest);
        }
        if let CaptureField::Request(request) = &manifest.normal_capture {
            request.validate()?;
        }
        manifest.ui.inventory(static_asset_max_bytes)?;
        let tenant_inventory = manifest.tenant.inventory(|_| TENANT_FILE_MAX_BYTES)?;
        if tenant_inventory.keys().copied().collect::<BTreeSet<_>>()
            != TENANT_PACKAGE_FILENAMES.into_iter().collect()
            || !manifest
                .ui
                .files
                .iter()
                .any(|file| file.path == "index.html")
            || !manifest
                .ui
                .files
                .iter()
                .any(|file| file.path == "openbot-bootstrap.mjs")
        {
            return Err(DesktopReleaseError::Manifest);
        }
        ReviewedPostgresSigningIdentity::from_reviewed_release(
            manifest.postgres.signing_identity.clone(),
        )
        .map_err(|_| DesktopReleaseError::Postgres)?;
        manifest.application_input()?;
        Ok(manifest)
    }

    fn application_input(&self) -> Result<DesktopLocalApplicationInput, DesktopReleaseError> {
        if self.provider.base_url.len() > 2048 || self.provider.egress_allow_cidrs.len() > 128 {
            return Err(DesktopReleaseError::Application);
        }
        let provider = DesktopOpenAiProviderInput::new(
            &self.provider.base_url,
            self.provider.egress_allow_cidrs.clone(),
        )
        .map_err(|_| DesktopReleaseError::Application)?;
        let budgets = DesktopAgentBudgets::new(
            self.agent_budgets
                .stall_timeout_ms
                .map(Duration::from_millis),
            self.agent_budgets
                .run_deadline_ms
                .map(Duration::from_millis),
            self.agent_budgets.max_output_tokens,
        )
        .map_err(|_| DesktopReleaseError::Application)?;
        DesktopLocalApplicationInput::new(provider, budgets)
            .map_err(|_| DesktopReleaseError::Application)
    }
}

impl ResourceTree {
    fn inventory(
        &self,
        file_limit: impl Fn(&str) -> u64,
    ) -> Result<BTreeMap<&str, &ResourceFile>, DesktopReleaseError> {
        if self.files.is_empty() || self.files.len() > TREE_MAX_ENTRIES {
            return Err(DesktopReleaseError::Manifest);
        }
        let mut names = BTreeSet::new();
        let mut inventory = BTreeMap::new();
        let mut total = 0_u64;
        for file in &self.files {
            if !valid_relative_path(&file.path)
                || file.bytes > file_limit(&file.path)
                || decode_digest(&file.sha256).is_none()
                || !names.insert(file.path.to_ascii_lowercase())
            {
                return Err(DesktopReleaseError::Manifest);
            }
            total = total
                .checked_add(file.bytes)
                .ok_or(DesktopReleaseError::Manifest)?;
            if total > TREE_MAX_BYTES {
                return Err(DesktopReleaseError::Manifest);
            }
            inventory.insert(file.path.as_str(), file);
        }
        Ok(inventory)
    }
}

/// All release resources verified without opening Keychain, creating app data, or spawning a child.
/// It contains only release-owned files; installation identity is supplied later by the existing
/// Desktop Local authority. The type deliberately exposes no raw path or signer accessor.
pub struct VerifiedDesktopRelease {
    ui: VerifiedUiAssets,
    postgres: VerifiedPostgresBundle,
    application: DesktopLocalApplicationInput,
    tenant: VerifiedTenantTemplate,
    capture: Option<ReviewedNormalCaptureRequest>,
}

impl core::fmt::Debug for VerifiedDesktopRelease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedDesktopRelease(<verified-release-resources>)")
    }
}

impl VerifiedDesktopRelease {
    /// Verify the outer trust binding first, then both exact resource inventories and the existing
    /// PostgreSQL release contract. `root` must be an absolute canonical directory with no symlink.
    pub fn open(
        root: &Path,
        expected: TrustedDesktopReleaseDigest,
    ) -> Result<Self, DesktopReleaseError> {
        if !root.is_absolute()
            || fs::canonicalize(root).map_err(|_| DesktopReleaseError::Resource)? != root
        {
            return Err(DesktopReleaseError::Resource);
        }
        require_directory(root)?;
        let bytes = read_file(&root.join(RELEASE_MANIFEST_FILE), MANIFEST_MAX_BYTES)?;
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != expected.0 {
            return Err(DesktopReleaseError::Digest);
        }
        let manifest = ReleaseManifest::parse(&bytes)?;
        let application = manifest.application_input()?;
        let mut capture = match manifest.normal_capture {
            CaptureField::Request(request) => Some(request.verify(root, expected.0)?),
            CaptureField::Missing | CaptureField::Null => None,
        };
        let ui_files = verify_tree(root, &manifest.ui, static_asset_max_bytes)?;
        let ui = VerifiedUiAssets::from_verified_release(ui_files)
            .map_err(|_| DesktopReleaseError::Resource)?;
        let tenant_files = verify_tree(root, &manifest.tenant, |_| TENANT_FILE_MAX_BYTES)?;
        let tenant = VerifiedTenantTemplate::new(root.join(&manifest.tenant.root), tenant_files)?;
        let signer = ReviewedPostgresSigningIdentity::from_reviewed_release(
            manifest.postgres.signing_identity,
        )
        .map_err(|_| DesktopReleaseError::Postgres)?;
        let expected_pg = PostgresBundleDigest::from_hex(&manifest.postgres.manifest_sha256)
            .map_err(|_| DesktopReleaseError::Postgres)?;
        let postgres =
            VerifiedPostgresBundle::open(root.join(&manifest.postgres.root), expected_pg, &signer)
                .map_err(|_error| {
                    #[cfg(debug_assertions)]
                    if capture.is_some() {
                        use crate::postgres_sidecar::PostgresSidecarError;
                        let code = match &_error {
                            PostgresSidecarError::Io(_) => "postgres_sidecar_io",
                            PostgresSidecarError::ManifestDigest => "postgres_sidecar_manifest_digest",
                            PostgresSidecarError::BundleShape => "postgres_sidecar_bundle_shape",
                            PostgresSidecarError::FileDigest => "postgres_sidecar_file_digest",
                            _ => "wrok_bot_release_postgres_invalid",
                        };
                        eprintln!("{code}");
                    }
                    DesktopReleaseError::Postgres
                })?;
        // Only these already verified release inputs are sealed. The original maintenance
        // verify/FD/error order above is unchanged; nothing is published while DATA is absent.
        if let Some(capture) = capture.as_mut() {
            capture.bind_original_release_compatibility(
                (
                    manifest.schema_version,
                    manifest.core_version,
                    manifest.release_epoch,
                    manifest.platform,
                    manifest.arch,
                ),
                (manifest.ui, manifest.tenant),
                (
                    manifest.postgres.root,
                    manifest.postgres.manifest_sha256,
                    manifest.postgres.key_store_service,
                ),
                manifest.agent_budgets,
            )?;
        }
        Ok(Self {
            ui,
            postgres,
            application,
            tenant,
            capture,
        })
    }

    /// Reuse the existing authority → real PG/SCRAM → current PG actor → OS Vault → Agent → window
    /// assembly. The lazy real Keychain adapter is first touched by that background assembly.
    pub fn into_runtime_config(self) -> Result<DesktopLocalRuntimeConfig, DesktopReleaseError> {
        let fixture = crate::tauri_background::bind_self_owned_capture_fixture(self.capture.as_ref())
            .map_err(|_| DesktopReleaseError::Application)?;
        let (fixture_binding, secret_store): (_, Arc<dyn OsSecretStore>) = match fixture {
            Some((binding, store)) => (Some(binding), store),
            None => (None, Arc::new(DeferredCurrentUserKeychain::default())),
        };
        let pg_service = ReviewedPostgresKeyStoreService::from_reviewed_release(
            POSTGRES_KEY_STORE_SERVICE.to_owned(),
        )
        .map_err(|_| DesktopReleaseError::Application)?;
        let vault_service = ReviewedDesktopVaultKeyStoreService::from_reviewed_release(
            VAULT_KEY_STORE_SERVICE.to_owned(),
        )
        .map_err(|_| DesktopReleaseError::Application)?;
        let release = DesktopLocalReleaseInput::new_with_ui(
            DesktopUiResource::Verified(self.ui),
            PROTOCOL_SCHEME,
            MAIN_WINDOW,
            self.postgres,
            pg_service,
            vault_service,
            secret_store,
        )
        .map_err(|_| DesktopReleaseError::Application)?;
        let tenant = self.tenant;
        let runtime = DesktopLocalRuntimeConfig::new(release, self.application, move |authority| {
            tenant.bind(authority.auth_context().tenant().as_str())
        }).with_reviewed_normal_capture(self.capture);
        Ok(match fixture_binding {
            Some(binding) => runtime.with_self_owned_capture_fixture(binding),
            None => runtime,
        })
    }
}

struct VerifiedTenantTemplate {
    source: String,
    contents: [String; 5],
}

impl VerifiedTenantTemplate {
    fn new(
        source: PathBuf,
        mut files: BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, DesktopReleaseError> {
        let mut contents = Vec::with_capacity(5);
        for filename in TENANT_PACKAGE_FILENAMES {
            contents.push(
                String::from_utf8(files.remove(filename).ok_or(DesktopReleaseError::Tenant)?)
                    .map_err(|_| DesktopReleaseError::Tenant)?,
            );
        }
        if contents[0] != INSTANCE_BRAND_TEMPLATE
            || contents[1..].iter().any(|text| text.contains("${"))
        {
            return Err(DesktopReleaseError::Tenant);
        }
        // Validate the template as text, without inventing a runtime actor or installation tenant.
        // The placeholder is never used for authority and is replaced before synchronization.
        validate_tenant_package(TenantPackageFiles {
            brand: contents[0].clone(),
            agents: contents[1].clone(),
            channels: contents[2].clone(),
            model: contents[3].clone(),
            knowledge: contents[4].clone(),
        })
        .map_err(|_| DesktopReleaseError::Tenant)?;
        Ok(Self {
            source: source
                .to_str()
                .ok_or(DesktopReleaseError::Tenant)?
                .to_owned(),
            contents: contents
                .try_into()
                .map_err(|_| DesktopReleaseError::Tenant)?,
        })
    }

    fn bind(mut self, tenant: &str) -> Result<LoadedTenantPackage, TenantPackageError> {
        // The only value comes from the installation authority. JSON string encoding is also a
        // valid YAML quoted scalar, and prevents changing the shape of the brand document.
        let quoted =
            serde_json::to_string(tenant).map_err(|_| TenantPackageError::LoadedMetadataInvalid)?;
        self.contents[0] = format!("tenant:\n  id: {quoted}\n  product_name: Wrok Bot\n");
        let mut hash = Sha256::new();
        for (index, content) in self.contents.iter().enumerate() {
            if index > 0 {
                hash.update(b"\n");
            }
            hash.update(content.as_bytes());
        }
        let [brand, agents, channels, model, knowledge] = self.contents;
        let package = validate_tenant_package(TenantPackageFiles {
            brand,
            agents,
            channels,
            model,
            knowledge,
        })?;
        if package.tenant_id != tenant || package.product_name != PRODUCT_NAME {
            return Err(TenantPackageError::LoadedMetadataInvalid);
        }
        LoadedTenantPackage::new(package, self.source, format!("{:x}", hash.finalize()))
    }
}

#[derive(Default)]
struct DeferredCurrentUserKeychain {
    store: OnceLock<Result<MacOsKeychainSecretStore, OsSecretStoreError>>,
}

impl DeferredCurrentUserKeychain {
    fn store(&self) -> Result<&MacOsKeychainSecretStore, OsSecretStoreError> {
        self.store
            .get_or_init(MacOsKeychainSecretStore::current_user_default)
            .as_ref()
            .map_err(|error| *error)
    }
}

impl OsSecretStore for DeferredCurrentUserKeychain {
    fn read(
        &self,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretBytes>, OsSecretStoreError> {
        self.store()?.read(service, account)
    }
    fn write(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), OsSecretStoreError> {
        self.store()?.write(service, account, secret)
    }
}

/// Reject context changes before registration, app-data resolution, or native window construction.
pub fn validate_product_context(
    context: &tauri::Context<tauri::Wry>,
) -> Result<(), DesktopReleaseError> {
    let mut approved: tauri::Config = serde_json::from_str(include_str!("../tauri.conf.json"))
        .map_err(|_| DesktopReleaseError::Context)?;
    // Locked tauri-utils Config::to_tokens intentionally omits the editor-only $schema field.
    approved.schema = None;
    if context.config() != &approved
        || context.package_info().name != PRODUCT_NAME
        || context.package_info().version.to_string() != env!("CARGO_PKG_VERSION")
    {
        return Err(DesktopReleaseError::Context);
    }
    Ok(())
}

fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn valid_relative_path(value: &str) -> bool {
    value.len() <= 512
        && !value.is_empty()
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

fn require_directory(path: &Path) -> Result<(), DesktopReleaseError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DesktopReleaseError::Resource)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DesktopReleaseError::Resource);
    }
    Ok(())
}

fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, DesktopReleaseError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DesktopReleaseError::Resource)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DesktopReleaseError::Resource);
    }
    let file: File = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)
        .map_err(|_| DesktopReleaseError::Resource)?;
    let before = file.metadata().map_err(|_| DesktopReleaseError::Resource)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(DesktopReleaseError::Resource);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DesktopReleaseError::Resource)?;
    if bytes.len() as u64 != before.len() || bytes.len() as u64 > limit {
        return Err(DesktopReleaseError::Resource);
    }
    Ok(bytes)
}

fn verify_tree(
    root: &Path,
    tree: &ResourceTree,
    limit: impl Fn(&str) -> u64,
) -> Result<BTreeMap<String, Vec<u8>>, DesktopReleaseError> {
    let root = root.join(&tree.root);
    require_directory(&root)?;
    let inventory = tree.inventory(&limit)?;
    let mut pending = vec![root.clone()];
    let mut actual = BTreeMap::new();
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|_| DesktopReleaseError::Resource)? {
            visited += 1;
            if visited > TREE_MAX_ENTRIES {
                return Err(DesktopReleaseError::Resource);
            }
            let path = entry.map_err(|_| DesktopReleaseError::Resource)?.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| DesktopReleaseError::Resource)?;
            let relative = path
                .strip_prefix(&root)
                .ok()
                .and_then(Path::to_str)
                .ok_or(DesktopReleaseError::Resource)?;
            if !valid_relative_path(relative) || metadata.file_type().is_symlink() {
                return Err(DesktopReleaseError::Resource);
            }
            if metadata.is_dir() {
                // Empty or undeclared directory trees are not part of the closed inventory.
                if !inventory
                    .keys()
                    .any(|file| file.starts_with(&format!("{relative}/")))
                {
                    return Err(DesktopReleaseError::Resource);
                }
                pending.push(path);
            } else {
                let expected = inventory
                    .get(relative)
                    .ok_or(DesktopReleaseError::Resource)?;
                let bytes = read_file(&path, limit(relative))?;
                if bytes.len() as u64 != expected.bytes
                    || <[u8; 32]>::from(Sha256::digest(&bytes))
                        != decode_digest(&expected.sha256).ok_or(DesktopReleaseError::Manifest)?
                {
                    return Err(DesktopReleaseError::Resource);
                }
                actual.insert(relative.to_owned(), bytes);
            }
        }
    }
    if actual.len() != inventory.len() {
        return Err(DesktopReleaseError::Resource);
    }
    Ok(actual)
}

#[cfg(test)]
pub(crate) fn verified_ui_snapshot_for_test(root: &Path, inventory: &[u8]) -> VerifiedUiAssets {
    let tree: ResourceTree = serde_json::from_slice(inventory).unwrap();
    assert_eq!(tree.root, root.file_name().unwrap().to_str().unwrap());
    let files = verify_tree(root.parent().unwrap(), &tree, static_asset_max_bytes).unwrap();
    VerifiedUiAssets::from_verified_release(files).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    const VALID_INDEX: &str = "<!doctype html><html lang=\"en\"><head><script type=\"module\" src=\"/openbot-bootstrap.mjs\"></script></head><body></body></html>";
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "wrok-bot-release-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn tenant_texts() -> [&'static str; 5] {
        [
            INSTANCE_BRAND_TEMPLATE,
            include_str!("../../../examples/wrok-bot/agents.yaml"),
            include_str!("../../../examples/wrok-bot/channels.yaml"),
            include_str!("../../../examples/wrok-bot/model.yaml"),
            include_str!("../../../examples/wrok-bot/knowledge.yaml"),
        ]
    }
    fn file(path: &str, bytes: &[u8]) -> Value {
        json!({"path":path, "bytes":bytes.len(), "sha256":format!("{:x}", Sha256::digest(bytes))})
    }
    fn fixture() -> Value {
        json!({
            "schema":"wrok-bot-desktop-release", "schema_version":1,
            "product_name":PRODUCT_NAME, "bundle_identifier":BUNDLE_IDENTIFIER,
            "scheme":PROTOCOL_SCHEME, "window_label":MAIN_WINDOW,
            "core_version":env!("CARGO_PKG_VERSION"), "release_epoch":ENGINE_RELEASE_EPOCH,
            "platform":"macos", "arch":std::env::consts::ARCH,
            "ui":{"root":"ui","files":[file("index.html",VALID_INDEX.as_bytes()),file("openbot-bootstrap.mjs",b"export {};")]},
            "tenant":{"root":"tenant","files":TENANT_PACKAGE_FILENAMES.into_iter().zip(tenant_texts()).map(|(path, text)| file(path,text.as_bytes())).collect::<Vec<_>>()},
            // A parser fixture only. There are no executable PG bytes, and the product verifier
            // must reject it. It is never used as a native signing identity or startup fallback.
            "postgres":{"root":"postgres","manifest_sha256":"a".repeat(64),"signing_identity":"unit-parser-only","key_store_service":POSTGRES_KEY_STORE_SERVICE},
            "vault_key_store_service":VAULT_KEY_STORE_SERVICE,
            "provider":{"base_url":"https://api.example.invalid/v1/","egress_allow_cidrs":[]},
            "agent_budgets":{"stall_timeout_ms":30000,"run_deadline_ms":300000,"max_output_tokens":4096}
        })
    }
    fn parse(value: &Value) -> Result<ReleaseManifest, DesktopReleaseError> {
        ReleaseManifest::parse(&serde_json::to_vec(value).unwrap())
    }
    fn write_fixture(root: &Path) -> TrustedDesktopReleaseDigest {
        fs::create_dir(root.join("ui")).unwrap();
        fs::create_dir(root.join("tenant")).unwrap();
        fs::write(root.join("ui/index.html"), VALID_INDEX.as_bytes()).unwrap();
        fs::write(root.join("ui/openbot-bootstrap.mjs"), b"export {};").unwrap();
        for (filename, text) in TENANT_PACKAGE_FILENAMES.into_iter().zip(tenant_texts()) {
            fs::write(root.join("tenant").join(filename), text).unwrap();
        }
        let bytes = serde_json::to_vec(&fixture()).unwrap();
        fs::write(root.join(RELEASE_MANIFEST_FILE), &bytes).unwrap();
        // Tests deliberately create their own fixture trust anchor; the product binary only
        // accepts its compile-time reviewed value and has no such self-hash fallback.
        TrustedDesktopReleaseDigest(Sha256::digest(bytes).into())
    }

    #[test]
    fn manifest_requires_exact_product_platform_epoch_and_no_unknown_fields() {
        assert!(parse(&fixture()).is_ok());
        for key in [
            "product_name",
            "bundle_identifier",
            "scheme",
            "window_label",
            "core_version",
            "platform",
            "arch",
            "vault_key_store_service",
        ] {
            let mut value = fixture();
            value[key] = json!("wrong");
            assert!(parse(&value).is_err(), "{key}");
        }
        for key in ["schema_version", "release_epoch"] {
            let mut value = fixture();
            value[key] = json!(0);
            assert!(parse(&value).is_err());
        }
        for pointer in [
            "",
            "/provider",
            "/agent_budgets",
            "/postgres",
            "/ui",
            "/ui/files/0",
        ] {
            let mut value = fixture();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("secret".into(), json!("never-echo-me"));
            let error = parse(&value).err().unwrap();
            assert!(!format!("{error:?} {error}").contains("never-echo-me"));
        }
    }

    #[test]
    fn manifest_rejects_path_aliases_duplicate_inventory_and_bad_hashes() {
        for path in [
            "../index.html",
            "/index.html",
            "a//b",
            "a/./b",
            "a\\b",
            "a/../../b",
            "a\0b",
        ] {
            assert!(!valid_relative_path(path));
        }
        for path in ["../ui", "UI", "/ui"] {
            let mut value = fixture();
            value["ui"]["root"] = json!(path);
            assert!(parse(&value).is_err());
        }
        let mut value = fixture();
        let mut duplicate = value["ui"]["files"][0].clone();
        duplicate["path"] = json!("INDEX.html");
        value["ui"]["files"].as_array_mut().unwrap().push(duplicate);
        assert!(parse(&value).is_err());
        for digest in ["A".repeat(64), "0".repeat(63), "g".repeat(64)] {
            let mut value = fixture();
            value["ui"]["files"][0]["sha256"] = json!(digest);
            assert!(parse(&value).is_err());
        }
        let mut value = fixture();
        value["ui"]["files"][0]["bytes"] = json!(static_asset_max_bytes("index.html") + 1);
        assert!(parse(&value).is_err());
        assert!(ReleaseManifest::parse(&vec![b' '; MANIFEST_MAX_BYTES as usize + 1]).is_err());
    }

    #[test]
    fn provider_and_budget_validation_reuses_existing_closed_inputs() {
        for endpoint in [
            "http://example.invalid/",
            "https://u:p@example.invalid/",
            "https://example.invalid/?secret=x",
            "https://example.invalid/#x",
        ] {
            let mut value = fixture();
            value["provider"]["base_url"] = json!(endpoint);
            assert!(parse(&value).is_err());
        }
        let mut value = fixture();
        value["provider"]["egress_allow_cidrs"] = json!(["not-a-cidr"]);
        assert!(parse(&value).is_err());
        for key in ["stall_timeout_ms", "run_deadline_ms", "max_output_tokens"] {
            let mut value = fixture();
            value["agent_budgets"][key] = json!(0);
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn build_trust_is_required_and_digest_precedes_json_or_postgres() {
        assert_eq!(
            TrustedDesktopReleaseDigest::from_reviewed_build(None).err(),
            Some(DesktopReleaseError::Trust)
        );
        assert_eq!(
            TrustedDesktopReleaseDigest::from_reviewed_build(Some("bad")).err(),
            Some(DesktopReleaseError::Trust)
        );
        let root = TempRoot::new();
        fs::write(root.0.join(RELEASE_MANIFEST_FILE), b"not JSON").unwrap();
        assert_eq!(
            VerifiedDesktopRelease::open(&root.0, TrustedDesktopReleaseDigest([0; 32])).err(),
            Some(DesktopReleaseError::Digest)
        );
    }

    #[test]
    fn full_preflight_refuses_missing_trusted_postgres_without_touching_os_store() {
        let root = TempRoot::new();
        let expected = write_fixture(&root.0);
        assert_eq!(
            VerifiedDesktopRelease::open(&root.0, expected).err(),
            Some(DesktopReleaseError::Postgres)
        );
        assert!(!root.0.join("postgres").exists());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 3);
        assert!(DeferredCurrentUserKeychain::default().store.get().is_none());
    }

    #[test]
    fn resource_tamper_extra_missing_and_empty_subtree_are_rejected() {
        for case in 0..4 {
            let root = TempRoot::new();
            let expected = write_fixture(&root.0);
            match case {
                0 => fs::write(root.0.join("ui/index.html"), "tampered").unwrap(),
                1 => fs::write(root.0.join("ui/unreviewed.js"), "unexpected").unwrap(),
                2 => fs::remove_file(root.0.join("ui/index.html")).unwrap(),
                _ => fs::create_dir(root.0.join("ui/undeclared")).unwrap(),
            }
            assert_eq!(
                VerifiedDesktopRelease::open(&root.0, expected).err(),
                Some(DesktopReleaseError::Resource)
            );
        }
    }

    #[test]
    fn symlinks_and_hardlinks_cannot_be_release_resources() {
        let root = TempRoot::new();
        let expected = write_fixture(&root.0);
        let original = root.0.join("ui/index.html");
        let target = root.0.join("original.html");
        fs::rename(&original, &target).unwrap();
        symlink(&target, &original).unwrap();
        assert_eq!(
            VerifiedDesktopRelease::open(&root.0, expected).err(),
            Some(DesktopReleaseError::Resource)
        );
        fs::remove_file(&original).unwrap();
        fs::hard_link(&target, &original).unwrap();
        assert_eq!(
            VerifiedDesktopRelease::open(&root.0, expected).err(),
            Some(DesktopReleaseError::Resource)
        );
        fs::remove_file(&original).unwrap();
        fs::rename(&target, &original).unwrap();
        fs::rename(root.0.join("ui"), root.0.join("ui-original")).unwrap();
        symlink(root.0.join("ui-original"), root.0.join("ui")).unwrap();
        assert_eq!(
            VerifiedDesktopRelease::open(&root.0, expected).err(),
            Some(DesktopReleaseError::Resource)
        );
    }

    fn template() -> VerifiedTenantTemplate {
        VerifiedTenantTemplate::new(
            PathBuf::from("/reviewed/tenant"),
            TENANT_PACKAGE_FILENAMES
                .into_iter()
                .zip(tenant_texts())
                .map(|(name, text)| (name.to_owned(), text.as_bytes().to_vec()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn tenant_binding_recomputes_checksum_and_never_reuses_template_tenant() {
        let first = template().bind("desktop-local-unit-first").unwrap();
        let other = template().bind("desktop-local-unit-second").unwrap();
        assert_eq!(first.package.tenant_id, "desktop-local-unit-first");
        assert_eq!(other.package.tenant_id, "desktop-local-unit-second");
        assert_ne!(first.checksum, other.checksum);
        let mut expected = Sha256::new();
        for (index, text) in tenant_texts().into_iter().enumerate() {
            if index > 0 {
                expected.update(b"\n");
            }
            if index == 0 {
                expected.update(
                    b"tenant:\n  id: \"desktop-local-unit-first\"\n  product_name: Wrok Bot\n",
                );
            } else {
                expected.update(text.as_bytes());
            }
        }
        assert_eq!(first.checksum, format!("{:x}", expected.finalize()));
    }

    #[test]
    fn template_rejects_fixed_tenant_or_parent_environment_expansion() {
        for (index, replacement) in [
            (0, "tenant:\n  id: fixed\n  product_name: Wrok Bot\n"),
            (3, "${PARENT_API_KEY}"),
        ] {
            let mut files: BTreeMap<_, _> = TENANT_PACKAGE_FILENAMES
                .into_iter()
                .zip(tenant_texts())
                .map(|(name, text)| (name.to_owned(), text.as_bytes().to_vec()))
                .collect();
            files.insert(
                TENANT_PACKAGE_FILENAMES[index].into(),
                replacement.as_bytes().to_vec(),
            );
            assert!(VerifiedTenantTemplate::new(PathBuf::from("/reviewed/tenant"), files).is_err());
        }
    }

    #[test]
    fn product_acl_is_exactly_three_local_commands_and_no_precreated_windows() {
        let config: Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["productName"], PRODUCT_NAME);
        assert_eq!(config["identifier"], BUNDLE_IDENTIFIER);
        assert_eq!(config["app"]["windows"], json!([]));
        assert_eq!(config["app"]["withGlobalTauri"], false);
        assert!(config.pointer("/build/devUrl").is_none());
        assert_eq!(
            config["app"]["security"]["capabilities"],
            json!(["desktop-main"])
        );
        let capability: Value =
            serde_json::from_str(include_str!("../capabilities/desktop-main.json")).unwrap();
        assert_eq!(capability["local"], true);
        assert_eq!(capability["windows"], json!(["main"]));
        assert!(capability.get("remote").is_none());
        assert_eq!(
            capability["permissions"],
            json!([
                "allow-openbot-structured-events-open",
                "allow-openbot-structured-events-close",
                "allow-wrok-bot-window-chrome"
            ])
        );
    }
}
