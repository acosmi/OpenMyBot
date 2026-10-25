use crate::{DaemonError, config};
use openbot_application::tenant::package::{LoadedTenantPackage, TenantPackageEnvironment};
use openbot_infra::tenant::load_tenant_package;
use std::path::Path;

// These five inputs describe composition only. There is no callable model or runtime entry.
const AGENTS: &str = "agents: []\n";
const CHANNELS: &str = "channels: []\n";
const MODEL: &str = "model:\n  provider: openai\n  default_model: omb-unconfigured\n  credential_secret_ref: omb-unconfigured\n";
const KNOWLEDGE: &str = "sources: []\n";

pub(crate) fn write_and_load(
    root: &Path,
    deployment: &str,
) -> Result<LoadedTenantPackage, DaemonError> {
    let brand = format!("tenant:\n  id: {deployment}\n  product_name: OpenMyBot\n");
    for (name, text) in [
        ("brand.yaml", brand.as_str()),
        ("agents.yaml", AGENTS),
        ("channels.yaml", CHANNELS),
        ("model.yaml", MODEL),
        ("knowledge.yaml", KNOWLEDGE),
    ] {
        let path = root.join("tenant").join(name);
        let create_new = match std::fs::symlink_metadata(&path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => return Err(DaemonError::TenantPackageFailed),
        };
        config::write_private(&path, text.as_bytes(), create_new)
            .map_err(|_| DaemonError::TenantPackageFailed)?;
    }
    load_tenant_package(
        &root.join("tenant"),
        &TenantPackageEnvironment::from_explicit([]),
    )
    .map_err(|_| DaemonError::TenantPackageFailed)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn embedded_package_has_empty_runtime_entries_and_valid_scope() {
        let root = config::test_dir();
        config::make_dir(&root.join("tenant")).unwrap();
        let id = "omb-local-0123456789abcdef0123456789abcdef";
        let loaded = write_and_load(&root, id).unwrap();
        assert_eq!(loaded.package.tenant_id, id);
        assert!(loaded.package.agents.is_empty());
        assert!(loaded.package.channels.is_empty());
        assert!(loaded.package.knowledge_sources.is_empty());
        assert!(!loaded.package.model.default_model.is_empty());
        assert!(!loaded.package.model.credential_secret_ref.is_empty());
        assert_eq!(std::fs::read_dir(root.join("tenant")).unwrap().count(), 5);
        std::fs::remove_dir_all(root).unwrap();
    }
}
