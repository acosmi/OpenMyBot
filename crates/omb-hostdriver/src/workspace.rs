//! Workspace roots, validated once at the configuration boundary.
use std::path::{Path, PathBuf};

/// Real paths of the configured roots: each a proper subdirectory of the owner's home outside
/// `$HOME/Library`.
#[derive(Clone, Debug)]
pub struct WorkspaceRoots(Vec<PathBuf>);
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceRootError {
    #[error("workspace_root_invalid")]
    Invalid,
}
impl WorkspaceRoots {
    pub fn parse(home: &Path, roots: &[PathBuf]) -> Result<Self, WorkspaceRootError> {
        let home = std::fs::canonicalize(home).map_err(|_| WorkspaceRootError::Invalid)?;
        let library = home.join("Library");
        roots
            .iter()
            .map(|root| {
                if !root.is_absolute() {
                    return Err(WorkspaceRootError::Invalid);
                }
                let real = std::fs::canonicalize(root).map_err(|_| WorkspaceRootError::Invalid)?;
                if real == home || !real.starts_with(&home) || real.starts_with(&library) {
                    return Err(WorkspaceRootError::Invalid);
                }
                Ok(real)
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
    /// The workspace's real path when it equals or lies inside a root, compared by components.
    pub fn resolve(&self, workspace: &Path) -> Option<PathBuf> {
        let real = std::fs::canonicalize(workspace).ok()?;
        self.0
            .iter()
            .any(|root| real.starts_with(root))
            .then_some(real)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fresh directory under the system temporary directory; the caller removes it.
    pub(crate) fn temp(name: &str) -> PathBuf {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).unwrap();
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("omb-hd-{name}-{suffix}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn roots_must_be_true_subdirectories_of_home_outside_library() {
        let home = temp("home");
        let outside = temp("outside");
        std::fs::create_dir_all(home.join("Library/Projects")).unwrap();
        std::fs::create_dir_all(home.join("code/a")).unwrap();
        let parsed =
            WorkspaceRoots::parse(&home, &[home.join("code"), home.join("code/a")]).unwrap();
        assert_eq!(parsed.0.len(), 2);
        assert!(WorkspaceRoots::parse(&home, &[]).unwrap().0.is_empty());
        for root in [
            home.clone(),
            outside.clone(),
            home.join("Library"),
            home.join("Library/Projects"),
            PathBuf::from("code"),
            home.join("missing"),
        ] {
            assert_eq!(
                WorkspaceRoots::parse(&home, &[home.join("code"), root.clone()]).unwrap_err(),
                WorkspaceRootError::Invalid,
                "{}",
                root.display()
            );
        }
        std::fs::remove_dir_all(home).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn symlink_root_is_stored_by_realpath_and_symlink_into_library_is_refused() {
        let home = temp("home");
        std::fs::create_dir_all(home.join("code")).unwrap();
        std::fs::create_dir_all(home.join("Library/Data")).unwrap();
        std::os::unix::fs::symlink(home.join("code"), home.join("link")).unwrap();
        std::os::unix::fs::symlink(home.join("Library/Data"), home.join("sneaky")).unwrap();
        let parsed = WorkspaceRoots::parse(&home, &[home.join("link")]).unwrap();
        let real = std::fs::canonicalize(home.join("code")).unwrap();
        assert_eq!(parsed.0, vec![real.clone()]);
        // The temporary directory itself sits behind a symlink on macOS (/var -> /private/var).
        assert_ne!(home, std::fs::canonicalize(&home).unwrap());
        assert!(real.starts_with(std::fs::canonicalize(&home).unwrap()));
        assert_eq!(
            WorkspaceRoots::parse(&home, &[home.join("sneaky")]).unwrap_err(),
            WorkspaceRootError::Invalid
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn resolve_uses_realpath_by_components() {
        let home = temp("home");
        let outside = temp("outside");
        for dir in ["a/b", "a/bc", "a/b/deep"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(&outside, home.join("a/b/escape")).unwrap();
        let roots = WorkspaceRoots::parse(&home, &[home.join("a/b")]).unwrap();
        let real = std::fs::canonicalize(home.join("a/b")).unwrap();
        assert_eq!(roots.resolve(&home.join("a/b")), Some(real.clone()));
        assert_eq!(
            roots.resolve(&home.join("a/b/deep")),
            Some(real.join("deep"))
        );
        assert_eq!(roots.resolve(&home.join("a/bc")), None);
        assert_eq!(roots.resolve(&home.join("a/b/escape")), None);
        assert_eq!(roots.resolve(&home.join("a/b/../bc")), None);
        assert_eq!(roots.resolve(&home.join("a/b/missing")), None);
        std::fs::remove_dir_all(home).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
