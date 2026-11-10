//! An observation bound to the live startup owner and its exact private data directory.
//! This is not the complete durable initialization or recovery protocol.

use super::{
    PostgresSidecarError, PostgresSidecarOrigin, PostgresStartLock, data_directory_origin,
    validate_supervisor_paths,
};
use std::path::{Path, PathBuf};

/// Directory state scoped to one borrowed startup owner; not a transferable creation capability.
pub struct PostgresDataDisposition<'a> {
    owner: &'a PostgresStartLock,
    data_dir: PathBuf,
    origin: PostgresSidecarOrigin,
}

impl core::fmt::Debug for PostgresDataDisposition<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PostgresDataDisposition")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl<'a> PostgresDataDisposition<'a> {
    pub(crate) fn inspect(
        owner: &'a PostgresStartLock,
        data_dir: &Path,
    ) -> Result<Self, PostgresSidecarError> {
        owner.ensure_current()?;
        let root = owner
            .path
            .parent()
            .ok_or(PostgresSidecarError::DataDirectoryInvalid)?;
        validate_supervisor_paths(root, &owner.instance_id, &owner.data_dir_name, data_dir)?;
        let origin = data_directory_origin(data_dir)?;
        Ok(Self {
            owner,
            data_dir: data_dir.to_owned(),
            origin,
        })
    }

    pub(super) fn is_current_for(&self, owner: &PostgresStartLock) -> bool {
        if !std::ptr::eq(self.owner, owner) || !owner.ownership_is_current() {
            return false;
        }
        let Some(root) = owner.path.parent() else {
            return false;
        };
        if validate_supervisor_paths(
            root,
            &owner.instance_id,
            &owner.data_dir_name,
            &self.data_dir,
        )
        .is_err()
        {
            return false;
        }
        data_directory_origin(&self.data_dir).is_ok_and(|origin| origin == self.origin)
    }

    /// State observed under the owner. It must still be checked at use time.
    #[must_use]
    pub const fn origin(&self) -> PostgresSidecarOrigin {
        self.origin
    }
    /// Whether the original observation contained a PostgreSQL cluster.
    #[must_use]
    pub const fn is_existing(&self) -> bool {
        matches!(self.origin, PostgresSidecarOrigin::Existing)
    }
    /// Whether the original observation was an empty private data directory.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        matches!(self.origin, PostgresSidecarOrigin::Fresh)
    }

    pub(super) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(test)]
    pub(crate) fn for_test(owner: &'a PostgresStartLock, origin: PostgresSidecarOrigin) -> Self {
        let data = owner.path.parent().unwrap().join(&*owner.data_dir_name);
        std::fs::create_dir_all(&data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if origin == PostgresSidecarOrigin::Existing {
            std::fs::write(data.join("PG_VERSION"), b"17\n").unwrap();
        }
        Self::inspect(owner, &data).unwrap()
    }
}
