use crate::{DaemonError, DataDirectoryInput};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const DIRECTORIES: &[&str] = &[
    "keys",
    "pg",
    "pg/data",
    "run",
    "tenant",
    "hosts",
    "hosts/crabcode",
    "hosts/crabcode/tmp",
    "logs",
];
pub(crate) const TOKEN_BYTES: usize = 32;
pub(crate) const HBA: &[u8] = b"host all openmybot 127.0.0.1/32 scram-sha-256";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) deployment_id: String,
    pub(crate) pg_bin_dir: PathBuf,
    pub(crate) hosts: Hosts,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hosts {
    pub(crate) crabcode: Crabcode,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Crabcode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) binary: Option<PathBuf>,
    pub(crate) workspace_roots: Vec<PathBuf>,
}

pub fn resolve_data_dir(input: DataDirectoryInput) -> Result<PathBuf, DaemonError> {
    for value in [&input.explicit, &input.environment, &input.home]
        .into_iter()
        .flatten()
    {
        if !value.is_absolute() {
            return Err(DaemonError::InvalidArguments);
        }
    }
    let path = input
        .explicit
        .or(input.environment)
        .or_else(|| {
            input
                .home
                .map(|p| p.join("Library/Application Support/OpenMyBot"))
        })
        .ok_or(DaemonError::InvalidArguments)?;
    validate_path(&path)?;
    Ok(path)
}
pub(crate) fn validate_path(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(DaemonError::InvalidArguments);
    }
    if path
        .join("run/control.sock")
        .as_os_str()
        .as_encoded_bytes()
        .len()
        > 103
    {
        return Err(DaemonError::ControlSocketPathTooLong);
    }
    Ok(())
}
pub(crate) fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn metadata_matches(meta: &fs::Metadata, directory: bool, expected_uid: u32) -> bool {
    meta.uid() == expected_uid
        && meta.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
        && if directory {
            meta.is_dir()
        } else {
            meta.is_file() || meta.file_type().is_socket()
        }
}
use std::os::unix::fs::FileTypeExt;
pub(crate) fn check(path: &Path, directory: bool) -> Result<(), DaemonError> {
    let meta = fs::symlink_metadata(path).map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !metadata_matches(&meta, directory, uid()) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    Ok(())
}
pub(crate) fn make_dir(path: &Path) -> Result<(), DaemonError> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| DaemonError::InitFailed)?;
    check(path, true)
}
pub(crate) fn write_private(
    path: &Path,
    bytes: &[u8],
    create_new: bool,
) -> Result<(), DaemonError> {
    if !create_new {
        check(path, false)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(create_new)
        .truncate(!create_new)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !metadata_matches(
        &file
            .metadata()
            .map_err(|_| DaemonError::DataDirPermissionsInvalid)?,
        false,
        uid(),
    ) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)
}
pub(crate) fn read_private(path: &Path, maximum: usize) -> Result<Vec<u8>, DaemonError> {
    check(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !metadata_matches(
        &file
            .metadata()
            .map_err(|_| DaemonError::DataDirPermissionsInvalid)?,
        false,
        uid(),
    ) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if bytes.len() > maximum {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    Ok(bytes)
}
pub(crate) fn hex_random(count: usize) -> Result<String, DaemonError> {
    let mut bytes = vec![0; count];
    getrandom::fill(&mut bytes).map_err(|_| DaemonError::InitFailed)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub(crate) fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn load(root: &Path) -> Result<Config, DaemonError> {
    validate_path(root)?;
    check(root, true)?;
    for name in DIRECTORIES {
        check(&root.join(name), true)?;
    }
    check_tree(&root.join("pg/data"))?;
    check_tree(&root.join("logs"))?;
    for name in ["keys/vault-kek.key", "keys/app-master.key"] {
        if read_private(&root.join(name), 32)?.len() != 32 {
            return Err(DaemonError::DataDirPermissionsInvalid);
        }
    }
    let password = read_private(&root.join("pg/password"), 64)?;
    if !std::str::from_utf8(&password).is_ok_and(|s| is_hex(s, 64)) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    for name in ["run/daemon.lock", "run/control.token", "run/control.sock"] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => check(&path, false)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(DaemonError::DataDirPermissionsInvalid),
        }
    }
    let config: Config = toml::from_str(
        std::str::from_utf8(&read_private(&root.join("config.toml"), 64 * 1024)?)
            .map_err(|_| DaemonError::DataDirPermissionsInvalid)?,
    )
    .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !config.pg_bin_dir.is_absolute()
        || !config
            .deployment_id
            .strip_prefix("omb-local-")
            .is_some_and(|id| is_hex(id, 32))
    {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    Ok(config)
}
fn check_tree(directory: &Path) -> Result<(), DaemonError> {
    for entry in fs::read_dir(directory).map_err(|_| DaemonError::DataDirPermissionsInvalid)? {
        let entry = entry.map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
        if metadata.is_dir() {
            check(&path, true)?;
            check_tree(&path)?;
        } else if metadata.is_file() {
            check(&path, false)?;
        } else {
            return Err(DaemonError::DataDirPermissionsInvalid);
        }
    }
    Ok(())
}
pub(crate) fn lock(root: &Path) -> Result<File, DaemonError> {
    validate_path(root)?;
    check(root, true)?;
    check(&root.join("run"), true)?;
    let path = root.join("run/daemon.lock");
    if fs::symlink_metadata(&path).is_ok() {
        check(&path, false)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    if !metadata_matches(
        &file
            .metadata()
            .map_err(|_| DaemonError::DataDirPermissionsInvalid)?,
        false,
        uid(),
    ) {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                DaemonError::DaemonAlreadyRunning
            } else {
                DaemonError::DataDirPermissionsInvalid
            }
        },
    )?;
    Ok(file)
}
pub(crate) fn remove_runtime(root: &Path, name: &str) -> Result<(), DaemonError> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            check(&path, false)?;
            fs::remove_file(&path).map_err(|_| DaemonError::ShutdownFailed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DaemonError::ShutdownFailed),
    }
}

#[cfg(test)]
pub(crate) fn test_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!("omb-{}", hex_random(8).unwrap()));
    make_dir(&path).unwrap();
    path
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn rejects_unknown_config_fields() {
        let base = "deployment_id='omb-local-00000000000000000000000000000000'\npg_bin_dir='/pg'\n[hosts.crabcode]\nworkspace_roots=[]\n";
        assert!(toml::from_str::<Config>(base).is_ok());
        assert!(toml::from_str::<Config>(&format!("unknown=1\n{base}")).is_err());
        assert!(toml::from_str::<Config>(&format!("{base}unknown=1\n")).is_err());
        assert!(
            toml::from_str::<Config>(
                &base.replace("[hosts.crabcode]", "[hosts]\nunknown=1\n[hosts.crabcode]")
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_relative_and_overlong_socket_paths() {
        assert_eq!(
            validate_path(Path::new("relative")),
            Err(DaemonError::InvalidArguments)
        );
        assert!(validate_path(Path::new(&format!("/{}", "a".repeat(85)))).is_ok());
        assert_eq!(
            validate_path(Path::new(&format!("/{}", "a".repeat(86)))),
            Err(DaemonError::ControlSocketPathTooLong)
        );
    }
    #[test]
    fn rejects_symlink_wrong_owner_and_permissions() {
        let root = test_dir();
        let path = root.join("file");
        write_private(&path, b"private", true).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert!(!metadata_matches(&metadata, false, uid().wrapping_add(1)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            check(&path, false),
            Err(DaemonError::DataDirPermissionsInvalid)
        );
        let link = root.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            read_private(&link, 100),
            Err(DaemonError::DataDirPermissionsInvalid)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
