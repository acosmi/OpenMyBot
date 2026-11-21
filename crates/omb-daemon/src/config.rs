use crate::{DaemonError, DataDirectoryInput};
use omb_hostdriver::{HostKind, WorkspaceRoots};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(crate) const DIRECTORIES: &[&str] =
    &["keys", "pg", "pg/data", "run", "tenant", "hosts", "logs"];
pub(crate) const TOKEN_BYTES: usize = 32;
pub(crate) const HBA: &[u8] = b"host all openmybot 127.0.0.1/32 scram-sha-256";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) deployment_id: String,
    pub(crate) pg_bin_dir: PathBuf,
    /// One list for every host.
    pub(crate) workspace_roots: Vec<PathBuf>,
    #[serde(default)]
    pub(crate) hosts: Hosts,
    /// Absent in instances initialized before channel plugins.
    #[serde(default)]
    pub(crate) plugins: PluginsConfig,
}
/// The `plugins` section: absolute directories appended to the plugins' fixed `PATH`.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginsConfig {
    #[serde(default)]
    pub(crate) path_extra: Vec<PathBuf>,
}
/// One optional section per host of `HostKind`; a host without a binary refuses every start.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Hosts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) crabcode: Option<HostSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) claude: Option<HostSection>,
}
/// A `hosts.<host>` section as written in `config.toml`.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostSection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) binary: Option<PathBuf>,
}
/// The host sections and the workspace roots as types: validated once at startup.
pub(crate) struct HostsConfig {
    /// The configured binary of each host that has one.
    pub(crate) binaries: BTreeMap<HostKind, PathBuf>,
    pub(crate) roots: WorkspaceRoots,
}
impl HostsConfig {
    /// Every binary must be absolute; each root must be a proper subdirectory of `home` outside
    /// `home/Library`.
    pub(crate) fn parse(config: &Config, home: &Path) -> Result<Self, DaemonError> {
        let mut binaries = BTreeMap::new();
        for (kind, section) in [
            (HostKind::Crabcode, &config.hosts.crabcode),
            (HostKind::Claude, &config.hosts.claude),
        ] {
            if let Some(binary) = section.as_ref().and_then(|section| section.binary.clone()) {
                if !binary.is_absolute() {
                    return Err(DaemonError::HostBinaryInvalid);
                }
                binaries.insert(kind, binary);
            }
        }
        Ok(Self {
            binaries,
            roots: WorkspaceRoots::parse(home, &config.workspace_roots)
                .map_err(|_| DaemonError::WorkspaceRootInvalid)?,
        })
    }
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
    // Instances initialized before a host was added get its directories here.
    for kind in HostKind::ALL {
        for name in [
            format!("hosts/{}", kind.as_str()),
            format!("hosts/{}/tmp", kind.as_str()),
        ] {
            let path = root.join(name);
            if path.exists() {
                check(&path, true)?;
            } else {
                make_dir(&path)?;
            }
        }
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
    let text = String::from_utf8(read_private(&root.join("config.toml"), 64 * 1024)?)
        .map_err(|_| DaemonError::DataDirPermissionsInvalid)?;
    let config = parse_config(&text)?;
    if !config.pg_bin_dir.is_absolute()
        || !config
            .plugins
            .path_extra
            .iter()
            .all(|path| path.is_absolute())
        || !config
            .deployment_id
            .strip_prefix("omb-local-")
            .is_some_and(|id| is_hex(id, 32))
    {
        return Err(DaemonError::DataDirPermissionsInvalid);
    }
    Ok(config)
}
/// Unknown keys refuse startup; `workspace_roots` inside `[hosts.crabcode]` is the layout before
/// the host table and is refused with its own code, without a silent migration.
fn parse_config(text: &str) -> Result<Config, DaemonError> {
    toml::from_str(text).map_err(|_| {
        let old = toml::from_str::<toml::Table>(text).is_ok_and(|table| {
            table
                .get("hosts")
                .and_then(|hosts| hosts.get("crabcode"))
                .and_then(|crabcode| crabcode.get("workspace_roots"))
                .is_some()
        });
        if old {
            DaemonError::ConfigInvalid
        } else {
            DaemonError::DataDirPermissionsInvalid
        }
    })
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
    const BASE: &str = "deployment_id='omb-local-00000000000000000000000000000000'\npg_bin_dir='/pg'\nworkspace_roots=[]\n";
    #[test]
    fn rejects_unknown_config_fields_and_hosts_outside_the_table() {
        let base = format!("{BASE}[hosts.crabcode]\n[hosts.claude]\nbinary='/opt/claude'\n");
        assert!(parse_config(&base).is_ok());
        assert!(parse_config(BASE).is_ok());
        for text in [
            format!("unknown=1\n{base}"),
            format!("{base}unknown=1\n"),
            base.replace("[hosts.crabcode]", "[hosts]\nunknown=1\n[hosts.crabcode]"),
            format!("{BASE}[hosts.dsh]\nbinary='/opt/dsh'\n"),
            format!("{BASE}[hosts.pi]\n"),
            format!("{BASE}[hosts.wrok]\n"),
            format!("{BASE}[hosts.claude]\nworkspace_roots=[]\n"),
            BASE.replace("workspace_roots=[]\n", ""),
        ] {
            assert_eq!(
                parse_config(&text).err(),
                Some(DaemonError::DataDirPermissionsInvalid),
                "{text}"
            );
        }
    }
    #[test]
    fn layout_with_roots_inside_the_crabcode_section_is_config_invalid() {
        let old = "deployment_id='omb-local-00000000000000000000000000000000'\npg_bin_dir='/pg'\n[hosts.crabcode]\nbinary='/opt/crab/bin/crabcode'\nworkspace_roots=[]\n";
        assert_eq!(parse_config(old).err(), Some(DaemonError::ConfigInvalid));
        assert_eq!(
            parse_config(&format!("workspace_roots=[]\n{old}")).err(),
            Some(DaemonError::ConfigInvalid)
        );
        assert_eq!(DaemonError::ConfigInvalid.code(), "config_invalid");
    }
    fn hosts(crabcode: Option<&str>, claude: Option<&str>, roots: &[PathBuf]) -> Config {
        let section = |binary: Option<&str>| {
            binary.map(|binary| HostSection {
                binary: Some(PathBuf::from(binary)),
            })
        };
        Config {
            deployment_id: "omb-local-00000000000000000000000000000000".into(),
            pg_bin_dir: "/pg".into(),
            workspace_roots: roots.to_vec(),
            hosts: Hosts {
                crabcode: section(crabcode),
                claude: section(claude),
            },
            plugins: PluginsConfig::default(),
        }
    }
    #[test]
    fn host_sections_and_roots_are_parsed_once_into_typed_binaries_and_roots() {
        let home = test_dir();
        let project = home.join("code/project");
        fs::create_dir_all(&project).unwrap();
        let text = format!(
            "{}[hosts.crabcode]\nbinary='/opt/crab/bin/crabcode'\n[hosts.claude]\n",
            BASE.replace("[]", &format!("['{}']", home.join("code").display()))
        );
        let parsed = HostsConfig::parse(&parse_config(&text).unwrap(), &home).unwrap();
        assert_eq!(
            parsed.binaries,
            BTreeMap::from([(HostKind::Crabcode, PathBuf::from("/opt/crab/bin/crabcode"))])
        );
        assert_eq!(
            parsed.roots.resolve(&project),
            Some(fs::canonicalize(&project).unwrap())
        );
        assert_eq!(parsed.roots.resolve(&home), None);
        let both =
            HostsConfig::parse(&hosts(Some("/a/crabcode"), Some("/b/claude"), &[]), &home).unwrap();
        assert_eq!(both.binaries.len(), 2);
        assert_eq!(both.binaries[&HostKind::Claude], PathBuf::from("/b/claude"));
        let none = HostsConfig::parse(&hosts(None, None, &[]), &home).unwrap();
        assert!(none.binaries.is_empty());
        assert_eq!(none.roots.resolve(&project), None);
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn roots_outside_home_or_in_library_refuse_startup() {
        let home = test_dir();
        let outside = test_dir();
        fs::create_dir_all(home.join("Library/Work")).unwrap();
        for root in [
            outside.clone(),
            home.clone(),
            home.join("Library/Work"),
            home.join("missing"),
            PathBuf::from("relative"),
        ] {
            assert_eq!(
                HostsConfig::parse(&hosts(None, None, &[root]), &home).err(),
                Some(DaemonError::WorkspaceRootInvalid)
            );
        }
        assert_eq!(
            DaemonError::WorkspaceRootInvalid.code(),
            "workspace_root_invalid"
        );
        fs::remove_dir_all(home).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn relative_binary_refuses_startup() {
        let home = test_dir();
        for config in [
            hosts(Some("bin/crabcode"), None, &[]),
            hosts(None, Some("claude"), &[]),
        ] {
            assert_eq!(
                HostsConfig::parse(&config, &home).err(),
                Some(DaemonError::HostBinaryInvalid)
            );
        }
        assert_eq!(DaemonError::HostBinaryInvalid.code(), "host_binary_invalid");
        fs::remove_dir_all(home).unwrap();
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
    #[test]
    fn plugins_section_defaults_to_no_path_extra_and_a_relative_entry_refuses_startup() {
        let base = format!("{BASE}[hosts.crabcode]\n");
        let base = base.as_str();
        assert!(
            toml::from_str::<Config>(base)
                .unwrap()
                .plugins
                .path_extra
                .is_empty()
        );
        assert!(toml::from_str::<Config>(&format!("{base}[plugins]\nunknown=1\n")).is_err());
        let root = test_dir();
        for name in DIRECTORIES {
            make_dir(&root.join(name)).unwrap();
        }
        for name in ["keys/vault-kek.key", "keys/app-master.key"] {
            write_private(&root.join(name), &[7; 32], true).unwrap();
        }
        write_private(&root.join("pg/password"), "a".repeat(64).as_bytes(), true).unwrap();
        let config = root.join("config.toml");
        write_private(
            &config,
            format!("{base}[plugins]\npath_extra=['/opt/node/bin']\n").as_bytes(),
            true,
        )
        .unwrap();
        assert_eq!(
            load(&root).unwrap().plugins.path_extra,
            [PathBuf::from("/opt/node/bin")]
        );
        // The host directories of an instance initialized before a host was added are created.
        for kind in HostKind::ALL {
            check(&root.join(format!("hosts/{}/tmp", kind.as_str())), true).unwrap();
        }
        write_private(
            &config,
            format!("{base}[plugins]\npath_extra=['node/bin']\n").as_bytes(),
            false,
        )
        .unwrap();
        assert_eq!(
            load(&root).err(),
            Some(DaemonError::DataDirPermissionsInvalid)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
