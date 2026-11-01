//! Installed channel plugins: the package manifest read once at install, the copied package under
//! `<data>/plugins/<name>/`, and `<data>/plugins.lock.json`, the record the daemon runs them from.
use crate::{DaemonError, ProcessState, channels::rfc3339_utc, config};
use omb_channel_sdk::PROTOCOL;
use omb_store::ChannelKind;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

const LOCK: &str = "plugins.lock.json";
/// Bytes read of a package manifest or of the lock file.
const FILE_MAX: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CredentialField {
    pub(crate) name: String,
    pub(crate) secret: bool,
}
/// How one channel of an installed plugin is run and bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelEntry {
    /// `./`-relative to the package root.
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) credential_fields: Vec<CredentialField>,
    pub(crate) status_note: String,
}
/// One plugin of the lock file; every channel key passed `ChannelKind::parse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Installed {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) installed_at: String,
    pub(crate) channels: BTreeMap<String, ChannelEntry>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    plugins: Vec<Installed>,
}

/// The root `plugin.json` of an Agent Plugins package; only the OpenMyBot extension is read.
#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "$schema")]
    _schema: String,
    name: String,
    version: Option<String>,
    extensions: Extensions,
}
#[derive(Deserialize)]
struct Extensions {
    #[serde(rename = "org.openmybot")]
    openmybot: OpenMyBot,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenMyBot {
    channels: BTreeMap<String, ManifestChannel>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestChannel {
    protocol: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    credential_fields: Vec<CredentialField>,
    status_note: String,
}

/// The last known state of one channel's plugin process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct View {
    pub(crate) running: bool,
    pub(crate) last_exit_code: Option<i32>,
}

/// The installed plugins and the run environment they get, shared by the operations, the plugin
/// supervisors and the status segment; the operations' control lock serializes every change.
#[derive(Clone)]
pub(crate) struct Plugins {
    root: PathBuf,
    pub(crate) path_extra: Vec<PathBuf>,
    pub(crate) home: PathBuf,
    lock: Arc<Mutex<Lock>>,
    views: Arc<Mutex<HashMap<ChannelKind, View>>>,
}

/// `^[a-z0-9][a-z0-9-]{0,63}$`: no `.` or `/`, so the name is one path component.
fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn read_capped(path: &Path) -> Option<String> {
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(FILE_MAX as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= FILE_MAX).then_some(text)
}

/// Copies the package tree: directories 0700, files 0600, files with an execute bit 0700; a
/// symbolic link is copied as the file it resolves to inside the package, any other is refused.
fn copy_tree(package: &Path, from: &Path, to: &Path) -> Result<(), DaemonError> {
    let invalid = DaemonError::PluginInvalid;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(to)
        .map_err(|_| DaemonError::InternalError)?;
    for entry in fs::read_dir(from).map_err(|_| invalid)? {
        let path = entry.map_err(|_| invalid)?.path();
        let target = to.join(path.file_name().ok_or(invalid)?);
        let link = fs::symlink_metadata(&path).map_err(|_| invalid)?;
        if link.is_dir() {
            copy_tree(package, &path, &target)?;
            continue;
        }
        let source = if link.is_symlink() {
            fs::canonicalize(&path)
                .ok()
                .filter(|real| real.starts_with(package))
                .ok_or(invalid)?
        } else {
            path
        };
        let meta = fs::metadata(&source).map_err(|_| invalid)?;
        if !meta.is_file() {
            return Err(invalid);
        }
        fs::copy(&source, &target).map_err(|_| DaemonError::InternalError)?;
        let mode = if meta.permissions().mode() & 0o111 == 0 {
            0o600
        } else {
            0o700
        };
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))
            .map_err(|_| DaemonError::InternalError)?;
    }
    Ok(())
}

impl Plugins {
    /// Reads the lock file once at startup; a missing file is no plugin, a corrupt one refuses
    /// startup.
    pub(crate) fn load(
        root: &Path,
        path_extra: Vec<PathBuf>,
        home: PathBuf,
    ) -> Result<Self, DaemonError> {
        let path = root.join(LOCK);
        let lock = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Lock::default(),
            _ => {
                let lock: Lock = serde_json::from_slice(&config::read_private(&path, FILE_MAX)?)
                    .map_err(|_| DaemonError::PluginInvalid)?;
                let mut kinds = HashSet::new();
                for plugin in &lock.plugins {
                    if !valid_name(&plugin.name)
                        || !plugin.channels.keys().all(|kind| {
                            ChannelKind::parse(kind).is_some() && kinds.insert(kind.clone())
                        })
                    {
                        return Err(DaemonError::PluginInvalid);
                    }
                }
                lock
            }
        };
        Ok(Self {
            root: root.to_path_buf(),
            path_extra,
            home,
            lock: Arc::new(Mutex::new(lock)),
            views: Arc::default(),
        })
    }
    /// The plugin that provides `kind`.
    pub(crate) fn provider(&self, kind: &ChannelKind) -> Option<Installed> {
        self.lock
            .lock()
            .unwrap()
            .plugins
            .iter()
            .find(|plugin| plugin.channels.contains_key(kind.as_str()))
            .cloned()
    }
    pub(crate) fn list(&self) -> Vec<Installed> {
        self.lock.lock().unwrap().plugins.clone()
    }
    /// The copied package of an installed plugin.
    pub(crate) fn package(&self, name: &str) -> PathBuf {
        self.root.join("plugins").join(name)
    }
    /// The plugin's own data directory, kept when the plugin is removed.
    pub(crate) fn data(&self, name: &str) -> PathBuf {
        self.root.join("plugins-data").join(name)
    }
    pub(crate) fn set_view(&self, kind: &ChannelKind, view: View) {
        self.views.lock().unwrap().insert(kind.clone(), view);
    }
    /// Running when any channel of the plugin runs a process; the exit code of the latest exit.
    pub(crate) fn process(&self, plugin: &Installed) -> (ProcessState, Option<i32>) {
        let views: Vec<View> = self
            .views
            .lock()
            .unwrap()
            .iter()
            .filter(|(kind, _)| plugin.channels.contains_key(kind.as_str()))
            .map(|(_, view)| *view)
            .collect();
        let state = if views.iter().any(|view| view.running) {
            ProcessState::Running
        } else {
            ProcessState::Stopped
        };
        (state, views.iter().find_map(|view| view.last_exit_code))
    }
    fn write(&self, lock: &Lock) -> Result<(), DaemonError> {
        let path = self.root.join(LOCK);
        let bytes = serde_json::to_vec_pretty(lock).map_err(|_| DaemonError::InternalError)?;
        config::write_private(&path, &bytes, !path.exists())
    }
    /// Installs the package at `dir`: the manifest is checked, the package is copied and the lock
    /// records it. A plugin of the same name is replaced unless one of its channels has a binding
    /// in `live`.
    pub(crate) fn install(
        &self,
        dir: &Path,
        live: &HashSet<String>,
    ) -> Result<Installed, DaemonError> {
        let invalid = DaemonError::PluginInvalid;
        let package = fs::canonicalize(dir).map_err(|_| invalid)?;
        let manifest: Manifest =
            serde_json::from_str(&read_capped(&package.join("plugin.json")).ok_or(invalid)?)
                .map_err(|_| invalid)?;
        if !valid_name(&manifest.name) {
            return Err(invalid);
        }
        let mut channels = BTreeMap::new();
        for (kind, channel) in manifest.extensions.openmybot.channels {
            let inside = channel.command.starts_with("./")
                && fs::canonicalize(package.join(&channel.command))
                    .is_ok_and(|command| command.starts_with(&package));
            if ChannelKind::parse(&kind).is_none() || channel.protocol != PROTOCOL || !inside {
                return Err(invalid);
            }
            channels.insert(
                kind,
                ChannelEntry {
                    command: channel.command,
                    args: channel.args,
                    credential_fields: channel.credential_fields,
                    status_note: channel.status_note,
                },
            );
        }
        for plugin in &self.lock.lock().unwrap().plugins {
            let provides = |kind: &String| plugin.channels.contains_key(kind);
            if plugin.name != manifest.name && channels.keys().any(provides) {
                return Err(DaemonError::ChannelKindTaken);
            }
            if plugin.name == manifest.name && live.iter().any(provides) {
                return Err(DaemonError::PluginInUse);
            }
        }
        let plugins = self.root.join("plugins");
        if !plugins.exists() {
            config::make_dir(&plugins).map_err(|_| DaemonError::InternalError)?;
        }
        // A name has no `.`, so the staging directory never collides with an installed package.
        let staging = plugins.join(format!("{}.new", manifest.name));
        if staging.exists() {
            fs::remove_dir_all(&staging).map_err(|_| DaemonError::InternalError)?;
        }
        copy_tree(&package, &package, &staging)?;
        let target = self.package(&manifest.name);
        if target.exists() {
            fs::remove_dir_all(&target).map_err(|_| DaemonError::InternalError)?;
        }
        fs::rename(&staging, &target).map_err(|_| DaemonError::InternalError)?;
        let installed_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| DaemonError::InternalError)?
            .as_nanos();
        let installed = Installed {
            name: manifest.name,
            version: manifest.version.unwrap_or_default(),
            installed_at: rfc3339_utc(installed_at as i128)?,
            channels,
        };
        let mut lock = self.lock.lock().unwrap();
        lock.plugins.retain(|plugin| plugin.name != installed.name);
        lock.plugins.push(installed.clone());
        self.write(&lock)?;
        Ok(installed)
    }
    /// Removes the plugin and its package unless one of its channels has a binding in `live`; the
    /// plugin's data directory stays.
    pub(crate) fn remove(&self, name: &str, live: &HashSet<String>) -> Result<(), DaemonError> {
        let mut lock = self.lock.lock().unwrap();
        let index = lock
            .plugins
            .iter()
            .position(|plugin| plugin.name == name)
            .ok_or(DaemonError::PluginNotInstalled)?;
        if lock.plugins[index]
            .channels
            .keys()
            .any(|kind| live.contains(kind))
        {
            return Err(DaemonError::PluginInUse);
        }
        fs::remove_dir_all(self.package(name)).map_err(|_| DaemonError::InternalError)?;
        lock.plugins.remove(index);
        self.write(&lock)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::io::Write;

    /// The fake channel plugin binary.
    pub(crate) fn fake() -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os("OMB_TEST_CHANNEL_PLUGIN")
                .expect("OMB_TEST_CHANNEL_PLUGIN: absolute path of the fake channel plugin"),
        );
        assert!(path.is_absolute());
        path
    }
    /// The files one fake plugin channel reads and writes: events it emits after `start` (tests
    /// append lines), and the logs of the sends and of every frame it received.
    pub(crate) struct Logs {
        pub(crate) dir: PathBuf,
    }
    impl Logs {
        pub(crate) fn new() -> Self {
            Self {
                dir: config::test_dir(),
            }
        }
        pub(crate) fn events(&self) -> PathBuf {
            self.dir.join("events.jsonl")
        }
        pub(crate) fn sent_log(&self) -> PathBuf {
            self.dir.join("sent.jsonl")
        }
        pub(crate) fn recv_log(&self) -> PathBuf {
            self.dir.join("recv.jsonl")
        }
        /// Appends one event line; a running fake picks it up within 100 ms.
        pub(crate) fn push(&self, event: &Value) {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.events())
                .unwrap();
            writeln!(file, "{event}").unwrap();
        }
        /// The complete lines: the fake may be mid-way through writing the last one.
        fn lines(path: &Path) -> Vec<Value> {
            fs::read_to_string(path)
                .unwrap_or_default()
                .split_inclusive('\n')
                .filter(|line| line.ends_with('\n'))
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        /// Every `send` the fake handled, in order.
        pub(crate) fn sent(&self) -> Vec<Value> {
            Self::lines(&self.sent_log())
        }
        /// Every frame the fake received, in order.
        pub(crate) fn received(&self) -> Vec<Value> {
            Self::lines(&self.recv_log())
        }
        /// The received frames of one `type`.
        pub(crate) fn received_of(&self, kind: &str) -> Vec<Value> {
            self.received()
                .into_iter()
                .filter(|frame| frame["type"] == kind)
                .collect()
        }
    }
    impl Drop for Logs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    /// The manifest channel entry of the fake for `kind`, with `logs` and `scenario`.
    pub(crate) fn fake_channel(kind: &str, logs: &Logs, scenario: &str, fields: Value) -> Value {
        json!({
            "protocol": PROTOCOL,
            "command": "./bin/fake-channel-plugin",
            "args": [
                "--channel-kind", kind,
                "--events", logs.events(),
                "--sent-log", logs.sent_log(),
                "--recv-log", logs.recv_log(),
                "--scenario", scenario,
            ],
            "credential_fields": fields,
            "status_note": format!("{kind} fake note"),
        })
    }
    /// A package directory named `name` with the fake binary copied in and `channels` as the
    /// manifest's channel map.
    pub(crate) fn package(name: &str, channels: Value) -> PathBuf {
        let dir = config::test_dir();
        fs::create_dir(dir.join("bin")).unwrap();
        fs::copy(fake(), dir.join("bin/fake-channel-plugin")).unwrap();
        let manifest = json!({
            "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name": name,
            "version": "0.1.0",
            "description": "fake channel plugin",
            "extensions": {"org.openmybot": {"channels": channels}, "com.example": {"x": 1}},
        });
        fs::write(dir.join("plugin.json"), manifest.to_string()).unwrap();
        dir
    }
    /// The plugins of data directory `root` with the fake installed as `name`, serving `kind`
    /// with one secret field `token`.
    pub(crate) fn installed(root: &Path, kind: &str, logs: &Logs, scenario: &str) -> Plugins {
        let plugins = Plugins::load(root, Vec::new(), root.to_path_buf()).unwrap();
        let package = package(
            &format!("fake-{}", kind.replace('_', "-")),
            json!({kind: fake_channel(kind, logs, scenario, json!([{"name": "token", "secret": true}]))}),
        );
        plugins.install(&package, &HashSet::new()).unwrap();
        fs::remove_dir_all(package).unwrap();
        plugins
    }

    fn manifest(dir: &Path) -> Value {
        serde_json::from_slice(&fs::read(dir.join("plugin.json")).unwrap()).unwrap()
    }
    fn rewrite(dir: &Path, edit: impl FnOnce(&mut Value)) {
        let mut value = manifest(dir);
        edit(&mut value);
        fs::write(dir.join("plugin.json"), value.to_string()).unwrap();
    }
    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn plugins_add_copies_the_package_with_private_modes_and_records_the_lock() {
        let root = config::test_dir();
        let logs = Logs::new();
        let package = package(
            "fake-plugin",
            json!({"fake": fake_channel("fake", &logs, "normal", json!([]))}),
        );
        fs::write(package.join("README"), "readme").unwrap();
        fs::set_permissions(package.join("README"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::create_dir(package.join("lib")).unwrap();
        fs::write(package.join("lib/data.txt"), "data").unwrap();
        std::os::unix::fs::symlink("../README", package.join("lib/readme-link")).unwrap();
        let plugins = Plugins::load(&root, Vec::new(), root.clone()).unwrap();
        let installed = plugins.install(&package, &HashSet::new()).unwrap();
        assert_eq!(installed.name, "fake-plugin");
        assert_eq!(installed.version, "0.1.0");
        assert_eq!(installed.channels.keys().collect::<Vec<_>>(), ["fake"]);
        let copied = root.join("plugins/fake-plugin");
        assert_eq!(mode(&root.join("plugins")), 0o700);
        assert_eq!(mode(&copied), 0o700);
        assert_eq!(mode(&copied.join("lib")), 0o700);
        assert_eq!(mode(&copied.join("bin/fake-channel-plugin")), 0o700);
        assert_eq!(mode(&copied.join("README")), 0o600);
        assert_eq!(mode(&copied.join("lib/data.txt")), 0o600);
        // The link is copied as the file it names.
        assert!(
            fs::symlink_metadata(copied.join("lib/readme-link"))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            fs::read_to_string(copied.join("lib/readme-link")).unwrap(),
            "readme"
        );
        assert_eq!(mode(&root.join("plugins.lock.json")), 0o600);
        let lock: Value =
            serde_json::from_slice(&fs::read(root.join("plugins.lock.json")).unwrap()).unwrap();
        assert_eq!(lock["plugins"][0]["name"], "fake-plugin");
        assert_eq!(
            lock["plugins"][0]["channels"]["fake"]["command"],
            "./bin/fake-channel-plugin"
        );
        assert_eq!(
            lock["plugins"][0]["channels"]["fake"]["status_note"],
            "fake fake note"
        );
        // A restart reads the same plugins back.
        let reloaded = Plugins::load(&root, Vec::new(), root.clone()).unwrap();
        assert_eq!(reloaded.list(), plugins.list());
        assert_eq!(
            reloaded
                .provider(&ChannelKind::from_static("fake"))
                .map(|plugin| plugin.name),
            Some("fake-plugin".to_owned())
        );
        assert_eq!(reloaded.provider(&ChannelKind::from_static("other")), None);
        // Reinstalling the same name without live bindings replaces the whole directory.
        fs::remove_file(package.join("README")).unwrap();
        fs::remove_file(package.join("lib/readme-link")).unwrap();
        plugins.install(&package, &HashSet::new()).unwrap();
        assert!(!copied.join("README").exists());
        assert_eq!(plugins.list().len(), 1);
        for dir in [root, package] {
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn plugins_add_rejects_command_outside_package() {
        let root = config::test_dir();
        let outside = config::test_dir();
        fs::copy(fake(), outside.join("fake-channel-plugin")).unwrap();
        let logs = Logs::new();
        let package = package(
            "fake-plugin",
            json!({"fake": fake_channel("fake", &logs, "normal", json!([]))}),
        );
        let plugins = Plugins::load(&root, Vec::new(), root.clone()).unwrap();
        let command = |value: &str| {
            let value = value.to_owned();
            rewrite(&package, |manifest| {
                manifest["extensions"]["org.openmybot"]["channels"]["fake"]["command"] =
                    json!(value);
            });
            plugins.install(&package, &HashSet::new()).err()
        };
        // Not `./`-relative, climbing out, or a link that resolves outside the package.
        std::os::unix::fs::symlink(outside.join("fake-channel-plugin"), package.join("bin/out"))
            .unwrap();
        for value in [
            "bin/fake-channel-plugin",
            "/bin/sh",
            "./../fake-channel-plugin",
            "./bin/../../fake-channel-plugin",
            "./bin/out",
            "./bin/missing",
        ] {
            assert_eq!(command(value), Some(DaemonError::PluginInvalid), "{value}");
        }
        // A package link to a file outside is refused when copying.
        fs::remove_file(package.join("bin/out")).unwrap();
        std::os::unix::fs::symlink(outside.join("fake-channel-plugin"), package.join("extra"))
            .unwrap();
        assert_eq!(
            command("./bin/fake-channel-plugin"),
            Some(DaemonError::PluginInvalid)
        );
        fs::remove_file(package.join("extra")).unwrap();
        assert_eq!(command("./bin/fake-channel-plugin"), None);
        assert!(!root.join("plugins/fake-plugin.new").exists());
        for dir in [root, outside, package] {
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn plugins_add_rejects_bad_name_and_taken_kind() {
        let root = config::test_dir();
        let logs = Logs::new();
        let plugins = Plugins::load(&root, Vec::new(), root.clone()).unwrap();
        let package = package(
            "fake-plugin",
            json!({"fake": fake_channel("fake", &logs, "normal", json!([]))}),
        );
        let install = |edit: &dyn Fn(&mut Value)| {
            let mut value = manifest(&package);
            edit(&mut value);
            let dir = config::test_dir();
            fs::create_dir(dir.join("bin")).unwrap();
            fs::copy(fake(), dir.join("bin/fake-channel-plugin")).unwrap();
            fs::write(dir.join("plugin.json"), value.to_string()).unwrap();
            let result = plugins.install(&dir, &HashSet::new());
            fs::remove_dir_all(dir).unwrap();
            result.map(|plugin| plugin.name)
        };
        for name in [
            "",
            "Fake",
            "-fake",
            "fake.plugin",
            "fake/plugin",
            "../fake",
            "fake_plugin",
            &"a".repeat(65),
        ] {
            let name = name.to_owned();
            assert_eq!(
                install(&|value| value["name"] = json!(name)),
                Err(DaemonError::PluginInvalid),
                "{name}"
            );
        }
        assert_eq!(
            install(&|value| {
                let channel = value["extensions"]["org.openmybot"]["channels"]["fake"].clone();
                value["name"] = json!("a".repeat(64));
                value["extensions"]["org.openmybot"]["channels"] = json!({"long_name": channel});
            }),
            Ok("a".repeat(64))
        );
        for kind in ["host", "Fake", "1fake", "fa-ke", &"k".repeat(33)] {
            let kind = kind.to_owned();
            assert_eq!(
                install(&|value| {
                    let channel = value["extensions"]["org.openmybot"]["channels"]["fake"].clone();
                    value["name"] = json!("other");
                    value["extensions"]["org.openmybot"]["channels"] =
                        json!({kind.clone(): channel});
                }),
                Err(DaemonError::PluginInvalid),
                "{kind}"
            );
        }
        // Missing `$schema`, a foreign protocol, unknown channel keys and a missing extension.
        for edit in [
            &(|value: &mut Value| {
                value.as_object_mut().unwrap().remove("$schema");
            }) as &dyn Fn(&mut Value),
            &|value| {
                value["extensions"]["org.openmybot"]["channels"]["fake"]["protocol"] =
                    json!("openmybot-channel/2")
            },
            &|value| value["extensions"]["org.openmybot"]["channels"]["fake"]["extra"] = json!(1),
            &|value| {
                value["extensions"]
                    .as_object_mut()
                    .unwrap()
                    .remove("org.openmybot");
            },
        ] {
            assert_eq!(install(edit), Err(DaemonError::PluginInvalid));
        }
        assert_eq!(install(&|_| ()), Ok("fake-plugin".to_owned()));
        // Another plugin may not provide the same channel.
        assert_eq!(
            install(&|value| value["name"] = json!("another")),
            Err(DaemonError::ChannelKindTaken)
        );
        assert_eq!(plugins.list().len(), 2);
        for dir in [root, package] {
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn plugins_remove_refuses_in_use() {
        let root = config::test_dir();
        let logs = Logs::new();
        let plugins = installed(&root, "fake", &logs, "normal");
        fs::create_dir_all(root.join("plugins-data/fake-fake")).unwrap();
        let live = HashSet::from(["fake".to_owned()]);
        assert_eq!(
            plugins.remove("fake-fake", &live),
            Err(DaemonError::PluginInUse)
        );
        // Replacing the same name is refused too while its channel has a live binding.
        let package = package(
            "fake-fake",
            json!({"fake": fake_channel("fake", &logs, "normal", json!([]))}),
        );
        assert_eq!(
            plugins.install(&package, &live).err(),
            Some(DaemonError::PluginInUse)
        );
        assert_eq!(
            plugins.remove("missing", &HashSet::new()),
            Err(DaemonError::PluginNotInstalled)
        );
        assert_eq!(
            plugins.remove("fake-fake", &HashSet::from(["telegram".to_owned()])),
            Ok(())
        );
        assert!(plugins.list().is_empty());
        assert!(!root.join("plugins/fake-fake").exists());
        // The plugin's data stays.
        assert!(root.join("plugins-data/fake-fake").exists());
        let lock: Value =
            serde_json::from_slice(&fs::read(root.join("plugins.lock.json")).unwrap()).unwrap();
        assert_eq!(lock, json!({"plugins": []}));
        for dir in [root, package] {
            fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn corrupt_lock_refuses_startup_with_plugin_invalid() {
        let root = config::test_dir();
        assert!(
            Plugins::load(&root, Vec::new(), root.clone())
                .unwrap()
                .list()
                .is_empty()
        );
        let lock = root.join(LOCK);
        for text in [
            "not json",
            r#"{"plugins":[],"extra":1}"#,
            r#"{"plugins":[{"name":"Bad","version":"","installed_at":"","channels":{}}]}"#,
            r#"{"plugins":[{"name":"a","version":"","installed_at":"","channels":{"host":{"command":"./x","args":[],"credential_fields":[],"status_note":""}}}]}"#,
            r#"{"plugins":[{"name":"a","version":"","installed_at":"","channels":{"k":{"command":"./x","args":[],"credential_fields":[],"status_note":""}}},{"name":"b","version":"","installed_at":"","channels":{"k":{"command":"./x","args":[],"credential_fields":[],"status_note":""}}}]}"#,
        ] {
            config::write_private(&lock, text.as_bytes(), !lock.exists()).unwrap();
            assert_eq!(
                Plugins::load(&root, Vec::new(), root.clone()).err(),
                Some(DaemonError::PluginInvalid),
                "{text}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
