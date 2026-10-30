use crate::{
    DaemonError, InitOptions, InitResult,
    config::{self, Config, DIRECTORIES, HBA, Hosts},
    pg::{self, Postgres},
};
use std::fs;

pub async fn init(options: InitOptions) -> Result<InitResult, DaemonError> {
    config::validate_path(&options.data_dir)?;
    if !options.pg_bin_dir.is_absolute() {
        return Err(DaemonError::InvalidArguments);
    }
    match fs::symlink_metadata(&options.data_dir) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(DaemonError::DataDirPermissionsInvalid);
            }
            if fs::read_dir(&options.data_dir)
                .map_err(|_| DaemonError::InitFailed)?
                .next()
                .is_some()
            {
                return Err(DaemonError::DataDirNotEmpty);
            }
            config::check(&options.data_dir, true)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(DaemonError::InitFailed),
    }
    pg::verify_binaries(&options.pg_bin_dir).await?;
    // Tighten creation in this foreground process; all files additionally request explicit modes.
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    if !options.data_dir.exists() {
        config::make_dir(&options.data_dir)?;
    }
    let root = &options.data_dir;
    for name in DIRECTORIES {
        // initdb requires its target to be absent or empty; the directory remains private either way.
        config::make_dir(&root.join(name))?;
    }
    for name in ["keys/vault-kek.key", "keys/app-master.key"] {
        let mut key = [0; 32];
        getrandom::fill(&mut key).map_err(|_| DaemonError::InitFailed)?;
        config::write_private(&root.join(name), &key, true).map_err(|_| DaemonError::InitFailed)?;
    }
    let password = config::hex_random(32)?;
    config::write_private(&root.join("pg/password"), password.as_bytes(), true)
        .map_err(|_| DaemonError::InitFailed)?;
    let config = Config {
        deployment_id: format!("omb-local-{}", config::hex_random(16)?),
        pg_bin_dir: options.pg_bin_dir.clone(),
        hosts: Hosts::default(),
    };
    let pwfile = root.join("pg/initdb-password");
    config::write_private(&pwfile, password.as_bytes(), true)
        .map_err(|_| DaemonError::InitFailed)?;
    let args = vec![
        "-D".into(),
        root.join("pg/data").into_os_string(),
        "-U".into(),
        "openmybot".into(),
        "--auth=scram-sha-256".into(),
        format!("--pwfile={}", pwfile.display()).into(),
        "-E".into(),
        "UTF8".into(),
        "--locale=C".into(),
    ];
    let result = pg::tool(&options.pg_bin_dir.join("initdb"), &args).await;
    let removed = fs::remove_file(&pwfile).map_err(|_| DaemonError::InitFailed);
    result.map_err(|_| DaemonError::InitFailed)?;
    removed?;
    config::write_private(&root.join("pg/data/pg_hba.conf"), HBA, false)
        .map_err(|_| DaemonError::InitFailed)?;
    let encoded = toml::to_string(&config).map_err(|_| DaemonError::InitFailed)?;
    config::write_private(&root.join("config.toml"), encoded.as_bytes(), true)
        .map_err(|_| DaemonError::InitFailed)?;
    let mut pg = Postgres::start(root, &config).await?;
    let result = pg.create_database().await;
    let stopped = pg.stop().await;
    stopped?;
    result?;
    // Writing the package is a daemon-start responsibility, after the engine is initialized.
    Ok(InitResult {
        deployment_id: config.deployment_id,
    })
}
