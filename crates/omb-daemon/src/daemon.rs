use crate::{
    DaemonError, DaemonOptions, StatusSnapshot, config,
    control::{self, ControlState, ENGINE_PIN},
    engine,
    pg::{self, Postgres},
};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};

pub async fn daemon(options: DaemonOptions) -> Result<(), DaemonError> {
    let root = &options.data_dir;
    let _lock = config::lock(root)?;
    let config = config::load(root)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| DaemonError::InternalError)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| DaemonError::InternalError)?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    pg::stop_stale(root, &config).await?;
    config::remove_runtime(root, "run/control.sock")?;
    config::remove_runtime(root, "run/control.token")?;
    let mut postgres = Postgres::start(root, &config).await?;
    let mut engine = None;
    let mut token_id = None;
    use sha2::Digest as _;
    let result=async {
        let prepared=engine::prepare(root,&config.deployment_id,&mut postgres).await?;
        let token=config::hex_random(config::TOKEN_BYTES).map_err(|_|DaemonError::ControlTokenFailed)?;
        config::write_private(&root.join("run/control.token"),token.as_bytes(),true).map_err(|_|DaemonError::ControlTokenFailed)?;
        let current_token_id=uuid::Uuid::now_v7();
        token_id=Some(current_token_id);
        let token_sha256:[u8;32]=sha2::Sha256::digest(token.as_bytes()).into();
        postgres.start_control_token(omb_store::ControlTokenStart{token_id:current_token_id,token_sha256,daemon_pid:i32::try_from(std::process::id()).map_err(|_|DaemonError::ControlTokenFailed)?,engine_pin:ENGINE_PIN,omb_version:env!("CARGO_PKG_VERSION")}).await?;
        engine=Some(engine::assemble(root,prepared).await?);
        let path=root.join("run/control.sock");
        let listener=UnixListener::bind(&path).map_err(|_|DaemonError::ControlSocketFailed)?;
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).map_err(|_|DaemonError::ControlSocketFailed)?;
        config::check(&path,false)?;
        let state=ControlState::new(token,StatusSnapshot{
            deployment_id:config.deployment_id,daemon_pid:std::process::id(),pg_pid:postgres.pid(),
            pg_server_version_num:postgres.version,daemon_version:env!("CARGO_PKG_VERSION").into(),engine_pin:ENGINE_PIN.into(),authentication_failures:0,
        });
        let mut connections=JoinSet::new();
        let mut health=tokio::time::interval(Duration::from_millis(200));
        let outcome=loop {
            tokio::select! {
                _=interrupt.recv()=>break Ok(()),
                _=terminate.recv()=>break Ok(()),
                _=health.tick()=>{
                    match postgres.is_alive() {
                        Ok(true)=>(),
                        Ok(false)|Err(_)=>break Err(DaemonError::PgStartFailed),
                    }
                },
                accepted=listener.accept()=>match accepted {
                    Ok((stream,_))=>{if connections.len()<64 {connections.spawn(control::handle(stream,Arc::clone(&state)));}},
                    Err(_)=>break Err(DaemonError::ControlSocketFailed),
                },
                finished=connections.join_next(),if !connections.is_empty()=>{
                    if finished.is_some_and(|r|r.is_err()){break Err(DaemonError::ControlSocketFailed);}
                },
            }
        };
        drop(listener);
        connections.abort_all();while connections.join_next().await.is_some() {}
        outcome
    }.await;
    if let Some(engine) = engine {
        engine.shutdown().await;
    }
    let revoked = match token_id {
        Some(id) => postgres.stop_control_token(id).await,
        None => Ok(()),
    };
    let stopped = postgres.stop().await;
    let socket = config::remove_runtime(root, "run/control.sock");
    let token = config::remove_runtime(root, "run/control.token");
    stopped?;
    socket?;
    token?;
    result?;
    revoked
}
