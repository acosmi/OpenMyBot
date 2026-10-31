use crate::{
    DaemonError, DaemonOptions, StatusSnapshot,
    agent::AgentRuntime,
    channels::{Channels, Outbound},
    config,
    control::{self, ControlState, ENGINE_PIN},
    engine,
    ops::{BindingRunCanceller, CancelQueue, Ops, ReceiverCommand, ThreadMinter},
    pg::{self, Postgres},
};
use omb_channels::{
    CANCEL_QUEUE, Endpoints, FeishuEndpoint, TERMINAL_QUEUE, TelegramEndpoint, TerminalQueue,
    Timings,
};
use omb_hostdriver::{HostDriver, HostDriverConfig, Limits, VersionWindow};
use openbot_application::RunTerminalNotice;
use openbot_contracts::ids::ActorId;
use openbot_infra::{
    auth::single_user::SINGLE_USER_ACTOR_ID,
    net::safe_http::{EgressPolicy, SafeDialer},
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::UnixListener,
    signal::unix::{SignalKind, signal},
    sync::{Mutex, mpsc},
    task::JoinSet,
};

pub async fn daemon(options: DaemonOptions) -> Result<(), DaemonError> {
    let root = &options.data_dir;
    let _lock = config::lock(root)?;
    let config = config::load(root)?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or(DaemonError::WorkspaceRootInvalid)?;
    let crabcode = config::Crabcode::parse(&config, &home)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| DaemonError::InternalError)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| DaemonError::InternalError)?;
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    pg::stop_stale(root, &config).await?;
    config::remove_runtime(root, "run/control.sock")?;
    config::remove_runtime(root, "run/control.token")?;
    let mut postgres = Postgres::start(root, &config).await?;
    let mut engine = None;
    let mut token_id = None;
    let mut channels = None;
    let mut agent = None;
    let mut host: Option<HostDriver> = None;
    let mut host_link = None;
    let mut canceller: Option<CancelQueue> = None;
    let mut control_link = None;
    use sha2::Digest as _;
    let result=async {
        let prepared=engine::prepare(root,&config.deployment_id,&mut postgres).await?;
        let resident=postgres.open_resident_connection("omb-hostdriver").await?;
        host_link=Some(resident.driver);
        let crabcode_binary=crabcode.binary.clone();
        let driver=host.insert(HostDriver::new(HostDriverConfig{binary:crabcode.binary,home,tmp_dir:root.join("hosts/crabcode/tmp"),roots:crabcode.roots.clone(),window:VersionWindow::embedded(),limits:Limits::default()},Arc::new(resident.client)));
        let token=config::hex_random(config::TOKEN_BYTES).map_err(|_|DaemonError::ControlTokenFailed)?;
        config::write_private(&root.join("run/control.token"),token.as_bytes(),true).map_err(|_|DaemonError::ControlTokenFailed)?;
        let current_token_id=uuid::Uuid::now_v7();
        token_id=Some(current_token_id);
        let token_sha256:[u8;32]=sha2::Sha256::digest(token.as_bytes()).into();
        postgres.start_control_token(omb_store::ControlTokenStart{token_id:current_token_id,token_sha256,daemon_pid:i32::try_from(std::process::id()).map_err(|_|DaemonError::ControlTokenFailed)?,engine_pin:ENGINE_PIN,omb_version:env!("CARGO_PKG_VERSION")}).await?;
        let (queue,terminals)=mpsc::channel::<RunTerminalNotice>(TERMINAL_QUEUE);
        let assembled=engine.insert(engine::assemble(root,prepared,driver,Some(Arc::new(TerminalQueue(queue)))).await?);
        agent=Some(AgentRuntime::start(assembled,postgres.database_config())?);
        let control_connection=postgres.open_resident_connection("openmybot-control").await?;
        control_link=Some(control_connection.driver);
        let canceller_connection=postgres.open_resident_connection("openmybot-canceller").await?;
        let (cancel,requests)=mpsc::channel(CANCEL_QUEUE);
        let (receiver,mut commands)=mpsc::channel(8);
        let dialer=SafeDialer::new(EgressPolicy::default());
        let endpoints=Endpoints{telegram:TelegramEndpoint::production(dialer.clone()),feishu:FeishuEndpoint::production(dialer)};
        // The one dispatch gate of the daemon, shared by the dispatcher and the run canceller, and
        // the runs whose begin outcome is unknown.
        let gate=Arc::default();
        let started=channels.insert(Channels::start(&mut postgres,assembled,current_token_id,Timings::default(),endpoints.clone(),cancel,Outbound{terminals,crabcode:crabcode_binary},Arc::clone(&gate)).await?);
        let run_canceller=BindingRunCanceller::new(assembled.assembly.application.clone(),assembled.resolver.clone(),Arc::new(canceller_connection.client),gate);
        canceller=Some(CancelQueue::start(run_canceller.clone(),canceller_connection.driver,requests));
        let ops=Ops{control:Mutex::new(control_connection.client),application:assembled.assembly.application.clone(),resolver:assembled.resolver.clone(),vault:assembled.vault.clone(),owner:ActorId::new(SINGLE_USER_ACTOR_ID),roots:crabcode.roots,endpoints,receiver,wake:started.wake(),minter:ThreadMinter::new(assembled.assembly.application.clone(),assembled.resolver.clone()),canceller:run_canceller,counters:started.status_source().counters};
        let path=root.join("run/control.sock");
        let listener=UnixListener::bind(&path).map_err(|_|DaemonError::ControlSocketFailed)?;
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).map_err(|_|DaemonError::ControlSocketFailed)?;
        config::check(&path,false)?;
        let state=ControlState::new(token,current_token_id,StatusSnapshot{
            deployment_id:config.deployment_id,daemon_pid:std::process::id(),pg_pid:postgres.pid(),
            pg_server_version_num:postgres.version,daemon_version:env!("CARGO_PKG_VERSION").into(),engine_pin:ENGINE_PIN.into(),authentication_failures:0,channels:Vec::new(),
        },Some(started.status_source()),Some(ops));
        let mut connections=JoinSet::new();
        let mut health=tokio::time::interval(Duration::from_millis(200));
        let outcome=loop {
            tokio::select! {
                _=interrupt.recv()=>break Ok(()),
                _=terminate.recv()=>break Ok(()),
                error=started.finished()=>break Err(error),
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
                // Receiver changes run here, where the store handle and the running tasks live.
                Some(command)=commands.recv()=>match command {
                    ReceiverCommand::Start(row,done)=>{let _=done.send(started.start_receiver(&mut postgres,row).await);},
                    ReceiverCommand::Stop(binding_id,done)=>{started.stop_receiver(binding_id).await;let _=done.send(());},
                },
            }
        };
        drop(listener);
        connections.abort_all();while connections.join_next().await.is_some() {}
        if let Some(started)=channels.take() {started.stop().await;}
        if let Some(runner)=canceller.take() {runner.stop().await;}
        if let Some(runtime)=agent.take() {runtime.stop().await;}
        if let Some(driver)=host.take() {driver.shutdown().await;}
        if let Some(link)=host_link.take() {link.abort();let _=link.await;}
        if let Some(link)=control_link.take() {link.abort();let _=link.await;}
        outcome
    }.await;
    if let Some(channels) = channels {
        channels.stop().await;
    }
    if let Some(runner) = canceller {
        runner.stop().await;
    }
    if let Some(runtime) = agent {
        runtime.stop().await;
    }
    if let Some(driver) = host {
        driver.shutdown().await;
    }
    if let Some(link) = host_link {
        link.abort();
        let _ = link.await;
    }
    if let Some(link) = control_link {
        link.abort();
        let _ = link.await;
    }
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
