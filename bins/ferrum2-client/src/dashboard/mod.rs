mod config;
mod controller;
mod http;
mod sampling;

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use ferrum2_dashboard::Dashboard;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

/// Explicit local management settings; authentication never enters network configuration.
pub(crate) struct Options {
    pub(crate) listen: SocketAddr,
    pub(crate) token_file: PathBuf,
    pub(crate) details: bool,
}

pub(crate) fn run(path: PathBuf, options: Options) -> Result<(), &'static str> {
    if !options.listen.ip().is_loopback() {
        return Err("dashboard.loopback_required");
    }
    let token = read_token(options.token_file)?;
    let dashboard = Dashboard::new(options.details);
    let log_level = Arc::new(std::sync::atomic::AtomicU8::new(
        ferrum2_observability::LogLevel::Info as u8,
    ));
    let controller = controller::Controller::new(path, dashboard.clone(), Arc::clone(&log_level))?;
    let writer_dashboard = dashboard.clone();
    let subscriber = ferrum2_observability::json_subscriber(
        move || sampling::LogWriter::new(writer_dashboard.clone()),
        move || sampling::log_level(&log_level),
    );
    tracing::subscriber::set_global_default(subscriber).map_err(|_| "dashboard.observability")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "dashboard.runtime")?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(options.listen)
            .await
            .map_err(|_| "dashboard.bind")?;
        let address = listener.local_addr().map_err(|_| "dashboard.bind")?;
        let snapshot = Arc::new(RwLock::new(Bytes::from(dashboard.snapshot().to_string())));
        let (commands, requests) = mpsc::channel(16);
        let state = Arc::new(http::HttpState {
            address,
            token,
            commands,
            snapshot: Arc::clone(&snapshot),
        });
        let (stop, stopped) = watch::channel(false);
        let mut owners = JoinSet::new();
        owners.spawn(http::serve(listener, state, stopped.clone()));
        owners.spawn(controller.run(requests, stopped.clone()));
        owners.spawn(sampling::run(dashboard, snapshot, stopped));
        // This is the local public UI address, never a peer or a configuration secret.
        let _ = writeln!(std::io::stderr().lock(), "dashboard: http://{address}/");
        let result = tokio::select! {
            _ = crate::run::shutdown_signal() => Ok(()),
            result = owners.join_next() => match result {
                Some(Ok(Err(code))) => Err(code),
                Some(Ok(Ok(()))) | Some(Err(_)) | None => Err("dashboard.owner_stopped"),
            },
        };
        let _ = stop.send(true);
        let mut cleanup = Ok(());
        while let Some(owner) = owners.join_next().await {
            match owner {
                Ok(Ok(())) => {}
                Ok(Err(code)) => cleanup = Err(code),
                Err(_) => cleanup = Err("dashboard.owner_join"),
            }
        }
        cleanup.and(result)
    })
}

fn read_token(path: PathBuf) -> Result<Vec<u8>, &'static str> {
    let before = std::fs::symlink_metadata(&path).map_err(|_| "dashboard.token_file")?;
    if !before.is_file() {
        return Err("dashboard.token_file");
    }
    let file = std::fs::File::open(path).map_err(|_| "dashboard.token_file")?;
    let metadata = file.metadata().map_err(|_| "dashboard.token_file")?;
    if !metadata.is_file() || metadata.len() > 258 {
        return Err("dashboard.token_format");
    }
    #[cfg(windows)]
    ferrum2_platform_windows::validate_private_file(&file)
        .map_err(|_| "dashboard.token_permissions")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let pid = sysinfo::get_current_pid().map_err(|_| "dashboard.token_permissions")?;
        let mut process = sysinfo::System::new();
        process.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_user(sysinfo::UpdateKind::Always),
        );
        let owner = process
            .process(pid)
            .and_then(sysinfo::Process::user_id)
            .is_some_and(|uid| **uid == metadata.uid());
        if metadata.mode() & 0o077 != 0 || !owner {
            return Err("dashboard.token_permissions");
        }
    }
    let mut token = Vec::with_capacity(258);
    file.take(259)
        .read_to_end(&mut token)
        .map_err(|_| "dashboard.token_file")?;
    while matches!(token.last(), Some(b'\r' | b'\n')) {
        token.pop();
    }
    if !(32..=256).contains(&token.len()) || !token.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err("dashboard.token_format");
    }
    Ok(token)
}
