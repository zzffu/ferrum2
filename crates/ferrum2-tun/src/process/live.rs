use std::time::Duration;

use ferrum2_runtime::{OwnerRegistry, ProcessCancellation, ProcessRoot};

use super::limits::runtime_limits_are_exact;
use super::{NetworkLifecycleHandler, RootErrors, RootSpec, TcpHandler, UdpHandler};
use crate::lifecycle::owner_main;
use crate::{
    Config, NetworkResetBridgeOutcome, OwnerControl, OwnerExit, OwnerReady, OwnerSessionServices,
    OwnerThread, OwnerWake, TunEventSink, TunNetworkLifecycle, TunNetworkResetError, TunRoot,
    UnderlayPublisher, map_owner_spawn,
};

pub(super) fn build<E>(spec: RootSpec<E>) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
{
    ProcessRoot::new_cancellable(move |cancellation| async move {
        let RootSpec {
            config,
            initial_network_generation,
            underlay,
            network_catalog,
            errors,
            registry,
            handle_tcp,
            handle_udp,
            handle_network_lifecycle,
            events,
        } = spec;
        if !runtime_limits_are_exact(&config) {
            return Err(errors.startup);
        }
        underlay.set_event_sink(events.clone());
        prepare(
            config,
            initial_network_generation,
            underlay,
            errors,
            cancellation,
            RootServices {
                registry,
                network_catalog,
                handle_tcp,
                handle_udp,
                handle_network_lifecycle,
                events,
            },
        )
        .await
    })
}

struct RootServices {
    registry: OwnerRegistry,
    network_catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    handle_tcp: TcpHandler,
    handle_udp: UdpHandler,
    handle_network_lifecycle: NetworkLifecycleHandler,
    events: TunEventSink,
}

async fn prepare<E>(
    config: Config,
    initial_network_generation: u64,
    underlay: UnderlayPublisher,
    errors: RootErrors<E>,
    mut cancellation: ProcessCancellation,
    services: RootServices,
) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    let RootServices {
        registry,
        network_catalog,
        handle_tcp,
        handle_udp,
        handle_network_lifecycle,
        events,
    } = services;
    let timeout = config.ready_timeout;
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now);
    let max_udp_associations = config.max_udp_mappings;
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (flow_sender, flows) = tokio::sync::mpsc::channel(config.max_tcp_flows);
    let (datagram_sender, datagrams) = tokio::sync::mpsc::channel(max_udp_associations);
    let (network_reset_sender, network_resets) = tokio::sync::mpsc::channel(1);
    let (done_sender, _done_receiver) = tokio::sync::oneshot::channel();
    let control = OwnerControl::new();
    let owner_control = control.clone();
    let owner_registry = registry.clone();
    let thread = map_owner_spawn(
        std::thread::Builder::new()
            .name("ferrum2-tun-owner".into())
            .spawn(move || {
                let result = owner_main(
                    config,
                    initial_network_generation,
                    owner_control,
                    deadline,
                    OwnerSessionServices {
                        ready: ready_sender,
                        registry: owner_registry,
                        network_catalog,
                        events,
                        underlay,
                        flow_output: flow_sender,
                        datagram_output: datagram_sender,
                        network_lifecycle_output: network_reset_sender,
                        max_udp_associations,
                    },
                );
                let _ = done_sender.send(result);
                result
            }),
        errors.startup,
    )?;
    let guard = OwnerThread {
        control: control.clone(),
        work: OwnerWake::default(),
        thread: Some(thread),
    };
    let mut guard = guard;
    loop {
        if cancellation.is_cancelled() {
            return cancel_prepare(guard, errors.cleanup).await;
        }
        if std::time::Instant::now() >= deadline {
            return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
        }
        match ready_receiver.try_recv() {
            Ok(OwnerReady::Ready {
                work,
                snapshot,
                initialization,
            }) => {
                if std::time::Instant::now() >= deadline {
                    let _ = initialization.send(NetworkResetBridgeOutcome::Stopped);
                    return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
                }
                let mut initialization_cancellation = cancellation.clone();
                let initialized = tokio::select! {
                    biased;
                    () = initialization_cancellation.cancelled() => {
                        NetworkResetBridgeOutcome::Stopped
                    }
                    result = (handle_network_lifecycle)(snapshot, TunNetworkLifecycle::Initialize) => {
                        match result {
                            Ok(()) => NetworkResetBridgeOutcome::Completed,
                            Err(TunNetworkResetError) => NetworkResetBridgeOutcome::Retry,
                        }
                    }
                };
                let _ = initialization.send(initialized);
                if initialized != NetworkResetBridgeOutcome::Completed {
                    return if cancellation.is_cancelled() {
                        cancel_prepare(guard, errors.cleanup).await
                    } else {
                        Err(prepare_failure(guard, errors.startup, errors.cleanup).await)
                    };
                }
                guard.work = work;
                return Ok(Some(TunRoot {
                    owner: guard,
                    done: _done_receiver,
                    runtime: Some(errors.runtime),
                    cleanup: Some(errors.cleanup),
                    flows,
                    datagrams,
                    network_resets,
                    flow_count: control.flow_count,
                    association_count: control.association_count,
                    registry,
                    handle_tcp,
                    handle_udp,
                    handle_network_lifecycle,
                }));
            }
            Ok(OwnerReady::Failed) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(prepare_failure(guard, errors.startup, errors.cleanup).await);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return cancel_prepare(guard, errors.cleanup).await;
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }
}

async fn cancel_prepare<E>(guard: OwnerThread, cleanup: E) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    if guard.reap().await == OwnerExit::CleanupFailed {
        Err(cleanup)
    } else {
        Ok(None)
    }
}

async fn prepare_failure<E>(guard: OwnerThread, startup: E, cleanup: E) -> E
where
    E: Copy + Send + 'static,
{
    if guard.reap().await == OwnerExit::CleanupFailed {
        cleanup
    } else {
        startup
    }
}
