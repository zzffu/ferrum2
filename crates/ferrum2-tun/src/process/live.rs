use std::sync::Arc;
use std::time::Instant;

use ferrum2_runtime::{ProcessCancellation, ProcessRoot};

use super::TunRootRequest;
use super::limits::runtime_limits_are_exact;
use crate::lifecycle::owner_main;
use crate::{
    NativeLifecycleOwner, OwnerControl, OwnerExit, OwnerSessionServices, PreparationFailure,
    RunOwner, TunEventSink, TunRoot,
};

pub(super) fn build<E>(request: TunRootRequest<E>) -> ProcessRoot<E>
where
    E: Copy + Send + 'static,
{
    ProcessRoot::new_cancellable(move |cancellation| prepare(request, cancellation))
}

async fn prepare<E>(
    request: TunRootRequest<E>,
    cancellation: ProcessCancellation,
) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    let TunRootRequest {
        config,
        initial_network_generation,
        underlay,
        network_catalog,
        startup,
        runtime,
        cleanup,
        registry,
        handle_tcp,
        handle_udp,
        handle_network_lifecycle,
        events,
    } = request;
    if !runtime_limits_are_exact(&config) {
        return Err(startup);
    }
    let events = TunEventSink::new(move |event| events(event));
    underlay.set_event_sink(events.clone());
    let deadline = Instant::now()
        .checked_add(config.ready_timeout)
        .unwrap_or_else(Instant::now);
    let max_udp_associations = config.max_udp_mappings;
    let (flow_sender, flows) = tokio::sync::mpsc::channel(config.max_tcp_flows);
    let (datagram_sender, datagrams) = tokio::sync::mpsc::channel(max_udp_associations);
    let control = OwnerControl::new();
    let owner_registry = registry.clone();
    let (mut owner, done) = NativeLifecycleOwner::spawn(
        control.clone(),
        Box::new(move |link, control| {
            owner_main(
                config,
                initial_network_generation,
                control,
                deadline,
                OwnerSessionServices {
                    registry: owner_registry,
                    network_catalog,
                    events,
                    underlay,
                    flow_output: flow_sender,
                    datagram_output: datagram_sender,
                    network_lifecycle_output: link,
                    max_udp_associations,
                },
            )
        }),
    )
    .map_err(|_| startup)?;
    match owner
        .prepare(&handle_network_lifecycle, cancellation, deadline)
        .await
    {
        Ok(work) => {
            owner.work = work;
            Ok(Some(TunRoot {
                owner: RunOwner::new(owner),
                done,
                runtime: Some(runtime),
                cleanup: Some(cleanup),
                flows,
                datagrams,
                flow_count: Arc::clone(&control.flow_count),
                association_count: Arc::clone(&control.association_count),
                registry,
                handle_tcp,
                handle_udp,
                handle_network_lifecycle,
            }))
        }
        Err(PreparationFailure::Stopped) => cancel_prepare(owner, cleanup).await,
        Err(PreparationFailure::Failed) => Err(prepare_failure(owner, startup, cleanup).await),
    }
}

async fn cancel_prepare<E>(owner: NativeLifecycleOwner, cleanup: E) -> Result<Option<TunRoot<E>>, E>
where
    E: Copy + Send + 'static,
{
    if owner.reap().await == OwnerExit::CleanupFailed {
        Err(cleanup)
    } else {
        Ok(None)
    }
}

async fn prepare_failure<E>(owner: NativeLifecycleOwner, startup: E, cleanup: E) -> E
where
    E: Copy + Send + 'static,
{
    if owner.reap().await == OwnerExit::CleanupFailed {
        cleanup
    } else {
        startup
    }
}
