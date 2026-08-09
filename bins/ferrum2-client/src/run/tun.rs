use std::sync::Arc;

use ferrum2_config::TunConfig;
use ferrum2_core::TargetAddr;
use ferrum2_runtime::{ProcessCancellation, ProcessRoot, relay_lifecycle};

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::routing::{ClientTerminalRoute, ReplayIo, relay_hijacked_tcp};
use super::tokio_io::TokioFramed;

pub(super) fn process_root(
    config: TunConfig,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
) -> ProcessRoot<RunError> {
    let metrics = Arc::clone(&context.metrics);
    let accepted_metrics = Arc::clone(&metrics);
    let handler_context = Arc::clone(&context);
    ferrum2_tun::process_root(
        ferrum2_tun::Config {
            adapter_name: config.adapter_name,
            ipv4: config.ipv4_address.addr(),
            ipv4_prefix: config.ipv4_address.prefix_len(),
            ipv6: config.ipv6_address.addr(),
            ipv6_prefix: config.ipv6_address.prefix_len(),
            mtu: config.mtu,
            ring_capacity: config.ring_capacity,
            ready_timeout: config.ready_timeout,
            max_tcp_flows: config.max_tcp_flows,
            tcp_buffer_bytes: config.tcp_buffer_bytes,
            tcp_timeout: context.runtime.idle_timeout,
            max_udp_mappings: config.max_udp_mappings,
            max_udp_buffered_bytes: config.max_udp_buffered_bytes,
            owned_buffer_bytes: config.owned_buffer_bytes,
        },
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
        move |flow, cancellation| {
            let context = Arc::clone(&handler_context);
            let routing = Arc::clone(&routing);
            Box::pin(run_tcp(flow, cancellation, context, routing, inbound))
        },
        move || accepted_metrics.tun_packet_accepted(),
        move || metrics.tun_packet_foundation_dropped(),
    )
}

async fn run_tcp(
    mut flow: ferrum2_tun::TcpFlow,
    mut cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
) {
    let Ok(target) = TargetAddr::ip(flow.target()) else {
        return;
    };
    let Some(selection) = routing
        .select_tcp(
            inbound,
            &target,
            &mut flow,
            cancellation.clone().forced(),
            &context.registry,
            &context.metrics,
        )
        .await
    else {
        return;
    };
    let mut flow = ReplayIo::new(flow, selection.prefix);
    match selection.terminal {
        ClientTerminalRoute::Reject => {}
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                return;
            };
            relay_hijacked_tcp(
                &mut flow,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                cancellation.forced(),
            )
            .await;
        }
        ClientTerminalRoute::Route(plan) => {
            let opened = tokio::select! {
                _ = cancellation.forced() => return,
                opened = context.egress.open_tcp(
                    plan,
                    &target,
                    None,
                    #[cfg(test)]
                    None,
                ) => opened,
            };
            let Ok(opened) = opened else {
                return;
            };
            let mut opened = TokioFramed::new(opened);
            let _ = relay_lifecycle(
                &mut flow,
                &mut opened,
                context.runtime.idle_timeout,
                &context.registry,
                cancellation.forced(),
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ferrum2_runtime::{
        OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
        ProcessSupervisor,
    };
    use tokio::sync::Notify;

    use super::super::{RunError, report_result};

    struct NeverPrepared;

    impl PreparedProcessRoot<RunError> for NeverPrepared {
        fn activate(&mut self) -> Result<(), RunError> {
            Ok(())
        }

        fn run(
            self: Box<Self>,
            _cancellation: ProcessCancellation,
        ) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }

        fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn cancelled_prepare_cleanup_failure_maps_to_shutdown_cleanup() {
        let entered = Arc::new(Notify::new());
        let prepare_entered = Arc::clone(&entered);
        let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
            prepare_entered.notify_one();
            cancellation.cancelled().await;
            Err::<Option<NeverPrepared>, _>(RunError::ShutdownCleanup)
        });
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
                .expect("one required root");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        entered.notified().await;
        shutdown_tx.send(()).expect("shutdown");
        let report = run.await.expect("process owner");
        assert_eq!(report_result(report), Err(RunError::ShutdownCleanup));
    }
}
