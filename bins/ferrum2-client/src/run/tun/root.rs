use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::TunConfig;
use ferrum2_observability::{Role, StrictRouteDiagnosticStatus, emit_strict_route_diagnostic};
use ferrum2_runtime::{NetworkRuntimeOwnerKind, ProcessRoot};

use crate::run::RunError;
use crate::run::context::{ClientContext, ClientRouting};

use super::network_lifecycle::{ClientNetworkResetRuntime, TunNetworkServices};
use super::observation::record_tun_event;
use super::tcp::run_tcp;
use super::udp::{SyntheticDns, run_udp};

pub(in crate::run) fn process_root(
    config: TunConfig,
    udp_idle_timeout: Duration,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    network: TunNetworkServices,
    direct_binder: bool,
) -> ProcessRoot<RunError> {
    let TunNetworkServices {
        coordinator: network_reset_coordinator,
        underlay,
        network_interface_catalog,
        #[cfg(all(windows, not(test)))]
        network_socket_service,
    } = network;
    let strict_route_requested = config.strict_route_requested();
    let strict_route = config.strict_route_effective();
    let synthetic_dns = SyntheticDns {
        ipv4: config.ipv4_dns_address,
        ipv6: config.ipv6_dns_address,
    };
    let metrics = Arc::clone(&context.metrics);
    metrics.set_tun_strict_route_requested(strict_route_requested);
    metrics.set_tun_strict_route_effective(strict_route);
    if !strict_route_requested {
        emit_strict_route_diagnostic(Role::Client, StrictRouteDiagnosticStatus::NotRequested);
    } else if !strict_route {
        emit_strict_route_diagnostic(
            Role::Client,
            StrictRouteDiagnosticStatus::RequestedIneffective,
        );
    }
    let initial_network_generation = network_reset_coordinator.status().published_generation();
    let network_reset = Arc::new(ClientNetworkResetRuntime::new(
        &context,
        network_reset_coordinator,
        #[cfg(all(windows, not(test)))]
        network_socket_service,
    ));
    let event_snapshots = network_reset.coordinator.snapshots();
    let handler_context = Arc::clone(&context);
    let udp_context = Arc::clone(&context);
    let tcp_routing = Arc::clone(&routing);
    let tcp_network_reset = Arc::clone(&network_reset);
    let udp_network_reset = Arc::clone(&network_reset);
    let reset_driver = Arc::clone(&network_reset);
    ferrum2_tun::process_root(ferrum2_tun::TunRootRequest {
        config: ferrum2_tun::Config {
            adapter_name: config.adapter_name,
            ipv4: config
                .ipv4_address
                .map(|network| (network.addr(), network.prefix_len())),
            ipv6: config
                .ipv6_address
                .map(|network| (network.addr(), network.prefix_len())),
            mtu: config.mtu,
            ring_capacity: config.ring_capacity,
            ready_timeout: config.ready_timeout,
            max_tcp_flows: config.max_tcp_flows,
            tcp_timeout: context.runtime.idle_timeout,
            udp_timeout: udp_idle_timeout,
            max_udp_mappings: config.max_udp_mappings,
            udp_filtering: match config.udp_filtering {
                ferrum2_config::UdpFiltering::AddressDependent => {
                    ferrum2_tun::UdpFiltering::AddressDependent
                }
                ferrum2_config::UdpFiltering::EndpointIndependent => {
                    ferrum2_tun::UdpFiltering::EndpointIndependent
                }
            },
            capture_routes: config
                .capture_routes
                .into_iter()
                .map(|route| (route.network(), route.prefix_len()))
                .collect(),
            physical_endpoints: config.physical_endpoints,
            default_binder: direct_binder,
            ipv4_dns_address: synthetic_dns.ipv4,
            ipv6_dns_address: synthetic_dns.ipv6,
            strict_route,
        },
        initial_network_generation,
        underlay,
        network_catalog: network_interface_catalog,
        startup: RunError::StartupProtocol,
        runtime: RunError::RuntimeRoot,
        cleanup: RunError::ShutdownCleanup,
        registry: context.registry.clone(),
        udp_buffer_budget: context
            .egress
            .udp
            .as_ref()
            .expect("TUN preparation always creates its UDP context")
            .tun_budget
            .clone(),
        handle_tcp: Arc::new(move |flow, cancellation, session_cancellation| {
            let context = Arc::clone(&handler_context);
            let routing = Arc::clone(&tcp_routing);
            let network_reset = Arc::clone(&tcp_network_reset);
            Box::pin(async move {
                let generation = network_reset.coordinator.status().published_generation();
                let Ok(mut owner) = network_reset
                    .coordinator
                    .register_runtime_owner(generation, NetworkRuntimeOwnerKind::TcpConnection)
                else {
                    return;
                };
                let source = flow.source();
                tokio::select! {
                    _ = owner.cancelled() => {}
                    _ = run_tcp(
                        source,
                        flow.target(),
                        flow,
                        cancellation,
                        context,
                        routing,
                        inbound,
                        synthetic_dns,
                        Some(session_cancellation),
                    ) => {}
                }
            })
        }),
        handle_udp: Arc::new(move |candidate, cancellation, session_cancellation| {
            let context = Arc::clone(&udp_context);
            let routing = Arc::clone(&routing);
            let network_reset = Arc::clone(&udp_network_reset);
            Box::pin(async move {
                let generation = network_reset.coordinator.status().published_generation();
                let Ok(mut owner) = network_reset
                    .coordinator
                    .register_runtime_owner(generation, NetworkRuntimeOwnerKind::UdpAssociation)
                else {
                    return;
                };
                tokio::select! {
                    _ = owner.cancelled() => {}
                    _ = run_udp(
                        candidate,
                        cancellation,
                        context,
                        routing,
                        inbound,
                        synthetic_dns,
                        session_cancellation,
                    ) => {}
                }
            })
        }),
        handle_network_lifecycle: Arc::new(move |snapshot, lifecycle| {
            let network_reset = Arc::clone(&reset_driver);
            Box::pin(async move { network_reset.transition(snapshot, lifecycle).await })
        }),
        events: Arc::new(move |event| {
            record_tun_event(&metrics, event, || event_snapshots.generation())
        }),
    })
}
