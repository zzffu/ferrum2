use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use ferrum2_config::UdpConfig;
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_crypto::{Clock as _, SystemClock};
use ferrum2_net::{DialOptions, RouteNetworkOptions, UdpResolver};
use ferrum2_observability::Metrics;
use ferrum2_rule::RuleEvaluationScratch;
use ferrum2_runtime::{
    DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSocketFactory, MAX_UDP_RESOLVED_CANDIDATES,
    MAX_UDP_WIRE_DATAGRAM_BYTES, OwnerRegistry, UdpBufferReservation, UdpRuntimeError,
    UdpRuntimeLimits, UdpSessionManager,
};
use ferrum2_shadowsocks::{UdpPacketError, UdpServer};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralHub, StructuralLocal};

use crate::run::network::ServerNetworkSocketService;
use crate::run::routing::ServerRouting;
use crate::run::{RunError, dns_egress, run_error_for_rule_compile};

use super::identity::UdpMappings;
use super::listener::{
    ServerUdpListener, ServerUdpResponseHandler, ServerUdpRuntime, UDP_RECONCILE_INTERVAL,
};
#[cfg(test)]
use super::physical::ServerSystemUdpSocketFactory;
use super::physical::{ServerNetworkUdpSocketFactory, ServerUdpNetworkPolicy};
use super::response_codec::ResponseCodecPool;
use super::response_codec::maximum_response_codec_reservation_bytes;

pub(in crate::run) fn udp_runtime_limits(config: &UdpConfig) -> Option<UdpRuntimeLimits> {
    UdpRuntimeLimits::new(
        config.max_sessions,
        config.max_buffered_bytes,
        config.idle_timeout,
    )
    .ok()
}

pub(in crate::run) fn validate_udp_listener_budget(
    config: &UdpConfig,
    inbound_count: usize,
) -> Result<(), RunError> {
    if !config.enabled {
        return Ok(());
    }
    let roots = inbound_count
        .checked_mul(config.receive_workers)
        .ok_or(RunError::StartupProtocol)?;
    let per_root = maximum_response_codec_reservation_bytes(config.max_sessions)
        .and_then(|codec| codec.checked_add(MAX_UDP_WIRE_DATAGRAM_BYTES))
        .ok_or(RunError::StartupProtocol)?;
    let fixed = roots
        .checked_mul(per_root)
        .ok_or(RunError::StartupProtocol)?;
    if fixed > config.max_buffered_bytes {
        return Err(RunError::StartupProtocol);
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct ServerUdpNetworkPolicies {
    pub(super) outbound_dial_options: Arc<[DialOptions]>,
    pub(super) route_network: Arc<RouteNetworkOptions>,
}

pub(in crate::run) struct PreparedUdpServer<L, F>
where
    L: ServerUdpListener,
    F: DirectUdpSocketFactory<OpenContext = Option<ServerUdpNetworkPolicy>>,
{
    pub(super) inbound: usize,
    pub(super) routing: Arc<ServerRouting>,
    pub(super) listener: Arc<L>,
    pub(super) protocol: Arc<UdpServer>,
    pub(super) clock: Arc<SystemClock>,
    pub(super) config: UdpConfig,
    pub(super) registry: OwnerRegistry,
    pub(super) metrics: Arc<Metrics>,
    pub(super) direct_resolvers: Arc<[dns_egress::ServerDnsResolver]>,
    pub(super) connect_timeout: std::time::Duration,
    pub(super) network_policies: Option<ServerUdpNetworkPolicies>,
    pub(super) runtime: ServerUdpRuntime<L, F>,
    pub(super) mappings: Arc<UdpMappings>,
    pub(super) admission: Arc<tokio::sync::Mutex<()>>,
    pub(super) route_scratch: RuleEvaluationScratch,
    pub(super) wire: BytesMut,
    pub(super) maintenance: tokio::time::Interval,
    pub(super) _receive_wire: UdpBufferReservation,
    #[cfg(feature = "structural-metrics")]
    pub(super) structural: StructuralLocal,
}

#[derive(Clone)]
pub(in crate::run) struct ServerUdpShared {
    pub(in crate::run) routing: Arc<ServerRouting>,
    pub(in crate::run) protocol: Arc<UdpServer>,
    pub(in crate::run) clock: Arc<SystemClock>,
    pub(in crate::run) config: UdpConfig,
    pub(in crate::run) sessions: UdpSessionManager,
    pub(in crate::run) mappings: Arc<UdpMappings>,
    pub(in crate::run) admission: Arc<tokio::sync::Mutex<()>>,
    pub(in crate::run) connect_timeout: std::time::Duration,
    pub(in crate::run) direct_resolvers: Arc<[dns_egress::ServerDnsResolver]>,
    pub(in crate::run) registry: OwnerRegistry,
    pub(in crate::run) metrics: Arc<Metrics>,
    #[cfg(feature = "structural-metrics")]
    pub(in crate::run) structural: StructuralHub,
}

#[cfg(test)]
pub(super) fn prepare_udp_server<L>(
    inbound: usize,
    listener: Arc<L>,
    shared: ServerUdpShared,
) -> Result<PreparedUdpServer<L, ServerSystemUdpSocketFactory>, RunError>
where
    L: ServerUdpListener,
{
    prepare_udp_server_with_socket_factory(inbound, listener, shared, ServerSystemUdpSocketFactory)
}

pub(in crate::run) fn prepare_udp_server_with_network<L>(
    inbound: usize,
    listener: Arc<L>,
    shared: ServerUdpShared,
    sockets: Arc<ServerNetworkSocketService>,
    outbound_dial_options: Arc<[DialOptions]>,
    route_network: Arc<RouteNetworkOptions>,
) -> Result<PreparedUdpServer<L, ServerNetworkUdpSocketFactory>, RunError>
where
    L: ServerUdpListener,
{
    let metrics = Arc::clone(&shared.metrics);
    prepare_udp_server_with_socket_factory_and_policies(
        inbound,
        listener,
        shared,
        ServerNetworkUdpSocketFactory { sockets, metrics },
        Some(ServerUdpNetworkPolicies {
            outbound_dial_options,
            route_network,
        }),
    )
}

#[cfg(test)]
pub(super) fn prepare_udp_server_with_socket_factory<L, F>(
    inbound: usize,
    listener: Arc<L>,
    shared: ServerUdpShared,
    socket_factory: F,
) -> Result<PreparedUdpServer<L, F>, RunError>
where
    L: ServerUdpListener,
    F: DirectUdpSocketFactory<OpenContext = Option<ServerUdpNetworkPolicy>>,
{
    prepare_udp_server_with_socket_factory_and_policies(
        inbound,
        listener,
        shared,
        socket_factory,
        None,
    )
}

fn prepare_udp_server_with_socket_factory_and_policies<L, F>(
    inbound: usize,
    listener: Arc<L>,
    shared: ServerUdpShared,
    socket_factory: F,
    network_policies: Option<ServerUdpNetworkPolicies>,
) -> Result<PreparedUdpServer<L, F>, RunError>
where
    L: ServerUdpListener,
    F: DirectUdpSocketFactory<OpenContext = Option<ServerUdpNetworkPolicy>>,
{
    let ServerUdpShared {
        routing,
        protocol,
        clock,
        config,
        sessions,
        mappings,
        admission,
        connect_timeout,
        direct_resolvers,
        registry,
        metrics,
        #[cfg(feature = "structural-metrics")]
        structural,
    } = shared;
    #[cfg(feature = "structural-metrics")]
    let structural = structural.local();
    let budget = sessions.buffer_budget();
    let response_codec = Arc::new(
        ResponseCodecPool::new(budget.clone(), config.max_sessions)
            .map_err(|_| RunError::StartupProtocol)?,
    );
    let handler = ServerUdpResponseHandler {
        listener: Arc::clone(&listener),
        protocol: Arc::clone(&protocol),
        mappings: Arc::clone(&mappings),
        clock: Arc::clone(&clock),
        codec: Arc::clone(&response_codec),
        metrics: Arc::clone(&metrics),
        #[cfg(feature = "structural-metrics")]
        structural: structural.clone(),
    };
    let default_resolver = direct_resolvers
        .first()
        .cloned()
        .ok_or(RunError::StartupProtocol)?;
    let runtime = DirectUdpRuntime::with_shared_adapters(
        sessions,
        connect_timeout,
        default_resolver.for_inbound(inbound),
        socket_factory,
        handler,
        registry.clone(),
    );
    let receive_wire = budget
        .reserve(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| RunError::StartupProtocol)?;
    let wire = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
    if wire.capacity() != receive_wire.capacity() {
        return Err(RunError::StartupProtocol);
    }
    let mut maintenance = tokio::time::interval(UDP_RECONCILE_INTERVAL);
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let route_scratch = routing
        .route_scratch()
        .map_err(run_error_for_rule_compile)?;
    Ok(PreparedUdpServer {
        inbound,
        routing,
        listener,
        protocol,
        clock,
        config,
        registry,
        metrics,
        direct_resolvers,
        connect_timeout,
        network_policies,
        runtime,
        mappings,
        admission,
        route_scratch,
        wire,
        maintenance,
        _receive_wire: receive_wire,
        #[cfg(feature = "structural-metrics")]
        structural,
    })
}

pub(super) fn reconcile_udp_generations<R, F, H>(
    runtime: &DirectUdpRuntime<R, F, H>,
    mappings: &UdpMappings,
) where
    R: ferrum2_net::UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    F: ferrum2_runtime::DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    mappings.reconcile_runtime(runtime.sessions());
}

pub(super) fn protocol_identity_has_capacity<R, F, H>(
    runtime: &DirectUdpRuntime<R, F, H>,
    mappings: &UdpMappings,
    protocol: &UdpServer,
    clock: &SystemClock,
    max_sessions: usize,
) -> Result<bool, UdpPacketError>
where
    R: ferrum2_net::UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    F: ferrum2_runtime::DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    reconcile_udp_generations(runtime, mappings);
    mappings.prune_protocol(protocol, clock.monotonic_now());
    Ok(protocol.session_count()? < max_sessions)
}

pub(super) async fn resolve_udp_selection_candidates<R>(
    resolver: &R,
    target: &TargetAddr,
    timeout: std::time::Duration,
) -> Result<Vec<SocketAddr>, UdpRuntimeError>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
{
    if let Some(destination) = target.as_socket_addr() {
        return Ok(vec![destination]);
    }
    let TargetHostRef::Domain(host) = target.host() else {
        return Err(UdpRuntimeError::Resolve);
    };
    let candidates = tokio::time::timeout(timeout, resolver.resolve(host, target.port().get()))
        .await
        .map_err(|_| UdpRuntimeError::Resolve)?
        .map_err(|_| UdpRuntimeError::Resolve)?;
    let candidates: Vec<_> = candidates
        .into_iter()
        .take(MAX_UDP_RESOLVED_CANDIDATES)
        .collect();
    if candidates.is_empty() {
        Err(UdpRuntimeError::Resolve)
    } else {
        Ok(candidates)
    }
}
