use std::fmt;
use std::fmt::Write as _;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use super::Metrics;
use super::core::TRANSPORTS;
use super::family::{
    CachedCounter, SharedClosedFamily, pair_index, pair_labels, single_labels, u64_gauge,
    usize_counter, usize_gauge,
};
use crate::trace::{
    InterfaceResolutionResult, InterfaceResolutionSource, NetworkFullRebuildReason,
    NetworkLifecycleOperation, NetworkLifecycleResult, NetworkResetReason,
    StrictRouteFilterInstallResult, Transport, TunPacketRejectReason, TunUdpAssociationRouteResult,
    TunUdpResponseDropReason,
};

macro_rules! impl_label_value {
    ($type:ty) => {
        impl EncodeLabelValue for $type {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> fmt::Result {
                encoder.write_str(self.as_str())
            }
        }
    };
}

impl_label_value!(TunPacketRejectReason);
impl_label_value!(TunUdpResponseDropReason);
impl_label_value!(NetworkLifecycleOperation);
impl_label_value!(NetworkLifecycleResult);
impl_label_value!(NetworkResetReason);
impl_label_value!(NetworkFullRebuildReason);
impl_label_value!(StrictRouteFilterInstallResult);
impl_label_value!(InterfaceResolutionSource);
impl_label_value!(InterfaceResolutionResult);
impl_label_value!(TunUdpAssociationRouteResult);

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TunPacketRejectLabels {
    reason: TunPacketRejectReason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TunUdpResponseDropLabels {
    reason: TunUdpResponseDropReason,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct NetworkResetLabels {
    reason: NetworkResetReason,
    result: NetworkLifecycleResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct NetworkFullRebuildLabels {
    reason: NetworkFullRebuildReason,
    result: NetworkLifecycleResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct NetworkAssociationsResetLabels {
    operation: NetworkLifecycleOperation,
    transport: Transport,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct StrictRouteFilterInstallLabels {
    result: StrictRouteFilterInstallResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct InterfaceResolutionLabels {
    source: InterfaceResolutionSource,
    result: InterfaceResolutionResult,
}

#[derive(Debug, prometheus_client::encoding::EncodeLabelSet)]
struct TunUdpAssociationRouteLabels {
    result: TunUdpAssociationRouteResult,
}

const TUN_PACKET_REJECT_REASONS: &[TunPacketRejectReason] = &[
    TunPacketRejectReason::InvalidIpVersion,
    TunPacketRejectReason::FamilyDisabled,
    TunPacketRejectReason::InvalidIpLength,
    TunPacketRejectReason::InvalidIpChecksum,
    TunPacketRejectReason::InvalidExtensionHeader,
    TunPacketRejectReason::UnsupportedIpProtocol,
    TunPacketRejectReason::IcmpEchoUnsupported,
    TunPacketRejectReason::FragmentMalformed,
    TunPacketRejectReason::FragmentOverlap,
    TunPacketRejectReason::FragmentTimeout,
    TunPacketRejectReason::FragmentLimit,
    TunPacketRejectReason::InvalidTransportLength,
    TunPacketRejectReason::InvalidTransportChecksum,
    TunPacketRejectReason::InvalidSource,
    TunPacketRejectReason::InvalidDestination,
    TunPacketRejectReason::IngressFull,
    TunPacketRejectReason::TcpFlowLimit,
    TunPacketRejectReason::UdpAssociationLimit,
    TunPacketRejectReason::UdpCandidateTimeout,
    TunPacketRejectReason::UdpQueueFull,
    TunPacketRejectReason::UdpResponseFiltered,
    TunPacketRejectReason::UdpResponseClosed,
    TunPacketRejectReason::StaleGeneration,
    TunPacketRejectReason::WintunRingFull,
];
const TUN_UDP_RESPONSE_DROP_REASONS: &[TunUdpResponseDropReason] = &[
    TunUdpResponseDropReason::StaleGeneration,
    TunUdpResponseDropReason::AssociationClosed,
    TunUdpResponseDropReason::QueueFull,
    TunUdpResponseDropReason::MalformedResponse,
    TunUdpResponseDropReason::Filtered,
    TunUdpResponseDropReason::InjectionRejected,
    TunUdpResponseDropReason::SessionReset,
    TunUdpResponseDropReason::Shutdown,
    TunUdpResponseDropReason::OwnerFatal,
];
const NETWORK_LIFECYCLE_OPERATIONS: &[NetworkLifecycleOperation] = &[
    NetworkLifecycleOperation::ResetNetwork,
    NetworkLifecycleOperation::FullRebuild,
];
const NETWORK_LIFECYCLE_RESULTS: &[NetworkLifecycleResult] = &[
    NetworkLifecycleResult::Started,
    NetworkLifecycleResult::Succeeded,
    NetworkLifecycleResult::Failed,
];
const NETWORK_RESET_REASONS: &[NetworkResetReason] =
    &[NetworkResetReason::NetworkChange, NetworkResetReason::Retry];
const NETWORK_FULL_REBUILD_REASONS: &[NetworkFullRebuildReason] = &[
    NetworkFullRebuildReason::AdapterDamage,
    NetworkFullRebuildReason::SessionDamage,
    NetworkFullRebuildReason::AddressDamage,
    NetworkFullRebuildReason::RouteDamage,
    NetworkFullRebuildReason::DnsDamage,
    NetworkFullRebuildReason::StrictRouteDamage,
    NetworkFullRebuildReason::OwnershipLedgerDamage,
];
const STRICT_ROUTE_FILTER_INSTALL_RESULTS: &[StrictRouteFilterInstallResult] = &[
    StrictRouteFilterInstallResult::Success,
    StrictRouteFilterInstallResult::Failure,
];
const INTERFACE_RESOLUTION_SOURCES: &[InterfaceResolutionSource] = &[
    InterfaceResolutionSource::OutboundExplicit,
    InterfaceResolutionSource::AutoDetected,
    InterfaceResolutionSource::RouteDefault,
    InterfaceResolutionSource::SystemBestRoute,
];
const INTERFACE_RESOLUTION_RESULTS: &[InterfaceResolutionResult] = &[
    InterfaceResolutionResult::Success,
    InterfaceResolutionResult::Failure,
];
const TUN_UDP_ASSOCIATION_ROUTE_RESULTS: &[TunUdpAssociationRouteResult] = &[
    TunUdpAssociationRouteResult::Success,
    TunUdpAssociationRouteResult::Rejected,
    TunUdpAssociationRouteResult::Failure,
    TunUdpAssociationRouteResult::StaleGeneration,
];

const TUN_PACKET_REJECT_SERIES: usize = TUN_PACKET_REJECT_REASONS.len();
const TUN_UDP_RESPONSE_DROP_SERIES: usize = TUN_UDP_RESPONSE_DROP_REASONS.len();
const NETWORK_RESET_SERIES: usize = NETWORK_RESET_REASONS.len() * NETWORK_LIFECYCLE_RESULTS.len();
const NETWORK_FULL_REBUILD_SERIES: usize =
    NETWORK_FULL_REBUILD_REASONS.len() * NETWORK_LIFECYCLE_RESULTS.len();
const NETWORK_ASSOCIATIONS_RESET_SERIES: usize =
    NETWORK_LIFECYCLE_OPERATIONS.len() * TRANSPORTS.len();
const STRICT_ROUTE_FILTER_INSTALL_SERIES: usize = STRICT_ROUTE_FILTER_INSTALL_RESULTS.len();
const INTERFACE_RESOLUTION_SERIES: usize =
    INTERFACE_RESOLUTION_SOURCES.len() * INTERFACE_RESOLUTION_RESULTS.len();
const TUN_UDP_ASSOCIATION_ROUTE_SERIES: usize = TUN_UDP_ASSOCIATION_ROUTE_RESULTS.len();

type TunPacketRejectFamily =
    SharedClosedFamily<TunPacketRejectLabels, CachedCounter, TUN_PACKET_REJECT_SERIES>;
type TunUdpResponseDropFamily =
    SharedClosedFamily<TunUdpResponseDropLabels, CachedCounter, TUN_UDP_RESPONSE_DROP_SERIES>;
type NetworkResetFamily =
    SharedClosedFamily<NetworkResetLabels, CachedCounter, NETWORK_RESET_SERIES>;
type NetworkFullRebuildFamily =
    SharedClosedFamily<NetworkFullRebuildLabels, CachedCounter, NETWORK_FULL_REBUILD_SERIES>;
type NetworkAssociationsResetFamily = SharedClosedFamily<
    NetworkAssociationsResetLabels,
    CachedCounter,
    NETWORK_ASSOCIATIONS_RESET_SERIES,
>;
type StrictRouteFilterInstallFamily = SharedClosedFamily<
    StrictRouteFilterInstallLabels,
    CachedCounter,
    STRICT_ROUTE_FILTER_INSTALL_SERIES,
>;
type InterfaceResolutionFamily =
    SharedClosedFamily<InterfaceResolutionLabels, CachedCounter, INTERFACE_RESOLUTION_SERIES>;
type TunUdpAssociationRouteFamily = SharedClosedFamily<
    TunUdpAssociationRouteLabels,
    CachedCounter,
    TUN_UDP_ASSOCIATION_ROUTE_SERIES,
>;

pub(super) struct TunMetrics {
    tun_packets_accepted: Counter,
    tun_packets_foundation_dropped: Counter,
    tun_session_started: Counter,
    tun_session_generation: Gauge,
    tun_session_active: Gauge,
    tun_packets_ingress: Counter,
    tun_packets_egress: Counter,
    tun_packets_rejected: TunPacketRejectFamily,
    tun_internal_egress_backpressured: Counter,
    tun_pending_udp_responses: Gauge,
    tun_udp_response_dropped: TunUdpResponseDropFamily,
    tun_wintun_ring_full_dropped: Counter,
    tun_tcp_flows_active: Gauge,
    tun_tcp_flows_rejected_limit: Counter,
    tun_tcp_flows_reset_restart: Counter,
    tun_tcp_bridge_blocked: Counter,
    tun_udp_associations_active: Gauge,
    tun_udp_candidates_active: Gauge,
    tun_udp_association_created: Counter,
    tun_udp_association_rejected_limit: Counter,
    tun_udp_datagram_queue_full: Counter,
    tun_udp_response_queue_full: Counter,
    tun_udp_response_filtered: Counter,
    tun_udp_stale_generation: Counter,
    tun_reassembly_entries_active: Gauge,
    tun_reassembly_started: Counter,
    tun_reassembly_completed: Counter,
    tun_reassembly_dropped_overlap: Counter,
    tun_reassembly_dropped_timeout: Counter,
    tun_reassembly_dropped_limit: Counter,
    tun_reassembly_dropped_malformed: Counter,
    tun_network_change: Counter,
    tun_underlay_bind_stale: Counter,
    network_resets: NetworkResetFamily,
    network_full_rebuilds: NetworkFullRebuildFamily,
    network_generation: Gauge,
    network_associations_reset: NetworkAssociationsResetFamily,
    tun_strict_route_requested: Gauge,
    tun_strict_route_effective: Gauge,
    tun_strict_route_filter_installs: StrictRouteFilterInstallFamily,
    outbound_interface_resolutions: InterfaceResolutionFamily,
    outbound_interface_resolution_cache_hits: Counter,
    tun_udp_association_routes: TunUdpAssociationRouteFamily,
}

impl TunMetrics {
    pub(super) fn register(registry: &mut Registry) -> Self {
        let tun_packets_accepted = Counter::default();
        let tun_packets_foundation_dropped = Counter::default();
        let tun_session_started = Counter::default();
        let tun_session_generation = Gauge::default();
        let tun_session_active = Gauge::default();
        let tun_packets_ingress = Counter::default();
        let tun_packets_egress = Counter::default();
        let tun_packets_rejected =
            TunPacketRejectFamily::new(single_labels(TUN_PACKET_REJECT_REASONS, |reason| {
                TunPacketRejectLabels { reason }
            }));
        let tun_internal_egress_backpressured = Counter::default();
        let tun_pending_udp_responses = Gauge::default();
        let tun_udp_response_dropped =
            TunUdpResponseDropFamily::new(single_labels(TUN_UDP_RESPONSE_DROP_REASONS, |reason| {
                TunUdpResponseDropLabels { reason }
            }));
        let tun_wintun_ring_full_dropped = Counter::default();
        let tun_tcp_flows_active = Gauge::default();
        let tun_tcp_flows_rejected_limit = Counter::default();
        let tun_tcp_flows_reset_restart = Counter::default();
        let tun_tcp_bridge_blocked = Counter::default();
        let tun_udp_associations_active = Gauge::default();
        let tun_udp_candidates_active = Gauge::default();
        let tun_udp_association_created = Counter::default();
        let tun_udp_association_rejected_limit = Counter::default();
        let tun_udp_datagram_queue_full = Counter::default();
        let tun_udp_response_queue_full = Counter::default();
        let tun_udp_response_filtered = Counter::default();
        let tun_udp_stale_generation = Counter::default();
        let tun_reassembly_entries_active = Gauge::default();
        let tun_reassembly_started = Counter::default();
        let tun_reassembly_completed = Counter::default();
        let tun_reassembly_dropped_overlap = Counter::default();
        let tun_reassembly_dropped_timeout = Counter::default();
        let tun_reassembly_dropped_limit = Counter::default();
        let tun_reassembly_dropped_malformed = Counter::default();
        let tun_network_change = Counter::default();
        let tun_underlay_bind_stale = Counter::default();
        let network_resets = NetworkResetFamily::new(pair_labels(
            NETWORK_RESET_REASONS,
            NETWORK_LIFECYCLE_RESULTS,
            |reason, result| NetworkResetLabels { reason, result },
        ));
        let network_full_rebuilds = NetworkFullRebuildFamily::new(pair_labels(
            NETWORK_FULL_REBUILD_REASONS,
            NETWORK_LIFECYCLE_RESULTS,
            |reason, result| NetworkFullRebuildLabels { reason, result },
        ));
        let network_generation = Gauge::default();
        let network_associations_reset = NetworkAssociationsResetFamily::new(pair_labels(
            NETWORK_LIFECYCLE_OPERATIONS,
            TRANSPORTS,
            |operation, transport| NetworkAssociationsResetLabels {
                operation,
                transport,
            },
        ));
        let tun_strict_route_requested = Gauge::default();
        let tun_strict_route_effective = Gauge::default();
        let tun_strict_route_filter_installs = StrictRouteFilterInstallFamily::new(single_labels(
            STRICT_ROUTE_FILTER_INSTALL_RESULTS,
            |result| StrictRouteFilterInstallLabels { result },
        ));
        let outbound_interface_resolutions = InterfaceResolutionFamily::new(pair_labels(
            INTERFACE_RESOLUTION_SOURCES,
            INTERFACE_RESOLUTION_RESULTS,
            |source, result| InterfaceResolutionLabels { source, result },
        ));
        let outbound_interface_resolution_cache_hits = Counter::default();
        let tun_udp_association_routes = TunUdpAssociationRouteFamily::new(single_labels(
            TUN_UDP_ASSOCIATION_ROUTE_RESULTS,
            |result| TunUdpAssociationRouteLabels { result },
        ));
        registry.register(
            "ferrum2_tun_packets_accepted",
            "Validated TUN packets accepted by the foundation stack",
            tun_packets_accepted.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_foundation_dropped",
            "TUN packets deterministically dropped before policy composition",
            tun_packets_foundation_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_session_started",
            "TUN sessions that reached their initial start",
            tun_session_started.clone(),
        );
        registry.register(
            "ferrum2_tun_session_generation",
            "Current TUN session generation",
            tun_session_generation.clone(),
        );
        registry.register(
            "ferrum2_tun_session_active",
            "Whether a TUN session is active",
            tun_session_active.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_ingress",
            "Packets received from Wintun by the TUN owner",
            tun_packets_ingress.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_egress",
            "Packets sent successfully to Wintun by the TUN owner",
            tun_packets_egress.clone(),
        );
        registry.register(
            "ferrum2_tun_packets_rejected",
            "TUN packets rejected by a closed low-cardinality reason",
            tun_packets_rejected.clone(),
        );
        registry.register(
            "ferrum2_tun_internal_egress_backpressured",
            "TUN internal egress backpressure observations; packets are retained for retry",
            tun_internal_egress_backpressured.clone(),
        );
        registry.register(
            "ferrum2_tun_pending_udp_responses",
            "TUN UDP responses retained for owner-thread injection",
            tun_pending_udp_responses.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_dropped",
            "Terminal TUN UDP response drops by a closed low-cardinality reason",
            tun_udp_response_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_wintun_ring_full_dropped",
            "TUN packets dropped because the Wintun send ring was full",
            tun_wintun_ring_full_dropped.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_active",
            "Active TUN TCP flows",
            tun_tcp_flows_active.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_rejected_limit",
            "TUN TCP flows rejected by the configured flow limit",
            tun_tcp_flows_rejected_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_flows_reset_restart",
            "TUN TCP flows reset during session restart",
            tun_tcp_flows_reset_restart.clone(),
        );
        registry.register(
            "ferrum2_tun_tcp_bridge_blocked",
            "TUN TCP bridge operations that observed bounded backpressure",
            tun_tcp_bridge_blocked.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_associations_active",
            "Active TUN UDP associations",
            tun_udp_associations_active.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_candidates_active",
            "Active uncommitted TUN UDP association candidates",
            tun_udp_candidates_active.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_association_created",
            "TUN UDP associations created",
            tun_udp_association_created.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_association_rejected_limit",
            "TUN UDP associations rejected by the configured limit",
            tun_udp_association_rejected_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_datagram_queue_full",
            "TUN UDP datagrams dropped because an association queue was full",
            tun_udp_datagram_queue_full.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_queue_full",
            "TUN UDP responses dropped because the response queue was full",
            tun_udp_response_queue_full.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_response_filtered",
            "TUN UDP responses rejected by endpoint filtering",
            tun_udp_response_filtered.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_stale_generation",
            "TUN UDP work rejected after its session generation became stale",
            tun_udp_stale_generation.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_entries_active",
            "Active bounded TUN fragment reassembly entries",
            tun_reassembly_entries_active.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_started",
            "TUN fragment reassemblies started",
            tun_reassembly_started.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_completed",
            "TUN fragment reassemblies completed",
            tun_reassembly_completed.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_overlap",
            "TUN fragment reassemblies dropped for overlap",
            tun_reassembly_dropped_overlap.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_timeout",
            "TUN fragment reassemblies dropped after timeout",
            tun_reassembly_dropped_timeout.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_limit",
            "TUN fragment reassemblies dropped by a bounded limit",
            tun_reassembly_dropped_limit.clone(),
        );
        registry.register(
            "ferrum2_tun_reassembly_dropped_malformed",
            "Malformed TUN fragment reassemblies dropped",
            tun_reassembly_dropped_malformed.clone(),
        );
        registry.register(
            "ferrum2_tun_network_change",
            "Semantic network changes observed by the TUN session",
            tun_network_change.clone(),
        );
        registry.register(
            "ferrum2_tun_underlay_bind_stale",
            "TUN underlay binds rejected because their generation was stale",
            tun_underlay_bind_stale.clone(),
        );
        registry.register(
            "ferrum2_network_reset",
            "Lightweight ResetNetwork attempts by closed initiating reason and result",
            network_resets.clone(),
        );
        registry.register(
            "ferrum2_network_full_rebuild",
            "Managed network-plane full rebuild attempts by closed damage reason and result",
            network_full_rebuilds.clone(),
        );
        registry.register(
            "ferrum2_network_generation",
            "Current fully published network runtime generation",
            network_generation.clone(),
        );
        registry.register(
            "ferrum2_network_associations_reset",
            "TCP and UDP associations closed by a network lifecycle operation",
            network_associations_reset.clone(),
        );
        registry.register(
            "ferrum2_tun_strict_route_requested",
            "Whether strict route was requested by validated configuration",
            tun_strict_route_requested.clone(),
        );
        registry.register(
            "ferrum2_tun_strict_route_effective",
            "Whether strict route is effective under the auto-route gate",
            tun_strict_route_effective.clone(),
        );
        registry.register(
            "ferrum2_tun_strict_route_filter_install",
            "Windows strict-route filter installation outcomes",
            tun_strict_route_filter_installs.clone(),
        );
        registry.register(
            "ferrum2_outbound_interface_resolution",
            "Outbound interface resolutions by closed selection source and result",
            outbound_interface_resolutions.clone(),
        );
        registry.register(
            "ferrum2_outbound_interface_resolution_cache_hit",
            "Outbound interface resolver cache hits",
            outbound_interface_resolution_cache_hits.clone(),
        );
        registry.register(
            "ferrum2_tun_udp_association_route",
            "Single route evaluations for TUN UDP associations by closed result",
            tun_udp_association_routes.clone(),
        );
        Self {
            tun_packets_accepted,
            tun_packets_foundation_dropped,
            tun_session_started,
            tun_session_generation,
            tun_session_active,
            tun_packets_ingress,
            tun_packets_egress,
            tun_packets_rejected,
            tun_internal_egress_backpressured,
            tun_pending_udp_responses,
            tun_udp_response_dropped,
            tun_wintun_ring_full_dropped,
            tun_tcp_flows_active,
            tun_tcp_flows_rejected_limit,
            tun_tcp_flows_reset_restart,
            tun_tcp_bridge_blocked,
            tun_udp_associations_active,
            tun_udp_candidates_active,
            tun_udp_association_created,
            tun_udp_association_rejected_limit,
            tun_udp_datagram_queue_full,
            tun_udp_response_queue_full,
            tun_udp_response_filtered,
            tun_udp_stale_generation,
            tun_reassembly_entries_active,
            tun_reassembly_started,
            tun_reassembly_completed,
            tun_reassembly_dropped_overlap,
            tun_reassembly_dropped_timeout,
            tun_reassembly_dropped_limit,
            tun_reassembly_dropped_malformed,
            tun_network_change,
            tun_underlay_bind_stale,
            network_resets,
            network_full_rebuilds,
            network_generation,
            network_associations_reset,
            tun_strict_route_requested,
            tun_strict_route_effective,
            tun_strict_route_filter_installs,
            outbound_interface_resolutions,
            outbound_interface_resolution_cache_hits,
            tun_udp_association_routes,
        }
    }
}

impl Metrics {
    pub fn tun_packet_accepted(&self) {
        self.tun.tun_packets_accepted.inc();
    }

    /// Records one accepted packet consumed by the foundation stack before policy.
    pub fn tun_packet_foundation_dropped(&self) {
        self.tun.tun_packets_foundation_dropped.inc();
    }

    /// Records the first successful start of a TUN session.
    pub fn tun_session_started(&self) {
        self.tun.tun_session_started.inc();
    }

    /// Sets the currently published TUN session generation.
    pub fn set_tun_session_generation(&self, generation: u64) {
        self.tun.tun_session_generation.set(u64_gauge(generation));
    }

    /// Marks one TUN session active.
    pub fn tun_session_active_inc(&self) {
        self.tun.tun_session_active.inc();
    }

    /// Marks one TUN session inactive after a matching increment.
    pub fn tun_session_active_dec(&self) {
        self.tun.tun_session_active.dec();
    }

    /// Sets whether the single owned TUN session is active.
    pub fn set_tun_session_active(&self, active: bool) {
        self.tun.tun_session_active.set(i64::from(active));
    }

    /// Records one packet received from Wintun by the TUN owner.
    pub fn tun_packet_ingress(&self) {
        self.tun.tun_packets_ingress.inc();
    }

    /// Records one packet sent successfully to Wintun by the TUN owner.
    pub fn tun_packet_egress(&self) {
        self.tun.tun_packets_egress.inc();
    }

    /// Records one TUN packet rejection using only a closed reason code.
    pub fn tun_packet_rejected(&self, reason: TunPacketRejectReason) {
        self.tun.tun_packets_rejected.metric(reason as usize).inc();
    }

    /// Records one observation of bounded internal egress backpressure.
    pub fn tun_internal_egress_backpressured(&self) {
        self.tun.tun_internal_egress_backpressured.inc();
    }

    /// Sets whether one TUN UDP response is retained for owner-thread injection.
    pub fn set_tun_pending_udp_responses(&self, responses: usize) {
        debug_assert!(responses <= 1);
        self.tun
            .tun_pending_udp_responses
            .set(usize_gauge(responses));
    }

    /// Records one terminal TUN UDP response drop.
    pub fn tun_udp_response_dropped(&self, reason: TunUdpResponseDropReason) {
        self.tun
            .tun_udp_response_dropped
            .metric(reason as usize)
            .inc();
    }

    /// Records one expected packet drop caused by a full Wintun send ring.
    pub fn tun_wintun_ring_full_dropped(&self) {
        self.tun.tun_wintun_ring_full_dropped.inc();
    }

    /// Increments the active TUN TCP flow gauge.
    pub fn tun_tcp_flows_active_inc(&self) {
        self.tun.tun_tcp_flows_active.inc();
    }

    /// Decrements the active TUN TCP flow gauge after a matching increment.
    pub fn tun_tcp_flows_active_dec(&self) {
        self.tun.tun_tcp_flows_active.dec();
    }

    /// Sets the exact active TUN TCP flow count.
    pub fn set_tun_tcp_flows_active(&self, flows: usize) {
        self.tun.tun_tcp_flows_active.set(usize_gauge(flows));
    }

    /// Records one TUN TCP flow rejected by the configured flow limit.
    pub fn tun_tcp_flow_rejected_limit(&self) {
        self.tun.tun_tcp_flows_rejected_limit.inc();
    }

    /// Records one TUN TCP flow reset during session restart.
    pub fn tun_tcp_flow_reset_restart(&self) {
        self.tun.tun_tcp_flows_reset_restart.inc();
    }

    /// Records one bounded wait caused by TUN TCP bridge backpressure.
    pub fn tun_tcp_bridge_blocked(&self) {
        self.tun.tun_tcp_bridge_blocked.inc();
    }

    /// Increments the active TUN UDP association gauge.
    pub fn tun_udp_associations_active_inc(&self) {
        self.tun.tun_udp_associations_active.inc();
    }

    /// Decrements the active TUN UDP association gauge after a matching increment.
    pub fn tun_udp_associations_active_dec(&self) {
        self.tun.tun_udp_associations_active.dec();
    }

    /// Sets the exact active TUN UDP association count.
    pub fn set_tun_udp_associations_active(&self, associations: usize) {
        self.tun
            .tun_udp_associations_active
            .set(usize_gauge(associations));
    }

    /// Increments the active uncommitted TUN UDP candidate gauge.
    pub fn tun_udp_candidates_active_inc(&self) {
        self.tun.tun_udp_candidates_active.inc();
    }

    /// Decrements the active TUN UDP candidate gauge after a matching increment.
    pub fn tun_udp_candidates_active_dec(&self) {
        self.tun.tun_udp_candidates_active.dec();
    }

    /// Sets the exact active uncommitted TUN UDP candidate count.
    pub fn set_tun_udp_candidates_active(&self, candidates: usize) {
        self.tun
            .tun_udp_candidates_active
            .set(usize_gauge(candidates));
    }

    /// Records one committed TUN UDP association.
    pub fn tun_udp_association_created(&self) {
        self.tun.tun_udp_association_created.inc();
    }

    /// Records one TUN UDP association rejected by the configured limit.
    pub fn tun_udp_association_rejected_limit(&self) {
        self.tun.tun_udp_association_rejected_limit.inc();
    }

    /// Records one TUN UDP datagram dropped because its queue was full.
    pub fn tun_udp_datagram_queue_full(&self) {
        self.tun.tun_udp_datagram_queue_full.inc();
    }

    /// Records one TUN UDP response dropped because the owner queue was full.
    pub fn tun_udp_response_queue_full(&self) {
        self.tun.tun_udp_response_queue_full.inc();
    }

    /// Records one TUN UDP response rejected by endpoint filtering.
    pub fn tun_udp_response_filtered(&self) {
        self.tun.tun_udp_response_filtered.inc();
    }

    /// Records TUN UDP work rejected after its session generation became stale.
    pub fn tun_udp_stale_generation(&self) {
        self.tun.tun_udp_stale_generation.inc();
    }

    /// Increments the active TUN fragment reassembly entry gauge.
    pub fn tun_reassembly_entries_active_inc(&self) {
        self.tun.tun_reassembly_entries_active.inc();
    }

    /// Decrements the reassembly entry gauge after a matching increment.
    pub fn tun_reassembly_entries_active_dec(&self) {
        self.tun.tun_reassembly_entries_active.dec();
    }

    /// Sets the exact active TUN fragment reassembly entry count.
    pub fn set_tun_reassembly_entries_active(&self, entries: usize) {
        self.tun
            .tun_reassembly_entries_active
            .set(usize_gauge(entries));
    }

    /// Records one newly allocated TUN fragment reassembly entry.
    pub fn tun_reassembly_started(&self) {
        self.tun.tun_reassembly_started.inc();
    }

    /// Records one completed TUN fragment reassembly.
    pub fn tun_reassembly_completed(&self) {
        self.tun.tun_reassembly_completed.inc();
    }

    /// Records one TUN fragment reassembly dropped for overlap.
    pub fn tun_reassembly_dropped_overlap(&self) {
        self.tun.tun_reassembly_dropped_overlap.inc();
    }

    /// Records one TUN fragment reassembly dropped after timeout.
    pub fn tun_reassembly_dropped_timeout(&self) {
        self.tun.tun_reassembly_dropped_timeout.inc();
    }

    /// Records one TUN fragment reassembly dropped by a bounded limit.
    pub fn tun_reassembly_dropped_limit(&self) {
        self.tun.tun_reassembly_dropped_limit.inc();
    }

    /// Records one malformed TUN fragment reassembly drop.
    pub fn tun_reassembly_dropped_malformed(&self) {
        self.tun.tun_reassembly_dropped_malformed.inc();
    }

    /// Records one semantic network change delivered to the TUN session.
    pub fn tun_network_change(&self) {
        self.tun.tun_network_change.inc();
    }

    /// Records one underlay bind rejected because its generation was stale.
    pub fn tun_underlay_bind_stale(&self) {
        self.tun.tun_underlay_bind_stale.inc();
    }

    /// Records one lightweight ResetNetwork lifecycle transition.
    pub fn network_reset(&self, reason: NetworkResetReason, result: NetworkLifecycleResult) {
        self.tun
            .network_resets
            .metric(pair_index(
                reason as usize,
                result as usize,
                NETWORK_LIFECYCLE_RESULTS.len(),
            ))
            .inc();
    }

    /// Records one managed-plane full-rebuild lifecycle transition.
    pub fn network_full_rebuild(
        &self,
        reason: NetworkFullRebuildReason,
        result: NetworkLifecycleResult,
    ) {
        self.tun
            .network_full_rebuilds
            .metric(pair_index(
                reason as usize,
                result as usize,
                NETWORK_LIFECYCLE_RESULTS.len(),
            ))
            .inc();
    }

    /// Sets the current fully published network runtime generation.
    pub fn set_network_generation(&self, generation: u64) {
        self.tun.network_generation.set(u64_gauge(generation));
    }

    /// Adds associations closed by one network lifecycle operation.
    pub fn network_associations_reset(
        &self,
        operation: NetworkLifecycleOperation,
        transport: Transport,
        associations: usize,
    ) {
        self.tun
            .network_associations_reset
            .metric(pair_index(
                operation as usize,
                transport as usize,
                TRANSPORTS.len(),
            ))
            .inc_by(usize_counter(associations));
    }

    /// Sets whether validated configuration requested Windows strict-route protection.
    pub fn set_tun_strict_route_requested(&self, requested: bool) {
        self.tun
            .tun_strict_route_requested
            .set(i64::from(requested));
    }

    /// Sets whether strict route is effective under the auto-route gate.
    pub fn set_tun_strict_route_effective(&self, effective: bool) {
        self.tun
            .tun_strict_route_effective
            .set(i64::from(effective));
    }

    /// Records one effective Windows strict-route filter installation outcome.
    pub fn tun_strict_route_filter_install(&self, result: StrictRouteFilterInstallResult) {
        self.tun
            .tun_strict_route_filter_installs
            .metric(result as usize)
            .inc();
    }

    /// Records one shared outbound interface-resolution outcome.
    pub fn outbound_interface_resolution(
        &self,
        source: InterfaceResolutionSource,
        result: InterfaceResolutionResult,
    ) {
        self.tun
            .outbound_interface_resolutions
            .metric(pair_index(
                source as usize,
                result as usize,
                INTERFACE_RESOLUTION_RESULTS.len(),
            ))
            .inc();
    }

    /// Records one outbound interface-resolution cache hit.
    pub fn outbound_interface_resolution_cache_hit(&self) {
        self.tun.outbound_interface_resolution_cache_hits.inc();
    }

    /// Records the result of the one route evaluation for a TUN UDP association.
    pub fn tun_udp_association_route(&self, result: TunUdpAssociationRouteResult) {
        self.tun
            .tun_udp_association_routes
            .metric(result as usize)
            .inc();
    }
}
