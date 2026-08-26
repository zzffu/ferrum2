use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::UdpFiltering;

/// Complete, already-validated construction input for the private TUN owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub adapter_name: Box<str>,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    pub max_tcp_flows: usize,
    pub tcp_buffer_bytes: usize,
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub max_udp_mappings: usize,
    pub udp_filtering: UdpFiltering,
    pub capture_routes: Vec<(IpAddr, u8)>,
    pub physical_endpoints: Vec<SocketAddr>,
    pub default_binder: bool,
    pub ipv4_dns_address: Option<Ipv4Addr>,
    pub ipv6_dns_address: Option<Ipv6Addr>,
    pub strict_route: bool,
}

/// Closed, low-cardinality reasons for rejecting work at the TUN boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunRejectReason {
    InvalidIpVersion,
    FamilyDisabled,
    InvalidIpLength,
    InvalidIpChecksum,
    InvalidExtensionHeader,
    UnsupportedIpProtocol,
    IcmpEchoUnsupported,
    FragmentMalformed,
    FragmentOverlap,
    FragmentTimeout,
    FragmentLimit,
    InvalidTransportLength,
    InvalidTransportChecksum,
    InvalidSource,
    InvalidDestination,
    IngressFull,
    TcpFlowLimit,
    UdpAssociationLimit,
    UdpCandidateTimeout,
    UdpQueueFull,
    UdpResponseFiltered,
    UdpResponseClosed,
    StaleGeneration,
    WintunRingFull,
}

/// Closed, identity-free reasons why one UDP response became terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpResponseDropReason {
    StaleGeneration,
    AssociationClosed,
    QueueFull,
    MalformedResponse,
    Filtered,
    InjectionRejected,
    SessionReset,
    Shutdown,
    OwnerFatal,
}

/// Closed address-family label for redacted TUN diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunIpFamily {
    Ipv4,
    Ipv6,
}

/// Closed diagnostic reasons that require a structured log in addition to metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunDiagnosticReason {
    WintunRingFull,
}

/// One redacted event emitted by the TUN owner or a generation-bound bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunEvent {
    PacketAccepted,
    PacketFoundationDropped,
    SessionStarted,
    StrictRouteFilterInstalled,
    StrictRouteFilterInstallFailed,
    NetworkResetStarted(TunNetworkResetReason),
    NetworkResetSucceeded(TunNetworkResetReason),
    NetworkResetFailed(TunNetworkResetReason),
    NetworkFullRebuildStarted {
        reason: TunNetworkFullRebuildReason,
        generation: u64,
        tcp_associations: usize,
        udp_associations: usize,
    },
    NetworkFullRebuildSucceeded {
        reason: TunNetworkFullRebuildReason,
        generation: u64,
        tcp_associations: usize,
        udp_associations: usize,
    },
    NetworkFullRebuildFailed {
        reason: TunNetworkFullRebuildReason,
        generation: u64,
        tcp_associations: usize,
        udp_associations: usize,
    },
    SessionGeneration(u64),
    SessionActive(bool),
    PacketIngress,
    PacketEgress,
    PacketRejected(TunRejectReason),
    InternalEgressBackpressured,
    WintunRingFullDropped,
    TcpFlowsActive(usize),
    TcpFlowRejectedLimit,
    TcpFlowResetRestart,
    TcpBridgeBlocked,
    UdpAssociationsActive(usize),
    UdpCandidatesActive(usize),
    UdpAssociationCreated,
    UdpAssociationRejectedLimit,
    UdpDatagramQueueFull,
    UdpResponseQueueFull,
    UdpResponseFiltered,
    UdpResponseDropped(UdpResponseDropReason),
    UdpPendingResponses(usize),
    UdpStaleGeneration,
    ReassemblyEntriesActive(usize),
    ReassemblyStarted,
    ReassemblyCompleted,
    ReassemblyDroppedOverlap,
    ReassemblyDroppedTimeout,
    ReassemblyDroppedLimit,
    ReassemblyDroppedMalformed,
    NetworkChange,
    UnderlayBindStale,
    Diagnostic {
        reason: TunDiagnosticReason,
        family: TunIpFamily,
    },
}

/// Closed reason for one lightweight network-runtime reset attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunNetworkResetReason {
    /// A debounced route, interface, address, or DNS notification changed the underlay.
    NetworkChange,
    /// A prior reset attempt could not publish a complete replacement runtime.
    Retry,
}

/// Closed managed-plane damage reason that permits recreating the owned TUN plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunNetworkFullRebuildReason {
    AdapterDamage,
    SessionDamage,
    AddressDamage,
    RouteDamage,
    DnsDamage,
    StrictRouteDamage,
    OwnershipLedgerDamage,
}

/// One generation-aware transition requested by the private TUN owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunNetworkLifecycle {
    /// Publishes the first real platform snapshot before the process root can activate.
    Initialize,
    /// Replaces only generation-bound runtime state while preserving the managed TUN plane.
    ResetNetwork(TunNetworkResetReason),
    /// Closes admission and records the managed-plane rebuild intent before teardown.
    FullRebuildStarted(TunNetworkFullRebuildReason),
    /// Publishes the rebuilt plane's read-back snapshot and reopens admission.
    FullRebuildCompleted(TunNetworkFullRebuildReason),
}

/// Closed failure returned by the client network-lifecycle coordinator bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunNetworkResetError;

#[derive(Clone)]
pub(crate) struct TunEventSink {
    emit: Arc<dyn Fn(TunEvent) + Send + Sync>,
}

impl TunEventSink {
    pub(crate) fn new(emit: impl Fn(TunEvent) + Send + Sync + 'static) -> Self {
        Self {
            emit: Arc::new(emit),
        }
    }

    pub(crate) fn emit(&self, event: TunEvent) {
        (self.emit)(event);
    }
}

impl Default for TunEventSink {
    fn default() -> Self {
        Self::new(|_| {})
    }
}
