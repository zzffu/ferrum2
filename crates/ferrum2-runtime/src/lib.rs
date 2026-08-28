#![forbid(unsafe_code)]

mod connector;
mod deadline;
mod metrics;
mod network;
mod network_socket;
mod owner;
mod process;
mod relay;
mod reset;
mod sniff;
mod supervisor;
mod udp;

pub use connector::{
    DirectOutbound, MAX_RESOLVED_CANDIDATES, RuntimeTcpStream, SocketInspector,
    SystemSocketInspector, SystemTcpDialer, SystemTcpResolver, TcpConnector, TcpDialer,
};
pub use deadline::{DeadlineError, with_deadline};
pub use metrics::{
    METRICS_CONNECTION_LIMIT, METRICS_HEADER_BYTES, METRICS_HEADER_TIMEOUT, MetricsEndpoint,
    MetricsEndpointError, serve_metrics_connection,
};
pub use network::{
    NetworkResetError, NetworkResetFuture, NetworkSnapshotPublishError, NetworkSnapshotPublisher,
    ResetNetwork,
};
pub use network_socket::{
    GenerationBoundSocketError, NetworkSocketMode, NetworkSocketOperations, NetworkSocketService,
    NetworkSocketServiceError, NetworkTcpStream, NetworkUdpSocket, SystemNetworkSocketError,
    SystemNetworkSocketOperations,
};
pub use owner::{OwnerRegistry, OwnerSnapshot, TunHandlerTaskOwner, TunTcpFlowOwner};
pub use process::{
    PreparedProcessRoot, ProcessCancellation, ProcessCancellationPhase, ProcessCause,
    ProcessCleanupFailure, ProcessExitKind, ProcessFuture, ProcessReport, ProcessRoot,
    ProcessRootEvent, ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory,
    ProcessRootId, ProcessState, ProcessSupervisor, ProcessSupervisorConfigError,
    ProcessTransition,
};
pub use relay::{
    BUFFERED_RELAY_BUFFERS_PER_CONNECTION, RELAY_BUFFER_BYTES, RelayFailure, RelayRunError,
    RelayStats, relay_bidirectional, relay_bidirectional_tracked,
    relay_bidirectional_with_idle_timeout, relay_lifecycle, relay_lifecycle_buffered_inbound,
    relay_lifecycle_buffered_outbound,
};
pub use reset::{
    AdmittedNetworkRuntimeResource, DEFAULT_NETWORK_RESET_HOOKS, DEFAULT_NETWORK_RUNTIME_OWNERS,
    MAX_NETWORK_RESET_HOOKS, MAX_NETWORK_RUNTIME_OWNERS, ManagedNetworkDamage,
    NetworkResetCoordinator, NetworkResetCoordinatorError, NetworkResetHookRegistration,
    NetworkResetHookRegistrationError, NetworkResetHookStage, NetworkResetIntent,
    NetworkResetLimits, NetworkResetLimitsError, NetworkResetOutcome, NetworkResetReason,
    NetworkResetReport, NetworkResetRequestDisposition, NetworkResetSignal, NetworkResetState,
    NetworkResetStatus, NetworkRuntimeCancellation, NetworkRuntimeOwner,
    NetworkRuntimeOwnerCancellation, NetworkRuntimeOwnerKind, NetworkRuntimeOwnerRegistrationError,
    NetworkRuntimeResourceAdmissionError,
};
pub use sniff::{PrefixDecision, SniffPrefix, SniffPrefixOutcome, collect_sniff_prefix};
pub use supervisor::{
    AcceptListener, BoundedSupervisor, CancellationToken, SupervisorConfigError, SupervisorError,
};
pub use udp::{
    AccountedDatagram, DEFAULT_UDP_IDLE_TIMEOUT, DEFAULT_UDP_MAX_BUFFERED_BYTES,
    DEFAULT_UDP_MAX_SESSIONS, DirectUdpPacketHandler, DirectUdpRuntime, DirectUdpSessionAdmission,
    DirectUdpSocket, DirectUdpSocketFactory, MAX_UDP_IDLE_TIMEOUT, MAX_UDP_MAX_BUFFERED_BYTES,
    MAX_UDP_MAX_SESSIONS, MAX_UDP_RESOLVED_CANDIDATES, MAX_UDP_WIRE_DATAGRAM_BYTES,
    MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, MIN_UDP_MAX_SESSIONS, PendingUdpDatagram,
    PendingUdpSession, SystemDirectUdpSocket, SystemDirectUdpSocketFactory, SystemUdpResolver,
    UDP_SESSION_QUEUE_DEPTH, UdpBufferBudget, UdpBufferReservation, UdpCommitError, UdpDirection,
    UdpLimitError, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle, UdpSessionManager,
};

/// Default first-handshake deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default direct-connect deadline.
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Default idle relay deadline.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Default graceful shutdown allowance.
pub const DEFAULT_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
