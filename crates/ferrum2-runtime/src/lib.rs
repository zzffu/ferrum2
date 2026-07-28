#![forbid(unsafe_code)]

mod connector;
mod deadline;
mod metrics;
mod owner;
mod relay;
mod supervisor;

pub use connector::{
    DirectOutbound, MAX_RESOLVED_CANDIDATES, RuntimeTcpStream, SocketInspector,
    SystemSocketInspector, SystemTcpDialer, SystemTcpResolver, TcpConnector, TcpDialer,
    TcpResolver,
};
pub use deadline::{DeadlineError, with_deadline};
pub use metrics::{
    METRICS_CONNECTION_LIMIT, METRICS_HEADER_BYTES, METRICS_HEADER_TIMEOUT, MetricsEndpoint,
    MetricsEndpointError, serve_metrics_connection,
};
pub use owner::{OwnerRegistry, OwnerSnapshot};
pub use relay::{
    RELAY_BUFFER_BYTES, RelayFailure, RelayRunError, RelayStats, relay_bidirectional,
    relay_bidirectional_tracked, relay_bidirectional_with_idle_timeout, relay_lifecycle,
};
pub use supervisor::{
    AcceptListener, BoundedSupervisor, CancellationToken, SupervisorConfigError, SupervisorError,
};

/// Default first-handshake deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default direct-connect deadline.
pub const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Default idle relay deadline.
pub const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// Default graceful shutdown allowance.
pub const DEFAULT_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
