use std::fmt;
use std::time::Duration;

/// Default independent client/server UDP session limit.
pub const DEFAULT_UDP_MAX_SESSIONS: usize = 4_096;
/// Smallest configurable UDP session limit.
pub const MIN_UDP_MAX_SESSIONS: usize = 1;
/// Largest configurable UDP session limit.
pub const MAX_UDP_MAX_SESSIONS: usize = 65_535;
/// Default global user-space UDP allocated-capacity budget.
pub const DEFAULT_UDP_MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
/// Smallest configurable UDP allocated-capacity budget.
pub const MIN_UDP_MAX_BUFFERED_BYTES: usize = 1024 * 1024;
/// Largest configurable UDP allocated-capacity budget.
pub const MAX_UDP_MAX_BUFFERED_BYTES: usize = 256 * 1024 * 1024;
/// Fixed number of datagrams retained per session and direction.
pub const UDP_SESSION_QUEUE_DEPTH: usize = 4;
/// Hard bound for one complete UDP wire datagram.
pub const MAX_UDP_WIRE_DATAGRAM_BYTES: usize = 65_507;
/// Default UDP session idle lifetime.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Smallest configurable UDP session idle lifetime.
pub const MIN_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest configurable UDP session idle lifetime.
pub const MAX_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(86_400);
/// Maximum ordered candidates consumed from system UDP resolution.
pub const MAX_UDP_RESOLVED_CANDIDATES: usize = 16;
/// Bounded per-association last-success candidate hints.
pub(super) const UDP_CANDIDATE_HINT_ENTRIES: usize = 16;

/// Validated, protocol-neutral UDP resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpRuntimeLimits {
    max_sessions: usize,
    max_buffered_bytes: usize,
    idle_timeout: Duration,
}

impl UdpRuntimeLimits {
    /// Validates all configurable UDP resource boundaries.
    pub fn new(
        max_sessions: usize,
        max_buffered_bytes: usize,
        idle_timeout: Duration,
    ) -> Result<Self, UdpLimitError> {
        if !(MIN_UDP_MAX_SESSIONS..=MAX_UDP_MAX_SESSIONS).contains(&max_sessions) {
            return Err(UdpLimitError::Sessions);
        }
        if !(MIN_UDP_MAX_BUFFERED_BYTES..=MAX_UDP_MAX_BUFFERED_BYTES).contains(&max_buffered_bytes)
        {
            return Err(UdpLimitError::BufferedBytes);
        }
        if !(MIN_UDP_IDLE_TIMEOUT..=MAX_UDP_IDLE_TIMEOUT).contains(&idle_timeout) {
            return Err(UdpLimitError::IdleTimeout);
        }
        Ok(Self {
            max_sessions,
            max_buffered_bytes,
            idle_timeout,
        })
    }

    /// Returns the validated session limit.
    pub const fn max_sessions(self) -> usize {
        self.max_sessions
    }

    /// Returns the validated allocated-capacity byte limit.
    pub const fn max_buffered_bytes(self) -> usize {
        self.max_buffered_bytes
    }

    /// Returns the validated idle lifetime.
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout
    }
}

impl Default for UdpRuntimeLimits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_UDP_MAX_SESSIONS,
            max_buffered_bytes: DEFAULT_UDP_MAX_BUFFERED_BYTES,
            idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
        }
    }
}

/// Invalid UDP resource configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpLimitError {
    /// Session count is outside 1..=65,535.
    Sessions,
    /// Allocated-capacity budget is outside 1 MiB..=256 MiB.
    BufferedBytes,
    /// Idle lifetime is outside 60s..=86,400s.
    IdleTimeout,
}

impl fmt::Display for UdpLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = match self {
            Self::Sessions => "UDP session limit",
            Self::BufferedBytes => "UDP buffered-byte limit",
            Self::IdleTimeout => "UDP idle timeout",
        };
        write!(formatter, "{field} is outside its valid range")
    }
}

impl std::error::Error for UdpLimitError {}

/// Closed runtime failure categories for one affected UDP operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRuntimeError {
    /// A local datagram or capacity bound was invalid.
    Bounds,
    /// No session slot was available without evicting active state.
    SessionLimit,
    /// The global allocated-capacity budget was exhausted.
    BufferLimit,
    /// The fixed per-direction queue was full.
    QueueFull,
    /// A generation counter could not advance without wrapping.
    Counter,
    /// Bounded resolution failed.
    Resolve,
    /// Direct target transmission failed.
    Send,
    /// Direct target reception failed.
    Receive,
    /// The session became idle.
    Idle,
    /// The session was cancelled.
    Cancelled,
}

impl fmt::Display for UdpRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self {
            Self::Bounds => "bounds",
            Self::SessionLimit => "session_limit",
            Self::BufferLimit => "buffer_limit",
            Self::QueueFull => "queue_full",
            Self::Counter => "counter",
            Self::Resolve => "resolve",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Idle => "idle",
            Self::Cancelled => "cancelled",
        };
        formatter.write_str(category)
    }
}

impl std::error::Error for UdpRuntimeError {}

/// Result of the serialized runtime-generation and protocol-state commit.
pub enum UdpCommitError<E> {
    /// Runtime capacity or generation changed before the serialized commit.
    Runtime(UdpRuntimeError),
    /// The protocol owner rejected its own state transition.
    Protocol(E),
}

impl<E> fmt::Debug for UdpCommitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => formatter.debug_tuple("Runtime").field(error).finish(),
            Self::Protocol(_) => formatter.write_str("Protocol([closed])"),
        }
    }
}

/// Direction of one protocol-neutral per-session datagram queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpDirection {
    /// Validated client-side datagram travelling to its target.
    ToTarget,
    /// Target response travelling back to the protocol adapter.
    ToClient,
}

impl UdpDirection {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::ToTarget => 0,
            Self::ToClient => 1,
        }
    }
}

/// Opaque process-local, generation-bound UDP session capability.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UdpSessionHandle {
    pub(super) slot: u32,
    pub(super) generation: u64,
}

impl fmt::Debug for UdpSessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpSessionHandle([redacted])")
    }
}
