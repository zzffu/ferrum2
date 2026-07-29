use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::Datagram;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, ProcessCancellation};

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
    const fn index(self) -> usize {
        match self {
            Self::ToTarget => 0,
            Self::ToClient => 1,
        }
    }
}

/// Opaque process-local, generation-bound UDP session capability.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UdpSessionHandle {
    slot: u32,
    generation: u64,
}

impl fmt::Debug for UdpSessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpSessionHandle([redacted])")
    }
}

#[derive(Debug)]
struct BufferBudgetInner {
    limit: usize,
    reserved: AtomicUsize,
    released: Notify,
    registry: OwnerRegistry,
}

/// Cloneable global allocated-capacity budget.
#[derive(Clone, Debug)]
pub struct UdpBufferBudget {
    inner: Arc<BufferBudgetInner>,
}

impl UdpBufferBudget {
    fn new(limit: usize, registry: OwnerRegistry) -> Self {
        Self {
            inner: Arc::new(BufferBudgetInner {
                limit,
                reserved: AtomicUsize::new(0),
                released: Notify::new(),
                registry,
            }),
        }
    }

    /// Returns allocated-capacity bytes currently reserved.
    pub fn reserved_bytes(&self) -> usize {
        self.inner.reserved.load(Ordering::SeqCst)
    }

    /// Reserves exact allocated capacity before accepted protocol state advances.
    pub fn reserve(&self, capacity: usize) -> Result<UdpBufferReservation, UdpRuntimeError> {
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        let mut current = self.inner.reserved.load(Ordering::SeqCst);
        loop {
            let Some(next) = current.checked_add(capacity) else {
                return Err(UdpRuntimeError::BufferLimit);
            };
            if next > self.inner.limit {
                return Err(UdpRuntimeError::BufferLimit);
            }
            match self.inner.reserved.compare_exchange_weak(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.inner.registry.add_udp_buffered_bytes(capacity);
                    return Ok(UdpBufferReservation {
                        inner: Arc::clone(&self.inner),
                        capacity,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    async fn reserve_when_available(
        &self,
        capacity: usize,
    ) -> Result<UdpBufferReservation, UdpRuntimeError> {
        loop {
            let notified = self.inner.released.notified();
            match self.reserve(capacity) {
                Ok(reservation) => return Ok(reservation),
                Err(UdpRuntimeError::BufferLimit) => notified.await,
                Err(error) => return Err(error),
            }
        }
    }
}

/// Single-charge ownership of allocated buffer capacity.
pub struct UdpBufferReservation {
    inner: Arc<BufferBudgetInner>,
    capacity: usize,
}

impl UdpBufferReservation {
    /// Returns the exact allocated capacity charged by this owner.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    fn attach(self, datagram: Datagram) -> Result<AccountedDatagram, UdpRuntimeError> {
        if datagram.allocated_capacity() != self.capacity
            || datagram.payload().len() > MAX_UDP_WIRE_DATAGRAM_BYTES
        {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(AccountedDatagram {
            datagram,
            reservation: self,
        })
    }
}

impl fmt::Debug for UdpBufferReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpBufferReservation")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Drop for UdpBufferReservation {
    fn drop(&mut self) {
        let previous = self
            .inner
            .reserved
            .fetch_sub(self.capacity, Ordering::SeqCst);
        debug_assert!(
            previous >= self.capacity,
            "UDP buffer reservation underflow"
        );
        self.inner.registry.remove_udp_buffered_bytes(self.capacity);
        self.inner.released.notify_waiters();
    }
}

/// Datagram coupled to exactly one allocated-capacity charge.
pub struct AccountedDatagram {
    datagram: Datagram,
    reservation: UdpBufferReservation,
}

impl AccountedDatagram {
    /// Returns the bounded datagram.
    pub fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    /// Returns the charged backing capacity.
    pub const fn allocated_capacity(&self) -> usize {
        self.reservation.capacity()
    }
}

impl fmt::Debug for AccountedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountedDatagram")
            .field("datagram", &self.datagram)
            .field("allocated_capacity", &self.allocated_capacity())
            .finish()
    }
}

struct QueuedDatagram {
    datagram: AccountedDatagram,
    _guard: OwnerGuard,
}

struct DatagramQueue {
    entries: [Option<QueuedDatagram>; UDP_SESSION_QUEUE_DEPTH],
    head: usize,
    len: usize,
}

impl DatagramQueue {
    fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            head: 0,
            len: 0,
        }
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn push_back(&mut self, datagram: QueuedDatagram) {
        debug_assert!(self.len < UDP_SESSION_QUEUE_DEPTH);
        let index = (self.head + self.len) % UDP_SESSION_QUEUE_DEPTH;
        self.entries[index] = Some(datagram);
        self.len += 1;
    }

    fn pop_front(&mut self) -> Option<QueuedDatagram> {
        if self.len == 0 {
            return None;
        }
        let datagram = self.entries[self.head].take();
        self.head = (self.head + 1) % UDP_SESSION_QUEUE_DEPTH;
        self.len -= 1;
        datagram
    }
}

struct SessionEntry {
    generation: u64,
    last_activity: Instant,
    committed: bool,
    pending: [usize; 2],
    queues: [DatagramQueue; 2],
    notify: Arc<Notify>,
    cancellation: watch::Sender<bool>,
    _guard: OwnerGuard,
}

#[derive(Default)]
struct SessionState {
    entries: BTreeMap<u32, SessionEntry>,
    next_generation: u64,
    shutting_down: bool,
}

struct UdpSessionManagerInner {
    limits: UdpRuntimeLimits,
    budget: UdpBufferBudget,
    state: Mutex<SessionState>,
    registry: OwnerRegistry,
}

/// Protocol-neutral owner of generation, capacity, queues, and byte reservations.
#[derive(Clone)]
pub struct UdpSessionManager {
    inner: Arc<UdpSessionManagerInner>,
}

impl UdpSessionManager {
    /// Creates an empty manager without allocating per-session state.
    pub fn new(limits: UdpRuntimeLimits, registry: OwnerRegistry) -> Self {
        let budget = UdpBufferBudget::new(limits.max_buffered_bytes(), registry.clone());
        Self {
            inner: Arc::new(UdpSessionManagerInner {
                limits,
                budget,
                state: Mutex::new(SessionState::default()),
                registry,
            }),
        }
    }

    /// Returns the global allocated-capacity reservation owner.
    pub fn buffer_budget(&self) -> UdpBufferBudget {
        self.inner.budget.clone()
    }

    /// Returns the number of live committed and provisional session owners.
    pub fn session_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .expect("UDP session state lock poisoned")
            .entries
            .len()
    }

    /// Reserves a new generation without committing protocol activity.
    ///
    /// At capacity, exactly the deterministic oldest committed idle-expired
    /// entry is removed. Active and provisional state is never evicted.
    pub fn reserve_session(&self, now: Instant) -> Result<PendingUdpSession, UdpRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        if state.entries.len() == self.inner.limits.max_sessions() {
            let expired = state
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.committed
                        && now.saturating_duration_since(entry.last_activity)
                            >= self.inner.limits.idle_timeout()
                })
                .min_by_key(|(slot, entry)| (entry.last_activity, **slot))
                .map(|(slot, _)| *slot);
            if let Some(slot) = expired {
                remove_entry(&mut state, slot);
            }
        }
        if state.entries.len() == self.inner.limits.max_sessions() {
            return Err(UdpRuntimeError::SessionLimit);
        }

        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or(UdpRuntimeError::Counter)?;
        state.next_generation = generation;
        let slot = (0..self.inner.limits.max_sessions() as u32)
            .find(|slot| !state.entries.contains_key(slot))
            .ok_or(UdpRuntimeError::SessionLimit)?;
        let handle = UdpSessionHandle { slot, generation };
        let (cancellation, _) = watch::channel(false);
        state.entries.insert(
            slot,
            SessionEntry {
                generation,
                last_activity: now,
                committed: false,
                pending: [0; 2],
                queues: std::array::from_fn(|_| DatagramQueue::new()),
                notify: Arc::new(Notify::new()),
                cancellation,
                _guard: self.inner.registry.track_udp_session(),
            },
        );
        Ok(PendingUdpSession {
            manager: Arc::clone(&self.inner),
            handle,
            committed: false,
        })
    }

    /// Reserves one queue slot and its exact backing capacity for a live session.
    pub fn reserve_datagram(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(&self.inner, handle, direction, allocated_capacity, true)
    }

    /// Removes one exact generation and invalidates every late capability.
    pub fn remove(&self, handle: UdpSessionHandle) -> bool {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if entry_matches(&state, handle) {
            remove_entry(&mut state, handle.slot);
            true
        } else {
            false
        }
    }

    /// Removes every session and wakes every owned worker.
    pub fn cancel_all(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        state.shutting_down = true;
        let slots: Vec<_> = state.entries.keys().copied().collect();
        for slot in slots {
            remove_entry(&mut state, slot);
        }
    }

    /// Requests shutdown without discarding already admitted queue entries.
    pub fn signal_all(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        state.shutting_down = true;
        for entry in state.entries.values() {
            entry.cancellation.send_replace(true);
            entry.notify.notify_waiters();
        }
    }

    /// Pops one queued datagram without changing accepted activity.
    pub fn pop(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
    ) -> Result<Option<AccountedDatagram>, UdpRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        let entry = matching_entry_mut(&mut state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        Ok(entry.queues[direction.index()]
            .pop_front()
            .map(|queued| queued.datagram))
    }

    fn enqueue_accounted(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        datagram: AccountedDatagram,
    ) -> Result<(), UdpRuntimeError> {
        let notify = {
            let mut state = self
                .inner
                .state
                .lock()
                .expect("UDP session state lock poisoned");
            if state.shutting_down {
                return Err(UdpRuntimeError::Cancelled);
            }
            let entry = matching_entry_mut(&mut state, handle)?;
            let index = direction.index();
            if entry.pending[index] + entry.queues[index].len() >= UDP_SESSION_QUEUE_DEPTH {
                return Err(UdpRuntimeError::QueueFull);
            }
            entry.queues[index].push_back(QueuedDatagram {
                datagram,
                _guard: self.inner.registry.track_udp_queue_entry(),
            });
            Arc::clone(&entry.notify)
        };
        notify.notify_one();
        Ok(())
    }

    fn commit_activity(
        &self,
        handle: UdpSessionHandle,
        now: Instant,
    ) -> Result<(), UdpRuntimeError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        let entry = matching_entry_mut(&mut state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        entry.last_activity = now;
        Ok(())
    }

    fn cancellation(
        &self,
        handle: UdpSessionHandle,
    ) -> Result<watch::Receiver<bool>, UdpRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        let entry = matching_entry(&state, handle)?;
        Ok(entry.cancellation.subscribe())
    }

    fn notify(&self, handle: UdpSessionHandle) -> Result<Arc<Notify>, UdpRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        Ok(Arc::clone(&matching_entry(&state, handle)?.notify))
    }

    fn idle_deadline(&self, handle: UdpSessionHandle) -> Result<Instant, UdpRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        Ok(matching_entry(&state, handle)?.last_activity + self.inner.limits.idle_timeout())
    }
}

/// Resolves a bounded ordered sequence of UDP target candidates.
pub trait UdpResolver: Send + Sync + 'static {
    /// Candidate storage or iterator returned by this resolver.
    type Candidates: IntoIterator<Item = SocketAddr> + Send;

    /// Resolves one validated ASCII domain and non-zero port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Self::Candidates>> + Send;
}

/// Production system UDP resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemUdpResolver;

impl UdpResolver for SystemUdpResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .take(MAX_UDP_RESOLVED_CANDIDATES)
            .collect())
    }
}

/// One owned datagram socket used by a direct UDP session task.
pub trait DirectUdpSocket: Send + Sync + 'static {
    /// Sends one complete datagram to an IP candidate.
    fn send_to(
        &self,
        payload: &[u8],
        target: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;

    /// Receives one complete target datagram and its source address.
    fn recv_from(
        &self,
        payload: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}

impl DirectUdpSocket for UdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, payload, target).await
    }

    async fn recv_from(&self, payload: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, payload).await
    }
}

/// Production dual-stack socket that normalizes IPv4-mapped endpoints.
pub struct SystemDirectUdpSocket {
    socket: UdpSocket,
}

impl DirectUdpSocket for SystemDirectUdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        let target = match target {
            SocketAddr::V4(target) => SocketAddr::V6(SocketAddrV6::new(
                target.ip().to_ipv6_mapped(),
                target.port(),
                0,
                0,
            )),
            SocketAddr::V6(target) => SocketAddr::V6(target),
        };
        self.socket.send_to(payload, target).await
    }

    async fn recv_from(&self, payload: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (length, source) = self.socket.recv_from(payload).await?;
        let source = match source {
            SocketAddr::V6(source) => match source.ip().to_ipv4_mapped() {
                Some(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, source.port())),
                None => SocketAddr::V6(source),
            },
            SocketAddr::V4(source) => SocketAddr::V4(source),
        };
        Ok((length, source))
    }
}

/// Creates one direct socket for one committed server session.
pub trait DirectUdpSocketFactory: Send + Sync + 'static {
    /// Owned direct socket.
    type Socket: DirectUdpSocket;

    /// Opens one unconnected dual-family datagram socket.
    fn open(&self) -> impl Future<Output = io::Result<Self::Socket>> + Send;
}

/// Production one-socket-per-session factory.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDirectUdpSocketFactory;

impl DirectUdpSocketFactory for SystemDirectUdpSocketFactory {
    async fn open(&self) -> io::Result<Self::Socket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).into())?;
        let socket: std::net::UdpSocket = socket.into();
        Ok(SystemDirectUdpSocket {
            socket: UdpSocket::from_std(socket)?,
        })
    }

    type Socket = SystemDirectUdpSocket;
}

/// Protocol-neutral callback for one bounded target response.
pub trait DirectUdpPacketHandler: Send + Sync + 'static {
    /// Closed handler error; its value is never formatted by the runtime.
    type Error: Send;

    /// Consumes one generation-bound, allocated-capacity-accounted response.
    fn handle_target_response(
        &self,
        session: UdpSessionHandle,
        response: AccountedDatagram,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Capacity and socket reservation made before protocol accepted-state commit.
pub struct DirectUdpSessionAdmission<S> {
    session: PendingUdpSession,
    first_datagram: PendingUdpDatagram,
    socket: S,
    socket_guard: OwnerGuard,
    owner_slot: OwnedSemaphorePermit,
}

impl<S> fmt::Debug for DirectUdpSessionAdmission<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectUdpSessionAdmission([redacted])")
    }
}

struct DirectOwnerLifetime {
    task_guard: Option<OwnerGuard>,
    socket_guard: Option<OwnerGuard>,
    owner_slot: Option<OwnedSemaphorePermit>,
}

impl Drop for DirectOwnerLifetime {
    fn drop(&mut self) {
        drop(self.socket_guard.take());
        drop(self.task_guard.take());
        drop(self.owner_slot.take());
    }
}

/// Owns all direct UDP sessions, sockets, tasks, queues, and cancellation paths.
pub struct DirectUdpRuntime<R, F, H>
where
    R: UdpResolver,
    F: DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    manager: UdpSessionManager,
    resolver: Arc<R>,
    socket_factory: F,
    handler: Arc<H>,
    connect_timeout: Duration,
    registry: OwnerRegistry,
    tasks: JoinSet<()>,
    owner_slots: Arc<Semaphore>,
}

impl<H> DirectUdpRuntime<SystemUdpResolver, SystemDirectUdpSocketFactory, H>
where
    H: DirectUdpPacketHandler,
{
    /// Creates a production direct UDP runtime without opening a socket or task.
    pub fn new(
        limits: UdpRuntimeLimits,
        connect_timeout: Duration,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        Self::with_adapters(
            limits,
            connect_timeout,
            SystemUdpResolver,
            SystemDirectUdpSocketFactory,
            handler,
            registry,
        )
    }
}

impl<R, F, H> DirectUdpRuntime<R, F, H>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    F: DirectUdpSocketFactory,
    H: DirectUdpPacketHandler,
{
    /// Creates a runtime with deterministic resolver/socket/handler adapters.
    pub fn with_adapters(
        limits: UdpRuntimeLimits,
        connect_timeout: Duration,
        resolver: R,
        socket_factory: F,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        Self {
            manager: UdpSessionManager::new(limits, registry.clone()),
            resolver: Arc::new(resolver),
            socket_factory,
            handler: Arc::new(handler),
            connect_timeout,
            registry,
            tasks: JoinSet::new(),
            owner_slots: Arc::new(Semaphore::new(limits.max_sessions())),
        }
    }

    /// Returns the protocol-neutral capacity manager.
    pub fn sessions(&self) -> &UdpSessionManager {
        &self.manager
    }

    /// Reserves capacity, first queue entry, and one socket before replay commit.
    pub async fn reserve_session(
        &mut self,
        now: Instant,
        first_allocated_capacity: usize,
    ) -> Result<DirectUdpSessionAdmission<F::Socket>, UdpRuntimeError> {
        while self.tasks.try_join_next().is_some() {}
        let session = self.manager.reserve_session(now)?;
        let owner_slot = Arc::clone(&self.owner_slots)
            .try_acquire_owned()
            .map_err(|_| UdpRuntimeError::SessionLimit)?;
        let first_datagram =
            session.reserve_datagram(UdpDirection::ToTarget, first_allocated_capacity)?;
        let socket = self
            .socket_factory
            .open()
            .await
            .map_err(|_| UdpRuntimeError::Send)?;
        let socket_guard = self.registry.track_udp_socket();
        Ok(DirectUdpSessionAdmission {
            session,
            first_datagram,
            socket,
            socket_guard,
            owner_slot,
        })
    }

    /// Commits the first validated datagram and starts exactly one owned task.
    pub fn commit_session(
        &mut self,
        admission: DirectUdpSessionAdmission<F::Socket>,
        datagram: Datagram,
        now: Instant,
    ) -> Result<UdpSessionHandle, UdpRuntimeError> {
        match self.commit_session_with(admission, datagram, now, || Ok::<(), Infallible>(())) {
            Ok(handle) => Ok(handle),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Atomically rechecks generation, runs protocol commit, and starts one task.
    pub fn commit_session_with<E, C>(
        &mut self,
        admission: DirectUdpSessionAdmission<F::Socket>,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<UdpSessionHandle, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        let DirectUdpSessionAdmission {
            session,
            first_datagram,
            socket,
            socket_guard,
            owner_slot,
        } = admission;
        let handle = session.commit_with(first_datagram, datagram, now, protocol_commit)?;
        let manager = self.manager.clone();
        let resolver = Arc::clone(&self.resolver);
        let handler = Arc::clone(&self.handler);
        let connect_timeout = self.connect_timeout;
        let registry = self.registry.clone();
        let task_guard = self.registry.track_udp_task();
        let owner_lifetime = DirectOwnerLifetime {
            task_guard: Some(task_guard),
            socket_guard: Some(socket_guard),
            owner_slot: Some(owner_slot),
        };
        self.tasks.spawn(async move {
            let _owner_lifetime = owner_lifetime;
            let _ = run_direct_session(
                manager.clone(),
                resolver,
                handler,
                socket,
                handle,
                connect_timeout,
                registry,
            )
            .await;
            manager.remove(handle);
        });
        Ok(handle)
    }

    /// Reserves a live session's request capacity before replay commit.
    pub fn reserve_datagram(
        &self,
        handle: UdpSessionHandle,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        self.manager
            .reserve_datagram(handle, UdpDirection::ToTarget, allocated_capacity)
    }

    /// Invalidates one session generation and wakes its owner task.
    pub fn remove_session(&self, handle: UdpSessionHandle) -> bool {
        self.manager.remove(handle)
    }

    /// Cancels, joins, and if necessary aborts every owned task by one deadline.
    pub async fn shutdown(self, grace: Duration) {
        self.shutdown_with_control(UdpShutdownControl::Relative(Instant::now() + grace))
            .await;
    }

    /// Drains until the process lineage forces shutdown, then cancels and reaps
    /// every owned task without starting another relative grace interval.
    pub async fn shutdown_with_cancellation(self, cancellation: ProcessCancellation) {
        self.shutdown_with_control(UdpShutdownControl::Process(cancellation))
            .await;
    }

    async fn shutdown_with_control(mut self, mut control: UdpShutdownControl) {
        self.manager.signal_all();
        if self.tasks.is_empty() {
            self.manager.cancel_all();
            return;
        }
        loop {
            tokio::select! {
                biased;
                () = control.forced() => break,
                result = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if result.is_none() || self.tasks.is_empty() {
                        self.manager.cancel_all();
                        return;
                    }
                }
            }
        }
        self.registry.record_udp_forced_shutdowns(self.tasks.len());
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.manager.cancel_all();
    }
}

enum UdpShutdownControl {
    Relative(Instant),
    Process(ProcessCancellation),
}

impl UdpShutdownControl {
    async fn forced(&mut self) {
        match self {
            Self::Relative(deadline) => tokio::time::sleep_until(*deadline).await,
            Self::Process(cancellation) => cancellation.forced().await,
        }
    }
}

async fn run_direct_session<R, H, S>(
    manager: UdpSessionManager,
    resolver: Arc<R>,
    handler: Arc<H>,
    socket: S,
    handle: UdpSessionHandle,
    connect_timeout: Duration,
    registry: OwnerRegistry,
) -> Result<(), UdpRuntimeError>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    H: DirectUdpPacketHandler,
    S: DirectUdpSocket,
{
    let mut cancellation = manager.cancellation(handle)?;
    let notify = manager.notify(handle)?;
    loop {
        while let Some(request) = manager.pop(handle, UdpDirection::ToTarget)? {
            send_direct(&socket, &*resolver, request.datagram(), connect_timeout).await?;
        }
        if *cancellation.borrow() {
            return Err(UdpRuntimeError::Cancelled);
        }
        let idle_deadline = manager.idle_deadline(handle)?;
        tokio::select! {
            biased;
            changed = cancellation.changed() => {
                let _ = changed;
                while let Some(request) = manager.pop(handle, UdpDirection::ToTarget)? {
                    send_direct(&socket, &*resolver, request.datagram(), connect_timeout).await?;
                }
                return Err(UdpRuntimeError::Cancelled);
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                if Instant::now() >= manager.idle_deadline(handle)? {
                    return Err(UdpRuntimeError::Idle);
                }
            }
            () = notify.notified() => {}
            response = receive_target(
                &socket,
                manager.buffer_budget(),
                registry.clone(),
            ) => {
                let response = response?;
                manager.enqueue_accounted(
                    handle,
                    UdpDirection::ToClient,
                    response,
                )?;
                let response = manager
                    .pop(handle, UdpDirection::ToClient)?
                    .ok_or(UdpRuntimeError::Receive)?;
                handler
                    .handle_target_response(handle, response)
                    .await
                    .map_err(|_| UdpRuntimeError::Receive)?;
                manager.commit_activity(handle, Instant::now())?;
            }
        }
    }
}

async fn receive_target<S>(
    socket: &S,
    budget: UdpBufferBudget,
    registry: OwnerRegistry,
) -> Result<AccountedDatagram, UdpRuntimeError>
where
    S: DirectUdpSocket,
{
    let reservation = budget
        .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
        .await?;
    let scratch_guard = registry.track_udp_scratch();
    let mut scratch = BytesMut::zeroed(MAX_UDP_WIRE_DATAGRAM_BYTES);
    if scratch.capacity() != reservation.capacity() {
        return Err(UdpRuntimeError::Bounds);
    }
    let (length, source) = socket
        .recv_from(&mut scratch)
        .await
        .map_err(|_| UdpRuntimeError::Receive)?;
    if length > MAX_UDP_WIRE_DATAGRAM_BYTES {
        return Err(UdpRuntimeError::Bounds);
    }
    scratch.truncate(length);
    drop(scratch_guard);
    let target = ferrum2_core::TargetAddr::ip(source).map_err(|_| UdpRuntimeError::Bounds)?;
    let datagram = Datagram::new(target, scratch, MAX_UDP_WIRE_DATAGRAM_BYTES)
        .map_err(|_| UdpRuntimeError::Bounds)?;
    reservation.attach(datagram)
}

async fn send_direct<R, S>(
    socket: &S,
    resolver: &R,
    datagram: &Datagram,
    timeout: Duration,
) -> Result<(), UdpRuntimeError>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    S: DirectUdpSocket,
{
    let deadline = Instant::now() + timeout;
    if let Some(target) = datagram.target().as_socket_addr() {
        return send_candidate(socket, datagram.payload(), target, deadline).await;
    }

    let ferrum2_core::TargetHostRef::Domain(host) = datagram.target().host() else {
        return Err(UdpRuntimeError::Resolve);
    };
    let candidates = match tokio::time::timeout_at(
        deadline,
        resolver.resolve(host, datagram.target().port().get()),
    )
    .await
    {
        Ok(Ok(candidates)) => candidates,
        Ok(Err(_)) => return Err(UdpRuntimeError::Resolve),
        Err(_) => return Err(UdpRuntimeError::Send),
    };
    let mut attempted = false;
    for candidate in candidates.into_iter().take(MAX_UDP_RESOLVED_CANDIDATES) {
        attempted = true;
        if send_candidate(socket, datagram.payload(), candidate, deadline)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(UdpRuntimeError::Send);
        }
    }
    if attempted {
        Err(UdpRuntimeError::Send)
    } else {
        Err(UdpRuntimeError::Resolve)
    }
}

async fn send_candidate<S>(
    socket: &S,
    payload: &[u8],
    target: SocketAddr,
    deadline: Instant,
) -> Result<(), UdpRuntimeError>
where
    S: DirectUdpSocket,
{
    match tokio::time::timeout_at(deadline, socket.send_to(payload, target)).await {
        Ok(Ok(length)) if length == payload.len() => Ok(()),
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Err(UdpRuntimeError::Send),
    }
}

/// Provisional session capacity that rolls back unless atomically activated.
pub struct PendingUdpSession {
    manager: Arc<UdpSessionManagerInner>,
    handle: UdpSessionHandle,
    committed: bool,
}

impl PendingUdpSession {
    /// Returns the opaque generation for protocol-side capability binding.
    pub const fn handle(&self) -> UdpSessionHandle {
        self.handle
    }

    /// Reserves the first datagram without making the session active.
    pub fn reserve_datagram(
        &self,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.manager,
            self.handle,
            direction,
            allocated_capacity,
            false,
        )
    }

    /// Activates this generation and enqueues its first post-validation datagram.
    pub fn commit(
        self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<UdpSessionHandle, UdpRuntimeError> {
        match self.commit_with(datagram_reservation, datagram, now, || {
            Ok::<(), Infallible>(())
        }) {
            Ok(handle) => Ok(handle),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Serializes generation recheck, protocol commit, activity, and enqueue.
    pub fn commit_with<E, C>(
        mut self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<UdpSessionHandle, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        if datagram_reservation.handle != self.handle {
            return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
        }
        datagram_reservation.commit_inner_with(datagram, now, true, protocol_commit)?;
        self.committed = true;
        Ok(self.handle)
    }
}

impl fmt::Debug for PendingUdpSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingUdpSession([redacted])")
    }
}

impl Drop for PendingUdpSession {
    fn drop(&mut self) {
        if !self.committed {
            let manager = UdpSessionManager {
                inner: Arc::clone(&self.manager),
            };
            manager.remove(self.handle);
        }
    }
}

/// Reserved queue and byte capacity that has not advanced accepted activity.
pub struct PendingUdpDatagram {
    manager: Weak<UdpSessionManagerInner>,
    handle: UdpSessionHandle,
    direction: UdpDirection,
    reservation: Option<UdpBufferReservation>,
    pending: bool,
}

impl PendingUdpDatagram {
    /// Enqueues a datagram after the protocol owner completes its atomic commit.
    pub fn commit(self, datagram: Datagram, now: Instant) -> Result<(), UdpRuntimeError> {
        match self.commit_with(datagram, now, || Ok::<(), Infallible>(())) {
            Ok(()) => Ok(()),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Serializes generation recheck, protocol commit, activity, and enqueue.
    pub fn commit_with<E, C>(
        self,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<(), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        self.commit_inner_with(datagram, now, false, protocol_commit)
    }

    fn commit_inner_with<E, C>(
        mut self,
        datagram: Datagram,
        now: Instant,
        activate_session: bool,
        protocol_commit: C,
    ) -> Result<(), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        let manager = self
            .manager
            .upgrade()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let reservation = self
            .reservation
            .take()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let accounted = reservation
            .attach(datagram)
            .map_err(UdpCommitError::Runtime)?;
        let notify = {
            let mut state = manager
                .state
                .lock()
                .expect("UDP session state lock poisoned");
            if state.shutting_down {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            let entry =
                matching_entry_mut(&mut state, self.handle).map_err(UdpCommitError::Runtime)?;
            if entry.committed == activate_session {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            protocol_commit().map_err(UdpCommitError::Protocol)?;
            let index = self.direction.index();
            debug_assert!(entry.pending[index] > 0);
            entry.pending[index] -= 1;
            entry.committed = true;
            entry.last_activity = now;
            entry.queues[index].push_back(QueuedDatagram {
                datagram: accounted,
                _guard: manager.registry.track_udp_queue_entry(),
            });
            Arc::clone(&entry.notify)
        };
        self.pending = false;
        notify.notify_one();
        Ok(())
    }
}

impl fmt::Debug for PendingUdpDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingUdpDatagram([redacted])")
    }
}

impl Drop for PendingUdpDatagram {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        let Some(manager) = self.manager.upgrade() else {
            return;
        };
        let mut state = manager
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if let Ok(entry) = matching_entry_mut(&mut state, self.handle) {
            let pending = &mut entry.pending[self.direction.index()];
            debug_assert!(*pending > 0);
            *pending -= 1;
        }
    }
}

fn reserve_datagram(
    manager: &Arc<UdpSessionManagerInner>,
    handle: UdpSessionHandle,
    direction: UdpDirection,
    allocated_capacity: usize,
    require_committed: bool,
) -> Result<PendingUdpDatagram, UdpRuntimeError> {
    let reservation = manager.budget.reserve(allocated_capacity)?;
    let mut state = manager
        .state
        .lock()
        .expect("UDP session state lock poisoned");
    if state.shutting_down {
        return Err(UdpRuntimeError::Cancelled);
    }
    let entry = matching_entry_mut(&mut state, handle)?;
    if entry.committed != require_committed {
        return Err(UdpRuntimeError::Cancelled);
    }
    let index = direction.index();
    if entry.pending[index] + entry.queues[index].len() >= UDP_SESSION_QUEUE_DEPTH {
        return Err(UdpRuntimeError::QueueFull);
    }
    entry.pending[index] += 1;
    Ok(PendingUdpDatagram {
        manager: Arc::downgrade(manager),
        handle,
        direction,
        reservation: Some(reservation),
        pending: true,
    })
}

fn entry_matches(state: &SessionState, handle: UdpSessionHandle) -> bool {
    state
        .entries
        .get(&handle.slot)
        .is_some_and(|entry| entry.generation == handle.generation)
}

fn matching_entry(
    state: &SessionState,
    handle: UdpSessionHandle,
) -> Result<&SessionEntry, UdpRuntimeError> {
    state
        .entries
        .get(&handle.slot)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

fn matching_entry_mut(
    state: &mut SessionState,
    handle: UdpSessionHandle,
) -> Result<&mut SessionEntry, UdpRuntimeError> {
    state
        .entries
        .get_mut(&handle.slot)
        .filter(|entry| entry.generation == handle.generation)
        .ok_or(UdpRuntimeError::Cancelled)
}

fn remove_entry(state: &mut SessionState, slot: u32) {
    if let Some(entry) = state.entries.remove(&slot) {
        entry.cancellation.send_replace(true);
        entry.notify.notify_waiters();
    }
}
