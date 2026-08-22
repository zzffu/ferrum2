use std::collections::{BTreeMap, VecDeque};
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
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, broadcast, watch};
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
/// Bounded per-association last-success candidate hints.
const UDP_CANDIDATE_HINT_ENTRIES: usize = 16;

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
    ///
    /// The atomic is only a numeric capacity gate; it does not publish buffer
    /// contents or session state, which remain protected by their own owners.
    pub fn reserved_bytes(&self) -> usize {
        self.inner.reserved.load(Ordering::Relaxed)
    }

    /// Reserves exact allocated capacity before accepted protocol state advances.
    pub fn reserve(&self, capacity: usize) -> Result<UdpBufferReservation, UdpRuntimeError> {
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        let mut current = self.inner.reserved.load(Ordering::Relaxed);
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
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.inner.registry.add_udp_buffered_bytes(capacity);
                    return Ok(UdpBufferReservation {
                        inner: Some(Arc::clone(&self.inner)),
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
            tokio::pin!(notified);
            match self.reserve(capacity) {
                Ok(reservation) => return Ok(reservation),
                Err(UdpRuntimeError::BufferLimit) => {
                    notified.as_mut().enable();
                    match self.reserve(capacity) {
                        Ok(reservation) => return Ok(reservation),
                        Err(UdpRuntimeError::BufferLimit) => notified.as_mut().await,
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Ownership token for one exact allocated buffer capacity.
///
/// Ordinary tokens carry the global UDP byte-budget charge. Runtime session
/// APIs may also create an unmetered token for a structurally bounded caller;
/// both kinds retain the same exact-capacity validation at commit time.
pub struct UdpBufferReservation {
    inner: Option<Arc<BufferBudgetInner>>,
    capacity: usize,
}

impl UdpBufferReservation {
    fn unmetered(capacity: usize) -> Result<Self, UdpRuntimeError> {
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            inner: None,
            capacity,
        })
    }

    /// Returns the exact allocated capacity owned by this token.
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
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        let previous = inner.reserved.fetch_sub(self.capacity, Ordering::Relaxed);
        debug_assert!(
            previous >= self.capacity,
            "UDP buffer reservation underflow"
        );
        inner.registry.remove_udp_buffered_bytes(self.capacity);
        if self.capacity != 0 {
            inner.released.notify_waiters();
        }
    }
}

/// Datagram coupled to exactly one allocated-capacity ownership token.
pub struct AccountedDatagram {
    datagram: Datagram,
    reservation: UdpBufferReservation,
}

impl AccountedDatagram {
    /// Returns the bounded datagram.
    pub fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    /// Returns the owned backing capacity.
    pub const fn allocated_capacity(&self) -> usize {
        self.reservation.capacity()
    }

    /// Separates the datagram from its exact capacity owner for a caller that
    /// recycles the backing allocation into another already-owned buffer.
    /// The reservation must remain alive until that transfer is complete.
    pub fn into_parts(self) -> (Datagram, UdpBufferReservation) {
        (self.datagram, self.reservation)
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
    owner_slots: Arc<Semaphore>,
    runtime_owners: AtomicUsize,
    running_runtimes: AtomicUsize,
    state: Mutex<SessionState>,
    removal_events: broadcast::Sender<UdpSessionHandle>,
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
        let (removal_events, _) = broadcast::channel(limits.max_sessions());
        Self {
            inner: Arc::new(UdpSessionManagerInner {
                limits,
                budget,
                owner_slots: Arc::new(Semaphore::new(limits.max_sessions())),
                runtime_owners: AtomicUsize::new(0),
                running_runtimes: AtomicUsize::new(0),
                state: Mutex::new(SessionState::default()),
                removal_events,
                registry,
            }),
        }
    }

    /// Returns the global allocated-capacity reservation owner.
    pub fn buffer_budget(&self) -> UdpBufferBudget {
        self.inner.budget.clone()
    }

    fn owner_slots(&self) -> Arc<Semaphore> {
        Arc::clone(&self.inner.owner_slots)
    }

    fn runtime_owner(&self) -> UdpRuntimeOwner {
        self.inner.runtime_owners.fetch_add(1, Ordering::Relaxed);
        self.inner.running_runtimes.fetch_add(1, Ordering::Relaxed);
        UdpRuntimeOwner {
            manager: self.clone(),
            shutdown_started: false,
        }
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

    /// Subscribes to exact generation removals for event-driven mapping
    /// invalidation. A lagged receiver must fall back to a batch liveness pass.
    pub fn subscribe_removals(&self) -> broadcast::Receiver<UdpSessionHandle> {
        self.inner.removal_events.subscribe()
    }

    /// Retains only committed live generations using one read-only state lock.
    ///
    /// Shutdown, missing or stale generations, and provisional sessions are
    /// not live. Queue and buffer capacity do not affect liveness, and this
    /// check does not reserve capacity, refresh activity, or wake workers.
    pub fn retain_live_sessions(&self, handles: &mut Vec<UdpSessionHandle>) {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if state.shutting_down {
            handles.clear();
            return;
        }
        handles.retain(|handle| {
            state
                .entries
                .get(&handle.slot)
                .is_some_and(|entry| entry.generation == handle.generation && entry.committed)
        });
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
            if let Some(slot) = expired
                && let Some(handle) = remove_entry(&mut state, slot)
            {
                publish_removal(&self.inner, handle);
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
        let pending = PendingUdpSession {
            manager: Arc::clone(&self.inner),
            handle,
            committed: false,
        };
        Ok(pending)
    }

    /// Reserves one queue slot and its exact backing capacity for a live session.
    pub fn reserve_datagram(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.inner,
            handle,
            direction,
            allocated_capacity,
            true,
            true,
        )
    }

    /// Reserves one queue slot without charging the global UDP byte budget.
    ///
    /// This is only for callers whose datagrams remain structurally bounded by
    /// independent packet, queue, and owner-count limits. Bounds, queue depth,
    /// session generation, cancellation, and reserve-then-commit checks remain
    /// identical to [`Self::reserve_datagram`].
    pub fn reserve_unmetered_datagram(
        &self,
        handle: UdpSessionHandle,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.inner,
            handle,
            direction,
            allocated_capacity,
            true,
            false,
        )
    }

    /// Removes one exact generation and invalidates every late capability.
    pub fn remove(&self, handle: UdpSessionHandle) -> bool {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        let removed = if entry_matches(&state, handle) {
            remove_entry(&mut state, handle.slot)
        } else {
            None
        };
        drop(state);
        if let Some(handle) = removed {
            publish_removal(&self.inner, handle);
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
        let removed: Vec<_> = slots
            .into_iter()
            .filter_map(|slot| remove_entry(&mut state, slot))
            .collect();
        drop(state);
        for handle in removed {
            publish_removal(&self.inner, handle);
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

    fn validate_direct_response(&self, handle: UdpSessionHandle) -> Result<(), UdpRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        if state.shutting_down {
            return Err(UdpRuntimeError::Cancelled);
        }
        let entry = matching_entry(&state, handle)?;
        if !entry.committed {
            return Err(UdpRuntimeError::Cancelled);
        }
        let index = UdpDirection::ToClient.index();
        if entry.pending[index] + entry.queues[index].len() >= UDP_SESSION_QUEUE_DEPTH {
            return Err(UdpRuntimeError::QueueFull);
        }
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

    /// Subscribes to cancellation for one exact live generation.
    pub fn cancellation(
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

    /// Returns the manager-owned idle deadline for one exact live generation.
    pub fn idle_deadline(&self, handle: UdpSessionHandle) -> Result<Instant, UdpRuntimeError> {
        let state = self
            .inner
            .state
            .lock()
            .expect("UDP session state lock poisoned");
        Ok(matching_entry(&state, handle)?.last_activity + self.inner.limits.idle_timeout())
    }
}

struct UdpRuntimeOwner {
    manager: UdpSessionManager,
    shutdown_started: bool,
}

impl UdpRuntimeOwner {
    fn begin_shutdown(&mut self) {
        if !self.shutdown_started {
            self.shutdown_started = true;
            if self
                .manager
                .inner
                .running_runtimes
                .fetch_sub(1, Ordering::AcqRel)
                == 1
            {
                self.manager.signal_all();
            }
        }
    }
}

impl Drop for UdpRuntimeOwner {
    fn drop(&mut self) {
        self.begin_shutdown();
        if self
            .manager
            .inner
            .runtime_owners
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            self.manager.cancel_all();
        }
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

    /// Waits until a non-blocking receive attempt may make progress.
    fn readable(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Receives one complete target datagram and its source address.
    fn recv_buf_from(
        &self,
        payload: &mut BytesMut,
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    /// Attempts one non-blocking receive into spare `BytesMut` capacity.
    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)>;
}

impl DirectUdpSocket for UdpSocket {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, payload, target).await
    }

    async fn readable(&self) -> io::Result<()> {
        UdpSocket::readable(self).await
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_buf_from(self, payload).await
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::try_recv_buf_from(self, payload)
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

    async fn readable(&self) -> io::Result<()> {
        self.socket.readable().await
    }

    async fn recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let (length, source) = self.socket.recv_buf_from(payload).await?;
        Ok((length, normalize_direct_source(source)))
    }

    fn try_recv_buf_from(&self, payload: &mut BytesMut) -> io::Result<(usize, SocketAddr)> {
        let (length, source) = self.socket.try_recv_buf_from(payload)?;
        Ok((length, normalize_direct_source(source)))
    }
}

fn normalize_direct_source(source: SocketAddr) -> SocketAddr {
    match source {
        SocketAddr::V6(source) => match source.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, source.port())),
            None => SocketAddr::V6(source),
        },
        SocketAddr::V4(source) => SocketAddr::V4(source),
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
    _runtime_owner: UdpRuntimeOwner,
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
        Self::with_shared_adapters(
            UdpSessionManager::new(limits, registry.clone()),
            connect_timeout,
            SystemUdpResolver,
            SystemDirectUdpSocketFactory,
            handler,
            registry,
        )
    }

    /// Creates one production runtime sharing aggregate process UDP capacity.
    pub fn with_shared_capacity(
        manager: UdpSessionManager,
        connect_timeout: Duration,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        Self::with_shared_adapters(
            manager,
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
        Self::with_shared_adapters(
            UdpSessionManager::new(limits, registry.clone()),
            connect_timeout,
            resolver,
            socket_factory,
            handler,
            registry,
        )
    }

    /// Creates one runtime sharing aggregate session, byte, and owner capacity.
    pub fn with_shared_adapters(
        manager: UdpSessionManager,
        connect_timeout: Duration,
        resolver: R,
        socket_factory: F,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        let owner_slots = manager.owner_slots();
        let runtime_owner = manager.runtime_owner();
        Self {
            manager,
            resolver: Arc::new(resolver),
            socket_factory,
            handler: Arc::new(handler),
            connect_timeout,
            registry,
            tasks: JoinSet::new(),
            owner_slots,
            _runtime_owner: runtime_owner,
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
        self.commit_session_with_resolver_arc(
            admission,
            datagram,
            now,
            Arc::clone(&self.resolver),
            protocol_commit,
        )
    }

    /// Atomically commits one session with a resolver fixed for that session.
    ///
    /// This is used when the selected direct outbound owns its resolver policy.
    /// Later changes to routing or another outbound cannot change the resolver
    /// used by the already-committed UDP generation.
    pub fn commit_session_with_resolver<E, C>(
        &mut self,
        admission: DirectUdpSessionAdmission<F::Socket>,
        datagram: Datagram,
        now: Instant,
        resolver: R,
        protocol_commit: C,
    ) -> Result<UdpSessionHandle, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        self.commit_session_with_resolver_arc(
            admission,
            datagram,
            now,
            Arc::new(resolver),
            protocol_commit,
        )
    }

    fn commit_session_with_resolver_arc<E, C>(
        &mut self,
        admission: DirectUdpSessionAdmission<F::Socket>,
        datagram: Datagram,
        now: Instant,
        resolver: Arc<R>,
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
    pub async fn shutdown(self, grace: Duration) -> usize {
        self.shutdown_with_control(UdpShutdownControl::Relative(Instant::now() + grace))
            .await
    }

    /// Drains until the process lineage forces shutdown, then cancels and reaps
    /// every owned task without starting another relative grace interval.
    pub async fn shutdown_with_cancellation(self, cancellation: ProcessCancellation) -> usize {
        self.shutdown_with_control(UdpShutdownControl::Process(cancellation))
            .await
    }

    async fn shutdown_with_control(mut self, mut control: UdpShutdownControl) -> usize {
        self._runtime_owner.begin_shutdown();
        if self.tasks.is_empty() {
            return 0;
        }
        loop {
            tokio::select! {
                biased;
                result = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if result.is_none() || self.tasks.is_empty() {
                        return 0;
                    }
                }
                () = control.forced() => break,
            }
        }
        let forced = self.tasks.len();
        self.registry.record_udp_forced_shutdowns(forced);
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        forced
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

struct UdpCandidateHint {
    host: String,
    port: u16,
    last_successful_index: usize,
}

#[derive(Default)]
struct UdpAssociationCandidateHints {
    entries: VecDeque<UdpCandidateHint>,
}

impl UdpAssociationCandidateHints {
    fn start_index(&self, host: &str, port: u16) -> usize {
        self.entries
            .iter()
            .find(|entry| entry.host == host && entry.port == port)
            .map_or(0, |entry| entry.last_successful_index)
    }

    fn record_success(&mut self, host: &str, port: u16, last_successful_index: usize) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.host == host && entry.port == port)
        {
            self.entries.remove(index);
        } else if self.entries.len() == UDP_CANDIDATE_HINT_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(UdpCandidateHint {
            host: host.to_owned(),
            port,
            last_successful_index,
        });
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
    let mut candidate_hints = UdpAssociationCandidateHints::default();
    loop {
        while let Some(request) = manager.pop(handle, UdpDirection::ToTarget)? {
            send_direct(
                &socket,
                &*resolver,
                &mut candidate_hints,
                request.datagram(),
                connect_timeout,
            )
            .await?;
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
                    send_direct(
                        &socket,
                        &*resolver,
                        &mut candidate_hints,
                        request.datagram(),
                        connect_timeout,
                    )
                    .await?;
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
                // This task is the sole consumer of direct target responses and
                // awaits the handler before receiving another one. Preserve the
                // generation, shutdown, and queue-capacity checks without a
                // same-task enqueue/notify/pop round trip.
                manager.validate_direct_response(handle)?;
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
    loop {
        socket
            .readable()
            .await
            .map_err(|_| UdpRuntimeError::Receive)?;
        let reservation = budget
            .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
            .await?;
        let scratch_guard = registry.track_udp_scratch();
        let mut scratch = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
        if scratch.capacity() != reservation.capacity() {
            return Err(UdpRuntimeError::Bounds);
        }
        let (length, source) = match socket.try_recv_buf_from(&mut scratch) {
            Ok(received) => received,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(UdpRuntimeError::Receive),
        };
        if length > MAX_UDP_WIRE_DATAGRAM_BYTES || scratch.len() != length {
            return Err(UdpRuntimeError::Bounds);
        }
        drop(scratch_guard);
        let target = ferrum2_core::TargetAddr::ip(source).map_err(|_| UdpRuntimeError::Bounds)?;
        let datagram = Datagram::new(target, scratch, MAX_UDP_WIRE_DATAGRAM_BYTES)
            .map_err(|_| UdpRuntimeError::Bounds)?;
        return reservation.attach(datagram);
    }
}

async fn send_direct<R, S>(
    socket: &S,
    resolver: &R,
    candidate_hints: &mut UdpAssociationCandidateHints,
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
    let port = datagram.target().port().get();
    let candidates = resolve_candidates(resolver, host, port, deadline).await?;
    let start_index = candidate_hints.start_index(host, port);
    match send_candidates(
        socket,
        datagram.payload(),
        &candidates,
        start_index,
        deadline,
    )
    .await
    {
        Ok(index) => {
            candidate_hints.record_success(host, port, index);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn resolve_candidates<R>(
    resolver: &R,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, UdpRuntimeError>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
{
    let candidates = match tokio::time::timeout_at(deadline, resolver.resolve(host, port)).await {
        Ok(Ok(candidates)) => candidates,
        Ok(Err(_)) => return Err(UdpRuntimeError::Resolve),
        Err(_) => return Err(UdpRuntimeError::Send),
    };
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

async fn send_candidates<S>(
    socket: &S,
    payload: &[u8],
    candidates: &[SocketAddr],
    start: usize,
    deadline: Instant,
) -> Result<usize, UdpRuntimeError>
where
    S: DirectUdpSocket,
{
    if candidates.is_empty() {
        return Err(UdpRuntimeError::Resolve);
    }
    for offset in 0..candidates.len() {
        let index = (start + offset) % candidates.len();
        if send_candidate(socket, payload, candidates[index], deadline)
            .await
            .is_ok()
        {
            return Ok(index);
        }
        if Instant::now() >= deadline {
            return Err(UdpRuntimeError::Send);
        }
    }
    Err(UdpRuntimeError::Send)
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
            true,
        )
    }

    /// Reserves the first datagram without charging the global UDP byte budget.
    ///
    /// This is only for callers whose datagrams remain structurally bounded by
    /// independent packet, queue, and owner-count limits. Bounds, queue depth,
    /// session generation, cancellation, and reserve-then-commit checks remain
    /// identical to [`Self::reserve_datagram`].
    pub fn reserve_unmetered_datagram(
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

    /// Activates this generation and returns its first datagram directly to
    /// the sole same-task consumer without a queue or notification round trip.
    pub fn commit_immediate(
        self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<(UdpSessionHandle, AccountedDatagram), UdpRuntimeError> {
        match self.commit_immediate_with(datagram_reservation, datagram, now, || {
            Ok::<(), Infallible>(())
        }) {
            Ok(result) => Ok(result),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Atomically activates this generation, commits protocol state, and
    /// returns the accounted first datagram without publishing it to a queue.
    pub fn commit_immediate_with<E, C>(
        mut self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<(UdpSessionHandle, AccountedDatagram), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        if datagram_reservation.handle != self.handle
            || datagram_reservation.manager.as_ptr() != Arc::as_ptr(&self.manager)
        {
            return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
        }
        let datagram = datagram_reservation.commit_immediate_inner_with(
            datagram,
            now,
            true,
            protocol_commit,
        )?;
        self.committed = true;
        Ok((self.handle, datagram))
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
        if datagram_reservation.handle != self.handle
            || datagram_reservation.manager.as_ptr() != Arc::as_ptr(&self.manager)
        {
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

    /// Commits accepted activity and returns this datagram directly to the
    /// sole same-task consumer without queue ownership or notification work.
    pub fn commit_immediate(
        self,
        datagram: Datagram,
        now: Instant,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        match self.commit_immediate_with(datagram, now, || Ok::<(), Infallible>(())) {
            Ok(datagram) => Ok(datagram),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Atomically rechecks generation, commits protocol state and activity,
    /// and returns this datagram without publishing it to a queue.
    pub fn commit_immediate_with<E, C>(
        self,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<AccountedDatagram, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        self.commit_immediate_inner_with(datagram, now, false, protocol_commit)
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

    fn commit_immediate_inner_with<E, C>(
        mut self,
        datagram: Datagram,
        now: Instant,
        activate_session: bool,
        protocol_commit: C,
    ) -> Result<AccountedDatagram, UdpCommitError<E>>
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
        {
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
        }
        self.pending = false;
        Ok(accounted)
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
    meter_buffer: bool,
) -> Result<PendingUdpDatagram, UdpRuntimeError> {
    let reservation = if meter_buffer {
        manager.budget.reserve(allocated_capacity)?
    } else {
        UdpBufferReservation::unmetered(allocated_capacity)?
    };
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

fn remove_entry(state: &mut SessionState, slot: u32) -> Option<UdpSessionHandle> {
    if let Some(entry) = state.entries.remove(&slot) {
        let handle = UdpSessionHandle {
            slot,
            generation: entry.generation,
        };
        entry.cancellation.send_replace(true);
        entry.notify.notify_waiters();
        Some(handle)
    } else {
        None
    }
}

fn publish_removal(manager: &UdpSessionManagerInner, handle: UdpSessionHandle) {
    let _ = manager.removal_events.send(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exhaust_budget(budget: &UdpBufferBudget, limit: usize) -> Vec<UdpBufferReservation> {
        let mut remaining = limit
            .checked_sub(budget.reserved_bytes())
            .expect("test budget is not overcommitted");
        let mut held = Vec::new();
        while remaining != 0 {
            let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            held.push(budget.reserve(capacity).expect("fill test budget"));
            remaining -= capacity;
        }
        held
    }

    fn test_datagram(capacity: usize) -> Datagram {
        let mut payload = BytesMut::with_capacity(capacity);
        payload.extend_from_slice(b"x");
        assert_eq!(payload.capacity(), capacity);
        Datagram::new(
            ferrum2_core::TargetAddr::ip("192.0.2.1:53".parse().expect("test target"))
                .expect("nonzero target port"),
            payload,
            capacity,
        )
        .expect("bounded datagram")
    }

    #[test]
    fn unmetered_datagrams_bypass_only_the_global_byte_budget() {
        let limit = MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(2, limit, MIN_UDP_IDLE_TIMEOUT).expect("test limits"),
            OwnerRegistry::new(),
        );
        let budget = manager.buffer_budget();
        let held = exhaust_budget(&budget, limit);
        assert_eq!(budget.reserved_bytes(), limit);

        let session = manager
            .reserve_session(Instant::now())
            .expect("provisional session");
        assert_eq!(
            session
                .reserve_datagram(UdpDirection::ToTarget, 8)
                .expect_err("metered datagram must observe the full budget"),
            UdpRuntimeError::BufferLimit
        );
        assert_eq!(
            session
                .reserve_unmetered_datagram(
                    UdpDirection::ToTarget,
                    MAX_UDP_WIRE_DATAGRAM_BYTES + 1,
                )
                .expect_err("unmetered datagrams retain the packet bound"),
            UdpRuntimeError::Bounds
        );
        let first = session
            .reserve_unmetered_datagram(UdpDirection::ToTarget, 8)
            .expect("unmetered first datagram");
        let (handle, first) = session
            .commit_immediate(first, test_datagram(8), Instant::now())
            .expect("activate unmetered session");
        assert_eq!(budget.reserved_bytes(), limit);
        drop(first);
        assert_eq!(budget.reserved_bytes(), limit);

        let pending = (0..UDP_SESSION_QUEUE_DEPTH)
            .map(|_| {
                manager
                    .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                    .expect("bounded pending slot")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            manager
                .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                .expect_err("unmetered datagrams retain queue depth"),
            UdpRuntimeError::QueueFull
        );
        assert_eq!(budget.reserved_bytes(), limit);
        drop(pending);

        assert!(manager.remove(handle));
        assert_eq!(
            manager
                .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                .expect_err("unmetered datagrams retain generation checks"),
            UdpRuntimeError::Cancelled
        );
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn budget_wait_is_cancel_safe_and_release_cannot_be_lost() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let budget = manager.buffer_budget();
        let mut held = Vec::new();
        while let Ok(reservation) = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES) {
            held.push(reservation);
        }
        assert!(!held.is_empty());
        assert_eq!(
            budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES).unwrap_err(),
            UdpRuntimeError::BufferLimit
        );

        let started = Arc::new(Notify::new());
        let cancelled_budget = budget.clone();
        let cancelled_started = Arc::clone(&started);
        let cancelled = tokio::spawn(async move {
            cancelled_started.notify_one();
            cancelled_budget
                .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
                .await
        });
        started.notified().await;
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("cancelled waiter")
                .is_cancelled()
        );

        let started = Arc::new(Notify::new());
        let waiting_budget = budget.clone();
        let waiting_started = Arc::clone(&started);
        let waiting = tokio::spawn(async move {
            waiting_started.notify_one();
            waiting_budget
                .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
                .await
        });
        started.notified().await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        drop(held.pop());
        let acquired = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("released capacity wakes waiter")
            .expect("waiter task")
            .expect("capacity reservation");
        drop(acquired);
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }
}
