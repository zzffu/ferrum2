use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::Datagram;
use ferrum2_net::UdpResolver;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::owner::OwnerGuard;
use crate::{OwnerRegistry, ProcessCancellation};

use super::direct_owner::{
    self, DirectTaskFailure, DirectTaskOwner, DirectTaskRecord, SharedDirectTasks, ShutdownControl,
};
use super::socket::{DirectUdpSocket, DirectUdpSocketFactory, SystemDirectUdpSocketFactory};
use super::{
    AccountedDatagram, MAX_UDP_RESOLVED_CANDIDATES, MAX_UDP_WIRE_DATAGRAM_BYTES,
    PendingUdpDatagram, PendingUdpSession, UDP_CANDIDATE_HINT_ENTRIES, UdpBufferBudget,
    UdpCommitError, UdpDirection, UdpRuntimeError, UdpRuntimeLimits, UdpSessionHandle,
    UdpSessionManager,
};
use super::{DirectUdpCleanup, DirectUdpCompletion, DirectUdpShutdownReport};

/// Protocol-neutral callback for one bounded target response.
pub trait DirectUdpPacketHandler: Send + Sync + 'static {
    /// Closed, source-free handler error retained until the parent observes the
    /// joined completion. Its value is never formatted by the runtime.
    type Error: Send + 'static;

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
    initial_candidates: Option<Vec<SocketAddr>>,
    physical: DirectUdpSocketAdmission<S>,
}

// Field order guarantees physical closure before accounting/capacity release,
// including rejection before the task future has been constructed.
struct DirectUdpSocketAdmission<S> {
    socket: S,
    socket_guard: OwnerGuard,
    owner_slot: OwnedSemaphorePermit,
}

impl<S> fmt::Debug for DirectUdpSessionAdmission<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectUdpSessionAdmission([redacted])")
    }
}

struct DirectUdpSessionRoot<S> {
    socket: S,
    handle: UdpSessionHandle,
    initial_candidates: Option<Vec<SocketAddr>>,
}

struct DirectOwnerLifetime {
    manager: UdpSessionManager,
    session: UdpSessionHandle,
    socket_guard: Option<OwnerGuard>,
}

impl Drop for DirectOwnerLifetime {
    fn drop(&mut self) {
        // Retire the exact generation even if the task is aborted or a caller's
        // handler panics. Publish removal before making owner capacity reusable.
        self.manager.remove(self.session);
        drop(self.socket_guard.take());
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
    tasks: SharedDirectTasks<H::Error>,
    cleanup_taken: bool,
    owner_slots: Arc<Semaphore>,
}

impl<R, H> DirectUdpRuntime<R, SystemDirectUdpSocketFactory, H>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    H: DirectUdpPacketHandler,
{
    /// Creates a production direct UDP runtime without opening a socket or task.
    pub fn new(
        limits: UdpRuntimeLimits,
        connect_timeout: Duration,
        resolver: R,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        Self::with_shared_adapters(
            UdpSessionManager::new(limits, registry.clone()),
            connect_timeout,
            resolver,
            SystemDirectUdpSocketFactory,
            handler,
            registry,
        )
    }

    /// Creates one production runtime sharing aggregate process UDP capacity.
    pub fn with_shared_capacity(
        manager: UdpSessionManager,
        connect_timeout: Duration,
        resolver: R,
        handler: H,
        registry: OwnerRegistry,
    ) -> Self {
        Self::with_shared_adapters(
            manager,
            connect_timeout,
            resolver,
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
        let tasks = Arc::new(Mutex::new(DirectTaskOwner::new(
            manager.clone(),
            registry.clone(),
        )));
        Self {
            manager,
            resolver: Arc::new(resolver),
            socket_factory,
            handler: Arc::new(handler),
            connect_timeout,
            registry,
            tasks,
            cleanup_taken: false,
            owner_slots,
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
        open_context: F::OpenContext,
        selection_destination: SocketAddr,
    ) -> Result<DirectUdpSessionAdmission<F::Socket>, UdpRuntimeError> {
        self.reserve_session_inner(
            now,
            first_allocated_capacity,
            open_context,
            selection_destination,
            None,
        )
        .await
    }

    /// Reserves a session whose first domain target was already resolved for socket selection.
    ///
    /// The bounded candidate set is retained through commit and used for the first datagram,
    /// keeping the socket's selected interface and its first transmission on one resolution
    /// snapshot. Later domain datagrams continue to resolve normally.
    pub async fn reserve_session_with_initial_candidates(
        &mut self,
        now: Instant,
        first_allocated_capacity: usize,
        open_context: F::OpenContext,
        initial_candidates: Vec<SocketAddr>,
    ) -> Result<DirectUdpSessionAdmission<F::Socket>, UdpRuntimeError> {
        let initial_candidates: Vec<_> = initial_candidates
            .into_iter()
            .take(MAX_UDP_RESOLVED_CANDIDATES)
            .collect();
        let selection_destination = initial_candidates
            .first()
            .copied()
            .ok_or(UdpRuntimeError::Resolve)?;
        self.reserve_session_inner(
            now,
            first_allocated_capacity,
            open_context,
            selection_destination,
            Some(initial_candidates),
        )
        .await
    }

    async fn reserve_session_inner(
        &mut self,
        now: Instant,
        first_allocated_capacity: usize,
        open_context: F::OpenContext,
        selection_destination: SocketAddr,
        initial_candidates: Option<Vec<SocketAddr>>,
    ) -> Result<DirectUdpSessionAdmission<F::Socket>, UdpRuntimeError> {
        if !self
            .tasks
            .lock()
            .expect("Direct task owner lock")
            .accepting()
        {
            return Err(UdpRuntimeError::Cancelled);
        }
        let session = self.manager.reserve_session(now)?;
        let owner_slot = Arc::clone(&self.owner_slots)
            .try_acquire_owned()
            .map_err(|_| UdpRuntimeError::SessionLimit)?;
        let first_datagram =
            session.reserve_datagram(UdpDirection::ToTarget, first_allocated_capacity)?;
        let socket = self
            .socket_factory
            .open(open_context, selection_destination)
            .await
            .map_err(|_| UdpRuntimeError::Send)?;
        let socket_guard = self.registry.track_udp_socket();
        Ok(DirectUdpSessionAdmission {
            session,
            first_datagram,
            initial_candidates,
            physical: DirectUdpSocketAdmission {
                socket,
                socket_guard,
                owner_slot,
            },
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
    /// The callback must be bounded, synchronous, nonblocking and nonreentrant;
    /// see [`PendingUdpSession::commit_with`] for its fail-closed obligations.
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
            initial_candidates,
            physical,
        } = admission;
        if !self
            .tasks
            .lock()
            .expect("Direct task owner lock")
            .accepting()
        {
            return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
        }
        let handle = session.commit_with(first_datagram, datagram, now, protocol_commit)?;
        let DirectUdpSocketAdmission {
            socket,
            socket_guard,
            owner_slot,
        } = physical;
        let manager = self.manager.clone();
        let handler = Arc::clone(&self.handler);
        let connect_timeout = self.connect_timeout;
        let registry = self.registry.clone();
        let task_guard = self.registry.track_udp_task();
        let owner_lifetime = DirectOwnerLifetime {
            manager: manager.clone(),
            session: handle,
            socket_guard: Some(socket_guard),
        };
        let resources = DirectTaskResources {
            root: DirectUdpSessionRoot {
                socket,
                handle,
                initial_candidates,
            },
            lifetime: owner_lifetime,
        };
        let mut tasks = self.tasks.lock().expect("Direct task owner lock");
        let id = tasks
            .tasks
            .spawn(async move {
                // Before the first poll, struct field order drops the physical
                // socket before its lifetime acknowledgement. After polling, the
                // child future is dropped before this retained lifetime guard.
                let DirectTaskResources { root, lifetime } = resources;
                let _lifetime = lifetime;
                run_direct_session(manager, resolver, handler, root, connect_timeout, registry)
                    .await
            })
            .id();
        tasks
            .records
            .insert(id, DirectTaskRecord::new(handle, task_guard, owner_slot));
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

    /// Takes the external cleanup custody once, before a run future can be aborted.
    pub fn take_cleanup(&mut self) -> Option<DirectUdpCleanup<H::Error>> {
        if self.cleanup_taken {
            return None;
        }
        self.cleanup_taken = true;
        Some(DirectUdpCleanup {
            tasks: Arc::clone(&self.tasks),
        })
    }

    /// Returns a ready joined completion without retaining an event queue.
    pub fn try_next_completion(&mut self) -> Option<DirectUdpCompletion<H::Error>> {
        self.tasks
            .lock()
            .expect("Direct task owner lock")
            .try_completion()
    }

    /// Waits for one joined terminal. A cancelled await retains task custody.
    pub async fn next_completion(&mut self) -> Option<DirectUdpCompletion<H::Error>> {
        direct_owner::next_completion(&self.tasks).await
    }

    /// Returns whether admitted-but-unjoined tasks remain.
    pub fn has_tasks(&self) -> bool {
        !self
            .tasks
            .lock()
            .expect("Direct task owner lock")
            .tasks
            .is_empty()
    }

    /// Cancels, joins, and if necessary aborts every owned task by one deadline.
    /// Cancelling this await preserves task and completion data for a retry.
    pub async fn shutdown(&mut self, grace: Duration) -> DirectUdpShutdownReport<H::Error> {
        direct_owner::shutdown(
            &self.tasks,
            ShutdownControl::Relative(Instant::now() + grace),
        )
        .await
    }

    /// Uses the process shutdown lineage rather than starting another grace interval.
    pub async fn shutdown_with_cancellation(
        &mut self,
        cancellation: ProcessCancellation,
    ) -> DirectUdpShutdownReport<H::Error> {
        direct_owner::shutdown(&self.tasks, ShutdownControl::Process(cancellation)).await
    }
}

struct DirectTaskResources<S> {
    root: DirectUdpSessionRoot<S>,
    lifetime: DirectOwnerLifetime,
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
    session: DirectUdpSessionRoot<S>,
    connect_timeout: Duration,
    registry: OwnerRegistry,
) -> Result<(), DirectTaskFailure<H::Error>>
where
    R: UdpResolver,
    <R::Candidates as IntoIterator>::IntoIter: Send,
    H: DirectUdpPacketHandler,
    S: DirectUdpSocket,
{
    let DirectUdpSessionRoot {
        socket,
        handle,
        mut initial_candidates,
    } = session;
    let mut cancellation = manager.cancellation(handle)?;
    let notify = manager.notify(handle)?;
    let mut candidate_hints = UdpAssociationCandidateHints::default();
    loop {
        // A bounded queue is not a bounded drain when producers keep refilling
        // it. Alternate one request with a response opportunity, and account
        // for fully-ready adapters in Tokio's cooperative scheduling budget.
        tokio::task::consume_budget().await;
        let sent_request = if let Some(request) = manager.pop(handle, UdpDirection::ToTarget)? {
            send_direct(
                &socket,
                &*resolver,
                &mut candidate_hints,
                request.datagram(),
                connect_timeout,
                initial_candidates.take(),
            )
            .await?;
            true
        } else {
            false
        };
        if *cancellation.borrow() {
            if sent_request {
                continue;
            }
            return Ok(());
        }
        let idle_deadline = manager.idle_deadline(handle)?;
        tokio::select! {
            biased;
            changed = cancellation.changed() => {
                if changed.is_err() {
                    return Err(UdpRuntimeError::Cancelled.into());
                }
                // Closed admission makes the remaining queue finite. Reuse the
                // cooperative request path until every admitted packet drains.
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                if Instant::now() >= manager.idle_deadline(handle)? {
                    return Err(UdpRuntimeError::Idle.into());
                }
            }
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
                    .map_err(DirectTaskFailure::Handler)?;
                manager.commit_activity(handle, Instant::now())?;
            }
            // Notifications coalesce. Poll for another queued request after
            // progress instead of requiring one notification per datagram.
            () = std::future::ready(()), if sent_request => {}
            () = notify.notified() => {}
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
    initial_candidates: Option<Vec<SocketAddr>>,
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
    let candidates = match initial_candidates {
        Some(candidates) if !candidates.is_empty() => candidates,
        Some(_) => return Err(UdpRuntimeError::Resolve),
        None => resolve_candidates(resolver, host, port, deadline).await?,
    };
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
    match socket.try_send_to(payload, target) {
        Ok(length) if length == payload.len() => return Ok(()),
        Ok(_) => return Err(UdpRuntimeError::Send),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return Err(UdpRuntimeError::Send),
    }
    match tokio::time::timeout_at(deadline, socket.send_to(payload, target)).await {
        Ok(Ok(length)) if length == payload.len() => Ok(()),
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Err(UdpRuntimeError::Send),
    }
}
