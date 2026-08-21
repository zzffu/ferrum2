use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, Spawn, TokioTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinSet;
use tokio::time::Instant;

const HICKORY_PLACEHOLDER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

tokio::task_local! {
    pub(crate) static DNS_QUERY_SCOPE: DnsQueryScope;
}

pub(crate) fn hickory_placeholder(port: NonZeroU16) -> SocketAddr {
    SocketAddr::new(HICKORY_PLACEHOLDER_IP.into(), port.get())
}

/// Owned future returned by a DNS egress adapter.
pub type DnsIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'static>>;

/// Owned Tokio TCP I/O supplied to Hickory without changing DNS framing.
pub trait DnsTcpIo: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> DnsTcpIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Boxed TCP I/O returned by [`DnsEgress`].
pub type BoxedDnsTcpIo = Box<dyn DnsTcpIo>;

/// Datagram I/O connected to the logical target selected for one DNS query.
pub trait DnsDatagramIo: Send + Sync + Unpin + 'static {
    /// Polls one datagram received from the selected logical target.
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>>;

    /// Polls one complete datagram send to the selected logical target.
    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>>;
}

/// Boxed UDP I/O returned by [`DnsEgress`].
pub type BoxedDnsDatagramIo = Box<dyn DnsDatagramIo>;

/// Runtime-neutral selected egress for one DNS connection or socket.
pub trait DnsEgress: Send + Sync + 'static {
    /// Connects to the validated logical target through the optional concrete plan.
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo>;

    /// Binds datagram I/O for the validated logical target and optional plan.
    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo>;
}

/// Direct production egress using Tokio numeric sockets only.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsEgress;

impl DnsEgress for SystemDnsEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        Box::pin(async move {
            if plan.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "detoured DNS egress requires an adapter",
                ));
            }
            let target = target.as_socket_addr().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system DNS egress requires a numeric target",
                )
            })?;
            let stream = tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS connect timeout"))??;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        Box::pin(async move {
            if plan.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "detoured DNS egress requires an adapter",
                ));
            }
            let target = target.as_socket_addr().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "system DNS egress requires a numeric target",
                )
            })?;
            let local = match target.ip() {
                IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            };
            let socket = UdpSocket::bind(local).await?;
            socket.connect(target).await?;
            Ok(Box::new(SystemDnsDatagram(socket)) as BoxedDnsDatagramIo)
        })
    }
}

struct SystemDnsDatagram(UdpSocket);

impl DnsDatagramIo for SystemDnsDatagram {
    fn poll_recv(&self, context: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut read = ReadBuf::new(buffer);
        ready!(self.0.poll_recv(context, &mut read))?;
        Poll::Ready(Ok(read.filled().len()))
    }

    fn poll_send(&self, context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(context, buffer)
    }
}

#[derive(Default)]
pub(crate) struct RuntimeCounters {
    pub(crate) queries: AtomicUsize,
    pub(crate) tasks: AtomicUsize,
    pub(crate) tcp_streams: AtomicUsize,
    pub(crate) udp_sockets: AtomicUsize,
    pub(crate) bridge_tasks: AtomicUsize,
    pub(crate) sessions: AtomicUsize,
    pub(crate) queues: AtomicUsize,
    pub(crate) buffers: AtomicUsize,
}

struct QueryAdmission {
    permit: Option<OwnedSemaphorePermit>,
    counters: Arc<RuntimeCounters>,
}

impl Drop for QueryAdmission {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.counters.queries.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One aggregate admission shared by every query in a validated dependency chain.
pub(crate) struct DnsQueryContext {
    admission: Arc<QueryAdmission>,
    dependency_depth: usize,
    deadline: Instant,
}

impl DnsQueryContext {
    pub(crate) fn root(
        permit: OwnedSemaphorePermit,
        counters: Arc<RuntimeCounters>,
        deadline: Instant,
    ) -> Self {
        counters.queries.fetch_add(1, Ordering::AcqRel);
        Self {
            admission: Arc::new(QueryAdmission {
                permit: Some(permit),
                counters,
            }),
            dependency_depth: 0,
            deadline,
        }
    }

    pub(crate) fn scope(&self) -> DnsQueryScope {
        DnsQueryScope {
            admission: Arc::downgrade(&self.admission),
            owner: Arc::downgrade(&self.admission.counters),
            dependency_depth: self.dependency_depth,
            deadline: self.deadline,
        }
    }

    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// Weak task-local view that propagates chain identity without extending admission.
#[derive(Clone)]
pub(crate) struct DnsQueryScope {
    admission: std::sync::Weak<QueryAdmission>,
    owner: std::sync::Weak<RuntimeCounters>,
    dependency_depth: usize,
    deadline: Instant,
}

impl DnsQueryScope {
    pub(crate) fn belongs_to(&self, counters: &Arc<RuntimeCounters>) -> bool {
        std::sync::Weak::ptr_eq(&self.owner, &Arc::downgrade(counters))
    }

    pub(crate) fn child(&self, server_count: usize) -> Option<DnsQueryContext> {
        let dependency_depth = self.dependency_depth.checked_add(1)?;
        if dependency_depth >= server_count {
            return None;
        }
        Some(DnsQueryContext {
            admission: self.admission.upgrade()?,
            dependency_depth,
            deadline: self.deadline,
        })
    }
}

#[derive(Default)]
struct TaskSetState {
    closed: bool,
    tasks: JoinSet<()>,
}

#[derive(Clone, Default)]
pub(crate) struct TaskSet(Arc<Mutex<TaskSetState>>);

impl TaskSet {
    fn spawn_counted(
        &self,
        counters: Arc<RuntimeCounters>,
        kind: CounterKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let guard = CounterGuard::new(counters, kind);
        let rejected = {
            let mut state = self.0.lock().expect("DNS task set poisoned");
            if state.closed {
                Some((future, guard))
            } else {
                while state.tasks.try_join_next().is_some() {}
                state.tasks.spawn(async move {
                    let _guard = guard;
                    future.await;
                });
                None
            }
        };
        drop(rejected);
    }

    pub(crate) async fn abort_and_join(&self) {
        let mut tasks = {
            let mut state = self.0.lock().expect("DNS task set poisoned");
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

/// Kind of detour work registered under one logical DNS query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEgressTaskKind {
    /// A bounded I/O bridge carrying the selected DNS transport.
    Bridge,
    /// A concrete detour session owned by that bridge.
    Session,
}

/// Kind of bounded detour storage owned under one logical DNS query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEgressResourceKind {
    /// A bounded queue between the adapter and its bridge.
    Queue,
    /// Fixed-capacity bridge buffer storage.
    Buffer,
}

/// RAII ownership for bounded detour storage.
#[must_use = "keep the guard with its queue or buffer owner"]
pub struct DnsResourceGuard {
    counters: Arc<RuntimeCounters>,
    kind: DnsEgressResourceKind,
}

impl Drop for DnsResourceGuard {
    fn drop(&mut self) {
        match self.kind {
            DnsEgressResourceKind::Queue => &self.counters.queues,
            DnsEgressResourceKind::Buffer => &self.counters.buffers,
        }
        .fetch_sub(1, Ordering::AcqRel);
    }
}

impl std::fmt::Debug for DnsResourceGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsResourceGuard([redacted])")
    }
}

/// Registers detour work for abort-and-join with its logical DNS query.
#[derive(Clone)]
pub struct DnsTaskRegistrar {
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl DnsTaskRegistrar {
    fn new(tasks: TaskSet, counters: Arc<RuntimeCounters>, query_scope: DnsQueryScope) -> Self {
        Self {
            tasks,
            counters,
            query_scope,
        }
    }

    /// Spawns one bridge or session task on the exclusive DNS runtime.
    pub fn spawn(
        &self,
        kind: DnsEgressTaskKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let kind = match kind {
            DnsEgressTaskKind::Bridge => CounterKind::Bridge,
            DnsEgressTaskKind::Session => CounterKind::Session,
        };
        self.tasks.spawn_counted(
            Arc::clone(&self.counters),
            kind,
            DNS_QUERY_SCOPE.scope(self.query_scope.clone(), future),
        );
    }

    /// Registers one bounded queue or buffer until the returned guard is dropped.
    pub fn own(&self, kind: DnsEgressResourceKind) -> DnsResourceGuard {
        match kind {
            DnsEgressResourceKind::Queue => &self.counters.queues,
            DnsEgressResourceKind::Buffer => &self.counters.buffers,
        }
        .fetch_add(1, Ordering::AcqRel);
        DnsResourceGuard {
            counters: Arc::clone(&self.counters),
            kind,
        }
    }
}

#[derive(Clone)]
pub(crate) struct TrackedHandle {
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl Spawn for TrackedHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn_counted(
            Arc::clone(&self.counters),
            CounterKind::Hickory,
            DNS_QUERY_SCOPE.scope(self.query_scope.clone(), future),
        );
    }
}

#[derive(Clone, Copy)]
enum CounterKind {
    Hickory,
    Bridge,
    Session,
}

struct CounterGuard {
    counters: Arc<RuntimeCounters>,
    kind: CounterKind,
}

impl CounterGuard {
    fn new(counters: Arc<RuntimeCounters>, kind: CounterKind) -> Self {
        match kind {
            CounterKind::Hickory => &counters.tasks,
            CounterKind::Bridge => &counters.bridge_tasks,
            CounterKind::Session => &counters.sessions,
        }
        .fetch_add(1, Ordering::AcqRel);
        Self { counters, kind }
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        match self.kind {
            CounterKind::Hickory => &self.counters.tasks,
            CounterKind::Bridge => &self.counters.bridge_tasks,
            CounterKind::Session => &self.counters.sessions,
        }
        .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Hickory runtime provider bound to one target, deadline, and plan snapshot.
#[derive(Clone)]
pub(crate) struct FerrumRuntimeProvider {
    egress: Arc<dyn DnsEgress>,
    target: TargetAddr,
    placeholder: SocketAddr,
    plan: Option<EgressPlanSnapshot>,
    deadline: Instant,
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl FerrumRuntimeProvider {
    pub(crate) fn new(
        egress: Arc<dyn DnsEgress>,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        deadline: Instant,
        tasks: TaskSet,
        counters: Arc<RuntimeCounters>,
        query_scope: DnsQueryScope,
    ) -> Self {
        let placeholder = hickory_placeholder(target.port());
        Self {
            egress,
            target,
            placeholder,
            plan,
            deadline,
            tasks,
            counters,
            query_scope,
        }
    }

    pub(crate) fn for_target(&self, target: TargetAddr, deadline: Instant) -> Self {
        Self {
            placeholder: hickory_placeholder(target.port()),
            target,
            deadline,
            egress: Arc::clone(&self.egress),
            plan: self.plan.clone(),
            tasks: self.tasks.clone(),
            counters: Arc::clone(&self.counters),
            query_scope: self.query_scope.clone(),
        }
    }
}

impl RuntimeProvider for FerrumRuntimeProvider {
    type Handle = TrackedHandle;
    type Timer = TokioTime;
    type Udp = CountedUdp;
    type Tcp = AsyncIoTokioAsStd<CountedTcp>;

    fn create_handle(&self) -> Self::Handle {
        TrackedHandle {
            tasks: self.tasks.clone(),
            counters: Arc::clone(&self.counters),
            query_scope: self.query_scope.clone(),
        }
    }

    fn connect_tcp(
        &self,
        _server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> DnsIoFuture<Self::Tcp> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let timeout = timeout.map_or(remaining, |timeout| timeout.min(remaining));
        let future = self.egress.connect_tcp(
            self.target.clone(),
            self.plan.clone(),
            timeout,
            DnsTaskRegistrar::new(
                self.tasks.clone(),
                Arc::clone(&self.counters),
                self.query_scope.clone(),
            ),
        );
        let counters = Arc::clone(&self.counters);
        let deadline = self.deadline;
        Box::pin(async move {
            let inner = tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS connect timeout"))??;
            counters.tcp_streams.fetch_add(1, Ordering::AcqRel);
            Ok(AsyncIoTokioAsStd(CountedTcp { inner, counters }))
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> DnsIoFuture<Self::Udp> {
        let future = self.egress.bind_udp(
            self.target.clone(),
            self.plan.clone(),
            DnsTaskRegistrar::new(
                self.tasks.clone(),
                Arc::clone(&self.counters),
                self.query_scope.clone(),
            ),
        );
        let counters = Arc::clone(&self.counters);
        let placeholder = self.placeholder;
        let deadline = self.deadline;
        Box::pin(async move {
            let inner = tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS bind timeout"))??;
            counters.udp_sockets.fetch_add(1, Ordering::AcqRel);
            Ok(CountedUdp {
                inner,
                counters,
                placeholder,
            })
        })
    }
}

pub(crate) struct CountedTcp {
    inner: BoxedDnsTcpIo,
    counters: Arc<RuntimeCounters>,
}

impl AsyncRead for CountedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for CountedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Drop for CountedTcp {
    fn drop(&mut self) {
        self.counters.tcp_streams.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct CountedUdp {
    inner: BoxedDnsDatagramIo,
    counters: Arc<RuntimeCounters>,
    placeholder: SocketAddr,
}

impl DnsUdpSocket for CountedUdp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.inner
            .poll_recv(context, buffer)
            .map_ok(|length| (length, self.placeholder))
    }

    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        _target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_send(context, buffer)
    }
}

impl Drop for CountedUdp {
    fn drop(&mut self) {
        self.counters.udp_sockets.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicBool;

    struct NeverPolled {
        polled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl Future for NeverPolled {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polled.store(true, Ordering::Release);
            Poll::Ready(())
        }
    }

    impl Drop for NeverPolled {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn never_polled() -> (NeverPolled, Arc<AtomicBool>, Arc<AtomicBool>) {
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        (
            NeverPolled {
                polled: Arc::clone(&polled),
                dropped: Arc::clone(&dropped),
            },
            polled,
            dropped,
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_before_first_poll_and_late_spawn_leave_no_task_or_counter() {
        for _ in 0..100 {
            let tasks = TaskSet::default();
            let counters = Arc::new(RuntimeCounters::default());
            let admission = Arc::new(tokio::sync::Semaphore::new(1));
            let context = DnsQueryContext::root(
                admission.try_acquire_owned().expect("test query admission"),
                Arc::clone(&counters),
                Instant::now() + Duration::from_secs(1),
            );
            let query_scope = context.scope();
            let registrar =
                DnsTaskRegistrar::new(tasks.clone(), Arc::clone(&counters), query_scope.clone());
            let mut handle = TrackedHandle {
                tasks: tasks.clone(),
                counters: Arc::clone(&counters),
                query_scope,
            };
            let mut polled = Vec::new();
            for spawn in [DnsEgressTaskKind::Bridge, DnsEgressTaskKind::Session] {
                let (future, was_polled, _) = never_polled();
                polled.push(was_polled);
                registrar.spawn(spawn, future);
            }
            let (future, was_polled, _) = never_polled();
            polled.push(was_polled);
            handle.spawn_bg(future);

            tasks.abort_and_join().await;
            assert!(polled.iter().all(|flag| !flag.load(Ordering::Acquire)));
            assert_eq!(counters.tasks.load(Ordering::Acquire), 0);
            assert_eq!(counters.bridge_tasks.load(Ordering::Acquire), 0);
            assert_eq!(counters.sessions.load(Ordering::Acquire), 0);

            let (late, late_polled, late_dropped) = never_polled();
            registrar.spawn(DnsEgressTaskKind::Bridge, late);
            assert!(!late_polled.load(Ordering::Acquire));
            assert!(late_dropped.load(Ordering::Acquire));
            assert_eq!(counters.bridge_tasks.load(Ordering::Acquire), 0);
        }
    }
}
