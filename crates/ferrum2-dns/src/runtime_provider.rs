use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, Spawn, TokioTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Owned future returned by a DNS egress adapter.
pub type DnsIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'static>>;

/// One immutable concrete egress-plan selection.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanSnapshot(Arc<[usize]>);

impl PlanSnapshot {
    pub(crate) fn new(hops: &[usize]) -> Self {
        Self(Arc::from(hops))
    }

    /// Returns concrete outbound identities in traversal order.
    pub fn hops(&self) -> &[usize] {
        &self.0
    }
}

impl std::fmt::Debug for PlanSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PlanSnapshot([redacted])")
    }
}

/// Owned Tokio TCP I/O supplied to Hickory without changing DNS framing.
pub trait DnsTcpIo: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

impl<T> DnsTcpIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Boxed TCP I/O returned by [`DnsEgress`].
pub type BoxedDnsTcpIo = Box<dyn DnsTcpIo>;

/// Unconnected datagram I/O supplied to Hickory.
pub trait DnsDatagramIo: Send + Sync + Unpin + 'static {
    /// Polls one datagram and its authenticated socket source.
    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>>;

    /// Polls one complete datagram send.
    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}

/// Boxed UDP I/O returned by [`DnsEgress`].
pub type BoxedDnsDatagramIo = Box<dyn DnsDatagramIo>;

/// Runtime-neutral selected egress for one DNS connection or socket.
pub trait DnsEgress: Send + Sync + 'static {
    /// Connects to the validated numeric target through the optional concrete plan.
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo>;

    /// Binds one unconnected socket for the validated numeric target and optional plan.
    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo>;
}

/// Direct production egress using Tokio numeric sockets only.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsEgress;

impl DnsEgress for SystemDnsEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
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
            let stream = tokio::time::timeout(timeout, TcpStream::connect(target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS connect timeout"))??;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxedDnsTcpIo)
        })
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        Box::pin(async move {
            if plan.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "detoured DNS egress requires an adapter",
                ));
            }
            let local = match target.ip() {
                IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            };
            Ok(Box::new(SystemDnsDatagram(UdpSocket::bind(local).await?)) as BoxedDnsDatagramIo)
        })
    }
}

struct SystemDnsDatagram(UdpSocket);

impl DnsDatagramIo for SystemDnsDatagram {
    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut read = ReadBuf::new(buffer);
        let source = ready!(self.0.poll_recv_from(context, &mut read))?;
        Poll::Ready(Ok((read.filled().len(), source)))
    }

    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send_to(context, buffer, target)
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

#[derive(Clone, Default)]
pub(crate) struct TaskSet(Arc<Mutex<JoinSet<()>>>);

impl TaskSet {
    fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.0.lock().expect("DNS task set poisoned");
        while tasks.try_join_next().is_some() {}
        tasks.spawn(future);
    }

    pub(crate) async fn abort_and_join(&self) {
        let mut tasks = {
            let mut locked = self.0.lock().expect("DNS task set poisoned");
            std::mem::take(&mut *locked)
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
}

impl DnsTaskRegistrar {
    fn new(tasks: TaskSet, counters: Arc<RuntimeCounters>) -> Self {
        Self { tasks, counters }
    }

    /// Spawns one bridge or session task on the exclusive DNS runtime.
    pub fn spawn(
        &self,
        kind: DnsEgressTaskKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let counter = match kind {
            DnsEgressTaskKind::Bridge => &self.counters.bridge_tasks,
            DnsEgressTaskKind::Session => &self.counters.sessions,
        };
        counter.fetch_add(1, Ordering::AcqRel);
        let counters = Arc::clone(&self.counters);
        self.tasks.spawn(async move {
            let counter = match kind {
                DnsEgressTaskKind::Bridge => &counters.bridge_tasks,
                DnsEgressTaskKind::Session => &counters.sessions,
            };
            let _guard = CounterGuard::new(counter);
            future.await;
        });
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
}

impl Spawn for TrackedHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.counters.tasks.fetch_add(1, Ordering::AcqRel);
        let counter = Arc::clone(&self.counters);
        let future = async move {
            let _guard = CounterGuard::new(&counter.tasks);
            future.await;
        };
        self.tasks.spawn(future);
    }
}

struct CounterGuard<'a>(&'a AtomicUsize);

impl<'a> CounterGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        Self(counter)
    }
}

impl Drop for CounterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) struct QueryGuard {
    counters: Arc<RuntimeCounters>,
}

impl QueryGuard {
    pub(crate) fn new(counters: Arc<RuntimeCounters>) -> Self {
        counters.queries.fetch_add(1, Ordering::AcqRel);
        Self { counters }
    }
}

impl Drop for QueryGuard {
    fn drop(&mut self) {
        self.counters.queries.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Hickory runtime provider bound to one target, deadline, and plan snapshot.
#[derive(Clone)]
pub(crate) struct FerrumRuntimeProvider {
    egress: Arc<dyn DnsEgress>,
    plan: Option<PlanSnapshot>,
    deadline: Instant,
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
}

impl FerrumRuntimeProvider {
    pub(crate) fn new(
        egress: Arc<dyn DnsEgress>,
        plan: Option<PlanSnapshot>,
        deadline: Instant,
        tasks: TaskSet,
        counters: Arc<RuntimeCounters>,
    ) -> Self {
        Self {
            egress,
            plan,
            deadline,
            tasks,
            counters,
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
        }
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> DnsIoFuture<Self::Tcp> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let timeout = timeout.map_or(remaining, |timeout| timeout.min(remaining));
        let future = self.egress.connect_tcp(
            server_addr,
            self.plan.clone(),
            timeout,
            DnsTaskRegistrar::new(self.tasks.clone(), Arc::clone(&self.counters)),
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

    fn bind_udp(&self, _local_addr: SocketAddr, server_addr: SocketAddr) -> DnsIoFuture<Self::Udp> {
        let future = self.egress.bind_udp(
            server_addr,
            self.plan.clone(),
            DnsTaskRegistrar::new(self.tasks.clone(), Arc::clone(&self.counters)),
        );
        let counters = Arc::clone(&self.counters);
        let deadline = self.deadline;
        Box::pin(async move {
            let inner = tokio::time::timeout_at(deadline, future)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS bind timeout"))??;
            counters.udp_sockets.fetch_add(1, Ordering::AcqRel);
            Ok(CountedUdp { inner, counters })
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
}

impl DnsUdpSocket for CountedUdp {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.inner.poll_recv_from(context, buffer)
    }

    fn poll_send_to(
        &self,
        context: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_send_to(context, buffer, target)
    }
}

impl Drop for CountedUdp {
    fn drop(&mut self) {
        self.counters.udp_sockets.fetch_sub(1, Ordering::AcqRel);
    }
}
