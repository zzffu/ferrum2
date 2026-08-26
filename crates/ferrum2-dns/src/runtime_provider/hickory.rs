use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, TokioTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use super::admission::{DnsQueryScope, RuntimeCounters};
use super::egress::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsIoFuture, hickory_placeholder,
};
use super::tracking::{DnsTaskRegistrar, TaskSet, TrackedHandle};

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
        TrackedHandle::new(
            self.tasks.clone(),
            Arc::clone(&self.counters),
            self.query_scope.clone(),
        )
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
