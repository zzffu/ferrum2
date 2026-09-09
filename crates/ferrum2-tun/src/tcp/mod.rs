use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "benchmark"
))]
use ferrum2_runtime::OwnerRegistry;
use ferrum2_runtime::TunTcpFlowOwner;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(test)]
use tokio::net::TcpStream;

use crate::OwnerWake;

#[cfg(all(test, feature = "benchmark"))]
mod memory_tests;

mod socket;
pub(crate) use socket::FlowSocket;

/// One non-cloneable application-side TUN TCP stream with an immutable original target.
pub struct TcpFlow {
    target: SocketAddr,
    shared: Arc<FlowShared>,
}

impl TcpFlow {
    /// Returns the numeric destination captured from the initial IP packet.
    pub const fn target(&self) -> SocketAddr {
        self.target
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        if !shared.valid.load(Ordering::Acquire) {
            return Poll::Ready(Err(connection_reset()));
        }
        if destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut socket = shared.state.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.stream.as_mut() else {
            return Poll::Ready(Err(connection_reset()));
        };

        match Pin::new(stream).poll_read(context, destination) {
            Poll::Ready(result) => {
                socket.read.take();
                Poll::Ready(result.map_err(|error| shared.map_io_error(error)))
            }
            Poll::Pending => {
                set_waker(&mut socket.read, context.waker());
                if shared.valid.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(connection_reset()))
                }
            }
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        if !shared.valid.load(Ordering::Acquire) {
            return Poll::Ready(Err(connection_reset()));
        }
        if shared.write_shutdown.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP write half is closed",
            )));
        }
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut socket = shared.state.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.stream.as_mut() else {
            return Poll::Ready(Err(connection_reset()));
        };
        match Pin::new(stream).poll_write(context, source) {
            Poll::Ready(result) => {
                socket.write.take();
                Poll::Ready(result.map_err(|error| shared.map_io_error(error)))
            }
            Poll::Pending => {
                set_waker(&mut socket.write, context.waker());
                if shared.valid.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(connection_reset()))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.valid.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(connection_reset()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        if !shared.valid.load(Ordering::Acquire) {
            return Poll::Ready(Err(connection_reset()));
        }
        if shared.write_shutdown.swap(true, Ordering::AcqRel) {
            return Poll::Ready(Ok(()));
        }
        let mut socket = shared.state.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.stream.as_mut() else {
            return Poll::Ready(Err(connection_reset()));
        };
        let result = stream.shutdown(_context);
        if shared.valid.load(Ordering::Acquire) {
            result
        } else {
            Poll::Ready(Err(connection_reset()))
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        self.shared.flow_present.store(false, Ordering::Release);
        self.shared.close_socket();
        self.shared.owner_wake.signal();
    }
}

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "benchmark"
))]
/// Owner-side lease for fencing and closing the real system socket.
pub(crate) struct TcpSocketLease {
    shared: Arc<FlowShared>,
}

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "benchmark"
))]
impl TcpSocketLease {
    pub(crate) fn fence(&self) -> io::Result<()> {
        self.shared.invalidate()
    }

    pub(crate) fn flow_dropped(&self) -> bool {
        !self.shared.flow_present.load(Ordering::Acquire)
    }
    pub(crate) fn generation(&self) -> u64 {
        self.shared.generation
    }
}

struct FlowShared {
    // Socket polling and cancellation-waker registration share one critical
    // section. Fencing takes both before waking outside the lock.
    state: Mutex<FlowState>,
    #[cfg(any(
        all(windows, target_arch = "x86_64", feature = "live-backend"),
        test,
        feature = "benchmark"
    ))]
    generation: u64,
    valid: AtomicBool,
    write_shutdown: AtomicBool,
    flow_present: AtomicBool,
    owner_wake: OwnerWake,
    registry_owner: Mutex<Option<TunTcpFlowOwner>>,
}

impl FlowShared {
    fn close_socket(&self) {
        let (stream, wakers) = {
            let mut state = self.state.lock().expect("TUN TCP flow socket");
            (state.stream.take(), [state.read.take(), state.write.take()])
        };
        drop(wakers);
        if let Some(stream) = stream {
            stream.close();
        }
        self.registry_owner
            .lock()
            .expect("TUN TCP flow registry owner")
            .take();
    }
    #[cfg(any(
        all(windows, target_arch = "x86_64", feature = "live-backend"),
        test,
        feature = "benchmark"
    ))]
    fn invalidate(&self) -> io::Result<()> {
        self.valid.store(false, Ordering::Release);
        let (stream, wakers) = {
            let mut state = self.state.lock().expect("TUN TCP flow socket");
            (state.stream.take(), [state.read.take(), state.write.take()])
        };
        let result = stream.map_or(Ok(()), FlowSocket::abort);
        self.registry_owner
            .lock()
            .expect("TUN TCP flow registry owner")
            .take();
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
        self.owner_wake.signal();
        result
    }

    fn map_io_error(&self, error: io::Error) -> io::Error {
        if self.valid.load(Ordering::Acquire) {
            error
        } else {
            connection_reset()
        }
    }
}

impl Drop for FlowShared {
    fn drop(&mut self) {
        self.valid.store(false, Ordering::Release);
        if let Some(stream) = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .stream
            .take()
        {
            stream.close();
        }
        self.registry_owner
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[derive(Default)]
struct FlowState {
    stream: Option<FlowSocket>,
    read: Option<Waker>,
    write: Option<Waker>,
}

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "benchmark"
))]
pub(crate) fn tcp_flow_from_stream(
    stream: impl Into<FlowSocket>,
    target: SocketAddr,
    generation: u64,
    registry: &OwnerRegistry,
    owner_wake: OwnerWake,
) -> (TcpFlow, TcpSocketLease) {
    let shared = Arc::new(FlowShared {
        state: Mutex::new(FlowState {
            stream: Some(stream.into()),
            ..FlowState::default()
        }),
        generation,
        valid: AtomicBool::new(true),
        write_shutdown: AtomicBool::new(false),
        flow_present: AtomicBool::new(true),
        owner_wake,
        registry_owner: Mutex::new(Some(registry.track_tun_tcp_flow())),
    });
    (
        TcpFlow {
            target,
            shared: Arc::clone(&shared),
        },
        TcpSocketLease { shared },
    )
}

fn set_waker(slot: &mut Option<Waker>, waker: &Waker) {
    if slot
        .as_ref()
        .is_none_or(|current| !current.will_wake(waker))
    {
        *slot = Some(waker.clone());
    }
}

fn connection_reset() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "TUN TCP flow reset")
}

#[cfg(test)]
pub(crate) async fn tcp_flow_for_test(
    target: SocketAddr,
) -> io::Result<(TcpFlow, TcpStream, TcpSocketLease)> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let local = listener.local_addr()?;
    let connect = TcpStream::connect(local);
    let accept = listener.accept();
    let (peer, accepted) = tokio::join!(connect, accept);
    let peer = peer?;
    let (accepted, _) = accepted?;
    let (flow, lease) = tcp_flow_from_stream(
        accepted,
        target,
        1,
        &OwnerRegistry::new(),
        OwnerWake::default(),
    );
    Ok((flow, peer, lease))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

    use super::tcp_flow_for_test;

    #[tokio::test]
    async fn system_stream_preserves_bidirectional_io_and_half_close() {
        let target = "192.0.2.1:443".parse().expect("target");
        let (mut flow, mut peer, _lease) = tcp_flow_for_test(target).await.expect("flow");
        assert_eq!(flow.target(), target);

        flow.write_all(b"request").await.expect("flow write");
        let mut request = [0_u8; 7];
        peer.read_exact(&mut request).await.expect("peer read");
        assert_eq!(&request, b"request");

        peer.write_all(b"response").await.expect("peer write");
        peer.shutdown().await.expect("peer half close");
        let mut response = Vec::new();
        flow.read_to_end(&mut response).await.expect("flow read");
        assert_eq!(response, b"response");

        flow.write_all(b"after-fin")
            .await
            .expect("write after peer FIN");
        let mut after_fin = [0_u8; 9];
        peer.read_exact(&mut after_fin).await.expect("peer read");
        assert_eq!(&after_fin, b"after-fin");
    }

    #[tokio::test]
    async fn local_shutdown_preserves_the_read_half() {
        let (mut flow, mut peer, _lease) =
            tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
                .await
                .expect("flow");
        flow.shutdown().await.expect("flow write half close");
        let mut end = [0_u8; 1];
        assert_eq!(peer.read(&mut end).await.expect("peer EOF"), 0);

        peer.write_all(b"still-readable").await.expect("peer write");
        let mut response = [0_u8; 14];
        flow.read_exact(&mut response).await.expect("flow read");
        assert_eq!(&response, b"still-readable");
    }

    #[tokio::test]
    async fn exhausted_readiness_wakes_again_when_more_data_arrives() {
        let (mut flow, mut peer, _lease) =
            tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
                .await
                .expect("flow");
        peer.write_all(b"a").await.expect("first write");
        let mut byte = [0_u8; 1];
        flow.read_exact(&mut byte).await.expect("first read");
        assert_eq!(&byte, b"a");

        let wake = Arc::new(ReadinessWake(tokio::sync::Notify::new()));
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let mut read = ReadBuf::new(&mut byte);
        assert!(matches!(
            AsyncRead::poll_read(Pin::new(&mut flow), &mut context, &mut read),
            Poll::Pending
        ));

        peer.write_all(b"b").await.expect("second write");
        tokio::time::timeout(std::time::Duration::from_secs(2), wake.0.notified())
            .await
            .expect("new socket data must wake the pending read");
        flow.read_exact(&mut byte).await.expect("second read");
        assert_eq!(&byte, b"b");
    }

    async fn exhaust_write_capacity(flow: &mut super::TcpFlow) -> (usize, Arc<ReadinessWake>) {
        {
            let socket = flow.shared.state.lock().expect("socket");
            socket
                .stream
                .as_ref()
                .expect("live socket")
                .set_send_buffer_size(4096)
                .expect("bounded socket send buffer");
        }
        flow.write_all(b"x")
            .await
            .expect("initial writable transition");
        let wake = Arc::new(ReadinessWake(tokio::sync::Notify::new()));
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        let block = [b'x'; 16384];
        let mut accepted = 1;
        loop {
            match tokio::io::AsyncWrite::poll_write(Pin::new(&mut *flow), &mut context, &block) {
                Poll::Ready(Ok(count)) => {
                    assert!(count > 0);
                    accepted += count;
                    assert!(
                        accepted < 64 * 1024 * 1024,
                        "bounded kernel queue must backpressure"
                    );
                }
                Poll::Ready(Err(error)) => panic!("socket write: {error}"),
                Poll::Pending => return (accepted, wake),
            }
        }
    }

    #[tokio::test]
    async fn exhausted_write_readiness_recovers_after_peer_drains() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut flow, mut peer, _lease) =
                tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
                    .await
                    .expect("flow");
            let (accepted, wake) = exhaust_write_capacity(&mut flow).await;
            let mut received = vec![0; accepted];
            peer.read_exact(&mut received)
                .await
                .expect("drain bounded socket queue");
            assert!(received.iter().all(|byte| *byte == b'x'));
            wake.0.notified().await;
            flow.write_all(b"recovered")
                .await
                .expect("write after capacity returns");
            flow.shutdown().await.expect("FIN follows recovered bytes");
            let mut remainder = Vec::new();
            peer.read_to_end(&mut remainder)
                .await
                .expect("peer observes FIN");
            assert_eq!(remainder, b"recovered");
            peer.write_all(b"duplex")
                .await
                .expect("reverse half remains live");
            let mut response = [0; 6];
            flow.read_exact(&mut response)
                .await
                .expect("read after write half close");
            assert_eq!(&response, b"duplex");
        })
        .await
        .expect("reactor must recover without a timer retry");
    }

    #[tokio::test]
    async fn fence_wakes_a_capacity_blocked_writer_and_prevents_revival() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut flow, mut peer, lease) =
                tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
                    .await
                    .expect("flow");
            let (_, wake) = exhaust_write_capacity(&mut flow).await;
            // Consume any coalesced reactor wake before registering the fence witness.
            let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
            let waker = Waker::from(Arc::clone(&flag));
            let mut context = Context::from_waker(&waker);
            loop {
                match tokio::io::AsyncWrite::poll_write(
                    Pin::new(&mut flow),
                    &mut context,
                    &[b'x'; 16384],
                ) {
                    Poll::Pending => break,
                    Poll::Ready(Ok(count)) => assert!(count > 0),
                    Poll::Ready(Err(error)) => panic!("socket write: {error}"),
                }
            }
            flag.0.store(false, Ordering::Release);
            lease.fence().expect("abortive generation fence");
            assert!(
                flag.0.load(Ordering::Acquire),
                "fence must wake pending writer"
            );
            assert_eq!(
                flow.write(b"late").await.expect_err("fenced write").kind(),
                io::ErrorKind::ConnectionReset
            );
            let mut queued = Vec::new();
            let error = peer
                .read_to_end(&mut queued)
                .await
                .expect_err("peer observes reset without draining before fence");
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            drop(wake);
        })
        .await
        .expect("bounded fence transition");
    }

    #[tokio::test]
    async fn dropping_flow_closes_the_real_socket_even_while_owner_lease_exists() {
        let (flow, mut peer, _lease) = tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
            .await
            .expect("flow");
        drop(flow);
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).await.expect("peer EOF"), 0);
    }

    #[tokio::test]
    async fn generation_fence_wakes_pending_io_and_resets_every_operation() {
        let (mut flow, mut peer, lease) =
            tcp_flow_for_test("192.0.2.1:443".parse().expect("target"))
                .await
                .expect("flow");
        let mut byte = [0_u8; 1];
        let mut read = ReadBuf::new(&mut byte);
        let wake = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&wake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(
            AsyncRead::poll_read(Pin::new(&mut flow), &mut context, &mut read),
            Poll::Pending
        ));

        lease.fence().expect("abortive generation fence");
        assert!(wake.0.load(Ordering::Acquire), "pending read was not woken");
        assert_eq!(
            peer.read(&mut byte)
                .await
                .expect_err("peer reset after fence")
                .kind(),
            io::ErrorKind::ConnectionReset
        );
        let error = flow.read(&mut byte).await.expect_err("fenced read");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let error = flow.write(b"x").await.expect_err("fenced write");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let error = flow.flush().await.expect_err("fenced flush");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let error = flow.shutdown().await.expect_err("fenced shutdown");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    struct ReadinessWake(tokio::sync::Notify);

    impl Wake for ReadinessWake {
        fn wake(self: Arc<Self>) {
            self.0.notify_one();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.notify_one();
        }
    }

    struct WakeFlag(AtomicBool);

    impl Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }
}
