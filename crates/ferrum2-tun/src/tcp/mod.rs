use std::io;
use std::net::{Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
use ferrum2_runtime::OwnerRegistry;
use ferrum2_runtime::TunTcpFlowOwner;
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::OwnerWake;

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
        let mut socket = shared.stream.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.as_mut() else {
            return Poll::Ready(Err(connection_reset()));
        };

        match Pin::new(stream).poll_read(context, destination) {
            Poll::Ready(result) => {
                shared.clear_read_waker();
                Poll::Ready(result.map_err(|error| shared.map_io_error(error)))
            }
            Poll::Pending => {
                shared.register_read_waker(context.waker());
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

        let mut socket = shared.stream.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.as_mut() else {
            return Poll::Ready(Err(connection_reset()));
        };
        match Pin::new(stream).poll_write(context, source) {
            Poll::Ready(result) => {
                shared.clear_write_waker();
                Poll::Ready(result.map_err(|error| shared.map_io_error(error)))
            }
            Poll::Pending => {
                shared.register_write_waker(context.waker());
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
        let socket = shared.stream.lock().expect("TUN TCP flow socket");
        let Some(stream) = socket.as_ref() else {
            return Poll::Ready(Err(connection_reset()));
        };
        let result = SockRef::from(stream).shutdown(Shutdown::Write);
        if shared.valid.load(Ordering::Acquire) {
            Poll::Ready(result)
        } else {
            Poll::Ready(Err(connection_reset()))
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        self.shared.flow_present.store(false, Ordering::Release);
        self.shared.clear_wakers();
        self.shared.close_socket();
        self.shared.owner_wake.signal();
    }
}

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
/// Owner-side lease for fencing and closing the real system socket.
pub(crate) struct TcpSocketLease {
    shared: Arc<FlowShared>,
}

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
impl TcpSocketLease {
    pub(crate) fn fence(&self) {
        self.shared.invalidate();
    }

    pub(crate) fn flow_dropped(&self) -> bool {
        !self.shared.flow_present.load(Ordering::Acquire)
    }
    pub(crate) fn generation(&self) -> u64 {
        self.shared.generation
    }
}

struct FlowShared {
    stream: Mutex<Option<TcpStream>>,
    #[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
    generation: u64,
    valid: AtomicBool,
    write_shutdown: AtomicBool,
    flow_present: AtomicBool,
    wakers: Mutex<FlowWakers>,
    owner_wake: OwnerWake,
    registry_owner: Mutex<Option<TunTcpFlowOwner>>,
}

impl FlowShared {
    fn register_read_waker(&self, waker: &Waker) {
        set_waker(
            &mut self.wakers.lock().expect("TUN TCP flow wakers").read,
            waker,
        );
    }

    fn register_write_waker(&self, waker: &Waker) {
        set_waker(
            &mut self.wakers.lock().expect("TUN TCP flow wakers").write,
            waker,
        );
    }
    fn clear_read_waker(&self) {
        self.wakers.lock().expect("TUN TCP flow wakers").read.take();
    }

    fn clear_write_waker(&self) {
        self.wakers
            .lock()
            .expect("TUN TCP flow wakers")
            .write
            .take();
    }

    fn clear_wakers(&self) {
        let mut wakers = self.wakers.lock().expect("TUN TCP flow wakers");
        wakers.read.take();
        wakers.write.take();
    }

    fn close_socket(&self) {
        if let Some(stream) = self.stream.lock().expect("TUN TCP flow socket").take() {
            let _ = SockRef::from(&stream).shutdown(Shutdown::Both);
        }
        self.registry_owner
            .lock()
            .expect("TUN TCP flow registry owner")
            .take();
    }
    #[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
        self.close_socket();
        let wakers = {
            let mut wakers = self.wakers.lock().expect("TUN TCP flow wakers");
            [wakers.read.take(), wakers.write.take()]
        };
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
        self.owner_wake.signal();
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
            .stream
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            let _ = SockRef::from(&stream).shutdown(Shutdown::Both);
        }
        self.registry_owner
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[derive(Default)]
struct FlowWakers {
    read: Option<Waker>,
    write: Option<Waker>,
}

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
pub(crate) fn tcp_flow_from_stream(
    stream: TcpStream,
    target: SocketAddr,
    generation: u64,
    registry: &OwnerRegistry,
    owner_wake: OwnerWake,
) -> (TcpFlow, TcpSocketLease) {
    let shared = Arc::new(FlowShared {
        stream: Mutex::new(Some(stream)),
        generation,
        valid: AtomicBool::new(true),
        write_shutdown: AtomicBool::new(false),
        flow_present: AtomicBool::new(true),
        wakers: Mutex::new(FlowWakers::default()),
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

        lease.fence();
        assert!(wake.0.load(Ordering::Acquire), "pending read was not woken");
        assert_eq!(peer.read(&mut byte).await.expect("peer EOF after fence"), 0);
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
