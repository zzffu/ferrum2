use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{OwnerWake, TunEvent, TunEventSink};

/// One non-cloneable application-side TUN TCP stream with an immutable original target.
pub struct TcpFlow {
    target: SocketAddr,
    bridge: Arc<Mutex<Bridge>>,
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
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = bridge.to_application.pop(destination.initialize_unfilled());
        if copied != 0 {
            destination.advance(copied);
            let wake = bridge.owner_wake.clone();
            drop(bridge);
            wake.signal();
            return Poll::Ready(Ok(()));
        }
        if bridge.reset {
            return Poll::Ready(Err(connection_reset()));
        }
        if bridge.remote_closed {
            return Poll::Ready(Ok(()));
        }
        set_waker(&mut bridge.read_waker, context.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        if bridge.reset {
            return Poll::Ready(Err(connection_reset()));
        }
        if bridge.shutdown_requested {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP write half is closed",
            )));
        }
        let copied = bridge.to_stack.push(source);
        if copied == 0 && !source.is_empty() {
            bridge.events.emit(TunEvent::TcpBridgeBlocked);
        }
        if copied != 0 || source.is_empty() {
            let wake = (copied != 0).then(|| bridge.owner_wake.clone());
            drop(bridge);
            if let Some(wake) = wake {
                wake.signal();
            }
            Poll::Ready(Ok(copied))
        } else {
            set_waker(&mut bridge.write_waker, context.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        if bridge.reset {
            return Poll::Ready(Err(connection_reset()));
        }
        if bridge.to_stack.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            set_waker(&mut bridge.write_waker, context.waker());
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        if bridge.reset {
            return Poll::Ready(Err(connection_reset()));
        }
        let changed = !bridge.shutdown_requested;
        bridge.shutdown_requested = true;
        let result = if bridge.fin_sent {
            Poll::Ready(Ok(()))
        } else {
            set_waker(&mut bridge.shutdown_waker, context.waker());
            Poll::Pending
        };
        let wake = changed.then(|| bridge.owner_wake.clone());
        drop(bridge);
        if let Some(wake) = wake {
            wake.signal();
        }
        result
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        if !bridge.fin_sent {
            let changed = !bridge.aborted;
            bridge.aborted = true;
            let wake = changed.then(|| bridge.owner_wake.clone());
            drop(bridge);
            if let Some(wake) = wake {
                wake.signal();
            }
        }
    }
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(super) struct FlowOwner {
    bridge: Arc<Mutex<Bridge>>,
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
impl FlowOwner {
    #[cfg(test)]
    pub(super) fn read_to_stack(&mut self, destination: &mut [u8]) -> usize {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = bridge.to_stack.pop(destination);
        if copied != 0 {
            bridge.write_waker.take().into_iter().for_each(Waker::wake);
        }
        copied
    }

    pub(super) fn drain_to_stack(&mut self, send: impl FnOnce(&[u8]) -> usize) -> usize {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = send(bridge.to_stack.first());
        if copied == 0 && bridge.to_stack.len != 0 {
            bridge.events.emit(TunEvent::TcpBridgeBlocked);
        }
        bridge.to_stack.consume(copied);
        if copied != 0 {
            bridge.write_waker.take().into_iter().for_each(Waker::wake);
        }
        copied
    }

    pub(super) fn write_from_stack(&mut self, source: &[u8]) -> usize {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = bridge.to_application.push(source);
        if copied == 0 && !source.is_empty() {
            bridge.events.emit(TunEvent::TcpBridgeBlocked);
        }
        if copied != 0 {
            bridge.read_waker.take().into_iter().for_each(Waker::wake);
        }
        copied
    }

    pub(super) fn application_capacity(&self) -> usize {
        self.bridge
            .lock()
            .expect("TUN TCP bridge")
            .to_application
            .remaining()
    }

    pub(super) fn stack_buffered(&self) -> usize {
        self.bridge.lock().expect("TUN TCP bridge").to_stack.len
    }

    pub(super) fn shutdown_requested(&self) -> bool {
        self.bridge
            .lock()
            .expect("TUN TCP bridge")
            .shutdown_requested
    }

    pub(super) fn mark_fin_sent(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        bridge.fin_sent = true;
        bridge
            .shutdown_waker
            .take()
            .into_iter()
            .for_each(Waker::wake);
    }

    pub(super) fn mark_remote_closed(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        bridge.remote_closed = true;
        bridge.read_waker.take().into_iter().for_each(Waker::wake);
    }

    pub(super) fn mark_reset(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        bridge.reset = true;
        for waker in [
            bridge.read_waker.take(),
            bridge.write_waker.take(),
            bridge.shutdown_waker.take(),
        ]
        .into_iter()
        .flatten()
        {
            waker.wake();
        }
    }

    pub(super) fn is_aborted(&self) -> bool {
        self.bridge.lock().expect("TUN TCP bridge").aborted
    }
}

#[cfg(test)]
pub(super) fn tcp_flow_pair(target: SocketAddr, capacity: usize) -> (TcpFlow, FlowOwner) {
    tcp_flow_pair_with_wake(target, capacity, OwnerWake::default())
}

#[cfg(test)]
pub(super) fn tcp_flow_pair_with_wake(
    target: SocketAddr,
    capacity: usize,
    owner_wake: OwnerWake,
) -> (TcpFlow, FlowOwner) {
    tcp_flow_pair_with_events(target, capacity, owner_wake, TunEventSink::default())
}

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
pub(super) fn tcp_flow_pair_with_events(
    target: SocketAddr,
    capacity: usize,
    owner_wake: OwnerWake,
    events: TunEventSink,
) -> (TcpFlow, FlowOwner) {
    let bridge = Arc::new(Mutex::new(Bridge {
        to_application: ByteQueue::new(capacity),
        to_stack: ByteQueue::new(capacity),
        remote_closed: false,
        reset: false,
        shutdown_requested: false,
        fin_sent: false,
        aborted: false,
        read_waker: None,
        write_waker: None,
        shutdown_waker: None,
        owner_wake,
        events,
    }));
    (
        TcpFlow {
            target,
            bridge: Arc::clone(&bridge),
        },
        FlowOwner { bridge },
    )
}

struct Bridge {
    to_application: ByteQueue,
    to_stack: ByteQueue,
    remote_closed: bool,
    reset: bool,
    shutdown_requested: bool,
    fin_sent: bool,
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    shutdown_waker: Option<Waker>,
    owner_wake: OwnerWake,
    events: TunEventSink,
}

struct ByteQueue {
    bytes: Box<[u8]>,
    head: usize,
    len: usize,
}

impl ByteQueue {
    #[cfg(any(all(windows, target_arch = "x86_64"), test))]
    fn new(capacity: usize) -> Self {
        assert!(capacity != 0, "TUN TCP queue capacity must be non-zero");
        Self {
            bytes: vec![0; capacity].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.len
    }

    fn push(&mut self, source: &[u8]) -> usize {
        let count = source.len().min(self.remaining());
        if count == 0 {
            return 0;
        }
        let tail = (self.head + self.len) % self.bytes.len();
        let first = count.min(self.bytes.len() - tail);
        self.bytes[tail..tail + first].copy_from_slice(&source[..first]);
        let second = count - first;
        self.bytes[..second].copy_from_slice(&source[first..count]);
        self.len += count;
        count
    }

    fn pop(&mut self, destination: &mut [u8]) -> usize {
        let count = destination.len().min(self.len);
        if count == 0 {
            return 0;
        }
        let first = count.min(self.bytes.len() - self.head);
        destination[..first].copy_from_slice(&self.bytes[self.head..self.head + first]);
        let second = count - first;
        destination[first..count].copy_from_slice(&self.bytes[..second]);
        self.head = if count == self.bytes.len() {
            0
        } else {
            (self.head + count) % self.bytes.len()
        };
        self.len -= count;
        count
    }

    #[cfg(any(all(windows, target_arch = "x86_64"), test))]
    fn first(&self) -> &[u8] {
        let count = self.len.min(self.bytes.len() - self.head);
        &self.bytes[self.head..self.head + count]
    }

    #[cfg(any(all(windows, target_arch = "x86_64"), test))]
    fn consume(&mut self, count: usize) {
        assert!(count <= self.len, "TUN TCP queue consume is bounded");
        if count != 0 {
            self.head = if count == self.bytes.len() {
                0
            } else {
                (self.head + count) % self.bytes.len()
            };
        }
        self.len -= count;
    }
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
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::{ByteQueue, tcp_flow_pair_with_wake};
    use crate::OwnerWake;

    #[test]
    fn byte_queue_wraparound_uses_bounded_two_segment_copies() {
        let mut queue = ByteQueue::new(8);
        assert_eq!(queue.push(b"abcdef"), 6);
        let mut prefix = [0_u8; 5];
        assert_eq!(queue.pop(&mut prefix), 5);
        assert_eq!(&prefix, b"abcde");

        assert_eq!(queue.push(b"ghijklmn"), 7);
        assert_eq!(queue.remaining(), 0);
        assert_eq!(queue.first(), b"fgh");

        let mut output = [0_u8; 8];
        assert_eq!(queue.pop(&mut output), 8);
        assert_eq!(&output, b"fghijklm");
        assert!(queue.is_empty());
        assert_eq!(queue.push(b"n"), 1);
        assert_eq!(queue.pop(&mut output[..1]), 1);
        assert_eq!(output[0], b'n');
    }

    #[test]
    fn byte_queue_empty_io_is_explicit_and_full_input_is_truncated() {
        let mut queue = ByteQueue::new(3);
        assert_eq!(queue.push(&[]), 0);
        assert_eq!(queue.pop(&mut []), 0);
        assert_eq!(queue.push(b"abcd"), 3);
        assert_eq!(queue.push(b"z"), 0);
        let mut output = [0_u8; 4];
        assert_eq!(queue.pop(&mut output), 3);
        assert_eq!(&output[..3], b"abc");
    }

    #[test]
    #[should_panic(expected = "capacity must be non-zero")]
    fn byte_queue_rejects_zero_capacity() {
        let _ = ByteQueue::new(0);
    }

    #[tokio::test]
    async fn application_state_transitions_wake_the_idle_owner_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let wake = OwnerWake::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        });
        let (mut flow, mut owner) =
            tcp_flow_pair_with_wake("192.0.2.1:443".parse().expect("target"), 8, wake);

        flow.write_all(b"x").await.expect("application write");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut outbound = [0_u8; 1];
        assert_eq!(owner.read_to_stack(&mut outbound), 1);

        assert_eq!(owner.write_from_stack(b"y"), 1);
        let mut inbound = [0_u8; 1];
        flow.read_exact(&mut inbound)
            .await
            .expect("application read");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            AsyncWrite::poll_shutdown(Pin::new(&mut flow), &mut context),
            Poll::Pending
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(matches!(
            AsyncWrite::poll_shutdown(Pin::new(&mut flow), &mut context),
            Poll::Pending
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        drop(flow);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }
}
