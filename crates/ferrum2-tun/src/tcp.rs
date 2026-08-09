use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        if copied != 0 || source.is_empty() {
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
        bridge.shutdown_requested = true;
        if bridge.fin_sent {
            Poll::Ready(Ok(()))
        } else {
            set_waker(&mut bridge.shutdown_waker, context.waker());
            Poll::Pending
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        if !bridge.fin_sent {
            bridge.aborted = true;
        }
    }
}

pub(super) struct FlowOwner {
    bridge: Arc<Mutex<Bridge>>,
}

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
        bridge.to_stack.consume(copied);
        if copied != 0 {
            bridge.write_waker.take().into_iter().for_each(Waker::wake);
        }
        copied
    }

    pub(super) fn write_from_stack(&mut self, source: &[u8]) -> usize {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = bridge.to_application.push(source);
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

pub(super) fn tcp_flow_pair(target: SocketAddr, capacity: usize) -> (TcpFlow, FlowOwner) {
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
}

struct ByteQueue {
    bytes: Box<[u8]>,
    head: usize,
    len: usize,
}

impl ByteQueue {
    fn new(capacity: usize) -> Self {
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
        for (offset, byte) in source[..count].iter().copied().enumerate() {
            self.bytes[(self.head + self.len + offset) % self.bytes.len()] = byte;
        }
        self.len += count;
        count
    }

    fn pop(&mut self, destination: &mut [u8]) -> usize {
        let count = destination.len().min(self.len);
        for (offset, byte) in destination[..count].iter_mut().enumerate() {
            *byte = self.bytes[(self.head + offset) % self.bytes.len()];
        }
        self.head = (self.head + count) % self.bytes.len();
        self.len -= count;
        count
    }

    fn first(&self) -> &[u8] {
        let count = self.len.min(self.bytes.len() - self.head);
        &self.bytes[self.head..self.head + count]
    }

    fn consume(&mut self, count: usize) {
        assert!(count <= self.len, "TUN TCP queue consume is bounded");
        self.head = (self.head + count) % self.bytes.len();
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
