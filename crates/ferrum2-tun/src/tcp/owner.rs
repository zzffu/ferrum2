use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Waker;

use super::{Bridge, ByteQueue, TcpFlow};
use crate::{OwnerWake, TunEvent, TunEventSink};

pub(crate) struct FlowOwner {
    bridge: Arc<Mutex<Bridge>>,
}

impl FlowOwner {
    #[cfg(test)]
    pub(crate) fn read_to_stack(&mut self, destination: &mut [u8]) -> usize {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        let copied = bridge.to_stack.pop(destination);
        if copied != 0 {
            bridge.write_waker.take().into_iter().for_each(Waker::wake);
        }
        copied
    }

    pub(crate) fn drain_to_stack(&mut self, send: impl FnOnce(&[u8]) -> usize) -> usize {
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

    pub(crate) fn write_from_stack(&mut self, source: &[u8]) -> usize {
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

    pub(crate) fn application_capacity(&self) -> usize {
        self.bridge
            .lock()
            .expect("TUN TCP bridge")
            .to_application
            .remaining()
    }

    pub(crate) fn stack_buffered(&self) -> usize {
        self.bridge.lock().expect("TUN TCP bridge").to_stack.len
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        self.bridge
            .lock()
            .expect("TUN TCP bridge")
            .shutdown_requested
    }

    pub(crate) fn mark_fin_sent(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        bridge.fin_sent = true;
        bridge
            .shutdown_waker
            .take()
            .into_iter()
            .for_each(Waker::wake);
    }

    pub(crate) fn mark_remote_closed(&mut self) {
        let mut bridge = self.bridge.lock().expect("TUN TCP bridge");
        bridge.remote_closed = true;
        bridge.read_waker.take().into_iter().for_each(Waker::wake);
    }

    pub(crate) fn mark_reset(&mut self) {
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

    pub(crate) fn is_aborted(&self) -> bool {
        self.bridge.lock().expect("TUN TCP bridge").aborted
    }
}

#[cfg(test)]
pub(crate) fn tcp_flow_pair(target: SocketAddr, capacity: usize) -> (TcpFlow, FlowOwner) {
    tcp_flow_pair_with_wake(target, capacity, OwnerWake::default())
}

#[cfg(test)]
pub(crate) fn tcp_flow_pair_with_wake(
    target: SocketAddr,
    capacity: usize,
    owner_wake: OwnerWake,
) -> (TcpFlow, FlowOwner) {
    tcp_flow_pair_with_events(target, capacity, owner_wake, TunEventSink::default())
}

pub(crate) fn tcp_flow_pair_with_events(
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

impl ByteQueue {
    pub(super) fn new(capacity: usize) -> Self {
        assert!(capacity != 0, "TUN TCP queue capacity must be non-zero");
        Self {
            bytes: vec![0; capacity].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    pub(super) fn first(&self) -> &[u8] {
        let count = self.len.min(self.bytes.len() - self.head);
        &self.bytes[self.head..self.head + count]
    }

    pub(super) fn consume(&mut self, count: usize) {
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
