use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Read-only snapshot of resources with explicit runtime owners.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerSnapshot {
    /// Children currently owned by a supervisor `JoinSet`.
    pub active_supervisor_children: usize,
    /// Active connection owner tasks.
    pub connection_tasks: usize,
    /// Fixed relay buffers owned by active flows.
    pub owned_buffers: usize,
    /// Connection permits held before or after accept.
    pub owned_permits: usize,
    /// Bound listeners owned by supervisors.
    pub listeners: usize,
    /// Flows terminated after a graceful deadline.
    pub forced_shutdowns: usize,
    /// Active protocol-neutral UDP sessions.
    pub udp_sessions: usize,
    /// Direct UDP sockets owned by active sessions.
    pub udp_sockets: usize,
    /// Direct UDP session tasks owned by the runtime.
    pub udp_tasks: usize,
    /// Datagram entries currently held in runtime queues.
    pub udp_queued_datagrams: usize,
    /// Allocated-capacity bytes held by UDP runtime owners.
    pub udp_buffered_bytes: usize,
    /// UDP receive scratch buffers currently owned by session tasks.
    pub udp_scratch_buffers: usize,
    /// UDP session tasks terminated after their graceful deadline.
    pub udp_forced_shutdowns: usize,
}

#[derive(Debug, Default)]
struct OwnerCounters {
    supervisor_children: AtomicUsize,
    connection_tasks: AtomicUsize,
    buffers: AtomicUsize,
    permits: AtomicUsize,
    listeners: AtomicUsize,
    forced_shutdowns: AtomicUsize,
    udp_sessions: AtomicUsize,
    udp_sockets: AtomicUsize,
    udp_tasks: AtomicUsize,
    udp_queued_datagrams: AtomicUsize,
    udp_buffered_bytes: AtomicUsize,
    udp_scratch_buffers: AtomicUsize,
    udp_forced_shutdowns: AtomicUsize,
}

/// Cloneable owner accounting used by deterministic lifecycle tests.
#[derive(Clone, Debug, Default)]
pub struct OwnerRegistry {
    counters: Arc<OwnerCounters>,
}

impl OwnerRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns current owner counts without mutating runtime state.
    pub fn snapshot(&self) -> OwnerSnapshot {
        OwnerSnapshot {
            active_supervisor_children: self.counters.supervisor_children.load(Ordering::SeqCst),
            connection_tasks: self.counters.connection_tasks.load(Ordering::SeqCst),
            owned_buffers: self.counters.buffers.load(Ordering::SeqCst),
            owned_permits: self.counters.permits.load(Ordering::SeqCst),
            listeners: self.counters.listeners.load(Ordering::SeqCst),
            forced_shutdowns: self.counters.forced_shutdowns.load(Ordering::SeqCst),
            udp_sessions: self.counters.udp_sessions.load(Ordering::SeqCst),
            udp_sockets: self.counters.udp_sockets.load(Ordering::SeqCst),
            udp_tasks: self.counters.udp_tasks.load(Ordering::SeqCst),
            udp_queued_datagrams: self.counters.udp_queued_datagrams.load(Ordering::SeqCst),
            udp_buffered_bytes: self.counters.udp_buffered_bytes.load(Ordering::SeqCst),
            udp_scratch_buffers: self.counters.udp_scratch_buffers.load(Ordering::SeqCst),
            udp_forced_shutdowns: self.counters.udp_forced_shutdowns.load(Ordering::SeqCst),
        }
    }

    pub(crate) fn track_supervisor_child(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::SupervisorChild)
    }

    pub(crate) fn track_connection_task(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::ConnectionTask)
    }

    pub(crate) fn track_buffer(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::Buffer)
    }

    pub(crate) fn track_permit(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::Permit)
    }

    pub(crate) fn track_listener(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::Listener)
    }

    pub(crate) fn track_udp_session(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::UdpSession)
    }

    pub(crate) fn track_udp_socket(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::UdpSocket)
    }

    pub(crate) fn track_udp_task(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::UdpTask)
    }

    pub(crate) fn track_udp_queue_entry(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::UdpQueueEntry)
    }

    pub(crate) fn track_udp_scratch(&self) -> OwnerGuard {
        OwnerGuard::new(self, OwnerKind::UdpScratch)
    }

    pub(crate) fn add_udp_buffered_bytes(&self, bytes: usize) {
        self.counters
            .udp_buffered_bytes
            .fetch_add(bytes, Ordering::SeqCst);
    }

    pub(crate) fn remove_udp_buffered_bytes(&self, bytes: usize) {
        let previous = self
            .counters
            .udp_buffered_bytes
            .fetch_sub(bytes, Ordering::SeqCst);
        debug_assert!(previous >= bytes, "UDP byte owner counter underflow");
    }

    pub(crate) fn record_udp_forced_shutdowns(&self, count: usize) {
        self.counters
            .udp_forced_shutdowns
            .fetch_add(count, Ordering::SeqCst);
    }

    pub(crate) fn record_forced_shutdowns(&self, count: usize) {
        self.counters
            .forced_shutdowns
            .fetch_add(count, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug)]
enum OwnerKind {
    SupervisorChild,
    ConnectionTask,
    Buffer,
    Permit,
    Listener,
    UdpSession,
    UdpSocket,
    UdpTask,
    UdpQueueEntry,
    UdpScratch,
}

#[derive(Debug)]
pub(crate) struct OwnerGuard {
    counters: Arc<OwnerCounters>,
    kind: OwnerKind,
}

impl OwnerGuard {
    fn new(registry: &OwnerRegistry, kind: OwnerKind) -> Self {
        counter(&registry.counters, kind).fetch_add(1, Ordering::SeqCst);
        Self {
            counters: Arc::clone(&registry.counters),
            kind,
        }
    }
}

impl Drop for OwnerGuard {
    fn drop(&mut self) {
        let previous = counter(&self.counters, self.kind).fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "owner counter underflow");
    }
}

fn counter(counters: &OwnerCounters, kind: OwnerKind) -> &AtomicUsize {
    match kind {
        OwnerKind::SupervisorChild => &counters.supervisor_children,
        OwnerKind::ConnectionTask => &counters.connection_tasks,
        OwnerKind::Buffer => &counters.buffers,
        OwnerKind::Permit => &counters.permits,
        OwnerKind::Listener => &counters.listeners,
        OwnerKind::UdpSession => &counters.udp_sessions,
        OwnerKind::UdpSocket => &counters.udp_sockets,
        OwnerKind::UdpTask => &counters.udp_tasks,
        OwnerKind::UdpQueueEntry => &counters.udp_queued_datagrams,
        OwnerKind::UdpScratch => &counters.udp_scratch_buffers,
    }
}
