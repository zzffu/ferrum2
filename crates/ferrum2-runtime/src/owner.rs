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
}

#[derive(Debug, Default)]
struct OwnerCounters {
    supervisor_children: AtomicUsize,
    connection_tasks: AtomicUsize,
    buffers: AtomicUsize,
    permits: AtomicUsize,
    listeners: AtomicUsize,
    forced_shutdowns: AtomicUsize,
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
    }
}
