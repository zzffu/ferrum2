use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;

tokio::task_local! {
    pub(crate) static DNS_QUERY_SCOPE: DnsQueryScope;
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
