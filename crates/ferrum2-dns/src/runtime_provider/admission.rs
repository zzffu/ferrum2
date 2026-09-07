use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Context;

use futures_util::task::AtomicWaker;

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
    chain: Mutex<QueryChain>,
    changed: Arc<AtomicWaker>,
}

struct QueryChain {
    contexts: usize,
    closed: bool,
    failed: bool,
    waiters: Vec<std::sync::Weak<AtomicWaker>>,
}

impl QueryChain {
    fn wake_all(&self) {
        for waiter in &self.waiters {
            if let Some(waiter) = waiter.upgrade() {
                waiter.wake();
            }
        }
    }
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
    changed: Arc<AtomicWaker>,
}

impl DnsQueryContext {
    pub(crate) fn root(
        permit: OwnedSemaphorePermit,
        counters: Arc<RuntimeCounters>,
        deadline: Instant,
    ) -> Self {
        counters.queries.fetch_add(1, Ordering::AcqRel);
        let changed = Arc::new(AtomicWaker::new());
        Self {
            admission: Arc::new(QueryAdmission {
                permit: Some(permit),
                counters,
                chain: Mutex::new(QueryChain {
                    contexts: 1,
                    closed: false,
                    failed: false,
                    waiters: vec![Arc::downgrade(&changed)],
                }),
                changed: Arc::clone(&changed),
            }),
            dependency_depth: 0,
            deadline,
            changed,
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

    pub(crate) fn is_root(&self) -> bool {
        self.dependency_depth == 0
    }

    pub(crate) fn register(&self, cx: &Context<'_>) {
        self.changed.register(cx.waker());
    }

    pub(crate) fn close_chain(&self) {
        let mut chain = self
            .admission
            .chain
            .lock()
            .expect("DNS query chain poisoned");
        if !chain.closed {
            chain.closed = true;
            chain.wake_all();
        }
    }

    pub(crate) fn chain_closed(&self) -> bool {
        self.admission
            .chain
            .lock()
            .expect("DNS query chain poisoned")
            .closed
    }

    pub(crate) fn task_failed(&self) {
        let mut chain = self
            .admission
            .chain
            .lock()
            .expect("DNS query chain poisoned");
        if !chain.failed {
            chain.failed = true;
            chain.wake_all();
        }
    }

    pub(crate) fn has_task_failure(&self) -> bool {
        self.admission
            .chain
            .lock()
            .expect("DNS query chain poisoned")
            .failed
    }

    pub(crate) fn children_drained(&self, cx: &Context<'_>) -> bool {
        self.register(cx);
        self.admission
            .chain
            .lock()
            .expect("DNS query chain poisoned")
            .contexts
            == 1
    }
}

impl Drop for DnsQueryContext {
    fn drop(&mut self) {
        self.admission
            .chain
            .lock()
            .expect("DNS query chain poisoned")
            .contexts -= 1;
        self.admission.changed.wake();
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
        let admission = self.admission.upgrade()?;
        let changed = Arc::new(AtomicWaker::new());
        {
            let mut chain = admission.chain.lock().expect("DNS query chain poisoned");
            if chain.closed {
                return None;
            }
            // Retain only live subscriptions; sequential dependencies cannot grow this list.
            chain.waiters.retain(|waiter| waiter.strong_count() != 0);
            chain.waiters.push(Arc::downgrade(&changed));
            chain.contexts += 1;
        }
        Some(DnsQueryContext {
            admission,
            dependency_depth,
            deadline: self.deadline,
            changed,
        })
    }
}
