use std::future::Future;
#[cfg(test)]
use std::future::poll_fn;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use futures_util::task::AtomicWaker;
use hickory_resolver::net::runtime::Spawn;
use tokio::task::JoinSet;

use super::admission::{DNS_QUERY_SCOPE, DnsQueryScope, RuntimeCounters};
use crate::DnsError;

#[derive(Default)]
struct TaskSetState {
    closed: bool,
    failed: bool,
    resources: usize,
    tasks: JoinSet<()>,
}

#[derive(Default)]
struct TaskSetInner {
    state: Mutex<TaskSetState>,
    changed: AtomicWaker,
}

/// Unique query-owned authority over descendants and registered resources.
#[derive(Default)]
pub(crate) struct TaskSet(Arc<TaskSetInner>);

/// May register work while its unique query owner remains open; never owns joins.
#[derive(Clone)]
pub(crate) struct TaskRegistration(Weak<TaskSetInner>);

impl TaskSet {
    pub(crate) fn registrar(&self) -> TaskRegistration {
        TaskRegistration(Arc::downgrade(&self.0))
    }

    pub(crate) fn close(&mut self) {
        let mut state = self.0.state.lock().expect("DNS task set poisoned");
        state.closed = true;
        state.tasks.abort_all();
    }

    /// Reap live completions too, so a failed descendant interrupts a pending body.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> (bool, bool) {
        self.0.changed.register(cx.waker());
        let mut state = self.0.state.lock().expect("DNS task set poisoned");
        while let Poll::Ready(Some(result)) = state.tasks.poll_join_next(cx) {
            if let Err(error) = result
                && (error.is_panic() || !state.closed)
            {
                state.failed = true;
            }
        }
        (state.failed, state.tasks.is_empty() && state.resources == 0)
    }

    #[cfg(test)]
    pub(crate) async fn abort_and_join(&mut self) -> Result<(), DnsError> {
        self.close();
        poll_fn(|cx| {
            let (failed, drained) = self.poll(cx);
            if drained {
                Poll::Ready(if failed {
                    Err(DnsError::Runtime)
                } else {
                    Ok(())
                })
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

impl TaskRegistration {
    fn spawn_counted(
        &self,
        counters: Arc<RuntimeCounters>,
        kind: CounterKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let Some(owner) = self.0.upgrade() else {
            return;
        };
        let mut state = owner.state.lock().expect("DNS task set poisoned");
        if state.closed {
            drop(state);
            return;
        }
        let guard = CounterGuard::new(counters, kind);
        state.tasks.spawn(async move {
            let _guard = guard;
            future.await;
        });
        drop(state);
        owner.changed.wake();
    }
}

/// Kind of detour work registered under one logical DNS query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEgressTaskKind {
    /// A bounded I/O bridge carrying the selected DNS transport.
    Bridge,
    /// A concrete detour session owned by that bridge.
    Session,
}

/// Kind of bounded detour storage owned under one logical DNS query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsEgressResourceKind {
    /// A bounded queue between the adapter and its bridge.
    Queue,
    /// Fixed-capacity bridge buffer storage.
    Buffer,
}

/// RAII ownership for bounded detour storage.
#[must_use = "keep the guard with its queue or buffer owner"]
pub struct DnsResourceGuard {
    owner: Weak<TaskSetInner>,
    counters: Arc<RuntimeCounters>,
    kind: DnsEgressResourceKind,
}

impl Drop for DnsResourceGuard {
    fn drop(&mut self) {
        match self.kind {
            DnsEgressResourceKind::Queue => &self.counters.queues,
            DnsEgressResourceKind::Buffer => &self.counters.buffers,
        }
        .fetch_sub(1, Ordering::AcqRel);
        if let Some(owner) = self.owner.upgrade() {
            owner.state.lock().expect("DNS task set poisoned").resources -= 1;
            owner.changed.wake();
        }
    }
}

impl std::fmt::Debug for DnsResourceGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DnsResourceGuard([redacted])")
    }
}

/// Registers detour work for abort-and-join with its logical DNS query.
#[derive(Clone)]
pub struct DnsTaskRegistrar {
    tasks: TaskRegistration,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl DnsTaskRegistrar {
    pub(super) fn new(
        tasks: TaskRegistration,
        counters: Arc<RuntimeCounters>,
        query_scope: DnsQueryScope,
    ) -> Self {
        Self {
            tasks,
            counters,
            query_scope,
        }
    }

    /// Spawns one bridge or session task on the exclusive DNS runtime.
    pub fn spawn(
        &self,
        kind: DnsEgressTaskKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let kind = match kind {
            DnsEgressTaskKind::Bridge => CounterKind::Bridge,
            DnsEgressTaskKind::Session => CounterKind::Session,
        };
        self.tasks.spawn_counted(
            Arc::clone(&self.counters),
            kind,
            DNS_QUERY_SCOPE.scope(self.query_scope.clone(), future),
        );
    }

    /// Registers bounded storage until its actual owner drops the guard.
    /// Returns Shutdown after registration closes. Callers must release their
    /// newly created storage on failure and retain accepted guards with it.
    pub fn own(&self, kind: DnsEgressResourceKind) -> Result<DnsResourceGuard, DnsError> {
        let owner = self.tasks.0.upgrade().ok_or(DnsError::Shutdown)?;
        let mut state = owner.state.lock().expect("DNS task set poisoned");
        if state.closed {
            return Err(DnsError::Shutdown);
        }
        state.resources += 1;
        match kind {
            DnsEgressResourceKind::Queue => &self.counters.queues,
            DnsEgressResourceKind::Buffer => &self.counters.buffers,
        }
        .fetch_add(1, Ordering::AcqRel);
        Ok(DnsResourceGuard {
            owner: Arc::downgrade(&owner),
            counters: Arc::clone(&self.counters),
            kind,
        })
    }
}

#[derive(Clone)]
pub(crate) struct TrackedHandle {
    tasks: TaskRegistration,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl TrackedHandle {
    pub(super) fn new(
        tasks: TaskRegistration,
        counters: Arc<RuntimeCounters>,
        query_scope: DnsQueryScope,
    ) -> Self {
        Self {
            tasks,
            counters,
            query_scope,
        }
    }
}

impl Spawn for TrackedHandle {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn_counted(
            Arc::clone(&self.counters),
            CounterKind::Hickory,
            DNS_QUERY_SCOPE.scope(self.query_scope.clone(), future),
        );
    }
}

#[derive(Clone, Copy)]
pub(super) enum CounterKind {
    Hickory,
    Bridge,
    Session,
}

pub(super) struct CounterGuard {
    counters: Arc<RuntimeCounters>,
    kind: CounterKind,
}

impl CounterGuard {
    pub(super) fn new(counters: Arc<RuntimeCounters>, kind: CounterKind) -> Self {
        match kind {
            CounterKind::Hickory => &counters.tasks,
            CounterKind::Bridge => &counters.bridge_tasks,
            CounterKind::Session => &counters.sessions,
        }
        .fetch_add(1, Ordering::AcqRel);
        Self { counters, kind }
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        match self.kind {
            CounterKind::Hickory => &self.counters.tasks,
            CounterKind::Bridge => &self.counters.bridge_tasks,
            CounterKind::Session => &self.counters.sessions,
        }
        .fetch_sub(1, Ordering::AcqRel);
    }
}
