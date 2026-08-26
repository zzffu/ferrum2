use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use hickory_resolver::net::runtime::Spawn;
use tokio::task::JoinSet;

use super::admission::{DNS_QUERY_SCOPE, DnsQueryScope, RuntimeCounters};

#[derive(Default)]
struct TaskSetState {
    closed: bool,
    tasks: JoinSet<()>,
}

#[derive(Clone, Default)]
pub(crate) struct TaskSet(Arc<Mutex<TaskSetState>>);

impl TaskSet {
    fn spawn_counted(
        &self,
        counters: Arc<RuntimeCounters>,
        kind: CounterKind,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        let guard = CounterGuard::new(counters, kind);
        let rejected = {
            let mut state = self.0.lock().expect("DNS task set poisoned");
            if state.closed {
                Some((future, guard))
            } else {
                while state.tasks.try_join_next().is_some() {}
                state.tasks.spawn(async move {
                    let _guard = guard;
                    future.await;
                });
                None
            }
        };
        drop(rejected);
    }

    pub(crate) async fn abort_and_join(&self) {
        let mut tasks = {
            let mut state = self.0.lock().expect("DNS task set poisoned");
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
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
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl DnsTaskRegistrar {
    pub(super) fn new(
        tasks: TaskSet,
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

    /// Registers one bounded queue or buffer until the returned guard is dropped.
    pub fn own(&self, kind: DnsEgressResourceKind) -> DnsResourceGuard {
        match kind {
            DnsEgressResourceKind::Queue => &self.counters.queues,
            DnsEgressResourceKind::Buffer => &self.counters.buffers,
        }
        .fetch_add(1, Ordering::AcqRel);
        DnsResourceGuard {
            counters: Arc::clone(&self.counters),
            kind,
        }
    }
}

#[derive(Clone)]
pub(crate) struct TrackedHandle {
    tasks: TaskSet,
    counters: Arc<RuntimeCounters>,
    query_scope: DnsQueryScope,
}

impl TrackedHandle {
    pub(super) fn new(
        tasks: TaskSet,
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
