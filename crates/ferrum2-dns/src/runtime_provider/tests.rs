use super::*;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use hickory_resolver::net::runtime::Spawn;
use tokio::time::Instant;

use super::tracking::TrackedHandle;

struct NeverPolled {
    polled: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Future for NeverPolled {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        self.polled.store(true, Ordering::Release);
        Poll::Ready(())
    }
}

impl Drop for NeverPolled {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

fn never_polled() -> (NeverPolled, Arc<AtomicBool>, Arc<AtomicBool>) {
    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    (
        NeverPolled {
            polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped),
        },
        polled,
        dropped,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn close_before_first_poll_and_late_spawn_leave_no_task_or_counter() {
    for _ in 0..100 {
        let mut tasks = TaskSet::default();
        let counters = Arc::new(RuntimeCounters::default());
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let context = DnsQueryContext::root(
            admission.try_acquire_owned().expect("test query admission"),
            Arc::clone(&counters),
            Instant::now() + Duration::from_secs(1),
        );
        let query_scope = context.scope();
        let registrar = DnsTaskRegistrar::new(
            tasks.registrar(),
            Arc::clone(&counters),
            query_scope.clone(),
        );
        let mut handle = TrackedHandle::new(tasks.registrar(), Arc::clone(&counters), query_scope);
        let mut polled = Vec::new();
        for spawn in [DnsEgressTaskKind::Bridge, DnsEgressTaskKind::Session] {
            let (future, was_polled, _) = never_polled();
            polled.push(was_polled);
            registrar.spawn(spawn, future);
        }
        let (future, was_polled, _) = never_polled();
        polled.push(was_polled);
        handle.spawn_bg(future);

        tasks.abort_and_join().await.expect("joined descendants");
        assert!(polled.iter().all(|flag| !flag.load(Ordering::Acquire)));
        assert_eq!(counters.tasks.load(Ordering::Acquire), 0);
        assert_eq!(counters.bridge_tasks.load(Ordering::Acquire), 0);
        assert_eq!(counters.sessions.load(Ordering::Acquire), 0);

        let (late, late_polled, late_dropped) = never_polled();
        registrar.spawn(DnsEgressTaskKind::Bridge, late);
        assert!(!late_polled.load(Ordering::Acquire));
        assert!(late_dropped.load(Ordering::Acquire));
        assert_eq!(counters.bridge_tasks.load(Ordering::Acquire), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn descendant_panic_is_sticky_and_join_waits_for_actual_resource_owner() {
    let mut tasks = TaskSet::default();
    let counters = Arc::new(RuntimeCounters::default());
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let context = DnsQueryContext::root(
        admission.clone().try_acquire_owned().unwrap(),
        counters.clone(),
        Instant::now() + Duration::from_secs(2),
    );
    let registrar = DnsTaskRegistrar::new(tasks.registrar(), counters.clone(), context.scope());
    let storage = registrar.own(DnsEgressResourceKind::Buffer).unwrap();
    let retained_registrar = registrar.clone();
    registrar.spawn(DnsEgressTaskKind::Bridge, async move {
        let _retained = retained_registrar;
        std::future::pending::<()>().await;
    });
    registrar.spawn(DnsEgressTaskKind::Session, async {
        panic!("injected descendant failure")
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| {
            let (failed, drained) = tasks.poll(cx);
            if failed {
                assert!(!drained);
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    tasks.close();
    assert_eq!(
        registrar.own(DnsEgressResourceKind::Queue).unwrap_err(),
        crate::DnsError::Shutdown
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), tasks.abort_and_join())
            .await
            .is_err()
    );
    assert_eq!(counters.buffers.load(Ordering::Acquire), 1);
    drop(storage);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), tasks.abort_and_join())
            .await
            .unwrap(),
        Err(crate::DnsError::Runtime)
    );
    assert_eq!(counters.bridge_tasks.load(Ordering::Acquire), 0);
    assert_eq!(counters.sessions.load(Ordering::Acquire), 0);
    assert_eq!(counters.buffers.load(Ordering::Acquire), 0);
    drop(tasks);
    assert_eq!(
        registrar.own(DnsEgressResourceKind::Buffer).unwrap_err(),
        crate::DnsError::Shutdown
    );
    drop(context);
    assert_eq!(admission.available_permits(), 1);
}
