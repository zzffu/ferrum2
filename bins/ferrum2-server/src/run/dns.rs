use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum2_dns::TaggedResolverOwner;
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};
use tokio::sync::Notify;

use super::RunError;
use super::dns_egress;

#[derive(Clone)]
pub(super) struct ServerDnsDrain {
    state: Arc<ServerDnsDrainState>,
}

struct ServerDnsDrainState {
    dependents: AtomicUsize,
    released: Notify,
}

impl ServerDnsDrain {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(ServerDnsDrainState {
                dependents: AtomicUsize::new(0),
                released: Notify::new(),
            }),
        }
    }

    pub(super) fn lease(&self) -> ServerDnsDrainLease {
        self.state.dependents.fetch_add(1, Ordering::AcqRel);
        ServerDnsDrainLease {
            state: Arc::clone(&self.state),
        }
    }

    async fn wait_for_dependents(&self) {
        loop {
            let released = self.state.released.notified();
            if self.state.dependents.load(Ordering::Acquire) == 0 {
                return;
            }
            released.await;
        }
    }
}

pub(super) struct ServerDnsDrainLease {
    state: Arc<ServerDnsDrainState>,
}

impl Drop for ServerDnsDrainLease {
    fn drop(&mut self) {
        let previous = self.state.dependents.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0, "server DNS drain lease underflow");
        if previous == 1 {
            self.state.released.notify_one();
        }
    }
}

pub(super) struct ServerDnsDependentRoot<R> {
    root: Option<R>,
    lease: Option<ServerDnsDrainLease>,
}

impl<R> ServerDnsDependentRoot<R> {
    pub(super) fn new(root: R, lease: Option<ServerDnsDrainLease>) -> Self {
        Self {
            root: Some(root),
            lease,
        }
    }
}

impl<R> PreparedProcessRoot<RunError> for ServerDnsDependentRoot<R>
where
    R: PreparedProcessRoot<RunError>,
{
    fn activate(&mut self) -> Result<(), RunError> {
        self.root
            .as_mut()
            .expect("prepared DNS-dependent root")
            .activate()
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let root = Box::new(self.root.take().expect("activated DNS-dependent root"));
        let lease = self.lease.take();
        Box::pin(async move {
            let _lease = lease;
            root.run(cancellation).await
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        let root = Box::new(self.root.take().expect("prepared DNS-dependent root"));
        let lease = self.lease.take();
        Box::pin(async move {
            let _lease = lease;
            root.rollback().await
        })
    }
}

pub(super) struct ServerDnsRoot {
    pub(super) state: Arc<dns_egress::ServerDnsState>,
    pub(super) owner: TaggedResolverOwner,
    pub(super) drain: ServerDnsDrain,
}

impl ServerDnsRoot {
    async fn close(&mut self) -> Result<(), RunError> {
        self.state.take();
        self.owner
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| RunError::ShutdownCleanup)
    }
}

impl PreparedProcessRoot<RunError> for ServerDnsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            cancellation.cancelled().await;
            self.drain.wait_for_dependents().await;
            self.close().await
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.close().await })
    }
}
