use std::sync::Arc;

use ferrum2_dns::TaggedResolverOwner;
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

use super::RunError;
use super::dns_egress;

pub(super) struct ServerDnsRoot {
    pub(super) state: Arc<dns_egress::ServerDnsState>,
    pub(super) owner: TaggedResolverOwner,
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
            self.close().await
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.close().await })
    }
}
