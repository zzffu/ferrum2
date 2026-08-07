use super::*;

pub(super) struct ClientDnsRoot {
    pub(super) listeners: Option<DnsProxyListeners>,
    pub(super) resolver: Option<Arc<TaggedResolver>>,
    pub(super) owner: Option<TaggedResolverOwner>,
    #[cfg(test)]
    pub(super) readiness_gate: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ClientDnsRoot {
    async fn close_resolver(&mut self) -> Result<(), RunError> {
        self.listeners.take();
        self.resolver.take();
        self.owner
            .as_mut()
            .expect("prepared DNS owner")
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| RunError::ShutdownCleanup)
    }
}

impl PreparedProcessRoot<RunError> for ClientDnsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            #[cfg(test)]
            if let Some(readiness_gate) = self.readiness_gate.take() {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        self.close_resolver().await?;
                        return Ok(());
                    }
                    _ = readiness_gate => {}
                }
            }
            let ready = {
                let owner = self.owner.as_mut().expect("prepared DNS owner");
                tokio::select! {
                    _ = cancellation.cancelled() => None,
                    result = owner.ready() => Some(result),
                }
            };
            match ready {
                None => {
                    self.close_resolver().await?;
                    return Ok(());
                }
                Some(Err(_)) => {
                    self.close_resolver().await?;
                    return Err(RunError::StartupProtocol);
                }
                Some(Ok(())) => {}
            }
            let listeners = self.listeners.take().expect("prepared DNS listeners");
            let result = listeners.run(cancellation.cancelled()).await;
            self.close_resolver().await?;
            result.map_err(|_| RunError::RuntimeListener)
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.close_resolver().await })
    }
}
