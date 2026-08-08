use std::sync::Arc;

use ferrum2_dns::{DnsProxyListeners, TaggedResolver, TaggedResolverOwner};
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

use super::RunError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::report_result;
    use crate::run::test_support::*;

    #[tokio::test]
    async fn dns_proxy_prepare_cancellation_awaits_owner_and_rebinds() {
        let dns = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("readiness upstream");
        let upstream_address = upstream.local_addr().expect("readiness upstream address");
        let sockets = DnsProxySockets::bind(
            vec![SocketAddr::V4(dns)],
            16,
            std::num::NonZeroU16::new(1).expect("one DNS connection"),
            Duration::from_secs(1),
        )
        .await
        .expect("prepared paired DNS sockets");
        let (resolver, owner) = TaggedResolver::new(
            vec![ferrum2_dns::DnsUpstreamSpec {
                transport: ferrum2_dns::DnsUpstreamTransport::Udp,
                address: upstream_address,
                detour: None,
            }],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(1).expect("one DNS query"),
            Arc::new(ferrum2_dns::SystemDnsEgress),
        )
        .expect("resolver owner handoff");
        let resolver = Arc::new(resolver);
        let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), |_, _, _, _| Some(0)));
        let (readiness_sender, readiness_gate) = tokio::sync::oneshot::channel();
        let root = ProcessRoot::new(move || async move {
            Ok(ClientDnsRoot {
                listeners: Some(sockets.with_proxy(proxy)),
                resolver: Some(resolver),
                owner: Some(owner),
                readiness_gate: Some(readiness_gate),
            })
        });
        let registry = OwnerRegistry::new();
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
                .expect("readiness supervisor");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            report_result(
                supervisor
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await,
            )
        });
        for _ in 0..100 {
            if registry.snapshot().active_process_roots == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.snapshot().active_process_roots, 1);
        stop.send(()).expect("cancel during readiness");
        assert_eq!(task.await.expect("readiness client join"), Ok(()));
        drop(readiness_sender);
        drop(upstream);
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        drop(
            UdpSocket::bind(dns)
                .await
                .expect("readiness DNS UDP rebind"),
        );
        drop(
            TcpListener::bind(dns)
                .await
                .expect("readiness DNS TCP rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("readiness upstream rebind"),
        );

        let first_address = SocketAddr::V4(reserve_address());
        let occupied_address = SocketAddr::V4(reserve_address());
        let occupied = TcpListener::bind(occupied_address)
            .await
            .expect("rollback occupied TCP");
        assert!(
            DnsProxySockets::bind(
                vec![first_address, occupied_address],
                8,
                std::num::NonZeroU16::new(1).expect("rollback connection"),
                Duration::from_secs(1),
            )
            .await
            .is_err(),
            "paired DNS preparation unexpectedly succeeded"
        );
        drop(
            UdpSocket::bind(first_address)
                .await
                .expect("rollback first UDP rebind"),
        );
        drop(
            TcpListener::bind(first_address)
                .await
                .expect("rollback first TCP rebind"),
        );
        drop(
            UdpSocket::bind(occupied_address)
                .await
                .expect("rollback occupied UDP rebind"),
        );
        drop(occupied);
    }
}
