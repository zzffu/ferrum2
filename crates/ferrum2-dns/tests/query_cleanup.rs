use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsEgressResourceKind, DnsEgressTaskKind,
    DnsError, DnsIoFuture, DnsResourceGuard, DnsTaskRegistrar, DnsUpstreamSpec,
    DnsUpstreamTransport, RuntimeStats, TaggedResolver,
};
use hickory_proto::rr::{Name, RecordType};
use std::future::pending;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
enum Failure {
    Body,
    Descendant,
}

struct FailingEgress {
    failure: Failure,
    started: Mutex<Option<oneshot::Sender<(DnsResourceGuard, DnsTaskRegistrar)>>>,
}

impl DnsEgress for FailingEgress {
    fn connect_tcp(
        &self,
        _: TargetAddr,
        _: Option<EgressPlanSnapshot>,
        _: Duration,
        _: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        Box::pin(async { Err(std::io::Error::other("unexpected TCP")) })
    }
    fn bind_udp(
        &self,
        _: TargetAddr,
        _: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let started = self.started.lock().unwrap().take().unwrap();
        let failure = self.failure;
        Box::pin(async move {
            let guard = tasks.own(DnsEgressResourceKind::Buffer).unwrap();
            let retained = tasks.clone();
            tasks.spawn(DnsEgressTaskKind::Bridge, async move {
                let _registrar = retained;
                pending::<()>().await;
            });
            assert!(started.send((guard, tasks.clone())).is_ok());
            match failure {
                Failure::Body => panic!("injected body failure"),
                Failure::Descendant => {
                    tasks.spawn(DnsEgressTaskKind::Session, async {
                        panic!("injected child failure")
                    });
                    pending().await
                }
            }
        })
    }
}

#[tokio::test]
async fn panic_keeps_admission_until_resources_drop_and_shutdown_failure_is_retryable() {
    for failure in [Failure::Body, Failure::Descendant] {
        let (started, receive) = oneshot::channel();
        let egress = Arc::new(FailingEgress {
            failure,
            started: Mutex::new(Some(started)),
        });
        let server = DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip("192.0.2.1:53".parse().unwrap()).unwrap(),
            resolved_targets: Box::new([]),
            detour: None,
        };
        let (resolver, mut owner) = TaggedResolver::new(
            vec![server],
            Duration::from_secs(5),
            NonZeroU16::new(1).unwrap(),
            egress,
        )
        .unwrap();
        owner.ready().await.unwrap();
        let name = Name::from_ascii("cleanup.test.").unwrap();
        let mut query = tokio::spawn(resolver.lookup(0, name.clone(), RecordType::A));
        let (guard, registrar) = tokio::time::timeout(Duration::from_secs(2), receive)
            .await
            .unwrap()
            .unwrap();
        // Cleanup can join the body and descendants, but cannot claim this storage was released.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut query)
                .await
                .is_err()
        );
        assert_eq!(
            resolver.lookup(0, name, RecordType::A).await,
            Err(DnsError::Busy)
        );
        assert_eq!(
            registrar.own(DnsEgressResourceKind::Queue).unwrap_err(),
            DnsError::Shutdown
        );
        drop(guard);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), query)
                .await
                .unwrap()
                .unwrap(),
            Err(DnsError::Runtime)
        );
        assert_eq!(resolver.stats(), RuntimeStats::default());
        drop(resolver);
        assert_eq!(owner.shutdown().await, Err(DnsError::Runtime));
        assert_eq!(owner.shutdown().await, Err(DnsError::Runtime));
    }
}
