use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum2_config::{DnsServerConfig, DnsTransport};
use ferrum2_dns::{
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsError, DnsIoFuture, PlanSnapshot,
    RuntimeStats, SystemDnsEgress, TaggedResolver,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;

struct ControlledUdp {
    address: SocketAddr,
    respond: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct GatedEgress(AtomicBool);

impl DnsEgress for GatedEgress {
    fn connect_tcp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
        timeout: Duration,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        SystemDnsEgress.connect_tcp(target, plan, timeout)
    }

    fn bind_udp(
        &self,
        target: SocketAddr,
        plan: Option<PlanSnapshot>,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        if self.0.load(Ordering::Acquire) {
            Box::pin(std::future::pending())
        } else {
            SystemDnsEgress.bind_udp(target, plan)
        }
    }
}

impl ControlledUdp {
    async fn start() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind controlled UDP");
        let address = socket.local_addr().expect("controlled UDP address");
        let respond = Arc::new(AtomicBool::new(false));
        let task_respond = Arc::clone(&respond);
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4_096];
            loop {
                let (length, peer) = socket
                    .recv_from(&mut buffer)
                    .await
                    .expect("receive controlled query");
                if !task_respond.load(Ordering::Acquire) {
                    continue;
                }
                let request = Message::from_vec(&buffer[..length]).expect("Hickory request decode");
                let query = request.queries.first().expect("one query").clone();
                let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
                response.metadata.recursion_available = true;
                response
                    .add_query(query.clone())
                    .add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, 99))),
                    ));
                socket
                    .send_to(&response.to_vec().expect("Hickory response encode"), peer)
                    .await
                    .expect("send controlled response");
            }
        });
        Self {
            address,
            respond,
            task,
        }
    }

    async fn shutdown(self) {
        self.task.abort();
        assert!(
            self.task
                .await
                .expect_err("controlled task should cancel")
                .is_cancelled()
        );
    }
}

fn direct_udp(address: SocketAddr) -> DnsServerConfig {
    DnsServerConfig {
        transport: DnsTransport::Udp,
        address,
        server_name: None,
        path: None,
        detour: None,
    }
}

async fn wait_for_nonzero(resolver: &TaggedResolver) {
    for _ in 0..100 {
        if resolver.stats().queries != 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("query never entered the owned runtime");
}

async fn wait_for_zero(resolver: &TaggedResolver) {
    for _ in 0..250 {
        if resolver.stats() == RuntimeStats::default() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("DNS owners did not return to zero: {:?}", resolver.stats());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturation_timeout_recovery_shutdown_and_rebind_are_bounded() {
    let upstream = ControlledUdp::start().await;
    let resolver = Arc::new(
        TaggedResolver::direct(
            vec![direct_udp(upstream.address)],
            Duration::from_millis(250),
            NonZeroU16::new(1).expect("nonzero admission"),
        )
        .expect("start resolver"),
    );
    assert_eq!(resolver.stats(), RuntimeStats::default());
    assert_eq!(
        resolver
            .lookup(
                1,
                Name::from_ascii("invalid.resolver.test.").expect("invalid name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::InvalidServer)
    );

    let slow_resolver = Arc::clone(&resolver);
    let slow = tokio::spawn(async move {
        slow_resolver
            .lookup(
                0,
                Name::from_ascii("slow.resolver.test.").expect("slow name"),
                RecordType::A,
            )
            .await
    });
    wait_for_nonzero(&resolver).await;
    assert_eq!(
        resolver
            .lookup(
                0,
                Name::from_ascii("busy.resolver.test.").expect("busy name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::Busy)
    );
    assert_eq!(slow.await.expect("slow task join"), Err(DnsError::Timeout));
    wait_for_zero(&resolver).await;

    upstream.respond.store(true, Ordering::Release);
    let valid = resolver
        .lookup(
            0,
            Name::from_ascii("valid.resolver.test.").expect("valid name"),
            RecordType::A,
        )
        .await
        .expect("valid query after timeout");
    assert!(
        valid
            .answers()
            .iter()
            .any(|record| { record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 99))) })
    );
    wait_for_zero(&resolver).await;

    let resolver = Arc::try_unwrap(resolver).ok().expect("one resolver owner");
    assert_eq!(
        resolver.shutdown().await.expect("shutdown").runtime_tasks,
        0
    );

    let egress = Arc::new(GatedEgress::default());
    egress.0.store(true, Ordering::Release);
    let resolver = TaggedResolver::new(
        vec![direct_udp(upstream.address)],
        Duration::from_millis(50),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start gated resolver");
    assert_eq!(
        resolver
            .lookup(
                0,
                Name::from_ascii("gated.resolver.test.").expect("gated name"),
                RecordType::A,
            )
            .await,
        Err(DnsError::Timeout)
    );
    wait_for_zero(&resolver).await;
    egress.0.store(false, Ordering::Release);
    assert!(
        resolver
            .lookup(
                0,
                Name::from_ascii("recovered.resolver.test.").expect("recovered name"),
                RecordType::A,
            )
            .await
            .is_ok()
    );
    assert_eq!(
        resolver
            .shutdown()
            .await
            .expect("gated shutdown")
            .runtime_tasks,
        0
    );
    let address = upstream.address;
    upstream.shutdown().await;
    assert!(UdpSocket::bind(address).await.is_ok());
}
