use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot, Network};
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveContext, ApplicationResolveRequest,
    BoxedDnsDatagramIo, BoxedDnsTcpIo, DnsEgress, DnsError, DnsIoFuture, DnsStrategy,
    DnsTaskRegistrar, DnsUpstreamSpec, DnsUpstreamTransport, SystemDnsEgress, TaggedResolver,
    TaggedServerApplicationResolveBackend,
};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, SOA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_server::Server;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, Catalog, ZoneType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(10_000);

async fn bind_paired_sockets() -> (SocketAddr, UdpSocket, TcpListener) {
    loop {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(port < 30_000, "no paired test address available");
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if let (Ok(tcp), Ok(udp)) = (
            TcpListener::bind(address).await,
            UdpSocket::bind(address).await,
        ) {
            return (address, udp, tcp);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EgressCall {
    network: &'static str,
    target: TargetAddr,
    plan: Option<Vec<usize>>,
}

#[derive(Default)]
struct RecordingEgress {
    calls: Mutex<Vec<EgressCall>>,
    plan_ptrs: Mutex<Vec<usize>>,
    dial_override: Option<SocketAddr>,
}

impl RecordingEgress {
    fn calls(&self) -> Vec<EgressCall> {
        self.calls.lock().expect("egress calls poisoned").clone()
    }

    fn plan_ptrs(&self) -> Vec<usize> {
        self.plan_ptrs
            .lock()
            .expect("plan pointers poisoned")
            .clone()
    }

    fn with_dial_override(dial_override: SocketAddr) -> Self {
        Self {
            dial_override: Some(dial_override),
            ..Self::default()
        }
    }

    fn record(
        &self,
        network: &'static str,
        target: &TargetAddr,
        plan: &Option<EgressPlanSnapshot>,
    ) {
        if let Some(plan) = plan {
            self.plan_ptrs
                .lock()
                .expect("plan pointers poisoned")
                .push(plan.hops().as_ptr() as usize);
        }
        self.calls
            .lock()
            .expect("egress calls poisoned")
            .push(EgressCall {
                network,
                target: target.clone(),
                plan: plan.as_ref().map(|plan| plan.hops().to_vec()),
            });
    }

    fn dial_target(&self, logical: &TargetAddr) -> TargetAddr {
        match self.dial_override {
            Some(address) => TargetAddr::ip(address).expect("non-zero fixture target"),
            None => logical.clone(),
        }
    }
}

impl DnsEgress for RecordingEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        self.record("tcp", &target, &plan);
        SystemDnsEgress.connect_tcp(self.dial_target(&target), None, timeout, tasks)
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        self.record("udp", &target, &plan);
        SystemDnsEgress.bind_udp(self.dial_target(&target), None, tasks)
    }
}

struct PlainFixture {
    address: SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl PlainFixture {
    async fn start() -> Self {
        let (address, udp, tcp) = bind_paired_sockets().await;

        let origin = Name::from_ascii("resolver.test.").expect("zone origin");
        let mut zone = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::Deny,
        );
        let ns = Name::from_ascii("ns.resolver.test.").expect("NS name");
        zone.upsert_mut(
            Record::from_rdata(
                origin.clone(),
                60,
                RData::SOA(SOA::new(
                    ns.clone(),
                    Name::from_ascii("hostmaster.resolver.test.").expect("SOA mailbox"),
                    1,
                    60,
                    60,
                    60,
                    60,
                )),
            ),
            1,
        );
        zone.upsert_mut(Record::from_rdata(origin.clone(), 60, RData::NS(NS(ns))), 1);
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("answer.resolver.test.").expect("A name"),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("answer.resolver.test.").expect("AAAA name"),
                60,
                RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("a-only.resolver.test.").expect("A-only name"),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 42))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("v6.resolver.test.").expect("AAAA name"),
                60,
                RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 41))),
            ),
            1,
        );
        zone.upsert_mut(
            Record::from_rdata(
                Name::from_ascii("alias.resolver.test.").expect("CNAME owner"),
                60,
                RData::CNAME(CNAME(
                    Name::from_ascii("answer.resolver.test.").expect("CNAME target"),
                )),
            ),
            1,
        );

        let mut catalog = Catalog::new();
        catalog.upsert(LowerName::new(&origin), vec![Arc::new(zone)]);
        let mut server = Server::new(catalog);
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(2), 4);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = stopped.await;
            server
                .shutdown_gracefully()
                .await
                .expect("fixture server failed");
        });
        Self {
            address,
            stop,
            task,
        }
    }

    async fn shutdown(self) {
        self.stop.send(()).expect("fixture shutdown signal");
        self.task.await.expect("fixture shutdown task");
    }
}

fn configured_server(
    address: SocketAddr,
    transport: DnsUpstreamTransport,
    detoured: bool,
) -> DnsUpstreamSpec {
    DnsUpstreamSpec {
        transport,
        target: TargetAddr::ip(address).expect("non-zero fixture target"),
        resolved_targets: Box::new([]),
        detour: detoured.then(|| EgressPlanHandle::direct(0)),
    }
}

fn numeric_target(address: SocketAddr) -> TargetAddr {
    TargetAddr::ip(address).expect("non-zero fixture target")
}

#[path = "tagged_upstreams/detour.rs"]
mod detour;
#[path = "tagged_upstreams/lifecycle.rs"]
mod lifecycle;
#[path = "tagged_upstreams/selection.rs"]
mod selection;
#[path = "tagged_upstreams/transport.rs"]
mod transport;
