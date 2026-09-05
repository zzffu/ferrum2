use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::TargetAddr;
use ferrum2_dns::{
    DnsPolicyProgram, DnsPolicyRoute, DnsProxy, DnsProxyListeners, DnsServerId, DnsStrategy,
    DnsUpstreamSpec, DnsUpstreamTransport, TaggedResolver,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshotBuilder};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn panicking_tcp_request_fails_listener_and_joins_sibling_connections() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream.local_addr().unwrap()).unwrap(),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_millis(20),
        NonZeroU16::new(2).unwrap(),
    )
    .unwrap();
    owner.ready().await.unwrap();
    let resolver = Arc::new(resolver);
    let snapshot = RuleEngineSnapshotBuilder::new(1).build().unwrap();
    let policy = DnsPolicyProgram::try_new(
        Vec::new(),
        DnsPolicyRoute::new(DnsServerId::new(0), DnsStrategy::Ipv4Only),
        &snapshot,
    )
    .unwrap();
    let proxy = Arc::new(
        DnsProxy::new(
            Arc::clone(&resolver),
            Arc::new(policy),
            Arc::new(RuleEngineRegistry::new(snapshot)),
            /* listener_count */ 1,
            /* ordinary_count */ 0,
        )
        .with_policy_observer(Arc::new(|_| panic!("injected observer failure"))),
    );
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let listeners = DnsProxyListeners::bind(
        vec![address],
        /* backlog */ 8,
        NonZeroU16::new(2).unwrap(),
        Duration::from_secs(30),
        Arc::clone(&proxy),
    )
    .await
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(listeners.run(async {
        let _ = stopped.await;
    }));
    let idle = TcpStream::connect(address).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let mut query = Message::new(1, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("failure.test.").unwrap(),
        RecordType::A,
    ));
    let wire = query.to_vec().unwrap();
    client
        .write_u16(u16::try_from(wire.len()).unwrap())
        .await
        .unwrap();
    client.write_all(&wire).await.unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(2), &mut task).await;
    // Also reap the old implementation on regression failure.
    let _ = stop.send(());
    if outcome.is_err() {
        task.await.unwrap().unwrap();
    }
    assert_eq!(Arc::strong_count(&proxy), 1, "all request owners joined");
    drop((idle, client, proxy, resolver));
    let cleanup = owner.shutdown().await.unwrap();
    let tcp = TcpListener::bind(address)
        .await
        .expect("TCP listener released");
    let udp = UdpSocket::bind(address)
        .await
        .expect("UDP listener released");
    drop((tcp, udp));
    assert_eq!(cleanup.runtime_tasks, 0);
    let error = outcome
        .expect("a panicking request must fail the listener")
        .expect("listener task must join")
        .expect_err("request panic must not be swallowed");
    assert_eq!(error.to_string(), "DNS TCP request task stopped");
}
