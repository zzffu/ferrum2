use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::Network;
use ferrum2_core::{CanonicalDomain, TargetAddr};
use ferrum2_dns::{
    ApplicationResolveContext, ApplicationResolveRequest, DnsError, DnsPolicyProgram,
    DnsPolicyRoute, DnsProxy, DnsProxyListeners, DnsServerId, DnsStrategy, DnsUdpEvent,
    DnsUpstreamSpec, DnsUpstreamTransport, ProxyIngress, ProxyTransport, TaggedResolver,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshotBuilder};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn final_proxy(
    resolver: Arc<TaggedResolver>,
    strategy: DnsStrategy,
    listener_count: usize,
    ordinary_count: usize,
) -> DnsProxy {
    let snapshot = RuleEngineSnapshotBuilder::new(1)
        .build()
        .expect("empty rule snapshot");
    let policy = Arc::new(
        DnsPolicyProgram::try_new(
            Vec::new(),
            DnsPolicyRoute::new(DnsServerId::new(0), strategy),
            &snapshot,
        )
        .expect("final-only DNS policy"),
    );
    DnsProxy::new(
        resolver,
        policy,
        Arc::new(RuleEngineRegistry::new(snapshot)),
        listener_count,
        ordinary_count,
    )
}

#[tokio::test]
async fn application_resolution_uses_qtype_policy_strategy_and_no_system_fallback() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application upstream bind");
    let upstream_address = upstream.local_addr().expect("application upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for expected in [RecordType::AAAA, RecordType::A] {
            let (length, peer) = upstream
                .recv_from(&mut wire)
                .await
                .expect("application query");
            let request = Message::from_vec(&wire[..length]).expect("application request");
            let query = request
                .queries
                .first()
                .expect("one application query")
                .clone();
            assert_eq!(query.query_type(), expected);
            let answer = match expected {
                RecordType::A => RData::A(A(Ipv4Addr::new(192, 0, 2, 73))),
                RecordType::AAAA => {
                    RData::AAAA(AAAA("2001:db8::73".parse().expect("application IPv6")))
                }
                _ => unreachable!("bounded application query types"),
            };
            let mut response = Message::response(request.id, OpCode::Query);
            response
                .add_query(query.clone())
                .add_answer(Record::from_rdata(query.name().clone(), 30, answer));
            upstream
                .send_to(&response.to_vec().expect("application response"), peer)
                .await
                .expect("application response send");
        }
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("non-zero upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(2).expect("two application queries"),
    )
    .expect("application resolver");
    owner.ready().await.expect("application resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv6, 0, 8);
    let domain = CanonicalDomain::new("Strategy.Example.").expect("canonical application name");
    let request = ApplicationResolveRequest::new(
        ApplicationResolveContext::new(7, Network::Tcp),
        &domain,
        NonZeroU16::new(443).expect("application port"),
        DnsStrategy::PreferIpv6,
    );

    assert_eq!(
        proxy
            .resolve_application(request)
            .await
            .expect("configured application resolution"),
        [
            SocketAddr::new(
                Ipv6Addr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x73
                ])
                .into(),
                443
            ),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 73).into(), 443),
        ]
    );
    upstream_task.await.expect("application upstream join");

    let closed = final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv6, 0, 0);
    assert_eq!(
        closed
            .resolve_application(request)
            .await
            .expect_err("missing configured selection is terminal"),
        DnsError::InvalidServer
    );
    drop((closed, proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("application resolver shutdown")
            .runtime_tasks,
        0
    );
}

fn reserve_paired_addresses(count: usize) -> Vec<SocketAddr> {
    let mut reservations = Vec::with_capacity(count);
    while reservations.len() < count {
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP reserve");
        let address = tcp.local_addr().expect("paired reserve address");
        if let Ok(udp) = std::net::UdpSocket::bind(address) {
            reservations.push((address, tcp, udp));
        }
    }
    reservations
        .into_iter()
        .map(|(address, _, _)| address)
        .collect()
}

fn udp_query(id: u16, name: &str) -> Vec<u8> {
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii(name).expect("UDP concurrency query name"),
        RecordType::A,
    ));
    request.to_vec().expect("UDP concurrency query")
}

fn udp_answer(request: &Message, octet: u8) -> Vec<u8> {
    let question = request
        .queries
        .first()
        .expect("UDP concurrency question")
        .clone();
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response
        .add_query(question.clone())
        .add_answer(Record::from_rdata(
            question.name().clone(),
            30,
            RData::A(A(Ipv4Addr::new(192, 0, 2, octet))),
        ));
    response.to_vec().expect("UDP concurrency answer")
}

#[tokio::test]
async fn udp_listener_fast_query_overtakes_a_slow_query() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("concurrent upstream bind");
    let upstream_address = upstream.local_addr().expect("concurrent upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let mut requests = Vec::with_capacity(2);
        for _ in 0..2 {
            let (length, peer) = upstream
                .recv_from(&mut wire)
                .await
                .expect("concurrent query");
            requests.push((
                Message::from_vec(&wire[..length]).expect("typed concurrent query"),
                peer,
            ));
        }
        let (fast, fast_peer) = requests
            .iter()
            .find(|(request, _)| request.metadata.id == 0x6102)
            .expect("fast query");
        upstream
            .send_to(&udp_answer(fast, 2), *fast_peer)
            .await
            .expect("fast answer send");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (slow, slow_peer) = requests
            .iter()
            .find(|(request, _)| request.metadata.id == 0x6101)
            .expect("slow query");
        upstream
            .send_to(&udp_answer(slow, 1), *slow_peer)
            .await
            .expect("slow answer send");
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("concurrent upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(2).expect("two concurrent queries"),
    )
    .expect("concurrent resolver");
    owner.ready().await.expect("concurrent resolver ready");
    let resolver = Arc::new(resolver);
    let listen = reserve_paired_addresses(1)[0];
    let listeners = DnsProxyListeners::bind(
        vec![listen],
        8,
        NonZeroU16::new(2).expect("two inflight UDP requests"),
        Duration::from_secs(1),
        Arc::new(final_proxy(
            Arc::clone(&resolver),
            DnsStrategy::PreferIpv4,
            1,
            0,
        )),
    )
    .await
    .expect("concurrent listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("concurrent client");
    client
        .send_to(&udp_query(0x6101, "slow.concurrent.example."), listen)
        .await
        .expect("slow query send");
    client
        .send_to(&udp_query(0x6102, "fast.concurrent.example."), listen)
        .await
        .expect("fast query send");

    let mut wire = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut wire))
        .await
        .expect("fast response was blocked by slow query")
        .expect("fast response receive");
    assert_eq!(
        Message::from_vec(&wire[..length])
            .expect("typed fast response")
            .metadata
            .id,
        0x6102
    );
    let (length, _) = tokio::time::timeout(Duration::from_millis(400), client.recv_from(&mut wire))
        .await
        .expect("slow response timeout")
        .expect("slow response receive");
    assert_eq!(
        Message::from_vec(&wire[..length])
            .expect("typed slow response")
            .metadata
            .id,
        0x6101
    );

    stop.send(()).expect("stop concurrent listener");
    assert!(running.await.expect("concurrent listener join").is_ok());
    upstream_task.await.expect("concurrent upstream join");
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("concurrent resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn udp_listener_drops_new_datagrams_when_the_inflight_pool_is_saturated() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("saturation upstream bind");
    let upstream_address = upstream.local_addr().expect("saturation upstream address");
    let (first_seen, first_seen_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let (length, peer) = upstream.recv_from(&mut wire).await.expect("first query");
        let first = Message::from_vec(&wire[..length]).expect("typed first query");
        first_seen.send(()).expect("announce first query");
        release_rx.await.expect("release first query");
        upstream
            .send_to(&udp_answer(&first, 1), peer)
            .await
            .expect("first answer send");
        tokio::time::timeout(Duration::from_millis(100), upstream.recv_from(&mut wire))
            .await
            .is_ok()
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("saturation upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(2).expect("resolver admission"),
    )
    .expect("saturation resolver");
    owner.ready().await.expect("saturation resolver ready");
    let resolver = Arc::new(resolver);
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observer_events = Arc::clone(&events);
    let listen = reserve_paired_addresses(1)[0];
    let listeners = DnsProxyListeners::bind(
        vec![listen],
        8,
        NonZeroU16::new(1).expect("one inflight UDP request"),
        Duration::from_secs(1),
        Arc::new(
            final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv4, 1, 0).with_udp_observer(
                Arc::new(move |event| {
                    observer_events
                        .lock()
                        .expect("DNS event observer")
                        .push(event);
                }),
            ),
        ),
    )
    .await
    .expect("saturation listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("saturation client");
    client
        .send_to(&udp_query(0x6201, "first.saturated.example."), listen)
        .await
        .expect("first query send");
    first_seen_rx.await.expect("first query reached upstream");
    client
        .send_to(&udp_query(0x6202, "dropped.saturated.example."), listen)
        .await
        .expect("saturated query send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    release.send(()).expect("release first answer");

    let mut wire = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut wire))
        .await
        .expect("first response timeout")
        .expect("first response receive");
    assert_eq!(
        Message::from_vec(&wire[..length])
            .expect("typed first response")
            .metadata
            .id,
        0x6201
    );
    assert!(
        !upstream_task.await.expect("saturation upstream join"),
        "saturated query reached the upstream"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.recv_from(&mut wire))
            .await
            .is_err(),
        "saturated query unexpectedly received a response"
    );

    stop.send(()).expect("stop saturation listener");
    assert!(running.await.expect("saturation listener join").is_ok());
    {
        let events = events.lock().expect("DNS event observations");
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == DnsUdpEvent::Acquired)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == DnsUdpEvent::Completed)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == DnsUdpEvent::PoolDrop)
                .count(),
            1
        );
        assert!(!events.contains(&DnsUdpEvent::EncodeFailure));
    }
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("saturation resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn udp_listener_shutdown_aborts_and_joins_active_requests() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("shutdown upstream bind");
    let upstream_address = upstream.local_addr().expect("shutdown upstream address");
    let (seen, seen_rx) = tokio::sync::oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        upstream.recv_from(&mut wire).await.expect("active query");
        seen.send(()).expect("announce active query");
        std::future::pending::<()>().await;
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("shutdown upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(30),
        NonZeroU16::new(1).expect("one active query"),
    )
    .expect("shutdown resolver");
    owner.ready().await.expect("shutdown resolver ready");
    let resolver = Arc::new(resolver);
    let listen = reserve_paired_addresses(1)[0];
    let listeners = DnsProxyListeners::bind(
        vec![listen],
        8,
        NonZeroU16::new(1).expect("one active UDP request"),
        Duration::from_secs(1),
        Arc::new(final_proxy(
            Arc::clone(&resolver),
            DnsStrategy::PreferIpv4,
            1,
            0,
        )),
    )
    .await
    .expect("shutdown listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("shutdown client");
    client
        .send_to(&udp_query(0x6301, "active.shutdown.example."), listen)
        .await
        .expect("active query send");
    seen_rx.await.expect("active query reached upstream");
    stop.send(()).expect("stop active listener");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .expect("active listener did not converge")
            .expect("active listener join")
            .is_ok()
    );

    upstream_task.abort();
    assert!(
        upstream_task
            .await
            .expect_err("abort stalled upstream")
            .is_cancelled()
    );
    drop(resolver);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .expect("active resolver shutdown did not converge")
            .expect("active resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn udp_proxy_preserves_positive_and_negative_upstream_responses() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream bind");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for index in 0..5 {
            let (length, peer) = upstream.recv_from(&mut wire).await.expect("query");
            let request = Message::from_vec(&wire[..length]).expect("Hickory request");
            let query = request.queries.first().expect("one question").clone();
            let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
            response.add_query(query.clone());
            match index {
                0 => {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
                    ));
                }
                1 => {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::AAAA(AAAA("2001:db8::44".parse().expect("AAAA answer"))),
                    ));
                }
                2 => {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        30,
                        RData::CNAME(CNAME(
                            Name::from_ascii("selected.example.").expect("CNAME target"),
                        )),
                    ));
                }
                3 => {
                    response.metadata.response_code = ResponseCode::NXDomain;
                    response
                        .add_authority(Record::from_rdata(
                            Name::from_ascii("example.").expect("authority owner"),
                            60,
                            RData::SOA(SOA::new(
                                Name::from_ascii("ns.example.").expect("primary name"),
                                Name::from_ascii("hostmaster.example.").expect("responsible name"),
                                7,
                                60,
                                60,
                                300,
                                30,
                            )),
                        ))
                        .add_additional(Record::from_rdata(
                            Name::from_ascii("ns.example.").expect("additional owner"),
                            60,
                            RData::A(A(Ipv4Addr::new(198, 51, 100, 53))),
                        ))
                        .set_edns({
                            let mut edns = Edns::new();
                            edns.set_max_payload(1232);
                            edns
                        });
                }
                4 => {}
                _ => unreachable!("bounded response table"),
            }
            upstream
                .send_to(&response.to_vec().expect("response encode"), peer)
                .await
                .expect("response send");
        }
    });
    let server = DnsUpstreamSpec {
        transport: DnsUpstreamTransport::Udp,
        target: TargetAddr::ip(upstream_address).expect("non-zero upstream target"),
        resolved_targets: Box::new([]),
        detour: None,
    };
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv4, 1, 0);
    let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("selected.example.").expect("query name"),
        RecordType::A,
    ));

    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("request encode"),
        )
        .await
        .expect("safe response");
    let response = Message::from_vec(&response).expect("Hickory response");
    assert_eq!(response.id, 0x1234);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(192, 0, 2, 44))))
    );

    for (id, name, record_type, expected) in [
        (
            0x1235,
            "v6.example.",
            RecordType::AAAA,
            RData::AAAA(AAAA("2001:db8::44".parse().expect("AAAA expected"))),
        ),
        (
            0x1236,
            "alias.example.",
            RecordType::A,
            RData::CNAME(CNAME(
                Name::from_ascii("selected.example.").expect("CNAME expected"),
            )),
        ),
    ] {
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii(name).expect("typed positive name"),
            record_type,
        ));
        let response = proxy
            .answer(
                ProxyIngress::Listener(0),
                ProxyTransport::Udp,
                &request.to_vec().expect("typed positive request"),
            )
            .await
            .expect("safe positive response");
        let response = Message::from_vec(&response).expect("typed positive response");
        assert_eq!(response.metadata.id, id);
        assert_eq!(
            response.answers.first().map(|record| &record.data),
            Some(&expected)
        );
    }

    let mut request = Message::new(0x4321, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("missing.example.").expect("missing query name"),
        RecordType::A,
    ));
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("negative request encode"),
        )
        .await
        .expect("safe negative response");
    let response = Message::from_vec(&response).expect("Hickory negative response");
    assert_eq!(response.id, 0x4321);
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(matches!(
        response.authorities.as_slice(),
        [Record {
            data: RData::SOA(_),
            ..
        }]
    ));
    assert_eq!(
        response.additionals.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 53))))
    );
    assert_eq!(response.edns.as_ref().map(Edns::max_payload), Some(1232));

    let mut request = Message::new(0x4322, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("nodata.example.").expect("NODATA query name"),
        RecordType::AAAA,
    ));
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("NODATA request encode"),
        )
        .await
        .expect("safe NODATA response");
    let response = Message::from_vec(&response).expect("typed NODATA response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());

    let mut request = Message::new(0x4323, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("deep.suffix.example.").expect("ordinary query name"),
        RecordType::AAAA,
    ));
    let response = proxy
        .answer(
            ProxyIngress::Ordinary(0),
            ProxyTransport::Tcp,
            &request.to_vec().expect("ordinary request encode"),
        )
        .await
        .expect("ordinary safe response");
    assert_eq!(
        Message::from_vec(&response)
            .expect("ordinary typed response")
            .metadata
            .response_code,
        ResponseCode::ServFail
    );

    upstream_task.await.expect("upstream task");
    drop(proxy);
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
    assert!(
        UdpSocket::bind(SocketAddr::new(
            upstream_address.ip(),
            upstream_address.port()
        ))
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn udp_proxy_drops_malformed_and_rejects_shape_without_upstream_work() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("unused upstream bind");
    let server = DnsUpstreamSpec {
        transport: DnsUpstreamTransport::Udp,
        target: TargetAddr::ip(upstream.local_addr().expect("unused upstream address"))
            .expect("non-zero upstream target"),
        resolved_targets: Box::new([]),
        detour: None,
    };
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(100),
        NonZeroU16::new(1).expect("one query"),
    )
    .expect("shape resolver");
    owner.ready().await.expect("shape resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = Arc::new(final_proxy(
        Arc::clone(&resolver),
        DnsStrategy::PreferIpv4,
        1,
        0,
    ));
    let listen = reserve_paired_addresses(1)[0];
    let listeners = DnsProxyListeners::bind(
        vec![listen],
        8,
        NonZeroU16::new(1).expect("one connection"),
        Duration::from_millis(50),
        proxy,
    )
    .await
    .expect("shape listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let listener_task = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("shape client");
    client
        .send_to(&[0_u8], listen)
        .await
        .expect("malformed send");
    let mut wire = [0_u8; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut wire))
            .await
            .is_err(),
        "malformed query produced a response"
    );

    let mut zero = Message::new(0x5101, MessageType::Query, OpCode::Query);
    let mut multiple = Message::new(0x5102, MessageType::Query, OpCode::Query);
    multiple
        .add_query(Query::query(
            Name::from_ascii("one.shape.example.").expect("first shape name"),
            RecordType::A,
        ))
        .add_query(Query::query(
            Name::from_ascii("two.shape.example.").expect("second shape name"),
            RecordType::A,
        ));
    let mut response_message = Message::new(0x5103, MessageType::Response, OpCode::Query);
    response_message.add_query(Query::query(
        Name::from_ascii("response.shape.example.").expect("response shape name"),
        RecordType::A,
    ));
    let mut update = Message::new(0x5104, MessageType::Query, OpCode::Update);
    update.add_query(Query::query(
        Name::from_ascii("update.shape.example.").expect("update shape name"),
        RecordType::A,
    ));
    let mut non_in = Message::new(0x5105, MessageType::Query, OpCode::Query);
    let mut question = Query::query(
        Name::from_ascii("class.shape.example.").expect("class shape name"),
        RecordType::A,
    );
    question.set_query_class(DNSClass::CH);
    non_in.add_query(question);
    for (request, expected) in [
        (&mut zero, ResponseCode::FormErr),
        (&mut multiple, ResponseCode::FormErr),
        (&mut response_message, ResponseCode::NotImp),
        (&mut update, ResponseCode::NotImp),
        (&mut non_in, ResponseCode::Refused),
    ] {
        let request = request.to_vec().expect("shape request");
        client.send_to(&request, listen).await.expect("shape send");
        let (length, _) =
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut wire))
                .await
                .expect("shape response timeout")
                .expect("shape response");
        assert_eq!(
            Message::from_vec(&wire[..length])
                .expect("typed shape response")
                .metadata
                .response_code,
            expected
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), upstream.recv_from(&mut wire))
            .await
            .is_err(),
        "invalid request reached upstream"
    );
    stop.send(()).expect("stop shape listeners");
    listener_task
        .await
        .expect("shape listener join")
        .expect("shape listener shutdown");
    drop((client, upstream, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("shape resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn proxy_busy_timeout_and_udp_truncation_are_typed() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("timeout upstream");
    let server = DnsUpstreamSpec {
        transport: DnsUpstreamTransport::Udp,
        target: TargetAddr::ip(upstream.local_addr().expect("timeout upstream address"))
            .expect("non-zero upstream target"),
        resolved_targets: Box::new([]),
        detour: None,
    };
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![server],
        Duration::from_millis(50),
        NonZeroU16::new(1).expect("one query"),
    )
    .expect("timeout resolver");
    owner.ready().await.expect("timeout resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = Arc::new(final_proxy(
        Arc::clone(&resolver),
        DnsStrategy::PreferIpv4,
        1,
        0,
    ));
    let query = |id| {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("timeout.proxy.example.").expect("timeout name"),
            RecordType::A,
        ));
        message.to_vec().expect("timeout query")
    };
    let first_proxy = Arc::clone(&proxy);
    let first = tokio::spawn(async move {
        first_proxy
            .answer(
                ProxyIngress::Listener(0),
                ProxyTransport::Udp,
                &query(0x5201),
            )
            .await
            .expect("timeout response")
    });
    let mut upstream_wire = [0_u8; 4096];
    let _ = tokio::time::timeout(
        Duration::from_millis(100),
        upstream.recv_from(&mut upstream_wire),
    )
    .await
    .expect("first upstream timeout")
    .expect("first upstream query");
    let busy = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &query(0x5202),
        )
        .await
        .expect("busy response");
    assert_eq!(
        Message::from_vec(&busy)
            .expect("typed busy response")
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            upstream.recv_from(&mut upstream_wire)
        )
        .await
        .is_err(),
        "busy request reached upstream"
    );
    let timeout = Message::from_vec(&first.await.expect("timeout query join"))
        .expect("typed timeout response");
    assert_eq!(timeout.metadata.response_code, ResponseCode::ServFail);
    drop((proxy, resolver, upstream));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("timeout resolver shutdown")
            .runtime_tasks,
        0
    );

    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("large upstream");
    let address = upstream.local_addr().expect("large upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("large connection");
        let length = stream.read_u16().await.expect("large query length");
        let mut wire = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut wire).await.expect("large query");
        let request = Message::from_vec(&wire).expect("typed large query");
        let question = request.queries.first().expect("large question").clone();
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.add_query(question.clone());
        for octet in 1..=30 {
            response.add_answer(Record::from_rdata(
                Name::from_ascii(format!("answer-{octet}.large.proxy.example."))
                    .expect("large answer name"),
                30,
                RData::A(A(Ipv4Addr::new(198, 51, 100, octet))),
            ));
        }
        let response = response.to_vec().expect("large response");
        stream
            .write_u16(u16::try_from(response.len()).expect("bounded large response"))
            .await
            .expect("large response length");
        stream
            .write_all(&response)
            .await
            .expect("large response send");
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Tcp,
            target: TargetAddr::ip(address).expect("non-zero upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("one large query"),
    )
    .expect("large resolver");
    owner.ready().await.expect("large resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv4, 1, 0);
    let mut request = Message::new(0x5203, MessageType::Query, OpCode::Query);
    request
        .add_query(Query::query(
            Name::from_ascii("large.proxy.example.").expect("large name"),
            RecordType::A,
        ))
        .set_edns({
            let mut edns = Edns::new();
            edns.set_max_payload(512);
            edns
        });
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("large request"),
        )
        .await
        .expect("truncated response");
    assert!(response.len() <= 512);
    let response = Message::from_vec(&response).expect("typed truncated response");
    assert!(
        response.metadata.truncation,
        "response was not truncated: {response:?}"
    );
    assert_eq!(response.metadata.id, 0x5203);
    upstream_task.await.expect("large upstream join");
    drop((proxy, resolver));
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("large resolver shutdown")
            .runtime_tasks,
        0
    );
}

#[tokio::test]
async fn udp_tc_retries_tcp_on_the_same_selected_server() {
    let _network = TEST_NETWORK.lock().await;
    let address = reserve_paired_addresses(1)[0];
    let udp = UdpSocket::bind(address).await.expect("TC UDP bind");
    let tcp = TcpListener::bind(address).await.expect("TC TCP bind");
    let udp_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        let (length, peer) = udp.recv_from(&mut wire).await.expect("TC UDP query");
        let request = Message::from_vec(&wire[..length]).expect("typed TC UDP query");
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.truncation = true;
        response.add_queries(request.queries);
        udp.send_to(&response.to_vec().expect("TC UDP response"), peer)
            .await
            .expect("TC UDP send");
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.expect("TC TCP accept");
        let length = stream.read_u16().await.expect("TC TCP length");
        let mut wire = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut wire).await.expect("TC TCP query");
        let request = Message::from_vec(&wire).expect("typed TC TCP query");
        let query = request.queries.first().expect("TC question").clone();
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response
            .add_query(query.clone())
            .add_answer(Record::from_rdata(
                query.name().clone(),
                30,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 53))),
            ));
        let response = response.to_vec().expect("TC TCP response");
        stream
            .write_u16(u16::try_from(response.len()).expect("bounded TC response"))
            .await
            .expect("TC response length");
        stream.write_all(&response).await.expect("TC response");
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(address).expect("non-zero upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("one TC query"),
    )
    .expect("TC resolver");
    owner.ready().await.expect("TC resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = final_proxy(Arc::clone(&resolver), DnsStrategy::PreferIpv4, 1, 0);
    let mut request = Message::new(0x5301, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("tc.proxy.example.").expect("TC proxy name"),
        RecordType::A,
    ));
    let response = proxy
        .answer(
            ProxyIngress::Listener(0),
            ProxyTransport::Udp,
            &request.to_vec().expect("TC proxy request"),
        )
        .await
        .expect("TC proxy response");
    let response = Message::from_vec(&response).expect("typed TC proxy response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 53))))
    );
    udp_task.await.expect("TC UDP join");
    tcp_task.await.expect("TC TCP join");
    drop((proxy, resolver));
    assert_eq!(
        owner.shutdown().await.expect("TC shutdown").runtime_tasks,
        0
    );
}

#[tokio::test]
async fn tcp_listener_handles_multi_query_frames_bounds_and_clean_eof() {
    let _network = TEST_NETWORK.lock().await;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream bind");
    let upstream_address = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for answer in [8, 9] {
            let (length, peer) = upstream.recv_from(&mut wire).await.expect("query");
            let request = Message::from_vec(&wire[..length]).expect("Hickory request");
            let query = request.queries[0].clone();
            let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
            response
                .add_query(query.clone())
                .add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::A(A(Ipv4Addr::new(198, 51, 100, answer))),
                ));
            upstream
                .send_to(&response.to_vec().expect("response encode"), peer)
                .await
                .expect("response send");
        }
    });
    let (resolver, mut owner) = TaggedResolver::direct(
        vec![DnsUpstreamSpec {
            transport: DnsUpstreamTransport::Udp,
            target: TargetAddr::ip(upstream_address).expect("non-zero upstream target"),
            resolved_targets: Box::new([]),
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = Arc::new(final_proxy(
        Arc::clone(&resolver),
        DnsStrategy::PreferIpv4,
        2,
        0,
    ));
    let listen: [SocketAddr; 2] = reserve_paired_addresses(2)
        .try_into()
        .expect("two paired listener addresses");
    let listeners = DnsProxyListeners::bind(
        listen.to_vec(),
        16,
        NonZeroU16::new(1).expect("nonzero connections"),
        Duration::from_millis(50),
        proxy,
    )
    .await
    .expect("paired listeners");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(listeners.run(async move {
        let _ = stopped.await;
    }));
    let mut client = TcpStream::connect(listen[0]).await.expect("TCP connect");
    for id in [0x2345, 0x2346] {
        let mut request = Message::new(id, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("tcp.example.").expect("query name"),
            RecordType::A,
        ));
        let request = request.to_vec().expect("request encode");
        client
            .write_u16(request.len() as u16)
            .await
            .expect("request length");
        client.write_all(&request).await.expect("request");
        let length = client.read_u16().await.expect("response length");
        let mut response = vec![0; usize::from(length)];
        client.read_exact(&mut response).await.expect("response");
        assert_eq!(
            Message::from_vec(&response).expect("response decode").id,
            id
        );
    }

    let mut contender = TcpStream::connect(listen[1])
        .await
        .expect("aggregate contender");
    let mut one = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), contender.read(&mut one))
            .await
            .expect("aggregate close timeout")
            .expect("aggregate close"),
        0
    );
    client.shutdown().await.expect("clean client EOF");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), client.read(&mut one))
            .await
            .expect("clean EOF timeout")
            .expect("clean EOF"),
        0
    );

    let mut zero = TcpStream::connect(listen[1])
        .await
        .expect("zero-frame connect");
    zero.write_u16(0).await.expect("zero frame");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(150), zero.read(&mut one))
            .await
            .expect("zero-frame close timeout")
            .expect("zero-frame close"),
        0
    );

    let mut partial = TcpStream::connect(listen[1])
        .await
        .expect("partial-frame connect");
    partial.write_u16(10).await.expect("partial length");
    partial.write_all(&[1, 2]).await.expect("partial body");
    partial.shutdown().await.expect("partial EOF");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), partial.read(&mut one))
            .await
            .expect("partial close timeout")
            .expect("partial close"),
        0
    );

    let mut maximum = TcpStream::connect(listen[1])
        .await
        .expect("maximum-frame connect");
    maximum.write_u16(u16::MAX).await.expect("maximum length");
    maximum
        .write_all(&vec![0_u8; usize::from(u16::MAX)])
        .await
        .expect("maximum body");
    let response_len = tokio::time::timeout(Duration::from_millis(150), maximum.read_u16())
        .await
        .expect("maximum response timeout")
        .expect("maximum response length");
    let mut response = vec![0_u8; usize::from(response_len)];
    maximum
        .read_exact(&mut response)
        .await
        .expect("maximum response");
    assert_eq!(
        Message::from_vec(&response)
            .expect("typed maximum response")
            .metadata
            .response_code,
        ResponseCode::FormErr
    );
    maximum.shutdown().await.expect("maximum EOF");

    let mut idle = TcpStream::connect(listen[1]).await.expect("idle connect");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(150), idle.read(&mut one))
            .await
            .expect("idle close timeout")
            .expect("idle close"),
        0
    );

    stop.send(()).expect("stop listeners");
    assert!(running.await.expect("listener task").is_ok());
    upstream_task.await.expect("upstream task");
    drop((client, contender, zero, partial, maximum, idle));
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("resolver shutdown")
            .runtime_tasks,
        0
    );
}
