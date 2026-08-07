use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum2_dns::{
    DnsProxy, DnsProxyListeners, DnsUpstreamSpec, DnsUpstreamTransport, ProxyTransport,
    TaggedResolver,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

static TEST_NETWORK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        address: upstream_address,
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
    let proxy = DnsProxy::new(Arc::clone(&resolver), |inbound, transport, name| {
        assert_eq!(inbound, 3);
        assert_eq!(transport, ProxyTransport::Udp);
        assert!(name.is_fqdn(), "wire query must be absolute");
        Some(0)
    });
    let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("selected.example.").expect("query name"),
        RecordType::A,
    ));

    let response = proxy
        .answer(
            3,
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
                3,
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
            3,
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
            3,
            ProxyTransport::Udp,
            &request.to_vec().expect("NODATA request encode"),
        )
        .await
        .expect("safe NODATA response");
    let response = Message::from_vec(&response).expect("typed NODATA response");
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());

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
        address: upstream.local_addr().expect("unused upstream address"),
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
    let selections = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&selections);
    let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), move |_, _, _| {
        observed.fetch_add(1, Ordering::AcqRel);
        Some(0)
    }));
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
    assert_eq!(selections.load(Ordering::Acquire), 0);
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
        address: upstream.local_addr().expect("timeout upstream address"),
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
    let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), |_, _, _| Some(0)));
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
            .answer(0, ProxyTransport::Udp, &query(0x5201))
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
        .answer(0, ProxyTransport::Udp, &query(0x5202))
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
            address,
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("one large query"),
    )
    .expect("large resolver");
    owner.ready().await.expect("large resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = DnsProxy::new(Arc::clone(&resolver), |_, _, _| Some(0));
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
            0,
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
            address,
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("one TC query"),
    )
    .expect("TC resolver");
    owner.ready().await.expect("TC resolver ready");
    let resolver = Arc::new(resolver);
    let selections = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&selections);
    let proxy = DnsProxy::new(Arc::clone(&resolver), move |_, _, _| {
        observed.fetch_add(1, Ordering::AcqRel);
        Some(0)
    });
    let mut request = Message::new(0x5301, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("tc.proxy.example.").expect("TC proxy name"),
        RecordType::A,
    ));
    let response = proxy
        .answer(
            0,
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
    assert_eq!(selections.load(Ordering::Acquire), 1);
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
            address: upstream_address,
            detour: None,
        }],
        Duration::from_secs(1),
        NonZeroU16::new(1).expect("nonzero admission"),
    )
    .expect("resolver");
    owner.ready().await.expect("resolver ready");
    let resolver = Arc::new(resolver);
    let proxy = Arc::new(DnsProxy::new(Arc::clone(&resolver), |_, transport, _| {
        assert_eq!(transport, ProxyTransport::Tcp);
        Some(0)
    }));
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
