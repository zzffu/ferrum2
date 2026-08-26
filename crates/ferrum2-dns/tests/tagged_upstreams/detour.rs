use super::*;

fn answer(request: &hickory_proto::op::Message) -> hickory_proto::op::Message {
    use hickory_proto::op::{Message, MessageType, OpCode};

    let query = request.queries.first().expect("one query").clone();
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_available = true;
    response
        .add_query(query.clone())
        .add_answer(Record::from_rdata(
            query.name().clone(),
            30,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 44))),
        ));
    response
}

async fn tc_fixture() -> (SocketAddr, Vec<tokio::task::JoinHandle<()>>) {
    use hickory_proto::op::Message;

    let (address, udp, tcp) = bind_paired_sockets().await;
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = udp.recv_from(&mut buffer).await.expect("TC UDP receive");
        let request = Message::from_vec(&buffer[..length]).expect("TC query decode");
        udp.send_to(
            &answer(&request).truncate().to_vec().expect("TC encode"),
            peer,
        )
        .await
        .expect("TC send");
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.expect("TC TCP accept");
        let length = stream.read_u16().await.expect("TC length");
        let mut bytes = vec![0; usize::from(length)];
        stream.read_exact(&mut bytes).await.expect("TC request");
        let response = answer(&Message::from_vec(&bytes).expect("TCP query decode"))
            .to_vec()
            .expect("TCP answer encode");
        stream
            .write_u16(response.len() as u16)
            .await
            .expect("answer length");
        stream.write_all(&response).await.expect("answer bytes");
    });
    (address, vec![udp_task, tcp_task])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_target_and_plan_survive_udp_truncation_tcp_upgrade() {
    let _network = TEST_NETWORK.lock().await;
    let (address, tasks) = tc_fixture().await;
    let logical_target = TargetAddr::domain("deferred-upstream.resolver.test", address.port())
        .expect("valid logical DNS target");
    let server = DnsUpstreamSpec {
        transport: DnsUpstreamTransport::Udp,
        target: logical_target.clone(),
        resolved_targets: Box::new([]),
        detour: Some(EgressPlanHandle::direct(0)),
    };
    let plan_ptr = server
        .detour
        .as_ref()
        .expect("configured domain detour")
        .snapshot_owned()
        .hops()
        .as_ptr() as usize;
    let egress = Arc::new(RecordingEgress::with_dial_override(address));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![server],
        Duration::from_millis(250),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start domain resolver");
    owner.ready().await.expect("domain resolver ready");

    let lookup = resolver
        .lookup(
            0,
            Name::from_ascii("tc.resolver.test.").expect("TC name"),
            RecordType::A,
        )
        .await
        .expect("domain target TC lookup");
    assert!(
        lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 44))))
    );
    assert_eq!(
        egress.calls(),
        vec![
            EgressCall {
                network: "udp",
                target: logical_target.clone(),
                plan: Some(vec![0]),
            },
            EgressCall {
                network: "tcp",
                target: logical_target,
                plan: Some(vec![0]),
            },
        ]
    );
    assert_eq!(egress.plan_ptrs(), vec![plan_ptr; 2]);

    drop(resolver);
    owner.shutdown().await.expect("domain resolver shutdown");
    for task in tasks {
        task.await.expect("domain TC fixture join");
    }
}

#[derive(Clone, Copy)]
enum UdpFault {
    WrongSource,
    WrongId,
    Malformed,
}

async fn udp_fault(fault: UdpFault) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use hickory_proto::op::Message;

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fault UDP bind");
    let address = socket.local_addr().expect("fault UDP address");
    let task = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = socket.recv_from(&mut buffer).await.expect("fault receive");
        let request = Message::from_vec(&buffer[..length]).expect("fault query decode");
        match fault {
            UdpFault::WrongSource => {
                let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("spoof socket");
                other
                    .send_to(&answer(&request).to_vec().expect("spoof encode"), peer)
                    .await
                    .expect("spoof send");
            }
            UdpFault::WrongId => {
                let mut response = answer(&request);
                response.metadata.id = response.id.wrapping_add(1);
                socket
                    .send_to(&response.to_vec().expect("wrong-ID encode"), peer)
                    .await
                    .expect("wrong-ID send");
            }
            UdpFault::Malformed => {
                socket
                    .send_to(&[0, 1, 2], peer)
                    .await
                    .expect("malformed send");
            }
        }
    });
    (address, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn address_lookup_shares_one_deadline_admission_plan_and_owner() {
    use hickory_proto::op::{Message, MessageType, OpCode};

    let _network = TEST_NETWORK.lock().await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("address fixture bind");
    let address = socket.local_addr().expect("address fixture address");
    let (observed, mut observations) = tokio::sync::mpsc::unbounded_channel();
    let (release_a, released_a) = tokio::sync::oneshot::channel();
    let fixture = tokio::spawn(async move {
        let mut buffer = [0_u8; 4096];
        let (length, peer) = socket
            .recv_from(&mut buffer)
            .await
            .expect("address A receive");
        let request = Message::from_vec(&buffer[..length]).expect("address A decode");
        assert_eq!(request.queries[0].query_type(), RecordType::A);
        observed.send(RecordType::A).expect("observe A");
        released_a.await.expect("release A NODATA");
        let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
        response.add_query(request.queries[0].clone());
        socket
            .send_to(&response.to_vec().expect("A NODATA encode"), peer)
            .await
            .expect("A NODATA send");

        let (length, _) = socket
            .recv_from(&mut buffer)
            .await
            .expect("address AAAA receive");
        let request = Message::from_vec(&buffer[..length]).expect("address AAAA decode");
        assert_eq!(request.queries[0].query_type(), RecordType::AAAA);
        observed.send(RecordType::AAAA).expect("observe AAAA");
        std::future::pending::<()>().await;
    });
    let egress = Arc::new(RecordingEgress::default());
    let server = configured_server(address, DnsUpstreamTransport::Udp, true);
    let configured_plan_ptr = server
        .detour
        .as_ref()
        .expect("configured address detour")
        .snapshot_owned()
        .hops()
        .as_ptr() as usize;
    let (resolver, mut owner) = TaggedResolver::new(
        vec![server],
        Duration::from_millis(200),
        NonZeroU16::new(1).expect("one admission"),
        egress.clone(),
    )
    .expect("start address resolver");
    owner.ready().await.expect("address resolver ready");
    let started = tokio::time::Instant::now();
    let lookup = tokio::spawn(resolver.lookup_ips(
        0,
        Name::from_ascii("deadline.resolver.test.").expect("address name"),
    ));
    assert_eq!(observations.recv().await, Some(RecordType::A));
    assert_eq!(resolver.stats().queries, 1);
    assert_eq!(
        resolver
            .lookup_ips(
                0,
                Name::from_ascii("busy.resolver.test.").expect("busy name"),
            )
            .await,
        Err(DnsError::Busy)
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    release_a.send(()).expect("release delayed A");
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(50), observations.recv())
            .await
            .expect("AAAA followed A"),
        Some(RecordType::AAAA)
    );
    assert_eq!(
        lookup.await.expect("address lookup join"),
        Err(DnsError::Timeout)
    );
    assert!(
        started.elapsed() < Duration::from_millis(280),
        "AAAA received a fresh deadline"
    );
    assert_eq!(resolver.stats(), ferrum2_dns::RuntimeStats::default());
    assert_eq!(
        egress.calls(),
        vec![
            EgressCall {
                network: "udp",
                target: numeric_target(address),
                plan: Some(vec![0]),
            },
            EgressCall {
                network: "udp",
                target: numeric_target(address),
                plan: Some(vec![0]),
            },
        ]
    );
    let plan_ptrs = egress.plan_ptrs();
    assert_eq!(plan_ptrs, vec![configured_plan_ptr; 2]);
    drop(resolver);
    assert_eq!(
        owner
            .shutdown()
            .await
            .expect("address resolver shutdown")
            .stats,
        ferrum2_dns::RuntimeStats::default()
    );
    fixture.abort();
    assert!(
        fixture
            .await
            .expect_err("fixture cancellation")
            .is_cancelled()
    );
    assert!(UdpSocket::bind(address).await.is_ok());
}

async fn half_frame() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("half-frame bind");
    let address = listener.local_addr().expect("half-frame address");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("half-frame accept");
        let length = stream.read_u16().await.expect("query length");
        let mut query = vec![0; usize::from(length)];
        stream.read_exact(&mut query).await.expect("query frame");
        stream.write_u16(32).await.expect("partial length");
        stream.write_all(&[0]).await.expect("partial byte");
    });
    (address, task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncation_and_invalid_wire_inputs_never_change_plan_or_transport() {
    let _network = TEST_NETWORK.lock().await;
    let (address, tasks) = tc_fixture().await;
    let egress = Arc::new(RecordingEgress::default());
    let server = configured_server(address, DnsUpstreamTransport::Udp, true);
    let configured_plan_ptr = server
        .detour
        .as_ref()
        .expect("configured TC detour")
        .snapshot_owned()
        .hops()
        .as_ptr() as usize;
    let (resolver, mut owner) = TaggedResolver::new(
        vec![server],
        Duration::from_millis(250),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start TC resolver");
    owner.ready().await.expect("TC resolver ready");
    let tc_result = resolver
        .lookup(
            0,
            Name::from_ascii("tc.resolver.test.").expect("TC name"),
            RecordType::A,
        )
        .await;
    assert!(
        tc_result.as_ref().is_ok_and(|lookup| lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 44))))),
        "TC result {tc_result:?}, calls {:?}",
        egress.calls()
    );
    assert_eq!(
        egress.calls(),
        vec![
            EgressCall {
                network: "udp",
                target: numeric_target(address),
                plan: Some(vec![0])
            },
            EgressCall {
                network: "tcp",
                target: numeric_target(address),
                plan: Some(vec![0])
            },
        ]
    );
    let plan_ptrs = egress.plan_ptrs();
    assert_eq!(plan_ptrs, vec![configured_plan_ptr; 2]);
    drop(resolver);
    owner.shutdown().await.expect("TC resolver shutdown");
    for task in tasks {
        task.await.expect("TC fixture join");
    }

    for fault in [
        UdpFault::WrongSource,
        UdpFault::WrongId,
        UdpFault::Malformed,
    ] {
        let (address, task) = udp_fault(fault).await;
        let egress = Arc::new(RecordingEgress::default());
        let (resolver, mut owner) = TaggedResolver::new(
            vec![configured_server(address, DnsUpstreamTransport::Udp, true)],
            Duration::from_millis(50),
            NonZeroU16::new(1).expect("nonzero admission"),
            egress.clone(),
        )
        .expect("start fault resolver");
        owner.ready().await.expect("fault resolver ready");
        assert!(
            resolver
                .lookup(
                    0,
                    Name::from_ascii("fault.resolver.test.").expect("fault name"),
                    RecordType::A,
                )
                .await
                .is_err()
        );
        assert_eq!(
            egress.calls(),
            vec![EgressCall {
                network: "udp",
                target: numeric_target(address),
                plan: Some(vec![0])
            }]
        );
        drop(resolver);
        owner.shutdown().await.expect("fault resolver shutdown");
        task.await.expect("fault fixture join");
    }

    let (address, task) = half_frame().await;
    let egress = Arc::new(RecordingEgress::default());
    let (resolver, mut owner) = TaggedResolver::new(
        vec![configured_server(address, DnsUpstreamTransport::Tcp, true)],
        Duration::from_millis(100),
        NonZeroU16::new(1).expect("nonzero admission"),
        egress.clone(),
    )
    .expect("start half-frame resolver");
    owner.ready().await.expect("half-frame resolver ready");
    assert!(
        resolver
            .lookup(
                0,
                Name::from_ascii("half.resolver.test.").expect("half-frame name"),
                RecordType::A,
            )
            .await
            .is_err()
    );
    assert_eq!(
        egress.calls(),
        vec![EgressCall {
            network: "tcp",
            target: numeric_target(address),
            plan: Some(vec![0])
        }]
    );
    drop(resolver);
    owner
        .shutdown()
        .await
        .expect("half-frame resolver shutdown");
    task.await.expect("half-frame fixture join");
}
