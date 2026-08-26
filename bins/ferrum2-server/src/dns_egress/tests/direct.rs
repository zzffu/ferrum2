use super::*;

pub(super) async fn answer_a(socket: &UdpSocket, expected: &str, address: Ipv4Addr) {
    let mut wire = [0_u8; 4096];
    let (length, peer) = recv_udp(socket, &mut wire).await;
    let request = Message::from_vec(&wire[..length]).expect("DNS query decode");
    let [query] = request.queries.as_slice() else {
        panic!("one DNS query");
    };
    assert_eq!(query.name().to_ascii(), expected);
    assert_eq!(query.query_type(), RecordType::A);
    let mut response = Message::response(request.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    response.add_answer(Record::from_rdata(
        query.name().clone(),
        60,
        RData::A(A(address)),
    ));
    socket
        .send_to(&response.to_vec().expect("DNS response encode"), peer)
        .await
        .expect("DNS response send");
}

fn a_response(request: &Message, addresses: &[Ipv4Addr]) -> Vec<u8> {
    let [query] = request.queries.as_slice() else {
        panic!("one DNS query");
    };
    let mut response = Message::response(request.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    for &address in addresses {
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A(address)),
        ));
    }
    response.to_vec().expect("DNS response encode")
}

async fn answer_udp_queries(
    socket: UdpSocket,
    expected: &'static str,
    answer_sets: Vec<Vec<Ipv4Addr>>,
) {
    let mut wire = [0_u8; 4096];
    for addresses in answer_sets {
        let (length, peer) = recv_udp(&socket, &mut wire).await;
        let request = Message::from_vec(&wire[..length]).expect("UDP DNS query decode");
        assert_eq!(request.queries[0].name().to_ascii(), expected);
        assert_eq!(request.queries[0].query_type(), RecordType::A);
        socket
            .send_to(&a_response(&request, &addresses), peer)
            .await
            .expect("UDP DNS response");
    }
}

async fn answer_tcp_query(listener: TcpListener, expected: &'static str, addresses: Vec<Ipv4Addr>) {
    let (mut stream, _) = listener.accept().await.expect("TCP DNS accept");
    let length = stream.read_u16().await.expect("TCP DNS length");
    let mut wire = vec![0_u8; usize::from(length)];
    stream.read_exact(&mut wire).await.expect("TCP DNS query");
    let request = Message::from_vec(&wire).expect("TCP DNS query decode");
    assert_eq!(request.queries[0].name().to_ascii(), expected);
    assert_eq!(request.queries[0].query_type(), RecordType::A);
    let response = a_response(&request, &addresses);
    stream
        .write_u16(u16::try_from(response.len()).expect("bounded DNS response"))
        .await
        .expect("TCP DNS response length");
    stream.write_all(&response).await.expect("TCP DNS response");
}

async fn paired_upstream() -> (SocketAddr, UdpSocket, TcpListener) {
    loop {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("paired TCP bind");
        let address = tcp.local_addr().expect("paired address");
        if let Ok(udp) = UdpSocket::bind(address).await {
            return (address, udp, tcp);
        }
    }
}

fn upstream_spec(
    target: TargetAddr,
    transport: DnsUpstreamTransport,
    detoured: bool,
) -> DnsUpstreamSpec {
    DnsUpstreamSpec {
        transport,
        target,
        resolved_targets: Box::new([]),
        detour: detoured.then(|| EgressPlanHandle::direct(0)),
    }
}

#[tokio::test]
async fn direct_exact_server_resolves_domain_tcp_and_udp_without_policy_fallback() {
    let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bootstrap DNS bind");
    let bootstrap_address = bootstrap.local_addr().expect("bootstrap DNS address");
    let bootstrap_task = tokio::spawn(answer_udp_queries(
        bootstrap,
        "exact-upstream.test.",
        vec![
            vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)],
            vec![Ipv4Addr::LOCALHOST],
        ],
    ));
    let (upstream_address, udp, tcp) = paired_upstream().await;
    let udp_task = tokio::spawn(answer_udp_queries(
        udp,
        "payload.test.",
        vec![vec![Ipv4Addr::new(192, 0, 2, 81)]],
    ));
    let tcp_task = tokio::spawn(answer_tcp_query(
        tcp,
        "payload.test.",
        vec![Ipv4Addr::new(192, 0, 2, 82)],
    ));

    let tagged = Arc::new(OnceLock::new());
    let direct = ServerDnsResolver::for_direct(
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: ferrum2_config::DnsStrategy::Ipv4Only,
        },
        Arc::clone(&tagged),
    );
    let logical = TargetAddr::domain("exact-upstream.test", upstream_address.port())
        .expect("logical upstream");
    let egress = Arc::new(ServerDnsEgress::test(1).with_outbound_resolvers(vec![direct]));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![
            upstream_spec(
                TargetAddr::ip(bootstrap_address).expect("numeric bootstrap target"),
                DnsUpstreamTransport::Udp,
                false,
            ),
            upstream_spec(logical.clone(), DnsUpstreamTransport::Tcp, true),
            upstream_spec(logical, DnsUpstreamTransport::Udp, true),
        ],
        Duration::from_secs(1),
        std::num::NonZeroU16::new(4).expect("nested query admission"),
        egress,
    )
    .expect("domain upstream resolver");
    owner.ready().await.expect("domain upstream ready");
    let resolver = Arc::new(resolver);
    tagged
        .set(Arc::downgrade(&resolver))
        .map_err(|_| ())
        .expect("install shared exact resolver");

    let tcp_lookup = resolver
        .lookup(
            1,
            "payload.test.".parse().expect("TCP payload query name"),
            RecordType::A,
        )
        .await
        .expect("exact-server TCP lookup");
    assert!(
        tcp_lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 82))))
    );
    let udp_lookup = resolver
        .lookup(
            2,
            "payload.test.".parse().expect("UDP payload query name"),
            RecordType::A,
        )
        .await
        .expect("exact-server UDP lookup");
    assert!(
        udp_lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 81))))
    );

    bootstrap_task.await.expect("bootstrap DNS join");
    tcp_task.await.expect("TCP upstream join");
    udp_task.await.expect("UDP upstream join");
    drop(resolver);
    owner.shutdown().await.expect("domain upstream shutdown");
    drop(tagged);
}

#[tokio::test]
async fn direct_system_resolver_connects_domain_tcp() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("system target bind");
    let address = listener.local_addr().expect("system target address");
    let upstream = tokio::spawn(answer_tcp_query(
        listener,
        "system-payload.test.",
        vec![Ipv4Addr::new(192, 0, 2, 83)],
    ));
    let unavailable = ServerDnsResolver::for_direct(
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: ferrum2_config::DnsStrategy::Ipv4Only,
        },
        Arc::new(OnceLock::new()),
    );
    let system =
        ServerDnsResolver::for_direct(DirectDomainResolver::System, Arc::new(OnceLock::new()));
    let egress =
        Arc::new(ServerDnsEgress::test(2).with_outbound_resolvers(vec![unavailable, system]));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![DnsUpstreamSpec {
            target: TargetAddr::domain("localhost", address.port()).expect("localhost target"),
            transport: DnsUpstreamTransport::Tcp,
            resolved_targets: Box::new([]),
            detour: Some(EgressPlanHandle::direct(1)),
        }],
        Duration::from_secs(1),
        std::num::NonZeroU16::new(1).expect("query admission"),
        egress,
    )
    .expect("system domain resolver");
    owner.ready().await.expect("system domain ready");

    let lookup = resolver
        .lookup(
            0,
            "system-payload.test.".parse().expect("system payload name"),
            RecordType::A,
        )
        .await
        .expect("system-resolved TCP lookup");
    assert!(
        lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 83))))
    );
    upstream.await.expect("system upstream join");
    drop(resolver);
    owner.shutdown().await.expect("system domain shutdown");
}

#[tokio::test]
async fn numeric_target_bypasses_uninitialized_exact_resolver() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("numeric target bind");
    let address = listener.local_addr().expect("numeric target address");
    let upstream = tokio::spawn(answer_tcp_query(
        listener,
        "numeric-payload.test.",
        vec![Ipv4Addr::new(192, 0, 2, 84)],
    ));
    let direct = ServerDnsResolver::for_direct(
        DirectDomainResolver::DnsServer {
            server: 0,
            strategy: ferrum2_config::DnsStrategy::Ipv4Only,
        },
        Arc::new(OnceLock::new()),
    );
    let egress = Arc::new(ServerDnsEgress::test(1).with_outbound_resolvers(vec![direct]));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![upstream_spec(
            TargetAddr::ip(address).expect("numeric target"),
            DnsUpstreamTransport::Tcp,
            true,
        )],
        Duration::from_secs(1),
        std::num::NonZeroU16::new(1).expect("query admission"),
        egress,
    )
    .expect("numeric resolver");
    owner.ready().await.expect("numeric resolver ready");

    let lookup = resolver
        .lookup(
            0,
            "numeric-payload.test."
                .parse()
                .expect("numeric payload name"),
            RecordType::A,
        )
        .await
        .expect("numeric lookup");
    assert!(
        lookup
            .answers()
            .iter()
            .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 84))))
    );
    upstream.await.expect("numeric upstream join");
    drop(resolver);
    owner.shutdown().await.expect("numeric resolver shutdown");
}

#[tokio::test]
async fn domain_target_without_plan_fails_closed_before_connect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("no-plan target bind");
    let address = listener.local_addr().expect("no-plan target address");
    let direct =
        ServerDnsResolver::for_direct(DirectDomainResolver::System, Arc::new(OnceLock::new()));
    let egress = Arc::new(ServerDnsEgress::test(1).with_outbound_resolvers(vec![direct]));
    let (resolver, mut owner) = TaggedResolver::new(
        vec![upstream_spec(
            TargetAddr::domain("localhost", address.port()).expect("no-plan domain target"),
            DnsUpstreamTransport::Tcp,
            false,
        )],
        Duration::from_millis(100),
        std::num::NonZeroU16::new(1).expect("query admission"),
        egress,
    )
    .expect("no-plan resolver");
    owner.ready().await.expect("no-plan resolver ready");

    assert!(
        resolver
            .lookup(
                0,
                "no-plan.test.".parse().expect("no-plan query name"),
                RecordType::A,
            )
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "domain target connected without a detour plan"
    );
    drop(resolver);
    owner.shutdown().await.expect("no-plan resolver shutdown");
}
