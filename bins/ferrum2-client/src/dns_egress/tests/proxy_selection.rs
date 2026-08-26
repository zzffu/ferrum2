use super::*;

#[tokio::test]
async fn dns_proxy_selector_snapshot_and_no_fallback() {
    let socks = reserve_address();
    let dns = reserve_address();
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("TCP DNS upstream");
    let upstream_address = upstream.local_addr().expect("TCP DNS upstream address");
    let detours = [
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("outer DNS detour"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("inner DNS detour"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("later DNS detour"),
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("selected dead detour"),
    ];
    let detour_addresses: [SocketAddrV4; 4] =
        detours.each_ref().map(
            |listener| match listener.local_addr().expect("detour address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 DNS detour"),
            },
        );
    let [outer_server, inner_server, later_server, dead_server] = detour_addresses;
    let [outer, inner, later, dead] = detours;
    let path = write_client_test_source(&format!(
        r#"schema_version = 2
[runtime]
shutdown_grace_ms = 0
[[inbounds]]
tag = "entry"
listen = "{socks}"
outbound = "dead"
[[outbounds]]
tag = "outer"
type = "shadowsocks"
server = "{outer_server}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "inner"
type = "shadowsocks"
server = "{inner_server}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "later"
type = "shadowsocks"
server = "{later_server}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[outbounds]]
tag = "dead"
type = "shadowsocks"
server = "{dead_server}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[[chains]]
tag = "chain"
hops = ["outer", "inner"]
[[selectors]]
tag = "dns-manual"
outbounds = ["chain", "later", "dead"]
default = "chain"
[dns]
timeout_ms = 150
max_inflight = 1
[[dns.inbounds]]
tag = "dns-in"
listen = "{dns}"
[[dns.servers]]
tag = "upstream"
transport = "tcp"
address = "{upstream_address}"
detour = "dns-manual"
[dns.route]
final = "upstream"
"#,
    ));
    let prepared = prepare_client(&path).expect("prepare DNS selector config");
    let config = finish_client_v2(prepared, ClientV2Resources::default())
        .expect("finish DNS selector config");
    let selector = config.selector_control();
    let upstream_task = tokio::spawn(async move {
        for answer in [
            Ipv4Addr::new(203, 0, 113, 50),
            Ipv4Addr::new(203, 0, 113, 51),
        ] {
            let (mut stream, _) = upstream.accept().await.expect("TCP DNS connection");
            let length = stream.read_u16().await.expect("TCP DNS request length");
            let mut wire = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut wire).await.expect("TCP DNS request");
            let request = Message::from_vec(&wire).expect("typed TCP DNS request");
            let question = request
                .queries
                .first()
                .expect("one TCP DNS question")
                .clone();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response
                .add_query(question.clone())
                .add_answer(Record::from_rdata(
                    question.name().clone(),
                    30,
                    RData::A(A(answer)),
                ));
            let response = response.to_vec().expect("typed TCP DNS response");
            stream
                .write_u16(u16::try_from(response.len()).expect("bounded TCP DNS response"))
                .await
                .expect("TCP DNS response length");
            stream.write_all(&response).await.expect("TCP DNS response");
        }
    });
    let outer_target = SocketAddr::V4(detour_addresses[1]);
    let (opened, opened_inner) = tokio::sync::oneshot::channel();
    let (release_inner, release) = tokio::sync::oneshot::channel();
    let outer_task = tokio::spawn(dns_tcp_detour_once(outer, outer_target, None, None));
    let inner_task = tokio::spawn(dns_tcp_detour_once(
        inner,
        upstream_address,
        Some(opened),
        Some(release),
    ));
    let later_task = tokio::spawn(dns_tcp_detour_once(later, upstream_address, None, None));
    let registry = OwnerRegistry::new();
    let metrics = Arc::new(Metrics::new());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(run_with_registry_and_metrics(
        config,
        registry.clone(),
        async move {
            let _ = stopped.await;
        },
        Arc::clone(&metrics),
    ));
    wait_until_bound(dns).await;
    let mut client = tokio::net::TcpStream::connect(dns)
        .await
        .expect("selector DNS client");
    let query = |id, name: &str| {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(name).expect("selector query name"),
            RecordType::A,
        ));
        query.to_vec().expect("typed selector query")
    };
    let write_query = async |client: &mut tokio::net::TcpStream, query: &[u8]| {
        client
            .write_u16(u16::try_from(query.len()).expect("bounded selector query"))
            .await
            .expect("selector query length");
        client.write_all(query).await.expect("selector query");
    };
    let read_response = async |client: &mut tokio::net::TcpStream| {
        let length = client.read_u16().await.expect("selector response length");
        let mut wire = vec![0_u8; usize::from(length)];
        client
            .read_exact(&mut wire)
            .await
            .expect("selector response");
        Message::from_vec(&wire).expect("typed selector response")
    };

    write_query(&mut client, &query(0x4401, "held.selector.example.")).await;
    tokio::time::timeout(Duration::from_secs(2), opened_inner)
        .await
        .expect("held chain open timeout")
        .expect("held chain opened");
    selector
        .switch("dns-manual", "later")
        .expect("switch later DNS member");
    release_inner.send(()).expect("release held chain");
    let first = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
        .await
        .expect("held selector response timeout");
    assert_eq!(first.metadata.id, 0x4401);
    assert_eq!(
        first.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 50))))
    );

    write_query(&mut client, &query(0x4402, "later.selector.example.")).await;
    let second = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
        .await
        .expect("later selector response timeout");
    assert_eq!(second.metadata.id, 0x4402);
    assert_eq!(
        second.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(203, 0, 113, 51))))
    );

    selector
        .switch("dns-manual", "dead")
        .expect("switch selected failure");
    write_query(&mut client, &query(0x4403, "dead.selector.example.")).await;
    let failed = tokio::time::timeout(Duration::from_secs(2), read_response(&mut client))
        .await
        .expect("selected failure response timeout");
    assert_eq!(failed.metadata.id, 0x4403);
    assert_eq!(failed.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(outer_task.await.expect("outer detour join"), 1);
    assert_eq!(inner_task.await.expect("inner detour join"), 1);
    assert_eq!(later_task.await.expect("later detour join"), 1);
    let (selected_dead, _) = tokio::time::timeout(Duration::from_secs(1), dead.accept())
        .await
        .expect("selected dead timeout")
        .expect("selected dead connection");
    drop(selected_dead);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), dead.accept())
            .await
            .is_err(),
        "selected failure retried"
    );
    upstream_task.await.expect("TCP DNS upstream join");
    let telemetry = metrics.encode_text().expect("selector metrics");
    let bootstrap_sentinel = upstream_address.to_string();
    for sentinel in [
        "held.selector.example.",
        "later.selector.example.",
        "dead.selector.example.",
        "dns-manual",
        bootstrap_sentinel.as_str(),
    ] {
        assert!(
            !telemetry.contains(sentinel),
            "DNS sentinel leaked: {sentinel}"
        );
    }
    drop(client);
    stop.send(()).expect("stop selector client");
    assert_eq!(task.await.expect("selector client join"), Ok(()));
    drop(dead);
    drop(UdpSocket::bind(dns).await.expect("selector DNS UDP rebind"));
    drop(
        TcpListener::bind(dns)
            .await
            .expect("selector DNS TCP rebind"),
    );
    for address in detour_addresses {
        drop(
            TcpListener::bind(address)
                .await
                .expect("selector detour rebind"),
        );
    }
    drop(
        TcpListener::bind(upstream_address)
            .await
            .expect("selector upstream rebind"),
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove selector config");
}

#[tokio::test]
async fn dns_proxy_first_match_direct_and_detoured_transports() {
    let socks = reserve_address();
    let shadowsocks = reserve_address();
    let dns = reserve_address();
    let upstreams = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("rule DNS upstream"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("ANY DNS upstream"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("qtype-less DNS upstream"),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("final DNS upstream"),
    ];
    let upstream_addresses = upstreams
        .each_ref()
        .map(|upstream| upstream.local_addr().expect("upstream address"));
    let (path, _) = client_test_config(socks, shadowsocks);
    let source = format!(
        "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{socks}\"\n\
             [[outbounds]]\n\
             tag = \"o0\"\n\
             type = \"shadowsocks\"\n\
             server = \"{shadowsocks}\"\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [route]\n\
             final = \"o0\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n\
             [dns]\n\
             [[dns.inbounds]]\n\
             tag = \"d0\"\n\
             listen = \"{dns}\"\n\
             [[dns.servers]]\n\
             tag = \"rule\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"any\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"untyped\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [[dns.servers]]\n\
             tag = \"final\"\n\
             transport = \"udp\"\n\
             address = \"{}\"\n\
             [dns.route]\n\
             final = \"final\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname_suffix = \"selected.example\"\n\
             qtype = \"A\"\n\
             action = \"route\"\n\
             server = \"rule\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"tcp\"\n\
             qname = \"exact.example\"\n\
             qtype = \"AAAA\"\n\
             action = \"route\"\n\
             server = \"rule\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname = \"unknown.policy.example\"\n\
             qtype = \"ANY\"\n\
             action = \"route\"\n\
             server = \"any\"\n\
             [[dns.route.rules]]\n\
             inbound = \"d0\"\n\
             network = \"udp\"\n\
             qname = \"unknown.policy.example\"\n\
             action = \"route\"\n\
             server = \"untyped\"\n",
        upstream_addresses[0], upstream_addresses[1], upstream_addresses[2], upstream_addresses[3],
    );
    std::fs::write(&path, source).expect("write v2 DNS policy config");
    let prepared = prepare_client(&path).expect("prepare v2 DNS policy config");
    let config = finish_client_v2(prepared, ClientV2Resources::default())
        .expect("materialize v2 DNS policy config");
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);
    let upstream_tasks: Vec<_> = upstreams
        .into_iter()
        .zip([
            vec![
                (
                    Some("selected.example."),
                    RecordType::A,
                    Ipv4Addr::new(192, 0, 2, 44),
                ),
                (
                    Some("exact.example."),
                    RecordType::AAAA,
                    Ipv4Addr::new(192, 0, 2, 46),
                ),
            ],
            vec![(
                Some("unknown.policy.example."),
                RecordType::ANY,
                Ipv4Addr::new(192, 0, 2, 48),
            )],
            vec![(
                Some("unknown.policy.example."),
                RecordType::Unknown(65_400),
                Ipv4Addr::new(192, 0, 2, 49),
            )],
            vec![
                (
                    Some("selected.example."),
                    RecordType::AAAA,
                    Ipv4Addr::new(192, 0, 2, 45),
                ),
                (
                    Some("unmatched.policy.example."),
                    RecordType::Unknown(65_400),
                    Ipv4Addr::new(192, 0, 2, 50),
                ),
                (None, RecordType::A, Ipv4Addr::new(192, 0, 2, 47)),
            ],
        ])
        .map(|(upstream, expectations)| {
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                for (expected_name, expected_type, answer) in expectations {
                    let (length, peer) =
                        upstream.recv_from(&mut request).await.expect("DNS request");
                    let request = Message::from_vec(&request[..length]).expect("typed DNS request");
                    assert_eq!(request.metadata.message_type, MessageType::Query);
                    assert_eq!(request.metadata.op_code, OpCode::Query);
                    let question = request.queries.first().expect("one question").clone();
                    assert_eq!(question.query_type(), expected_type);
                    if let Some(expected_name) = expected_name {
                        assert_eq!(
                            question.name(),
                            &Name::from_ascii(expected_name).expect("expected query name")
                        );
                    }
                    let mut response = Message::response(request.metadata.id, OpCode::Query);
                    response.metadata.recursion_available = true;
                    response
                        .add_query(question.clone())
                        .add_answer(Record::from_rdata(
                            question.name().clone(),
                            30,
                            RData::A(A(answer)),
                        ));
                    upstream
                        .send_to(&response.to_vec().expect("typed DNS response"), peer)
                        .await
                        .expect("DNS response");
                }
            })
        })
        .collect();
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("DNS client");
    let binary_name = Name::from_labels([
        vec![0x80; 63],
        vec![0x81; 63],
        vec![0x82; 63],
        vec![0x83; 61],
    ])
    .expect("valid maximum wire name");
    assert!(binary_name.to_ascii().len() > 255);
    wait_until_bound(dns).await;
    for (id, name, record_type, expected) in [
        (
            0x1234,
            Name::from_ascii("SeLeCtEd.ExAmPlE.").expect("absolute query name"),
            RecordType::A,
            Ipv4Addr::new(192, 0, 2, 44),
        ),
        (
            0x1235,
            Name::from_ascii("selected.example.").expect("wrong qtype name"),
            RecordType::AAAA,
            Ipv4Addr::new(192, 0, 2, 45),
        ),
        (
            0x1238,
            Name::from_ascii("unknown.policy.example.").expect("unknown qtype name"),
            RecordType::Unknown(65_400),
            Ipv4Addr::new(192, 0, 2, 49),
        ),
        (
            0x1239,
            Name::from_ascii("unmatched.policy.example.").expect("unknown final name"),
            RecordType::Unknown(65_400),
            Ipv4Addr::new(192, 0, 2, 50),
        ),
        (
            0x123a,
            Name::from_ascii("unknown.policy.example.").expect("ANY policy name"),
            RecordType::ANY,
            Ipv4Addr::new(192, 0, 2, 48),
        ),
    ] {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name, record_type));
        let query = query.to_vec().expect("typed query");
        let mut response = [0_u8; 4096];
        client.send_to(&query, dns).await.expect("proxy query");
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .expect("DNS proxy response timeout")
                .expect("DNS proxy response");
        let response = Message::from_vec(&response[..length]).expect("typed proxy response");
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert_eq!(response.metadata.op_code, OpCode::Query);
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "query {id:#06x}",
        );
        assert_eq!(response.queries.len(), 1);
        assert_eq!(
            response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(expected)))
        );
    }
    for (id, name, record_type, expected) in [
        (
            0x1236,
            Name::from_ascii("EXACT.EXAMPLE.").expect("exact TCP query name"),
            RecordType::AAAA,
            Ipv4Addr::new(192, 0, 2, 46),
        ),
        (
            0x1237,
            binary_name,
            RecordType::A,
            Ipv4Addr::new(192, 0, 2, 47),
        ),
    ] {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(name, record_type));
        let query = query.to_vec().expect("typed TCP query");
        let mut client = tokio::net::TcpStream::connect(dns)
            .await
            .expect("DNS TCP client");
        client
            .write_u16(u16::try_from(query.len()).expect("bounded TCP query"))
            .await
            .expect("DNS TCP query length");
        client.write_all(&query).await.expect("DNS TCP query");
        let length = client.read_u16().await.expect("DNS TCP response length");
        let mut response = vec![0_u8; usize::from(length)];
        client
            .read_exact(&mut response)
            .await
            .expect("DNS TCP response");
        let response = Message::from_vec(&response).expect("typed TCP proxy response");
        assert_eq!(response.metadata.id, id);
        assert_eq!(
            response.answers.first().map(|record| &record.data),
            Some(&RData::A(A(expected)))
        );
    }
    for upstream_task in upstream_tasks {
        upstream_task.await.expect("upstream task");
    }
    stop.send(()).expect("stop client");
    assert_eq!(task.await.expect("client task"), Ok(()));
    drop(client);
    drop(UdpSocket::bind(dns).await.expect("DNS UDP rebind"));
    drop(TcpListener::bind(dns).await.expect("DNS TCP rebind"));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove config");
}
