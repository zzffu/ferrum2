use super::*;

#[tokio::test]
async fn dns_proxy_detoured_udp_with_public_associate_off() {
    let socks = reserve_address();
    let shadowsocks_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("Shadowsocks UDP hop");
    let shadowsocks = match shadowsocks_socket
        .local_addr()
        .expect("Shadowsocks hop address")
    {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 Shadowsocks hop"),
    };
    let dns = reserve_address();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("detoured DNS upstream");
    let upstream_address = upstream.local_addr().expect("detoured upstream address");
    let upstream_target = TargetAddr::domain("deferred-dns.example.test", upstream_address.port())
        .expect("deferred DNS target");
    let path = write_client_test_source(&format!(
        r#"schema_version = 2
[runtime]
shutdown_grace_ms = 0
[udp]
enabled = false
[[inbounds]]
tag = "proxy"
listen = "{socks}"
outbound = "proxy-out"
[[outbounds]]
tag = "proxy-out"
type = "shadowsocks"
server = "{shadowsocks}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[dns]
timeout_ms = 1000
max_inflight = 1
[[dns.inbounds]]
tag = "dns-in"
listen = "{dns}"
[[dns.servers]]
tag = "upstream"
transport = "udp"
address = "deferred-dns.example.test:{}"
detour = "proxy-out"
[dns.route]
final = "upstream"
"#,
        upstream_address.port()
    ));
    let prepared = prepare_client(&path).expect("prepare detoured DNS config");
    let config = finish_client_v2(prepared, ClientV2Resources::default())
        .expect("finish detoured DNS config");
    let registry = OwnerRegistry::new();
    let (stop, task) = spawn_test_client(config, &registry);

    let upstream_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for answer in [
            Ipv4Addr::new(198, 51, 100, 41),
            Ipv4Addr::new(198, 51, 100, 42),
        ] {
            let (length, peer) = upstream
                .recv_from(&mut wire)
                .await
                .expect("plain DNS query");
            let request = Message::from_vec(&wire[..length]).expect("typed detoured request");
            let question = request.queries.first().expect("detoured question").clone();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response
                .add_query(question.clone())
                .add_answer(Record::from_rdata(
                    question.name().clone(),
                    30,
                    RData::A(A(answer)),
                ));
            upstream
                .send_to(&response.to_vec().expect("typed detoured response"), peer)
                .await
                .expect("plain DNS response");
        }
    });

    let hop_task = tokio::spawn(async move {
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk()));
        let server = UdpServer::new(&keys).expect("Shadowsocks UDP server");
        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut scratch = UdpPacketScratch::new();
        for prefix in [
            DnsUdpResponsePrefix::AuthenticatedTarget(
                TargetAddr::domain("wrong-dns.example.test", upstream_address.port())
                    .expect("wrong deferred response target"),
            ),
            DnsUdpResponsePrefix::None,
        ] {
            relay_dns_udp_hop_once(
                &shadowsocks_socket,
                &server,
                DnsUdpHopTarget {
                    logical: upstream_target.clone(),
                    upstream: upstream_address,
                },
                &clock,
                &random,
                &mut scratch,
                prefix,
            )
            .await;
        }
        assert_eq!(
            server.session_count().expect("DNS UDP session count"),
            2,
            "a wrong authenticated target must taint the SIP022 UDP session"
        );
    });

    wait_until_bound(socks).await;
    wait_until_bound(dns).await;
    let mut rejected = tokio::net::TcpStream::connect(socks)
        .await
        .expect("SOCKS public-off connect");
    rejected
        .write_all(&[5, 1, 0])
        .await
        .expect("SOCKS public-off greeting");
    let mut method = [0_u8; 2];
    rejected
        .read_exact(&mut method)
        .await
        .expect("SOCKS public-off method");
    rejected
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("SOCKS public-off UDP request");
    let mut reply = [0_u8; 10];
    assert!(
        rejected.read_exact(&mut reply).await.is_err() || reply[..2] != [5, 0],
        "internal DNS enabled public UDP"
    );
    drop(rejected);

    let query = |id, name: &str| {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(name).expect("absolute detoured name"),
            RecordType::A,
        ));
        query.to_vec().expect("typed detoured query")
    };
    let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("detoured UDP client");
    let udp_query = query(0x2201, "udp.detoured.example.");
    let mut response = [0_u8; 4096];
    udp_client
        .send_to(&udp_query, dns)
        .await
        .expect("detoured UDP query");
    let (udp_length, _) =
        tokio::time::timeout(Duration::from_secs(2), udp_client.recv_from(&mut response))
            .await
            .expect("detoured DNS response timeout")
            .expect("detoured DNS response");
    let udp_response = Message::from_vec(&response[..udp_length]).expect("detoured UDP response");
    assert_eq!(udp_response.metadata.id, 0x2201);
    assert_eq!(
        udp_response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 41))))
    );

    let mut tcp_client = tokio::net::TcpStream::connect(dns)
        .await
        .expect("detoured TCP client");
    let tcp_query = query(0x2202, "tcp.detoured.example.");
    tcp_client
        .write_u16(u16::try_from(tcp_query.len()).expect("bounded TCP query"))
        .await
        .expect("detoured TCP length");
    tcp_client
        .write_all(&tcp_query)
        .await
        .expect("detoured TCP query");
    let length = tcp_client
        .read_u16()
        .await
        .expect("detoured TCP response length");
    let mut response = vec![0_u8; usize::from(length)];
    tcp_client
        .read_exact(&mut response)
        .await
        .expect("detoured TCP response");
    let response = Message::from_vec(&response).expect("typed detoured TCP response");
    assert_eq!(response.metadata.id, 0x2202);
    assert_eq!(
        response.answers.first().map(|record| &record.data),
        Some(&RData::A(A(Ipv4Addr::new(198, 51, 100, 42))))
    );

    upstream_task.await.expect("detoured upstream task");
    hop_task.await.expect("detoured hop task");
    stop.send(()).expect("stop detoured client");
    assert_eq!(task.await.expect("detoured client task"), Ok(()));
    drop((tcp_client, udp_client));
    drop(UdpSocket::bind(dns).await.expect("detoured DNS UDP rebind"));
    drop(
        TcpListener::bind(dns)
            .await
            .expect("detoured DNS TCP rebind"),
    );
    drop(
        UdpSocket::bind(shadowsocks)
            .await
            .expect("Shadowsocks hop rebind"),
    );
    drop(
        UdpSocket::bind(upstream_address)
            .await
            .expect("DNS upstream rebind"),
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove detoured config");
}

#[tokio::test]
async fn dns_proxy_detour_saturation_shutdown_and_exact_rebind() {
    let socks = reserve_address();
    let hop = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("stalled Shadowsocks hop");
    let shadowsocks = match hop.local_addr().expect("stalled Shadowsocks hop address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 stalled Shadowsocks hop"),
    };
    let dns = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("stalled DNS upstream");
    let upstream_address = upstream.local_addr().expect("stalled upstream address");
    let (seen, mut received) = tokio::sync::oneshot::channel();
    let hop_task = tokio::spawn(async move {
        let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
        let _ = hop
            .recv_from(&mut wire)
            .await
            .expect("stalled encrypted query");
        let _ = seen.send(());
        std::future::pending::<()>().await;
    });

    let path = write_client_test_source(&format!(
        r#"schema_version = 2
[runtime]
shutdown_grace_ms = 0
[udp]
max_sessions = 1
max_buffered_bytes = 1048576
[[inbounds]]
tag = "proxy"
listen = "{socks}"
outbound = "proxy-out"
[[outbounds]]
tag = "proxy-out"
type = "shadowsocks"
server = "{shadowsocks}"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
[dns]
timeout_ms = 5000
max_inflight = 1
[[dns.inbounds]]
tag = "dns-a"
listen = "{}"
[[dns.inbounds]]
tag = "dns-b"
listen = "{}"
[[dns.servers]]
tag = "upstream"
transport = "udp"
address = "{upstream_address}"
detour = "proxy-out"
[dns.route]
final = "upstream"
"#,
        dns[0], dns[1]
    ));
    let prepared = prepare_client(&path).expect("prepare saturated DNS config");
    let config = finish_client_v2(prepared, ClientV2Resources::default())
        .expect("finish saturated DNS config");
    let registry = OwnerRegistry::new();
    let (observed, resolver) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    let task = tokio::spawn(run_with_registry_and_metrics_inner(
        config,
        registry.clone(),
        async move {
            let _ = stopped.await;
        },
        Arc::new(Metrics::new()),
        None,
        Some(observed),
        ClientRunResources::test_unmaterialized(dns_specs),
    ));
    let (context, resolver) = resolver.await.expect("observed DNS resolver");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("saturation DNS client");
    let query = |id, name: &str| {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii(name).expect("absolute saturation name"),
            RecordType::A,
        ));
        query.to_vec().expect("typed saturation query")
    };
    let first = query(0x3301, "held.detoured.example.");
    wait_until_bound(dns[0]).await;
    client
        .send_to(&first, dns[0])
        .await
        .expect("held detoured query");
    tokio::time::timeout(Duration::from_secs(1), &mut received)
        .await
        .expect("detoured hop receive timeout")
        .expect("detoured hop receive signal");
    let held = active(registry.snapshot());
    assert_eq!(held.udp_sessions, 1);
    assert_eq!(held.udp_buffered_bytes, MAX_UDP_WIRE_LEN);
    let dns_held = resolver.stats();
    assert_eq!(dns_held.queries, 1);
    assert_eq!(dns_held.udp_sockets, 1);
    assert_eq!(dns_held.bridge_tasks, 1);
    assert_eq!(dns_held.sessions, 1);
    assert_eq!(dns_held.queues, 4);
    assert_eq!(dns_held.buffers, 1);
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("shared DNS/public UDP manager")
            .manager
            .session_count(),
        1
    );
    let (public_control, public_application, public_relay) = udp_association(socks).await;
    let public_target =
        TargetAddr::ip("192.0.2.80:53".parse().expect("public target")).expect("public target");
    let mut public_request = [0_u8; 64];
    let public_length = encode_udp_datagram(&public_target, b"busy", &mut public_request)
        .expect("public UDP request");
    public_application
        .send_to(&public_request[..public_length], public_relay)
        .await
        .expect("public UDP send");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("shared DNS/public UDP manager")
            .manager
            .session_count(),
        1,
        "public UDP bypassed the saturated shared manager"
    );
    drop((public_control, public_application));
    assert_eq!(active(registry.snapshot()), held);

    let second = query(0x3302, "busy.detoured.example.");
    client
        .send_to(&second, dns[1])
        .await
        .expect("saturated DNS query");
    let mut wire = [0_u8; 4096];
    let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut wire))
        .await
        .expect("saturated response timeout")
        .expect("saturated response");
    let response = Message::from_vec(&wire[..length]).expect("typed saturated response");
    assert_eq!(response.metadata.id, 0x3302);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(active(registry.snapshot()), held);

    stop.send(()).expect("stop saturated client");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("bounded saturated shutdown")
            .expect("saturated client task"),
        Ok(())
    );
    hop_task.abort();
    assert!(
        hop_task
            .await
            .expect_err("stalled hop cancellation")
            .is_cancelled()
    );
    assert_eq!(resolver.stats(), ferrum2_dns::RuntimeStats::default());
    drop((context, resolver));
    drop((client, upstream));
    for listen in dns {
        drop(
            UdpSocket::bind(listen)
                .await
                .expect("saturated DNS UDP rebind"),
        );
        drop(
            TcpListener::bind(listen)
                .await
                .expect("saturated DNS TCP rebind"),
        );
    }
    drop(
        UdpSocket::bind(shadowsocks)
            .await
            .expect("stalled hop rebind"),
    );
    drop(
        UdpSocket::bind(upstream_address)
            .await
            .expect("stalled upstream rebind"),
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove saturation config");
}
