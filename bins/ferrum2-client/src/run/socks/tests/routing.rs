use super::*;

#[tokio::test]
async fn client_route_reject_hijack() {
    let listen = reserve_address();
    let dns_listen = reserve_address();
    let shadowsocks_address = reserve_address();
    let shadowsocks = TcpListener::bind(shadowsocks_address)
        .await
        .expect("Shadowsocks listener");
    let shadowsocks_udp = UdpSocket::bind(shadowsocks_address)
        .await
        .expect("Shadowsocks UDP listener");
    let dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("DNS upstream");
    let dns_address = dns.local_addr().expect("DNS upstream address");
    let (path, _) = client_test_config(listen, shadowsocks_address);
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"{listen}\"\n\
         [[outbounds]]\n\
         tag = \"o0\"\n\
         type = \"shadowsocks\"\n\
         server = \"{shadowsocks_address}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [route]\n\
         final = \"o0\"\n\
         [[route.rules]]\n\
         port = 9\n\
         action = \"reject\"\n\
         [[route.rules]]\n\
         port = 53\n\
         action = \"hijack-dns\"\n\
         [dns]\n\
         [[dns.inbounds]]\n\
         tag = \"d0\"\n\
         listen = \"{dns_listen}\"\n\
         [[dns.servers]]\n\
         tag = \"upstream\"\n\
         transport = \"udp\"\n\
         address = \"{dns_address}\"\n\
         [dns.route]\n\
         final = \"upstream\"\n\
         [runtime]\n\
         shutdown_grace_ms = 0\n\
         [udp]\n\
         enabled = true\n\
         max_sessions = 1\n\
         max_buffered_bytes = 1048576\n"
    );
    std::fs::write(&path, source).expect("schema v2 client config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare client route actions");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish client route actions");
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let dns_task = tokio::spawn(async move {
        let mut wire = [0_u8; 4096];
        for answer in [
            Ipv4Addr::new(203, 0, 113, 70),
            Ipv4Addr::new(203, 0, 113, 71),
            Ipv4Addr::new(203, 0, 113, 72),
            Ipv4Addr::new(203, 0, 113, 73),
        ] {
            let (length, peer) = dns.recv_from(&mut wire).await.expect("DNS request");
            let request = Message::from_vec(&wire[..length]).expect("typed DNS request");
            let question = request.queries.first().expect("one question").clone();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response
                .add_query(question.clone())
                .add_answer(Record::from_rdata(
                    question.name().clone(),
                    30,
                    RData::A(A(answer)),
                ));
            dns.send_to(&response.to_vec().expect("DNS response"), peer)
                .await
                .expect("send DNS response");
        }
    });
    let (stop, task) = spawn_test_client(config, &registry);
    wait_until_bound(listen).await;

    let accepted = tokio::spawn(async move {
        shadowsocks
            .accept()
            .await
            .expect("route opened Shadowsocks")
            .0
    });
    let (route, reply) = socks_connect_port(listen, 80).await;
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let routed = accepted.await.expect("route accept task");
    drop((route, routed));

    let (mut rejected, reply) = socks_connect_port(listen, 9).await;
    assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut closed = [0_u8; 1];
    assert_eq!(rejected.read(&mut closed).await.expect("reject close"), 0);

    let (mut hijacked, reply) = socks_connect_port(listen, 53).await;
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    for id in [17, 18] {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("hijack.example.").expect("query name"),
            RecordType::A,
        ));
        let query = query.to_vec().expect("DNS query");
        hijacked
            .write_u16(u16::try_from(query.len()).expect("query frame"))
            .await
            .expect("DNS frame length");
        hijacked.write_all(&query).await.expect("DNS frame");
        let length = hijacked.read_u16().await.expect("response frame length");
        let mut response = vec![0_u8; usize::from(length)];
        hijacked
            .read_exact(&mut response)
            .await
            .expect("response frame");
        let response = Message::from_vec(&response).expect("typed DNS response");
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }
    drop(hijacked);

    let (hijack_control, hijack_application, hijack_relay) = udp_association(listen).await;
    let hijack_target = TargetAddr::domain("hijack.example", 53).expect("UDP hijack target");
    let mut socks_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    for id in [19, 20] {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("hijack.example.").expect("query name"),
            RecordType::A,
        ));
        let query = query.to_vec().expect("UDP DNS query");
        let length = encode_udp_datagram(&hijack_target, &query, &mut socks_wire)
            .expect("UDP hijack request");
        hijack_application
            .send_to(&socks_wire[..length], hijack_relay)
            .await
            .expect("send UDP hijack request");
        let length = hijack_application
            .recv(&mut socks_wire)
            .await
            .expect("UDP hijack response");
        let response = decode_udp_datagram(&socks_wire[..length]).expect("SOCKS DNS response");
        assert_eq!(response.to_target_addr(), hijack_target);
        assert_eq!(
            Message::from_vec(response.payload())
                .expect("typed response")
                .metadata
                .id,
            id
        );
    }
    let later = encode_udp_datagram(&hijack_target, b"not DNS", &mut socks_wire)
        .expect("later non-DNS packet");
    hijack_application
        .send_to(&socks_wire[..later], hijack_relay)
        .await
        .expect("later non-DNS packet");
    hijack_application
        .send_to(&[0, 0, 0, 9], hijack_relay)
        .await
        .expect("later malformed packet");
    tokio::task::yield_now().await;
    assert_eq!(registry.snapshot().udp_sessions, 0);
    let mut absent = [0_u8; 1];
    assert_eq!(
        shadowsocks_udp
            .try_recv(&mut absent)
            .expect_err("hijack never entered Shadowsocks")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    drop(hijack_control);

    let (mut reject_control, reject_application, reject_relay) = udp_association(listen).await;
    let reject_target =
        TargetAddr::ipv4("192.0.2.9:9".parse().expect("reject target")).expect("target");
    let length =
        encode_udp_datagram(&reject_target, b"reject", &mut socks_wire).expect("reject packet");
    reject_application
        .send_to(&socks_wire[..length], reject_relay)
        .await
        .expect("send reject packet");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), reject_control.read(&mut absent))
            .await
            .expect("reject control close")
            .expect("reject control read"),
        0
    );
    assert_eq!(
        reject_application
            .try_recv(&mut absent)
            .expect_err("reject sends no UDP response")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(
        shadowsocks_udp
            .try_recv(&mut absent)
            .expect_err("reject never entered Shadowsocks")
            .kind(),
        io::ErrorKind::WouldBlock
    );

    dns_task.await.expect("DNS task");
    stop.send(()).expect("stop client");
    assert_eq!(task.await.expect("client task"), Ok(()));
    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn routed_udp_first_valid_packet_selects_association_once() {
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let mut upstreams = Vec::new();
    for _ in 0..5 {
        upstreams.push(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream"),
        );
    }
    let servers = upstreams
        .iter()
        .map(|socket| {
            let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                unreachable!("IPv4 upstream")
            };
            address
        })
        .collect::<Vec<_>>();
    let (path, mut context) = udp_test_context_for_server(registry.clone(), servers[0]);
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"{}\"\n\
         [[outbounds]]\n\
         tag = \"o0\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [[outbounds]]\n\
         tag = \"o1\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [[outbounds]]\n\
         tag = \"o2\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [[outbounds]]\n\
         tag = \"o3\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [[outbounds]]\n\
         tag = \"o4\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [[chains]]\n\
         tag = \"selected-a\"\n\
         hops = [\"o1\", \"o2\"]\n\
         [[chains]]\n\
         tag = \"selected-b\"\n\
         hops = [\"o3\", \"o4\"]\n\
         [[selectors]]\n\
         tag = \"manual\"\n\
         outbounds = [\"selected-a\", \"selected-b\"]\n\
         default = \"selected-a\"\n\
         [route]\n\
         final = \"o0\"\n\
         [[route.rules]]\n\
         inbound = \"i0\"\n\
         network = \"udp\"\n\
         action = \"sniff\"\n\
         sniffers = \"dns\"\n\
         [[route.rules]]\n\
         inbound = \"i0\"\n\
         network = \"udp\"\n\
         domain = \"query.example\"\n\
         port = 53\n\
         action = \"route\"\n\
         outbound = \"manual\"\n\
         [udp]\n\
         enabled = true\n\
         max_sessions = 1\n\
         max_buffered_bytes = 1048576\n",
        reserve_address(),
        servers[0],
        servers[1],
        servers[2],
        servers[3],
        servers[4],
    );
    std::fs::write(&path, source).expect("schema v2 client config");
    let prepared = ferrum2_config::prepare_client(&path).expect("prepare schema v2 route");
    let config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish schema v2 route");
    let selector = config.selector_control();
    let outbounds = prepare_client_outbounds(config.outbounds).expect("schema v2 outbounds");
    Arc::get_mut(&mut Arc::get_mut(&mut context).expect("unique context").egress)
        .expect("unique egress")
        .outbounds = Arc::clone(&outbounds);
    let routing = Arc::new(ClientRouting {
        program: config.route,
        outbounds,
        selector: selector.clone(),
    });

    let (association, mut peer) = parsed_udp_association().await;
    let task = tokio::spawn(execute_test_udp_association(
        association,
        Arc::clone(&context),
        Arc::clone(&routing),
        UdpSocket::bind,
    ));
    let mut reply = [0_u8; 10];
    peer.read_exact(&mut reply)
        .await
        .expect("UDP success reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let udp = context.egress.udp.as_ref().expect("UDP context");
    assert_eq!(udp.manager.session_count(), 0);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    assert!(udp.live_ids.lock().expect("live IDs").is_empty());

    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application");
    let wrong_source = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
        .await
        .expect("wrong source");
    let target = TargetAddr::domain("query.example", 53).expect("DNS target");
    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("query.example.").expect("query name"),
        RecordType::A,
    ));
    let query = query.to_vec().expect("DNS query");
    let mut wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let valid = encode_udp_datagram(&target, &query, &mut wire).expect("valid request");

    wrong_source
        .send_to(&wire[..valid], relay)
        .await
        .expect("wrong-source request");
    wait_for_metric(
        &context.metrics,
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
    )
    .await;
    assert_eq!(udp.manager.session_count(), 0);

    application
        .send_to(&[0, 0, 0, 9], relay)
        .await
        .expect("malformed request");
    wait_for_metric(
        &context.metrics,
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 2",
    )
    .await;
    wire[2] = 1;
    application
        .send_to(&wire[..valid], relay)
        .await
        .expect("fragmented request");
    wait_for_metric(
        &context.metrics,
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 3",
    )
    .await;
    assert_eq!(udp.manager.session_count(), 0);
    assert!(udp.live_ids.lock().expect("live IDs").is_empty());

    wire[2] = 0;
    let plan_limit = composed_udp_plan_limit(&routing.outbounds, &[1, 2], false, 17);
    let one_over = encode_udp_datagram(&target, &vec![0x5a; plan_limit + 1], &mut wire)
        .expect("SOCKS-valid selected-plan maximum+1");
    let unclassified = registry.snapshot();
    application
        .send_to(&wire[..one_over], relay)
        .await
        .expect("maximum+1 classification candidate");
    wait_for_metric(
        &context.metrics,
        "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 4",
    )
    .await;
    assert_eq!(registry.snapshot(), unclassified);
    assert_eq!(udp.manager.session_count(), 0);
    assert!(udp.live_ids.lock().expect("live IDs").is_empty());
    assert!(
        !context
            .metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 1"),
        "maximum+1 changed accepted activity"
    );
    let mut absent = [0_u8; 1];
    for upstream in &upstreams {
        assert_eq!(
            upstream
                .try_recv(&mut absent)
                .expect_err("maximum+1 emitted no wire")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    selector
        .switch("manual", "selected-b")
        .expect("switch selector after rejected candidate");

    let accepted_application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("following valid source");
    let exact_payload = vec![0x6b; plan_limit];
    let exact = encode_udp_datagram(&target, &exact_payload, &mut wire)
        .expect("exact selected-plan maximum");
    accepted_application
        .send_to(&wire[..exact], relay)
        .await
        .expect("classification request");
    let protocol_server = UdpServer::new(&context.keys).expect("protocol server");
    let mut scratch = UdpPacketScratch::new();
    let clock = SystemClock::new();
    let random = SystemRandom;
    let (first_len, first_peer) =
        tokio::time::timeout(Duration::from_secs(2), upstreams[3].recv_from(&mut wire))
            .await
            .expect("selected first request timeout")
            .expect("selected first request");
    let outer = protocol_server
        .prepare_request(&clock, &wire[..first_len], &mut scratch)
        .expect("selected outer request");
    assert_eq!(
        outer.datagram().target(),
        &TargetAddr::ipv4(servers[4]).expect("selected inner target")
    );
    let inner_wire = outer.datagram().payload().to_vec();
    let (_, commit) = outer.into_parts();
    protocol_server
        .commit_request(commit, first_peer, clock.monotonic_now(), &random)
        .expect("selected outer commit");
    let inner = protocol_server
        .prepare_request(&clock, &inner_wire, &mut scratch)
        .expect("selected inner request");
    assert_eq!(inner.datagram().target(), &target);
    assert_eq!(inner.datagram().payload(), exact_payload);
    let (_, commit) = inner.into_parts();
    protocol_server
        .commit_request(commit, first_peer, clock.monotonic_now(), &random)
        .expect("selected inner commit");
    assert_eq!(udp.manager.session_count(), 1);
    assert_eq!(udp.live_ids.lock().expect("live IDs").len(), 2);

    selector
        .switch("manual", "selected-a")
        .expect("switch selector after terminal selection");

    let later_target =
        TargetAddr::ipv4("192.0.2.7:5353".parse().expect("later target")).expect("target");
    let later = encode_udp_datagram(&later_target, b"not DNS", &mut wire).expect("later request");
    accepted_application
        .send_to(&wire[..later], relay)
        .await
        .expect("later request");
    let (later_len, later_peer) =
        tokio::time::timeout(Duration::from_secs(2), upstreams[3].recv_from(&mut wire))
            .await
            .expect("selected later request timeout")
            .expect("selected later request");
    assert_eq!(later_peer, first_peer);
    let outer = protocol_server
        .prepare_request(&clock, &wire[..later_len], &mut scratch)
        .expect("selected later outer");
    assert_eq!(
        outer.datagram().target(),
        &TargetAddr::ipv4(servers[4]).expect("selected inner target")
    );
    let inner_wire = outer.datagram().payload().to_vec();
    let (_, commit) = outer.into_parts();
    protocol_server
        .commit_request(commit, later_peer, clock.monotonic_now(), &random)
        .expect("selected later outer commit");
    let inner = protocol_server
        .prepare_request(&clock, &inner_wire, &mut scratch)
        .expect("selected later inner");
    assert_eq!(inner.datagram().target(), &later_target);
    assert_eq!(inner.datagram().payload(), b"not DNS");
    let (_, commit) = inner.into_parts();
    protocol_server
        .commit_request(commit, later_peer, clock.monotonic_now(), &random)
        .expect("selected later inner commit");
    assert_eq!(udp.manager.session_count(), 1);
    assert_eq!(udp.live_ids.lock().expect("live IDs").len(), 2);
    for upstream in [&upstreams[0], &upstreams[1], &upstreams[2], &upstreams[4]] {
        assert_eq!(
            upstream
                .try_recv(&mut absent)
                .expect_err("ordinary route or switched selector was not entered")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    drop(peer);
    task.await.expect("association task");
    assert_eq!(registry.snapshot(), baseline);
    std::fs::remove_file(path).expect("remove config");
}
