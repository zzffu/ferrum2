use super::*;

#[tokio::test]
async fn composed_udp_boundaries_are_real_and_sequential_for_every_method_and_target() {
    let targets = [
        (
            "IPv4",
            TargetAddr::ipv4("192.0.2.1:53".parse().expect("IPv4")).expect("target"),
            7,
        ),
        (
            "IPv6",
            TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
            19,
        ),
        (
            "domain",
            TargetAddr::domain("example.test", 53).expect("domain"),
            16,
        ),
    ];
    for method in MethodProfile::ALL {
        for (kind, target, target_len) in &targets {
            let label = format!("{method:?}/{kind}");
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream socket");
            let server_address = match upstream.local_addr().expect("upstream address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            };
            let (path, mut context) = udp_test_context_for_psk(
                registry.clone(),
                server_address,
                Some(psk_for_method(method)),
            );
            let routing = Arc::new(test_routing(server_address, psk_for_method(method)));
            Arc::get_mut(
                &mut Arc::get_mut(&mut context)
                    .expect("unique boundary context")
                    .egress,
            )
            .expect("unique boundary egress")
            .outbounds = Arc::clone(&routing.outbounds);
            let endpoint = SocksUdpEndpoint::bind(
                Ipv4Addr::LOCALHOST,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
                UdpSocket::bind,
            )
            .await
            .expect("SOCKS endpoint");
            let relay = SocketAddr::V4(endpoint.local_addr().expect("relay address"));
            let mut prepared = context
                .egress
                .prepare_udp_with(
                    ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                    UdpSocket::bind,
                )
                .await
                .expect("prepared relay");
            prepared
                .activate(&context.egress)
                .expect("relay activation");
            let handle = prepared.handle();
            let manager = context.egress.udp.as_ref().expect("UDP").manager.clone();
            let (association, peer) = parsed_udp_association().await;
            let running = start_udp_relay(
                endpoint,
                prepared,
                association.control,
                Arc::clone(&context),
                routing,
            )
            .await;
            drop(association.reply);
            let source_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("source A");
            let source_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("source B");
            let owner_deadline = Instant::now() + Duration::from_secs(2);
            while registry.snapshot().active_supervisor_children != 1 {
                assert!(
                    Instant::now() < owner_deadline,
                    "relay owner startup: {label}"
                );
                tokio::task::yield_now().await;
            }
            let request_limit = composed_udp_request_limit(method, *target_len);
            assert_eq!(
                request_limit,
                max_udp_payload_len(method, false, target, 0).expect("request limit"),
                "Shadowsocks is the request bound for {label}"
            );
            let stable_before = registry.snapshot();
            let deadline_before = manager.idle_deadline(handle).expect("pending deadline");
            let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
            let one_over = encode_udp_datagram(target, &vec![0xa5; request_limit + 1], &mut socks)
                .expect("SOCKS-valid one-over request");
            source_a
                .send_to(&socks[..one_over], relay)
                .await
                .expect("one-over enters concrete relay socket");
            wait_for_metric(
                &context.metrics,
                "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
            )
            .await;
            assert_eq!(
                registry.snapshot(),
                stable_before,
                "one-over owners: {label}"
            );
            assert_eq!(manager.session_count(), 1, "one-over session: {label}");
            assert_eq!(
                manager.idle_deadline(handle),
                Ok(deadline_before),
                "one-over activity: {label}"
            );
            let mut absent = [0; 1];
            assert_eq!(
                upstream
                    .try_recv_from(&mut absent)
                    .expect_err("one-over not emitted")
                    .kind(),
                io::ErrorKind::WouldBlock,
                "{label}"
            );

            let exact_payload = vec![0x5a; request_limit];
            let exact = encode_udp_datagram(target, &exact_payload, &mut socks)
                .expect("exact SOCKS request");
            source_a
                .send_to(&socks[..exact], relay)
                .await
                .expect("exact pinned-source request");
            let mut request_wire = [0; MAX_UDP_WIRE_LEN];
            let (request_len, upstream_client) = tokio::time::timeout(
                Duration::from_secs(2),
                upstream.recv_from(&mut request_wire),
            )
            .await
            .expect("exact upstream timeout")
            .expect("exact upstream request");
            let server = UdpServer::new(&context.keys).expect("protocol server");
            let clock = SystemClock::new();
            let random = SystemRandom;
            let mut scratch = UdpPacketScratch::new();
            let pending = server
                .prepare_request(&clock, &request_wire[..request_len], &mut scratch)
                .expect("exact authenticated request");
            assert_eq!(pending.datagram().target(), target, "target: {label}");
            assert_eq!(
                pending.datagram().payload(),
                exact_payload,
                "payload: {label}"
            );
            let (_, commit) = pending.into_parts();
            let request_activity = clock.monotonic_now();
            let accepted = server
                .commit_request(commit, upstream_client, request_activity, &random)
                .expect("exact request commit");
            let server_snapshot = server
                .session_snapshot(accepted.capability())
                .expect("server snapshot")
                .expect("server session");
            assert_eq!(
                server_snapshot.highest_packet_id(),
                Some(0),
                "packet ID: {label}"
            );
            assert_eq!(server_snapshot.peer(), upstream_client, "pin: {label}");
            assert_eq!(
                server_snapshot.last_activity(),
                request_activity,
                "server activity: {label}"
            );
            let committed_deadline = manager.idle_deadline(handle).expect("committed deadline");
            assert!(
                committed_deadline >= deadline_before,
                "request activity: {label}"
            );
            assert_eq!(
                registry.snapshot().udp_queued_datagrams,
                0,
                "request queue: {label}"
            );

            let response_limit = composed_udp_response_limit(method, *target_len);
            assert_eq!(
                response_limit,
                max_udp_payload_len(method, true, target, 0).expect("response limit"),
                "Shadowsocks is the response bound for {label}"
            );
            let response_payload = vec![0x6b; response_limit];
            let response = test_datagram(target.clone(), &response_payload);
            let mut response_wire = vec![0; MAX_UDP_WIRE_LEN];
            let encoded = server
                .encode_response(
                    accepted.capability(),
                    &clock,
                    &random,
                    &response,
                    0,
                    &mut response_wire,
                )
                .expect("exact response encode");
            let response_wire_len = encoded.wire_len();
            upstream
                .send_to(&response_wire[..response_wire_len], encoded.peer())
                .await
                .expect("exact response send");
            let mut emitted = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
            let emitted_len =
                tokio::time::timeout(Duration::from_secs(2), source_a.recv(&mut emitted))
                    .await
                    .expect("SOCKS response timeout")
                    .expect("SOCKS response");
            let decoded =
                decode_udp_datagram(&emitted[..emitted_len]).expect("SOCKS response decode");
            assert_eq!(
                decoded.to_target_addr(),
                *target,
                "response target: {label}"
            );
            assert_eq!(
                decoded.payload(),
                response_payload,
                "response payload: {label}"
            );
            assert_eq!(
                emitted_len,
                response_limit + 3 + target_len,
                "emission bound: {label}"
            );
            if *kind == "IPv6" {
                assert_eq!(emitted_len - response_limit, 22, "IPv6 SOCKS header");
            }
            assert_eq!(
                source_b
                    .try_recv(&mut absent)
                    .expect_err("source B stays unpinned")
                    .kind(),
                io::ErrorKind::WouldBlock,
                "{label}"
            );
            wait_for_metric(
                &context.metrics,
                "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"accepted\"} 1",
            )
            .await;
            let client_deadline = manager.idle_deadline(handle).expect("response activity");
            let client_state = registry.snapshot();
            assert_eq!(
                client_state.udp_queued_datagrams, 0,
                "response queue: {label}"
            );
            assert_eq!(
                client_state.udp_buffered_bytes, MAX_UDP_WIRE_LEN,
                "allocation: {label}"
            );

            let oversized = test_datagram(target.clone(), &vec![0x7c; response_limit + 1]);
            assert_eq!(
                server
                    .encode_response(
                        accepted.capability(),
                        &clock,
                        &random,
                        &oversized,
                        0,
                        &mut response_wire,
                    )
                    .expect_err("SS response max+1 rejected before emission"),
                UdpPacketError::Bounds,
                "{label}"
            );
            assert_eq!(
                registry.snapshot(),
                client_state,
                "max+1 client owners: {label}"
            );
            assert_eq!(
                manager.idle_deadline(handle),
                Ok(client_deadline),
                "max+1 client activity: {label}"
            );
            assert_eq!(
                source_a
                    .try_recv(&mut absent)
                    .expect_err("max+1 has no wire emission")
                    .kind(),
                io::ErrorKind::WouldBlock,
                "{label}"
            );

            upstream
                .send_to(&response_wire[..response_wire_len], upstream_client)
                .await
                .expect("duplicate response send");
            wait_for_metric(
                &context.metrics,
                "ferrum2_udp_replay_rejections_total{role=\"client\",direction=\"target_to_client\",reason=\"duplicate\"} 1",
            )
            .await;
            assert_eq!(
                manager.idle_deadline(handle),
                Ok(client_deadline),
                "replay activity: {label}"
            );
            assert_eq!(registry.snapshot(), client_state, "replay owners: {label}");
            assert_eq!(
                source_a
                    .try_recv(&mut absent)
                    .expect_err("replay has no emission")
                    .kind(),
                io::ErrorKind::WouldBlock,
                "{label}"
            );

            drop(peer);
            finish_udp_relay(running).await;
            assert_eq!(registry.snapshot(), baseline, "closed: {label}");
            std::fs::remove_file(path).expect("remove config");
        }
    }
}
