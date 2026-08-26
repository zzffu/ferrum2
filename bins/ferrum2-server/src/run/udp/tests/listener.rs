use super::*;

#[tokio::test]
async fn udp_proxy_returns_unsolicited_same_family_source_with_actual_endpoint() {
    let listen = reserve_address();
    let target = udp_loopback().await;
    let alternate = udp_loopback().await;
    let target_endpoint = target.local_addr().expect("target endpoint");
    let alternate_endpoint = alternate.local_addr().expect("alternate endpoint");
    assert_eq!(target_endpoint.ip(), alternate_endpoint.ip());
    assert_ne!(target_endpoint.port(), alternate_endpoint.port());

    let (path, config) = server_test_config(listen);
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let client_socket = udp_loopback().await;
    let client_registry = OwnerRegistry::new();
    let client_manager =
        UdpSessionManager::new(UdpRuntimeLimits::default(), client_registry.clone());
    let mut client_handle = None;
    let request = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target_endpoint).expect("target address"),
        b"authorize target IP",
    );
    client_socket
        .send_to(&request, listen)
        .await
        .expect("send proxy request");

    let mut target_wire = [0_u8; 64];
    let (length, relay_endpoint) = recv_udp(&target, &mut target_wire).await;
    assert_eq!(&target_wire[..length], b"authorize target IP");
    target
        .send_to(b"first response", relay_endpoint)
        .await
        .expect("first target response");

    let mut proxy_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    let (length, peer) = recv_udp(&client_socket, &mut proxy_wire).await;
    assert_eq!(peer, SocketAddr::V4(listen));
    let mut response_scratch = UdpPacketScratch::new();
    let first = commit_client_response_wire(
        &client,
        &client_manager,
        &mut client_handle,
        &clock,
        &proxy_wire[..length],
        &mut response_scratch,
    );
    assert_eq!(
        first.datagram().target(),
        &TargetAddr::ip(target_endpoint).expect("first response source")
    );
    assert_eq!(first.datagram().payload(), b"first response");

    alternate
        .send_to(b"same IP alternate port", relay_endpoint)
        .await
        .expect("unsolicited alternate response");
    let (length, peer) = recv_udp(&client_socket, &mut proxy_wire).await;
    assert_eq!(peer, SocketAddr::V4(listen));
    let alternate_response = commit_client_response_wire(
        &client,
        &client_manager,
        &mut client_handle,
        &clock,
        &proxy_wire[..length],
        &mut response_scratch,
    );
    assert_eq!(
        alternate_response.datagram().target(),
        &TargetAddr::ip(alternate_endpoint).expect("alternate response source"),
        "the generation capability must not bind a response to the request's target port"
    );
    assert_eq!(
        alternate_response.datagram().payload(),
        b"same IP alternate port"
    );

    stop.send(()).expect("stop UDP server");
    assert_eq!(server.await.expect("UDP server task"), Ok(()));
    client_manager.cancel_all();
    assert_eq!(client_registry.snapshot().udp_sessions, 0);
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove UDP config");
}
