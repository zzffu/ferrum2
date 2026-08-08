use std::net::Ipv4Addr;
use std::time::Duration;

use ferrum2_core::{ConnectError, Connector, TargetAddr};
use ferrum2_crypto::{Aes128Psk, MethodProfile, MethodTcpSalt, SinglePskProvider};
use ferrum2_runtime::OwnerSnapshot;
use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::run::test_support::*;

#[tokio::test]
async fn route_sniff_reject_lifecycle_composition_contract_prefix_is_exact() {
    let listen = reserve_address();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("application target");
    let source = format!(
        "schema_version = 2\n\
        [[inbounds]]\n\
        tag = \"i0\"\n\
        listen = \"{listen}\"\n\
        [[outbounds]]\n\
        tag = \"direct\"\n\
        [[outbounds]]\n\
        tag = \"missing\"\n\
        [[selectors]]\n\
        tag = \"manual\"\n\
        outbounds = [\"direct\", \"missing\"]\n\
        default = \"missing\"\n\
        [route]\n\
        final = \"missing\"\n\
        [route.sniff]\n\
        timeout_ms = 300\n\
        max_bytes = 512\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        action = \"sniff\"\n\
        sniffers = [\"dns\", \"tls\", \"http\"]\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        protocol = \"dns\"\n\
        domain = \"dns.test\"\n\
        action = \"reject\"\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        protocol = \"tls\"\n\
        domain = \"tls.test\"\n\
        action = \"reject\"\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        protocol = \"http\"\n\
        domain = \"reject.test\"\n\
        action = \"reject\"\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        protocol = \"http\"\n\
        domain = \"route.test\"\n\
        action = \"route\"\n\
        outbound = \"manual\"\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        protocol = \"http\"\n\
        domain = \"route.test\"\n\
        action = \"route\"\n\
        outbound = \"missing\"\n\
        [shadowsocks]\n\
        method = \"2022-blake3-aes-128-gcm\"\n\
        psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
        [runtime]\n\
        shutdown_grace_ms = 0\n"
    );
    let metrics = reserve_address();
    let (path, mut config) = server_test_config_source("m14-selector", &source);
    let selector = config.selector_control();
    config.outbounds.truncate(1);
    config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let keys = SinglePskProvider::new(Aes128Psk::from_bytes(PSK_BYTES));
    let connector = ProtocolClientConnector {
        inner: TcpConnector::new(Duration::from_secs(5)),
    };
    let clock = SystemClock::new();
    let random = SystemRandom;
    let outbound = ClientTcpOutbound::new(
        TargetAddr::ipv4(listen).expect("server target"),
        &keys,
        &connector,
        &clock,
        &random,
    );

    let mut dns = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'd', b'n',
        b's', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let mut dns_frame = u16::try_from(dns.len())
        .expect("DNS frame length")
        .to_be_bytes()
        .to_vec();
    dns_frame.append(&mut dns);
    let tls_name = b"tls.test";
    let mut tls_extensions = vec![0x00, 0x00];
    let server_name_len = 2 + 1 + 2 + tls_name.len();
    tls_extensions.extend_from_slice(
        &u16::try_from(server_name_len)
            .expect("SNI extension length")
            .to_be_bytes(),
    );
    tls_extensions.extend_from_slice(
        &u16::try_from(server_name_len - 2)
            .expect("SNI list length")
            .to_be_bytes(),
    );
    tls_extensions.push(0);
    tls_extensions.extend_from_slice(
        &u16::try_from(tls_name.len())
            .expect("SNI name length")
            .to_be_bytes(),
    );
    tls_extensions.extend_from_slice(tls_name);
    tls_extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
    let mut client_hello = vec![0x03, 0x03];
    client_hello.extend_from_slice(&[0x5a; 32]);
    client_hello.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    client_hello.extend_from_slice(
        &u16::try_from(tls_extensions.len())
            .expect("TLS extension length")
            .to_be_bytes(),
    );
    client_hello.extend_from_slice(&tls_extensions);
    let mut tls = vec![0x16, 0x03, 0x01];
    let handshake_len = client_hello.len();
    tls.extend_from_slice(
        &u16::try_from(4 + handshake_len)
            .expect("TLS record length")
            .to_be_bytes(),
    );
    tls.push(0x01);
    tls.extend_from_slice(&[
        ((handshake_len >> 16) & 0xff) as u8,
        ((handshake_len >> 8) & 0xff) as u8,
        (handshake_len & 0xff) as u8,
    ]);
    tls.extend_from_slice(&client_hello);
    let prefixes = [
        ("DNS", dns_frame),
        ("TLS", tls),
        (
            "HTTP",
            b"GET / HTTP/1.1\r\nHost: reject.test\r\n\r\n".to_vec(),
        ),
    ];
    let timestamp = clock.unix_seconds().expect("wall clock");
    for (index, (name, prefix)) in prefixes.iter().enumerate() {
        let salt_bytes = [0x61 + u8::try_from(index).expect("small protocol table"); 16];
        let salt = MethodTcpSalt::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &salt_bytes)
            .expect("initial request salt");
        let wire =
            encode_request_first_write(&keys, &salt, timestamp, &target_address, &[0xa1], prefix)
                .unwrap_or_else(|error| panic!("{name} initial wire: {error}"));
        let mut initial = tokio::net::TcpStream::connect(listen)
            .await
            .unwrap_or_else(|error| panic!("{name} initial connect: {error}"));
        initial
            .write_all(&wire)
            .await
            .unwrap_or_else(|error| panic!("{name} initial write: {error}"));
        let _ = tokio::time::timeout(Duration::from_secs(5), initial.read(&mut [0_u8; 1]))
            .await
            .unwrap_or_else(|_| panic!("{name} initial reject close"));
        assert_pending(
            target.accept(),
            &format!("{name} initial sniff opened target"),
        )
        .await;

        let flow = outbound
            .connect_server()
            .await
            .unwrap_or_else(|error| panic!("{name} fragmented connect: {error}"))
            .write_request(&target_address)
            .await
            .unwrap_or_else(|error| panic!("{name} fragmented request: {error}"));
        let mut fragmented = TokioFramed::new(flow);
        let middle = prefix.len() / 2;
        fragmented
            .write_all(&prefix[..middle])
            .await
            .unwrap_or_else(|error| panic!("{name} first fragment: {error}"));
        fragmented
            .flush()
            .await
            .unwrap_or_else(|error| panic!("{name} first flush: {error}"));
        assert_pending(
            target.accept(),
            &format!("{name} partial sniff opened target"),
        )
        .await;
        fragmented
            .write_all(&prefix[middle..])
            .await
            .unwrap_or_else(|error| panic!("{name} second fragment: {error}"));
        fragmented
            .flush()
            .await
            .unwrap_or_else(|error| panic!("{name} second flush: {error}"));
        let _ = tokio::time::timeout(Duration::from_secs(5), fragmented.read(&mut [0_u8; 1]))
            .await
            .unwrap_or_else(|_| panic!("{name} fragmented reject close"));
        assert_pending(
            target.accept(),
            &format!("{name} fragmented sniff opened target"),
        )
        .await;
    }

    let mut route_prefix = b"GET / HTTP/1.1\r\nHost: route.test\r\n\r\n".to_vec();
    route_prefix.resize(512, b'x');
    let flow = outbound
        .connect_server()
        .await
        .expect("route connect")
        .write_request(&target_address)
        .await
        .expect("route request");
    let mut client = TokioFramed::new(flow);
    client
        .write_all(&route_prefix[..21])
        .await
        .expect("fragment one");
    client.flush().await.expect("flush fragment one");
    assert_pending(target.accept(), "partial HTTP prefix opened target").await;
    selector
        .switch("manual", "direct")
        .expect("switch while sniff waits");
    client
        .write_all(&route_prefix[21..])
        .await
        .expect("fragment two");
    client.flush().await.expect("flush fragment two");
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), target.accept())
        .await
        .expect("route target deadline")
        .expect("route target accept");
    let mut received = vec![0_u8; route_prefix.len()];
    tokio::time::timeout(Duration::from_secs(5), accepted.read_exact(&mut received))
        .await
        .expect("prefix replay deadline")
        .expect("exact sniff prefix");
    assert_eq!(received, route_prefix);
    assert_pending(accepted.read(&mut [0_u8; 1]), "prefix was duplicated").await;
    selector
        .switch("manual", "missing")
        .expect("switch after terminal selection");
    client
        .write_all(b"captured-direct")
        .await
        .expect("in-flight relay write");
    client.flush().await.expect("flush in-flight relay");
    let mut in_flight = [0_u8; 15];
    accepted
        .read_exact(&mut in_flight)
        .await
        .expect("selected flow retained direct snapshot");
    assert_eq!(&in_flight, b"captured-direct");
    drop((client, accepted));

    let flow = outbound
        .connect_server()
        .await
        .expect("reject connect")
        .write_request(&target_address)
        .await
        .expect("reject request");
    let mut rejected = TokioFramed::new(flow);
    rejected
        .write_all(b"GET / HTTP/1.1\r\nHost: reject.test\r\n\r\n")
        .await
        .expect("reject prefix");
    rejected.flush().await.expect("flush reject prefix");
    let _ = tokio::time::timeout(Duration::from_secs(5), rejected.read(&mut [0_u8; 1]))
        .await
        .expect("reject close deadline");
    assert_pending(target.accept(), "terminal reject opened target").await;

    let flow = outbound
        .connect_server()
        .await
        .expect("missing selector connect")
        .write_request(&target_address)
        .await
        .expect("missing selector request");
    let mut missing = TokioFramed::new(flow);
    missing
        .write_all(&route_prefix)
        .await
        .expect("missing selector prefix");
    missing
        .flush()
        .await
        .expect("flush missing selector prefix");
    let _ = tokio::time::timeout(Duration::from_secs(5), missing.read(&mut [0_u8; 1]))
        .await
        .expect("missing selector close deadline");
    assert_pending(target.accept(), "missing selector fell back to direct").await;

    selector
        .switch("manual", "direct")
        .expect("restore direct for terminal I/O cases");
    let closed_target = TargetAddr::ipv4(reserve_address()).expect("closed numeric target");
    let flow = outbound
        .connect_server()
        .await
        .expect("selected failure connect")
        .write_request(&closed_target)
        .await
        .expect("selected failure request");
    let mut selected_failure = TokioFramed::new(flow);
    selected_failure
        .write_all(&route_prefix)
        .await
        .expect("selected failure prefix");
    selected_failure
        .flush()
        .await
        .expect("selected failure flush");
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        selected_failure.read(&mut [0_u8; 1]),
    )
    .await
    .expect("selected failure close deadline");
    let mut metrics_client = tokio::net::TcpStream::connect(metrics)
        .await
        .expect("selected failure metrics connect");
    metrics_client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("selected failure metrics request");
    let mut encoded = String::new();
    metrics_client
        .read_to_string(&mut encoded)
        .await
        .expect("selected failure metrics response");
    assert!(encoded.contains(
        "ferrum2_tcp_failures_total{role=\"server\",stage=\"direct\",reason=\"connection_refused\"} 1"
    ));
    assert_pending(target.accept(), "selected open failure fell back").await;

    let flow = outbound
        .connect_server()
        .await
        .expect("read-error connect")
        .write_request(&target_address)
        .await
        .expect("read-error request");
    let mut read_error = TokioFramed::new(flow);
    read_error.write_all(b"G").await.expect("partial HTTP");
    read_error.flush().await.expect("flush partial HTTP");
    read_error.shutdown().await.expect("close partial HTTP");
    assert_pending(target.accept(), "sniff read error opened target").await;

    let flow = outbound
        .connect_server()
        .await
        .expect("cancel connect")
        .write_request(&target_address)
        .await
        .expect("cancel request");
    let mut cancelled = TokioFramed::new(flow);
    cancelled
        .write_all(b"G")
        .await
        .expect("cancel partial HTTP");
    cancelled.flush().await.expect("flush cancel partial HTTP");

    stop.send(()).expect("stop server");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server shutdown deadline")
            .expect("server task"),
        Ok(())
    );
    assert_pending(target.accept(), "sniff cancellation opened target").await;
    drop((read_error, cancelled));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove v2 config");
}

#[tokio::test]
async fn route_sniff_reject_tcp_timeout_continues_to_final() {
    let listen = reserve_address();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("application target");
    let route = "[route]\n\
        final = \"direct\"\n\
        [route.sniff]\n\
        timeout_ms = 10\n\
        max_bytes = 512\n\
        [[route.rules]]\n\
        network = \"tcp\"\n\
        action = \"sniff\"\n\
        sniffers = \"tls\"\n";
    let metrics = reserve_address();
    let (path, mut config) = server_v2_test_config(listen, route);
    config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let keys = SinglePskProvider::new(Aes128Psk::from_bytes(PSK_BYTES));
    let connector = ProtocolClientConnector {
        inner: TcpConnector::new(Duration::from_secs(5)),
    };
    let clock = SystemClock::new();
    let random = SystemRandom;
    let outbound = ClientTcpOutbound::new(
        TargetAddr::ipv4(listen).expect("server target"),
        &keys,
        &connector,
        &clock,
        &random,
    );
    let mut malformed_bound = vec![0_u8; 512];
    malformed_bound[..5].copy_from_slice(b"\x16\x03\x03\x00\x00");
    let mut exact_bound = vec![0_u8; 512];
    exact_bound[..5].copy_from_slice(b"\x16\x03\x03\x01\xfc");
    for (name, prefix) in [
        ("unknown", b"G".to_vec()),
        ("invalid", b"\x16\x03\x03\x00\x00".to_vec()),
        ("invalid exact bound", malformed_bound),
        ("exact bound", exact_bound),
    ] {
        let flow = outbound
            .connect_server()
            .await
            .unwrap_or_else(|error| panic!("{name} connect: {error}"))
            .write_request(&target_address)
            .await
            .unwrap_or_else(|error| panic!("{name} request: {error}"));
        let mut client = TokioFramed::new(flow);
        client
            .write_all(&prefix)
            .await
            .unwrap_or_else(|error| panic!("{name} prefix: {error}"));
        client
            .flush()
            .await
            .unwrap_or_else(|error| panic!("{name} flush: {error}"));
        let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), target.accept())
            .await
            .unwrap_or_else(|_| panic!("{name} continuation deadline"))
            .unwrap_or_else(|error| panic!("{name} continuation accept: {error}"));
        let mut received = vec![0_u8; prefix.len()];
        accepted
            .read_exact(&mut received)
            .await
            .unwrap_or_else(|error| panic!("{name} exact prefix: {error}"));
        assert_eq!(received, prefix, "{name}");
        drop((client, accepted));
    }
    let flow = outbound
        .connect_server()
        .await
        .expect("timeout connect")
        .write_request(&target_address)
        .await
        .expect("timeout request");
    let mut client = TokioFramed::new(flow);
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), target.accept())
        .await
        .expect("timeout continuation deadline")
        .expect("timeout continuation target");
    client
        .write_all(b"after-timeout")
        .await
        .expect("relay write");
    client.flush().await.expect("flush relay write");
    let mut received = [0_u8; 13];
    tokio::time::timeout(Duration::from_secs(5), accepted.read_exact(&mut received))
        .await
        .expect("post-timeout relay deadline")
        .expect("relay after timeout");
    assert_eq!(&received, b"after-timeout");

    let mut metrics_client = tokio::net::TcpStream::connect(metrics)
        .await
        .expect("metrics connect");
    metrics_client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("metrics request");
    let mut encoded = String::new();
    metrics_client
        .read_to_string(&mut encoded)
        .await
        .expect("metrics response");
    assert!(encoded.contains(
        "ferrum2_sniff_total{role=\"server\",transport=\"tcp\",stage=\"sniff\",outcome=\"limit\",protocol=\"none\"} 1"
    ));
    assert!(encoded.contains(
        "ferrum2_sniff_total{role=\"server\",transport=\"tcp\",stage=\"sniff\",outcome=\"invalid\",protocol=\"none\"} 2"
    ));

    drop((client, accepted));
    stop.send(()).expect("stop server");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server shutdown deadline")
            .expect("server task"),
        Ok(())
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove timeout config");
}

#[tokio::test]
async fn route_sniff_reject_udp_prepares_before_policy_and_rejects_before_reservation() {
    const REJECT_DNS_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'r', b'e',
        b'j', b'e', b'c', b't', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let listen = reserve_address();
    let target = udp_loopback().await;
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("application target");
    let route = "[route]\n\
        final = \"direct\"\n\
        [[route.rules]]\n\
        network = \"udp\"\n\
        action = \"sniff\"\n\
        sniffers = \"dns\"\n\
        [[route.rules]]\n\
        network = \"udp\"\n\
        protocol = \"dns\"\n\
        domain = \"reject.test\"\n\
        action = \"reject\"\n";
    let (path, config) = server_v2_test_config(listen, route);
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;
    let baseline = registry.snapshot();
    let peer = udp_loopback().await;
    let mut received = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];

    peer.send_to(b"unauthenticated", listen)
        .await
        .expect("invalid send");
    assert_pending(
        target.recv_from(&mut received),
        "unauthenticated input reached target",
    )
    .await;
    assert_eq!(registry.snapshot(), baseline);

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("UDP client protocol");
    let rejected = encoded_udp_request(
        &mut client,
        &clock,
        target_address.clone(),
        REJECT_DNS_QUERY,
    );
    peer.send_to(&rejected, listen)
        .await
        .expect("rejected DNS send");
    assert_pending(
        target.recv_from(&mut received),
        "rejected DNS reached target",
    )
    .await;
    assert_eq!(
        registry.snapshot(),
        baseline,
        "reject reserved target runtime"
    );
    peer.send_to(&rejected, listen)
        .await
        .expect("duplicate rejected DNS send");
    assert_pending(
        target.recv_from(&mut received),
        "replayed reject reached target",
    )
    .await;
    assert_eq!(
        registry.snapshot(),
        baseline,
        "replayed reject reserved runtime"
    );

    let routed = encoded_udp_request(&mut client, &clock, target_address, b"not-dns");
    peer.send_to(&routed, listen)
        .await
        .expect("routed UDP send");
    let (length, _) = recv_udp(&target, &mut received).await;
    assert_eq!(&received[..length], b"not-dns");

    stop.send(()).expect("stop server");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server shutdown deadline")
            .expect("server task"),
        Ok(())
    );
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove UDP route config");
}

#[tokio::test]
async fn tagged_udp_is_process_bounded_and_bound_to_its_local_inbound() {
    let first_listen = reserve_address();
    let second_listen = reserve_address();
    let target = udp_loopback().await;
    let target_address = target.local_addr().expect("target address");
    let routed_target = udp_loopback().await;
    let routed_address = routed_target.local_addr().expect("routed target address");
    let routed_domain =
        TargetAddr::domain("127.0.0.1", routed_address.port()).expect("domain target");
    let poison_new = udp_loopback().await;
    let poison_new_address = TargetAddr::ip(poison_new.local_addr().expect("new poison address"))
        .expect("new poison target");
    let poison_existing = udp_loopback().await;
    let poison_existing_address = TargetAddr::domain(
        "127.0.0.1",
        poison_existing
            .local_addr()
            .expect("existing poison address")
            .port(),
    )
    .expect("existing poison target");
    let (path, mut config) = tagged_server_test_config([first_listen, second_listen], true);
    let selector = config.selector_control();
    config.outbounds.truncate(1);
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, first_listen).await;
    wait_until_bound(&mut server, second_listen).await;

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let first_peer = udp_loopback().await;
    let roaming_peer = udp_loopback().await;
    let cross_peer = udp_loopback().await;
    let mut second = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let poison_wire = encoded_udp_request(&mut second, &clock, poison_new_address, b"new-poison");
    let baseline = registry.snapshot();
    selector.switch("manual", "o1").expect("select missing B");
    cross_peer
        .send_to(&poison_wire, second_listen)
        .await
        .expect("new poison send");
    let mut payload = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    assert_pending(
        poison_new.recv_from(&mut payload),
        "new poison reached target",
    )
    .await;
    assert_eq!(registry.snapshot(), baseline);
    assert_eq!(selector.selected("manual"), Ok("o1"));
    selector.switch("manual", "o0").expect("select direct A");
    let first_wire = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target_address).expect("target"),
        b"first",
    );
    first_peer
        .send_to(&first_wire, second_listen)
        .await
        .expect("first send");
    let (received, direct_peer) = recv_udp(&target, &mut payload).await;
    assert_eq!(&payload[..received], b"first");
    selector.switch("manual", "o1").expect("switch in flight");
    target
        .send_to(b"first-response", direct_peer)
        .await
        .expect("first target response");
    let (_, response_source) = recv_udp(&first_peer, &mut payload).await;
    assert_eq!(response_source, SocketAddr::V4(second_listen));
    let poison_wire = encoded_udp_request(
        &mut client,
        &clock,
        poison_existing_address,
        b"existing-poison",
    );
    let before_poison = registry.snapshot();
    first_peer
        .send_to(&poison_wire, second_listen)
        .await
        .expect("existing poison send");
    assert_pending(
        poison_existing.recv_from(&mut payload),
        "existing poison reached target",
    )
    .await;
    assert_eq!(registry.snapshot(), before_poison);
    selector.switch("manual", "o0").expect("restore direct A");
    let cross_wire = encoded_udp_request(&mut client, &clock, routed_domain, b"cross-fresh");
    let before_cross = registry.snapshot();

    cross_peer
        .send_to(&cross_wire, first_listen)
        .await
        .expect("cross-inbound send");
    assert_pending(
        routed_target.recv_from(&mut payload),
        "cross-inbound session reached target",
    )
    .await;
    let after_cross = registry.snapshot();
    assert_eq!(after_cross, before_cross);
    roaming_peer
        .send_to(&cross_wire, second_listen)
        .await
        .expect("same-inbound roaming send");
    let (received, direct_peer) = recv_udp(&routed_target, &mut payload).await;
    assert_eq!(&payload[..received], b"cross-fresh");
    selector
        .switch("manual", "o1")
        .expect("switch routed response");
    routed_target
        .send_to(b"roaming-response", direct_peer)
        .await
        .expect("roaming target response");
    let (_, response_source) = recv_udp(&roaming_peer, &mut payload).await;
    assert_eq!(response_source, SocketAddr::V4(second_listen));
    selector.switch("manual", "o0").expect("restore direct A");
    let second_wire = encoded_udp_request(
        &mut second,
        &clock,
        TargetAddr::ip(target_address).expect("second target"),
        b"over-capacity",
    );
    roaming_peer
        .send_to(&second_wire, second_listen)
        .await
        .expect("second inbound capacity send");
    assert_pending(
        target.recv_from(&mut payload),
        "second inbound multiplied process session cap",
    )
    .await;
    stop.send(()).expect("stop tagged server");
    assert_eq!(server.await.expect("tagged server owner"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove tagged config");
}

#[tokio::test]
async fn tagged_tcp_shares_static_direct_mapping_and_one_replay_store() {
    let first_listen = reserve_address();
    let second_listen = reserve_address();
    let first_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("first target bind");
    let second_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("second target bind");
    let first_address = TargetAddr::ip(first_target.local_addr().expect("first target address"))
        .expect("first target");
    let second_address = TargetAddr::ip(second_target.local_addr().expect("second target address"))
        .expect("second target");
    let (path, mut config) = tagged_server_test_config([first_listen, second_listen], true);
    let selector = config.selector_control();
    config.outbounds.truncate(1);
    let registry = OwnerRegistry::new();
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, first_listen).await;
    wait_until_bound(&mut server, second_listen).await;

    let keys = aes_keys();
    let timestamp = SystemClock::new().unix_seconds().expect("wall clock");
    let request = |salt_byte, target: &TargetAddr, payload: &[u8]| {
        let salt =
            MethodTcpSalt::try_from_slice(MethodProfile::Blake3Aes128Gcm2022, &[salt_byte; 16])
                .expect("request salt");
        encode_request_first_write(&keys, &salt, timestamp, target, &[0xa1], payload)
            .expect("request wire")
    };
    let mut invalid = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("invalid inbound connect");
    invalid
        .write_all(b"invalid")
        .await
        .expect("invalid request");
    invalid.shutdown().await.expect("invalid shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), invalid.read(&mut [0_u8; 1]))
        .await
        .expect("invalid close deadline");
    assert_pending(first_target.accept(), "invalid request reached target").await;

    let replayed = request(0x51, &first_address, b"first");
    let mut first = tokio::net::TcpStream::connect(first_listen)
        .await
        .expect("first inbound connect");
    first.write_all(&replayed).await.expect("first request");
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), first_target.accept())
        .await
        .expect("first direct deadline")
        .expect("first direct accept");
    let mut payload = [0_u8; 5];
    accepted
        .read_exact(&mut payload)
        .await
        .expect("first initial payload");
    assert_eq!(&payload, b"first");
    selector.switch("manual", "o1").expect("switch to B");
    accepted
        .write_all(b"captured A")
        .await
        .expect("target write");
    assert!(first.read(&mut [0; 64]).await.expect("captured A wire") > 0);

    let mut replay = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("replay inbound connect");
    replay.write_all(&replayed).await.expect("replayed request");
    let poison = request(0x52, &first_address, b"poison");
    let mut second = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("second inbound connect");
    second.write_all(&poison).await.expect("poison request");
    assert_pending(
        first_target.accept(),
        "second listener bypassed process permit",
    )
    .await;
    assert_eq!(registry.snapshot().connection_tasks, 1);

    drop((first, accepted));
    for rejected in [&mut replay, &mut second] {
        let _ = tokio::time::timeout(Duration::from_secs(5), rejected.read(&mut payload))
            .await
            .expect("rejected deadline");
    }
    assert_eq!(selector.selected("manual"), Ok("o1"));
    let final_poison = request(0x53, &second_address, b"final");
    let mut final_flow = tokio::net::TcpStream::connect(first_listen)
        .await
        .expect("final-route connect");
    final_flow
        .write_all(&final_poison)
        .await
        .expect("final request");
    let _ = tokio::time::timeout(Duration::from_secs(5), final_flow.read(&mut payload))
        .await
        .expect("final close deadline");
    assert_pending(second_target.accept(), "final poison reached target").await;
    assert_pending(
        first_target.accept(),
        "replay or inbound poison reached target",
    )
    .await;
    selector.switch("manual", "o0").expect("restore A");
    let selected = request(0x54, &second_address, b"selected");
    let mut later = tokio::net::TcpStream::connect(second_listen)
        .await
        .expect("later inbound connect");
    later.write_all(&selected).await.expect("later request");
    let (mut accepted, _) = tokio::time::timeout(Duration::from_secs(5), second_target.accept())
        .await
        .expect("later direct deadline")
        .expect("later direct accept");
    let mut payload = [0; 8];
    accepted
        .read_exact(&mut payload)
        .await
        .expect("later initial payload");
    assert_eq!(&payload, b"selected");
    drop((later, accepted));

    stop.send(()).expect("stop tagged server");
    assert_eq!(server.await.expect("tagged server owner"), Ok(()));
    assert_eq!(registry.snapshot().connection_tasks, 0);
    std::fs::remove_file(path).expect("remove tagged config");
}

#[tokio::test]
async fn tagged_prepare_failure_positions_rollback_every_bound_address() {
    for block in 0..7 {
        let listens = [reserve_address(), reserve_address(), reserve_address()];
        let metrics = reserve_address();
        let (path, mut config) = tagged_server_test_config(listens, false);
        config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
        let incumbent: Box<dyn Send> = match block {
            0..=2 => {
                Box::new(std::net::TcpListener::bind(listens[block]).expect("occupy TCP position"))
            }
            3..=5 => Box::new(
                std::net::UdpSocket::bind(listens[block - 3]).expect("occupy UDP position"),
            ),
            _ => Box::new(std::net::TcpListener::bind(metrics).expect("occupy metrics position")),
        };
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        assert_eq!(
            run_with_registry(config, registry.clone(), std::future::pending()).await,
            Err(RunError::StartupBind)
        );
        drop(incumbent);
        for listen in listens {
            let tcp = std::net::TcpListener::bind(listen).expect("TCP rollback rebind");
            let udp = std::net::UdpSocket::bind(listen).expect("UDP rollback rebind");
            drop((tcp, udp));
        }
        drop(std::net::TcpListener::bind(metrics).expect("metrics rollback rebind"));
        assert_eq!(active(registry.snapshot()), baseline);
        std::fs::remove_file(path).expect("remove tagged failure config");
    }
}

struct ProtocolClientConnector {
    inner: TcpConnector,
}

impl Connector for ProtocolClientConnector {
    type Stream = TokioTransport<RuntimeTcpStream>;

    async fn connect(&self, target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
        self.inner.connect(target).await.map(TokioTransport::new)
    }
}

#[tokio::test]
async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
    let listen = reserve_address();
    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener");
    let target_address = match target_listener.local_addr().expect("target address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 target"),
    };
    let (config_path, config) = server_test_config(listen);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, mut run_task) = spawn_test_server(config, &registry);
    wait_until_bound(&mut run_task, listen).await;

    let target_accept =
        tokio::spawn(async move { target_listener.accept().await.expect("target accept").0 });
    let keys = SinglePskProvider::new(Aes128Psk::from_bytes(PSK_BYTES));
    let connector = ProtocolClientConnector {
        inner: TcpConnector::new(Duration::from_secs(5)),
    };
    let server_target = TargetAddr::ipv4(listen).expect("server target");
    let application_target = TargetAddr::ipv4(target_address).expect("application target");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let outbound = ClientTcpOutbound::new(server_target, &keys, &connector, &clock, &random);
    let flow = outbound
        .connect_server()
        .await
        .expect("connect server")
        .write_request(&application_target)
        .await
        .expect("write request");
    let target_stream = target_accept.await.expect("target accept task");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let live = registry.snapshot();
        if live.active_supervisor_children == 1
            && live.connection_tasks == 1
            && live.owned_buffers == 2
            && live.owned_permits >= 1
            && live.listeners == 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "registry never exposed the live production path: {live:?}"
        );
        tokio::task::yield_now().await;
    }

    shutdown_sender.send(()).expect("request shutdown");
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    drop(flow);
    drop(target_stream);
    let final_snapshot = registry.snapshot();
    assert_eq!(
        final_snapshot.active_supervisor_children,
        baseline.active_supervisor_children
    );
    assert_eq!(final_snapshot.connection_tasks, baseline.connection_tasks);
    assert_eq!(final_snapshot.owned_buffers, baseline.owned_buffers);
    assert_eq!(final_snapshot.owned_permits, baseline.owned_permits);
    assert_eq!(final_snapshot.listeners, baseline.listeners);
    assert!(
        final_snapshot.process_forced_roots > baseline.process_forced_roots,
        "zero-grace process did not force any required root: {final_snapshot:?}"
    );
    assert_eq!(
        final_snapshot.forced_shutdowns,
        baseline.forced_shutdowns + 1,
        "phase-aware TCP root did not explicitly force and reap its child"
    );
    std::fs::remove_file(config_path).expect("remove server test config");
}
