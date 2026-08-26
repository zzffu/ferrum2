#![allow(unused_imports)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ferrum2_core::{ConnectError, Connector, TargetAddr};
use ferrum2_crypto::{MethodProfile, MethodTcpSalt};
use ferrum2_runtime::OwnerSnapshot;
use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::*;
use super::dns_lifecycle::ProtocolClientConnector;
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

    let keys = aes_keys();
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
    for expected in [
        "ferrum2_rule_program_mode{program=\"route\",mode=\"small_linear\"} 1",
        "ferrum2_rule_program_rules{program=\"route\"} 6",
        "ferrum2_route_match_total{source=\"inline\",type=\"domain\",result=\"matched\"}",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_candidate_count_count{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_count{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }
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

    let keys = aes_keys();
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
