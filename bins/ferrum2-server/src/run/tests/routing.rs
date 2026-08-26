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
use crate::run::test_support::*;

#[tokio::test]
async fn route_sniff_reject_udp_freezes_first_terminal_before_reservation() {
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
    let metrics = reserve_address();
    let (path, mut config) = server_v2_test_config(listen, route);
    config.metrics = Some(ferrum2_config::MetricsConfig { listen: metrics });
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

    let frozen_reject =
        encoded_udp_request(&mut client, &clock, target_address.clone(), b"not-dns");
    peer.send_to(&frozen_reject, listen)
        .await
        .expect("frozen reject UDP send");
    assert_pending(
        target.recv_from(&mut received),
        "frozen reject identity reached target",
    )
    .await;
    assert_eq!(
        registry.snapshot(),
        baseline,
        "frozen reject reserved target runtime"
    );

    let mut direct_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("direct UDP identity");
    let routed = encoded_udp_request(&mut direct_client, &clock, target_address, b"not-dns");
    peer.send_to(&routed, listen)
        .await
        .expect("fresh routed UDP send");
    let (length, _) = recv_udp(&target, &mut received).await;
    assert_eq!(&received[..length], b"not-dns");

    let mut metrics_client = tokio::net::TcpStream::connect(metrics)
        .await
        .expect("UDP route metrics connect");
    metrics_client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("UDP route metrics request");
    let mut encoded = String::new();
    metrics_client
        .read_to_string(&mut encoded)
        .await
        .expect("UDP route metrics response");
    for expected in [
        "ferrum2_rule_program_rules{program=\"route\"} 2",
        "ferrum2_route_match_total{source=\"inline\",type=\"domain\",result=\"matched\"}",
        "ferrum2_route_match_total{source=\"inline\",type=\"scalar\",result=\"matched\"}",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
    for identity in [
        "ferrum2_rule_program_candidate_count_sum{program=\"route\"}",
        "ferrum2_rule_program_match_ns_sum{program=\"route\"}",
    ] {
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
            "zero or missing `{identity}`\n{encoded}"
        );
    }

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
