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
async fn tagged_udp_is_process_bounded_and_bound_to_its_local_inbound() {
    let first_listen = reserve_address();
    let second_listen = reserve_address();
    let target = udp_loopback().await;
    let target_address = target.local_addr().expect("target address");
    let routed_target = udp_loopback().await;
    let routed_address = routed_target.local_addr().expect("routed target address");
    let routed_domain =
        TargetAddr::domain("127.0.0.1", routed_address.port()).expect("domain target");
    let source = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"i0\"\nlisten = \"{first_listen}\"\n\
         [[inbounds]]\ntag = \"i1\"\nlisten = \"{second_listen}\"\n\
         [[outbounds]]\ntag = \"o0\"\n\
         [[outbounds]]\ntag = \"o1\"\n\
         [[selectors]]\ntag = \"manual\"\noutbounds = [\"o0\", \"o1\"]\ndefault = \"o0\"\n\
         [route]\nfinal = \"manual\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
         [runtime]\nmax_connections = 1\nshutdown_grace_ms = 0\n\
         [udp]\nmax_sessions = 1\n"
    );
    let (path, config) = server_test_config_source("tagged-udp", &source);
    let selector = config.selector_control();
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
    let mut payload = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
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
    assert!(
        tokio::time::timeout(Duration::from_secs(5), first.read(&mut [0; 64]))
            .await
            .expect("captured A response deadline")
            .expect("captured A wire")
            > 0
    );

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
