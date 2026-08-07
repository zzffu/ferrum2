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
