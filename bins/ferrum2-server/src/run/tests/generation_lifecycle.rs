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

use super::dns_lifecycle::{ProtocolClientConnector, gated_a_dns, operational_dns_drain_source};
use super::support::*;

#[tokio::test]
async fn unresolved_udp_selection_is_cancelled_before_session_admission() {
    let listen = reserve_address();
    let target = udp_loopback().await;
    let target_address = TargetAddr::domain(
        "udp-drain.test",
        target
            .local_addr()
            .expect("UDP drain target address")
            .port(),
    )
    .expect("UDP drain domain target");
    let (dns_address, query_observed, release_answer, dns_task) =
        gated_a_dns("udp-drain.test.").await;
    let source = operational_dns_drain_source(listen, dns_address, true);
    let (config_path, _) = server_test_config_source("udp-dns-drain", &source);
    let config = finish_server_test_config(&config_path);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, mut run_task) = spawn_test_server(config, &registry);
    wait_until_bound(&mut run_task, listen).await;

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("UDP drain client");
    let peer = udp_loopback().await;
    let wire = encoded_udp_request(&mut client, &clock, target_address, b"udp-drain");
    peer.send_to(&wire, listen).await.expect("UDP drain send");
    tokio::time::timeout(Duration::from_secs(1), query_observed)
        .await
        .expect("UDP drain DNS query deadline")
        .expect("observe UDP drain DNS query");

    shutdown_sender.send(()).expect("quiesce UDP drain server");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), run_task)
            .await
            .expect("UDP selection cancellation shutdown deadline")
            .expect("UDP selection cancellation server task"),
        Ok(())
    );
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions);
    assert_eq!(registry.snapshot().udp_sockets, baseline.udp_sockets);
    assert_eq!(registry.snapshot().udp_tasks, baseline.udp_tasks);

    release_answer.send(()).expect("answer UDP drain DNS query");
    let mut payload = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    assert_pending(
        target.recv_from(&mut payload),
        "unresolved UDP target received a datagram after pre-admission cancellation",
    )
    .await;
    dns_task.await.expect("UDP drain DNS task join");

    assert_eq!(active(registry.snapshot()), active(baseline));
    std::fs::remove_file(config_path).expect("remove UDP drain server config");
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
    let keys = aes_keys();
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
            && live.owned_buffers == baseline.owned_buffers
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
