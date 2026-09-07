use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_runtime::OwnerRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;

use super::listener::AcceptedSocket;
use super::{AddressFamily, PortQuarantine, ReverseTuple, SystemTcp, TCP_ACK, TCP_RST, TCP_SYN};
use crate::packet::test_support::{repair_ipv4_header, repair_transport_checksum};
use crate::packet::{Families, IP_PROTOCOL_TCP, PacketParser, ParsedIpPacket, ParsedPacket};
use crate::system_tcp::TCP_FIN;
use crate::{OwnerWake, TunRejectReason};

const LOCAL_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const PEER_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TARGET_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LISTENER_V4_PORT: u16 = 40_001;

#[test]
fn ipv4_options_and_ipv6_extension_offsets_round_trip_with_valid_checksums() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(4, 60_000, Arc::clone(&quarantine));
    system
        .configure_bindings_for_test(
            (
                Some((LOCAL_V4, 30)),
                Some(("2001:db8::2".parse().expect("IPv6 local"), 126)),
            ),
            (Some(LISTENER_V4_PORT), Some(40_002)),
        )
        .expect("test bindings");

    let mut ipv4 = ipv4_syn(443, 7);
    let ipv4_options = ipv4[20..24].to_vec();
    let tcp_options = ipv4[44..48].to_vec();
    let parsed = parse_complete(&ipv4);
    assert_eq!(parsed.transport_offset, 24);
    system
        .rewrite(&mut ipv4, parsed, true, 10)
        .expect("IPv4 forward rewrite");
    let translated_v4 = parse_complete(&ipv4);
    assert_eq!(translated_v4.source, IpAddr::V4(PEER_V4));
    assert_eq!(translated_v4.destination, IpAddr::V4(LOCAL_V4));
    assert_eq!(&ipv4[20..24], ipv4_options.as_slice());
    assert_eq!(&ipv4[44..48], tcp_options.as_slice());

    let mut reverse_v4 = reverse_packet(ipv4, translated_v4.transport_offset, TCP_ACK);
    let parsed = parse_complete(&reverse_v4);
    system
        .rewrite(&mut reverse_v4, parsed, true, 11)
        .expect("IPv4 reverse rewrite");
    let restored_v4 = parse_complete(&reverse_v4);
    assert_eq!(restored_v4.source, IpAddr::V4(TARGET_V4));
    assert_eq!(restored_v4.destination, IpAddr::V4(LOCAL_V4));

    let mut ipv6 = ipv6_syn(853, 9);
    let extension = ipv6[40..48].to_vec();
    let tcp_options = ipv6[68..72].to_vec();
    let parsed = parse_complete(&ipv6);
    assert_eq!(parsed.transport_offset, 48);
    system
        .rewrite(&mut ipv6, parsed, true, 12)
        .expect("IPv6 forward rewrite");
    let translated_v6 = parse_complete(&ipv6);
    assert_eq!(
        translated_v6.source,
        "2001:db8::1".parse::<IpAddr>().expect("IPv6 peer")
    );
    assert_eq!(
        translated_v6.destination,
        "2001:db8::2".parse::<IpAddr>().expect("IPv6 local")
    );
    assert_eq!(&ipv6[40..48], extension.as_slice());
    assert_eq!(&ipv6[68..72], tcp_options.as_slice());

    let mut reverse_v6 = reverse_packet(ipv6, translated_v6.transport_offset, TCP_ACK);
    let parsed = parse_complete(&reverse_v6);
    system
        .rewrite(&mut reverse_v6, parsed, true, 13)
        .expect("IPv6 reverse rewrite");
    let restored_v6 = parse_complete(&reverse_v6);
    assert_eq!(
        restored_v6.source,
        "2001:db8:1::1".parse::<IpAddr>().expect("IPv6 target")
    );
    assert_eq!(
        restored_v6.destination,
        "2001:db8::2".parse::<IpAddr>().expect("IPv6 source")
    );
}

#[test]
fn same_source_port_to_distinct_targets_uses_distinct_reverse_identities() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(2, 60_000, quarantine);
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");

    let mut https = ipv4_syn(443, 1);
    let parsed = parse_complete(&https);
    system
        .rewrite(&mut https, parsed, true, 10)
        .expect("HTTPS mapping");
    let mut http = ipv4_syn(80, 2);
    let parsed = parse_complete(&http);
    system
        .rewrite(&mut http, parsed, true, 11)
        .expect("HTTP mapping");
    assert_ne!(&https[24..26], &http[24..26]);
    assert_eq!(system.live_flows(), 2);

    let mut https_reply = reverse_packet(https, 24, TCP_ACK);
    let parsed = parse_complete(&https_reply);
    system
        .rewrite(&mut https_reply, parsed, true, 12)
        .expect("HTTPS reverse mapping");
    assert_eq!(u16::from_be_bytes([https_reply[24], https_reply[25]]), 443);
    assert_eq!(
        u16::from_be_bytes([https_reply[26], https_reply[27]]),
        10_000
    );

    let mut http_reply = reverse_packet(http, 24, TCP_ACK);
    let parsed = parse_complete(&http_reply);
    system
        .rewrite(&mut http_reply, parsed, true, 13)
        .expect("HTTP reverse mapping");
    assert_eq!(u16::from_be_bytes([http_reply[24], http_reply[25]]), 80);
    assert_eq!(u16::from_be_bytes([http_reply[26], http_reply[27]]), 10_000);
}

#[test]
fn unknown_reverse_tuple_is_rejected_without_mutation() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(1, 60_000, quarantine);
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    let mut packet = ipv4_syn(443, 1);
    packet[12..16].copy_from_slice(&LOCAL_V4.octets());
    packet[16..20].copy_from_slice(&PEER_V4.octets());
    packet[24..26].copy_from_slice(&LISTENER_V4_PORT.to_be_bytes());
    packet[26..28].copy_from_slice(&55_555_u16.to_be_bytes());
    packet[37] = TCP_ACK;
    repair_transport_checksum(&mut packet, 24, IP_PROTOCOL_TCP);
    repair_ipv4_header(&mut packet);
    let original = packet.clone();
    let parsed = parse_complete(&packet);

    assert_eq!(
        system.rewrite(&mut packet, parsed, true, 10),
        Err(TunRejectReason::InvalidDestination)
    );
    assert_eq!(packet, original);
}

#[test]
fn exhausted_translation_identity_space_rejects_admission() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(1, 60_000, Arc::clone(&quarantine));
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    {
        let mut quarantine = quarantine.lock().expect("quarantine");
        for port in 1..=u16::MAX {
            if port != LISTENER_V4_PORT {
                assert!(quarantine.claim(AddressFamily::Ipv4, port));
            }
        }
    }
    let mut packet = ipv4_syn(443, 1);
    let parsed = parse_complete(&packet);

    assert_eq!(
        system.rewrite(&mut packet, parsed, true, 10),
        Err(TunRejectReason::InvalidDestination)
    );
    assert_eq!(system.live_flows(), 0);
    assert_eq!(system.quarantine_counts().0, (usize::from(u16::MAX), 0));
}

#[test]
fn duplicate_syn_limit_retirement_and_quarantine_are_deterministic() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(1, 1_000, Arc::clone(&quarantine));
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");

    let original = ipv4_syn(443, 0x1020_3040);
    let mut first = original.clone();
    let parsed = parse_complete(&first);
    system
        .rewrite(&mut first, parsed, true, 10)
        .expect("initial SYN");
    let translated_port = u16::from_be_bytes([first[24], first[25]]);
    assert_eq!(system.live_flows(), 1);

    let mut duplicate = original.clone();
    let parsed = parse_complete(&duplicate);
    system
        .rewrite(&mut duplicate, parsed, true, 11)
        .expect("same-ISN retransmission");
    assert_eq!(
        u16::from_be_bytes([duplicate[24], duplicate[25]]),
        translated_port
    );
    assert_eq!(system.live_flows(), 1);

    let mut conflicting = original.clone();
    conflicting[28..32].copy_from_slice(&0x1020_3041_u32.to_be_bytes());
    repair_transport_checksum(&mut conflicting, 24, IP_PROTOCOL_TCP);
    let parsed = parse_complete(&conflicting);
    assert_eq!(
        system.rewrite(&mut conflicting, parsed, true, 12),
        Err(TunRejectReason::InvalidDestination)
    );

    let mut second_target = ipv4_syn(80, 5);
    let parsed = parse_complete(&second_target);
    assert_eq!(
        system.rewrite(&mut second_target, parsed, true, 13),
        Err(TunRejectReason::TcpFlowLimit)
    );

    let mut reset = original.clone();
    reset[37] = TCP_RST | TCP_ACK;
    repair_transport_checksum(&mut reset, 24, IP_PROTOCOL_TCP);
    let parsed = parse_complete(&reset);
    system
        .rewrite(&mut reset, parsed, true, 14)
        .expect("RST rewrite before retirement");
    assert_eq!(system.live_flows(), 1);
    assert!(!system.expire(14));
    assert!(system.expire(15));
    assert_eq!(system.live_flows(), 0);
    assert_eq!(system.quarantine_counts().0, (1, 1));
    assert_eq!(system.next_deadline_millis(), Some(240_015));

    let mut premature_reuse = original.clone();
    let parsed = parse_complete(&premature_reuse);
    assert_eq!(
        system.rewrite(&mut premature_reuse, parsed, true, 240_014),
        Err(TunRejectReason::InvalidDestination)
    );
    assert!(system.expire(240_015));
    assert_eq!(system.quarantine_counts().0, (1, 0));

    let mut after_quarantine = original;
    let parsed = parse_complete(&after_quarantine);
    system
        .rewrite(&mut after_quarantine, parsed, true, 240_015)
        .expect("tuple may be admitted after quarantine");
    assert_ne!(
        u16::from_be_bytes([after_quarantine[24], after_quarantine[25]]),
        translated_port
    );
}

#[test]
fn bidirectional_fin_enters_fixed_retirement_without_losing_final_tuple_rewrite() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(1, 1_000, quarantine);
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");

    let original = ipv4_syn(443, 6);
    let mut translated = original.clone();
    let parsed = parse_complete(&translated);
    system
        .rewrite(&mut translated, parsed, true, 10)
        .expect("initial SYN");

    let mut application_fin = original;
    application_fin[37] = TCP_FIN | TCP_ACK;
    repair_transport_checksum(&mut application_fin, 24, IP_PROTOCOL_TCP);
    let parsed = parse_complete(&application_fin);
    system
        .rewrite(&mut application_fin, parsed, true, 20)
        .expect("application FIN");

    let mut listener_fin = reverse_packet(translated, 24, TCP_FIN | TCP_ACK);
    let parsed = parse_complete(&listener_fin);
    system
        .rewrite(&mut listener_fin, parsed, true, 21)
        .expect("listener FIN");
    let restored = parse_complete(&listener_fin);
    assert_eq!(restored.source, IpAddr::V4(TARGET_V4));
    assert_eq!(restored.destination, IpAddr::V4(LOCAL_V4));
    assert_eq!(system.live_flows(), 1);
    assert!(!system.expire(1_009));
    assert!(system.expire(1_010));
    assert_eq!(system.live_flows(), 0);
}

#[test]
fn shared_quarantine_prevents_reset_generation_port_reuse() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut first, _flows) = test_system(1, 1_000, Arc::clone(&quarantine));
    first
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("first binding");
    let mut packet = ipv4_syn(443, 1);
    let parsed = parse_complete(&packet);
    first
        .rewrite(&mut packet, parsed, true, 10)
        .expect("first SYN");
    let old_port = u16::from_be_bytes([packet[24], packet[25]]);
    first.fence(2).expect("new generation");
    assert_eq!(first.retire(2), 1);
    drop(first);

    let (mut second, _flows) = test_system_with_generation(1, 1_000, 2, Arc::clone(&quarantine));
    let error = second
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect_err("old listener identity remains quarantined");
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    assert_eq!(
        quarantine
            .lock()
            .expect("shared quarantine")
            .next_deadline_millis(),
        Some(10),
        "pending retirement must request a fresh supervisor-clock observation"
    );
    second
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(40_003), None))
        .expect("second binding");
    let mut packet = ipv4_syn(8443, 2);
    let parsed = parse_complete(&packet);
    second
        .rewrite(&mut packet, parsed, true, 100_000)
        .expect("second generation SYN");
    assert_ne!(u16::from_be_bytes([packet[24], packet[25]]), old_port);
    assert_eq!(second.quarantine_counts().0, (2, 2));
    assert_eq!(
        quarantine
            .lock()
            .expect("shared quarantine")
            .next_deadline_millis(),
        Some(340_000)
    );
}

#[tokio::test]
async fn expired_half_open_mapping_cannot_be_revived_by_a_late_accept() {
    let (mut system, mut flows) =
        test_system(1, 1_000, Arc::new(Mutex::new(PortQuarantine::default())));
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    let mut syn = ipv4_syn(443, 3);
    let parsed = parse_complete(&syn);
    system.rewrite(&mut syn, parsed, true, 0).expect("SYN");
    let translated = parse_complete(&syn);
    let (accepted, mut peer) = connected_pair().await.expect("late connection");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch: system.bindings[0].epoch,
            local: SocketAddr::new(translated.destination, LISTENER_V4_PORT),
            peer: SocketAddr::new(translated.source, u16::from_be_bytes([syn[24], syn[25]])),
            stream: accepted,
        })
        .expect("queue late accept");

    assert!(system.expire(1_000));
    assert_eq!(system.live_flows(), 0);
    assert!(matches!(
        flows.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
            .await
            .expect("rejected socket closes")
            .expect("peer EOF"),
        0
    );
}

#[test]
fn terminal_generation_retires_flows_without_reopening_the_stack() {
    let (mut system, _flows) = test_system_with_generation(
        1,
        1_000,
        u64::MAX,
        Arc::new(Mutex::new(PortQuarantine::default())),
    );
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    let mut syn = ipv4_syn(443, 3);
    let parsed = parse_complete(&syn);
    system.rewrite(&mut syn, parsed, true, 0).expect("SYN");
    system.fence(0).expect("terminal fence");
    assert_eq!(system.retire(0), 1);
    assert_eq!(system.live_flows(), 0);
    let mut next = ipv4_syn(443, 4);
    let parsed = parse_complete(&next);
    assert_eq!(
        system.rewrite(&mut next, parsed, true, 1),
        Err(TunRejectReason::StaleGeneration)
    );
}

#[test]
fn poisoned_quarantine_keeps_cleanup_failure_visible_without_panicking() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, _flows) = test_system(1, 1_000, Arc::clone(&quarantine));
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    let mut syn = ipv4_syn(443, 3);
    let parsed = parse_complete(&syn);
    system.rewrite(&mut syn, parsed, true, 0).expect("SYN");
    let poisoned = Arc::clone(&quarantine);
    let panic = std::panic::catch_unwind(move || {
        let _guard = poisoned.lock().expect("unpoisoned pool");
        panic!("injected quarantine owner failure");
    });
    assert!(panic.is_err());
    assert_eq!(system.stop_and_join(), Err(()));
    assert!(system.failed());
    assert_eq!(system.retire(2), 1);
    assert_eq!(system.live_flows(), 0);
    drop(system);
}

#[tokio::test]
async fn accept_requires_current_epoch_and_exact_peer_before_publication() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (mut system, mut flows) = test_system(1, 60_000, quarantine);
    system
        .configure_bindings_for_test((Some((LOCAL_V4, 30)), None), (Some(LISTENER_V4_PORT), None))
        .expect("test binding");
    let mut syn = ipv4_syn(443, 3);
    let parsed = parse_complete(&syn);
    system.rewrite(&mut syn, parsed, true, 10).expect("SYN");
    let translated = parse_complete(&syn);
    let reverse = ReverseTuple {
        listener: SocketAddr::new(translated.destination, LISTENER_V4_PORT),
        peer: SocketAddr::new(translated.source, u16::from_be_bytes([syn[24], syn[25]])),
    };
    let epoch = system.bindings[0].epoch;

    let (accepted, _peer) = connected_pair().await.expect("bad epoch pair");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch: epoch.wrapping_add(1),
            local: reverse.listener,
            peer: reverse.peer,
            stream: accepted,
        })
        .expect("queue bad epoch");
    assert!(system.expire(11));
    assert!(matches!(
        flows.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let (accepted, _peer) = connected_pair().await.expect("wrong peer pair");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch,
            local: reverse.listener,
            peer: SocketAddr::new(reverse.peer.ip(), reverse.peer.port().wrapping_add(1)),
            stream: accepted,
        })
        .expect("queue wrong peer");
    assert!(system.expire(12));
    assert!(matches!(
        flows.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    let (accepted, mut peer) = connected_pair().await.expect("accepted pair");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch,
            local: reverse.listener,
            peer: reverse.peer,
            stream: accepted,
        })
        .expect("queue accepted socket");
    assert!(system.expire(13));
    let mut flow = flows.try_recv().expect("published mapped flow");
    assert_eq!(flow.target(), SocketAddr::new(IpAddr::V4(TARGET_V4), 443));
    flow.write_all(b"mapped").await.expect("flow write");
    let mut bytes = [0_u8; 6];
    peer.read_exact(&mut bytes).await.expect("peer read");
    assert_eq!(&bytes, b"mapped");

    let (duplicate, _peer) = connected_pair().await.expect("duplicate pair");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch,
            local: reverse.listener,
            peer: reverse.peer,
            stream: duplicate,
        })
        .expect("queue duplicate");
    assert!(system.expire(14));
    assert!(matches!(
        flows.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    system.fence(2).expect("generation fence");
    let error = flow.read_u8().await.expect_err("fenced flow read");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(system.retire(2), 1);

    let (late, _peer) = connected_pair().await.expect("late pair");
    system
        .accepted_sender
        .try_send(AcceptedSocket {
            epoch,
            local: reverse.listener,
            peer: reverse.peer,
            stream: late,
        })
        .expect("queue late accept");
    assert!(system.expire(15));
    assert!(matches!(
        flows.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_loopback_listener_accepts_only_the_mapped_synthetic_peer() {
    let quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let (system, mut flows) = test_system(1, 60_000, Arc::clone(&quarantine));
    let runtime = tokio::runtime::Handle::current();
    let (mut system, endpoints) = tokio::task::spawn_blocking(move || {
        let mut system = system;
        let endpoints = system
            .start((Some((Ipv4Addr::new(127, 0, 0, 2), 30)), None), &runtime)
            .expect("start loopback listener");
        (system, endpoints)
    })
    .await
    .expect("native start owner");
    let endpoint = endpoints[0];
    assert_eq!(
        endpoint.local().ip(),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
    );
    assert_eq!(endpoint.peer(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    let (socket, source_port) = loop {
        let socket = TcpSocket::new_v4().expect("client socket");
        socket
            .bind(SocketAddr::new(endpoint.peer(), 0))
            .expect("bind synthetic peer");
        let source_port = socket.local_addr().expect("source identity").port();
        if source_port != endpoint.local().port() {
            break (socket, source_port);
        }
    };
    quarantine
        .lock()
        .expect("quarantine")
        .set_next_port_for_test(AddressFamily::Ipv4, source_port);

    let mut syn = ipv4_syn(443, 4);
    syn[12..16].copy_from_slice(&[127, 0, 0, 2]);
    repair_transport_checksum(&mut syn, 24, IP_PROTOCOL_TCP);
    repair_ipv4_header(&mut syn);
    let parsed = parse_complete(&syn);
    system.rewrite(&mut syn, parsed, true, 20).expect("map SYN");
    assert_eq!(u16::from_be_bytes([syn[24], syn[25]]), source_port);

    let mut peer = socket
        .connect(endpoint.local())
        .await
        .expect("connect listener");
    let mut flow = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            system.expire(21);
            match flows.try_recv() {
                Ok(flow) => break flow,
                Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(mpsc::error::TryRecvError::Disconnected) => panic!("flow channel closed"),
            }
        }
    })
    .await
    .expect("mapped accept deadline");
    peer.write_all(b"listener").await.expect("peer write");
    let mut bytes = [0_u8; 8];
    flow.read_exact(&mut bytes).await.expect("flow read");
    assert_eq!(&bytes, b"listener");

    system.fence(2).expect("fence before stop");
    let (stop, retired, failed) = tokio::task::spawn_blocking(move || {
        let stop = system.stop_and_join();
        let retired = system.retire(2);
        (stop, retired, system.failed())
    })
    .await
    .expect("native stop owner");
    assert_eq!(stop, Ok(()));
    assert_eq!(retired, 1);
    assert!(
        !failed,
        "intentional listener shutdown is not an owner failure"
    );
}

fn test_system(
    max_flows: usize,
    timeout_millis: u64,
    quarantine: Arc<Mutex<PortQuarantine>>,
) -> (SystemTcp, mpsc::Receiver<crate::TcpFlow>) {
    test_system_with_generation(max_flows, timeout_millis, 1, quarantine)
}

fn test_system_with_generation(
    max_flows: usize,
    timeout_millis: u64,
    generation: u64,
    quarantine: Arc<Mutex<PortQuarantine>>,
) -> (SystemTcp, mpsc::Receiver<crate::TcpFlow>) {
    SystemTcp::new(
        max_flows,
        Duration::from_millis(timeout_millis),
        generation,
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        OwnerWake::default(),
        quarantine,
    )
}

fn parse_complete(packet: &[u8]) -> ParsedIpPacket {
    match PacketParser::new(Families::DUAL)
        .parse(packet)
        .expect("valid packet")
    {
        ParsedPacket::Complete(parsed) => parsed,
        ParsedPacket::Fragment(_) => panic!("test packet must be complete"),
    }
}

fn ipv4_syn(target_port: u16, sequence: u32) -> Vec<u8> {
    let transport_offset = 24;
    let total_len = transport_offset + 24;
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x46;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = IP_PROTOCOL_TCP;
    packet[12..16].copy_from_slice(&LOCAL_V4.octets());
    packet[16..20].copy_from_slice(&TARGET_V4.octets());
    packet[20..24].copy_from_slice(&[1, 1, 0, 0]);
    packet[transport_offset..transport_offset + 2].copy_from_slice(&10_000_u16.to_be_bytes());
    packet[transport_offset + 2..transport_offset + 4].copy_from_slice(&target_port.to_be_bytes());
    packet[transport_offset + 4..transport_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[transport_offset + 12] = 6 << 4;
    packet[transport_offset + 13] = TCP_SYN;
    packet[transport_offset + 14..transport_offset + 16].copy_from_slice(&8_192_u16.to_be_bytes());
    packet[transport_offset + 20..].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    repair_transport_checksum(&mut packet, transport_offset, IP_PROTOCOL_TCP);
    repair_ipv4_header(&mut packet);
    packet
}

fn ipv6_syn(target_port: u16, sequence: u32) -> Vec<u8> {
    let transport_offset = 48;
    let mut packet = vec![0_u8; transport_offset + 24];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&32_u16.to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[8..24].copy_from_slice(
        &"2001:db8::2"
            .parse::<Ipv6Addr>()
            .expect("IPv6 source")
            .octets(),
    );
    packet[24..40].copy_from_slice(
        &"2001:db8:1::1"
            .parse::<Ipv6Addr>()
            .expect("IPv6 target")
            .octets(),
    );
    packet[40] = IP_PROTOCOL_TCP;
    packet[41] = 0;
    packet[transport_offset..transport_offset + 2].copy_from_slice(&10_001_u16.to_be_bytes());
    packet[transport_offset + 2..transport_offset + 4].copy_from_slice(&target_port.to_be_bytes());
    packet[transport_offset + 4..transport_offset + 8].copy_from_slice(&sequence.to_be_bytes());
    packet[transport_offset + 12] = 6 << 4;
    packet[transport_offset + 13] = TCP_SYN;
    packet[transport_offset + 14..transport_offset + 16].copy_from_slice(&8_192_u16.to_be_bytes());
    packet[transport_offset + 20..].copy_from_slice(&[2, 4, 0x05, 0xb4]);
    repair_transport_checksum(&mut packet, transport_offset, IP_PROTOCOL_TCP);
    packet
}

fn reverse_packet(mut packet: Vec<u8>, transport_offset: usize, flags: u8) -> Vec<u8> {
    match packet[0] >> 4 {
        4 => {
            let source: [u8; 4] = packet[12..16].try_into().expect("IPv4 source");
            let destination: [u8; 4] = packet[16..20].try_into().expect("IPv4 target");
            packet[12..16].copy_from_slice(&destination);
            packet[16..20].copy_from_slice(&source);
        }
        6 => {
            let source: [u8; 16] = packet[8..24].try_into().expect("IPv6 source");
            let destination: [u8; 16] = packet[24..40].try_into().expect("IPv6 target");
            packet[8..24].copy_from_slice(&destination);
            packet[24..40].copy_from_slice(&source);
        }
        _ => unreachable!(),
    }
    let source_port: [u8; 2] = packet[transport_offset..transport_offset + 2]
        .try_into()
        .expect("TCP source port");
    let destination_port: [u8; 2] = packet[transport_offset + 2..transport_offset + 4]
        .try_into()
        .expect("TCP target port");
    packet[transport_offset..transport_offset + 2].copy_from_slice(&destination_port);
    packet[transport_offset + 2..transport_offset + 4].copy_from_slice(&source_port);
    packet[transport_offset + 13] = flags;
    repair_transport_checksum(&mut packet, transport_offset, IP_PROTOCOL_TCP);
    if packet[0] >> 4 == 4 {
        repair_ipv4_header(&mut packet);
    }
    packet
}

async fn connected_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let connect = TcpStream::connect(address);
    let accept = listener.accept();
    let (peer, accepted) = tokio::join!(connect, accept);
    Ok((accepted?.0, peer?))
}
