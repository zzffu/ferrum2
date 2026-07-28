mod common;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{MethodProfile, MonotonicInstant};
use ferrum2_shadowsocks::{
    UDP_REPLAY_LAG, UdpClientSession, UdpPacketError, UdpPacketScratch, UdpReplayWindow, UdpServer,
};

use common::{FakeClock, FillRandom, udp_provider};

#[test]
fn replay_window_boundary_jump_duplicate_and_overflow_table() {
    let mut window = UdpReplayWindow::new();
    assert_eq!(window.highest(), None);
    window.commit(10_000).expect("first ID");
    window.commit(9_999).expect("out of order");
    window
        .commit(10_000 - UDP_REPLAY_LAG)
        .expect("inclusive lag boundary");
    assert_eq!(window.commit(10_000), Err(UdpPacketError::Duplicate));
    assert_eq!(
        window.commit(10_000 - UDP_REPLAY_LAG - 1),
        Err(UdpPacketError::TooOld)
    );

    window.commit(u64::MAX).expect("large forward jump");
    window
        .commit(u64::MAX - UDP_REPLAY_LAG)
        .expect("maximum-ID lag boundary");
    assert_eq!(
        window.commit(u64::MAX - UDP_REPLAY_LAG - 1),
        Err(UdpPacketError::TooOld)
    );
    assert_eq!(window.highest(), Some(u64::MAX));
}

#[test]
fn same_authenticated_id_has_one_atomic_winner_across_64_commits() {
    let keys = udp_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = Arc::new(FakeClock::new(1_700_000_000, 0));
    let client_random = FillRandom::new(0x10);
    let server_random = Arc::new(FillRandom::new(0x80));
    let mut client =
        UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("target");
    let request = Datagram::new(target, BytesMut::from(&b"race"[..]), 4).expect("datagram");
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; 65_507];
    let wire_len = client
        .encode_request(
            clock.as_ref(),
            &client_random,
            &request,
            0,
            &mut wire,
            &mut scratch,
        )
        .expect("request");
    wire.truncate(wire_len);

    let server = Arc::new(UdpServer::new(&keys).expect("server"));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152));
    let results = (0..64)
        .map(|_| {
            let server = Arc::clone(&server);
            let clock = Arc::clone(&clock);
            let random = Arc::clone(&server_random);
            let wire = wire.clone();
            thread::spawn(move || {
                let mut scratch = UdpPacketScratch::new();
                let pending = server
                    .prepare_request(clock.as_ref(), &wire, &mut scratch)
                    .expect("all copies authenticate");
                let (_, commit) = pending.into_parts();
                server.commit_request(
                    commit,
                    peer,
                    MonotonicInstant::from_duration(Duration::ZERO),
                    random.as_ref(),
                )
            })
        })
        .map(|handle| handle.join().expect("worker"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UdpPacketError::Duplicate)))
            .count(),
        63
    );
    assert_eq!(server.session_count().expect("state"), 1);
    let capability = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .expect("winner")
        .capability();
    let snapshot = server
        .session_snapshot(capability)
        .expect("snapshot")
        .expect("live session");
    assert_eq!(snapshot.highest_packet_id(), Some(0));
    assert_eq!(snapshot.peer(), peer);
}

#[test]
fn dropped_capacity_reservation_does_not_poison_replay_or_create_session() {
    let keys = udp_provider(MethodProfile::Blake3Aes256Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let client_random = FillRandom::new(0x10);
    let mut client = UdpClientSession::new(&keys, &client_random, |_| false).expect("client");
    let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("target");
    let request = Datagram::new(target, BytesMut::from(&b"reserve"[..]), 7).expect("datagram");
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; 65_507];
    let length = client
        .encode_request(&clock, &client_random, &request, 0, &mut wire, &mut scratch)
        .expect("request");
    let server = UdpServer::new(&keys).expect("server");

    let pending = server
        .prepare_request(&clock, &wire[..length], &mut scratch)
        .expect("authenticated request");
    drop(pending);
    assert_eq!(server.session_count().expect("state"), 0);

    let pending = server
        .prepare_request(&clock, &wire[..length], &mut scratch)
        .expect("same packet remains admissible");
    let (_, commit) = pending.into_parts();
    server
        .commit_request(
            commit,
            "127.0.0.1:49152".parse().expect("peer"),
            MonotonicInstant::ZERO,
            &FillRandom::new(0x80),
        )
        .expect("post-reservation commit");
    assert_eq!(server.session_count().expect("state"), 1);
}
