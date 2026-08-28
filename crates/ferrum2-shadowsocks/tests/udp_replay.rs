mod common;

use std::collections::BTreeSet;
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
fn replay_ring_uses_constant_work_for_sequential_ids_and_wraps_physical_head() {
    let mut window = UdpReplayWindow::new();
    window.commit(0).unwrap();
    assert_eq!(window.last_advance_word_clears(), 0);
    for packet_id in 1..=20_000 {
        window.commit(packet_id).unwrap();
        assert_eq!(window.last_advance_word_clears(), 1);
    }
    window.commit(20_063).unwrap();
    assert!(window.last_advance_word_clears() <= 2);
    window.commit(20_127).unwrap();
    assert!(window.last_advance_word_clears() <= 2);
    window.commit(20_192).unwrap();
    assert!(window.last_advance_word_clears() <= 2);
    window.commit(28_320).unwrap();
    assert!((127..=128).contains(&window.last_advance_word_clears()));
    window.commit(36_449).unwrap();
    assert_eq!(window.last_advance_word_clears(), 128);
}

#[test]
fn replay_ring_matches_reference_across_long_random_reorder_duplicate_and_jump_stream() {
    let mut ring = UdpReplayWindow::new();
    let mut reference = ReferenceReplay::default();
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut frontier = 100_000_u64;

    for iteration in 0..100_000_u64 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let packet_id = match seed & 7 {
            0..=2 => {
                frontier = frontier.saturating_add(seed % 67 + 1);
                frontier
            }
            3 => frontier.saturating_add(UDP_REPLAY_LAG + 1 + seed % 257),
            4 => frontier.saturating_sub(seed % (UDP_REPLAY_LAG + 65)),
            5 => frontier,
            6 => iteration % 17,
            _ => u64::MAX.saturating_sub(seed % (UDP_REPLAY_LAG + 2)),
        };
        let expected_check = reference.check(packet_id);
        assert_eq!(ring.check(packet_id), expected_check);
        let expected_commit = reference.commit(packet_id);
        assert_eq!(ring.commit(packet_id), expected_commit);
        assert_eq!(ring.highest(), reference.highest);
        if expected_commit.is_ok() && packet_id > frontier {
            frontier = packet_id;
        }
    }
}

#[derive(Default)]
struct ReferenceReplay {
    highest: Option<u64>,
    seen: BTreeSet<u64>,
}

impl ReferenceReplay {
    fn check(&self, packet_id: u64) -> Result<(), UdpPacketError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if packet_id > highest {
            return Ok(());
        }
        if highest - packet_id > UDP_REPLAY_LAG {
            return Err(UdpPacketError::TooOld);
        }
        if self.seen.contains(&packet_id) {
            Err(UdpPacketError::Duplicate)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, packet_id: u64) -> Result<(), UdpPacketError> {
        self.check(packet_id)?;
        if self.highest.is_none_or(|highest| packet_id > highest) {
            self.highest = Some(packet_id);
            let oldest = packet_id.saturating_sub(UDP_REPLAY_LAG);
            self.seen = self.seen.split_off(&oldest);
        }
        self.seen.insert(packet_id);
        Ok(())
    }
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
    let mut wire = vec![0_u8; 65_507];
    let wire_len = client
        .encode_request(clock.as_ref(), &client_random, &request, 0, &mut wire)
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
                let pending = match server.prepare_request(clock.as_ref(), &wire, &mut scratch) {
                    Ok(pending) => pending,
                    Err(error) => return Err(error),
                };
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
        .encode_request(&clock, &client_random, &request, 0, &mut wire)
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
