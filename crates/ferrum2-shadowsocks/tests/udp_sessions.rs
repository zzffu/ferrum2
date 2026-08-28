mod common;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Barrier, Condvar, Mutex, mpsc};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{MethodProfile, MonotonicInstant, RandomError, SecureRandom};
use ferrum2_shadowsocks::{
    ServerResponseCapability, UdpClientSession, UdpPacketError, UdpPacketScratch, UdpServer,
};

use common::{FakeClock, FillRandom, udp_provider};

#[derive(Default)]
struct BlockingRandomState {
    entered: bool,
    released: bool,
}

struct BlockingRandom {
    state: Mutex<BlockingRandomState>,
    changed: Condvar,
}

struct CountingFillRandom {
    next: Mutex<u8>,
    calls: AtomicUsize,
}

impl CountingFillRandom {
    fn new(first: u8) -> Self {
        Self {
            next: Mutex::new(first),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SecureRandom for CountingFillRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        let mut next = self.next.lock().expect("counting random");
        destination.fill(*next);
        *next = next.wrapping_add(1);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl BlockingRandom {
    fn new() -> Self {
        Self {
            state: Mutex::new(BlockingRandomState::default()),
            changed: Condvar::new(),
        }
    }

    fn wait_until_entered(&self) {
        let mut state = self.state.lock().expect("blocking random state");
        while !state.entered {
            state = self.changed.wait(state).expect("blocking random wait");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("blocking random state");
        state.released = true;
        self.changed.notify_all();
    }
}

impl SecureRandom for BlockingRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        let mut state = self.state.lock().expect("blocking random state");
        state.entered = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).expect("blocking random wait");
        }
        destination.fill(0xa5);
        Ok(())
    }
}

fn instant(millis: u64) -> MonotonicInstant {
    MonotonicInstant::from_duration(Duration::from_millis(millis))
}

fn target() -> TargetAddr {
    TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 25), 53)).expect("test target")
}

fn datagram(payload: &[u8]) -> Datagram {
    Datagram::new(target(), BytesMut::from(payload), payload.len()).expect("bounded datagram")
}

fn request_wire(
    client: &mut UdpClientSession,
    clock: &FakeClock,
    random: &FillRandom,
    payload: &[u8],
) -> Vec<u8> {
    let mut wire = vec![0_u8; 65_507];
    let length = client
        .encode_request(clock, random, &datagram(payload), 0, &mut wire)
        .expect("request encodes");
    wire.truncate(length);
    wire
}

fn accept(
    server: &UdpServer,
    clock: &FakeClock,
    random: &(impl SecureRandom + ?Sized),
    wire: &[u8],
    peer: SocketAddr,
    now_millis: u64,
) -> ServerResponseCapability {
    let mut scratch = UdpPacketScratch::new();
    let pending = server
        .prepare_request(clock, wire, &mut scratch)
        .expect("request validates");
    let (_, commit) = pending.into_parts();
    server
        .commit_request(commit, peer, instant(now_millis), random)
        .expect("reserved request commits")
        .capability()
}

fn response_wire(
    server: &UdpServer,
    capability: ServerResponseCapability,
    clock: &FakeClock,
    random: &FillRandom,
    payload: &[u8],
) -> Vec<u8> {
    let mut wire = vec![0_u8; 65_507];
    let encoded = server
        .encode_response(capability, clock, random, &datagram(payload), 0, &mut wire)
        .expect("response encodes");
    wire.truncate(encoded.wire_len());
    wire
}

fn accept_response(
    client: &UdpClientSession,
    clock: &FakeClock,
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
    now_millis: u64,
) -> Result<Datagram, UdpPacketError> {
    let pending = client.prepare_response(clock, wire, scratch)?;
    let (datagram, commit) = pending.into_parts();
    client.commit_response(commit, instant(now_millis))?;
    Ok(datagram)
}

#[test]
fn dropped_client_reservations_leave_response_admissible_and_concurrent_commit_rechecks() {
    let keys = udp_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let client_random = FillRandom::new(0x10);
    let server_random = FillRandom::new(0x80);
    let mut client =
        UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
    let server = UdpServer::new(&keys).expect("server");
    let request = request_wire(&mut client, &clock, &client_random, b"request");
    let capability = accept(
        &server,
        &clock,
        &server_random,
        &request,
        "127.0.0.1:49152".parse().expect("peer"),
        0,
    );
    let response = response_wire(&server, capability, &clock, &server_random, b"response");
    let empty = client.association_snapshot().expect("empty snapshot");

    for _simulated_failure in ["buffer", "queue", "cancelled", "generation"] {
        let mut scratch = UdpPacketScratch::new();
        let pending = client
            .prepare_response(&clock, &response, &mut scratch)
            .expect("authentication remains admissible");
        drop(pending);
        assert_eq!(client.association_snapshot().expect("unchanged"), empty);
    }

    let mut first_scratch = UdpPacketScratch::new();
    let mut second_scratch = UdpPacketScratch::new();
    let (_, first_commit) = client
        .prepare_response(&clock, &response, &mut first_scratch)
        .expect("first pending")
        .into_parts();
    let (_, second_commit) = client
        .prepare_response(&clock, &response, &mut second_scratch)
        .expect("stale pending")
        .into_parts();
    let results = std::thread::scope(|scope| {
        let client_ref = &client;
        let first = scope.spawn(move || client_ref.commit_response(first_commit, instant(1)));
        let second = scope.spawn(move || client_ref.commit_response(second_commit, instant(1)));
        [
            first.join().expect("first worker"),
            second.join().expect("second worker"),
        ]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(UdpPacketError::Duplicate)))
            .count(),
        1
    );
    assert_eq!(
        client
            .association_snapshot()
            .expect("accepted snapshot")
            .association_count(),
        1
    );
}

#[test]
fn client_retains_current_and_old_and_rotates_at_exactly_sixty_seconds() {
    let keys = udp_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let client_random = FillRandom::new(0x10);
    let mut client =
        UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
    let servers = [
        UdpServer::new(&keys).expect("server one"),
        UdpServer::new(&keys).expect("server two"),
        UdpServer::new(&keys).expect("server three"),
    ];
    let server_randoms = [
        FillRandom::new(0x80),
        FillRandom::new(0x90),
        FillRandom::new(0xa0),
    ];
    let peer: SocketAddr = "127.0.0.1:49152".parse().expect("peer");
    let requests = [
        request_wire(&mut client, &clock, &client_random, b"one"),
        request_wire(&mut client, &clock, &client_random, b"two"),
        request_wire(&mut client, &clock, &client_random, b"three"),
    ];
    let capabilities = [
        accept(
            &servers[0],
            &clock,
            &server_randoms[0],
            &requests[0],
            peer,
            0,
        ),
        accept(
            &servers[1],
            &clock,
            &server_randoms[1],
            &requests[1],
            peer,
            1,
        ),
        accept(
            &servers[2],
            &clock,
            &server_randoms[2],
            &requests[2],
            peer,
            2,
        ),
    ];

    let first = response_wire(
        &servers[0],
        capabilities[0],
        &clock,
        &server_randoms[0],
        b"first",
    );
    let second = response_wire(
        &servers[1],
        capabilities[1],
        &clock,
        &server_randoms[1],
        b"second",
    );
    let third_early = response_wire(
        &servers[2],
        capabilities[2],
        &clock,
        &server_randoms[2],
        b"early",
    );
    let mut scratch = UdpPacketScratch::new();
    accept_response(&client, &clock, &first, &mut scratch, 0).expect("first association");
    clock.set_monotonic_millis(1);
    accept_response(&client, &clock, &second, &mut scratch, 1).expect("second association");
    let before = client.association_snapshot().expect("snapshot");
    assert_eq!(before.association_count(), 2);
    assert_eq!(before.old_last_valid(), Some(instant(0)));

    clock.set_monotonic_millis(59_999);
    assert!(matches!(
        accept_response(&client, &clock, &third_early, &mut scratch, 59_999),
        Err(UdpPacketError::AssociationLimit)
    ));
    assert_eq!(
        client.association_snapshot().expect("unchanged"),
        before,
        "rejected third association must not refresh age or rotate state"
    );

    let mut tampered_old = response_wire(
        &servers[0],
        capabilities[0],
        &clock,
        &server_randoms[0],
        b"tampered",
    );
    *tampered_old.last_mut().expect("tag byte") ^= 1;
    assert!(matches!(
        accept_response(&client, &clock, &tampered_old, &mut scratch, 59_999),
        Err(UdpPacketError::Authentication)
    ));
    assert_eq!(client.association_snapshot().expect("unchanged"), before);

    let third_at_boundary = response_wire(
        &servers[2],
        capabilities[2],
        &clock,
        &server_randoms[2],
        b"boundary",
    );
    clock.set_monotonic_millis(60_000);
    accept_response(&client, &clock, &third_at_boundary, &mut scratch, 60_000)
        .expect("old association rotates at exactly sixty seconds");
    let after = client.association_snapshot().expect("rotated");
    assert_eq!(after.association_count(), 2);
    assert_eq!(after.current_last_valid(), Some(instant(60_000)));
    assert_eq!(after.old_last_valid(), Some(instant(1)));
}

#[test]
fn server_routes_by_authenticated_id_supports_roaming_and_rejects_stale_generation() {
    let keys = udp_provider(MethodProfile::Blake3ChaCha20Poly13052022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let server_random = FillRandom::new(0x80);
    let server = UdpServer::new(&keys).expect("server");
    let first_random = FillRandom::new(0x10);
    let second_random = FillRandom::new(0x40);
    let mut first =
        UdpClientSession::new(&keys, &first_random, |_| false).expect("first client ID");
    let mut second =
        UdpClientSession::new(&keys, &second_random, |_| false).expect("second client ID");
    let peer_one: SocketAddr = "127.0.0.1:49152".parse().expect("peer one");
    let peer_two: SocketAddr = "127.0.0.2:49153".parse().expect("peer two");

    let first_wire = request_wire(&mut first, &clock, &first_random, b"first");
    let first_capability = accept(&server, &clock, &server_random, &first_wire, peer_one, 0);
    let roaming_wire = request_wire(&mut first, &clock, &first_random, b"roam");
    let roaming_capability = accept(&server, &clock, &server_random, &roaming_wire, peer_two, 10);
    assert_eq!(roaming_capability, first_capability);
    let roaming = server
        .session_snapshot(first_capability)
        .expect("snapshot")
        .expect("live");
    assert_eq!(roaming.peer(), peer_two);
    assert_eq!(roaming.highest_packet_id(), Some(1));
    assert_eq!(roaming.last_activity(), instant(10));

    let second_wire = request_wire(&mut second, &clock, &second_random, b"second");
    let second_capability = accept(&server, &clock, &server_random, &second_wire, peer_two, 20);
    assert_ne!(second_capability, first_capability);
    assert_eq!(server.session_count().expect("count"), 2);

    let mut invalid = request_wire(&mut first, &clock, &first_random, b"invalid");
    *invalid.last_mut().expect("tag") ^= 1;
    let mut scratch = UdpPacketScratch::new();
    assert!(matches!(
        server.prepare_request(&clock, &invalid, &mut scratch),
        Err(UdpPacketError::Authentication)
    ));
    assert_eq!(
        server
            .session_snapshot(first_capability)
            .expect("snapshot")
            .expect("live"),
        roaming
    );

    assert!(
        !server
            .remove_session(first_capability, instant(60_009))
            .expect("retention check")
    );
    assert!(
        server
            .remove_session(first_capability, instant(60_010))
            .expect("expiry")
    );
    let recreate_wire = request_wire(&mut first, &clock, &first_random, b"recreate");
    let replacement = accept(
        &server,
        &clock,
        &server_random,
        &recreate_wire,
        peer_one,
        60_010,
    );
    assert_ne!(replacement, first_capability);

    let mut output = vec![0_u8; 65_507];
    assert_eq!(
        server.encode_response(
            first_capability,
            &clock,
            &server_random,
            &datagram(b"late"),
            0,
            &mut output,
        ),
        Err(UdpPacketError::Generation)
    );
    let encoded = server
        .encode_response(
            replacement,
            &clock,
            &server_random,
            &datagram(b"new"),
            0,
            &mut output,
        )
        .expect("replacement response");
    assert_eq!(encoded.peer(), peer_one);
}

#[test]
fn outbound_session_index_reuses_removed_ids_without_stale_generation_cleanup() {
    let keys = udp_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let server = UdpServer::new(&keys).expect("server");
    let peer: SocketAddr = "127.0.0.1:49152".parse().expect("peer");

    let mut first_client =
        UdpClientSession::new(&keys, &FillRandom::new(0x10), |_| false).expect("first client");
    let first_client_random = FillRandom::new(0x20);
    let first_wire = request_wire(&mut first_client, &clock, &first_client_random, b"first");
    let first_random = CountingFillRandom::new(0x80);
    let first = accept(&server, &clock, &first_random, &first_wire, peer, 0);
    assert_eq!(first_random.calls(), 1);

    let mut second_client =
        UdpClientSession::new(&keys, &FillRandom::new(0x30), |_| false).expect("second client");
    let second_client_random = FillRandom::new(0x40);
    let second_wire = request_wire(&mut second_client, &clock, &second_client_random, b"second");
    let colliding_random = CountingFillRandom::new(0x80);
    let second = accept(&server, &clock, &colliding_random, &second_wire, peer, 0);
    assert_ne!(second, first);
    assert_eq!(colliding_random.calls(), 2, "live outbound ID retries once");

    assert!(
        server
            .remove_session(first, instant(60_000))
            .expect("first removal")
    );

    let mut third_client =
        UdpClientSession::new(&keys, &FillRandom::new(0x50), |_| false).expect("third client");
    let third_client_random = FillRandom::new(0x60);
    let third_wire = request_wire(&mut third_client, &clock, &third_client_random, b"third");
    let reused_random = CountingFillRandom::new(0x80);
    let third = accept(&server, &clock, &reused_random, &third_wire, peer, 60_000);
    assert_eq!(reused_random.calls(), 1, "removed outbound ID is reusable");
    assert!(
        !server
            .remove_session(first, instant(120_000))
            .expect("stale removal")
    );

    let mut fourth_client =
        UdpClientSession::new(&keys, &FillRandom::new(0x70), |_| false).expect("fourth client");
    let fourth_client_random = FillRandom::new(0x71);
    let fourth_wire = request_wire(&mut fourth_client, &clock, &fourth_client_random, b"fourth");
    let generation_safe_random = CountingFillRandom::new(0x80);
    let fourth = accept(
        &server,
        &clock,
        &generation_safe_random,
        &fourth_wire,
        peer,
        120_000,
    );
    assert_ne!(fourth, third);
    assert_eq!(
        generation_safe_random.calls(),
        3,
        "stale cleanup must retain both reused and independently live outbound IDs"
    );
    assert_eq!(server.session_count().expect("live index count"), 3);
}

#[test]
fn capability_index_survives_middle_removal_and_generation_replacement() {
    const SESSION_COUNT: u8 = 64;
    const VICTIM: usize = 31;

    let keys = udp_provider(MethodProfile::Blake3Aes128Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let server_random = FillRandom::new(0x80);
    let server = UdpServer::new(&keys).expect("server");
    let peer: SocketAddr = "127.0.0.1:49152".parse().expect("peer");
    let mut capabilities = Vec::with_capacity(usize::from(SESSION_COUNT));
    let mut victim = None;

    for index in 0..SESSION_COUNT {
        let random = FillRandom::new(index + 1);
        let mut client =
            UdpClientSession::new(&keys, &random, |_| false).expect("distinct client session");
        let wire = request_wire(&mut client, &clock, &random, b"request");
        capabilities.push(accept(&server, &clock, &server_random, &wire, peer, 0));
        if usize::from(index) == VICTIM {
            victim = Some((client, random));
        }
    }

    let stale = capabilities[VICTIM];
    assert!(
        server
            .remove_session(stale, instant(60_000))
            .expect("middle generation removal")
    );
    assert_eq!(
        server.session_count().expect("session count"),
        usize::from(SESSION_COUNT) - 1
    );
    assert_eq!(server.session_snapshot(stale).expect("stale lookup"), None);
    assert!(
        server
            .session_snapshot(capabilities[VICTIM - 1])
            .expect("preceding lookup")
            .is_some()
    );
    assert!(
        server
            .session_snapshot(capabilities[VICTIM + 1])
            .expect("following lookup")
            .is_some()
    );

    let (mut victim_client, victim_random) = victim.expect("retained victim client");
    let replacement_wire = request_wire(&mut victim_client, &clock, &victim_random, b"replacement");
    let replacement = accept(
        &server,
        &clock,
        &server_random,
        &replacement_wire,
        peer,
        60_000,
    );
    assert_ne!(replacement, stale);
    assert_eq!(
        server.session_count().expect("restored session count"),
        usize::from(SESSION_COUNT)
    );
    assert!(
        server
            .session_snapshot(replacement)
            .expect("replacement lookup")
            .is_some()
    );

    let mut output = vec![0_u8; 65_507];
    assert_eq!(
        server.encode_response(
            stale,
            &clock,
            &server_random,
            &datagram(b"stale"),
            0,
            &mut output,
        ),
        Err(UdpPacketError::Generation)
    );
}

#[test]
fn different_sessions_encode_concurrently_while_one_session_preserves_nonce_order() {
    let keys = udp_provider(MethodProfile::Blake3ChaCha20Poly13052022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let first_random = FillRandom::new(0x10);
    let second_random = FillRandom::new(0x20);
    let server_random = FillRandom::new(0x80);
    let mut first_client =
        UdpClientSession::new(&keys, &first_random, |_| false).expect("first client");
    let mut second_client =
        UdpClientSession::new(&keys, &second_random, |_| false).expect("second client");
    let server = UdpServer::new(&keys).expect("server");
    let first_request = request_wire(&mut first_client, &clock, &first_random, b"first");
    let second_request = request_wire(&mut second_client, &clock, &second_random, b"second");
    let first_capability = accept(
        &server,
        &clock,
        &server_random,
        &first_request,
        "127.0.0.1:49152".parse().expect("first peer"),
        0,
    );
    let second_capability = accept(
        &server,
        &clock,
        &server_random,
        &second_request,
        "127.0.0.2:49153".parse().expect("second peer"),
        0,
    );
    let blocking_random = BlockingRandom::new();
    let worker_start = Barrier::new(3);
    let (completed_tx, completed_rx) = mpsc::channel();

    let (first_wire, different_wire, same_wire) = std::thread::scope(|scope| {
        let first_server = &server;
        let first_clock = &clock;
        let first_blocking_random = &blocking_random;
        let first_worker = scope.spawn(move || -> Result<Vec<u8>, UdpPacketError> {
            let mut output = vec![0_u8; 65_507];
            let encoded = first_server.encode_response(
                first_capability,
                first_clock,
                first_blocking_random,
                &datagram(b"first response"),
                0,
                &mut output,
            )?;
            output.truncate(encoded.wire_len());
            Ok(output)
        });
        blocking_random.wait_until_entered();

        let different_tx = completed_tx.clone();
        let different_start = &worker_start;
        let different_server = &server;
        let different_clock = &clock;
        let different_worker = scope.spawn(move || {
            different_start.wait();
            let random = FillRandom::new(0xb0);
            let mut output = vec![0_u8; 65_507];
            let result = different_server
                .encode_response(
                    second_capability,
                    different_clock,
                    &random,
                    &datagram(b"different session"),
                    0,
                    &mut output,
                )
                .map(|encoded| {
                    output.truncate(encoded.wire_len());
                    output
                });
            different_tx
                .send(("different", result))
                .expect("different completion receiver");
        });

        let same_tx = completed_tx.clone();
        let same_start = &worker_start;
        let same_server = &server;
        let same_clock = &clock;
        let same_worker = scope.spawn(move || {
            same_start.wait();
            let random = FillRandom::new(0xc0);
            let mut output = vec![0_u8; 65_507];
            let result = same_server
                .encode_response(
                    first_capability,
                    same_clock,
                    &random,
                    &datagram(b"same session"),
                    0,
                    &mut output,
                )
                .map(|encoded| {
                    output.truncate(encoded.wire_len());
                    output
                });
            same_tx
                .send(("same", result))
                .expect("same completion receiver");
        });

        worker_start.wait();
        let first_completion = completed_rx.recv_timeout(Duration::from_secs(5));
        blocking_random.release();
        let (first_label, first_result) =
            first_completion.expect("another session must not wait for the blocked nonce owner");
        assert_eq!(first_label, "different");
        let different_wire = first_result.expect("different session response");

        let (second_label, second_result) = completed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("same session resumes after its nonce owner");
        assert_eq!(second_label, "same");
        let same_wire = second_result.expect("same session response");
        let first_wire = first_worker
            .join()
            .expect("blocked response worker")
            .expect("first session response");
        different_worker.join().expect("different worker");
        same_worker.join().expect("same worker");
        (first_wire, different_wire, same_wire)
    });

    let mut first_scratch = UdpPacketScratch::new();
    assert_eq!(
        accept_response(&first_client, &clock, &first_wire, &mut first_scratch, 1)
            .expect("first ordered response")
            .payload(),
        b"first response"
    );
    assert_eq!(
        accept_response(&first_client, &clock, &same_wire, &mut first_scratch, 2)
            .expect("second ordered response")
            .payload(),
        b"same session"
    );
    let mut second_scratch = UdpPacketScratch::new();
    assert_eq!(
        accept_response(
            &second_client,
            &clock,
            &different_wire,
            &mut second_scratch,
            1,
        )
        .expect("independent response")
        .payload(),
        b"different session"
    );
}

#[test]
fn concurrent_expiry_and_request_commit_never_returns_a_stale_capability() {
    let keys = udp_provider(MethodProfile::Blake3Aes256Gcm2022);
    let clock = FakeClock::new(1_700_000_000, 0);
    let old_peer: SocketAddr = "127.0.0.1:49152".parse().expect("old peer");
    let new_peer: SocketAddr = "127.0.0.2:49153".parse().expect("new peer");

    for case in 0..32_u8 {
        let client_random = FillRandom::new(0x10 + case);
        let server_random = FillRandom::new(0x80);
        let mut client =
            UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
        let server = UdpServer::new(&keys).expect("server");
        let first_wire = request_wire(&mut client, &clock, &client_random, b"first");
        let old_capability = accept(&server, &clock, &server_random, &first_wire, old_peer, 0);
        let next_wire = request_wire(&mut client, &clock, &client_random, b"next");
        let mut scratch = UdpPacketScratch::new();
        let (_, commit) = server
            .prepare_request(&clock, &next_wire, &mut scratch)
            .expect("next request prepares")
            .into_parts();
        let start = Barrier::new(3);

        let (removed, accepted) = std::thread::scope(|scope| {
            let remove_start = &start;
            let remove = scope.spawn(|| {
                remove_start.wait();
                server.remove_session(old_capability, instant(60_000))
            });
            let commit_start = &start;
            let commit = scope.spawn(|| {
                commit_start.wait();
                server.commit_request(commit, new_peer, instant(60_000), &server_random)
            });
            start.wait();
            (
                remove.join().expect("remove worker").expect("remove state"),
                commit
                    .join()
                    .expect("commit worker")
                    .expect("request commit"),
            )
        });

        let accepted_capability = accepted.capability();
        let snapshot = server
            .session_snapshot(accepted_capability)
            .expect("accepted lookup")
            .expect("accepted generation stays live");
        assert_eq!(snapshot.peer(), new_peer);
        assert_eq!(snapshot.last_activity(), instant(60_000));
        assert_eq!(snapshot.highest_packet_id(), Some(1));
        assert_eq!(server.session_count().expect("single session"), 1);
        if removed {
            assert_ne!(accepted_capability, old_capability);
            assert_eq!(
                server
                    .session_snapshot(old_capability)
                    .expect("stale lookup"),
                None
            );
        } else {
            assert_eq!(accepted_capability, old_capability);
        }
    }
}
