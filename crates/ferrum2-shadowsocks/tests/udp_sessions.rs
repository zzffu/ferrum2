mod common;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{MethodProfile, MonotonicInstant};
use ferrum2_shadowsocks::{
    ServerResponseCapability, UdpClientSession, UdpPacketError, UdpPacketScratch, UdpServer,
};

use common::{FakeClock, FillRandom, udp_provider};

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
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; 65_507];
    let length = client
        .encode_request(
            clock,
            random,
            &datagram(payload),
            0,
            &mut wire,
            &mut scratch,
        )
        .expect("request encodes");
    wire.truncate(length);
    wire
}

fn accept(
    server: &UdpServer,
    clock: &FakeClock,
    random: &FillRandom,
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
    let mut scratch = UdpPacketScratch::new();
    let mut wire = vec![0_u8; 65_507];
    let encoded = server
        .encode_response(
            capability,
            clock,
            random,
            &datagram(payload),
            0,
            &mut wire,
            &mut scratch,
        )
        .expect("response encodes");
    wire.truncate(encoded.wire_len());
    wire
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
    client
        .decode_response(&clock, &first, &mut scratch)
        .expect("first association");
    clock.set_monotonic_millis(1);
    client
        .decode_response(&clock, &second, &mut scratch)
        .expect("second association");
    let before = client.association_snapshot().expect("snapshot");
    assert_eq!(before.association_count(), 2);
    assert_eq!(before.old_last_valid(), Some(instant(0)));

    clock.set_monotonic_millis(59_999);
    assert!(matches!(
        client.decode_response(&clock, &third_early, &mut scratch),
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
        client.decode_response(&clock, &tampered_old, &mut scratch),
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
    client
        .decode_response(&clock, &third_at_boundary, &mut scratch)
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
            &mut scratch,
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
            &mut scratch,
        )
        .expect("replacement response");
    assert_eq!(encoded.peer(), peer_one);
}
