mod common;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{
    KeySelector, MethodKeyProvider, MethodProfile, MethodPsk, MethodSinglePskProvider,
    MonotonicInstant, UdpCrypto,
};
use ferrum2_shadowsocks::{
    MAX_UDP_WIRE_LEN, MethodKeyAdapter, UdpClientSession, UdpPacketError, UdpPacketScratch,
    UdpServer, max_udp_payload_len,
};

use serde_json::Value;

use common::{FakeClock, FillRandom, NOW, ScriptedRandom, udp_provider};

const UDP_FIXTURE: &str = include_str!("../../../tests/fixtures/sip022/sip022-udp-v1.json");

fn datagram(target: TargetAddr, payload: &[u8]) -> Datagram {
    Datagram::new(target, BytesMut::from(payload), payload.len()).expect("bounded datagram")
}

fn raw_packet(crypto: &UdpCrypto, session_byte: u8, body: &[u8], random: &FillRandom) -> Vec<u8> {
    let session_random = FillRandom::new(session_byte);
    let mut outbound = crypto
        .generate_outbound_session(&session_random, |_| false)
        .expect("raw fixture session");
    let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
    let sealed = crypto
        .seal(&mut outbound, body, &mut wire, random)
        .expect("raw packet seals");
    wire.truncate(sealed.wire_len());
    wire
}

fn raw_request_body(message_type: u8, timestamp: u64, padding_len: u16) -> Vec<u8> {
    let mut body = vec![message_type];
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&padding_len.to_be_bytes());
    body.extend_from_slice(&[1, 192, 0, 2, 1, 0, 53]);
    body.extend_from_slice(b"payload");
    body
}

fn fixture_profile(method: &str) -> MethodProfile {
    MethodProfile::ALL
        .into_iter()
        .find(|profile| profile.canonical_name() == method)
        .expect("supported fixture method")
}

fn fixture_target(kind: &str) -> TargetAddr {
    match kind {
        "ipv4" => TargetAddr::ip("192.0.2.1:53".parse().expect("IPv4")).expect("target"),
        "ipv6" => TargetAddr::ip("[2001:db8::1]:5353".parse().expect("IPv6")).expect("target"),
        "domain" => TargetAddr::domain("example.test", 8443).expect("target"),
        other => panic!("unexpected target kind {other}"),
    }
}

fn accept_response(
    client: &UdpClientSession,
    clock: &FakeClock,
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
) -> Result<Datagram, UdpPacketError> {
    let pending = client.prepare_response(clock, wire, scratch)?;
    let (datagram, commit) = pending.into_parts();
    client.commit_response(commit, MonotonicInstant::ZERO)?;
    Ok(datagram)
}

#[test]
fn three_method_request_response_table_round_trips_every_address_kind() {
    let cases = [
        (
            MethodProfile::Blake3Aes128Gcm2022,
            TargetAddr::ip(SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53))
                .expect("IPv4 target"),
        ),
        (
            MethodProfile::Blake3Aes256Gcm2022,
            TargetAddr::ip(SocketAddr::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(),
                5353,
            ))
            .expect("IPv6 target"),
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            TargetAddr::domain("example.test", 8443).expect("domain target"),
        ),
        (
            MethodProfile::Blake3Aes128Gcm2022,
            TargetAddr::domain("a", 443).expect("one-byte domain"),
        ),
        (
            MethodProfile::Blake3ChaCha20Poly13052022,
            TargetAddr::domain(&"x".repeat(255), 443).expect("255-byte domain"),
        ),
    ];

    for (profile, target) in cases {
        let keys = MethodKeyAdapter::new(udp_provider(profile));
        let client_random = FillRandom::new(0x10);
        let server_random = FillRandom::new(0x80);
        let clock = FakeClock::new(1_700_000_000, 0);
        let mut client =
            UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
        let server = UdpServer::new(&keys).expect("server protocol");
        let request = datagram(target.clone(), b"request payload");
        let mut request_scratch = UdpPacketScratch::new();
        let mut request_wire = vec![0_u8; 65_507];

        let request_len = client
            .encode_request(
                &clock,
                &client_random,
                &request,
                7,
                &mut request_wire,
                &mut request_scratch,
            )
            .expect("request encodes");
        let pending = server
            .prepare_request(&clock, &request_wire[..request_len], &mut request_scratch)
            .expect("request authenticates and validates");
        assert_eq!(pending.datagram().target(), &target);
        assert_eq!(pending.datagram().payload(), b"request payload");
        let (opened_request, commit) = pending.into_parts();
        let peer = "127.0.0.1:49152".parse().expect("peer");
        let accepted = server
            .commit_request(
                commit,
                peer,
                MonotonicInstant::from_duration(Duration::ZERO),
                &server_random,
            )
            .expect("reserved request commits");
        assert_eq!(opened_request.target(), &target);

        let response = datagram(target.clone(), b"response payload");
        let mut response_scratch = UdpPacketScratch::new();
        let mut response_wire = vec![0_u8; 65_507];
        let encoded = server
            .encode_response(
                accepted.capability(),
                &clock,
                &server_random,
                &response,
                5,
                &mut response_wire,
                &mut response_scratch,
            )
            .expect("response encodes");
        assert_eq!(encoded.peer(), peer);
        let opened_response = accept_response(
            &client,
            &clock,
            &response_wire[..encoded.wire_len()],
            &mut response_scratch,
        )
        .expect("response authenticates, binds, and commits");
        assert_eq!(opened_response.target(), &target);
        assert_eq!(opened_response.payload(), b"response payload");
    }
}

#[test]
fn complete_wire_bound_is_exact_and_failed_capacity_does_not_consume_packet_id() {
    for profile in MethodProfile::ALL {
        let keys = udp_provider(profile);
        let random = FillRandom::new(0x20);
        let clock = FakeClock::new(NOW, 0);
        let mut client = UdpClientSession::new(&keys, &random, |_| false).expect("client session");
        let server = UdpServer::new(&keys).expect("server");
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("target");
        let maximum =
            max_udp_payload_len(profile, false, &target, 0).expect("checked payload maximum");
        let maximum_datagram = datagram(target.clone(), &vec![0x5a; maximum]);
        let mut scratch = UdpPacketScratch::new();
        let identity = scratch.storage_identity();
        let mut short = vec![0_u8; MAX_UDP_WIRE_LEN - 1];
        assert_eq!(
            client.encode_request(
                &clock,
                &random,
                &maximum_datagram,
                0,
                &mut short,
                &mut scratch,
            ),
            Err(UdpPacketError::Bounds)
        );

        let mut wire = vec![0_u8; MAX_UDP_WIRE_LEN];
        let wire_len = client
            .encode_request(
                &clock,
                &random,
                &maximum_datagram,
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("exact maximum");
        assert_eq!(wire_len, MAX_UDP_WIRE_LEN);
        assert_eq!(scratch.storage_identity(), identity);
        let pending = server
            .prepare_request(&clock, &wire, &mut scratch)
            .expect("maximum authenticates");
        let (_, commit) = pending.into_parts();
        let accepted = server
            .commit_request(
                commit,
                "127.0.0.1:49152".parse().expect("peer"),
                MonotonicInstant::ZERO,
                &FillRandom::new(0x80),
            )
            .expect("maximum commits");
        assert_eq!(
            server
                .session_snapshot(accepted.capability())
                .expect("snapshot")
                .expect("live")
                .highest_packet_id(),
            Some(0),
            "short output must not consume the first packet ID"
        );

        let oversized = datagram(target, &vec![0x5a; maximum + 1]);
        assert_eq!(
            client.encode_request(&clock, &random, &oversized, 0, &mut wire, &mut scratch,),
            Err(UdpPacketError::Bounds)
        );
    }
}

#[test]
fn authenticated_semantic_negative_table_has_zero_server_mutation() {
    let profile = MethodProfile::Blake3Aes128Gcm2022;
    let keys = udp_provider(profile);
    let crypto = keys
        .with_method_key(KeySelector::Default, |key| key.udp_crypto())
        .expect("key");
    let server = UdpServer::new(&keys).expect("server");
    let clock = FakeClock::new(NOW, 0);
    let packet_random = FillRandom::new(0x30);
    let mut invalid_padding = vec![0];
    invalid_padding.extend_from_slice(&NOW.to_be_bytes());
    invalid_padding.extend_from_slice(&2_u16.to_be_bytes());
    invalid_padding.push(0xa1);
    let mut invalid_address = vec![0];
    invalid_address.extend_from_slice(&NOW.to_be_bytes());
    invalid_address.extend_from_slice(&0_u16.to_be_bytes());
    invalid_address.extend_from_slice(&[0xff, 1, 2, 3]);
    let mut zero_port = vec![0];
    zero_port.extend_from_slice(&NOW.to_be_bytes());
    zero_port.extend_from_slice(&0_u16.to_be_bytes());
    zero_port.extend_from_slice(&[1, 192, 0, 2, 1, 0, 0]);
    let mut empty_domain = vec![0];
    empty_domain.extend_from_slice(&NOW.to_be_bytes());
    empty_domain.extend_from_slice(&0_u16.to_be_bytes());
    empty_domain.extend_from_slice(&[3, 0, 0, 53]);
    let mut non_ascii_domain = vec![0];
    non_ascii_domain.extend_from_slice(&NOW.to_be_bytes());
    non_ascii_domain.extend_from_slice(&0_u16.to_be_bytes());
    non_ascii_domain.extend_from_slice(&[3, 1, 0xff, 0, 53]);
    let cases = [
        (
            raw_packet(&crypto, 0x40, &raw_request_body(1, NOW, 0), &packet_random),
            UdpPacketError::Type,
        ),
        (
            raw_packet(
                &crypto,
                0x41,
                &raw_request_body(0, NOW - 31, 0),
                &packet_random,
            ),
            UdpPacketError::Timestamp,
        ),
        (
            raw_packet(&crypto, 0x42, &invalid_padding, &packet_random),
            UdpPacketError::Padding,
        ),
        (
            raw_packet(&crypto, 0x43, &invalid_address, &packet_random),
            UdpPacketError::Address,
        ),
        (
            raw_packet(&crypto, 0x44, &zero_port, &packet_random),
            UdpPacketError::Address,
        ),
        (
            raw_packet(&crypto, 0x45, &empty_domain, &packet_random),
            UdpPacketError::Address,
        ),
        (
            raw_packet(&crypto, 0x46, &non_ascii_domain, &packet_random),
            UdpPacketError::Address,
        ),
    ];
    let mut scratch = UdpPacketScratch::new();
    for (wire, expected) in cases {
        assert!(matches!(
            server.prepare_request(&clock, &wire, &mut scratch),
            Err(error) if error == expected
        ));
        assert_eq!(server.session_count().expect("state"), 0);
    }

    let mut tampered = raw_packet(&crypto, 0x47, &raw_request_body(0, NOW, 0), &packet_random);
    *tampered.last_mut().expect("tag") ^= 1;
    assert!(matches!(
        server.prepare_request(&clock, &tampered, &mut scratch),
        Err(UdpPacketError::Authentication)
    ));
    tampered.pop();
    assert!(matches!(
        server.prepare_request(&clock, &tampered, &mut scratch),
        Err(UdpPacketError::Authentication)
    ));
    let oversized = vec![0_u8; MAX_UDP_WIRE_LEN + 1];
    assert!(matches!(
        server.prepare_request(&clock, &oversized, &mut scratch),
        Err(UdpPacketError::Bounds)
    ));
    assert_eq!(server.session_count().expect("state"), 0);
}

#[test]
fn authenticated_response_with_wrong_client_binding_is_rejected_without_association() {
    let profile = MethodProfile::Blake3ChaCha20Poly13052022;
    let keys = udp_provider(profile);
    let crypto = keys
        .with_method_key(KeySelector::Default, |key| key.udp_crypto())
        .expect("key");
    let client_random = FillRandom::new(0x10);
    let client = UdpClientSession::new(&keys, &client_random, |_| false).expect("client session");
    let mut body = vec![1];
    body.extend_from_slice(&NOW.to_be_bytes());
    body.extend_from_slice(&[0xff; 8]);
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&[1, 192, 0, 2, 1, 0, 53]);
    body.extend_from_slice(b"response");
    let wire = raw_packet(&crypto, 0x80, &body, &FillRandom::new(0x90));
    let clock = FakeClock::new(NOW, 0);
    let mut scratch = UdpPacketScratch::new();
    assert!(matches!(
        client.prepare_response(&clock, &wire, &mut scratch),
        Err(UdpPacketError::Binding)
    ));
    assert_eq!(
        client
            .association_snapshot()
            .expect("association snapshot")
            .association_count(),
        0
    );
}

#[test]
fn independent_three_method_composite_fixture_matches_exact_request_and_response_wire() {
    let fixture: Value = serde_json::from_str(UDP_FIXTURE).expect("valid UDP fixture");
    let cases = fixture["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), MethodProfile::ALL.len());
    let provenance = include_str!("../../../tests/fixtures/sip022/PROVENANCE.toml");
    assert!(provenance.contains(
        "fixture_sha256 = \"ad74ba801eb8c0249af74708b88d88c6887375743409723172204c38d3b28240\""
    ));
    assert!(provenance.contains(
        "generator_sha256 = \"5d06c7ef76d85ceb446c5c1895e79fc56f60bea36b50c4b9dde5dba626599e06\""
    ));
    assert!(!include_str!("../../../tests/fixtures/sip022/udp_generator.rs").contains("ferrum2_"));

    for case in cases {
        let profile = fixture_profile(case["method"].as_str().expect("method"));
        let psk = hex::decode(case["psk"].as_str().expect("PSK")).expect("PSK");
        let keys = MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, &psk).expect("fixture PSK"),
        );
        let target = fixture_target(case["target_kind"].as_str().expect("target kind"));
        let request_payload =
            hex::decode(case["request_payload"].as_str().expect("payload")).expect("payload");
        let response_payload =
            hex::decode(case["response_payload"].as_str().expect("payload")).expect("payload");
        let padding = hex::decode(case["padding"].as_str().expect("padding")).expect("padding");
        let packet_id = case["packet_id"].as_u64().expect("packet ID");
        let mut client_random_bytes =
            hex::decode(case["client_session_id"].as_str().expect("client ID")).expect("client ID");
        if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            for prior in 0..packet_id {
                client_random_bytes.extend_from_slice(&[0xd0 + prior as u8; 24]);
            }
        }
        client_random_bytes.extend_from_slice(&padding);
        if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            client_random_bytes.extend_from_slice(
                &hex::decode(case["request_nonce"].as_str().expect("request nonce"))
                    .expect("request nonce"),
            );
        }
        let client_random = ScriptedRandom::new(client_random_bytes);
        let clock = FakeClock::new(NOW, 0);
        let mut client = UdpClientSession::new(&keys, &client_random, |_| false).expect("client");
        let mut scratch = UdpPacketScratch::new();
        let mut output = vec![0_u8; MAX_UDP_WIRE_LEN];
        for _ in 0..packet_id {
            client
                .encode_request(
                    &clock,
                    &client_random,
                    &datagram(target.clone(), b"prior"),
                    0,
                    &mut output,
                    &mut scratch,
                )
                .expect("preceding request");
        }
        let request_len = client
            .encode_request(
                &clock,
                &client_random,
                &datagram(target.clone(), &request_payload),
                padding.len(),
                &mut output,
                &mut scratch,
            )
            .expect("fixture request");
        assert_eq!(
            hex::encode(&output[..request_len]),
            case["request_wire"].as_str().expect("request wire"),
            "{} request",
            profile.canonical_name()
        );

        let server = UdpServer::new(&keys).expect("server");
        let pending = server
            .prepare_request(&clock, &output[..request_len], &mut scratch)
            .expect("fixture request opens");
        assert_eq!(pending.datagram().target(), &target);
        assert_eq!(pending.datagram().payload(), request_payload);
        let (_, commit) = pending.into_parts();
        let mut server_random_bytes =
            hex::decode(case["server_session_id"].as_str().expect("server ID")).expect("server ID");
        if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            for prior in 0..packet_id {
                server_random_bytes.extend_from_slice(&[0xe0 + prior as u8; 24]);
            }
        }
        server_random_bytes.extend_from_slice(&padding);
        if profile == MethodProfile::Blake3ChaCha20Poly13052022 {
            server_random_bytes.extend_from_slice(
                &hex::decode(case["response_nonce"].as_str().expect("response nonce"))
                    .expect("response nonce"),
            );
        }
        let server_random = ScriptedRandom::new(server_random_bytes);
        let accepted = server
            .commit_request(
                commit,
                "127.0.0.1:49152".parse().expect("peer"),
                MonotonicInstant::ZERO,
                &server_random,
            )
            .expect("request commit");
        for _ in 0..packet_id {
            server
                .encode_response(
                    accepted.capability(),
                    &clock,
                    &server_random,
                    &datagram(target.clone(), b"prior"),
                    0,
                    &mut output,
                    &mut scratch,
                )
                .expect("preceding response");
        }
        let response = server
            .encode_response(
                accepted.capability(),
                &clock,
                &server_random,
                &datagram(target.clone(), &response_payload),
                padding.len(),
                &mut output,
                &mut scratch,
            )
            .expect("fixture response");
        assert_eq!(
            hex::encode(&output[..response.wire_len()]),
            case["response_wire"].as_str().expect("response wire"),
            "{} response",
            profile.canonical_name()
        );
        let opened = accept_response(
            &client,
            &clock,
            &output[..response.wire_len()],
            &mut scratch,
        )
        .expect("fixture response opens");
        assert_eq!(opened.target(), &target);
        assert_eq!(opened.payload(), response_payload);
    }
}
