mod common;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_crypto::{MethodProfile, MethodPsk, MethodSinglePskProvider, MethodTcpSalt};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, MethodKeyAdapter, ShadowsocksError, ShadowsocksTcpInbound,
    TcpReplayStore, encode_request_first_write, encode_response_first_write,
};
use serde_json::Value;

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes,
    read_plain, server_target,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/sip022/aes128-tcp-v1.json"
    ))
    .expect("reviewed fixture is valid JSON")
}

fn provider() -> MethodKeyAdapter<MethodSinglePskProvider> {
    MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes128([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ])))
}

fn request_salt() -> MethodTcpSalt {
    MethodTcpSalt::try_from_slice(
        MethodProfile::Blake3Aes128Gcm2022,
        &[
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ],
    )
    .expect("AES-128 salt")
}

#[test]
fn unofficial_composite_request_and_response_match_exact_reviewed_wire() {
    let fixture = fixture();
    assert!(
        fixture["classification"]
            .as_str()
            .expect("classification")
            .contains("unofficial")
    );

    let target =
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)).expect("fixture target");
    let request_a = encode_request_first_write(
        &provider(),
        &request_salt(),
        1_700_000_000,
        &target,
        &[0xa1, 0xb2, 0xc3],
        &[],
    )
    .expect("request A encodes");
    assert_eq!(
        hex::encode(&request_a),
        fixture["request_a"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&request_a[16..43]),
        fixture["request_a"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
    assert_eq!(
        hex::encode(&request_a[43..]),
        fixture["request_a"]["variable_ciphertext_and_tag"]
            .as_str()
            .expect("variable chunk")
    );

    let request_b = encode_request_first_write(
        &provider(),
        &request_salt(),
        1_700_000_000,
        &target,
        &[],
        b"ping",
    )
    .expect("request B encodes");
    assert_eq!(
        hex::encode(&request_b),
        fixture["request_b"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&request_b[16..43]),
        fixture["request_b"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
    assert_eq!(
        hex::encode(&request_b[43..]),
        fixture["request_b"]["variable_ciphertext_and_tag"]
            .as_str()
            .expect("variable chunk")
    );

    let response_salt = MethodTcpSalt::try_from_slice(
        MethodProfile::Blake3Aes128Gcm2022,
        &[
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ],
    )
    .expect("AES-128 salt");
    let response = encode_response_first_write(
        &provider(),
        &response_salt,
        1_700_000_000,
        &request_salt(),
        b"pong",
    )
    .expect("response encodes");
    assert_eq!(
        hex::encode(&response),
        fixture["response"]["first_write"].as_str().expect("wire")
    );
    assert_eq!(
        hex::encode(&response[16..59]),
        fixture["response"]["fixed_ciphertext_and_tag"]
            .as_str()
            .expect("fixed chunk")
    );
}

#[tokio::test]
async fn one_shared_flow_round_trips_all_profiles_and_target_classes() {
    let targets = [
        TargetAddr::ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 9),
            443,
        )))
        .expect("IPv4 target"),
        TargetAddr::ip(SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::9".parse::<Ipv6Addr>().expect("IPv6"),
            443,
            0,
            0,
        )))
        .expect("IPv6 target"),
        TargetAddr::domain("a", 443).expect("one-byte domain"),
        TargetAddr::domain(&"z".repeat(255), 443).expect("255-byte domain"),
    ];

    for (profile_index, profile) in MethodProfile::ALL.into_iter().enumerate() {
        let key = vec![0x20 + profile_index as u8; profile.key_bytes()];
        let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            MethodPsk::try_from_slice(profile, &key).expect("method PSK"),
        ));
        let request_salt = MethodTcpSalt::try_from_slice(
            profile,
            &vec![0x40 + profile_index as u8; profile.salt_bytes()],
        )
        .expect("request salt");
        let response_salt = MethodTcpSalt::try_from_slice(
            profile,
            &vec![0x50 + profile_index as u8; profile.salt_bytes()],
        )
        .expect("response salt");

        for target in &targets {
            let wire = encode_request_first_write(&keys, &request_salt, NOW, target, &[0xa1], &[])
                .expect("request wire");
            let first = profile.initial_request_read_bytes();
            let (io, observation) =
                RecordingIo::new([wire[..first].to_vec(), wire[first..].to_vec()]);
            let clock = FakeClock::new(NOW, 0);
            let random = ScriptedRandom::new([]);
            let replay = TcpReplayStore::new(1024).expect("replay");
            let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
            let session = inbound
                .accept_stream(io)
                .await
                .expect("shared flow accepts");

            assert_eq!(session.target, *target);
            assert_eq!(
                observation.lock().expect("observation").read_lengths[0],
                profile.initial_request_read_bytes()
            );
        }

        let response = encode_response_first_write(&keys, &response_salt, NOW, &request_salt, b"x")
            .expect("response wire");
        assert_eq!(
            response.len(),
            profile.initial_response_read_bytes() + 1 + profile.tag_bytes()
        );

        let first = profile.initial_response_read_bytes();
        let (io, _) = RecordingIo::new([response[..first].to_vec(), response[first..].to_vec()]);
        let connector = RecordingConnector::succeeds(io);
        let clock = FakeClock::new(NOW, 0);
        let random = ScriptedRandom::new(client_random_bytes(&request_salt));
        let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
        let mut flow = outbound
            .connect_server()
            .await
            .expect("server connection")
            .write_request(&targets[0])
            .await
            .expect("shared client flow");
        let mut payload = [0_u8; 1];
        assert_eq!(read_plain(&mut flow, &mut payload).await.unwrap(), 1);
        assert_eq!(payload, *b"x");
    }

    assert!(matches!(targets[2].host(), TargetHostRef::Domain("a")));
}

#[tokio::test]
async fn wide_profile_replay_and_response_binding_use_all_32_salt_bytes() {
    let profile = MethodProfile::Blake3Aes256Gcm2022;
    let keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(MethodPsk::aes256([0x21; 32])));
    let first_salt = MethodTcpSalt::try_from_slice(profile, &[0x31; 32]).expect("first salt");
    let mut second_bytes = [0x31; 32];
    second_bytes[31] = 0x32;
    let second_salt = MethodTcpSalt::try_from_slice(profile, &second_bytes).expect("second salt");
    let target = TargetAddr::domain("example.test", 443).expect("domain target");
    let replay = TcpReplayStore::new(1024).expect("replay");
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);

    for salt in [&first_salt, &second_salt] {
        let wire =
            encode_request_first_write(&keys, salt, NOW, &target, &[0xa1], &[]).expect("request");
        let first = profile.initial_request_read_bytes();
        let (io, _) = RecordingIo::new([wire[..first].to_vec(), wire[first..].to_vec()]);
        ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
            .accept_stream(io)
            .await
            .expect("full-width distinct salt");
    }
    let duplicate = encode_request_first_write(&keys, &first_salt, NOW, &target, &[0xa1], &[])
        .expect("duplicate request");
    let first = profile.initial_request_read_bytes();
    let (io, _) = RecordingIo::new([duplicate[..first].to_vec(), duplicate[first..].to_vec()]);
    assert!(matches!(
        ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
            .accept_stream(io)
            .await,
        Err(ShadowsocksError::Detection(DetectionReason::Replay))
    ));

    let response_salt = MethodTcpSalt::try_from_slice(profile, &[0x41; 32]).expect("response salt");
    let response = encode_response_first_write(&keys, &response_salt, NOW, &second_salt, b"x")
        .expect("mismatched binding response");
    let first = profile.initial_response_read_bytes();
    let (io, _) = RecordingIo::new([response[..first].to_vec(), response[first..].to_vec()]);
    let connector = RecordingConnector::succeeds(io);
    let client_random = ScriptedRandom::new(client_random_bytes(&first_salt));
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random);
    let mut flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target)
        .await
        .expect("client request");
    let mut payload = [0_u8; 1];
    assert_eq!(
        read_plain(&mut flow, &mut payload).await,
        Err(ShadowsocksError::Detection(
            DetectionReason::ResponseBinding
        ))
    );
}
