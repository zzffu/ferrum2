mod common;

use ferrum2_crypto::MethodProfile;
use ferrum2_shadowsocks::{
    DetectionReason, ShadowsocksError, ShadowsocksTcpInbound, TcpReplayStore,
};

use common::{
    FakeClock, NOW, RecordingIo, ScriptedRandom, custom_request_wire_for, method_provider,
    method_salt_from_u64, valid_request_wire_for,
};

#[tokio::test]
async fn authenticated_semantic_table_all_profiles_fails_before_replay_or_owned_session() {
    let valid = &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0][..];
    let cases: &[(DetectionReason, u8, u64, &[u8])] = &[
        (DetectionReason::InvalidType, 1, NOW, valid),
        (DetectionReason::TimestampSkew, 0, NOW + 31, valid),
        (DetectionReason::AddressBounds, 0, NOW, &[]),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[2, 127, 0, 0, 1, 0, 80, 0, 1, 0],
        ),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[1, 127, 0, 0, 1, 0, 0, 0, 1, 0],
        ),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[3, 0, 0, 80, 0, 1, 0],
        ),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[3, 2, 0xc3, 0xa9, 0, 80, 0, 1, 0],
        ),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[3, 3, b'a', b'b', b'c', 0, 0, 0, 1, 0],
        ),
        (DetectionReason::AddressBounds, 0, NOW, &[3, 3, b'a', b'b']),
        (
            DetectionReason::AddressBounds,
            0,
            NOW,
            &[
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0,
            ],
        ),
        (
            DetectionReason::PaddingBounds,
            0,
            NOW,
            &[1, 127, 0, 0, 1, 0, 80, 3, 133, 0],
        ),
        (
            DetectionReason::PaddingBounds,
            0,
            NOW,
            &[1, 127, 0, 0, 1, 0, 80, 0, 2, 0],
        ),
        (
            DetectionReason::PaddingBounds,
            0,
            NOW,
            &[3, 3, b'a', b'b', b'c', 0, 80, 3, 133, 0],
        ),
        (
            DetectionReason::EmptyRequest,
            0,
            NOW,
            &[1, 127, 0, 0, 1, 0, 80, 0, 0],
        ),
    ];

    for profile in MethodProfile::ALL {
        for (index, (reason, message_type, timestamp, variable)) in cases.iter().enumerate() {
            let keys = method_provider(profile);
            let clock = FakeClock::new(NOW, 0);
            let replay = TcpReplayStore::new(1024).expect("approved capacity");
            let random = ScriptedRandom::new([]);
            let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
            let salt = method_salt_from_u64(profile, 400 + index as u64);
            let wire = custom_request_wire_for(&keys, &salt, *message_type, *timestamp, variable);
            let first = profile.initial_request_read_bytes();
            let (io, observation) =
                RecordingIo::new([wire[..first].to_vec(), wire[first..].to_vec()]);
            let error = match inbound.accept_stream(io).await {
                Ok(_) => panic!("{profile:?} case {index}: invalid request returned owned session"),
                Err(error) => error,
            };
            assert_eq!(error, ShadowsocksError::Detection(*reason));
            assert_eq!(replay.entry_count().expect("snapshot"), 0);
            assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
        }
    }
}

#[tokio::test]
async fn auth_bit_flips_in_each_authenticated_chunk_are_rejected() {
    for profile in MethodProfile::ALL {
        let first = profile.initial_request_read_bytes();
        for (index, offset) in [profile.salt_bytes() + 4, first + 2]
            .into_iter()
            .enumerate()
        {
            let keys = method_provider(profile);
            let clock = FakeClock::new(NOW, 0);
            let replay = TcpReplayStore::new(1024).expect("approved capacity");
            let random = ScriptedRandom::new([]);
            let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
            let salt = method_salt_from_u64(profile, 500 + index as u64);
            let mut wire = valid_request_wire_for(&keys, NOW, &salt);
            wire[offset] ^= 1;
            let (io, _) = RecordingIo::new([wire[..first].to_vec(), wire[first..].to_vec()]);
            assert_eq!(
                inbound.accept_stream(io).await.err(),
                Some(ShadowsocksError::Detection(DetectionReason::Authentication))
            );
            assert_eq!(replay.entry_count().expect("snapshot"), 0);
        }
    }
}

#[tokio::test]
async fn auth_truncation_at_every_initial_chunk_prefix_is_rejected() {
    for profile in MethodProfile::ALL {
        let keys = method_provider(profile);
        let clock = FakeClock::new(NOW, 0);
        let random = ScriptedRandom::new([]);
        let first = profile.initial_request_read_bytes();
        for truncated in 0..first {
            let replay = TcpReplayStore::new(1024).expect("approved capacity");
            let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
            let wire = valid_request_wire_for(
                &keys,
                NOW,
                &method_salt_from_u64(profile, 600 + truncated as u64),
            );
            let (io, _) = RecordingIo::new([wire[..truncated].to_vec()]);
            assert!(matches!(
                inbound.accept_stream(io).await,
                Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
            ));
        }

        let wire = valid_request_wire_for(&keys, NOW, &method_salt_from_u64(profile, 700));
        let variable_wire = &wire[first..];
        for truncated in 0..variable_wire.len() {
            let replay = TcpReplayStore::new(1024).expect("approved capacity");
            let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
            let (io, _) =
                RecordingIo::new([wire[..first].to_vec(), variable_wire[..truncated].to_vec()]);
            assert!(matches!(
                inbound.accept_stream(io).await,
                Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
            ));
        }
    }
}
