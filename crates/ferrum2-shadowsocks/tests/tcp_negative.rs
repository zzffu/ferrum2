mod common;

use ferrum2_shadowsocks::{
    DetectionReason, REQUEST_FIRST_READ_LEN, ShadowsocksError, ShadowsocksTcpInbound,
    TcpReplayStore,
};

use common::{
    FakeClock, NOW, RecordingIo, ScriptedRandom, custom_request_wire, provider, salt_from_u64,
    valid_request_wire,
};

#[tokio::test]
async fn bounds_address_padding_and_empty_content_table_fails_before_replay() {
    let cases: &[(DetectionReason, &[u8])] = &[
        (DetectionReason::AddressBounds, &[]),
        (
            DetectionReason::AddressBounds,
            &[2, 127, 0, 0, 1, 0, 80, 0, 1, 0],
        ),
        (
            DetectionReason::AddressBounds,
            &[1, 127, 0, 0, 1, 0, 0, 0, 1, 0],
        ),
        (
            DetectionReason::PaddingBounds,
            &[1, 127, 0, 0, 1, 0, 80, 3, 133, 0],
        ),
        (
            DetectionReason::PaddingBounds,
            &[1, 127, 0, 0, 1, 0, 80, 0, 2, 0],
        ),
        (
            DetectionReason::EmptyRequest,
            &[1, 127, 0, 0, 1, 0, 80, 0, 0],
        ),
    ];

    for (index, (reason, variable)) in cases.iter().enumerate() {
        let keys = provider();
        let clock = FakeClock::new(NOW, 0);
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let random = ScriptedRandom::new([]);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let salt = salt_from_u64(400 + index as u64);
        let wire = custom_request_wire(&salt, 0, NOW, variable);
        let (io, observation) = RecordingIo::request(&wire);
        let error = inbound
            .accept_stream(io)
            .await
            .err()
            .expect("invalid semantic request");
        assert_eq!(error, ShadowsocksError::Detection(*reason));
        assert_eq!(replay.entry_count().expect("snapshot"), 0);
        assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
    }
}

#[tokio::test]
async fn auth_bit_flips_in_each_authenticated_chunk_are_rejected() {
    for (index, offset) in [20_usize, REQUEST_FIRST_READ_LEN + 2]
        .into_iter()
        .enumerate()
    {
        let keys = provider();
        let clock = FakeClock::new(NOW, 0);
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let random = ScriptedRandom::new([]);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let salt = salt_from_u64(500 + index as u64);
        let mut wire = valid_request_wire(NOW, &salt);
        wire[offset] ^= 1;
        let (io, _) = RecordingIo::request(&wire);
        assert_eq!(
            inbound.accept_stream(io).await.err(),
            Some(ShadowsocksError::Detection(DetectionReason::Authentication))
        );
        assert_eq!(replay.entry_count().expect("snapshot"), 0);
    }
}

#[tokio::test]
async fn auth_truncation_at_every_initial_chunk_prefix_is_rejected() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    for truncated in 0..REQUEST_FIRST_READ_LEN {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let wire = valid_request_wire(NOW, &salt_from_u64(600 + truncated as u64));
        let (io, _) = RecordingIo::new([wire[..truncated].to_vec()]);
        assert!(matches!(
            inbound.accept_stream(io).await,
            Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
        ));
    }

    let wire = valid_request_wire(NOW, &salt_from_u64(700));
    let variable_wire = &wire[REQUEST_FIRST_READ_LEN..];
    for truncated in 0..variable_wire.len() {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let (io, _) = RecordingIo::new([
            wire[..REQUEST_FIRST_READ_LEN].to_vec(),
            variable_wire[..truncated].to_vec(),
        ]);
        assert!(matches!(
            inbound.accept_stream(io).await,
            Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
        ));
    }
}
