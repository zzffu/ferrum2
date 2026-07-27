mod common;

use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, REQUEST_FIRST_READ_LEN, ShadowsocksError, TcpReplayStore,
    accept_server_request,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes,
    custom_request_wire, provider, salt_with_last, target, valid_request_wire,
};

#[tokio::test]
async fn each_initial_request_failure_uses_one_fixed_read_and_one_abortive_mark() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);

    let salt = salt_with_last(10);
    let valid = valid_request_wire(NOW, &salt);
    let mut bad_tag = valid.clone();
    bad_tag[20] ^= 1;
    let bad_type = custom_request_wire(
        &salt_with_last(11),
        1,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_time = custom_request_wire(
        &salt_with_last(12),
        0,
        NOW + 31,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_length = custom_request_wire(&salt_with_last(13), 0, NOW, &[]);

    let cases = [
        (
            vec![valid[..REQUEST_FIRST_READ_LEN - 1].to_vec()],
            DetectionReason::ShortRead,
        ),
        (
            vec![bad_tag[..REQUEST_FIRST_READ_LEN].to_vec()],
            DetectionReason::Authentication,
        ),
        (
            vec![bad_type[..REQUEST_FIRST_READ_LEN].to_vec()],
            DetectionReason::InvalidType,
        ),
        (
            vec![bad_time[..REQUEST_FIRST_READ_LEN].to_vec()],
            DetectionReason::TimestampSkew,
        ),
        (
            vec![
                bad_length[..REQUEST_FIRST_READ_LEN].to_vec(),
                bad_length[REQUEST_FIRST_READ_LEN..].to_vec(),
            ],
            DetectionReason::AddressBounds,
        ),
    ];

    for (reads, expected) in cases {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let (io, observation) = RecordingIo::new(reads);
        let error = accept_server_request(io, &keys, &clock, &replay)
            .await
            .err()
            .expect("case rejected");
        assert_eq!(error, ShadowsocksError::Detection(expected));
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], REQUEST_FIRST_READ_LEN);
        assert_eq!(observed.abortive_calls, 1);
        assert_eq!(observed.write_calls, 0);
    }
}

#[tokio::test]
async fn initial_read_error_is_terminal_and_marked_once() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let (io, observation) = RecordingIo::new([]);
    let io = io.with_read_failure();

    let error = accept_server_request(io, &keys, &clock, &replay)
        .await
        .err()
        .expect("read error");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ReadFailed)
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.read_calls, 1);
    assert_eq!(observed.abortive_calls, 1);
}

#[tokio::test]
async fn abortive_mark_failure_still_returns_closed_terminal_detection() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let (io, observation) = RecordingIo::new([vec![0_u8; 1]]);
    let io = io.with_abortive_failure();

    let error = accept_server_request(io, &keys, &clock, &replay)
        .await
        .err()
        .expect("short read");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ShortRead)
    );
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
}

#[tokio::test]
async fn client_entropy_and_clock_failures_mark_once_before_any_write() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::failing();
    let (entropy_io, entropy_observation) = RecordingIo::new([]);
    let entropy_connector = RecordingConnector::succeeds(entropy_io);
    let outbound = ClientTcpOutbound::new(&keys, &entropy_connector, &clock, &random);
    assert_eq!(
        outbound.open_stream(&target()).await.err(),
        Some(ShadowsocksError::Detection(
            DetectionReason::RandomUnavailable
        ))
    );
    {
        let observed = entropy_observation.lock().expect("observation");
        assert_eq!(observed.write_calls, 0);
        assert_eq!(observed.abortive_calls, 1);
    }

    let failing_clock = FakeClock::failing();
    let request_salt = salt_with_last(19);
    let random = ScriptedRandom::new(request_salt.as_bytes().iter().copied());
    let (clock_io, clock_observation) = RecordingIo::new([]);
    let clock_connector = RecordingConnector::succeeds(clock_io);
    let outbound = ClientTcpOutbound::new(&keys, &clock_connector, &failing_clock, &random);
    assert_eq!(
        outbound.open_stream(&target()).await.err(),
        Some(ShadowsocksError::Detection(
            DetectionReason::ClockUnavailable
        ))
    );
    let observed = clock_observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 0);
    assert_eq!(observed.abortive_calls, 1);
}

#[tokio::test]
async fn request_first_write_is_one_operation_and_short_write_is_terminal() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_with_last(20);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io.with_write_limit(1));
    let outbound = ClientTcpOutbound::new(&keys, &connector, &clock, &random);

    let error = outbound
        .open_stream(&target())
        .await
        .err()
        .expect("short write");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ShortWrite)
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 1);
    assert_eq!(observed.abortive_calls, 1);
    assert_eq!(observed.read_calls, 0);
}

#[tokio::test]
async fn response_first_write_is_one_operation_and_short_write_is_terminal() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let request_salt = salt_with_last(21);
    let request = valid_request_wire(NOW, &request_salt);
    let (io, observation) = RecordingIo::request(&request);
    let io = io.with_write_limit(1);
    let accepted = accept_server_request(io, &keys, &clock, &replay)
        .await
        .expect("authenticated request");
    let (target_io, _) = RecordingIo::new([]);
    let target_connector = RecordingConnector::succeeds(target_io);
    let connected = accepted
        .connect_target(&target_connector)
        .await
        .expect("target connection");
    let response_salt = salt_with_last(22);
    let random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());

    let error = connected
        .write_first_response(&keys, &clock, &random, b"pong")
        .await
        .err()
        .expect("short response write");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ShortWrite)
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 1);
    assert_eq!(observed.abortive_calls, 1);
}

#[tokio::test]
async fn target_eof_before_first_payload_sends_no_header_and_is_not_detection() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let request_salt = salt_with_last(23);
    let request = valid_request_wire(NOW, &request_salt);
    let (io, observation) = RecordingIo::request(&request);
    let accepted = accept_server_request(io, &keys, &clock, &replay)
        .await
        .expect("authenticated request");
    let (target_io, _) = RecordingIo::new([]);
    let target_connector = RecordingConnector::succeeds(target_io);
    let connected = accepted
        .connect_target(&target_connector)
        .await
        .expect("target connection");
    let random = ScriptedRandom::failing();

    let error = connected
        .write_first_response(&keys, &clock, &random, b"")
        .await
        .err()
        .expect("target EOF");

    assert_eq!(error, ShadowsocksError::ResponseUnavailable);
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 0);
    assert_eq!(observed.abortive_calls, 0);
}
