mod common;

use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, FlowTerminal, PlainDuplex, REQUEST_FIRST_READ_LEN,
    RESPONSE_FIRST_READ_LEN, ShadowsocksError, ShadowsocksTcpInbound, TcpReplayStore,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, RecordingObservers, ScriptedRandom,
    client_random_bytes, custom_request_wire, custom_response_wire, flush_plain, provider,
    read_plain, response_wire_and_frames, salt_with_last, server_target, shutdown_plain, target,
    valid_request_wire, write_plain,
};

#[tokio::test]
async fn each_initial_request_failure_uses_one_fixed_read_and_terminal_before_abortive() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let salt = salt_with_last(10);
    let valid = valid_request_wire(NOW, &salt);
    let mut bad_tag = valid.clone();
    bad_tag[20] ^= 1;
    let mut bad_variable_tag = valid.clone();
    *bad_variable_tag.last_mut().expect("variable tag") ^= 1;
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
    let bad_padding = custom_request_wire(
        &salt_with_last(14),
        0,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0x03, 0x85],
    );
    let empty_request =
        custom_request_wire(&salt_with_last(15), 0, NOW, &[1, 127, 0, 0, 1, 0, 80, 0, 0]);

    let cases = vec![
        (
            vec![valid[..REQUEST_FIRST_READ_LEN - 1].to_vec()],
            None,
            DetectionReason::ShortRead,
        ),
        (Vec::new(), Some(0), DetectionReason::ReadFailed),
        (
            vec![bad_tag[..REQUEST_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::Authentication,
        ),
        (
            vec![bad_type[..REQUEST_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::InvalidType,
        ),
        (
            vec![bad_time[..REQUEST_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::TimestampSkew,
        ),
        (
            vec![
                bad_length[..REQUEST_FIRST_READ_LEN].to_vec(),
                bad_length[REQUEST_FIRST_READ_LEN..].to_vec(),
            ],
            None,
            DetectionReason::AddressBounds,
        ),
        (
            vec![
                valid[..REQUEST_FIRST_READ_LEN].to_vec(),
                valid[REQUEST_FIRST_READ_LEN..REQUEST_FIRST_READ_LEN + 1].to_vec(),
            ],
            None,
            DetectionReason::ShortRead,
        ),
        (
            vec![
                bad_variable_tag[..REQUEST_FIRST_READ_LEN].to_vec(),
                bad_variable_tag[REQUEST_FIRST_READ_LEN..].to_vec(),
            ],
            None,
            DetectionReason::Authentication,
        ),
        (
            vec![
                bad_padding[..REQUEST_FIRST_READ_LEN].to_vec(),
                bad_padding[REQUEST_FIRST_READ_LEN..].to_vec(),
            ],
            None,
            DetectionReason::PaddingBounds,
        ),
        (
            vec![
                empty_request[..REQUEST_FIRST_READ_LEN].to_vec(),
                empty_request[REQUEST_FIRST_READ_LEN..].to_vec(),
            ],
            None,
            DetectionReason::EmptyRequest,
        ),
    ];

    for (reads, fail_after, expected) in cases {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let observers = RecordingObservers::default();
        let (io, observation) = RecordingIo::new(reads);
        let mut io = io
            .with_abortive_failure()
            .with_sequence(observers.sequence.clone());
        if let Some(successful_reads) = fail_after {
            io = io.with_read_failure_after(successful_reads);
        }
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
            .with_observers(&observers, &observers);
        let error = inbound
            .accept_stream(io)
            .await
            .err()
            .expect("case rejected");
        assert_eq!(error, ShadowsocksError::Detection(expected));
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], REQUEST_FIRST_READ_LEN);
        assert_eq!(
            observed
                .read_lengths
                .iter()
                .filter(|length| **length == REQUEST_FIRST_READ_LEN)
                .count(),
            1
        );
        assert_eq!(observed.abortive_calls, 1);
        assert_eq!(observed.write_calls, 0);
        assert_eq!(
            *observers.sequence.lock().expect("sequence"),
            vec!["terminal", "abortive"]
        );
        assert_eq!(
            *observers.terminals.lock().expect("terminals"),
            vec![FlowTerminal::Detection(expected)]
        );
    }
}

#[tokio::test]
async fn abortive_mark_failure_does_not_restore_the_flow() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let observers = RecordingObservers::default();
    let (io, observation) = RecordingIo::new([vec![0_u8; 1]]);
    let io = io
        .with_abortive_failure()
        .with_sequence(observers.sequence.clone());
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .with_observers(&observers, &observers);

    let error = inbound.accept_stream(io).await.err().expect("short read");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ShortRead)
    );
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
    assert_eq!(
        *observers.sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );
}

#[tokio::test]
async fn client_entropy_and_clock_failures_mark_once_before_any_write() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::failing();
    let entropy_observers = RecordingObservers::default();
    let (entropy_io, entropy_observation) = RecordingIo::new([]);
    let entropy_connector = RecordingConnector::succeeds(
        entropy_io
            .with_abortive_failure()
            .with_sequence(entropy_observers.sequence.clone()),
    );
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &entropy_connector, &clock, &random)
            .with_observers(&entropy_observers, &entropy_observers);
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
    assert_eq!(
        *entropy_observers.sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );

    let failing_clock = FakeClock::failing();
    let request_salt = salt_with_last(19);
    let random = ScriptedRandom::new(request_salt.as_bytes().iter().copied());
    let clock_observers = RecordingObservers::default();
    let (clock_io, clock_observation) = RecordingIo::new([]);
    let clock_connector = RecordingConnector::succeeds(
        clock_io
            .with_abortive_failure()
            .with_sequence(clock_observers.sequence.clone()),
    );
    let outbound = ClientTcpOutbound::new(
        server_target(),
        &keys,
        &clock_connector,
        &failing_clock,
        &random,
    )
    .with_observers(&clock_observers, &clock_observers);
    assert_eq!(
        outbound.open_stream(&target()).await.err(),
        Some(ShadowsocksError::Detection(
            DetectionReason::ClockUnavailable
        ))
    );
    let observed = clock_observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 0);
    assert_eq!(observed.abortive_calls, 1);
    assert_eq!(
        *clock_observers.sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );
}

#[tokio::test]
async fn request_first_write_is_one_operation_and_short_write_is_terminal() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_with_last(20);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let observers = RecordingObservers::default();
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(
        io.with_write_limit(1)
            .with_abortive_failure()
            .with_sequence(observers.sequence.clone()),
    );
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random)
        .with_observers(&observers, &observers);

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
    assert_eq!(
        *observers.sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );
}

#[tokio::test]
async fn every_scripted_in_flow_response_detection_is_single_fixed_io_terminal_before_abortive() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(30);
    let response_salt = salt_with_last(31);
    let other_request_salt = salt_with_last(32);
    let (valid, _) = response_wire_and_frames(&request_salt, &response_salt, b"payload", &[]);
    let mut fixed_auth = valid.clone();
    fixed_auth[20] ^= 1;
    let bad_type = custom_response_wire(&response_salt, 0, NOW, &request_salt, b"payload");
    let bad_time = custom_response_wire(&response_salt, 1, NOW + 31, &request_salt, b"payload");
    let bad_binding = custom_response_wire(&response_salt, 1, NOW, &other_request_salt, b"payload");
    let zero_payload = custom_response_wire(&response_salt, 1, NOW, &request_salt, b"");
    let mut payload_auth = valid.clone();
    *payload_auth.last_mut().expect("payload tag") ^= 1;
    let cases = vec![
        (
            "short fixed",
            vec![valid[..RESPONSE_FIRST_READ_LEN - 1].to_vec()],
            None,
            DetectionReason::ShortRead,
        ),
        (
            "fixed transport",
            Vec::new(),
            Some(0),
            DetectionReason::ReadFailed,
        ),
        (
            "fixed auth",
            vec![fixed_auth[..RESPONSE_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::Authentication,
        ),
        (
            "fixed type",
            vec![bad_type[..RESPONSE_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::InvalidType,
        ),
        (
            "fixed time",
            vec![bad_time[..RESPONSE_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::TimestampSkew,
        ),
        (
            "fixed binding",
            vec![bad_binding[..RESPONSE_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::ResponseBinding,
        ),
        (
            "fixed bounds",
            vec![zero_payload[..RESPONSE_FIRST_READ_LEN].to_vec()],
            None,
            DetectionReason::FrameBounds,
        ),
        (
            "payload transport",
            vec![valid[..RESPONSE_FIRST_READ_LEN].to_vec()],
            Some(1),
            DetectionReason::ReadFailed,
        ),
        (
            "payload short",
            vec![
                valid[..RESPONSE_FIRST_READ_LEN].to_vec(),
                valid[RESPONSE_FIRST_READ_LEN..RESPONSE_FIRST_READ_LEN + 3].to_vec(),
            ],
            None,
            DetectionReason::ShortRead,
        ),
        (
            "payload auth",
            vec![
                payload_auth[..RESPONSE_FIRST_READ_LEN].to_vec(),
                payload_auth[RESPONSE_FIRST_READ_LEN..].to_vec(),
            ],
            None,
            DetectionReason::Authentication,
        ),
    ];

    for (name, reads, fail_after, expected) in cases {
        let observers = RecordingObservers::default();
        let (io, observation) = RecordingIo::new(reads);
        let mut io = io
            .with_abortive_failure()
            .with_sequence(observers.sequence.clone());
        if let Some(successful_reads) = fail_after {
            io = io.with_read_failure_after(successful_reads);
        }
        let connector = RecordingConnector::succeeds(io);
        let random = ScriptedRandom::new(client_random_bytes(&request_salt));
        let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random)
            .with_observers(&observers, &observers);
        let mut flow = outbound.open_stream(&target()).await.expect("client");
        let mut destination = [0_u8; 16];

        let error = read_plain(&mut flow, &mut destination)
            .await
            .expect_err(name);

        assert_eq!(error, ShadowsocksError::Detection(expected), "{name}");
        assert_eq!(
            flow.terminal(),
            Some(FlowTerminal::Detection(expected)),
            "{name}: terminal"
        );
        let frozen = {
            let observed = observation.lock().expect("observation");
            assert_eq!(
                observed
                    .read_lengths
                    .iter()
                    .filter(|length| **length == RESPONSE_FIRST_READ_LEN)
                    .count(),
                1,
                "{name}: fixed response completed once"
            );
            assert_eq!(observed.abortive_calls, 1, "{name}: abortive count");
            (
                observed.read_calls,
                observed.write_calls,
                observed.abortive_calls,
            )
        };
        assert_eq!(
            *observers.sequence.lock().expect("sequence"),
            vec!["terminal", "abortive"],
            "{name}: ordering"
        );
        assert_eq!(
            read_plain(&mut flow, &mut destination).await,
            Err(ShadowsocksError::Detection(expected)),
            "{name}: terminal persistence"
        );
        let observed = observation.lock().expect("observation");
        assert_eq!(
            (
                observed.read_calls,
                observed.write_calls,
                observed.abortive_calls
            ),
            frozen,
            "{name}: mark failure must not restore I/O"
        );
    }
}

#[tokio::test]
async fn response_first_write_is_one_operation_and_short_write_is_terminal() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let request_salt = salt_with_last(21);
    let request = valid_request_wire(NOW, &request_salt);
    let observers = RecordingObservers::default();
    let (io, observation) = RecordingIo::request(&request);
    let io = io
        .with_write_limit(1)
        .with_abortive_failure()
        .with_sequence(observers.sequence.clone());
    let response_salt = salt_with_last(22);
    let random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .with_observers(&observers, &observers);
    let mut flow = inbound
        .accept_stream(io)
        .await
        .expect("authenticated request")
        .stream;

    assert_eq!(write_plain(&mut flow, b"pong").await, Ok(4));
    let error = flush_plain(&mut flow)
        .await
        .expect_err("short response write");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ShortWrite)
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Detection(DetectionReason::ShortWrite))
    );
    let frozen = {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.write_calls, 1);
        assert_eq!(observed.abortive_calls, 1);
        (
            observed.read_calls,
            observed.write_calls,
            observed.abortive_calls,
        )
    };
    assert_eq!(
        flush_plain(&mut flow).await,
        Err(ShadowsocksError::Detection(DetectionReason::ShortWrite))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(
        (
            observed.read_calls,
            observed.write_calls,
            observed.abortive_calls
        ),
        frozen
    );
    assert_eq!(
        *observers.sequence.lock().expect("sequence"),
        vec!["terminal", "abortive"]
    );
}

#[tokio::test]
async fn target_eof_before_first_payload_shuts_down_without_header_or_detection() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let request_salt = salt_with_last(23);
    let request = valid_request_wire(NOW, &request_salt);
    let (io, observation) = RecordingIo::request(&request);
    let random = ScriptedRandom::failing();
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(io)
        .await
        .expect("authenticated request")
        .stream;

    assert_eq!(shutdown_plain(&mut flow).await, Ok(()));
    assert_eq!(flow.terminal(), None);
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 0);
    assert_eq!(observed.shutdown_calls, 1);
    assert_eq!(observed.abortive_calls, 0);
}
