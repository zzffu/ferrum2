mod common;

use ferrum2_core::{ConnectErrorKind, LocalEndpoint, Session};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, REQUEST_FIRST_READ_LEN, ShadowsocksError,
    ShadowsocksTcpInbound, TcpReplayStore,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes,
    custom_request_wire, provider, salt_with_last, server_target, target, valid_request_wire,
};

#[derive(Default)]
struct DownstreamEffects {
    accepted_sessions: usize,
    connector_calls: usize,
    forwarded_bytes: usize,
}

impl DownstreamEffects {
    fn consume<S, R>(&mut self, session: Session<S, R>) {
        self.accepted_sessions += 1;
        self.connector_calls += 1;
        self.forwarded_bytes += session.initial_payload.len();
    }
}

#[tokio::test]
async fn every_s0_through_s3_reject_precedes_all_downstream_and_replay_mutation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let valid = valid_request_wire(NOW, &salt_with_last(1));
    let mut fixed_auth = valid.clone();
    fixed_auth[20] ^= 1;
    let mut variable_auth = valid.clone();
    *variable_auth.last_mut().expect("variable tag") ^= 1;
    let bad_type = custom_request_wire(
        &salt_with_last(2),
        1,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_time = custom_request_wire(
        &salt_with_last(3),
        0,
        NOW + 31,
        &[1, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_address = custom_request_wire(
        &salt_with_last(4),
        0,
        NOW,
        &[2, 127, 0, 0, 1, 0, 80, 0, 1, 0],
    );
    let bad_padding = custom_request_wire(
        &salt_with_last(5),
        0,
        NOW,
        &[1, 127, 0, 0, 1, 0, 80, 0x03, 0x85],
    );
    let empty_request =
        custom_request_wire(&salt_with_last(6), 0, NOW, &[1, 127, 0, 0, 1, 0, 80, 0, 0]);
    let cases = vec![
        (
            "short fixed",
            RecordingIo::new([valid[..REQUEST_FIRST_READ_LEN - 1].to_vec()]).0,
            DetectionReason::ShortRead,
        ),
        (
            "fixed transport",
            RecordingIo::new([]).0.with_read_failure(),
            DetectionReason::ReadFailed,
        ),
        (
            "fixed auth",
            RecordingIo::new([fixed_auth[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::Authentication,
        ),
        (
            "fixed type",
            RecordingIo::new([bad_type[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::InvalidType,
        ),
        (
            "fixed time",
            RecordingIo::new([bad_time[..REQUEST_FIRST_READ_LEN].to_vec()]).0,
            DetectionReason::TimestampSkew,
        ),
        (
            "short variable",
            RecordingIo::new([
                valid[..REQUEST_FIRST_READ_LEN].to_vec(),
                valid[REQUEST_FIRST_READ_LEN..REQUEST_FIRST_READ_LEN + 1].to_vec(),
            ])
            .0,
            DetectionReason::ShortRead,
        ),
        (
            "variable auth",
            RecordingIo::request(&variable_auth).0,
            DetectionReason::Authentication,
        ),
        (
            "address semantics",
            RecordingIo::request(&bad_address).0,
            DetectionReason::AddressBounds,
        ),
        (
            "padding semantics",
            RecordingIo::request(&bad_padding).0,
            DetectionReason::PaddingBounds,
        ),
        (
            "empty semantics",
            RecordingIo::request(&empty_request).0,
            DetectionReason::EmptyRequest,
        ),
    ];

    for (name, io, expected) in cases {
        let replay = TcpReplayStore::new(1024).expect("approved capacity");
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
        let mut effects = DownstreamEffects::default();

        let error = match inbound.accept_stream(io).await {
            Ok(session) => {
                effects.consume(session);
                panic!("{name}: reject unexpectedly returned a session");
            }
            Err(error) => error,
        };

        assert_eq!(
            error,
            ShadowsocksError::Detection(expected),
            "{name}: closed reason"
        );
        assert_eq!(
            (
                effects.connector_calls,
                effects.forwarded_bytes,
                effects.accepted_sessions,
                replay.entry_count().expect("replay snapshot"),
            ),
            (0, 0, 0, 0),
            "{name}: reject ordering"
        );
    }
}

#[tokio::test]
async fn valid_request_is_reserved_before_session_is_returned() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_with_last(2);
    let wire = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&wire);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

    let session = inbound
        .accept_stream(io)
        .await
        .expect("authenticated request");

    assert_eq!(session.target, target());
    assert!(session.initial_payload.is_empty());
    assert_eq!(replay.entry_count().expect("replay snapshot"), 1);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn connector_error_before_write() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::failing();
    let (unreturned_io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::fails_with_unreturned_stream(
        ConnectErrorKind::NetworkUnreachable,
        unreturned_io,
    );
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let error = outbound
        .open_stream(&target())
        .await
        .err()
        .expect("connector failure");

    assert_eq!(
        error,
        ShadowsocksError::Connect(ConnectErrorKind::NetworkUnreachable)
    );
    assert_eq!(connector.call_count(), 1);
    assert_eq!(connector.targets(), vec![server_target()]);
    assert_eq!(observation.lock().expect("observation").write_calls, 0);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn connector_target_and_request_target() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(3);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let _flow = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");

    assert_eq!(connector.targets(), vec![server_target()]);
    let wire = observation.lock().expect("observation").writes[0].clone();
    let (server_io, _) = RecordingIo::request(&wire);
    let server_random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let session = inbound
        .accept_stream(server_io)
        .await
        .expect("authenticated request");
    assert_eq!(session.target, target());
}

#[tokio::test]
async fn opened_stream_delegates_stored_local_endpoint_without_open_time_query() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_with_last(4);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);

    let opened = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");
    {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.write_calls, 1);
        assert_eq!(observed.endpoint_calls, 0);
    }
    assert_eq!(opened.local_endpoint().port(), 49152);
    assert_eq!(observation.lock().expect("observation").endpoint_calls, 1);
}
