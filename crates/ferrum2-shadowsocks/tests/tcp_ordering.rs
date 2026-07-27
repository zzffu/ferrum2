mod common;

use ferrum2_core::{ConnectErrorKind, LocalEndpoint};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, ShadowsocksError, TcpReplayStore, accept_server_request,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes, provider,
    salt_with_last, target, valid_request_wire,
};

#[tokio::test]
async fn authenticated_semantics_precede_replay_and_connector_side_effects() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_with_last(1);
    let mut wire = valid_request_wire(NOW, &salt);
    wire[20] ^= 1;
    let (io, observation) = RecordingIo::request(&wire);
    let (unused_target, _) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(unused_target);

    let error = accept_server_request(io, &keys, &clock, &replay)
        .await
        .err()
        .expect("tamper rejected");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::Authentication)
    );
    assert_eq!(replay.entry_count().expect("replay snapshot"), 0);
    assert_eq!(connector.call_count(), 0);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
}

#[tokio::test]
async fn valid_request_is_reserved_before_target_connector_failure() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("approved capacity");
    let salt = salt_with_last(2);
    let wire = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&wire);
    let connector = RecordingConnector::fails(ConnectErrorKind::ConnectionRefused);

    let accepted = accept_server_request(io, &keys, &clock, &replay)
        .await
        .expect("authenticated request");
    let error = accepted
        .connect_target(&connector)
        .await
        .err()
        .expect("target refusal");

    assert_eq!(
        error,
        ShadowsocksError::Connect(ConnectErrorKind::ConnectionRefused)
    );
    assert_eq!(connector.call_count(), 1);
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
    let outbound = ClientTcpOutbound::new(&keys, &connector, &clock, &random);

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
    assert_eq!(observation.lock().expect("observation").write_calls, 0);
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn opened_stream_delegates_stored_local_endpoint_without_open_time_query() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let salt = salt_with_last(3);
    let random = ScriptedRandom::new(client_random_bytes(&salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io);
    let outbound = ClientTcpOutbound::new(&keys, &connector, &clock, &random);

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
