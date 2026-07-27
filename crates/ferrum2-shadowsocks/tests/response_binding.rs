mod common;

use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, RESPONSE_FIRST_READ_LEN, ShadowsocksError,
    encode_response_first_write,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes, provider,
    read_plain, salt_with_last, server_target, target,
};

#[tokio::test]
async fn full_request_salt_binding_precedes_first_payload_forwarding() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(30);
    let wrong_request_salt = salt_with_last(31);
    let response_salt = salt_with_last(32);
    let response = encode_response_first_write(
        &keys,
        &response_salt,
        NOW,
        &wrong_request_salt,
        b"must-not-forward",
    )
    .expect("fixture response");
    let (io, observation) = RecordingIo::new([
        response[..RESPONSE_FIRST_READ_LEN].to_vec(),
        response[RESPONSE_FIRST_READ_LEN..].to_vec(),
    ]);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");
    let mut destination = [0_u8; 64];

    let error = read_plain(&mut flow, &mut destination)
        .await
        .expect_err("binding mismatch");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::ResponseBinding)
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.read_calls, 1);
    assert_eq!(observed.abortive_calls, 1);
    assert!(destination.iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn authenticated_bound_response_releases_exact_first_payload() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(40);
    let response_salt = salt_with_last(41);
    let response = encode_response_first_write(&keys, &response_salt, NOW, &request_salt, b"pong")
        .expect("fixture response");
    let (io, observation) = RecordingIo::new([
        response[..RESPONSE_FIRST_READ_LEN].to_vec(),
        response[RESPONSE_FIRST_READ_LEN..].to_vec(),
    ]);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");
    let mut destination = [0_u8; 16];

    let read = read_plain(&mut flow, &mut destination)
        .await
        .expect("response authentication");

    assert_eq!(&destination[..read], b"pong");
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.read_calls, 2);
    assert_eq!(observed.read_lengths[0], RESPONSE_FIRST_READ_LEN);
    assert_eq!(observed.abortive_calls, 0);
}

#[tokio::test]
async fn tampered_first_payload_is_never_released() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_with_last(50);
    let response_salt = salt_with_last(51);
    let mut response =
        encode_response_first_write(&keys, &response_salt, NOW, &request_salt, b"pong")
            .expect("fixture response")
            .to_vec();
    *response.last_mut().expect("tag byte") ^= 1;
    let (io, observation) = RecordingIo::new([
        response[..RESPONSE_FIRST_READ_LEN].to_vec(),
        response[RESPONSE_FIRST_READ_LEN..].to_vec(),
    ]);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .open_stream(&target())
        .await
        .expect("request first-write");
    let mut destination = [0_u8; 16];

    let error = read_plain(&mut flow, &mut destination)
        .await
        .expect_err("payload authentication");

    assert_eq!(
        error,
        ShadowsocksError::Detection(DetectionReason::Authentication)
    );
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
    assert!(destination.iter().all(|byte| *byte == 0));
}
