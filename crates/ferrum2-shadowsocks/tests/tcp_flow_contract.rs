mod common;

use std::error::Error;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ferrum2_core::{ConnectErrorKind, TargetAddr};
use ferrum2_crypto::{MethodPsk, MethodSinglePskProvider, TcpMethodProfile};
use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, FlowTerminal, MethodKeyAdapter, PlainDuplex,
    ProtocolReason, ShadowsocksError, ShadowsocksTcpInbound, TcpKeyProvider, TcpReplayStore,
    TransportPhase, encode_response_first_write,
};

use common::{
    FakeClock, IoObservation, NOW, RecordingConnector, RecordingIo, RecordingObservers,
    ScriptedRandom, client_random_bytes, flush_plain, method_salt_from_u64, provider, read_plain,
    request_data_frames, salt_from_u64, server_target, shutdown_plain, target, valid_request_wire,
    write_plain,
};

fn distinct_provider(
    profile: TcpMethodProfile,
    byte: u8,
) -> MethodKeyAdapter<MethodSinglePskProvider> {
    let key = vec![byte; profile.key_bytes()];
    MethodKeyAdapter::new(MethodSinglePskProvider::new(
        MethodPsk::try_from_slice(profile, &key).expect("method PSK"),
    ))
}

async fn decode_request(
    keys: &impl TcpKeyProvider,
    wire: &[u8],
    read_payload: bool,
    replay: &TcpReplayStore,
) -> Result<(TargetAddr, Vec<u8>), ShadowsocksError> {
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(keys, &clock, &random, replay);
    let mut session = inbound
        .accept_stream(RecordingIo::new([wire.to_vec()]).0)
        .await?;
    let mut payload = vec![0_u8; 4_096];
    let length = if read_payload {
        read_plain(&mut session.stream, &mut payload).await?
    } else {
        0
    };
    payload.truncate(length);
    Ok((session.target, payload))
}

async fn client_chain_exchange(
    first_keys: &impl TcpKeyProvider,
    second_keys: &impl TcpKeyProvider,
    servers: [TargetAddr; 2],
    application: &TargetAddr,
    request_salts: [&ferrum2_crypto::MethodTcpSalt; 2],
    response_wire: Vec<u8>,
    observers: &RecordingObservers,
) -> (
    Result<Vec<u8>, ShadowsocksError>,
    Arc<Mutex<IoObservation>>,
    usize,
    usize,
) {
    let mut random_bytes = client_random_bytes(request_salts[0]);
    random_bytes.extend(client_random_bytes(request_salts[1]));
    let random = ScriptedRandom::new(random_bytes);
    let clock = FakeClock::new(NOW, 0);
    let (io, observation) = RecordingIo::new([response_wire]);
    let first_connector = RecordingConnector::succeeds(io);
    let second_connector = RecordingConnector::fails(ConnectErrorKind::Other);
    let first = ClientTcpOutbound::new(
        servers[0].clone(),
        first_keys,
        &first_connector,
        &clock,
        &random,
    )
    .with_observers(observers, observers);
    let second = ClientTcpOutbound::new(
        servers[1].clone(),
        second_keys,
        &second_connector,
        &clock,
        &random,
    )
    .with_observers(observers, observers);
    let result = async {
        let outer = first
            .connect_server()
            .await?
            .write_request(&servers[1])
            .await?
            .into_boxed();
        let mut flow = second
            .write_request_on(outer, application)
            .await?
            .into_boxed();
        flush_plain(&mut flow).await?;
        let mut response = vec![0_u8; 256];
        let length = read_plain(&mut flow, &mut response).await?;
        response.truncate(length);
        shutdown_plain(&mut flow).await?;
        Ok(response)
    }
    .await;
    (
        result,
        observation,
        first_connector.call_count(),
        second_connector.call_count(),
    )
}

#[test]
fn closed_contract_is_copyable_opaque_and_source_free() {
    fn assert_closed<T: Clone + Copy + std::fmt::Debug + Eq + PartialEq>() {}
    assert_closed::<ProtocolReason>();
    assert_closed::<TransportPhase>();
    assert_closed::<FlowTerminal>();
    assert_closed::<ShadowsocksError>();

    let protocol = ShadowsocksError::Protocol(ProtocolReason::Authentication);
    let transport = ShadowsocksError::Transport(TransportPhase::WriteZero);
    let rendered = format!("{protocol}\n{transport}");
    assert!(!protocol.to_string().is_empty());
    assert!(!transport.to_string().is_empty());
    assert_ne!(protocol.to_string(), transport.to_string());
    assert!(!rendered.contains("Authentication"));
    assert!(!rendered.contains("WriteZero"));
    assert!(protocol.source().is_none());
    assert!(transport.source().is_none());
}

#[tokio::test]
async fn write_admission_and_single_scratch_backpressure_cover_0_1_16384_16385() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(1000);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io.with_write_limit_after(1, 1));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound.open_stream(&target()).await.expect("client");

    assert_eq!(write_plain(&mut flow, &[]).await, Ok(0));
    assert_eq!(observation.lock().expect("observation").write_calls, 1);
    assert_eq!(write_plain(&mut flow, &[1]).await, Ok(1));
    assert_eq!(observation.lock().expect("observation").write_calls, 1);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(matches!(
        Pin::new(&mut flow).poll_write_plain(&mut cx, &[2; 16_384]),
        Poll::Pending
    ));
    assert_eq!(observation.lock().expect("observation").write_calls, 2);

    assert_eq!(write_plain(&mut flow, &[2; 16_384]).await, Ok(16_384));
    assert_eq!(write_plain(&mut flow, &[3; 16_385]).await, Ok(16_384));
}

#[tokio::test]
async fn response_pending_opposite_direction_failures_keep_protocol_or_transport_class() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);

    let client_salt = salt_from_u64(1001);
    let client_random = ScriptedRandom::new(client_random_bytes(&client_salt));
    let (client_io, client_observation) = RecordingIo::new([]);
    let client_connector = RecordingConnector::succeeds(client_io.with_write_failure_after(1));
    let client_outbound = ClientTcpOutbound::new(
        server_target(),
        &keys,
        &client_connector,
        &clock,
        &client_random,
    );
    let mut client = client_outbound
        .open_stream(&target())
        .await
        .expect("client");
    assert_eq!(
        write_plain(&mut client, &[0x5a; 16_385]).await,
        Ok(16_384),
        "response-pending client TX admits its structural maximum without a fatal"
    );
    assert_eq!(client.terminal(), None);
    assert_eq!(
        flush_plain(&mut client).await,
        Err(ShadowsocksError::Transport(TransportPhase::Write))
    );
    assert_eq!(
        client.terminal(),
        Some(FlowTerminal::Transport(TransportPhase::Write))
    );
    assert_eq!(
        client_observation
            .lock()
            .expect("observation")
            .abortive_calls,
        0
    );

    let replay = TcpReplayStore::new(1024).expect("capacity");
    let server_salt = salt_from_u64(1002);
    let request = valid_request_wire(NOW, &server_salt);
    let mut frames = request_data_frames(&server_salt, &[b"bad-auth"]);
    *frames[1].last_mut().expect("tag") ^= 1;
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (server_io, server_observation) = RecordingIo::new(reads);
    let server_random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let mut server = inbound
        .accept_stream(server_io)
        .await
        .expect("server")
        .stream;
    let mut destination = [0_u8; 32];
    assert_eq!(
        read_plain(&mut server, &mut destination).await,
        Err(ShadowsocksError::Protocol(ProtocolReason::Authentication))
    );
    assert_eq!(
        server.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::Authentication))
    );
    assert_eq!(
        server_observation
            .lock()
            .expect("observation")
            .abortive_calls,
        0
    );

    let replay = TcpReplayStore::new(1024).expect("capacity");
    let transport_salt = salt_from_u64(1003);
    let request = valid_request_wire(NOW, &transport_salt);
    let (transport_io, transport_observation) = RecordingIo::request(&request);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let mut server = inbound
        .accept_stream(transport_io.with_read_failure_after(2))
        .await
        .expect("server")
        .stream;
    assert_eq!(
        read_plain(&mut server, &mut destination).await,
        Err(ShadowsocksError::Transport(TransportPhase::Read))
    );
    assert_eq!(
        server.terminal(),
        Some(FlowTerminal::Transport(TransportPhase::Read))
    );
    assert_eq!(
        transport_observation
            .lock()
            .expect("observation")
            .abortive_calls,
        0
    );

    let replay = TcpReplayStore::new(1024).expect("capacity");
    let bounds_salt = salt_from_u64(1004);
    let request = valid_request_wire(NOW, &bounds_salt);
    let frames = request_data_frames(&bounds_salt, &[b"bounds"]);
    let (bounds_io, bounds_observation) = RecordingIo::new([
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0][..3].to_vec(),
    ]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let mut server = inbound
        .accept_stream(bounds_io)
        .await
        .expect("server")
        .stream;
    assert_eq!(
        read_plain(&mut server, &mut destination).await,
        Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds))
    );
    assert_eq!(
        server.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::FrameBounds))
    );
    {
        let observed = bounds_observation.lock().expect("observation");
        assert_eq!(observed.write_calls, 0, "response remains pending");
        assert_eq!(observed.abortive_calls, 0);
    }
}

#[tokio::test]
async fn transport_phase_table_is_exact_and_fatal_freezes_all_counts() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);

    for (phase, io) in [
        (
            TransportPhase::Write,
            RecordingIo::new([]).0.with_write_failure_after(1),
        ),
        (
            TransportPhase::WriteZero,
            RecordingIo::new([]).0.with_write_limit_after(1, 0),
        ),
    ] {
        let request_salt = salt_from_u64(1100 + phase as u64);
        let random = ScriptedRandom::new(client_random_bytes(&request_salt));
        let connector = RecordingConnector::succeeds(io);
        let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
        let mut flow = outbound.open_stream(&target()).await.expect("client");
        assert_eq!(write_plain(&mut flow, b"data").await, Ok(4));
        assert_eq!(
            flush_plain(&mut flow).await,
            Err(ShadowsocksError::Transport(phase))
        );
        assert_eq!(flow.terminal(), Some(FlowTerminal::Transport(phase)));
    }

    let request_salt = salt_from_u64(1110);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io.with_flush_failure());
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound.open_stream(&target()).await.expect("client");
    assert_eq!(
        flush_plain(&mut flow).await,
        Err(ShadowsocksError::Transport(TransportPhase::Flush))
    );
    let frozen = {
        let observed = observation.lock().expect("observation");
        (
            observed.read_calls,
            observed.write_calls,
            observed.flush_calls,
        )
    };
    assert_eq!(
        shutdown_plain(&mut flow).await,
        Err(ShadowsocksError::Transport(TransportPhase::Flush))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(
        (
            observed.read_calls,
            observed.write_calls,
            observed.flush_calls
        ),
        frozen
    );
}

#[tokio::test]
async fn real_transport_source_sentinel_is_erased_from_debug_display_and_source_chain() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(1150);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io.with_write_failure_after(1));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound.open_stream(&target()).await.expect("client");
    assert_eq!(write_plain(&mut flow, b"data").await, Ok(4));

    let error = flush_plain(&mut flow)
        .await
        .expect_err("scripted source sentinel");

    assert_eq!(error, ShadowsocksError::Transport(TransportPhase::Write));
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains("sentinel-source-debug"));
    assert!(!diagnostics.contains("sentinel-source-display"));
    assert!(error.source().is_none());
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.abortive_calls, 0);
    assert_eq!(observed.read_calls, 0, "response remains pending");
}

#[tokio::test]
async fn response_pending_flush_is_zero_io_and_shutdown_failure_is_transport() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(1200);
    let request = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&request);
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(io.with_shutdown_failure())
        .await
        .expect("server")
        .stream;

    assert_eq!(flush_plain(&mut flow).await, Ok(()));
    assert_eq!(observation.lock().expect("observation").flush_calls, 0);
    assert_eq!(
        shutdown_plain(&mut flow).await,
        Err(ShadowsocksError::Transport(TransportPhase::Shutdown))
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Transport(TransportPhase::Shutdown))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.write_calls, 0);
    assert_eq!(observed.abortive_calls, 0);
}

#[tokio::test]
async fn normal_terminal_is_immutable_and_repeated_polls_are_closed_success_without_io() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(1300);
    let request = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&request);
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("server").stream;
    let mut destination = [0_u8; 8];

    assert_eq!(read_plain(&mut flow, &mut destination).await, Ok(0));
    assert_eq!(flow.terminal(), None, "TX remains live");
    assert_eq!(shutdown_plain(&mut flow).await, Ok(()));
    assert_eq!(flow.terminal(), Some(FlowTerminal::Normal));
    let frozen = {
        let observed = observation.lock().expect("observation");
        (
            observed.read_calls,
            observed.write_calls,
            observed.flush_calls,
            observed.shutdown_calls,
        )
    };
    assert_eq!(read_plain(&mut flow, &mut destination).await, Ok(0));
    assert_eq!(write_plain(&mut flow, b"ignored").await, Ok(0));
    assert_eq!(flush_plain(&mut flow).await, Ok(()));
    assert_eq!(shutdown_plain(&mut flow).await, Ok(()));
    assert_eq!(flow.terminal(), Some(FlowTerminal::Normal));
    let observed = observation.lock().expect("observation");
    assert_eq!(
        (
            observed.read_calls,
            observed.write_calls,
            observed.flush_calls,
            observed.shutdown_calls,
        ),
        frozen
    );
}

#[tokio::test]
async fn nonempty_write_after_shutdown_while_rx_live_installs_transport_write() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(1400);
    let request = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::request(&request);
    let random = ScriptedRandom::new([]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("server").stream;

    assert_eq!(shutdown_plain(&mut flow).await, Ok(()));
    assert_eq!(
        write_plain(&mut flow, b"late").await,
        Err(ShadowsocksError::Transport(TransportPhase::Write))
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Transport(TransportPhase::Write))
    );
    assert_eq!(observation.lock().expect("observation").abortive_calls, 0);
}

#[tokio::test]
async fn mixed_method_nested_flows_bind_order_credentials_tamper_and_recursive_ownership() {
    let rotations = [
        (
            TcpMethodProfile::Blake3Aes128Gcm2022,
            TcpMethodProfile::Blake3Aes256Gcm2022,
        ),
        (
            TcpMethodProfile::Blake3Aes256Gcm2022,
            TcpMethodProfile::Blake3ChaCha20Poly13052022,
        ),
        (
            TcpMethodProfile::Blake3ChaCha20Poly13052022,
            TcpMethodProfile::Blake3Aes128Gcm2022,
        ),
    ];
    for (case, (first_profile, second_profile)) in rotations.into_iter().enumerate() {
        let first_keys = distinct_provider(first_profile, 0x21 + case as u8);
        let second_keys = distinct_provider(second_profile, 0x31 + case as u8);
        let wrong_first = distinct_provider(first_profile, 0x71 + case as u8);
        let wrong_second = distinct_provider(second_profile, 0x81 + case as u8);
        let first_server = TargetAddr::ipv4(
            format!("127.0.0.1:{}", 43_000 + case * 10)
                .parse()
                .expect("first server"),
        )
        .expect("first server target");
        let second_server = TargetAddr::ipv4(
            format!("127.0.0.1:{}", 43_001 + case * 10)
                .parse()
                .expect("second server"),
        )
        .expect("second server target");
        let application = TargetAddr::ipv4(
            format!("192.0.2.1:{}", 443 + case)
                .parse()
                .expect("application"),
        )
        .expect("application target");
        let first_request_salt = method_salt_from_u64(first_profile, 2_000 + case as u64);
        let second_request_salt = method_salt_from_u64(second_profile, 3_000 + case as u64);
        let first_response_salt = method_salt_from_u64(first_profile, 4_000 + case as u64);
        let second_response_salt = method_salt_from_u64(second_profile, 5_000 + case as u64);
        let inner_response = encode_response_first_write(
            &second_keys,
            &second_response_salt,
            NOW,
            &second_request_salt,
            b"reply",
        )
        .expect("inner response")
        .to_vec();
        let valid_response = encode_response_first_write(
            &first_keys,
            &first_response_salt,
            NOW,
            &first_request_salt,
            &inner_response,
        )
        .expect("outer response")
        .to_vec();

        let observers = RecordingObservers::default();
        let (valid, observation, first_dials, second_dials) = client_chain_exchange(
            &first_keys,
            &second_keys,
            [first_server.clone(), second_server.clone()],
            &application,
            [&first_request_salt, &second_request_salt],
            valid_response.clone(),
            &observers,
        )
        .await;
        assert_eq!(valid, Ok(b"reply".to_vec()), "rotation {case}");
        assert_eq!((first_dials, second_dials), (1, 0), "rotation {case}");
        let (shutdown_calls, raw_request) = {
            let observed = observation.lock().expect("wire observation");
            (observed.shutdown_calls, observed.writes.concat())
        };
        assert_eq!(shutdown_calls, 1, "rotation {case}");
        let (buffer_count, unique_buffers) = {
            let buffers = observers.buffers.lock().expect("buffers");
            (
                buffers.len(),
                buffers
                    .iter()
                    .map(|(_, _, identity)| identity)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
            )
        };
        assert_eq!(buffer_count, 4, "two fixed buffers per layer: {case}");
        assert_eq!(
            unique_buffers, 4,
            "simultaneous layer buffers are distinct: {case}"
        );

        let outer_replay = TcpReplayStore::new(1024).expect("outer replay");
        let (outer_target, inner_request) =
            decode_request(&first_keys, &raw_request, true, &outer_replay)
                .await
                .expect("outer request");
        assert_eq!(outer_target, second_server, "rotation {case}");
        let inner_replay = TcpReplayStore::new(1024).expect("inner replay");
        let (inner_target, payload) =
            decode_request(&second_keys, &inner_request, false, &inner_replay)
                .await
                .expect("inner request");
        assert_eq!(inner_target, application, "rotation {case}");
        assert!(
            payload.is_empty(),
            "no premature application payload: {case}"
        );

        for (label, keys, wire, payload, valid_keys, valid_wire) in [
            (
                "wrong hop 1",
                &wrong_first,
                raw_request.clone(),
                true,
                &first_keys,
                &raw_request,
            ),
            (
                "wrong hop 2",
                &wrong_second,
                inner_request.clone(),
                false,
                &second_keys,
                &inner_request,
            ),
        ] {
            let replay = TcpReplayStore::new(1024).expect("negative replay");
            assert!(
                matches!(
                    decode_request(keys, &wire, payload, &replay).await,
                    Err(ShadowsocksError::Detection(DetectionReason::Authentication))
                ),
                "{label}: rotation {case}"
            );
            decode_request(valid_keys, valid_wire, payload, &replay)
                .await
                .expect("valid request after isolated wrong credential");
        }
        for (label, keys, mut wire, payload, valid_keys, valid_wire) in [
            (
                "outer request tamper",
                &first_keys,
                raw_request.clone(),
                true,
                &first_keys,
                &raw_request,
            ),
            (
                "inner request tamper",
                &second_keys,
                inner_request.clone(),
                false,
                &second_keys,
                &inner_request,
            ),
        ] {
            wire[keys.tcp_profile().salt_bytes()] ^= 1;
            let replay = TcpReplayStore::new(1024).expect("tamper replay");
            assert!(
                matches!(
                    decode_request(keys, &wire, payload, &replay).await,
                    Err(ShadowsocksError::Detection(DetectionReason::Authentication))
                ),
                "{label}: rotation {case}"
            );
            decode_request(valid_keys, valid_wire, payload, &replay)
                .await
                .expect("valid request after isolated tamper");
        }

        let mut outer_tamper = valid_response.clone();
        outer_tamper[first_profile.salt_bytes()] ^= 1;
        let mut inner_tamper = inner_response.clone();
        inner_tamper[second_profile.salt_bytes()] ^= 1;
        let wrapped_inner_tamper = encode_response_first_write(
            &first_keys,
            &first_response_salt,
            NOW,
            &first_request_salt,
            &inner_tamper,
        )
        .expect("authenticated outer tamper wrapper")
        .to_vec();
        let wrong_outer_response = encode_response_first_write(
            &wrong_first,
            &first_response_salt,
            NOW,
            &first_request_salt,
            &inner_response,
        )
        .expect("wrong outer credential response")
        .to_vec();
        let wrong_inner = encode_response_first_write(
            &wrong_second,
            &second_response_salt,
            NOW,
            &second_request_salt,
            b"reply",
        )
        .expect("wrong inner credential response");
        let wrong_inner_response = encode_response_first_write(
            &first_keys,
            &first_response_salt,
            NOW,
            &first_request_salt,
            &wrong_inner,
        )
        .expect("wrong inner wrapper")
        .to_vec();
        for (label, response) in [
            ("outer response tamper", outer_tamper),
            ("inner response tamper", wrapped_inner_tamper),
            ("wrong hop 1 response credential", wrong_outer_response),
            ("wrong hop 2 response credential", wrong_inner_response),
        ] {
            let negative_observers = RecordingObservers::default();
            let (result, _, first_dials, second_dials) = client_chain_exchange(
                &first_keys,
                &second_keys,
                [first_server.clone(), second_server.clone()],
                &application,
                [&first_request_salt, &second_request_salt],
                response,
                &negative_observers,
            )
            .await;
            assert!(
                matches!(
                    result,
                    Err(ShadowsocksError::Detection(
                        DetectionReason::Authentication | DetectionReason::ReadFailed
                    ))
                ),
                "{label}: rotation {case}: {result:?}"
            );
            assert_eq!(
                (first_dials, second_dials),
                (1, 0),
                "{label}: rotation {case}"
            );
            let after_observers = RecordingObservers::default();
            assert_eq!(
                client_chain_exchange(
                    &first_keys,
                    &second_keys,
                    [first_server.clone(), second_server.clone()],
                    &application,
                    [&first_request_salt, &second_request_salt],
                    valid_response.clone(),
                    &after_observers,
                )
                .await
                .0,
                Ok(b"reply".to_vec()),
                "valid response after {label}: rotation {case}"
            );
        }
    }
}
