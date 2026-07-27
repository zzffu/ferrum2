mod common;

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use ferrum2_shadowsocks::{
    ClientTcpOutbound, FlowTerminal, PlainDuplex, ProtocolReason, ShadowsocksError,
    ShadowsocksTcpInbound, TcpReplayStore, TransportPhase,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes,
    flush_plain, provider, read_plain, request_data_frames, salt_from_u64, server_target,
    shutdown_plain, target, valid_request_wire, write_plain,
};

#[test]
fn closed_contract_is_exact_copyable_and_source_free() {
    fn assert_closed<T: Clone + Copy + std::fmt::Debug + Eq + PartialEq>() {}
    assert_closed::<ProtocolReason>();
    assert_closed::<TransportPhase>();
    assert_closed::<FlowTerminal>();
    assert_closed::<ShadowsocksError>();

    let protocol = ShadowsocksError::Protocol(ProtocolReason::Authentication);
    let transport = ShadowsocksError::Transport(TransportPhase::WriteZero);
    assert_eq!(format!("{protocol}"), "SIP022 protocol failure");
    assert_eq!(format!("{transport}"), "SIP022 transport failure");
    assert!(!format!("{protocol:?}{transport:?}").contains("sentinel-source"));
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
    assert_eq!(write_plain(&mut client, b"upload").await, Ok(6));
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
