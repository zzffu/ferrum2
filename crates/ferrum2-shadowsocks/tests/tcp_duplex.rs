mod common;

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use ferrum2_shadowsocks::{ClientTcpOutbound, PlainDuplex, ShadowsocksTcpInbound, TcpReplayStore};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes,
    custom_request_wire, flush_plain, provider, read_plain, request_data_frames,
    response_wire_and_frames, salt_from_u64, server_target, target, valid_request_wire,
    write_plain,
};

#[tokio::test]
async fn client_upload_progresses_while_response_fixed_read_is_pending() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(800);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let (io, observation) = RecordingIo::new([]);
    let connector = RecordingConnector::succeeds(io.with_pending_reads(1));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .open_stream(&target())
        .await
        .expect("request first write");

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut destination = [0_u8; 16];
    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(write_plain(&mut flow, b"first").await, Ok(5));
    assert_eq!(write_plain(&mut flow, b"second").await, Ok(6));
    flush_plain(&mut flow).await.expect("drain upload");

    let observed = observation.lock().expect("observation");
    assert_eq!(observed.read_calls, 0);
    assert!(observed.write_calls >= 3, "request plus two upload frames");
}

#[tokio::test]
async fn server_request_rx_progresses_while_first_response_is_pending() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let request_salt = salt_from_u64(801);
    let request = valid_request_wire(NOW, &request_salt);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(request_data_frames(&request_salt, &[b"upload"]));
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [0_u8; 16];

    let read = read_plain(&mut flow, &mut destination)
        .await
        .expect("subsequent request");

    assert_eq!(&destination[..read], b"upload");
    assert_eq!(observation.lock().expect("observation").write_calls, 0);
}

#[tokio::test]
async fn session_owns_initial_payload_and_flow_starts_at_subsequent_frame() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let request_salt = salt_from_u64(802);
    let variable = [1, 127, 0, 0, 1, 0x1f, 0x90, 0, 0, b'p', b'i', b'n', b'g'];
    let request = custom_request_wire(&request_salt, 0, NOW, &variable);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(request_data_frames(&request_salt, &[b"later"]));
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let session = inbound.accept_stream(io).await.expect("request");

    assert_eq!(session.target, target());
    assert_eq!(session.initial_payload.as_ref(), b"ping");
    let mut flow = session.stream;
    let mut destination = [0_u8; 16];
    let read = read_plain(&mut flow, &mut destination)
        .await
        .expect("subsequent frame");
    assert_eq!(&destination[..read], b"later");
}

#[tokio::test]
async fn production_shaped_flows_are_send_and_unpin() {
    fn assert_send_unpin<T: Send + Unpin>(_: &T) {}

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let request_salt = salt_from_u64(803);
    let request = valid_request_wire(NOW, &request_salt);
    let response_salt = salt_from_u64(804);
    let random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());
    let (server_io, _) = RecordingIo::request(&request);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let server = inbound.accept_stream(server_io).await.expect("server");
    assert_send_unpin(&server.stream);

    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"pong", &[]);
    let (client_io, _) = RecordingIo::new([response[..59].to_vec(), response[59..].to_vec()]);
    let connector = RecordingConnector::succeeds(client_io);
    let client_random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random);
    let client = outbound.open_stream(&target()).await.expect("client");
    assert_send_unpin(&client);
}
