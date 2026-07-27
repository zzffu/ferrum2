mod common;

use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use ferrum2_shadowsocks::{ClientTcpOutbound, PlainDuplex, ShadowsocksTcpInbound, TcpReplayStore};

use common::{
    CountingKeyProvider, FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom,
    client_random_bytes, custom_request_wire, flush_plain, provider, read_plain,
    request_data_frames, response_wire_and_frames, salt_from_u64, server_target, target,
    valid_request_wire, write_plain,
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

#[tokio::test]
async fn pending_response_capability_derives_each_direction_cipher_exactly_once() {
    let keys = CountingKeyProvider::new();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(805);
    let response_salt = salt_from_u64(806);
    let (response, frames) =
        response_wire_and_frames(&request_salt, &response_salt, b"first", &[b"later"]);
    let (client_io, _) = RecordingIo::new([
        response[..59].to_vec(),
        response[59..].to_vec(),
        frames[0].clone(),
        frames[1].clone(),
    ]);
    let connector = RecordingConnector::succeeds(client_io.with_pending_reads(3));
    let client_random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound =
        ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &client_random);
    let mut client = outbound.open_stream(&target()).await.expect("client");
    assert_eq!(keys.call_count(), 1, "request sealer is the current owner");

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut destination = [0_u8; 16];
    for _ in 0..3 {
        assert!(matches!(
            Pin::new(&mut client).poll_read_plain(&mut cx, &mut destination),
            Poll::Pending
        ));
        assert_eq!(
            keys.call_count(),
            1,
            "pending capability must not derive early"
        );
    }
    assert!(matches!(
        Pin::new(&mut client).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(keys.call_count(), 2, "response opener derives exactly once");
    let first = read_plain(&mut client, &mut destination)
        .await
        .expect("first response");
    assert_eq!(&destination[..first], b"first");
    let subsequent = read_plain(&mut client, &mut destination)
        .await
        .expect("subsequent response");
    assert_eq!(&destination[..subsequent], b"later");
    assert_eq!(keys.call_count(), 2, "subsequent RX reuses the opener");

    let replay = TcpReplayStore::new(1024).expect("capacity");
    let request = valid_request_wire(NOW, &request_salt);
    let (server_io, _) = RecordingIo::request(&request);
    let server_random = ScriptedRandom::new(response_salt.as_bytes().iter().copied());
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &server_random, &replay);
    let mut server = inbound
        .accept_stream(server_io)
        .await
        .expect("server")
        .stream;
    assert_eq!(keys.call_count(), 3, "request opener is the current owner");
    assert_eq!(write_plain(&mut server, &[]).await, Ok(0));
    assert_eq!(flush_plain(&mut server).await, Ok(()));
    assert_eq!(
        keys.call_count(),
        3,
        "pending response capability is still unused"
    );
    assert_eq!(write_plain(&mut server, b"first").await, Ok(5));
    assert_eq!(keys.call_count(), 4, "response sealer derives once");
    flush_plain(&mut server).await.expect("first response");
    assert_eq!(write_plain(&mut server, b"later").await, Ok(5));
    flush_plain(&mut server).await.expect("subsequent response");
    assert_eq!(keys.call_count(), 4, "subsequent TX reuses the sealer");
}

#[tokio::test]
async fn always_ready_one_byte_duplex_uses_at_most_one_io_per_outer_poll_and_is_fair() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(807);
    let response_salt = salt_from_u64(808);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"x", &[]);
    let mut reads = vec![response[..59].to_vec()];
    reads.extend(response[59..].iter().map(|byte| vec![*byte]));
    let (io, observation) = RecordingIo::new(reads);
    let connector = RecordingConnector::succeeds(io.with_write_limit_after(1, 1));
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound.open_stream(&target()).await.expect("client");
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut destination = [0_u8; 8];

    let mut read_completed = false;
    let mut admitted_upload = false;
    for _ in 0..64 {
        let before = {
            let observed = observation.lock().expect("observation");
            observed.read_calls + observed.write_calls
        };
        match Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination) {
            Poll::Ready(Ok(1)) => read_completed = true,
            Poll::Ready(Ok(other)) => panic!("unexpected response length {other}"),
            Poll::Ready(Err(error)) => panic!("unexpected response error {error:?}"),
            Poll::Pending => {}
        }
        let after = {
            let observed = observation.lock().expect("observation");
            observed.read_calls + observed.write_calls
        };
        assert!(
            after - before <= 1,
            "read outer poll performed multiple I/O"
        );

        let before = after;
        match Pin::new(&mut flow).poll_write_plain(&mut cx, b"u") {
            Poll::Ready(Ok(1)) => admitted_upload = true,
            Poll::Ready(Ok(other)) => panic!("unexpected upload admission {other}"),
            Poll::Ready(Err(error)) => panic!("unexpected upload error {error:?}"),
            Poll::Pending => {}
        }
        let after = {
            let observed = observation.lock().expect("observation");
            observed.read_calls + observed.write_calls
        };
        assert!(
            after - before <= 1,
            "write outer poll performed multiple I/O"
        );
        if read_completed && admitted_upload {
            break;
        }
    }

    let observed = observation.lock().expect("observation");
    assert!(read_completed, "one-byte response made bounded progress");
    assert_eq!(destination[0], b'x');
    assert!(admitted_upload, "opposite TX made bounded progress");
    assert!(observed.read_calls <= 18, "fixed plus 17 payload bytes");
    assert!(
        observed.write_calls > 1,
        "request and upload both progressed"
    );
}
