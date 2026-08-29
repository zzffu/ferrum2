mod common;

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, FlowTerminal, MAX_PAYLOAD_LEN, PlainDuplex, ProtocolReason,
    REQUEST_FIRST_READ_LEN, RESPONSE_FIRST_READ_LEN, ShadowsocksError, ShadowsocksTcpInbound,
    TcpReplayStore,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, client_random_bytes, provider,
    read_plain, request_data_frames, response_wire_and_frames, salt_from_u64, server_target,
    target, valid_request_wire,
};

#[tokio::test]
async fn request_fixed_region_is_single_operation_then_variable_accepts_one_byte_and_mixed() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let salt = salt_from_u64(900);
    let request = valid_request_wire(NOW, &salt);
    let one_byte = request[REQUEST_FIRST_READ_LEN..]
        .iter()
        .map(|byte| vec![*byte])
        .collect::<Vec<_>>();
    let variable = &request[REQUEST_FIRST_READ_LEN..];
    let mixed = vec![
        variable[..1].to_vec(),
        variable[1..4].to_vec(),
        variable[4..].to_vec(),
    ];

    for fragments in [one_byte, mixed] {
        let replay = TcpReplayStore::new(1024).expect("capacity");
        let mut reads = vec![request[..REQUEST_FIRST_READ_LEN].to_vec()];
        let fragment_count = fragments.len();
        reads.extend(fragments);
        let (io, observation) = RecordingIo::new(reads);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

        inbound.accept_stream(io).await.expect("fragmented request");

        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], REQUEST_FIRST_READ_LEN);
        assert_eq!(observed.read_calls, 1 + fragment_count);
    }
}

#[tokio::test]
async fn response_fixed_region_is_single_operation_then_payload_accepts_one_byte_and_mixed() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(901);
    let response_salt = salt_from_u64(902);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"fragmented", &[]);
    let payload = &response[RESPONSE_FIRST_READ_LEN..];
    let one_byte = payload.iter().map(|byte| vec![*byte]).collect::<Vec<_>>();
    let mixed = vec![
        payload[..1].to_vec(),
        payload[1..5].to_vec(),
        payload[5..].to_vec(),
    ];

    for fragments in [one_byte, mixed] {
        let mut reads = vec![response[..RESPONSE_FIRST_READ_LEN].to_vec()];
        let fragment_count = fragments.len();
        reads.extend(fragments);
        let (io, observation) = RecordingIo::new(reads);
        let connector = RecordingConnector::succeeds(io);
        let random = ScriptedRandom::new(client_random_bytes(&request_salt));
        let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
        let mut flow = outbound
            .connect_server()
            .await
            .expect("server connection")
            .write_request(&target())
            .await
            .expect("client");
        let mut destination = [0_u8; 32];

        let read = read_plain(&mut flow, &mut destination)
            .await
            .expect("fragmented response");

        assert_eq!(&destination[..read], b"fragmented");
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], RESPONSE_FIRST_READ_LEN);
        assert_eq!(observed.read_calls, 1 + fragment_count);
    }
}

#[tokio::test]
async fn subsequent_length_and_payload_accept_one_byte_and_mixed_fragmentation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(903);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"one-byte", b"mixed"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    for byte in frames[0].iter().chain(frames[1].iter()) {
        reads.push(vec![*byte]);
    }
    reads.push(frames[2][..5].to_vec());
    reads.push(frames[2][5..].to_vec());
    reads.push(frames[3][..2].to_vec());
    reads.push(frames[3][2..].to_vec());
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [0_u8; 32];

    let first = read_plain(&mut flow, &mut destination)
        .await
        .expect("first");
    assert_eq!(&destination[..first], b"one-byte");
    let second = read_plain(&mut flow, &mut destination)
        .await
        .expect("second");
    assert_eq!(&destination[..second], b"mixed");
}

#[tokio::test]
async fn client_subsequent_length_and_payload_accept_one_byte_and_mixed_fragmentation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(907);
    let response_salt = salt_from_u64(908);
    let (response, frames) = response_wire_and_frames(
        &request_salt,
        &response_salt,
        b"first",
        &[b"one-byte", b"mixed"],
    );
    let mut reads = vec![response[..59].to_vec(), response[59..].to_vec()];
    for byte in frames[0].iter().chain(frames[1].iter()) {
        reads.push(vec![*byte]);
    }
    reads.push(frames[2][..3].to_vec());
    reads.push(frames[2][3..].to_vec());
    reads.push(frames[3][..1].to_vec());
    reads.push(frames[3][1..4].to_vec());
    reads.push(frames[3][4..].to_vec());
    let (io, _) = RecordingIo::new(reads);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("client");
    let mut destination = [0_u8; 32];

    let first = read_plain(&mut flow, &mut destination)
        .await
        .expect("first response");
    assert_eq!(&destination[..first], b"first");
    let one_byte = read_plain(&mut flow, &mut destination)
        .await
        .expect("one-byte fragmented subsequent response");
    assert_eq!(&destination[..one_byte], b"one-byte");
    let mixed = read_plain(&mut flow, &mut destination)
        .await
        .expect("mixed fragmented subsequent response");
    assert_eq!(&destination[..mixed], b"mixed");
}

#[tokio::test]
async fn ready_plaintext_range_never_exposes_stale_or_unauthenticated_bytes() {
    const SENTINEL: u8 = 0x6d;

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(909);
    let request = valid_request_wire(NOW, &salt);
    let large = vec![0xa5; 257];
    let mut frames = request_data_frames(&salt, &[&large, b"z", b"tampered"]);
    *frames[5].last_mut().expect("tampered payload tag") ^= 1;
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [SENTINEL; 7];
    let mut received = Vec::with_capacity(large.len());

    while received.len() < large.len() {
        destination.fill(SENTINEL);
        let read = read_plain(&mut flow, &mut destination)
            .await
            .expect("large frame chunk");
        received.extend_from_slice(&destination[..read]);
        assert!(destination[read..].iter().all(|byte| *byte == SENTINEL));
    }
    assert_eq!(received, large);

    destination.fill(SENTINEL);
    let read = read_plain(&mut flow, &mut destination)
        .await
        .expect("one-byte frame");
    assert_eq!(read, 1);
    assert_eq!(destination[0], b'z');
    assert!(destination[1..].iter().all(|byte| *byte == SENTINEL));

    destination.fill(SENTINEL);
    assert!(read_plain(&mut flow, &mut destination).await.is_err());
    assert!(destination.iter().all(|byte| *byte == SENTINEL));
}

#[tokio::test]
async fn worker_local_copyback_handles_large_remainder_and_tamper_without_publication() {
    const SENTINEL: u8 = 0x6d;

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(913);
    let request = valid_request_wire(NOW, &salt);
    let ordinary = vec![0xa5; 32 * 1024];
    let maximum = (0..MAX_PAYLOAD_LEN)
        .map(|index| (index % 251) as u8 + 1)
        .collect::<Vec<_>>();
    let tampered = vec![0x5a; 4 * 1024];
    let mut frames = request_data_frames(&salt, &[&ordinary, &maximum, &tampered]);
    *frames[5].last_mut().expect("tampered payload tag") ^= 1;
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;

    let mut full_destination = vec![SENTINEL; ordinary.len() + 7];
    let read = read_plain(&mut flow, &mut full_destination)
        .await
        .expect("32 KiB frame");
    assert_eq!(read, ordinary.len());
    assert_eq!(&full_destination[..read], ordinary);
    assert!(
        full_destination[read..]
            .iter()
            .all(|byte| *byte == SENTINEL)
    );

    let mut small_destination = [SENTINEL; 997];
    let mut received = Vec::with_capacity(maximum.len());
    while received.len() < maximum.len() {
        small_destination.fill(SENTINEL);
        let read = read_plain(&mut flow, &mut small_destination)
            .await
            .expect("maximum frame remainder");
        assert!(read > 0);
        received.extend_from_slice(&small_destination[..read]);
        assert!(
            small_destination[read..]
                .iter()
                .all(|byte| *byte == SENTINEL)
        );
    }
    assert_eq!(received, maximum);

    small_destination.fill(SENTINEL);
    assert!(read_plain(&mut flow, &mut small_destination).await.is_err());
    assert!(small_destination.iter().all(|byte| *byte == SENTINEL));
}

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn authenticated_zero_length_frame_self_wakes_and_never_looks_like_eof() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(904);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"", b"after-zero"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0_u8; 32];

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("next nonempty frame must become visible");
    };
    assert_eq!(&destination[..read], b"after-zero");
    assert!(wake_counter.0.load(Ordering::SeqCst) >= 3);
}

#[tokio::test]
async fn mid_subsequent_frame_eof_is_protocol_not_detection_and_freezes_counts() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(905);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"truncated"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.push(frames[0].clone());
    reads.push(frames[1][..3].to_vec());
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [0_u8; 32];

    let error = read_plain(&mut flow, &mut destination)
        .await
        .expect_err("mid-frame EOF");

    assert_eq!(
        error,
        ShadowsocksError::Protocol(ProtocolReason::FrameBounds)
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::FrameBounds))
    );
    let counts = {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.abortive_calls, 0);
        (observed.read_calls, observed.write_calls)
    };
    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!((observed.read_calls, observed.write_calls), counts);
}

#[tokio::test]
async fn mid_request_variable_eof_is_detection_before_replay_mutation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(909);
    let request = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::new([
        request[..REQUEST_FIRST_READ_LEN].to_vec(),
        request[REQUEST_FIRST_READ_LEN..REQUEST_FIRST_READ_LEN + 3].to_vec(),
    ]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

    assert_eq!(
        inbound.accept_stream(io).await.err(),
        Some(ShadowsocksError::Detection(DetectionReason::ShortRead))
    );
    assert_eq!(replay.entry_count().expect("replay"), 0);
    let observed = observation.lock().expect("observation");
    assert_eq!(observed.abortive_calls, 1);
    assert_eq!(observed.write_calls, 0);
}

#[tokio::test]
async fn mid_response_first_payload_eof_is_detection_and_terminal_is_frozen() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(910);
    let response_salt = salt_from_u64(911);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"payload", &[]);
    let (io, observation) = RecordingIo::new([
        response[..RESPONSE_FIRST_READ_LEN].to_vec(),
        response[RESPONSE_FIRST_READ_LEN..RESPONSE_FIRST_READ_LEN + 3].to_vec(),
    ]);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("client");
    let mut destination = [0_u8; 16];

    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Detection(DetectionReason::ShortRead))
    );
    let frozen = {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.abortive_calls, 1);
        (observed.read_calls, observed.write_calls)
    };
    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!((observed.read_calls, observed.write_calls), frozen);
    assert_eq!(observed.abortive_calls, 1);
}

#[tokio::test]
async fn mid_subsequent_length_eof_is_protocol_and_terminal_is_frozen() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(912);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"length"]);
    let (io, observation) = RecordingIo::new([
        request[..REQUEST_FIRST_READ_LEN].to_vec(),
        request[REQUEST_FIRST_READ_LEN..].to_vec(),
        frames[0][..3].to_vec(),
    ]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [0_u8; 16];

    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds))
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::FrameBounds))
    );
    let frozen = {
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.abortive_calls, 0);
        (observed.read_calls, observed.write_calls)
    };
    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds))
    );
    let observed = observation.lock().expect("observation");
    assert_eq!((observed.read_calls, observed.write_calls), frozen);
    assert_eq!(observed.abortive_calls, 0);
}

#[tokio::test]
async fn short_fixed_response_remains_detection() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(906);
    let (io, observation) = RecordingIo::new([vec![0; RESPONSE_FIRST_READ_LEN - 1]]);
    let connector = RecordingConnector::succeeds(io);
    let random = ScriptedRandom::new(client_random_bytes(&request_salt));
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .connect_server()
        .await
        .expect("server connection")
        .write_request(&target())
        .await
        .expect("client");
    let mut destination = [0_u8; 8];

    assert_eq!(
        read_plain(&mut flow, &mut destination).await,
        Err(ShadowsocksError::Detection(DetectionReason::ShortRead))
    );
    assert_eq!(observation.lock().expect("observation").abortive_calls, 1);
}
