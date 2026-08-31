mod common;

use ferrum2_core::AbortiveClose;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use ferrum2_shadowsocks::{
    ClientTcpOutbound, DetectionReason, FlowTerminal, PlainDuplex, ProtocolReason,
    REQUEST_FIRST_READ_LEN, RESPONSE_FIRST_READ_LEN, ShadowsocksError, ShadowsocksTcpInbound,
    TcpReplayStore, TransportIo,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, ScriptedRandom, SourceSentinel,
    client_random_bytes, provider, read_plain, request_data_frames, response_wire_and_frames,
    salt_from_u64, server_target, target, valid_request_wire,
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
async fn subsequent_frames_run_through_ready_fragments_without_self_wake() {
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
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0_u8; 32];

    let Poll::Ready(Ok(first)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("one-byte fragments must complete in one outer poll");
    };
    assert_eq!(&destination[..first], b"one-byte");
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 0);

    let Poll::Ready(Ok(second)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("mixed fragments must complete in one outer poll");
    };
    assert_eq!(&destination[..second], b"mixed");
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn buffered_plaintext_drains_before_the_next_transport_read() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(914);
    let request = valid_request_wire(NOW, &salt);
    let payload = b"buffered-data";
    let frames = request_data_frames(&salt, &[payload, b"next"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut destination = [0_u8; 4];
    let mut opened = Vec::new();

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("first frame must authenticate and publish in one outer poll");
    };
    opened.extend_from_slice(&destination[..read]);
    let reads_after_frame = observation.lock().expect("observation").read_calls;

    while opened.len() < payload.len() {
        let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
        else {
            panic!("buffered plaintext must remain immediately readable");
        };
        opened.extend_from_slice(&destination[..read]);
        assert_eq!(
            observation.lock().expect("observation").read_calls,
            reads_after_frame,
            "BufferedData must drain before reading the next frame"
        );
    }
    assert_eq!(opened, payload);

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("next frame must become readable after BufferedData drains");
    };
    assert_eq!(&destination[..read], b"next");
    assert!(
        observation.lock().expect("observation").read_calls > reads_after_frame,
        "transport reads resume only after BufferedData completes"
    );
}

#[tokio::test]
async fn failed_payload_authentication_never_publishes_or_reads_a_later_frame() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(915);
    let request = valid_request_wire(NOW, &salt);
    let mut frames = request_data_frames(&salt, &[b"forged", b"must-not-read"]);
    *frames[1].last_mut().expect("payload tag") ^= 1;
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0xa5_u8; 32];

    assert_eq!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Protocol(
            ProtocolReason::Authentication
        )))
    );
    assert_eq!(destination, [0xa5; 32]);
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 0);
    let reads_at_failure = observation.lock().expect("observation").read_calls;
    assert_eq!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Protocol(
            ProtocolReason::Authentication
        )))
    );
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        reads_at_failure,
        "frozen terminal must not read the later frame"
    );
}

#[tokio::test]
async fn empty_destination_does_not_consume_transport_or_rx_nonce() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(916);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"after-empty"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let reads_before_empty = observation.lock().expect("observation").read_calls;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut empty = [];

    assert_eq!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut empty),
        Poll::Ready(Ok(0))
    );
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        reads_before_empty
    );

    let mut destination = [0_u8; 32];
    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("nonempty destination must read with the original RX nonce");
    };
    assert_eq!(&destination[..read], b"after-empty");
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

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

enum ReadBoundary {
    Pending(Arc<Mutex<Option<Waker>>>),
    OverReport,
}

struct ReadBoundaryAfterReads {
    inner: RecordingIo,
    boundary_after: usize,
    successful_reads: usize,
    boundary: Option<ReadBoundary>,
}

impl TransportIo for ReadBoundaryAfterReads {
    type IoError = SourceSentinel;

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        if self.successful_reads == self.boundary_after
            && let Some(boundary) = self.boundary.take()
        {
            match boundary {
                ReadBoundary::Pending(registered_waker) => {
                    *registered_waker.lock().expect("registered waker") = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                ReadBoundary::OverReport => return Poll::Ready(Ok(usize::MAX)),
            }
        }
        let result = Pin::new(&mut self.inner).poll_read(cx, destination);
        if matches!(&result, Poll::Ready(Ok(read)) if *read > 0) {
            self.successful_reads += 1;
        }
        result
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut self.inner).poll_write(cx, source)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AbortiveClose for ReadBoundaryAfterReads {
    type Error = ();

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive()
    }
}

#[tokio::test]
async fn completed_length_stops_only_at_payload_io_pending_and_uses_transport_waker() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(913);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"after-pending"]);
    let (inner, _) = RecordingIo::new([
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0].clone(),
        frames[1].clone(),
    ]);
    let registered_waker = Arc::new(Mutex::new(None));
    let io = ReadBoundaryAfterReads {
        inner,
        boundary_after: 3,
        successful_reads: 0,
        boundary: Some(ReadBoundary::Pending(Arc::clone(&registered_waker))),
    };
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
    assert_eq!(
        wake_counter.0.load(Ordering::SeqCst),
        0,
        "codec must not self-wake after the completed length"
    );
    let transport_waker = registered_waker
        .lock()
        .expect("registered waker")
        .take()
        .expect("payload Pending registered the current waker");
    assert!(transport_waker.will_wake(&waker));
    transport_waker.wake_by_ref();

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("repoll after transport readiness must finish the saved payload");
    };
    assert_eq!(&destination[..read], b"after-pending");
    assert_eq!(
        wake_counter.0.load(Ordering::SeqCst),
        1,
        "only the transport readiness wake is observable"
    );
}

#[tokio::test]
async fn overreported_partial_length_is_frozen_frame_bounds_instead_of_panicking() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(917);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"unread"]);
    let (inner, observation) = RecordingIo::new([
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0][..1].to_vec(),
    ]);
    let io = ReadBoundaryAfterReads {
        inner,
        boundary_after: 3,
        successful_reads: 0,
        boundary: Some(ReadBoundary::OverReport),
    };
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut destination = [0xa5_u8; 16];

    assert_eq!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds)))
    );
    assert_eq!(destination, [0xa5; 16]);
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::FrameBounds))
    );
    let reads_at_failure = observation.lock().expect("observation").read_calls;
    assert_eq!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Protocol(ProtocolReason::FrameBounds)))
    );
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        reads_at_failure
    );
}

#[tokio::test]
async fn authenticated_zero_length_frame_continues_inline_without_false_eof_or_self_wake() {
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

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("zero frame and following payload must complete in one outer poll");
    };
    assert_eq!(&destination[..read], b"after-zero");
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 0);
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
