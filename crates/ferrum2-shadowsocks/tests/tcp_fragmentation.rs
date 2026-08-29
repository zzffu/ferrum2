mod common;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use ferrum2_shadowsocks::{
    BufferRole, ClientTcpOutbound, DetectionReason, FlowTerminal, MAX_PAYLOAD_LEN,
    PlainBufferedDuplex, PlainDuplex, ProtocolReason, REQUEST_FIRST_READ_LEN,
    RESPONSE_FIRST_READ_LEN, ShadowsocksError, ShadowsocksTcpInbound, TcpReplayStore,
    TransportPhase,
};

use common::{
    FakeClock, NOW, RecordingConnector, RecordingIo, RecordingObservers, ScriptedRandom,
    client_random_bytes, provider, read_plain, request_data_frames, response_wire_and_frames,
    salt_from_u64, server_target, target, valid_request_wire,
};

async fn fill_plain_snapshot(
    flow: &mut (impl PlainBufferedDuplex + ?Sized),
) -> Result<(usize, Vec<u8>), ShadowsocksError> {
    poll_fn(|cx| match Pin::new(&mut *flow).poll_fill_plain_buf(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(view)) => Poll::Ready(Ok((view.as_ptr() as usize, view.to_vec()))),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    })
    .await
}

#[tokio::test]
async fn request_fixed_region_accepts_one_and_seven_byte_reads_across_pending() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let salt = salt_from_u64(900);
    let request = valid_request_wire(NOW, &salt);

    for width in [1, 7] {
        let replay = TcpReplayStore::new(1024).expect("capacity");
        let mut reads = request[..REQUEST_FIRST_READ_LEN]
            .chunks(width)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        reads.push(request[REQUEST_FIRST_READ_LEN..].to_vec());
        let (io, observation) = RecordingIo::new(reads);
        let io = io.with_pending_reads_after(1, 1);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

        let session = inbound.accept_stream(io).await.expect("fragmented request");

        assert_eq!(session.target, target(), "width {width}");
        assert!(session.initial_payload.is_empty(), "width {width}");
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], REQUEST_FIRST_READ_LEN);
        assert_eq!(
            observed.read_calls,
            REQUEST_FIRST_READ_LEN.div_ceil(width) + 1,
            "width {width}"
        );
    }
}

#[tokio::test]
async fn request_variable_region_accepts_one_byte_and_mixed_fragmentation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let salt = salt_from_u64(901);
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
        let mut remaining = request.len() - REQUEST_FIRST_READ_LEN;
        let expected_read_lengths = std::iter::once(REQUEST_FIRST_READ_LEN)
            .chain(fragments.iter().map(|fragment| {
                let exposed = remaining;
                remaining -= fragment.len();
                exposed
            }))
            .collect::<Vec<_>>();
        assert_eq!(remaining, 0);
        let replay = TcpReplayStore::new(1024).expect("capacity");
        let mut reads = vec![request[..REQUEST_FIRST_READ_LEN].to_vec()];
        let fragment_count = fragments.len();
        reads.extend(fragments);
        let (io, observation) = RecordingIo::new(reads);
        let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);

        inbound.accept_stream(io).await.expect("fragmented request");

        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths, expected_read_lengths);
        assert_eq!(observed.read_calls, 1 + fragment_count);
    }
}

#[tokio::test]
async fn response_fixed_region_accepts_one_and_seven_byte_reads_across_pending() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(902);
    let response_salt = salt_from_u64(903);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"fragmented", &[]);

    for width in [1, 7] {
        let mut reads = response[..RESPONSE_FIRST_READ_LEN]
            .chunks(width)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        reads.push(response[RESPONSE_FIRST_READ_LEN..].to_vec());
        let (io, observation) = RecordingIo::new(reads);
        let connector = RecordingConnector::succeeds(io.with_pending_reads_after(1, 1));
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

        assert_eq!(&destination[..read], b"fragmented", "width {width}");
        let observed = observation.lock().expect("observation");
        assert_eq!(observed.read_lengths[0], RESPONSE_FIRST_READ_LEN);
        assert_eq!(
            observed.read_calls,
            RESPONSE_FIRST_READ_LEN.div_ceil(width) + 1,
            "width {width}"
        );
    }
}

#[tokio::test]
async fn response_payload_accepts_one_byte_and_mixed_fragmentation() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(904);
    let response_salt = salt_from_u64(905);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"fragmented", &[]);
    let payload = &response[RESPONSE_FIRST_READ_LEN..];
    let one_byte = payload.iter().map(|byte| vec![*byte]).collect::<Vec<_>>();
    let mixed = vec![
        payload[..1].to_vec(),
        payload[1..5].to_vec(),
        payload[5..].to_vec(),
    ];

    for fragments in [one_byte, mixed] {
        let mut remaining = response.len() - RESPONSE_FIRST_READ_LEN;
        let expected_read_lengths = std::iter::once(RESPONSE_FIRST_READ_LEN)
            .chain(fragments.iter().map(|fragment| {
                let exposed = remaining;
                remaining -= fragment.len();
                exposed
            }))
            .collect::<Vec<_>>();
        assert_eq!(remaining, 0);
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
        assert_eq!(observed.read_lengths, expected_read_lengths);
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
    let (io, observation) = RecordingIo::new(reads);
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

    let mut expected_read_lengths = vec![
        REQUEST_FIRST_READ_LEN,
        request.len() - REQUEST_FIRST_READ_LEN,
    ];
    expected_read_lengths.extend((1..=frames[0].len()).rev());
    expected_read_lengths.extend((1..=frames[1].len()).rev());
    expected_read_lengths.extend([frames[2].len(), frames[2].len() - 5]);
    expected_read_lengths.extend([frames[3].len(), frames[3].len() - 2]);
    assert_eq!(
        observation.lock().expect("observation").read_lengths,
        expected_read_lengths
    );
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

    let mut expected_read_lengths = vec![
        RESPONSE_FIRST_READ_LEN,
        response.len() - RESPONSE_FIRST_READ_LEN,
    ];
    expected_read_lengths.extend((1..=frames[0].len()).rev());
    expected_read_lengths.extend((1..=frames[1].len()).rev());
    expected_read_lengths.extend([frames[2].len(), frames[2].len() - 3]);
    expected_read_lengths.extend([frames[3].len(), frames[3].len() - 1, frames[3].len() - 4]);
    assert_eq!(
        observation.lock().expect("observation").read_lengths,
        expected_read_lengths
    );
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
    let mut reads = vec![
        request[..REQUEST_FIRST_READ_LEN].to_vec(),
        request[REQUEST_FIRST_READ_LEN..].to_vec(),
    ];
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

#[tokio::test]
async fn fused_borrowed_view_points_to_copyback_scratch_without_losing_bytes() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let observers = RecordingObservers::default();
    let salt = salt_from_u64(914);
    let request = valid_request_wire(NOW, &salt);
    let first = (0..4096)
        .map(|index| (index % 251) as u8 + 1)
        .collect::<Vec<_>>();
    let second = vec![0x7b; 777];
    let frames = request_data_frames(&salt, &[&first, &second]);
    let mut reads = vec![
        request[..REQUEST_FIRST_READ_LEN].to_vec(),
        request[REQUEST_FIRST_READ_LEN..].to_vec(),
    ];
    reads.extend(frames);
    let (io, _) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay)
        .with_observers(&observers, &observers);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let decrypt_storage = observers
        .buffers
        .lock()
        .expect("buffers")
        .iter()
        .find_map(|(role, _, storage)| (*role == BufferRole::Decrypt).then_some(*storage))
        .expect("decrypt scratch allocation");

    let (first_pointer, first_view) = fill_plain_snapshot(&mut flow)
        .await
        .expect("first borrowed view");
    assert_eq!(first_pointer, decrypt_storage);
    assert_eq!(first_view, first);

    let consumed = 997;
    Pin::new(&mut flow).consume_plain(consumed);
    let (remainder_pointer, remainder) = fill_plain_snapshot(&mut flow)
        .await
        .expect("borrowed remainder");
    assert_eq!(remainder_pointer, decrypt_storage + consumed);
    assert_eq!(remainder, first[consumed..]);
    Pin::new(&mut flow).consume_plain(remainder.len());

    let (second_pointer, second_view) = fill_plain_snapshot(&mut flow)
        .await
        .expect("next borrowed view");
    assert_eq!(second_pointer, decrypt_storage);
    assert_eq!(second_view, second);
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
async fn request_fixed_partial_reads_yield_and_self_wake_once_per_transition() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(920);
    let request = valid_request_wire(NOW, &salt);
    let (io, observation) = RecordingIo::new([
        request[..7].to_vec(),
        request[7..14].to_vec(),
        request[14..REQUEST_FIRST_READ_LEN].to_vec(),
        request[REQUEST_FIRST_READ_LEN..].to_vec(),
    ]);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut accept = Box::pin(inbound.accept_stream(io));
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(accept.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(observation.lock().expect("observation").read_calls, 1);
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);

    assert!(matches!(accept.as_mut().poll(&mut cx), Poll::Pending));
    assert_eq!(observation.lock().expect("observation").read_calls, 2);
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn response_fixed_partial_reads_yield_and_self_wake_once_per_transition() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let request_salt = salt_from_u64(921);
    let response_salt = salt_from_u64(922);
    let (response, _) = response_wire_and_frames(&request_salt, &response_salt, b"payload", &[]);
    let (io, observation) = RecordingIo::new([
        response[..7].to_vec(),
        response[7..14].to_vec(),
        response[14..RESPONSE_FIRST_READ_LEN].to_vec(),
        response[RESPONSE_FIRST_READ_LEN..].to_vec(),
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
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0_u8; 16];

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(observation.lock().expect("observation").read_calls, 1);
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(observation.lock().expect("observation").read_calls, 2);
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn authenticated_zero_length_frame_yields_before_reading_the_next_frame() {
    const SENTINEL: u8 = 0x6d;

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(904);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"", b"after-zero"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.extend(frames);
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [SENTINEL; 32];

    let baseline = observation.lock().expect("observation").read_calls;

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2,
        "the zero-length frame consumes only its length and payload"
    );
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
    assert!(destination.iter().all(|byte| *byte == SENTINEL));

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("the next ready length and payload complete together");
    };
    assert_eq!(&destination[..read], b"after-zero");
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 4
    );
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ready_length_polls_one_partial_payload_without_draining() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(912);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"fragmented"]);
    let mut reads = vec![request[..43].to_vec(), request[43..].to_vec()];
    reads.push(frames[0].clone());
    reads.push(frames[1][..3].to_vec());
    reads.push(frames[1][3..].to_vec());
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0_u8; 32];
    let baseline = observation.lock().expect("observation").read_calls;

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2,
        "the completed length polls exactly one payload fragment"
    );
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("the final payload fragment produces plaintext");
    };
    assert_eq!(&destination[..read], b"fragmented");
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 3
    );
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ready_length_uses_the_pending_payload_waker_without_self_waking() {
    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(923);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"pending"]);
    let reads = [
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0].clone(),
        frames[1].clone(),
    ];
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(io.with_pending_reads_after(3, 1))
        .await
        .expect("request")
        .stream;
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);
    let mut destination = [0_u8; 16];
    let baseline = observation.lock().expect("observation").read_calls;
    assert_eq!(baseline, 2, "request handshake uses the scripted two reads");

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 1,
        "pending payload does not count as a completed transport read"
    );
    assert_eq!(
        wake_counter.0.load(Ordering::SeqCst),
        1,
        "only the underlying pending transport wakes the task"
    );

    let Poll::Ready(Ok(read)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("the payload completes when its registered waker is polled");
    };
    assert_eq!(&destination[..read], b"pending");
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2
    );
    assert_eq!(wake_counter.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mid_subsequent_frame_eof_is_protocol_not_detection_and_freezes_counts() {
    const SENTINEL: u8 = 0x6d;

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
    let mut destination = [SENTINEL; 32];
    let baseline = observation.lock().expect("observation").read_calls;
    let mut cx = Context::from_waker(Waker::noop());

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Pending
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2,
        "the ready length polls exactly one partial payload fragment"
    );
    assert!(destination.iter().all(|byte| *byte == SENTINEL));

    let Poll::Ready(Err(error)) = Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination)
    else {
        panic!("payload EOF is classified after the partial payload stage");
    };

    assert_eq!(
        error,
        ShadowsocksError::Protocol(ProtocolReason::FrameBounds)
    );
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::FrameBounds))
    );
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 3,
        "the next payload poll observes EOF without reading ahead"
    );
    assert!(destination.iter().all(|byte| *byte == SENTINEL));
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
async fn ready_length_payload_transport_error_is_terminal_without_publication() {
    const SENTINEL: u8 = 0x6d;

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(924);
    let request = valid_request_wire(NOW, &salt);
    let frames = request_data_frames(&salt, &[b"transport"]);
    let reads = [
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0].clone(),
        frames[1].clone(),
    ];
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(io.with_read_failure_after(3))
        .await
        .expect("request")
        .stream;
    let mut destination = [SENTINEL; 32];
    let baseline = observation.lock().expect("observation").read_calls;
    let mut cx = Context::from_waker(Waker::noop());

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Transport(TransportPhase::Read)))
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2,
        "the ready length directly observes the payload read error"
    );
    assert!(destination.iter().all(|byte| *byte == SENTINEL));
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Transport(TransportPhase::Read))
    );
}

#[tokio::test]
async fn ready_length_payload_auth_failure_is_terminal_without_publication() {
    const SENTINEL: u8 = 0x6d;

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1024).expect("capacity");
    let salt = salt_from_u64(925);
    let request = valid_request_wire(NOW, &salt);
    let mut frames = request_data_frames(&salt, &[b"authentication"]);
    *frames[1].last_mut().expect("payload tag") ^= 1;
    let reads = [
        request[..43].to_vec(),
        request[43..].to_vec(),
        frames[0].clone(),
        frames[1].clone(),
    ];
    let (io, observation) = RecordingIo::new(reads);
    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound.accept_stream(io).await.expect("request").stream;
    let mut destination = [SENTINEL; 32];
    let baseline = observation.lock().expect("observation").read_calls;
    let mut cx = Context::from_waker(Waker::noop());

    assert!(matches!(
        Pin::new(&mut flow).poll_read_plain(&mut cx, &mut destination),
        Poll::Ready(Err(ShadowsocksError::Protocol(
            ProtocolReason::Authentication
        )))
    ));
    assert_eq!(
        observation.lock().expect("observation").read_calls,
        baseline + 2,
        "the ready length authenticates exactly one payload"
    );
    assert!(destination.iter().all(|byte| *byte == SENTINEL));
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::Protocol(ProtocolReason::Authentication))
    );
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
