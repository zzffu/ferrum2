//! In-memory socket versus leased-flow costs, not TCP reactor or OS throughput.
//! Recipe v1: Quick = 64-byte payload, 64 windows; Confirm = 1360-byte
//! payload, 128 windows. Every window has 1024 continuous rounds on one duplex
//! pair, capacity exactly one payload. Payload byte i is (i * 37 + 11) modulo
//! 256. Each round receives one payload and sends two; pending recipes additionally
//! poll the empty receive half and full send half before the peer makes progress.
//! Both subjects use the same monomorphized driver, captures and counting waker.
//! The initial untimed window warms storage and verifies the full recipe. No
//! clock is consumed by I/O: round indices are explicit logical ticks. Instant
//! measures only fixed windows. This does not instrument or claim allocations.

use crate::OwnerWake;
use crate::tcp::{FlowSocket, tcp_flow_from_stream};
use ferrum2_runtime::OwnerRegistry;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

const ROUNDS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    Ready(usize),
    Error(io::ErrorKind),
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

struct Capture {
    received: Vec<u8>,
    sent_first: Vec<u8>,
    sent_second: Vec<u8>,
    outcomes: Vec<[Outcome; 8]>,
}

impl Capture {
    fn new(payload_len: usize) -> Self {
        Self {
            received: vec![0; ROUNDS * payload_len],
            sent_first: vec![0; ROUNDS * payload_len],
            sent_second: vec![0; ROUNDS * payload_len],
            outcomes: vec![[Outcome::Pending; 8]; ROUNDS],
        }
    }

    fn validate(&self, payload: &[u8], pending: bool) {
        let ready = Outcome::Ready(payload.len());
        let initial = if pending { Outcome::Pending } else { ready };
        let expected = [initial, ready, ready, ready, initial, ready, ready, ready];
        for (tick, outcomes) in self.outcomes.iter().enumerate() {
            assert_eq!(*outcomes, expected, "poll outcomes at logical tick {tick}");
        }
        for capture in [&self.received, &self.sent_first, &self.sent_second] {
            for (tick, bytes) in capture.chunks_exact(payload.len()).enumerate() {
                assert_eq!(bytes, payload, "complete bytes at logical tick {tick}");
            }
        }
    }
}

fn read<S: AsyncRead + Unpin>(
    stream: &mut S,
    context: &mut Context<'_>,
    destination: &mut [u8],
) -> Outcome {
    let mut buffer = ReadBuf::new(destination);
    match Pin::new(stream).poll_read(context, &mut buffer) {
        Poll::Pending => Outcome::Pending,
        Poll::Ready(Ok(())) => Outcome::Ready(buffer.filled().len()),
        Poll::Ready(Err(error)) => Outcome::Error(error.kind()),
    }
}

fn write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    context: &mut Context<'_>,
    payload: &[u8],
) -> Outcome {
    match Pin::new(stream).poll_write(context, payload) {
        Poll::Pending => Outcome::Pending,
        Poll::Ready(Ok(written)) => Outcome::Ready(written),
        Poll::Ready(Err(error)) => Outcome::Error(error.kind()),
    }
}

fn window<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    peer: &mut DuplexStream,
    context: &mut Context<'_>,
    payload: &[u8],
    pending: bool,
    capture: &mut Capture,
) {
    let width = payload.len();
    for tick in 0..ROUNDS {
        let range = tick * width..(tick + 1) * width;
        let received = &mut capture.received[range.clone()];
        let sent_first = &mut capture.sent_first[range.clone()];
        let sent_second = &mut capture.sent_second[range];
        let outcomes = &mut capture.outcomes[tick];
        // For Ready recipes these two slots are sentinels, not extra polls.
        outcomes[0] = if pending {
            read(stream, context, received)
        } else {
            Outcome::Ready(width)
        };
        outcomes[1] = write(peer, context, payload);
        outcomes[2] = read(stream, context, received);
        outcomes[3] = write(stream, context, payload);
        outcomes[4] = if pending {
            write(stream, context, payload)
        } else {
            Outcome::Ready(width)
        };
        outcomes[5] = read(peer, context, sent_first);
        outcomes[6] = write(stream, context, payload);
        outcomes[7] = read(peer, context, sent_second);
    }
}

struct Measurement {
    elapsed: u128,
    checked: usize,
    wakes: usize,
}

fn measure<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    mut peer: DuplexStream,
    payload: &[u8],
    pending: bool,
    windows: usize,
) -> Measurement {
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut capture = Capture::new(payload.len());
    let expected_wakes = if pending { ROUNDS * 2 } else { 0 };
    window(
        stream,
        &mut peer,
        &mut context,
        payload,
        pending,
        &mut capture,
    );
    capture.validate(payload, pending);
    assert_eq!(counter.0.swap(0, Ordering::Relaxed), expected_wakes);

    let mut elapsed = 0;
    let mut wakes = 0;
    for _ in 0..windows {
        // Poison all byte captures outside the clock so a missing output cannot
        // pass merely because the previous continuous window wrote the same data.
        capture.received.fill(0);
        capture.sent_first.fill(0);
        capture.sent_second.fill(0);
        let started = Instant::now();
        window(
            stream,
            &mut peer,
            &mut context,
            payload,
            pending,
            &mut capture,
        );
        elapsed += started.elapsed().as_nanos();
        capture.validate(payload, pending);
        let observed_wakes = counter.0.swap(0, Ordering::Relaxed);
        assert_eq!(observed_wakes, expected_wakes);
        wakes += observed_wakes;
    }

    // Peer close and observable EOF/error semantics are intentionally untimed.
    drop(peer);
    let mut eof = [0; 1];
    assert_eq!(read(stream, &mut context, &mut eof), Outcome::Ready(0));
    assert_eq!(
        write(stream, &mut context, payload),
        Outcome::Error(io::ErrorKind::BrokenPipe)
    );
    Measurement {
        elapsed,
        checked: ROUNDS * windows,
        wakes,
    }
}

pub(super) fn trial(scenario: &str, mode: &str) -> Result<String, &'static str> {
    let (wrapped, pending) = match scenario {
        "tcp-socket-ready" => (false, false),
        "tcp-flow-ready" => (true, false),
        "tcp-socket-pending" => (false, true),
        "tcp-flow-pending" => (true, true),
        _ => return Err("unknown flow detail scenario"),
    };
    let (payload_len, windows) = match mode {
        "Quick" => (64, 64),
        "Confirm" => (1360, 128),
        _ => return Err("mode must be Quick or Confirm"),
    };
    let payload: Vec<u8> = (0..payload_len)
        .map(|index| ((index * 37 + 11) % 256) as u8)
        .collect();
    let (socket, peer) = tokio::io::duplex(payload_len);
    let socket = FlowSocket::Memory(socket);
    let measurement = if wrapped {
        let registry = OwnerRegistry::new();
        let source = ([198, 18, 0, 2], 10_000).into();
        let target = ([198, 18, 0, 1], 443).into();
        let (mut flow, lease) =
            tcp_flow_from_stream(socket, source, target, 1, &registry, OwnerWake::default());
        assert_eq!(flow.source(), source);
        assert_eq!(flow.target(), target);
        assert_eq!(lease.generation(), 1);
        let measurement = measure(&mut flow, peer, &payload, pending, windows);
        // Keep the owner lease alive through every window and verify fencing
        // only afterward; no lifecycle work belongs in the read/write timing.
        assert!(!lease.flow_dropped());
        lease.fence().expect("memory lease fence");
        let mut context = Context::from_waker(Waker::noop());
        let mut destination = [0; 1];
        assert_eq!(
            read(&mut flow, &mut context, &mut destination),
            Outcome::Error(io::ErrorKind::ConnectionReset)
        );
        assert_eq!(
            write(&mut flow, &mut context, &payload),
            Outcome::Error(io::ErrorKind::ConnectionReset)
        );
        drop(flow);
        assert!(lease.flow_dropped());
        drop(lease);
        measurement
    } else {
        let mut socket = socket;
        let measurement = measure(&mut socket, peer, &payload, pending, windows);
        drop(socket);
        measurement
    };
    let Measurement {
        elapsed,
        checked,
        wakes,
    } = measurement;
    let bytes = checked * payload_len * 3;
    let polls = checked * if pending { 8 } else { 6 };
    let pending_polls = if pending { checked * 2 } else { 0 };
    let readiness = if pending { "pending" } else { "ready" };
    // Paired direct/wrapped scenarios deliberately share recipe identity.
    let recipe_id = format!("tun-memory-flow-v1-{readiness}-{mode}");
    Ok(format!(
        "{{\"schema_version\":1,\"kind\":\"ferrum2.tun-detail.trial\",\"scenario\":\"{scenario}\",\"mode\":\"{mode}\",\"checked_units\":{checked},\"elapsed_nanoseconds\":{elapsed},\"unit\":\"roundtrips\",\"recipe_id\":\"{recipe_id}\",\"observation\":{{\"payload_bytes\":{payload_len},\"transferred_bytes\":{bytes},\"poll_calls\":{polls},\"pending_polls\":{pending_polls},\"wake_calls\":{wakes},\"windows\":{windows},\"rounds_per_window\":{ROUNDS},\"logical_ticks\":{checked}}}}}"
    ))
}
