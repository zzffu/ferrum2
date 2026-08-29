use std::convert::Infallible;
use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_core::AbortiveClose;
use ferrum2_shadowsocks::{ShadowsocksTcpInbound, TcpReplayStore, TransportIo};

use crate::common::{
    FakeClock, NOW, ScriptedRandom, provider, read_plain, request_data_frames, salt_from_u64,
    valid_request_wire,
};

pub const PAYLOAD_LENGTHS: [usize; 3] = [1, 1_024, 32_768];

pub struct Measurement<R> {
    pub observation: R,
    pub checksum: u64,
}

struct LinearReadIo {
    input: Vec<u8>,
    position: usize,
}

impl LinearReadIo {
    fn new(input: Vec<u8>) -> Self {
        Self { input, position: 0 }
    }
}

impl AbortiveClose for LinearReadIo {
    type Error = Infallible;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl TransportIo for LinearReadIo {
    type IoError = Infallible;

    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        let copied = destination
            .len()
            .min(self.input.len().saturating_sub(self.position));
        let end = self.position + copied;
        destination[..copied].copy_from_slice(&self.input[self.position..end]);
        self.position = end;
        Poll::Ready(Ok(copied))
    }

    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Poll::Ready(Ok(source.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::IoError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Poll::Ready(Ok(()))
    }
}

/// Exercises only steady-state server-side TCP data frames inside the supplied
/// measurement guard. Fixture construction, the request handshake, destination
/// allocation, and warm-up all happen before `start_measurement` is called.
pub async fn measure_steady_frames<G, R>(
    payload_len: usize,
    warmup_frames: usize,
    measured_frames: usize,
    start_measurement: impl FnOnce() -> G,
    finish_measurement: impl FnOnce(G) -> R,
) -> Measurement<R> {
    assert!(payload_len > 0);
    assert!(measured_frames > 0);

    let keys = provider();
    let clock = FakeClock::new(NOW, 0);
    let random = ScriptedRandom::new([]);
    let replay = TcpReplayStore::new(1_024).expect("approved replay capacity");
    let salt = salt_from_u64(10_000 + payload_len as u64);
    let payload = (0..payload_len)
        .map(|index| (index % 251) as u8 + 1)
        .collect::<Vec<_>>();
    let frame_count = warmup_frames + measured_frames;
    let payloads = vec![payload.as_slice(); frame_count];
    let frames = request_data_frames(&salt, &payloads);
    let wire_len =
        valid_request_wire(NOW, &salt).len() + frames.iter().map(Vec::len).sum::<usize>();
    let mut wire = Vec::with_capacity(wire_len);
    wire.extend_from_slice(&valid_request_wire(NOW, &salt));
    for frame in frames {
        wire.extend_from_slice(&frame);
    }

    let inbound = ShadowsocksTcpInbound::new(&keys, &clock, &random, &replay);
    let mut flow = inbound
        .accept_stream(LinearReadIo::new(wire))
        .await
        .expect("measurement handshake")
        .stream;
    let mut destination = vec![0_u8; payload_len];
    for _ in 0..warmup_frames {
        let read = read_plain(&mut flow, &mut destination)
            .await
            .expect("warm-up frame");
        assert_eq!(read, payload_len);
    }

    let guard = start_measurement();
    let mut checksum = 0_u64;
    for frame in 0..measured_frames {
        let read = read_plain(&mut flow, &mut destination)
            .await
            .expect("measured frame");
        assert_eq!(read, payload_len);
        checksum = checksum.wrapping_add(u64::from(destination[frame % payload_len]));
        black_box(&destination[..read]);
    }
    let observation = finish_measurement(guard);

    assert_ne!(black_box(checksum), u64::MAX);
    Measurement {
        observation,
        checksum,
    }
}
