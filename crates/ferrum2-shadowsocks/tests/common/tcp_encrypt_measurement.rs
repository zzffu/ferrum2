use std::convert::Infallible;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::task::{Context, Poll};

use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_shadowsocks::{ClientTcpOutbound, PlainDuplex, TransportIo};

use crate::common::{
    FakeClock, FillRandom, NOW, flush_plain, provider, server_target, target, write_plain,
};

pub const PAYLOAD_LENGTHS: [usize; 3] = [1, 1_024, 32_768];

pub struct Measurement<R> {
    pub observation: R,
    pub checksum: u64,
}

struct SinkIo;

impl AbortiveClose for SinkIo {
    type Error = Infallible;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl LocalEndpoint for SinkIo {
    fn local_socket_addr(&self) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_152).into()
    }
}

impl TransportIo for SinkIo {
    type IoError = Infallible;

    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Poll::Pending
    }

    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        black_box(source);
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

/// Exercises only steady-state client-side TCP data-frame admission and drain
/// inside the supplied measurement guard. Flow construction, request first
/// write, payload allocation, and warm-up all happen before measurement.
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
    let random = FillRandom::new(0x51);
    let connector = ();
    let outbound = ClientTcpOutbound::new(server_target(), &keys, &connector, &clock, &random);
    let mut flow = outbound
        .write_request_on(SinkIo, &target())
        .await
        .expect("measurement request first-write");
    let payload = (0..payload_len)
        .map(|index| (index % 251) as u8 + 1)
        .collect::<Vec<_>>();

    for _ in 0..warmup_frames {
        let written = write_plain(&mut flow, &payload)
            .await
            .expect("warm-up frame admission");
        assert_eq!(written, payload_len);
        flush_plain(&mut flow).await.expect("warm-up frame drain");
    }

    let guard = start_measurement();
    let mut checksum = 0_u64;
    for frame in 0..measured_frames {
        let written = write_plain(&mut flow, &payload)
            .await
            .expect("measured frame admission");
        assert_eq!(written, payload_len);
        flush_plain(&mut flow).await.expect("measured frame drain");
        checksum = checksum
            .wrapping_add(written as u64)
            .wrapping_add(u64::from(payload[frame % payload_len]));
    }
    let observation = finish_measurement(guard);

    assert_eq!(flow.terminal(), None);
    assert_ne!(black_box(checksum), u64::MAX);
    Measurement {
        observation,
        checksum,
    }
}
