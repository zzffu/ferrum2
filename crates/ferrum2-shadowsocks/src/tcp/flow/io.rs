use std::convert::Infallible;
#[cfg(feature = "tokio")]
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;

use super::worker_local::try_with_wire_staging;
use super::{
    DataRx, Lifecycle, StagedKind, StagedWrite, TransportIo, TxState, prepare_decrypt,
    protocol_cipher_boundary,
};
use crate::tcp::error::{
    DetectionReason, FlowTerminal, ProtocolReason, ShadowsocksError, TransportPhase,
    frame_from_open_aead,
};
use crate::tcp::observe::FlowObserver;
use crate::tcp::wire::{
    ENCRYPTED_LENGTH_LEN, EncodeFrameSizer, MAX_DECRYPT_WIRE_LEN, TAG_LEN, seal_data_chunk_into,
};
use ferrum2_crypto::{TcpOpener, TcpSealer};
#[cfg(feature = "tokio")]
use tokio::io::AsyncWrite;

// Bound both useful bulk work and pathological tiny-ready fragmentation per outer poll.
const POLL_FRAME_BUDGET: usize = 8;
const POLL_BYTE_BUDGET: usize = 256 * 1024;
const POLL_READY_IO_BUDGET: usize = 64;

/// Per-outer-poll fairness budget shared across ready state transitions.
pub(super) struct PollBudget {
    frames: usize,
    bytes: usize,
    ready_io: usize,
}

impl PollBudget {
    pub(super) const fn new() -> Self {
        Self {
            frames: 0,
            bytes: 0,
            ready_io: 0,
        }
    }

    pub(super) fn record_io(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.ready_io = self.ready_io.saturating_add(1);
    }

    pub(super) fn record_frame(&mut self) {
        self.frames = self.frames.saturating_add(1);
    }

    pub(super) fn yield_if_exhausted(&self, cx: &mut Context<'_>) -> bool {
        let exhausted = self.frames >= POLL_FRAME_BUDGET
            || self.bytes >= POLL_BYTE_BUDGET
            || self.ready_io >= POLL_READY_IO_BUDGET;
        if exhausted {
            cx.waker().wake_by_ref();
        }
        exhausted
    }
}

pub(super) enum DataPoll {
    Pending(DataRx),
    Ready(DataRx, Result<DataRead, ShadowsocksError>),
}

pub(super) enum DataRead {
    Buffered,
    Eof,
}

#[cfg(feature = "tokio")]
pub(super) enum FusedDataPoll {
    Pending(DataRx),
    Advanced(DataRx),
    Ready(DataRx, Result<FusedDataRead, ShadowsocksError>),
}

#[cfg(feature = "tokio")]
pub(crate) enum FusedDataRead {
    Advanced,
    Buffered,
    Eof,
    Forwarded(FusedSinkPoll),
}

#[cfg(feature = "tokio")]
pub(crate) enum FusedSinkPoll {
    Pending,
    Written { bytes: usize, frame_complete: bool },
    Error(io::Error),
}

enum InnerDataPoll<F> {
    Pending(DataRx),
    Advanced(DataRx),
    Ready(DataRx, Result<InnerDataRead<F>, ShadowsocksError>),
}

enum InnerDataRead<F> {
    Buffered,
    Eof,
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    Forwarded {
        result: F,
        frame_complete: bool,
    },
}

trait PayloadDelivery {
    type Forwarded;

    fn deliver(
        &mut self,
        cx: &mut Context<'_>,
        plaintext: &[u8],
        scratch: &mut BytesMut,
    ) -> InnerDataRead<Self::Forwarded>;
}

struct BufferedDelivery;

impl PayloadDelivery for BufferedDelivery {
    type Forwarded = Infallible;

    fn deliver(
        &mut self,
        _cx: &mut Context<'_>,
        plaintext: &[u8],
        scratch: &mut BytesMut,
    ) -> InnerDataRead<Self::Forwarded> {
        scratch[..plaintext.len()].copy_from_slice(plaintext);
        scratch.truncate(plaintext.len());
        InnerDataRead::Buffered
    }
}

#[cfg(feature = "tokio")]
struct FusedDelivery<'a, W>(&'a mut W);

#[cfg(feature = "tokio")]
impl<W> PayloadDelivery for FusedDelivery<'_, W>
where
    W: AsyncWrite + Unpin,
{
    type Forwarded = FusedSinkPoll;

    fn deliver(
        &mut self,
        cx: &mut Context<'_>,
        plaintext: &[u8],
        scratch: &mut BytesMut,
    ) -> InnerDataRead<Self::Forwarded> {
        let result = match Pin::new(&mut *self.0).poll_write(cx, plaintext) {
            Poll::Pending => FusedSinkPoll::Pending,
            Poll::Ready(Err(error)) => FusedSinkPoll::Error(error),
            Poll::Ready(Ok(0)) => FusedSinkPoll::Error(io::ErrorKind::WriteZero.into()),
            Poll::Ready(Ok(written)) if written <= plaintext.len() => FusedSinkPoll::Written {
                bytes: written,
                frame_complete: written == plaintext.len(),
            },
            Poll::Ready(Ok(_)) => FusedSinkPoll::Error(io::ErrorKind::InvalidData.into()),
        };
        let consumed = match &result {
            FusedSinkPoll::Written { bytes, .. } => *bytes,
            FusedSinkPoll::Pending | FusedSinkPoll::Error(_) => 0,
        };
        let remaining = plaintext.len() - consumed;
        if remaining == 0 {
            scratch.clear();
        } else {
            scratch[..remaining].copy_from_slice(&plaintext[consumed..]);
            scratch.truncate(remaining);
        }
        InnerDataRead::Forwarded {
            result,
            frame_complete: remaining == 0,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_data_fill<S: TransportIo>(
    io: &mut S,
    opener: &mut TcpOpener,
    scratch: &mut BytesMut,
    state: DataRx,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
) -> DataPoll {
    let mut delivery = BufferedDelivery;
    match poll_data_fill_inner(
        io,
        opener,
        scratch,
        state,
        lifecycle,
        observer,
        cx,
        &mut delivery,
    ) {
        InnerDataPoll::Pending(state) => DataPoll::Pending(state),
        InnerDataPoll::Advanced(state) => {
            cx.waker().wake_by_ref();
            DataPoll::Pending(state)
        }
        InnerDataPoll::Ready(state, result) => DataPoll::Ready(
            state,
            result.map(|read| match read {
                InnerDataRead::Buffered => DataRead::Buffered,
                InnerDataRead::Eof => DataRead::Eof,
                InnerDataRead::Forwarded { result, .. } => match result {},
            }),
        ),
    }
}

#[cfg(feature = "tokio")]
#[allow(clippy::too_many_arguments)]
pub(super) fn poll_data_forward<S, W>(
    io: &mut S,
    opener: &mut TcpOpener,
    scratch: &mut BytesMut,
    state: DataRx,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
    sink: &mut W,
) -> FusedDataPoll
where
    S: TransportIo,
    W: AsyncWrite + Unpin,
{
    let mut delivery = FusedDelivery(sink);
    match poll_data_fill_inner(
        io,
        opener,
        scratch,
        state,
        lifecycle,
        observer,
        cx,
        &mut delivery,
    ) {
        InnerDataPoll::Pending(state) => FusedDataPoll::Pending(state),
        InnerDataPoll::Advanced(state) => FusedDataPoll::Advanced(state),
        InnerDataPoll::Ready(state, result) => FusedDataPoll::Ready(
            state,
            result.map(|read| match read {
                InnerDataRead::Buffered => FusedDataRead::Buffered,
                InnerDataRead::Eof => FusedDataRead::Eof,
                InnerDataRead::Forwarded { result, .. } => FusedDataRead::Forwarded(result),
            }),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn poll_data_fill_inner<S, D>(
    io: &mut S,
    opener: &mut TcpOpener,
    scratch: &mut BytesMut,
    state: DataRx,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
    delivery: &mut D,
) -> InnerDataPoll<D::Forwarded>
where
    S: TransportIo,
    D: PayloadDelivery,
{
    match state {
        DataRx::Length { mut filled } => {
            if filled == 0 {
                prepare_decrypt(scratch, ENCRYPTED_LENGTH_LEN);
            }
            let remaining = ENCRYPTED_LENGTH_LEN - filled;
            match Pin::new(&mut *io).poll_read_buf(cx, scratch, remaining) {
                Poll::Pending => InnerDataPoll::Pending(DataRx::Length { filled }),
                Poll::Ready(Err(_)) => {
                    let error = lifecycle.install_transport(observer, TransportPhase::Read);
                    InnerDataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(0)) if filled == 0 => {
                    scratch.clear();
                    lifecycle.close_rx(observer);
                    InnerDataPoll::Ready(DataRx::Closed, Ok(InnerDataRead::Eof))
                }
                Poll::Ready(Ok(0)) => {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    InnerDataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(read)) => {
                    let Some(next) = filled
                        .checked_add(read)
                        .filter(|next| *next <= ENCRYPTED_LENGTH_LEN)
                    else {
                        let error =
                            lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                        return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                    };
                    if scratch.len() != next {
                        let error =
                            lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                        return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    filled = next;
                    if filled < ENCRYPTED_LENGTH_LEN {
                        InnerDataPoll::Advanced(DataRx::Length { filled })
                    } else {
                        if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                            opener.open_in_place(scratch).map_err(frame_from_open_aead)
                        }) {
                            return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        if scratch.len() != 2 {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        let payload_len = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
                        let Some(wire_len) = payload_len.checked_add(TAG_LEN) else {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                        };
                        if wire_len > MAX_DECRYPT_WIRE_LEN {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        prepare_decrypt(scratch, wire_len);
                        let next = DataRx::Payload {
                            wire_len,
                            filled: 0,
                        };
                        InnerDataPoll::Advanced(next)
                    }
                }
            }
        }
        DataRx::Payload {
            wire_len,
            mut filled,
        } => match Pin::new(&mut *io).poll_read_buf(cx, scratch, wire_len - filled) {
            Poll::Pending => InnerDataPoll::Pending(DataRx::Payload { wire_len, filled }),
            Poll::Ready(Err(_)) => {
                let error = lifecycle.install_transport(observer, TransportPhase::Read);
                InnerDataPoll::Ready(DataRx::Poison, Err(error))
            }
            Poll::Ready(Ok(0)) => {
                let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                InnerDataPoll::Ready(DataRx::Poison, Err(error))
            }
            Poll::Ready(Ok(read)) => {
                let Some(next) = filled.checked_add(read).filter(|next| *next <= wire_len) else {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                };
                if scratch.len() != next {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                }
                filled = next;
                if filled < wire_len {
                    InnerDataPoll::Advanced(DataRx::Payload { wire_len, filled })
                } else {
                    let payload_len = wire_len - TAG_LEN;
                    let opened = try_with_wire_staging(wire_len, |worker_wire| {
                        worker_wire.copy_from_slice(&scratch[..wire_len]);
                        protocol_cipher_boundary(lifecycle, observer, || {
                            opener
                                .open_slice_in_place(worker_wire)
                                .map_err(frame_from_open_aead)
                        })?;
                        if payload_len == 0 {
                            scratch.clear();
                            return Ok(InnerDataRead::Buffered);
                        }
                        Ok(delivery.deliver(cx, &worker_wire[..payload_len], scratch))
                    });
                    match opened {
                        Some(Ok(InnerDataRead::Forwarded {
                            result,
                            frame_complete,
                        })) => {
                            let state = if frame_complete {
                                DataRx::Length { filled: 0 }
                            } else {
                                DataRx::Ready { position: 0 }
                            };
                            return InnerDataPoll::Ready(
                                state,
                                Ok(InnerDataRead::Forwarded {
                                    result,
                                    frame_complete,
                                }),
                            );
                        }
                        Some(Ok(InnerDataRead::Buffered)) => {}
                        Some(Ok(InnerDataRead::Eof)) => {
                            unreachable!("payload open cannot report EOF")
                        }
                        Some(Err(error)) => {
                            return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        None => {
                            if let Err(error) =
                                protocol_cipher_boundary(lifecycle, observer, || {
                                    opener.open_in_place(scratch).map_err(frame_from_open_aead)
                                })
                            {
                                return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                            }
                            if scratch.len() != payload_len {
                                let error = lifecycle
                                    .install_protocol(observer, ProtocolReason::FrameBounds);
                                return InnerDataPoll::Ready(DataRx::Poison, Err(error));
                            }
                        }
                    }
                    if payload_len == 0 {
                        InnerDataPoll::Advanced(DataRx::Length { filled: 0 })
                    } else {
                        InnerDataPoll::Ready(
                            DataRx::Ready { position: 0 },
                            Ok(InnerDataRead::Buffered),
                        )
                    }
                }
            }
        },
        DataRx::Ready { position } => {
            InnerDataPoll::Ready(DataRx::Ready { position }, Ok(InnerDataRead::Buffered))
        }
        DataRx::Closed => InnerDataPoll::Ready(DataRx::Closed, Ok(InnerDataRead::Eof)),
        DataRx::Poison => {
            let error = lifecycle
                .fatal_error()
                .expect("poison state only exists after fatal installation");
            InnerDataPoll::Ready(DataRx::Poison, Err(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_write_open<S: TransportIo>(
    io: &mut S,
    sealer: &mut TcpSealer,
    scratch: &mut BytesMut,
    staged: &mut Option<StagedWrite>,
    tx: &mut TxState,
    frame_sizer: &mut EncodeFrameSizer,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
    source: &[u8],
) -> Poll<Result<usize, ShadowsocksError>> {
    if let Some(error) = lifecycle.fatal_error() {
        return Poll::Ready(Err(error));
    }
    if source.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if lifecycle.terminal == Some(FlowTerminal::Normal) {
        return Poll::Ready(Ok(0));
    }
    if lifecycle.tx_closed {
        let error = lifecycle.install_transport(observer, TransportPhase::Write);
        return Poll::Ready(Err(error));
    }
    if staged.is_some() {
        match drain_staged(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
    }
    if let Err(error) =
        protocol_cipher_boundary(lifecycle, observer, || frame_sizer.prepare_scratch(scratch))
    {
        return Poll::Ready(Err(error));
    }
    let admitted = source.len().min(frame_sizer.payload_limit());
    match protocol_cipher_boundary(lifecycle, observer, || {
        seal_data_chunk_into(sealer, &source[..admitted], scratch)
    }) {
        Ok(()) => {
            if let Err(error) =
                protocol_cipher_boundary(lifecycle, observer, || frame_sizer.record(admitted))
            {
                return Poll::Ready(Err(error));
            }
            *staged = Some(StagedWrite {
                kind: StagedKind::Subsequent,
                position: 0,
            });
            *tx = TxState::Open;
            Poll::Ready(Ok(admitted))
        }
        Err(error) => Poll::Ready(Err(error)),
    }
}

pub(super) fn drain_staged<S: TransportIo>(
    io: &mut S,
    scratch: &mut BytesMut,
    staged: &mut Option<StagedWrite>,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
) -> Poll<Result<(), ShadowsocksError>> {
    let mut budget = PollBudget::new();
    loop {
        let progress = match poll_staged_once(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(progress)) => progress,
        };
        budget.record_io(progress.written);
        if progress.drained {
            budget.record_frame();
            if budget.yield_if_exhausted(cx) {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(()));
        }
        if budget.yield_if_exhausted(cx) {
            return Poll::Pending;
        }
    }
}

pub(super) struct StagedWriteProgress {
    written: usize,
    pub(super) drained: bool,
}

pub(super) fn poll_staged_once<S: TransportIo>(
    io: &mut S,
    scratch: &mut BytesMut,
    staged: &mut Option<StagedWrite>,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
) -> Poll<Result<StagedWriteProgress, ShadowsocksError>> {
    let current = staged.as_mut().expect("caller checked staged wire");
    let source = &scratch[current.position..];
    match Pin::new(&mut *io).poll_write(cx, source) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(_)) if current.kind == StagedKind::First => {
            let error = lifecycle.install_detection(io, observer, DetectionReason::WriteFailed);
            Poll::Ready(Err(error))
        }
        Poll::Ready(Err(_)) => {
            let error = lifecycle.install_transport(observer, TransportPhase::Write);
            Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(0)) if current.kind == StagedKind::First => {
            let error = lifecycle.install_detection(io, observer, DetectionReason::ShortWrite);
            Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(0)) => {
            let error = lifecycle.install_transport(observer, TransportPhase::WriteZero);
            Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(written)) => {
            let Some(next) = current
                .position
                .checked_add(written)
                .filter(|next| *next <= scratch.len())
            else {
                let error = if current.kind == StagedKind::First {
                    lifecycle.install_detection(io, observer, DetectionReason::ShortWrite)
                } else {
                    lifecycle.install_transport(observer, TransportPhase::Write)
                };
                return Poll::Ready(Err(error));
            };
            current.position = next;
            let drained = current.position == scratch.len();
            if drained {
                scratch.clear();
                *staged = None;
            }
            Poll::Ready(Ok(StagedWriteProgress { written, drained }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_flush<S: TransportIo>(
    io: &mut S,
    scratch: &mut BytesMut,
    staged: &mut Option<StagedWrite>,
    tx: TxState,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
) -> Poll<Result<(), ShadowsocksError>> {
    if let Some(error) = lifecycle.fatal_error() {
        return Poll::Ready(Err(error));
    }
    if lifecycle.terminal == Some(FlowTerminal::Normal) || lifecycle.tx_closed {
        return Poll::Ready(Ok(()));
    }
    if staged.is_some() {
        match drain_staged(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
    }
    if tx == TxState::ResponsePending {
        return Poll::Ready(Ok(()));
    }
    match Pin::new(io).poll_flush(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        Poll::Ready(Err(_)) => {
            let error = lifecycle.install_transport(observer, TransportPhase::Flush);
            Poll::Ready(Err(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_shutdown<S: TransportIo>(
    io: &mut S,
    scratch: &mut BytesMut,
    staged: &mut Option<StagedWrite>,
    tx: &mut TxState,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
) -> Poll<Result<(), ShadowsocksError>> {
    if let Some(error) = lifecycle.fatal_error() {
        return Poll::Ready(Err(error));
    }
    if lifecycle.terminal == Some(FlowTerminal::Normal) || lifecycle.tx_closed {
        return Poll::Ready(Ok(()));
    }
    if staged.is_some() {
        match drain_staged(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
    }
    match Pin::new(io).poll_shutdown(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(())) => {
            *tx = TxState::Closed;
            lifecycle.close_tx(observer);
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Err(_)) => {
            let error = lifecycle.install_transport(observer, TransportPhase::Shutdown);
            Poll::Ready(Err(error))
        }
    }
}
