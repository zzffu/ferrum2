use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;

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
    ENCRYPTED_LENGTH_LEN, MAX_DECRYPT_WIRE_LEN, MAX_ENCODE_PAYLOAD_LEN, TAG_LEN,
    seal_data_chunk_into,
};
use ferrum2_crypto::{TcpOpener, TcpSealer};

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
    // Yield after every successful transport read that has not produced
    // plaintext. On edge-triggered transports a partial read may clear
    // readiness; the one-read scheduling boundary and explicit self-wake
    // guarantee that the next receive step is polled promptly.
    match state {
        DataRx::Length { mut filled } => {
            if filled == 0 {
                prepare_decrypt(scratch, ENCRYPTED_LENGTH_LEN);
            }
            let remaining = ENCRYPTED_LENGTH_LEN - filled;
            match Pin::new(&mut *io).poll_read_buf(cx, scratch, remaining) {
                Poll::Pending => DataPoll::Pending(DataRx::Length { filled }),
                Poll::Ready(Err(_)) => {
                    let error = lifecycle.install_transport(observer, TransportPhase::Read);
                    DataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(0)) if filled == 0 => {
                    scratch.clear();
                    lifecycle.close_rx(observer);
                    DataPoll::Ready(DataRx::Closed, Ok(DataRead::Eof))
                }
                Poll::Ready(Ok(0)) => {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    DataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(read)) => {
                    filled += read;
                    if filled > ENCRYPTED_LENGTH_LEN || scratch.len() != filled {
                        let error =
                            lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                        return DataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    if filled < ENCRYPTED_LENGTH_LEN {
                        let next = DataRx::Length { filled };
                        cx.waker().wake_by_ref();
                        DataPoll::Pending(next)
                    } else {
                        if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                            opener.open_in_place(scratch).map_err(frame_from_open_aead)
                        }) {
                            return DataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        if scratch.len() != 2 {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return DataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        let payload_len = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
                        let Some(wire_len) = payload_len.checked_add(TAG_LEN) else {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return DataPoll::Ready(DataRx::Poison, Err(error));
                        };
                        if wire_len > MAX_DECRYPT_WIRE_LEN {
                            let error =
                                lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                            return DataPoll::Ready(DataRx::Poison, Err(error));
                        }
                        prepare_decrypt(scratch, wire_len);
                        let next = DataRx::Payload {
                            wire_len,
                            filled: 0,
                        };
                        cx.waker().wake_by_ref();
                        DataPoll::Pending(next)
                    }
                }
            }
        }
        DataRx::Payload {
            wire_len,
            mut filled,
        } => match Pin::new(&mut *io).poll_read_buf(cx, scratch, wire_len - filled) {
            Poll::Pending => DataPoll::Pending(DataRx::Payload { wire_len, filled }),
            Poll::Ready(Err(_)) => {
                let error = lifecycle.install_transport(observer, TransportPhase::Read);
                DataPoll::Ready(DataRx::Poison, Err(error))
            }
            Poll::Ready(Ok(0)) => {
                let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                DataPoll::Ready(DataRx::Poison, Err(error))
            }
            Poll::Ready(Ok(read)) => {
                filled += read;
                if filled > wire_len || scratch.len() != filled {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if filled < wire_len {
                    let next = DataRx::Payload { wire_len, filled };
                    cx.waker().wake_by_ref();
                    DataPoll::Pending(next)
                } else {
                    if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                        opener.open_in_place(scratch).map_err(frame_from_open_aead)
                    }) {
                        return DataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    if scratch.is_empty() {
                        let next = DataRx::Length { filled: 0 };
                        cx.waker().wake_by_ref();
                        DataPoll::Pending(next)
                    } else {
                        DataPoll::Ready(DataRx::Ready { position: 0 }, Ok(DataRead::Buffered))
                    }
                }
            }
        },
        DataRx::Ready { position } => {
            DataPoll::Ready(DataRx::Ready { position }, Ok(DataRead::Buffered))
        }
        DataRx::Closed => DataPoll::Ready(DataRx::Closed, Ok(DataRead::Eof)),
        DataRx::Poison => {
            let error = lifecycle
                .fatal_error()
                .expect("poison state only exists after fatal installation");
            DataPoll::Ready(DataRx::Poison, Err(error))
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
    let admitted = source.len().min(MAX_ENCODE_PAYLOAD_LEN);
    match protocol_cipher_boundary(lifecycle, observer, || {
        seal_data_chunk_into(sealer, &source[..admitted], scratch)
    }) {
        Ok(()) => {
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
        let current = staged.as_mut().expect("caller checked staged wire");
        let source = &scratch[current.position..];
        match Pin::new(&mut *io).poll_write(cx, source) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) if current.kind == StagedKind::First => {
                let error = lifecycle.install_detection(io, observer, DetectionReason::WriteFailed);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Err(_)) => {
                let error = lifecycle.install_transport(observer, TransportPhase::Write);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(written)) if current.kind == StagedKind::First => {
                if written != source.len() {
                    let error =
                        lifecycle.install_detection(io, observer, DetectionReason::ShortWrite);
                    return Poll::Ready(Err(error));
                }
                scratch.clear();
                *staged = None;
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Ok(0)) => {
                let error = lifecycle.install_transport(observer, TransportPhase::WriteZero);
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(written)) => {
                budget.record_io(written);
                current.position += written;
                if current.position > scratch.len() {
                    let error = lifecycle.install_transport(observer, TransportPhase::Write);
                    return Poll::Ready(Err(error));
                }
                if current.position == scratch.len() {
                    scratch.clear();
                    *staged = None;
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
