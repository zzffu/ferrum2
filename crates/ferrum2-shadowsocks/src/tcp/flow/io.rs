use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;

use super::{
    DataRx, Lifecycle, StagedKind, StagedWrite, TransportIo, TxState, copy_ready,
    protocol_cipher_boundary, reset_decrypt,
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

pub(super) enum DataPoll {
    Pending(DataRx),
    Ready(DataRx, Result<usize, ShadowsocksError>),
}

#[allow(clippy::too_many_arguments)]
pub(super) fn poll_data_read<S: TransportIo>(
    io: &mut S,
    opener: &mut TcpOpener,
    scratch: &mut BytesMut,
    state: DataRx,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
    destination: &mut [u8],
) -> DataPoll {
    let mut state = state;
    loop {
        match state {
            DataRx::Length { mut filled } => {
                if filled == 0 {
                    reset_decrypt(scratch);
                }
                let read = match Pin::new(&mut *io)
                    .poll_read(cx, &mut scratch[filled..ENCRYPTED_LENGTH_LEN])
                {
                    Poll::Pending => {
                        return DataPoll::Pending(DataRx::Length { filled });
                    }
                    Poll::Ready(Err(_)) => {
                        let error = lifecycle.install_transport(observer, TransportPhase::Read);
                        return DataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    Poll::Ready(Ok(read)) => read,
                };
                if read == 0 {
                    if filled == 0 {
                        lifecycle.close_rx(observer);
                        return DataPoll::Ready(DataRx::Closed, Ok(0));
                    }
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                let Some(next_filled) = filled.checked_add(read) else {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                };
                filled = next_filled;
                if filled > ENCRYPTED_LENGTH_LEN {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if filled < ENCRYPTED_LENGTH_LEN {
                    state = DataRx::Length { filled };
                    continue;
                }
                scratch.truncate(ENCRYPTED_LENGTH_LEN);
                if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                    opener.open_in_place(scratch).map_err(frame_from_open_aead)
                }) {
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if scratch.len() != 2 {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                let payload_len = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
                let Some(wire_len) = payload_len.checked_add(TAG_LEN) else {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                };
                if wire_len > MAX_DECRYPT_WIRE_LEN {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                reset_decrypt(scratch);
                state = DataRx::Payload {
                    wire_len,
                    filled: 0,
                };
            }
            DataRx::Payload {
                wire_len,
                mut filled,
            } => {
                let read = match Pin::new(&mut *io).poll_read(cx, &mut scratch[filled..wire_len]) {
                    Poll::Pending => {
                        return DataPoll::Pending(DataRx::Payload { wire_len, filled });
                    }
                    Poll::Ready(Err(_)) => {
                        let error = lifecycle.install_transport(observer, TransportPhase::Read);
                        return DataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    Poll::Ready(Ok(read)) => read,
                };
                if read == 0 {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                let Some(next_filled) = filled.checked_add(read) else {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                };
                filled = next_filled;
                if filled > wire_len {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if filled < wire_len {
                    state = DataRx::Payload { wire_len, filled };
                    continue;
                }
                scratch.truncate(wire_len);
                if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                    opener.open_in_place(scratch).map_err(frame_from_open_aead)
                }) {
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if scratch.is_empty() {
                    reset_decrypt(scratch);
                    state = DataRx::Length { filled: 0 };
                    continue;
                }
                let mut position = 0;
                let (copied, complete) = copy_ready(scratch, &mut position, destination);
                let next = if complete {
                    reset_decrypt(scratch);
                    DataRx::Length { filled: 0 }
                } else {
                    DataRx::Ready { position }
                };
                return DataPoll::Ready(next, Ok(copied));
            }
            DataRx::Ready { mut position } => {
                let (copied, complete) = copy_ready(scratch, &mut position, destination);
                let next = if complete {
                    reset_decrypt(scratch);
                    DataRx::Length { filled: 0 }
                } else {
                    DataRx::Ready { position }
                };
                return DataPoll::Ready(next, Ok(copied));
            }
            DataRx::Closed => return DataPoll::Ready(DataRx::Closed, Ok(0)),
            DataRx::Poison => {
                let error = lifecycle
                    .fatal_error()
                    .expect("poison state only exists after fatal installation");
                return DataPoll::Ready(DataRx::Poison, Err(error));
            }
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
        Poll::Ready(Ok(written)) if current.kind == StagedKind::First => {
            if written != source.len() {
                let error = lifecycle.install_detection(io, observer, DetectionReason::ShortWrite);
                return Poll::Ready(Err(error));
            }
            scratch.clear();
            *staged = None;
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Ok(0)) => {
            let error = lifecycle.install_transport(observer, TransportPhase::WriteZero);
            Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(written)) => {
            current.position += written;
            if current.position > scratch.len() {
                let error = lifecycle.install_transport(observer, TransportPhase::Write);
                return Poll::Ready(Err(error));
            }
            if current.position == scratch.len() {
                scratch.clear();
                *staged = None;
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
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
        return match drain_staged(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            other => other,
        };
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
        return match drain_staged(io, scratch, staged, lifecycle, observer, cx) {
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            other => other,
        };
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
