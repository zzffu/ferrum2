mod client;
#[cfg(feature = "tokio")]
mod fused;
mod io;
mod server;
#[cfg(not(feature = "__single-worker-direct-open-diagnostic"))]
mod worker_local;

pub use client::{BoxedClientFlow, ClientFlow};
#[cfg(feature = "tokio")]
pub(crate) use fused::{FusedRelayDirection, fused_relay};
pub use server::ServerFlow;

/// Closed artifact identity for the subsequent-payload receive-open strategy.
pub const TCP_SUBSEQUENT_PAYLOAD_OPEN_BUILD_IDENTITY: &str =
    if cfg!(feature = "__single-worker-direct-open-diagnostic") {
        "single-worker-direct-open-diagnostic"
    } else {
        "worker-local-copyback"
    };

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::AbortiveClose;

use super::error::{
    DetectionReason, FlowTerminal, FrameError, ProtocolReason, ShadowsocksError, TransportPhase,
    protocol_from_frame,
};
use super::observe::FlowObserver;
use super::wire::MAX_DECRYPT_WIRE_LEN;

/// Executor-neutral transport capability owned by one opaque flow.
pub trait TransportIo: AbortiveClose + Send + Unpin {
    /// Underlying error type. It is immediately erased into a closed phase.
    type IoError;

    /// Appends at most `limit` transport bytes to `destination`.
    ///
    /// `Pending` and `Err` leave the visible length unchanged. Implementations
    /// may write directly into spare capacity, but only a successful read may
    /// expose newly initialized bytes.
    fn poll_read_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut BytesMut,
        limit: usize,
    ) -> Poll<Result<usize, Self::IoError>>;

    /// Reads into an already initialized caller-owned plaintext slice.
    ///
    /// Protocol receive state uses [`Self::poll_read_buf`]; this operation is
    /// retained for direct transports that do not own a reusable receive view.
    fn poll_read_initialized(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>>;

    /// Polls one transport write operation.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>>;

    /// Polls one transport flush operation.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::IoError>>;

    /// Polls one transport write-half shutdown operation.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>)
    -> Poll<Result<(), Self::IoError>>;
}

/// Plaintext duplex interface exposed by the deep protocol module.
pub trait PlainDuplex: Send + Unpin {
    /// Polls authenticated plaintext from the peer.
    fn poll_read_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>>;

    /// Polls admission of plaintext for encryption.
    fn poll_write_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>>;

    /// Polls pending ciphertext drain followed by transport flush.
    fn poll_flush_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>>;

    /// Polls pending ciphertext drain followed by write-half shutdown.
    fn poll_shutdown_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>>;

    /// Propagates an abortive close through a nested plaintext transport.
    fn mark_abortive_plain(&mut self) -> Result<(), ShadowsocksError> {
        Ok(())
    }

    /// Returns the flow's sole immutable terminal latch.
    fn terminal(&self) -> Option<FlowTerminal>;
}

/// Plaintext duplex whose receive side exposes its authenticated backing view.
pub trait PlainBufferedDuplex: PlainDuplex {
    /// Polls the current authenticated plaintext view without copying it.
    ///
    /// The returned view remains valid until bytes are consumed or the flow is
    /// mutably polled again. An empty view denotes authenticated EOF.
    fn poll_fill_plain_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<&[u8], ShadowsocksError>>;

    /// Releases bytes from the current plaintext view.
    fn consume_plain(self: Pin<&mut Self>, amount: usize);
}

#[derive(Default)]
pub(super) struct Lifecycle {
    pub(super) terminal: Option<FlowTerminal>,
    rx_closed: bool,
    tx_closed: bool,
}

impl Lifecycle {
    fn fatal_error(&self) -> Option<ShadowsocksError> {
        match self.terminal {
            Some(FlowTerminal::Detection(reason)) => Some(ShadowsocksError::Detection(reason)),
            Some(FlowTerminal::Protocol(reason)) => Some(ShadowsocksError::Protocol(reason)),
            Some(FlowTerminal::Transport(phase)) => Some(ShadowsocksError::Transport(phase)),
            Some(FlowTerminal::Normal) | None => None,
        }
    }

    fn close_rx(&mut self, observer: &dyn FlowObserver) {
        if self.terminal.is_some() {
            return;
        }
        self.rx_closed = true;
        self.maybe_normal(observer);
    }

    fn close_tx(&mut self, observer: &dyn FlowObserver) {
        if self.terminal.is_some() {
            return;
        }
        self.tx_closed = true;
        self.maybe_normal(observer);
    }

    fn maybe_normal(&mut self, observer: &dyn FlowObserver) {
        if self.rx_closed && self.tx_closed && self.terminal.is_none() {
            self.terminal = Some(FlowTerminal::Normal);
            observer.terminal_installed(FlowTerminal::Normal);
        }
    }

    fn install_protocol(
        &mut self,
        observer: &dyn FlowObserver,
        reason: ProtocolReason,
    ) -> ShadowsocksError {
        if self.terminal.is_none() {
            let terminal = FlowTerminal::Protocol(reason);
            self.terminal = Some(terminal);
            observer.terminal_installed(terminal);
        }
        self.fatal_error()
            .expect("protocol installation creates fatal terminal")
    }

    fn install_transport(
        &mut self,
        observer: &dyn FlowObserver,
        phase: TransportPhase,
    ) -> ShadowsocksError {
        if self.terminal.is_none() {
            let terminal = FlowTerminal::Transport(phase);
            self.terminal = Some(terminal);
            observer.terminal_installed(terminal);
        }
        self.fatal_error()
            .expect("transport installation creates fatal terminal")
    }

    fn install_detection<S: AbortiveClose>(
        &mut self,
        io: &mut S,
        observer: &dyn FlowObserver,
        reason: DetectionReason,
    ) -> ShadowsocksError {
        if self.terminal.is_none() {
            let terminal = FlowTerminal::Detection(reason);
            self.terminal = Some(terminal);
            observer.terminal_installed(terminal);
            let _ = io.mark_abortive();
        }
        self.fatal_error()
            .expect("detection installation creates fatal terminal")
    }
}

pub(super) enum ClientRx {
    ResponseFixed { filled: usize },
    ResponsePayload { wire_len: usize, filled: usize },
    Data(DataRx),
    Poison,
}

pub(super) enum DataRx {
    Length { filled: usize },
    Payload { wire_len: usize, filled: usize },
    Ready { position: usize },
    Closed,
    Poison,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum TxState {
    ResponsePending,
    Open,
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum StagedKind {
    First,
    Subsequent,
}

pub(super) struct StagedWrite {
    kind: StagedKind,
    position: usize,
}

/// Exposes exactly one receive stage while retaining the fixed backing allocation.
pub(super) fn prepare_decrypt(scratch: &mut BytesMut, exact_len: usize) {
    debug_assert!(exact_len <= MAX_DECRYPT_WIRE_LEN);
    debug_assert!(exact_len <= scratch.capacity());
    scratch.clear();
}

pub(super) fn protocol_cipher_boundary(
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    operation: impl FnOnce() -> Result<(), FrameError>,
) -> Result<(), ShadowsocksError> {
    if let Some(error) = lifecycle.fatal_error() {
        return Err(error);
    }
    operation().map_err(|error| lifecycle.install_protocol(observer, protocol_from_frame(error)))
}
