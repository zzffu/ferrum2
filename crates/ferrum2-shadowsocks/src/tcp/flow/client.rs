use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_core::{AbortiveClose, LocalEndpoint};
use ferrum2_crypto::{Clock, MethodTcpSalt, TcpOpener, TcpSealer};

use super::io::{DataPoll, poll_data_read, poll_flush, poll_shutdown, poll_write_open};
use super::{
    ClientRx, DataRx, Lifecycle, PlainDuplex, StagedWrite, TransportIo, TxState, copy_ready,
};
use crate::tcp::error::{
    DetectionReason, FlowTerminal, ShadowsocksError, TransportPhase, detection_from_aead,
};
use crate::tcp::handshake::TcpKeyProvider;
use crate::tcp::observe::{BufferRole, Observers, inspect_scratch};
use crate::tcp::wire::{
    MAX_DECRYPT_WIRE_LEN, RESPONSE_TYPE, TAG_LEN, opener_for, response_fixed_plaintext_len,
};

/// Opaque client flow retaining unsplit transport and both cipher directions.
pub struct ClientFlow<'a, S, K, T> {
    pub(super) io: S,
    pub(super) keys: &'a K,
    pub(super) clock: &'a T,
    pub(super) request_salt: MethodTcpSalt,
    pub(super) request_sealer: TcpSealer,
    pub(super) response_opener: Option<TcpOpener>,
    pub(super) rx: ClientRx,
    pub(super) tx: TxState,
    pub(super) encrypt: BytesMut,
    pub(super) decrypt: BytesMut,
    pub(super) staged: Option<StagedWrite>,
    pub(super) lifecycle: Lifecycle,
    pub(super) observers: Observers<'a>,
}

impl<'a, S, K, T> ClientFlow<'a, S, K, T> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::tcp) fn from_handshake(
        io: S,
        keys: &'a K,
        clock: &'a T,
        request_salt: MethodTcpSalt,
        request_sealer: TcpSealer,
        encrypt: BytesMut,
        decrypt: BytesMut,
        observers: Observers<'a>,
    ) -> Self {
        Self {
            io,
            keys,
            clock,
            request_salt,
            request_sealer,
            response_opener: None,
            rx: ClientRx::ResponseFixed { filled: 0 },
            tx: TxState::Open,
            encrypt,
            decrypt,
            staged: None,
            lifecycle: Lifecycle::default(),
            observers,
        }
    }
}

impl<S, K, T> Drop for ClientFlow<'_, S, K, T> {
    fn drop(&mut self) {
        self.observers.flow.owner_dropped();
    }
}

/// Type-erased owner used only to nest a bounded sequence of client flows.
pub struct BoxedClientFlow<'a> {
    inner: Box<dyn PlainDuplex + 'a>,
    local_socket_addr: SocketAddr,
}

impl<'a> BoxedClientFlow<'a> {
    fn new<F>(flow: F) -> Self
    where
        F: PlainDuplex + LocalEndpoint + 'a,
    {
        let local_socket_addr = flow.local_socket_addr();
        Self {
            inner: Box::new(flow),
            local_socket_addr,
        }
    }
}

impl<'a, S, K, T> ClientFlow<'a, S, K, T>
where
    Self: PlainDuplex,
    S: LocalEndpoint + 'a,
    K: 'a,
    T: 'a,
{
    /// Retains this flow as one transport layer for the next client hop.
    pub fn into_boxed(self) -> BoxedClientFlow<'a> {
        BoxedClientFlow::new(self)
    }
}

impl LocalEndpoint for BoxedClientFlow<'_> {
    fn local_socket_addr(&self) -> SocketAddr {
        self.local_socket_addr
    }
}

impl AbortiveClose for BoxedClientFlow<'_> {
    type Error = ShadowsocksError;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive_plain()
    }
}

impl TransportIo for BoxedClientFlow<'_> {
    type IoError = ShadowsocksError;

    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut *self.inner).poll_read_plain(cx, destination)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        Pin::new(&mut *self.inner).poll_write_plain(cx, source)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut *self.inner).poll_flush_plain(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        Pin::new(&mut *self.inner).poll_shutdown_plain(cx)
    }
}

impl<S: LocalEndpoint, K, T> LocalEndpoint for ClientFlow<'_, S, K, T> {
    fn local_socket_addr(&self) -> SocketAddr {
        self.io.local_socket_addr()
    }
}

impl<'a, S, K, T> ClientFlow<'a, S, K, T>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
{
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        if let Some(error) = self.lifecycle.fatal_error() {
            return Poll::Ready(Err(error));
        }
        if destination.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.lifecycle.terminal == Some(FlowTerminal::Normal) || self.lifecycle.rx_closed {
            return Poll::Ready(Ok(0));
        }

        let state = std::mem::replace(&mut self.rx, ClientRx::Poison);
        match state {
            ClientRx::ResponseFixed { mut filled } => {
                let response_first_read_len =
                    self.request_salt.profile().initial_response_read_bytes();
                match Pin::new(&mut self.io)
                    .poll_read(cx, &mut self.decrypt[filled..response_first_read_len])
                {
                    Poll::Pending => {
                        self.rx = ClientRx::ResponseFixed { filled };
                        Poll::Pending
                    }
                    Poll::Ready(Err(_)) => {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            DetectionReason::ReadFailed,
                        );
                        Poll::Ready(Err(error))
                    }
                    Poll::Ready(Ok(0)) => {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            DetectionReason::ShortRead,
                        );
                        Poll::Ready(Err(error))
                    }
                    Poll::Ready(Ok(read)) => {
                        let Some(next) = filled
                            .checked_add(read)
                            .filter(|next| *next <= response_first_read_len)
                        else {
                            let error = self.lifecycle.install_detection(
                                &mut self.io,
                                self.observers.flow,
                                DetectionReason::ShortRead,
                            );
                            return Poll::Ready(Err(error));
                        };
                        filled = next;
                        if filled < response_first_read_len {
                            self.rx = ClientRx::ResponseFixed { filled };
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        let result = self.open_response_fixed();
                        match result {
                            Ok(wire_len) => {
                                self.rx = ClientRx::ResponsePayload {
                                    wire_len,
                                    filled: 0,
                                };
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Err(reason) => {
                                let error = self.lifecycle.install_detection(
                                    &mut self.io,
                                    self.observers.flow,
                                    reason,
                                );
                                Poll::Ready(Err(error))
                            }
                        }
                    }
                }
            }
            ClientRx::ResponsePayload {
                wire_len,
                mut filled,
            } => match Pin::new(&mut self.io).poll_read(cx, &mut self.decrypt[filled..wire_len]) {
                Poll::Pending => {
                    self.rx = ClientRx::ResponsePayload { wire_len, filled };
                    Poll::Pending
                }
                Poll::Ready(Err(_)) => {
                    let error = self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        DetectionReason::ReadFailed,
                    );
                    Poll::Ready(Err(error))
                }
                Poll::Ready(Ok(0)) => {
                    let error = self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        DetectionReason::ShortRead,
                    );
                    Poll::Ready(Err(error))
                }
                Poll::Ready(Ok(read)) => {
                    filled += read;
                    if filled > wire_len {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            DetectionReason::FrameBounds,
                        );
                        return Poll::Ready(Err(error));
                    }
                    if filled < wire_len {
                        self.rx = ClientRx::ResponsePayload { wire_len, filled };
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let opened = self
                        .response_opener
                        .as_mut()
                        .expect("fixed response installed opener")
                        .open_slice_in_place(&mut self.decrypt[..wire_len]);
                    let plaintext_len = match opened {
                        Ok(plaintext_len) => plaintext_len,
                        Err(error) => {
                            let error = self.lifecycle.install_detection(
                                &mut self.io,
                                self.observers.flow,
                                detection_from_aead(error),
                            );
                            return Poll::Ready(Err(error));
                        }
                    };
                    if plaintext_len + TAG_LEN != wire_len {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            DetectionReason::FrameBounds,
                        );
                        return Poll::Ready(Err(error));
                    }
                    let mut position = 0;
                    let (copied, complete) =
                        copy_ready(&self.decrypt, &mut position, plaintext_len, destination);
                    self.rx = if complete {
                        ClientRx::Data(DataRx::Length { filled: 0 })
                    } else {
                        ClientRx::Data(DataRx::Ready {
                            position,
                            end: plaintext_len,
                        })
                    };
                    Poll::Ready(Ok(copied))
                }
            },
            ClientRx::Data(state) => {
                let result = poll_data_read(
                    &mut self.io,
                    self.response_opener
                        .as_mut()
                        .expect("response opener exists in data state"),
                    &mut self.decrypt,
                    state,
                    &mut self.lifecycle,
                    self.observers.flow,
                    cx,
                    destination,
                );
                match result {
                    DataPoll::Pending(state) => {
                        self.rx = ClientRx::Data(state);
                        Poll::Pending
                    }
                    DataPoll::Ready(state, result) => {
                        self.rx = ClientRx::Data(state);
                        Poll::Ready(result)
                    }
                }
            }
            ClientRx::Poison => unreachable!("client RX state is restored before returning"),
        }
    }

    fn open_response_fixed(&mut self) -> Result<usize, DetectionReason> {
        let profile = self.request_salt.profile();
        let salt_len = profile.salt_bytes();
        let response_first_read_len = profile.initial_response_read_bytes();
        let fixed_plaintext_len = response_fixed_plaintext_len(profile);
        let response_salt = MethodTcpSalt::try_from_slice(profile, &self.decrypt[..salt_len])
            .map_err(|_| DetectionReason::FrameBounds)?;
        if response_salt == self.request_salt {
            return Err(DetectionReason::ResponseBinding);
        }
        let mut opener = opener_for(self.keys, &response_salt)?;
        let fixed_wire_len = fixed_plaintext_len + TAG_LEN;
        self.decrypt
            .copy_within(salt_len..response_first_read_len, 0);
        let plaintext_len = opener
            .open_slice_in_place(&mut self.decrypt[..fixed_wire_len])
            .map_err(detection_from_aead)?;
        if plaintext_len != fixed_plaintext_len {
            return Err(DetectionReason::FrameBounds);
        }
        if self.decrypt[0] != RESPONSE_TYPE {
            return Err(DetectionReason::InvalidType);
        }
        let timestamp = u64::from_be_bytes(self.decrypt[1..9].try_into().expect("timestamp"));
        let now = self
            .clock
            .unix_seconds()
            .map_err(|_| DetectionReason::ClockUnavailable)?;
        if now.abs_diff(timestamp) > 30 {
            return Err(DetectionReason::TimestampSkew);
        }
        let binding_end = 9 + salt_len;
        if self.decrypt[9..binding_end] != *self.request_salt.as_bytes() {
            return Err(DetectionReason::ResponseBinding);
        }
        let payload_len = usize::from(u16::from_be_bytes(
            self.decrypt[binding_end..binding_end + 2]
                .try_into()
                .expect("length"),
        ));
        if payload_len == 0 {
            return Err(DetectionReason::FrameBounds);
        }
        let wire_len = payload_len
            .checked_add(TAG_LEN)
            .filter(|length| *length <= MAX_DECRYPT_WIRE_LEN)
            .ok_or(DetectionReason::FrameBounds)?;
        self.response_opener = Some(opener);
        Ok(wire_len)
    }

    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        poll_write_open(
            &mut self.io,
            &mut self.request_sealer,
            &mut self.encrypt,
            &mut self.staged,
            &mut self.tx,
            &mut self.lifecycle,
            self.observers.flow,
            cx,
            source,
        )
    }
}

impl<S, K, T> PlainDuplex for ClientFlow<'_, S, K, T>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
{
    fn poll_read_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        let this = self.get_mut();
        inspect_scratch(BufferRole::Encrypt, &this.encrypt, this.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &this.decrypt, this.observers.buffer);
        this.poll_read(cx, destination)
    }

    fn poll_write_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        let this = self.get_mut();
        inspect_scratch(BufferRole::Encrypt, &this.encrypt, this.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &this.decrypt, this.observers.buffer);
        this.poll_write(cx, source)
    }

    fn poll_flush_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        let this = self.get_mut();
        inspect_scratch(BufferRole::Encrypt, &this.encrypt, this.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &this.decrypt, this.observers.buffer);
        poll_flush(
            &mut this.io,
            &mut this.encrypt,
            &mut this.staged,
            this.tx,
            &mut this.lifecycle,
            this.observers.flow,
            cx,
        )
    }

    fn poll_shutdown_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        let this = self.get_mut();
        inspect_scratch(BufferRole::Encrypt, &this.encrypt, this.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &this.decrypt, this.observers.buffer);
        poll_shutdown(
            &mut this.io,
            &mut this.encrypt,
            &mut this.staged,
            &mut this.tx,
            &mut this.lifecycle,
            this.observers.flow,
            cx,
        )
    }

    fn mark_abortive_plain(&mut self) -> Result<(), ShadowsocksError> {
        self.io
            .mark_abortive()
            .map_err(|_| ShadowsocksError::Transport(TransportPhase::Shutdown))
    }

    fn terminal(&self) -> Option<FlowTerminal> {
        self.lifecycle.terminal
    }
}

impl PlainDuplex for BoxedClientFlow<'_> {
    fn poll_read_plain(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        Pin::new(&mut *self.inner).poll_read_plain(cx, destination)
    }

    fn poll_write_plain(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        Pin::new(&mut *self.inner).poll_write_plain(cx, source)
    }

    fn poll_flush_plain(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        Pin::new(&mut *self.inner).poll_flush_plain(cx)
    }

    fn poll_shutdown_plain(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>> {
        Pin::new(&mut *self.inner).poll_shutdown_plain(cx)
    }

    fn mark_abortive_plain(&mut self) -> Result<(), ShadowsocksError> {
        self.inner.mark_abortive_plain()
    }

    fn terminal(&self) -> Option<FlowTerminal> {
        self.inner.terminal()
    }
}
