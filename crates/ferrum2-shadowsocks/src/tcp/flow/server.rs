use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use ferrum2_crypto::{
    Clock, MethodTcpSalt, SecureRandom, TcpOpener, TcpSealer, generate_method_response_salt,
};

use super::io::{DataPoll, DataRead, drain_staged, poll_data_fill, poll_flush, poll_shutdown};
use super::{
    DataRx, Lifecycle, PlainBufferedDuplex, PlainDuplex, StagedKind, StagedWrite, TransportIo,
    TxState, protocol_cipher_boundary,
};
use crate::tcp::error::{
    DetectionReason, FlowTerminal, ShadowsocksError, TransportPhase, detection_from_frame,
};
use crate::tcp::handshake::TcpKeyProvider;
use crate::tcp::observe::{BufferRole, Observers, inspect_scratch};
use crate::tcp::wire::{MAX_ENCODE_PAYLOAD_LEN, encode_response_state_into, seal_data_chunk_into};

/// Opaque server flow retaining unsplit transport and both cipher directions.
pub struct ServerFlow<'a, S, K, T, R> {
    pub(super) io: S,
    pub(super) keys: &'a K,
    pub(super) clock: &'a T,
    pub(super) random: &'a R,
    pub(super) request_salt: MethodTcpSalt,
    pub(super) request_opener: TcpOpener,
    pub(super) response_sealer: Option<TcpSealer>,
    pub(super) rx: DataRx,
    pub(super) tx: TxState,
    pub(super) encrypt: BytesMut,
    pub(super) decrypt: BytesMut,
    pub(super) staged: Option<StagedWrite>,
    pub(super) lifecycle: Lifecycle,
    pub(super) observers: Observers<'a>,
}

impl<'a, S, K, T, R> ServerFlow<'a, S, K, T, R> {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::tcp) fn from_handshake(
        io: S,
        keys: &'a K,
        clock: &'a T,
        random: &'a R,
        request_salt: MethodTcpSalt,
        request_opener: TcpOpener,
        encrypt: BytesMut,
        decrypt: BytesMut,
        observers: Observers<'a>,
    ) -> Self {
        Self {
            io,
            keys,
            clock,
            random,
            request_salt,
            request_opener,
            response_sealer: None,
            rx: DataRx::Length { filled: 0 },
            tx: TxState::ResponsePending,
            encrypt,
            decrypt,
            staged: None,
            lifecycle: Lifecycle::default(),
            observers,
        }
    }
}

impl<'a, S, K, T, R> ServerFlow<'a, S, K, T, R>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
{
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<&[u8], ShadowsocksError>> {
        if let Some(error) = self.lifecycle.fatal_error() {
            return Poll::Ready(Err(error));
        }
        if self.lifecycle.terminal == Some(FlowTerminal::Normal) || self.lifecycle.rx_closed {
            return Poll::Ready(Ok(&[]));
        }
        let state = std::mem::replace(&mut self.rx, DataRx::Poison);
        match poll_data_fill(
            &mut self.io,
            &mut self.request_opener,
            &mut self.decrypt,
            state,
            &mut self.lifecycle,
            self.observers.flow,
            cx,
        ) {
            DataPoll::Pending(state) => {
                self.rx = state;
                Poll::Pending
            }
            DataPoll::Ready(state, result) => {
                self.rx = state;
                match result {
                    Ok(DataRead::Buffered) => Poll::Ready(Ok(self.current_plaintext())),
                    Ok(DataRead::Eof) => Poll::Ready(Ok(&[])),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
        }
    }

    fn current_plaintext(&self) -> &[u8] {
        let DataRx::Ready { position } = self.rx else {
            unreachable!("plaintext view requires ready data state")
        };
        &self.decrypt[position..]
    }

    fn consume(&mut self, amount: usize) {
        let complete = match &mut self.rx {
            DataRx::Ready { position } => {
                assert!(amount <= self.decrypt.len() - *position);
                *position += amount;
                *position == self.decrypt.len()
            }
            _ => {
                assert_eq!(amount, 0, "consume requires a current plaintext view");
                false
            }
        };
        if complete {
            self.decrypt.clear();
            self.rx = DataRx::Length { filled: 0 };
        }
    }

    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        if destination.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.poll_fill(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(source)) => {
                let copied = source.len().min(destination.len());
                destination[..copied].copy_from_slice(&source[..copied]);
                if copied != 0 {
                    self.consume(copied);
                }
                Poll::Ready(Ok(copied))
            }
        }
    }

    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>> {
        if let Some(error) = self.lifecycle.fatal_error() {
            return Poll::Ready(Err(error));
        }
        if source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.lifecycle.terminal == Some(FlowTerminal::Normal) {
            return Poll::Ready(Ok(0));
        }
        if self.lifecycle.tx_closed {
            let error = self
                .lifecycle
                .install_transport(self.observers.flow, TransportPhase::Write);
            return Poll::Ready(Err(error));
        }

        if self.staged.is_some() {
            match drain_staged(
                &mut self.io,
                &mut self.encrypt,
                &mut self.staged,
                &mut self.lifecycle,
                self.observers.flow,
                cx,
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }

        let admitted = source.len().min(MAX_ENCODE_PAYLOAD_LEN);
        if self.tx == TxState::ResponsePending {
            let response_salt = match generate_method_response_salt(self.random, &self.request_salt)
            {
                Ok(salt) => salt,
                Err(_) => {
                    let error = self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        DetectionReason::RandomUnavailable,
                    );
                    return Poll::Ready(Err(error));
                }
            };
            let timestamp = match self.clock.unix_seconds() {
                Ok(timestamp) => timestamp,
                Err(_) => {
                    let error = self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        DetectionReason::ClockUnavailable,
                    );
                    return Poll::Ready(Err(error));
                }
            };
            match encode_response_state_into(
                self.keys,
                &response_salt,
                timestamp,
                &self.request_salt,
                &source[..admitted],
                &mut self.encrypt,
            ) {
                Ok(sealer) => self.response_sealer = Some(sealer),
                Err(error) => {
                    let error = self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        detection_from_frame(error),
                    );
                    return Poll::Ready(Err(error));
                }
            }
            self.staged = Some(StagedWrite {
                kind: StagedKind::First,
                position: 0,
            });
            self.tx = TxState::Open;
            return Poll::Ready(Ok(admitted));
        }

        let sealer = self
            .response_sealer
            .as_mut()
            .expect("open server TX has response sealer");
        match protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            seal_data_chunk_into(sealer, &source[..admitted], &mut self.encrypt)
        }) {
            Ok(()) => {
                self.staged = Some(StagedWrite {
                    kind: StagedKind::Subsequent,
                    position: 0,
                });
                Poll::Ready(Ok(admitted))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S, K, T, R> PlainDuplex for ServerFlow<'_, S, K, T, R>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
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

    fn terminal(&self) -> Option<FlowTerminal> {
        self.lifecycle.terminal
    }
}

impl<S, K, T, R> PlainBufferedDuplex for ServerFlow<'_, S, K, T, R>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
{
    fn poll_fill_plain_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<&[u8], ShadowsocksError>> {
        let this = self.get_mut();
        inspect_scratch(BufferRole::Encrypt, &this.encrypt, this.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &this.decrypt, this.observers.buffer);
        this.poll_fill(cx)
    }

    fn consume_plain(self: Pin<&mut Self>, amount: usize) {
        self.get_mut().consume(amount);
    }
}
