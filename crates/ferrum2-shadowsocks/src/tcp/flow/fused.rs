use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
#[cfg(feature = "structural-metrics")]
use ferrum2_core::AbortiveClose;
use ferrum2_crypto::{Clock, SecureRandom, generate_method_response_salt};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralCounter, StructuralLocal};
use tokio::io::{AsyncRead, AsyncWrite};

use super::io::drain_staged;
use super::{
    ClientFlow, PlainBufferedDuplex, ServerFlow, StagedKind, StagedWrite, TransportIo, TxState,
    protocol_cipher_boundary,
};
use crate::tcp::error::{DetectionReason, ShadowsocksError, detection_from_frame};
use crate::tcp::handshake::TcpKeyProvider;
use crate::tcp::observe::{BufferRole, inspect_scratch};
use crate::tcp::wire::{
    ENCRYPTED_LENGTH_LEN, prepare_data_chunk_into, prepare_response_state_in_place,
    seal_prepared_data_chunk_into, seal_prepared_response_state_into,
};

/// Direction of one completed plaintext admission in the fused engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FusedRelayDirection {
    PlainToTunnel,
    TunnelToPlain,
}

pub(crate) fn fused_relay<'a, P, F, O>(
    plain: &'a mut P,
    flow: &'a mut F,
    observe: O,
    #[cfg(feature = "structural-metrics")] structural: &'a StructuralLocal,
) -> FusedRelay<'a, P, F, O>
where
    P: AsyncRead + AsyncWrite + Unpin,
    F: FusedProtocolFlow,
    O: FnMut(FusedRelayDirection, usize) + Unpin,
{
    let pending_upload_plaintext = flow.has_staged_upload().then_some(0);
    #[cfg(feature = "structural-metrics")]
    let structural_stats = FusedStructuralStats::new(flow.structural_buffer_capacities());
    FusedRelay {
        plain,
        flow,
        observe,
        #[cfg(feature = "structural-metrics")]
        structural,
        #[cfg(feature = "structural-metrics")]
        structural_stats,
        pending_upload_plaintext,
        upload_eof: false,
        download_eof: false,
        upload_done: false,
        download_done: false,
        upload_first: true,
    }
}

pub(crate) struct FusedRelay<'a, P, F, O> {
    plain: &'a mut P,
    flow: &'a mut F,
    observe: O,
    #[cfg(feature = "structural-metrics")]
    structural: &'a StructuralLocal,
    #[cfg(feature = "structural-metrics")]
    structural_stats: FusedStructuralStats,
    pending_upload_plaintext: Option<usize>,
    upload_eof: bool,
    download_eof: bool,
    upload_done: bool,
    download_done: bool,
    upload_first: bool,
}

#[cfg(feature = "structural-metrics")]
impl<P, F, O> Drop for FusedRelay<'_, P, F, O> {
    fn drop(&mut self) {
        self.structural_stats.publish(self.structural);
    }
}

#[cfg(feature = "structural-metrics")]
struct FusedStructuralStats {
    owned_upload_frames: u64,
    borrowed_download_frames: u64,
    partial_writes: u64,
    encrypt_buffer_capacity: u64,
    decrypt_buffer_capacity: u64,
    download_frame_open: bool,
}

#[cfg(feature = "structural-metrics")]
impl FusedStructuralStats {
    fn new((encrypt, decrypt): (usize, usize)) -> Self {
        Self {
            owned_upload_frames: 0,
            borrowed_download_frames: 0,
            partial_writes: 0,
            encrypt_buffer_capacity: encrypt as u64,
            decrypt_buffer_capacity: decrypt as u64,
            download_frame_open: false,
        }
    }

    fn publish(&self, structural: &StructuralLocal) {
        structural.add(
            StructuralCounter::FtbrOwnedUploadFrames,
            self.owned_upload_frames,
        );
        structural.add(
            StructuralCounter::FtbrBorrowedDownloadFrames,
            self.borrowed_download_frames,
        );
        structural.add(StructuralCounter::FtbrPartialWrites, self.partial_writes);
        structural.add(
            StructuralCounter::FtbrFrames,
            self.owned_upload_frames
                .saturating_add(self.borrowed_download_frames),
        );
        structural.add(
            StructuralCounter::FtbrEncryptBufferCapacityBytes,
            self.encrypt_buffer_capacity,
        );
        structural.add(
            StructuralCounter::FtbrDecryptBufferCapacityBytes,
            self.decrypt_buffer_capacity,
        );
    }
}

impl<P, F, O> Future for FusedRelay<'_, P, F, O>
where
    P: AsyncRead + AsyncWrite + Unpin,
    F: FusedProtocolFlow,
    O: FnMut(FusedRelayDirection, usize) + Unpin,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let upload_first = this.upload_first;
        this.upload_first = !this.upload_first;

        if upload_first {
            if let Poll::Ready(result) = this.poll_upload(cx) {
                result?;
            }
            if let Poll::Ready(result) = this.poll_download(cx) {
                result?;
            }
        } else {
            if let Poll::Ready(result) = this.poll_download(cx) {
                result?;
            }
            if let Poll::Ready(result) = this.poll_upload(cx) {
                result?;
            }
        }

        if this.upload_done && this.download_done {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl<P, F, O> FusedRelay<'_, P, F, O>
where
    P: AsyncRead + AsyncWrite + Unpin,
    F: FusedProtocolFlow,
    O: FnMut(FusedRelayDirection, usize),
{
    fn poll_upload(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.upload_done {
            return Poll::Ready(Ok(()));
        }
        self.flow.inspect_buffers();

        if self.pending_upload_plaintext.is_some() {
            match self.poll_pending_upload(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if self.upload_eof {
            return self.poll_upload_shutdown(cx);
        }

        self.flow.prepare_upload_read().map_err(framed_error)?;
        let before = self.flow.upload_scratch().len();
        let payload_limit = self.flow.upload_payload_limit();
        let read = {
            let mut limited = (&mut *self.flow.upload_scratch()).limit(payload_limit);
            tokio_util::io::poll_read_buf(Pin::new(&mut *self.plain), cx, &mut limited)
        };
        let read = match read {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(read)) => read,
        };
        if self.flow.upload_scratch().len() != before.saturating_add(read) {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        if read == 0 {
            self.flow.discard_upload_read();
            self.upload_eof = true;
            return self.poll_upload_shutdown(cx);
        }

        self.flow.seal_upload_read(read).map_err(framed_error)?;
        #[cfg(feature = "structural-metrics")]
        {
            self.structural_stats.owned_upload_frames =
                self.structural_stats.owned_upload_frames.saturating_add(1);
        }
        self.pending_upload_plaintext = Some(read);
        match self.poll_pending_upload(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_pending_upload(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flow.has_staged_upload() {
            match self
                .flow
                .poll_drain_upload(
                    cx,
                    #[cfg(feature = "structural-metrics")]
                    &mut self.structural_stats.partial_writes,
                )
                .map_err(framed_error)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        let plaintext_len = self
            .pending_upload_plaintext
            .take()
            .expect("pending plaintext exists until its complete wire drain");
        if plaintext_len != 0 {
            (self.observe)(FusedRelayDirection::PlainToTunnel, plaintext_len);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_upload_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self.flow)
            .poll_shutdown_plain(cx)
            .map_err(framed_error)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                self.upload_done = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_download(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.download_done {
            return Poll::Ready(Ok(()));
        }
        self.flow.inspect_buffers();
        if self.download_eof {
            return self.poll_download_shutdown(cx);
        }
        let fill = Pin::new(&mut *self.flow)
            .poll_fill_plain_buf(cx)
            .map_err(framed_error);
        let source = match fill {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(source)) => source,
        };
        if source.is_empty() {
            self.download_eof = true;
            return self.poll_download_shutdown(cx);
        }
        #[cfg(feature = "structural-metrics")]
        if !self.structural_stats.download_frame_open {
            self.structural_stats.borrowed_download_frames = self
                .structural_stats
                .borrowed_download_frames
                .saturating_add(1);
            self.structural_stats.download_frame_open = true;
        }
        #[cfg(feature = "structural-metrics")]
        let source_len = source.len();
        let written = match Pin::new(&mut *self.plain).poll_write(cx, source) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            Poll::Ready(Ok(written)) if written <= source.len() => written,
            Poll::Ready(Ok(_)) => {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
        };
        #[cfg(feature = "structural-metrics")]
        {
            if written < source_len {
                self.structural_stats.partial_writes =
                    self.structural_stats.partial_writes.saturating_add(1);
            } else {
                self.structural_stats.download_frame_open = false;
            }
        }
        Pin::new(&mut *self.flow).consume_plain(written);
        (self.observe)(FusedRelayDirection::TunnelToPlain, written);
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_download_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self.plain).poll_shutdown(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                self.download_done = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

pub(crate) trait FusedProtocolFlow: PlainBufferedDuplex {
    fn inspect_buffers(&self);
    fn has_staged_upload(&self) -> bool;
    fn prepare_upload_read(&mut self) -> Result<(), ShadowsocksError>;
    fn upload_payload_limit(&self) -> usize;
    fn upload_scratch(&mut self) -> &mut BytesMut;
    fn seal_upload_read(&mut self, payload_len: usize) -> Result<(), ShadowsocksError>;
    fn discard_upload_read(&mut self);
    fn poll_drain_upload(
        &mut self,
        cx: &mut Context<'_>,
        #[cfg(feature = "structural-metrics")] partial_writes: &mut u64,
    ) -> Poll<Result<(), ShadowsocksError>>;
    #[cfg(feature = "structural-metrics")]
    fn structural_buffer_capacities(&self) -> (usize, usize);
}

#[cfg(feature = "structural-metrics")]
struct PartialWriteTransport<'a, S> {
    inner: &'a mut S,
    partial_writes: &'a mut u64,
}

#[cfg(feature = "structural-metrics")]
impl<S> AbortiveClose for PartialWriteTransport<'_, S>
where
    S: TransportIo,
{
    type Error = S::Error;

    fn mark_abortive(&mut self) -> Result<(), Self::Error> {
        self.inner.mark_abortive()
    }
}

#[cfg(feature = "structural-metrics")]
impl<S> TransportIo for PartialWriteTransport<'_, S>
where
    S: TransportIo,
{
    type IoError = S::IoError;

    fn poll_read_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut BytesMut,
        limit: usize,
    ) -> Poll<Result<usize, Self::IoError>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read_buf(cx, destination, limit)
    }

    fn poll_read_initialized(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read_initialized(cx, destination)
    }

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, source);
        if let Poll::Ready(Ok(written)) = &result
            && *written != 0
            && *written < source.len()
        {
            *this.partial_writes = this.partial_writes.saturating_add(1);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::IoError>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

impl<S, K, T> FusedProtocolFlow for ClientFlow<'_, S, K, T>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
{
    fn inspect_buffers(&self) {
        inspect_scratch(BufferRole::Encrypt, &self.encrypt, self.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &self.decrypt, self.observers.buffer);
    }

    fn has_staged_upload(&self) -> bool {
        self.staged.is_some()
    }

    fn prepare_upload_read(&mut self) -> Result<(), ShadowsocksError> {
        if self.encrypt.is_empty() {
            protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
                self.frame_sizer.prepare_scratch(&mut self.encrypt)?;
                prepare_data_chunk_into(&mut self.encrypt)
            })?;
        } else if self.encrypt.len() != ENCRYPTED_LENGTH_LEN {
            return Err(self
                .lifecycle
                .install_protocol(self.observers.flow, crate::tcp::ProtocolReason::FrameBounds));
        }
        Ok(())
    }

    fn upload_payload_limit(&self) -> usize {
        self.frame_sizer.payload_limit()
    }

    fn upload_scratch(&mut self) -> &mut BytesMut {
        &mut self.encrypt
    }

    fn seal_upload_read(&mut self, payload_len: usize) -> Result<(), ShadowsocksError> {
        protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            seal_prepared_data_chunk_into(&mut self.request_sealer, payload_len, &mut self.encrypt)
        })?;
        protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            self.frame_sizer.record(payload_len)
        })?;
        self.staged = Some(StagedWrite {
            kind: StagedKind::Subsequent,
            position: 0,
        });
        self.tx = TxState::Open;
        Ok(())
    }

    fn discard_upload_read(&mut self) {
        self.encrypt.clear();
    }

    fn poll_drain_upload(
        &mut self,
        cx: &mut Context<'_>,
        #[cfg(feature = "structural-metrics")] partial_writes: &mut u64,
    ) -> Poll<Result<(), ShadowsocksError>> {
        #[cfg(not(feature = "structural-metrics"))]
        {
            drain_staged(
                &mut self.io,
                &mut self.encrypt,
                &mut self.staged,
                &mut self.lifecycle,
                self.observers.flow,
                cx,
            )
        }
        #[cfg(feature = "structural-metrics")]
        {
            let mut io = PartialWriteTransport {
                inner: &mut self.io,
                partial_writes,
            };
            drain_staged(
                &mut io,
                &mut self.encrypt,
                &mut self.staged,
                &mut self.lifecycle,
                self.observers.flow,
                cx,
            )
        }
    }

    #[cfg(feature = "structural-metrics")]
    fn structural_buffer_capacities(&self) -> (usize, usize) {
        (self.encrypt.capacity(), self.decrypt.capacity())
    }
}

impl<S, K, T, R> FusedProtocolFlow for ServerFlow<'_, S, K, T, R>
where
    S: TransportIo,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
{
    fn inspect_buffers(&self) {
        inspect_scratch(BufferRole::Encrypt, &self.encrypt, self.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &self.decrypt, self.observers.buffer);
    }

    fn has_staged_upload(&self) -> bool {
        self.staged.is_some()
    }

    fn prepare_upload_read(&mut self) -> Result<(), ShadowsocksError> {
        if !self.encrypt.is_empty() {
            let expected = if self.tx == TxState::ResponsePending {
                self.request_salt.profile().initial_response_read_bytes()
            } else {
                ENCRYPTED_LENGTH_LEN
            };
            if self.encrypt.len() == expected {
                return Ok(());
            }
            return Err(self
                .lifecycle
                .install_protocol(self.observers.flow, crate::tcp::ProtocolReason::FrameBounds));
        }

        protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            self.frame_sizer.prepare_scratch(&mut self.encrypt)
        })?;

        if self.tx == TxState::ResponsePending {
            let response_first_read_len = self.request_salt.profile().initial_response_read_bytes();
            if response_first_read_len > self.encrypt.capacity() {
                return Err(self.lifecycle.install_protocol(
                    self.observers.flow,
                    crate::tcp::ProtocolReason::FrameBounds,
                ));
            }
            self.encrypt.resize(response_first_read_len, 0);
            return Ok(());
        }

        protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            prepare_data_chunk_into(&mut self.encrypt)
        })
    }

    fn upload_payload_limit(&self) -> usize {
        self.frame_sizer.payload_limit()
    }

    fn upload_scratch(&mut self) -> &mut BytesMut {
        &mut self.encrypt
    }

    fn seal_upload_read(&mut self, payload_len: usize) -> Result<(), ShadowsocksError> {
        let kind = if self.tx == TxState::ResponsePending {
            let response_salt = generate_method_response_salt(self.random, &self.request_salt)
                .map_err(|_| {
                    self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        DetectionReason::RandomUnavailable,
                    )
                })?;
            let timestamp = self.clock.unix_seconds().map_err(|_| {
                self.lifecycle.install_detection(
                    &mut self.io,
                    self.observers.flow,
                    DetectionReason::ClockUnavailable,
                )
            })?;
            let mut sealer = prepare_response_state_in_place(
                self.keys,
                &response_salt,
                timestamp,
                &self.request_salt,
                &mut self.encrypt,
            )
            .map_err(|error| {
                self.lifecycle.install_detection(
                    &mut self.io,
                    self.observers.flow,
                    detection_from_frame(error),
                )
            })?;
            let profile = self.request_salt.profile();
            seal_prepared_response_state_into(&mut sealer, profile, payload_len, &mut self.encrypt)
                .map_err(|error| {
                    self.lifecycle.install_detection(
                        &mut self.io,
                        self.observers.flow,
                        detection_from_frame(error),
                    )
                })?;
            self.response_sealer = Some(sealer);
            self.tx = TxState::Open;
            StagedKind::First
        } else {
            let sealer = self
                .response_sealer
                .as_mut()
                .expect("open server TX owns its sealer");
            protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
                seal_prepared_data_chunk_into(sealer, payload_len, &mut self.encrypt)
            })?;
            StagedKind::Subsequent
        };
        protocol_cipher_boundary(&mut self.lifecycle, self.observers.flow, || {
            self.frame_sizer.record(payload_len)
        })?;
        self.staged = Some(StagedWrite { kind, position: 0 });
        Ok(())
    }

    fn discard_upload_read(&mut self) {
        self.encrypt.clear();
        if self.tx == TxState::ResponsePending {
            self.response_sealer = None;
        }
    }

    fn poll_drain_upload(
        &mut self,
        cx: &mut Context<'_>,
        #[cfg(feature = "structural-metrics")] partial_writes: &mut u64,
    ) -> Poll<Result<(), ShadowsocksError>> {
        #[cfg(not(feature = "structural-metrics"))]
        {
            drain_staged(
                &mut self.io,
                &mut self.encrypt,
                &mut self.staged,
                &mut self.lifecycle,
                self.observers.flow,
                cx,
            )
        }
        #[cfg(feature = "structural-metrics")]
        {
            let mut io = PartialWriteTransport {
                inner: &mut self.io,
                partial_writes,
            };
            drain_staged(
                &mut io,
                &mut self.encrypt,
                &mut self.staged,
                &mut self.lifecycle,
                self.observers.flow,
                cx,
            )
        }
    }

    #[cfg(feature = "structural-metrics")]
    fn structural_buffer_capacities(&self) -> (usize, usize) {
        (self.encrypt.capacity(), self.decrypt.capacity())
    }
}

fn framed_error(error: ShadowsocksError) -> io::Error {
    let kind = match error {
        ShadowsocksError::Detection(_) | ShadowsocksError::Protocol(_) => {
            io::ErrorKind::InvalidData
        }
        ShadowsocksError::Transport(_) | ShadowsocksError::Connect(_) => io::ErrorKind::Other,
    };
    kind.into()
}
