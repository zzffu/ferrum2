use std::convert::Infallible;
use std::future::{Future, poll_fn, ready};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;

use ferrum2_core::{
    ConnectErrorKind, Connector, Inbound, LocalEndpoint, Outbound, Session, SessionReply,
    TargetAddr,
};
use ferrum2_crypto::{
    Clock, KeySelector, MethodKeyProvider, MethodProfile, MethodSecretKeyRef, MethodTcpSalt,
    SecureRandom, TcpOpener, TcpSealer, generate_method_request_salt,
};
use thiserror::Error;

use super::error::{
    DetectionReason, ShadowsocksError, detection_from_aead, detection_from_frame,
    terminate_detection,
};
use super::flow::{ClientFlow, ServerFlow, TransportIo, prepare_decrypt};
use super::observe::{
    BufferObserver, BufferRole, FlowObserver, Observers, fixed_scratch, inspect_scratch,
};
use super::replay::{ReplayInsertError, TcpReplayStore};
use super::wire::{
    INITIAL_ENCRYPT_WIRE_LEN, MAX_DECRYPT_WIRE_LEN, MAX_PADDING_LEN, REQUEST_FIXED_PLAINTEXT_LEN,
    REQUEST_TYPE, TAG_LEN, encode_request_state_into, opener_for, parse_request_variable,
    sample_nonzero_padding,
};

/// Narrow method-aware key capability consumed by the shared TCP state machine.
pub trait TcpKeyProvider: Send + Sync {
    /// Returns the immutable method profile before wire buffers are read.
    fn tcp_profile(&self) -> MethodProfile;

    /// Creates the outbound owner for a same-profile salt.
    fn tcp_sealer(&self, salt: &MethodTcpSalt) -> Result<TcpSealer, TcpKeyError>;

    /// Creates the inbound owner for a same-profile salt.
    fn tcp_opener(&self, salt: &MethodTcpSalt) -> Result<TcpOpener, TcpKeyError>;
}

/// Closed method-profile or key-lookup failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("TCP key unavailable")]
pub struct TcpKeyError;

/// Owns a method-aware crypto provider behind the shared protocol capability.
pub struct MethodKeyAdapter<K>(K);

impl<K> MethodKeyAdapter<K> {
    /// Wraps one method-aware provider without exposing raw key material.
    pub fn new(inner: K) -> Self {
        Self(inner)
    }

    /// Returns the wrapped provider.
    pub fn into_inner(self) -> K {
        self.0
    }
}

impl<K: MethodKeyProvider> TcpKeyProvider for MethodKeyAdapter<K> {
    fn tcp_profile(&self) -> MethodProfile {
        self.0.profile()
    }

    fn tcp_sealer(&self, salt: &MethodTcpSalt) -> Result<TcpSealer, TcpKeyError> {
        self.0
            .with_method_key(KeySelector::Default, |key| {
                key.derive_tcp_subkey(salt).map(TcpSealer::new)
            })
            .map_err(|_| TcpKeyError)?
            .map_err(|_| TcpKeyError)
    }

    fn tcp_opener(&self, salt: &MethodTcpSalt) -> Result<TcpOpener, TcpKeyError> {
        self.0
            .with_method_key(KeySelector::Default, |key| {
                key.derive_tcp_subkey(salt).map(TcpOpener::new)
            })
            .map_err(|_| TcpKeyError)?
            .map_err(|_| TcpKeyError)
    }
}

impl<K: MethodKeyProvider> MethodKeyProvider for MethodKeyAdapter<K> {
    type Error = K::Error;

    fn profile(&self) -> MethodProfile {
        self.0.profile()
    }

    fn with_method_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(MethodSecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error> {
        self.0.with_method_key(selector, use_key)
    }
}

/// A no-op server reply capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReply;

impl SessionReply for NoReply {
    type Error = Infallible;

    fn succeeded_socket(
        self,
        _bound: SocketAddr,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready(Ok(()))
    }

    fn failed(
        self,
        _kind: ConnectErrorKind,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready(Ok(()))
    }
}

/// Client outbound that stores the configured Shadowsocks server independently
/// from each application target passed to [`Outbound::open`].
pub struct ClientTcpOutbound<'a, K, C, T, R> {
    server: TargetAddr,
    keys: &'a K,
    connector: &'a C,
    clock: &'a T,
    random: &'a R,
    observers: Observers<'a>,
}

impl<'a, K, C, T, R> ClientTcpOutbound<'a, K, C, T, R> {
    /// Creates an outbound for one validated configured Shadowsocks server.
    pub fn new(
        server: TargetAddr,
        keys: &'a K,
        connector: &'a C,
        clock: &'a T,
        random: &'a R,
    ) -> Self {
        Self {
            server,
            keys,
            connector,
            clock,
            random,
            observers: Observers::noop(),
        }
    }

    /// Installs safe recording observers for focused tests.
    pub fn with_observers(
        mut self,
        buffer: &'a dyn BufferObserver,
        flow: &'a dyn FlowObserver,
    ) -> Self {
        self.observers = Observers { buffer, flow };
        self
    }

    /// Writes this hop's request over an already authenticated outer flow.
    pub async fn write_request_on<S>(
        &self,
        io: S,
        application_target: &TargetAddr,
    ) -> Result<ClientFlow<'a, S, K, T>, ShadowsocksError>
    where
        S: TransportIo + LocalEndpoint,
        K: TcpKeyProvider + Sync,
        T: Clock + Sync,
        R: SecureRandom,
    {
        ConnectedClientOpen {
            io,
            keys: self.keys,
            clock: self.clock,
            random: self.random,
            observers: self.observers,
        }
        .write_request(application_target)
        .await
    }
}

/// Opaque single-use capability for a connected client transport.
///
/// Consuming [`Self::write_request`] completes the SIP022 request first-write
/// and returns the only flow that can use the connected transport.
pub struct ConnectedClientOpen<'a, S, K, T, R> {
    io: S,
    keys: &'a K,
    clock: &'a T,
    random: &'a R,
    observers: Observers<'a>,
}

impl<'a, K, C, T, R> ClientTcpOutbound<'a, K, C, T, R>
where
    C: Connector,
{
    /// Dials only the stored configured Shadowsocks server.
    pub async fn connect_server(
        &self,
    ) -> Result<ConnectedClientOpen<'a, C::Stream, K, T, R>, ShadowsocksError> {
        let io = self
            .connector
            .connect(&self.server)
            .await
            .map_err(|error| ShadowsocksError::Connect(error.kind()))?;
        Ok(ConnectedClientOpen {
            io,
            keys: self.keys,
            clock: self.clock,
            random: self.random,
            observers: self.observers,
        })
    }
}

impl<'a, S, K, T, R> ConnectedClientOpen<'a, S, K, T, R>
where
    S: TransportIo + LocalEndpoint,
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
{
    /// Consumes the connected capability and completes one contiguous request write.
    pub async fn write_request(
        self,
        application_target: &TargetAddr,
    ) -> Result<ClientFlow<'a, S, K, T>, ShadowsocksError> {
        let Self {
            mut io,
            keys,
            clock,
            random,
            observers,
        } = self;
        let mut encrypt = fixed_scratch(
            BufferRole::Encrypt,
            INITIAL_ENCRYPT_WIRE_LEN,
            observers.buffer,
        );
        let decrypt = fixed_scratch(BufferRole::Decrypt, MAX_DECRYPT_WIRE_LEN, observers.buffer);

        let salt = generate_method_request_salt(keys.tcp_profile(), random).map_err(|_| {
            terminate_detection(&mut io, observers.flow, DetectionReason::RandomUnavailable)
        })?;
        let timestamp = clock.unix_seconds().map_err(|_| {
            terminate_detection(&mut io, observers.flow, DetectionReason::ClockUnavailable)
        })?;
        let mut padding = [0_u8; MAX_PADDING_LEN];
        let padding_len = sample_nonzero_padding(random, &mut padding).map_err(|_| {
            terminate_detection(&mut io, observers.flow, DetectionReason::RandomUnavailable)
        })?;
        let request_sealer = encode_request_state_into(
            keys,
            &salt,
            timestamp,
            application_target,
            &padding[..padding_len],
            &[],
            &mut encrypt,
        )
        .map_err(|error| {
            terminate_detection(&mut io, observers.flow, detection_from_frame(error))
        })?;
        let expected = encrypt.len();
        let mut position = 0;
        let first_write =
            poll_fn(
                |cx| match Pin::new(&mut io).poll_write(cx, &encrypt[position..]) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(_)) => Poll::Ready(Err(DetectionReason::WriteFailed)),
                    Poll::Ready(Ok(0)) => Poll::Ready(Err(DetectionReason::ShortWrite)),
                    Poll::Ready(Ok(written)) => {
                        let Some(next) = position
                            .checked_add(written)
                            .filter(|next| *next <= expected)
                        else {
                            return Poll::Ready(Err(DetectionReason::ShortWrite));
                        };
                        position = next;
                        if position == expected {
                            Poll::Ready(Ok(()))
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                },
            )
            .await;
        if let Err(reason) = first_write {
            return Err(terminate_detection(&mut io, observers.flow, reason));
        }
        encrypt.clear();
        inspect_scratch(BufferRole::Encrypt, &encrypt, observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &decrypt, observers.buffer);

        Ok(ClientFlow::from_handshake(
            io,
            keys,
            clock,
            salt,
            request_sealer,
            encrypt,
            decrypt,
            observers,
        ))
    }
}

impl<'a, K, C, T, R> ClientTcpOutbound<'a, K, C, T, R>
where
    K: TcpKeyProvider + Sync,
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint,
    T: Clock + Sync,
    R: SecureRandom,
{
}

impl<'a, K, C, T, R> Outbound for ClientTcpOutbound<'a, K, C, T, R>
where
    K: TcpKeyProvider + Sync,
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint,
    T: Clock + Sync,
    R: SecureRandom,
{
    type Stream = ClientFlow<'a, C::Stream, K, T>;
    type Error = ShadowsocksError;

    async fn open(&self, target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        self.connect_server().await?.write_request(target).await
    }
}

/// Server inbound that authenticates into a core session and opaque flow.
pub struct ShadowsocksTcpInbound<'a, K, T, R> {
    keys: &'a K,
    clock: &'a T,
    random: &'a R,
    replay: &'a TcpReplayStore,
    observers: Observers<'a>,
}

impl<'a, K, T, R> ShadowsocksTcpInbound<'a, K, T, R> {
    /// Creates a server-side inbound.
    pub const fn new(keys: &'a K, clock: &'a T, random: &'a R, replay: &'a TcpReplayStore) -> Self {
        Self {
            keys,
            clock,
            random,
            replay,
            observers: Observers::noop(),
        }
    }

    /// Installs safe recording observers for focused tests.
    pub fn with_observers(
        mut self,
        buffer: &'a dyn BufferObserver,
        flow: &'a dyn FlowObserver,
    ) -> Self {
        self.observers = Observers { buffer, flow };
        self
    }
}

impl<'a, K, T, R> ShadowsocksTcpInbound<'a, K, T, R>
where
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
{
    /// Authenticates one request and returns exact target/payload ownership.
    pub async fn accept_stream<S>(
        &self,
        mut io: S,
    ) -> Result<Session<ServerFlow<'a, S, K, T, R>, NoReply>, ShadowsocksError>
    where
        S: TransportIo,
    {
        let mut decrypt = fixed_scratch(
            BufferRole::Decrypt,
            MAX_DECRYPT_WIRE_LEN,
            self.observers.buffer,
        );
        let encrypt = fixed_scratch(
            BufferRole::Encrypt,
            INITIAL_ENCRYPT_WIRE_LEN,
            self.observers.buffer,
        );
        let profile = self.keys.tcp_profile();
        let salt_len = profile.salt_bytes();
        let request_first_read_len = profile.initial_request_read_bytes();
        prepare_decrypt(&mut decrypt, request_first_read_len);
        let mut fixed_filled = 0;
        let fixed_read = poll_fn(|cx| {
            match Pin::new(&mut io).poll_read_buf(
                cx,
                &mut decrypt,
                request_first_read_len - fixed_filled,
            ) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(_)) => Poll::Ready(Err(DetectionReason::ReadFailed)),
                Poll::Ready(Ok(0)) => Poll::Ready(Err(DetectionReason::ShortRead)),
                Poll::Ready(Ok(read)) => {
                    let Some(next) = fixed_filled
                        .checked_add(read)
                        .filter(|next| *next <= request_first_read_len)
                    else {
                        return Poll::Ready(Err(DetectionReason::ShortRead));
                    };
                    if decrypt.len() != next {
                        return Poll::Ready(Err(DetectionReason::ShortRead));
                    }
                    fixed_filled = next;
                    if fixed_filled == request_first_read_len {
                        Poll::Ready(Ok(()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
        })
        .await;
        if let Err(reason) = fixed_read {
            return Err(terminate_detection(&mut io, self.observers.flow, reason));
        }

        let request_salt =
            MethodTcpSalt::try_from_slice(profile, &decrypt[..salt_len]).map_err(|_| {
                terminate_detection(&mut io, self.observers.flow, DetectionReason::FrameBounds)
            })?;
        let mut opener = opener_for(self.keys, &request_salt)
            .map_err(|reason| terminate_detection(&mut io, self.observers.flow, reason))?;
        let fixed_wire: [u8; REQUEST_FIXED_PLAINTEXT_LEN + TAG_LEN] = decrypt
            [salt_len..request_first_read_len]
            .try_into()
            .expect("fixed encrypted request width");
        decrypt.clear();
        decrypt.extend_from_slice(&fixed_wire);
        opener.open_in_place(&mut decrypt).map_err(|error| {
            terminate_detection(&mut io, self.observers.flow, detection_from_aead(error))
        })?;
        if decrypt.len() != REQUEST_FIXED_PLAINTEXT_LEN {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::FrameBounds,
            ));
        }
        if decrypt[0] != REQUEST_TYPE {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::InvalidType,
            ));
        }
        let timestamp = u64::from_be_bytes(decrypt[1..9].try_into().expect("timestamp"));
        let now = self.clock.unix_seconds().map_err(|_| {
            terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::ClockUnavailable,
            )
        })?;
        if now.abs_diff(timestamp) > 30 {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::TimestampSkew,
            ));
        }
        let variable_len = usize::from(u16::from_be_bytes(
            decrypt[9..11].try_into().expect("length"),
        ));
        let wire_len = variable_len
            .checked_add(TAG_LEN)
            .filter(|length| *length <= MAX_DECRYPT_WIRE_LEN)
            .ok_or_else(|| {
                terminate_detection(&mut io, self.observers.flow, DetectionReason::FrameBounds)
            })?;

        prepare_decrypt(&mut decrypt, wire_len);
        let mut filled = 0;
        while filled < wire_len {
            let read =
                poll_fn(|cx| Pin::new(&mut io).poll_read_buf(cx, &mut decrypt, wire_len - filled))
                    .await
                    .map_err(|_| {
                        terminate_detection(
                            &mut io,
                            self.observers.flow,
                            DetectionReason::ReadFailed,
                        )
                    })?;
            if read == 0 {
                return Err(terminate_detection(
                    &mut io,
                    self.observers.flow,
                    DetectionReason::ShortRead,
                ));
            }
            filled = filled
                .checked_add(read)
                .filter(|n| *n <= wire_len)
                .ok_or_else(|| {
                    terminate_detection(&mut io, self.observers.flow, DetectionReason::FrameBounds)
                })?;
            if decrypt.len() != filled {
                return Err(terminate_detection(
                    &mut io,
                    self.observers.flow,
                    DetectionReason::FrameBounds,
                ));
            }
        }
        opener.open_in_place(&mut decrypt).map_err(|error| {
            terminate_detection(&mut io, self.observers.flow, detection_from_aead(error))
        })?;
        if decrypt.len() != variable_len {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::FrameBounds,
            ));
        }
        let parsed = parse_request_variable(&decrypt)
            .map_err(|reason| terminate_detection(&mut io, self.observers.flow, reason))?;
        match self
            .replay
            .check_and_insert(&request_salt, self.clock.monotonic_now())
        {
            Ok(()) => {}
            Err(ReplayInsertError::Duplicate) => {
                return Err(terminate_detection(
                    &mut io,
                    self.observers.flow,
                    DetectionReason::Replay,
                ));
            }
            Err(ReplayInsertError::Capacity) => {
                return Err(terminate_detection(
                    &mut io,
                    self.observers.flow,
                    DetectionReason::ReplayCapacity,
                ));
            }
            Err(ReplayInsertError::Unavailable) => {
                return Err(terminate_detection(
                    &mut io,
                    self.observers.flow,
                    DetectionReason::ReplayUnavailable,
                ));
            }
        }

        let initial_payload = parsed.initial_payload;
        decrypt.clear();
        inspect_scratch(BufferRole::Encrypt, &encrypt, self.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &decrypt, self.observers.buffer);
        Ok(Session {
            target: parsed.target,
            stream: ServerFlow::from_handshake(
                io,
                self.keys,
                self.clock,
                self.random,
                request_salt,
                opener,
                encrypt,
                decrypt,
                self.observers,
            ),
            initial_payload,
            reply: NoReply,
        })
    }
}

impl<'a, K, T, R, S> Inbound<S> for ShadowsocksTcpInbound<'a, K, T, R>
where
    K: TcpKeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
    S: TransportIo,
{
    type Stream = ServerFlow<'a, S, K, T, R>;
    type Reply = NoReply;
    type Error = ShadowsocksError;

    async fn accept(&self, io: S) -> Result<Session<Self::Stream, Self::Reply>, Self::Error> {
        self.accept_stream(io).await
    }
}
