#![forbid(unsafe_code)]

//! SIP022 TCP framing and opaque duplex flows for the AES-128 M0 slice.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::future::{Future, poll_fn, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ferrum2_core::{
    AbortiveClose, ConnectErrorKind, Connector, Inbound, LocalEndpoint, Outbound, Session,
    SessionReply, TargetAddr,
};
use ferrum2_crypto::{
    AeadError, Clock, KeyProvider, KeySelector, MonotonicInstant, SecureRandom, TcpMethod,
    TcpOpener, TcpSalt, TcpSealer, generate_request_salt, generate_response_salt,
};
use thiserror::Error;

/// Request salt width for `2022-blake3-aes-128-gcm`.
pub const TCP_SALT_LEN: usize = 16;
/// AES-GCM tag width.
pub const TAG_LEN: usize = 16;
/// Request salt plus encrypted fixed request header.
pub const REQUEST_FIRST_READ_LEN: usize = 43;
/// Response salt plus encrypted fixed response header.
pub const RESPONSE_FIRST_READ_LEN: usize = 59;
/// Largest plaintext chunk accepted from a compatible peer.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
/// Fixed usable limit requested for each receive-direction scratch.
pub const MAX_DECRYPT_WIRE_LEN: usize = MAX_PAYLOAD_LEN + TAG_LEN;
/// Largest application chunk emitted by ferrum2.
pub const MAX_ENCODE_PAYLOAD_LEN: usize = 16_384;
/// Fixed usable limit requested for the single per-flow encrypt scratch.
pub const MAX_ENCRYPT_WIRE_LEN: usize =
    TCP_SALT_LEN + RESPONSE_FIXED_PLAINTEXT_LEN + TAG_LEN + MAX_ENCODE_PAYLOAD_LEN + TAG_LEN;
/// Largest SIP022 request padding accepted by M0.
pub const MAX_PADDING_LEN: usize = 900;

const REQUEST_TYPE: u8 = 0;
const RESPONSE_TYPE: u8 = 1;
const IPV4_ATYP: u8 = 1;
const REQUEST_FIXED_PLAINTEXT_LEN: usize = 11;
const RESPONSE_FIXED_PLAINTEXT_LEN: usize = 27;
const ENCRYPTED_LENGTH_LEN: usize = 2 + TAG_LEN;
const REPLAY_RETENTION: Duration = Duration::from_secs(60);
const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const MIN_REPLAY_CAPACITY: usize = 1_024;
const MAX_REPLAY_CAPACITY: usize = 1_048_576;

/// A closed deterministic codec failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FrameError {
    /// The configured key could not be selected.
    #[error("key unavailable")]
    KeyUnavailable,
    /// The cryptographic operation failed without exposing its source.
    #[error("cipher operation failed")]
    Cipher,
    /// The nonce owner has no unused nonce.
    #[error("nonce exhausted")]
    NonceExhausted,
    /// A length cannot be represented by the SIP022 frame.
    #[error("frame bounds invalid")]
    Bounds,
    /// M0 accepts only IPv4 target addresses.
    #[error("target address unsupported")]
    AddressUnsupported,
    /// Padding exceeds the fixed M0 bound.
    #[error("padding bounds invalid")]
    PaddingBounds,
    /// A request supplied neither padding nor initial payload.
    #[error("request content is empty")]
    EmptyRequest,
    /// A first response payload must be nonempty.
    #[error("response payload is empty")]
    EmptyResponse,
    /// Response and request salt must differ.
    #[error("response salt repeats request salt")]
    ResponseSaltReuse,
}

/// Closed reason for an initial-envelope detection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionReason {
    /// An initial fixed read completed short.
    ShortRead,
    /// An initial contiguous write completed short.
    ShortWrite,
    /// An authenticated chunk failed verification.
    Authentication,
    /// The authenticated message type was invalid for this direction.
    InvalidType,
    /// The authenticated timestamp exceeded the inclusive 30-second window.
    TimestampSkew,
    /// Authenticated frame lengths were invalid.
    FrameBounds,
    /// The authenticated address was not a valid M0 IPv4 target.
    AddressBounds,
    /// Authenticated padding was malformed or exceeded 900 bytes.
    PaddingBounds,
    /// A request had neither padding nor initial payload.
    EmptyRequest,
    /// A response did not bind the complete request salt.
    ResponseBinding,
    /// The configured key was unavailable.
    KeyUnavailable,
    /// Wall time was unavailable.
    ClockUnavailable,
    /// Secure randomness was unavailable or repeatedly collided.
    RandomUnavailable,
    /// The exact incoming TCP salt was already live.
    Replay,
    /// All replay slots were occupied by live entries.
    ReplayCapacity,
    /// Exact replay state could not be safely mutated.
    ReplayUnavailable,
    /// The underlying initial read failed.
    ReadFailed,
    /// The underlying initial write failed.
    WriteFailed,
}

/// Closed reason for a post-first-envelope protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolReason {
    /// A subsequent authenticated chunk failed verification.
    Authentication,
    /// A subsequent frame was truncated or outside its bounds.
    FrameBounds,
    /// A cipher owner had no unused nonce.
    NonceExhausted,
}

/// Closed phase for a post-first-envelope transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPhase {
    /// A read operation failed.
    Read,
    /// A write operation failed.
    Write,
    /// A nonempty pending write completed with zero bytes.
    WriteZero,
    /// A flush operation failed.
    Flush,
    /// A shutdown operation failed.
    Shutdown,
}

/// Immutable terminal state for an opaque duplex flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowTerminal {
    /// Both logical directions closed normally.
    Normal,
    /// An initial-envelope failure installed an abortive terminal.
    Detection(DetectionReason),
    /// A subsequent wire failure terminated both directions.
    Protocol(ProtocolReason),
    /// A subsequent transport failure terminated both directions.
    Transport(TransportPhase),
}

/// Closed public error surface. No variant retains an underlying source.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShadowsocksError {
    /// A configured-server connector failed before any protocol write.
    #[error("connection failed")]
    Connect(ConnectErrorKind),
    /// An initial envelope failed closed.
    #[error("SIP022 detection failure")]
    Detection(DetectionReason),
    /// A subsequent protocol operation failed closed.
    #[error("SIP022 protocol failure")]
    Protocol(ProtocolReason),
    /// A subsequent transport operation failed closed.
    #[error("SIP022 transport failure")]
    Transport(TransportPhase),
}

/// Executor-neutral transport capability owned by one opaque flow.
pub trait TransportIo: AbortiveClose + Send + Unpin {
    /// Underlying error type. It is immediately erased into a closed phase.
    type IoError;

    /// Polls one transport read operation.
    fn poll_read(
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

    /// Returns the flow's sole immutable terminal latch.
    fn terminal(&self) -> Option<FlowTerminal>;
}

/// Fixed scratch allocation roles observable without exposing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferRole {
    /// The one per-flow encrypt scratch.
    Encrypt,
    /// The one receive-direction decrypt scratch.
    Decrypt,
}

/// Safe fixed-buffer observation seam.
pub trait BufferObserver: Send + Sync {
    /// Records one fixed usable-limit request and opaque storage identity.
    fn allocated(&self, role: BufferRole, usable_limit: usize, storage_identity: usize);

    /// Records the current identity at a public flow poll boundary.
    fn inspected(&self, _role: BufferRole, _storage_identity: usize) {}
}

/// Closed terminal observation seam.
pub trait FlowObserver: Send + Sync {
    /// Records installation of the sole terminal latch.
    fn terminal_installed(&self, terminal: FlowTerminal);
}

struct NoopObserver;

impl BufferObserver for NoopObserver {
    fn allocated(&self, _role: BufferRole, _usable_limit: usize, _storage_identity: usize) {}
}

impl FlowObserver for NoopObserver {
    fn terminal_installed(&self, _terminal: FlowTerminal) {}
}

static NOOP_OBSERVER: NoopObserver = NoopObserver;

#[derive(Clone, Copy)]
struct Observers<'a> {
    buffer: &'a dyn BufferObserver,
    flow: &'a dyn FlowObserver,
}

impl Observers<'static> {
    const fn noop() -> Self {
        Self {
            buffer: &NOOP_OBSERVER,
            flow: &NOOP_OBSERVER,
        }
    }
}

fn fixed_scratch(role: BufferRole, limit: usize, observer: &dyn BufferObserver) -> BytesMut {
    let scratch = BytesMut::with_capacity(limit);
    observer.allocated(role, limit, scratch.as_ptr() as usize);
    scratch
}

fn inspect_scratch(role: BufferRole, scratch: &BytesMut, observer: &dyn BufferObserver) {
    observer.inspected(role, scratch.as_ptr() as usize);
}

/// Exact, bounded TCP replay state shared by server handshakes.
pub struct TcpReplayStore {
    capacity: usize,
    state: Mutex<ReplayState>,
}

struct ReplayState {
    entries: HashMap<TcpSalt, MonotonicInstant>,
    insertion_order: VecDeque<TcpSalt>,
}

/// Invalid replay capacity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("replay capacity is outside the approved range")]
pub struct ReplayCapacityError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayInsertError {
    Duplicate,
    Capacity,
    Unavailable,
}

impl TcpReplayStore {
    /// Creates exact replay state with the approved default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_REPLAY_CAPACITY).expect("the approved default is in range")
    }

    /// Creates exact replay state with a validated capacity.
    pub fn new(capacity: usize) -> Result<Self, ReplayCapacityError> {
        if !(MIN_REPLAY_CAPACITY..=MAX_REPLAY_CAPACITY).contains(&capacity) {
            return Err(ReplayCapacityError);
        }
        Ok(Self {
            capacity,
            state: Mutex::new(ReplayState {
                entries: HashMap::with_capacity(capacity),
                insertion_order: VecDeque::with_capacity(capacity),
            }),
        })
    }

    /// Returns the exact number of live or not-yet-purged entries.
    pub fn entry_count(&self) -> Result<usize, ShadowsocksError> {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .map_err(|_| ShadowsocksError::Detection(DetectionReason::ReplayUnavailable))
    }

    fn check_and_insert(
        &self,
        salt: &TcpSalt,
        now: MonotonicInstant,
    ) -> Result<(), ReplayInsertError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReplayInsertError::Unavailable)?;
        purge_expired(&mut state, now);
        if state.entries.contains_key(salt) {
            return Err(ReplayInsertError::Duplicate);
        }
        if state.entries.len() == self.capacity {
            return Err(ReplayInsertError::Capacity);
        }
        state.entries.insert(salt.clone(), now);
        state.insertion_order.push_back(salt.clone());
        Ok(())
    }
}

impl Default for TcpReplayStore {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

fn purge_expired(state: &mut ReplayState, now: MonotonicInstant) {
    while let Some(oldest) = state.insertion_order.front() {
        let Some(inserted) = state.entries.get(oldest).copied() else {
            state.insertion_order.pop_front();
            continue;
        };
        if !now
            .duration_since(inserted)
            .is_some_and(|elapsed| elapsed >= REPLAY_RETENTION)
        {
            break;
        }
        let salt = state
            .insertion_order
            .pop_front()
            .expect("front was observed");
        state.entries.remove(&salt);
    }
}

/// A no-op server reply capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReply;

impl SessionReply for NoReply {
    type Error = Infallible;

    fn succeeded(
        self,
        _bound: SocketAddrV4,
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
}

impl<'a, K, C, T, R> ClientTcpOutbound<'a, K, C, T, R>
where
    K: KeyProvider + Sync,
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint,
    T: Clock + Sync,
    R: SecureRandom,
{
    /// Dials the stored server and completes one contiguous request write.
    pub async fn open_stream(
        &self,
        application_target: &TargetAddr,
    ) -> Result<ClientFlow<'a, C::Stream, K, T>, ShadowsocksError> {
        let mut io = self
            .connector
            .connect(&self.server)
            .await
            .map_err(|error| ShadowsocksError::Connect(error.kind()))?;
        let mut encrypt = fixed_scratch(
            BufferRole::Encrypt,
            MAX_ENCRYPT_WIRE_LEN,
            self.observers.buffer,
        );
        let decrypt = fixed_scratch(
            BufferRole::Decrypt,
            MAX_DECRYPT_WIRE_LEN,
            self.observers.buffer,
        );

        let salt = generate_request_salt(self.random).map_err(|_| {
            terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::RandomUnavailable,
            )
        })?;
        let timestamp = self.clock.unix_seconds().map_err(|_| {
            terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::ClockUnavailable,
            )
        })?;
        let mut padding = [0_u8; MAX_PADDING_LEN];
        let padding_len = sample_nonzero_padding(self.random, &mut padding).map_err(|_| {
            terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::RandomUnavailable,
            )
        })?;
        let request_sealer = encode_request_state_into(
            self.keys,
            &salt,
            timestamp,
            application_target,
            &padding[..padding_len],
            &[],
            &mut encrypt,
        )
        .map_err(|error| {
            terminate_detection(&mut io, self.observers.flow, detection_from_frame(error))
        })?;
        let expected = encrypt.len();
        let write = poll_fn(|cx| Pin::new(&mut io).poll_write(cx, &encrypt)).await;
        let written = write.map_err(|_| {
            terminate_detection(&mut io, self.observers.flow, DetectionReason::WriteFailed)
        })?;
        if written != expected {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::ShortWrite,
            ));
        }
        encrypt.clear();
        inspect_scratch(BufferRole::Encrypt, &encrypt, self.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &decrypt, self.observers.buffer);

        Ok(ClientFlow {
            io,
            keys: self.keys,
            clock: self.clock,
            request_salt: salt,
            request_sealer,
            response_opener: None,
            rx: ClientRx::ResponseFixed,
            tx: TxState::Open,
            encrypt,
            decrypt,
            staged: None,
            lifecycle: Lifecycle::default(),
            observers: self.observers,
        })
    }
}

impl<'a, K, C, T, R> Outbound for ClientTcpOutbound<'a, K, C, T, R>
where
    K: KeyProvider + Sync,
    C: Connector,
    C::Stream: TransportIo + LocalEndpoint,
    T: Clock + Sync,
    R: SecureRandom,
{
    type Stream = ClientFlow<'a, C::Stream, K, T>;
    type Error = ShadowsocksError;

    async fn open(&self, target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        self.open_stream(target).await
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
    K: KeyProvider + Sync,
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
            MAX_ENCRYPT_WIRE_LEN,
            self.observers.buffer,
        );
        reset_decrypt(&mut decrypt);

        let first_read =
            poll_fn(|cx| Pin::new(&mut io).poll_read(cx, &mut decrypt[..REQUEST_FIRST_READ_LEN]))
                .await
                .map_err(|_| {
                    terminate_detection(&mut io, self.observers.flow, DetectionReason::ReadFailed)
                })?;
        if first_read != REQUEST_FIRST_READ_LEN {
            return Err(terminate_detection(
                &mut io,
                self.observers.flow,
                DetectionReason::ShortRead,
            ));
        }

        let request_salt = TcpSalt::from_bytes(
            decrypt[..TCP_SALT_LEN]
                .try_into()
                .expect("fixed salt region"),
        );
        let mut opener = opener_for(self.keys, &request_salt)
            .map_err(|reason| terminate_detection(&mut io, self.observers.flow, reason))?;
        let fixed_wire: [u8; REQUEST_FIXED_PLAINTEXT_LEN + TAG_LEN] = decrypt
            [TCP_SALT_LEN..REQUEST_FIRST_READ_LEN]
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

        reset_decrypt(&mut decrypt);
        let mut filled = 0;
        while filled < wire_len {
            let read =
                poll_fn(|cx| Pin::new(&mut io).poll_read(cx, &mut decrypt[filled..wire_len]))
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
        }
        decrypt.truncate(wire_len);
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
        reset_decrypt(&mut decrypt);
        inspect_scratch(BufferRole::Encrypt, &encrypt, self.observers.buffer);
        inspect_scratch(BufferRole::Decrypt, &decrypt, self.observers.buffer);
        Ok(Session {
            target: parsed.target,
            stream: ServerFlow {
                io,
                keys: self.keys,
                clock: self.clock,
                random: self.random,
                request_salt,
                request_opener: opener,
                response_sealer: None,
                rx: DataRx::Length { filled: 0 },
                tx: TxState::ResponsePending,
                encrypt,
                decrypt,
                staged: None,
                lifecycle: Lifecycle::default(),
                observers: self.observers,
            },
            initial_payload,
            reply: NoReply,
        })
    }
}

impl<'a, K, T, R, S> Inbound<S> for ShadowsocksTcpInbound<'a, K, T, R>
where
    K: KeyProvider + Sync,
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

#[derive(Default)]
struct Lifecycle {
    terminal: Option<FlowTerminal>,
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

enum ClientRx {
    ResponseFixed,
    ResponsePayload { wire_len: usize, filled: usize },
    Data(DataRx),
    Poison,
}

enum DataRx {
    Length { filled: usize },
    Payload { wire_len: usize, filled: usize },
    Ready { position: usize },
    Closed,
    Poison,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TxState {
    ResponsePending,
    Open,
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StagedKind {
    First,
    Subsequent,
}

struct StagedWrite {
    kind: StagedKind,
    position: usize,
}

/// Opaque client flow retaining unsplit transport and both cipher directions.
pub struct ClientFlow<'a, S, K, T> {
    io: S,
    keys: &'a K,
    clock: &'a T,
    request_salt: TcpSalt,
    request_sealer: TcpSealer,
    response_opener: Option<TcpOpener>,
    rx: ClientRx,
    tx: TxState,
    encrypt: BytesMut,
    decrypt: BytesMut,
    staged: Option<StagedWrite>,
    lifecycle: Lifecycle,
    observers: Observers<'a>,
}

impl<S: LocalEndpoint, K, T> LocalEndpoint for ClientFlow<'_, S, K, T> {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.io.local_endpoint()
    }
}

/// Opaque server flow retaining unsplit transport and both cipher directions.
pub struct ServerFlow<'a, S, K, T, R> {
    io: S,
    keys: &'a K,
    clock: &'a T,
    random: &'a R,
    request_salt: TcpSalt,
    request_opener: TcpOpener,
    response_sealer: Option<TcpSealer>,
    rx: DataRx,
    tx: TxState,
    encrypt: BytesMut,
    decrypt: BytesMut,
    staged: Option<StagedWrite>,
    lifecycle: Lifecycle,
    observers: Observers<'a>,
}

fn reset_decrypt(scratch: &mut BytesMut) {
    scratch.clear();
    scratch.resize(MAX_DECRYPT_WIRE_LEN, 0);
}

fn copy_ready(scratch: &BytesMut, position: &mut usize, destination: &mut [u8]) -> (usize, bool) {
    let remaining = scratch.len().saturating_sub(*position);
    let copied = remaining.min(destination.len());
    destination[..copied].copy_from_slice(&scratch[*position..*position + copied]);
    *position += copied;
    (copied, *position == scratch.len())
}

fn protocol_cipher_boundary(
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    operation: impl FnOnce() -> Result<(), FrameError>,
) -> Result<(), ShadowsocksError> {
    if let Some(error) = lifecycle.fatal_error() {
        return Err(error);
    }
    operation().map_err(|error| lifecycle.install_protocol(observer, protocol_from_frame(error)))
}

impl<'a, S, K, T> ClientFlow<'a, S, K, T>
where
    S: TransportIo,
    K: KeyProvider + Sync,
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
            ClientRx::ResponseFixed => {
                reset_decrypt(&mut self.decrypt);
                match Pin::new(&mut self.io)
                    .poll_read(cx, &mut self.decrypt[..RESPONSE_FIRST_READ_LEN])
                {
                    Poll::Pending => {
                        self.rx = ClientRx::ResponseFixed;
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
                    Poll::Ready(Ok(read)) if read != RESPONSE_FIRST_READ_LEN => {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            DetectionReason::ShortRead,
                        );
                        Poll::Ready(Err(error))
                    }
                    Poll::Ready(Ok(_)) => {
                        let result = self.open_response_fixed();
                        match result {
                            Ok(wire_len) => {
                                reset_decrypt(&mut self.decrypt);
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
                    self.decrypt.truncate(wire_len);
                    let opened = self
                        .response_opener
                        .as_mut()
                        .expect("fixed response installed opener")
                        .open_in_place(&mut self.decrypt);
                    if let Err(error) = opened {
                        let error = self.lifecycle.install_detection(
                            &mut self.io,
                            self.observers.flow,
                            detection_from_aead(error),
                        );
                        return Poll::Ready(Err(error));
                    }
                    let mut position = 0;
                    let (copied, complete) = copy_ready(&self.decrypt, &mut position, destination);
                    self.rx = if complete {
                        reset_decrypt(&mut self.decrypt);
                        ClientRx::Data(DataRx::Length { filled: 0 })
                    } else {
                        ClientRx::Data(DataRx::Ready { position })
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
        let response_salt =
            TcpSalt::from_bytes(self.decrypt[..TCP_SALT_LEN].try_into().expect("fixed salt"));
        if response_salt == self.request_salt {
            return Err(DetectionReason::ResponseBinding);
        }
        let mut opener = opener_for(self.keys, &response_salt)?;
        let fixed_wire: [u8; RESPONSE_FIXED_PLAINTEXT_LEN + TAG_LEN] = self.decrypt
            [TCP_SALT_LEN..RESPONSE_FIRST_READ_LEN]
            .try_into()
            .expect("fixed encrypted response width");
        self.decrypt.clear();
        self.decrypt.extend_from_slice(&fixed_wire);
        opener
            .open_in_place(&mut self.decrypt)
            .map_err(detection_from_aead)?;
        if self.decrypt.len() != RESPONSE_FIXED_PLAINTEXT_LEN {
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
        if self.decrypt[9..25] != *self.request_salt.as_bytes() {
            return Err(DetectionReason::ResponseBinding);
        }
        let payload_len = usize::from(u16::from_be_bytes(
            self.decrypt[25..27].try_into().expect("length"),
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
    K: KeyProvider + Sync,
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

    fn terminal(&self) -> Option<FlowTerminal> {
        self.lifecycle.terminal
    }
}

impl<'a, S, K, T, R> ServerFlow<'a, S, K, T, R>
where
    S: TransportIo,
    K: KeyProvider + Sync,
    T: Clock + Sync,
    R: SecureRandom,
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
        let state = std::mem::replace(&mut self.rx, DataRx::Poison);
        match poll_data_read(
            &mut self.io,
            &mut self.request_opener,
            &mut self.decrypt,
            state,
            &mut self.lifecycle,
            self.observers.flow,
            cx,
            destination,
        ) {
            DataPoll::Pending(state) => {
                self.rx = state;
                Poll::Pending
            }
            DataPoll::Ready(state, result) => {
                self.rx = state;
                Poll::Ready(result)
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
            let response_salt = match generate_response_salt(self.random, &self.request_salt) {
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
    K: KeyProvider + Sync,
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

enum DataPoll {
    Pending(DataRx),
    Ready(DataRx, Result<usize, ShadowsocksError>),
}

#[allow(clippy::too_many_arguments)]
fn poll_data_read<S: TransportIo>(
    io: &mut S,
    opener: &mut TcpOpener,
    scratch: &mut BytesMut,
    state: DataRx,
    lifecycle: &mut Lifecycle,
    observer: &dyn FlowObserver,
    cx: &mut Context<'_>,
    destination: &mut [u8],
) -> DataPoll {
    match state {
        DataRx::Length { mut filled } => {
            if filled == 0 {
                reset_decrypt(scratch);
            }
            match Pin::new(io).poll_read(cx, &mut scratch[filled..ENCRYPTED_LENGTH_LEN]) {
                Poll::Pending => DataPoll::Pending(DataRx::Length { filled }),
                Poll::Ready(Err(_)) => {
                    let error = lifecycle.install_transport(observer, TransportPhase::Read);
                    DataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(0)) if filled == 0 => {
                    lifecycle.close_rx(observer);
                    DataPoll::Ready(DataRx::Closed, Ok(0))
                }
                Poll::Ready(Ok(0)) => {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    DataPoll::Ready(DataRx::Poison, Err(error))
                }
                Poll::Ready(Ok(read)) => {
                    filled += read;
                    if filled > ENCRYPTED_LENGTH_LEN {
                        let error =
                            lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                        return DataPoll::Ready(DataRx::Poison, Err(error));
                    }
                    if filled < ENCRYPTED_LENGTH_LEN {
                        cx.waker().wake_by_ref();
                        return DataPoll::Pending(DataRx::Length { filled });
                    }
                    scratch.truncate(ENCRYPTED_LENGTH_LEN);
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
                    reset_decrypt(scratch);
                    cx.waker().wake_by_ref();
                    DataPoll::Pending(DataRx::Payload {
                        wire_len,
                        filled: 0,
                    })
                }
            }
        }
        DataRx::Payload {
            wire_len,
            mut filled,
        } => match Pin::new(io).poll_read(cx, &mut scratch[filled..wire_len]) {
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
                if filled > wire_len {
                    let error = lifecycle.install_protocol(observer, ProtocolReason::FrameBounds);
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if filled < wire_len {
                    cx.waker().wake_by_ref();
                    return DataPoll::Pending(DataRx::Payload { wire_len, filled });
                }
                scratch.truncate(wire_len);
                if let Err(error) = protocol_cipher_boundary(lifecycle, observer, || {
                    opener.open_in_place(scratch).map_err(frame_from_open_aead)
                }) {
                    return DataPoll::Ready(DataRx::Poison, Err(error));
                }
                if scratch.is_empty() {
                    reset_decrypt(scratch);
                    cx.waker().wake_by_ref();
                    return DataPoll::Pending(DataRx::Length { filled: 0 });
                }
                let mut position = 0;
                let (copied, complete) = copy_ready(scratch, &mut position, destination);
                let next = if complete {
                    reset_decrypt(scratch);
                    DataRx::Length { filled: 0 }
                } else {
                    DataRx::Ready { position }
                };
                DataPoll::Ready(next, Ok(copied))
            }
        },
        DataRx::Ready { mut position } => {
            let (copied, complete) = copy_ready(scratch, &mut position, destination);
            let next = if complete {
                reset_decrypt(scratch);
                DataRx::Length { filled: 0 }
            } else {
                DataRx::Ready { position }
            };
            DataPoll::Ready(next, Ok(copied))
        }
        DataRx::Closed => DataPoll::Ready(DataRx::Closed, Ok(0)),
        DataRx::Poison => {
            let error = lifecycle
                .fatal_error()
                .expect("poison state only exists after fatal installation");
            DataPoll::Ready(DataRx::Poison, Err(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn poll_write_open<S: TransportIo>(
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

fn drain_staged<S: TransportIo>(
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
fn poll_flush<S: TransportIo>(
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
fn poll_shutdown<S: TransportIo>(
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

struct ParsedRequest {
    target: TargetAddr,
    initial_payload: Bytes,
}

fn parse_request_variable(variable: &[u8]) -> Result<ParsedRequest, DetectionReason> {
    const ADDRESS_AND_PADDING_LEN: usize = 9;
    if variable.len() < ADDRESS_AND_PADDING_LEN || variable[0] != IPV4_ATYP {
        return Err(DetectionReason::AddressBounds);
    }
    let address = Ipv4Addr::new(variable[1], variable[2], variable[3], variable[4]);
    let port = u16::from_be_bytes([variable[5], variable[6]]);
    let target = TargetAddr::ipv4(SocketAddrV4::new(address, port))
        .map_err(|_| DetectionReason::AddressBounds)?;
    let padding_len = usize::from(u16::from_be_bytes([variable[7], variable[8]]));
    if padding_len > MAX_PADDING_LEN {
        return Err(DetectionReason::PaddingBounds);
    }
    let payload_start = ADDRESS_AND_PADDING_LEN
        .checked_add(padding_len)
        .ok_or(DetectionReason::FrameBounds)?;
    if payload_start > variable.len() {
        return Err(DetectionReason::PaddingBounds);
    }
    let initial_payload = &variable[payload_start..];
    if padding_len == 0 && initial_payload.is_empty() {
        return Err(DetectionReason::EmptyRequest);
    }
    Ok(ParsedRequest {
        target,
        initial_payload: Bytes::copy_from_slice(initial_payload),
    })
}

/// Builds a deterministic contiguous request first-write for reviewed fixtures.
pub fn encode_request_first_write<K: KeyProvider>(
    keys: &K,
    salt: &TcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(REQUEST_FIRST_READ_LEN + MAX_DECRYPT_WIRE_LEN);
    let _ = encode_request_state_into(
        keys,
        salt,
        timestamp,
        target,
        padding,
        initial_payload,
        &mut scratch,
    )?;
    Ok(scratch.freeze())
}

fn encode_request_state_into<K: KeyProvider>(
    keys: &K,
    salt: &TcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    if padding.len() > MAX_PADDING_LEN {
        return Err(FrameError::PaddingBounds);
    }
    if padding.is_empty() && initial_payload.is_empty() {
        return Err(FrameError::EmptyRequest);
    }
    let socket = target
        .as_socket_addr()
        .ok_or(FrameError::AddressUnsupported)?;
    let IpAddr::V4(address) = socket.ip() else {
        return Err(FrameError::AddressUnsupported);
    };
    let variable_len = 9_usize
        .checked_add(padding.len())
        .and_then(|length| length.checked_add(initial_payload.len()))
        .ok_or(FrameError::Bounds)?;
    let variable_u16 = u16::try_from(variable_len).map_err(|_| FrameError::Bounds)?;

    scratch.clear();
    scratch.extend_from_slice(&[REQUEST_TYPE]);
    scratch.extend_from_slice(&timestamp.to_be_bytes());
    scratch.extend_from_slice(&variable_u16.to_be_bytes());
    let mut sealer = sealer_for(keys, salt)?;
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let fixed: [u8; REQUEST_FIXED_PLAINTEXT_LEN + TAG_LEN] = scratch[..]
        .try_into()
        .expect("fixed encrypted request width");

    scratch.clear();
    scratch.extend_from_slice(&[IPV4_ATYP]);
    scratch.extend_from_slice(&address.octets());
    scratch.extend_from_slice(&target.port().get().to_be_bytes());
    scratch.extend_from_slice(
        &u16::try_from(padding.len())
            .map_err(|_| FrameError::PaddingBounds)?
            .to_be_bytes(),
    );
    scratch.extend_from_slice(padding);
    scratch.extend_from_slice(initial_payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let variable_wire_len = scratch.len();
    let total = REQUEST_FIRST_READ_LEN
        .checked_add(variable_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..variable_wire_len, REQUEST_FIRST_READ_LEN);
    scratch[..TCP_SALT_LEN].copy_from_slice(salt.as_bytes());
    scratch[TCP_SALT_LEN..REQUEST_FIRST_READ_LEN].copy_from_slice(&fixed);
    Ok(sealer)
}

/// Builds a deterministic contiguous response first-write for reviewed fixtures.
pub fn encode_response_first_write<K: KeyProvider>(
    keys: &K,
    response_salt: &TcpSalt,
    timestamp: u64,
    request_salt: &TcpSalt,
    first_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(MAX_ENCRYPT_WIRE_LEN);
    let _ = encode_response_state_into(
        keys,
        response_salt,
        timestamp,
        request_salt,
        first_payload,
        &mut scratch,
    )?;
    Ok(scratch.freeze())
}

fn encode_response_state_into<K: KeyProvider>(
    keys: &K,
    response_salt: &TcpSalt,
    timestamp: u64,
    request_salt: &TcpSalt,
    first_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    if first_payload.is_empty() {
        return Err(FrameError::EmptyResponse);
    }
    if first_payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    if response_salt == request_salt {
        return Err(FrameError::ResponseSaltReuse);
    }
    let payload_len = u16::try_from(first_payload.len()).map_err(|_| FrameError::Bounds)?;

    scratch.clear();
    scratch.extend_from_slice(&[RESPONSE_TYPE]);
    scratch.extend_from_slice(&timestamp.to_be_bytes());
    scratch.extend_from_slice(request_salt.as_bytes());
    scratch.extend_from_slice(&payload_len.to_be_bytes());
    let mut sealer = sealer_for(keys, response_salt)?;
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let fixed: [u8; RESPONSE_FIXED_PLAINTEXT_LEN + TAG_LEN] = scratch[..]
        .try_into()
        .expect("fixed encrypted response width");

    scratch.clear();
    scratch.extend_from_slice(first_payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let payload_wire_len = scratch.len();
    let total = RESPONSE_FIRST_READ_LEN
        .checked_add(payload_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..payload_wire_len, RESPONSE_FIRST_READ_LEN);
    scratch[..TCP_SALT_LEN].copy_from_slice(response_salt.as_bytes());
    scratch[TCP_SALT_LEN..RESPONSE_FIRST_READ_LEN].copy_from_slice(&fixed);
    Ok(sealer)
}

fn seal_data_chunk_into(
    sealer: &mut TcpSealer,
    payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| FrameError::Bounds)?;
    scratch.clear();
    scratch.extend_from_slice(&payload_len.to_be_bytes());
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let length: [u8; ENCRYPTED_LENGTH_LEN] =
        scratch[..].try_into().expect("encrypted length width");

    scratch.clear();
    scratch.extend_from_slice(payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let payload_wire_len = scratch.len();
    let total = ENCRYPTED_LENGTH_LEN
        .checked_add(payload_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..payload_wire_len, ENCRYPTED_LENGTH_LEN);
    scratch[..ENCRYPTED_LENGTH_LEN].copy_from_slice(&length);
    Ok(())
}

/// Authenticates one complete subsequent frame for deterministic codec tests.
pub fn open_data_frame(
    opener: &mut TcpOpener,
    encrypted_length: &[u8],
    encrypted_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(MAX_DECRYPT_WIRE_LEN);
    open_data_frame_into(opener, encrypted_length, encrypted_payload, &mut scratch)?;
    Ok(scratch.freeze())
}

fn open_data_frame_into(
    opener: &mut TcpOpener,
    encrypted_length: &[u8],
    encrypted_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if encrypted_length.len() != ENCRYPTED_LENGTH_LEN
        || encrypted_payload.len() > MAX_DECRYPT_WIRE_LEN
    {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.extend_from_slice(encrypted_length);
    opener
        .open_in_place(scratch)
        .map_err(frame_from_open_aead)?;
    if scratch.len() != 2 {
        return Err(FrameError::Bounds);
    }
    let payload_len = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
    if encrypted_payload.len() != payload_len.checked_add(TAG_LEN).ok_or(FrameError::Bounds)? {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.extend_from_slice(encrypted_payload);
    opener
        .open_in_place(scratch)
        .map_err(frame_from_open_aead)?;
    if scratch.len() != payload_len {
        return Err(FrameError::Bounds);
    }
    Ok(())
}

fn sealer_for<K: KeyProvider>(keys: &K, salt: &TcpSalt) -> Result<TcpSealer, FrameError> {
    keys.with_key(KeySelector::Default, |key| {
        TcpSealer::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt))
    })
    .map_err(|_| FrameError::KeyUnavailable)
}

fn opener_for<K: KeyProvider>(keys: &K, salt: &TcpSalt) -> Result<TcpOpener, DetectionReason> {
    keys.with_key(KeySelector::Default, |key| {
        TcpOpener::new(key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt))
    })
    .map_err(|_| DetectionReason::KeyUnavailable)
}

fn terminate_detection<S: AbortiveClose>(
    io: &mut S,
    observer: &dyn FlowObserver,
    reason: DetectionReason,
) -> ShadowsocksError {
    observer.terminal_installed(FlowTerminal::Detection(reason));
    let _ = io.mark_abortive();
    ShadowsocksError::Detection(reason)
}

fn detection_from_aead(error: AeadError) -> DetectionReason {
    match error {
        AeadError::NonceExhausted => DetectionReason::FrameBounds,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => {
            DetectionReason::Authentication
        }
    }
}

fn frame_from_seal_aead(error: AeadError) -> FrameError {
    match error {
        AeadError::NonceExhausted => FrameError::NonceExhausted,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => FrameError::Cipher,
    }
}

fn frame_from_open_aead(error: AeadError) -> FrameError {
    match error {
        AeadError::NonceExhausted => FrameError::NonceExhausted,
        AeadError::AuthenticationFailed | AeadError::OperationFailed => FrameError::Cipher,
    }
}

fn detection_from_frame(error: FrameError) -> DetectionReason {
    match error {
        FrameError::KeyUnavailable => DetectionReason::KeyUnavailable,
        FrameError::Cipher => DetectionReason::Authentication,
        FrameError::NonceExhausted | FrameError::Bounds | FrameError::EmptyResponse => {
            DetectionReason::FrameBounds
        }
        FrameError::AddressUnsupported => DetectionReason::AddressBounds,
        FrameError::PaddingBounds => DetectionReason::PaddingBounds,
        FrameError::EmptyRequest => DetectionReason::EmptyRequest,
        FrameError::ResponseSaltReuse => DetectionReason::ResponseBinding,
    }
}

fn protocol_from_frame(error: FrameError) -> ProtocolReason {
    match error {
        FrameError::NonceExhausted => ProtocolReason::NonceExhausted,
        FrameError::Cipher => ProtocolReason::Authentication,
        FrameError::KeyUnavailable
        | FrameError::Bounds
        | FrameError::AddressUnsupported
        | FrameError::PaddingBounds
        | FrameError::EmptyRequest
        | FrameError::EmptyResponse
        | FrameError::ResponseSaltReuse => ProtocolReason::FrameBounds,
    }
}

#[cfg(test)]
struct OneShotCipherFault {
    armed: bool,
    calls: usize,
}

#[cfg(test)]
impl Default for OneShotCipherFault {
    fn default() -> Self {
        Self {
            armed: true,
            calls: 0,
        }
    }
}

#[cfg(test)]
impl OneShotCipherFault {
    fn seal(&mut self) -> Result<(), AeadError> {
        self.fail()
    }

    fn open(&mut self) -> Result<(), AeadError> {
        self.fail()
    }

    fn fail(&mut self) -> Result<(), AeadError> {
        self.calls += 1;
        if std::mem::take(&mut self.armed) {
            Err(AeadError::NonceExhausted)
        } else {
            Ok(())
        }
    }

    const fn calls(&self) -> usize {
        self.calls
    }
}

fn sample_nonzero_padding(
    random: &(impl SecureRandom + ?Sized),
    padding: &mut [u8; MAX_PADDING_LEN],
) -> Result<usize, FrameError> {
    const SAMPLE_RANGE: u32 = (u16::MAX as u32) + 1;
    const ACCEPTED_RANGE: u32 = (SAMPLE_RANGE / MAX_PADDING_LEN as u32) * MAX_PADDING_LEN as u32;
    let mut sample = [0_u8; 2];
    let length = loop {
        random.fill(&mut sample).map_err(|_| FrameError::Bounds)?;
        let value = u32::from(u16::from_be_bytes(sample));
        if value < ACCEPTED_RANGE {
            break (value % MAX_PADDING_LEN as u32) as usize + 1;
        }
    };
    random
        .fill(&mut padding[..length])
        .map_err(|_| FrameError::Bounds)?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ferrum2_crypto::{Aes128Psk, SinglePskProvider};

    use super::*;

    #[derive(Default)]
    struct CountingFlowObserver {
        terminals: AtomicUsize,
        abortive: AtomicUsize,
    }

    impl FlowObserver for CountingFlowObserver {
        fn terminal_installed(&self, _terminal: FlowTerminal) {
            self.terminals.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl AbortiveClose for CountingFlowObserver {
        type Error = ();

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.abortive.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct SequenceFlowObserver(Arc<Mutex<Vec<&'static str>>>);

    impl FlowObserver for SequenceFlowObserver {
        fn terminal_installed(&self, _terminal: FlowTerminal) {
            self.0.lock().expect("sequence").push("terminal");
        }
    }

    struct FailingAbortive {
        calls: usize,
        sequence: Arc<Mutex<Vec<&'static str>>>,
    }

    impl AbortiveClose for FailingAbortive {
        type Error = ();

        fn mark_abortive(&mut self) -> Result<(), Self::Error> {
            self.calls += 1;
            self.sequence.lock().expect("sequence").push("abortive");
            Err(())
        }
    }

    fn provider() -> SinglePskProvider {
        SinglePskProvider::new(Aes128Psk::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]))
    }

    fn salt(last: u8) -> TcpSalt {
        let mut bytes = [0_u8; TCP_SALT_LEN];
        bytes[TCP_SALT_LEN - 1] = last;
        TcpSalt::from_bytes(bytes)
    }

    fn assert_scratch_unchanged(scratch: &BytesMut, identity: usize, capacity: usize) {
        assert_eq!(scratch.as_ptr() as usize, identity);
        assert_eq!(scratch.capacity(), capacity);
    }

    fn encrypted_frame(sealer: &mut TcpSealer, payload: &[u8]) -> (BytesMut, BytesMut) {
        let mut length = BytesMut::from(
            &u16::try_from(payload.len())
                .expect("test payload fits")
                .to_be_bytes()[..],
        );
        let mut payload = BytesMut::from(payload);
        sealer.seal_in_place(&mut length).expect("seal length");
        sealer.seal_in_place(&mut payload).expect("seal payload");
        (length, payload)
    }

    #[test]
    fn client_seal_nonce_flow_internal_contract() {
        let observer = CountingFlowObserver::default();
        let mut lifecycle = Lifecycle::default();
        let mut fault = OneShotCipherFault::default();

        let error = protocol_cipher_boundary(&mut lifecycle, &observer, || {
            fault.seal().map_err(frame_from_seal_aead)
        })
        .expect_err("nonce exhaustion");

        assert_eq!(
            error,
            ShadowsocksError::Protocol(ProtocolReason::NonceExhausted)
        );
        assert_eq!(
            lifecycle.terminal,
            Some(FlowTerminal::Protocol(ProtocolReason::NonceExhausted))
        );
        assert_eq!(fault.calls(), 1);
        assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
        assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);

        let repeated = protocol_cipher_boundary(&mut lifecycle, &observer, || {
            fault.seal().map_err(frame_from_seal_aead)
        });
        assert_eq!(repeated, Err(error));
        assert_eq!(fault.calls(), 1, "terminal freezes the one-shot boundary");
        assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
        assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn server_open_nonce_flow_internal_contract() {
        let observer = CountingFlowObserver::default();
        let mut lifecycle = Lifecycle::default();
        let mut fault = OneShotCipherFault::default();

        let error = protocol_cipher_boundary(&mut lifecycle, &observer, || {
            fault.open().map_err(frame_from_open_aead)
        })
        .expect_err("nonce exhaustion");

        assert_eq!(
            error,
            ShadowsocksError::Protocol(ProtocolReason::NonceExhausted)
        );
        assert_eq!(
            lifecycle.terminal,
            Some(FlowTerminal::Protocol(ProtocolReason::NonceExhausted))
        );
        assert_eq!(fault.calls(), 1);
        assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
        assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);

        let repeated = protocol_cipher_boundary(&mut lifecycle, &observer, || {
            fault.open().map_err(frame_from_open_aead)
        });
        assert_eq!(repeated, Err(error));
        assert_eq!(fault.calls(), 1, "terminal freezes the one-shot boundary");
        assert_eq!(observer.terminals.load(Ordering::SeqCst), 1);
        assert_eq!(observer.abortive.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn encrypt_scratch_capacity_flow_internal_contract() {
        let keys = provider();
        let mut sealer = sealer_for(&keys, &salt(1)).expect("sealer");
        let mut scratch = fixed_scratch(BufferRole::Encrypt, MAX_ENCRYPT_WIRE_LEN, &NOOP_OBSERVER);
        let identity = scratch.as_ptr() as usize;
        let capacity = scratch.capacity();

        for payload in [Vec::new(), vec![0x5a; MAX_ENCODE_PAYLOAD_LEN]]
            .into_iter()
            .chain((0_u8..32).map(|value| vec![value]))
        {
            seal_data_chunk_into(&mut sealer, &payload, &mut scratch).expect("seal frame");
            assert_scratch_unchanged(&scratch, identity, capacity);
        }
    }

    #[test]
    fn decrypt_scratch_capacity_flow_internal_contract() {
        let keys = provider();
        let salt = salt(2);
        let mut sealer = sealer_for(&keys, &salt).expect("sealer");
        let mut opener = opener_for(&keys, &salt).expect("opener");
        let mut scratch = fixed_scratch(BufferRole::Decrypt, MAX_DECRYPT_WIRE_LEN, &NOOP_OBSERVER);
        let identity = scratch.as_ptr() as usize;
        let capacity = scratch.capacity();

        for payload in [Vec::new(), vec![0xa5; MAX_PAYLOAD_LEN]]
            .into_iter()
            .chain((0_u8..32).map(|value| vec![value]))
        {
            let (length, encrypted_payload) = encrypted_frame(&mut sealer, &payload);
            open_data_frame_into(&mut opener, &length, &encrypted_payload, &mut scratch)
                .expect("open frame");
            assert_eq!(scratch.as_ref(), payload);
            assert_scratch_unchanged(&scratch, identity, capacity);
        }
    }

    #[test]
    fn replay_unavailable_detection_reason_contract() {
        let replay = TcpReplayStore::new(MIN_REPLAY_CAPACITY).expect("capacity");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = replay.state.lock().expect("replay lock");
            panic!("poison replay state for the private failure-path contract");
        }));
        assert_eq!(
            replay.check_and_insert(&salt(3), MonotonicInstant::from_duration(Duration::ZERO),),
            Err(ReplayInsertError::Unavailable)
        );

        let sequence = Arc::new(Mutex::new(Vec::new()));
        let observer = SequenceFlowObserver(sequence.clone());
        let mut io = FailingAbortive {
            calls: 0,
            sequence: sequence.clone(),
        };
        let error = terminate_detection(&mut io, &observer, DetectionReason::ReplayUnavailable);

        assert_eq!(
            error,
            ShadowsocksError::Detection(DetectionReason::ReplayUnavailable)
        );
        assert_eq!(io.calls, 1);
        assert_eq!(
            *sequence.lock().expect("sequence"),
            vec!["terminal", "abortive"]
        );
    }
}
