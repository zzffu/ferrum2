#![forbid(unsafe_code)]

//! SIP022 TCP framing and security state for the AES-128 M0 vertical slice.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ferrum2_core::{
    AbortiveClose, ConnectErrorKind, Connector, LocalEndpoint, Outbound, TargetAddr,
};
use ferrum2_crypto::{
    Clock, KeyProvider, KeySelector, MonotonicInstant, SecureRandom, TcpMethod, TcpOpener, TcpSalt,
    TcpSealer, generate_request_salt, generate_response_salt,
};
use thiserror::Error;

/// Request salt width for `2022-blake3-aes-128-gcm`.
pub const TCP_SALT_LEN: usize = 16;
/// AES-GCM tag width.
pub const TAG_LEN: usize = 16;
/// Request salt plus the encrypted fixed request header.
pub const REQUEST_FIRST_READ_LEN: usize = 43;
/// Response salt plus the encrypted fixed response header.
pub const RESPONSE_FIRST_READ_LEN: usize = 59;
/// Largest plaintext chunk accepted from a compatible peer.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
/// Largest encrypted peer chunk stored by one decrypt direction.
pub const MAX_DECRYPT_WIRE_LEN: usize = MAX_PAYLOAD_LEN + TAG_LEN;
/// Largest application chunk emitted by ferrum2.
pub const MAX_ENCODE_PAYLOAD_LEN: usize = 16_384;
/// Largest SIP022 request padding accepted by M0.
pub const MAX_PADDING_LEN: usize = 900;

const REQUEST_TYPE: u8 = 0;
const RESPONSE_TYPE: u8 = 1;
const IPV4_ATYP: u8 = 1;
const REQUEST_FIXED_PLAINTEXT_LEN: usize = 11;
const RESPONSE_FIXED_PLAINTEXT_LEN: usize = 27;
const REPLAY_RETENTION: Duration = Duration::from_secs(60);
const DEFAULT_REPLAY_CAPACITY: usize = 65_536;
const MIN_REPLAY_CAPACITY: usize = 1_024;
const MAX_REPLAY_CAPACITY: usize = 1_048_576;

/// A closed frame-construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FrameError {
    /// The configured key could not be selected.
    #[error("key unavailable")]
    KeyUnavailable,
    /// The cryptographic operation failed without exposing its source.
    #[error("cipher operation failed")]
    Cipher,
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

/// The closed reason for an approved SIP022 detection-prevention failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionReason {
    /// An initial header read returned fewer bytes than requested.
    ShortRead,
    /// An initial header write returned fewer bytes than supplied.
    ShortWrite,
    /// An authenticated chunk failed verification.
    Authentication,
    /// The authenticated message type was not valid for this direction.
    InvalidType,
    /// The authenticated wall timestamp exceeded the inclusive 30-second window.
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

/// Closed SIP022 transport failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ShadowsocksError {
    /// A detection-prevention failure terminated the transport.
    #[error("SIP022 detection failure")]
    Detection(DetectionReason),
    /// A protocol-neutral connector failed before an initial protocol write.
    #[error("connection failed")]
    Connect(ConnectErrorKind),
    /// The target closed before producing a first nonempty response payload.
    #[error("response payload unavailable")]
    ResponseUnavailable,
}

/// The single-operation transport seam for SIP022 initial headers and chunks.
pub trait HeaderIo: Send {
    /// Closed transport error type. It is never retained or displayed.
    type Error;

    /// Performs exactly one underlying read into `destination`.
    fn read_header<'a>(
        &'a mut self,
        destination: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;

    /// Performs exactly one underlying write from `source`.
    fn write_header<'a>(
        &'a mut self,
        source: &'a [u8],
    ) -> impl Future<Output = Result<usize, Self::Error>> + Send;
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
        let expired = now
            .duration_since(inserted)
            .is_some_and(|elapsed| elapsed >= REPLAY_RETENTION);
        if !expired {
            break;
        }
        let expired_salt = state
            .insertion_order
            .pop_front()
            .expect("front was observed");
        state.entries.remove(&expired_salt);
    }
}

/// A client-side SIP022 outbound whose dependencies are explicit capabilities.
pub struct ClientTcpOutbound<'a, K, C, T, R> {
    keys: &'a K,
    connector: &'a C,
    clock: &'a T,
    random: &'a R,
}

impl<'a, K, C, T, R> ClientTcpOutbound<'a, K, C, T, R> {
    /// Creates a client-side outbound.
    pub const fn new(keys: &'a K, connector: &'a C, clock: &'a T, random: &'a R) -> Self {
        Self {
            keys,
            connector,
            clock,
            random,
        }
    }
}

impl<K, C, T, R> ClientTcpOutbound<'_, K, C, T, R>
where
    K: KeyProvider,
    C: Connector,
    C::Stream: AbortiveClose + HeaderIo,
    T: Clock,
    R: SecureRandom,
{
    /// Connects first, then produces one contiguous request first-write.
    pub async fn open_stream(
        &self,
        target: &TargetAddr,
    ) -> Result<OpenedClientStream<C::Stream>, ShadowsocksError> {
        let mut io = self
            .connector
            .connect(target)
            .await
            .map_err(|error| ShadowsocksError::Connect(error.kind()))?;

        let salt = match generate_request_salt(self.random) {
            Ok(salt) => salt,
            Err(_) => return Err(terminate_detection(io, DetectionReason::RandomUnavailable)),
        };
        let timestamp = match self.clock.unix_seconds() {
            Ok(timestamp) => timestamp,
            Err(_) => return Err(terminate_detection(io, DetectionReason::ClockUnavailable)),
        };
        let padding = match sample_nonzero_padding(self.random) {
            Ok(padding) => padding,
            Err(_) => return Err(terminate_detection(io, DetectionReason::RandomUnavailable)),
        };
        let (wire, request_sealer) =
            match encode_request_state(self.keys, &salt, timestamp, target, &padding, &[]) {
                Ok(state) => state,
                Err(error) => return Err(terminate_detection(io, detection_from_frame(error))),
            };

        let written = match io.write_header(&wire).await {
            Ok(written) => written,
            Err(_) => return Err(terminate_detection(io, DetectionReason::WriteFailed)),
        };
        if written != wire.len() {
            return Err(terminate_detection(io, DetectionReason::ShortWrite));
        }
        Ok(OpenedClientStream {
            io,
            request_salt: salt,
            request_sealer,
        })
    }
}

impl<K, C, T, R> Outbound for ClientTcpOutbound<'_, K, C, T, R>
where
    K: KeyProvider,
    C: Connector,
    C::Stream: AbortiveClose + HeaderIo + Send,
    T: Clock + Sync,
    R: SecureRandom,
{
    type Stream = OpenedClientStream<C::Stream>;
    type Error = ShadowsocksError;

    async fn open(&self, target: &TargetAddr) -> Result<Self::Stream, Self::Error> {
        self.open_stream(target).await
    }
}

/// A client stream after its request first-write succeeded.
pub struct OpenedClientStream<S> {
    io: S,
    request_salt: TcpSalt,
    request_sealer: TcpSealer,
}

impl<S: LocalEndpoint> LocalEndpoint for OpenedClientStream<S> {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.io.local_endpoint()
    }
}

impl<S> OpenedClientStream<S> {
    /// Returns the redacted typed request salt used for response binding.
    pub const fn request_salt(&self) -> &TcpSalt {
        &self.request_salt
    }

    /// Encodes one client-to-server data frame after the initial request.
    pub fn seal_request_chunk(&mut self, payload: &[u8]) -> Result<Bytes, FrameError> {
        seal_data_chunk(&mut self.request_sealer, payload)
    }

    /// Returns the underlying connector-owned transport.
    pub fn into_inner(self) -> S {
        self.io
    }
}

/// A fully authenticated server-side request.
pub struct AcceptedServerStream<S> {
    io: S,
    target: TargetAddr,
    initial_payload: Bytes,
    request_salt: TcpSalt,
    request_opener: TcpOpener,
}

impl<S> AcceptedServerStream<S> {
    /// Returns the authenticated target.
    pub const fn target(&self) -> &TargetAddr {
        &self.target
    }

    /// Returns authenticated initial payload bytes.
    pub const fn initial_payload(&self) -> &Bytes {
        &self.initial_payload
    }

    /// Returns the typed request salt used for response binding.
    pub const fn request_salt(&self) -> &TcpSalt {
        &self.request_salt
    }

    /// Connects only after authentication, semantics, and replay insertion.
    pub async fn connect_target<C: Connector>(
        self,
        connector: &C,
    ) -> Result<ConnectedServerStream<S, C::Stream>, ShadowsocksError> {
        let target_stream = connector
            .connect(&self.target)
            .await
            .map_err(|error| ShadowsocksError::Connect(error.kind()))?;
        Ok(ConnectedServerStream {
            io: self.io,
            target_stream,
            request_salt: self.request_salt,
            request_opener: self.request_opener,
        })
    }
}

/// Server-side request state after the target connector succeeded.
pub struct ConnectedServerStream<S, D> {
    io: S,
    target_stream: D,
    request_salt: TcpSalt,
    request_opener: TcpOpener,
}

impl<S, D> ConnectedServerStream<S, D> {
    /// Borrows the connector-owned target stream.
    pub const fn target_stream(&self) -> &D {
        &self.target_stream
    }

    /// Mutably borrows the connector-owned target stream.
    pub fn target_stream_mut(&mut self) -> &mut D {
        &mut self.target_stream
    }

    /// Authenticates one client-to-server data frame.
    pub fn open_request_chunk(
        &mut self,
        encrypted_length: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<Bytes, FrameError> {
        open_data_frame(
            &mut self.request_opener,
            encrypted_length,
            encrypted_payload,
        )
    }
}

impl<S, D> ConnectedServerStream<S, D>
where
    S: AbortiveClose + HeaderIo,
{
    /// Writes the first nonempty server response in one underlying operation.
    pub async fn write_first_response<K, T, R>(
        self,
        keys: &K,
        clock: &T,
        random: &R,
        first_payload: &[u8],
    ) -> Result<ServerDataStream<S, D>, ShadowsocksError>
    where
        K: KeyProvider,
        T: Clock,
        R: SecureRandom + ?Sized,
    {
        let Self {
            mut io,
            target_stream,
            request_salt,
            request_opener,
        } = self;
        if first_payload.is_empty() {
            return Err(ShadowsocksError::ResponseUnavailable);
        }
        let response_salt = match generate_response_salt(random, &request_salt) {
            Ok(salt) => salt,
            Err(_) => return Err(terminate_detection(io, DetectionReason::RandomUnavailable)),
        };
        let timestamp = match clock.unix_seconds() {
            Ok(timestamp) => timestamp,
            Err(_) => return Err(terminate_detection(io, DetectionReason::ClockUnavailable)),
        };
        let (wire, response_sealer) = match encode_response_state(
            keys,
            &response_salt,
            timestamp,
            &request_salt,
            first_payload,
        ) {
            Ok(state) => state,
            Err(error) => return Err(terminate_detection(io, detection_from_frame(error))),
        };
        let written = match io.write_header(&wire).await {
            Ok(written) => written,
            Err(_) => return Err(terminate_detection(io, DetectionReason::WriteFailed)),
        };
        if written != wire.len() {
            return Err(terminate_detection(io, DetectionReason::ShortWrite));
        }
        Ok(ServerDataStream {
            io,
            target_stream,
            request_opener,
            response_sealer,
        })
    }
}

/// Server-side framed stream after its response first-write.
pub struct ServerDataStream<S, D> {
    io: S,
    target_stream: D,
    request_opener: TcpOpener,
    response_sealer: TcpSealer,
}

impl<S: LocalEndpoint, D> LocalEndpoint for ServerDataStream<S, D> {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.io.local_endpoint()
    }
}

impl<S, D> ServerDataStream<S, D> {
    /// Encodes one server-to-client data frame.
    pub fn seal_response_chunk(&mut self, payload: &[u8]) -> Result<Bytes, FrameError> {
        seal_data_chunk(&mut self.response_sealer, payload)
    }

    /// Returns the underlying streams and authenticated request opener.
    pub fn into_parts(self) -> (S, D, TcpOpener) {
        (self.io, self.target_stream, self.request_opener)
    }
}

/// Authenticates a server request, validates all semantics, and only then
/// mutates exact replay state.
pub async fn accept_server_request<S, K, T>(
    mut io: S,
    keys: &K,
    clock: &T,
    replay: &TcpReplayStore,
) -> Result<AcceptedServerStream<S>, ShadowsocksError>
where
    S: AbortiveClose + HeaderIo,
    K: KeyProvider,
    T: Clock,
{
    let mut first_read = [0_u8; REQUEST_FIRST_READ_LEN];
    let read = match io.read_header(&mut first_read).await {
        Ok(read) => read,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ReadFailed)),
    };
    if read != REQUEST_FIRST_READ_LEN {
        return Err(terminate_detection(io, DetectionReason::ShortRead));
    }

    let salt_bytes: [u8; TCP_SALT_LEN] = first_read[..TCP_SALT_LEN]
        .try_into()
        .expect("fixed salt region");
    let request_salt = TcpSalt::from_bytes(salt_bytes);
    let mut opener = match opener_for(keys, &request_salt) {
        Ok(opener) => opener,
        Err(reason) => return Err(terminate_detection(io, reason)),
    };
    let mut fixed = BytesMut::with_capacity(REQUEST_FIXED_PLAINTEXT_LEN + TAG_LEN);
    fixed.extend_from_slice(&first_read[TCP_SALT_LEN..]);
    if opener.open_in_place(&mut fixed).is_err() {
        return Err(terminate_detection(io, DetectionReason::Authentication));
    }
    if fixed.len() != REQUEST_FIXED_PLAINTEXT_LEN {
        return Err(terminate_detection(io, DetectionReason::FrameBounds));
    }
    if fixed[0] != REQUEST_TYPE {
        return Err(terminate_detection(io, DetectionReason::InvalidType));
    }
    let timestamp = u64::from_be_bytes(fixed[1..9].try_into().expect("fixed timestamp"));
    let now_wall = match clock.unix_seconds() {
        Ok(now) => now,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ClockUnavailable)),
    };
    if now_wall.abs_diff(timestamp) > 30 {
        return Err(terminate_detection(io, DetectionReason::TimestampSkew));
    }
    let variable_len = usize::from(u16::from_be_bytes(
        fixed[9..11].try_into().expect("fixed variable length"),
    ));
    let wire_len = match variable_len.checked_add(TAG_LEN) {
        Some(length) if length <= MAX_DECRYPT_WIRE_LEN => length,
        _ => return Err(terminate_detection(io, DetectionReason::FrameBounds)),
    };

    // Allocation size is the fixed protocol maximum, never the peer value.
    let mut read_scratch = vec![0_u8; MAX_DECRYPT_WIRE_LEN];
    let read = match io.read_header(&mut read_scratch[..wire_len]).await {
        Ok(read) => read,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ReadFailed)),
    };
    if read != wire_len {
        return Err(terminate_detection(io, DetectionReason::ShortRead));
    }
    let mut variable = BytesMut::with_capacity(MAX_DECRYPT_WIRE_LEN);
    variable.extend_from_slice(&read_scratch[..wire_len]);
    if opener.open_in_place(&mut variable).is_err() {
        return Err(terminate_detection(io, DetectionReason::Authentication));
    }
    if variable.len() != variable_len {
        return Err(terminate_detection(io, DetectionReason::FrameBounds));
    }
    let parsed = match parse_request_variable(&variable) {
        Ok(parsed) => parsed,
        Err(reason) => return Err(terminate_detection(io, reason)),
    };

    match replay.check_and_insert(&request_salt, clock.monotonic_now()) {
        Ok(()) => {}
        Err(ReplayInsertError::Duplicate) => {
            return Err(terminate_detection(io, DetectionReason::Replay));
        }
        Err(ReplayInsertError::Capacity) => {
            return Err(terminate_detection(io, DetectionReason::ReplayCapacity));
        }
        Err(ReplayInsertError::Unavailable) => {
            return Err(terminate_detection(io, DetectionReason::ReplayUnavailable));
        }
    }

    Ok(AcceptedServerStream {
        io,
        target: parsed.target,
        initial_payload: parsed.initial_payload,
        request_salt,
        request_opener: opener,
    })
}

struct ParsedRequest {
    target: TargetAddr,
    initial_payload: Bytes,
}

fn parse_request_variable(variable: &[u8]) -> Result<ParsedRequest, DetectionReason> {
    const ADDRESS_AND_PADDING_LEN: usize = 9;
    if variable.len() < ADDRESS_AND_PADDING_LEN {
        return Err(DetectionReason::AddressBounds);
    }
    if variable[0] != IPV4_ATYP {
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

/// Authenticates the response first-read, checks full request-salt binding,
/// authenticates the first payload, and only then returns application bytes.
pub async fn accept_client_response<S, K, T>(
    stream: OpenedClientStream<S>,
    keys: &K,
    clock: &T,
) -> Result<OpenedClientResponse<S>, ShadowsocksError>
where
    S: AbortiveClose + HeaderIo,
    K: KeyProvider,
    T: Clock,
{
    let OpenedClientStream {
        mut io,
        request_salt,
        request_sealer,
    } = stream;
    let mut first_read = [0_u8; RESPONSE_FIRST_READ_LEN];
    let read = match io.read_header(&mut first_read).await {
        Ok(read) => read,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ReadFailed)),
    };
    if read != RESPONSE_FIRST_READ_LEN {
        return Err(terminate_detection(io, DetectionReason::ShortRead));
    }
    let response_salt = TcpSalt::from_bytes(
        first_read[..TCP_SALT_LEN]
            .try_into()
            .expect("fixed salt region"),
    );
    if response_salt == request_salt {
        return Err(terminate_detection(io, DetectionReason::ResponseBinding));
    }
    let mut opener = match opener_for(keys, &response_salt) {
        Ok(opener) => opener,
        Err(reason) => return Err(terminate_detection(io, reason)),
    };
    let mut fixed = BytesMut::with_capacity(RESPONSE_FIXED_PLAINTEXT_LEN + TAG_LEN);
    fixed.extend_from_slice(&first_read[TCP_SALT_LEN..]);
    if opener.open_in_place(&mut fixed).is_err() {
        return Err(terminate_detection(io, DetectionReason::Authentication));
    }
    if fixed.len() != RESPONSE_FIXED_PLAINTEXT_LEN {
        return Err(terminate_detection(io, DetectionReason::FrameBounds));
    }
    if fixed[0] != RESPONSE_TYPE {
        return Err(terminate_detection(io, DetectionReason::InvalidType));
    }
    let timestamp = u64::from_be_bytes(fixed[1..9].try_into().expect("fixed timestamp"));
    let now_wall = match clock.unix_seconds() {
        Ok(now) => now,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ClockUnavailable)),
    };
    if now_wall.abs_diff(timestamp) > 30 {
        return Err(terminate_detection(io, DetectionReason::TimestampSkew));
    }
    if fixed[9..25] != *request_salt.as_bytes() {
        return Err(terminate_detection(io, DetectionReason::ResponseBinding));
    }
    let payload_len = usize::from(u16::from_be_bytes(
        fixed[25..27].try_into().expect("fixed payload length"),
    ));
    if payload_len == 0 {
        return Err(terminate_detection(io, DetectionReason::FrameBounds));
    }
    let wire_len = match payload_len
        .checked_add(TAG_LEN)
        .filter(|length| *length <= MAX_DECRYPT_WIRE_LEN)
    {
        Some(length) => length,
        None => return Err(terminate_detection(io, DetectionReason::FrameBounds)),
    };
    let mut scratch = vec![0_u8; MAX_DECRYPT_WIRE_LEN];
    let read = match io.read_header(&mut scratch[..wire_len]).await {
        Ok(read) => read,
        Err(_) => return Err(terminate_detection(io, DetectionReason::ReadFailed)),
    };
    if read != wire_len {
        return Err(terminate_detection(io, DetectionReason::ShortRead));
    }
    let mut payload = BytesMut::with_capacity(MAX_DECRYPT_WIRE_LEN);
    payload.extend_from_slice(&scratch[..wire_len]);
    if opener.open_in_place(&mut payload).is_err() {
        return Err(terminate_detection(io, DetectionReason::Authentication));
    }
    if payload.len() != payload_len {
        return Err(terminate_detection(io, DetectionReason::FrameBounds));
    }
    Ok(OpenedClientResponse {
        io,
        first_payload: payload.freeze(),
        request_sealer,
        response_opener: opener,
    })
}

/// Client-side state after response authentication and request-salt binding.
pub struct OpenedClientResponse<S> {
    io: S,
    first_payload: Bytes,
    request_sealer: TcpSealer,
    response_opener: TcpOpener,
}

impl<S: LocalEndpoint> LocalEndpoint for OpenedClientResponse<S> {
    fn local_endpoint(&self) -> SocketAddrV4 {
        self.io.local_endpoint()
    }
}

impl<S> OpenedClientResponse<S> {
    /// Returns the authenticated first server payload.
    pub const fn first_payload(&self) -> &Bytes {
        &self.first_payload
    }

    /// Encodes one subsequent request data frame.
    pub fn seal_request_chunk(&mut self, payload: &[u8]) -> Result<Bytes, FrameError> {
        seal_data_chunk(&mut self.request_sealer, payload)
    }

    /// Authenticates one subsequent server-to-client data frame.
    pub fn open_response_chunk(
        &mut self,
        encrypted_length: &[u8],
        encrypted_payload: &[u8],
    ) -> Result<Bytes, FrameError> {
        open_data_frame(
            &mut self.response_opener,
            encrypted_length,
            encrypted_payload,
        )
    }

    /// Returns the transport and response opener for runtime-owned relay.
    pub fn into_parts(self) -> (S, TcpOpener) {
        (self.io, self.response_opener)
    }
}

/// Builds the contiguous SIP022 request first-write from already selected,
/// validated inputs.
///
/// Production callers obtain the salt, timestamp, and padding through their
/// injected capabilities. Exposing the deterministic codec also lets reviewed
/// wire fixtures exercise the same state transition.
pub fn encode_request_first_write<K: KeyProvider>(
    keys: &K,
    salt: &TcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
) -> Result<Bytes, FrameError> {
    encode_request_state(keys, salt, timestamp, target, padding, initial_payload)
        .map(|(wire, _sealer)| wire)
}

fn encode_request_state<K: KeyProvider>(
    keys: &K,
    salt: &TcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
) -> Result<(Bytes, TcpSealer), FrameError> {
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

    let variable_len = 1_usize
        .checked_add(4)
        .and_then(|length| length.checked_add(2))
        .and_then(|length| length.checked_add(2))
        .and_then(|length| length.checked_add(padding.len()))
        .and_then(|length| length.checked_add(initial_payload.len()))
        .ok_or(FrameError::Bounds)?;
    let variable_len_u16 = u16::try_from(variable_len).map_err(|_| FrameError::Bounds)?;

    let mut variable = BytesMut::with_capacity(variable_len);
    variable.extend_from_slice(&[IPV4_ATYP]);
    variable.extend_from_slice(&address.octets());
    variable.extend_from_slice(&target.port().get().to_be_bytes());
    variable.extend_from_slice(
        &u16::try_from(padding.len())
            .map_err(|_| FrameError::PaddingBounds)?
            .to_be_bytes(),
    );
    variable.extend_from_slice(padding);
    variable.extend_from_slice(initial_payload);

    let mut fixed = BytesMut::with_capacity(11);
    fixed.extend_from_slice(&[REQUEST_TYPE]);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(&variable_len_u16.to_be_bytes());

    let sealer = keys
        .with_key(KeySelector::Default, |key| {
            let subkey = key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt);
            let mut sealer = TcpSealer::new(subkey);
            sealer
                .seal_in_place(&mut fixed)
                .map_err(|_| FrameError::Cipher)?;
            sealer
                .seal_in_place(&mut variable)
                .map_err(|_| FrameError::Cipher)?;
            Ok::<_, FrameError>(sealer)
        })
        .map_err(|_| FrameError::KeyUnavailable)?;
    let sealer = sealer?;

    let capacity = TCP_SALT_LEN
        .checked_add(fixed.len())
        .and_then(|length| length.checked_add(variable.len()))
        .ok_or(FrameError::Bounds)?;
    let mut wire = BytesMut::with_capacity(capacity);
    wire.extend_from_slice(salt.as_bytes());
    wire.extend_from_slice(&fixed);
    wire.extend_from_slice(&variable);
    Ok((wire.freeze(), sealer))
}

/// Builds the contiguous SIP022 response first-write and binds it to the full
/// request salt.
pub fn encode_response_first_write<K: KeyProvider>(
    keys: &K,
    response_salt: &TcpSalt,
    timestamp: u64,
    request_salt: &TcpSalt,
    first_payload: &[u8],
) -> Result<Bytes, FrameError> {
    encode_response_state(keys, response_salt, timestamp, request_salt, first_payload)
        .map(|(wire, _sealer)| wire)
}

fn encode_response_state<K: KeyProvider>(
    keys: &K,
    response_salt: &TcpSalt,
    timestamp: u64,
    request_salt: &TcpSalt,
    first_payload: &[u8],
) -> Result<(Bytes, TcpSealer), FrameError> {
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

    let mut fixed = BytesMut::with_capacity(27);
    fixed.extend_from_slice(&[RESPONSE_TYPE]);
    fixed.extend_from_slice(&timestamp.to_be_bytes());
    fixed.extend_from_slice(request_salt.as_bytes());
    fixed.extend_from_slice(&payload_len.to_be_bytes());
    let mut payload = BytesMut::with_capacity(first_payload.len());
    payload.extend_from_slice(first_payload);

    let sealer = keys
        .with_key(KeySelector::Default, |key| {
            let subkey = key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, response_salt);
            let mut sealer = TcpSealer::new(subkey);
            sealer
                .seal_in_place(&mut fixed)
                .map_err(|_| FrameError::Cipher)?;
            sealer
                .seal_in_place(&mut payload)
                .map_err(|_| FrameError::Cipher)?;
            Ok::<_, FrameError>(sealer)
        })
        .map_err(|_| FrameError::KeyUnavailable)?;
    let sealer = sealer?;

    let capacity = TCP_SALT_LEN
        .checked_add(fixed.len())
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(FrameError::Bounds)?;
    let mut wire = BytesMut::with_capacity(capacity);
    wire.extend_from_slice(response_salt.as_bytes());
    wire.extend_from_slice(&fixed);
    wire.extend_from_slice(&payload);
    Ok((wire.freeze(), sealer))
}

fn seal_data_chunk(sealer: &mut TcpSealer, payload: &[u8]) -> Result<Bytes, FrameError> {
    if payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| FrameError::Bounds)?;
    let mut length = BytesMut::with_capacity(2);
    length.extend_from_slice(&payload_len.to_be_bytes());
    let mut encrypted_payload = BytesMut::with_capacity(payload.len());
    encrypted_payload.extend_from_slice(payload);
    sealer
        .seal_in_place(&mut length)
        .map_err(|_| FrameError::Cipher)?;
    sealer
        .seal_in_place(&mut encrypted_payload)
        .map_err(|_| FrameError::Cipher)?;
    let mut wire = BytesMut::with_capacity(length.len() + encrypted_payload.len());
    wire.extend_from_slice(&length);
    wire.extend_from_slice(&encrypted_payload);
    Ok(wire.freeze())
}

/// Authenticates and decodes one complete SIP022 data frame.
///
/// `encrypted_length` is exactly the encrypted two-byte length chunk and
/// `encrypted_payload` is the corresponding encrypted payload chunk. The
/// decoder accepts the full peer range `0..=65535`.
pub fn open_data_frame(
    opener: &mut TcpOpener,
    encrypted_length: &[u8],
    encrypted_payload: &[u8],
) -> Result<Bytes, FrameError> {
    if encrypted_length.len() != 2 + TAG_LEN || encrypted_payload.len() > MAX_DECRYPT_WIRE_LEN {
        return Err(FrameError::Bounds);
    }
    let mut length = BytesMut::with_capacity(2 + TAG_LEN);
    length.extend_from_slice(encrypted_length);
    opener
        .open_in_place(&mut length)
        .map_err(|_| FrameError::Cipher)?;
    if length.len() != 2 {
        return Err(FrameError::Bounds);
    }
    let payload_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let expected_wire_len = payload_len.checked_add(TAG_LEN).ok_or(FrameError::Bounds)?;
    if encrypted_payload.len() != expected_wire_len {
        return Err(FrameError::Bounds);
    }
    let mut payload = BytesMut::with_capacity(MAX_DECRYPT_WIRE_LEN);
    payload.extend_from_slice(encrypted_payload);
    opener
        .open_in_place(&mut payload)
        .map_err(|_| FrameError::Cipher)?;
    if payload.len() != payload_len {
        return Err(FrameError::Bounds);
    }
    Ok(payload.freeze())
}

fn opener_for<K: KeyProvider>(keys: &K, salt: &TcpSalt) -> Result<TcpOpener, DetectionReason> {
    keys.with_key(KeySelector::Default, |key| {
        let subkey = key.derive_tcp_subkey(TcpMethod::Blake3Aes128Gcm2022, salt);
        TcpOpener::new(subkey)
    })
    .map_err(|_| DetectionReason::KeyUnavailable)
}

fn terminate_detection<S: AbortiveClose>(mut io: S, reason: DetectionReason) -> ShadowsocksError {
    let _ = io.mark_abortive();
    ShadowsocksError::Detection(reason)
}

fn detection_from_frame(error: FrameError) -> DetectionReason {
    match error {
        FrameError::KeyUnavailable => DetectionReason::KeyUnavailable,
        FrameError::Cipher => DetectionReason::Authentication,
        FrameError::Bounds | FrameError::EmptyResponse => DetectionReason::FrameBounds,
        FrameError::AddressUnsupported => DetectionReason::AddressBounds,
        FrameError::PaddingBounds => DetectionReason::PaddingBounds,
        FrameError::EmptyRequest => DetectionReason::EmptyRequest,
        FrameError::ResponseSaltReuse => DetectionReason::ResponseBinding,
    }
}

fn sample_nonzero_padding(random: &(impl SecureRandom + ?Sized)) -> Result<Vec<u8>, FrameError> {
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
    let mut padding = vec![0_u8; length];
    random.fill(&mut padding).map_err(|_| FrameError::Bounds)?;
    Ok(padding)
}
