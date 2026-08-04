use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::{
    Clock, KeySelector, MethodKeyProvider, MethodProfile, MonotonicInstant, SecureRandom,
    UdpCrypto, UdpCryptoError, UdpOutboundSession, UdpSessionId,
};
use thiserror::Error;

use super::{
    DetectionReason, FrameError, REQUEST_TYPE, RESPONSE_TYPE, encode_target_into,
    encoded_target_len, validate_target,
};

/// Hard maximum for one complete Shadowsocks UDP wire datagram.
pub const MAX_UDP_WIRE_LEN: usize = 65_507;
/// Number of packet IDs represented behind the highest accepted ID.
pub const UDP_REPLAY_LAG: u64 = 8_128;
/// Minimum valid lifetime of a replay/session association.
pub const UDP_ASSOCIATION_RETENTION: Duration = Duration::from_secs(60);

const TIMESTAMP_LEN: usize = 8;
const SESSION_ID_LEN: usize = 8;
const PADDING_LEN: usize = 2;
const COMMON_HEADER_LEN: usize = 1 + TIMESTAMP_LEN + PADDING_LEN;
const RESPONSE_BINDING_LEN: usize = SESSION_ID_LEN;
const REPLAY_WORDS: usize = 129;

/// Fixed caller-reusable plaintext storage for packet construction and opening.
pub struct UdpPacketScratch {
    body: BytesMut,
}

impl UdpPacketScratch {
    /// Allocates the one fixed hard-bounded protocol scratch.
    pub fn new() -> Self {
        Self {
            body: BytesMut::with_capacity(MAX_UDP_WIRE_LEN),
        }
    }

    /// Returns the fixed usable bound.
    pub const fn usable_limit(&self) -> usize {
        MAX_UDP_WIRE_LEN
    }

    /// Returns an opaque allocation identity for reuse evidence.
    pub fn storage_identity(&self) -> usize {
        self.body.as_ptr() as usize
    }
}

impl Default for UdpPacketScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UdpPacketScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpPacketScratch")
            .field("usable_limit", &MAX_UDP_WIRE_LEN)
            .finish()
    }
}

/// Closed packet, replay, association, or generation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UdpPacketError {
    /// A complete wire, output, padding, or payload bound was violated.
    #[error("UDP bounds rejected")]
    Bounds,
    /// Cryptographic authentication failed.
    #[error("UDP authentication rejected")]
    Authentication,
    /// The authenticated message type was wrong for the direction.
    #[error("UDP type rejected")]
    Type,
    /// Wall time was unavailable.
    #[error("UDP clock unavailable")]
    Clock,
    /// The authenticated timestamp was outside the inclusive 30-second window.
    #[error("UDP timestamp rejected")]
    Timestamp,
    /// The authenticated address was malformed.
    #[error("UDP address rejected")]
    Address,
    /// The authenticated padding encoding was malformed.
    #[error("UDP padding rejected")]
    Padding,
    /// A server response did not bind the requesting client session.
    #[error("UDP response binding rejected")]
    Binding,
    /// The packet ID was already accepted.
    #[error("UDP duplicate rejected")]
    Duplicate,
    /// The packet ID fell behind the represented replay window.
    #[error("UDP packet too old")]
    TooOld,
    /// Current and old client associations are both still retained.
    #[error("UDP association limit reached")]
    AssociationLimit,
    /// A response capability no longer names the same live generation.
    #[error("UDP generation rejected")]
    Generation,
    /// The configured method-bound key could not be selected.
    #[error("UDP key unavailable")]
    Key,
    /// Secure randomness was unavailable.
    #[error("UDP random unavailable")]
    Random,
    /// Every outbound packet ID was consumed.
    #[error("UDP packet counter exhausted")]
    Counter,
    /// Accepted state could not be safely serialized.
    #[error("UDP state unavailable")]
    StateUnavailable,
}

/// Exact sliding window representing the highest ID plus 8,128 earlier IDs.
#[derive(Clone)]
pub struct UdpReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WORDS],
}

impl UdpReplayWindow {
    /// Creates an empty replay window.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bits: [0; REPLAY_WORDS],
        }
    }

    /// Returns the highest accepted ID, if any.
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Checks an ID without changing accepted state.
    pub fn check(&self, packet_id: u64) -> Result<(), UdpPacketError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if packet_id > highest {
            return Ok(());
        }
        let distance = highest - packet_id;
        if distance > UDP_REPLAY_LAG {
            return Err(UdpPacketError::TooOld);
        }
        let index = usize::try_from(distance).map_err(|_| UdpPacketError::TooOld)?;
        if self.bit(index) {
            Err(UdpPacketError::Duplicate)
        } else {
            Ok(())
        }
    }

    /// Atomically rechecks and marks an ID under the caller's serialized owner.
    pub fn commit(&mut self, packet_id: u64) -> Result<(), UdpPacketError> {
        self.check(packet_id)?;
        match self.highest {
            None => {
                self.highest = Some(packet_id);
                self.bits[0] = 1;
            }
            Some(highest) if packet_id > highest => {
                let advance = packet_id - highest;
                self.shift(advance);
                self.highest = Some(packet_id);
                self.bits[0] |= 1;
            }
            Some(highest) => {
                let distance =
                    usize::try_from(highest - packet_id).map_err(|_| UdpPacketError::TooOld)?;
                self.set_bit(distance);
            }
        }
        Ok(())
    }

    fn bit(&self, index: usize) -> bool {
        self.bits[index / 64] & (1_u64 << (index % 64)) != 0
    }

    fn set_bit(&mut self, index: usize) {
        self.bits[index / 64] |= 1_u64 << (index % 64);
    }

    fn shift(&mut self, advance: u64) {
        if advance > UDP_REPLAY_LAG {
            self.bits.fill(0);
            return;
        }
        let advance = usize::try_from(advance).expect("replay advance is at most 8128");
        let word_shift = advance / 64;
        let bit_shift = advance % 64;
        let old = self.bits;
        self.bits.fill(0);
        for destination in word_shift..REPLAY_WORDS {
            let source = destination - word_shift;
            self.bits[destination] |= old[source] << bit_shift;
            if bit_shift != 0 && source > 0 {
                self.bits[destination] |= old[source - 1] >> (64 - bit_shift);
            }
        }
        self.bits[REPLAY_WORDS - 1] &= 1;
    }
}

impl Default for UdpReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UdpReplayWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpReplayWindow")
            .field("highest", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct ClientAssociation {
    session_id: UdpSessionId,
    replay: UdpReplayWindow,
    last_valid: MonotonicInstant,
}

#[derive(Clone, Default)]
struct ClientAssociations {
    current: Option<ClientAssociation>,
    old: Option<ClientAssociation>,
}

/// Non-secret client association state for deterministic acceptance evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAssociationSnapshot {
    association_count: usize,
    current_last_valid: Option<MonotonicInstant>,
    old_last_valid: Option<MonotonicInstant>,
}

impl ClientAssociationSnapshot {
    /// Returns the number of retained server-session associations.
    pub const fn association_count(self) -> usize {
        self.association_count
    }

    /// Returns current association activity without exposing its wire ID.
    pub const fn current_last_valid(self) -> Option<MonotonicInstant> {
        self.current_last_valid
    }

    /// Returns old association activity without exposing its wire ID.
    pub const fn old_last_valid(self) -> Option<MonotonicInstant> {
        self.old_last_valid
    }
}

/// One bounded socket-free SIP022 UDP client protocol session.
pub struct UdpClientSession {
    crypto: UdpCrypto,
    outbound: UdpOutboundSession,
    associations: Mutex<ClientAssociations>,
}

impl UdpClientSession {
    /// Creates a fresh client direction using the configured method capability.
    pub fn new<K: MethodKeyProvider>(
        keys: &K,
        random: &(impl SecureRandom + ?Sized),
        is_live: impl FnMut(&UdpSessionId) -> bool,
    ) -> Result<Self, UdpPacketError> {
        let crypto = udp_crypto(keys)?;
        let outbound = crypto
            .generate_outbound_session(random, is_live)
            .map_err(|_| UdpPacketError::Random)?;
        Ok(Self {
            crypto,
            outbound,
            associations: Mutex::new(ClientAssociations::default()),
        })
    }

    /// Returns the opaque live ID for collision-safe process-local registration.
    pub const fn session_id(&self) -> &UdpSessionId {
        self.outbound.session_id()
    }

    /// Encodes one request into caller-owned bounded output.
    pub fn encode_request(
        &mut self,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &Datagram,
        padding_len: usize,
        output: &mut [u8],
        scratch: &mut UdpPacketScratch,
    ) -> Result<usize, UdpPacketError> {
        self.encode_request_parts(
            clock,
            random,
            datagram.target(),
            datagram.payload(),
            padding_len,
            output,
            scratch,
        )
    }

    /// Encodes one request from borrowed target/payload parts into caller-owned output.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_request_parts(
        &mut self,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        target: &TargetAddr,
        payload: &[u8],
        padding_len: usize,
        output: &mut [u8],
        scratch: &mut UdpPacketScratch,
    ) -> Result<usize, UdpPacketError> {
        encode_packet(
            &self.crypto,
            &mut self.outbound,
            clock,
            random,
            REQUEST_TYPE,
            None,
            target,
            payload,
            padding_len,
            output,
            scratch,
        )
    }

    /// Authenticates, semantically validates, and reserves an owned response
    /// payload without changing association, replay, or activity state.
    pub fn prepare_response(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &[u8],
        scratch: &mut UdpPacketScratch,
    ) -> Result<PendingUdpResponse, UdpPacketError> {
        self.prepare_response_borrowed(clock, wire, scratch)
            .map(BorrowedPendingUdpResponse::materialize)
    }

    /// Authenticates and validates a response without materializing its target or payload.
    pub fn prepare_response_borrowed<'a>(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &[u8],
        scratch: &'a mut UdpPacketScratch,
    ) -> Result<BorrowedPendingUdpResponse<'a>, UdpPacketError> {
        let opened = open_packet_borrowed(
            &self.crypto,
            clock,
            wire,
            scratch,
            RESPONSE_TYPE,
            Some(self.outbound.session_id()),
        )?;
        Ok(BorrowedPendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            target: opened.target,
            payload: opened.payload,
        })
    }

    /// Atomically rechecks and commits a reserved response transition.
    ///
    /// T04 must call this only from the T03 byte/queue/session/generation
    /// reservation commit closure (`QA-M2-T02-N01`).
    pub fn commit_response(
        &self,
        commit: UdpResponseCommit,
        now: MonotonicInstant,
    ) -> Result<(), UdpPacketError> {
        if commit.owner_id != *self.outbound.session_id() {
            return Err(UdpPacketError::Binding);
        }
        let mut associations = self
            .associations
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        commit_client_association(&mut associations, commit.session_id, commit.packet_id, now)
    }

    /// Atomically commits one ordered response transition per distinct client session.
    pub fn commit_responses(
        sessions: &[&Self],
        commits: Vec<UdpResponseCommit>,
        now: MonotonicInstant,
    ) -> Result<(), UdpPacketError> {
        if sessions.is_empty() || sessions.len() > 8 || sessions.len() != commits.len() {
            return Err(UdpPacketError::Bounds);
        }
        for (index, session) in sessions.iter().enumerate() {
            if commits[index].owner_id != *session.outbound.session_id()
                || sessions[..index]
                    .iter()
                    .any(|other| std::ptr::eq(*other, *session))
            {
                return Err(UdpPacketError::Binding);
            }
        }
        let mut guards = sessions
            .iter()
            .map(|session| {
                session
                    .associations
                    .lock()
                    .map_err(|_| UdpPacketError::StateUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut updated = guards
            .iter()
            .map(|associations| (**associations).clone())
            .collect::<Vec<_>>();
        for (associations, commit) in updated.iter_mut().zip(commits) {
            commit_client_association(associations, commit.session_id, commit.packet_id, now)?;
        }
        for (associations, replacement) in guards.iter_mut().zip(updated) {
            **associations = replacement;
        }
        Ok(())
    }

    /// Returns a redacted snapshot of current+old association state.
    pub fn association_snapshot(&self) -> Result<ClientAssociationSnapshot, UdpPacketError> {
        let associations = self
            .associations
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(ClientAssociationSnapshot {
            association_count: usize::from(associations.current.is_some())
                + usize::from(associations.old.is_some()),
            current_last_valid: associations
                .current
                .as_ref()
                .map(|association| association.last_valid),
            old_last_valid: associations
                .old
                .as_ref()
                .map(|association| association.last_valid),
        })
    }
}

impl fmt::Debug for UdpClientSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpClientSession([redacted])")
    }
}

fn commit_client_association(
    associations: &mut ClientAssociations,
    session_id: UdpSessionId,
    packet_id: u64,
    now: MonotonicInstant,
) -> Result<(), UdpPacketError> {
    if let Some(current) = associations
        .current
        .as_mut()
        .filter(|association| association.session_id == session_id)
    {
        current.replay.commit(packet_id)?;
        current.last_valid = now;
        return Ok(());
    }
    if let Some(old) = associations
        .old
        .as_mut()
        .filter(|association| association.session_id == session_id)
    {
        old.replay.commit(packet_id)?;
        old.last_valid = now;
        return Ok(());
    }

    let mut replay = UdpReplayWindow::new();
    replay.commit(packet_id)?;
    let new = ClientAssociation {
        session_id,
        replay,
        last_valid: now,
    };
    match associations.current.take() {
        None => {
            associations.current = Some(new);
        }
        Some(current) if associations.old.is_none() => {
            associations.old = Some(current);
            associations.current = Some(new);
        }
        Some(current) => {
            let old_expired = associations.old.as_ref().is_some_and(|old| {
                now.duration_since(old.last_valid)
                    .is_some_and(|age| age >= UDP_ASSOCIATION_RETENTION)
            });
            if !old_expired {
                associations.current = Some(current);
                return Err(UdpPacketError::AssociationLimit);
            }
            associations.old = Some(current);
            associations.current = Some(new);
        }
    }
    Ok(())
}

struct OpenedPacket {
    session_id: UdpSessionId,
    packet_id: u64,
    datagram: Datagram,
}

struct BorrowedOpenedPacket<'a> {
    session_id: UdpSessionId,
    packet_id: u64,
    target: super::ValidatedTarget<'a>,
    payload: &'a [u8],
}

/// Fully authenticated response awaiting its runtime-state commit.
pub struct PendingUdpResponse {
    owner_id: UdpSessionId,
    session_id: UdpSessionId,
    packet_id: u64,
    datagram: Datagram,
}

impl PendingUdpResponse {
    /// Returns the authenticated datagram without exposing commit state.
    pub const fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    /// Separates the authenticated datagram and opaque commit token.
    pub fn into_parts(self) -> (Datagram, UdpResponseCommit) {
        (
            self.datagram,
            UdpResponseCommit {
                owner_id: self.owner_id,
                session_id: self.session_id,
                packet_id: self.packet_id,
            },
        )
    }
}

impl fmt::Debug for PendingUdpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingUdpResponse")
            .field("payload_len", &self.datagram.payload().len())
            .finish_non_exhaustive()
    }
}

/// Fully authenticated borrowed response awaiting exact runtime reservation.
pub struct BorrowedPendingUdpResponse<'a> {
    owner_id: UdpSessionId,
    session_id: UdpSessionId,
    packet_id: u64,
    target: super::ValidatedTarget<'a>,
    payload: &'a [u8],
}

impl BorrowedPendingUdpResponse<'_> {
    /// Returns the authenticated payload borrowed from charged scratch.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Returns the exact capacity required by the sole owned materialization.
    pub const fn allocated_capacity(&self) -> usize {
        self.payload.len()
    }

    /// Returns the validated SIP022 target field width without materializing it.
    pub fn encoded_target_len(&self) -> usize {
        match &self.target {
            super::ValidatedTarget::Ip(SocketAddr::V4(_)) => 7,
            super::ValidatedTarget::Ip(SocketAddr::V6(_)) => 19,
            super::ValidatedTarget::Domain(host, _) => 4 + host.len(),
        }
    }

    /// Compares the authenticated target without allocating an owned address.
    pub fn target_matches(&self, expected: &TargetAddr) -> bool {
        match (&self.target, expected.host()) {
            (super::ValidatedTarget::Ip(actual), TargetHostRef::Ip(expected_ip)) => {
                actual.ip() == expected_ip && actual.port() == expected.port().get()
            }
            (
                super::ValidatedTarget::Domain(actual, port),
                TargetHostRef::Domain(expected_host),
            ) => *actual == expected_host && *port == expected.port().get(),
            (super::ValidatedTarget::Ip(_), TargetHostRef::Domain(_))
            | (super::ValidatedTarget::Domain(_, _), TargetHostRef::Ip(_)) => false,
        }
    }

    /// Copies the authenticated payload into caller-owned bounded storage.
    pub fn copy_payload_to(&self, output: &mut [u8]) -> Result<usize, UdpPacketError> {
        let destination = output
            .get_mut(..self.payload.len())
            .ok_or(UdpPacketError::Bounds)?;
        destination.copy_from_slice(self.payload);
        Ok(destination.len())
    }

    /// Extracts only the opaque commit transition after the caller copied nested wire.
    pub fn into_commit(self) -> UdpResponseCommit {
        UdpResponseCommit {
            owner_id: self.owner_id,
            session_id: self.session_id,
            packet_id: self.packet_id,
        }
    }

    /// Materializes once after reservation and separates the opaque commit token.
    pub fn materialize(self) -> PendingUdpResponse {
        let target = self
            .target
            .into_owned()
            .expect("authenticated response target was already validated");
        let payload_len = self.payload.len();
        let datagram = Datagram::new(target, BytesMut::from(self.payload), payload_len)
            .expect("authenticated response payload was already bounded");
        PendingUdpResponse {
            datagram,
            owner_id: self.owner_id,
            session_id: self.session_id,
            packet_id: self.packet_id,
        }
    }
}

impl fmt::Debug for BorrowedPendingUdpResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BorrowedPendingUdpResponse")
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Move-only authenticated response identity committed after reservation.
pub struct UdpResponseCommit {
    owner_id: UdpSessionId,
    session_id: UdpSessionId,
    packet_id: u64,
}

impl fmt::Debug for UdpResponseCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpResponseCommit([redacted])")
    }
}

/// Fully authenticated and semantically validated request awaiting reservation.
pub struct PendingUdpRequest {
    session_id: UdpSessionId,
    packet_id: u64,
    datagram: Datagram,
}

impl PendingUdpRequest {
    /// Borrows the validated datagram for bounded capacity planning only.
    pub const fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    /// Separates the owned datagram from the opaque post-reservation commit token.
    pub fn into_parts(self) -> (Datagram, UdpRequestCommit) {
        (
            self.datagram,
            UdpRequestCommit {
                session_id: self.session_id,
                packet_id: self.packet_id,
            },
        )
    }
}

impl fmt::Debug for PendingUdpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingUdpRequest")
            .field("datagram", &self.datagram)
            .finish_non_exhaustive()
    }
}

/// Move-only authenticated identity used only after runtime reservation.
pub struct UdpRequestCommit {
    session_id: UdpSessionId,
    packet_id: u64,
}

impl fmt::Debug for UdpRequestCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpRequestCommit([redacted])")
    }
}

/// Opaque generation-bound response capability.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ServerResponseCapability {
    slot: u64,
    generation: u64,
}

impl fmt::Debug for ServerResponseCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerResponseCapability([redacted])")
    }
}

/// Result of the serialized post-reservation request commit.
pub struct AcceptedUdpRequest {
    capability: ServerResponseCapability,
}

impl AcceptedUdpRequest {
    /// Returns the capability to bind target responses to this generation.
    pub const fn capability(&self) -> ServerResponseCapability {
        self.capability
    }
}

impl fmt::Debug for AcceptedUdpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AcceptedUdpRequest([redacted])")
    }
}

struct ServerSession {
    capability: ServerResponseCapability,
    outbound: UdpOutboundSession,
    replay: UdpReplayWindow,
    peer: SocketAddr,
    last_activity: MonotonicInstant,
}

struct ServerState {
    sessions: HashMap<UdpSessionId, ServerSession>,
    next_generation: u64,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            next_generation: 1,
        }
    }
}

/// Non-secret snapshot of one live server generation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServerSessionSnapshot {
    peer: SocketAddr,
    last_activity: MonotonicInstant,
    highest_packet_id: Option<u64>,
}

impl fmt::Debug for ServerSessionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerSessionSnapshot")
            .field("peer", &"[redacted]")
            .field("last_activity", &self.last_activity)
            .field("highest_packet_id", &"[redacted]")
            .finish()
    }
}

impl ServerSessionSnapshot {
    /// Returns the latest successfully validated roaming peer.
    pub const fn peer(self) -> SocketAddr {
        self.peer
    }

    /// Returns accepted activity without exposing wire identity.
    pub const fn last_activity(self) -> MonotonicInstant {
        self.last_activity
    }

    /// Returns the highest accepted incoming packet ID.
    pub const fn highest_packet_id(self) -> Option<u64> {
        self.highest_packet_id
    }
}

/// One socket-free server-side packet, replay, routing, and generation owner.
pub struct UdpServer {
    crypto: UdpCrypto,
    state: Mutex<ServerState>,
}

impl UdpServer {
    /// Creates protocol state without creating sockets or runtime resources.
    pub fn new<K: MethodKeyProvider>(keys: &K) -> Result<Self, UdpPacketError> {
        Ok(Self {
            crypto: udp_crypto(keys)?,
            state: Mutex::new(ServerState::default()),
        })
    }

    /// Authenticates and fully validates a client packet with zero accepted mutation.
    pub fn prepare_request(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &[u8],
        scratch: &mut UdpPacketScratch,
    ) -> Result<PendingUdpRequest, UdpPacketError> {
        let opened = open_packet(&self.crypto, clock, wire, scratch, REQUEST_TYPE, None)?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
        })
    }

    /// Looks up only the authenticated request identity without mutation.
    pub fn existing_capability(
        &self,
        pending: &PendingUdpRequest,
    ) -> Result<Option<ServerResponseCapability>, UdpPacketError> {
        let state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(state
            .sessions
            .get(&pending.session_id)
            .map(|session| session.capability))
    }

    /// Performs the atomic replay/generation recheck and peer/activity commit.
    ///
    /// Callers invoke this only inside the T03 reservation commit closure.
    pub fn commit_request(
        &self,
        commit: UdpRequestCommit,
        peer: SocketAddr,
        now: MonotonicInstant,
        random: &(impl SecureRandom + ?Sized),
    ) -> Result<AcceptedUdpRequest, UdpPacketError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if let Some(session) = state.sessions.get_mut(&commit.session_id) {
            session.replay.commit(commit.packet_id)?;
            session.peer = peer;
            session.last_activity = now;
            return Ok(AcceptedUdpRequest {
                capability: session.capability,
            });
        }

        let generation = state.next_generation;
        let next_generation = state
            .next_generation
            .checked_add(1)
            .ok_or(UdpPacketError::Generation)?;
        let outbound = self
            .crypto
            .generate_distinct_outbound_session(random, &commit.session_id, |candidate| {
                state.sessions.keys().any(|id| id == candidate)
                    || state
                        .sessions
                        .values()
                        .any(|session| session.outbound.session_id() == candidate)
            })
            .map_err(|_| UdpPacketError::Random)?;
        let mut replay = UdpReplayWindow::new();
        replay.commit(commit.packet_id)?;
        let capability = ServerResponseCapability {
            slot: generation,
            generation,
        };
        state.next_generation = next_generation;
        state.sessions.insert(
            commit.session_id,
            ServerSession {
                capability,
                outbound,
                replay,
                peer,
                last_activity: now,
            },
        );
        Ok(AcceptedUdpRequest { capability })
    }

    /// Encodes a response only for the same live generation and latest peer.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_response(
        &self,
        capability: ServerResponseCapability,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &Datagram,
        padding_len: usize,
        output: &mut [u8],
        scratch: &mut UdpPacketScratch,
    ) -> Result<EncodedUdpResponse, UdpPacketError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let binding = session_id_for_binding(&state.sessions, capability)?;
        let session = state
            .sessions
            .get_mut(&binding)
            .filter(|session| session.capability == capability)
            .ok_or(UdpPacketError::Generation)?;
        let wire_len = encode_packet(
            &self.crypto,
            &mut session.outbound,
            clock,
            random,
            RESPONSE_TYPE,
            Some(&binding),
            datagram.target(),
            datagram.payload(),
            padding_len,
            output,
            scratch,
        )?;
        Ok(EncodedUdpResponse {
            wire_len,
            peer: session.peer,
        })
    }

    /// Removes an idle generation only after the mandatory retention period.
    pub fn remove_session(
        &self,
        capability: ServerResponseCapability,
        now: MonotonicInstant,
    ) -> Result<bool, UdpPacketError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let removable = state.sessions.iter().find_map(|(id, session)| {
            (session.capability == capability
                && now
                    .duration_since(session.last_activity)
                    .is_some_and(|age| age >= UDP_ASSOCIATION_RETENTION))
            .then(|| id.clone())
        });
        Ok(removable
            .and_then(|id| state.sessions.remove(&id))
            .is_some())
    }

    /// Returns a redacted live-generation snapshot.
    pub fn session_snapshot(
        &self,
        capability: ServerResponseCapability,
    ) -> Result<Option<ServerSessionSnapshot>, UdpPacketError> {
        let state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(state
            .sessions
            .values()
            .find(|session| session.capability == capability)
            .map(|session| ServerSessionSnapshot {
                peer: session.peer,
                last_activity: session.last_activity,
                highest_packet_id: session.replay.highest(),
            }))
    }

    /// Returns the number of authenticated live client-session identities.
    pub fn session_count(&self) -> Result<usize, UdpPacketError> {
        self.state
            .lock()
            .map(|state| state.sessions.len())
            .map_err(|_| UdpPacketError::StateUnavailable)
    }
}

impl fmt::Debug for UdpServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpServer([redacted])")
    }
}

fn session_id_for_binding(
    sessions: &HashMap<UdpSessionId, ServerSession>,
    capability: ServerResponseCapability,
) -> Result<UdpSessionId, UdpPacketError> {
    sessions
        .iter()
        .find_map(|(id, session)| (session.capability == capability).then(|| id.clone()))
        .ok_or(UdpPacketError::Generation)
}

/// Complete encoded response metadata without exposing wire IDs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EncodedUdpResponse {
    wire_len: usize,
    peer: SocketAddr,
}

impl fmt::Debug for EncodedUdpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedUdpResponse")
            .field("wire_len", &self.wire_len)
            .field("peer", &"[redacted]")
            .finish()
    }
}

impl EncodedUdpResponse {
    /// Returns the complete wire length in caller output.
    pub const fn wire_len(self) -> usize {
        self.wire_len
    }

    /// Returns the latest successfully validated client peer.
    pub const fn peer(self) -> SocketAddr {
        self.peer
    }
}

/// Computes the largest payload fitting the complete 65,507-byte wire bound.
pub fn max_udp_payload_len(
    profile: MethodProfile,
    response: bool,
    target: &TargetAddr,
    padding_len: usize,
) -> Result<usize, UdpPacketError> {
    let address_len = encoded_target_len(target).map_err(map_frame)?;
    max_udp_payload_len_for_encoded_target(profile, response, address_len, padding_len)
}

/// Computes the largest payload from an already validated encoded target width.
pub fn max_udp_payload_len_for_encoded_target(
    profile: MethodProfile,
    response: bool,
    encoded_target_len: usize,
    padding_len: usize,
) -> Result<usize, UdpPacketError> {
    let semantic_overhead = COMMON_HEADER_LEN
        .checked_add(if response { RESPONSE_BINDING_LEN } else { 0 })
        .and_then(|length| length.checked_add(padding_len))
        .and_then(|length| length.checked_add(encoded_target_len))
        .ok_or(UdpPacketError::Bounds)?;
    if padding_len > usize::from(u16::MAX) {
        return Err(UdpPacketError::Bounds);
    }
    MAX_UDP_WIRE_LEN
        .checked_sub(profile.udp_wire_overhead_bytes())
        .and_then(|length| length.checked_sub(semantic_overhead))
        .ok_or(UdpPacketError::Bounds)
}

#[allow(clippy::too_many_arguments)]
fn encode_packet(
    crypto: &UdpCrypto,
    outbound: &mut UdpOutboundSession,
    clock: &(impl Clock + ?Sized),
    random: &(impl SecureRandom + ?Sized),
    message_type: u8,
    binding: Option<&UdpSessionId>,
    target: &TargetAddr,
    payload: &[u8],
    padding_len: usize,
    output: &mut [u8],
    scratch: &mut UdpPacketScratch,
) -> Result<usize, UdpPacketError> {
    let response = message_type == RESPONSE_TYPE;
    let max_payload = max_udp_payload_len(crypto.profile(), response, target, padding_len)?;
    if payload.len() > max_payload {
        return Err(UdpPacketError::Bounds);
    }
    let body_len = MAX_UDP_WIRE_LEN
        - crypto.profile().udp_wire_overhead_bytes()
        - (max_payload - payload.len());
    let wire_len = body_len
        .checked_add(crypto.profile().udp_wire_overhead_bytes())
        .ok_or(UdpPacketError::Bounds)?;
    if output.len() < wire_len {
        return Err(UdpPacketError::Bounds);
    }
    let timestamp = clock.unix_seconds().map_err(|_| UdpPacketError::Clock)?;

    scratch.body.clear();
    scratch.body.extend_from_slice(&[message_type]);
    scratch.body.extend_from_slice(&timestamp.to_be_bytes());
    if let Some(binding) = binding {
        let start = scratch.body.len();
        scratch.body.resize(start + SESSION_ID_LEN, 0);
        binding
            .write_wire(&mut scratch.body[start..])
            .map_err(map_crypto)?;
    }
    scratch.body.extend_from_slice(
        &u16::try_from(padding_len)
            .map_err(|_| UdpPacketError::Bounds)?
            .to_be_bytes(),
    );
    let padding_start = scratch.body.len();
    scratch.body.resize(padding_start + padding_len, 0);
    if padding_len != 0 {
        random
            .fill(&mut scratch.body[padding_start..])
            .map_err(|_| UdpPacketError::Random)?;
    }
    encode_target_into(target, &mut scratch.body).map_err(map_frame)?;
    scratch.body.extend_from_slice(payload);
    debug_assert_eq!(scratch.body.len(), body_len);

    crypto
        .seal(outbound, &scratch.body, output, random)
        .map(|sealed| sealed.wire_len())
        .map_err(map_crypto)
}

fn open_packet(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<OpenedPacket, UdpPacketError> {
    let opened = open_packet_borrowed(crypto, clock, wire, scratch, expected_type, binding)?;
    let target = opened.target.into_owned().map_err(map_target)?;
    let payload_len = opened.payload.len();
    let datagram = Datagram::new(target, BytesMut::from(opened.payload), payload_len)
        .map_err(|_| UdpPacketError::Bounds)?;
    Ok(OpenedPacket {
        session_id: opened.session_id,
        packet_id: opened.packet_id,
        datagram,
    })
}

fn open_packet_borrowed<'a>(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &[u8],
    scratch: &'a mut UdpPacketScratch,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<BorrowedOpenedPacket<'a>, UdpPacketError> {
    if wire.len() > MAX_UDP_WIRE_LEN {
        return Err(UdpPacketError::Bounds);
    }
    scratch.body.clear();
    scratch.body.resize(wire.len(), 0);
    let opened = crypto.open(wire, &mut scratch.body).map_err(map_crypto)?;
    scratch.body.truncate(opened.plaintext_len());
    let (target, payload_start) = parse_body(&scratch.body, clock, expected_type, binding)?;
    Ok(BorrowedOpenedPacket {
        session_id: opened.session_id().clone(),
        packet_id: opened.packet_id(),
        target,
        payload: &scratch.body[payload_start..],
    })
}

fn parse_body<'a>(
    body: &'a [u8],
    clock: &(impl Clock + ?Sized),
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<(super::ValidatedTarget<'a>, usize), UdpPacketError> {
    let message_type = *body.first().ok_or(UdpPacketError::Bounds)?;
    if message_type != expected_type {
        return Err(UdpPacketError::Type);
    }
    let timestamp_end = 1 + TIMESTAMP_LEN;
    let timestamp = u64::from_be_bytes(
        body.get(1..timestamp_end)
            .ok_or(UdpPacketError::Bounds)?
            .try_into()
            .expect("timestamp width"),
    );
    let now = clock.unix_seconds().map_err(|_| UdpPacketError::Clock)?;
    if now.abs_diff(timestamp) > 30 {
        return Err(UdpPacketError::Timestamp);
    }
    let mut cursor = timestamp_end;
    if let Some(binding) = binding {
        let end = cursor
            .checked_add(SESSION_ID_LEN)
            .ok_or(UdpPacketError::Bounds)?;
        let encoded = body.get(cursor..end).ok_or(UdpPacketError::Bounds)?;
        if !binding.matches_wire(encoded) {
            return Err(UdpPacketError::Binding);
        }
        cursor = end;
    }
    let padding_end = cursor
        .checked_add(PADDING_LEN)
        .ok_or(UdpPacketError::Bounds)?;
    let padding_len = usize::from(u16::from_be_bytes(
        body.get(cursor..padding_end)
            .ok_or(UdpPacketError::Padding)?
            .try_into()
            .expect("padding width"),
    ));
    let address_start = padding_end
        .checked_add(padding_len)
        .ok_or(UdpPacketError::Padding)?;
    let address = body.get(address_start..).ok_or(UdpPacketError::Padding)?;
    let (target, address_len) = validate_target(address).map_err(map_target)?;
    let payload_start = address_start
        .checked_add(address_len)
        .ok_or(UdpPacketError::Bounds)?;
    Ok((target, payload_start))
}

fn udp_crypto<K: MethodKeyProvider>(keys: &K) -> Result<UdpCrypto, UdpPacketError> {
    keys.with_method_key(KeySelector::Default, |key| key.udp_crypto())
        .map_err(|_| UdpPacketError::Key)
}

fn map_frame(error: FrameError) -> UdpPacketError {
    match error {
        FrameError::AddressUnsupported => UdpPacketError::Address,
        _ => UdpPacketError::Bounds,
    }
}

fn map_target(error: DetectionReason) -> UdpPacketError {
    match error {
        DetectionReason::AddressBounds => UdpPacketError::Address,
        _ => UdpPacketError::Bounds,
    }
}

fn map_crypto(error: UdpCryptoError) -> UdpPacketError {
    match error {
        UdpCryptoError::AuthenticationFailed => UdpPacketError::Authentication,
        UdpCryptoError::RandomUnavailable => UdpPacketError::Random,
        UdpCryptoError::CounterExhausted => UdpPacketError::Counter,
        UdpCryptoError::InputTooShort | UdpCryptoError::OutputTooSmall => UdpPacketError::Bounds,
        UdpCryptoError::MethodMismatch | UdpCryptoError::OperationFailed => UdpPacketError::Key,
    }
}
