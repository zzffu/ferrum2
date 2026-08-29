use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
#[cfg(feature = "structural-metrics")]
use ferrum2_crypto::MethodProfile;
use ferrum2_crypto::{
    Clock, MethodKeyProvider, MonotonicInstant, SecureRandom, UdpAesSessionCipher, UdpCrypto,
    UdpOutboundSession, UdpSessionId,
};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralCounter, StructuralLocal};

#[cfg(feature = "structural-metrics")]
use super::UdpProtocolStructuralEvidence;
use super::replay::UdpReplayWindow;
#[cfg(feature = "candidate-udp-owned-headroom")]
use super::wire::encode_packet_owned_headroom;
use super::wire::{
    encode_packet, open_packet_borrowed, open_packet_in_place_borrowed, open_packet_owned,
    udp_crypto, udp_wire_len,
};
use super::{UDP_ASSOCIATION_RETENTION, UdpPacketError, UdpPacketScratch};
use crate::tcp::wire::{REQUEST_TYPE, RESPONSE_TYPE, ValidatedTarget};

#[derive(Clone)]
struct ClientAssociation {
    session_id: UdpSessionId,
    aes_body_cipher: Option<Arc<UdpAesSessionCipher>>,
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

    /// Creates an instrumented client direction for structural qualification.
    #[cfg(feature = "structural-metrics")]
    pub fn new_structural<K: MethodKeyProvider>(
        keys: &K,
        random: &(impl SecureRandom + ?Sized),
        is_live: impl FnMut(&UdpSessionId) -> bool,
        structural: &StructuralLocal,
    ) -> Result<Self, UdpPacketError> {
        let session = Self::new(keys, random, is_live)?;
        if matches!(
            session.crypto.profile(),
            MethodProfile::Blake3Aes128Gcm2022 | MethodProfile::Blake3Aes256Gcm2022
        ) {
            structural.add(StructuralCounter::UdpAesBodyCipherConstructions, 1);
        }
        Ok(session)
    }

    /// Returns the opaque live ID for collision-safe process-local registration.
    pub const fn session_id(&self) -> &UdpSessionId {
        self.outbound.session_id()
    }

    /// Returns the exact output span required by one request for this session's method.
    ///
    /// This is mutation-free: callers can resize reusable storage to the returned
    /// logical length before calling [`Self::encode_request_parts`].
    pub fn request_wire_len(
        &self,
        target: &TargetAddr,
        payload_len: usize,
        padding_len: usize,
    ) -> Result<usize, UdpPacketError> {
        udp_wire_len(
            self.crypto.profile(),
            false,
            target,
            payload_len,
            padding_len,
        )
    }

    /// Encodes one request into caller-owned bounded output.
    pub fn encode_request(
        &mut self,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &Datagram,
        padding_len: usize,
        output: &mut [u8],
    ) -> Result<usize, UdpPacketError> {
        self.encode_request_parts(
            clock,
            random,
            datagram.target(),
            datagram.payload(),
            padding_len,
            output,
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
        )
    }

    /// Seals one request in the datagram's existing owned headroom without
    /// moving or copying its application payload.
    #[cfg(feature = "candidate-udp-owned-headroom")]
    pub fn encode_request_owned_headroom(
        &mut self,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &mut Datagram,
        padding_len: usize,
    ) -> Result<std::ops::Range<usize>, UdpPacketError> {
        encode_packet_owned_headroom(
            &self.crypto,
            &mut self.outbound,
            clock,
            random,
            REQUEST_TYPE,
            None,
            datagram,
            padding_len,
        )
    }

    /// Seals one owned-headroom request and records a zero-copy fast-path hit.
    #[cfg(all(
        feature = "candidate-udp-owned-headroom",
        feature = "structural-metrics"
    ))]
    pub fn encode_request_owned_headroom_structural(
        &mut self,
        clock: &(impl Clock + ?Sized),
        random: &(impl SecureRandom + ?Sized),
        datagram: &mut Datagram,
        padding_len: usize,
        structural: &StructuralLocal,
    ) -> Result<std::ops::Range<usize>, UdpPacketError> {
        let wire_range =
            self.encode_request_owned_headroom(clock, random, datagram, padding_len)?;
        structural.add(StructuralCounter::UdpOwnedFastPathHits, 1);
        Ok(wire_range)
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

    /// Destructively authenticates and validates an exclusively owned response wire.
    ///
    /// The semantic body stays inside the owned wire until timestamp, binding,
    /// target, and current replay checks pass. Payload materialization then
    /// splits the original allocation without a wire-to-scratch copy.
    pub fn prepare_response_owned(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: BytesMut,
    ) -> Result<PendingUdpResponse, UdpPacketError> {
        let opened = open_packet_owned(
            &self.crypto,
            clock,
            wire,
            RESPONSE_TYPE,
            Some(self.outbound.session_id()),
            |session_id| self.cached_response_cipher(session_id),
        )?;
        self.check_response_replay(opened.session_id(), opened.packet_id())?;
        let opened = opened.into_opened_packet()?;
        Ok(PendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
            aes_session_cipher: opened.aes_session_cipher,
        })
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
            |session_id| self.cached_response_cipher(session_id),
            |session_id, packet_id| self.check_response_replay(session_id, packet_id),
        )?;
        Ok(BorrowedPendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            target: opened.target,
            payload: opened.payload,
            aes_session_cipher: opened.aes_session_cipher,
        })
    }

    /// Destructively authenticates an exclusive response wire and returns guarded views.
    ///
    /// No association or replay state changes until the returned commit token is
    /// committed. Every authentication, semantic, binding, or replay failure
    /// clears the received wire before returning.
    pub fn prepare_response_in_place<'a>(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &'a mut BytesMut,
    ) -> Result<BorrowedPendingUdpResponse<'a>, UdpPacketError> {
        let opened = open_packet_in_place_borrowed(
            &self.crypto,
            clock,
            wire,
            RESPONSE_TYPE,
            Some(self.outbound.session_id()),
            |session_id| self.cached_response_cipher(session_id),
            |session_id, packet_id| self.check_response_replay(session_id, packet_id),
        )?;
        Ok(BorrowedPendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            target: opened.target,
            payload: opened.payload,
            aes_session_cipher: opened.aes_session_cipher,
        })
    }

    /// Opens one exclusively owned response and records accepted structural work.
    #[cfg(feature = "structural-metrics")]
    pub fn prepare_response_in_place_structural<'a>(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &'a mut BytesMut,
        structural: &StructuralLocal,
    ) -> Result<BorrowedPendingUdpResponse<'a>, UdpPacketError> {
        let pending = self.prepare_response_in_place(clock, wire)?;
        structural.add(StructuralCounter::UdpOwnedFastPathHits, 1);
        if pending.aes_session_cipher.is_some() {
            structural.add(StructuralCounter::UdpAesBodyCipherConstructions, 1);
        }
        Ok(pending)
    }

    fn check_response_replay(
        &self,
        session_id: &UdpSessionId,
        packet_id: u64,
    ) -> Result<(), UdpPacketError> {
        let associations = self
            .associations
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if let Some(association) = associations
            .current
            .as_ref()
            .filter(|association| association.session_id == *session_id)
            .or_else(|| {
                associations
                    .old
                    .as_ref()
                    .filter(|association| association.session_id == *session_id)
            })
        {
            association.replay.check(packet_id)?;
        }
        Ok(())
    }

    fn cached_response_cipher(
        &self,
        session_id: &UdpSessionId,
    ) -> Option<Arc<UdpAesSessionCipher>> {
        let associations = self.associations.lock().ok()?;
        associations
            .current
            .as_ref()
            .filter(|association| association.session_id == *session_id)
            .or_else(|| {
                associations
                    .old
                    .as_ref()
                    .filter(|association| association.session_id == *session_id)
            })?
            .aes_body_cipher
            .as_ref()
            .map(Arc::clone)
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
        #[cfg(feature = "structural-metrics")]
        let mut evidence = UdpProtocolStructuralEvidence::default();
        self.commit_response_inner(
            commit,
            now,
            #[cfg(feature = "structural-metrics")]
            &mut evidence,
        )
    }

    /// Commits one response and publishes its structural work once.
    #[cfg(feature = "structural-metrics")]
    pub fn commit_response_structural(
        &self,
        commit: UdpResponseCommit,
        now: MonotonicInstant,
        structural: &StructuralLocal,
    ) -> Result<(), UdpPacketError> {
        let mut evidence = UdpProtocolStructuralEvidence::default();
        let result = self.commit_response_inner(commit, now, &mut evidence);
        evidence.publish(structural);
        result
    }

    fn commit_response_inner(
        &self,
        commit: UdpResponseCommit,
        now: MonotonicInstant,
        #[cfg(feature = "structural-metrics")] evidence: &mut UdpProtocolStructuralEvidence,
    ) -> Result<(), UdpPacketError> {
        if commit.owner_id != *self.outbound.session_id() {
            return Err(UdpPacketError::Binding);
        }
        let mut associations = self
            .associations
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        commit_client_association(
            &self.crypto,
            &mut associations,
            commit.session_id,
            commit.packet_id,
            commit.aes_session_cipher,
            now,
            #[cfg(feature = "structural-metrics")]
            evidence,
        )
    }

    /// Atomically commits one ordered response transition per distinct client session.
    pub fn commit_responses(
        sessions: &[&Self],
        commits: Vec<UdpResponseCommit>,
        now: MonotonicInstant,
    ) -> Result<(), UdpPacketError> {
        #[cfg(feature = "structural-metrics")]
        let mut evidence = UdpProtocolStructuralEvidence::default();
        Self::commit_responses_inner(
            sessions,
            commits,
            now,
            #[cfg(feature = "structural-metrics")]
            &mut evidence,
        )
    }

    /// Atomically commits a response batch and publishes structural work once.
    #[cfg(feature = "structural-metrics")]
    pub fn commit_responses_structural(
        sessions: &[&Self],
        commits: Vec<UdpResponseCommit>,
        now: MonotonicInstant,
        structural: &StructuralLocal,
    ) -> Result<(), UdpPacketError> {
        let mut evidence = UdpProtocolStructuralEvidence::default();
        let result = Self::commit_responses_inner(sessions, commits, now, &mut evidence);
        evidence.publish(structural);
        result
    }

    fn commit_responses_inner(
        sessions: &[&Self],
        commits: Vec<UdpResponseCommit>,
        now: MonotonicInstant,
        #[cfg(feature = "structural-metrics")] evidence: &mut UdpProtocolStructuralEvidence,
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
        let mut transitions = sessions.iter().copied().zip(commits).collect::<Vec<_>>();
        // Borrowed sessions stay alive for the batch, so their addresses define one lock order.
        transitions.sort_unstable_by_key(|(session, _)| std::ptr::from_ref(*session) as usize);
        let (ordered_sessions, ordered_commits): (Vec<_>, Vec<_>) = transitions.into_iter().unzip();
        let mut guards = ordered_sessions
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
        for ((session, associations), commit) in ordered_sessions
            .iter()
            .zip(updated.iter_mut())
            .zip(ordered_commits)
        {
            commit_client_association(
                &session.crypto,
                associations,
                commit.session_id,
                commit.packet_id,
                commit.aes_session_cipher,
                now,
                #[cfg(feature = "structural-metrics")]
                evidence,
            )?;
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
    crypto: &UdpCrypto,
    associations: &mut ClientAssociations,
    session_id: UdpSessionId,
    packet_id: u64,
    aes_session_cipher: Option<UdpAesSessionCipher>,
    now: MonotonicInstant,
    #[cfg(feature = "structural-metrics")] evidence: &mut UdpProtocolStructuralEvidence,
) -> Result<(), UdpPacketError> {
    if let Some(current) = associations
        .current
        .as_mut()
        .filter(|association| association.session_id == session_id)
    {
        current.replay.commit(packet_id)?;
        #[cfg(feature = "structural-metrics")]
        evidence.observe_replay(&current.replay);
        current.last_valid = now;
        return Ok(());
    }
    if let Some(old) = associations
        .old
        .as_mut()
        .filter(|association| association.session_id == session_id)
    {
        old.replay.commit(packet_id)?;
        #[cfg(feature = "structural-metrics")]
        evidence.observe_replay(&old.replay);
        old.last_valid = now;
        return Ok(());
    }

    let mut replay = UdpReplayWindow::new();
    replay.commit(packet_id)?;
    #[cfg(feature = "structural-metrics")]
    evidence.observe_replay(&replay);
    #[cfg(feature = "structural-metrics")]
    let cold_miss_cipher = aes_session_cipher.is_some();
    let new = ClientAssociation {
        // Normal cold misses move their single authenticated derivation here.
        // Only a cache-hit prepare that raced with rotation needs one new
        // derivation for the replacement association.
        aes_body_cipher: aes_session_cipher
            .or_else(|| crypto.derive_aes_session_cipher(&session_id))
            .map(Arc::new),
        session_id,
        replay,
        last_valid: now,
    };
    #[cfg(feature = "structural-metrics")]
    if !cold_miss_cipher && new.aes_body_cipher.is_some() {
        evidence.aes_body_cipher_constructions =
            evidence.aes_body_cipher_constructions.saturating_add(1);
    }
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

/// Fully authenticated response awaiting its runtime-state commit.
pub struct PendingUdpResponse {
    owner_id: UdpSessionId,
    session_id: UdpSessionId,
    packet_id: u64,
    datagram: Datagram,
    aes_session_cipher: Option<UdpAesSessionCipher>,
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
                aes_session_cipher: self.aes_session_cipher,
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
    target: ValidatedTarget<'a>,
    payload: &'a [u8],
    aes_session_cipher: Option<UdpAesSessionCipher>,
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
            ValidatedTarget::Ip(SocketAddr::V4(_)) => 7,
            ValidatedTarget::Ip(SocketAddr::V6(_)) => 19,
            ValidatedTarget::Domain(host, _) => 4 + host.len(),
        }
    }

    /// Compares the authenticated target without allocating an owned address.
    pub fn target_matches(&self, expected: &TargetAddr) -> bool {
        match (&self.target, expected.host()) {
            (ValidatedTarget::Ip(actual), TargetHostRef::Ip(expected_ip)) => {
                actual.ip() == expected_ip && actual.port() == expected.port().get()
            }
            (ValidatedTarget::Domain(actual, port), TargetHostRef::Domain(expected_host)) => {
                *actual == expected_host && *port == expected.port().get()
            }
            (ValidatedTarget::Ip(_), TargetHostRef::Domain(_))
            | (ValidatedTarget::Domain(_, _), TargetHostRef::Ip(_)) => false,
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
            aes_session_cipher: self.aes_session_cipher,
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
            aes_session_cipher: self.aes_session_cipher,
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
    aes_session_cipher: Option<UdpAesSessionCipher>,
}

impl fmt::Debug for UdpResponseCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpResponseCommit([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ferrum2_crypto::{
        ClockError, MethodPsk, MethodSinglePskProvider, RandomError, SecureRandom,
    };

    use super::super::MAX_UDP_WIRE_LEN;
    use super::super::server::UdpServer;

    struct FixedClock;

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<u64, ClockError> {
            Ok(1_700_000_000)
        }

        fn monotonic_now(&self) -> MonotonicInstant {
            MonotonicInstant::ZERO
        }
    }

    struct SequenceRandom(Mutex<u8>);

    impl SequenceRandom {
        fn new(first: u8) -> Self {
            Self(Mutex::new(first))
        }
    }

    impl SecureRandom for SequenceRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
            let mut next = self.0.lock().expect("test random");
            destination.fill(*next);
            *next = next.wrapping_add(1);
            Ok(())
        }
    }

    #[cfg(feature = "structural-metrics")]
    #[test]
    fn structural_outbound_aes_constructs_once_and_chacha_constructs_none() {
        let structural = ferrum2_structural::StructuralHub::new();
        let local = structural.local();
        UdpClientSession::new_structural(
            &MethodSinglePskProvider::new(MethodPsk::aes128([0x47; 16])),
            &SequenceRandom::new(0x48),
            |_| false,
            &local,
        )
        .expect("structural AES client");
        UdpClientSession::new_structural(
            &MethodSinglePskProvider::new(MethodPsk::chacha20_poly1305([0x49; 32])),
            &SequenceRandom::new(0x4a),
            |_| false,
            &local,
        )
        .expect("structural ChaCha client");
        assert_eq!(
            structural
                .snapshot()
                .get(StructuralCounter::UdpAesBodyCipherConstructions),
            1,
        );
    }

    #[test]
    fn inbound_response_aes_miss_moves_one_cipher_and_established_hits_derive_none() {
        fn exercise(keys: MethodSinglePskProvider, expects_aes: bool) {
            let client_random = SequenceRandom::new(0x31);
            let server_random = SequenceRandom::new(0x91);
            let mut client = UdpClientSession::new(&keys, &client_random, |_| false)
                .expect("response cache client");
            let server = UdpServer::new(&keys).expect("response cache server");
            let target = TargetAddr::ip("192.0.2.1:53".parse().expect("response endpoint"))
                .expect("response target");
            let request = Datagram::new(target.clone(), BytesMut::from(&b"request"[..]), 7)
                .expect("request datagram");
            let mut request_wire = vec![
                0;
                client
                    .request_wire_len(request.target(), request.payload().len(), 0)
                    .expect("request wire length")
            ];
            let request_len = client
                .encode_request(&FixedClock, &client_random, &request, 0, &mut request_wire)
                .expect("request encode");
            request_wire.truncate(request_len);
            let mut scratch = UdpPacketScratch::new();
            let (_, request_commit) = server
                .prepare_request(&FixedClock, &request_wire, &mut scratch)
                .expect("request prepare")
                .into_parts();
            let capability = server
                .commit_request(
                    request_commit,
                    "127.0.0.1:49154".parse().expect("response peer"),
                    MonotonicInstant::ZERO,
                    &server_random,
                )
                .expect("request commit")
                .capability();

            let response = Datagram::new(target, BytesMut::from(&b"response"[..]), 8)
                .expect("response datagram");
            let mut dropped_wire = vec![0; MAX_UDP_WIRE_LEN];
            let dropped_len = server
                .encode_response(
                    capability,
                    &FixedClock,
                    &server_random,
                    &response,
                    0,
                    &mut dropped_wire,
                )
                .expect("dropped response")
                .wire_len();
            dropped_wire.truncate(dropped_len);
            let dropped = client
                .prepare_response_owned(&FixedClock, BytesMut::from(dropped_wire.as_slice()))
                .expect("dropped cold response");
            assert_eq!(dropped.aes_session_cipher.is_some(), expects_aes);
            drop(dropped);

            let mut first_wire = vec![0; MAX_UDP_WIRE_LEN];
            let first_len = server
                .encode_response(
                    capability,
                    &FixedClock,
                    &server_random,
                    &response,
                    0,
                    &mut first_wire,
                )
                .expect("first response")
                .wire_len();
            first_wire.truncate(first_len);
            let first = client
                .prepare_response_owned(&FixedClock, BytesMut::from(first_wire.as_slice()))
                .expect("cold response");
            assert_eq!(first.aes_session_cipher.is_some(), expects_aes);
            let (_, response_commit) = first.into_parts();
            client
                .commit_response(response_commit, MonotonicInstant::ZERO)
                .expect("cold response commit");

            let mut established_wire = vec![0; MAX_UDP_WIRE_LEN];
            let established_len = server
                .encode_response(
                    capability,
                    &FixedClock,
                    &server_random,
                    &response,
                    0,
                    &mut established_wire,
                )
                .expect("established response")
                .wire_len();
            established_wire.truncate(established_len);
            let established = client
                .prepare_response(&FixedClock, &established_wire, &mut scratch)
                .expect("established response open");
            assert!(established.aes_session_cipher.is_none());
        }

        exercise(
            MethodSinglePskProvider::new(MethodPsk::aes128([0x51; 16])),
            true,
        );
        exercise(
            MethodSinglePskProvider::new(MethodPsk::chacha20_poly1305([0x52; 32])),
            false,
        );

        let mut associations = ClientAssociations::default();
        let aes_keys = MethodSinglePskProvider::new(MethodPsk::aes128([0x63; 16]));
        let aes_random = SequenceRandom::new(0x64);
        let aes_session =
            UdpClientSession::new(&aes_keys, &aes_random, |_| false).expect("AES association ID");
        let aes_crypto = udp_crypto(&aes_keys).expect("AES association crypto");
        #[cfg(feature = "structural-metrics")]
        let mut evidence = UdpProtocolStructuralEvidence::default();
        commit_client_association(
            &aes_crypto,
            &mut associations,
            aes_session.session_id().clone(),
            0,
            None,
            MonotonicInstant::ZERO,
            #[cfg(feature = "structural-metrics")]
            &mut evidence,
        )
        .expect("cache-hit rotation derives one replacement AES token");
        assert!(
            associations
                .current
                .as_ref()
                .is_some_and(|association| association.aes_body_cipher.is_some())
        );
        let chacha_keys = MethodSinglePskProvider::new(MethodPsk::chacha20_poly1305([0x65; 32]));
        let chacha_random = SequenceRandom::new(0x66);
        let chacha_session = UdpClientSession::new(&chacha_keys, &chacha_random, |_| false)
            .expect("ChaCha association ID");
        let chacha_crypto = udp_crypto(&chacha_keys).expect("ChaCha association crypto");
        commit_client_association(
            &chacha_crypto,
            &mut associations,
            chacha_session.session_id().clone(),
            0,
            None,
            MonotonicInstant::ZERO,
            #[cfg(feature = "structural-metrics")]
            &mut evidence,
        )
        .expect("ChaCha association needs no AES token");
    }
}
