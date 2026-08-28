use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::{
    Clock, MethodKeyProvider, MonotonicInstant, SecureRandom, UdpCrypto, UdpOutboundSession,
    UdpSessionId,
};

use super::replay::UdpReplayWindow;
use super::wire::{
    encode_packet, open_packet_borrowed, open_packet_in_place_borrowed, open_packet_owned,
    udp_crypto,
};
use super::{UDP_ASSOCIATION_RETENTION, UdpPacketError, UdpPacketScratch};
use crate::tcp::wire::{REQUEST_TYPE, RESPONSE_TYPE, ValidatedTarget};

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
        )?;
        self.check_response_replay(opened.session_id(), opened.packet_id())?;
        let opened = opened.into_opened_packet()?;
        Ok(PendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
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
            |session_id, packet_id| self.check_response_replay(session_id, packet_id),
        )?;
        Ok(BorrowedPendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            target: opened.target,
            payload: opened.payload,
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
            |session_id, packet_id| self.check_response_replay(session_id, packet_id),
        )?;
        Ok(BorrowedPendingUdpResponse {
            owner_id: self.outbound.session_id().clone(),
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            target: opened.target,
            payload: opened.payload,
        })
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
        for (associations, commit) in updated.iter_mut().zip(ordered_commits) {
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
    target: ValidatedTarget<'a>,
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
