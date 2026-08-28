use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::Datagram;
use ferrum2_crypto::{
    Clock, MethodKeyProvider, MonotonicInstant, SecureRandom, UdpCrypto, UdpOutboundSession,
    UdpSessionId,
};

use super::replay::UdpReplayWindow;
use super::wire::{
    encode_packet, open_packet, open_packet_in_place, open_packet_owned, udp_crypto,
};
use super::{UDP_ASSOCIATION_RETENTION, UdpPacketError, UdpPacketScratch};
use crate::tcp::wire::{REQUEST_TYPE, RESPONSE_TYPE};

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
    outbound: UdpOutboundSession,
    replay: UdpReplayWindow,
    peer: SocketAddr,
    last_activity: MonotonicInstant,
    // Lookups may retain this owner after map removal; the flag closes that race.
    live: bool,
}

struct ServerSessionEntry {
    capability: ServerResponseCapability,
    outbound_session_id: UdpSessionId,
    protocol: Arc<Mutex<ServerSession>>,
}

struct ServerSessionLookup {
    binding: UdpSessionId,
    protocol: Arc<Mutex<ServerSession>>,
}

struct ServerState {
    // Never acquire a per-session protocol lock while holding this map lock.
    // Removal uses the inverse order and rechecks both indexes before unlinking.
    sessions: HashMap<UdpSessionId, ServerSessionEntry>,
    capability_sessions: HashMap<ServerResponseCapability, UdpSessionId>,
    outbound_sessions: HashMap<UdpSessionId, ServerResponseCapability>,
    next_generation: u64,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            capability_sessions: HashMap::new(),
            outbound_sessions: HashMap::new(),
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
        let opened = open_packet(
            &self.crypto,
            clock,
            wire,
            scratch,
            REQUEST_TYPE,
            None,
            |session_id, packet_id| self.check_request_replay(session_id, packet_id),
        )?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
        })
    }

    /// Destructively authenticates and validates one exclusively owned request wire.
    ///
    /// The semantic body remains guarded inside the owned wire through target,
    /// timestamp, and current replay validation. Successful materialization
    /// splits the payload from that allocation without copying it.
    pub fn prepare_request_owned(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: BytesMut,
    ) -> Result<PendingUdpRequest, UdpPacketError> {
        let opened = open_packet_owned(&self.crypto, clock, wire, REQUEST_TYPE, None)?;
        self.check_request_replay(opened.session_id(), opened.packet_id())?;
        let opened = opened.into_opened_packet()?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
        })
    }

    /// Destructively authenticates an exclusive receive wire and materializes
    /// only the authenticated payload bytes.
    ///
    /// The receive allocation remains caller-owned and is logically cleared
    /// on success. Rejected candidate plaintext is physically cleared, while
    /// accepted replay/session state still changes only in [`Self::commit_request`].
    pub fn prepare_request_in_place(
        &self,
        clock: &(impl Clock + ?Sized),
        wire: &mut BytesMut,
    ) -> Result<PendingUdpRequest, UdpPacketError> {
        let opened = open_packet_in_place(
            &self.crypto,
            clock,
            wire,
            REQUEST_TYPE,
            None,
            |session_id, packet_id| self.check_request_replay(session_id, packet_id),
        )?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
        })
    }

    fn check_request_replay(
        &self,
        session_id: &UdpSessionId,
        packet_id: u64,
    ) -> Result<(), UdpPacketError> {
        let protocol = {
            let state = self
                .state
                .lock()
                .map_err(|_| UdpPacketError::StateUnavailable)?;
            state
                .sessions
                .get(session_id)
                .map(|entry| Arc::clone(&entry.protocol))
        };
        if let Some(protocol) = protocol {
            let session = protocol
                .lock()
                .map_err(|_| UdpPacketError::StateUnavailable)?;
            if session.live {
                session.replay.check(packet_id)?;
            }
        }
        Ok(())
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
            .map(|entry| entry.capability))
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
        let UdpRequestCommit {
            session_id,
            packet_id,
        } = commit;
        loop {
            let existing = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| UdpPacketError::StateUnavailable)?;
                if let Some(entry) = state.sessions.get(&session_id) {
                    Some((entry.capability, Arc::clone(&entry.protocol)))
                } else {
                    let generation = state.next_generation;
                    let next_generation = state
                        .next_generation
                        .checked_add(1)
                        .ok_or(UdpPacketError::Generation)?;
                    let outbound = self
                        .crypto
                        .generate_distinct_outbound_session(random, &session_id, |candidate| {
                            state.sessions.contains_key(candidate)
                                || state.outbound_sessions.contains_key(candidate)
                        })
                        .map_err(|_| UdpPacketError::Random)?;
                    let outbound_session_id = outbound.session_id().clone();
                    let mut replay = UdpReplayWindow::new();
                    replay.commit(packet_id)?;
                    let capability = ServerResponseCapability {
                        slot: generation,
                        generation,
                    };
                    let protocol = Arc::new(Mutex::new(ServerSession {
                        outbound,
                        replay,
                        peer,
                        last_activity: now,
                        live: true,
                    }));
                    state.next_generation = next_generation;
                    let previous_capability = state
                        .capability_sessions
                        .insert(capability, session_id.clone());
                    let previous_session = state.sessions.insert(
                        session_id.clone(),
                        ServerSessionEntry {
                            capability,
                            outbound_session_id: outbound_session_id.clone(),
                            protocol,
                        },
                    );
                    let previous_outbound = state
                        .outbound_sessions
                        .insert(outbound_session_id, capability);
                    debug_assert!(previous_capability.is_none());
                    debug_assert!(previous_session.is_none());
                    debug_assert!(previous_outbound.is_none());
                    debug_assert_eq!(state.capability_sessions.len(), state.sessions.len());
                    debug_assert_eq!(state.outbound_sessions.len(), state.sessions.len());
                    return Ok(AcceptedUdpRequest { capability });
                }
            };

            let (capability, protocol) = existing.expect("existing session branch");
            let mut session = protocol
                .lock()
                .map_err(|_| UdpPacketError::StateUnavailable)?;
            if !session.live {
                continue;
            }
            session.replay.commit(packet_id)?;
            session.peer = peer;
            session.last_activity = now;
            return Ok(AcceptedUdpRequest { capability });
        }
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
    ) -> Result<EncodedUdpResponse, UdpPacketError> {
        let ServerSessionLookup { binding, protocol } = self
            .session_by_capability(capability)?
            .ok_or(UdpPacketError::Generation)?;
        let mut session = protocol
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if !session.live {
            return Err(UdpPacketError::Generation);
        }
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
        let Some(ServerSessionLookup { binding, protocol }) =
            self.session_by_capability(capability)?
        else {
            return Ok(false);
        };
        let mut session = protocol
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if !session.live
            || !now
                .duration_since(session.last_activity)
                .is_some_and(|age| age >= UDP_ASSOCIATION_RETENTION)
        {
            return Ok(false);
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let reverse_matches = state
            .capability_sessions
            .get(&capability)
            .is_some_and(|current| *current == binding);
        let session_matches = state.sessions.get(&binding).is_some_and(|entry| {
            entry.capability == capability && Arc::ptr_eq(&entry.protocol, &protocol)
        });
        if !reverse_matches || !session_matches {
            return Ok(false);
        }

        let outbound_session_id = state
            .sessions
            .get(&binding)
            .expect("validated server session entry")
            .outbound_session_id
            .clone();
        let outbound_matches = state
            .outbound_sessions
            .get(&outbound_session_id)
            .is_some_and(|current| *current == capability);
        if !outbound_matches {
            return Err(UdpPacketError::StateUnavailable);
        }

        let removed_capability = state.capability_sessions.remove(&capability);
        let removed_session = state.sessions.remove(&binding);
        let removed_outbound = state.outbound_sessions.remove(&outbound_session_id);
        debug_assert!(removed_capability.is_some());
        debug_assert!(removed_session.is_some());
        debug_assert_eq!(removed_outbound, Some(capability));
        debug_assert_eq!(state.capability_sessions.len(), state.sessions.len());
        debug_assert_eq!(state.outbound_sessions.len(), state.sessions.len());
        session.live = false;
        Ok(true)
    }

    /// Returns a redacted live-generation snapshot.
    pub fn session_snapshot(
        &self,
        capability: ServerResponseCapability,
    ) -> Result<Option<ServerSessionSnapshot>, UdpPacketError> {
        let Some(ServerSessionLookup { protocol, .. }) = self.session_by_capability(capability)?
        else {
            return Ok(None);
        };
        let session = protocol
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(session.live.then(|| ServerSessionSnapshot {
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

    fn session_by_capability(
        &self,
        capability: ServerResponseCapability,
    ) -> Result<Option<ServerSessionLookup>, UdpPacketError> {
        let state = self
            .state
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let Some(binding) = state.capability_sessions.get(&capability) else {
            return Ok(None);
        };
        let entry = state
            .sessions
            .get(binding)
            .filter(|entry| entry.capability == capability)
            .ok_or(UdpPacketError::StateUnavailable)?;
        Ok(Some(ServerSessionLookup {
            binding: binding.clone(),
            protocol: Arc::clone(&entry.protocol),
        }))
    }
}

impl fmt::Debug for UdpServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UdpServer([redacted])")
    }
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
