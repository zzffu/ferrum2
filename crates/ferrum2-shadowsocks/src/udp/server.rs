use std::collections::{HashMap, HashSet, hash_map::RandomState};
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use ferrum2_core::Datagram;
use ferrum2_crypto::{
    Clock, MethodKeyProvider, MonotonicInstant, SecureRandom, UdpAesSessionCipher, UdpCrypto,
    UdpOutboundSession, UdpSessionId,
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
    aes_session_cipher: Option<UdpAesSessionCipher>,
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
                aes_session_cipher: self.aes_session_cipher,
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
    aes_session_cipher: Option<UdpAesSessionCipher>,
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
    inbound_aes_body_cipher: Option<Arc<UdpAesSessionCipher>>,
    protocol: Arc<Mutex<ServerSession>>,
}

struct ServerSessionLookup {
    binding: UdpSessionId,
    protocol: Arc<Mutex<ServerSession>>,
}

enum SessionCreation {
    Created(ServerResponseCapability),
    Existing(ExistingServerSession),
}

struct ExistingServerSession {
    capability: ServerResponseCapability,
    protocol: Arc<Mutex<ServerSession>>,
}

#[derive(Default)]
struct InboundShard {
    // Hot lookups clone their Arc/cache and release this guard before taking
    // the per-session protocol mutex.
    sessions: HashMap<UdpSessionId, ServerSessionEntry>,
}

#[derive(Default)]
struct CapabilityShard {
    sessions: HashMap<ServerResponseCapability, ServerSessionLookup>,
}

struct CreationState {
    // Shared cold-index lock order is creation -> inbound shard -> capability
    // shard. Removal may already own its protocol mutex; no path holds a cold
    // index lock while waiting for a protocol mutex. Hot paths never acquire
    // this mutex.
    live_inbound_sessions: HashSet<UdpSessionId>,
    outbound_sessions: HashMap<UdpSessionId, ServerResponseCapability>,
    next_generation: u64,
}

impl Default for CreationState {
    fn default() -> Self {
        Self {
            live_inbound_sessions: HashSet::new(),
            outbound_sessions: HashMap::new(),
            next_generation: 1,
        }
    }
}

const UDP_SERVER_SHARD_COUNT: usize = 16;
const UDP_SERVER_SHARD_MASK: usize = UDP_SERVER_SHARD_COUNT - 1;
const _: () = assert!(UDP_SERVER_SHARD_COUNT.is_power_of_two());

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
    inbound_shards: [Mutex<InboundShard>; UDP_SERVER_SHARD_COUNT],
    capability_shards: [Mutex<CapabilityShard>; UDP_SERVER_SHARD_COUNT],
    creation: Mutex<CreationState>,
    inbound_shard_hasher: RandomState,
    session_count: AtomicUsize,
}

impl UdpServer {
    /// Creates protocol state without creating sockets or runtime resources.
    pub fn new<K: MethodKeyProvider>(keys: &K) -> Result<Self, UdpPacketError> {
        Ok(Self {
            crypto: udp_crypto(keys)?,
            inbound_shards: std::array::from_fn(|_| Mutex::new(InboundShard::default())),
            capability_shards: std::array::from_fn(|_| Mutex::new(CapabilityShard::default())),
            creation: Mutex::new(CreationState::default()),
            inbound_shard_hasher: RandomState::new(),
            session_count: AtomicUsize::new(0),
        })
    }

    fn inbound_shard_index(&self, session_id: &UdpSessionId) -> usize {
        self.inbound_shard_hasher.hash_one(session_id) as usize & UDP_SERVER_SHARD_MASK
    }

    const fn capability_shard_index(capability: ServerResponseCapability) -> usize {
        capability.slot as usize & UDP_SERVER_SHARD_MASK
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
            |session_id| self.cached_request_cipher(session_id),
            |session_id, packet_id| self.check_request_replay(session_id, packet_id),
        )?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
            aes_session_cipher: opened.aes_session_cipher,
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
        let opened = open_packet_owned(
            &self.crypto,
            clock,
            wire,
            REQUEST_TYPE,
            None,
            |session_id| self.cached_request_cipher(session_id),
        )?;
        self.check_request_replay(opened.session_id(), opened.packet_id())?;
        let opened = opened.into_opened_packet()?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
            aes_session_cipher: opened.aes_session_cipher,
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
            |session_id| self.cached_request_cipher(session_id),
            |session_id, packet_id| self.check_request_replay(session_id, packet_id),
        )?;
        Ok(PendingUdpRequest {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram: opened.datagram,
            aes_session_cipher: opened.aes_session_cipher,
        })
    }

    fn check_request_replay(
        &self,
        session_id: &UdpSessionId,
        packet_id: u64,
    ) -> Result<(), UdpPacketError> {
        let protocol = {
            let shard = self.inbound_shards[self.inbound_shard_index(session_id)]
                .lock()
                .map_err(|_| UdpPacketError::StateUnavailable)?;
            shard
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

    fn cached_request_cipher(&self, session_id: &UdpSessionId) -> Option<Arc<UdpAesSessionCipher>> {
        self.inbound_shards[self.inbound_shard_index(session_id)]
            .lock()
            .ok()?
            .sessions
            .get(session_id)?
            .inbound_aes_body_cipher
            .as_ref()
            .map(Arc::clone)
    }

    /// Looks up only the authenticated request identity without mutation.
    pub fn existing_capability(
        &self,
        pending: &PendingUdpRequest,
    ) -> Result<Option<ServerResponseCapability>, UdpPacketError> {
        let shard = self.inbound_shards[self.inbound_shard_index(&pending.session_id)]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(shard
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
            aes_session_cipher,
        } = commit;
        let mut aes_session_cipher = Some(aes_session_cipher);
        loop {
            if let Some(existing) = self.inbound_session(&session_id)? {
                if Self::commit_live_session(&existing.protocol, packet_id, peer, now)? {
                    return Ok(AcceptedUdpRequest {
                        capability: existing.capability,
                    });
                }
                continue;
            }
            let cold_miss_cipher = aes_session_cipher
                .take()
                .ok_or(UdpPacketError::Generation)?;
            match self.create_session(
                &session_id,
                packet_id,
                peer,
                now,
                random,
                cold_miss_cipher,
            )? {
                SessionCreation::Created(capability) => {
                    return Ok(AcceptedUdpRequest { capability });
                }
                SessionCreation::Existing(existing) => {
                    if Self::commit_live_session(&existing.protocol, packet_id, peer, now)? {
                        return Ok(AcceptedUdpRequest {
                            capability: existing.capability,
                        });
                    }
                    return Err(UdpPacketError::Generation);
                }
            }
        }
    }

    fn inbound_session(
        &self,
        session_id: &UdpSessionId,
    ) -> Result<Option<ExistingServerSession>, UdpPacketError> {
        let shard = self.inbound_shards[self.inbound_shard_index(session_id)]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        Ok(shard
            .sessions
            .get(session_id)
            .map(|entry| ExistingServerSession {
                capability: entry.capability,
                protocol: Arc::clone(&entry.protocol),
            }))
    }

    fn commit_live_session(
        protocol: &Arc<Mutex<ServerSession>>,
        packet_id: u64,
        peer: SocketAddr,
        now: MonotonicInstant,
    ) -> Result<bool, UdpPacketError> {
        let mut session = protocol
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if !session.live {
            return Ok(false);
        }
        session.replay.commit(packet_id)?;
        session.peer = peer;
        session.last_activity = now;
        Ok(true)
    }

    fn create_session(
        &self,
        session_id: &UdpSessionId,
        packet_id: u64,
        peer: SocketAddr,
        now: MonotonicInstant,
        random: &(impl SecureRandom + ?Sized),
        inbound_aes_body_cipher: Option<UdpAesSessionCipher>,
    ) -> Result<SessionCreation, UdpPacketError> {
        let mut creation = self
            .creation
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let inbound_index = self.inbound_shard_index(session_id);
        let mut inbound = self.inbound_shards[inbound_index]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if let Some(entry) = inbound.sessions.get(session_id) {
            return Ok(SessionCreation::Existing(ExistingServerSession {
                capability: entry.capability,
                protocol: Arc::clone(&entry.protocol),
            }));
        }
        if creation.live_inbound_sessions.contains(session_id) {
            return Err(UdpPacketError::StateUnavailable);
        }
        if creation.outbound_sessions.contains_key(session_id) {
            return Err(UdpPacketError::Generation);
        }
        let generation = creation.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(UdpPacketError::Generation)?;
        let outbound = self
            .crypto
            .generate_distinct_outbound_session(random, session_id, |candidate| {
                creation.live_inbound_sessions.contains(candidate)
                    || creation.outbound_sessions.contains_key(candidate)
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
        // Normal cold misses move their single authenticated derivation here.
        // Only a cache-hit prepare that raced with removal needs one new
        // derivation for the replacement generation.
        let inbound_aes_body_cipher = inbound_aes_body_cipher
            .or_else(|| self.crypto.derive_aes_session_cipher(session_id))
            .map(Arc::new);
        let capability_index = Self::capability_shard_index(capability);
        let mut capabilities = self.capability_shards[capability_index]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        if capabilities.sessions.contains_key(&capability) {
            return Err(UdpPacketError::StateUnavailable);
        }

        creation.next_generation = next_generation;
        let inbound_registered = creation.live_inbound_sessions.insert(session_id.clone());
        let previous_outbound = creation
            .outbound_sessions
            .insert(outbound_session_id.clone(), capability);
        let previous_session = inbound.sessions.insert(
            session_id.clone(),
            ServerSessionEntry {
                capability,
                outbound_session_id,
                inbound_aes_body_cipher,
                protocol: Arc::clone(&protocol),
            },
        );
        let previous_capability = capabilities.sessions.insert(
            capability,
            ServerSessionLookup {
                binding: session_id.clone(),
                protocol,
            },
        );
        debug_assert!(inbound_registered);
        debug_assert!(previous_outbound.is_none());
        debug_assert!(previous_session.is_none());
        debug_assert!(previous_capability.is_none());
        self.session_count.fetch_add(1, Ordering::Release);
        Ok(SessionCreation::Created(capability))
    }

    /// Commits only an already-existing request generation selected by the caller.
    ///
    /// Missing, replaced, or closed generations fail before replay, peer, or
    /// activity mutation. This path never creates a protocol generation.
    pub fn commit_existing_request(
        &self,
        commit: UdpRequestCommit,
        expected_capability: ServerResponseCapability,
        peer: SocketAddr,
        now: MonotonicInstant,
    ) -> Result<AcceptedUdpRequest, UdpPacketError> {
        let protocol = {
            let shard = self.inbound_shards[self.inbound_shard_index(&commit.session_id)]
                .lock()
                .map_err(|_| UdpPacketError::StateUnavailable)?;
            let entry = shard
                .sessions
                .get(&commit.session_id)
                .filter(|entry| entry.capability == expected_capability)
                .ok_or(UdpPacketError::Generation)?;
            Arc::clone(&entry.protocol)
        };
        if !Self::commit_live_session(&protocol, commit.packet_id, peer, now)? {
            return Err(UdpPacketError::Generation);
        }
        Ok(AcceptedUdpRequest {
            capability: expected_capability,
        })
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

        let mut creation = self
            .creation
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let inbound_index = self.inbound_shard_index(&binding);
        let capability_index = Self::capability_shard_index(capability);
        let mut inbound = self.inbound_shards[inbound_index]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let mut capabilities = self.capability_shards[capability_index]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let reverse_matches = capabilities.sessions.get(&capability).is_some_and(|entry| {
            entry.binding == binding && Arc::ptr_eq(&entry.protocol, &protocol)
        });
        let session_matches = inbound.sessions.get(&binding).is_some_and(|entry| {
            entry.capability == capability && Arc::ptr_eq(&entry.protocol, &protocol)
        });
        if !reverse_matches || !session_matches {
            return Ok(false);
        }

        let outbound_session_id = inbound
            .sessions
            .get(&binding)
            .expect("validated server session entry")
            .outbound_session_id
            .clone();
        let inbound_registered = creation.live_inbound_sessions.contains(&binding);
        let outbound_matches = creation
            .outbound_sessions
            .get(&outbound_session_id)
            .is_some_and(|current| *current == capability);
        if !inbound_registered || !outbound_matches {
            return Err(UdpPacketError::StateUnavailable);
        }

        session.live = false;
        let removed_capability = capabilities.sessions.remove(&capability);
        let removed_session = inbound.sessions.remove(&binding);
        let removed_inbound = creation.live_inbound_sessions.remove(&binding);
        let removed_outbound = creation.outbound_sessions.remove(&outbound_session_id);
        debug_assert!(removed_capability.is_some());
        debug_assert!(removed_session.is_some());
        debug_assert!(removed_inbound);
        debug_assert_eq!(removed_outbound, Some(capability));
        let previous_count = self.session_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous_count != 0);
        drop(capabilities);
        drop(inbound);
        drop(creation);
        drop(removed_capability);
        drop(removed_session);
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
        Ok(self.session_count.load(Ordering::Acquire))
    }

    fn session_by_capability(
        &self,
        capability: ServerResponseCapability,
    ) -> Result<Option<ServerSessionLookup>, UdpPacketError> {
        let shard = self.capability_shards[Self::capability_shard_index(capability)]
            .lock()
            .map_err(|_| UdpPacketError::StateUnavailable)?;
        let Some(entry) = shard.sessions.get(&capability) else {
            return Ok(None);
        };
        Ok(Some(ServerSessionLookup {
            binding: entry.binding.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    use ferrum2_core::TargetAddr;
    use ferrum2_crypto::{
        ClockError, MethodPsk, MethodSinglePskProvider, RandomError, SecureRandom,
    };

    use super::super::client::UdpClientSession;

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

    fn keys() -> MethodSinglePskProvider {
        MethodSinglePskProvider::new(MethodPsk::aes128([0x41; 16]))
    }

    fn chacha_keys() -> MethodSinglePskProvider {
        MethodSinglePskProvider::new(MethodPsk::chacha20_poly1305([0x42; 32]))
    }

    fn client_for(byte: u8) -> (UdpClientSession, SequenceRandom) {
        let keys = keys();
        let random = SequenceRandom::new(byte);
        let client = UdpClientSession::new(&keys, &random, |_| false).expect("test client session");
        (client, random)
    }

    fn request(client: &mut UdpClientSession, random: &SequenceRandom, payload: &[u8]) -> Vec<u8> {
        let target =
            TargetAddr::ip("192.0.2.1:53".parse().expect("test endpoint")).expect("test target");
        let datagram =
            Datagram::new(target, BytesMut::from(payload), payload.len()).expect("test datagram");
        let exact = client
            .request_wire_len(datagram.target(), payload.len(), 0)
            .expect("exact request length");
        let mut wire = vec![0; exact];
        let encoded = client
            .encode_request(&FixedClock, random, &datagram, 0, &mut wire)
            .expect("request encoding");
        wire.truncate(encoded);
        wire
    }

    fn establish(
        server: &UdpServer,
        client: &mut UdpClientSession,
        client_random: &SequenceRandom,
        server_random: &SequenceRandom,
        peer: SocketAddr,
    ) -> ServerResponseCapability {
        let wire = request(client, client_random, b"establish");
        let mut scratch = UdpPacketScratch::new();
        let (_, commit) = server
            .prepare_request(&FixedClock, &wire, &mut scratch)
            .expect("request prepare")
            .into_parts();
        server
            .commit_request(commit, peer, MonotonicInstant::ZERO, server_random)
            .expect("request commit")
            .capability()
    }

    fn pending(
        server: &UdpServer,
        client: &mut UdpClientSession,
        random: &SequenceRandom,
    ) -> PendingUdpRequest {
        let wire = request(client, random, b"lookup");
        let mut scratch = UdpPacketScratch::new();
        server
            .prepare_request(&FixedClock, &wire, &mut scratch)
            .expect("lookup prepare")
    }

    #[test]
    fn inbound_aes_miss_moves_one_cipher_into_the_session_and_established_hits_derive_none() {
        fn exercise(keys: MethodSinglePskProvider, expects_aes: bool) {
            let server = UdpServer::new(&keys).expect("cache handoff server");
            let client_random = SequenceRandom::new(0x21);
            let server_random = SequenceRandom::new(0x81);
            let mut client = UdpClientSession::new(&keys, &client_random, |_| false)
                .expect("cache handoff client");
            let peer = "127.0.0.1:49153".parse().expect("cache handoff peer");
            let dropped_wire = request(&mut client, &client_random, b"dropped");
            let mut scratch = UdpPacketScratch::new();
            let dropped = server
                .prepare_request(&FixedClock, &dropped_wire, &mut scratch)
                .expect("dropped cold request");
            assert_eq!(dropped.aes_session_cipher.is_some(), expects_aes);
            drop(dropped);

            let first_wire = request(&mut client, &client_random, b"cold");
            let first = server
                .prepare_request(&FixedClock, &first_wire, &mut scratch)
                .expect("cold request");
            assert_eq!(first.aes_session_cipher.is_some(), expects_aes);
            let (_, commit) = first.into_parts();
            let capability = server
                .commit_request(commit, peer, MonotonicInstant::ZERO, &server_random)
                .expect("cold request commit")
                .capability();

            let established_wire = request(&mut client, &client_random, b"established");
            let established = server
                .prepare_request(&FixedClock, &established_wire, &mut scratch)
                .expect("established request");
            assert!(established.aes_session_cipher.is_none());
            if expects_aes {
                let (_, stale_commit) = established.into_parts();
                assert!(
                    server
                        .remove_session(
                            capability,
                            MonotonicInstant::from_duration(Duration::from_secs(60)),
                        )
                        .expect("remove cached generation")
                );
                server
                    .commit_request(
                        stale_commit,
                        peer,
                        MonotonicInstant::from_duration(Duration::from_secs(60)),
                        &server_random,
                    )
                    .expect("cache-hit removal race recreates one cached generation");
                let retried = server
                    .prepare_request(&FixedClock, &established_wire, &mut scratch)
                    .expect_err("committed packet remains replay protected");
                assert_eq!(retried, UdpPacketError::Duplicate);

                let next_wire = request(&mut client, &client_random, b"replacement-established");
                let replacement = server
                    .prepare_request(&FixedClock, &next_wire, &mut scratch)
                    .expect("replacement established request");
                assert!(replacement.aes_session_cipher.is_none());
            }
        }

        exercise(keys(), true);
        exercise(chacha_keys(), false);
    }

    #[test]
    fn blocked_inbound_shard_does_not_serialize_a_different_shard() {
        let server = UdpServer::new(&keys()).expect("server");
        let base_byte = 1_u8;
        let (base_probe, _) = client_for(base_byte);
        let base_shard = server.inbound_shard_index(base_probe.session_id());
        let mut same_byte = None;
        let mut different_byte = None;
        for byte in 2_u8..=u8::MAX {
            let (probe, _) = client_for(byte);
            if server.inbound_shard_index(probe.session_id()) == base_shard {
                same_byte.get_or_insert(byte);
            } else {
                different_byte.get_or_insert(byte);
            }
            if same_byte.is_some() && different_byte.is_some() {
                break;
            }
        }
        let (mut base, base_random) = client_for(base_byte);
        let (mut same, same_random) = client_for(same_byte.expect("same-shard session"));
        let (mut different, different_random) =
            client_for(different_byte.expect("different-shard session"));
        let server_random = SequenceRandom::new(0x80);
        let peer = "127.0.0.1:49152".parse().expect("peer");
        establish(&server, &mut base, &base_random, &server_random, peer);
        establish(&server, &mut same, &same_random, &server_random, peer);
        establish(
            &server,
            &mut different,
            &different_random,
            &server_random,
            peer,
        );
        let same_pending = pending(&server, &mut same, &same_random);
        let different_pending = pending(&server, &mut different, &different_random);
        let locked = server.inbound_shards[base_shard]
            .lock()
            .expect("locked test shard");

        std::thread::scope(|scope| {
            let (started_tx, started_rx) = mpsc::channel();
            let (completed_tx, completed_rx) = mpsc::channel();
            let different_server = &server;
            let different_completed = completed_tx.clone();
            scope.spawn(move || {
                started_tx.send("different").expect("started receiver");
                different_completed
                    .send((
                        "different",
                        different_server.existing_capability(&different_pending),
                    ))
                    .expect("completion receiver");
            });
            assert_eq!(
                started_rx.recv_timeout(Duration::from_secs(5)),
                Ok("different")
            );
            let (label, result) = completed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("different shard must progress");
            assert_eq!(label, "different");
            assert!(result.expect("different lookup").is_some());

            let (same_started_tx, same_started_rx) = mpsc::channel();
            let same_server = &server;
            scope.spawn(move || {
                same_started_tx.send(()).expect("started receiver");
                completed_tx
                    .send(("same", same_server.existing_capability(&same_pending)))
                    .expect("completion receiver");
            });
            same_started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("same shard worker starts");
            assert!(
                completed_rx
                    .recv_timeout(Duration::from_millis(100))
                    .is_err(),
                "same-shard lookup must remain serialized"
            );
            drop(locked);
            let (label, result) = completed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("same shard resumes");
            assert_eq!(label, "same");
            assert!(result.expect("same lookup").is_some());
        });
    }
}
