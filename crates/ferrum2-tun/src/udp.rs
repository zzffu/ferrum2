// Public bridge types still compile on unsupported hosts; their owner half is unreachable there.
#![cfg_attr(not(any(all(windows, target_arch = "x86_64"), test)), allow(dead_code))]

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as sync_mpsc};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::{OwnerWake, TunEvent, TunEventSink, TunRejectReason};

const DATAGRAM_QUEUE_PACKETS: usize = 8;
const RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION: usize = 8;
#[cfg(test)]
const OWNER_EVENT_QUANTUM: usize = 8;
const CANDIDATE_TIMEOUT_MILLIS: i64 = 5_000;

/// Fixed maximum number of address-dependent peers retained by one association.
pub const UDP_ADF_PEER_CAP: usize = 256;

/// Immutable endpoints for one UDP datagram.
///
/// This remains as a compatibility view for the current packet builder. It is
/// never used as the association-table key; only `source` is indexed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpTuple {
    source: SocketAddr,
    target: SocketAddr,
}

impl UdpTuple {
    pub(crate) const fn new(source: SocketAddr, target: SocketAddr) -> Self {
        Self { source, target }
    }

    /// Local application endpoint captured from the validated packet.
    pub const fn source(self) -> SocketAddr {
        self.source
    }

    /// Actual target of this individual datagram.
    pub const fn target(self) -> SocketAddr {
        self.target
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct GenerationId {
    pub(crate) slot: usize,
    pub(crate) generation: u32,
}

pub(crate) struct GenerationTable {
    pub(crate) slots: Box<[u32]>,
}

impl GenerationTable {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            slots: vec![0; capacity].into_boxed_slice(),
        }
    }

    pub(crate) fn current(&self, slot: usize) -> Option<GenerationId> {
        self.slots
            .get(slot)
            .copied()
            .filter(|generation| *generation != u32::MAX)
            .map(|generation| GenerationId { slot, generation })
    }

    pub(crate) fn recycle(&mut self, id: GenerationId) -> bool {
        let Some(generation) = self.slots.get_mut(id.slot) else {
            return false;
        };
        if *generation != id.generation {
            return false;
        }
        let Some(next) = generation.checked_add(1) else {
            return false;
        };
        *generation = next;
        true
    }
}

/// UDP response filtering applied independently of endpoint-independent mapping.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UdpFiltering {
    /// Accept responses only from an IP address explicitly authorized after send.
    #[default]
    AddressDependent,
    /// Accept responses from any valid same-family unicast endpoint.
    EndpointIndependent,
}

/// Result of authorizing one address-dependent peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpPeerAuthorization {
    Authorized,
    AlreadyAuthorized,
    NotRequired,
    InvalidPeer,
    LimitReached,
}

/// Result of reserving one ADF peer before an outbound datagram is sent.
pub enum UdpPeerReservationOutcome {
    Reserved(UdpPeerReservation),
    AlreadyAuthorized,
    NotRequired,
    InvalidPeer,
    LimitReached,
}

/// Result of queueing one response for owner-thread injection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpResponseSendOutcome {
    Queued,
    QueueFull,
    Filtered,
    InvalidSource,
    PayloadTooLarge,
    StaleGeneration,
    Closed,
}

/// Explicit result returned by the packet-output injection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InjectOutcome {
    Injected,
    Backpressured,
    Rejected(TunRejectReason),
}

/// One complete application datagram delivered in EIM-association order.
pub struct UdpDatagram {
    source: SocketAddr,
    target: SocketAddr,
    payload: Arc<[u8]>,
}

impl UdpDatagram {
    /// Local application source which is also the EIM association key.
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Per-datagram target; it is never frozen at association creation.
    pub const fn target(&self) -> SocketAddr {
        self.target
    }

    /// Compatibility endpoint view for the current client migration.
    pub const fn tuple(&self) -> UdpTuple {
        UdpTuple::new(self.source, self.target)
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum LeasePhase {
    Candidate = 0,
    CommitPending = 1,
    Association = 2,
    Closed = 3,
}

impl LeasePhase {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Candidate,
            1 => Self::CommitPending,
            2 => Self::Association,
            _ => Self::Closed,
        }
    }
}

struct CommitRequest {
    selected_payload_bound: usize,
    reply: oneshot::Sender<Result<(), UdpCommitError>>,
}

#[derive(Clone, Copy)]
struct ControlNotice {
    id: GenerationId,
    session_generation: u64,
}

struct AssociationLease {
    id: GenerationId,
    session_generation: u64,
    session_epoch: Arc<AtomicU64>,
    phase: AtomicU8,
    commit: Mutex<Option<CommitRequest>>,
    controls: sync_mpsc::Sender<ControlNotice>,
    wake: OwnerWake,
    events: TunEventSink,
}

impl AssociationLease {
    fn new(
        id: GenerationId,
        session_generation: u64,
        session_epoch: Arc<AtomicU64>,
        controls: sync_mpsc::Sender<ControlNotice>,
        wake: OwnerWake,
        events: TunEventSink,
    ) -> Self {
        Self {
            id,
            session_generation,
            session_epoch,
            phase: AtomicU8::new(LeasePhase::Candidate as u8),
            commit: Mutex::new(None),
            controls,
            wake,
            events,
        }
    }

    fn phase(&self) -> LeasePhase {
        LeasePhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    fn is_stale(&self) -> bool {
        self.session_epoch.load(Ordering::Acquire) != self.session_generation
    }

    fn notify(&self) -> Result<(), ()> {
        self.controls
            .send(ControlNotice {
                id: self.id,
                session_generation: self.session_generation,
            })
            .map_err(|_| ())?;
        self.wake.signal();
        Ok(())
    }

    fn request_commit(
        &self,
        selected_payload_bound: usize,
    ) -> Result<oneshot::Receiver<Result<(), UdpCommitError>>, UdpCommitError> {
        if self.is_stale() || self.phase() != LeasePhase::Candidate {
            if self.is_stale() {
                self.events.emit(TunEvent::UdpStaleGeneration);
                self.events
                    .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            }
            return Err(UdpCommitError::Rejected);
        }
        let (reply, receive) = oneshot::channel();
        {
            let mut commit = lock_unpoisoned(&self.commit);
            if commit.is_some() || self.phase() != LeasePhase::Candidate {
                return Err(UdpCommitError::Rejected);
            }
            *commit = Some(CommitRequest {
                selected_payload_bound,
                reply,
            });
        }
        if self
            .phase
            .compare_exchange(
                LeasePhase::Candidate as u8,
                LeasePhase::CommitPending as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            let _ = lock_unpoisoned(&self.commit).take();
            return Err(UdpCommitError::Rejected);
        }
        if self.notify().is_err() {
            self.owner_close();
            return Err(UdpCommitError::Unavailable);
        }
        Ok(receive)
    }

    fn take_commit(&self) -> Option<CommitRequest> {
        lock_unpoisoned(&self.commit).take()
    }

    fn mark_live(&self) -> bool {
        self.phase
            .compare_exchange(
                LeasePhase::CommitPending as u8,
                LeasePhase::Association as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn close(&self) {
        if self.phase.swap(LeasePhase::Closed as u8, Ordering::AcqRel) != LeasePhase::Closed as u8
            && self.notify().is_err()
            && let Some(commit) = self.take_commit()
        {
            let _ = commit.reply.send(Err(UdpCommitError::Unavailable));
        }
    }

    fn owner_close(&self) {
        self.phase
            .store(LeasePhase::Closed as u8, Ordering::Release);
        if let Some(commit) = self.take_commit() {
            let _ = commit.reply.send(Err(UdpCommitError::Rejected));
        }
    }
}

struct PeerPolicy {
    filtering: UdpFiltering,
    local_ip: IpAddr,
    peers: Mutex<PeerEntries>,
}

struct PeerEntries {
    authorized: HashSet<IpAddr>,
    reserved: HashMap<IpAddr, usize>,
}

impl PeerPolicy {
    fn new(filtering: UdpFiltering, local_ip: IpAddr) -> Self {
        Self {
            filtering,
            local_ip,
            peers: Mutex::new(PeerEntries {
                authorized: HashSet::with_capacity(UDP_ADF_PEER_CAP),
                reserved: HashMap::new(),
            }),
        }
    }

    fn authorize(&self, peer: IpAddr) -> UdpPeerAuthorization {
        if !same_ip_family(self.local_ip, peer) || !valid_unicast_ip(peer) {
            return UdpPeerAuthorization::InvalidPeer;
        }
        if self.filtering == UdpFiltering::EndpointIndependent {
            return UdpPeerAuthorization::NotRequired;
        }
        let mut peers = lock_unpoisoned(&self.peers);
        if peers.authorized.contains(&peer) {
            return UdpPeerAuthorization::AlreadyAuthorized;
        }
        if peers.authorized.len() + peers.reserved.len() == UDP_ADF_PEER_CAP
            && !peers.reserved.contains_key(&peer)
        {
            return UdpPeerAuthorization::LimitReached;
        }
        peers.reserved.remove(&peer);
        peers.authorized.insert(peer);
        UdpPeerAuthorization::Authorized
    }

    fn finish_reservation(&self, peer: IpAddr, authorize: bool) -> UdpPeerAuthorization {
        let mut peers = lock_unpoisoned(&self.peers);
        if peers.authorized.contains(&peer) {
            return UdpPeerAuthorization::AlreadyAuthorized;
        }
        let Some(count) = peers.reserved.get_mut(&peer) else {
            return UdpPeerAuthorization::LimitReached;
        };
        if authorize {
            peers.reserved.remove(&peer);
            peers.authorized.insert(peer);
            UdpPeerAuthorization::Authorized
        } else {
            *count -= 1;
            if *count == 0 {
                peers.reserved.remove(&peer);
            }
            UdpPeerAuthorization::LimitReached
        }
    }

    fn allows(&self, source: SocketAddr) -> Result<bool, ()> {
        if source.port() == 0
            || !same_ip_family(self.local_ip, source.ip())
            || !valid_unicast_ip(source.ip())
        {
            return Err(());
        }
        Ok(self.filtering == UdpFiltering::EndpointIndependent
            || lock_unpoisoned(&self.peers)
                .authorized
                .contains(&source.ip()))
    }
}

/// A unique-capacity ADF reservation which authorizes only after explicit commit.
#[must_use = "an uncommitted UDP peer reservation is released on drop"]
pub struct UdpPeerReservation {
    policy: Arc<PeerPolicy>,
    peer: IpAddr,
    active: bool,
}

impl UdpPeerReservation {
    pub fn commit(mut self) -> UdpPeerAuthorization {
        self.active = false;
        self.policy.finish_reservation(self.peer, true)
    }
}

impl Drop for UdpPeerReservation {
    fn drop(&mut self) {
        if self.active {
            let _ = self.policy.finish_reservation(self.peer, false);
        }
    }
}

/// Cloneable handle used to authorize ADF peers only after outbound acceptance.
#[derive(Clone)]
pub struct UdpPeerPolicyHandle {
    inner: Arc<PeerPolicy>,
}

impl UdpPeerPolicyHandle {
    pub fn filtering(&self) -> UdpFiltering {
        self.inner.filtering
    }

    pub fn authorize_peer(&self, peer: IpAddr) -> UdpPeerAuthorization {
        self.inner.authorize(peer)
    }

    /// Reserves bounded ADF capacity without authorizing responses before send succeeds.
    pub fn reserve_peer(&self, peer: IpAddr) -> UdpPeerReservationOutcome {
        if !same_ip_family(self.inner.local_ip, peer) || !valid_unicast_ip(peer) {
            return UdpPeerReservationOutcome::InvalidPeer;
        }
        if self.inner.filtering == UdpFiltering::EndpointIndependent {
            return UdpPeerReservationOutcome::NotRequired;
        }
        let mut peers = lock_unpoisoned(&self.inner.peers);
        if peers.authorized.contains(&peer) {
            return UdpPeerReservationOutcome::AlreadyAuthorized;
        }
        if let Some(count) = peers.reserved.get_mut(&peer) {
            *count = count.saturating_add(1);
        } else {
            if peers.authorized.len() + peers.reserved.len() == UDP_ADF_PEER_CAP {
                return UdpPeerReservationOutcome::LimitReached;
            }
            peers.reserved.insert(peer, 1);
        }
        drop(peers);
        UdpPeerReservationOutcome::Reserved(UdpPeerReservation {
            policy: Arc::clone(&self.inner),
            peer,
            active: true,
        })
    }
}

struct OwnerResponse {
    lease: Arc<AssociationLease>,
    peer_policy: Arc<PeerPolicy>,
    association_source: SocketAddr,
    response_source: SocketAddr,
    payload: Vec<u8>,
}

/// Cloneable, generation-bound response path for one EIM association.
#[derive(Clone)]
pub struct UdpResponseSink {
    source: SocketAddr,
    payload_bound: usize,
    lease: Arc<AssociationLease>,
    peer_policy: Arc<PeerPolicy>,
    responses: mpsc::Sender<OwnerResponse>,
    wake: OwnerWake,
    events: TunEventSink,
}

impl UdpResponseSink {
    pub const fn association_source(&self) -> SocketAddr {
        self.source
    }

    /// Queues one response while preserving its actual remote source endpoint.
    pub fn send(&self, source: SocketAddr, payload: &[u8]) -> UdpResponseSendOutcome {
        if self.lease.is_stale() {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return UdpResponseSendOutcome::StaleGeneration;
        }
        if self.lease.phase() != LeasePhase::Association {
            return UdpResponseSendOutcome::Closed;
        }
        if payload.len() > self.payload_bound {
            self.events.emit(TunEvent::PacketRejected(
                TunRejectReason::InvalidTransportLength,
            ));
            return UdpResponseSendOutcome::PayloadTooLarge;
        }
        match self.peer_policy.allows(source) {
            Err(()) => {
                self.events
                    .emit(TunEvent::PacketRejected(TunRejectReason::InvalidSource));
                return UdpResponseSendOutcome::InvalidSource;
            }
            Ok(false) => {
                self.events.emit(TunEvent::UdpResponseFiltered);
                self.events.emit(TunEvent::PacketRejected(
                    TunRejectReason::UdpResponseFiltered,
                ));
                return UdpResponseSendOutcome::Filtered;
            }
            Ok(true) => {}
        }
        let response = OwnerResponse {
            lease: Arc::clone(&self.lease),
            peer_policy: Arc::clone(&self.peer_policy),
            association_source: self.source,
            response_source: source,
            payload: payload.to_vec(),
        };
        match self.responses.try_send(response) {
            Ok(()) => {
                self.wake.signal();
                UdpResponseSendOutcome::Queued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.events.emit(TunEvent::UdpResponseQueueFull);
                self.events
                    .emit(TunEvent::PacketRejected(TunRejectReason::UdpQueueFull));
                UdpResponseSendOutcome::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => UdpResponseSendOutcome::Closed,
        }
    }
}

/// A validated first datagram awaiting a generation-checked owner commit.
pub struct UdpCandidate {
    source: SocketAddr,
    first_target: SocketAddr,
    first_payload: Arc<[u8]>,
    packet_payload_bound: usize,
    receiver: Option<mpsc::Receiver<UdpDatagram>>,
    lease: Arc<AssociationLease>,
    peer_policy: Arc<PeerPolicy>,
    responses: mpsc::Sender<OwnerResponse>,
    wake: OwnerWake,
    handed_off: bool,
}

impl UdpCandidate {
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    pub const fn first_target(&self) -> SocketAddr {
        self.first_target
    }

    /// Compatibility endpoint view for the current client migration.
    pub const fn tuple(&self) -> UdpTuple {
        UdpTuple::new(self.source, self.first_target)
    }

    pub fn first_payload(&self) -> &[u8] {
        &self.first_payload
    }

    /// Compatibility alias for `first_payload`.
    pub fn payload(&self) -> &[u8] {
        self.first_payload()
    }

    pub const fn packet_payload_bound(&self) -> usize {
        self.packet_payload_bound
    }

    async fn commit_core(
        &mut self,
        selected_payload_bound: usize,
    ) -> Result<UdpAssociation, UdpCommitError> {
        if selected_payload_bound > self.packet_payload_bound {
            return Err(UdpCommitError::Rejected);
        }
        let committed = self.lease.request_commit(selected_payload_bound)?;
        match committed.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(UdpCommitError::Unavailable),
        }
        if self.lease.is_stale() || self.lease.phase() != LeasePhase::Association {
            return Err(UdpCommitError::Rejected);
        }
        let Some(receiver) = self.receiver.take() else {
            return Err(UdpCommitError::Rejected);
        };
        let association = UdpAssociation {
            source: self.source,
            first_target: self.first_target,
            receiver,
            response: UdpResponseSink {
                source: self.source,
                payload_bound: selected_payload_bound,
                lease: Arc::clone(&self.lease),
                peer_policy: Arc::clone(&self.peer_policy),
                responses: self.responses.clone(),
                wake: self.wake.clone(),
                events: self.lease.events.clone(),
            },
            peer_policy: UdpPeerPolicyHandle {
                inner: Arc::clone(&self.peer_policy),
            },
            lease: Arc::clone(&self.lease),
        };
        self.handed_off = true;
        Ok(association)
    }

    /// Commits the source-keyed association without freezing a business terminal.
    pub async fn commit_association(mut self) -> Result<UdpAssociation, UdpCommitError> {
        let payload_bound = self.packet_payload_bound;
        self.commit_core(payload_bound).await
    }

    /// Commits after the first target's route has selected its exact payload ceiling.
    pub async fn commit_association_with_payload_bound(
        mut self,
        selected_payload_bound: usize,
    ) -> Result<UdpAssociation, UdpCommitError> {
        self.commit_core(selected_payload_bound).await
    }
}

impl Drop for UdpCandidate {
    fn drop(&mut self) {
        if !self.handed_off {
            self.lease.close();
        }
    }
}

/// Closed failure returned when a provisional decision cannot become live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCommitError {
    Rejected,
    Unavailable,
}

/// A committed EIM association keyed solely by its local source endpoint.
pub struct UdpAssociation {
    source: SocketAddr,
    first_target: SocketAddr,
    receiver: mpsc::Receiver<UdpDatagram>,
    response: UdpResponseSink,
    peer_policy: UdpPeerPolicyHandle,
    lease: Arc<AssociationLease>,
}

impl UdpAssociation {
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    pub const fn first_target(&self) -> SocketAddr {
        self.first_target
    }

    pub const fn tuple(&self) -> UdpTuple {
        UdpTuple::new(self.source, self.first_target)
    }

    pub fn response_sink(&self) -> UdpResponseSink {
        self.response.clone()
    }

    pub fn peer_policy(&self) -> UdpPeerPolicyHandle {
        self.peer_policy.clone()
    }

    pub fn authorize_peer(&self, peer: IpAddr) -> UdpPeerAuthorization {
        self.peer_policy.authorize_peer(peer)
    }

    pub async fn receive(&mut self) -> Option<UdpDatagram> {
        self.receiver.recv().await
    }

    pub fn send_response(&self, source: SocketAddr, payload: &[u8]) -> UdpResponseSendOutcome {
        self.response.send(source, payload)
    }
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.lease.close();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Provisional,
    CandidateQueued,
    Mapped,
    Dropped,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct EventOutcome {
    pub(crate) committed: usize,
    pub(crate) injected: usize,
    pub(crate) backpressured: usize,
    pub(crate) dropped: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseProcessOutcome {
    Idle,
    Injected,
    Backpressured,
    Dropped,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ExpireOutcome {
    pub(crate) candidates: usize,
    pub(crate) associations: usize,
}

enum Slot {
    Candidate {
        source: SocketAddr,
        payload_bound: usize,
        sender: mpsc::Sender<UdpDatagram>,
        peer_policy: Arc<PeerPolicy>,
        lease: Arc<AssociationLease>,
        deadline_millis: i64,
    },
    Association {
        source: SocketAddr,
        payload_bound: usize,
        sender: mpsc::Sender<UdpDatagram>,
        peer_policy: Arc<PeerPolicy>,
        lease: Arc<AssociationLease>,
        deadline_millis: i64,
    },
}

impl Slot {
    fn source(&self) -> SocketAddr {
        match self {
            Self::Candidate { source, .. } | Self::Association { source, .. } => *source,
        }
    }

    fn lease(&self) -> &Arc<AssociationLease> {
        match self {
            Self::Candidate { lease, .. } | Self::Association { lease, .. } => lease,
        }
    }

    fn deadline_millis(&self) -> i64 {
        match self {
            Self::Candidate {
                deadline_millis, ..
            }
            | Self::Association {
                deadline_millis, ..
            } => *deadline_millis,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DeadlineEntry {
    deadline_millis: i64,
    session_generation: u64,
    id: GenerationId,
}

pub(crate) struct UdpTable {
    slots: Box<[Option<Slot>]>,
    generations: GenerationTable,
    index: HashMap<SocketAddr, usize>,
    free_list: Vec<usize>,
    association_count: usize,
    candidate_count: usize,
    deadlines: BinaryHeap<Reverse<DeadlineEntry>>,
    candidates: mpsc::Sender<UdpCandidate>,
    controls: sync_mpsc::Receiver<ControlNotice>,
    control_sender: sync_mpsc::Sender<ControlNotice>,
    responses: mpsc::Receiver<OwnerResponse>,
    response_sender: mpsc::Sender<OwnerResponse>,
    pending_response: Option<OwnerResponse>,
    filtering: UdpFiltering,
    idle_millis: i64,
    session_generation: u64,
    session_epoch: Arc<AtomicU64>,
    wake: OwnerWake,
    events: TunEventSink,
}

impl UdpTable {
    pub(crate) fn with_options(
        capacity: usize,
        idle: Duration,
        filtering: UdpFiltering,
        session_generation: u64,
        wake: OwnerWake,
    ) -> (Self, mpsc::Receiver<UdpCandidate>) {
        let channel_capacity = capacity.max(1);
        let response_capacity = channel_capacity
            .saturating_mul(RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION)
            .max(1);
        let (candidate_sender, candidate_receiver) = mpsc::channel(channel_capacity);
        let (control_sender, controls) = sync_mpsc::channel();
        let (response_sender, responses) = mpsc::channel(response_capacity);
        let session_epoch = Arc::new(AtomicU64::new(session_generation));
        (
            Self {
                slots: std::iter::repeat_with(|| None)
                    .take(capacity)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                generations: GenerationTable::new(capacity),
                index: HashMap::with_capacity(capacity),
                free_list: (0..capacity).rev().collect(),
                association_count: 0,
                candidate_count: 0,
                deadlines: BinaryHeap::new(),
                candidates: candidate_sender,
                controls,
                control_sender,
                responses,
                response_sender,
                pending_response: None,
                filtering,
                idle_millis: duration_millis(idle),
                session_generation,
                session_epoch,
                wake,
                events: TunEventSink::default(),
            },
            candidate_receiver,
        )
    }

    pub(crate) fn set_event_sink(&mut self, events: TunEventSink) {
        self.events = events;
    }

    pub(crate) fn admit(
        &mut self,
        tuple: UdpTuple,
        payload: &[u8],
        payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.admit_with_ingress_bound(
            tuple,
            payload,
            payload_bound,
            payload_bound,
            now_millis,
            admitting,
        )
    }

    pub(crate) fn admit_reassembled(
        &mut self,
        tuple: UdpTuple,
        payload: &[u8],
        response_payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.admit_with_ingress_bound(
            tuple,
            payload,
            response_payload_bound,
            payload.len(),
            now_millis,
            admitting,
        )
    }

    fn admit_with_ingress_bound(
        &mut self,
        tuple: UdpTuple,
        payload: &[u8],
        response_payload_bound: usize,
        ingress_payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.expire(now_millis);
        if let Some(reason) = invalid_datagram_endpoint(tuple.source, tuple.target) {
            self.events.emit(TunEvent::PacketRejected(reason));
            return Admission::Dropped;
        }
        if payload.len() > ingress_payload_bound {
            self.events.emit(TunEvent::PacketRejected(
                TunRejectReason::InvalidTransportLength,
            ));
            return Admission::Dropped;
        }

        if let Some(slot) = self.index.get(&tuple.source).copied() {
            let closed = self
                .slots
                .get(slot)
                .and_then(Option::as_ref)
                .is_none_or(|entry| entry.lease().phase() == LeasePhase::Closed);
            if closed {
                if let Some(id) = self.generations.current(slot) {
                    self.remove(id);
                }
            } else {
                return self.enqueue_existing(
                    slot,
                    tuple,
                    payload,
                    ingress_payload_bound,
                    now_millis,
                );
            }
        }

        if !admitting {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return Admission::Dropped;
        }
        let Some(slot) = self.free_list.pop() else {
            self.events.emit(TunEvent::UdpAssociationRejectedLimit);
            self.events.emit(TunEvent::PacketRejected(
                TunRejectReason::UdpAssociationLimit,
            ));
            return Admission::Dropped;
        };
        let Some(id) = self.generations.current(slot) else {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return Admission::Dropped;
        };
        let (sender, receiver) = mpsc::channel(DATAGRAM_QUEUE_PACKETS);
        let first_payload: Arc<[u8]> = Arc::from(payload);
        let first = UdpDatagram {
            source: tuple.source,
            target: tuple.target,
            payload: Arc::clone(&first_payload),
        };
        if sender.try_send(first).is_err() {
            self.free_list.push(slot);
            self.events.emit(TunEvent::UdpDatagramQueueFull);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::UdpQueueFull));
            return Admission::Dropped;
        }
        let lease = Arc::new(AssociationLease::new(
            id,
            self.session_generation,
            Arc::clone(&self.session_epoch),
            self.control_sender.clone(),
            self.wake.clone(),
            self.events.clone(),
        ));
        let peer_policy = Arc::new(PeerPolicy::new(self.filtering, tuple.source.ip()));
        let deadline_millis = now_millis.saturating_add(CANDIDATE_TIMEOUT_MILLIS);
        self.slots[slot] = Some(Slot::Candidate {
            source: tuple.source,
            payload_bound: response_payload_bound,
            sender,
            peer_policy: Arc::clone(&peer_policy),
            lease: Arc::clone(&lease),
            deadline_millis,
        });
        self.index.insert(tuple.source, slot);
        self.candidate_count += 1;
        self.events
            .emit(TunEvent::UdpCandidatesActive(self.candidate_count));
        self.schedule_deadline(id, deadline_millis);
        let candidate = UdpCandidate {
            source: tuple.source,
            first_target: tuple.target,
            first_payload,
            packet_payload_bound: response_payload_bound,
            receiver: Some(receiver),
            lease,
            peer_policy,
            responses: self.response_sender.clone(),
            wake: self.wake.clone(),
            handed_off: false,
        };
        if self.candidates.try_send(candidate).is_err() {
            self.events.emit(TunEvent::UdpDatagramQueueFull);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::UdpQueueFull));
            self.remove(id);
            return Admission::Dropped;
        }
        Admission::Provisional
    }

    fn enqueue_existing(
        &mut self,
        slot: usize,
        tuple: UdpTuple,
        payload: &[u8],
        ingress_payload_bound: usize,
        now_millis: i64,
    ) -> Admission {
        let Some(id) = self.generations.current(slot) else {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return Admission::Dropped;
        };
        let datagram = UdpDatagram {
            source: tuple.source,
            target: tuple.target,
            payload: Arc::from(payload),
        };
        let mut refresh_deadline = None;
        let admission = match self.slots.get_mut(slot).and_then(Option::as_mut) {
            Some(Slot::Candidate { sender, .. }) => {
                if payload.len() > ingress_payload_bound {
                    self.events.emit(TunEvent::PacketRejected(
                        TunRejectReason::InvalidTransportLength,
                    ));
                    Admission::Dropped
                } else if sender.try_send(datagram).is_err() {
                    self.events.emit(TunEvent::UdpDatagramQueueFull);
                    self.events
                        .emit(TunEvent::PacketRejected(TunRejectReason::UdpQueueFull));
                    Admission::Dropped
                } else {
                    Admission::CandidateQueued
                }
            }
            Some(Slot::Association {
                sender,
                deadline_millis,
                ..
            }) => {
                if payload.len() > ingress_payload_bound {
                    self.events.emit(TunEvent::PacketRejected(
                        TunRejectReason::InvalidTransportLength,
                    ));
                    Admission::Dropped
                } else if sender.try_send(datagram).is_err() {
                    self.events.emit(TunEvent::UdpDatagramQueueFull);
                    self.events
                        .emit(TunEvent::PacketRejected(TunRejectReason::UdpQueueFull));
                    Admission::Dropped
                } else {
                    *deadline_millis = now_millis.saturating_add(self.idle_millis);
                    refresh_deadline = Some(*deadline_millis);
                    Admission::Mapped
                }
            }
            None => Admission::Dropped,
        };
        if let Some(deadline_millis) = refresh_deadline {
            self.schedule_deadline(id, deadline_millis);
        }
        admission
    }

    #[cfg(test)]
    pub(crate) fn process_events(
        &mut self,
        now_millis: i64,
        admitting: bool,
        inject: impl FnMut(UdpTuple, &[u8]) -> InjectOutcome,
    ) -> EventOutcome {
        self.expire(now_millis);
        let mut outcome = EventOutcome::default();
        for _ in 0..OWNER_EVENT_QUANTUM {
            let Some(committed) = self.process_one_control(now_millis, admitting) else {
                break;
            };
            if committed {
                outcome.committed += 1;
            }
        }
        match self.process_one_response(now_millis, inject) {
            ResponseProcessOutcome::Idle => {}
            ResponseProcessOutcome::Injected => outcome.injected += 1,
            ResponseProcessOutcome::Backpressured => outcome.backpressured += 1,
            ResponseProcessOutcome::Dropped => outcome.dropped += 1,
        }
        outcome
    }

    /// Processes at most one reliable lifecycle notification.
    ///
    /// `Some(true)` denotes a successful candidate commit, `Some(false)` any
    /// other lifecycle work, and `None` means the control queue was empty.
    pub(crate) fn process_one_control(&mut self, now_millis: i64, admitting: bool) -> Option<bool> {
        let notice = self.controls.try_recv().ok()?;
        if notice.session_generation != self.session_generation
            || self.generations.current(notice.id.slot) != Some(notice.id)
        {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return Some(false);
        }
        let Some(lease) = self
            .slots
            .get(notice.id.slot)
            .and_then(Option::as_ref)
            .map(|slot| Arc::clone(slot.lease()))
        else {
            return Some(false);
        };
        match lease.phase() {
            LeasePhase::Closed => {
                self.remove(notice.id);
                Some(false)
            }
            LeasePhase::CommitPending => {
                self.commit_candidate(notice.id, lease, now_millis, admitting)
            }
            LeasePhase::Candidate | LeasePhase::Association => Some(false),
        }
    }

    fn commit_candidate(
        &mut self,
        id: GenerationId,
        lease: Arc<AssociationLease>,
        now_millis: i64,
        admitting: bool,
    ) -> Option<bool> {
        let Some(commit) = lease.take_commit() else {
            return Some(false);
        };
        let valid = admitting
            && !lease.is_stale()
            && matches!(
                self.slots.get(id.slot).and_then(Option::as_ref),
                Some(Slot::Candidate {
                    payload_bound,
                    lease: current,
                    ..
                }) if Arc::ptr_eq(current, &lease)
                    && commit.selected_payload_bound <= *payload_bound
            );
        if !valid || !lease.mark_live() {
            if lease.is_stale() {
                self.events.emit(TunEvent::UdpStaleGeneration);
                self.events
                    .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            }
            let _ = commit.reply.send(Err(UdpCommitError::Rejected));
            self.remove(id);
            return Some(false);
        }
        let Some(Slot::Candidate {
            source,
            sender,
            peer_policy,
            lease: slot_lease,
            ..
        }) = self.slots[id.slot].take()
        else {
            let _ = commit.reply.send(Err(UdpCommitError::Rejected));
            self.remove(id);
            return Some(false);
        };
        let deadline_millis = now_millis.saturating_add(self.idle_millis);
        self.slots[id.slot] = Some(Slot::Association {
            source,
            payload_bound: commit.selected_payload_bound,
            sender,
            peer_policy,
            lease: slot_lease,
            deadline_millis,
        });
        self.candidate_count -= 1;
        self.association_count += 1;
        self.schedule_deadline(id, deadline_millis);
        if commit.reply.send(Ok(())).is_err() {
            self.remove(id);
            return Some(false);
        }
        self.events.emit(TunEvent::UdpAssociationCreated);
        self.events
            .emit(TunEvent::UdpCandidatesActive(self.candidate_count));
        self.events
            .emit(TunEvent::UdpAssociationsActive(self.association_count));
        Some(true)
    }

    /// Processes at most one response and retains it on internal backpressure.
    pub(crate) fn process_one_response(
        &mut self,
        now_millis: i64,
        mut inject: impl FnMut(UdpTuple, &[u8]) -> InjectOutcome,
    ) -> ResponseProcessOutcome {
        let response = match self.pending_response.take() {
            Some(response) => response,
            None => match self.responses.try_recv() {
                Ok(response) => response,
                Err(_) => return ResponseProcessOutcome::Idle,
            },
        };
        let id = response.lease.id;
        let valid = response.lease.session_generation == self.session_generation
            && !response.lease.is_stale()
            && response.lease.phase() == LeasePhase::Association
            && self.generations.current(id.slot) == Some(id)
            && matches!(
                self.slots.get(id.slot).and_then(Option::as_ref),
                Some(Slot::Association {
                    source,
                    payload_bound,
                    lease,
                    peer_policy,
                    ..
                }) if *source == response.association_source
                    && response.payload.len() <= *payload_bound
                    && Arc::ptr_eq(lease, &response.lease)
                    && Arc::ptr_eq(peer_policy, &response.peer_policy)
            );
        if !valid {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return ResponseProcessOutcome::Dropped;
        }
        if response.peer_policy.allows(response.response_source) != Ok(true) {
            self.events.emit(TunEvent::UdpResponseFiltered);
            self.events.emit(TunEvent::PacketRejected(
                TunRejectReason::UdpResponseFiltered,
            ));
            return ResponseProcessOutcome::Dropped;
        }
        let tuple = UdpTuple::new(response.association_source, response.response_source);
        match inject(tuple, &response.payload) {
            InjectOutcome::Injected => {
                let deadline_millis = now_millis.saturating_add(self.idle_millis);
                if let Some(Slot::Association {
                    deadline_millis: current,
                    ..
                }) = self.slots.get_mut(id.slot).and_then(Option::as_mut)
                {
                    *current = deadline_millis;
                }
                self.schedule_deadline(id, deadline_millis);
                ResponseProcessOutcome::Injected
            }
            InjectOutcome::Backpressured => {
                self.pending_response = Some(response);
                ResponseProcessOutcome::Backpressured
            }
            InjectOutcome::Rejected(reason) => {
                self.events.emit(TunEvent::PacketRejected(reason));
                ResponseProcessOutcome::Dropped
            }
        }
    }

    pub(crate) fn active_associations(&self) -> usize {
        self.association_count
    }

    #[cfg(test)]
    pub(crate) fn provisional_candidates(&self) -> usize {
        self.candidate_count
    }

    #[cfg(test)]
    pub(crate) fn active_entries(&self) -> usize {
        self.association_count + self.candidate_count
    }

    #[cfg(test)]
    pub(crate) fn deadline_entry_count(&self) -> usize {
        self.deadlines.len()
    }

    #[allow(dead_code)]
    pub(crate) fn has_pending_response(&self) -> bool {
        self.pending_response.is_some()
    }

    /// Returns the earliest live deadline after pruning stale heap entries.
    #[allow(dead_code)]
    pub(crate) fn next_deadline_millis(&mut self) -> Option<i64> {
        loop {
            let Reverse(deadline) = self.deadlines.peek().copied()?;
            let current = deadline.session_generation == self.session_generation
                && self.generations.current(deadline.id.slot) == Some(deadline.id)
                && self
                    .slots
                    .get(deadline.id.slot)
                    .and_then(Option::as_ref)
                    .is_some_and(|slot| slot.deadline_millis() == deadline.deadline_millis);
            if current {
                return Some(deadline.deadline_millis);
            }
            self.deadlines.pop();
        }
    }

    pub(crate) fn expire(&mut self, now_millis: i64) -> ExpireOutcome {
        let mut outcome = ExpireOutcome::default();
        while let Some(Reverse(deadline)) = self.deadlines.peek().copied() {
            if deadline.deadline_millis > now_millis {
                break;
            }
            self.deadlines.pop();
            if deadline.session_generation != self.session_generation
                || self.generations.current(deadline.id.slot) != Some(deadline.id)
            {
                continue;
            }
            let Some(slot) = self.slots.get(deadline.id.slot).and_then(Option::as_ref) else {
                continue;
            };
            if slot.deadline_millis() != deadline.deadline_millis {
                continue;
            }
            match slot {
                Slot::Candidate { .. } => {
                    outcome.candidates += 1;
                    self.events.emit(TunEvent::PacketRejected(
                        TunRejectReason::UdpCandidateTimeout,
                    ));
                }
                Slot::Association { .. } => outcome.associations += 1,
            }
            self.remove(deadline.id);
        }
        outcome
    }

    fn schedule_deadline(&mut self, id: GenerationId, deadline_millis: i64) {
        self.deadlines.push(Reverse(DeadlineEntry {
            deadline_millis,
            session_generation: self.session_generation,
            id,
        }));
        self.compact_deadlines_if_needed();
    }

    fn compact_deadlines_if_needed(&mut self) {
        // Refreshes intentionally use lazy invalidation so the hot path never
        // searches the heap. Rebuild occasionally to keep stale entries
        // bounded by configured association capacity rather than packet rate.
        let limit = self.slots.len().saturating_mul(2).max(1);
        if self.deadlines.len() <= limit {
            return;
        }
        self.deadlines = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(slot_index, slot)| {
                let slot = slot.as_ref()?;
                let id = self.generations.current(slot_index)?;
                Some(Reverse(DeadlineEntry {
                    deadline_millis: slot.deadline_millis(),
                    session_generation: self.session_generation,
                    id,
                }))
            })
            .collect();
    }

    /// Invalidates every old-session handle before a rebuilt session admits work.
    #[allow(dead_code)]
    pub(crate) fn invalidate_session(&mut self, new_generation: u64) {
        self.session_epoch.store(new_generation, Ordering::Release);
        for slot in 0..self.slots.len() {
            if self.slots[slot].is_some()
                && let Some(id) = self.generations.current(slot)
            {
                self.remove(id);
            }
        }
        self.pending_response = None;
        while self.responses.try_recv().is_ok() {}
        self.deadlines.clear();
        self.session_generation = new_generation;
    }

    fn remove(&mut self, id: GenerationId) {
        if self.generations.current(id.slot) != Some(id) {
            return;
        }
        let Some(slot) = self.slots.get_mut(id.slot).and_then(Option::take) else {
            return;
        };
        let source = slot.source();
        if self.index.get(&source) == Some(&id.slot) {
            self.index.remove(&source);
        }
        match &slot {
            Slot::Candidate { .. } => self.candidate_count -= 1,
            Slot::Association { .. } => self.association_count -= 1,
        }
        self.events
            .emit(TunEvent::UdpCandidatesActive(self.candidate_count));
        self.events
            .emit(TunEvent::UdpAssociationsActive(self.association_count));
        slot.lease().owner_close();
        if self.generations.recycle(id) && self.generations.current(id.slot).is_some() {
            self.free_list.push(id.slot);
        }
    }
}

impl Drop for UdpTable {
    fn drop(&mut self) {
        self.session_epoch
            .store(self.session_generation.wrapping_add(1), Ordering::Release);
        for slot in self.slots.iter().flatten() {
            slot.lease().owner_close();
        }
    }
}

fn duration_millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn valid_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

fn invalid_datagram_endpoint(source: SocketAddr, target: SocketAddr) -> Option<TunRejectReason> {
    if source.port() == 0 || !valid_unicast_ip(source.ip()) {
        return Some(TunRejectReason::InvalidSource);
    }
    if target.port() == 0
        || !valid_unicast_ip(target.ip())
        || !same_ip_family(source.ip(), target.ip())
    {
        return Some(TunRejectReason::InvalidDestination);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn v4(address: &str) -> SocketAddr {
        address.parse().expect("IPv4 socket address")
    }

    fn v6(address: &str) -> SocketAddr {
        address.parse().expect("IPv6 socket address")
    }

    fn tuple(source_port: u16, target: &str) -> UdpTuple {
        UdpTuple::new(v4(&format!("198.18.0.1:{source_port}")), v4(target))
    }

    fn table(
        capacity: usize,
        idle_millis: u64,
        filtering: UdpFiltering,
        generation: u64,
    ) -> (UdpTable, mpsc::Receiver<UdpCandidate>, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let (table, candidates) = UdpTable::with_options(
            capacity,
            Duration::from_millis(idle_millis),
            filtering,
            generation,
            OwnerWake::new(move || {
                wake_count.fetch_add(1, Ordering::Relaxed);
            }),
        );
        (table, candidates, wakes)
    }

    async fn commit(
        table: &mut UdpTable,
        candidate: UdpCandidate,
        now_millis: i64,
    ) -> UdpAssociation {
        let task = tokio::spawn(candidate.commit_association());
        tokio::task::yield_now().await;
        assert_eq!(table.process_one_control(now_millis, true), Some(true));
        task.await.expect("commit task").expect("association")
    }

    #[test]
    fn invalid_admission_endpoints_emit_exact_source_or_destination_reason() {
        let (mut table, _candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        table.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("UDP events").push(event);
        }));
        let cases = [
            (
                UdpTuple::new(v4("0.0.0.0:10000"), v4("192.0.2.1:53")),
                TunRejectReason::InvalidSource,
            ),
            (
                UdpTuple::new(v4("198.18.0.1:0"), v4("192.0.2.1:53")),
                TunRejectReason::InvalidSource,
            ),
            (
                UdpTuple::new(v4("198.18.0.1:10000"), v4("192.0.2.1:0")),
                TunRejectReason::InvalidDestination,
            ),
            (
                UdpTuple::new(v4("198.18.0.1:10000"), v4("224.0.0.1:53")),
                TunRejectReason::InvalidDestination,
            ),
            (
                UdpTuple::new(v4("198.18.0.1:10000"), v6("[2001:db8::1]:53")),
                TunRejectReason::InvalidDestination,
            ),
        ];

        for (tuple, reason) in cases {
            observed.lock().expect("UDP events").clear();
            assert_eq!(table.admit(tuple, b"q", 1_392, 0, true), Admission::Dropped);
            assert_eq!(
                *observed.lock().expect("UDP events"),
                [TunEvent::PacketRejected(reason)]
            );
            assert_eq!(table.active_entries(), 0);
        }
    }

    #[tokio::test]
    async fn c2_response_backpressure_preserves_current_event_and_does_not_consume_next() {
        let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
        assert_eq!(
            table.admit(tuple(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
        assert_eq!(
            association.authorize_peer(v4("192.0.2.1:1").ip()),
            UdpPeerAuthorization::Authorized
        );
        let sink = association.response_sink();
        assert_eq!(
            sink.send(v4("192.0.2.1:53"), b"first"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            sink.send(v4("192.0.2.1:5353"), b"second"),
            UdpResponseSendOutcome::Queued
        );

        let mut observed = Vec::new();
        assert_eq!(
            table.process_one_response(2, |tuple, payload| {
                observed.push((tuple.target(), payload.to_vec()));
                InjectOutcome::Backpressured
            }),
            ResponseProcessOutcome::Backpressured
        );
        assert!(table.has_pending_response());
        assert_eq!(observed, [(v4("192.0.2.1:53"), b"first".to_vec())]);
        assert_eq!(
            table.process_one_response(3, |tuple, payload| {
                observed.push((tuple.target(), payload.to_vec()));
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
        assert!(!table.has_pending_response());
        assert_eq!(
            table.process_one_response(4, |tuple, payload| {
                observed.push((tuple.target(), payload.to_vec()));
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
        assert_eq!(
            observed,
            [
                (v4("192.0.2.1:53"), b"first".to_vec()),
                (v4("192.0.2.1:53"), b"first".to_vec()),
                (v4("192.0.2.1:5353"), b"second".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn response_injection_preserves_the_specific_packet_reject_reason() {
        let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        table.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("UDP events").push(event);
        }));
        assert_eq!(
            table.admit(tuple(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
        let sink = association.response_sink();
        assert_eq!(
            sink.send(v4("192.0.2.1:53"), b"response"),
            UdpResponseSendOutcome::Queued
        );
        observed.lock().expect("UDP events").clear();

        assert_eq!(
            table.process_one_response(2, |_, _| {
                InjectOutcome::Rejected(TunRejectReason::InvalidIpChecksum)
            }),
            ResponseProcessOutcome::Dropped
        );
        assert_eq!(
            *observed.lock().expect("UDP events"),
            [TunEvent::PacketRejected(TunRejectReason::InvalidIpChecksum)]
        );
    }

    #[tokio::test]
    async fn response_queue_full_emits_specific_and_generic_reject_once() {
        let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 1);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&observed);
        table.set_event_sink(TunEventSink::new(move |event| {
            captured.lock().expect("UDP events").push(event);
        }));
        assert_eq!(
            table.admit(tuple(10_000, "192.0.2.1:53"), b"q", 1_392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
        assert_eq!(
            association.authorize_peer(v4("192.0.2.1:1").ip()),
            UdpPeerAuthorization::Authorized
        );
        let sink = association.response_sink();
        for index in 0..RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION {
            assert_eq!(
                sink.send(v4("192.0.2.1:53"), &[u8::try_from(index).unwrap()]),
                UdpResponseSendOutcome::Queued
            );
        }
        observed.lock().expect("UDP events").clear();
        assert_eq!(
            sink.send(v4("192.0.2.1:53"), b"full"),
            UdpResponseSendOutcome::QueueFull
        );
        assert_eq!(
            *observed.lock().expect("UDP events"),
            [
                TunEvent::UdpResponseQueueFull,
                TunEvent::PacketRejected(TunRejectReason::UdpQueueFull),
            ]
        );
    }

    #[tokio::test]
    async fn c8_lifecycle_control_is_reliable_when_data_queues_are_congested() {
        let (mut table, mut candidates, wakes) =
            table(1, 60_000, UdpFiltering::EndpointIndependent, 1);
        let key = tuple(10_001, "192.0.2.1:53");
        assert_eq!(
            table.admit(key, b"first", 1_392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;

        for _ in 1..DATAGRAM_QUEUE_PACKETS {
            assert_eq!(table.admit(key, b"data", 1_392, 2, true), Admission::Mapped);
        }
        assert_eq!(
            table.admit(key, b"full", 1_392, 2, true),
            Admission::Dropped
        );
        let sink = association.response_sink();
        let mut queued = 0;
        loop {
            match sink.send(v4("203.0.113.1:53"), b"response") {
                UdpResponseSendOutcome::Queued => queued += 1,
                UdpResponseSendOutcome::QueueFull => break,
                other => panic!("unexpected response outcome: {other:?}"),
            }
        }
        assert!(queued > 0);
        drop(association);
        assert_eq!(table.process_one_control(3, true), Some(false));
        assert_eq!(table.active_associations(), 0);
        assert_eq!(table.active_entries(), 0);
        assert!(wakes.load(Ordering::Relaxed) >= queued + 2);
    }

    #[tokio::test]
    async fn c9_candidate_timeout_is_fixed_five_seconds_and_separate_from_idle() {
        let (mut table, mut candidates, _) = table(1, 60_000, UdpFiltering::AddressDependent, 9);
        assert_eq!(
            table.admit(tuple(10_002, "192.0.2.1:53"), b"q", 1_392, 10, true),
            Admission::Provisional
        );
        let candidate = candidates.recv().await.unwrap();
        assert_eq!(table.expire(5_009), ExpireOutcome::default());
        assert_eq!(table.provisional_candidates(), 1);
        assert_eq!(
            table.expire(5_010),
            ExpireOutcome {
                candidates: 1,
                associations: 0,
            }
        );
        assert_eq!(table.active_entries(), 0);
        assert!(matches!(
            candidate.commit_association().await,
            Err(UdpCommitError::Rejected)
        ));

        assert_eq!(
            table.admit(tuple(10_002, "192.0.2.2:53"), b"new", 1_392, 6_000, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 6_001).await;
        assert_eq!(table.expire(11_001), ExpireOutcome::default());
        assert_eq!(
            table.active_associations(),
            1,
            "association idle deadline is not the candidate deadline"
        );
        drop(association);
        table.process_one_control(11_002, true);
    }

    #[tokio::test]
    async fn c10_hash_index_free_list_counts_and_generation_deadlines_are_exact() {
        let (mut table, mut candidates, _) = table(1, 10, UdpFiltering::EndpointIndependent, 3);
        let first = tuple(10_003, "192.0.2.1:53");
        assert_eq!(
            table.admit(first, b"one", 1_392, 0, true),
            Admission::Provisional
        );
        assert_eq!(table.index.len(), 1);
        assert!(table.free_list.is_empty());
        assert_eq!(table.next_deadline_millis(), Some(5_000));
        let mut association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
        assert_eq!(table.next_deadline_millis(), Some(11));
        assert_eq!(table.active_associations(), 1);
        assert_eq!(table.provisional_candidates(), 0);
        assert_eq!(
            table.admit(tuple(10_004, "192.0.2.2:53"), b"new", 1_392, 2, true),
            Admission::Dropped,
            "capacity pressure drops the new source and never evicts live state"
        );
        assert_eq!(table.active_associations(), 1);

        drop(association.receive().await.expect("first datagram"));
        assert_eq!(
            table.admit(first, b"refresh", 1_392, 8, true),
            Admission::Mapped
        );
        assert_eq!(
            table.next_deadline_millis(),
            Some(18),
            "deadline lookup lazily removes the superseded association entry"
        );
        assert_eq!(
            table.expire(11),
            ExpireOutcome::default(),
            "generation-checked stale heap deadline is ignored"
        );
        assert_eq!(table.active_associations(), 1);
        assert_eq!(
            table.expire(18),
            ExpireOutcome {
                candidates: 0,
                associations: 1,
            }
        );
        assert_eq!(table.active_entries(), 0);
        assert_eq!(table.index.len(), 0);
        assert_eq!(table.free_list.len(), 1);
        assert_eq!(table.next_deadline_millis(), None);
        drop(association);

        assert_eq!(
            table.admit(tuple(10_004, "192.0.2.2:53"), b"reused", 1_392, 19, true),
            Admission::Provisional
        );
        assert_eq!(table.active_entries(), 1);
        drop(candidates.recv().await.unwrap());
        while table.process_one_control(20, true).is_some() {}
        assert_eq!(table.active_entries(), 0);
    }

    #[tokio::test]
    async fn deadline_heap_stays_capacity_bounded_under_high_rate_refresh() {
        let capacity = 4;
        let (mut table, mut candidates, _) =
            table(capacity, 100, UdpFiltering::EndpointIndependent, 31);
        assert_eq!(
            table.admit(tuple(10_031, "192.0.2.1:53"), b"q", 1_392, 0, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 1).await;
        let sink = association.response_sink();

        for now_millis in 2..=4_097 {
            assert_eq!(
                sink.send(v4("192.0.2.1:53"), b"response"),
                UdpResponseSendOutcome::Queued
            );
            assert_eq!(
                table.process_one_response(now_millis, |_, _| InjectOutcome::Injected),
                ResponseProcessOutcome::Injected
            );
            assert!(
                table.deadline_entry_count() <= capacity * 2,
                "lazy refresh entries must remain bounded by configured capacity"
            );
        }

        assert_eq!(table.next_deadline_millis(), Some(4_197));
        assert_eq!(table.expire(4_196), ExpireOutcome::default());
        assert_eq!(
            table.expire(4_197),
            ExpireOutcome {
                candidates: 0,
                associations: 1,
            }
        );
        assert_eq!(table.deadline_entry_count(), 0);
        drop(association);
    }

    #[tokio::test]
    async fn c17_stale_generation_handles_cannot_commit_close_or_inject() {
        let (mut table, mut candidates, _) =
            table(1, 60_000, UdpFiltering::EndpointIndependent, 41);
        let first = tuple(10_005, "192.0.2.1:53");
        assert_eq!(
            table.admit(first, b"old", 1_392, 0, true),
            Admission::Provisional
        );
        let stale_candidate = candidates.recv().await.unwrap();
        table.invalidate_session(42);
        assert!(matches!(
            stale_candidate.commit_association().await,
            Err(UdpCommitError::Rejected)
        ));

        assert_eq!(
            table.admit(first, b"new", 1_392, 1, true),
            Admission::Provisional
        );
        let association = commit(&mut table, candidates.recv().await.unwrap(), 2).await;
        let stale_sink = association.response_sink();
        assert_eq!(
            stale_sink.send(v4("203.0.113.1:53"), b"queued"),
            UdpResponseSendOutcome::Queued
        );
        table.invalidate_session(43);
        assert_eq!(
            stale_sink.send(v4("203.0.113.1:53"), b"late"),
            UdpResponseSendOutcome::StaleGeneration
        );
        assert_eq!(
            table.process_one_response(3, |_, _| InjectOutcome::Injected),
            ResponseProcessOutcome::Idle,
            "restart clears queued old-generation responses"
        );

        assert_eq!(
            table.admit(first, b"fresh", 1_392, 4, true),
            Admission::Provisional
        );
        drop(association);
        while table.process_one_control(5, true).is_some() {}
        assert_eq!(
            table.provisional_candidates(),
            1,
            "stale close cannot remove a reused slot"
        );
        drop(candidates.recv().await.unwrap());
        while table.process_one_control(6, true).is_some() {}
        assert_eq!(table.active_entries(), 0);
    }

    #[tokio::test]
    async fn c19_eim_adf_eif_and_actual_response_source_are_enforced() {
        let (mut adf, mut candidates, _) = table(3, 60_000, UdpFiltering::AddressDependent, 1);
        let source = v4("198.18.0.1:10");
        let first_target = v4("192.0.2.1:53");
        let second_target = v4("198.51.100.2:5353");
        assert_eq!(
            adf.admit(UdpTuple::new(source, first_target), b"one", 1_392, 0, true),
            Admission::Provisional
        );
        assert_eq!(
            adf.admit(UdpTuple::new(source, second_target), b"two", 1_392, 1, true),
            Admission::CandidateQueued,
            "different targets share one source-keyed candidate"
        );
        assert_eq!(adf.provisional_candidates(), 1);
        let mut association = commit(&mut adf, candidates.recv().await.unwrap(), 2).await;
        assert_eq!(association.source(), source);
        assert_eq!(association.first_target(), first_target);
        assert_eq!(association.receive().await.unwrap().target(), first_target);
        assert_eq!(association.receive().await.unwrap().target(), second_target);

        let other_v4_source = v4("198.18.0.1:11");
        let v6_source = v6("[2001:db8::10]:10");
        assert_eq!(
            adf.admit(
                UdpTuple::new(other_v4_source, first_target),
                b"other-port",
                1_392,
                2,
                true
            ),
            Admission::Provisional,
            "a different local source port is a distinct association key"
        );
        assert_eq!(
            adf.admit(
                UdpTuple::new(v6_source, v6("[2001:db8::20]:53")),
                b"v6",
                1_392,
                2,
                true
            ),
            Admission::Provisional,
            "IPv4 and IPv6 local sources are distinct association keys"
        );
        let other_v4 = candidates.recv().await.unwrap();
        let other_v6 = candidates.recv().await.unwrap();
        assert_eq!(other_v4.source(), other_v4_source);
        assert_eq!(other_v6.source(), v6_source);
        drop(other_v4);
        drop(other_v6);
        while adf.process_one_control(2, true).is_some() {}
        assert_eq!(adf.active_associations(), 1);

        let allowed_ip = first_target.ip();
        assert_eq!(
            association.authorize_peer(allowed_ip),
            UdpPeerAuthorization::Authorized
        );
        let sink = association.response_sink();
        let actual_source = v4("192.0.2.1:9999");
        assert_eq!(
            sink.send(actual_source, b"allowed"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            sink.send(v4("203.0.113.9:53"), b"filtered"),
            UdpResponseSendOutcome::Filtered
        );
        assert_eq!(
            sink.send(v6("[2001:db8::1]:53"), b"mixed"),
            UdpResponseSendOutcome::InvalidSource
        );
        assert_eq!(
            sink.send(v4("224.0.0.1:53"), b"multicast"),
            UdpResponseSendOutcome::InvalidSource
        );
        assert_eq!(
            sink.send(v4("0.0.0.0:53"), b"unspecified"),
            UdpResponseSendOutcome::InvalidSource
        );
        let mut injected = None;
        assert_eq!(
            adf.process_one_response(3, |tuple, payload| {
                injected = Some((tuple, payload.to_vec()));
                InjectOutcome::Injected
            }),
            ResponseProcessOutcome::Injected
        );
        assert_eq!(
            injected,
            Some((UdpTuple::new(source, actual_source), b"allowed".to_vec()))
        );

        for index in 0..(UDP_ADF_PEER_CAP - 1) {
            let peer = IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                u8::try_from(index / 254).unwrap(),
                u8::try_from(index % 254 + 1).unwrap(),
                1,
            ));
            assert_eq!(
                association.authorize_peer(peer),
                UdpPeerAuthorization::Authorized
            );
        }
        assert_eq!(
            association.authorize_peer(v4("11.0.0.1:1").ip()),
            UdpPeerAuthorization::LimitReached,
            "peer cap drops new authorization without evicting old peers"
        );
        assert_eq!(
            sink.send(actual_source, b"still-authorized"),
            UdpResponseSendOutcome::Queued
        );

        assert_eq!(
            adf.admit(
                UdpTuple::new(source, v6("[2001:db8::1]:53")),
                b"mixed",
                1_392,
                4,
                true
            ),
            Admission::Dropped
        );
        assert_eq!(
            adf.admit(
                UdpTuple::new(source, v4("224.0.0.1:53")),
                b"multicast",
                1_392,
                4,
                true
            ),
            Admission::Dropped
        );

        let (mut eif, mut eif_candidates, _) =
            table(1, 60_000, UdpFiltering::EndpointIndependent, 7);
        assert_eq!(
            eif.admit(tuple(11, "192.0.2.10:53"), b"q", 1_392, 0, true),
            Admission::Provisional
        );
        let eif_association = commit(&mut eif, eif_candidates.recv().await.unwrap(), 1).await;
        assert_eq!(
            eif_association.send_response(v4("203.0.113.77:65000"), b"unseen"),
            UdpResponseSendOutcome::Queued
        );
        assert_eq!(
            eif_association.send_response(v6("[2001:db8::77]:65000"), b"mixed"),
            UdpResponseSendOutcome::InvalidSource
        );
    }

    #[test]
    fn adf_peer_reservations_are_bounded_and_authorize_only_on_commit() {
        fn handle(filtering: UdpFiltering) -> UdpPeerPolicyHandle {
            UdpPeerPolicyHandle {
                inner: Arc::new(PeerPolicy::new(filtering, "198.18.0.1".parse().unwrap())),
            }
        }

        fn reserved(outcome: UdpPeerReservationOutcome) -> UdpPeerReservation {
            match outcome {
                UdpPeerReservationOutcome::Reserved(reservation) => reservation,
                _ => panic!("expected a peer reservation"),
            }
        }

        let policy = handle(UdpFiltering::AddressDependent);
        let peer = "192.0.2.1".parse().unwrap();
        let first = reserved(policy.reserve_peer(peer));
        let second = reserved(policy.reserve_peer(peer));
        assert_eq!(policy.inner.allows(v4("192.0.2.1:53")), Ok(false));
        assert_eq!(first.commit(), UdpPeerAuthorization::Authorized);
        assert_eq!(policy.inner.allows(v4("192.0.2.1:5353")), Ok(true));
        assert_eq!(second.commit(), UdpPeerAuthorization::AlreadyAuthorized);
        assert!(matches!(
            policy.reserve_peer(peer),
            UdpPeerReservationOutcome::AlreadyAuthorized
        ));

        let bounded = handle(UdpFiltering::AddressDependent);
        let mut reservations = Vec::with_capacity(UDP_ADF_PEER_CAP);
        for index in 0..UDP_ADF_PEER_CAP {
            let peer = IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                u8::try_from(index / 254).unwrap(),
                u8::try_from(index % 254 + 1).unwrap(),
                1,
            ));
            reservations.push(reserved(bounded.reserve_peer(peer)));
        }
        assert!(matches!(
            bounded.reserve_peer("11.0.0.1".parse().unwrap()),
            UdpPeerReservationOutcome::LimitReached
        ));
        drop(reservations.pop());
        let replacement = reserved(bounded.reserve_peer("11.0.0.1".parse().unwrap()));
        assert_eq!(replacement.commit(), UdpPeerAuthorization::Authorized);
        drop(reservations);

        assert!(matches!(
            policy.reserve_peer("224.0.0.1".parse().unwrap()),
            UdpPeerReservationOutcome::InvalidPeer
        ));
        assert!(matches!(
            policy.reserve_peer("2001:db8::1".parse().unwrap()),
            UdpPeerReservationOutcome::InvalidPeer
        ));
        assert!(matches!(
            handle(UdpFiltering::EndpointIndependent).reserve_peer("203.0.113.1".parse().unwrap()),
            UdpPeerReservationOutcome::NotRequired
        ));
    }
}
