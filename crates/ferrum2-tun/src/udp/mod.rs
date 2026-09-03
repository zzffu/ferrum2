// Public bridge types still compile on unsupported hosts; their owner half is unreachable there.
#![cfg_attr(
    not(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test)),
    allow(dead_code)
)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as sync_mpsc};

use tokio::sync::{mpsc, oneshot};

use crate::{OwnerWake, TunEvent, TunEventSink, TunRejectReason, UdpResponseDropReason};

const DATAGRAM_QUEUE_PACKETS: usize = 8;
const RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION: usize = 8;
#[cfg(test)]
const OWNER_EVENT_QUANTUM: usize = 8;
const CANDIDATE_TIMEOUT_MILLIS: i64 = 5_000;

/// Fixed maximum number of address-dependent peers retained by one association.
pub const UDP_ADF_PEER_CAP: usize = 256;

/// Immutable validated endpoints for one UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UdpDatagramEndpoints {
    source: SocketAddr,
    target: SocketAddr,
}

impl UdpDatagramEndpoints {
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
    AddressDependent,
    /// Accept responses from any valid same-family unicast endpoint.
    #[default]
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
    kind: ControlNoticeKind,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ControlNoticeKind {
    Commit,
    Close,
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
    peer_policy: PeerPolicy,
}

impl AssociationLease {
    fn new(
        id: GenerationId,
        session_generation: u64,
        session_epoch: Arc<AtomicU64>,
        controls: sync_mpsc::Sender<ControlNotice>,
        wake: OwnerWake,
        events: TunEventSink,
        peer_policy: PeerPolicy,
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
            peer_policy,
        }
    }

    fn phase(&self) -> LeasePhase {
        LeasePhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    fn is_stale(&self) -> bool {
        self.session_epoch.load(Ordering::Acquire) != self.session_generation
    }

    fn notify(&self, kind: ControlNoticeKind) -> Result<(), ()> {
        self.controls
            .send(ControlNotice {
                id: self.id,
                session_generation: self.session_generation,
                kind,
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
        if self.notify(ControlNoticeKind::Commit).is_err() {
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
            && self.notify(ControlNoticeKind::Close).is_err()
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
    peers: Option<Mutex<PeerEntries>>,
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
            peers: (filtering == UdpFiltering::AddressDependent).then(|| {
                Mutex::new(PeerEntries {
                    authorized: HashSet::new(),
                    reserved: HashMap::new(),
                })
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
        let mut peers = lock_unpoisoned(
            self.peers
                .as_ref()
                .expect("address-dependent policy owns peer state"),
        );
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
        let mut peers = lock_unpoisoned(
            self.peers
                .as_ref()
                .expect("address-dependent policy owns peer state"),
        );
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
            || lock_unpoisoned(
                self.peers
                    .as_ref()
                    .expect("address-dependent policy owns peer state"),
            )
            .authorized
            .contains(&source.ip()))
    }
}

/// A unique-capacity ADF reservation which authorizes only after explicit commit.
#[must_use = "an uncommitted UDP peer reservation is released on drop"]
pub struct UdpPeerReservation {
    policy: Arc<AssociationLease>,
    peer: IpAddr,
    active: bool,
}

impl UdpPeerReservation {
    pub fn commit(mut self) -> UdpPeerAuthorization {
        self.active = false;
        self.policy.peer_policy.finish_reservation(self.peer, true)
    }
}

impl Drop for UdpPeerReservation {
    fn drop(&mut self) {
        if self.active {
            let _ = self.policy.peer_policy.finish_reservation(self.peer, false);
        }
    }
}

/// Cloneable handle used to authorize ADF peers only after outbound acceptance.
#[derive(Clone)]
pub struct UdpPeerPolicyHandle {
    inner: Arc<AssociationLease>,
}

impl UdpPeerPolicyHandle {
    pub fn filtering(&self) -> UdpFiltering {
        self.inner.peer_policy.filtering
    }

    pub fn authorize_peer(&self, peer: IpAddr) -> UdpPeerAuthorization {
        self.inner.peer_policy.authorize(peer)
    }

    /// Reserves bounded ADF capacity without authorizing responses before send succeeds.
    pub fn reserve_peer(&self, peer: IpAddr) -> UdpPeerReservationOutcome {
        if !same_ip_family(self.inner.peer_policy.local_ip, peer) || !valid_unicast_ip(peer) {
            return UdpPeerReservationOutcome::InvalidPeer;
        }
        if self.inner.peer_policy.filtering == UdpFiltering::EndpointIndependent {
            return UdpPeerReservationOutcome::NotRequired;
        }
        let mut peers = lock_unpoisoned(
            self.inner
                .peer_policy
                .peers
                .as_ref()
                .expect("address-dependent policy owns peer state"),
        );
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
    association_source: SocketAddr,
    response_source: SocketAddr,
    payload: Vec<u8>,
}

fn emit_response_drop(
    events: &TunEventSink,
    reason: UdpResponseDropReason,
    reject_reason: TunRejectReason,
) {
    events.emit(TunEvent::UdpResponseDropped(reason));
    events.emit(TunEvent::PacketRejected(reject_reason));
}

/// Cloneable, generation-bound response path for one EIM association.
#[derive(Clone)]
pub struct UdpResponseSink {
    source: SocketAddr,
    payload_bound: usize,
    lease: Arc<AssociationLease>,
    responses: mpsc::Sender<OwnerResponse>,
}

impl UdpResponseSink {
    pub const fn association_source(&self) -> SocketAddr {
        self.source
    }

    /// Queues one response while preserving its actual remote source endpoint.
    pub fn send(&self, source: SocketAddr, payload: &[u8]) -> UdpResponseSendOutcome {
        if self.lease.is_stale() {
            self.lease.events.emit(TunEvent::UdpStaleGeneration);
            emit_response_drop(
                &self.lease.events,
                UdpResponseDropReason::StaleGeneration,
                TunRejectReason::StaleGeneration,
            );
            return UdpResponseSendOutcome::StaleGeneration;
        }
        if self.lease.phase() != LeasePhase::Association {
            emit_response_drop(
                &self.lease.events,
                UdpResponseDropReason::AssociationClosed,
                TunRejectReason::UdpResponseClosed,
            );
            return UdpResponseSendOutcome::Closed;
        }
        if payload.len() > self.payload_bound {
            emit_response_drop(
                &self.lease.events,
                UdpResponseDropReason::MalformedResponse,
                TunRejectReason::InvalidTransportLength,
            );
            return UdpResponseSendOutcome::PayloadTooLarge;
        }
        match self.lease.peer_policy.allows(source) {
            Err(()) => {
                emit_response_drop(
                    &self.lease.events,
                    UdpResponseDropReason::MalformedResponse,
                    TunRejectReason::InvalidSource,
                );
                return UdpResponseSendOutcome::InvalidSource;
            }
            Ok(false) => {
                self.lease.events.emit(TunEvent::UdpResponseFiltered);
                emit_response_drop(
                    &self.lease.events,
                    UdpResponseDropReason::Filtered,
                    TunRejectReason::UdpResponseFiltered,
                );
                return UdpResponseSendOutcome::Filtered;
            }
            Ok(true) => {}
        }
        let response = OwnerResponse {
            lease: Arc::clone(&self.lease),
            association_source: self.source,
            response_source: source,
            payload: payload.to_vec(),
        };
        match self.responses.try_send(response) {
            Ok(()) => {
                self.lease.wake.signal();
                UdpResponseSendOutcome::Queued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.lease.events.emit(TunEvent::UdpResponseQueueFull);
                emit_response_drop(
                    &self.lease.events,
                    UdpResponseDropReason::QueueFull,
                    TunRejectReason::UdpQueueFull,
                );
                UdpResponseSendOutcome::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                emit_response_drop(
                    &self.lease.events,
                    UdpResponseDropReason::AssociationClosed,
                    TunRejectReason::UdpResponseClosed,
                );
                UdpResponseSendOutcome::Closed
            }
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
    responses: mpsc::Sender<OwnerResponse>,
    handed_off: bool,
}

impl UdpCandidate {
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    pub const fn first_target(&self) -> SocketAddr {
        self.first_target
    }

    pub fn first_payload(&self) -> &[u8] {
        &self.first_payload
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
                responses: self.responses.clone(),
            },
            peer_policy: UdpPeerPolicyHandle {
                inner: Arc::clone(&self.lease),
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

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "fuzzing"
))]
mod table;
#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "fuzzing"
))]
pub(crate) use table::{Admission, ResponseProcessOutcome, UdpTable};
#[cfg(test)]
pub(crate) use table::{EventOutcome, ExpireOutcome};

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

#[cfg(test)]
mod tests;
