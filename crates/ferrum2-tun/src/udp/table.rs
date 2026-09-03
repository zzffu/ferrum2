use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as sync_mpsc};
use std::time::Duration;

use tokio::sync::mpsc;

#[cfg(test)]
use super::OWNER_EVENT_QUANTUM;
use super::{
    AssociationLease, CANDIDATE_TIMEOUT_MILLIS, ControlNotice, ControlNoticeKind,
    DATAGRAM_QUEUE_PACKETS, GenerationId, GenerationTable, InjectOutcome, LeasePhase,
    OwnerResponse, PeerPolicy, RESPONSE_QUEUE_PACKETS_PER_ASSOCIATION, UdpCandidate,
    UdpCommitError, UdpDatagram, UdpDatagramEndpoints, UdpFiltering, emit_response_drop,
    same_ip_family, valid_unicast_ip,
};
use crate::{OwnerWake, TunEvent, TunEventSink, TunRejectReason, UdpResponseDropReason};

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
    Deferred,
    Dropped(UdpResponseDropReason),
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
        lease: Arc<AssociationLease>,
        deadline_millis: i64,
    },
    Association {
        source: SocketAddr,
        payload_bound: usize,
        sender: mpsc::Sender<UdpDatagram>,
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
    #[cfg(test)]
    pub(crate) fn set_session_epoch_for_test(&self, generation: u64) {
        self.session_epoch.store(generation, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn index_len_for_test(&self) -> usize {
        self.index.len()
    }

    #[cfg(test)]
    pub(crate) fn free_slots_for_test(&self) -> usize {
        self.free_list.len()
    }

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
        endpoints: UdpDatagramEndpoints,
        payload: &[u8],
        payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.admit_with_ingress_bound(
            endpoints,
            payload,
            payload_bound,
            payload_bound,
            now_millis,
            admitting,
        )
    }

    pub(crate) fn admit_reassembled(
        &mut self,
        endpoints: UdpDatagramEndpoints,
        payload: &[u8],
        response_payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.admit_with_ingress_bound(
            endpoints,
            payload,
            response_payload_bound,
            payload.len(),
            now_millis,
            admitting,
        )
    }

    fn admit_with_ingress_bound(
        &mut self,
        endpoints: UdpDatagramEndpoints,
        payload: &[u8],
        response_payload_bound: usize,
        ingress_payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.expire(now_millis);
        if let Some(reason) = invalid_datagram_endpoint(endpoints.source, endpoints.target) {
            self.events.emit(TunEvent::PacketRejected(reason));
            return Admission::Dropped;
        }
        if payload.len() > ingress_payload_bound {
            self.events.emit(TunEvent::PacketRejected(
                TunRejectReason::InvalidTransportLength,
            ));
            return Admission::Dropped;
        }

        if let Some(slot) = self.index.get(&endpoints.source).copied()
            && let Some(admission) =
                self.enqueue_existing(slot, endpoints, payload, ingress_payload_bound, now_millis)
        {
            return admission;
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
            source: endpoints.source,
            target: endpoints.target,
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
            PeerPolicy::new(self.filtering, endpoints.source.ip()),
        ));
        let deadline_millis = now_millis.saturating_add(CANDIDATE_TIMEOUT_MILLIS);
        self.slots[slot] = Some(Slot::Candidate {
            source: endpoints.source,
            payload_bound: response_payload_bound,
            sender,
            lease: Arc::clone(&lease),
            deadline_millis,
        });
        self.index.insert(endpoints.source, slot);
        self.candidate_count += 1;
        self.events
            .emit(TunEvent::UdpCandidatesActive(self.candidate_count));
        self.schedule_deadline(id, deadline_millis);
        let candidate = UdpCandidate {
            source: endpoints.source,
            first_target: endpoints.target,
            first_payload,
            packet_payload_bound: response_payload_bound,
            receiver: Some(receiver),
            lease,
            responses: self.response_sender.clone(),
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
        endpoints: UdpDatagramEndpoints,
        payload: &[u8],
        ingress_payload_bound: usize,
        now_millis: i64,
    ) -> Option<Admission> {
        let id = self.generations.current(slot);
        let Some(entry) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
            if let Some(id) = id {
                self.remove(id);
            }
            return None;
        };
        if entry.lease().phase() == LeasePhase::Closed {
            if let Some(id) = id {
                self.remove(id);
            }
            return None;
        }
        let Some(id) = id else {
            self.events.emit(TunEvent::UdpStaleGeneration);
            self.events
                .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            return Some(Admission::Dropped);
        };
        let datagram = UdpDatagram {
            source: endpoints.source,
            target: endpoints.target,
            payload: Arc::from(payload),
        };
        let mut refresh_deadline = None;
        let admission = match entry {
            Slot::Candidate { sender, .. } => {
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
            Slot::Association {
                sender,
                deadline_millis,
                ..
            } => {
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
        };
        if let Some(deadline_millis) = refresh_deadline {
            self.schedule_deadline(id, deadline_millis);
        }
        Some(admission)
    }

    #[cfg(test)]
    pub(crate) fn process_events(
        &mut self,
        now_millis: i64,
        admitting: bool,
        inject: impl FnMut(UdpDatagramEndpoints, &[u8]) -> InjectOutcome,
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
            ResponseProcessOutcome::Deferred => outcome.backpressured += 1,
            ResponseProcessOutcome::Dropped(_) => outcome.dropped += 1,
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
            // Close is only an idempotent owner-reclamation hint. Once that owner has already
            // recycled the identity, it carries no commit, datagram, or response to reject.
            if notice.kind == ControlNoticeKind::Commit {
                self.events.emit(TunEvent::UdpStaleGeneration);
                self.events
                    .emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
            }
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
        mut inject: impl FnMut(UdpDatagramEndpoints, &[u8]) -> InjectOutcome,
    ) -> ResponseProcessOutcome {
        let (response, was_pending) = match self.pending_response.take() {
            Some(response) => (response, true),
            None => match self.responses.try_recv() {
                Ok(response) => (response, false),
                Err(_) => return ResponseProcessOutcome::Idle,
            },
        };
        let id = response.lease.id;
        let stale = response.lease.session_generation != self.session_generation
            || response.lease.is_stale()
            || self.generations.current(id.slot) != Some(id);
        if stale {
            if was_pending {
                self.events.emit(TunEvent::UdpPendingResponses(0));
            }
            self.events.emit(TunEvent::UdpStaleGeneration);
            emit_response_drop(
                &self.events,
                UdpResponseDropReason::StaleGeneration,
                TunRejectReason::StaleGeneration,
            );
            return ResponseProcessOutcome::Dropped(UdpResponseDropReason::StaleGeneration);
        }
        let (association_matches, payload_bound) =
            match self.slots.get(id.slot).and_then(Option::as_ref) {
                Some(Slot::Association {
                    source,
                    payload_bound,
                    lease,
                    ..
                }) => (
                    response.lease.phase() == LeasePhase::Association
                        && *source == response.association_source
                        && Arc::ptr_eq(lease, &response.lease),
                    *payload_bound,
                ),
                _ => (false, 0),
            };
        if !association_matches {
            if was_pending {
                self.events.emit(TunEvent::UdpPendingResponses(0));
            }
            emit_response_drop(
                &self.events,
                UdpResponseDropReason::AssociationClosed,
                TunRejectReason::UdpResponseClosed,
            );
            return ResponseProcessOutcome::Dropped(UdpResponseDropReason::AssociationClosed);
        }
        if response.payload.len() > payload_bound {
            if was_pending {
                self.events.emit(TunEvent::UdpPendingResponses(0));
            }
            emit_response_drop(
                &self.events,
                UdpResponseDropReason::MalformedResponse,
                TunRejectReason::InvalidTransportLength,
            );
            return ResponseProcessOutcome::Dropped(UdpResponseDropReason::MalformedResponse);
        }
        match response.lease.peer_policy.allows(response.response_source) {
            Err(()) => {
                if was_pending {
                    self.events.emit(TunEvent::UdpPendingResponses(0));
                }
                emit_response_drop(
                    &self.events,
                    UdpResponseDropReason::MalformedResponse,
                    TunRejectReason::InvalidSource,
                );
                return ResponseProcessOutcome::Dropped(UdpResponseDropReason::MalformedResponse);
            }
            Ok(false) => {
                if was_pending {
                    self.events.emit(TunEvent::UdpPendingResponses(0));
                }
                self.events.emit(TunEvent::UdpResponseFiltered);
                emit_response_drop(
                    &self.events,
                    UdpResponseDropReason::Filtered,
                    TunRejectReason::UdpResponseFiltered,
                );
                return ResponseProcessOutcome::Dropped(UdpResponseDropReason::Filtered);
            }
            Ok(true) => {}
        }
        let endpoints =
            UdpDatagramEndpoints::new(response.association_source, response.response_source);
        match inject(endpoints, &response.payload) {
            InjectOutcome::Injected => {
                if was_pending {
                    self.events.emit(TunEvent::UdpPendingResponses(0));
                }
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
                if !was_pending {
                    self.events.emit(TunEvent::UdpPendingResponses(1));
                }
                ResponseProcessOutcome::Deferred
            }
            InjectOutcome::Rejected(reason) => {
                if was_pending {
                    self.events.emit(TunEvent::UdpPendingResponses(0));
                }
                emit_response_drop(
                    &self.events,
                    UdpResponseDropReason::InjectionRejected,
                    reason,
                );
                ResponseProcessOutcome::Dropped(UdpResponseDropReason::InjectionRejected)
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
    pub(crate) fn invalidate_session(
        &mut self,
        new_generation: u64,
        response_drop_reason: UdpResponseDropReason,
    ) {
        self.session_epoch.store(new_generation, Ordering::Release);
        for slot in 0..self.slots.len() {
            if self.slots[slot].is_some()
                && let Some(id) = self.generations.current(slot)
            {
                self.remove(id);
            }
        }
        self.drop_retained_responses(response_drop_reason);
        self.deadlines.clear();
        self.session_generation = new_generation;
    }

    fn drop_retained_responses(&mut self, reason: UdpResponseDropReason) {
        let reject_reason = match reason {
            UdpResponseDropReason::SessionReset | UdpResponseDropReason::StaleGeneration => {
                TunRejectReason::StaleGeneration
            }
            UdpResponseDropReason::Shutdown
            | UdpResponseDropReason::OwnerFatal
            | UdpResponseDropReason::AssociationClosed => TunRejectReason::UdpResponseClosed,
            UdpResponseDropReason::QueueFull
            | UdpResponseDropReason::MalformedResponse
            | UdpResponseDropReason::Filtered
            | UdpResponseDropReason::InjectionRejected => {
                debug_assert!(false, "non-lifecycle UDP response drop reason");
                TunRejectReason::UdpResponseClosed
            }
        };
        if self.pending_response.take().is_some() {
            self.events.emit(TunEvent::UdpPendingResponses(0));
            emit_response_drop(&self.events, reason, reject_reason);
        }
        while self.responses.try_recv().is_ok() {
            emit_response_drop(&self.events, reason, reject_reason);
        }
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
        self.responses.close();
        for slot in self.slots.iter().flatten() {
            slot.lease().owner_close();
        }
        self.drop_retained_responses(UdpResponseDropReason::Shutdown);
    }
}

fn duration_millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
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
