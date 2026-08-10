use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

const MAPPING_QUEUE_PACKETS: usize = 8;

/// Immutable application-to-target identity for one TUN UDP mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpTuple {
    source: SocketAddr,
    target: SocketAddr,
}

impl UdpTuple {
    pub(crate) const fn new(source: SocketAddr, target: SocketAddr) -> Self {
        Self { source, target }
    }

    /// Application endpoint captured from the validated packet.
    pub const fn source(self) -> SocketAddr {
        self.source
    }

    /// Immutable original destination captured from the validated packet.
    pub const fn target(self) -> SocketAddr {
        self.target
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

struct ByteBudget {
    used: AtomicUsize,
    limit: usize,
}

impl ByteBudget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(Reservation {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(observed) => used = observed,
            }
        }
    }
}

struct Reservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// A validated, mapping-free first datagram awaiting the caller's terminal decision.
pub struct UdpCandidate<T> {
    tuple: UdpTuple,
    payload: Option<Vec<u8>>,
    payload_bound: usize,
    reservation: Option<Reservation>,
    id: GenerationId,
    events: std::sync::mpsc::SyncSender<OwnerEvent<T>>,
}

impl<T> UdpCandidate<T> {
    /// Immutable five-tuple endpoints (the IP protocol is UDP).
    pub const fn tuple(&self) -> UdpTuple {
        self.tuple
    }

    /// Owned first application payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_deref().unwrap_or_default()
    }

    /// Largest unfragmented UDP payload for this packet family and configured MTU.
    pub const fn packet_payload_bound(&self) -> usize {
        self.payload_bound
    }
}

/// Closed failure returned when a provisional decision cannot become the live mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpCommitError {
    /// The candidate is stale, duplicated, over its selected bound, or no longer admissible.
    Rejected,
    /// The bounded owner decision queue is full or closed.
    Unavailable,
}

impl<T: Send + 'static> UdpCandidate<T> {
    /// Atomically asks the owner thread to commit this candidate with an opaque caller token.
    pub async fn commit(
        mut self,
        terminal: T,
        selected_payload_bound: usize,
    ) -> Result<UdpMapping<T>, UdpCommitError> {
        if self.payload().len() > selected_payload_bound
            || selected_payload_bound > self.payload_bound
        {
            return Err(UdpCommitError::Rejected);
        }
        let (reply, committed) = oneshot::channel();
        let event = OwnerEvent::Commit {
            id: self.id,
            tuple: self.tuple,
            payload: self.payload.take().expect("candidate payload retained"),
            payload_bound: self.payload_bound,
            selected_payload_bound,
            reservation: self.reservation.take().expect("candidate bytes retained"),
            terminal,
            reply,
        };
        self.events
            .try_send(event)
            .map_err(|_| UdpCommitError::Unavailable)?;
        committed.await.unwrap_or(Err(UdpCommitError::Rejected))
    }
}

impl<T> Drop for UdpCandidate<T> {
    fn drop(&mut self) {
        if self.payload.is_some() {
            let _ = self.events.try_send(OwnerEvent::Drop { id: self.id });
        }
    }
}

/// One complete application datagram delivered in mapping order.
pub struct UdpDatagram {
    tuple: UdpTuple,
    payload: Vec<u8>,
    _reservation: Reservation,
}

impl UdpDatagram {
    pub const fn tuple(&self) -> UdpTuple {
        self.tuple
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A committed mapping stream. The terminal token remains opaque to `ferrum2-tun`.
pub struct UdpMapping<T> {
    id: GenerationId,
    tuple: UdpTuple,
    terminal: T,
    payload_bound: usize,
    receiver: mpsc::Receiver<UdpDatagram>,
    events: std::sync::mpsc::SyncSender<OwnerEvent<T>>,
    budget: Arc<ByteBudget>,
}

impl<T> UdpMapping<T> {
    pub const fn tuple(&self) -> UdpTuple {
        self.tuple
    }

    pub const fn terminal(&self) -> &T {
        &self.terminal
    }

    pub async fn receive(&mut self) -> Option<UdpDatagram> {
        self.receiver.recv().await
    }

    /// Queues one target-bound response for generation-checked owner-thread injection.
    pub fn send_response(&self, source: SocketAddr, payload: &[u8]) -> bool {
        if source != self.tuple.target || payload.len() > self.payload_bound {
            return false;
        }
        let Some(reservation) = self.budget.reserve(payload.len()) else {
            return false;
        };
        self.events
            .try_send(OwnerEvent::Response {
                id: self.id,
                tuple: self.tuple,
                source,
                payload: payload.to_vec(),
                _reservation: reservation,
            })
            .is_ok()
    }
}

impl<T> Drop for UdpMapping<T> {
    fn drop(&mut self) {
        let _ = self.events.try_send(OwnerEvent::Close { id: self.id });
    }
}

enum OwnerEvent<T> {
    Commit {
        id: GenerationId,
        tuple: UdpTuple,
        payload: Vec<u8>,
        payload_bound: usize,
        selected_payload_bound: usize,
        reservation: Reservation,
        terminal: T,
        reply: oneshot::Sender<Result<UdpMapping<T>, UdpCommitError>>,
    },
    Drop {
        id: GenerationId,
    },
    Close {
        id: GenerationId,
    },
    Response {
        id: GenerationId,
        tuple: UdpTuple,
        source: SocketAddr,
        payload: Vec<u8>,
        _reservation: Reservation,
    },
}

enum Slot {
    Candidate {
        tuple: UdpTuple,
        since_millis: i64,
    },
    Mapping {
        tuple: UdpTuple,
        selected_payload_bound: usize,
        sender: mpsc::Sender<UdpDatagram>,
        active_millis: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Admission {
    Provisional,
    Mapped,
    Dropped,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EventOutcome {
    pub(crate) committed: usize,
    pub(crate) injected: usize,
    pub(crate) dropped: usize,
}

pub(crate) struct UdpTable<T> {
    slots: Box<[Option<Slot>]>,
    generations: GenerationTable,
    candidates: mpsc::Sender<UdpCandidate<T>>,
    events: std::sync::mpsc::Receiver<OwnerEvent<T>>,
    event_sender: std::sync::mpsc::SyncSender<OwnerEvent<T>>,
    budget: Arc<ByteBudget>,
    idle_millis: i64,
}

impl<T: Send + 'static> UdpTable<T> {
    pub(crate) fn new(
        capacity: usize,
        buffered_bytes: usize,
        idle: Duration,
    ) -> (Self, mpsc::Receiver<UdpCandidate<T>>) {
        let (candidate_sender, candidate_receiver) = mpsc::channel(capacity);
        let (event_sender, events) = std::sync::mpsc::sync_channel(capacity * 2);
        (
            Self {
                slots: std::iter::repeat_with(|| None)
                    .take(capacity)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                generations: GenerationTable::new(capacity),
                candidates: candidate_sender,
                events,
                event_sender,
                budget: Arc::new(ByteBudget {
                    used: AtomicUsize::new(0),
                    limit: buffered_bytes,
                }),
                idle_millis: i64::try_from(idle.as_millis()).unwrap_or(i64::MAX),
            },
            candidate_receiver,
        )
    }

    pub(crate) fn admit(
        &mut self,
        tuple: UdpTuple,
        payload: &[u8],
        payload_bound: usize,
        now_millis: i64,
        admitting: bool,
    ) -> Admission {
        self.expire(now_millis);
        if let Some(index) = self.find(tuple) {
            let Some(Slot::Mapping {
                selected_payload_bound,
                sender,
                active_millis,
                ..
            }) = self.slots[index].as_mut()
            else {
                return Admission::Dropped;
            };
            if payload.len() > *selected_payload_bound {
                return Admission::Dropped;
            }
            let Some(reservation) = self.budget.reserve(payload.len()) else {
                return Admission::Dropped;
            };
            let datagram = UdpDatagram {
                tuple,
                payload: payload.to_vec(),
                _reservation: reservation,
            };
            if sender.try_send(datagram).is_err() {
                return Admission::Dropped;
            }
            *active_millis = now_millis;
            return Admission::Mapped;
        }
        if !admitting {
            return Admission::Dropped;
        }
        let Some(slot) = self.slots.iter().position(Option::is_none) else {
            return Admission::Dropped;
        };
        let Some(id) = self.generations.current(slot) else {
            return Admission::Dropped;
        };
        let Some(reservation) = self.budget.reserve(payload.len()) else {
            return Admission::Dropped;
        };
        self.slots[slot] = Some(Slot::Candidate {
            tuple,
            since_millis: now_millis,
        });
        let candidate = UdpCandidate {
            tuple,
            payload: Some(payload.to_vec()),
            payload_bound,
            reservation: Some(reservation),
            id,
            events: self.event_sender.clone(),
        };
        if self.candidates.try_send(candidate).is_err() {
            self.remove(id);
            return Admission::Dropped;
        }
        Admission::Provisional
    }

    pub(crate) fn process_events(
        &mut self,
        now_millis: i64,
        admitting: bool,
        mut inject: impl FnMut(UdpTuple, &[u8]) -> bool,
    ) -> EventOutcome {
        self.expire(now_millis);
        let mut outcome = EventOutcome::default();
        for _ in 0..crate::PACKET_QUANTUM {
            let Ok(event) = self.events.try_recv() else {
                break;
            };
            match event {
                OwnerEvent::Commit {
                    id,
                    tuple,
                    payload,
                    payload_bound,
                    selected_payload_bound,
                    reservation,
                    terminal,
                    reply,
                } => {
                    let current = self.slots.get(id.slot).and_then(Option::as_ref);
                    let valid = admitting
                        && self.generations.current(id.slot) == Some(id)
                        && matches!(current, Some(Slot::Candidate { tuple: current, .. }) if *current == tuple)
                        && payload.len() <= selected_payload_bound
                        && selected_payload_bound <= payload_bound;
                    if !valid {
                        let _ = reply.send(Err(UdpCommitError::Rejected));
                        outcome.dropped += 1;
                        continue;
                    }
                    let (sender, receiver) = mpsc::channel(MAPPING_QUEUE_PACKETS);
                    self.slots[id.slot] = Some(Slot::Mapping {
                        tuple,
                        selected_payload_bound,
                        sender: sender.clone(),
                        active_millis: now_millis,
                    });
                    let first = UdpDatagram {
                        tuple,
                        payload,
                        _reservation: reservation,
                    };
                    if sender.try_send(first).is_err() {
                        self.remove(id);
                        let _ = reply.send(Err(UdpCommitError::Rejected));
                        outcome.dropped += 1;
                        continue;
                    }
                    let mapping = UdpMapping {
                        id,
                        tuple,
                        terminal,
                        payload_bound,
                        receiver,
                        events: self.event_sender.clone(),
                        budget: Arc::clone(&self.budget),
                    };
                    if reply.send(Ok(mapping)).is_err() {
                        self.remove(id);
                        outcome.dropped += 1;
                    } else {
                        outcome.committed += 1;
                    }
                }
                OwnerEvent::Drop { id } | OwnerEvent::Close { id } => {
                    self.remove(id);
                }
                OwnerEvent::Response {
                    id,
                    tuple,
                    source,
                    payload,
                    ..
                } => {
                    let Some(Slot::Mapping {
                        tuple: current,
                        active_millis,
                        ..
                    }) = self.slots.get_mut(id.slot).and_then(Option::as_mut)
                    else {
                        outcome.dropped += 1;
                        continue;
                    };
                    if self.generations.current(id.slot) != Some(id)
                        || *current != tuple
                        || source != tuple.target
                        || !inject(tuple, &payload)
                    {
                        outcome.dropped += 1;
                    } else {
                        *active_millis = now_millis;
                        outcome.injected += 1;
                    }
                }
            }
        }
        outcome
    }

    pub(crate) fn live_mappings(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Some(Slot::Mapping { .. })))
            .count()
    }

    #[cfg(test)]
    pub(crate) fn provisional_candidates(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Some(Slot::Candidate { .. })))
            .count()
    }

    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.budget.used.load(Ordering::Acquire)
    }

    fn find(&self, tuple: UdpTuple) -> Option<usize> {
        self.slots.iter().position(|slot| match slot {
            Some(Slot::Candidate { tuple: current, .. })
            | Some(Slot::Mapping { tuple: current, .. }) => *current == tuple,
            None => false,
        })
    }

    fn expire(&mut self, now_millis: i64) {
        for slot in 0..self.slots.len() {
            let expired = self.slots[slot].as_ref().is_some_and(|entry| {
                let observed = match entry {
                    Slot::Candidate { since_millis, .. } => *since_millis,
                    Slot::Mapping { active_millis, .. } => *active_millis,
                };
                now_millis.saturating_sub(observed) >= self.idle_millis
            });
            if expired && let Some(id) = self.generations.current(slot) {
                self.remove(id);
            }
        }
    }

    fn remove(&mut self, id: GenerationId) {
        if self.generations.current(id.slot) == Some(id)
            && self.slots.get(id.slot).is_some_and(Option::is_some)
        {
            self.slots[id.slot] = None;
            let _ = self.generations.recycle(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(port: u16) -> UdpTuple {
        UdpTuple::new(
            format!("198.18.0.1:{port}").parse().expect("source"),
            "192.0.2.1:53".parse().expect("target"),
        )
    }

    #[tokio::test]
    async fn udp_candidate_is_mapping_free_until_owner_commit_and_releases_first_exactly_once() {
        let (mut table, mut candidates) =
            UdpTable::<&'static str>::new(1, 64, Duration::from_secs(60));
        assert_eq!(
            table.admit(tuple(10_000), b"query", 1_392, 0, true),
            Admission::Provisional
        );
        assert_eq!(table.live_mappings(), 0);
        assert_eq!(table.provisional_candidates(), 1);
        let candidate = candidates.try_recv().expect("one provisional candidate");
        assert_eq!(candidate.tuple(), tuple(10_000));
        assert_eq!(candidate.payload(), b"query");
        assert_eq!(candidate.packet_payload_bound(), 1_392);

        let commit = tokio::spawn(candidate.commit("route-a", 32));
        tokio::task::yield_now().await;
        let outcome = table.process_events(1, true, |_, _| true);
        assert_eq!(outcome.committed, 1);
        let mut mapping = commit.await.expect("decision task").expect("owner commit");
        assert_eq!(mapping.terminal(), &"route-a");
        assert_eq!(table.live_mappings(), 1);
        let first = mapping.receive().await.expect("first datagram");
        assert_eq!(first.tuple(), tuple(10_000));
        assert_eq!(first.payload(), b"query");
        assert!(mapping.receiver.try_recv().is_err(), "first released once");
    }

    #[tokio::test]
    async fn udp_quiesce_rejects_a_preexisting_provisional_commit() {
        let (mut table, mut candidates) =
            UdpTable::<&'static str>::new(1, 64, Duration::from_secs(60));
        assert_eq!(
            table.admit(tuple(10_001), b"query", 1_392, 0, true),
            Admission::Provisional
        );
        let commit = tokio::spawn(
            candidates
                .try_recv()
                .expect("provisional candidate")
                .commit("route-a", 32),
        );
        tokio::task::yield_now().await;
        let outcome = table.process_events(1, false, |_, _| true);
        assert_eq!(outcome.committed, 0);
        assert_eq!(outcome.dropped, 1);
        assert!(matches!(
            commit.await.expect("decision task"),
            Err(UdpCommitError::Rejected)
        ));
        assert_eq!(table.live_mappings(), 0);
        assert_eq!(table.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn udp_over_limit_queue_capacity_expiry_and_generation_are_fail_closed() {
        let (mut table, mut candidates) = UdpTable::<u8>::new(1, 16, Duration::from_millis(10));
        assert_eq!(
            table.admit(tuple(1), b"12345", 32, 0, true),
            Admission::Provisional
        );
        assert_eq!(
            table.admit(tuple(2), b"x", 32, 0, true),
            Admission::Dropped,
            "a provisional slot is bounded and never evicted"
        );
        let candidate = candidates.try_recv().expect("candidate");
        assert!(
            matches!(candidate.commit(1, 4).await, Err(UdpCommitError::Rejected)),
            "selected bound rejects without a mapping"
        );
        table.process_events(1, true, |_, _| true);
        assert_eq!(table.live_mappings(), 0);
        assert_eq!(table.buffered_bytes(), 0);

        assert_eq!(
            table.admit(tuple(1), b"ok", 32, 2, true),
            Admission::Provisional
        );
        let candidate = candidates.try_recv().expect("new generation candidate");
        let commit = tokio::spawn(candidate.commit(2, 8));
        tokio::task::yield_now().await;
        table.process_events(3, true, |_, _| true);
        let mut mapping = commit.await.expect("commit task").expect("mapping");
        drop(mapping.receive().await.expect("first"));
        for _ in 0..MAPPING_QUEUE_PACKETS {
            assert_eq!(table.admit(tuple(1), b"x", 32, 4, true), Admission::Mapped);
        }
        assert_eq!(
            table.admit(tuple(1), b"x", 32, 4, true),
            Admission::Dropped,
            "full mapping queue drops one complete datagram"
        );
        drop(mapping);
        table.process_events(5, true, |_, _| true);
        assert_eq!(table.live_mappings(), 0);
        assert_eq!(table.buffered_bytes(), 0);

        assert_eq!(
            table.admit(tuple(1), b"new", 32, 20, true),
            Admission::Provisional,
            "expiry/generation reuse permits reevaluation"
        );
    }

    #[tokio::test]
    async fn udp_response_requires_live_generation_exact_target_and_available_output() {
        let (mut table, mut candidates) = UdpTable::<()>::new(1, 64, Duration::from_secs(1));
        assert_eq!(
            table.admit(tuple(1), b"q", 32, 0, true),
            Admission::Provisional
        );
        let commit = tokio::spawn(candidates.try_recv().expect("candidate").commit((), 8));
        tokio::task::yield_now().await;
        table.process_events(1, true, |_, _| true);
        let mapping = commit.await.expect("task").expect("mapping");
        assert!(!mapping.send_response("192.0.2.2:53".parse().unwrap(), b"bad"));
        assert!(mapping.send_response(tuple(1).target(), b"answer"));
        let mut observed = Vec::new();
        assert_eq!(
            table
                .process_events(2, true, |mapped, payload| {
                    observed.push((mapped, payload.to_vec()));
                    true
                })
                .injected,
            1
        );
        assert_eq!(observed, vec![(tuple(1), b"answer".to_vec())]);
        assert!(mapping.send_response(tuple(1).target(), b"late"));
        drop(mapping);
        assert_eq!(
            table.process_events(1_003, true, |_, _| true).dropped,
            1,
            "queued stale generation response cannot inject after close"
        );
        assert_eq!(table.live_mappings(), 0);
    }
}
