use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use ferrum2_core::Datagram;
use tokio::sync::oneshot;

use crate::OwnerRegistry;

use super::{MAX_UDP_WIRE_DATAGRAM_BYTES, UdpRuntimeError};

pub(super) struct BufferBudgetInner {
    limit: usize,
    reserved: AtomicUsize,
    waiters: StdMutex<BudgetWaiters>,
    registry: OwnerRegistry,
}

const MAX_BUDGET_GRANTS_PER_PASS: usize = 8;
const MAX_OLDEST_WAITER_BYPASSES: u8 = 8;

#[derive(Default)]
struct BudgetWaiters {
    entries: VecDeque<BudgetWaiter>,
    next_sequence: u64,
}

struct BudgetWaiter {
    requested_capacity: usize,
    sequence: u64,
    bypasses: u8,
    grant: oneshot::Sender<UdpBufferReservation>,
}

type BudgetGrant = (oneshot::Sender<UdpBufferReservation>, UdpBufferReservation);

impl fmt::Debug for BufferBudgetInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BufferBudgetInner")
            .field("limit", &self.limit)
            .field("reserved", &self.reserved.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Cloneable global allocated-capacity budget.
#[derive(Clone, Debug)]
pub struct UdpBufferBudget {
    inner: Arc<BufferBudgetInner>,
}

impl UdpBufferBudget {
    pub(super) fn new(limit: usize, registry: OwnerRegistry) -> Self {
        Self {
            inner: Arc::new(BufferBudgetInner {
                limit,
                reserved: AtomicUsize::new(0),
                waiters: StdMutex::new(BudgetWaiters::default()),
                registry,
            }),
        }
    }

    /// Returns allocated-capacity bytes currently reserved.
    ///
    /// The atomic is only a numeric capacity gate; it does not publish buffer
    /// contents or session state, which remain protected by their own owners.
    pub fn reserved_bytes(&self) -> usize {
        self.inner.reserved.load(Ordering::Relaxed)
    }

    /// Reserves exact allocated capacity before accepted protocol state advances.
    pub fn reserve(&self, capacity: usize) -> Result<UdpBufferReservation, UdpRuntimeError> {
        validate_capacity(capacity)?;
        self.reserve_validated(capacity)
    }

    #[cfg(feature = "candidate-udp-owned-headroom")]
    pub(super) fn reserve_headroom(
        &self,
        capacity: usize,
    ) -> Result<UdpBufferReservation, UdpRuntimeError> {
        if capacity > super::headroom::MAX_UDP_HEADROOM_ALLOCATION_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        self.reserve_validated(capacity)
    }

    fn reserve_validated(&self, capacity: usize) -> Result<UdpBufferReservation, UdpRuntimeError> {
        if capacity == 0 {
            return Ok(zero_capacity_reservation(&self.inner));
        }
        let (reservation, grants) = {
            let mut waiters = lock_unpoisoned(&self.inner.waiters);
            let grants = grant_waiters_locked(&self.inner, &mut waiters);
            let reservation = if waiters.entries.is_empty() {
                try_reserve_locked(&self.inner, capacity)
            } else {
                // An immediate caller must not repeatedly steal capacity from
                // older async waiters. It retains the existing fail-fast API.
                Err(UdpRuntimeError::BufferLimit)
            };
            (reservation, grants)
        };
        dispatch_grants(grants);
        reservation
    }

    pub(super) async fn reserve_when_available(
        &self,
        capacity: usize,
    ) -> Result<UdpBufferReservation, UdpRuntimeError> {
        validate_capacity(capacity)?;
        if capacity == 0 {
            return Ok(zero_capacity_reservation(&self.inner));
        }
        let (immediate, receiver, grants) = {
            let mut waiters = lock_unpoisoned(&self.inner.waiters);
            if waiters.entries.is_empty() {
                match try_reserve_locked(&self.inner, capacity) {
                    Ok(reservation) => (Some(reservation), None, Vec::new()),
                    Err(UdpRuntimeError::BufferLimit) => {
                        let receiver = enqueue_waiter(&mut waiters, capacity);
                        let grants = grant_waiters_locked(&self.inner, &mut waiters);
                        (None, Some(receiver), grants)
                    }
                    Err(error) => return Err(error),
                }
            } else {
                let receiver = enqueue_waiter(&mut waiters, capacity);
                let grants = grant_waiters_locked(&self.inner, &mut waiters);
                (None, Some(receiver), grants)
            }
        };
        dispatch_grants(grants);
        if let Some(reservation) = immediate {
            return Ok(reservation);
        }
        let reservation = receiver
            .expect("queued UDP budget waiter")
            .await
            .map_err(|_| UdpRuntimeError::Cancelled)?;
        // Continue a bounded handoff chain when one release made enough room
        // for more than a single grant batch. Every receiver is targeted, so
        // this does not turn back into a broadcast wakeup.
        wake_available_waiters(&self.inner);
        Ok(reservation)
    }
}

fn validate_capacity(capacity: usize) -> Result<(), UdpRuntimeError> {
    if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
        Err(UdpRuntimeError::Bounds)
    } else {
        Ok(())
    }
}

fn zero_capacity_reservation(inner: &Arc<BufferBudgetInner>) -> UdpBufferReservation {
    UdpBufferReservation {
        charge: UdpBufferCharge::Metered(Arc::clone(inner)),
        capacity: 0,
    }
}

fn enqueue_waiter(
    waiters: &mut BudgetWaiters,
    requested_capacity: usize,
) -> oneshot::Receiver<UdpBufferReservation> {
    if waiters.next_sequence == u64::MAX {
        for (sequence, waiter) in waiters.entries.iter_mut().enumerate() {
            waiter.sequence = sequence as u64;
        }
        waiters.next_sequence = waiters.entries.len() as u64;
    }
    let sequence = waiters.next_sequence;
    waiters.next_sequence += 1;
    let (grant, receiver) = oneshot::channel();
    waiters.entries.push_back(BudgetWaiter {
        requested_capacity,
        sequence,
        bypasses: 0,
        grant,
    });
    receiver
}

fn try_reserve_locked(
    inner: &Arc<BufferBudgetInner>,
    capacity: usize,
) -> Result<UdpBufferReservation, UdpRuntimeError> {
    let current = inner.reserved.load(Ordering::Relaxed);
    let Some(next) = current.checked_add(capacity) else {
        return Err(UdpRuntimeError::BufferLimit);
    };
    if next > inner.limit {
        return Err(UdpRuntimeError::BufferLimit);
    }
    inner.reserved.store(next, Ordering::Relaxed);
    inner.registry.add_udp_buffered_bytes(capacity);
    Ok(UdpBufferReservation {
        charge: UdpBufferCharge::Metered(Arc::clone(inner)),
        capacity,
    })
}

fn grant_waiters_locked(
    inner: &Arc<BufferBudgetInner>,
    waiters: &mut BudgetWaiters,
) -> Vec<BudgetGrant> {
    waiters.entries.retain(|waiter| !waiter.grant.is_closed());
    let mut grants = Vec::new();
    while grants.len() < MAX_BUDGET_GRANTS_PER_PASS && !waiters.entries.is_empty() {
        let available = inner
            .limit
            .saturating_sub(inner.reserved.load(Ordering::Relaxed));
        let grant_index = if waiters.entries[0].requested_capacity <= available {
            Some(0)
        } else if waiters.entries[0].bypasses < MAX_OLDEST_WAITER_BYPASSES {
            waiters
                .entries
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(_, waiter)| waiter.requested_capacity <= available)
                .min_by_key(|(_, waiter)| waiter.sequence)
                .map(|(index, _)| index)
        } else {
            None
        };
        let Some(grant_index) = grant_index else {
            break;
        };
        if grant_index != 0 {
            waiters.entries[0].bypasses += 1;
        }
        let waiter = waiters
            .entries
            .remove(grant_index)
            .expect("selected UDP budget waiter");
        let reservation = try_reserve_locked(inner, waiter.requested_capacity)
            .expect("selected UDP waiter fits available capacity");
        grants.push((waiter.grant, reservation));
    }
    grants
}

fn dispatch_grants(grants: Vec<BudgetGrant>) {
    let mut grants = VecDeque::from(grants);
    while let Some((grant, reservation)) = grants.pop_front() {
        if let Err(unclaimed) = grant.send(reservation) {
            let (inner, capacity) = unclaimed
                .take_metered_charge()
                .expect("budget queue grants only metered reservations");
            grants.extend(release_metered_capacity(&inner, capacity));
        }
    }
}

fn wake_available_waiters(inner: &Arc<BufferBudgetInner>) {
    let grants = {
        let mut waiters = lock_unpoisoned(&inner.waiters);
        grant_waiters_locked(inner, &mut waiters)
    };
    dispatch_grants(grants);
}

fn release_metered_capacity(inner: &Arc<BufferBudgetInner>, capacity: usize) -> Vec<BudgetGrant> {
    if capacity == 0 {
        return Vec::new();
    }
    let mut waiters = lock_unpoisoned(&inner.waiters);
    let previous = inner.reserved.load(Ordering::Relaxed);
    debug_assert!(previous >= capacity, "UDP buffer reservation underflow");
    inner
        .reserved
        .store(previous.saturating_sub(capacity), Ordering::Relaxed);
    inner.registry.remove_udp_buffered_bytes(capacity);
    grant_waiters_locked(inner, &mut waiters)
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Ownership token for one exact allocated buffer capacity.
///
/// Ordinary tokens carry the global UDP byte-budget charge. Runtime session
/// APIs may also create an unmetered token for a structurally bounded caller;
/// both kinds retain the same exact-capacity validation at commit time.
pub struct UdpBufferReservation {
    charge: UdpBufferCharge,
    capacity: usize,
}

enum UdpBufferCharge {
    Metered(Arc<BufferBudgetInner>),
    Unmetered,
}

impl UdpBufferReservation {
    pub(super) fn unmetered(capacity: usize) -> Result<Self, UdpRuntimeError> {
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            charge: UdpBufferCharge::Unmetered,
            capacity,
        })
    }

    /// Returns the exact allocated capacity owned by this token.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(feature = "candidate-udp-owned-headroom")]
    pub(super) fn belongs_to(&self, budget: &UdpBufferBudget) -> bool {
        matches!(
            &self.charge,
            UdpBufferCharge::Metered(inner) if Arc::ptr_eq(inner, &budget.inner)
        )
    }

    pub(super) fn attach(self, datagram: Datagram) -> Result<AccountedDatagram, UdpRuntimeError> {
        if datagram.allocated_capacity() != self.capacity
            || datagram.payload().len() > MAX_UDP_WIRE_DATAGRAM_BYTES
        {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(AccountedDatagram {
            datagram,
            reservation: self,
        })
    }

    fn take_metered_charge(mut self) -> Option<(Arc<BufferBudgetInner>, usize)> {
        let charge = std::mem::replace(&mut self.charge, UdpBufferCharge::Unmetered);
        let capacity = std::mem::replace(&mut self.capacity, 0);
        match charge {
            UdpBufferCharge::Metered(inner) => Some((inner, capacity)),
            UdpBufferCharge::Unmetered => None,
        }
    }
}

impl fmt::Debug for UdpBufferReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpBufferReservation")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Drop for UdpBufferReservation {
    fn drop(&mut self) {
        let UdpBufferCharge::Metered(inner) = &self.charge else {
            return;
        };
        let grants = release_metered_capacity(inner, self.capacity);
        dispatch_grants(grants);
    }
}

/// Datagram coupled to exactly one allocated-capacity ownership token.
pub struct AccountedDatagram {
    pub(super) datagram: Datagram,
    pub(super) reservation: UdpBufferReservation,
}

impl AccountedDatagram {
    /// Returns the bounded datagram.
    pub fn datagram(&self) -> &Datagram {
        &self.datagram
    }

    /// Returns the owned backing capacity.
    pub const fn allocated_capacity(&self) -> usize {
        self.reservation.capacity()
    }

    /// Separates the datagram from its exact capacity owner for a caller that
    /// recycles the backing allocation into another already-owned buffer.
    /// The reservation must remain alive until that transfer is complete.
    pub fn into_parts(self) -> (Datagram, UdpBufferReservation) {
        (self.datagram, self.reservation)
    }
}

impl fmt::Debug for AccountedDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountedDatagram")
            .field("datagram", &self.datagram)
            .field("allocated_capacity", &self.allocated_capacity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::BytesMut;

    use tokio::sync::Notify;
    use tokio::time::Instant;

    use super::super::{
        MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, UDP_SESSION_QUEUE_DEPTH, UdpDirection,
        UdpRuntimeLimits, UdpSessionManager,
    };
    use super::*;

    fn exhaust_budget(budget: &UdpBufferBudget, limit: usize) -> Vec<UdpBufferReservation> {
        let mut remaining = limit
            .checked_sub(budget.reserved_bytes())
            .expect("test budget is not overcommitted");
        let mut held = Vec::new();
        while remaining != 0 {
            let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            held.push(budget.reserve(capacity).expect("fill test budget"));
            remaining -= capacity;
        }
        held
    }

    async fn wait_for_waiter_count(budget: &UdpBufferBudget, expected: usize) {
        for _ in 0..200 {
            let count = lock_unpoisoned(&budget.inner.waiters).entries.len();
            if count == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("UDP budget waiter count did not reach {expected}");
    }

    fn test_datagram(capacity: usize) -> Datagram {
        let mut payload = BytesMut::with_capacity(capacity);
        payload.extend_from_slice(b"x");
        assert_eq!(payload.capacity(), capacity);
        Datagram::new(
            ferrum2_core::TargetAddr::ip("192.0.2.1:53".parse().expect("test target"))
                .expect("nonzero target port"),
            payload,
            capacity,
        )
        .expect("bounded datagram")
    }

    #[test]
    fn unmetered_datagrams_bypass_only_the_global_byte_budget() {
        let limit = MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(2, limit, MIN_UDP_IDLE_TIMEOUT).expect("test limits"),
            OwnerRegistry::new(),
        );
        let budget = manager.buffer_budget();
        let held = exhaust_budget(&budget, limit);
        assert_eq!(budget.reserved_bytes(), limit);

        let session = manager
            .reserve_session(Instant::now())
            .expect("provisional session");
        assert_eq!(
            session
                .reserve_datagram(UdpDirection::ToTarget, 8)
                .expect_err("metered datagram must observe the full budget"),
            UdpRuntimeError::BufferLimit
        );
        assert_eq!(
            session
                .reserve_unmetered_datagram(
                    UdpDirection::ToTarget,
                    MAX_UDP_WIRE_DATAGRAM_BYTES + 1,
                )
                .expect_err("unmetered datagrams retain the packet bound"),
            UdpRuntimeError::Bounds
        );
        let first = session
            .reserve_unmetered_datagram(UdpDirection::ToTarget, 8)
            .expect("unmetered first datagram");
        let (handle, first) = session
            .commit_immediate(first, test_datagram(8), Instant::now())
            .expect("activate unmetered session");
        assert_eq!(budget.reserved_bytes(), limit);
        drop(first);
        assert_eq!(budget.reserved_bytes(), limit);

        let pending = (0..UDP_SESSION_QUEUE_DEPTH)
            .map(|_| {
                manager
                    .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                    .expect("bounded pending slot")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            manager
                .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                .expect_err("unmetered datagrams retain queue depth"),
            UdpRuntimeError::QueueFull
        );
        assert_eq!(budget.reserved_bytes(), limit);
        drop(pending);

        assert!(manager.remove(handle));
        assert_eq!(
            manager
                .reserve_unmetered_datagram(handle, UdpDirection::ToClient, 8)
                .expect_err("unmetered datagrams retain generation checks"),
            UdpRuntimeError::Cancelled
        );
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[tokio::test]
    async fn budget_wait_is_cancel_safe_and_release_cannot_be_lost() {
        let registry = OwnerRegistry::new();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let budget = manager.buffer_budget();
        let mut held = Vec::new();
        while let Ok(reservation) = budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES) {
            held.push(reservation);
        }
        assert!(!held.is_empty());
        assert_eq!(
            budget.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES).unwrap_err(),
            UdpRuntimeError::BufferLimit
        );

        let started = Arc::new(Notify::new());
        let cancelled_budget = budget.clone();
        let cancelled_started = Arc::clone(&started);
        let cancelled = tokio::spawn(async move {
            cancelled_started.notify_one();
            cancelled_budget
                .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
                .await
        });
        started.notified().await;
        tokio::task::yield_now().await;
        assert!(!cancelled.is_finished());
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("cancelled waiter")
                .is_cancelled()
        );

        let started = Arc::new(Notify::new());
        let waiting_budget = budget.clone();
        let waiting_started = Arc::clone(&started);
        let waiting = tokio::spawn(async move {
            waiting_started.notify_one();
            waiting_budget
                .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
                .await
        });
        started.notified().await;
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());

        drop(held.pop());
        let acquired = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("released capacity wakes waiter")
            .expect("waiter task")
            .expect("capacity reservation");
        drop(acquired);
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }

    #[tokio::test]
    async fn one_release_grants_only_a_bounded_satisfiable_waiter_batch() {
        let registry = OwnerRegistry::new();
        let budget = UdpBufferBudget::new(MIN_UDP_MAX_BUFFERED_BYTES, registry.clone());
        let released = budget.reserve(8).expect("controlled release capacity");
        let held = exhaust_budget(&budget, MIN_UDP_MAX_BUFFERED_BYTES);

        let large_budget = budget.clone();
        let large = tokio::spawn(async move {
            large_budget
                .reserve_when_available(MAX_UDP_WIRE_DATAGRAM_BYTES)
                .await
        });
        wait_for_waiter_count(&budget, 1).await;

        let mut small = Vec::new();
        for _ in 0..20 {
            let small_budget = budget.clone();
            small.push(tokio::spawn(async move {
                small_budget.reserve_when_available(1).await
            }));
        }
        wait_for_waiter_count(&budget, 21).await;

        drop(released);
        assert_eq!(budget.reserved_bytes(), MIN_UDP_MAX_BUFFERED_BYTES);
        assert_eq!(
            lock_unpoisoned(&budget.inner.waiters).entries.len(),
            13,
            "one release grants only the fixed batch of eight satisfiable waiters"
        );

        large.abort();
        let _ = large.await;
        for waiter in small {
            waiter.abort();
            if let Ok(Ok(reservation)) = waiter.await {
                drop(reservation);
            }
        }
        drop(held);
        for _ in 0..200 {
            if budget.reserved_bytes() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }

    #[tokio::test]
    async fn oldest_large_waiter_is_protected_after_bounded_small_bypasses() {
        let registry = OwnerRegistry::new();
        let budget = UdpBufferBudget::new(MIN_UDP_MAX_BUFFERED_BYTES, registry.clone());
        let mut released = Vec::new();
        for _ in 0..40 {
            released.push(budget.reserve(1_024).expect("controlled release chunk"));
        }
        let held = exhaust_budget(&budget, MIN_UDP_MAX_BUFFERED_BYTES);

        let large_budget = budget.clone();
        let large = tokio::spawn(async move { large_budget.reserve_when_available(32_768).await });
        wait_for_waiter_count(&budget, 1).await;
        let mut small = Vec::new();
        for _ in 0..16 {
            let small_budget = budget.clone();
            small.push(tokio::spawn(async move {
                small_budget.reserve_when_available(1_024).await
            }));
        }
        wait_for_waiter_count(&budget, 17).await;

        for reservation in released.drain(..) {
            drop(reservation);
        }
        let large_reservation = tokio::time::timeout(Duration::from_secs(1), large)
            .await
            .expect("oldest large waiter is eventually granted")
            .expect("large waiter task")
            .expect("large capacity reservation");

        for waiter in small {
            waiter.abort();
            if let Ok(Ok(reservation)) = waiter.await {
                drop(reservation);
            }
        }
        drop(large_reservation);
        drop(held);
        for _ in 0..200 {
            if budget.reserved_bytes() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }

    #[tokio::test]
    async fn satisfiable_new_waiter_can_use_spare_capacity_behind_a_large_waiter() {
        let registry = OwnerRegistry::new();
        let budget = UdpBufferBudget::new(MIN_UDP_MAX_BUFFERED_BYTES, registry.clone());
        let mut remaining = MIN_UDP_MAX_BUFFERED_BYTES - 1_024;
        let mut held = Vec::new();
        while remaining != 0 {
            let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
            held.push(budget.reserve(capacity).expect("controlled held capacity"));
            remaining -= capacity;
        }

        let large_budget = budget.clone();
        let large = tokio::spawn(async move { large_budget.reserve_when_available(2_048).await });
        wait_for_waiter_count(&budget, 1).await;
        drop(
            budget
                .reserve(0)
                .expect("zero capacity never waits behind byte consumers"),
        );

        let small =
            tokio::time::timeout(Duration::from_secs(1), budget.reserve_when_available(1_024))
                .await
                .expect("satisfiable waiter receives the existing spare capacity")
                .expect("small capacity reservation");
        assert_eq!(small.capacity(), 1_024);
        assert!(!large.is_finished());

        large.abort();
        let _ = large.await;
        drop(small);
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }
}
