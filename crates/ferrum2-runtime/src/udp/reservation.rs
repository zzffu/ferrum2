use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ferrum2_core::Datagram;
use tokio::sync::Notify;

use crate::OwnerRegistry;

use super::{MAX_UDP_WIRE_DATAGRAM_BYTES, UdpRuntimeError};

mod receive_pool;

use receive_pool::{ReceiveBuffer, ReceiveCache};

#[derive(Clone, Copy, Debug)]
enum BufferDomain {
    Ordinary,
    Tun,
}

#[derive(Debug)]
pub(super) struct BufferBudgetInner {
    limit: usize,
    reserved: AtomicUsize,
    released: Notify,
    registry: OwnerRegistry,
    domain: BufferDomain,
    receive_cache: Mutex<ReceiveCache>,
}

/// Cloneable global allocated-capacity budget.
///
/// Direct receive buffers share one reclaimable idle allocation per budget.
/// Its full physical capacity remains charged until reuse or eviction.
#[derive(Clone, Debug)]
pub struct UdpBufferBudget {
    inner: Arc<BufferBudgetInner>,
}

impl UdpBufferBudget {
    pub(super) fn new(limit: usize, registry: OwnerRegistry) -> Self {
        Self::with_domain(limit, registry, BufferDomain::Ordinary)
    }

    /// Creates an independently bounded managed-TUN allocated-capacity domain.
    pub fn new_tun(limit: usize, registry: OwnerRegistry) -> Self {
        Self::with_domain(limit, registry, BufferDomain::Tun)
    }

    fn with_domain(limit: usize, registry: OwnerRegistry, domain: BufferDomain) -> Self {
        Self {
            inner: Arc::new(BufferBudgetInner {
                limit,
                reserved: AtomicUsize::new(0),
                released: Notify::new(),
                registry,
                domain,
                receive_cache: Mutex::new(ReceiveCache::default()),
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
    /// Reclaims idle receive storage before reporting exhausted capacity.
    pub fn reserve(&self, capacity: usize) -> Result<UdpBufferReservation, UdpRuntimeError> {
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        let mut current = self.inner.reserved.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(capacity);
            if next.is_none_or(|next| next > self.inner.limit) {
                if self.inner.evict_receive_buffer() {
                    current = self.inner.reserved.load(Ordering::Relaxed);
                    continue;
                }
                return Err(UdpRuntimeError::BufferLimit);
            }
            match self.inner.reserved.compare_exchange_weak(
                current,
                next.expect("bounded UDP reservation"),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.inner.add_bytes(capacity);
                    return Ok(UdpBufferReservation {
                        charge: UdpBufferCharge::Metered(Arc::clone(&self.inner)),
                        capacity,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Ownership token for one exact allocated buffer capacity.
///
/// Tokens carry either the ordinary or an independent UDP byte-domain charge,
/// or retain an already charged receive-buffer payload owner. All allocations
/// remain charged and exact-capacity validation applies at commit time.
pub struct UdpBufferReservation {
    charge: UdpBufferCharge,
    capacity: usize,
}

enum UdpBufferCharge {
    Metered(Arc<BufferBudgetInner>),
    PayloadOwned(Arc<ReceiveBuffer>),
    Released,
}

impl UdpBufferReservation {
    /// Returns the exact allocated capacity owned by this token.
    pub const fn capacity(&self) -> usize {
        self.capacity
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
        match &self.charge {
            UdpBufferCharge::Metered(inner) => inner.release_bytes(self.capacity),
            UdpBufferCharge::PayloadOwned(owner) => {
                // The shared owner keeps both allocation and charge live, even
                // when only a retained Bytes slice or this token survives.
                let _ = owner;
            }
            UdpBufferCharge::Released => {}
        }
    }
}

impl BufferBudgetInner {
    fn add_bytes(&self, capacity: usize) {
        match self.domain {
            BufferDomain::Ordinary => self.registry.add_udp_buffered_bytes(capacity),
            BufferDomain::Tun => self.registry.add_tun_udp_buffered_bytes(capacity),
        }
    }

    fn release_bytes(&self, capacity: usize) {
        let previous = self.reserved.fetch_sub(capacity, Ordering::Relaxed);
        debug_assert!(previous >= capacity, "UDP buffer reservation underflow");
        match self.domain {
            BufferDomain::Ordinary => self.registry.remove_udp_buffered_bytes(capacity),
            BufferDomain::Tun => self.registry.remove_tun_udp_buffered_bytes(capacity),
        }
        if capacity != 0 {
            self.released.notify_waiters();
        }
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
    /// Direct receive payloads additionally retain the charge through every
    /// cloned or sliced `Bytes`, so dropping the token cannot release live storage.
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
    fn independent_datagrams_preserve_shared_queue_and_generation_bounds() {
        let limit = MIN_UDP_MAX_BUFFERED_BYTES;
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(2, limit, MIN_UDP_IDLE_TIMEOUT).expect("test limits"),
            OwnerRegistry::new(),
        );
        let budget = manager.buffer_budget();
        let tun = UdpBufferBudget::new_tun(limit, OwnerRegistry::new());
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
                .reserve_datagram_in_budget(
                    UdpDirection::ToTarget,
                    MAX_UDP_WIRE_DATAGRAM_BYTES + 1,
                    &tun,
                )
                .expect_err("independent datagrams retain the packet bound"),
            UdpRuntimeError::Bounds
        );
        let first = session
            .reserve_datagram_in_budget(UdpDirection::ToTarget, 8, &tun)
            .expect("independent first datagram");
        let (handle, first) = session
            .commit_immediate(first, test_datagram(8), Instant::now())
            .expect("activate independent session");
        assert_eq!(budget.reserved_bytes(), limit);
        drop(first);
        assert_eq!(budget.reserved_bytes(), limit);

        let pending = (0..UDP_SESSION_QUEUE_DEPTH)
            .map(|_| {
                manager
                    .reserve_datagram_in_budget(handle, UdpDirection::ToClient, 8, &tun)
                    .expect("bounded pending slot")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            manager
                .reserve_datagram_in_budget(handle, UdpDirection::ToClient, 8, &tun)
                .expect_err("independent datagrams retain queue depth"),
            UdpRuntimeError::QueueFull
        );
        assert_eq!(budget.reserved_bytes(), limit);
        drop(pending);

        assert!(manager.remove(handle));
        assert_eq!(
            manager
                .reserve_datagram_in_budget(handle, UdpDirection::ToClient, 8, &tun)
                .expect_err("independent datagrams retain generation checks"),
            UdpRuntimeError::Cancelled
        );
        drop(held);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(tun.reserved_bytes(), 0);
    }

    #[test]
    fn activity_commit_releases_exact_capacity_and_queue_ownership() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(2, MIN_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT)
                .expect("test limits"),
            registry.clone(),
        );
        let budget = manager.buffer_budget();
        let tun = UdpBufferBudget::new_tun(7, registry.clone());
        let started = Instant::now();
        let first_activity = started + Duration::from_secs(1);
        let session = manager
            .reserve_session(started)
            .expect("provisional session");
        let first = session
            .reserve_datagram(UdpDirection::ToTarget, 8)
            .expect("metered first activity");
        assert_eq!(budget.reserved_bytes(), 8);
        let handle = session
            .commit_activity(first, first_activity)
            .expect("activate from borrowed activity");
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(
            manager.idle_deadline(handle).expect("first deadline"),
            first_activity + MIN_UDP_IDLE_TIMEOUT
        );

        let mut pending = (0..UDP_SESSION_QUEUE_DEPTH)
            .map(|_| {
                manager
                    .reserve_datagram(handle, UdpDirection::ToTarget, 1)
                    .expect("metered pending activity")
            })
            .collect::<Vec<_>>();
        assert_eq!(budget.reserved_bytes(), UDP_SESSION_QUEUE_DEPTH);
        assert_eq!(
            manager
                .reserve_datagram_in_budget(handle, UdpDirection::ToTarget, 7, &tun)
                .expect_err("activity admission retains queue depth"),
            UdpRuntimeError::QueueFull
        );

        let second_activity = first_activity + Duration::from_secs(1);
        pending
            .pop()
            .expect("reserved activity")
            .commit_activity(second_activity)
            .expect("commit metered activity");
        assert_eq!(budget.reserved_bytes(), UDP_SESSION_QUEUE_DEPTH - 1);
        let independent = manager
            .reserve_datagram_in_budget(handle, UdpDirection::ToTarget, 7, &tun)
            .expect("released queue slot");
        assert_eq!(budget.reserved_bytes(), UDP_SESSION_QUEUE_DEPTH - 1);
        assert_eq!(tun.reserved_bytes(), 7);
        let final_activity = second_activity + Duration::from_secs(1);
        independent
            .commit_activity(final_activity)
            .expect("commit independent activity");
        assert_eq!(budget.reserved_bytes(), UDP_SESSION_QUEUE_DEPTH - 1);
        assert_eq!(tun.reserved_bytes(), 0);
        drop(pending);
        assert_eq!(budget.reserved_bytes(), 0);
        assert!(
            manager
                .pop(handle, UdpDirection::ToTarget)
                .expect("live queue")
                .is_none()
        );
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);
        assert_eq!(
            manager.idle_deadline(handle).expect("final deadline"),
            final_activity + MIN_UDP_IDLE_TIMEOUT
        );
        assert!(manager.remove(handle));
        assert_eq!(registry.snapshot(), baseline);
    }

    #[test]
    fn activity_commit_rejects_a_fenced_generation_and_rolls_back() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let manager = UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone());
        let started = Instant::now();
        let session = manager
            .reserve_session(started)
            .expect("provisional session");
        let first = session
            .reserve_datagram(UdpDirection::ToTarget, 8)
            .expect("first activity");
        let handle = session
            .commit_activity(first, started)
            .expect("activate session");
        let pending = manager
            .reserve_datagram(handle, UdpDirection::ToTarget, 13)
            .expect("pending activity");
        assert_eq!(manager.buffer_budget().reserved_bytes(), 13);

        manager
            .fence_network_generation(1)
            .expect("fence current cohort");
        assert_eq!(
            pending.commit_activity(started + Duration::from_secs(1)),
            Err(UdpRuntimeError::Cancelled)
        );
        assert_eq!(manager.buffer_budget().reserved_bytes(), 0);
        assert!(!manager.cleanup_failed());
        assert_eq!(manager.retire_network_generation(1), Ok(1));
        manager
            .reopen_network_generation(1)
            .expect("complete network reset");
        assert_eq!(registry.snapshot(), baseline);
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
            cancelled_budget.receive_buffer().await
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
            waiting_budget.receive_buffer().await
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
        budget.clear_receive_cache();
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    }
}
