use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ferrum2_core::Datagram;
use tokio::sync::Notify;

use crate::OwnerRegistry;

use super::{MAX_UDP_WIRE_DATAGRAM_BYTES, UdpRuntimeError};

#[derive(Debug)]
pub(super) struct BufferBudgetInner {
    limit: usize,
    reserved: AtomicUsize,
    released: Notify,
    registry: OwnerRegistry,
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
                released: Notify::new(),
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
        if capacity > MAX_UDP_WIRE_DATAGRAM_BYTES {
            return Err(UdpRuntimeError::Bounds);
        }
        let mut current = self.inner.reserved.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(capacity) else {
                return Err(UdpRuntimeError::BufferLimit);
            };
            if next > self.inner.limit {
                return Err(UdpRuntimeError::BufferLimit);
            }
            match self.inner.reserved.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.inner.registry.add_udp_buffered_bytes(capacity);
                    return Ok(UdpBufferReservation {
                        charge: UdpBufferCharge::Metered(Arc::clone(&self.inner)),
                        capacity,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    pub(super) async fn reserve_when_available(
        &self,
        capacity: usize,
    ) -> Result<UdpBufferReservation, UdpRuntimeError> {
        loop {
            let notified = self.inner.released.notified();
            tokio::pin!(notified);
            match self.reserve(capacity) {
                Ok(reservation) => return Ok(reservation),
                Err(UdpRuntimeError::BufferLimit) => {
                    notified.as_mut().enable();
                    match self.reserve(capacity) {
                        Ok(reservation) => return Ok(reservation),
                        Err(UdpRuntimeError::BufferLimit) => notified.as_mut().await,
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
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
        let UdpBufferCharge::Metered(inner) = &self.charge else {
            return;
        };
        let previous = inner.reserved.fetch_sub(self.capacity, Ordering::Relaxed);
        debug_assert!(
            previous >= self.capacity,
            "UDP buffer reservation underflow"
        );
        inner.registry.remove_udp_buffered_bytes(self.capacity);
        if self.capacity != 0 {
            inner.released.notify_waiters();
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
}
