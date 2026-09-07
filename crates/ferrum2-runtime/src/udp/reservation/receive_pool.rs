use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use ferrum2_core::{Datagram, TargetAddr};

use super::{
    AccountedDatagram, BufferBudgetInner, MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget,
    UdpBufferCharge, UdpBufferReservation, UdpRuntimeError,
};

/// One idle allocation per shared byte domain, never one per idle session.
/// Cached physical capacity remains charged and is reclaimable by any reservation.
#[derive(Debug, Default)]
pub(super) struct ReceiveCache {
    epoch: u64,
    buffer: Option<BytesMut>,
}

pub(in crate::udp) struct ReceiveBuffer {
    buffer: Option<BytesMut>,
    reservation: UdpBufferReservation,
    epoch: u64,
}

impl std::fmt::Debug for ReceiveBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReceiveBuffer([redacted])")
    }
}

impl UdpBufferBudget {
    pub(in crate::udp) async fn receive_buffer(&self) -> Result<ReceiveBuffer, UdpRuntimeError> {
        loop {
            let notified = self.inner.released.notified();
            tokio::pin!(notified);
            // Register before observing both cache and counter: a returned buffer
            // may wake us without changing the charged capacity.
            notified.as_mut().enable();
            let epoch = {
                let mut cache = self.inner.lock_receive_cache();
                if let Some(buffer) = cache.buffer.take() {
                    return Ok(ReceiveBuffer {
                        reservation: UdpBufferReservation {
                            capacity: buffer.capacity(),
                            charge: UdpBufferCharge::Metered(Arc::clone(&self.inner)),
                        },
                        buffer: Some(buffer),
                        epoch: cache.epoch,
                    });
                }
                cache.epoch
            };
            match self.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES) {
                Ok(reservation) => {
                    let buffer = BytesMut::with_capacity(MAX_UDP_WIRE_DATAGRAM_BYTES);
                    if buffer.capacity() != reservation.capacity() {
                        return Err(UdpRuntimeError::Bounds);
                    }
                    return Ok(ReceiveBuffer {
                        buffer: Some(buffer),
                        reservation,
                        epoch,
                    });
                }
                Err(UdpRuntimeError::BufferLimit) => notified.as_mut().await,
                Err(error) => return Err(error),
            }
        }
    }

    /// Retires cached capacity and fences outstanding leases from refilling it.
    pub(in crate::udp) fn clear_receive_cache(&self) {
        let buffer = {
            let mut cache = self.inner.lock_receive_cache();
            cache.epoch = cache
                .epoch
                .checked_add(1)
                .expect("UDP receive cache epoch exhausted");
            cache.buffer.take()
        };
        self.inner.release_cached_buffer(buffer);
    }
}

impl BufferBudgetInner {
    fn lock_receive_cache(&self) -> std::sync::MutexGuard<'_, ReceiveCache> {
        match self.receive_cache.lock() {
            Ok(cache) => cache,
            Err(poisoned) => {
                // Never reuse a poisoned cache's backing storage or outstanding
                // leases; normal allocations remain available through the budget.
                let mut cache = poisoned.into_inner();
                cache.epoch = cache
                    .epoch
                    .checked_add(1)
                    .expect("UDP receive cache epoch exhausted");
                self.release_cached_buffer(cache.buffer.take());
                cache
            }
        }
    }

    pub(super) fn evict_receive_buffer(&self) -> bool {
        let buffer = self.lock_receive_cache().buffer.take();
        let evicted = buffer.is_some();
        self.release_cached_buffer(buffer);
        evicted
    }

    fn release_cached_buffer(&self, buffer: Option<BytesMut>) {
        if let Some(buffer) = buffer {
            let capacity = buffer.capacity();
            // Release physical storage before publishing reusable byte capacity.
            drop(buffer);
            self.release_bytes(capacity);
        }
    }
}

impl Drop for BufferBudgetInner {
    fn drop(&mut self) {
        let cache = match self.receive_cache.get_mut() {
            Ok(cache) => cache,
            Err(poisoned) => poisoned.into_inner(),
        };
        let buffer = cache.buffer.take();
        self.release_cached_buffer(buffer);
    }
}

impl ReceiveBuffer {
    pub(in crate::udp) fn buffer_mut(&mut self) -> &mut BytesMut {
        self.buffer.as_mut().expect("live UDP receive lease")
    }

    pub(in crate::udp) fn into_datagram(
        self,
        target: TargetAddr,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        let capacity = self.reservation.capacity();
        let owner = Arc::new(self);
        let payload = Bytes::from_owner(ReceivePayload(Arc::clone(&owner)));
        let datagram =
            Datagram::from_owned_bytes(target, payload, capacity, MAX_UDP_WIRE_DATAGRAM_BYTES)
                .map_err(|_| UdpRuntimeError::Bounds)?;
        UdpBufferReservation {
            charge: UdpBufferCharge::PayloadOwned(owner),
            capacity,
        }
        .attach(datagram)
    }
}

struct ReceivePayload(Arc<ReceiveBuffer>);

impl AsRef<[u8]> for ReceivePayload {
    fn as_ref(&self) -> &[u8] {
        self.0.buffer.as_ref().expect("live UDP receive lease")
    }
}

impl Drop for ReceiveBuffer {
    fn drop(&mut self) {
        let Some(mut buffer) = self.buffer.take() else {
            return;
        };
        let UdpBufferCharge::Metered(inner) = &self.reservation.charge else {
            unreachable!("receive allocation owns a metered reservation");
        };
        let mut cache = inner.lock_receive_cache();
        if cache.epoch == self.epoch && cache.buffer.is_none() {
            buffer.clear();
            cache.buffer = Some(buffer);
            inner.released.notify_waiters();
            drop(cache);
            // Transfer the existing counter charge to the cached physical buffer;
            // do not retain an Arc token in the cache (that would form a cycle).
            self.reservation.charge = UdpBufferCharge::Released;
        } else {
            drop(cache);
            drop(buffer);
        }
    }
}
