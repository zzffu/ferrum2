use std::fmt;
use std::ops::Range;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};

use super::{MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget, UdpBufferReservation, UdpRuntimeError};

pub(super) const MAX_UDP_HEADROOM_ALLOCATION_BYTES: usize = MAX_UDP_WIRE_DATAGRAM_BYTES * 2;

/// One fixed-capacity datagram layout reserved before socket receive starts.
///
/// `front_reserve` is the largest protocol prefix that may precede the
/// application payload. `rear_reserve` is the largest suffix that may follow
/// it. The remaining bytes are the complete receive bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpHeadroomLayout {
    capacity: usize,
    front_reserve: usize,
    rear_reserve: usize,
    receive_bound: usize,
}

impl UdpHeadroomLayout {
    /// Validates one protocol-neutral fixed layout.
    pub fn new(
        capacity: usize,
        front_reserve: usize,
        rear_reserve: usize,
    ) -> Result<Self, UdpRuntimeError> {
        let reserved = front_reserve
            .checked_add(rear_reserve)
            .ok_or(UdpRuntimeError::Bounds)?;
        if capacity == 0 || capacity > MAX_UDP_WIRE_DATAGRAM_BYTES || reserved >= capacity {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            capacity,
            front_reserve,
            rear_reserve,
            receive_bound: capacity - reserved,
        })
    }

    /// Builds a fixed allocation that can receive one complete maximum-sized
    /// ingress datagram after its front reserve without socket truncation.
    ///
    /// The rear reserve is validated after receive. Datagrams consuming that
    /// space are rejected intact rather than being silently shortened by the
    /// socket adapter.
    pub fn for_receive_bound(
        receive_bound: usize,
        front_reserve: usize,
        rear_reserve: usize,
    ) -> Result<Self, UdpRuntimeError> {
        let capacity = front_reserve
            .checked_add(receive_bound)
            .and_then(|capacity| capacity.checked_add(rear_reserve))
            .ok_or(UdpRuntimeError::Bounds)?;
        if receive_bound == 0
            || receive_bound > MAX_UDP_WIRE_DATAGRAM_BYTES
            || rear_reserve >= receive_bound
            || capacity > MAX_UDP_HEADROOM_ALLOCATION_BYTES
        {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(Self {
            capacity,
            front_reserve,
            rear_reserve,
            receive_bound,
        })
    }

    /// Returns the exact backing capacity charged to the runtime budget.
    pub const fn capacity(self) -> usize {
        self.capacity
    }

    /// Returns the fixed bytes preceding every receive payload.
    pub const fn front_reserve(self) -> usize {
        self.front_reserve
    }

    /// Returns the fixed bytes retained after the largest receive payload.
    pub const fn rear_reserve(self) -> usize {
        self.rear_reserve
    }

    /// Returns the largest application payload fitting this complete layout.
    pub const fn max_payload(self) -> usize {
        self.receive_bound
    }

    /// Returns the exact maximum bytes exposed to one socket receive.
    pub const fn receive_bound(self) -> usize {
        self.receive_bound
    }
}

/// Reusable fixed-capacity buffer whose budget is acquired before receive.
///
/// The lease never grows or splits its backing. Socket adapters append into
/// the spare capacity after the fixed front reserve, so Pending I/O retains the
/// same pointer, capacity, logical start, and receive bound.
pub struct UdpHeadroomLease {
    layout: UdpHeadroomLayout,
    backing: Option<BytesMut>,
    reservation: Option<UdpBufferReservation>,
    allocation_address: usize,
}

impl UdpHeadroomLease {
    /// Reserves the complete fixed capacity and creates one empty receive lease.
    pub fn reserve(
        budget: &UdpBufferBudget,
        layout: UdpHeadroomLayout,
    ) -> Result<Self, UdpRuntimeError> {
        let reservation = budget.reserve_headroom(layout.capacity())?;
        let backing = BytesMut::with_capacity(layout.capacity());
        if backing.capacity() != reservation.capacity() {
            return Err(UdpRuntimeError::Bounds);
        }
        let allocation_address = backing.as_ptr() as usize;
        Ok(Self {
            layout,
            backing: Some(backing),
            reservation: Some(reservation),
            allocation_address,
        })
    }

    /// Returns the immutable fixed layout.
    pub const fn layout(&self) -> UdpHeadroomLayout {
        self.layout
    }

    /// Returns the stable allocation identity for structural verification.
    pub fn storage_identity(&self) -> usize {
        self.allocation_address
    }

    /// Returns the current initialized logical length.
    pub fn logical_len(&self) -> usize {
        self.backing
            .as_ref()
            .expect("live UDP headroom lease owns its backing")
            .len()
    }

    /// Resets logical state and exposes the append-only receive buffer.
    ///
    /// Call this before constructing the socket receive future. No reserve,
    /// resize beyond existing capacity, split, or replacement is performed.
    pub fn prepare_receive(&mut self) -> Result<&mut BytesMut, UdpRuntimeError> {
        self.validate_allocation()?;
        let backing = self
            .backing
            .as_mut()
            .expect("live UDP headroom lease owns its backing");
        backing.clear();
        backing.resize(self.layout.front_reserve(), 0);
        debug_assert_eq!(backing.as_ptr() as usize, self.allocation_address);
        debug_assert_eq!(backing.capacity(), self.layout.capacity());
        Ok(backing)
    }

    /// Commits one atomic datagram receive into the fixed payload range.
    ///
    /// `received` must equal the number of bytes appended by the socket. A
    /// lying adapter, an oversized datagram, or an allocation change fails
    /// closed and drops a physically cleared lease.
    pub fn finish_receive(
        self,
        target: TargetAddr,
        received: usize,
    ) -> Result<UdpHeadroomPacket, UdpRuntimeError> {
        self.finish_receive_payload(target, received, 0..received)
    }

    /// Commits one receive while selecting an application payload nested in
    /// the appended ingress datagram (for example behind a SOCKS UDP header).
    pub fn finish_receive_payload(
        mut self,
        target: TargetAddr,
        received: usize,
        payload_in_receive: Range<usize>,
    ) -> Result<UdpHeadroomPacket, UdpRuntimeError> {
        self.validate_allocation()?;
        let received_end = self
            .layout
            .front_reserve()
            .checked_add(received)
            .ok_or(UdpRuntimeError::Bounds)?;
        let backing = self
            .backing
            .as_ref()
            .expect("live UDP headroom lease owns its backing");
        if payload_in_receive.start > payload_in_receive.end
            || payload_in_receive.end > received
            || backing.len() != received_end
        {
            return Err(UdpRuntimeError::Bounds);
        }
        let payload_start = self
            .layout
            .front_reserve()
            .checked_add(payload_in_receive.start)
            .ok_or(UdpRuntimeError::Bounds)?;
        let payload_end = self
            .layout
            .front_reserve()
            .checked_add(payload_in_receive.end)
            .ok_or(UdpRuntimeError::Bounds)?;
        if payload_end
            .checked_add(self.layout.rear_reserve())
            .is_none_or(|end| end > self.layout.capacity())
        {
            return Err(UdpRuntimeError::Bounds);
        }
        let payload_range = payload_start..payload_end;
        let backing = self
            .backing
            .take()
            .expect("live UDP headroom lease releases its backing once");
        let datagram =
            Datagram::from_payload_range(target, backing, payload_range, self.layout.max_payload())
                .map_err(|_| UdpRuntimeError::Bounds)?;
        let reservation = self
            .reservation
            .take()
            .expect("live UDP headroom lease releases its reservation once");
        Ok(UdpHeadroomPacket {
            layout: self.layout,
            datagram: Some(datagram),
            reservation: Some(reservation),
            allocation_address: self.allocation_address,
        })
    }

    /// Physically clears a rejected receive while retaining its fixed budget.
    pub fn clear_failure(&mut self) -> Result<(), UdpRuntimeError> {
        self.validate_allocation()?;
        clear_initialized(
            self.backing
                .as_mut()
                .expect("live UDP headroom lease owns its backing"),
        );
        Ok(())
    }

    fn validate_allocation(&self) -> Result<(), UdpRuntimeError> {
        let backing = self
            .backing
            .as_ref()
            .expect("live UDP headroom lease owns its backing");
        let reservation = self
            .reservation
            .as_ref()
            .expect("live UDP headroom lease owns its reservation");
        if backing.as_ptr() as usize != self.allocation_address
            || backing.capacity() != self.layout.capacity()
            || reservation.capacity() != self.layout.capacity()
        {
            Err(UdpRuntimeError::Bounds)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for UdpHeadroomLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpHeadroomLease")
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

impl Drop for UdpHeadroomLease {
    fn drop(&mut self) {
        if let Some(backing) = &mut self.backing {
            clear_initialized(backing);
        }
    }
}

/// One received datagram that retains its protocol framing headroom and budget.
///
/// A protocol adapter may fill the reserved prefix and suffix through
/// [`Self::backing_parts_mut`], seal in place, send a validated wire range, and
/// return the allocation with [`Self::recycle`]. Dropping on any error
/// physically clears every initialized byte before releasing the budget.
pub struct UdpHeadroomPacket {
    layout: UdpHeadroomLayout,
    datagram: Option<Datagram>,
    reservation: Option<UdpBufferReservation>,
    allocation_address: usize,
}

/// Allocation identity retained while a runtime queue temporarily owns the
/// packet's exact byte-budget reservation.
pub struct UdpHeadroomRecycleToken {
    layout: UdpHeadroomLayout,
    allocation_address: usize,
}

impl UdpHeadroomRecycleToken {
    /// Rejoins the ranged datagram with its exact returned reservation.
    pub fn restore(
        self,
        datagram: Datagram,
        reservation: UdpBufferReservation,
    ) -> Result<UdpHeadroomPacket, UdpRuntimeError> {
        let packet = UdpHeadroomPacket {
            layout: self.layout,
            datagram: Some(datagram),
            reservation: Some(reservation),
            allocation_address: self.allocation_address,
        };
        packet.validate_allocation()?;
        Ok(packet)
    }
}

impl UdpHeadroomPacket {
    /// Returns the received datagram view.
    pub fn datagram(&self) -> &Datagram {
        self.datagram
            .as_ref()
            .expect("live UDP headroom packet owns its datagram")
    }

    /// Mutably borrows the ranged datagram for an in-place protocol seal.
    pub fn datagram_mut(&mut self) -> Result<&mut Datagram, UdpRuntimeError> {
        self.validate_allocation()?;
        Ok(self
            .datagram
            .as_mut()
            .expect("live UDP headroom packet owns its datagram"))
    }

    /// Returns the exact capacity retained by the packet's budget owner.
    pub const fn allocated_capacity(&self) -> usize {
        self.layout.capacity()
    }

    /// Returns the stable base-allocation identity retained by this packet.
    pub fn storage_identity(&self) -> usize {
        self.allocation_address
    }

    /// Separates the ranged datagram and exact capacity owner for one atomic
    /// runtime queue commit, retaining only what is needed to restore the
    /// owned-headroom packet afterwards.
    pub fn into_accounting_parts(
        mut self,
    ) -> (Datagram, UdpBufferReservation, UdpHeadroomRecycleToken) {
        let datagram = self
            .datagram
            .take()
            .expect("live UDP headroom packet releases its datagram once");
        let reservation = self
            .reservation
            .take()
            .expect("live UDP headroom packet releases its reservation once");
        let token = UdpHeadroomRecycleToken {
            layout: self.layout,
            allocation_address: self.allocation_address,
        };
        (datagram, reservation, token)
    }

    /// Borrows framing parts while preserving the fixed allocation identity.
    pub fn backing_parts_mut(
        &mut self,
    ) -> Result<(&TargetAddr, &mut BytesMut, Range<usize>), UdpRuntimeError> {
        self.validate_allocation()?;
        Ok(self
            .datagram
            .as_mut()
            .expect("live UDP headroom packet owns its datagram")
            .backing_parts_mut())
    }

    /// Returns one complete sealed-wire range after validating it contains the
    /// original payload and remains inside the fixed allocation.
    pub fn wire(&self, wire_range: Range<usize>) -> Result<&[u8], UdpRuntimeError> {
        self.validate_allocation()?;
        let datagram = self
            .datagram
            .as_ref()
            .expect("live UDP headroom packet owns its datagram");
        let (_, backing, payload_range) = datagram.backing_parts();
        if wire_range.start > payload_range.start
            || wire_range.end < payload_range.end
            || wire_range.start > wire_range.end
            || wire_range.end > backing.len()
        {
            return Err(UdpRuntimeError::Bounds);
        }
        Ok(&backing[wire_range])
    }

    /// Physically clears every initialized byte after an undelivered request.
    ///
    /// The allocation and its exact budget reservation remain owned so the
    /// caller can recycle the same lease after cancellation or any other
    /// destructive failure.
    pub fn clear_failure(&mut self) -> Result<(), UdpRuntimeError> {
        self.validate_allocation()?;
        let datagram = self
            .datagram
            .as_mut()
            .expect("live UDP headroom packet owns its datagram");
        datagram.backing_parts_mut().1.fill(0);
        Ok(())
    }

    /// Logically clears an accepted packet and returns the same fixed lease.
    pub fn recycle(mut self) -> Result<UdpHeadroomLease, UdpRuntimeError> {
        self.validate_allocation()?;
        let datagram = self
            .datagram
            .take()
            .expect("live UDP headroom packet releases its datagram once");
        let (_, mut backing, _) = datagram.into_backing_parts();
        if backing.as_ptr() as usize != self.allocation_address
            || backing.capacity() != self.layout.capacity()
        {
            clear_initialized(&mut backing);
            return Err(UdpRuntimeError::Bounds);
        }
        backing.clear();
        let reservation = self
            .reservation
            .take()
            .expect("live UDP headroom packet releases its reservation once");
        Ok(UdpHeadroomLease {
            layout: self.layout,
            backing: Some(backing),
            reservation: Some(reservation),
            allocation_address: self.allocation_address,
        })
    }

    fn validate_allocation(&self) -> Result<(), UdpRuntimeError> {
        let datagram = self
            .datagram
            .as_ref()
            .expect("live UDP headroom packet owns its datagram");
        let (_, backing, payload_range) = datagram.backing_parts();
        let reservation = self
            .reservation
            .as_ref()
            .expect("live UDP headroom packet owns its reservation");
        if backing.as_ptr() as usize != self.allocation_address
            || backing.capacity() != self.layout.capacity()
            || reservation.capacity() != self.layout.capacity()
            || payload_range.start < self.layout.front_reserve()
            || payload_range.end > backing.len()
            || payload_range.len() > self.layout.max_payload()
            || payload_range
                .end
                .checked_add(self.layout.rear_reserve())
                .is_none_or(|end| end > self.layout.capacity())
        {
            Err(UdpRuntimeError::Bounds)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for UdpHeadroomPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpHeadroomPacket")
            .field("layout", &self.layout)
            .field("payload_len", &self.datagram().payload().len())
            .finish()
    }
}

impl Drop for UdpHeadroomPacket {
    fn drop(&mut self) {
        let Some(datagram) = self.datagram.take() else {
            return;
        };
        let (_, mut backing, _) = datagram.into_backing_parts();
        clear_initialized(&mut backing);
    }
}

fn clear_initialized(backing: &mut BytesMut) {
    backing.fill(0);
    backing.clear();
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use bytes::BufMut as _;

    use crate::OwnerRegistry;

    use super::super::MIN_UDP_MAX_BUFFERED_BYTES;
    use super::*;

    const FRONT_RESERVE: usize = 326;
    const REAR_RESERVE: usize = 16;

    fn layout() -> UdpHeadroomLayout {
        UdpHeadroomLayout::new(MAX_UDP_WIRE_DATAGRAM_BYTES, FRONT_RESERVE, REAR_RESERVE)
            .expect("test layout")
    }

    fn target() -> TargetAddr {
        TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)).expect("non-zero target port")
    }

    fn budget() -> UdpBufferBudget {
        UdpBufferBudget::new(MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry::new())
    }

    #[test]
    fn fixed_layout_rejects_unbounded_or_empty_payload_regions() {
        assert_eq!(
            UdpHeadroomLayout::new(0, 0, 0).unwrap_err(),
            UdpRuntimeError::Bounds
        );
        assert_eq!(
            UdpHeadroomLayout::new(MAX_UDP_WIRE_DATAGRAM_BYTES + 1, 1, 1).unwrap_err(),
            UdpRuntimeError::Bounds
        );
        assert_eq!(
            UdpHeadroomLayout::new(64, 48, 16).unwrap_err(),
            UdpRuntimeError::Bounds
        );
        assert_eq!(
            UdpHeadroomLayout::new(64, usize::MAX, 1).unwrap_err(),
            UdpRuntimeError::Bounds
        );
    }

    #[test]
    fn receive_frame_send_recycle_keeps_one_allocation_for_all_payload_sizes() {
        let budget = budget();
        let layout = layout();
        let mut lease = UdpHeadroomLease::reserve(&budget, layout).expect("fixed lease");
        let base_pointer = lease.prepare_receive().expect("prepare").as_ptr();
        assert_eq!(budget.reserved_bytes(), layout.capacity());

        for (index, payload_len) in [
            1,
            1_472,
            8_192,
            layout.max_payload(),
            32,
            layout.max_payload() - 1,
            7,
        ]
        .into_iter()
        .enumerate()
        {
            let receive = lease.prepare_receive().expect("prepare receive");
            assert_eq!(receive.as_ptr(), base_pointer);
            assert_eq!(receive.capacity(), layout.capacity());
            assert_eq!(receive.len(), FRONT_RESERVE);
            receive.resize(FRONT_RESERVE + payload_len, index as u8);

            let mut packet = lease
                .finish_receive(target(), payload_len)
                .expect("finish receive");
            assert_eq!(packet.datagram().payload(), vec![index as u8; payload_len]);
            assert_eq!(packet.allocated_capacity(), layout.capacity());

            let target_header = [7_usize, 19, 259][index % 3];
            let framing_prefix = 40 + 11 + 16 + target_header;
            let (framed_target, backing, payload_range) =
                packet.backing_parts_mut().expect("framing parts");
            assert_eq!(framed_target.port().get(), 53);
            assert_eq!(backing.as_ptr(), base_pointer);
            assert!(framing_prefix <= FRONT_RESERVE);
            let wire_start = payload_range.start - framing_prefix;
            let wire_end = payload_range.end + REAR_RESERVE;
            backing.resize(wire_end, 0);
            backing[wire_start..payload_range.start].fill(0xa5);
            backing[payload_range.end..wire_end].fill(0x5a);
            assert_eq!(backing.as_ptr(), base_pointer);
            assert_eq!(backing.capacity(), layout.capacity());
            assert_eq!(
                packet
                    .wire(wire_start..wire_end)
                    .expect("complete wire")
                    .len(),
                framing_prefix + payload_len + REAR_RESERVE
            );

            lease = packet.recycle().expect("recycle fixed lease");
            assert_eq!(budget.reserved_bytes(), layout.capacity());
        }

        drop(lease);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn complete_receive_bound_is_not_truncated_by_reserved_framing_space() {
        let budget = budget();
        let layout = UdpHeadroomLayout::for_receive_bound(
            MAX_UDP_WIRE_DATAGRAM_BYTES,
            FRONT_RESERVE,
            REAR_RESERVE,
        )
        .expect("complete receive layout");
        assert_eq!(
            layout.capacity(),
            FRONT_RESERVE + MAX_UDP_WIRE_DATAGRAM_BYTES + REAR_RESERVE
        );
        assert_eq!(layout.max_payload(), MAX_UDP_WIRE_DATAGRAM_BYTES);
        let mut lease = UdpHeadroomLease::reserve(&budget, layout).expect("complete receive lease");
        let allocation = lease.storage_identity();
        let receive = lease.prepare_receive().expect("prepare complete receive");
        {
            let mut bounded = (&mut *receive).limit(layout.receive_bound());
            assert_eq!(
                bounded.remaining_mut(),
                MAX_UDP_WIRE_DATAGRAM_BYTES,
                "the socket sees the complete UDP receive bound after front reserve"
            );
            bounded.put_bytes(0x5a, MAX_UDP_WIRE_DATAGRAM_BYTES);
        }
        assert_eq!(receive.as_ptr() as usize, allocation);
        let packet = lease
            .finish_receive(target(), MAX_UDP_WIRE_DATAGRAM_BYTES)
            .expect("complete datagram remains intact for protocol bounds");
        assert_eq!(
            packet.datagram().payload().len(),
            MAX_UDP_WIRE_DATAGRAM_BYTES
        );
        assert_eq!(packet.storage_identity(), allocation);
        drop(packet);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn receive_contract_rejects_length_lies_and_releases_budget() {
        let budget = budget();
        let layout = layout();
        let mut lease = UdpHeadroomLease::reserve(&budget, layout).expect("fixed lease");
        lease
            .prepare_receive()
            .expect("prepare")
            .extend_from_slice(b"short");
        assert_eq!(
            lease.finish_receive(target(), 6).unwrap_err(),
            UdpRuntimeError::Bounds
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn cancellation_drops_the_live_owner_and_releases_exact_capacity() {
        let budget = budget();
        let layout = layout();
        let mut lease = UdpHeadroomLease::reserve(&budget, layout).expect("fixed lease");
        lease
            .prepare_receive()
            .expect("prepare")
            .extend_from_slice(b"pending candidate");
        assert_eq!(budget.reserved_bytes(), layout.capacity());
        drop(lease);
        assert_eq!(budget.reserved_bytes(), 0);

        let mut lease = UdpHeadroomLease::reserve(&budget, layout).expect("fixed lease");
        lease
            .prepare_receive()
            .expect("prepare")
            .extend_from_slice(b"received candidate");
        let packet = lease
            .finish_receive(target(), b"received candidate".len())
            .expect("packet");
        assert_eq!(budget.reserved_bytes(), layout.capacity());
        drop(packet);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
