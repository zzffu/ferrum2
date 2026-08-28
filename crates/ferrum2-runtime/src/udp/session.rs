use std::convert::Infallible;
use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

use ferrum2_core::Datagram;
use tokio::time::Instant;

use crate::owner::OwnerGuard;

use super::manager::{
    UdpSessionManagerInner, lock_session_shard, matching_entry_mut, update_session_activity,
};
use super::reservation::{AccountedDatagram, UdpBufferReservation};
use super::{
    UDP_SESSION_QUEUE_DEPTH, UdpCommitError, UdpDirection, UdpRuntimeError, UdpSessionHandle,
    UdpSessionManager,
};

pub(super) struct QueuedDatagram {
    pub(super) datagram: AccountedDatagram,
    pub(super) _guard: OwnerGuard,
}

pub(super) struct DatagramQueue {
    pub(super) entries: [Option<QueuedDatagram>; UDP_SESSION_QUEUE_DEPTH],
    pub(super) head: usize,
    pub(super) len: usize,
}

impl DatagramQueue {
    pub(super) fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            head: 0,
            len: 0,
        }
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }

    pub(super) fn push_back(&mut self, datagram: QueuedDatagram) {
        debug_assert!(self.len < UDP_SESSION_QUEUE_DEPTH);
        let index = (self.head + self.len) % UDP_SESSION_QUEUE_DEPTH;
        self.entries[index] = Some(datagram);
        self.len += 1;
    }

    pub(super) fn pop_front(&mut self) -> Option<QueuedDatagram> {
        if self.len == 0 {
            return None;
        }
        let datagram = self.entries[self.head].take();
        self.head = (self.head + 1) % UDP_SESSION_QUEUE_DEPTH;
        self.len -= 1;
        datagram
    }
}

/// Provisional session capacity that rolls back unless atomically activated.
pub struct PendingUdpSession {
    pub(super) manager: Arc<UdpSessionManagerInner>,
    pub(super) handle: UdpSessionHandle,
    pub(super) committed: bool,
}

impl PendingUdpSession {
    /// Returns the opaque generation for protocol-side capability binding.
    pub const fn handle(&self) -> UdpSessionHandle {
        self.handle
    }

    /// Reserves the first datagram without making the session active.
    pub fn reserve_datagram(
        &self,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.manager,
            self.handle,
            direction,
            allocated_capacity,
            false,
            true,
        )
    }

    /// Reserves the first datagram without charging the global UDP byte budget.
    ///
    /// This is only for callers whose datagrams remain structurally bounded by
    /// independent packet, queue, and owner-count limits. Bounds, queue depth,
    /// session generation, cancellation, and reserve-then-commit checks remain
    /// identical to [`Self::reserve_datagram`].
    pub fn reserve_unmetered_datagram(
        &self,
        direction: UdpDirection,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        reserve_datagram(
            &self.manager,
            self.handle,
            direction,
            allocated_capacity,
            false,
            false,
        )
    }

    /// Activates this generation and enqueues its first post-validation datagram.
    pub fn commit(
        self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<UdpSessionHandle, UdpRuntimeError> {
        match self.commit_with(datagram_reservation, datagram, now, || {
            Ok::<(), Infallible>(())
        }) {
            Ok(handle) => Ok(handle),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Activates this generation and returns its first datagram directly to
    /// the sole same-task consumer without a queue or notification round trip.
    pub fn commit_immediate(
        self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<(UdpSessionHandle, AccountedDatagram), UdpRuntimeError> {
        match self.commit_immediate_with(datagram_reservation, datagram, now, || {
            Ok::<(), Infallible>(())
        }) {
            Ok(result) => Ok(result),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Atomically activates this generation, commits protocol state, and
    /// returns the accounted first datagram without publishing it to a queue.
    pub fn commit_immediate_with<E, C>(
        mut self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<(UdpSessionHandle, AccountedDatagram), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        if datagram_reservation.handle != self.handle
            || datagram_reservation.manager.as_ptr() != Arc::as_ptr(&self.manager)
        {
            return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
        }
        let datagram = datagram_reservation.commit_immediate_inner_with(
            datagram,
            now,
            true,
            protocol_commit,
        )?;
        self.committed = true;
        Ok((self.handle, datagram))
    }

    /// Serializes generation recheck, protocol commit, activity, and enqueue.
    pub fn commit_with<E, C>(
        mut self,
        datagram_reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<UdpSessionHandle, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        if datagram_reservation.handle != self.handle
            || datagram_reservation.manager.as_ptr() != Arc::as_ptr(&self.manager)
        {
            return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
        }
        datagram_reservation.commit_inner_with(datagram, now, true, protocol_commit)?;
        self.committed = true;
        Ok(self.handle)
    }
}

impl fmt::Debug for PendingUdpSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingUdpSession([redacted])")
    }
}

impl Drop for PendingUdpSession {
    fn drop(&mut self) {
        if !self.committed {
            let manager = UdpSessionManager {
                inner: Arc::clone(&self.manager),
            };
            manager.remove(self.handle);
        }
    }
}

/// Reserved queue and byte capacity that has not advanced accepted activity.
pub struct PendingUdpDatagram {
    pub(super) manager: Weak<UdpSessionManagerInner>,
    pub(super) handle: UdpSessionHandle,
    pub(super) direction: UdpDirection,
    pub(super) reservation: Option<UdpBufferReservation>,
    pub(super) pending: bool,
}

impl PendingUdpDatagram {
    /// Enqueues a datagram after the protocol owner completes its atomic commit.
    pub fn commit(self, datagram: Datagram, now: Instant) -> Result<(), UdpRuntimeError> {
        match self.commit_with(datagram, now, || Ok::<(), Infallible>(())) {
            Ok(()) => Ok(()),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Serializes generation recheck, protocol commit, activity, and enqueue.
    pub fn commit_with<E, C>(
        self,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<(), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        self.commit_inner_with(datagram, now, false, protocol_commit)
    }

    /// Commits accepted activity and returns this datagram directly to the
    /// sole same-task consumer without queue ownership or notification work.
    pub fn commit_immediate(
        self,
        datagram: Datagram,
        now: Instant,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        match self.commit_immediate_with(datagram, now, || Ok::<(), Infallible>(())) {
            Ok(datagram) => Ok(datagram),
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
    }

    /// Atomically rechecks generation, commits protocol state and activity,
    /// and returns this datagram without publishing it to a queue.
    pub fn commit_immediate_with<E, C>(
        self,
        datagram: Datagram,
        now: Instant,
        protocol_commit: C,
    ) -> Result<AccountedDatagram, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        self.commit_immediate_inner_with(datagram, now, false, protocol_commit)
    }

    fn commit_inner_with<E, C>(
        mut self,
        datagram: Datagram,
        now: Instant,
        activate_session: bool,
        protocol_commit: C,
    ) -> Result<(), UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        let manager = self
            .manager
            .upgrade()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let reservation = self
            .reservation
            .take()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let accounted = reservation
            .attach(datagram)
            .map_err(UdpCommitError::Runtime)?;
        let notify = {
            let mut shard = lock_session_shard(&manager, self.handle);
            if manager.shutting_down.load(Ordering::Acquire) {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            let notify = {
                let entry =
                    matching_entry_mut(&mut shard, self.handle).map_err(UdpCommitError::Runtime)?;
                if entry.committed == activate_session {
                    return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
                }
                protocol_commit().map_err(UdpCommitError::Protocol)?;
                let index = self.direction.index();
                debug_assert!(entry.pending[index] > 0);
                entry.pending[index] -= 1;
                entry.queues[index].push_back(QueuedDatagram {
                    datagram: accounted,
                    _guard: manager.registry.track_udp_queue_entry(),
                });
                Arc::clone(&entry.notify)
            };
            update_session_activity(
                &mut shard,
                self.handle,
                now,
                manager.limits.idle_timeout(),
                activate_session,
            );
            notify
        };
        self.pending = false;
        notify.notify_one();
        Ok(())
    }

    fn commit_immediate_inner_with<E, C>(
        mut self,
        datagram: Datagram,
        now: Instant,
        activate_session: bool,
        protocol_commit: C,
    ) -> Result<AccountedDatagram, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        let manager = self
            .manager
            .upgrade()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let reservation = self
            .reservation
            .take()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let accounted = reservation
            .attach(datagram)
            .map_err(UdpCommitError::Runtime)?;
        {
            let mut shard = lock_session_shard(&manager, self.handle);
            if manager.shutting_down.load(Ordering::Acquire) {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            {
                let entry =
                    matching_entry_mut(&mut shard, self.handle).map_err(UdpCommitError::Runtime)?;
                if entry.committed == activate_session {
                    return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
                }
                protocol_commit().map_err(UdpCommitError::Protocol)?;
                let index = self.direction.index();
                debug_assert!(entry.pending[index] > 0);
                entry.pending[index] -= 1;
            }
            update_session_activity(
                &mut shard,
                self.handle,
                now,
                manager.limits.idle_timeout(),
                activate_session,
            );
        }
        self.pending = false;
        Ok(accounted)
    }
}

impl fmt::Debug for PendingUdpDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingUdpDatagram([redacted])")
    }
}

impl Drop for PendingUdpDatagram {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        let Some(manager) = self.manager.upgrade() else {
            return;
        };
        let mut shard = lock_session_shard(&manager, self.handle);
        if let Ok(entry) = matching_entry_mut(&mut shard, self.handle) {
            let pending = &mut entry.pending[self.direction.index()];
            debug_assert!(*pending > 0);
            *pending -= 1;
        }
    }
}

pub(super) fn reserve_datagram(
    manager: &Arc<UdpSessionManagerInner>,
    handle: UdpSessionHandle,
    direction: UdpDirection,
    allocated_capacity: usize,
    require_committed: bool,
    meter_buffer: bool,
) -> Result<PendingUdpDatagram, UdpRuntimeError> {
    let reservation = if meter_buffer {
        manager.budget.reserve(allocated_capacity)?
    } else {
        UdpBufferReservation::unmetered(allocated_capacity)?
    };
    let mut shard = lock_session_shard(manager, handle);
    if manager.shutting_down.load(Ordering::Acquire) {
        return Err(UdpRuntimeError::Cancelled);
    }
    let entry = matching_entry_mut(&mut shard, handle)?;
    if entry.committed != require_committed {
        return Err(UdpRuntimeError::Cancelled);
    }
    let index = direction.index();
    if entry.pending[index] + entry.queues[index].len() >= UDP_SESSION_QUEUE_DEPTH {
        return Err(UdpRuntimeError::QueueFull);
    }
    entry.pending[index] += 1;
    Ok(PendingUdpDatagram {
        manager: Arc::downgrade(manager),
        handle,
        direction,
        reservation: Some(reservation),
        pending: true,
    })
}
