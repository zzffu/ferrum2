use std::convert::Infallible;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Weak};

use ferrum2_core::Datagram;
use tokio::time::Instant;

use crate::owner::OwnerGuard;

use super::manager::{
    UdpSessionManagerInner, lock_state, matching_entry_mut, release_pending, retire_exact,
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
    /// Activates this generation after a borrowed first datagram was encoded.
    ///
    /// This atomically rechecks the generation, commits accepted activity, and
    /// consumes the reserved queue slot and byte capacity without retaining an
    /// owned datagram. Protocol nonce lineage consumed before this call is not
    /// rolled back if the generation recheck fails.
    pub fn commit_activity(
        mut self,
        datagram_reservation: PendingUdpDatagram,
        now: Instant,
    ) -> Result<UdpSessionHandle, UdpRuntimeError> {
        if datagram_reservation.handle != self.handle
            || datagram_reservation.manager.as_ptr() != Arc::as_ptr(&self.manager)
        {
            return Err(UdpRuntimeError::Cancelled);
        }
        datagram_reservation.commit_activity_inner(now, true)?;
        self.committed = true;
        Ok(self.handle)
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
    /// The callback obeys the bounded, nonblocking, nonreentrant obligations of
    /// [`Self::commit_with`]; panic retires this generation without protocol rollback.
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
    ///
    /// The callback must be synchronous, bounded, nonblocking and nonreentrant:
    /// do not call the runtime manager, perform I/O, or emit diagnostics. A returned
    /// error must leave protocol accepted state unchanged. A panic retires this
    /// runtime generation; arbitrary protocol side effects are not rolled back.
    /// Activity never moves backwards when callers commit out of capture order.
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
    ///
    /// The callback must be synchronous, bounded, nonblocking and nonreentrant:
    /// do not call the runtime manager, perform I/O, or emit diagnostics. A returned
    /// error must leave protocol accepted state unchanged. A panic retires this
    /// runtime generation; arbitrary protocol side effects are not rolled back.
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
    /// Commits accepted activity after a borrowed datagram was encoded.
    ///
    /// This atomically rechecks the generation and consumes the reserved queue
    /// slot and byte capacity without retaining an owned datagram. A failed
    /// recheck releases provisional resources without refreshing activity;
    /// protocol nonce lineage consumed before this call is not rolled back.
    pub fn commit_activity(self, now: Instant) -> Result<(), UdpRuntimeError> {
        self.commit_activity_inner(now, false)
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
    /// The callback obeys the bounded, nonblocking, nonreentrant obligations of
    /// [`Self::commit_with`]; panic retires this generation without protocol rollback.
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

    fn commit_activity_inner(
        mut self,
        now: Instant,
        activate_session: bool,
    ) -> Result<(), UdpRuntimeError> {
        let reservation = self.reservation.take().ok_or(UdpRuntimeError::Cancelled)?;
        match self.commit_immediate_value_inner_with(reservation, now, activate_session, || {
            Ok::<(), Infallible>(())
        }) {
            Ok(reservation) => {
                drop(reservation);
                Ok(())
            }
            Err(UdpCommitError::Runtime(error)) => Err(error),
            Err(UdpCommitError::Protocol(never)) => match never {},
        }
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
            let mut state = lock_state(&manager);
            if state.shutting_down {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            let entry =
                matching_entry_mut(&mut state, self.handle).map_err(UdpCommitError::Runtime)?;
            if entry.committed == activate_session {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            if entry.pending[self.direction.index()] == 0 {
                state.cleanup_failed = true;
                retire_exact(&manager, &mut state, self.handle);
                return Err(UdpCommitError::Runtime(UdpRuntimeError::StateUnavailable));
            }
            // Catch inside the guard's scope: callback unwind must not poison
            // the manager or escape into reservation Drop while it is locked.
            match catch_unwind(AssertUnwindSafe(protocol_commit)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(UdpCommitError::Protocol(error)),
                Err(_) => {
                    state.cleanup_failed = true;
                    retire_exact(&manager, &mut state, self.handle);
                    return Err(UdpCommitError::Runtime(UdpRuntimeError::ProtocolPanicked));
                }
            }
            let entry =
                matching_entry_mut(&mut state, self.handle).map_err(UdpCommitError::Runtime)?;
            let index = self.direction.index();
            debug_assert!(entry.pending[index] > 0);
            entry.pending[index] -= 1;
            entry.committed = true;
            entry.last_activity = entry.last_activity.max(now);
            entry.queues[index].push_back(QueuedDatagram {
                datagram: accounted,
                _guard: manager.registry.track_udp_queue_entry(),
            });
            Arc::clone(&entry.notify)
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
        let reservation = self
            .reservation
            .take()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        let accounted = reservation
            .attach(datagram)
            .map_err(UdpCommitError::Runtime)?;
        self.commit_immediate_value_inner_with(accounted, now, activate_session, protocol_commit)
    }

    fn commit_immediate_value_inner_with<E, C, T>(
        mut self,
        value: T,
        now: Instant,
        activate_session: bool,
        protocol_commit: C,
    ) -> Result<T, UdpCommitError<E>>
    where
        C: FnOnce() -> Result<(), E>,
    {
        let manager = self
            .manager
            .upgrade()
            .ok_or(UdpCommitError::Runtime(UdpRuntimeError::Cancelled))?;
        {
            let mut state = lock_state(&manager);
            if state.shutting_down {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            let entry =
                matching_entry_mut(&mut state, self.handle).map_err(UdpCommitError::Runtime)?;
            if entry.committed == activate_session {
                return Err(UdpCommitError::Runtime(UdpRuntimeError::Cancelled));
            }
            if entry.pending[self.direction.index()] == 0 {
                state.cleanup_failed = true;
                retire_exact(&manager, &mut state, self.handle);
                return Err(UdpCommitError::Runtime(UdpRuntimeError::StateUnavailable));
            }
            // Catch inside the guard's scope: callback unwind must not poison
            // the manager or escape into reservation Drop while it is locked.
            match catch_unwind(AssertUnwindSafe(protocol_commit)) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(UdpCommitError::Protocol(error)),
                Err(_) => {
                    state.cleanup_failed = true;
                    retire_exact(&manager, &mut state, self.handle);
                    return Err(UdpCommitError::Runtime(UdpRuntimeError::ProtocolPanicked));
                }
            }
            let entry =
                matching_entry_mut(&mut state, self.handle).map_err(UdpCommitError::Runtime)?;
            let index = self.direction.index();
            debug_assert!(entry.pending[index] > 0);
            entry.pending[index] -= 1;
            entry.committed = true;
            entry.last_activity = entry.last_activity.max(now);
        }
        self.pending = false;
        Ok(value)
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
        let mut state = lock_state(&manager);
        release_pending(&manager, &mut state, self.handle, self.direction);
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
    let mut state = lock_state(manager);
    if state.shutting_down {
        return Err(UdpRuntimeError::Cancelled);
    }
    let entry = matching_entry_mut(&mut state, handle)?;
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
