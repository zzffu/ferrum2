use ferrum2_core::Datagram;
use ferrum2_runtime::{
    AccountedDatagram, PendingUdpDatagram, PendingUdpSession, UdpBufferBudget,
    UdpBufferReservation, UdpDirection, UdpRuntimeError, UdpSessionHandle, UdpSessionManager,
};
use tokio::time::Instant;

enum SessionLease {
    Pending(PendingUdpSession),
    Active(UdpSessionHandle),
    Closed,
}
pub(super) struct UdpAssociationLease {
    pub(super) manager: UdpSessionManager,
    session: SessionLease,
    budget: UdpBufferBudget,
    _fixed_capacity: Vec<UdpBufferReservation>,
}
impl UdpAssociationLease {
    pub(super) fn new(
        manager: UdpSessionManager,
        session: PendingUdpSession,
        budget: UdpBufferBudget,
        fixed_capacity: Vec<UdpBufferReservation>,
    ) -> Self {
        Self {
            manager,
            session: SessionLease::Pending(session),
            budget,
            _fixed_capacity: fixed_capacity,
        }
    }
    pub(super) fn handle(&self) -> Result<UdpSessionHandle, UdpRuntimeError> {
        match &self.session {
            SessionLease::Pending(session) => Ok(session.handle()),
            SessionLease::Active(handle) => Ok(*handle),
            SessionLease::Closed => Err(UdpRuntimeError::Cancelled),
        }
    }
    pub(super) fn reserve_request(
        &self,
        capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        match &self.session {
            SessionLease::Pending(session) => {
                session.reserve_datagram_in_budget(UdpDirection::ToTarget, capacity, &self.budget)
            }
            SessionLease::Active(handle) => self.manager.reserve_datagram_in_budget(
                *handle,
                UdpDirection::ToTarget,
                capacity,
                &self.budget,
            ),
            SessionLease::Closed => Err(UdpRuntimeError::Cancelled),
        }
    }
    pub(super) fn reserve_response(
        &self,
        capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        let SessionLease::Active(handle) = self.session else {
            return Err(UdpRuntimeError::Cancelled);
        };
        self.manager.reserve_datagram_in_budget(
            handle,
            UdpDirection::ToClient,
            capacity,
            &self.budget,
        )
    }
    pub(super) fn commit_activity(
        &mut self,
        reservation: PendingUdpDatagram,
        now: Instant,
    ) -> Result<(), UdpRuntimeError> {
        if matches!(self.session, SessionLease::Active(_)) {
            return reservation.commit_activity(now);
        }
        match std::mem::replace(&mut self.session, SessionLease::Closed) {
            SessionLease::Pending(session) => {
                let handle = session.commit_activity(reservation, now)?;
                self.session = SessionLease::Active(handle);
                Ok(())
            }
            SessionLease::Closed => Err(UdpRuntimeError::Cancelled),
            SessionLease::Active(_) => unreachable!("active lease handled before transition"),
        }
    }
    pub(super) fn commit(
        &mut self,
        reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        if matches!(self.session, SessionLease::Active(_)) {
            return reservation.commit_immediate(datagram, now);
        }
        match std::mem::replace(&mut self.session, SessionLease::Closed) {
            SessionLease::Pending(session) => {
                let (handle, datagram) = session.commit_immediate(reservation, datagram, now)?;
                self.session = SessionLease::Active(handle);
                Ok(datagram)
            }
            SessionLease::Closed => Err(UdpRuntimeError::Cancelled),
            SessionLease::Active(_) => unreachable!("active lease handled before transition"),
        }
    }
}
impl Drop for UdpAssociationLease {
    fn drop(&mut self) {
        if let SessionLease::Active(handle) = self.session {
            self.manager.remove(handle);
        }
        // Pending session Drop owns rollback; never remove it a second time here.
    }
}
