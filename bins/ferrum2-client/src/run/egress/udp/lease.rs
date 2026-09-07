use crate::run::egress::context::ClientRequestOrigin;
use ferrum2_core::Datagram;
use ferrum2_runtime::{
    AccountedDatagram, PendingUdpDatagram, PendingUdpSession, UdpBufferReservation, UdpDirection,
    UdpRuntimeError, UdpSessionHandle, UdpSessionManager,
};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UdpAccounting {
    Metered,
    TunUnmetered,
}
impl From<ClientRequestOrigin> for UdpAccounting {
    fn from(origin: ClientRequestOrigin) -> Self {
        match origin {
            ClientRequestOrigin::Tun => Self::TunUnmetered,
            ClientRequestOrigin::Socks
            | ClientRequestOrigin::Dns
            | ClientRequestOrigin::RuleSet => Self::Metered,
        }
    }
}

enum SessionLease {
    Pending(PendingUdpSession),
    Active(UdpSessionHandle),
    Closed,
}
pub(super) struct UdpAssociationLease {
    pub(super) manager: UdpSessionManager,
    session: SessionLease,
    pub(super) accounting: UdpAccounting,
    _fixed_capacity: Vec<UdpBufferReservation>,
}
impl UdpAssociationLease {
    pub(super) fn new(
        manager: UdpSessionManager,
        session: PendingUdpSession,
        accounting: UdpAccounting,
        fixed_capacity: Vec<UdpBufferReservation>,
    ) -> Self {
        Self {
            manager,
            session: SessionLease::Pending(session),
            accounting,
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
        match (&self.session, self.accounting) {
            (SessionLease::Pending(session), UdpAccounting::Metered) => {
                session.reserve_datagram(UdpDirection::ToTarget, capacity)
            }
            (SessionLease::Pending(session), UdpAccounting::TunUnmetered) => {
                session.reserve_unmetered_datagram(UdpDirection::ToTarget, capacity)
            }
            (SessionLease::Active(handle), UdpAccounting::Metered) => self
                .manager
                .reserve_datagram(*handle, UdpDirection::ToTarget, capacity),
            (SessionLease::Active(handle), UdpAccounting::TunUnmetered) => self
                .manager
                .reserve_unmetered_datagram(*handle, UdpDirection::ToTarget, capacity),
            (SessionLease::Closed, _) => Err(UdpRuntimeError::Cancelled),
        }
    }
    pub(super) fn reserve_response(
        &self,
        capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        let SessionLease::Active(handle) = self.session else {
            return Err(UdpRuntimeError::Cancelled);
        };
        match self.accounting {
            UdpAccounting::Metered => {
                self.manager
                    .reserve_datagram(handle, UdpDirection::ToClient, capacity)
            }
            UdpAccounting::TunUnmetered => {
                self.manager
                    .reserve_unmetered_datagram(handle, UdpDirection::ToClient, capacity)
            }
        }
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
