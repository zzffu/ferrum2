use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;

use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_f2p::ClientSession;
use ferrum2_runtime::{
    AccountedDatagram, MAX_UDP_WIRE_DATAGRAM_BYTES, UdpBufferBudget, UdpBufferReservation,
};
use ferrum2_shadowsocks::UdpPacketError;
use tokio::time::Instant;

use super::lease::UdpAssociationLease;
use super::response::UdpPlanResponseError;
use ferrum2_f2p::ClientTunnel;

const MAX_TARGETS: usize = 256;
// Fields drop in declaration order: target storage is freed before its charge.
struct OwnedTarget {
    target: TargetAddr,
    _capacity: Option<UdpBufferReservation>,
}
impl OwnedTarget {
    fn clone_in(target: &TargetAddr, budget: &UdpBufferBudget) -> io::Result<Self> {
        let bytes = match target.host() {
            TargetHostRef::Ip(_) => 0,
            TargetHostRef::Domain(original) => {
                original.len()
                    + target
                        .canonical_domain()
                        .map_or(0, |canonical| canonical.as_str().len())
            }
        };
        let capacity = if bytes == 0 {
            None
        } else {
            Some(budget.reserve(bytes).map_err(|_| budget_exhausted())?)
        };
        Ok(Self {
            target: target.clone(),
            _capacity: capacity,
        })
    }
}
struct Session {
    target: OwnedTarget,
    session: ClientSession,
}
enum RequestTarget {
    Session(usize),
    New(OwnedTarget),
    // The selected session closed between encoding and sending.
    Discard,
}
fn budget_exhausted() -> io::Error {
    io::Error::other("F2P session budget exhausted")
}
// A SOCKS association may address many peers; each target has a distinct
// protocol session. Association ownership provides local-source isolation.
pub(super) struct F2pAssociation {
    pub(super) plan: EgressPlanSnapshot,
    tunnel: Arc<ClientTunnel>,
    sessions: Vec<Session>,
    cursor: usize,
    request_target: Option<RequestTarget>,
    wire: Vec<u8>,
    response_source: Option<SocketAddr>,
    budget: UdpBufferBudget,
    _session_capacity: Option<UdpBufferReservation>,
}
impl F2pAssociation {
    pub(super) fn new(
        plan: EgressPlanSnapshot,
        tunnel: Arc<ClientTunnel>,
        budget: &ferrum2_runtime::UdpBufferBudget,
    ) -> io::Result<Self> {
        // The caller's fixed reservation covers wire, not mapping storage.
        Ok(Self {
            plan,
            tunnel,
            sessions: Vec::new(),
            cursor: 0,
            request_target: None,
            wire: vec![0; MAX_UDP_WIRE_DATAGRAM_BYTES],
            response_source: None,
            budget: budget.clone(),
            _session_capacity: None,
        })
    }
    pub(super) fn encode(
        &mut self,
        target: &TargetAddr,
        payload: &[u8],
    ) -> Result<usize, UdpPacketError> {
        if payload.len() > self.wire.len() {
            return Err(UdpPacketError::Bounds);
        }
        for index in (0..self.sessions.len()).rev() {
            if self.sessions[index].session.is_closed() {
                self.remove_session(index);
            }
        }
        let request = if let Some(index) = self
            .sessions
            .iter()
            .position(|entry| &entry.target.target == target)
        {
            RequestTarget::Session(index)
        } else if matches!(
            &self.request_target,
            Some(RequestTarget::New(staged)) if &staged.target == target
        ) {
            self.wire[..payload.len()].copy_from_slice(payload);
            return Ok(payload.len());
        } else if self.sessions.len() == MAX_TARGETS {
            RequestTarget::Discard
        } else {
            // Keep the old staged target charged until replacement succeeds and
            // actually drops it; distinct domain allocations overlap here.
            RequestTarget::New(
                OwnedTarget::clone_in(target, &self.budget)
                    .map_err(|_| UdpPacketError::StateUnavailable)?,
            )
        };
        self.request_target = Some(request);
        self.wire[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }
    pub(super) async fn send(&mut self, length: usize) -> io::Result<usize> {
        if self.tunnel.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let request = self
            .request_target
            .take()
            .ok_or_else(|| io::Error::other("F2P UDP target unavailable"))?;
        let index = match request {
            RequestTarget::Discard => return Ok(length),
            RequestTarget::Session(index) => index,
            RequestTarget::New(target) => {
                if self.grow_sessions().is_err() {
                    return Ok(length);
                }
                // OPEN consumes its target; reserve its temporary clone in
                // addition to the mapping's retained original and canonical.
                let OwnedTarget {
                    target: open_target,
                    _capacity: open_capacity,
                } = match OwnedTarget::clone_in(&target.target, &self.budget) {
                    Ok(target) => target,
                    Err(_) => return Ok(length),
                };
                let opened = self.tunnel.open(open_target).await;
                drop(open_capacity);
                let session = match opened {
                    Ok(session) => session,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(length),
                    Err(error) => return Err(error),
                };
                self.sessions.push(Session { target, session });
                self.sessions.len() - 1
            }
        };
        self.request_target = Some(RequestTarget::Session(index));
        // OPEN admission does not await OPEN_RESULT: first DATA is pipelined.
        if let Err(error) = self.sessions[index]
            .session
            .send(&self.wire[..length])
            .await
        {
            if self.sessions[index].session.is_closed() {
                self.remove_session(index);
            }
            if self.tunnel.is_closed() {
                return Err(error);
            }
            // Session-local failure/queue overflow drops this uncommitted datagram,
            // not other destinations in the same SOCKS or TUN association.
            return Ok(length);
        }
        Ok(length)
    }
    fn grow_sessions(&mut self) -> io::Result<()> {
        if self.sessions.len() < self.sessions.capacity() {
            return Ok(());
        }
        let capacity = (self.sessions.capacity() * 2).clamp(1, MAX_TARGETS);
        let bytes = capacity * std::mem::size_of::<Session>();
        let reservation = self.budget.reserve(bytes).map_err(|_| budget_exhausted())?;
        // Reserve a separate allocation, never realloc an already charged Vec:
        // both old and new backing buffers remain charged during the move.
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(capacity)
            .map_err(|_| budget_exhausted())?;
        // Global reports the exact requested backing capacity. Do not adopt
        // storage if that invariant changes: the token must cover its actual
        // capacity, and rejection must leave every old session untouched.
        if replacement.capacity() != capacity {
            return Err(io::Error::other("F2P session allocation capacity mismatch"));
        }
        replacement.append(&mut self.sessions);
        let old = std::mem::replace(&mut self.sessions, replacement);
        drop(old);
        self._session_capacity = Some(reservation);
        Ok(())
    }
    fn remove_session(&mut self, index: usize) {
        if let Some(RequestTarget::Session(selected)) = &mut self.request_target {
            if *selected == index {
                self.request_target = Some(RequestTarget::Discard);
            } else if *selected > index {
                *selected -= 1;
            }
        }
        self.sessions.remove(index);
    }
    pub(super) async fn receive(&mut self) -> io::Result<usize> {
        std::future::poll_fn(|cx| {
            if self.tunnel.is_closed() {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let mut remaining = self.sessions.len();
            while remaining != 0 {
                let index = self.cursor % self.sessions.len();
                match self.sessions[index]
                    .session
                    .poll_receive(cx, &mut self.wire)
                {
                    Poll::Ready(Ok((length, source))) => {
                        self.cursor = index + 1;
                        self.response_source = Some(source);
                        return Poll::Ready(Ok(length));
                    }
                    Poll::Ready(Err(_)) => {
                        self.remove_session(index);
                        self.cursor = index;
                    }
                    Poll::Pending => {
                        self.cursor = index + 1;
                    }
                }
                remaining -= 1;
            }
            Poll::Pending
        })
        .await
    }
    pub(super) fn response(
        &mut self,
        length: usize,
        lease: &UdpAssociationLease,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
        let source = self
            .response_source
            .take()
            .ok_or(UdpPlanResponseError::Packet(
                UdpPacketError::StateUnavailable,
            ))?;
        if length > self.wire.len() {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        let reservation = lease
            .reserve_response(length)
            .map_err(UdpPlanResponseError::Runtime)?;
        let target = TargetAddr::ip(source)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        let payload = BytesMut::from(&self.wire[..length]);
        let datagram = Datagram::new(target, payload, MAX_UDP_WIRE_DATAGRAM_BYTES)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        reservation
            .commit_immediate(datagram, Instant::now())
            .map_err(UdpPlanResponseError::Runtime)
    }
}
