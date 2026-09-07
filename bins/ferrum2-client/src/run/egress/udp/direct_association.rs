use super::direct::{
    DirectSocketState, DirectUdpCandidateHints, DirectUdpResponseMatch, DirectUdpResponsePolicy,
    receive_direct_response, send_direct_target_lazy,
};
use super::lease::UdpAssociationLease;
use super::response::UdpPlanResponseError;
use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_runtime::{AccountedDatagram, MAX_UDP_WIRE_DATAGRAM_BYTES, UDP_SESSION_QUEUE_DEPTH};
use ferrum2_shadowsocks::UdpPacketError;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use tokio::time::Instant;

enum DirectBufferState {
    Available(BytesMut),
    Received {
        payload: BytesMut,
        source: SocketAddr,
    },
    Lent,
}
pub(super) struct DirectAssociation {
    pub(super) plan: Option<ferrum2_core::route::EgressPlanSnapshot>,
    pub(super) socket: DirectSocketState,
    pub(super) resolver: ferrum2_dns::ApplicationResolverAdapter,
    pub(super) timeout: std::time::Duration,
    pub(super) policy: DirectUdpResponsePolicy,
    peers: VecDeque<SocketAddr>,
    hints: DirectUdpCandidateHints,
    request_target: Option<TargetAddr>,
    buffer: DirectBufferState,
}
impl DirectAssociation {
    pub(super) fn new(
        plan: Option<ferrum2_core::route::EgressPlanSnapshot>,
        socket: DirectSocketState,
        resolver: ferrum2_dns::ApplicationResolverAdapter,
        timeout: std::time::Duration,
        policy: DirectUdpResponsePolicy,
    ) -> Self {
        Self {
            plan,
            socket,
            resolver,
            timeout,
            policy,
            peers: VecDeque::with_capacity(UDP_SESSION_QUEUE_DEPTH),
            hints: DirectUdpCandidateHints::default(),
            request_target: None,
            buffer: DirectBufferState::Available(BytesMut::with_capacity(
                MAX_UDP_WIRE_DATAGRAM_BYTES,
            )),
        }
    }
    pub(super) fn encode(
        &mut self,
        target: &TargetAddr,
        payload: &[u8],
    ) -> Result<usize, UdpPacketError> {
        let DirectBufferState::Available(wire) = &mut self.buffer else {
            return Err(UdpPacketError::StateUnavailable);
        };
        wire.clear();
        wire.extend_from_slice(payload);
        self.request_target = Some(target.clone());
        Ok(wire.len())
    }
    pub(super) async fn send(&mut self, wire_len: usize) -> io::Result<usize> {
        let tracks_outstanding = self.policy == DirectUdpResponsePolicy::OutstandingPeers;
        if tracks_outstanding && self.peers.len() >= UDP_SESSION_QUEUE_DEPTH {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let target = self
            .request_target
            .as_ref()
            .ok_or_else(|| io::Error::other("direct UDP target unavailable"))?;
        let DirectBufferState::Available(wire) = &self.buffer else {
            return Err(io::Error::other("direct UDP wire unavailable"));
        };
        let (length, peer) = send_direct_target_lazy(
            &mut self.socket,
            &self.resolver,
            &mut self.hints,
            target,
            &wire[..wire_len],
            self.timeout,
        )
        .await?;
        if tracks_outstanding {
            self.peers.push_back(peer);
        }
        Ok(length)
    }
    pub(super) async fn receive(&mut self) -> io::Result<usize> {
        let DirectSocketState::Bound(socket) = &self.socket else {
            return Err(io::Error::other("direct UDP socket unavailable"));
        };
        let DirectBufferState::Available(wire) = &mut self.buffer else {
            return Err(io::Error::other("direct UDP response not consumed"));
        };
        let (length, source, response_match) =
            receive_direct_response(socket, &self.peers, self.policy, wire).await?;
        let DirectBufferState::Available(mut payload) =
            std::mem::replace(&mut self.buffer, DirectBufferState::Lent)
        else {
            unreachable!("available receive buffer")
        };
        drop(payload.split_off(length));
        if let DirectUdpResponseMatch::OutstandingPeer(position) = response_match {
            self.peers.remove(position);
        }
        self.buffer = DirectBufferState::Received { payload, source };
        Ok(length)
    }
    pub(super) fn response(
        &mut self,
        wire_len: usize,
        lease: &UdpAssociationLease,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
        let DirectBufferState::Received { payload, source } =
            std::mem::replace(&mut self.buffer, DirectBufferState::Lent)
        else {
            return Err(UdpPlanResponseError::Packet(
                UdpPacketError::StateUnavailable,
            ));
        };
        if payload.len() != wire_len {
            self.restore(payload);
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        let reservation = match lease.reserve_response(payload.capacity()) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.restore(payload);
                return Err(UdpPlanResponseError::Runtime(error));
            }
        };
        let target = TargetAddr::ip(source)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        let datagram = Datagram::new(target, payload, MAX_UDP_WIRE_DATAGRAM_BYTES)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        reservation
            .commit_immediate(datagram, Instant::now())
            .map_err(UdpPlanResponseError::Runtime)
    }
    fn restore(&mut self, mut wire: BytesMut) {
        wire.clear();
        if wire.capacity() < MAX_UDP_WIRE_DATAGRAM_BYTES {
            wire.reserve(MAX_UDP_WIRE_DATAGRAM_BYTES);
        }
        self.buffer = DirectBufferState::Available(wire);
    }
    pub(super) fn recycle(&mut self, response: AccountedDatagram) {
        let (datagram, reservation) = response.into_parts();
        let (_, payload) = datagram.into_parts();
        let wire = match payload.try_into_mut() {
            Ok(wire) => wire,
            Err(payload) => payload.into(),
        };
        self.restore(wire);
        drop(reservation);
    }
    #[cfg(test)]
    pub(super) fn outstanding(&self) -> usize {
        self.peers.len()
    }
}
