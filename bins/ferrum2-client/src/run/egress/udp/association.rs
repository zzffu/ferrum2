use super::direct_association::DirectAssociation;
use super::lease::UdpAssociationLease;
use super::proxy::ProxyAssociation;
use super::request::composed_udp_plan_limit;
use super::response::{
    UdpPlanResponseError, dns_response_target_matches, invalid_dns_target, runtime_error,
};
#[cfg(test)]
use super::socket::{UdpIoFaultPlan, UdpIoOperation};
use crate::run::egress::context::ClientOutboundContext;
use crate::run::egress::engine::ClientEgressEngine;
use bytes::BytesMut;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::{Clock, SecureRandom, UdpSessionId};
use ferrum2_runtime::{
    AccountedDatagram, MAX_UDP_WIRE_DATAGRAM_BYTES, PendingUdpDatagram, UdpRuntimeError,
    UdpSessionManager,
};
use ferrum2_shadowsocks::{MAX_UDP_WIRE_LEN, UdpPacketDirection, UdpPacketError};
use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

pub(in crate::run) struct ClientUdpContext {
    pub(in crate::run) manager: UdpSessionManager,
    pub(in crate::run) live_ids: Arc<Mutex<HashSet<UdpSessionId>>>,
}
impl ClientUdpContext {
    pub(in crate::run) fn cancel_all(&self) {
        self.manager.cancel_all();
    }
}

pub(in crate::run) struct ClientUdpAssociation {
    pub(super) path: UdpPath,
    pub(super) lease: UdpAssociationLease,
    #[cfg(test)]
    pub(super) io_fault: Option<Arc<UdpIoFaultPlan>>,
}
pub(super) enum UdpPath {
    Direct(DirectAssociation),
    Proxy(ProxyAssociation),
}
pub(in crate::run::egress) const MAX_UDP_PLAN_HOPS: usize = 8;

impl ClientUdpAssociation {
    pub(in crate::run) fn activate<C, T, R: SecureRandom>(
        &mut self,
        egress: &ClientEgressEngine<C, T, R>,
    ) -> Result<(), ()> {
        match &mut self.path {
            UdpPath::Direct(_) => Ok(()),
            UdpPath::Proxy(proxy) => proxy.activate(egress),
        }
    }
    pub(in crate::run) fn cancellation(
        &self,
    ) -> Result<tokio::sync::watch::Receiver<bool>, UdpRuntimeError> {
        self.lease.manager.cancellation(self.lease.handle()?)
    }
    pub(in crate::run) fn idle_deadline(&self) -> Result<Instant, UdpRuntimeError> {
        self.lease.manager.idle_deadline(self.lease.handle()?)
    }
    pub(in crate::run) fn idle_expired(&self, observed: Instant) -> bool {
        Instant::now() >= self.idle_deadline().unwrap_or(observed)
    }
    pub(in crate::run) fn encode_request<C, T: Clock, R: SecureRandom>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        datagram: &Datagram,
    ) -> Result<usize, UdpPacketError> {
        match &mut self.path {
            UdpPath::Direct(direct) => direct.encode(datagram),
            UdpPath::Proxy(proxy) => proxy.encode_request(engine, outbounds, datagram),
        }
    }
    pub(in crate::run) fn accept_response<C, T: Clock, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
        match &mut self.path {
            UdpPath::Direct(direct) => direct.response(wire_len, &self.lease),
            UdpPath::Proxy(proxy) => {
                proxy.accept_response(engine, outbounds, wire_len, &self.lease)
            }
        }
    }
    pub(in crate::run) fn reserve_application_datagram(
        &self,
        allocated_capacity: usize,
    ) -> Result<PendingUdpDatagram, UdpRuntimeError> {
        self.lease.reserve_request(allocated_capacity)
    }
    pub(in crate::run) fn commit_application_datagram(
        &mut self,
        reservation: PendingUdpDatagram,
        datagram: Datagram,
        now: Instant,
    ) -> Result<AccountedDatagram, UdpRuntimeError> {
        self.lease.commit(reservation, datagram, now)
    }
    fn plan(&self) -> Option<&EgressPlanSnapshot> {
        match &self.path {
            UdpPath::Direct(direct) => direct.plan.as_ref(),
            UdpPath::Proxy(proxy) => Some(&proxy.resources.plan),
        }
    }
    pub(in crate::run) fn payload_limit(
        &self,
        outbounds: &[ClientOutboundContext],
        direction: UdpPacketDirection,
        encoded_target_len: usize,
    ) -> usize {
        match &self.path {
            UdpPath::Direct(_) => MAX_UDP_WIRE_DATAGRAM_BYTES,
            UdpPath::Proxy(proxy) => composed_udp_plan_limit(
                outbounds,
                proxy.resources.plan.hops(),
                direction,
                encoded_target_len,
            ),
        }
    }
    pub(in crate::run) fn prepare_application_request<C, T: Clock, R: SecureRandom>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: &[u8],
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError> {
        self.prepare_owned_application_request(
            engine,
            outbounds,
            target,
            BytesMut::from(payload),
            now,
        )
    }
    pub(in crate::run) fn prepare_owned_application_request<C, T: Clock, R: SecureRandom>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        target: TargetAddr,
        payload: BytesMut,
        now: Instant,
    ) -> Result<usize, UdpPlanResponseError> {
        let encoded_target_len = match target.host() {
            TargetHostRef::Ip(std::net::IpAddr::V4(_)) => 7,
            TargetHostRef::Ip(std::net::IpAddr::V6(_)) => 19,
            TargetHostRef::Domain(name) => 3 + name.len(),
        };
        if payload.len()
            > self.payload_limit(outbounds, UdpPacketDirection::Request, encoded_target_len)
        {
            return Err(UdpPlanResponseError::Packet(UdpPacketError::Bounds));
        }
        let reservation = self
            .reserve_application_datagram(payload.capacity())
            .map_err(UdpPlanResponseError::Runtime)?;
        let payload_len = payload.len();
        let datagram = Datagram::new(target, payload, payload_len)
            .map_err(|_| UdpPlanResponseError::Packet(UdpPacketError::Bounds))?;
        // Encode before accepted-state/activity commit. A rejected packet never refreshes
        // the session; an encoding failure consumes its nonce lineage without rollback.
        let wire_len = self
            .encode_request(engine, outbounds, &datagram)
            .map_err(UdpPlanResponseError::Packet)?;
        self.commit_application_datagram(reservation, datagram, now)
            .map_err(UdpPlanResponseError::Runtime)?;
        Ok(wire_len)
    }
    pub(in crate::run) fn prepare_application_response<C, T: Clock, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        outbounds: &[ClientOutboundContext],
        wire_len: usize,
    ) -> Result<AccountedDatagram, UdpPlanResponseError> {
        self.accept_response(engine, outbounds, wire_len)
    }
    pub(in crate::run) fn recycle_application_response(&mut self, response: AccountedDatagram) {
        if let UdpPath::Direct(direct) = &mut self.path {
            direct.recycle(response);
        }
    }
    pub(in crate::run) fn try_send_encoded_request(&self, wire_len: usize) -> io::Result<usize> {
        #[cfg(test)]
        self.check_io_fault(UdpIoOperation::UpstreamSend)?;
        match &self.path {
            UdpPath::Direct(_) => Err(io::ErrorKind::WouldBlock.into()),
            UdpPath::Proxy(proxy) => proxy
                .resources
                .socket
                .try_send(&proxy.resources.upstream_wire[..wire_len]),
        }
    }
    pub(in crate::run) async fn send_encoded_request(
        &mut self,
        wire_len: usize,
    ) -> io::Result<usize> {
        #[cfg(test)]
        self.check_io_fault(UdpIoOperation::UpstreamSend)?;
        match &mut self.path {
            UdpPath::Direct(direct) => direct.send(wire_len).await,
            UdpPath::Proxy(proxy) => {
                proxy
                    .resources
                    .socket
                    .send(&proxy.resources.upstream_wire[..wire_len])
                    .await
            }
        }
    }
    pub(in crate::run) async fn receive_response_wire(&mut self) -> io::Result<usize> {
        #[cfg(test)]
        self.check_io_fault(UdpIoOperation::UpstreamRecv)?;
        match &mut self.path {
            UdpPath::Direct(direct) => direct.receive().await,
            UdpPath::Proxy(proxy) => {
                proxy
                    .resources
                    .socket
                    .receive(&mut proxy.resources.upstream_wire)
                    .await
            }
        }
    }
    #[cfg(test)]
    fn check_io_fault(&self, operation: UdpIoOperation) -> io::Result<()> {
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(operation))
        {
            Err(io::Error::other("injected UDP operation failure"))
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(in crate::run) fn set_io_fault(&mut self, fault: Option<Arc<UdpIoFaultPlan>>) {
        self.io_fault = fault;
    }
    #[cfg(test)]
    pub(in crate::run) fn handle(&self) -> ferrum2_runtime::UdpSessionHandle {
        self.lease.handle().expect("live test association")
    }
    #[cfg(test)]
    pub(in crate::run) fn upstream_local_addr(&self) -> io::Result<std::net::SocketAddr> {
        match &self.path {
            UdpPath::Proxy(proxy) => proxy.resources.socket.local_addr(),
            UdpPath::Direct(_) => Err(io::Error::other("UDP socket is opaque")),
        }
    }
    #[cfg(test)]
    pub(super) fn outstanding_requests(&self) -> usize {
        match &self.path {
            UdpPath::Direct(direct) => direct.outstanding(),
            UdpPath::Proxy(_) => 0,
        }
    }
    pub(in crate::run) async fn relay<C, T, R>(
        &mut self,
        engine: &ClientEgressEngine<C, T, R>,
        plan: Option<&EgressPlanSnapshot>,
        destination: TargetAddr,
        packet: Vec<u8>,
    ) -> io::Result<(Vec<u8>, bool)>
    where
        T: Clock,
        R: SecureRandom,
    {
        if packet.len() > MAX_UDP_WIRE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS UDP packet too large",
            ));
        }
        if self.plan() != plan {
            return Err(invalid_dns_target());
        }
        let expected_response_target = destination.clone();
        self.activate(engine).map_err(|_| runtime_error(()))?;
        let wire_len = self
            .prepare_owned_application_request(
                engine,
                &engine.outbounds,
                destination,
                bytes::Bytes::from(packet).into(),
                Instant::now(),
            )
            .map_err(|_| io::Error::other("DNS UDP encode failed"))?;
        let sent = self.send_encoded_request(wire_len).await?;
        if sent != wire_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short DNS UDP send",
            ));
        }
        let mut reusable = matches!(self.path, UdpPath::Proxy(_));
        loop {
            let length = self.receive_response_wire().await?;
            let response =
                match self.prepare_application_response(engine, &engine.outbounds, length) {
                    Ok(response) => response,
                    Err(_) => {
                        reusable = false;
                        continue;
                    }
                };
            if !dns_response_target_matches(&expected_response_target, response.datagram().target())
            {
                reusable = false;
                self.recycle_application_response(response);
                continue;
            }
            let payload = response.datagram().payload().to_vec();
            self.recycle_application_response(response);
            return Ok((payload, reusable));
        }
    }
}
