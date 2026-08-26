use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(test)]
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_socks5::{
    MAX_SOCKS_UDP_DATAGRAM_BYTES, SocksUdpDatagram, decode_udp_datagram, encode_udp_datagram,
};
use tokio::net::UdpSocket;
use tokio::time::Instant;

#[cfg(test)]
use crate::run::egress::{UdpIoFaultPlan, UdpIoOperation};

use super::source_pinning::SocksUdpSourcePin;

pub(super) struct SocksUdpEndpoint {
    socket: UdpSocket,
    source: SocksUdpSourcePin,
    wire: Vec<u8>,
    last_valid: Instant,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

pub(super) enum SocksUdpPacket<'a> {
    Valid {
        datagram: SocksUdpDatagram<'a>,
        source_port: u16,
    },
    WrongSource,
    InvalidWire,
}

impl SocksUdpEndpoint {
    pub(super) async fn bind<F, Fut>(
        local_ip: Ipv4Addr,
        peer_ip: IpAddr,
        requested_port: u16,
        mut bind: F,
    ) -> io::Result<Self>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = io::Result<UdpSocket>>,
    {
        Ok(Self {
            socket: bind(SocketAddrV4::new(local_ip, 0).into()).await?,
            source: SocksUdpSourcePin::new(peer_ip, requested_port),
            wire: vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES],
            last_valid: Instant::now(),
            #[cfg(test)]
            io_fault: None,
        })
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddrV4> {
        match self.socket.local_addr()? {
            SocketAddr::V4(address) => Ok(address),
            SocketAddr::V6(_) => Err(io::Error::other("SOCKS UDP endpoint is not IPv4")),
        }
    }

    pub(super) async fn receive(&mut self) -> io::Result<SocksUdpPacket<'_>> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationRecv))
        {
            return Err(io::Error::other("injected application receive failure"));
        }
        let (length, source) = self.socket.recv_from(&mut self.wire).await?;
        if !self.source.admits(source) {
            return Ok(SocksUdpPacket::WrongSource);
        }
        let Ok(datagram) = decode_udp_datagram(&self.wire[..length]) else {
            return Ok(SocksUdpPacket::InvalidWire);
        };
        Ok(SocksUdpPacket::Valid {
            datagram,
            source_port: source.port(),
        })
    }

    pub(super) fn accept(&mut self, source_port: u16) {
        self.source.accept_valid(source_port);
        self.last_valid = Instant::now();
    }

    pub(super) async fn send(&mut self, target: &TargetAddr, payload: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationSend))
        {
            return Err(io::Error::other("injected application send failure"));
        }
        let length = encode_udp_datagram(target, payload, &mut self.wire)
            .map_err(|_| io::Error::other("SOCKS UDP response encoding failed"))?;
        let destination = self.source.destination()?;
        let sent = self
            .socket
            .send_to(&self.wire[..length], destination)
            .await?;
        if sent != length {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short SOCKS UDP response",
            ));
        }
        Ok(sent)
    }

    pub(super) fn idle_deadline(&self, timeout: std::time::Duration) -> Instant {
        self.last_valid + timeout
    }

    #[cfg(test)]
    pub(super) fn set_io_fault(&mut self, fault: Option<Arc<UdpIoFaultPlan>>) {
        self.io_fault = fault;
    }
}
