use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::{Deref, DerefMut};
#[cfg(test)]
use std::sync::Arc;

use bytes::{Buf as _, BytesMut};
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_socks5::{MAX_SOCKS_UDP_DATAGRAM_BYTES, decode_udp_datagram, encode_udp_datagram};
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::{StructuralCounter, StructuralLocal};
use tokio::net::UdpSocket;
use tokio::time::Instant;

#[cfg(test)]
use crate::run::egress::{UdpIoFaultPlan, UdpIoOperation};

use super::source_pinning::SocksUdpSourcePin;

pub(super) struct SocksUdpEndpoint {
    socket: UdpSocket,
    source: SocksUdpSourcePin,
    receive_wire: Option<BytesMut>,
    send_wire: BytesMut,
    #[cfg(feature = "structural-metrics")]
    structural: Option<StructuralLocal>,
    last_valid: Instant,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

/// One validated SOCKS UDP request with its original allocation still owned.
pub(super) struct SocksUdpOwnedPacket {
    target: TargetAddr,
    encoded_target_len: usize,
    source_port: u16,
    payload: BytesMut,
}

impl SocksUdpOwnedPacket {
    pub(super) fn target(&self) -> &TargetAddr {
        &self.target
    }

    pub(super) fn encoded_target_len(&self) -> usize {
        self.encoded_target_len
    }

    pub(super) fn source_port(&self) -> u16 {
        self.source_port
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(super) fn payload_mut(&mut self) -> &mut BytesMut {
        &mut self.payload
    }

    fn into_wire(self) -> BytesMut {
        self.payload
    }

    #[cfg(test)]
    pub(super) fn allocation_pointer(&self) -> *const u8 {
        self.payload.as_ptr()
    }

    #[cfg(test)]
    pub(super) fn allocation_capacity(&self) -> usize {
        self.payload.capacity()
    }
}

pub(super) enum SocksUdpPacket {
    Valid(SocksUdpOwnedPacket),
    WrongSource,
    InvalidWire,
}

struct ClearOnDrop<'a>(&'a mut BytesMut);

impl Deref for ClearOnDrop<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl DerefMut for ClearOnDrop<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.clear();
    }
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
            receive_wire: Some(BytesMut::new()),
            send_wire: BytesMut::new(),
            #[cfg(feature = "structural-metrics")]
            structural: None,
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

    #[cfg(feature = "structural-metrics")]
    pub(super) fn with_structural(mut self, structural: StructuralLocal) -> Self {
        self.structural = Some(structural);
        self
    }

    pub(super) async fn receive(&mut self) -> io::Result<SocksUdpPacket> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationRecv))
        {
            return Err(io::Error::other("injected application receive failure"));
        }
        let wire = self
            .receive_wire
            .as_mut()
            .ok_or_else(|| io::Error::other("SOCKS UDP receive packet was not recycled"))?;
        wire.clear();
        #[cfg(feature = "structural-metrics")]
        let allocates = wire.capacity() == 0;
        wire.reserve(MAX_SOCKS_UDP_DATAGRAM_BYTES);
        #[cfg(feature = "structural-metrics")]
        if allocates && let Some(structural) = &self.structural {
            structural.add(StructuralCounter::SocksUdpAllocations, 1);
        }
        let received = self.socket.recv_buf_from(wire).await;
        let (length, source) = match received {
            Ok(received) => received,
            Err(error) => {
                wire.clear();
                return Err(error);
            }
        };
        if length != wire.len() || length > MAX_SOCKS_UDP_DATAGRAM_BYTES {
            wire.clear();
            return Ok(SocksUdpPacket::InvalidWire);
        }
        if !self.source.admits(source) {
            wire.clear();
            return Ok(SocksUdpPacket::WrongSource);
        }
        let Ok(datagram) = decode_udp_datagram(wire) else {
            wire.clear();
            return Ok(SocksUdpPacket::InvalidWire);
        };
        let (target, encoded_target_len, payload_offset) = {
            let target = datagram.to_target_addr();
            let encoded_target_len = datagram.encoded_target_len();
            let payload_offset = length
                .checked_sub(datagram.payload().len())
                .expect("decoded SOCKS UDP payload is within its wire");
            (target, encoded_target_len, payload_offset)
        };
        let source_port = source.port();
        let mut payload = self
            .receive_wire
            .take()
            .expect("validated SOCKS UDP request owns receive wire");
        payload.advance(payload_offset);
        Ok(SocksUdpPacket::Valid(SocksUdpOwnedPacket {
            target,
            encoded_target_len,
            source_port,
            payload,
        }))
    }

    pub(super) fn recycle(&mut self, packet: SocksUdpOwnedPacket) {
        let mut wire = packet.into_wire();
        wire.clear();
        #[cfg(feature = "structural-metrics")]
        let allocates = wire.capacity() == 0;
        wire.reserve(MAX_SOCKS_UDP_DATAGRAM_BYTES);
        #[cfg(feature = "structural-metrics")]
        if allocates && let Some(structural) = &self.structural {
            structural.add(StructuralCounter::SocksUdpAllocations, 1);
        }
        debug_assert!(self.receive_wire.is_none());
        self.receive_wire = Some(wire);
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
        let destination = self.source.destination()?;
        let wire_len = socks_udp_wire_len(target, payload.len())?;
        if self.send_wire.capacity() < wire_len {
            self.send_wire = BytesMut::with_capacity(MAX_SOCKS_UDP_DATAGRAM_BYTES);
            #[cfg(feature = "structural-metrics")]
            if let Some(structural) = &self.structural {
                structural.add(StructuralCounter::SocksUdpAllocations, 1);
            }
        }
        self.send_wire.resize(wire_len, 0);
        let socket = &self.socket;
        let mut wire = ClearOnDrop(&mut self.send_wire);
        let length = encode_udp_datagram(target, payload, &mut wire)
            .map_err(|_| io::Error::other("SOCKS UDP response encoding failed"))?;
        #[cfg(feature = "structural-metrics")]
        if let Some(structural) = &self.structural {
            structural.add(
                StructuralCounter::SocksUdpCopyBytes,
                u64::try_from(payload.len()).unwrap_or(u64::MAX),
            );
        }
        debug_assert_eq!(length, wire_len);
        let sent = socket.send_to(&wire, destination).await?;
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
    pub(super) fn buffer_state(&self) -> ((usize, usize), (usize, usize)) {
        let receive = self
            .receive_wire
            .as_ref()
            .map_or((0, 0), |wire| (wire.len(), wire.capacity()));
        (receive, (self.send_wire.len(), self.send_wire.capacity()))
    }

    #[cfg(test)]
    pub(super) fn receive_allocation_pointer(&self) -> Option<*const u8> {
        self.receive_wire.as_ref().map(|wire| wire.as_ptr())
    }

    #[cfg(test)]
    pub(super) fn send_allocation_pointer(&self) -> *const u8 {
        self.send_wire.as_ptr()
    }

    #[cfg(test)]
    pub(super) fn set_io_fault(&mut self, fault: Option<Arc<UdpIoFaultPlan>>) {
        self.io_fault = fault;
    }
}

fn socks_udp_wire_len(target: &TargetAddr, payload_len: usize) -> io::Result<usize> {
    let encoded_target_len = match target.host() {
        TargetHostRef::Ip(IpAddr::V4(_)) => 7,
        TargetHostRef::Ip(IpAddr::V6(_)) => 19,
        TargetHostRef::Domain(host) => 4_usize
            .checked_add(host.len())
            .ok_or_else(socks_udp_bounds_error)?,
    };
    3_usize
        .checked_add(encoded_target_len)
        .and_then(|length| length.checked_add(payload_len))
        .filter(|length| *length <= MAX_SOCKS_UDP_DATAGRAM_BYTES)
        .ok_or_else(socks_udp_bounds_error)
}

fn socks_udp_bounds_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "SOCKS UDP datagram too large")
}
