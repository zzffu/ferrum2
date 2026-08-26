use std::io;
use std::net::{IpAddr, SocketAddr};

pub(super) struct SocksUdpSourcePin {
    peer_ip: IpAddr,
    port: Option<u16>,
}

impl SocksUdpSourcePin {
    pub(super) fn new(peer_ip: IpAddr, requested_port: u16) -> Self {
        Self {
            peer_ip,
            port: (requested_port != 0).then_some(requested_port),
        }
    }

    pub(super) fn admits(&self, source: SocketAddr) -> bool {
        source.ip() == self.peer_ip && self.port.is_none_or(|port| port == source.port())
    }

    pub(super) fn accept_valid(&mut self, source_port: u16) {
        if self.port.is_none() {
            self.port = Some(source_port);
        }
    }

    pub(super) fn destination(&self) -> io::Result<SocketAddr> {
        self.port
            .map(|port| SocketAddr::new(self.peer_ip, port))
            .ok_or_else(|| io::Error::other("SOCKS UDP source unset"))
    }
}
