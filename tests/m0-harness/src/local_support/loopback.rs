use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::Mutex;

use socket2::{Domain, Protocol, Socket, Type};

use super::ISSUED_PORTS;

pub struct LoopbackReservation {
    listener: TcpListener,
    address: SocketAddrV4,
}

impl LoopbackReservation {
    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn release(self) -> SocketAddrV4 {
        drop(self.listener);
        self.address
    }
}

pub fn reserve_loopback() -> (TcpListener, SocketAddrV4) {
    let listener = bind_loopback_listener(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port");
    let address = match listener.local_addr().expect("reserved address") {
        std::net::SocketAddr::V4(address) => address,
        std::net::SocketAddr::V6(_) => unreachable!("IPv4 bind returned IPv6"),
    };
    (listener, address)
}

pub fn bind_loopback_listener(address: SocketAddrV4) -> io::Result<TcpListener> {
    loop {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::V4(address).into())?;
        socket.listen(128)?;
        let listener: TcpListener = socket.into();
        if address.port() != 0 {
            return Ok(listener);
        }
        let port = listener.local_addr()?.port();
        if ISSUED_PORTS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("issued-port registry")
            .insert(port)
        {
            return Ok(listener);
        }
    }
}

pub fn reserve_unused_loopback() -> LoopbackReservation {
    let (listener, address) = reserve_loopback();
    LoopbackReservation { listener, address }
}

pub fn unused_loopback() -> SocketAddrV4 {
    reserve_unused_loopback().release()
}

pub fn unused_tcp_udp_loopback() -> SocketAddrV4 {
    loop {
        let (tcp, address) = reserve_loopback();
        let Ok(udp) = UdpSocket::bind(address) else {
            drop(tcp);
            continue;
        };
        drop((tcp, udp));
        return address;
    }
}
