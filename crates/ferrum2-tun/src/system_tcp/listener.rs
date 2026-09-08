use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod live;
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
pub(super) use live::ListenerSet;

pub(super) struct AcceptedSocket {
    pub(super) epoch: u64,
    pub(super) local: SocketAddr,
    pub(super) peer: SocketAddr,
    pub(super) stream: crate::tcp::FlowSocket,
}

pub(super) fn derive_ipv4_peer(local: Ipv4Addr, prefix: u8) -> io::Result<Ipv4Addr> {
    if prefix > 30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system TCP IPv4 prefix must be /30 or wider",
        ));
    }
    let address = u32::from(local);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let network = address & mask;
    let broadcast = network | !mask;
    let mut candidate = network.saturating_add(1);
    if candidate == address {
        candidate = candidate.saturating_add(1);
    }
    if candidate >= broadcast {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system TCP IPv4 prefix has no synthetic peer",
        ));
    }
    Ok(Ipv4Addr::from(candidate))
}

pub(super) fn derive_ipv6_peer(local: Ipv6Addr, prefix: u8) -> io::Result<Ipv6Addr> {
    if prefix > 126 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "system TCP IPv6 prefix must be /126 or wider",
        ));
    }
    let address = u128::from(local);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    let network = address & mask;
    let mut candidate = network.saturating_add(1);
    if candidate == address {
        candidate = candidate.saturating_add(1);
    }
    Ok(Ipv6Addr::from(candidate))
}
