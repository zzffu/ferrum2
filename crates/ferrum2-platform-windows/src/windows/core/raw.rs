#![allow(unsafe_code)]

use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpPrefixOriginManual,
    IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0, SOCKADDR_INET,
};

#[cfg(test)]
use crate::Error;
use crate::IpPrefix;

pub(in crate::windows) const MANAGED_CAPTURE_ROUTE_METRIC: u32 = 1;

pub(in crate::windows) fn initialize_managed_address(row: &mut MIB_UNICASTIPADDRESS_ROW) {
    *row = MIB_UNICASTIPADDRESS_ROW::default();
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
}

pub(in crate::windows) fn managed_address_matches(
    expected: &MIB_UNICASTIPADDRESS_ROW,
    actual: &MIB_UNICASTIPADDRESS_ROW,
) -> bool {
    unsafe {
        actual.InterfaceLuid.Value == expected.InterfaceLuid.Value
            && actual.InterfaceIndex == expected.InterfaceIndex
            && sockaddr_matches(&expected.Address, &actual.Address)
            && actual.PrefixOrigin == expected.PrefixOrigin
            && actual.SuffixOrigin == expected.SuffixOrigin
            && actual.ValidLifetime == expected.ValidLifetime
            && actual.PreferredLifetime == expected.PreferredLifetime
            && actual.OnLinkPrefixLength == expected.OnLinkPrefixLength
            && actual.SkipAsSource == expected.SkipAsSource
            && actual.ScopeId.Anonymous.Value == expected.ScopeId.Anonymous.Value
    }
}

pub(in crate::windows) fn capture_route_row(
    luid: NET_LUID_LH,
    interface_index: u32,
    prefix: IpPrefix,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2 {
        InterfaceLuid: luid,
        InterfaceIndex: interface_index,
        SitePrefixLength: 0,
        ValidLifetime: u32::MAX,
        PreferredLifetime: u32::MAX,
        Metric: MANAGED_CAPTURE_ROUTE_METRIC,
        Protocol: MIB_IPPROTO_NETMGMT,
        Loopback: false,
        AutoconfigureAddress: false,
        Publish: false,
        Immortal: false,
        Age: 0,
        Origin: NlroManual,
        ..MIB_IPFORWARD_ROW2::default()
    };
    match prefix {
        IpPrefix::V4(prefix) => {
            row.DestinationPrefix.Prefix = ipv4_sockaddr(prefix.address());
            row.DestinationPrefix.PrefixLength = prefix.length();
            row.NextHop = ipv4_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
        }
        IpPrefix::V6(prefix) => {
            row.DestinationPrefix.Prefix = ipv6_sockaddr(prefix.address());
            row.DestinationPrefix.PrefixLength = prefix.length();
            row.NextHop = ipv6_sockaddr(std::net::Ipv6Addr::UNSPECIFIED);
        }
    }
    row
}

pub(in crate::windows) fn route_matches(
    expected: &MIB_IPFORWARD_ROW2,
    actual: &MIB_IPFORWARD_ROW2,
) -> bool {
    unsafe {
        actual.InterfaceLuid.Value == expected.InterfaceLuid.Value
            && actual.InterfaceIndex == expected.InterfaceIndex
            && sockaddr_matches(
                &expected.DestinationPrefix.Prefix,
                &actual.DestinationPrefix.Prefix,
            )
            && actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength
            && sockaddr_matches(&expected.NextHop, &actual.NextHop)
            && actual.SitePrefixLength == 0
            && actual.ValidLifetime == u32::MAX
            && actual.PreferredLifetime == u32::MAX
            && actual.Metric == MANAGED_CAPTURE_ROUTE_METRIC
            && actual.Protocol == MIB_IPPROTO_NETMGMT
            && !actual.Loopback
            && !actual.AutoconfigureAddress
            && !actual.Publish
            && !actual.Immortal
            && actual.Origin == NlroManual
    }
}

fn sockaddr_matches(expected: &SOCKADDR_INET, actual: &SOCKADDR_INET) -> bool {
    unsafe {
        match expected.si_family {
            AF_INET => {
                actual.si_family == AF_INET
                    && actual.Ipv4.sin_port == expected.Ipv4.sin_port
                    && actual.Ipv4.sin_addr.S_un.S_addr == expected.Ipv4.sin_addr.S_un.S_addr
            }
            AF_INET6 => {
                actual.si_family == AF_INET6
                    && actual.Ipv6.sin6_port == expected.Ipv6.sin6_port
                    && actual.Ipv6.sin6_flowinfo == expected.Ipv6.sin6_flowinfo
                    && actual.Ipv6.sin6_addr.u.Byte == expected.Ipv6.sin6_addr.u.Byte
                    && actual.Ipv6.Anonymous.sin6_scope_id == expected.Ipv6.Anonymous.sin6_scope_id
            }
            _ => false,
        }
    }
}

pub(in crate::windows) fn socket_addr_sockaddr(address: std::net::SocketAddr) -> SOCKADDR_INET {
    match address {
        std::net::SocketAddr::V4(address) => {
            let mut raw = ipv4_sockaddr(*address.ip());
            raw.Ipv4.sin_port = address.port().to_be();
            raw
        }
        std::net::SocketAddr::V6(address) => {
            let mut raw = ipv6_sockaddr(*address.ip());
            raw.Ipv6.sin6_port = address.port().to_be();
            raw.Ipv6.sin6_flowinfo = address.flowinfo().to_be();
            raw.Ipv6.Anonymous.sin6_scope_id = address.scope_id();
            raw
        }
    }
}

pub(in crate::windows) fn ipv4_sockaddr(address: std::net::Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

pub(in crate::windows) fn ipv6_sockaddr(address: std::net::Ipv6Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: address.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        },
    }
}

#[cfg(test)]
pub(in crate::windows) use test_support::{
    increment_route_interface_luid, increment_unicast_interface_luid, route_destination,
    route_next_hop, set_route_destination, set_route_next_hop, sockaddr_port, sockaddr_scope_id,
};

#[cfg(test)]
mod test_support {
    use super::*;

    pub(in crate::windows) fn sockaddr_port(address: &SOCKADDR_INET) -> Result<u16, Error> {
        unsafe {
            match address.si_family {
                AF_INET => Ok(u16::from_be(address.Ipv4.sin_port)),
                AF_INET6 => Ok(u16::from_be(address.Ipv6.sin6_port)),
                _ => Err(Error),
            }
        }
    }

    pub(in crate::windows) fn sockaddr_scope_id(address: &SOCKADDR_INET) -> Result<u32, Error> {
        unsafe {
            match address.si_family {
                AF_INET => Ok(0),
                AF_INET6 => Ok(address.Ipv6.Anonymous.sin6_scope_id),
                _ => Err(Error),
            }
        }
    }

    pub(in crate::windows) fn sockaddr_ip(
        address: &SOCKADDR_INET,
    ) -> Result<std::net::IpAddr, Error> {
        unsafe {
            match address.si_family {
                AF_INET => Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ))),
                AF_INET6 => Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    address.Ipv6.sin6_addr.u.Byte,
                ))),
                _ => Err(Error),
            }
        }
    }

    pub(in crate::windows) fn route_destination(
        row: &MIB_IPFORWARD_ROW2,
    ) -> Result<std::net::IpAddr, Error> {
        sockaddr_ip(&row.DestinationPrefix.Prefix)
    }

    pub(in crate::windows) fn route_next_hop(
        row: &MIB_IPFORWARD_ROW2,
    ) -> Result<std::net::IpAddr, Error> {
        sockaddr_ip(&row.NextHop)
    }

    pub(in crate::windows) fn set_route_destination(
        row: &mut MIB_IPFORWARD_ROW2,
        address: std::net::IpAddr,
    ) {
        row.DestinationPrefix.Prefix = match address {
            std::net::IpAddr::V4(address) => ipv4_sockaddr(address),
            std::net::IpAddr::V6(address) => ipv6_sockaddr(address),
        };
    }

    pub(in crate::windows) fn set_route_next_hop(
        row: &mut MIB_IPFORWARD_ROW2,
        address: std::net::IpAddr,
    ) {
        row.NextHop = match address {
            std::net::IpAddr::V4(address) => ipv4_sockaddr(address),
            std::net::IpAddr::V6(address) => ipv6_sockaddr(address),
        };
    }

    pub(in crate::windows) fn increment_route_interface_luid(row: &mut MIB_IPFORWARD_ROW2) {
        unsafe { row.InterfaceLuid.Value += 1 };
    }

    pub(in crate::windows) fn increment_unicast_interface_luid(row: &mut MIB_UNICASTIPADDRESS_ROW) {
        unsafe { row.InterfaceLuid.Value += 1 };
    }
}
