use std::sync::Arc;

use ferrum2_net::{
    InterfaceBinding, NetworkFamily, NetworkInterfaceKind, NetworkInterfaceObservation,
    ResolvedInterface,
};
use windows_sys::Win32::Networking::WinSock::{
    IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
};

use crate::Error;

use super::super::network::InterfaceIdentity;

pub(in crate::windows) trait ResolvedSocketBindingOperations {
    fn bind_interface(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<(), Error>;
    fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error>;
}

pub(in crate::windows) fn bind_resolved_socket_with(
    destination: std::net::SocketAddr,
    resolved: &ResolvedInterface,
    operations: &mut impl ResolvedSocketBindingOperations,
) -> Result<(), Error> {
    let family = NetworkFamily::of(destination.ip());
    let binding = resolved.binding();
    if !binding.supports(family) {
        return Err(Error::invalid_input());
    }
    let source = resolved.source_address();
    if source.is_some_and(|source| {
        NetworkFamily::of(source) != family || !binding.addresses().contains(&source)
    }) {
        return Err(Error::invalid_input());
    }

    operations.bind_interface(destination.ip(), binding.index())?;
    if let Some(source) = source {
        let scope_id = match source {
            std::net::IpAddr::V6(address) if address.is_unicast_link_local() => binding.index(),
            _ => 0,
        };
        operations.bind_source(with_scope_id(
            std::net::SocketAddr::new(source, 0),
            scope_id,
        ))?;
    }
    Ok(())
}

fn with_scope_id(address: std::net::SocketAddr, scope_id: u32) -> std::net::SocketAddr {
    match address {
        std::net::SocketAddr::V4(_) => address,
        std::net::SocketAddr::V6(address) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            *address.ip(),
            address.port(),
            address.flowinfo(),
            scope_id,
        )),
    }
}

pub(in crate::windows) fn interface_socket_option(
    family: std::net::IpAddr,
    interface_index: u32,
) -> (i32, i32, u32) {
    match family {
        std::net::IpAddr::V4(_) => (
            IPPROTO_IP,
            IP_UNICAST_IF,
            ipv4_interface_index_option_value(interface_index),
        ),
        std::net::IpAddr::V6(_) => (
            IPPROTO_IPV6,
            IPV6_UNICAST_IF,
            ipv6_interface_index_option_value(interface_index),
        ),
    }
}

pub(in crate::windows) const fn ipv4_interface_index_option_value(interface_index: u32) -> u32 {
    interface_index.to_be()
}

pub(in crate::windows) const fn ipv6_interface_index_option_value(interface_index: u32) -> u32 {
    interface_index
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::windows) struct CatalogInterfaceRow {
    pub(in crate::windows) identity: InterfaceIdentity,
    pub(in crate::windows) name: Box<str>,
    pub(in crate::windows) operational: bool,
    pub(in crate::windows) connected: bool,
    pub(in crate::windows) kind: NetworkInterfaceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::windows) struct CatalogFamilyRow {
    pub(in crate::windows) identity: InterfaceIdentity,
    pub(in crate::windows) family: NetworkFamily,
    pub(in crate::windows) addresses: Vec<std::net::IpAddr>,
    pub(in crate::windows) connected: bool,
    pub(in crate::windows) interface_metric: u32,
    pub(in crate::windows) default_route_metric: Option<u32>,
}

pub(in crate::windows) fn build_network_interface_observations(
    interfaces: &[CatalogInterfaceRow],
    families: &[CatalogFamilyRow],
    managed_tun: Option<InterfaceIdentity>,
) -> Result<Vec<NetworkInterfaceObservation>, Error> {
    let mut observations = Vec::with_capacity(families.len());
    for family in families {
        let mut matches = interfaces
            .iter()
            .filter(|interface| interface.identity == family.identity);
        let Some(interface) = matches.next() else {
            continue;
        };
        if matches.next().is_some() {
            return Err(Error);
        }
        let kind = if managed_tun == Some(interface.identity) {
            NetworkInterfaceKind::ManagedTun
        } else {
            interface.kind
        };
        let binding = InterfaceBinding::new(
            Arc::<str>::from(interface.name.as_ref()),
            interface.identity.luid,
            interface.identity.index,
            family.addresses.clone(),
        )
        .map_err(|_| Error)?;
        observations.push(
            NetworkInterfaceObservation::new(
                binding,
                family.family,
                interface.operational,
                interface.connected && family.connected,
                kind,
                family.interface_metric,
                family.default_route_metric,
            )
            .map_err(|_| Error)?,
        );
    }
    Ok(observations)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct InterfaceCandidate {
    pub(in crate::windows) identity: InterfaceIdentity,
    pub(in crate::windows) loopback: bool,
    pub(in crate::windows) operational: bool,
    pub(in crate::windows) admin_enabled: bool,
    pub(in crate::windows) connected: bool,
    pub(in crate::windows) hardware_interface: bool,
}

pub(in crate::windows) fn fallback_interface_identity(
    candidate: InterfaceCandidate,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    (candidate.identity.luid != 0
        && candidate.identity.index != 0
        && !candidate.loopback
        && candidate.operational
        && candidate.admin_enabled
        && candidate.connected
        && excluded != Some(candidate.identity))
    .then_some(candidate.identity)
}

pub(in crate::windows) fn eligible_interface_identity(
    candidate: InterfaceCandidate,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    (candidate.hardware_interface && fallback_interface_identity(candidate, excluded).is_some())
        .then_some(candidate.identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct DefaultRouteCandidate {
    pub(in crate::windows) identity: InterfaceIdentity,
    pub(in crate::windows) destination: std::net::IpAddr,
    pub(in crate::windows) prefix_length: u8,
    pub(in crate::windows) metric: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct CatalogDefaultRoute {
    pub(in crate::windows) identity: InterfaceIdentity,
    pub(in crate::windows) family: NetworkFamily,
    pub(in crate::windows) metric: u32,
}

pub(in crate::windows) fn catalog_default_route(
    candidate: DefaultRouteCandidate,
) -> Option<CatalogDefaultRoute> {
    (candidate.prefix_length == 0
        && candidate.destination.is_unspecified()
        && candidate.identity.luid != 0
        && candidate.identity.index != 0)
        .then(|| CatalogDefaultRoute {
            identity: candidate.identity,
            family: NetworkFamily::of(candidate.destination),
            metric: candidate.metric,
        })
}
