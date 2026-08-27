use std::ffi::c_void;
use std::os::windows::io::AsRawSocket;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use ferrum2_net::{
    NetworkFamily, NetworkInterfaceCatalog, NetworkInterfaceCatalogError, NetworkInterfaceKind,
    NetworkInterfaceObservation, ResolvedInterface, ResolvedSocketBinder, SystemBestRoute,
};
use socket2::Socket;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetBestInterfaceEx, GetBestRoute2, GetIfTable2, GetIpForwardTable2,
    GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, NET_LUID_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IpDadStateDeprecated, IpDadStatePreferred, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_INET, bind as winsock_bind, setsockopt,
};

use super::super::core::network::contract::CatalogDefaultRoute;
use super::super::core::network::{
    CatalogFamilyRow, CatalogInterfaceRow, DefaultRouteCandidate, InterfaceCandidate,
    ResolvedSocketBindingOperations, bind_resolved_socket_with,
    build_network_interface_observations, catalog_default_route as classify_default_route,
    eligible_interface_identity as classify_eligible_interface,
    fallback_interface_identity as classify_fallback_interface, interface_socket_option,
};
use super::super::core::network::{
    InterfaceIdentity, RouteFingerprint, SocketBindingOperations, UnderlayOperations,
    UnderlayPolicy, WindowsNetworkInterfaceCatalog, bind_fixed_with, bind_target_with,
    same_ip_family, snapshot_underlay_at,
};
use super::super::core::raw::socket_addr_sockaddr;
use super::managed::managed_interface_identity_matches;
use crate::Error;

impl NetworkInterfaceCatalog for WindowsNetworkInterfaceCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        read_network_interface_observations(
            self.managed_tun()
                .map_err(|_| NetworkInterfaceCatalogError)?,
        )
        .map_err(|_| NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        destination: std::net::SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        system_best_route(
            destination,
            self.managed_tun()
                .map_err(|_| NetworkInterfaceCatalogError)?,
        )
        .map_err(|_| NetworkInterfaceCatalogError)
    }
}

impl UnderlayPolicy {
    pub fn bind_fixed<T: AsRawSocket>(
        &self,
        socket: &T,
        endpoint: std::net::SocketAddr,
    ) -> Result<(), Error> {
        bind_fixed_socket(self, socket, endpoint)
    }

    pub fn bind_target<T: AsRawSocket>(
        &self,
        socket: &T,
        target: std::net::SocketAddr,
    ) -> Result<(), Error> {
        bind_target_socket(self, socket, target)
    }
}

pub(in crate::windows) fn bind_fixed_socket<T: AsRawSocket>(
    policy: &UnderlayPolicy,
    socket: &T,
    endpoint: std::net::SocketAddr,
) -> Result<(), Error> {
    bind_fixed_with(policy, endpoint, &mut PlatformSocketBinder(socket))
}

pub(in crate::windows) fn bind_target_socket<T: AsRawSocket>(
    policy: &UnderlayPolicy,
    socket: &T,
    target: std::net::SocketAddr,
) -> Result<(), Error> {
    bind_target_with(
        policy,
        target,
        &mut PlatformUnderlay,
        &mut PlatformSocketBinder(socket),
    )
}

pub(super) struct PlatformSocketBinder<'a, T>(&'a T);

impl<T: AsRawSocket> SocketBindingOperations for PlatformSocketBinder<'_, T> {
    fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error> {
        bind_socket(self.0, family, interface_index)
    }
}

/// Applies one shared runtime interface decision to an unconnected Windows socket.
///
/// The family-specific `IP_UNICAST_IF`/`IPV6_UNICAST_IF` constraint is installed first. When the
/// decision carries an explicit source address, the socket is then bound to that address and an
/// ephemeral port. Generation validation remains owned by the runtime resolver's prepare/commit
/// boundary; callers must discard the socket when this function or that commit fails.
pub fn bind_resolved_socket<T: AsRawSocket>(
    socket: &T,
    destination: std::net::SocketAddr,
    resolved: &ResolvedInterface,
) -> Result<(), Error> {
    bind_resolved_socket_with(
        destination,
        resolved,
        &mut PlatformResolvedSocketBinder(socket),
    )
}

/// Production adapter from the shared runtime socket service to the reviewed Windows boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsResolvedSocketBinder;

impl ResolvedSocketBinder for WindowsResolvedSocketBinder {
    type Error = Error;

    fn bind_resolved_socket(
        &self,
        socket: &Socket,
        destination: std::net::SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<(), Self::Error> {
        bind_resolved_socket(socket, destination, resolved)
    }
}

pub(super) struct PlatformResolvedSocketBinder<'a, T>(&'a T);

impl<T: AsRawSocket> ResolvedSocketBindingOperations for PlatformResolvedSocketBinder<'_, T> {
    fn bind_interface(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<(), Error> {
        bind_socket(self.0, family, interface_index)
    }

    fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error> {
        bind_source_socket(self.0, source)
    }
}

pub(super) fn bind_socket<T: AsRawSocket>(
    socket: &T,
    family: std::net::IpAddr,
    interface_index: u32,
) -> Result<(), Error> {
    let (level, option, value) = interface_socket_option(family, interface_index);
    let status = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&raw const value).cast(),
            i32::try_from(std::mem::size_of_val(&value)).map_err(|_| Error)?,
        )
    };
    if status == 0 { Ok(()) } else { Err(Error) }
}

pub(super) fn bind_source_socket<T: AsRawSocket>(
    socket: &T,
    source: std::net::SocketAddr,
) -> Result<(), Error> {
    let raw = socket_addr_sockaddr(source);
    let length = match source {
        std::net::SocketAddr::V4(_) => std::mem::size_of::<SOCKADDR_IN>(),
        std::net::SocketAddr::V6(_) => std::mem::size_of::<SOCKADDR_IN6>(),
    };
    let status = unsafe {
        winsock_bind(
            socket.as_raw_socket() as usize,
            (&raw const raw).cast::<SOCKADDR>(),
            i32::try_from(length).map_err(|_| Error)?,
        )
    };
    if status == 0 { Ok(()) } else { Err(Error) }
}

pub(super) fn snapshot_underlay(
    config: &crate::ManagedNetworkConfig,
    generation: Arc<AtomicU64>,
    expected_generation: u64,
) -> Result<UnderlayPolicy, Error> {
    snapshot_underlay_at(
        config,
        generation,
        expected_generation,
        &mut PlatformUnderlay,
    )
}

pub(super) struct PlatformUnderlay;

impl UnderlayOperations for PlatformUnderlay {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error> {
        eligible_interfaces(excluded)
    }

    fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error> {
        let destination = socket_addr_sockaddr(destination);
        let mut index = 0;
        if unsafe { GetBestInterfaceEx((&raw const destination).cast::<SOCKADDR>(), &mut index) }
            != ERROR_SUCCESS
            || index == 0
        {
            Err(Error)
        } else {
            Ok(index)
        }
    }

    fn interface_metric(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<u32, Error> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = match family {
            std::net::IpAddr::V4(_) => AF_INET,
            std::net::IpAddr::V6(_) => AF_INET6,
        };
        row.InterfaceIndex = interface_index;
        if unsafe { GetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS || !row.Connected {
            return Err(Error);
        }
        Ok(row.Metric)
    }

    fn constrained_route(
        &mut self,
        destination: std::net::SocketAddr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error> {
        constrained_route(destination, interface_index, require_source)
    }
}

pub(super) const MAX_CATALOG_INTERFACES: usize = 4_096;
pub(super) const MAX_CATALOG_ADDRESSES: usize = 16_384;
pub(super) const MAX_CATALOG_ROUTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CatalogAddressGroup {
    identity: InterfaceIdentity,
    family: NetworkFamily,
    addresses: Vec<std::net::IpAddr>,
}

pub(in crate::windows) fn read_network_interface_observations(
    managed_tun: Option<InterfaceIdentity>,
) -> Result<Vec<NetworkInterfaceObservation>, Error> {
    require_catalog_managed_identity(managed_tun)?;
    let interfaces = read_catalog_interfaces()?;
    let address_groups = read_catalog_address_groups()?;
    let default_routes = read_catalog_default_routes()?;
    let mut families = Vec::with_capacity(address_groups.len());
    for group in address_groups {
        let (connected, interface_metric) =
            read_catalog_family_state(group.identity, group.family)?;
        let default_route_metric = default_routes
            .iter()
            .filter(|route| route.identity == group.identity && route.family == group.family)
            .map(|route| route.metric)
            .min();
        families.push(CatalogFamilyRow {
            identity: group.identity,
            family: group.family,
            addresses: group.addresses,
            connected,
            interface_metric,
            default_route_metric,
        });
    }
    build_network_interface_observations(&interfaces, &families, managed_tun)
}

pub(super) fn read_catalog_interfaces() -> Result<Vec<CatalogInterfaceRow>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
    // SAFETY: GetIfTable2 allocated one table with NumEntries contiguous rows. `owner` keeps the
    // allocation live through this copy and releases it exactly once with FreeMibTable.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows.iter().filter_map(catalog_interface_row).collect();
    drop(owner);
    Ok(result)
}

pub(super) fn catalog_interface_row(row: &MIB_IF_ROW2) -> Option<CatalogInterfaceRow> {
    // SAFETY: InterfaceLuid.Value is the active NET_LUID_LH representation returned by
    // GetIfTable2; reading it does not outlive the copied row.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    if identity.luid == 0 || identity.index == 0 {
        return None;
    }
    let name = decode_interface_name(&row.Alias)?;
    Some(CatalogInterfaceRow {
        identity,
        name,
        operational: row.OperStatus == IfOperStatusUp && row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
        connected: row.MediaConnectState == MediaConnectStateConnected,
        kind: if row.Type
            == windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
        {
            NetworkInterfaceKind::Loopback
        } else {
            NetworkInterfaceKind::Underlay
        },
    })
}

pub(super) fn decode_interface_name(raw: &[u16]) -> Option<Box<str>> {
    let end = raw.iter().position(|unit| *unit == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    String::from_utf16(&raw[..end])
        .ok()
        .map(String::into_boxed_str)
}

pub(super) fn read_catalog_address_groups() -> Result<Vec<CatalogAddressGroup>, Error> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) } != ERROR_SUCCESS
        || table.is_null()
    {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_ADDRESSES {
        return Err(Error);
    }
    // SAFETY: GetUnicastIpAddressTable allocated NumEntries contiguous rows. `owner` holds the
    // allocation until every address has been copied into owned Rust values.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut groups = Vec::<CatalogAddressGroup>::new();
    for row in rows {
        let Some((identity, family, address)) = catalog_unicast_address(row) else {
            continue;
        };
        let group = if let Some(group) = groups
            .iter_mut()
            .find(|group| group.identity == identity && group.family == family)
        {
            group
        } else {
            groups.push(CatalogAddressGroup {
                identity,
                family,
                addresses: Vec::new(),
            });
            groups.last_mut().ok_or(Error)?
        };
        group.addresses.push(address);
    }
    for group in &mut groups {
        group.addresses.sort_unstable();
        group.addresses.dedup();
    }
    drop(owner);
    Ok(groups)
}

pub(super) fn catalog_unicast_address(
    row: &MIB_UNICASTIPADDRESS_ROW,
) -> Option<(InterfaceIdentity, NetworkFamily, std::net::IpAddr)> {
    if row.DadState != IpDadStatePreferred && row.DadState != IpDadStateDeprecated {
        return None;
    }
    // SAFETY: InterfaceLuid.Value is the active NET_LUID_LH representation in this IP Helper row.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    if identity.luid == 0 || identity.index == 0 {
        return None;
    }
    let address = sockaddr_ip(&row.Address).ok()?;
    if address.is_unspecified() || address.is_multicast() {
        return None;
    }
    Some((identity, NetworkFamily::of(address), address))
}

pub(super) fn read_catalog_default_routes() -> Result<Vec<CatalogDefaultRoute>, Error> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_ROUTES {
        return Err(Error);
    }
    // SAFETY: GetIpForwardTable2 allocated NumEntries contiguous rows. `owner` keeps the table
    // alive while each default-route identity and metric is copied.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let routes = rows.iter().filter_map(catalog_default_route).collect();
    drop(owner);
    Ok(routes)
}

pub(super) fn catalog_default_route(row: &MIB_IPFORWARD_ROW2) -> Option<CatalogDefaultRoute> {
    let destination = sockaddr_ip(&row.DestinationPrefix.Prefix).ok()?;
    classify_default_route(DefaultRouteCandidate {
        identity: InterfaceIdentity {
            luid: unsafe { row.InterfaceLuid.Value },
            index: row.InterfaceIndex,
        },
        destination,
        prefix_length: row.DestinationPrefix.PrefixLength,
        metric: row.Metric,
    })
}

pub(super) fn read_catalog_family_state(
    identity: InterfaceIdentity,
    family: NetworkFamily,
) -> Result<(bool, u32), Error> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = match family {
        NetworkFamily::Ipv4 => AF_INET,
        NetworkFamily::Ipv6 => AF_INET6,
    };
    row.InterfaceLuid = NET_LUID_LH {
        Value: identity.luid,
    };
    if unsafe { GetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
        return Err(Error);
    }
    // SAFETY: GetIpInterfaceEntry returned a fully initialized NET_LUID_LH row.
    if unsafe { row.InterfaceLuid.Value } != identity.luid || row.InterfaceIndex != identity.index {
        return Err(Error);
    }
    Ok((row.Connected, row.Metric))
}

pub(in crate::windows) fn system_best_route(
    destination: std::net::SocketAddr,
    managed_tun: Option<InterfaceIdentity>,
) -> Result<SystemBestRoute, Error> {
    require_catalog_managed_identity(managed_tun)?;
    let primary = unconstrained_route(destination)?;
    let primary_identity = route_identity(primary)?;
    let selected = if managed_tun != Some(primary_identity) {
        primary
    } else {
        let mut selected = None::<(RouteFingerprint, u64)>;
        for identity in catalog_fallback_interfaces(managed_tun)? {
            let Ok(route) = constrained_route(destination, identity.index, true) else {
                continue;
            };
            if route.interface_luid != identity.luid
                || route.interface_index != identity.index
                || !same_ip_family(destination.ip(), route.destination)
                || route
                    .source
                    .is_none_or(|source| !same_ip_family(destination.ip(), source))
            {
                continue;
            }
            let Ok(interface_metric) =
                PlatformUnderlay.interface_metric(destination.ip(), identity.index)
            else {
                continue;
            };
            let effective_metric = u64::from(route.metric) + u64::from(interface_metric);
            if selected.as_ref().is_none_or(|(current, current_metric)| {
                system_route_is_preferred(route, effective_metric, *current, *current_metric)
            }) {
                selected = Some((route, effective_metric));
            }
        }
        selected.map(|(route, _)| route).ok_or(Error)?
    };
    let identity = route_identity(selected)?;
    SystemBestRoute::new(identity.luid, identity.index).map_err(|_| Error)
}

pub(super) fn require_catalog_managed_identity(
    managed_tun: Option<InterfaceIdentity>,
) -> Result<(), Error> {
    let Some(managed_tun) = managed_tun else {
        return Ok(());
    };
    let luid = NET_LUID_LH {
        Value: managed_tun.luid,
    };
    managed_interface_identity_matches(luid, managed_tun.index)
        .then_some(())
        .ok_or(Error)
}

pub(super) fn unconstrained_route(
    destination: std::net::SocketAddr,
) -> Result<RouteFingerprint, Error> {
    let destination_sockaddr = socket_addr_sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    if unsafe {
        GetBestRoute2(
            null(),
            0,
            null(),
            &destination_sockaddr,
            0,
            &mut route,
            &mut source,
        )
    } != ERROR_SUCCESS
    {
        return Err(Error);
    }
    let source = sockaddr_ip(&source)?;
    if source.is_unspecified() || !same_ip_family(destination.ip(), source) {
        return Err(Error);
    }
    route_fingerprint(&route, Some(source))
}

pub(super) fn route_identity(route: RouteFingerprint) -> Result<InterfaceIdentity, Error> {
    if route.interface_luid == 0 || route.interface_index == 0 {
        return Err(Error);
    }
    Ok(InterfaceIdentity {
        luid: route.interface_luid,
        index: route.interface_index,
    })
}

pub(super) fn system_route_is_preferred(
    candidate: RouteFingerprint,
    candidate_metric: u64,
    current: RouteFingerprint,
    current_metric: u64,
) -> bool {
    candidate.prefix_length > current.prefix_length
        || (candidate.prefix_length == current.prefix_length
            && (candidate_metric < current_metric
                || (candidate_metric == current_metric
                    && (candidate.interface_luid, candidate.interface_index)
                        < (current.interface_luid, current.interface_index))))
}

pub(super) fn catalog_fallback_interfaces(
    excluded: Option<InterfaceIdentity>,
) -> Result<Vec<InterfaceIdentity>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
    // SAFETY: GetIfTable2 allocated NumEntries contiguous rows and `owner` retains the allocation
    // until every selected LUID/index pair has been copied.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows
        .iter()
        .filter_map(|row| catalog_fallback_interface_identity(row, excluded))
        .collect();
    drop(owner);
    Ok(result)
}

pub(super) fn catalog_fallback_interface_identity(
    row: &MIB_IF_ROW2,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    // SAFETY: InterfaceLuid.Value is the active representation returned by GetIfTable2.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    classify_fallback_interface(
        InterfaceCandidate {
            identity,
            loopback: row.Type
                == windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK,
            operational: row.OperStatus == IfOperStatusUp,
            admin_enabled: row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
            connected: row.MediaConnectState == MediaConnectStateConnected,
            hardware_interface: row.InterfaceAndOperStatusFlags._bitfield & 1 == 1,
        },
        excluded,
    )
}

pub(super) fn eligible_interfaces(
    excluded: Option<InterfaceIdentity>,
) -> Result<Vec<InterfaceIdentity>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows
        .iter()
        .filter_map(|row| eligible_interface_identity(row, excluded))
        .collect();
    drop(owner);
    Ok(result)
}

pub(super) fn eligible_interface_identity(
    row: &MIB_IF_ROW2,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    let identity = InterfaceIdentity {
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
    };
    classify_eligible_interface(
        InterfaceCandidate {
            identity,
            loopback: row.Type
                == windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK,
            operational: row.OperStatus == IfOperStatusUp,
            admin_enabled: row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
            connected: row.MediaConnectState == MediaConnectStateConnected,
            hardware_interface: row.InterfaceAndOperStatusFlags._bitfield & 1 == 1,
        },
        excluded,
    )
}

pub(super) struct MibTable(*mut c_void);

impl Drop for MibTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0) };
    }
}

pub(super) fn constrained_route(
    destination: std::net::SocketAddr,
    interface_index: u32,
    require_source: bool,
) -> Result<RouteFingerprint, Error> {
    let destination_sockaddr = socket_addr_sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    if unsafe {
        GetBestRoute2(
            null(),
            interface_index,
            null(),
            &destination_sockaddr,
            0,
            &mut route,
            &mut source,
        )
    } != ERROR_SUCCESS
        || route.InterfaceIndex != interface_index
    {
        return Err(Error);
    }
    let source = sockaddr_ip(&source)?;
    if !same_ip_family(destination.ip(), source) || (require_source && source.is_unspecified()) {
        return Err(Error);
    }
    route_fingerprint(&route, require_source.then_some(source))
}

pub(super) fn route_fingerprint(
    row: &MIB_IPFORWARD_ROW2,
    source: Option<std::net::IpAddr>,
) -> Result<RouteFingerprint, Error> {
    let destination = sockaddr_ip(&row.DestinationPrefix.Prefix)?;
    let next_hop = sockaddr_ip(&row.NextHop)?;
    if !same_ip_family(destination, next_hop)
        || source.is_some_and(|source| !same_ip_family(destination, source))
    {
        return Err(Error);
    }
    Ok(RouteFingerprint {
        interface_luid: unsafe { row.InterfaceLuid.Value },
        interface_index: row.InterfaceIndex,
        destination,
        prefix_length: row.DestinationPrefix.PrefixLength,
        next_hop,
        metric: row.Metric,
        source,
    })
}

pub(super) fn sockaddr_ip(address: &SOCKADDR_INET) -> Result<std::net::IpAddr, Error> {
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
