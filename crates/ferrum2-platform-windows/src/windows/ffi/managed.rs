use std::path::Path;
use std::ptr::null;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NOT_FOUND, ERROR_SUCCESS, GetLastError,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings,
    GetInterfaceDnsSettings, GetIpForwardEntry2, GetIpInterfaceEntry, GetUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid,
    IpDadStatePreferred, IpDadStateTentative, IpPrefixOriginManual, IpSuffixOriginManual,
    MIB_IPPROTO_NETMGMT, NL_DAD_STATE, NlroManual, SOCKADDR_INET,
};
use windows_sys::core::GUID;

use super::super::managed::{
    CleanupOperations, ManagedAddressCleanupOperations, ManagedAddressRead, ManagedDnsLease,
    ManagedDnsOperations, ManagedRouteCleanupOperations, ManagedRouteOperations, ManagedRouteRead,
    SetupOperations, delete_managed_address, delete_managed_route, managed_routes_match,
    restore_managed_dns, take_last_owned_route,
};
use super::super::network::{
    InterfaceIdentity, UnderlayOperations, UnderlayPolicy, underlay_matches_with,
};
use super::loader::wide;
use super::network::{MANAGED_CAPTURE_ROUTE_METRIC, ipv4_sockaddr, ipv6_sockaddr};
use super::notification::NotificationOwners;
use super::strict_route::PlatformStrictRouteSession;
use super::wintun::{Adapter, SessionState};
use crate::{Error, IpPrefix, ManagedStateDamage, ManagedTunHealth};

pub(super) struct ManagedState {
    pub(super) notifications: NotificationOwners,
    pub(super) validated_generation: u64,
    pub(super) policy: UnderlayPolicy,
    pub(super) capture_routes: Vec<IpPrefix>,
    pub(super) pending_route: Option<MIB_IPFORWARD_ROW2>,
    pub(super) routes: Vec<MIB_IPFORWARD_ROW2>,
    pub(super) ipv4_dns_address: Option<std::net::Ipv4Addr>,
    pub(super) ipv6_dns_address: Option<std::net::Ipv6Addr>,
    pub(super) dns_interface: Option<GUID>,
    pub(super) ipv4_dns: Option<ManagedDnsLease<Ipv4DnsSettings>>,
    pub(super) ipv6_dns: Option<ManagedDnsLease<Ipv6DnsSettings>>,
    pub(super) strict_route_intent: bool,
    // The dynamic engine belongs to the long-lived managed plane and closes only in full cleanup.
    pub(super) strict_route: Option<PlatformStrictRouteSession>,
}

#[derive(Clone, Copy)]
pub(super) struct ManagedOwnershipLedgerView<'a> {
    pub(super) capture_routes: &'a [IpPrefix],
    pub(super) pending_route: bool,
    pub(super) route_count: usize,
    pub(super) ipv4_dns_address: Option<std::net::Ipv4Addr>,
    pub(super) ipv6_dns_address: Option<std::net::Ipv6Addr>,
    pub(super) dns_interface: bool,
    pub(super) ipv4_dns_lease: bool,
    pub(super) ipv6_dns_lease: bool,
    pub(super) strict_route_intent: bool,
    pub(super) strict_route_session: bool,
}

/// Read-only owner of Windows route, interface, and unicast-address notifications.
///
/// This monitor does not create or mutate a TUN adapter. It lets binaries that use the shared
/// network socket service observe ordinary Windows network changes even when no managed TUN is
/// configured. Callers should debounce successful observations before capturing and publishing a
/// replacement network snapshot.

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Ipv4DnsSettings(pub(super) Option<Box<[u16]>>);

#[derive(Clone, Eq, PartialEq)]
pub(super) struct Ipv6DnsSettings(pub(super) Option<Box<[u16]>>);

pub(super) struct PlatformManagedIpv4Dns(pub(super) GUID);

impl ManagedDnsOperations for PlatformManagedIpv4Dns {
    type Settings = Ipv4DnsSettings;
    type Address = std::net::Ipv4Addr;

    fn snapshot(&mut self) -> Result<Self::Settings, Error> {
        read_ipv4_dns_settings(self.0)
    }

    fn apply(&mut self, address: std::net::Ipv4Addr) -> Result<Self::Settings, Error> {
        let settings = Ipv4DnsSettings(Some(
            address.to_string().encode_utf16().collect::<Box<[_]>>(),
        ));
        set_ipv4_dns_settings(self.0, &settings)?;
        Ok(settings)
    }

    fn readback(&mut self) -> Result<Self::Settings, Error> {
        read_ipv4_dns_settings(self.0)
    }

    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
        set_ipv4_dns_settings(self.0, settings)
    }
}

pub(super) struct PlatformManagedIpv6Dns(pub(super) GUID);

impl ManagedDnsOperations for PlatformManagedIpv6Dns {
    type Settings = Ipv6DnsSettings;
    type Address = std::net::Ipv6Addr;

    fn snapshot(&mut self) -> Result<Self::Settings, Error> {
        read_ipv6_dns_settings(self.0)
    }

    fn apply(&mut self, address: std::net::Ipv6Addr) -> Result<Self::Settings, Error> {
        let settings = Ipv6DnsSettings(Some(
            address.to_string().encode_utf16().collect::<Box<[_]>>(),
        ));
        set_ipv6_dns_settings(self.0, &settings)?;
        Ok(settings)
    }

    fn readback(&mut self) -> Result<Self::Settings, Error> {
        read_ipv6_dns_settings(self.0)
    }

    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
        set_ipv6_dns_settings(self.0, settings)
    }
}

#[derive(Clone, Copy)]
pub(super) enum DnsFamily {
    Ipv4,
    Ipv6,
}

pub(super) fn read_dns_settings(
    interface: GUID,
    family: DnsFamily,
) -> Result<Option<Box<[u16]>>, Error> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: dns_settings_query_flags(family),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    if unsafe { GetInterfaceDnsSettings(interface, &mut settings) } != ERROR_SUCCESS {
        return Err(Error);
    }
    let result = copy_bounded_wide(settings.NameServer)
        .and_then(|settings| normalize_dns_settings(settings.as_deref(), family));
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    result
}

pub(super) const fn dns_settings_query_flags(family: DnsFamily) -> u64 {
    match family {
        DnsFamily::Ipv4 => 0,
        DnsFamily::Ipv6 => DNS_SETTING_IPV6 as u64,
    }
}

pub(super) fn read_ipv4_dns_settings(interface: GUID) -> Result<Ipv4DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv4).map(Ipv4DnsSettings)
}

pub(super) fn read_ipv6_dns_settings(interface: GUID) -> Result<Ipv6DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv6).map(Ipv6DnsSettings)
}

pub(super) fn normalize_dns_settings(
    settings: Option<&[u16]>,
    family: DnsFamily,
) -> Result<Option<Box<[u16]>>, Error> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let settings = String::from_utf16(settings).map_err(|_| Error)?;
    let mut addresses = Vec::new();
    for candidate in settings.split(|character: char| character == ',' || character.is_whitespace())
    {
        if candidate.is_empty() {
            continue;
        }
        let address = candidate.parse::<std::net::IpAddr>().map_err(|_| Error)?;
        if matches!(
            (family, address),
            (DnsFamily::Ipv4, std::net::IpAddr::V4(_)) | (DnsFamily::Ipv6, std::net::IpAddr::V6(_))
        ) {
            addresses.push(address.to_string());
        }
    }
    if addresses.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            addresses.join(",").encode_utf16().collect::<Box<[_]>>(),
        ))
    }
}

pub(super) fn ipv4_dns_settings_input(
    settings: &Ipv4DnsSettings,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    dns_settings_input(settings.0.as_deref(), false)
}

pub(super) fn ipv6_dns_settings_input(
    settings: &Ipv6DnsSettings,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    dns_settings_input(settings.0.as_deref(), true)
}

pub(super) fn dns_settings_input(
    settings: Option<&[u16]>,
    ipv6: bool,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    let mut name_server = settings.unwrap_or_default().to_vec();
    name_server.push(0);
    let mut name_server = name_server.into_boxed_slice();
    let raw = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER)
            | if ipv6 { u64::from(DNS_SETTING_IPV6) } else { 0 },
        NameServer: name_server.as_mut_ptr(),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    (name_server, raw)
}

pub(super) fn set_ipv4_dns_settings(
    interface: GUID,
    settings: &Ipv4DnsSettings,
) -> Result<(), Error> {
    let (_name_server, raw) = ipv4_dns_settings_input(settings);
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}

pub(super) fn set_ipv6_dns_settings(
    interface: GUID,
    settings: &Ipv6DnsSettings,
) -> Result<(), Error> {
    let (_name_server, raw) = ipv6_dns_settings_input(settings);
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}

pub(super) fn copy_bounded_wide(value: *mut u16) -> Result<Option<Box<[u16]>>, Error> {
    if value.is_null() {
        return Ok(None);
    }
    for length in 0..=4096 {
        if unsafe { *value.add(length) } == 0 {
            if length == 0 {
                return Ok(None);
            }
            let value = unsafe { std::slice::from_raw_parts(value, length) };
            return Ok(Some(value.to_vec().into_boxed_slice()));
        }
    }
    Err(Error)
}

pub(super) struct PlatformManagedRoutes<'a>(pub(super) &'a mut ManagedState);

impl ManagedRouteOperations for PlatformManagedRoutes<'_> {
    type Row = MIB_IPFORWARD_ROW2;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error> {
        require_route_absent(row)
    }

    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error> {
        if unsafe { CreateIpForwardEntry2(&row) } != ERROR_SUCCESS {
            return Err(Error);
        }
        self.0.pending_route = Some(row);
        Ok(())
    }

    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error> {
        Ok(route_matches(row, &read_owned_route(row)?))
    }

    fn commit_pending(&mut self) -> Result<(), Error> {
        self.0
            .routes
            .push(self.0.pending_route.take().ok_or(Error)?);
        Ok(())
    }
}

pub(super) fn read_ip_interface(
    luid: NET_LUID_LH,
    family: u16,
) -> Result<MIB_IPINTERFACE_ROW, Error> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    if unsafe { GetIpInterfaceEntry(&mut row) } == ERROR_SUCCESS {
        Ok(row)
    } else {
        Err(Error)
    }
}

pub(super) fn address_key(intended: &MIB_UNICASTIPADDRESS_ROW) -> MIB_UNICASTIPADDRESS_ROW {
    let mut key = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut key) };
    key.Address = intended.Address;
    key.InterfaceLuid = intended.InterfaceLuid;
    key.InterfaceIndex = intended.InterfaceIndex;
    key
}

pub(super) fn initialize_managed_address(row: &mut MIB_UNICASTIPADDRESS_ROW) {
    unsafe { InitializeUnicastIpAddressEntry(row) };
    // Windows normalizes "unchanged" origins to manual when the row is created. Record the
    // normalized values up front so exact ownership readback and rollback remain comparable.
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
}

pub(super) fn require_address_absent(intended: &MIB_UNICASTIPADDRESS_ROW) -> Result<(), Error> {
    let mut current = address_key(intended);
    match unsafe { GetUnicastIpAddressEntry(&mut current) } {
        ERROR_NOT_FOUND => Ok(()),
        _ => Err(Error),
    }
}

pub(super) fn read_owned_address(
    intended: &MIB_UNICASTIPADDRESS_ROW,
) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
    let mut current = address_key(intended);
    if unsafe { GetUnicastIpAddressEntry(&mut current) } == ERROR_SUCCESS {
        Ok(current)
    } else {
        Err(Error)
    }
}

pub(super) fn managed_address_matches(
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

pub(super) struct PlatformManagedAddressCleanup;

impl ManagedAddressCleanupOperations for PlatformManagedAddressCleanup {
    type Row = MIB_UNICASTIPADDRESS_ROW;

    fn read(&mut self, intended: &Self::Row) -> ManagedAddressRead<Self::Row> {
        let mut current = address_key(intended);
        match unsafe { GetUnicastIpAddressEntry(&mut current) } {
            ERROR_NOT_FOUND => ManagedAddressRead::Absent,
            ERROR_SUCCESS => ManagedAddressRead::Present(current),
            _ => ManagedAddressRead::Failed,
        }
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        managed_address_matches(intended, current)
    }

    fn delete(&mut self, current: &Self::Row) -> Result<(), Error> {
        match unsafe { DeleteUnicastIpAddressEntry(current) } {
            ERROR_SUCCESS | ERROR_NOT_FOUND => Ok(()),
            _ => Err(Error),
        }
    }
}

pub(super) fn capture_route_row(
    luid: NET_LUID_LH,
    interface_index: u32,
    prefix: IpPrefix,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.InterfaceIndex = interface_index;
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
    row.SitePrefixLength = 0;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = MANAGED_CAPTURE_ROUTE_METRIC;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row.Age = 0;
    row.Origin = NlroManual;
    row
}

pub(super) fn route_key(intended: &MIB_IPFORWARD_ROW2) -> MIB_IPFORWARD_ROW2 {
    let mut key = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut key) };
    key.InterfaceLuid = intended.InterfaceLuid;
    key.InterfaceIndex = intended.InterfaceIndex;
    key.DestinationPrefix = intended.DestinationPrefix;
    key.NextHop = intended.NextHop;
    key
}

pub(super) fn require_route_absent(row: &MIB_IPFORWARD_ROW2) -> Result<(), Error> {
    let mut current = route_key(row);
    match unsafe { GetIpForwardEntry2(&mut current) } {
        ERROR_NOT_FOUND => Ok(()),
        _ => Err(Error),
    }
}

pub(super) fn read_owned_route(row: &MIB_IPFORWARD_ROW2) -> Result<MIB_IPFORWARD_ROW2, Error> {
    let mut current = route_key(row);
    if unsafe { GetIpForwardEntry2(&mut current) } == ERROR_SUCCESS {
        Ok(current)
    } else {
        Err(Error)
    }
}

pub(super) fn route_matches(expected: &MIB_IPFORWARD_ROW2, actual: &MIB_IPFORWARD_ROW2) -> bool {
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

pub(super) fn sockaddr_matches(expected: &SOCKADDR_INET, actual: &SOCKADDR_INET) -> bool {
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

pub(super) fn managed_device_health(
    adapter_present: bool,
    session_present: bool,
    ownership_ledger_exact: bool,
    mut identity_matches: impl FnMut() -> bool,
    mut addresses_match: impl FnMut() -> bool,
) -> ManagedTunHealth {
    if !adapter_present || !identity_matches() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Adapter);
    }
    if !session_present {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Session);
    }
    if !ownership_ledger_exact {
        return ManagedTunHealth::Damaged(ManagedStateDamage::OwnershipLedger);
    }
    if !addresses_match() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Address);
    }
    ManagedTunHealth::Healthy
}

pub(super) fn managed_ownership_ledger_exact(
    config: Option<&crate::ManagedNetworkConfig>,
    state: Option<ManagedOwnershipLedgerView<'_>>,
    pending_address: bool,
    address_count: usize,
    expected_address_count: usize,
    catalog_identity: Option<InterfaceIdentity>,
    owned_identity: InterfaceIdentity,
) -> bool {
    if pending_address
        || address_count != expected_address_count
        || owned_identity.luid == 0
        || owned_identity.index == 0
        || catalog_identity != Some(owned_identity)
    {
        return false;
    }
    match (config, state) {
        (None, None) => true,
        (Some(config), Some(state)) => {
            let has_dns =
                config.ipv4_dns_address().is_some() || config.ipv6_dns_address().is_some();
            state.capture_routes == config.capture_routes()
                && !state.pending_route
                && state.route_count == state.capture_routes.len()
                && state.ipv4_dns_address == config.ipv4_dns_address()
                && state.ipv6_dns_address == config.ipv6_dns_address()
                && state.ipv4_dns_lease == config.ipv4_dns_address().is_some()
                && state.ipv6_dns_lease == config.ipv6_dns_address().is_some()
                && state.dns_interface == has_dns
                && state.strict_route_intent == config.strict_route()
                && state.strict_route_session == config.strict_route()
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

pub(super) fn managed_interface_identity_matches(luid: NET_LUID_LH, expected_index: u32) -> bool {
    if unsafe { luid.Value } == 0 || expected_index == 0 {
        return false;
    }
    let mut current_index = 0_u32;
    (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut current_index) }) == ERROR_SUCCESS
        && current_index == expected_index
}

pub(super) fn managed_state_health<O: ManagedRouteCleanupOperations>(
    routes: &[O::Row],
    route_operations: &mut O,
    mut dns_matches: impl FnMut() -> Result<bool, Error>,
    mut strict_route_matches: impl FnMut() -> Result<bool, Error>,
) -> Result<ManagedTunHealth, Error> {
    if !managed_routes_match(routes, route_operations) {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Route));
    }
    if !dns_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Dns));
    }
    if !strict_route_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::StrictRoute));
    }
    Ok(ManagedTunHealth::Healthy)
}

pub(super) struct ManagedNetworkValidation<'a, R> {
    pub(super) policy: &'a UnderlayPolicy,
    pub(super) owned: InterfaceIdentity,
    pub(super) routes: &'a [R],
    pub(super) validated_generation: &'a mut u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManagedNetworkValidationOutcome {
    Unchanged,
    UnderlayChanged,
    ManagedStateDamaged(ManagedStateDamage),
}

pub(super) fn revalidate_managed_network<
    U: UnderlayOperations,
    O: ManagedRouteCleanupOperations,
    F: FnMut() -> Result<bool, Error>,
    S: FnMut() -> Result<bool, Error>,
>(
    validation: ManagedNetworkValidation<'_, O::Row>,
    force: bool,
    mut generation: impl FnMut() -> u64,
    underlay: &mut U,
    route_operations: &mut O,
    mut dns_matches: F,
    mut strict_route_matches: S,
) -> Result<ManagedNetworkValidationOutcome, Error> {
    let ManagedNetworkValidation {
        policy,
        owned,
        routes,
        validated_generation,
    } = validation;
    let mut before = generation();
    if !force && before == *validated_generation {
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    for _ in 0..2 {
        let underlay_matches = match underlay_matches_with(policy, owned, underlay) {
            Ok(matches) => matches,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let health = match managed_state_health(
            routes,
            route_operations,
            &mut dns_matches,
            &mut strict_route_matches,
        ) {
            Ok(health) => health,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let after = generation();
        if after != before {
            before = after;
            continue;
        }
        if let ManagedTunHealth::Damaged(reason) = health {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::ManagedStateDamaged(reason));
        }
        if !underlay_matches {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::UnderlayChanged);
        }
        *validated_generation = after;
        policy.accept_generation(after);
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    policy.invalidate();
    Ok(ManagedNetworkValidationOutcome::UnderlayChanged)
}

pub(super) struct PlatformManagedRouteCleanup;

impl ManagedRouteCleanupOperations for PlatformManagedRouteCleanup {
    type Row = MIB_IPFORWARD_ROW2;

    fn read(&mut self, intended: &Self::Row) -> ManagedRouteRead<Self::Row> {
        let mut current = route_key(intended);
        match unsafe { GetIpForwardEntry2(&mut current) } {
            ERROR_NOT_FOUND => ManagedRouteRead::Absent,
            ERROR_SUCCESS => ManagedRouteRead::Present(current),
            _ => ManagedRouteRead::Failed,
        }
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        route_matches(intended, current)
    }

    fn delete(&mut self, current: &Self::Row) -> Result<(), Error> {
        match unsafe { DeleteIpForwardEntry2(current) } {
            ERROR_SUCCESS | ERROR_NOT_FOUND => Ok(()),
            _ => Err(Error),
        }
    }
}

pub(super) struct PlatformCleanup<'a>(pub(super) &'a mut Adapter);

impl PlatformCleanup<'_> {
    fn restore_mtu(&mut self, slot: usize) -> Option<bool> {
        let state = self.0.mtus[slot].take()?;
        let Ok(mut row) = read_ip_interface(self.0.luid, state.family) else {
            return Some(true);
        };
        if row.NlMtu != state.configured {
            return Some(true);
        }
        if state.family == AF_INET {
            row.SitePrefixLength = 0;
        }
        row.NlMtu = state.previous;
        if unsafe { SetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
            return Some(true);
        }
        Some(match read_ip_interface(self.0.luid, state.family) {
            Ok(current) => current.NlMtu != state.previous,
            Err(_) => true,
        })
    }
}

impl CleanupOperations for PlatformCleanup<'_> {
    fn session_is_idle(&mut self) -> bool {
        self.0.session_journal.cleanup_is_safe()
    }

    fn cancel_notifications(&mut self) -> Option<bool> {
        self.0.managed.as_mut().map(|state| {
            state.policy.invalidate();
            state.notifications.cancel_all()
        })
    }

    fn close_strict_route(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let session = state.strict_route.as_mut()?;
        let failed = session.close().is_err();
        if !failed {
            state.strict_route = None;
        }
        Some(failed)
    }

    fn delete_last_route(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let intended = take_last_owned_route(&mut state.pending_route, &mut state.routes)?;
        Some(delete_managed_route(
            &mut PlatformManagedRouteCleanup,
            &intended,
        ))
    }

    fn restore_last_dns(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        if let Some(lease) = state.ipv6_dns.take() {
            return Some(state.dns_interface.is_none_or(|interface| {
                restore_managed_dns(&mut PlatformManagedIpv6Dns(interface), &lease)
            }));
        }
        if let Some(lease) = state.ipv4_dns.take() {
            return Some(state.dns_interface.is_none_or(|interface| {
                restore_managed_dns(&mut PlatformManagedIpv4Dns(interface), &lease)
            }));
        }
        state.dns_interface.take();
        None
    }

    fn end_session(&mut self) -> Option<bool> {
        let session = self.0.session.take()?;
        unsafe { (self.0.library.exports.end_session)(session.handle) };
        Some(false)
    }

    fn delete_last_address(&mut self) -> Option<bool> {
        let address = self
            .0
            .pending_address
            .take()
            .or_else(|| self.0.addresses.pop())?;
        Some(delete_managed_address(
            &mut PlatformManagedAddressCleanup,
            &address,
        ))
    }

    fn restore_ipv6_mtu(&mut self) -> Option<bool> {
        self.restore_mtu(1)
    }

    fn restore_ipv4_mtu(&mut self) -> Option<bool> {
        self.restore_mtu(0)
    }

    fn close_adapter(&mut self) -> Option<bool> {
        let adapter = self.0.adapter.take()?;
        unsafe { (self.0.library.exports.close_adapter)(adapter) };
        Some(false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DadProgress {
    Waiting,
    Ready,
}

pub(super) fn dad_progress(state: NL_DAD_STATE) -> Result<DadProgress, Error> {
    match state {
        value if value == IpDadStateTentative => Ok(DadProgress::Waiting),
        value if value == IpDadStatePreferred => Ok(DadProgress::Ready),
        value
            if value == IpDadStateDuplicate
                || value == IpDadStateInvalid
                || value == IpDadStateDeprecated =>
        {
            Err(Error)
        }
        _ => Err(Error),
    }
}

pub(super) fn dad_poll(waiting: bool, deadline_elapsed: bool) -> Result<DadProgress, Error> {
    match (waiting, deadline_elapsed) {
        (false, _) => Ok(DadProgress::Ready),
        (true, false) => Ok(DadProgress::Waiting),
        (true, true) => Err(Error),
    }
}

pub(super) fn dad_snapshot(
    session_started: bool,
    states: &[NL_DAD_STATE],
    deadline_elapsed: bool,
) -> Result<DadProgress, Error> {
    if !session_started || states.is_empty() {
        return Err(Error);
    }
    let mut waiting = false;
    for &state in states {
        waiting |= dad_progress(state)? == DadProgress::Waiting;
    }
    dad_poll(waiting, deadline_elapsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdapterCreateFailure {
    NoAdmin,
    NameCollision,
    Other,
}

impl AdapterCreateFailure {
    const fn into_error(self) -> Error {
        Error
    }
}

pub(super) fn classify_adapter_create_failure(error: u32) -> AdapterCreateFailure {
    match error {
        ERROR_ACCESS_DENIED => AdapterCreateFailure::NoAdmin,
        ERROR_ALREADY_EXISTS => AdapterCreateFailure::NameCollision,
        _ => AdapterCreateFailure::Other,
    }
}

pub(super) struct PlatformSetup<'a> {
    pub(super) owner: &'a mut Adapter,
    pub(super) deadline: Instant,
    pub(super) cancelled: &'a AtomicBool,
}

impl SetupOperations for PlatformSetup<'_> {
    fn check_cancelled(&mut self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn check_deadline(&mut self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn create_adapter(&mut self) -> Result<(), Error> {
        let name = wide(Path::new(self.owner.config.name.as_ref()));
        let tunnel = wide(Path::new("Ferrum2"));
        let adapter = unsafe {
            (self.owner.library.exports.create_adapter)(name.as_ptr(), tunnel.as_ptr(), null())
        };
        if adapter.is_null() {
            return Err(classify_adapter_create_failure(unsafe { GetLastError() }).into_error());
        }
        self.owner.adapter = Some(adapter);
        Ok(())
    }

    fn identify_adapter(&mut self) -> Result<(), Error> {
        let adapter = self.owner.adapter.ok_or(Error)?;
        unsafe { (self.owner.library.exports.get_adapter_luid)(adapter, &mut self.owner.luid) };
        if unsafe { ConvertInterfaceLuidToIndex(&self.owner.luid, &mut self.owner.interface_index) }
            != ERROR_SUCCESS
            || self.owner.interface_index == 0
        {
            return Err(Error);
        }
        self.owner
            .network_catalog
            .set_managed_tun(InterfaceIdentity {
                luid: unsafe { self.owner.luid.Value },
                index: self.owner.interface_index,
            })
    }

    fn check_driver(&mut self) -> Result<(), Error> {
        if unsafe { (self.owner.library.exports.get_running_driver_version)() } == 0 {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn ipv4_enabled(&self) -> bool {
        self.owner.config.ipv4.is_some()
    }

    fn ipv6_enabled(&self) -> bool {
        self.owner.config.ipv6.is_some()
    }

    fn start_session(&mut self) -> Result<(), Error> {
        let adapter = self.owner.adapter.ok_or(Error)?;
        let session = unsafe {
            (self.owner.library.exports.start_session)(adapter, self.owner.config.ring_capacity)
        };
        if session.is_null() {
            return Err(Error);
        }
        let read_event = unsafe { (self.owner.library.exports.get_read_wait_event)(session) };
        self.owner.session = Some(SessionState {
            handle: session,
            read_event,
        });
        if read_event.is_null() || read_event == INVALID_HANDLE_VALUE {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn set_ipv4_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET, 0)
    }

    fn set_ipv6_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET6, 1)
    }

    fn add_ipv4_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv4_address_row()?;
        self.owner.create_address(row)
    }

    fn add_ipv6_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv6_address_row()?;
        self.owner.create_address(row)
    }

    fn wait_for_dad(&mut self) -> Result<(), Error> {
        self.owner.wait_for_dad(self.deadline, self.cancelled)
    }
}
