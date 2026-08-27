use std::path::Path;
use std::ptr::null;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_SUCCESS, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, GetIpForwardEntry2, GetIpInterfaceEntry, GetUnicastIpAddressEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::core::GUID;

use super::super::core::dns::{Ipv4DnsSettings, Ipv6DnsSettings};
use super::super::core::managed::{
    CleanupOperations, ManagedAddressCleanupOperations, ManagedAddressRead, ManagedDnsLease,
    ManagedRouteCleanupOperations, ManagedRouteOperations, ManagedRouteRead, SetupOperations,
    classify_adapter_create_failure, delete_managed_address, delete_managed_route,
    restore_managed_dns, take_last_owned_route,
};
use super::super::core::network::{InterfaceIdentity, UnderlayPolicy};
use super::super::core::raw::{managed_address_matches, route_matches};
use super::loader::wide;
use super::managed_dns::{PlatformManagedIpv4Dns, PlatformManagedIpv6Dns};
use super::notification::NotificationOwners;
use super::strict_route::PlatformStrictRouteSession;
use super::wintun::{Adapter, SessionState};
use crate::{Error, IpPrefix};

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

pub(super) struct PlatformSetup<'a> {
    pub(super) owner: &'a mut Adapter,
    pub(super) deadline: Instant,
    pub(super) cancelled: &'a AtomicBool,
}

pub(super) fn managed_interface_identity_matches(luid: NET_LUID_LH, expected_index: u32) -> bool {
    if unsafe { luid.Value } == 0 || expected_index == 0 {
        return false;
    }
    let mut current_index = 0_u32;
    (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut current_index) }) == ERROR_SUCCESS
        && current_index == expected_index
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
            let _ = classify_adapter_create_failure(unsafe { GetLastError() });
            return Err(Error);
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
