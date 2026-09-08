use std::mem::MaybeUninit;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::super::core::managed::ipv4_link_local_health;
use super::managed::{read_ip_interface, read_owned_ip_interface};
use super::wintun::Adapter;
use crate::{Error, ManagedTunHealth};

pub(super) struct Ipv4LinkLocalLease {
    previous: bool,
}

impl Adapter {
    pub(super) fn disable_ipv4_link_local(&mut self) -> Result<(), Error> {
        if self.config.ipv4.is_some() || self.ipv4_link_local.is_some() {
            return Err(Error);
        }
        let row = read_ip_interface(self.luid, AF_INET)?;
        // Own the field before the setter: a failed call or readback can still leave
        // the installed policy behind and must go through bounded rollback.
        self.ipv4_link_local = Some(Ipv4LinkLocalLease {
            previous: row.ManagedAddressConfigurationSupported,
        });
        self.set_ipv4_managed_address_configuration(/* enabled: */ false)?;
        if read_ip_interface(self.luid, AF_INET)?.ManagedAddressConfigurationSupported {
            return Err(Error);
        }
        Ok(())
    }

    pub(super) fn restore_ipv4_link_local(&mut self) -> Option<bool> {
        let lease = self.ipv4_link_local.take()?;
        let Ok(row) = read_ip_interface(self.luid, AF_INET) else {
            return Some(true);
        };
        if row.ManagedAddressConfigurationSupported == lease.previous {
            return Some(false);
        }
        if row.ManagedAddressConfigurationSupported {
            // A foreign policy now owns the field; never overwrite it.
            return Some(true);
        }
        if self
            .set_ipv4_managed_address_configuration(lease.previous)
            .is_err()
        {
            return Some(true);
        }
        Some(match read_ip_interface(self.luid, AF_INET) {
            Ok(current) => current.ManagedAddressConfigurationSupported != lease.previous,
            Err(_) => true,
        })
    }

    fn set_ipv4_managed_address_configuration(&self, enabled: bool) -> Result<(), Error> {
        let mut update = MaybeUninit::<MIB_IPINTERFACE_ROW>::uninit();
        let update_pointer = update.as_mut_ptr();
        // Disable DHCP address configuration on the unconfigured IPv4 family.
        // LinkLocalAlwaysOff is rejected by Windows for this interface.
        // SAFETY: the initializer writes 0xff no-change sentinels into BOOLEAN
        // fields, which are not valid Rust bool values. Keep the entire patch in
        // raw storage and never materialize it as a Rust row. Only these owned
        // interface fields are written; Windows borrows but retains no pointer.
        let status = unsafe {
            InitializeIpInterfaceEntry(update_pointer);
            (&raw mut (*update_pointer).Family).write(AF_INET);
            (&raw mut (*update_pointer).InterfaceLuid).write(self.luid);
            (&raw mut (*update_pointer).SitePrefixLength).write(0);
            (&raw mut (*update_pointer).ManagedAddressConfigurationSupported).write(enabled);
            SetIpInterfaceEntry(update_pointer)
        };
        (status == ERROR_SUCCESS).then_some(()).ok_or(Error)
    }

    pub(super) fn ipv4_link_local_health(&self) -> Result<ManagedTunHealth, Error> {
        ipv4_link_local_health(
            self.config.ipv4.is_some(),
            self.ipv4_link_local.is_some(),
            || {
                read_owned_ip_interface(self.luid, AF_INET)
                    .map(|row| row.map(|row| !row.ManagedAddressConfigurationSupported))
            },
        )
    }
}
