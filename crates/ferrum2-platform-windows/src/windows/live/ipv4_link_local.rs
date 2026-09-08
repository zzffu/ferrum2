use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::SetIpInterfaceEntry;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, LinkLocalAlwaysOff, NL_LINK_LOCAL_ADDRESS_BEHAVIOR,
};

use super::super::core::managed::ipv4_link_local_health;
use super::managed::{read_ip_interface, read_owned_ip_interface};
use super::wintun::Adapter;
use crate::{Error, ManagedTunHealth};

pub(super) struct Ipv4LinkLocalLease {
    previous: NL_LINK_LOCAL_ADDRESS_BEHAVIOR,
}

impl Adapter {
    pub(super) fn disable_ipv4_link_local(&mut self) -> Result<(), Error> {
        if self.config.ipv4.is_some() || self.ipv4_link_local.is_some() {
            return Err(Error);
        }
        let mut row = read_ip_interface(self.luid, AF_INET)?;
        // Own the field before the setter: a failed call or readback can still leave
        // the installed policy behind and must go through bounded rollback.
        self.ipv4_link_local = Some(Ipv4LinkLocalLease {
            previous: row.LinkLocalAddressBehavior,
        });
        row.LinkLocalAddressBehavior = LinkLocalAlwaysOff;
        row.SitePrefixLength = 0;
        // SAFETY: the fresh row identifies only this owned adapter's IPv4 interface.
        // Windows borrows its stack storage without retaining a pointer; every
        // other current field is preserved, with IPv4's required prefix normalized.
        if unsafe { SetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
            return Err(Error);
        }
        if read_ip_interface(self.luid, AF_INET)?.LinkLocalAddressBehavior != LinkLocalAlwaysOff {
            return Err(Error);
        }
        Ok(())
    }

    pub(super) fn restore_ipv4_link_local(&mut self) -> Option<bool> {
        let lease = self.ipv4_link_local.take()?;
        let Ok(mut row) = read_ip_interface(self.luid, AF_INET) else {
            return Some(true);
        };
        if row.LinkLocalAddressBehavior == lease.previous {
            return Some(false);
        }
        if row.LinkLocalAddressBehavior != LinkLocalAlwaysOff {
            // A foreign policy now owns the field; never overwrite it.
            return Some(true);
        }
        row.LinkLocalAddressBehavior = lease.previous;
        row.SitePrefixLength = 0;
        // SAFETY: this fresh owned-LUID/IPv4 row still has our installed field.
        // Restore only that field (plus required IPv4 prefix normalization),
        // preserving all other current fields; Windows retains no pointer.
        if unsafe { SetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
            return Some(true);
        }
        Some(match read_ip_interface(self.luid, AF_INET) {
            Ok(current) => current.LinkLocalAddressBehavior != lease.previous,
            Err(_) => true,
        })
    }

    pub(super) fn ipv4_link_local_health(&self) -> Result<ManagedTunHealth, Error> {
        ipv4_link_local_health(
            self.config.ipv4.is_some(),
            self.ipv4_link_local.is_some(),
            || {
                read_owned_ip_interface(self.luid, AF_INET)
                    .map(|row| row.map(|row| row.LinkLocalAddressBehavior == LinkLocalAlwaysOff))
            },
        )
    }
}
