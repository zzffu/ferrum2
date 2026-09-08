use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
};
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
        let row = read_ip_interface(self.luid, AF_INET)?;
        // Own the field before the setter: a failed call or readback can still leave
        // the installed policy behind and must go through bounded rollback.
        self.ipv4_link_local = Some(Ipv4LinkLocalLease {
            previous: row.LinkLocalAddressBehavior,
        });
        self.set_ipv4_link_local(LinkLocalAlwaysOff)?;
        if read_ip_interface(self.luid, AF_INET)?.LinkLocalAddressBehavior != LinkLocalAlwaysOff {
            return Err(Error);
        }
        Ok(())
    }

    pub(super) fn restore_ipv4_link_local(&mut self) -> Option<bool> {
        let lease = self.ipv4_link_local.take()?;
        let Ok(row) = read_ip_interface(self.luid, AF_INET) else {
            return Some(true);
        };
        if row.LinkLocalAddressBehavior == lease.previous {
            return Some(false);
        }
        if row.LinkLocalAddressBehavior != LinkLocalAlwaysOff {
            // A foreign policy now owns the field; never overwrite it.
            return Some(true);
        }
        if self.set_ipv4_link_local(lease.previous).is_err() {
            return Some(true);
        }
        Some(match read_ip_interface(self.luid, AF_INET) {
            Ok(current) => current.LinkLocalAddressBehavior != lease.previous,
            Err(_) => true,
        })
    }

    fn set_ipv4_link_local(&self, behavior: NL_LINK_LOCAL_ADDRESS_BEHAVIOR) -> Result<(), Error> {
        let mut update = MIB_IPINTERFACE_ROW::default();
        // InitializeIpInterfaceEntry supplies the native no-change sentinels. Do
        // not round-trip unrelated readback fields: Windows can reject their
        // current values as setter input, and a full row could overwrite changes
        // made after our read. This patch changes only the owned IPv4 policy.
        // SAFETY: Windows initializes and borrows stack storage without retaining
        // its pointer. The nonzero owned LUID and AF_INET select this adapter.
        unsafe { InitializeIpInterfaceEntry(&mut update) };
        update.Family = AF_INET;
        update.InterfaceLuid = self.luid;
        update.SitePrefixLength = 0;
        update.LinkLocalAddressBehavior = behavior;
        (unsafe { SetIpInterfaceEntry(&mut update) } == ERROR_SUCCESS)
            .then_some(())
            .ok_or(Error)
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
