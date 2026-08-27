use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, FreeInterfaceDnsSettings,
    GetInterfaceDnsSettings, SetInterfaceDnsSettings,
};
use windows_sys::core::GUID;

use super::super::core::dns::{
    DnsFamily, Ipv4DnsSettings, Ipv6DnsSettings, copy_bounded_wide, dns_settings_query_flags,
    ipv4_dns_settings_input as core_ipv4_dns_settings_input,
    ipv6_dns_settings_input as core_ipv6_dns_settings_input, normalize_dns_settings,
};
use super::super::core::managed::ManagedDnsOperations;
use crate::Error;

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
    // SAFETY: a successful GetInterfaceDnsSettings call owns `NameServer` through `settings`
    // until FreeInterfaceDnsSettings. The API contract supplies a readable NUL-terminated UTF-16
    // string; the helper additionally rejects terminators beyond the reviewed 4096-unit bound.
    let result = unsafe { copy_os_dns_wide(settings.NameServer) }
        .and_then(|settings| normalize_dns_settings(settings.as_deref(), family));
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    result
}

unsafe fn copy_os_dns_wide(value: *mut u16) -> Result<Option<Box<[u16]>>, Error> {
    if value.is_null() {
        return copy_bounded_wide(None);
    }
    for length in 0..=4_096 {
        // SAFETY: the caller retains the successful GetInterfaceDnsSettings allocation and its
        // documented NUL-terminated NameServer string for this entire scan.
        if unsafe { *value.add(length) } == 0 {
            // SAFETY: the scan established that every unit through the terminator is readable.
            let value = unsafe { std::slice::from_raw_parts(value, length + 1) };
            return copy_bounded_wide(Some(value));
        }
    }
    Err(Error)
}

fn read_ipv4_dns_settings(interface: GUID) -> Result<Ipv4DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv4).map(Ipv4DnsSettings)
}

fn read_ipv6_dns_settings(interface: GUID) -> Result<Ipv6DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv6).map(Ipv6DnsSettings)
}

pub(super) fn ipv4_dns_settings_input(
    settings: &Ipv4DnsSettings,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    raw_dns_settings_input(core_ipv4_dns_settings_input(settings))
}

pub(super) fn ipv6_dns_settings_input(
    settings: &Ipv6DnsSettings,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    raw_dns_settings_input(core_ipv6_dns_settings_input(settings))
}

fn raw_dns_settings_input(
    input: (Box<[u16]>, super::super::core::dns::DnsSettingsInput),
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    let (mut name_server, input) = input;
    let raw = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: input.flags,
        NameServer: name_server.as_mut_ptr(),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    (name_server, raw)
}

fn set_ipv4_dns_settings(interface: GUID, settings: &Ipv4DnsSettings) -> Result<(), Error> {
    let (_name_server, raw) = ipv4_dns_settings_input(settings);
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}

fn set_ipv6_dns_settings(interface: GUID, settings: &Ipv6DnsSettings) -> Result<(), Error> {
    let (_name_server, raw) = ipv6_dns_settings_input(settings);
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}
