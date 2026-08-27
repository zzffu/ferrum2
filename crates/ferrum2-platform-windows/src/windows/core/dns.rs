use windows_sys::Win32::NetworkManagement::IpHelper::{DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER};

use crate::Error;

pub(in crate::windows) fn copy_bounded_wide(
    value: Option<&[u16]>,
) -> Result<Option<Box<[u16]>>, Error> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(length) = value.iter().take(4_097).position(|unit| *unit == 0) else {
        return Err(Error);
    };
    if length == 0 {
        Ok(None)
    } else {
        Ok(Some(value[..length].to_vec().into_boxed_slice()))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(in crate::windows) struct Ipv4DnsSettings(pub(in crate::windows) Option<Box<[u16]>>);

#[derive(Clone, Eq, PartialEq)]
pub(in crate::windows) struct Ipv6DnsSettings(pub(in crate::windows) Option<Box<[u16]>>);

#[derive(Clone, Copy)]
pub(in crate::windows) enum DnsFamily {
    Ipv4,
    Ipv6,
}

pub(in crate::windows) const fn dns_settings_query_flags(family: DnsFamily) -> u64 {
    match family {
        DnsFamily::Ipv4 => 0,
        DnsFamily::Ipv6 => DNS_SETTING_IPV6 as u64,
    }
}

pub(in crate::windows) fn normalize_dns_settings(
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct DnsSettingsInput {
    pub(in crate::windows) flags: u64,
}

pub(in crate::windows) fn ipv4_dns_settings_input(
    settings: &Ipv4DnsSettings,
) -> (Box<[u16]>, DnsSettingsInput) {
    dns_settings_input(settings.0.as_deref(), false)
}

pub(in crate::windows) fn ipv6_dns_settings_input(
    settings: &Ipv6DnsSettings,
) -> (Box<[u16]>, DnsSettingsInput) {
    dns_settings_input(settings.0.as_deref(), true)
}

fn dns_settings_input(settings: Option<&[u16]>, ipv6: bool) -> (Box<[u16]>, DnsSettingsInput) {
    let mut name_server = settings.unwrap_or_default().to_vec();
    name_server.push(0);
    (
        name_server.into_boxed_slice(),
        DnsSettingsInput {
            flags: u64::from(DNS_SETTING_NAMESERVER)
                | if ipv6 { u64::from(DNS_SETTING_IPV6) } else { 0 },
        },
    )
}
