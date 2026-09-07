use std::net::IpAddr;

use crate::{Error, ErrorKind, Ipv4Prefix, Ipv6Prefix, TcpIngressEndpoint};

pub(crate) const TCP_INGRESS_FILTER_WEIGHT: u8 = 15;
pub(crate) const MAX_TCP_INGRESS_ENDPOINTS: usize = 2;
pub(crate) const MAX_WFP_APP_ID_BYTES: usize = 131_072;
pub(crate) const TCP_PROTOCOL: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TcpIngressLayer {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TcpIngressCondition {
    AppId(Box<[u8]>),
    LocalInterfaceLuid(u64),
    IpProtocol(u8),
    LocalAddress(IpAddr),
    LocalPort(u16),
    RemoteAddress(IpAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TcpIngressRule {
    pub(crate) layer: TcpIngressLayer,
    pub(crate) weight: u8,
    pub(crate) conditions: Box<[TcpIngressCondition]>,
}

pub(crate) fn validate_tcp_ingress_endpoints(
    endpoints: &[TcpIngressEndpoint],
) -> Result<(), Error> {
    if endpoints.is_empty() || endpoints.len() > MAX_TCP_INGRESS_ENDPOINTS {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    let mut saw_v4 = false;
    let mut saw_v6 = false;
    for endpoint in endpoints {
        match (endpoint.local().ip(), endpoint.peer()) {
            (IpAddr::V4(_), IpAddr::V4(_)) if !saw_v4 => saw_v4 = true,
            (IpAddr::V6(_), IpAddr::V6(_)) if !saw_v6 => saw_v6 = true,
            _ => return Err(Error::new(ErrorKind::InvalidInput)),
        }
    }
    Ok(())
}

pub(crate) fn validate_tcp_ingress_addresses(
    endpoints: &[TcpIngressEndpoint],
    ipv4: Option<Ipv4Prefix>,
    ipv6: Option<Ipv6Prefix>,
) -> Result<(), Error> {
    validate_tcp_ingress_endpoints(endpoints)?;
    let mut saw_v4 = false;
    let mut saw_v6 = false;
    for endpoint in endpoints {
        match (endpoint.local().ip(), endpoint.peer()) {
            (IpAddr::V4(local), IpAddr::V4(peer)) => {
                let prefix = ipv4.ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - prefix.length()))
                    .unwrap_or(0);
                let network = u32::from(prefix.address()) & mask;
                let broadcast = network | !mask;
                let peer = u32::from(peer);
                if local != prefix.address()
                    || peer & mask != network
                    || peer == network
                    || peer == broadcast
                    || peer == u32::from(local)
                {
                    return Err(Error::new(ErrorKind::InvalidInput));
                }
                saw_v4 = true;
            }
            (IpAddr::V6(local), IpAddr::V6(peer)) => {
                let prefix = ipv6.ok_or_else(|| Error::new(ErrorKind::InvalidInput))?;
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - prefix.length()))
                    .unwrap_or(0);
                let network = u128::from(prefix.address()) & mask;
                let peer = u128::from(peer);
                if local != prefix.address()
                    || peer & mask != network
                    || peer == network
                    || peer == u128::from(local)
                {
                    return Err(Error::new(ErrorKind::InvalidInput));
                }
                saw_v6 = true;
            }
            _ => return Err(Error::new(ErrorKind::InvalidInput)),
        }
    }
    if saw_v4 != ipv4.is_some() || saw_v6 != ipv6.is_some() {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    Ok(())
}

pub(crate) fn tcp_ingress_rules(
    endpoints: &[TcpIngressEndpoint],
    app_id: &[u8],
    interface_luid: u64,
) -> Result<Vec<TcpIngressRule>, Error> {
    validate_tcp_ingress_endpoints(endpoints)?;
    if app_id.is_empty() || app_id.len() > MAX_WFP_APP_ID_BYTES || interface_luid == 0 {
        return Err(Error::new(ErrorKind::InvalidInput));
    }

    let mut rules = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let layer = match endpoint.local().ip() {
            IpAddr::V4(_) => TcpIngressLayer::V4,
            IpAddr::V6(_) => TcpIngressLayer::V6,
        };
        rules.push(TcpIngressRule {
            layer,
            weight: TCP_INGRESS_FILTER_WEIGHT,
            conditions: Box::new([
                TcpIngressCondition::AppId(app_id.into()),
                TcpIngressCondition::LocalInterfaceLuid(interface_luid),
                TcpIngressCondition::IpProtocol(TCP_PROTOCOL),
                TcpIngressCondition::LocalAddress(endpoint.local().ip()),
                TcpIngressCondition::LocalPort(endpoint.local().port()),
                TcpIngressCondition::RemoteAddress(endpoint.peer()),
            ]),
        });
    }
    Ok(rules)
}
