use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::{Config, OwnerControl, SessionCancellation, SessionItem};

pub(crate) fn build_adapter_config(
    config: &Config,
) -> Result<ferrum2_platform_windows::AdapterConfig, ferrum2_platform_windows::Error> {
    let ipv4 = config
        .ipv4
        .map(|(address, prefix)| ferrum2_platform_windows::Ipv4Prefix::new(address, prefix))
        .transpose()?;
    let ipv6 = config
        .ipv6
        .map(|(address, prefix)| ferrum2_platform_windows::Ipv6Prefix::new(address, prefix))
        .transpose()?;
    let adapter = ferrum2_platform_windows::AdapterConfig::new(
        config.adapter_name.clone(),
        ipv4,
        ipv6,
        config.mtu,
        config.ring_capacity,
        config.ready_timeout,
    )?;
    if config.capture_routes.is_empty()
        && config.physical_endpoints.is_empty()
        && !config.default_binder
        && config.ipv4_dns_address.is_none()
        && config.ipv6_dns_address.is_none()
        && !config.strict_route
    {
        return Ok(adapter);
    }
    let routes = config
        .capture_routes
        .iter()
        .map(|(address, length)| match address {
            IpAddr::V4(address) => ferrum2_platform_windows::Ipv4Prefix::new(*address, *length)
                .map(ferrum2_platform_windows::IpPrefix::V4),
            IpAddr::V6(address) => ferrum2_platform_windows::Ipv6Prefix::new(*address, *length)
                .map(ferrum2_platform_windows::IpPrefix::V6),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let managed = ferrum2_platform_windows::ManagedNetworkConfig::new(
        routes,
        config.physical_endpoints.clone(),
        config.default_binder,
        config.ipv4_dns_address,
        config.ipv6_dns_address,
    )?
    .with_strict_route(config.strict_route);
    adapter.with_managed_network(managed)
}

pub(crate) fn wait_owner_delay(control: &OwnerControl, delay: Duration) -> bool {
    let deadline = std::time::Instant::now()
        .checked_add(delay)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire) {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::park_timeout(deadline.saturating_duration_since(now));
    }
}

pub(crate) fn forward_session_item<T>(
    input: &mut tokio::sync::mpsc::Receiver<T>,
    pending: &mut Option<T>,
    output: &tokio::sync::mpsc::Sender<SessionItem<T>>,
    cancellation: &SessionCancellation,
) -> bool {
    if pending.is_none() {
        match input.try_recv() {
            Ok(value) => *pending = Some(value),
            Err(
                tokio::sync::mpsc::error::TryRecvError::Empty
                | tokio::sync::mpsc::error::TryRecvError::Disconnected,
            ) => return false,
        }
    }
    let value = pending.take().expect("pending session item");
    match output.try_send(SessionItem {
        value,
        cancellation: cancellation.clone(),
    }) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
            *pending = Some(item.value);
            false
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => true,
    }
}
