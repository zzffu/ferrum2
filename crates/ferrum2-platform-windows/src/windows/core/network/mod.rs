use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{Error, ManagedNetworkConfig};

pub(in crate::windows) mod contract;

pub(in crate::windows) use contract::{
    CatalogFamilyRow, CatalogInterfaceRow, DefaultRouteCandidate, InterfaceCandidate,
    ResolvedSocketBindingOperations, bind_resolved_socket_with,
    build_network_interface_observations, catalog_default_route, eligible_interface_identity,
    fallback_interface_identity, interface_socket_option,
};
#[cfg(test)]
pub(in crate::windows) use contract::{
    ipv4_interface_index_option_value, ipv6_interface_index_option_value,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::windows) struct RouteFingerprint {
    pub(in crate::windows) interface_luid: u64,
    pub(in crate::windows) interface_index: u32,
    pub(in crate::windows) destination: std::net::IpAddr,
    pub(in crate::windows) prefix_length: u8,
    pub(in crate::windows) next_hop: std::net::IpAddr,
    pub(in crate::windows) metric: u32,
    pub(in crate::windows) source: Option<std::net::IpAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) struct InterfaceIdentity {
    pub(in crate::windows) luid: u64,
    pub(in crate::windows) index: u32,
}

#[derive(Clone, Default)]
pub struct WindowsNetworkInterfaceCatalog {
    managed_tun: Arc<std::sync::Mutex<Option<InterfaceIdentity>>>,
}

impl WindowsNetworkInterfaceCatalog {
    pub fn system() -> Self {
        Self::default()
    }

    pub fn excluding_managed_tun(stable_id: u64, index: u32) -> Result<Self, Error> {
        if stable_id == 0 || index == 0 {
            return Err(Error::invalid_input());
        }
        let catalog = Self::system();
        catalog.set_managed_tun(InterfaceIdentity {
            luid: stable_id,
            index,
        })?;
        Ok(catalog)
    }

    pub(in crate::windows) fn managed_tun(&self) -> Result<Option<InterfaceIdentity>, Error> {
        self.managed_tun
            .lock()
            .map(|value| *value)
            .map_err(|_| Error)
    }

    pub(in crate::windows) fn set_managed_tun(
        &self,
        identity: InterfaceIdentity,
    ) -> Result<(), Error> {
        if identity.luid == 0 || identity.index == 0 {
            return Err(Error);
        }
        *self.managed_tun.lock().map_err(|_| Error)? = Some(identity);
        Ok(())
    }

    pub(in crate::windows) fn clear_managed_tun(
        &self,
        identity: InterfaceIdentity,
    ) -> Result<(), Error> {
        let mut managed_tun = self.managed_tun.lock().map_err(|_| Error)?;
        match *managed_tun {
            Some(current) if current == identity => {
                *managed_tun = None;
                Ok(())
            }
            None => Ok(()),
            Some(_) => Err(Error),
        }
    }
}

impl fmt::Debug for WindowsNetworkInterfaceCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNetworkInterfaceCatalog")
            .field(
                "managed_tun",
                &self.managed_tun().map(|v| v.is_some()).unwrap_or(true),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct UnderlayPolicy {
    pub(in crate::windows) fixed: Arc<[(std::net::SocketAddr, RouteFingerprint)]>,
    pub(in crate::windows) target_binder: bool,
    pub(in crate::windows) valid: Arc<AtomicBool>,
    pub(in crate::windows) generation: Arc<AtomicU64>,
    pub(in crate::windows) accepted_generation: Arc<AtomicU64>,
    pub(in crate::windows) owned_luid: Arc<AtomicU64>,
    pub(in crate::windows) owned_index: Arc<AtomicU32>,
}

impl UnderlayPolicy {
    pub fn generation_is_current(&self) -> bool {
        let generation = self.generation.load(Ordering::Acquire);
        self.valid.load(Ordering::Acquire)
            && self.accepted_generation.load(Ordering::Acquire) == generation
    }

    pub(in crate::windows) fn begin_binding(&self) -> Result<u64, Error> {
        let generation = self.generation.load(Ordering::Acquire);
        self.require_generation(generation)?;
        Ok(generation)
    }

    pub(in crate::windows) fn require_generation(&self, generation: u64) -> Result<(), Error> {
        (self.valid.load(Ordering::Acquire)
            && self.accepted_generation.load(Ordering::Acquire) == generation
            && self.generation.load(Ordering::Acquire) == generation)
            .then_some(())
            .ok_or(Error)
    }

    pub(in crate::windows) fn accept_generation(&self, generation: u64) {
        self.accepted_generation
            .store(generation, Ordering::Release);
    }

    pub(in crate::windows) fn set_owned_identity(
        &self,
        owned: InterfaceIdentity,
    ) -> Result<(), Error> {
        if owned.luid == 0 || owned.index == 0 {
            return Err(Error);
        }
        match self
            .owned_index
            .compare_exchange(0, owned.index, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(current) if current == owned.index => {}
            Err(_) => return Err(Error),
        }
        match self
            .owned_luid
            .compare_exchange(0, owned.luid, Ordering::Release, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(current) if current == owned.luid => Ok(()),
            Err(_) => Err(Error),
        }
    }

    pub(in crate::windows) fn owned_identity(&self) -> Result<InterfaceIdentity, Error> {
        let luid = self.owned_luid.load(Ordering::Acquire);
        let index = self.owned_index.load(Ordering::Acquire);
        if luid == 0 || index == 0 {
            Err(Error)
        } else {
            Ok(InterfaceIdentity { luid, index })
        }
    }

    pub(in crate::windows) fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }
}

pub(in crate::windows) trait SocketBindingOperations {
    fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error>;
}

pub(in crate::windows) fn bind_fixed_with(
    policy: &UnderlayPolicy,
    endpoint: std::net::SocketAddr,
    binder: &mut impl SocketBindingOperations,
) -> Result<(), Error> {
    let generation = policy.begin_binding()?;
    let route = policy
        .fixed
        .iter()
        .find(|(candidate, _)| *candidate == endpoint)
        .map(|(_, route)| *route)
        .ok_or(Error)?;
    if !same_ip_family(route.destination, endpoint.ip()) {
        return Err(Error);
    }
    policy.require_generation(generation)?;
    binder.bind(endpoint.ip(), route.interface_index)?;
    policy.require_generation(generation)
}

pub(in crate::windows) trait UnderlayOperations {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error>;
    fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error>;
    fn interface_metric(
        &mut self,
        _family: std::net::IpAddr,
        _interface_index: u32,
    ) -> Result<u32, Error> {
        Ok(0)
    }
    fn constrained_route(
        &mut self,
        destination: std::net::SocketAddr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error>;
}

pub(in crate::windows) fn bind_target_with(
    policy: &UnderlayPolicy,
    target: std::net::SocketAddr,
    underlay: &mut impl UnderlayOperations,
    binder: &mut impl SocketBindingOperations,
) -> Result<(), Error> {
    if !policy.target_binder {
        return Err(Error);
    }
    let generation = policy.begin_binding()?;
    let owned = policy.owned_identity()?;
    let interfaces = underlay.eligible_interfaces(Some(owned))?;
    let mut selected = None::<(RouteFingerprint, u64)>;
    for identity in interfaces {
        let Ok(route) = underlay.constrained_route(target, identity.index, true) else {
            continue;
        };
        if route.interface_luid != identity.luid
            || route.interface_index != identity.index
            || !same_ip_family(target.ip(), route.destination)
            || route
                .source
                .is_none_or(|source| !same_ip_family(target.ip(), source))
        {
            continue;
        }
        let effective_metric = u64::from(route.metric)
            + u64::from(underlay.interface_metric(target.ip(), identity.index)?);
        let preferred = selected.as_ref().is_none_or(|(current, current_metric)| {
            route.prefix_length > current.prefix_length
                || (route.prefix_length == current.prefix_length
                    && (effective_metric < *current_metric
                        || (effective_metric == *current_metric
                            && route.interface_index < current.interface_index)))
        });
        if preferred {
            selected = Some((route, effective_metric));
        }
    }
    let (route, _) = selected.ok_or(Error)?;
    policy.require_generation(generation)?;
    binder.bind(target.ip(), route.interface_index)?;
    policy.require_generation(generation)
}

pub(in crate::windows) const fn same_ip_family(
    left: std::net::IpAddr,
    right: std::net::IpAddr,
) -> bool {
    matches!(
        (left, right),
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
            | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
    )
}

#[cfg(test)]
pub(in crate::windows) fn snapshot_underlay_with(
    config: &ManagedNetworkConfig,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    snapshot_underlay_at(config, Arc::new(AtomicU64::new(0)), 0, operations)
}

pub(in crate::windows) fn snapshot_underlay_at(
    config: &ManagedNetworkConfig,
    generation: Arc<AtomicU64>,
    expected_generation: u64,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    if generation.load(Ordering::Acquire) != expected_generation {
        return Err(Error);
    }
    let interfaces = operations.eligible_interfaces(None)?;
    if config.needs_target_binder() && interfaces.is_empty() {
        return Err(Error);
    }
    let mut fixed = Vec::with_capacity(config.physical_endpoints().len());
    for endpoint in config.physical_endpoints() {
        let index = operations.best_interface(*endpoint)?;
        let identity = interfaces
            .iter()
            .find(|candidate| candidate.index == index)
            .ok_or(Error)?;
        let route = operations.constrained_route(*endpoint, index, true)?;
        if route.interface_luid != identity.luid
            || route.interface_index != identity.index
            || !same_ip_family(endpoint.ip(), route.destination)
        {
            return Err(Error);
        }
        fixed.push((*endpoint, route));
    }
    if generation.load(Ordering::Acquire) != expected_generation {
        return Err(Error);
    }
    Ok(UnderlayPolicy {
        fixed: fixed.into(),
        target_binder: config.needs_target_binder(),
        valid: Arc::new(AtomicBool::new(true)),
        generation,
        accepted_generation: Arc::new(AtomicU64::new(expected_generation)),
        owned_luid: Arc::new(AtomicU64::new(0)),
        owned_index: Arc::new(AtomicU32::new(0)),
    })
}

pub(in crate::windows) fn refresh_underlay_with(
    config: &ManagedNetworkConfig,
    current: &UnderlayPolicy,
    owned: InterfaceIdentity,
    validated_generation: &mut u64,
    generation: Arc<AtomicU64>,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    for attempt in 0..2 {
        let before = generation.load(Ordering::Acquire);
        let next = match snapshot_underlay_at(config, Arc::clone(&generation), before, operations) {
            Ok(next) => next,
            Err(_) if attempt == 0 && generation.load(Ordering::Acquire) != before => continue,
            Err(error) => return Err(error),
        };
        next.set_owned_identity(owned)?;
        if !underlay_matches_with(&next, owned, operations)? {
            next.invalidate();
            return Err(Error);
        }
        let after = generation.load(Ordering::Acquire);
        if after != before {
            next.invalidate();
            if attempt == 0 {
                continue;
            }
            return Err(Error);
        }
        *validated_generation = after;
        current.invalidate();
        return Ok(next);
    }
    unreachable!("underlay refresh has exactly two attempts")
}

pub(in crate::windows) fn classify_underlay_refresh<T>(
    result: Result<T, Error>,
) -> Result<T, Error> {
    result.map_err(|_| Error::recoverable_session())
}

pub(in crate::windows) fn underlay_matches_with(
    policy: &UnderlayPolicy,
    owned: InterfaceIdentity,
    operations: &mut impl UnderlayOperations,
) -> Result<bool, Error> {
    let interfaces = operations.eligible_interfaces(Some(owned))?;
    for (endpoint, expected) in policy.fixed.iter() {
        if !interfaces.iter().any(|candidate| {
            candidate.index == expected.interface_index && candidate.luid == expected.interface_luid
        }) || operations.constrained_route(*endpoint, expected.interface_index, true)?
            != *expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
pub(in crate::windows) fn underlay_snapshot_matches(
    policy: &UnderlayPolicy,
    owned: InterfaceIdentity,
    expected_generation: u64,
    mut generation: impl FnMut() -> u64,
    operations: &mut impl UnderlayOperations,
) -> Result<bool, Error> {
    let before = generation();
    if before != expected_generation || !underlay_matches_with(policy, owned, operations)? {
        return Ok(false);
    }
    Ok(generation() == before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_match_never_crosses_ip_versions() {
        assert!(same_ip_family(
            "192.0.2.1".parse().unwrap(),
            "198.51.100.1".parse().unwrap()
        ));
        assert!(!same_ip_family(
            "192.0.2.1".parse().unwrap(),
            "2001:db8::1".parse().unwrap()
        ));
    }

    #[test]
    fn managed_catalog_rejects_zero_identity_components() {
        assert!(WindowsNetworkInterfaceCatalog::excluding_managed_tun(0, 1).is_err());
        assert!(WindowsNetworkInterfaceCatalog::excluding_managed_tun(1, 0).is_err());
    }
}
