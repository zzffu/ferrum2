use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;

/// Address family used by one outbound dial attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkFamily {
    Ipv4,
    Ipv6,
}

impl NetworkFamily {
    /// Returns the address family for one IP address.
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Stable identity and usable source addresses for one underlay interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceBinding {
    name: Arc<str>,
    stable_id: u64,
    index: u32,
    addresses: Arc<[IpAddr]>,
}

impl InterfaceBinding {
    /// Builds one validated interface binding.
    pub fn new(
        name: impl Into<Arc<str>>,
        stable_id: u64,
        index: u32,
        addresses: impl Into<Arc<[IpAddr]>>,
    ) -> Result<Self, InterfaceBindingError> {
        let name = name.into();
        let mut addresses = addresses.into().to_vec();
        addresses.sort_unstable();
        addresses.dedup();
        if name.is_empty() || stable_id == 0 || index == 0 {
            return Err(InterfaceBindingError);
        }
        Ok(Self {
            name,
            stable_id,
            index,
            addresses: addresses.into(),
        })
    }

    /// Returns the platform interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a platform-stable identity, such as a Windows interface LUID.
    pub const fn stable_id(&self) -> u64 {
        self.stable_id
    }

    /// Returns the current platform interface index.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the source addresses captured in the same network generation.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns whether this binding has at least one address in the requested family.
    pub fn supports(&self, family: NetworkFamily) -> bool {
        self.addresses
            .iter()
            .any(|address| NetworkFamily::of(*address) == family)
    }

    fn owns(&self, address: IpAddr) -> bool {
        self.addresses.binary_search(&address).is_ok()
    }
}

/// A supplied interface identity was incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceBindingError;

/// Immutable, family-aware view of the current underlay network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSnapshot {
    generation: u64,
    ipv4_default: Option<InterfaceBinding>,
    ipv6_default: Option<InterfaceBinding>,
}

impl NetworkSnapshot {
    /// Builds a snapshot whose automatic defaults are valid for their own families.
    pub fn new(
        generation: u64,
        ipv4_default: Option<InterfaceBinding>,
        ipv6_default: Option<InterfaceBinding>,
    ) -> Result<Self, NetworkSnapshotError> {
        if ipv4_default
            .as_ref()
            .is_some_and(|binding| !binding.supports(NetworkFamily::Ipv4))
            || ipv6_default
                .as_ref()
                .is_some_and(|binding| !binding.supports(NetworkFamily::Ipv6))
        {
            return Err(NetworkSnapshotError);
        }
        Ok(Self {
            generation,
            ipv4_default,
            ipv6_default,
        })
    }

    /// Returns the monotonically increasing network generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the auto-detected default for the destination family.
    pub fn auto_interface(&self, destination: IpAddr) -> Option<&InterfaceBinding> {
        match destination {
            IpAddr::V4(_) => self.ipv4_default.as_ref(),
            IpAddr::V6(_) => self.ipv6_default.as_ref(),
        }
    }
}

/// A family default did not own an address in that family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkSnapshotError;

/// Atomically publishes immutable network generations to all runtime users.
#[derive(Clone)]
pub struct NetworkSnapshotPublisher {
    current: Arc<RwLock<Arc<NetworkSnapshot>>>,
}

impl NetworkSnapshotPublisher {
    /// Creates a publisher with one already-validated initial generation.
    pub fn new(initial: Arc<NetworkSnapshot>) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
        }
    }

    /// Returns one immutable snapshot of the current generation.
    pub fn snapshot(&self) -> Arc<NetworkSnapshot> {
        Arc::clone(&read_unpoisoned(&self.current))
    }

    /// Returns the currently published generation.
    pub fn generation(&self) -> u64 {
        read_unpoisoned(&self.current).generation()
    }

    /// Returns whether an operation prepared against `generation` may still publish resources.
    pub fn is_current(&self, generation: u64) -> bool {
        self.generation() == generation
    }

    /// Publishes a newer snapshot only if the expected generation is still current.
    pub fn publish_if_current(
        &self,
        expected_generation: u64,
        next: Arc<NetworkSnapshot>,
    ) -> Result<Arc<NetworkSnapshot>, NetworkSnapshotPublishError> {
        let mut current = write_unpoisoned(&self.current);
        if current.generation() != expected_generation {
            return Err(NetworkSnapshotPublishError::StaleExpectedGeneration);
        }
        if next.generation() <= expected_generation {
            return Err(NetworkSnapshotPublishError::NonMonotonicGeneration);
        }
        Ok(std::mem::replace(&mut *current, next))
    }
}

fn read_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Closed failure from atomically publishing a network snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSnapshotPublishError {
    StaleExpectedGeneration,
    NonMonotonicGeneration,
}

/// Closed reset-hook failure safe for runtime boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkResetError;

/// Boxed future returned by an object-safe network reset hook.
pub type NetworkResetFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), NetworkResetError>> + Send + 'a>>;

/// Generation-aware hook implemented by network-dependent runtime components.
pub trait ResetNetwork: Send + Sync {
    /// Replaces all generation-bound state without tearing down managed device state.
    fn reset_network(&self, snapshot: Arc<NetworkSnapshot>) -> NetworkResetFuture<'_>;
}

/// Shared source-address constraints for one outbound.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DialOptions {
    bind_interface: Option<Arc<str>>,
    inet4_bind_address: Option<Ipv4Addr>,
    inet6_bind_address: Option<Ipv6Addr>,
}

impl DialOptions {
    /// Builds immutable outbound dial options.
    pub fn new(
        bind_interface: Option<impl Into<Arc<str>>>,
        inet4_bind_address: Option<Ipv4Addr>,
        inet6_bind_address: Option<Ipv6Addr>,
    ) -> Self {
        Self {
            bind_interface: bind_interface.map(Into::into),
            inet4_bind_address,
            inet6_bind_address,
        }
    }

    /// Returns the explicit outbound interface, if configured.
    pub fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    fn source_address(&self, family: NetworkFamily) -> Option<IpAddr> {
        match family {
            NetworkFamily::Ipv4 => self.inet4_bind_address.map(IpAddr::V4),
            NetworkFamily::Ipv6 => self.inet6_bind_address.map(IpAddr::V6),
        }
    }
}

/// Route-level inputs to the shared interface resolver.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteNetworkOptions {
    auto_detect_interface: bool,
    default_interface: Option<Arc<str>>,
}

impl RouteNetworkOptions {
    /// Builds immutable route-level network options.
    pub fn new(
        auto_detect_interface: bool,
        default_interface: Option<impl Into<Arc<str>>>,
    ) -> Self {
        Self {
            auto_detect_interface,
            default_interface: default_interface.map(Into::into),
        }
    }

    /// Returns whether family-aware automatic interface selection is enabled.
    pub const fn auto_detect_interface(&self) -> bool {
        self.auto_detect_interface
    }

    /// Returns the route-level fallback interface, if configured.
    pub fn default_interface(&self) -> Option<&str> {
        self.default_interface.as_deref()
    }
}

/// Closed result of resolving a platform interface name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedInterfaceResolution {
    Available(InterfaceBinding),
    Missing,
    Ambiguous,
    Unavailable,
}

/// Platform adapter used by the shared four-tier resolver.
pub trait NetworkInterfaceCatalog: Send + Sync {
    /// Resolves one exact interface name for the requested family.
    fn resolve_named(&self, name: &str, family: NetworkFamily) -> NamedInterfaceResolution;

    /// Resolves the system best route for the actual dial destination.
    fn system_best_route(&self, destination: SocketAddr) -> Option<InterfaceBinding>;
}

/// Low-cardinality source selected by the shared resolver.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InterfaceSelectionSource {
    OutboundExplicit,
    AutoDetected,
    RouteDefault,
    SystemBestRoute,
}

/// Complete interface and source-address decision for one dial attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInterface {
    snapshot_generation: u64,
    binding: InterfaceBinding,
    source_address: Option<IpAddr>,
    selection_source: InterfaceSelectionSource,
}

impl ResolvedInterface {
    /// Returns the generation against which this decision was made.
    pub const fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    /// Returns the selected underlay interface.
    pub const fn binding(&self) -> &InterfaceBinding {
        &self.binding
    }

    /// Returns the configured family-specific source address, if any.
    pub const fn source_address(&self) -> Option<IpAddr> {
        self.source_address
    }

    /// Returns the closed, low-cardinality selection source.
    pub const fn selection_source(&self) -> InterfaceSelectionSource {
        self.selection_source
    }
}

/// Closed interface-resolution failure safe for runtime boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceResolutionError {
    ExplicitInterfaceMissing,
    ExplicitInterfaceAmbiguous,
    ExplicitInterfaceUnavailable,
    ExplicitInterfaceWrongFamily,
    SystemBestRouteUnavailable,
    SelectedInterfaceWrongFamily,
    SourceAddressUnavailable,
}

/// The one shared implementation of outbound interface priority.
pub struct NetworkInterfaceResolver<C> {
    catalog: C,
}

impl<C> NetworkInterfaceResolver<C> {
    /// Creates a resolver over one platform catalog.
    pub const fn new(catalog: C) -> Self {
        Self { catalog }
    }

    /// Returns the platform catalog, primarily for lifecycle composition.
    pub const fn catalog(&self) -> &C {
        &self.catalog
    }
}

impl<C: NetworkInterfaceCatalog> NetworkInterfaceResolver<C> {
    /// Resolves outbound explicit, auto-detected, route-default, then system-best-route.
    pub fn resolve(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        snapshot: &NetworkSnapshot,
    ) -> Result<ResolvedInterface, InterfaceResolutionError> {
        let family = NetworkFamily::of(destination.ip());
        let (binding, selection_source) = if let Some(name) = outbound.bind_interface() {
            let binding = match self.catalog.resolve_named(name, family) {
                NamedInterfaceResolution::Available(binding) => binding,
                NamedInterfaceResolution::Missing => {
                    return Err(InterfaceResolutionError::ExplicitInterfaceMissing);
                }
                NamedInterfaceResolution::Ambiguous => {
                    return Err(InterfaceResolutionError::ExplicitInterfaceAmbiguous);
                }
                NamedInterfaceResolution::Unavailable => {
                    return Err(InterfaceResolutionError::ExplicitInterfaceUnavailable);
                }
            };
            if !binding.supports(family) {
                return Err(InterfaceResolutionError::ExplicitInterfaceWrongFamily);
            }
            (binding, InterfaceSelectionSource::OutboundExplicit)
        } else if route.auto_detect_interface() {
            if let Some(binding) = snapshot.auto_interface(destination.ip()) {
                (binding.clone(), InterfaceSelectionSource::AutoDetected)
            } else {
                self.resolve_after_auto(route, destination, family)?
            }
        } else {
            self.resolve_after_auto(route, destination, family)?
        };

        if !binding.supports(family) {
            return Err(InterfaceResolutionError::SelectedInterfaceWrongFamily);
        }
        let source_address = outbound.source_address(family);
        if source_address.is_some_and(|address| !binding.owns(address)) {
            return Err(InterfaceResolutionError::SourceAddressUnavailable);
        }
        Ok(ResolvedInterface {
            snapshot_generation: snapshot.generation(),
            binding,
            source_address,
            selection_source,
        })
    }

    fn resolve_after_auto(
        &self,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        family: NetworkFamily,
    ) -> Result<(InterfaceBinding, InterfaceSelectionSource), InterfaceResolutionError> {
        if let Some(name) = route.default_interface()
            && let NamedInterfaceResolution::Available(binding) =
                self.catalog.resolve_named(name, family)
            && binding.supports(family)
        {
            return Ok((binding, InterfaceSelectionSource::RouteDefault));
        }
        let binding = self
            .catalog
            .system_best_route(destination)
            .ok_or(InterfaceResolutionError::SystemBestRouteUnavailable)?;
        Ok((binding, InterfaceSelectionSource::SystemBestRoute))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct Catalog {
        named: BTreeMap<String, NamedInterfaceResolution>,
        system: Option<InterfaceBinding>,
        system_destinations: Mutex<Vec<SocketAddr>>,
    }

    impl NetworkInterfaceCatalog for Catalog {
        fn resolve_named(&self, name: &str, _family: NetworkFamily) -> NamedInterfaceResolution {
            self.named
                .get(name)
                .cloned()
                .unwrap_or(NamedInterfaceResolution::Missing)
        }

        fn system_best_route(&self, destination: SocketAddr) -> Option<InterfaceBinding> {
            self.system_destinations.lock().unwrap().push(destination);
            self.system.clone()
        }
    }

    fn binding(name: &str, id: u64, index: u32, addresses: &[IpAddr]) -> InterfaceBinding {
        InterfaceBinding::new(name, id, index, Arc::<[IpAddr]>::from(addresses)).unwrap()
    }

    fn v4(name: &str, id: u64, index: u32, octet: u8) -> InterfaceBinding {
        binding(
            name,
            id,
            index,
            &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet))],
        )
    }

    fn v6(name: &str, id: u64, index: u32, suffix: u16) -> InterfaceBinding {
        binding(
            name,
            id,
            index,
            &[IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, suffix,
            ))],
        )
    }

    #[test]
    fn four_tier_priority_is_exact_and_system_fallback_is_target_aware() {
        let explicit = v4("explicit", 1, 11, 11);
        let automatic = v4("automatic", 2, 12, 12);
        let route_default = v4("route-default", 3, 13, 13);
        let system = v4("system", 4, 14, 14);
        let catalog = Catalog {
            named: BTreeMap::from([
                (
                    "explicit".to_owned(),
                    NamedInterfaceResolution::Available(explicit.clone()),
                ),
                (
                    "route-default".to_owned(),
                    NamedInterfaceResolution::Available(route_default.clone()),
                ),
            ]),
            system: Some(system.clone()),
            system_destinations: Mutex::default(),
        };
        let resolver = NetworkInterfaceResolver::new(catalog);
        let snapshot = NetworkSnapshot::new(7, Some(automatic.clone()), None).unwrap();
        let target = SocketAddr::from(([203, 0, 113, 9], 443));

        let selected = resolver
            .resolve(
                &DialOptions::new(Some("explicit"), None, None),
                &RouteNetworkOptions::new(true, Some("route-default")),
                target,
                &snapshot,
            )
            .unwrap();
        assert_eq!(selected.binding(), &explicit);
        assert_eq!(
            selected.selection_source(),
            InterfaceSelectionSource::OutboundExplicit
        );

        let selected = resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::new(true, Some("route-default")),
                target,
                &snapshot,
            )
            .unwrap();
        assert_eq!(selected.binding(), &automatic);
        assert_eq!(
            selected.selection_source(),
            InterfaceSelectionSource::AutoDetected
        );

        let no_auto = NetworkSnapshot::new(8, None, None).unwrap();
        let selected = resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::new(true, Some("route-default")),
                target,
                &no_auto,
            )
            .unwrap();
        assert_eq!(selected.binding(), &route_default);
        assert_eq!(
            selected.selection_source(),
            InterfaceSelectionSource::RouteDefault
        );

        let selected = resolver
            .resolve(
                &DialOptions::default(),
                &RouteNetworkOptions::new(false, Some("missing")),
                target,
                &no_auto,
            )
            .unwrap();
        assert_eq!(selected.binding(), &system);
        assert_eq!(
            selected.selection_source(),
            InterfaceSelectionSource::SystemBestRoute
        );
        assert_eq!(
            resolver
                .catalog()
                .system_destinations
                .lock()
                .unwrap()
                .as_slice(),
            [target]
        );
    }

    #[test]
    fn explicit_lookup_failure_never_falls_back() {
        for (resolution, expected) in [
            (
                NamedInterfaceResolution::Missing,
                InterfaceResolutionError::ExplicitInterfaceMissing,
            ),
            (
                NamedInterfaceResolution::Ambiguous,
                InterfaceResolutionError::ExplicitInterfaceAmbiguous,
            ),
            (
                NamedInterfaceResolution::Unavailable,
                InterfaceResolutionError::ExplicitInterfaceUnavailable,
            ),
        ] {
            let resolver = NetworkInterfaceResolver::new(Catalog {
                named: BTreeMap::from([("explicit".to_owned(), resolution)]),
                system: Some(v4("system", 4, 14, 14)),
                system_destinations: Mutex::default(),
            });
            let error = resolver
                .resolve(
                    &DialOptions::new(Some("explicit"), None, None),
                    &RouteNetworkOptions::new(true, Some("fallback")),
                    SocketAddr::from(([203, 0, 113, 9], 443)),
                    &NetworkSnapshot::new(1, Some(v4("auto", 2, 12, 12)), None).unwrap(),
                )
                .unwrap_err();
            assert_eq!(error, expected);
            assert!(
                resolver
                    .catalog()
                    .system_destinations
                    .lock()
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn family_defaults_and_source_addresses_are_independent() {
        let ipv4 = v4("v4", 4, 14, 14);
        let ipv6 = v6("v6", 6, 16, 16);
        let snapshot = NetworkSnapshot::new(22, Some(ipv4.clone()), Some(ipv6.clone())).unwrap();
        let resolver = NetworkInterfaceResolver::new(Catalog::default());
        let options = DialOptions::new(
            None::<&str>,
            Some(Ipv4Addr::new(192, 0, 2, 14)),
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 16)),
        );

        let selected_v4 = resolver
            .resolve(
                &options,
                &RouteNetworkOptions::new(true, None::<&str>),
                SocketAddr::from(([203, 0, 113, 9], 443)),
                &snapshot,
            )
            .unwrap();
        assert_eq!(selected_v4.binding(), &ipv4);
        assert_eq!(
            selected_v4.source_address(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14)))
        );
        assert_eq!(selected_v4.snapshot_generation(), 22);

        let selected_v6 = resolver
            .resolve(
                &options,
                &RouteNetworkOptions::new(true, None::<&str>),
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 9)),
                    443,
                ),
                &snapshot,
            )
            .unwrap();
        assert_eq!(selected_v6.binding(), &ipv6);
        assert_eq!(
            selected_v6.source_address(),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 16)))
        );
    }

    #[test]
    fn mismatched_source_or_family_is_rejected() {
        assert_eq!(
            NetworkSnapshot::new(1, Some(v6("wrong", 1, 1, 1)), None).unwrap_err(),
            NetworkSnapshotError
        );

        let resolver = NetworkInterfaceResolver::new(Catalog::default());
        let snapshot = NetworkSnapshot::new(1, Some(v4("v4", 1, 1, 1)), None).unwrap();
        assert_eq!(
            resolver
                .resolve(
                    &DialOptions::new(None::<&str>, Some(Ipv4Addr::new(192, 0, 2, 99)), None,),
                    &RouteNetworkOptions::new(true, None::<&str>),
                    SocketAddr::from(([203, 0, 113, 9], 443)),
                    &snapshot,
                )
                .unwrap_err(),
            InterfaceResolutionError::SourceAddressUnavailable
        );
    }

    #[test]
    fn snapshot_publication_is_atomic_and_monotonic() {
        let initial = Arc::new(NetworkSnapshot::new(4, Some(v4("old", 1, 1, 1)), None).unwrap());
        let publisher = NetworkSnapshotPublisher::new(Arc::clone(&initial));
        let next = Arc::new(NetworkSnapshot::new(5, Some(v4("new", 2, 2, 2)), None).unwrap());

        assert!(publisher.is_current(4));
        assert_eq!(
            publisher.publish_if_current(4, Arc::clone(&next)).unwrap(),
            initial
        );
        assert!(publisher.is_current(5));
        assert_eq!(publisher.snapshot(), next);

        assert_eq!(
            publisher
                .publish_if_current(4, Arc::new(NetworkSnapshot::new(6, None, None).unwrap()),)
                .unwrap_err(),
            NetworkSnapshotPublishError::StaleExpectedGeneration
        );
        assert_eq!(
            publisher
                .publish_if_current(5, Arc::new(NetworkSnapshot::new(5, None, None).unwrap()),)
                .unwrap_err(),
            NetworkSnapshotPublishError::NonMonotonicGeneration
        );
        assert_eq!(publisher.snapshot(), next);
    }
}
