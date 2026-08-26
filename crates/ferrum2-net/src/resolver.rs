use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use crate::{InterfaceBinding, NetworkFamily, NetworkInterfaceCatalog, NetworkSnapshot};

/// Shared source-address constraints for one outbound.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
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
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
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
    WrongFamily,
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
    cache_hit: bool,
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

    /// Returns whether this invocation reused a successful resolver-cache entry.
    pub const fn cache_hit(&self) -> bool {
        self.cache_hit
    }
}

/// Closed reason for an interface-resolution failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InterfaceResolutionErrorKind {
    ExplicitInterfaceMissing,
    ExplicitInterfaceAmbiguous,
    ExplicitInterfaceUnavailable,
    ExplicitInterfaceWrongFamily,
    SystemBestRouteUnavailable,
    SelectedInterfaceWrongFamily,
    SourceAddressUnavailable,
}

/// Closed interface-resolution failure safe for runtime boundaries.
///
/// The attempted source is retained separately from the reason so telemetry can use the same
/// low-cardinality source labels for successful and failed resolutions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceResolutionError {
    kind: InterfaceResolutionErrorKind,
    attempted_source: InterfaceSelectionSource,
}

impl InterfaceResolutionError {
    const fn new(
        kind: InterfaceResolutionErrorKind,
        attempted_source: InterfaceSelectionSource,
    ) -> Self {
        Self {
            kind,
            attempted_source,
        }
    }

    /// Returns the closed reason for the failure.
    pub const fn kind(self) -> InterfaceResolutionErrorKind {
        self.kind
    }

    /// Returns the low-cardinality selection source attempted by the failed resolution.
    pub const fn attempted_source(self) -> InterfaceSelectionSource {
        self.attempted_source
    }
}

/// Maximum successful interface decisions retained for one published network generation.
pub const NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY: usize = 256;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NetworkInterfaceResolutionCacheKey {
    snapshot_generation: u64,
    destination: SocketAddr,
    outbound: DialOptions,
    route: RouteNetworkOptions,
}

#[derive(Default)]
struct NetworkInterfaceResolutionCache {
    generation: Option<u64>,
    entries: BTreeMap<NetworkInterfaceResolutionCacheKey, ResolvedInterface>,
    insertion_order: VecDeque<NetworkInterfaceResolutionCacheKey>,
}

impl NetworkInterfaceResolutionCache {
    fn lookup(&mut self, key: &NetworkInterfaceResolutionCacheKey) -> Option<ResolvedInterface> {
        match self.generation {
            None => self.generation = Some(key.snapshot_generation),
            Some(generation) if key.snapshot_generation > generation => {
                self.entries.clear();
                self.insertion_order.clear();
                self.generation = Some(key.snapshot_generation);
            }
            Some(generation) if key.snapshot_generation < generation => return None,
            Some(_) => {}
        }
        self.entries.get(key).cloned().map(|mut resolved| {
            resolved.cache_hit = true;
            resolved
        })
    }

    fn insert(&mut self, key: NetworkInterfaceResolutionCacheKey, resolved: ResolvedInterface) {
        if self.generation != Some(key.snapshot_generation) || self.entries.contains_key(&key) {
            return;
        }
        while self.entries.len() >= NETWORK_INTERFACE_RESOLUTION_CACHE_CAPACITY {
            let Some(evicted) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&evicted);
        }
        self.insertion_order.push_back(key.clone());
        self.entries.insert(key, resolved);
    }
}

/// The one shared implementation of outbound interface priority.
pub struct NetworkInterfaceResolver<C> {
    catalog: C,
    successful: Mutex<NetworkInterfaceResolutionCache>,
}

impl<C> NetworkInterfaceResolver<C> {
    /// Creates a resolver over one platform catalog.
    pub fn new(catalog: C) -> Self {
        Self {
            catalog,
            successful: Mutex::new(NetworkInterfaceResolutionCache::default()),
        }
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
        let key = NetworkInterfaceResolutionCacheKey {
            snapshot_generation: snapshot.generation(),
            destination,
            outbound: outbound.clone(),
            route: route.clone(),
        };
        if let Some(resolved) = self
            .successful
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lookup(&key)
        {
            return Ok(resolved);
        }
        let resolved = self.resolve_uncached(outbound, route, destination, snapshot)?;
        self.successful
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, resolved.clone());
        Ok(resolved)
    }

    fn resolve_uncached(
        &self,
        outbound: &DialOptions,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        snapshot: &NetworkSnapshot,
    ) -> Result<ResolvedInterface, InterfaceResolutionError> {
        let family = NetworkFamily::of(destination.ip());
        let (binding, selection_source) = if let Some(name) = outbound.bind_interface() {
            let binding = match snapshot.resolve_named(name, family) {
                NamedInterfaceResolution::Available(binding) => binding,
                NamedInterfaceResolution::Missing => {
                    return Err(InterfaceResolutionError::new(
                        InterfaceResolutionErrorKind::ExplicitInterfaceMissing,
                        InterfaceSelectionSource::OutboundExplicit,
                    ));
                }
                NamedInterfaceResolution::Ambiguous => {
                    return Err(InterfaceResolutionError::new(
                        InterfaceResolutionErrorKind::ExplicitInterfaceAmbiguous,
                        InterfaceSelectionSource::OutboundExplicit,
                    ));
                }
                NamedInterfaceResolution::Unavailable => {
                    return Err(InterfaceResolutionError::new(
                        InterfaceResolutionErrorKind::ExplicitInterfaceUnavailable,
                        InterfaceSelectionSource::OutboundExplicit,
                    ));
                }
                NamedInterfaceResolution::WrongFamily => {
                    return Err(InterfaceResolutionError::new(
                        InterfaceResolutionErrorKind::ExplicitInterfaceWrongFamily,
                        InterfaceSelectionSource::OutboundExplicit,
                    ));
                }
            };
            (binding, InterfaceSelectionSource::OutboundExplicit)
        } else if route.auto_detect_interface() {
            if let Some(binding) = snapshot.auto_interface(destination.ip()) {
                (binding.clone(), InterfaceSelectionSource::AutoDetected)
            } else {
                self.resolve_after_auto(route, destination, family, snapshot)?
            }
        } else {
            self.resolve_after_auto(route, destination, family, snapshot)?
        };

        if !binding.supports(family) {
            return Err(InterfaceResolutionError::new(
                InterfaceResolutionErrorKind::SelectedInterfaceWrongFamily,
                selection_source,
            ));
        }
        let source_address = outbound.source_address(family);
        if source_address.is_some_and(|address| !binding.owns(address)) {
            return Err(InterfaceResolutionError::new(
                InterfaceResolutionErrorKind::SourceAddressUnavailable,
                selection_source,
            ));
        }
        Ok(ResolvedInterface {
            snapshot_generation: snapshot.generation(),
            binding,
            source_address,
            selection_source,
            cache_hit: false,
        })
    }

    fn resolve_after_auto(
        &self,
        route: &RouteNetworkOptions,
        destination: SocketAddr,
        family: NetworkFamily,
        snapshot: &NetworkSnapshot,
    ) -> Result<(InterfaceBinding, InterfaceSelectionSource), InterfaceResolutionError> {
        if let Some(name) = route.default_interface()
            && let NamedInterfaceResolution::Available(binding) =
                snapshot.resolve_named(name, family)
        {
            return Ok((binding, InterfaceSelectionSource::RouteDefault));
        }
        let route = self.catalog.system_best_route(destination).map_err(|_| {
            InterfaceResolutionError::new(
                InterfaceResolutionErrorKind::SystemBestRouteUnavailable,
                InterfaceSelectionSource::SystemBestRoute,
            )
        })?;
        let binding = snapshot
            .resolve_system_route(route, family)
            .ok_or_else(|| {
                InterfaceResolutionError::new(
                    InterfaceResolutionErrorKind::SystemBestRouteUnavailable,
                    InterfaceSelectionSource::SystemBestRoute,
                )
            })?;
        Ok((binding, InterfaceSelectionSource::SystemBestRoute))
    }
}
