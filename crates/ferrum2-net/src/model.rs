use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::resolver::NamedInterfaceResolution;

/// Address family used by one outbound dial attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    pub(crate) fn owns(&self, address: IpAddr) -> bool {
        self.addresses.binary_search(&address).is_ok()
    }
}

/// A supplied interface identity was incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceBindingError;

/// Closed interface kind used when selecting an automatic underlay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkInterfaceKind {
    /// An ordinary interface that may carry underlay traffic.
    Underlay,
    /// A software loopback interface.
    Loopback,
    /// The managed Ferrum TUN interface.
    ManagedTun,
}

/// Captured operational availability, without importing platform status codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceOperationalState {
    Operational,
    Unavailable,
}

/// Captured media-link availability, independent of interface operational state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceLinkState {
    Connected,
    Disconnected,
}

/// One family-specific interface row captured by a read-only platform adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkInterfaceObservation {
    binding: InterfaceBinding,
    family: NetworkFamily,
    operational: InterfaceOperationalState,
    connected: InterfaceLinkState,
    kind: NetworkInterfaceKind,
    interface_metric: u32,
    default_route_metric: Option<u32>,
}

impl NetworkInterfaceObservation {
    /// Builds one family-specific row from the same platform read as its addresses and metrics.
    pub fn new(
        binding: InterfaceBinding,
        family: NetworkFamily,
        operational: InterfaceOperationalState,
        connected: InterfaceLinkState,
        kind: NetworkInterfaceKind,
        interface_metric: u32,
        default_route_metric: Option<u32>,
    ) -> Result<Self, NetworkInterfaceObservationError> {
        if binding.addresses().is_empty()
            || binding
                .addresses()
                .iter()
                .any(|address| NetworkFamily::of(*address) != family)
        {
            return Err(NetworkInterfaceObservationError);
        }
        Ok(Self {
            binding,
            family,
            operational,
            connected,
            kind,
            interface_metric,
            default_route_metric,
        })
    }

    /// Returns the captured family-specific interface binding.
    pub const fn binding(&self) -> &InterfaceBinding {
        &self.binding
    }

    /// Returns the address family described by this row.
    pub const fn family(&self) -> NetworkFamily {
        self.family
    }

    /// Returns whether the interface was operational when captured.
    pub const fn operational(&self) -> bool {
        matches!(self.operational, InterfaceOperationalState::Operational)
    }

    /// Returns whether the interface media was connected when captured.
    pub const fn connected(&self) -> bool {
        matches!(self.connected, InterfaceLinkState::Connected)
    }

    /// Returns the closed interface kind used by automatic selection.
    pub const fn kind(&self) -> NetworkInterfaceKind {
        self.kind
    }

    /// Returns the Windows family-specific interface metric.
    pub const fn interface_metric(&self) -> u32 {
        self.interface_metric
    }

    /// Returns the best default-route metric for this family, if present.
    pub const fn default_route_metric(&self) -> Option<u32> {
        self.default_route_metric
    }

    fn is_available(&self) -> bool {
        self.operational() && self.connected()
    }

    fn automatic_rank(&self) -> Option<(u64, u64, u32, &str)> {
        (self.is_available()
            && self.kind == NetworkInterfaceKind::Underlay
            && self.default_route_metric.is_some())
        .then(|| {
            (
                u64::from(self.interface_metric)
                    + u64::from(self.default_route_metric.unwrap_or_default()),
                self.binding.stable_id(),
                self.binding.index(),
                self.binding.name(),
            )
        })
    }
}

/// A platform row mixed address families or did not carry a usable address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkInterfaceObservationError;

/// Stable interface identity returned by a target-aware system route lookup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SystemBestRoute {
    stable_id: u64,
    index: u32,
}

impl SystemBestRoute {
    /// Builds one complete route identity, such as a Windows LUID and family index.
    pub fn new(stable_id: u64, index: u32) -> Result<Self, SystemBestRouteError> {
        if stable_id == 0 || index == 0 {
            return Err(SystemBestRouteError);
        }
        Ok(Self { stable_id, index })
    }

    /// Returns the platform-stable interface identity.
    pub const fn stable_id(self) -> u64 {
        self.stable_id
    }

    /// Returns the family-specific platform interface index.
    pub const fn index(self) -> u32 {
        self.index
    }
}

/// A system best-route result omitted part of its interface identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemBestRouteError;

/// Closed read failure from a platform network catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkInterfaceCatalogError;

/// Stable routing state; deliberately excludes lifetimes that tick without routing changes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkRouteObservation {
    stable_id: u64,
    index: u32,
    destination: IpAddr,
    prefix_length: u8,
    next_hop: IpAddr,
    metric: u32,
}

impl NetworkRouteObservation {
    pub fn new(
        stable_id: u64,
        index: u32,
        destination: IpAddr,
        prefix_length: u8,
        next_hop: IpAddr,
        metric: u32,
    ) -> Self {
        Self {
            stable_id,
            index,
            destination,
            prefix_length,
            next_hop,
            metric,
        }
    }

    pub const fn stable_id(&self) -> u64 {
        self.stable_id
    }
    pub const fn index(&self) -> u32 {
        self.index
    }
    pub const fn destination(&self) -> IpAddr {
        self.destination
    }
    pub const fn prefix_length(&self) -> u8 {
        self.prefix_length
    }
    pub const fn next_hop(&self) -> IpAddr {
        self.next_hop
    }
    pub const fn metric(&self) -> u32 {
        self.metric
    }
}

/// Read-only platform seam used to capture interfaces and query target-specific routes.
///
/// The Windows implementation belongs at the existing platform unsafe boundary and should use
/// `GetIfTable2`/`GetIpForwardTable2` for rows and `GetBestRoute2` for the actual destination.
pub trait NetworkInterfaceCatalog: Send + Sync {
    /// Reads all family-specific interface rows needed for one immutable snapshot.
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError>;

    /// Reads complete per-family routes. Missing support fails capture closed.
    fn read_routes(&self) -> Result<Vec<NetworkRouteObservation>, NetworkInterfaceCatalogError>;

    /// Reads the system best route for the actual destination without changing network state.
    fn system_best_route(
        &self,
        destination: SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError>;
}

/// Immutable, family-aware view of the current underlay network.
#[derive(Clone, Debug, Eq)]
pub struct NetworkSnapshot {
    generation: u64,
    observation_id: u64,
    routes: Option<Arc<[NetworkRouteObservation]>>,
    ipv4_default: Option<InterfaceBinding>,
    ipv6_default: Option<InterfaceBinding>,
    interfaces: Arc<[NetworkInterfaceObservation]>,
}

impl PartialEq for NetworkSnapshot {
    fn eq(&self, other: &Self) -> bool {
        // The observation token fences cache/admission races, not semantic reset
        // equality: recapturing identical state must retain idempotent reset behavior.
        self.generation == other.generation
            && self.ipv4_default == other.ipv4_default
            && self.ipv6_default == other.ipv6_default
            && self.interfaces == other.interfaces
            && self.routes == other.routes
    }
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
        let mut interfaces = Vec::new();
        if let Some(binding) = ipv4_default.as_ref() {
            interfaces.push(default_observation(binding, NetworkFamily::Ipv4)?);
        }
        if let Some(binding) = ipv6_default.as_ref() {
            interfaces.push(default_observation(binding, NetworkFamily::Ipv6)?);
        }
        Self::from_interfaces_with_defaults(generation, interfaces, ipv4_default, ipv6_default)
    }

    /// Captures one immutable snapshot from a read-only platform catalog.
    pub fn capture(
        generation: u64,
        catalog: &impl NetworkInterfaceCatalog,
    ) -> Result<Self, NetworkSnapshotCaptureError> {
        let interfaces = catalog
            .read_interfaces()
            .map_err(|_| NetworkSnapshotCaptureError::CatalogUnavailable)?;
        let routes = catalog
            .read_routes()
            .map_err(|_| NetworkSnapshotCaptureError::CatalogUnavailable)?;
        Self::from_interfaces_and_routes(generation, interfaces, routes)
            .map_err(|_| NetworkSnapshotCaptureError::InvalidInterfaceCatalog)
    }

    /// Builds one immutable snapshot from already captured family-specific rows.
    pub fn from_interfaces(
        generation: u64,
        interfaces: Vec<NetworkInterfaceObservation>,
    ) -> Result<Self, NetworkSnapshotError> {
        validate_interface_identities(&interfaces)?;
        let ipv4_default = automatic_default(&interfaces, NetworkFamily::Ipv4);
        let ipv6_default = automatic_default(&interfaces, NetworkFamily::Ipv6);
        Self::from_interfaces_with_defaults(generation, interfaces, ipv4_default, ipv6_default)
    }

    /// Builds a complete observation, including nondefault route metrics and next hops.
    pub fn from_interfaces_and_routes(
        generation: u64,
        interfaces: Vec<NetworkInterfaceObservation>,
        mut routes: Vec<NetworkRouteObservation>,
    ) -> Result<Self, NetworkSnapshotError> {
        if routes.iter().any(|route| {
            route.stable_id == 0
                || route.index == 0
                || NetworkFamily::of(route.destination) != NetworkFamily::of(route.next_hop)
                || route.prefix_length > if route.destination.is_ipv4() { 32 } else { 128 }
        }) {
            return Err(NetworkSnapshotError);
        }
        routes.sort();
        routes.dedup();
        let mut snapshot = Self::from_interfaces(generation, interfaces)?;
        snapshot.routes = Some(routes.into());
        Ok(snapshot)
    }

    /// Distinguishes refreshed observations without retiring the work generation.
    pub const fn observation_id(&self) -> u64 {
        self.observation_id
    }

    /// Retains the work generation while publishing a newly captured observation.
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Whether existing bound work can survive this observation.
    ///
    /// Existing family rows and all their routes must be identical. New nondefault
    /// family rows cannot affect already interface-bound sockets, but become visible
    /// to new dials. Missing route evidence is never considered unchanged.
    pub fn preserves_work_from(&self, previous: &Self) -> bool {
        let (Some(routes), Some(old_routes)) = (&self.routes, &previous.routes) else {
            return false;
        };
        if self.ipv4_default != previous.ipv4_default
            || self.ipv6_default != previous.ipv6_default
            || previous
                .interfaces
                .iter()
                .any(|old| !self.interfaces.contains(old))
        {
            return false;
        }
        if old_routes
            .iter()
            .any(|route| routes.binary_search(route).is_err())
        {
            return false;
        }
        // Preserve pre-existing route evidence even when its family had no preferred
        // address. New routes on a previously unbindable family cannot affect old work.
        let identities = previous
            .interfaces
            .iter()
            .map(|row| {
                (
                    row.family(),
                    row.binding().stable_id(),
                    row.binding().index(),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        routes.iter().all(|route| {
            let relevant = route.prefix_length == 0
                || identities.contains(&(
                    NetworkFamily::of(route.destination),
                    route.stable_id,
                    route.index,
                ));
            !relevant || old_routes.binary_search(route).is_ok()
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

    /// Returns all family-specific interface rows captured in this generation.
    pub fn interfaces(&self) -> &[NetworkInterfaceObservation] {
        &self.interfaces
    }

    fn from_interfaces_with_defaults(
        generation: u64,
        mut interfaces: Vec<NetworkInterfaceObservation>,
        ipv4_default: Option<InterfaceBinding>,
        ipv6_default: Option<InterfaceBinding>,
    ) -> Result<Self, NetworkSnapshotError> {
        validate_interface_identities(&interfaces)?;
        interfaces.sort_by(|left, right| {
            (
                left.family(),
                left.binding().stable_id(),
                left.binding().index(),
                left.binding().name(),
            )
                .cmp(&(
                    right.family(),
                    right.binding().stable_id(),
                    right.binding().index(),
                    right.binding().name(),
                ))
        });
        Ok(Self {
            generation,
            observation_id: next_observation_id(),
            routes: None,
            ipv4_default,
            ipv6_default,
            interfaces: interfaces.into(),
        })
    }

    /// Resolves one exact interface name from this immutable generation.
    pub fn resolve_named(&self, name: &str, family: NetworkFamily) -> NamedInterfaceResolution {
        let named = self
            .interfaces
            .iter()
            .filter(|interface| interface.binding().name() == name)
            .collect::<Vec<_>>();
        if named.is_empty() {
            return NamedInterfaceResolution::Missing;
        }
        let mut family_rows = named
            .into_iter()
            .filter(|interface| interface.family() == family);
        let Some(first) = family_rows.next() else {
            return NamedInterfaceResolution::WrongFamily;
        };
        if family_rows.next().is_some() {
            return NamedInterfaceResolution::Ambiguous;
        }
        if first.is_available() {
            NamedInterfaceResolution::Available(first.binding().clone())
        } else {
            NamedInterfaceResolution::Unavailable
        }
    }

    pub(crate) fn resolve_system_route(
        &self,
        route: SystemBestRoute,
        family: NetworkFamily,
    ) -> Option<InterfaceBinding> {
        self.interfaces
            .iter()
            .find(|interface| {
                interface.family() == family
                    && interface.is_available()
                    && interface.binding().stable_id() == route.stable_id()
                    && interface.binding().index() == route.index()
            })
            .map(|interface| interface.binding().clone())
    }
}

fn next_observation_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |id| id.checked_add(1),
    )
    .expect("network observation identity exhausted")
}

fn default_observation(
    binding: &InterfaceBinding,
    family: NetworkFamily,
) -> Result<NetworkInterfaceObservation, NetworkSnapshotError> {
    let addresses = binding
        .addresses()
        .iter()
        .copied()
        .filter(|address| NetworkFamily::of(*address) == family)
        .collect::<Vec<_>>();
    let family_binding = InterfaceBinding::new(
        Arc::clone(&binding.name),
        binding.stable_id(),
        binding.index(),
        addresses,
    )
    .map_err(|_| NetworkSnapshotError)?;
    NetworkInterfaceObservation::new(
        family_binding,
        family,
        InterfaceOperationalState::Operational,
        InterfaceLinkState::Connected,
        NetworkInterfaceKind::Underlay,
        0,
        Some(0),
    )
    .map_err(|_| NetworkSnapshotError)
}

fn validate_interface_identities(
    interfaces: &[NetworkInterfaceObservation],
) -> Result<(), NetworkSnapshotError> {
    for (offset, interface) in interfaces.iter().enumerate() {
        if interfaces[offset + 1..].iter().any(|candidate| {
            candidate.family() == interface.family()
                && candidate.binding().stable_id() == interface.binding().stable_id()
                && candidate.binding().index() == interface.binding().index()
        }) {
            return Err(NetworkSnapshotError);
        }
    }
    Ok(())
}

fn automatic_default(
    interfaces: &[NetworkInterfaceObservation],
    family: NetworkFamily,
) -> Option<InterfaceBinding> {
    interfaces
        .iter()
        .filter(|interface| interface.family() == family)
        .filter_map(|interface| interface.automatic_rank().map(|rank| (rank, interface)))
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, interface)| interface.binding().clone())
}

/// A family row was invalid or the catalog repeated one family identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkSnapshotError;

/// Closed failure from capturing one immutable platform snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSnapshotCaptureError {
    CatalogUnavailable,
    InvalidInterfaceCatalog,
}
