#![deny(unsafe_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[allow(dead_code)]
mod artifact {
    pub(crate) const DLL_BYTES: u64 = 427_552;
    pub(crate) const DLL_SHA256: [u8; 32] = [
        0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85,
        0xc1, 0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d,
        0xaf, 0xce,
    ];
    pub(crate) const ABI_EXPORTS: [&[u8]; 11] = [
        b"WintunCreateAdapter\0",
        b"WintunCloseAdapter\0",
        b"WintunGetAdapterLUID\0",
        b"WintunGetRunningDriverVersion\0",
        b"WintunStartSession\0",
        b"WintunEndSession\0",
        b"WintunGetReadWaitEvent\0",
        b"WintunReceivePacket\0",
        b"WintunReleaseReceivePacket\0",
        b"WintunAllocateSendPacket\0",
        b"WintunSendPacket\0",
    ];
}

/// Result of handing one complete packet to the Wintun send ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// Wintun accepted the packet into its send ring.
    Sent,
    /// The send ring was full, so Wintun did not accept the packet.
    ///
    /// This is an intentional, non-fatal drop. Callers must not retry the packet or restart the
    /// session, and should account for it separately from a successful send.
    DroppedRingFull,
}

/// Reason one bounded adapter wait completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    /// Process-level stop was signalled.
    Stop,
    /// Wintun has at least one packet ready to receive.
    Readable,
    /// A route, interface, or address notification was observed.
    NetworkChanged,
    /// The bounded wait elapsed without a signalled handle.
    Timeout,
    /// Adapter-owner work was explicitly signalled.
    ///
    /// Work uses its own auto-reset event and remains distinct from process-level stop.
    Work,
}

/// Closed result of one bounded read-only Windows network-change wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChangeWaitOutcome {
    /// One or more route, interface, or unicast-address notifications were coalesced.
    Changed,
    /// The bounded wait elapsed without observing a network change.
    TimedOut,
    /// Process-level stop was signalled and takes precedence over a pending change.
    Stopped,
}

/// Stable semantic result after one debounced network-notification burst.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkChangeOutcome {
    /// Only irrelevant or Ferrum2-owned state changed; the current session remains valid.
    Unchanged,
    /// The frozen underlay no longer matches the current network.
    Changed,
    /// A Ferrum2-owned managed object no longer matches its transaction journal.
    ManagedStateDamaged(ManagedStateDamage),
}

/// Health of the Ferrum2-owned network objects in one managed TUN transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedTunHealth {
    Healthy,
    Damaged(ManagedStateDamage),
}

/// Closed reason that Ferrum2-owned managed state no longer matches exact readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedStateDamage {
    /// The adapter handle or its published interface identity is no longer usable.
    Adapter,
    /// The Wintun device session is no longer owned by the managed plane.
    Session,
    /// One or more owned interface-address rows are absent or no longer exact.
    Address,
    /// One or more owned capture-route rows are absent or no longer exact.
    Route,
    /// One or more managed DNS leases are absent or no longer exact.
    Dns,
    /// One or more owned strict-route WFP objects are absent or no longer exact.
    StrictRoute,
    /// The internal ownership journal is incomplete or contradicts the configured managed plane.
    OwnershipLedger,
}

/// Complete validated setup input for one newly-created Wintun adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterConfig {
    pub name: Box<str>,
    pub ipv4: Option<Ipv4Prefix>,
    pub ipv6: Option<Ipv6Prefix>,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
    managed: Option<ManagedNetworkConfig>,
}

/// One IPv4 address and prefix length. Platform route fields remain private.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Prefix {
    address: Ipv4Addr,
    length: u8,
}

impl Ipv4Prefix {
    pub fn new(address: Ipv4Addr, length: u8) -> Result<Self, Error> {
        if length == 0 || length > 32 {
            return Err(Error::invalid_input());
        }
        Ok(Self { address, length })
    }

    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    pub const fn length(self) -> u8 {
        self.length
    }

    fn is_canonical(self) -> bool {
        let mask = u32::MAX
            .checked_shl(u32::from(32 - self.length))
            .unwrap_or(0);
        u32::from(self.address) & mask == u32::from(self.address)
    }
}

/// One IPv6 address and prefix length. Platform route fields remain private.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Prefix {
    address: Ipv6Addr,
    length: u8,
}

impl Ipv6Prefix {
    pub fn new(address: Ipv6Addr, length: u8) -> Result<Self, Error> {
        if length == 0 || length > 128 {
            return Err(Error::invalid_input());
        }
        Ok(Self { address, length })
    }

    pub const fn address(self) -> Ipv6Addr {
        self.address
    }

    pub const fn length(self) -> u8 {
        self.length
    }

    fn is_canonical(self) -> bool {
        let mask = u128::MAX
            .checked_shl(u32::from(128 - self.length))
            .unwrap_or(0);
        u128::from(self.address) & mask == u128::from(self.address)
    }
}

/// One canonical managed capture prefix.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl IpPrefix {
    fn is_canonical(self) -> bool {
        match self {
            Self::V4(prefix) => prefix.is_canonical(),
            Self::V6(prefix) => prefix.is_canonical(),
        }
    }

    const fn is_ipv4(self) -> bool {
        matches!(self, Self::V4(_))
    }

    const fn is_ipv6(self) -> bool {
        matches!(self, Self::V6(_))
    }
}

/// Bounded family-neutral managed network intent consumed by the Adapter transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedNetworkConfig {
    capture_routes: Vec<IpPrefix>,
    physical_endpoints: Vec<SocketAddr>,
    target_binder: bool,
    ipv4_dns_address: Option<Ipv4Addr>,
    ipv6_dns_address: Option<Ipv6Addr>,
    strict_route: bool,
}

impl ManagedNetworkConfig {
    pub fn new(
        mut capture_routes: Vec<IpPrefix>,
        mut physical_endpoints: Vec<SocketAddr>,
        target_binder: bool,
        ipv4_dns_address: Option<Ipv4Addr>,
        ipv6_dns_address: Option<Ipv6Addr>,
    ) -> Result<Self, Error> {
        if capture_routes.len() > 256
            || physical_endpoints.len() > 256
            || capture_routes.iter().any(|prefix| !prefix.is_canonical())
        {
            return Err(Error::invalid_input());
        }
        capture_routes.sort_unstable();
        capture_routes.dedup();
        physical_endpoints.sort_unstable();
        physical_endpoints.dedup();
        if capture_routes.is_empty()
            && physical_endpoints.is_empty()
            && !target_binder
            && ipv4_dns_address.is_none()
            && ipv6_dns_address.is_none()
        {
            return Err(Error::invalid_input());
        }
        Ok(Self {
            capture_routes,
            physical_endpoints,
            target_binder,
            ipv4_dns_address,
            ipv6_dns_address,
            strict_route: false,
        })
    }

    /// Requests scoped family and managed-DNS Windows Filtering Platform guards.
    ///
    /// The intent defaults to disabled. Callers should enable it only after resolving any
    /// higher-level platform policy.
    pub fn with_strict_route(mut self, enabled: bool) -> Self {
        self.strict_route = enabled;
        self
    }
}

// These pure views stay available in fail-closed builds so capability selection remains a module
// boundary rather than a collection of item-level feature predicates.
#[allow(dead_code)]
impl ManagedNetworkConfig {
    pub(crate) fn capture_routes(&self) -> &[IpPrefix] {
        &self.capture_routes
    }

    pub(crate) fn physical_endpoints(&self) -> &[SocketAddr] {
        &self.physical_endpoints
    }

    pub(crate) const fn needs_target_binder(&self) -> bool {
        self.target_binder
    }

    pub(crate) const fn ipv4_dns_address(&self) -> Option<Ipv4Addr> {
        self.ipv4_dns_address
    }

    pub(crate) const fn ipv6_dns_address(&self) -> Option<Ipv6Addr> {
        self.ipv6_dns_address
    }

    pub(crate) const fn strict_route(&self) -> bool {
        self.strict_route
    }
}

impl AdapterConfig {
    /// Checks the platform Adapter's trust-boundary invariants without touching the OS.
    pub fn new(
        name: Box<str>,
        ipv4: Option<Ipv4Prefix>,
        ipv6: Option<Ipv6Prefix>,
        mtu: u16,
        ring_capacity: u32,
        ready_timeout: Duration,
    ) -> Result<Self, Error> {
        if name.is_empty()
            || name.encode_utf16().count() >= 128
            || name.chars().any(char::is_control)
            || (ipv4.is_none() && ipv6.is_none())
            || !(1280..=1500).contains(&mtu)
            || !(131_072..=67_108_864).contains(&ring_capacity)
            || !ring_capacity.is_power_of_two()
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&ready_timeout)
        {
            return Err(Error::invalid_input());
        }
        Ok(Self {
            name,
            ipv4,
            ipv6,
            mtu,
            ring_capacity,
            ready_timeout,
            managed: None,
        })
    }

    /// Adds a managed network plan after checking it against the enabled address families.
    pub fn with_managed_network(mut self, managed: ManagedNetworkConfig) -> Result<Self, Error> {
        if managed.capture_routes.iter().any(|prefix| {
            (prefix.is_ipv4() && self.ipv4.is_none()) || (prefix.is_ipv6() && self.ipv6.is_none())
        }) || (managed.ipv4_dns_address.is_some() && self.ipv4.is_none())
            || (managed.ipv6_dns_address.is_some() && self.ipv6.is_none())
        {
            return Err(Error::invalid_input());
        }
        self.managed = Some(managed);
        Ok(self)
    }
}

#[allow(dead_code)]
impl AdapterConfig {
    pub(crate) fn managed_network(&self) -> Option<&ManagedNetworkConfig> {
        self.managed.as_ref()
    }
}

/// Closed, redacted category for one Wintun operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// A caller supplied an invalid bounded configuration or operation input.
    InvalidInput,
    /// The current adapter session ended or became unusable and may be rebuilt.
    RecoverableSession,
    /// An invariant, handle, driver, or platform result was internally inconsistent.
    UnrecoverableCorruption,
    /// Reverse teardown could not prove that owned platform state was restored safely.
    Cleanup,
}

/// Redacted platform failure. Raw paths, identities and Win32 text are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Constructs a redacted error from one of the fixed public categories.
    pub const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the fixed category without exposing platform error detail.
    pub const fn kind(self) -> ErrorKind {
        self.kind
    }

    const fn invalid_input() -> Self {
        Self::new(ErrorKind::InvalidInput)
    }
}

#[allow(dead_code)]
impl Error {
    pub(crate) const fn recoverable_session() -> Self {
        Self::new(ErrorKind::RecoverableSession)
    }

    const fn unrecoverable_corruption() -> Self {
        Self::new(ErrorKind::UnrecoverableCorruption)
    }

    pub(crate) const fn cleanup() -> Self {
        Self::new(ErrorKind::Cleanup)
    }
}

// Existing trust-boundary code uses this conservative redacted value for failures that are not
// explicitly proven to be invalid input, a recoverable session end, or a cleanup failure.
#[allow(dead_code, non_upper_case_globals)]
pub(crate) const Error: Error = Error::unrecoverable_corruption();

/// Redacted adapter-creation failure that preserves only rollback integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateError {
    cleanup_failed: bool,
    strict_route_install_failed: bool,
}

impl CreateError {
    pub(crate) const fn operation() -> Self {
        Self {
            cleanup_failed: false,
            strict_route_install_failed: false,
        }
    }
}

#[allow(dead_code)]
impl CreateError {
    pub(crate) const fn cleanup() -> Self {
        Self {
            cleanup_failed: true,
            strict_route_install_failed: false,
        }
    }

    pub(crate) const fn strict_route_install(cleanup_failed: bool) -> Self {
        Self {
            cleanup_failed,
            strict_route_install_failed: true,
        }
    }

    /// Reports only whether reverse cleanup failed, without exposing platform detail.
    pub const fn is_cleanup_failure(self) -> bool {
        self.cleanup_failed
    }

    /// Reports only whether the scoped strict-route WFP transaction failed.
    pub const fn is_strict_route_install_failure(self) -> bool {
        self.strict_route_install_failed
    }
}

impl fmt::Display for CreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Wintun adapter creation failed")
    }
}

impl std::error::Error for CreateError {}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Wintun operation failed")
    }
}

impl std::error::Error for Error {}

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "fuzzing"
))]
mod strict_route;
#[cfg(feature = "fuzzing")]
pub use strict_route::{
    FUZZ_MAX_WFP_APP_ID_BYTES, StrictRouteRulePlanObservation, fuzz_strict_route_rule_plan,
};

#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    all(test, windows, target_arch = "x86_64")
))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
use windows::backend;

// Library tests always select the fail-closed hosted adapter. The live Windows backend is not
// exported into a test crate, so a hosted test cannot reach adapter creation or network mutation
// through the public interface.
#[cfg(any(
    test,
    not(all(windows, target_arch = "x86_64", feature = "live-backend"))
))]
#[path = "unsupported.rs"]
mod backend;

pub use backend::{
    Adapter, ReceivedPacket, StopSignal, UnderlayPolicy, WindowsNetworkChangeMonitor,
    WindowsNetworkInterfaceCatalog, WindowsResolvedSocketBinder, WorkSignal,
};

#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
pub use backend::bind_resolved_socket;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    use super::artifact::{ABI_EXPORTS, DLL_BYTES, DLL_SHA256};
    use super::{
        AdapterConfig, CreateError, Error, ErrorKind, IpPrefix, Ipv4Prefix, Ipv6Prefix,
        ManagedNetworkConfig, NetworkChangeWaitOutcome,
    };

    #[test]
    fn approved_artifact_and_required_exports_are_pinned() {
        assert_eq!(DLL_BYTES, 427_552);
        assert_eq!(
            DLL_SHA256,
            hex_literal("e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
        );
        assert!(ABI_EXPORTS.iter().all(|name| name.ends_with(&[0])));
    }

    #[test]
    fn safe_config_and_cleanup_classification_reject_mutations_without_os_work() {
        let make = |name: &str, ring| {
            AdapterConfig::new(
                name.into(),
                Some(Ipv4Prefix::new(Ipv4Addr::new(198, 18, 0, 2), 30).unwrap()),
                Some(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 126).unwrap()),
                1420,
                ring,
                Duration::from_secs(10),
            )
        };
        assert!(make("Ferrum2", 8_388_608).is_ok());
        assert_eq!(
            make("Ferrum2", 131_073).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            make("Ferrum2\0", 8_388_608).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert!(!CreateError::operation().is_cleanup_failure());
        assert!(CreateError::cleanup().is_cleanup_failure());
        assert!(!CreateError::operation().is_strict_route_install_failure());
        assert!(!CreateError::cleanup().is_strict_route_install_failure());
        assert!(CreateError::strict_route_install(false).is_strict_route_install_failure());
        assert!(CreateError::strict_route_install(true).is_cleanup_failure());
    }

    #[test]
    fn operation_error_kinds_are_closed_and_redacted() {
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::RecoverableSession,
            ErrorKind::UnrecoverableCorruption,
            ErrorKind::Cleanup,
        ] {
            let error = Error::new(kind);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "Wintun operation failed");
            assert!(!format!("{error:?}").is_empty());
        }
        assert_eq!(Error::cleanup().kind(), ErrorKind::Cleanup);
    }

    #[test]
    fn network_change_wait_outcomes_are_closed() {
        assert_eq!(
            [
                NetworkChangeWaitOutcome::Changed,
                NetworkChangeWaitOutcome::TimedOut,
                NetworkChangeWaitOutcome::Stopped,
            ]
            .map(|outcome| match outcome {
                NetworkChangeWaitOutcome::Changed => "changed",
                NetworkChangeWaitOutcome::TimedOut => "timed_out",
                NetworkChangeWaitOutcome::Stopped => "stopped",
            }),
            ["changed", "timed_out", "stopped"]
        );
    }

    #[test]
    fn shared_socket_binder_contract_is_available_on_every_target() {
        fn assert_binder<T: ferrum2_net::ResolvedSocketBinder<Error = Error>>() {}

        assert_binder::<super::WindowsResolvedSocketBinder>();
    }

    #[test]
    fn optional_families_and_family_neutral_managed_intent_are_checked_without_os_work() {
        let v4 = Ipv4Prefix::new("198.18.0.2".parse().unwrap(), 30).unwrap();
        let v6 = Ipv6Prefix::new("fd00::2".parse().unwrap(), 126).unwrap();
        let make = |ipv4, ipv6| {
            AdapterConfig::new(
                "Ferrum2".into(),
                ipv4,
                ipv6,
                1420,
                8_388_608,
                Duration::from_secs(10),
            )
        };
        assert!(make(None, None).is_err());
        assert!(make(Some(v4), None).is_ok());
        assert!(make(None, Some(v6)).is_ok());
        assert!(make(Some(v4), Some(v6)).is_ok());

        let routes = vec![
            IpPrefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24).unwrap()),
            IpPrefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32).unwrap()),
        ];
        let endpoints: Vec<SocketAddr> = vec![
            "203.0.113.9:443".parse().unwrap(),
            "[2001:db8::9]:443".parse().unwrap(),
        ];
        let managed = ManagedNetworkConfig::new(
            routes,
            endpoints,
            true,
            Some("198.18.0.1".parse().unwrap()),
            Some("fd00::1".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(managed.clone().with_strict_route(false), managed);
        assert_ne!(managed.clone().with_strict_route(true), managed);
        let configured = make(Some(v4), Some(v6))
            .unwrap()
            .with_managed_network(managed.clone())
            .unwrap();
        assert_eq!(configured.managed_network(), Some(&managed));
        assert!(
            make(Some(v4), None)
                .unwrap()
                .with_managed_network(managed.clone())
                .is_err()
        );
        assert!(
            make(None, Some(v6))
                .unwrap()
                .with_managed_network(managed)
                .is_err()
        );

        let v4_managed_with_ipv6_underlay = ManagedNetworkConfig::new(
            vec![IpPrefix::V4(
                Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24).unwrap(),
            )],
            vec!["[2001:db8::9]:443".parse().unwrap()],
            false,
            Some("198.18.0.1".parse().unwrap()),
            None,
        )
        .unwrap();
        assert!(
            make(Some(v4), None)
                .unwrap()
                .with_managed_network(v4_managed_with_ipv6_underlay)
                .is_ok(),
            "underlay endpoint family is independent from enabled tunnel families"
        );

        assert!(
            ManagedNetworkConfig::new(
                vec![IpPrefix::V4(
                    Ipv4Prefix::new("203.0.113.1".parse().unwrap(), 24).unwrap()
                )],
                Vec::new(),
                false,
                None,
                None,
            )
            .is_err()
        );
        assert!(ManagedNetworkConfig::new(Vec::new(), Vec::new(), false, None, None).is_err());
        assert!(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0).is_err());
        assert!(Ipv6Prefix::new(Ipv6Addr::UNSPECIFIED, 129).is_err());

        let too_many_routes =
            vec![IpPrefix::V4(Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24).unwrap()); 257];
        assert!(ManagedNetworkConfig::new(too_many_routes, Vec::new(), false, None, None).is_err());
    }

    fn hex_literal(value: &str) -> [u8; 32] {
        let mut result = [0_u8; 32];
        for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
        }
        result
    }
}
