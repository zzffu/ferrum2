pub(super) use super::super::core::dns::{
    DnsFamily, Ipv4DnsSettings, Ipv6DnsSettings, copy_bounded_wide, dns_settings_query_flags,
    ipv4_dns_settings_input, ipv6_dns_settings_input, normalize_dns_settings,
};
pub(super) use super::super::core::loader::{
    LoaderOperations, load_transaction, require_exports, validate_artifact,
};
pub(super) use super::super::core::managed::{
    AdapterCreateFailure, CleanupOperations, DadProgress, ManagedAddressCleanupOperations,
    ManagedAddressRead, ManagedDnsLease, ManagedDnsOperations, ManagedNetworkValidation,
    ManagedNetworkValidationOutcome, ManagedOwnershipLedgerView, ManagedRouteCleanupOperations,
    ManagedRouteOperations, ManagedRouteRead, SetupOperations, classify_adapter_create_failure,
    cleanup_transaction, dad_snapshot, delete_managed_address, delete_managed_route,
    finish_setup_transaction, install_managed_dns, install_managed_routes, managed_device_health,
    managed_dns_matches, managed_ownership_ledger_exact, managed_state_health,
    prepare_managed_intent, restore_managed_dns, revalidate_managed_network, setup_transaction,
    take_last_owned_route,
};
pub(super) use super::super::core::network::{
    CatalogFamilyRow, CatalogInterfaceRow, DefaultRouteCandidate, InterfaceCandidate,
    InterfaceIdentity, ResolvedSocketBindingOperations, RouteFingerprint, SocketBindingOperations,
    UnderlayOperations, WindowsNetworkInterfaceCatalog, bind_fixed_with, bind_resolved_socket_with,
    bind_target_with, build_network_interface_observations, catalog_default_route,
    classify_underlay_refresh, eligible_interface_identity, fallback_interface_identity,
    interface_socket_option, ipv4_interface_index_option_value, ipv6_interface_index_option_value,
    refresh_underlay_with, snapshot_underlay_at, snapshot_underlay_with, underlay_matches_with,
    underlay_snapshot_matches,
};
pub(super) use super::super::core::notification::{
    NetworkChangeWaitOperations, NotificationContext, cancel_notification_handles,
    classify_notification_luid, close_notification_handles, leak_notification_owners,
    managed_notification_family, subscribe_notification_sequence, wait_for_network_change,
};
pub(super) use super::super::core::raw::{
    capture_route_row, increment_route_interface_luid, increment_unicast_interface_luid,
    initialize_managed_address, ipv4_sockaddr, ipv6_sockaddr, managed_address_matches,
    route_destination, route_matches, route_next_hop, set_route_destination, set_route_next_hop,
    sockaddr_port, sockaddr_scope_id, socket_addr_sockaddr,
};
pub(super) use super::super::core::strict_route::{
    StrictRouteOperations, StrictRouteSession, guid_matches, strict_route_state_matches,
    wfp_readback_present,
};
pub(super) use super::super::core::wintun::{
    SessionJournal, classify_receive_null, classify_send_allocation_failure, classify_wait_result,
};
pub(super) use crate::artifact::{ABI_EXPORTS, DLL_BYTES, DLL_SHA256};
pub(super) use crate::strict_route::{
    STRICT_ROUTE_BLOCK_WEIGHT, StrictRouteAction, StrictRouteCondition, StrictRouteLayer,
    StrictRouteRule, StrictRouteRuleKind, strict_route_rules,
};
pub(super) use crate::{
    Error, ErrorKind, IpPrefix, Ipv4Prefix, Ipv6Prefix, ManagedStateDamage, ManagedTunHealth,
    NetworkChangeWaitOutcome, SendOutcome, WaitOutcome,
};
pub(super) use ferrum2_net::{
    DialOptions, InterfaceBinding, NetworkFamily, NetworkInterfaceCatalog,
    NetworkInterfaceCatalogError, NetworkInterfaceKind, NetworkInterfaceObservation,
    NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions, SystemBestRoute,
};
pub(super) use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF,
    ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, FWP_E_SESSION_ABORTED, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
pub(super) use windows_sys::Win32::NetworkManagement::IpHelper::{
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW,
};
pub(super) use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_UINT64, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};
pub(super) use windows_sys::Win32::Networking::WinSock::{
    AF_UNSPEC, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IpDadStateDeprecated,
    IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative,
    IpPrefixOriginManual, IpSuffixOriginManual,
};

#[derive(Clone)]
pub(super) struct InjectedUnderlay {
    pub(super) interfaces: Vec<InterfaceIdentity>,
    pub(super) routes: Vec<(std::net::IpAddr, RouteFingerprint)>,
    pub(super) interface_metrics: Vec<(u32, u32)>,
    pub(super) best_calls: usize,
    pub(super) fail_at: Option<&'static str>,
    pub(super) change_generation: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
}
