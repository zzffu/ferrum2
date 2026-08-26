pub(super) use super::super::{
    ABI_EXPORTS, AF_INET6, AF_UNSPEC, AdapterCreateFailure, CatalogFamilyRow, CatalogInterfaceRow,
    CleanupOperations, DLL_BYTES, DLL_SHA256, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DadProgress, DnsFamily, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW,
    ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, Error, EventHandle, InterfaceIdentity,
    IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred,
    IpDadStateTentative, Ipv4DnsSettings, Ipv6DnsSettings, LoaderOperations, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    ManagedAddressCleanupOperations, ManagedAddressRead, ManagedDnsLease, ManagedDnsOperations,
    ManagedNetworkValidation, ManagedNetworkValidationOutcome, ManagedOwnershipLedgerView,
    ManagedRouteCleanupOperations, ManagedRouteOperations, ManagedRouteRead, NET_LUID_LH,
    NetworkChangeWaitOperations, NotificationContext, NotificationOwners,
    ResolvedSocketBindingOperations, RouteFingerprint, SessionJournal, SetupOperations,
    SocketBindingOperations, StopSignal, StrictRouteAction, StrictRouteCondition, StrictRouteLayer,
    StrictRouteOperations, StrictRouteRule, StrictRouteRuleKind, StrictRouteSession,
    UnderlayOperations, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WaitForMultipleObjects,
    WindowsNetworkInterfaceCatalog, WorkSignal, address_changed, bind_fixed_with,
    bind_resolved_socket_with, bind_target_with, build_network_interface_observations,
    cancel_notification_handles, capture_route_row, catalog_default_route,
    catalog_fallback_interface_identity, classify_adapter_create_failure,
    classify_notification_luid, classify_receive_null, classify_send_allocation_failure,
    classify_underlay_refresh, classify_wait_result, cleanup_transaction,
    close_notification_handles, copy_bounded_wide, dad_snapshot, delete_managed_address,
    delete_managed_route, dns_settings_query_flags, eligible_interface_identity,
    finish_setup_transaction, initialize_managed_address, install_managed_dns,
    install_managed_routes, interface_changed, interface_socket_option, ipv4_dns_settings_input,
    ipv4_interface_index_option_value, ipv4_sockaddr, ipv6_dns_settings_input,
    ipv6_interface_index_option_value, ipv6_sockaddr, leak_notification_owners, load_transaction,
    managed_address_matches, managed_device_health, managed_dns_matches,
    managed_notification_family, managed_ownership_ledger_exact, managed_state_health,
    normalize_dns_settings, prepare_managed_intent, refresh_underlay_with, require_exports,
    restore_managed_dns, revalidate_managed_network, route_changed, route_matches,
    setup_transaction, snapshot_underlay_at, snapshot_underlay_with, socket_addr_sockaddr,
    strict_route_rules, strict_route_state_matches, subscribe_notification_sequence,
    take_last_owned_route, underlay_matches_with, underlay_snapshot_matches, validate_artifact,
    wait_for_network_change,
};
pub(super) use super::super::{
    ERROR_SUCCESS, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_E_FILTER_NOT_FOUND,
    FWP_E_SESSION_ABORTED, FWP_UINT64, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, IP_UNICAST_IF, IPPROTO_IP,
    IPPROTO_IPV6, IPV6_UNICAST_IF, IfOperStatusUp, IpPrefixOriginManual, IpSuffixOriginManual,
    MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, ResetEvent, STRICT_ROUTE_BLOCK_WEIGHT,
    guid_matches, wfp_readback_present,
};
pub(super) use crate::{
    ErrorKind, IpPrefix, Ipv4Prefix, Ipv6Prefix, ManagedStateDamage, ManagedTunHealth,
    NetworkChangeWaitOutcome, SendOutcome, WaitOutcome,
};
pub(super) use ferrum2_net::{
    DialOptions, InterfaceBinding, NetworkFamily, NetworkInterfaceCatalog,
    NetworkInterfaceCatalogError, NetworkInterfaceKind, NetworkInterfaceObservation,
    NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions, SystemBestRoute,
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
