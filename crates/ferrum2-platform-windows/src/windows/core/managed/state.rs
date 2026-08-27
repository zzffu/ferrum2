use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred,
    IpDadStateTentative, NL_DAD_STATE,
};

use crate::{Error, IpPrefix, ManagedStateDamage, ManagedTunHealth};

use super::super::managed::{ManagedRouteCleanupOperations, managed_routes_match};
use super::super::network::{
    InterfaceIdentity, UnderlayOperations, UnderlayPolicy, underlay_matches_with,
};

#[derive(Clone, Copy)]
pub(in crate::windows) struct ManagedOwnershipLedgerView<'a> {
    pub(in crate::windows) capture_routes: &'a [IpPrefix],
    pub(in crate::windows) pending_route: bool,
    pub(in crate::windows) route_count: usize,
    pub(in crate::windows) ipv4_dns_address: Option<std::net::Ipv4Addr>,
    pub(in crate::windows) ipv6_dns_address: Option<std::net::Ipv6Addr>,
    pub(in crate::windows) ipv4_dns_lease: bool,
    pub(in crate::windows) ipv6_dns_lease: bool,
    pub(in crate::windows) dns_interface: bool,
    pub(in crate::windows) strict_route_intent: bool,
    pub(in crate::windows) strict_route_session: bool,
}

pub(in crate::windows) fn managed_device_health(
    adapter_present: bool,
    session_present: bool,
    ownership_ledger_exact: bool,
    mut identity_matches: impl FnMut() -> bool,
    mut addresses_match: impl FnMut() -> bool,
) -> ManagedTunHealth {
    if !adapter_present || !identity_matches() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Adapter);
    }
    if !session_present {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Session);
    }
    if !ownership_ledger_exact {
        return ManagedTunHealth::Damaged(ManagedStateDamage::OwnershipLedger);
    }
    if !addresses_match() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Address);
    }
    ManagedTunHealth::Healthy
}

#[allow(clippy::too_many_arguments)]
pub(in crate::windows) fn managed_ownership_ledger_exact(
    config: Option<&crate::ManagedNetworkConfig>,
    state: Option<ManagedOwnershipLedgerView<'_>>,
    pending_address: bool,
    address_count: usize,
    expected_address_count: usize,
    catalog_identity: Option<InterfaceIdentity>,
    owned_identity: InterfaceIdentity,
) -> bool {
    if pending_address
        || address_count != expected_address_count
        || owned_identity.luid == 0
        || owned_identity.index == 0
        || catalog_identity != Some(owned_identity)
    {
        return false;
    }
    match (config, state) {
        (None, None) => true,
        (Some(config), Some(state)) => {
            let has_dns =
                config.ipv4_dns_address().is_some() || config.ipv6_dns_address().is_some();
            state.capture_routes == config.capture_routes()
                && !state.pending_route
                && state.route_count == state.capture_routes.len()
                && state.ipv4_dns_address == config.ipv4_dns_address()
                && state.ipv6_dns_address == config.ipv6_dns_address()
                && state.ipv4_dns_lease == config.ipv4_dns_address().is_some()
                && state.ipv6_dns_lease == config.ipv6_dns_address().is_some()
                && state.dns_interface == has_dns
                && state.strict_route_intent == config.strict_route()
                && state.strict_route_session == config.strict_route()
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

pub(in crate::windows) fn managed_state_health<O: ManagedRouteCleanupOperations>(
    routes: &[O::Row],
    route_operations: &mut O,
    mut dns_matches: impl FnMut() -> Result<bool, Error>,
    mut strict_route_matches: impl FnMut() -> Result<bool, Error>,
) -> Result<ManagedTunHealth, Error> {
    if !managed_routes_match(routes, route_operations) {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Route));
    }
    if !dns_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Dns));
    }
    if !strict_route_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::StrictRoute));
    }
    Ok(ManagedTunHealth::Healthy)
}

pub(in crate::windows) struct ManagedNetworkValidation<'a, R> {
    pub(in crate::windows) policy: &'a UnderlayPolicy,
    pub(in crate::windows) owned: InterfaceIdentity,
    pub(in crate::windows) routes: &'a [R],
    pub(in crate::windows) validated_generation: &'a mut u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum ManagedNetworkValidationOutcome {
    Unchanged,
    UnderlayChanged,
    ManagedStateDamaged(ManagedStateDamage),
}

pub(in crate::windows) fn revalidate_managed_network<
    U: UnderlayOperations,
    O: ManagedRouteCleanupOperations,
    F: FnMut() -> Result<bool, Error>,
    S: FnMut() -> Result<bool, Error>,
>(
    validation: ManagedNetworkValidation<'_, O::Row>,
    force: bool,
    mut generation: impl FnMut() -> u64,
    underlay: &mut U,
    route_operations: &mut O,
    mut dns_matches: F,
    mut strict_route_matches: S,
) -> Result<ManagedNetworkValidationOutcome, Error> {
    let ManagedNetworkValidation {
        policy,
        owned,
        routes,
        validated_generation,
    } = validation;
    let mut before = generation();
    if !force && before == *validated_generation {
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    for _ in 0..2 {
        let underlay_matches = match underlay_matches_with(policy, owned, underlay) {
            Ok(matches) => matches,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let health = match managed_state_health(
            routes,
            route_operations,
            &mut dns_matches,
            &mut strict_route_matches,
        ) {
            Ok(health) => health,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let after = generation();
        if after != before {
            before = after;
            continue;
        }
        if let ManagedTunHealth::Damaged(reason) = health {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::ManagedStateDamaged(reason));
        }
        if !underlay_matches {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::UnderlayChanged);
        }
        *validated_generation = after;
        policy.accept_generation(after);
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    policy.invalidate();
    Ok(ManagedNetworkValidationOutcome::UnderlayChanged)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum DadProgress {
    Waiting,
    Ready,
}

pub(in crate::windows) fn dad_progress(state: NL_DAD_STATE) -> Result<DadProgress, Error> {
    match state {
        value if value == IpDadStateTentative => Ok(DadProgress::Waiting),
        value if value == IpDadStatePreferred => Ok(DadProgress::Ready),
        value
            if value == IpDadStateDuplicate
                || value == IpDadStateInvalid
                || value == IpDadStateDeprecated =>
        {
            Err(Error)
        }
        _ => Err(Error),
    }
}

pub(in crate::windows) fn dad_snapshot(
    session_started: bool,
    states: &[NL_DAD_STATE],
    deadline_elapsed: bool,
) -> Result<DadProgress, Error> {
    if !session_started || states.is_empty() {
        return Err(Error);
    }
    let mut waiting = false;
    for &state in states {
        waiting |= dad_progress(state)? == DadProgress::Waiting;
    }
    match (waiting, deadline_elapsed) {
        (false, _) => Ok(DadProgress::Ready),
        (true, false) => Ok(DadProgress::Waiting),
        (true, true) => Err(Error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum AdapterCreateFailure {
    NoAdmin,
    NameCollision,
    Other,
}

pub(in crate::windows) fn classify_adapter_create_failure(error: u32) -> AdapterCreateFailure {
    match error {
        ERROR_ACCESS_DENIED => AdapterCreateFailure::NoAdmin,
        ERROR_ALREADY_EXISTS => AdapterCreateFailure::NameCollision,
        _ => AdapterCreateFailure::Other,
    }
}
