use crate::{Error, ErrorKind};

pub(crate) const STRICT_ROUTE_PERMIT_WEIGHT: u8 = 15;
pub(crate) const STRICT_ROUTE_BLOCK_WEIGHT: u8 = 5;
pub(crate) const MAX_WFP_APP_ID_BYTES: usize = 131_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRouteLayer {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRouteAction {
    Permit,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrictRouteRuleKind {
    AppPermitV4,
    AppPermitV6,
    TunPermitV4,
    TunPermitV6,
    FamilyBlockV4,
    FamilyBlockV6,
    DnsTcpBlockV4,
    DnsUdpBlockV4,
    DnsTcpBlockV6,
    DnsUdpBlockV6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StrictRouteCondition {
    AppId(Box<[u8]>),
    LocalInterfaceLuid(u64),
    IpProtocol(u8),
    RemotePort(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StrictRouteRule {
    pub(crate) kind: StrictRouteRuleKind,
    pub(crate) layer: StrictRouteLayer,
    pub(crate) action: StrictRouteAction,
    pub(crate) weight: u8,
    pub(crate) conditions: Box<[StrictRouteCondition]>,
}

pub(crate) fn strict_route_rules(
    has_ipv4: bool,
    has_ipv6: bool,
    has_managed_dns: bool,
    app_id: &[u8],
    interface_luid: u64,
) -> Result<Vec<StrictRouteRule>, Error> {
    if (!has_ipv4 && !has_ipv6)
        || app_id.is_empty()
        || app_id.len() > MAX_WFP_APP_ID_BYTES
        || interface_luid == 0
    {
        return Err(Error::new(ErrorKind::InvalidInput));
    }
    let mut rules = Vec::with_capacity(10);
    let mut push = |kind, layer, action, weight, conditions| {
        rules.push(StrictRouteRule {
            kind,
            layer,
            action,
            weight,
            conditions,
        });
    };
    push(
        StrictRouteRuleKind::AppPermitV4,
        StrictRouteLayer::V4,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::AppId(app_id.into())]),
    );
    push(
        StrictRouteRuleKind::AppPermitV6,
        StrictRouteLayer::V6,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::AppId(app_id.into())]),
    );
    push(
        StrictRouteRuleKind::TunPermitV4,
        StrictRouteLayer::V4,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::LocalInterfaceLuid(interface_luid)]),
    );
    push(
        StrictRouteRuleKind::TunPermitV6,
        StrictRouteLayer::V6,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::LocalInterfaceLuid(interface_luid)]),
    );
    if !has_ipv4 {
        push(
            StrictRouteRuleKind::FamilyBlockV4,
            StrictRouteLayer::V4,
            StrictRouteAction::Block,
            STRICT_ROUTE_BLOCK_WEIGHT,
            Box::new([]),
        );
    }
    if !has_ipv6 {
        push(
            StrictRouteRuleKind::FamilyBlockV6,
            StrictRouteLayer::V6,
            StrictRouteAction::Block,
            STRICT_ROUTE_BLOCK_WEIGHT,
            Box::new([]),
        );
    }
    if has_managed_dns {
        for (kind, layer, protocol) in [
            (StrictRouteRuleKind::DnsTcpBlockV4, StrictRouteLayer::V4, 6),
            (StrictRouteRuleKind::DnsUdpBlockV4, StrictRouteLayer::V4, 17),
            (StrictRouteRuleKind::DnsTcpBlockV6, StrictRouteLayer::V6, 6),
            (StrictRouteRuleKind::DnsUdpBlockV6, StrictRouteLayer::V6, 17),
        ] {
            push(
                kind,
                layer,
                StrictRouteAction::Block,
                STRICT_ROUTE_BLOCK_WEIGHT,
                Box::new([
                    StrictRouteCondition::IpProtocol(protocol),
                    StrictRouteCondition::RemotePort(53),
                ]),
            );
        }
    }
    Ok(rules)
}

/// Bounded semantic observation of the production strict-route rule plan for fuzzing.
#[cfg(feature = "fuzzing")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictRouteRulePlanObservation {
    rule_count: usize,
    permit_count: usize,
    block_count: usize,
    app_id_condition_count: usize,
    interface_condition_count: usize,
    dns_protocol_condition_count: usize,
    dns_port_condition_count: usize,
    empty_condition_count: usize,
}

#[cfg(feature = "fuzzing")]
impl StrictRouteRulePlanObservation {
    pub const fn rule_count(self) -> usize {
        self.rule_count
    }

    pub const fn permit_count(self) -> usize {
        self.permit_count
    }

    pub const fn block_count(self) -> usize {
        self.block_count
    }

    pub const fn app_id_condition_count(self) -> usize {
        self.app_id_condition_count
    }

    pub const fn interface_condition_count(self) -> usize {
        self.interface_condition_count
    }

    pub const fn dns_protocol_condition_count(self) -> usize {
        self.dns_protocol_condition_count
    }

    pub const fn dns_port_condition_count(self) -> usize {
        self.dns_port_condition_count
    }

    pub const fn empty_condition_count(self) -> usize {
        self.empty_condition_count
    }
}

/// Calls the production strict-route rule builder and returns identity-free plan counts.
#[cfg(feature = "fuzzing")]
pub fn fuzz_strict_route_rule_plan(
    has_ipv4: bool,
    has_ipv6: bool,
    has_managed_dns: bool,
    app_id: &[u8],
    interface_luid: u64,
) -> Result<StrictRouteRulePlanObservation, Error> {
    let rules = strict_route_rules(has_ipv4, has_ipv6, has_managed_dns, app_id, interface_luid)?;
    Ok(StrictRouteRulePlanObservation {
        rule_count: rules.len(),
        permit_count: rules
            .iter()
            .filter(|rule| rule.action == StrictRouteAction::Permit)
            .count(),
        block_count: rules
            .iter()
            .filter(|rule| rule.action == StrictRouteAction::Block)
            .count(),
        app_id_condition_count: rules
            .iter()
            .flat_map(|rule| rule.conditions.iter())
            .filter(|condition| matches!(condition, StrictRouteCondition::AppId(_)))
            .count(),
        interface_condition_count: rules
            .iter()
            .flat_map(|rule| rule.conditions.iter())
            .filter(|condition| matches!(condition, StrictRouteCondition::LocalInterfaceLuid(_)))
            .count(),
        dns_protocol_condition_count: rules
            .iter()
            .flat_map(|rule| rule.conditions.iter())
            .filter(|condition| matches!(condition, StrictRouteCondition::IpProtocol(6 | 17)))
            .count(),
        dns_port_condition_count: rules
            .iter()
            .flat_map(|rule| rule.conditions.iter())
            .filter(|condition| matches!(condition, StrictRouteCondition::RemotePort(53)))
            .count(),
        empty_condition_count: rules
            .iter()
            .filter(|rule| rule.conditions.is_empty())
            .count(),
    })
}

#[cfg(feature = "fuzzing")]
pub const FUZZ_MAX_WFP_APP_ID_BYTES: usize = MAX_WFP_APP_ID_BYTES;
