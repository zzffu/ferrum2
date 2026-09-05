use std::net::{Ipv4Addr, Ipv6Addr};

use ferrum2_core::route::compile_egress_plans_with_roots;
use ferrum2_rule::{
    EgressPlanHandle, SelectorCompileError, SelectorControl, SelectorDefinition, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};

use crate::error::{ConfigError, ConfigField};
use crate::model::{OutboundDialOptions, RouteNetworkConfig};
use crate::raw::{RawRoute, RawSelector};

use super::MAX_INTERFACE_NAME_UTF16_UNITS;

pub(super) fn validate_route_network(
    raw: Option<&RawRoute>,
) -> Result<RouteNetworkConfig, ConfigError> {
    let Some(raw) = raw else {
        return Ok(RouteNetworkConfig::default());
    };
    let default_interface = validate_interface_name(
        raw.default_interface.as_deref(),
        ConfigField::RouteDefaultInterface,
    )?;
    Ok(RouteNetworkConfig {
        auto_detect_interface: raw.auto_detect_interface,
        default_interface,
    })
}

pub(super) fn validate_interface_name(
    raw: Option<&str>,
    field: ConfigField,
) -> Result<Option<Box<str>>, ConfigError> {
    raw.map(|name| {
        if name.is_empty()
            || name.encode_utf16().count() > MAX_INTERFACE_NAME_UTF16_UNITS
            || name.chars().any(char::is_control)
        {
            return Err(ConfigError::semantic(field));
        }
        Ok(name.to_owned().into_boxed_str())
    })
    .transpose()
}

pub(super) fn validate_outbound_dial_options(
    bind_interface: Option<&str>,
    inet4_bind_address: Option<&str>,
    inet6_bind_address: Option<&str>,
) -> Result<OutboundDialOptions, ConfigError> {
    Ok(OutboundDialOptions {
        bind_interface: validate_interface_name(
            bind_interface,
            ConfigField::OutboundsBindInterface,
        )?,
        inet4_bind_address: inet4_bind_address
            .map(|address| {
                address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| ConfigError::semantic(ConfigField::OutboundsInet4BindAddress))
            })
            .transpose()?,
        inet6_bind_address: inet6_bind_address
            .map(|address| {
                address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| ConfigError::semantic(ConfigField::OutboundsInet6BindAddress))
            })
            .transpose()?,
    })
}

pub(super) fn compile_graph_roots(
    inbounds: &[&str],
    outbounds: &[&str],
    selectors: &[RawSelector],
    plans: &[TaggedPlan<'_>],
    roots: &[&str],
    explicit_route: bool,
) -> Result<(SelectorControl, Vec<EgressPlanHandle>), ConfigError> {
    let tagged_inbounds = inbounds
        .iter()
        .enumerate()
        .map(|(index, tag)| TaggedInbound::new(tag, index))
        .collect::<Vec<_>>();
    let tagged_outbounds = outbounds
        .iter()
        .enumerate()
        .map(|(index, tag)| TaggedOutbound::new(tag, index))
        .collect::<Vec<_>>();
    let definitions = selectors
        .iter()
        .map(|selector| {
            SelectorDefinition::new(
                &selector.tag,
                selector.outbounds.iter().map(String::as_str).collect(),
                selector.default.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    compile_egress_plans_with_roots(
        &tagged_inbounds,
        &tagged_outbounds,
        plans,
        &definitions,
        roots,
    )
    .map_err(|error| match error {
        SelectorCompileError::Allocation => ConfigError::rule_allocation(ConfigField::RouteRules),
        SelectorCompileError::RuleCompile => ConfigError::rule_compile(ConfigField::RouteRules),
        SelectorCompileError::ExtraRoot => ConfigError::semantic(ConfigField::DnsServersDetour),
        _ => ConfigError::semantic(selector_error_field(error, explicit_route)),
    })
}

pub(super) const fn selector_error_field(error: SelectorCompileError, routed: bool) -> ConfigField {
    match error {
        SelectorCompileError::Allocation | SelectorCompileError::RuleCompile => {
            ConfigField::RouteRules
        }
        SelectorCompileError::Inbounds => ConfigField::InboundsTag,
        SelectorCompileError::Outbounds => ConfigField::OutboundsTag,
        SelectorCompileError::Plans => ConfigField::Chains,
        SelectorCompileError::PlanTag | SelectorCompileError::UnreachablePlan => {
            ConfigField::ChainsTag
        }
        SelectorCompileError::PlanHops => ConfigField::ChainsHops,
        SelectorCompileError::Selectors => ConfigField::Selectors,
        SelectorCompileError::SelectorTag | SelectorCompileError::UnreachableSelector => {
            ConfigField::SelectorsTag
        }
        SelectorCompileError::SelectorOutbounds => ConfigField::SelectorsOutbounds,
        SelectorCompileError::SelectorDefault => ConfigField::SelectorsDefault,
        SelectorCompileError::StaticBinding => ConfigField::InboundsOutbound,
        SelectorCompileError::RouteRules => ConfigField::RouteRules,
        SelectorCompileError::RouteRuleInbound => ConfigField::RouteRulesInbound,
        SelectorCompileError::RouteRuleOutbound => ConfigField::RouteRulesOutbound,
        SelectorCompileError::ExtraRoot => ConfigField::RouteRulesOutbound,
        SelectorCompileError::RouteFinal => ConfigField::RouteFinal,
        SelectorCompileError::UnreachableOutbound if routed => ConfigField::RouteRulesOutbound,
        SelectorCompileError::UnreachableOutbound => ConfigField::OutboundsTag,
    }
}
