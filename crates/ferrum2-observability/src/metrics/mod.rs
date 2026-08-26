mod core;
mod family;
mod render;
mod rules_dns;
mod tun;

use prometheus_client::registry::Registry;

pub use core::{Direction, Inbound};
pub use render::MetricsEncodeError;
pub use rules_dns::{
    CompiledMatchType, DnsQueryType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind,
    RuleMatchResult, RuleMatchType, RuleProgram, RuleProgramMode, RuleSetResult, RuleSource,
    TargetResolutionComponent, TargetResolutionMode,
};

/// Explicit owner of the stable networking, rules, and DNS metric families.
///
/// This type installs no global recorder and starts no listener or task.
pub struct Metrics {
    registry: Registry,
    core: core::CoreMetrics,
    tun: tun::TunMetrics,
    rules_dns: rules_dns::RulesDnsMetrics,
}

impl Metrics {
    /// Creates an isolated registry containing the stable metric families.
    ///
    /// Later releases may add families without removing or repurposing these.
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let core = core::CoreMetrics::register(&mut registry);
        let tun = tun::TunMetrics::register(&mut registry);
        let rules_dns = rules_dns::RulesDnsMetrics::register(&mut registry);
        Self {
            registry,
            core,
            tun,
            rules_dns,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
