use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_rule::{RuleEngineRegistry, RuleSetId};

/// Ordered selected IP endpoints for a prepared domain-valued DNS server.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedDnsEndpoint {
    pub(super) server: u32,
    pub(super) addresses: Box<[SocketAddr]>,
}

impl ResolvedDnsEndpoint {
    pub fn from_candidates(server: u32, addresses: Box<[SocketAddr]>) -> Self {
        Self { server, addresses }
    }

    pub const fn server(&self) -> u32 {
        self.server
    }

    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl std::fmt::Debug for ResolvedDnsEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedDnsEndpoint([redacted])")
    }
}

/// One selected IP endpoint for a prepared domain-valued client outbound.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResolvedOutboundEndpoint {
    pub(super) outbound: u32,
    pub(super) address: SocketAddr,
}

impl ResolvedOutboundEndpoint {
    pub const fn new(outbound: u32, address: SocketAddr) -> Self {
        Self { outbound, address }
    }

    pub const fn outbound(&self) -> u32 {
        self.outbound
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }
}

impl std::fmt::Debug for ResolvedOutboundEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedOutboundEndpoint([redacted])")
    }
}

/// One complete RuleSet registry resource with stable declaration-order identities.
pub struct CompiledRuleSetResource {
    pub(super) registry: Arc<RuleEngineRegistry>,
    pub(super) rule_set_ids: Arc<[RuleSetId]>,
}

impl CompiledRuleSetResource {
    pub fn new(registry: Arc<RuleEngineRegistry>, rule_set_ids: Box<[RuleSetId]>) -> Self {
        Self {
            registry,
            rule_set_ids: Arc::from(rule_set_ids),
        }
    }

    /// Shares declaration identities already bound by RuleSet materialization.
    pub fn from_shared(registry: Arc<RuleEngineRegistry>, rule_set_ids: Arc<[RuleSetId]>) -> Self {
        Self {
            registry,
            rule_set_ids,
        }
    }

    pub fn registry(&self) -> &Arc<RuleEngineRegistry> {
        &self.registry
    }

    pub fn rule_set_ids(&self) -> &[RuleSetId] {
        &self.rule_set_ids
    }
}

impl std::fmt::Debug for CompiledRuleSetResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CompiledRuleSetResource([redacted])")
    }
}

/// Complete, closed resource input for [`crate::finish_client_v2`].
#[derive(Debug, Default)]
pub struct ClientV2Resources {
    pub(super) dns_endpoints: Vec<ResolvedDnsEndpoint>,
    pub(super) outbound_endpoints: Vec<ResolvedOutboundEndpoint>,
    pub(super) rule_sets: Option<CompiledRuleSetResource>,
}

impl ClientV2Resources {
    pub const fn new(
        dns_endpoints: Vec<ResolvedDnsEndpoint>,
        outbound_endpoints: Vec<ResolvedOutboundEndpoint>,
        rule_sets: Option<CompiledRuleSetResource>,
    ) -> Self {
        Self {
            dns_endpoints,
            outbound_endpoints,
            rule_sets,
        }
    }
}

/// Complete, closed resource input for [`crate::finish_server_v2`].
#[derive(Debug, Default)]
pub struct ServerV2Resources {
    pub(super) dns_endpoints: Vec<ResolvedDnsEndpoint>,
    pub(super) rule_sets: Option<CompiledRuleSetResource>,
}

impl ServerV2Resources {
    pub const fn new(
        dns_endpoints: Vec<ResolvedDnsEndpoint>,
        rule_sets: Option<CompiledRuleSetResource>,
    ) -> Self {
        Self {
            dns_endpoints,
            rule_sets,
        }
    }
}
