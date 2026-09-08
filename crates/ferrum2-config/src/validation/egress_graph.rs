use std::collections::{HashMap, HashSet};

use crate::dependency::DependencyNode;
use crate::error::{ConfigError, ConfigField};
use crate::prepared::PreparedEgressRef;
use crate::raw::{RawChain, RawClientRoot, RawDns, RawRoute, RawSelector, RawServerRoot};

use super::common::{validate_count, validate_tag};

struct OutboundInput<'a> {
    tag: &'a str,
    is_direct: bool,
    is_f2p: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VisitState {
    Unvisited,
    Active,
    Complete,
}

/// Admitted, immutable egress topology. Construction precedes endpoint/DNS drafts;
/// consumers cannot derive paths from unbounded or unresolved raw declarations.
pub(crate) struct AdmittedEgressGraph {
    tags: HashMap<String, PreparedEgressRef>,
    outbounds: usize,
    selectors: Vec<Vec<PreparedEgressRef>>,
    chains: Vec<Vec<usize>>,
    first_hops: Vec<u64>,
    domain_targets: Vec<bool>,
}

impl AdmittedEgressGraph {
    pub(crate) fn client(raw: &RawClientRoot) -> Result<Self, ConfigError> {
        let inbounds = raw.inbounds.as_deref().unwrap_or(&[]);
        validate_count(
            inbounds.len() + usize::from(raw.tun.is_some()),
            ConfigField::Inbounds,
        )?;
        let outbounds = raw.outbounds.as_deref().unwrap_or(&[]);
        validate_count(outbounds.len(), ConfigField::Outbounds)?;
        admit_cohorts(raw.selectors.as_deref(), raw.chains.as_deref())?;
        admit_resources(raw.dns.as_ref(), raw.route.as_ref(), DnsRole::Client)?;
        if let Some(tun) = &raw.tun {
            validate_tag(&tun.tag, ConfigField::TunTag)?;
        }
        Self::build(
            inbounds
                .iter()
                .map(|inbound| inbound.tag.as_str())
                .chain(raw.tun.iter().map(|tun| tun.tag.as_str())),
            outbounds.iter().map(|outbound| OutboundInput {
                tag: outbound.tag.as_str(),
                is_direct: outbound.outbound_type.as_deref() == Some("direct"),
                is_f2p: outbound.outbound_type.as_deref() == Some("f2p"),
            }),
            raw.selectors.as_deref().unwrap_or(&[]),
            raw.chains.as_deref().unwrap_or(&[]),
        )
    }

    pub(crate) fn server(raw: &RawServerRoot) -> Result<Self, ConfigError> {
        if raw.tun.is_some() {
            return Err(ConfigError::semantic(ConfigField::Tun));
        }
        if raw.chains.is_some() {
            return Err(ConfigError::semantic(ConfigField::Chains));
        }
        let inbounds = raw.inbounds.as_deref().unwrap_or(&[]);
        let outbounds = raw.outbounds.as_deref().unwrap_or(&[]);
        validate_count(inbounds.len(), ConfigField::Inbounds)?;
        validate_count(outbounds.len(), ConfigField::Outbounds)?;
        admit_cohorts(raw.selectors.as_deref(), None)?;
        admit_resources(raw.dns.as_ref(), raw.route.as_ref(), DnsRole::Server)?;
        Self::build(
            inbounds.iter().map(|inbound| inbound.tag.as_str()),
            outbounds.iter().map(|outbound| OutboundInput {
                tag: outbound.tag.as_str(),
                is_direct: true,
                is_f2p: false,
            }),
            raw.selectors.as_deref().unwrap_or(&[]),
            &[],
        )
    }

    fn build<'a>(
        inbounds: impl Iterator<Item = &'a str>,
        outbounds: impl Iterator<Item = OutboundInput<'a>>,
        selectors: &'a [RawSelector],
        chains: &'a [RawChain],
    ) -> Result<Self, ConfigError> {
        let mut identities = HashSet::new();
        for tag in inbounds {
            validate_tag(tag, ConfigField::InboundsTag)?;
            if !identities.insert(tag) {
                return Err(ConfigError::semantic(ConfigField::InboundsTag));
            }
        }
        let mut tags = HashMap::new();
        let mut direct = Vec::new();
        let mut f2p = 0_u64;
        for (
            index,
            OutboundInput {
                tag,
                is_direct,
                is_f2p,
            },
        ) in outbounds.enumerate()
        {
            validate_tag(tag, ConfigField::OutboundsTag)?;
            if !identities.insert(tag) {
                return Err(ConfigError::semantic(ConfigField::OutboundsTag));
            }
            tags.insert(tag.to_owned(), PreparedEgressRef::Outbound(index));
            direct.push(is_direct);
            if is_f2p {
                f2p |= 1_u64 << index;
            }
        }
        for (index, chain) in chains.iter().enumerate() {
            let tag = chain
                .tag
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::Chains))?;
            validate_tag(tag, ConfigField::ChainsTag)?;
            if !identities.insert(tag) {
                return Err(ConfigError::semantic(ConfigField::ChainsTag));
            }
            tags.insert(tag.to_owned(), PreparedEgressRef::Chain(index));
        }
        for (index, selector) in selectors.iter().enumerate() {
            validate_tag(&selector.tag, ConfigField::SelectorsTag)?;
            if !identities.insert(&selector.tag) {
                return Err(ConfigError::semantic(ConfigField::SelectorsTag));
            }
            tags.insert(selector.tag.clone(), PreparedEgressRef::Selector(index));
        }
        let count = direct.len() + selectors.len() + chains.len();
        let mut graph = Self {
            tags,
            outbounds: direct.len(),
            selectors: Vec::with_capacity(selectors.len()),
            chains: Vec::with_capacity(chains.len()),
            first_hops: vec![0; count],
            domain_targets: vec![false; count],
        };
        for (index, chain) in chains.iter().enumerate() {
            let hops = chain
                .hops
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?;
            let mut typed = Vec::with_capacity(hops.len());
            let mut seen = 0_u64;
            for hop in hops {
                let PreparedEgressRef::Outbound(outbound) =
                    graph.resolve(hop, ConfigField::ChainsHops)?
                else {
                    return Err(ConfigError::semantic(ConfigField::ChainsHops));
                };
                let bit = 1_u64 << outbound;
                if direct[outbound] || f2p & bit != 0 || seen & bit != 0 {
                    return Err(ConfigError::semantic(ConfigField::ChainsHops));
                }
                seen |= bit;
                typed.push(outbound);
            }
            // Chain admission has already required two to eight concrete hops.
            graph.first_hops[direct.len() + selectors.len() + index] = 1_u64 << typed[0];
            graph.chains.push(typed);
        }
        for selector in selectors {
            let mut members = Vec::with_capacity(selector.outbounds.len());
            let mut seen = [0_u64; 3];
            for member in &selector.outbounds {
                let member = graph.resolve(member, ConfigField::SelectorsOutbounds)?;
                let index = graph.node_index_with_selectors(member, selectors.len());
                let bit = 1_u64 << (index % 64);
                if seen[index / 64] & bit != 0 {
                    return Err(ConfigError::semantic(ConfigField::SelectorsOutbounds));
                }
                seen[index / 64] |= bit;
                members.push(member);
            }
            let default = selector
                .default
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::SelectorsDefault))?;
            let default = graph.resolve(default, ConfigField::SelectorsDefault)?;
            if !members.contains(&default) {
                return Err(ConfigError::semantic(ConfigField::SelectorsDefault));
            }
            graph.selectors.push(members);
        }
        // Every currently supported concrete outbound accepts a domain target.
        for index in 0..graph.outbounds {
            graph.first_hops[index] = 1_u64 << index;
            graph.domain_targets[index] = true;
        }
        for index in 0..graph.chains.len() {
            let terminal = *graph.chains[index].last().expect("admitted chain");
            let node = graph.node_index(PreparedEgressRef::Chain(index));
            graph.domain_targets[node] = graph.domain_targets[terminal];
        }
        graph.derive_selectors()?;
        Ok(graph)
    }

    fn derive_selectors(&mut self) -> Result<(), ConfigError> {
        let mut states = vec![VisitState::Unvisited; self.selectors.len()];
        let mut pending = Vec::with_capacity(self.selectors.len());
        for root in 0..self.selectors.len() {
            if states[root] == VisitState::Complete {
                continue;
            }
            states[root] = VisitState::Active;
            pending.push((root, 0));
            while let Some((node, member_index)) = pending.last_mut() {
                if let Some(member) = self.selectors[*node].get(*member_index).copied() {
                    *member_index += 1;
                    if let PreparedEgressRef::Selector(child) = member {
                        match states[child] {
                            VisitState::Unvisited => {
                                states[child] = VisitState::Active;
                                pending.push((child, 0));
                            }
                            VisitState::Active => {
                                let start = pending
                                    .iter()
                                    .position(|(node, _)| *node == child)
                                    .expect("active selector");
                                let mut path = pending[start..]
                                    .iter()
                                    .map(|(node, _)| DependencyNode::Selector(*node as u32))
                                    .collect::<Vec<_>>();
                                path.push(DependencyNode::Selector(child as u32));
                                return Err(ConfigError::dependency_cycle(path));
                            }
                            VisitState::Complete => {}
                        }
                    }
                    continue;
                }
                let node = *node;
                let mut first = 0;
                let mut domain = true;
                for member in &self.selectors[node] {
                    first |= self.first_hops(*member);
                    domain &= self.accepts_domain(*member);
                }
                let index = self.node_index(PreparedEgressRef::Selector(node));
                self.first_hops[index] = first;
                self.domain_targets[index] = domain;
                states[node] = VisitState::Complete;
                pending.pop();
            }
        }
        Ok(())
    }

    fn node_index_with_selectors(&self, egress: PreparedEgressRef, selectors: usize) -> usize {
        match egress {
            PreparedEgressRef::Outbound(index) => index,
            PreparedEgressRef::Selector(index) => self.outbounds + index,
            PreparedEgressRef::Chain(index) => self.outbounds + selectors + index,
        }
    }

    fn node_index(&self, egress: PreparedEgressRef) -> usize {
        self.node_index_with_selectors(egress, self.selectors.len())
    }

    pub(crate) fn resolve(
        &self,
        tag: &str,
        field: ConfigField,
    ) -> Result<PreparedEgressRef, ConfigError> {
        validate_tag(tag, field)?;
        self.tags
            .get(tag)
            .copied()
            .ok_or_else(|| ConfigError::semantic(field))
    }

    pub(crate) fn selector_members(&self) -> &[Vec<PreparedEgressRef>] {
        &self.selectors
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.outbounds
    }

    pub(crate) fn chain_hops(&self) -> &[Vec<usize>] {
        &self.chains
    }

    pub(crate) fn first_hops(&self, egress: PreparedEgressRef) -> u64 {
        self.first_hops[self.node_index(egress)]
    }

    pub(crate) fn accepts_domain(&self, egress: PreparedEgressRef) -> bool {
        self.domain_targets[self.node_index(egress)]
    }
}

fn admit_cohorts(
    selectors: Option<&[RawSelector]>,
    chains: Option<&[RawChain]>,
) -> Result<(), ConfigError> {
    if let Some(selectors) = selectors {
        validate_count(selectors.len(), ConfigField::Selectors)?;
        for selector in selectors {
            validate_count(selector.outbounds.len(), ConfigField::SelectorsOutbounds)?;
        }
    }
    if let Some(chains) = chains {
        validate_count(chains.len(), ConfigField::Chains)?;
        for chain in chains {
            let hops = chain
                .hops
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?;
            if !(2..=8).contains(&hops.len()) {
                return Err(ConfigError::semantic(ConfigField::ChainsHops));
            }
        }
    }
    Ok(())
}

enum DnsRole {
    Client,
    Server,
}

fn admit_resources(
    dns: Option<&RawDns>,
    route: Option<&RawRoute>,
    role: DnsRole,
) -> Result<(), ConfigError> {
    let rule_set_count = route.map_or(0, |route| route.rule_set.len());
    if rule_set_count != 0 {
        validate_count(rule_set_count, ConfigField::RouteRuleSet)?;
    }
    let Some(dns) = dns else {
        return Ok(());
    };
    match (role, dns.inbounds.as_deref()) {
        (DnsRole::Client, Some(inbounds)) => {
            validate_count(inbounds.len(), ConfigField::DnsInbounds)?
        }
        (DnsRole::Server, None) => {}
        (DnsRole::Client, None) | (DnsRole::Server, Some(_)) => {
            return Err(ConfigError::semantic(ConfigField::DnsInbounds));
        }
    }
    validate_count(
        dns.servers.as_deref().map_or(0, <[_]>::len),
        ConfigField::DnsServers,
    )
}

#[cfg(test)]
mod tests;
