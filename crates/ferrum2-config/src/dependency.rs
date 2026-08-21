//! Redacted dependency graph for fixed-endpoint materialization.
//!
//! An edge points from a resource to a resource that must be materialized
//! first. Consequently, [`DependencyGraph::topological_order`] returns
//! dependencies before their users.

use std::error::Error;
use std::fmt;

/// Stable, non-secret dependency-node category.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum DependencyNodeKind {
    SystemResolver,
    DnsServer,
    Outbound,
    Selector,
    Chain,
    RuleSet,
}

/// One dependency node identified only by its category and stable list index.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DependencyNode {
    SystemResolver,
    DnsServer(u32),
    Outbound(u32),
    Selector(u32),
    Chain(u32),
    RuleSet(u32),
}

impl DependencyNode {
    pub(crate) const fn system_resolver() -> Self {
        Self::SystemResolver
    }

    pub(crate) fn try_dns_server(index: u64) -> Result<Self, DependencyGraphError> {
        checked_index(index, DependencyNodeKind::DnsServer).map(Self::DnsServer)
    }

    pub(crate) fn try_outbound(index: u64) -> Result<Self, DependencyGraphError> {
        checked_index(index, DependencyNodeKind::Outbound).map(Self::Outbound)
    }

    pub(crate) fn try_selector(index: u64) -> Result<Self, DependencyGraphError> {
        checked_index(index, DependencyNodeKind::Selector).map(Self::Selector)
    }

    pub(crate) fn try_chain(index: u64) -> Result<Self, DependencyGraphError> {
        checked_index(index, DependencyNodeKind::Chain).map(Self::Chain)
    }

    pub(crate) fn try_rule_set(index: u64) -> Result<Self, DependencyGraphError> {
        checked_index(index, DependencyNodeKind::RuleSet).map(Self::RuleSet)
    }

    #[allow(dead_code)]
    pub(crate) const fn kind(self) -> DependencyNodeKind {
        match self {
            Self::SystemResolver => DependencyNodeKind::SystemResolver,
            Self::DnsServer(_) => DependencyNodeKind::DnsServer,
            Self::Outbound(_) => DependencyNodeKind::Outbound,
            Self::Selector(_) => DependencyNodeKind::Selector,
            Self::Chain(_) => DependencyNodeKind::Chain,
            Self::RuleSet(_) => DependencyNodeKind::RuleSet,
        }
    }

    pub(crate) const fn index(self) -> Option<u32> {
        match self {
            Self::SystemResolver => None,
            Self::DnsServer(index)
            | Self::Outbound(index)
            | Self::Selector(index)
            | Self::Chain(index)
            | Self::RuleSet(index) => Some(index),
        }
    }
}

impl fmt::Display for DependencyNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemResolver => formatter.write_str("system-resolver"),
            Self::DnsServer(index) => write!(formatter, "dns-server[{index}]"),
            Self::Outbound(index) => write!(formatter, "outbound[{index}]"),
            Self::Selector(index) => write!(formatter, "selector[{index}]"),
            Self::Chain(index) => write!(formatter, "chain[{index}]"),
            Self::RuleSet(index) => write!(formatter, "rule-set[{index}]"),
        }
    }
}

fn checked_index(index: u64, kind: DependencyNodeKind) -> Result<u32, DependencyGraphError> {
    u32::try_from(index).map_err(|_| DependencyGraphError::IndexOverflow { kind })
}

/// Safe origin metadata for one dependency edge.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DependencySource {
    DnsServerDomainResolver { server: u32 },
    DnsServerDetour { server: u32 },
    OutboundDomainResolver { outbound: u32 },
    SelectorMember { selector: u32, member: u32 },
    ChainHop { chain: u32, hop: u32 },
    RuleSetDownloadResolver { rule_set: u32 },
    RuleSetDownloadDetour { rule_set: u32 },
}

impl DependencySource {
    const fn owner(self) -> DependencyNode {
        match self {
            Self::DnsServerDomainResolver { server } | Self::DnsServerDetour { server } => {
                DependencyNode::DnsServer(server)
            }
            Self::OutboundDomainResolver { outbound } => DependencyNode::Outbound(outbound),
            Self::SelectorMember { selector, .. } => DependencyNode::Selector(selector),
            Self::ChainHop { chain, .. } => DependencyNode::Chain(chain),
            Self::RuleSetDownloadResolver { rule_set }
            | Self::RuleSetDownloadDetour { rule_set } => DependencyNode::RuleSet(rule_set),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DependencyEdge {
    from: DependencyNode,
    to: DependencyNode,
    source: DependencySource,
}

/// A complete, closed dependency cycle containing no configuration values.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DependencyCycle {
    path: Vec<DependencyNode>,
}

impl DependencyCycle {
    #[cfg(test)]
    pub(crate) fn path(&self) -> &[DependencyNode] {
        &self.path
    }

    pub(crate) fn into_path(self) -> Vec<DependencyNode> {
        self.path
    }
}

impl fmt::Display for DependencyCycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("dependency cycle: ")?;
        for (index, node) in self.path.iter().enumerate() {
            if index != 0 {
                formatter.write_str(" -> ")?;
            }
            node.fmt(formatter)?;
        }
        Ok(())
    }
}

/// Closed failure set for dependency-graph construction and validation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DependencyGraphError {
    Allocation,
    IndexOverflow {
        kind: DependencyNodeKind,
    },
    SystemResolverHasDependency,
    SourceOwnerMismatch {
        from: DependencyNode,
        owner: DependencyNode,
    },
    Cycle(DependencyCycle),
    Inconsistent,
}

impl DependencyGraphError {
    #[cfg(test)]
    pub(crate) fn cycle(&self) -> Option<&DependencyCycle> {
        match self {
            Self::Cycle(cycle) => Some(cycle),
            _ => None,
        }
    }
}

impl fmt::Display for DependencyGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("dependency graph allocation failed"),
            Self::IndexOverflow { kind } => {
                write!(formatter, "dependency graph {kind:?} index is out of range")
            }
            Self::SystemResolverHasDependency => {
                formatter.write_str("system resolver must be a terminal dependency")
            }
            Self::SourceOwnerMismatch { from, owner } => write!(
                formatter,
                "dependency edge source owner mismatch: {from} != {owner}"
            ),
            Self::Cycle(cycle) => cycle.fmt(formatter),
            Self::Inconsistent => formatter.write_str("dependency graph is inconsistent"),
        }
    }
}

impl Error for DependencyGraphError {}

/// Fallibly-built dependency graph with stable, insertion-independent results.
#[derive(Default)]
pub(crate) struct DependencyGraph {
    nodes: Vec<DependencyNode>,
    edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    pub(crate) const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Adds an isolated node. Repeated node declarations are idempotent.
    pub(crate) fn try_add_node(
        &mut self,
        node: DependencyNode,
    ) -> Result<(), DependencyGraphError> {
        if self.nodes.contains(&node) {
            return Ok(());
        }
        self.nodes
            .try_reserve(1)
            .map_err(|_| DependencyGraphError::Allocation)?;
        self.nodes.push(node);
        Ok(())
    }

    /// Adds one `from depends on to` edge and both endpoint nodes.
    pub(crate) fn try_add_edge(
        &mut self,
        from: DependencyNode,
        to: DependencyNode,
        source: DependencySource,
    ) -> Result<(), DependencyGraphError> {
        if from == DependencyNode::SystemResolver {
            return Err(DependencyGraphError::SystemResolverHasDependency);
        }
        let owner = source.owner();
        if owner != from {
            return Err(DependencyGraphError::SourceOwnerMismatch { from, owner });
        }
        let edge = DependencyEdge { from, to, source };
        if self.edges.contains(&edge) {
            return Ok(());
        }

        let from_missing = !self.nodes.contains(&from);
        let to_missing = to != from && !self.nodes.contains(&to);
        let missing = usize::from(from_missing) + usize::from(to_missing);
        self.nodes
            .try_reserve(missing)
            .map_err(|_| DependencyGraphError::Allocation)?;
        self.edges
            .try_reserve(1)
            .map_err(|_| DependencyGraphError::Allocation)?;
        if from_missing {
            self.nodes.push(from);
        }
        if to_missing {
            self.nodes.push(to);
        }
        self.edges.push(edge);
        Ok(())
    }

    /// Adds every selector member, including non-default members.
    pub(crate) fn try_add_selector_members<I>(
        &mut self,
        selector_index: u64,
        members: I,
    ) -> Result<(), DependencyGraphError>
    where
        I: IntoIterator<Item = DependencyNode>,
    {
        let selector = DependencyNode::try_selector(selector_index)?;
        self.try_add_node(selector)?;
        let selector_index = selector.index().ok_or(DependencyGraphError::Inconsistent)?;
        for (member, target) in members.into_iter().enumerate() {
            let member =
                u32::try_from(member).map_err(|_| DependencyGraphError::IndexOverflow {
                    kind: DependencyNodeKind::Selector,
                })?;
            self.try_add_edge(
                selector,
                target,
                DependencySource::SelectorMember {
                    selector: selector_index,
                    member,
                },
            )?;
        }
        Ok(())
    }

    /// Adds every chain hop, including intermediate hops.
    pub(crate) fn try_add_chain_hops<I>(
        &mut self,
        chain_index: u64,
        hops: I,
    ) -> Result<(), DependencyGraphError>
    where
        I: IntoIterator<Item = DependencyNode>,
    {
        let chain = DependencyNode::try_chain(chain_index)?;
        self.try_add_node(chain)?;
        let chain_index = chain.index().ok_or(DependencyGraphError::Inconsistent)?;
        for (hop, target) in hops.into_iter().enumerate() {
            let hop = u32::try_from(hop).map_err(|_| DependencyGraphError::IndexOverflow {
                kind: DependencyNodeKind::Chain,
            })?;
            self.try_add_edge(
                chain,
                target,
                DependencySource::ChainHop {
                    chain: chain_index,
                    hop,
                },
            )?;
        }
        Ok(())
    }

    /// Verifies acyclicity without retaining a topological result.
    ///
    /// Call this after adding every node and edge and before any network I/O.
    #[allow(dead_code)]
    pub(crate) fn validate_acyclic(&self) -> Result<(), DependencyGraphError> {
        self.topological_order().map(drop)
    }

    /// Returns a deterministic dependency-first topological order.
    ///
    /// Call this after adding every node and edge and before any network I/O.
    pub(crate) fn topological_order(&self) -> Result<Vec<DependencyNode>, DependencyGraphError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(self.nodes.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        nodes.extend_from_slice(&self.nodes);
        nodes.sort_unstable();

        let mut forward = Vec::new();
        forward
            .try_reserve_exact(self.edges.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        for edge in &self.edges {
            let from = nodes
                .binary_search(&edge.from)
                .map_err(|_| DependencyGraphError::Inconsistent)?;
            let to = nodes
                .binary_search(&edge.to)
                .map_err(|_| DependencyGraphError::Inconsistent)?;
            forward.push((from, to));
        }
        forward.sort_unstable();
        forward.dedup();

        let mut reverse = Vec::new();
        reverse
            .try_reserve_exact(forward.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        reverse.extend(forward.iter().map(|(from, to)| (*to, *from)));
        reverse.sort_unstable();

        let mut remaining_dependencies = Vec::new();
        remaining_dependencies
            .try_reserve_exact(nodes.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        remaining_dependencies.resize(nodes.len(), 0_usize);
        for &(from, _) in &forward {
            remaining_dependencies[from] = remaining_dependencies[from]
                .checked_add(1)
                .ok_or(DependencyGraphError::Inconsistent)?;
        }

        let mut ready = Vec::new();
        ready
            .try_reserve_exact(nodes.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        ready.extend(
            remaining_dependencies
                .iter()
                .enumerate()
                .filter_map(|(index, dependencies)| (*dependencies == 0).then_some(index)),
        );
        ready.sort_unstable_by(|left, right| right.cmp(left));

        let mut ordered = Vec::new();
        ordered
            .try_reserve_exact(nodes.len())
            .map_err(|_| DependencyGraphError::Allocation)?;
        while let Some(node) = ready.pop() {
            ordered.push(nodes[node]);
            let start = reverse.partition_point(|(dependency, _)| *dependency < node);
            let end = reverse.partition_point(|(dependency, _)| *dependency <= node);
            for &(_, dependent) in &reverse[start..end] {
                remaining_dependencies[dependent] = remaining_dependencies[dependent]
                    .checked_sub(1)
                    .ok_or(DependencyGraphError::Inconsistent)?;
                if remaining_dependencies[dependent] == 0 {
                    insert_ready(&mut ready, dependent);
                }
            }
        }

        if ordered.len() == nodes.len() {
            return Ok(ordered);
        }
        let cycle = find_cycle(&nodes, &forward, &remaining_dependencies)?
            .ok_or(DependencyGraphError::Inconsistent)?;
        Err(DependencyGraphError::Cycle(cycle))
    }
}

fn insert_ready(ready: &mut Vec<usize>, node: usize) {
    let position = ready.partition_point(|candidate| *candidate > node);
    ready.insert(position, node);
}

#[derive(Clone, Copy)]
struct DfsFrame {
    node: usize,
    next: usize,
    end: usize,
}

fn find_cycle(
    nodes: &[DependencyNode],
    forward: &[(usize, usize)],
    remaining_dependencies: &[usize],
) -> Result<Option<DependencyCycle>, DependencyGraphError> {
    let mut colors = Vec::new();
    colors
        .try_reserve_exact(nodes.len())
        .map_err(|_| DependencyGraphError::Allocation)?;
    colors.extend(
        remaining_dependencies
            .iter()
            .map(|remaining| if *remaining == 0 { 2_u8 } else { 0_u8 }),
    );
    let mut positions = Vec::new();
    positions
        .try_reserve_exact(nodes.len())
        .map_err(|_| DependencyGraphError::Allocation)?;
    positions.resize(nodes.len(), usize::MAX);
    let mut path = Vec::new();
    path.try_reserve_exact(nodes.len())
        .map_err(|_| DependencyGraphError::Allocation)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(nodes.len())
        .map_err(|_| DependencyGraphError::Allocation)?;

    for start_node in 0..nodes.len() {
        if colors[start_node] != 0 {
            continue;
        }
        push_frame(
            start_node,
            forward,
            &mut colors,
            &mut positions,
            &mut path,
            &mut frames,
        );
        while let Some(frame) = frames.last_mut() {
            if frame.next == frame.end {
                let completed = frame.node;
                frames.pop();
                let popped = path.pop().ok_or(DependencyGraphError::Inconsistent)?;
                if popped != completed {
                    return Err(DependencyGraphError::Inconsistent);
                }
                positions[completed] = usize::MAX;
                colors[completed] = 2;
                continue;
            }

            let target = forward[frame.next].1;
            frame.next += 1;
            match colors[target] {
                0 => push_frame(
                    target,
                    forward,
                    &mut colors,
                    &mut positions,
                    &mut path,
                    &mut frames,
                ),
                1 => {
                    let cycle_start = positions[target];
                    if cycle_start == usize::MAX || cycle_start >= path.len() {
                        return Err(DependencyGraphError::Inconsistent);
                    }
                    let mut cycle_path = Vec::new();
                    let cycle_len = path
                        .len()
                        .checked_sub(cycle_start)
                        .and_then(|length| length.checked_add(1))
                        .ok_or(DependencyGraphError::Inconsistent)?;
                    cycle_path
                        .try_reserve_exact(cycle_len)
                        .map_err(|_| DependencyGraphError::Allocation)?;
                    cycle_path.extend(path[cycle_start..].iter().map(|index| nodes[*index]));
                    cycle_path.push(nodes[target]);
                    return Ok(Some(DependencyCycle { path: cycle_path }));
                }
                2 => {}
                _ => return Err(DependencyGraphError::Inconsistent),
            }
        }
    }
    Ok(None)
}

fn push_frame(
    node: usize,
    forward: &[(usize, usize)],
    colors: &mut [u8],
    positions: &mut [usize],
    path: &mut Vec<usize>,
    frames: &mut Vec<DfsFrame>,
) {
    colors[node] = 1;
    positions[node] = path.len();
    path.push(node);
    let start = forward.partition_point(|(from, _)| *from < node);
    let end = forward.partition_point(|(from, _)| *from <= node);
    frames.push(DfsFrame {
        node,
        next: start,
        end,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(index: u64) -> DependencyNode {
        DependencyNode::try_dns_server(index).expect("test DNS index")
    }

    fn outbound(index: u64) -> DependencyNode {
        DependencyNode::try_outbound(index).expect("test outbound index")
    }

    fn selector(index: u64) -> DependencyNode {
        DependencyNode::try_selector(index).expect("test selector index")
    }

    fn chain(index: u64) -> DependencyNode {
        DependencyNode::try_chain(index).expect("test chain index")
    }

    fn rule_set(index: u64) -> DependencyNode {
        DependencyNode::try_rule_set(index).expect("test RuleSet index")
    }

    #[test]
    fn self_cycle_reports_a_closed_redacted_path() {
        let mut graph = DependencyGraph::new();
        graph
            .try_add_edge(
                dns(7),
                dns(7),
                DependencySource::DnsServerDomainResolver { server: 7 },
            )
            .unwrap();

        let error = graph.validate_acyclic().unwrap_err();
        let cycle = error.cycle().expect("cycle");
        assert_eq!(cycle.path(), &[dns(7), dns(7)]);
        assert_eq!(
            error.to_string(),
            "dependency cycle: dns-server[7] -> dns-server[7]"
        );
    }

    #[test]
    fn multi_node_cycle_is_complete_and_insertion_independent() {
        let edges = [
            (
                outbound(4),
                dns(2),
                DependencySource::OutboundDomainResolver { outbound: 4 },
            ),
            (
                selector(3),
                outbound(4),
                DependencySource::SelectorMember {
                    selector: 3,
                    member: 0,
                },
            ),
            (
                dns(2),
                selector(3),
                DependencySource::DnsServerDetour { server: 2 },
            ),
        ];
        let expected = [dns(2), selector(3), outbound(4), dns(2)];

        for reversed in [false, true] {
            let mut graph = DependencyGraph::new();
            if reversed {
                for edge in edges.into_iter().rev() {
                    graph.try_add_edge(edge.0, edge.1, edge.2).unwrap();
                }
            } else {
                for edge in edges {
                    graph.try_add_edge(edge.0, edge.1, edge.2).unwrap();
                }
            }
            assert_eq!(
                graph
                    .topological_order()
                    .unwrap_err()
                    .cycle()
                    .unwrap()
                    .path(),
                expected
            );
        }
    }

    #[test]
    fn selector_checks_every_member_not_only_the_default() {
        let mut graph = DependencyGraph::new();
        graph
            .try_add_selector_members(0, [outbound(0), outbound(1)])
            .unwrap();
        graph
            .try_add_edge(
                outbound(1),
                dns(0),
                DependencySource::OutboundDomainResolver { outbound: 1 },
            )
            .unwrap();
        graph
            .try_add_edge(
                dns(0),
                selector(0),
                DependencySource::DnsServerDetour { server: 0 },
            )
            .unwrap();

        assert_eq!(
            graph
                .validate_acyclic()
                .unwrap_err()
                .cycle()
                .unwrap()
                .path(),
            &[dns(0), selector(0), outbound(1), dns(0)]
        );
    }

    #[test]
    fn chain_checks_every_hop_including_intermediate_hops() {
        let mut graph = DependencyGraph::new();
        graph
            .try_add_chain_hops(5, [outbound(0), outbound(1), outbound(2)])
            .unwrap();
        graph
            .try_add_edge(
                outbound(1),
                dns(0),
                DependencySource::OutboundDomainResolver { outbound: 1 },
            )
            .unwrap();
        graph
            .try_add_edge(
                dns(0),
                chain(5),
                DependencySource::DnsServerDetour { server: 0 },
            )
            .unwrap();

        assert_eq!(
            graph
                .validate_acyclic()
                .unwrap_err()
                .cycle()
                .unwrap()
                .path(),
            &[dns(0), chain(5), outbound(1), dns(0)]
        );
    }

    #[test]
    fn system_resolver_is_terminal_and_precedes_its_users() {
        assert_eq!(
            DependencyNode::SystemResolver.kind(),
            DependencyNodeKind::SystemResolver
        );
        let mut graph = DependencyGraph::new();
        graph
            .try_add_edge(
                dns(0),
                DependencyNode::system_resolver(),
                DependencySource::DnsServerDomainResolver { server: 0 },
            )
            .unwrap();
        assert_eq!(
            graph.topological_order().unwrap(),
            [DependencyNode::SystemResolver, dns(0)]
        );

        let error = graph
            .try_add_edge(
                DependencyNode::SystemResolver,
                dns(0),
                DependencySource::DnsServerDomainResolver { server: 0 },
            )
            .unwrap_err();
        assert_eq!(error, DependencyGraphError::SystemResolverHasDependency);
    }

    #[test]
    fn acyclic_order_is_dependency_first_and_deterministic() {
        let expected = [
            DependencyNode::SystemResolver,
            dns(0),
            outbound(0),
            outbound(1),
            selector(0),
            chain(0),
            rule_set(0),
        ];

        let build = |reverse: bool| {
            let mut graph = DependencyGraph::new();
            let edges = [
                (
                    dns(0),
                    DependencyNode::SystemResolver,
                    DependencySource::DnsServerDomainResolver { server: 0 },
                ),
                (
                    outbound(1),
                    dns(0),
                    DependencySource::OutboundDomainResolver { outbound: 1 },
                ),
                (
                    rule_set(0),
                    chain(0),
                    DependencySource::RuleSetDownloadDetour { rule_set: 0 },
                ),
                (
                    rule_set(0),
                    dns(0),
                    DependencySource::RuleSetDownloadResolver { rule_set: 0 },
                ),
            ];
            if reverse {
                for edge in edges.into_iter().rev() {
                    graph.try_add_edge(edge.0, edge.1, edge.2).unwrap();
                }
            } else {
                for edge in edges {
                    graph.try_add_edge(edge.0, edge.1, edge.2).unwrap();
                }
            }
            graph
                .try_add_selector_members(0, [outbound(1), outbound(0)])
                .unwrap();
            graph.try_add_chain_hops(0, [selector(0)]).unwrap();
            graph
        };

        assert_eq!(build(false).topological_order().unwrap(), expected);
        assert_eq!(build(true).topological_order().unwrap(), expected);
    }

    #[test]
    fn oversized_index_fails_closed() {
        let oversized = u64::from(u32::MAX) + 1;
        assert_eq!(
            DependencyNode::try_rule_set(oversized).unwrap_err(),
            DependencyGraphError::IndexOverflow {
                kind: DependencyNodeKind::RuleSet
            }
        );
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_parallel_sources_are_supported() {
        let mut graph = DependencyGraph::new();
        let endpoint = DependencyNode::SystemResolver;
        let resolver_source = DependencySource::DnsServerDomainResolver { server: 0 };
        graph
            .try_add_edge(dns(0), endpoint, resolver_source)
            .unwrap();
        graph
            .try_add_edge(dns(0), endpoint, resolver_source)
            .unwrap();
        assert_eq!(graph.edges.len(), 1);

        graph
            .try_add_edge(
                dns(0),
                endpoint,
                DependencySource::DnsServerDetour { server: 0 },
            )
            .unwrap();
        assert_eq!(graph.edges.len(), 2);
        assert_eq!(
            graph.topological_order().unwrap(),
            [DependencyNode::SystemResolver, dns(0)]
        );
    }
}
