use std::array;
use std::num::NonZeroU16;

use ferrum2_core::route::Network;
use ferrum2_rule::{
    MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories, PortRangeCandidateIndex,
    PortRangeCandidateIndexBuilder, RuleCompileError, RuleEngineSnapshot, RuleSetId,
    SparseValueIndex, SparseValueIndexBuilder,
};
use hickory_proto::rr::RecordType;

use crate::policy::{DnsPolicyQuery, DnsPolicyRule, is_address_qtype};

const FIELD_COUNT: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QueryCandidateField {
    Inbound,
    Network,
    Qtype,
    Port,
    PortRange,
    QueryMatchSet,
    RuleSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum QueryCandidateDriver {
    Sparse(QueryCandidateField),
    DenseRuleSet,
}

impl QueryCandidateField {
    const ALL: [Self; FIELD_COUNT] = [
        Self::Inbound,
        Self::Network,
        Self::Qtype,
        Self::Port,
        Self::PortRange,
        Self::QueryMatchSet,
        Self::RuleSet,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Inbound => 0,
            Self::Network => 1,
            Self::Qtype => 2,
            Self::Port => 3,
            Self::PortRange => 4,
            Self::QueryMatchSet => 5,
            Self::RuleSet => 6,
        }
    }
}

pub(super) struct DnsQueryCandidateIndex {
    unconstrained: [Box<[u32]>; FIELD_COUNT],
    constrained: [bool; FIELD_COUNT],
    inbound: SparseValueIndex<usize>,
    network: SparseValueIndex<Network>,
    qtype: SparseValueIndex<RecordType>,
    port: SparseValueIndex<NonZeroU16>,
    port_range: PortRangeCandidateIndex,
    query_match_set: MatchCandidateIndex,
    rule_set: SparseValueIndex<RuleSetId>,
    rule_set_constrained: Box<[u32]>,
}

impl DnsQueryCandidateIndex {
    pub(super) fn try_build(rules: &[DnsPolicyRule]) -> Result<Self, RuleCompileError> {
        if rules.len() > u32::MAX as usize {
            return Err(RuleCompileError::IndexOverflow);
        }
        let mut unconstrained: [Vec<u32>; FIELD_COUNT] = array::from_fn(|_| Vec::new());
        for candidates in &mut unconstrained {
            candidates
                .try_reserve_exact(rules.len())
                .map_err(|_| RuleCompileError::Allocation)?;
        }
        let mut constrained = [false; FIELD_COUNT];
        let mut inbound = SparseValueIndexBuilder::new();
        let mut network = SparseValueIndexBuilder::new();
        let mut qtype = SparseValueIndexBuilder::new();
        let mut port = SparseValueIndexBuilder::new();
        let mut port_range = PortRangeCandidateIndexBuilder::new();
        let mut query_match_set = MatchCandidateIndexBuilder::new();
        let mut rule_set = SparseValueIndexBuilder::new();
        let mut rule_set_constrained = Vec::new();
        rule_set_constrained
            .try_reserve_exact(rules.len())
            .map_err(|_| RuleCompileError::Allocation)?;

        for (index, rule) in rules.iter().enumerate() {
            let candidate = u32::try_from(index).map_err(|_| RuleCompileError::IndexOverflow)?;
            let matcher = &rule.matcher;
            if matcher.inbounds.is_empty() {
                unconstrained[QueryCandidateField::Inbound.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::Inbound.index()] = true;
                for value in matcher.inbounds.iter().copied() {
                    inbound.try_add(value, index)?;
                }
            }
            if matcher.networks.is_empty() {
                unconstrained[QueryCandidateField::Network.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::Network.index()] = true;
                for value in matcher.networks.iter().copied() {
                    network.try_add(value, index)?;
                }
            }
            if matcher.qtypes.is_empty() {
                unconstrained[QueryCandidateField::Qtype.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::Qtype.index()] = true;
                for value in matcher.qtypes.iter().copied() {
                    qtype.try_add(value, index)?;
                }
            }
            if matcher.ports.is_empty() {
                unconstrained[QueryCandidateField::Port.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::Port.index()] = true;
                for value in matcher.ports.iter().copied() {
                    port.try_add(value, index)?;
                }
            }
            if matcher.port_ranges.is_empty() {
                unconstrained[QueryCandidateField::PortRange.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::PortRange.index()] = true;
                for range in matcher.port_ranges.iter().copied() {
                    port_range.try_add(range.first(), range.last(), index)?;
                }
            }
            if matcher.query_fields.is_empty() {
                unconstrained[QueryCandidateField::QueryMatchSet.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::QueryMatchSet.index()] = true;
                // Multiple ordinary fields are ANDed by the full matcher. Their
                // postings form a conservative union used only to find candidates.
                for field in matcher.query_fields.iter() {
                    query_match_set.try_add_match_set(index, field, MatchCategories::DOMAIN)?;
                }
            }
            if matcher.rule_sets.is_empty() {
                unconstrained[QueryCandidateField::RuleSet.index()].push(candidate);
            } else {
                constrained[QueryCandidateField::RuleSet.index()] = true;
                rule_set_constrained.push(candidate);
                for value in matcher.rule_sets.iter().copied() {
                    rule_set.try_add(value, index)?;
                }
            }
        }

        Ok(Self {
            unconstrained: unconstrained.map(Vec::into_boxed_slice),
            constrained,
            inbound: inbound.build()?,
            network: network.build()?,
            qtype: qtype.build()?,
            port: port.build()?,
            port_range: port_range.build()?,
            query_match_set: query_match_set.build()?,
            rule_set: rule_set.build()?,
            rule_set_constrained: rule_set_constrained.into_boxed_slice(),
        })
    }

    pub(super) fn select_driver(
        &self,
        query: &DnsPolicyQuery,
        snapshot: &RuleEngineSnapshot,
    ) -> Option<QueryCandidateDriver> {
        let mut selected = None;
        let mut selected_count = usize::MAX;
        for field in QueryCandidateField::ALL {
            if !self.constrained[field.index()] {
                continue;
            }
            let mut count = 0_usize;
            self.visit_candidate_lists(field, query, snapshot, |candidates| {
                count = count.saturating_add(candidates.len());
            });
            let (driver, driver_count) =
                if field == QueryCandidateField::RuleSet && is_address_qtype(query.qtype()) {
                    let dense_count = self.unconstrained[field.index()]
                        .len()
                        .saturating_add(self.rule_set_constrained.len());
                    if count >= dense_count.div_ceil(2) {
                        (QueryCandidateDriver::DenseRuleSet, dense_count)
                    } else {
                        (QueryCandidateDriver::Sparse(field), count)
                    }
                } else {
                    (QueryCandidateDriver::Sparse(field), count)
                };
            if driver_count < selected_count {
                selected = Some(driver);
                selected_count = driver_count;
            }
        }
        selected
    }

    pub(super) fn next_candidate(
        &self,
        driver: QueryCandidateDriver,
        cursor: usize,
        query: &DnsPolicyQuery,
        snapshot: &RuleEngineSnapshot,
    ) -> Option<usize> {
        let cursor = u32::try_from(cursor).ok()?;
        let mut next = None;
        let mut consider = |candidates: &[u32]| {
            let position = candidates.partition_point(|candidate| *candidate < cursor);
            if let Some(candidate) = candidates.get(position).copied()
                && next.is_none_or(|selected| candidate < selected)
            {
                next = Some(candidate);
            }
        };
        match driver {
            QueryCandidateDriver::Sparse(field) => {
                self.visit_candidate_lists(field, query, snapshot, &mut consider);
            }
            QueryCandidateDriver::DenseRuleSet => {
                consider(&self.unconstrained[QueryCandidateField::RuleSet.index()]);
                consider(&self.rule_set_constrained);
            }
        }
        next.map(|candidate| candidate as usize)
    }

    fn visit_candidate_lists(
        &self,
        field: QueryCandidateField,
        query: &DnsPolicyQuery,
        snapshot: &RuleEngineSnapshot,
        mut visit: impl FnMut(&[u32]),
    ) {
        visit(&self.unconstrained[field.index()]);
        match field {
            QueryCandidateField::Inbound => {
                self.inbound.visit_candidate_list(&query.inbound(), visit);
            }
            QueryCandidateField::Network => {
                self.network.visit_candidate_list(&query.network(), visit);
            }
            QueryCandidateField::Qtype => {
                self.qtype.visit_candidate_list(&query.qtype(), visit);
            }
            QueryCandidateField::Port => {
                if let Some(port) = query.port() {
                    self.port.visit_candidate_list(&port, visit);
                }
            }
            QueryCandidateField::PortRange => {
                if let Some(port) = query.port() {
                    self.port_range.visit_candidate_lists(port, visit);
                }
            }
            QueryCandidateField::QueryMatchSet => self.query_match_set.visit_match_candidate_lists(
                query.canonical_qname(),
                None,
                visit,
            ),
            QueryCandidateField::RuleSet => {
                snapshot.visit_matching_rule_sets(query.canonical_qname(), None, |rule_set| {
                    self.rule_set.visit_candidate_list(&rule_set, &mut visit);
                });
                if is_address_qtype(query.qtype()) {
                    snapshot.visit_ip_rule_sets(|rule_set| {
                        self.rule_set.visit_candidate_list(&rule_set, &mut visit);
                    });
                }
            }
        }
    }
}
