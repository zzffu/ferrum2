use std::num::NonZeroU16;

use ferrum2_core::TargetAddr;
use ferrum2_core::TargetHostRef;
use ferrum2_core::route::Network;

use crate::candidate::{
    MatchCandidateIndex, MatchCandidateIndexBuilder, MatchCategories, PortRangeCandidateIndex,
    PortRangeCandidateIndexBuilder, SparseValueIndex, SparseValueIndexBuilder,
};
use crate::{RuleCompileError, RuleEngineSnapshot, RuleProgramMode, RuleSetId};

use super::matcher::{CompiledField, FIELD_KIND_COUNT, FieldKind, RouteMetadata, selected_domain};
use super::{OrderedRouteProgram, OrderedRouteRule};

pub(super) struct ConstraintIndex<P> {
    masks: [Box<[u64]>; FIELD_KIND_COUNT],
    inbound: SparseValueIndex<usize>,
    network: SparseValueIndex<Network>,
    protocol: SparseValueIndex<P>,
    domain: MatchCandidateIndex,
    suffix: MatchCandidateIndex,
    keyword: MatchCandidateIndex,
    ip: MatchCandidateIndex,
    cidr: MatchCandidateIndex,
    port: SparseValueIndex<NonZeroU16>,
    port_range: PortRangeCandidateIndex,
    match_set: MatchCandidateIndex,
    rule_set: SparseValueIndex<RuleSetId>,
}

impl<P: Ord, A> OrderedRouteProgram<P, A> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn find_next(
        &self,
        cursor: usize,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
        scratch: &mut RuleEvaluationScratch,
    ) -> Option<usize> {
        scratch.candidate_visits = 0;
        if self.compiled.mode() == RuleProgramMode::SmallLinear {
            for (offset, rule) in self.compiled.rules()[cursor..].iter().enumerate() {
                scratch.candidate_visits = scratch.candidate_visits.saturating_add(1);
                if rule
                    .matcher
                    .matches(inbound, network, original, metadata, snapshot)
                {
                    return Some(cursor + offset);
                }
            }
            return None;
        }

        let constraints = self.compiled.index().expect("indexed constraints");
        scratch.fill_candidates(self.compiled.len(), cursor);
        for kind in FieldKind::ALL {
            let mask = &constraints.masks[kind.index()];
            if mask.iter().all(|word| *word == 0) {
                continue;
            }
            scratch.matched.fill(0);
            constraints.visit_matches(
                kind,
                inbound,
                network,
                original,
                metadata,
                snapshot,
                &mut scratch.matched,
                &mut scratch.candidate_visits,
            );
            for ((candidate, constraint), matched) in scratch
                .candidates
                .iter_mut()
                .zip(mask.iter())
                .zip(scratch.matched.iter())
            {
                *candidate &= !constraint | matched;
            }
            if scratch.candidates.iter().all(|word| *word == 0) {
                return None;
            }
        }
        first_set_bit(&scratch.candidates, cursor)
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn build_constraints<P: Clone + Ord, A>(
    rules: &[OrderedRouteRule<P, A>],
) -> Result<ConstraintIndex<P>, RuleCompileError> {
    let words = words_for(rules.len());
    let mut masks: [Vec<u64>; FIELD_KIND_COUNT] = std::array::from_fn(|_| Vec::new());
    for mask in &mut masks {
        mask.try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        mask.resize(words, 0);
    }
    let mut inbound = SparseValueIndexBuilder::new();
    let mut network = SparseValueIndexBuilder::new();
    let mut protocol = SparseValueIndexBuilder::new();
    let mut domain = MatchCandidateIndexBuilder::new();
    let mut suffix = MatchCandidateIndexBuilder::new();
    let mut keyword = MatchCandidateIndexBuilder::new();
    let mut ip = MatchCandidateIndexBuilder::new();
    let mut cidr = MatchCandidateIndexBuilder::new();
    let mut port = SparseValueIndexBuilder::new();
    let mut port_range = PortRangeCandidateIndexBuilder::new();
    let mut match_set = MatchCandidateIndexBuilder::new();
    let mut rule_set = SparseValueIndexBuilder::new();
    for (index, rule) in rules.iter().enumerate() {
        for field in &rule.matcher.fields {
            set_bit(&mut masks[field.kind().index()], index);
            match field {
                CompiledField::Inbound(values) => {
                    for value in values {
                        inbound.try_add(*value, index)?;
                    }
                }
                CompiledField::Network(values) => {
                    for value in values {
                        network.try_add(*value, index)?;
                    }
                }
                CompiledField::Protocol(values) => {
                    for value in values {
                        protocol.try_add(value.clone(), index)?;
                    }
                }
                CompiledField::Domain(values) => {
                    domain.try_add_match_set(index, values, MatchCategories::EXACT)?;
                }
                CompiledField::DomainSuffix(values) => {
                    suffix.try_add_match_set(index, values, MatchCategories::SUFFIX)?;
                }
                CompiledField::DomainKeyword(values) => {
                    keyword.try_add_match_set(index, values, MatchCategories::KEYWORD)?;
                }
                CompiledField::Ip(values) => {
                    ip.try_add_match_set(index, values, MatchCategories::IP)?;
                }
                CompiledField::Cidr(values) => {
                    cidr.try_add_match_set(index, values, MatchCategories::IP)?;
                }
                CompiledField::Port(values) => {
                    for value in values {
                        port.try_add(*value, index)?;
                    }
                }
                CompiledField::PortRange(values) => {
                    for value in values {
                        port_range.try_add(value.first(), value.last(), index)?;
                    }
                }
                CompiledField::MatchSet(values) => {
                    match_set.try_add_match_set(index, values, MatchCategories::ALL)?;
                }
                CompiledField::RuleSet(values) => {
                    for value in values {
                        rule_set.try_add(*value, index)?;
                    }
                }
            }
        }
    }
    Ok(ConstraintIndex {
        masks: masks.map(Vec::into_boxed_slice),
        inbound: inbound.build()?,
        network: network.build()?,
        protocol: protocol.build()?,
        domain: domain.build()?,
        suffix: suffix.build()?,
        keyword: keyword.build()?,
        ip: ip.build()?,
        cidr: cidr.build()?,
        port: port.build()?,
        port_range: port_range.build()?,
        match_set: match_set.build()?,
        rule_set: rule_set.build()?,
    })
}

impl<P: Ord> ConstraintIndex<P> {
    #[allow(clippy::too_many_arguments)]
    fn visit_matches(
        &self,
        kind: FieldKind,
        inbound: usize,
        network: Network,
        original: &TargetAddr,
        metadata: &RouteMetadata<'_, P>,
        snapshot: Option<&RuleEngineSnapshot>,
        matched: &mut [u64],
        visits: &mut usize,
    ) {
        let domain = selected_domain(original, metadata);
        let address = match original.host() {
            TargetHostRef::Ip(address) => Some(address),
            TargetHostRef::Domain(_) => None,
        };
        let mut mark = |candidate| {
            *visits = visits.saturating_add(1);
            set_bit(matched, candidate as usize);
        };
        match kind {
            FieldKind::Inbound => self.inbound.visit(&inbound, mark),
            FieldKind::Network => self.network.visit(&network, mark),
            FieldKind::Protocol => {
                if let Some(protocol) = metadata.protocol.as_ref() {
                    self.protocol.visit(protocol, mark);
                }
            }
            FieldKind::Domain => self.domain.visit_matches(domain, None, mark),
            FieldKind::DomainSuffix => self.suffix.visit_matches(domain, None, mark),
            FieldKind::DomainKeyword => self.keyword.visit_matches(domain, None, mark),
            FieldKind::Ip => self.ip.visit_matches(None, address, mark),
            FieldKind::Cidr => self.cidr.visit_matches(None, address, mark),
            FieldKind::Port => self.port.visit(&original.port(), mark),
            FieldKind::PortRange => self.port_range.visit(original.port(), mark),
            FieldKind::MatchSet => self.match_set.visit_matches(domain, address, mark),
            FieldKind::RuleSet => {
                if let Some(snapshot) = snapshot {
                    snapshot.visit_matching_rule_sets(domain, address, |rule_set| {
                        self.rule_set.visit(&rule_set, &mut mark);
                    });
                }
            }
        }
    }
}

/// Reusable bitmap workspace for indexed evaluation.
pub struct RuleEvaluationScratch {
    candidates: Vec<u64>,
    matched: Vec<u64>,
    candidate_visits: usize,
}

impl RuleEvaluationScratch {
    pub fn try_for_program<P, A>(
        program: &OrderedRouteProgram<P, A>,
    ) -> Result<Self, RuleCompileError> {
        let words = if program.compiled.mode() == RuleProgramMode::Indexed {
            words_for(program.compiled.len())
        } else {
            0
        };
        let mut candidates = Vec::new();
        let mut matched = Vec::new();
        candidates
            .try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        matched
            .try_reserve_exact(words)
            .map_err(|_| RuleCompileError::Allocation)?;
        candidates.resize(words, 0);
        matched.resize(words, 0);
        Ok(Self {
            candidates,
            matched,
            candidate_visits: 0,
        })
    }

    /// Returns the retained bitmap capacities for allocation-regression tests.
    pub fn reserved_words(&self) -> (usize, usize) {
        (self.candidates.capacity(), self.matched.capacity())
    }

    /// Returns the number of sparse posting candidates visited by the last step.
    /// This is a deterministic benchmark and selectivity-regression seam.
    pub const fn candidate_visits(&self) -> usize {
        self.candidate_visits
    }

    pub(super) fn assert_words(&self, words: usize) {
        assert!(
            self.candidates.len() >= words && self.matched.len() >= words,
            "rule evaluation scratch is undersized for this program"
        );
    }

    fn fill_candidates(&mut self, rules: usize, cursor: usize) {
        let words = words_for(rules);
        self.candidates.fill(0);
        self.candidates[..words].fill(u64::MAX);
        if let Some(last) = self.candidates.get_mut(words.saturating_sub(1)) {
            let used = rules % 64;
            if used != 0 {
                *last &= (1_u64 << used) - 1;
            }
        }
        let whole_words = cursor / 64;
        self.candidates[..whole_words.min(words)].fill(0);
        if whole_words < words {
            self.candidates[whole_words] &= u64::MAX << (cursor % 64);
        }
    }
}

pub(super) fn words_for(bits: usize) -> usize {
    bits.div_ceil(64)
}

fn set_bit(words: &mut [u64], index: usize) {
    words[index / 64] |= 1_u64 << (index % 64);
}

fn first_set_bit(words: &[u64], cursor: usize) -> Option<usize> {
    for (word_index, word) in words.iter().copied().enumerate().skip(cursor / 64) {
        let mut word = word;
        if word_index == cursor / 64 {
            word &= u64::MAX << (cursor % 64);
        }
        if word != 0 {
            return Some(word_index * 64 + word.trailing_zeros() as usize);
        }
    }
    None
}
