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
    active_fields: Box<[ActiveField]>,
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

#[derive(Clone, Copy)]
struct ActiveField {
    kind: FieldKind,
    first_word: usize,
    end_word: usize,
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
        scratch.reset_observation();
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
        let domain = selected_domain(original, metadata);
        let address = match original.host() {
            TargetHostRef::Ip(address) => Some(address),
            TargetHostRef::Domain(_) => None,
        };
        for field in constraints.active_fields.iter().copied() {
            let mask = &constraints.masks[field.kind.index()];
            scratch.matched[field.first_word..field.end_word].fill(0);
            scratch.bitmap_words_cleared = scratch
                .bitmap_words_cleared
                .saturating_add(field.end_word - field.first_word);
            constraints.visit_matches(
                field.kind,
                inbound,
                network,
                original,
                metadata,
                snapshot,
                domain,
                address,
                &mut scratch.matched,
                &mut scratch.candidate_visits,
            );
            for word in field.first_word..field.end_word {
                let candidate = &mut scratch.candidates[word];
                let was_nonzero = *candidate != 0;
                let constraint = mask[word];
                let matched = scratch.matched[word];
                *candidate &= !constraint | matched;
                let is_nonzero = *candidate != 0;
                match (was_nonzero, is_nonzero) {
                    (true, false) => {
                        scratch.nonzero_candidate_words -= 1;
                    }
                    (false, true) => {
                        scratch.nonzero_candidate_words += 1;
                    }
                    _ => {}
                }
                scratch.bitmap_words_combined = scratch.bitmap_words_combined.saturating_add(1);
            }
            if scratch.nonzero_candidate_words == 0 {
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
    let mut active_fields = Vec::new();
    active_fields
        .try_reserve_exact(FIELD_KIND_COUNT)
        .map_err(|_| RuleCompileError::Allocation)?;
    for kind in FieldKind::ALL {
        let mask = &masks[kind.index()];
        let Some(first_word) = mask.iter().position(|word| *word != 0) else {
            continue;
        };
        let end_word = mask
            .iter()
            .rposition(|word| *word != 0)
            .expect("active field has a last word")
            + 1;
        active_fields.push(ActiveField {
            kind,
            first_word,
            end_word,
        });
    }
    Ok(ConstraintIndex {
        masks: masks.map(Vec::into_boxed_slice),
        active_fields: active_fields.into_boxed_slice(),
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
        domain: Option<&ferrum2_core::CanonicalDomain>,
        address: Option<std::net::IpAddr>,
        matched: &mut [u64],
        visits: &mut usize,
    ) {
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
    nonzero_candidate_words: usize,
    candidate_words_initialized: usize,
    bitmap_words_cleared: usize,
    bitmap_words_combined: usize,
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
            nonzero_candidate_words: 0,
            candidate_words_initialized: 0,
            bitmap_words_cleared: 0,
            bitmap_words_combined: 0,
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

    /// Returns bitmap words cleared and combined by the last evaluation step.
    ///
    /// This deterministic structural observation is intended for qualification
    /// without exposing rule values or matcher inputs.
    pub const fn bitmap_word_operations(&self) -> (usize, usize) {
        (self.bitmap_words_cleared, self.bitmap_words_combined)
    }

    /// Returns candidate bitmap words initialized by the last evaluation step.
    pub const fn candidate_word_initializations(&self) -> usize {
        self.candidate_words_initialized
    }

    pub(super) fn assert_words(&self, words: usize) {
        assert!(
            self.candidates.len() >= words && self.matched.len() >= words,
            "rule evaluation scratch is undersized for this program"
        );
    }

    fn fill_candidates(&mut self, rules: usize, cursor: usize) {
        let words = words_for(rules);
        let first_word = (cursor / 64).min(words);
        self.candidates[..first_word].fill(0);
        self.candidates[first_word..words].fill(u64::MAX);
        self.candidates[words..].fill(0);
        self.candidate_words_initialized = self.candidates.len();
        if first_word < words {
            self.candidates[first_word] &= u64::MAX << (cursor % 64);
        }
        if words != 0 {
            let last = &mut self.candidates[words - 1];
            let used = rules % 64;
            if used != 0 {
                *last &= (1_u64 << used) - 1;
            }
        }
        self.nonzero_candidate_words = if cursor < rules {
            words - first_word
        } else {
            0
        };
    }

    fn reset_observation(&mut self) {
        self.candidate_visits = 0;
        self.candidate_words_initialized = 0;
        self.bitmap_words_cleared = 0;
        self.bitmap_words_combined = 0;
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
