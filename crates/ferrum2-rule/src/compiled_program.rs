use crate::{RuleCompileError, SMALL_LINEAR_RULE_LIMIT};

/// Selected compilation strategy for an ordered rule program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleProgramMode {
    SmallLinear,
    Indexed,
}

impl RuleProgramMode {
    /// Selects the shared compilation strategy for one ordered rule count.
    pub const fn for_rule_count(rule_count: usize) -> Self {
        if rule_count <= SMALL_LINEAR_RULE_LIMIT {
            Self::SmallLinear
        } else {
            Self::Indexed
        }
    }
}

/// Shared immutable ownership core for ordered compiled rule programs.
///
/// Match adapters retain their own index representation, but route and DNS
/// programs share the same ordered rule storage, mode threshold, overflow
/// contract, and index lifetime through this type.
pub struct CompiledRuleProgram<R, I> {
    rules: Box<[R]>,
    mode: RuleProgramMode,
    index: Option<I>,
}

impl<R, I> CompiledRuleProgram<R, I> {
    /// Compiles one ordered rule list using the shared mode threshold.
    pub fn try_new<F>(rules: Vec<R>, build_index: F) -> Result<Self, RuleCompileError>
    where
        F: FnOnce(&[R]) -> Result<I, RuleCompileError>,
    {
        let mode = RuleProgramMode::for_rule_count(rules.len());
        Self::try_new_in_mode(rules, mode, build_index)
    }

    pub(crate) fn try_new_in_mode<F>(
        rules: Vec<R>,
        mode: RuleProgramMode,
        build_index: F,
    ) -> Result<Self, RuleCompileError>
    where
        F: FnOnce(&[R]) -> Result<I, RuleCompileError>,
    {
        if rules.len() > u32::MAX as usize {
            return Err(RuleCompileError::IndexOverflow);
        }
        let index = if mode == RuleProgramMode::Indexed {
            Some(build_index(&rules)?)
        } else {
            None
        };
        Ok(Self {
            rules: rules.into_boxed_slice(),
            mode,
            index,
        })
    }

    pub const fn mode(&self) -> RuleProgramMode {
        self.mode
    }

    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[R] {
        &self.rules
    }

    pub const fn index(&self) -> Option<&I> {
        self.index.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_core_owns_rules_and_selects_the_common_mode_boundary() {
        let linear = CompiledRuleProgram::<_, usize>::try_new(
            (0..SMALL_LINEAR_RULE_LIMIT).collect(),
            |_| panic!("small programs do not build an index"),
        )
        .unwrap();
        assert_eq!(linear.mode(), RuleProgramMode::SmallLinear);
        assert_eq!(linear.rules().len(), SMALL_LINEAR_RULE_LIMIT);
        assert!(linear.index().is_none());

        let indexed = CompiledRuleProgram::try_new(
            (0..=SMALL_LINEAR_RULE_LIMIT).collect::<Vec<_>>(),
            |rules| Ok(rules.len()),
        )
        .unwrap();
        assert_eq!(indexed.mode(), RuleProgramMode::Indexed);
        assert_eq!(indexed.rules().len(), SMALL_LINEAR_RULE_LIMIT + 1);
        assert_eq!(indexed.index(), Some(&(SMALL_LINEAR_RULE_LIMIT + 1)));
    }
}
