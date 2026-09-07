use crate::{MatchSetResourceUsage, RuleCompileError};

/// Admission policy for retained snapshot contents and descriptor-expanded indexes.
/// These are input bounds, not allocator or RSS guarantees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleEngineSnapshotLimits {
    entries: usize,
    expanded_bytes: usize,
    keyword_bytes: usize,
}

impl RuleEngineSnapshotLimits {
    pub const DEFAULT: Self = Self {
        entries: 2_000_000,
        expanded_bytes: 128 * 1024 * 1024,
        keyword_bytes: 2 * 1024 * 1024,
    };

    /// Constructs positive limits no larger than the reviewed product policy.
    pub fn new(
        entries: usize,
        expanded_bytes: usize,
        keyword_bytes: usize,
    ) -> Result<Self, RuleCompileError> {
        if entries == 0
            || entries > Self::DEFAULT.entries
            || expanded_bytes == 0
            || expanded_bytes > Self::DEFAULT.expanded_bytes
            || keyword_bytes == 0
            || keyword_bytes > Self::DEFAULT.keyword_bytes
        {
            return Err(RuleCompileError::ResourceLimit);
        }
        Ok(Self {
            entries,
            expanded_bytes,
            keyword_bytes,
        })
    }

    /// Admits one additional set before retaining it or cloning its index values.
    /// Failure leaves the caller's previous accumulated usage unchanged.
    pub fn admit(
        self,
        current: MatchSetResourceUsage,
        additional: MatchSetResourceUsage,
    ) -> Result<MatchSetResourceUsage, RuleCompileError> {
        let next = current.checked_add(additional)?;
        if next.entries() > self.entries
            || next.expanded_bytes() > self.expanded_bytes
            || next.keyword_bytes() > self.keyword_bytes
        {
            return Err(RuleCompileError::ResourceLimit);
        }
        Ok(next)
    }
}

impl Default for RuleEngineSnapshotLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
