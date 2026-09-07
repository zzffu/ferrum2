use crate::RuleCompileError;

/// Retained unique matcher input, independent of decoder attempted-entry work.
/// Expanded bytes include exact domains, suffixes and keywords; IPs use entries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MatchSetResourceUsage {
    pub(super) entries: usize,
    pub(super) expanded_bytes: usize,
    pub(super) keyword_bytes: usize,
}

impl MatchSetResourceUsage {
    pub const fn entries(self) -> usize {
        self.entries
    }
    pub const fn expanded_bytes(self) -> usize {
        self.expanded_bytes
    }
    pub const fn keyword_bytes(self) -> usize {
        self.keyword_bytes
    }

    pub(crate) fn checked_add(self, additional: Self) -> Result<Self, RuleCompileError> {
        Ok(Self {
            entries: self
                .entries
                .checked_add(additional.entries)
                .ok_or(RuleCompileError::ResourceLimit)?,
            expanded_bytes: self
                .expanded_bytes
                .checked_add(additional.expanded_bytes)
                .ok_or(RuleCompileError::ResourceLimit)?,
            keyword_bytes: self
                .keyword_bytes
                .checked_add(additional.keyword_bytes)
                .ok_or(RuleCompileError::ResourceLimit)?,
        })
    }
}
