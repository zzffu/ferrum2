use std::error::Error;
use std::fmt;

/// Closed failures produced while compiling a rule or match set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleCompileError {
    EmptyMatcher,
    EmptyField,
    DuplicateField,
    DuplicateValue,
    ConflictingFields,
    InvalidDomain,
    NonCanonicalCidr,
    Allocation,
    IndexOverflow,
    InvalidId,
    InvalidTag,
    DuplicateRuleSet,
    InvalidGeneration,
    Internal,
}

impl fmt::Display for RuleCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyMatcher => "rule matcher is empty",
            Self::EmptyField => "rule matcher field is empty",
            Self::DuplicateField => "rule matcher field is duplicated",
            Self::DuplicateValue => "rule matcher value is duplicated",
            Self::ConflictingFields => "rule matcher fields conflict",
            Self::InvalidDomain => "rule domain is invalid",
            Self::NonCanonicalCidr => "rule CIDR is not canonical",
            Self::Allocation => "rule allocation failed",
            Self::IndexOverflow => "rule index overflowed",
            Self::InvalidId => "rule snapshot ID is invalid",
            Self::InvalidTag => "rule set tag is invalid",
            Self::DuplicateRuleSet => "rule set tag is duplicated",
            Self::InvalidGeneration => "rule snapshot generation is invalid",
            Self::Internal => "rule compiler consistency failure",
        })
    }
}

impl Error for RuleCompileError {}
