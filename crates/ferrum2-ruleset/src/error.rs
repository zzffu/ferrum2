use std::fmt;

use ferrum2_rule::RuleCompileError;
use ferrum2_rule::srs::SrsErrorKind;

use crate::download::RuleSetDownloadErrorKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetLoadErrorKind {
    InvalidCacheName,
    InvalidSource,
    InvalidLoaderConfig,
    CacheDirectory,
    CacheRead,
    CacheMetadata,
    CacheDigest,
    Download(RuleSetDownloadErrorKind),
    DownloadTimeout,
    DownloadBody,
    DownloadOverflow,
    Allocation,
    Decode(SrsErrorKind),
    CacheWrite,
    Task,
    NotModifiedWithoutCache,
    RegistryCompile,
    RegistryPublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSetLoadError {
    kind: RuleSetLoadErrorKind,
}

impl RuleSetLoadError {
    pub(crate) const fn new(kind: RuleSetLoadErrorKind) -> Self {
        Self { kind }
    }

    pub const fn kind(self) -> RuleSetLoadErrorKind {
        self.kind
    }
}

impl fmt::Display for RuleSetLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleSet materialization failed")
    }
}

impl std::error::Error for RuleSetLoadError {}

pub(crate) const fn rule_compile_load_error_kind(error: RuleCompileError) -> RuleSetLoadErrorKind {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => {
            RuleSetLoadErrorKind::Allocation
        }
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidId
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => RuleSetLoadErrorKind::RegistryCompile,
    }
}

pub(crate) const fn rule_compile_load_error(error: RuleCompileError) -> RuleSetLoadError {
    RuleSetLoadError::new(rule_compile_load_error_kind(error))
}

#[cfg(test)]
mod rule_compile_error_tests {
    use super::*;

    #[test]
    fn allocation_and_index_overflow_keep_the_allocation_category() {
        for error in [
            RuleCompileError::Allocation,
            RuleCompileError::IndexOverflow,
        ] {
            assert_eq!(
                rule_compile_load_error_kind(error),
                RuleSetLoadErrorKind::Allocation
            );
        }
    }

    #[test]
    fn remaining_compiler_failures_are_registry_compile_failures() {
        for error in [
            RuleCompileError::EmptyMatcher,
            RuleCompileError::EmptyField,
            RuleCompileError::DuplicateField,
            RuleCompileError::DuplicateValue,
            RuleCompileError::ConflictingFields,
            RuleCompileError::InvalidDomain,
            RuleCompileError::NonCanonicalCidr,
            RuleCompileError::InvalidId,
            RuleCompileError::InvalidTag,
            RuleCompileError::DuplicateRuleSet,
            RuleCompileError::InvalidGeneration,
            RuleCompileError::Internal,
        ] {
            assert_eq!(
                rule_compile_load_error_kind(error),
                RuleSetLoadErrorKind::RegistryCompile
            );
        }
    }
}
