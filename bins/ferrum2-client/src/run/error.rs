use ferrum2_rule::RuleCompileError;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
    StartupRecording,
    RecordingIncomplete,
    ConfigResourceMaterialization,
    DnsResolve,
    RuleCompile,
    RuleAllocation,
    RuleSetDownload,
    RuleSetCache,
    RuleSetFormat,
    RuleSetUnsupportedMatcher,
    RuleSetCompile,
    RuntimeListener,
    RuntimeChild,
    RuntimeRoot,
    ShutdownCleanup,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StartupObservability => {
                "error[startup.observability] process: unable to initialize diagnostics"
            }
            Self::StartupRuntime => {
                "error[startup.runtime] process: unable to create asynchronous runtime"
            }
            Self::StartupBind => "error[startup.bind] process: unable to prepare required endpoint",
            Self::StartupProtocol => {
                "error[startup.protocol] process: unable to prepare protocol resources"
            }
            Self::ConfigResourceMaterialization => {
                "error[config.resource_materialization] configuration: supplied resources are invalid"
            }
            Self::DnsResolve => {
                "error[dns.resolve] materialization: fixed endpoint resolution failed"
            }
            Self::RuleCompile => {
                "error[rule.compile] materialization: rule compilation failed"
            }
            Self::RuleAllocation => {
                "error[rule.allocation] materialization: rule allocation failed"
            }
            Self::RuleSetDownload => {
                "error[ruleset.download] materialization: RuleSet download failed"
            }
            Self::RuleSetCache => {
                "error[ruleset.cache] materialization: RuleSet cache failed"
            }
            Self::RuleSetFormat => {
                "error[ruleset.format] materialization: RuleSet format is invalid"
            }
            Self::RuleSetUnsupportedMatcher => {
                "error[ruleset.unsupported_matcher] materialization: RuleSet matcher is unsupported"
            }
            Self::RuleSetCompile => {
                "error[ruleset.compile] materialization: RuleSet compilation failed"
            }
            Self::RuntimeListener => "error[runtime.listener] process: required listener failed",
            Self::RuntimeChild => "error[runtime.child] process: required child failed",
            Self::RuntimeRoot => "error[runtime.root] process: required root stopped",
            Self::StartupRecording => "error[recording.startup] process: unable to start recording",
            Self::RecordingIncomplete => "error[recording.incomplete] process: recording is incomplete",
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

impl RunError {
    pub(crate) const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::StartupObservability => "startup.observability",
            Self::StartupRuntime => "startup.runtime",
            Self::StartupBind => "startup.bind",
            Self::StartupProtocol => "startup.protocol",
            Self::StartupRecording => "recording.startup",
            Self::RecordingIncomplete => "recording.incomplete",
            Self::ConfigResourceMaterialization => "config.resource_materialization",
            Self::DnsResolve => "dns.resolve",
            Self::RuleCompile => "rule.compile",
            Self::RuleAllocation => "rule.allocation",
            Self::RuleSetDownload => "ruleset.download",
            Self::RuleSetCache => "ruleset.cache",
            Self::RuleSetFormat => "ruleset.format",
            Self::RuleSetUnsupportedMatcher => "ruleset.unsupported_matcher",
            Self::RuleSetCompile => "ruleset.compile",
            Self::RuntimeListener => "runtime.listener",
            Self::RuntimeChild => "runtime.child",
            Self::RuntimeRoot => "runtime.root",
            Self::ShutdownCleanup => "shutdown.cleanup",
        }
    }
}

/// Classifies rule scratch construction failures after configuration has
/// already passed semantic validation. Allocation and index-capacity failures
/// retain their operator-visible category; every other closed compiler failure
/// is an internal compilation failure at this production boundary.
pub(super) const fn run_error_for_rule_compile(error: RuleCompileError) -> RunError {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => RunError::RuleAllocation,
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
        | RuleCompileError::ResourceLimit
        | RuleCompileError::Internal => RunError::RuleCompile,
    }
}

#[test]
fn rule_scratch_failures_keep_closed_runtime_categories() {
    for error in [
        RuleCompileError::Allocation,
        RuleCompileError::IndexOverflow,
    ] {
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleAllocation);
    }
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
        assert_eq!(run_error_for_rule_compile(error), RunError::RuleCompile);
    }
}
