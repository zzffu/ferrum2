#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind {
        descriptor: super::report::RootDescriptor,
        acquisition: EndpointAcquireError,
    },
    ProcessFailure(Box<super::report::ServerRunFailure>),
    StartupProtocol,
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

impl RunError {
    pub(super) fn category(&self) -> &'static str {
        match self {
            Self::StartupObservability => "startup.observability",
            Self::StartupRuntime => "startup.runtime",
            Self::StartupBind { .. } => "startup.bind",
            Self::StartupProtocol => "startup.protocol",
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
            Self::ProcessFailure(failure) => failure.category(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointAcquireStage {
    SocketCreate,
    Configure,
    Bind,
    Listen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointIoKind {
    AddressInUse,
    AddressUnavailable,
    PermissionDenied,
    InvalidInput,
    Unsupported,
    ResourceLimit,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EndpointAcquireError {
    stage: EndpointAcquireStage,
    kind: EndpointIoKind,
}

impl EndpointAcquireError {
    pub(super) fn new(stage: EndpointAcquireStage, error: std::io::Error) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::AddrInUse => EndpointIoKind::AddressInUse,
            std::io::ErrorKind::AddrNotAvailable => EndpointIoKind::AddressUnavailable,
            std::io::ErrorKind::PermissionDenied => EndpointIoKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput => EndpointIoKind::InvalidInput,
            std::io::ErrorKind::Unsupported => EndpointIoKind::Unsupported,
            std::io::ErrorKind::OutOfMemory => EndpointIoKind::ResourceLimit,
            // std::io::ErrorKind is non-exhaustive; retain no OS message or identity.
            _ => EndpointIoKind::Other,
        };
        Self { stage, kind }
    }
}

impl std::fmt::Display for EndpointAcquireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stage = match self.stage {
            EndpointAcquireStage::SocketCreate => "socket_create",
            EndpointAcquireStage::Configure => "configure",
            EndpointAcquireStage::Bind => "bind",
            EndpointAcquireStage::Listen => "listen",
        };
        let kind = match self.kind {
            EndpointIoKind::AddressInUse => "address_in_use",
            EndpointIoKind::AddressUnavailable => "address_unavailable",
            EndpointIoKind::PermissionDenied => "permission_denied",
            EndpointIoKind::InvalidInput => "invalid_input",
            EndpointIoKind::Unsupported => "unsupported",
            EndpointIoKind::ResourceLimit => "resource_limit",
            EndpointIoKind::Other => "other",
        };
        write!(formatter, "{stage} io_kind={kind}")
    }
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
            Self::StartupBind { descriptor, acquisition } => return write!(formatter, "error[startup.bind] process: root={descriptor} acquisition={acquisition}"),
            Self::ProcessFailure(failure) => return std::fmt::Display::fmt(failure, formatter),
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
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}
