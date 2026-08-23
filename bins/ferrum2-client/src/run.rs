use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use ferrum2_config::{
    ClientOutboundConfig, DirectDomainResolver, DnsConfig, DnsIngressId, PreparedClientV2,
    ValidatedClientConfig,
};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
use ferrum2_crypto::{SecureRandom, SystemClock, SystemRandom};
use ferrum2_dns::{
    ApplicationResolveOutcome, ApplicationResolver, ApplicationResolverMode, DnsCache,
    DnsPolicyCompileError, DnsPolicyMatchResult, DnsPolicyMatchSource, DnsPolicyMatchType,
    DnsPolicyObservation, DnsPolicyObserver, DnsPolicyProgram, DnsPolicyStage, DnsProxy,
    DnsProxySockets, DnsStrategy, ProxyIngress, ProxyTransport, ResolverGeneration, TaggedResolver,
    TaggedServerApplicationResolveBackend,
};
use ferrum2_observability::{
    Metrics, Role, RuleMatchResult, RuleMatchType, RuleProgram, RuleProgramMode, RuleSource,
    json_subscriber,
};
use ferrum2_rule::{RuleCompileError, RuleEngineRegistry};
use ferrum2_runtime::{
    ApplicationResolverAdapter, BoundedSupervisor, MAX_UDP_MAX_BUFFERED_BYTES,
    MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry, OwnerSnapshot, ProcessCause,
    ProcessCleanupFailure, ProcessReport, ProcessRoot, ProcessRootEventPhase, ProcessRootExit,
    ProcessRootExitCategory, ProcessRootId, ProcessState, ProcessSupervisor, UdpRuntimeLimits,
    UdpSessionManager,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;
use ferrum2_socks5::Socks5Inbound;

mod egress;

mod context;
mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod materialize;
mod observation;
mod routing;
mod socks;
#[path = "run/io.rs"]
mod tokio_io;
#[path = "run/tun.rs"]
mod tun;

use context::{ClientContext, ClientRouting};
use dns::ClientDnsRoot;
use observation::{ClientMetricsRoot, log_level};
use socks::{ClientTcpListeners, ClientTcpRoot};
use tokio_io::{TokioConnector, bind_listener, shutdown_signal};

#[cfg(test)]
use egress::IdSequenceRandom;
use egress::{ClientEgressEngine, ClientUdpContext, prepare_client_outbounds};

const DEPRECATED_TUN_UDP_BUFFER_WARNING: &str =
    "warning[config.deprecated] tun.max_udp_buffered_bytes: ignored and scheduled for removal";

fn emit_deprecated_tun_memory_warning(config: &ValidatedClientConfig) {
    if config
        .tun
        .as_ref()
        .is_some_and(|tun| tun.deprecated_max_udp_buffered_bytes_present)
    {
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::Write::write_fmt(
            &mut stderr,
            format_args!("{DEPRECATED_TUN_UDP_BUFFER_WARNING}\n"),
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
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
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

impl RunError {
    const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::StartupObservability => "startup.observability",
            Self::StartupRuntime => "startup.runtime",
            Self::StartupBind => "startup.bind",
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
        }
    }
}

/// Classifies rule scratch construction failures after configuration has
/// already passed semantic validation. Allocation and index-capacity failures
/// retain their operator-visible category; every other closed compiler failure
/// is an internal compilation failure at this production boundary.
const fn run_error_for_rule_compile(error: RuleCompileError) -> RunError {
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
        | RuleCompileError::Internal => RunError::RuleCompile,
    }
}

const fn run_error_for_dns_policy_compile(error: DnsPolicyCompileError) -> RunError {
    match error {
        DnsPolicyCompileError::Allocation | DnsPolicyCompileError::IndexOverflow => {
            RunError::RuleAllocation
        }
        DnsPolicyCompileError::EmptyRule
        | DnsPolicyCompileError::InvalidQueryMatchSet
        | DnsPolicyCompileError::DuplicateConstraint
        | DnsPolicyCompileError::InvalidPortRange
        | DnsPolicyCompileError::UnknownRuleSet
        | DnsPolicyCompileError::ResponseDependentReject
        | DnsPolicyCompileError::Internal => RunError::RuleCompile,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientRootName {
    Bootstrap,
    Socks,
    Dns,
    Metrics,
    Tun,
}

impl ClientRootName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Socks => "socks",
            Self::Dns => "dns",
            Self::Metrics => "metrics",
            Self::Tun => "tun",
        }
    }
}

#[derive(Debug, Default)]
struct ClientProcessRoots {
    roots: Vec<ProcessRoot<RunError>>,
    names: Vec<ClientRootName>,
}

impl ClientProcessRoots {
    fn push(&mut self, name: ClientRootName, root: ProcessRoot<RunError>) {
        self.names.push(name);
        self.roots.push(root);
    }

    fn into_parts(self) -> (Vec<ProcessRoot<RunError>>, ClientRootNames) {
        debug_assert_eq!(self.roots.len(), self.names.len());
        (self.roots, ClientRootNames(self.names))
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ClientRootNames(Vec<ClientRootName>);

impl ClientRootNames {
    fn root(&self, id: ProcessRootId) -> DiagnosticRoot {
        let name = *self
            .0
            .get(id.get())
            .expect("process root ID belongs to the composed client topology");
        DiagnosticRoot { id: id.get(), name }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiagnosticRoot {
    id: usize,
    name: ClientRootName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminationCauseKind {
    ExternalShutdown,
    PreparationFailed,
    PreparationPanicked,
    ActivationFailed,
    ActivationPanicked,
    RootStopped,
}

impl TerminationCauseKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalShutdown => "ExternalShutdown",
            Self::PreparationFailed => "PreparationFailed",
            Self::PreparationPanicked => "PreparationPanicked",
            Self::ActivationFailed => "ActivationFailed",
            Self::ActivationPanicked => "ActivationPanicked",
            Self::RootStopped => "RootStopped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootExitCategory {
    Completed,
    Failed,
    Panicked,
    JoinFailed,
}

impl RootExitCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Panicked => "Panicked",
            Self::JoinFailed => "JoinFailed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupFailureKind {
    RootFailed,
    RootPanicked,
    RootJoinFailed,
    ForceReapTimedOut,
    OwnerMismatch,
}

impl CleanupFailureKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RootFailed => "RootFailed",
            Self::RootPanicked => "RootPanicked",
            Self::RootJoinFailed => "RootJoinFailed",
            Self::ForceReapTimedOut => "ForceReapTimedOut",
            Self::OwnerMismatch => "OwnerMismatch",
        }
    }
}

macro_rules! owner_counters {
    ($macro:ident) => {
        $macro! {
            process_supervisors,
            prepared_process_roots,
            active_process_roots,
            process_root_reaps,
            process_root_rollbacks,
            process_forced_roots,
            active_tun_tcp_flows,
            active_tun_handler_tasks,
            active_supervisor_children,
            connection_tasks,
            owned_buffers,
            owned_permits,
            listeners,
            forced_shutdowns,
            udp_sessions,
            udp_sockets,
            udp_tasks,
            udp_queued_datagrams,
            udp_buffered_bytes,
            udp_scratch_buffers,
            udp_forced_shutdowns,
            sniff_buffered_bytes,
        }
    };
}

macro_rules! define_owner_delta {
    ($($field:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        struct OwnerDelta {
            $(
                $field: i128,
            )+
        }

        impl OwnerDelta {
            fn between(baseline: OwnerSnapshot, stopped: OwnerSnapshot) -> Self {
                Self {
                    $(
                        $field: stopped.$field as i128 - baseline.$field as i128,
                    )+
                }
            }
        }
    };
}

owner_counters!(define_owner_delta);

macro_rules! define_owner_json_writers {
    ($first:ident $(, $field:ident)* $(,)?) => {
        fn write_owner_snapshot(
            formatter: &mut std::fmt::Formatter<'_>,
            owner: OwnerSnapshot,
        ) -> std::fmt::Result {
            write!(formatter, concat!("{{\"", stringify!($first), "\":{}"), owner.$first)?;
            $(
                write!(
                    formatter,
                    concat!(",\"", stringify!($field), "\":{}"),
                    owner.$field,
                )?;
            )*
            formatter.write_str("}")
        }

        fn write_owner_delta(
            formatter: &mut std::fmt::Formatter<'_>,
            owner: OwnerDelta,
        ) -> std::fmt::Result {
            write!(formatter, concat!("{{\"", stringify!($first), "\":{}"), owner.$first)?;
            $(
                write!(
                    formatter,
                    concat!(",\"", stringify!($field), "\":{}"),
                    owner.$field,
                )?;
            )*
            formatter.write_str("}")
        }
    };
}

owner_counters!(define_owner_json_writers);

#[derive(Debug, Eq, PartialEq)]
struct CleanupDiagnostic {
    kind: CleanupFailureKind,
    root: Option<DiagnosticRoot>,
    roots: Vec<DiagnosticRoot>,
    error_category: Option<RunError>,
    prior: Option<Box<Self>>,
    owner_baseline: Option<OwnerSnapshot>,
    owner_stopped: Option<OwnerSnapshot>,
    owner_delta: Option<OwnerDelta>,
}

impl CleanupDiagnostic {
    fn new(kind: CleanupFailureKind) -> Self {
        Self {
            kind,
            root: None,
            roots: Vec::new(),
            error_category: None,
            prior: None,
            owner_baseline: None,
            owner_stopped: None,
            owner_delta: None,
        }
    }

    fn classify(failure: &ProcessCleanupFailure<RunError>, names: &ClientRootNames) -> Self {
        match failure {
            ProcessCleanupFailure::RootFailed { root, error } => {
                let mut diagnostic = Self::new(CleanupFailureKind::RootFailed);
                diagnostic.root = Some(names.root(*root));
                diagnostic.error_category = Some(*error);
                diagnostic
            }
            ProcessCleanupFailure::RootPanicked { root } => {
                let mut diagnostic = Self::new(CleanupFailureKind::RootPanicked);
                diagnostic.root = Some(names.root(*root));
                diagnostic
            }
            ProcessCleanupFailure::RootJoinFailed { root } => {
                let mut diagnostic = Self::new(CleanupFailureKind::RootJoinFailed);
                diagnostic.root = Some(names.root(*root));
                diagnostic
            }
            ProcessCleanupFailure::ForceReapTimedOut { roots, prior } => {
                let mut diagnostic = Self::new(CleanupFailureKind::ForceReapTimedOut);
                diagnostic.roots = roots.iter().map(|root| names.root(*root)).collect();
                diagnostic.prior = prior
                    .as_deref()
                    .map(|failure| Box::new(Self::classify(failure, names)));
                diagnostic
            }
            ProcessCleanupFailure::OwnerMismatch { baseline, stopped } => {
                let mut diagnostic = Self::new(CleanupFailureKind::OwnerMismatch);
                diagnostic.owner_baseline = Some(**baseline);
                diagnostic.owner_stopped = Some(**stopped);
                diagnostic.owner_delta = Some(OwnerDelta::between(**baseline, **stopped));
                diagnostic
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ShutdownDiagnostic {
    states: Vec<ProcessState>,
    transitions: Vec<DiagnosticTransition>,
    root_exit_events: Vec<DiagnosticRootEvent>,
    shutdown_grace_ns: u128,
    actual_grace_deadline_elapsed_ns: Option<u128>,
    termination_cause: TerminationCauseKind,
    root: Option<DiagnosticRoot>,
    root_exit_category: Option<RootExitCategory>,
    root_error_category: Option<RunError>,
    forced_root_count: usize,
    owner_baseline: OwnerSnapshot,
    owner_stopped: OwnerSnapshot,
    owner_delta: OwnerDelta,
    cleanup_failure: Option<CleanupDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiagnosticTransition {
    state: ProcessState,
    elapsed_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DiagnosticRootEvent {
    root: DiagnosticRoot,
    phase: ProcessRootEventPhase,
    exit: ProcessRootExitCategory,
    elapsed_ns: u128,
}

impl ShutdownDiagnostic {
    fn classify(
        report: &ProcessReport<RunError>,
        names: &ClientRootNames,
        shutdown_grace: std::time::Duration,
        owner_baseline: OwnerSnapshot,
        owner_stopped: OwnerSnapshot,
    ) -> Self {
        let (termination_cause, root, root_exit_category, root_error_category) =
            match report.cause() {
                ProcessCause::ExternalShutdown => {
                    (TerminationCauseKind::ExternalShutdown, None, None, None)
                }
                ProcessCause::PreparationFailed { root, error } => (
                    TerminationCauseKind::PreparationFailed,
                    Some(names.root(*root)),
                    None,
                    Some(*error),
                ),
                ProcessCause::PreparationPanicked { root } => (
                    TerminationCauseKind::PreparationPanicked,
                    Some(names.root(*root)),
                    None,
                    None,
                ),
                ProcessCause::ActivationFailed { root, error } => (
                    TerminationCauseKind::ActivationFailed,
                    Some(names.root(*root)),
                    None,
                    Some(*error),
                ),
                ProcessCause::ActivationPanicked { root } => (
                    TerminationCauseKind::ActivationPanicked,
                    Some(names.root(*root)),
                    None,
                    None,
                ),
                ProcessCause::RootStopped { root, exit } => {
                    let (exit, error) = match exit {
                        ProcessRootExit::Completed => (RootExitCategory::Completed, None),
                        ProcessRootExit::Failed(error) => (RootExitCategory::Failed, Some(*error)),
                        ProcessRootExit::Panicked => (RootExitCategory::Panicked, None),
                        ProcessRootExit::JoinFailed => (RootExitCategory::JoinFailed, None),
                    };
                    (
                        TerminationCauseKind::RootStopped,
                        Some(names.root(*root)),
                        Some(exit),
                        error,
                    )
                }
            };
        let transitions = report
            .transitions()
            .iter()
            .map(|transition| DiagnosticTransition {
                state: transition.state(),
                elapsed_ns: transition.elapsed().as_nanos(),
            })
            .collect::<Vec<_>>();
        let root_exit_events = report
            .root_events()
            .iter()
            .map(|event| DiagnosticRootEvent {
                root: names.root(event.root()),
                phase: event.phase(),
                exit: event.exit(),
                elapsed_ns: event.elapsed().as_nanos(),
            })
            .collect::<Vec<_>>();
        Self {
            states: report.states().to_vec(),
            transitions,
            root_exit_events,
            shutdown_grace_ns: shutdown_grace.as_nanos(),
            actual_grace_deadline_elapsed_ns: report
                .grace_deadline_elapsed()
                .map(|elapsed| elapsed.as_nanos()),
            termination_cause,
            root,
            root_exit_category,
            root_error_category,
            forced_root_count: report.forced_roots(),
            owner_baseline,
            owner_stopped,
            owner_delta: OwnerDelta::between(owner_baseline, owner_stopped),
            cleanup_failure: report
                .cleanup_failure()
                .map(|failure| CleanupDiagnostic::classify(failure, names)),
        }
    }
}

impl std::fmt::Display for ShutdownDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "{\"event\":\"process_shutdown_report\",\"role\":\"client\",\"process_states\":[",
        )?;
        for (index, state) in self.states.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "\"{}\"", process_state_name(*state))?;
        }
        formatter.write_str("],\"process_transitions\":[")?;
        for (index, transition) in self.transitions.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(
                formatter,
                "{{\"state\":\"{}\",\"elapsed_ns\":{}}}",
                process_state_name(transition.state),
                transition.elapsed_ns,
            )?;
        }
        formatter.write_str("],\"root_exit_events\":[")?;
        for (index, event) in self.root_exit_events.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            formatter.write_str("{\"root\":")?;
            write_root(formatter, event.root)?;
            write!(
                formatter,
                ",\"phase\":\"{}\",\"exit_category\":\"{}\",\"elapsed_ns\":{}}}",
                process_root_event_phase_name(event.phase),
                process_root_exit_category_name(event.exit),
                event.elapsed_ns,
            )?;
        }
        write!(
            formatter,
            "],\"shutdown_grace_ns\":{},\"actual_grace_deadline_elapsed_ns\":",
            self.shutdown_grace_ns,
        )?;
        match self.actual_grace_deadline_elapsed_ns {
            Some(elapsed_ns) => write!(formatter, "{elapsed_ns}")?,
            None => formatter.write_str("null")?,
        }
        match self.actual_grace_deadline_elapsed_ns {
            Some(_) => formatter
                .write_str(",\"actual_grace_deadline_source\":\"runtime_process_supervisor\"")?,
            None => formatter.write_str(",\"actual_grace_deadline_source\":null")?,
        }
        write!(
            formatter,
            ",\"termination_cause\":\"{}\",\"root\":",
            self.termination_cause.as_str(),
        )?;
        write_optional_root(formatter, self.root)?;
        formatter.write_str(",\"root_exit_category\":")?;
        write_optional_string(
            formatter,
            self.root_exit_category.map(RootExitCategory::as_str),
        )?;
        formatter.write_str(",\"root_error_category\":")?;
        write_optional_string(
            formatter,
            self.root_error_category.map(RunError::diagnostic_category),
        )?;
        write!(
            formatter,
            ",\"forced_root_count\":{},\"owner_baseline\":",
            self.forced_root_count,
        )?;
        write_owner_snapshot(formatter, self.owner_baseline)?;
        formatter.write_str(",\"owner_stopped\":")?;
        write_owner_snapshot(formatter, self.owner_stopped)?;
        formatter.write_str(",\"owner_delta\":")?;
        write_owner_delta(formatter, self.owner_delta)?;
        formatter.write_str(",\"cleanup_failure\":")?;
        match &self.cleanup_failure {
            Some(cleanup) => write_cleanup_diagnostic(formatter, cleanup)?,
            None => formatter.write_str("null")?,
        }
        formatter.write_str("}")
    }
}

fn process_state_name(state: ProcessState) -> &'static str {
    match state {
        ProcessState::Validated => "Validated",
        ProcessState::Preparing => "Preparing",
        ProcessState::Prepared => "Prepared",
        ProcessState::Active => "Active",
        ProcessState::Rollback => "Rollback",
        ProcessState::Fatal => "Fatal",
        ProcessState::Quiescing => "Quiescing",
        ProcessState::Draining => "Draining",
        ProcessState::Forced => "Forced",
        ProcessState::Stopped => "Stopped",
    }
}

fn process_root_event_phase_name(phase: ProcessRootEventPhase) -> &'static str {
    match phase {
        ProcessRootEventPhase::Active => "Active",
        ProcessRootEventPhase::Draining => "Draining",
        ProcessRootEventPhase::Forced => "Forced",
        ProcessRootEventPhase::WatchdogAbort => "WatchdogAbort",
    }
}

fn process_root_exit_category_name(exit: ProcessRootExitCategory) -> &'static str {
    match exit {
        ProcessRootExitCategory::Completed => "Completed",
        ProcessRootExitCategory::Failed => "Failed",
        ProcessRootExitCategory::Panicked => "Panicked",
        ProcessRootExitCategory::JoinFailed => "JoinFailed",
        ProcessRootExitCategory::Aborted => "Aborted",
    }
}

fn write_optional_string(
    formatter: &mut std::fmt::Formatter<'_>,
    value: Option<&str>,
) -> std::fmt::Result {
    match value {
        Some(value) => write!(formatter, "\"{value}\""),
        None => formatter.write_str("null"),
    }
}

fn write_root(formatter: &mut std::fmt::Formatter<'_>, root: DiagnosticRoot) -> std::fmt::Result {
    write!(
        formatter,
        "{{\"name\":\"{}\",\"id\":{}}}",
        root.name.as_str(),
        root.id,
    )
}

fn write_optional_root(
    formatter: &mut std::fmt::Formatter<'_>,
    root: Option<DiagnosticRoot>,
) -> std::fmt::Result {
    match root {
        Some(root) => write_root(formatter, root),
        None => formatter.write_str("null"),
    }
}

fn write_cleanup_diagnostic(
    formatter: &mut std::fmt::Formatter<'_>,
    cleanup: &CleanupDiagnostic,
) -> std::fmt::Result {
    write!(formatter, "{{\"kind\":\"{}\"", cleanup.kind.as_str())?;
    if let Some(root) = cleanup.root {
        formatter.write_str(",\"root\":")?;
        write_root(formatter, root)?;
    }
    if !cleanup.roots.is_empty() {
        formatter.write_str(",\"roots\":[")?;
        for (index, root) in cleanup.roots.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write_root(formatter, *root)?;
        }
        formatter.write_str("]")?;
    }
    if let Some(error) = cleanup.error_category {
        write!(
            formatter,
            ",\"root_error_category\":\"{}\"",
            error.diagnostic_category(),
        )?;
    }
    if let Some(prior) = &cleanup.prior {
        formatter.write_str(",\"prior\":")?;
        write_cleanup_diagnostic(formatter, prior)?;
    }
    if let (Some(baseline), Some(stopped), Some(delta)) = (
        cleanup.owner_baseline,
        cleanup.owner_stopped,
        cleanup.owner_delta,
    ) {
        formatter.write_str(",\"owner_baseline\":")?;
        write_owner_snapshot(formatter, baseline)?;
        formatter.write_str(",\"owner_stopped\":")?;
        write_owner_snapshot(formatter, stopped)?;
        formatter.write_str(",\"owner_delta\":")?;
        write_owner_delta(formatter, delta)?;
    }
    formatter.write_str("}")
}

/// Fully materializes a prepared schema-v2 client before any listener or TUN
/// root is allowed to prepare. The returned process owns the bootstrap DNS,
/// RuleSet refresh, and egress bridge lifecycle for its entire run.
pub(crate) fn run_prepared(prepared: PreparedClientV2) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
        let metrics = Arc::new(Metrics::new());
        let underlay = ferrum2_tun::UnderlayPublisher::new();
        let context = materialize::ClientV2MaterializeContext::new(Arc::clone(&metrics), underlay);
        let materialized = materialize::materialize_prepared(prepared, &context).await?;
        let subscriber = json_subscriber(
            std::io::stderr,
            log_level(materialized.config().logging.level),
        );
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            materialized.validate_only_shutdown().await?;
            return Err(RunError::StartupObservability);
        }
        let (config, materialization_root, materialized_cache, underlay) =
            materialized.into_run_parts().await?;
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
        run_with_registry_and_metrics_inner(
            config,
            OwnerRegistry::new(),
            shutdown_signal(),
            metrics,
            None,
            #[cfg(test)]
            None,
            ClientRunResources {
                materialization_root,
                materialized_cache,
                materialized_underlay: Some(underlay),
                dns_specs,
            },
        )
        .await
    })
}

/// Performs the opt-in networked validation pass, then explicitly joins every
/// bootstrap owner without constructing a listener, TUN, or refresh root.
pub(crate) fn validate_prepared_materialization(
    prepared: PreparedClientV2,
) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
        let metrics = Arc::new(Metrics::new());
        let context = materialize::ClientV2MaterializeContext::new(
            metrics,
            ferrum2_tun::UnderlayPublisher::new(),
        );
        let materialized = materialize::materialize_prepared(prepared, &context).await?;
        materialized.validate_only_shutdown().await.map(|_| ())
    })
}

struct ClientRunResources {
    materialization_root: Option<materialize::ClientV2RuntimeRoot>,
    materialized_cache: Option<DnsCache>,
    materialized_underlay: Option<ferrum2_tun::UnderlayPublisher>,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
}

impl ClientRunResources {
    #[cfg(test)]
    const fn test_unmaterialized(dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>) -> Self {
        Self {
            materialization_root: None,
            materialized_cache: None,
            materialized_underlay: None,
            dns_specs,
        }
    }
}

#[cfg(test)]
async fn run_with_registry<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    run_with_registry_and_metrics(config, registry, shutdown, Arc::new(Metrics::new())).await
}

#[cfg(test)]
async fn run_with_registry_and_metrics<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    run_with_registry_and_metrics_inner(
        config,
        registry,
        shutdown,
        metrics,
        None,
        #[cfg(test)]
        None,
        ClientRunResources::test_unmaterialized(dns_specs),
    )
    .await
}

async fn run_with_registry_and_metrics_inner<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    _udp_id_random: Option<Arc<dyn SecureRandom>>,
    #[cfg(test)] mut dns_observer: Option<
        tokio::sync::oneshot::Sender<(Arc<ClientContext>, Arc<TaggedResolver>)>,
    >,
    resources: ClientRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let ClientRunResources {
        mut materialization_root,
        materialized_cache,
        materialized_underlay,
        dns_specs,
    } = resources;
    let result = async {
        publish_rule_program_metadata(&config, &metrics);
        emit_deprecated_tun_memory_warning(&config);
        let selector = config.selector_control();
        let tun_config = config.tun;
        let tun_auto_route = tun_config.as_ref().is_some_and(|tun| tun.auto_route);
        let tun_direct = tun_config.is_some()
            && config.outbounds.iter().any(|outbound| {
                matches!(
                    outbound,
                    ferrum2_config::ClientOutboundConfig::Direct { .. }
                )
            });
        let underlay = materialized_underlay.unwrap_or_default();
        let mut dns = match (config.dns, config.dns_route, dns_specs) {
            (
                Some(DnsConfig {
                    inbounds,
                    servers,
                    route,
                    timeout,
                    max_inflight,
                    runtime,
                }),
                policy,
                Some(specs),
            ) => {
                let internal_udp_needed = servers
                    .iter()
                    .any(|server| server.transport == ferrum2_config::DnsTransport::Udp);
                Some((
                    inbounds,
                    specs,
                    route,
                    policy,
                    timeout,
                    max_inflight,
                    runtime,
                    internal_udp_needed,
                ))
            }
            (None, None, None) => None,
            _ => return Err(RunError::StartupProtocol),
        };
        let dns_proxy_runtime = dns
            .as_mut()
            .map(|dns| {
                ClientDnsProxyRuntime::try_new(dns.3.as_mut(), dns.6, materialized_cache, &metrics)
            })
            .transpose()?;
        if let Some(dns) = dns.as_mut()
            && dns
                .3
                .as_ref()
                .is_some_and(|policy| !policy.has_compatibility_program())
        {
            dns.3 = None;
        }
        let ordinary_dns = dns.as_ref().map(|_| Arc::new(std::sync::OnceLock::new()));
        let tagged_dns = Arc::new(std::sync::OnceLock::new());
        let application_resolver = ApplicationResolver::system_default();
        let application_resolver = ApplicationResolverAdapter::new(
            Arc::new(observed_application_resolver(
                application_resolver,
                &metrics,
            )),
            0,
            DnsStrategy::PreferIpv4,
        );
        let direct_resolvers =
            client_direct_resolvers(&config.outbounds, Arc::clone(&tagged_dns), &metrics);
        metrics.set_udp_sessions_active(Role::Client, 0);
        metrics.set_udp_buffered_bytes(Role::Client, 0);
        let configured_udp = config.udp;
        let public_udp_enabled = configured_udp.is_some_and(|udp| udp.enabled);
        let tun_udp_defaults = tun_config.as_ref().map(|_| {
            let defaults = UdpRuntimeLimits::default();
            (
                defaults.max_sessions(),
                defaults.max_buffered_bytes(),
                defaults.idle_timeout(),
            )
        });
        let internal_udp_needed =
            dns.as_ref().is_some_and(|dns| dns.7) || tun_udp_defaults.is_some();
        let udp_limits = if let Some(udp) = configured_udp {
            Some((udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout))
        } else if let Some(defaults) = tun_udp_defaults {
            Some(defaults)
        } else if let Some(dns) = dns.as_ref().filter(|dns| dns.7) {
            let sessions = usize::from(dns.5.get());
            let bytes = sessions
                .checked_mul(3 * MAX_UDP_WIRE_LEN)
                .ok_or(RunError::StartupProtocol)?
                .clamp(MIN_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_BUFFERED_BYTES);
            Some((sessions, bytes, dns.4.max(MIN_UDP_IDLE_TIMEOUT)))
        } else {
            None
        };
        let tun_udp_idle_timeout = tun_config
            .as_ref()
            .map(|_| udp_limits.expect("TUN UDP requires internal limits").2);
        let runtime = config.runtime;
        #[cfg(test)]
        let test_udp_server = match config.outbounds[0].server().expect("proxy-only runtime") {
            std::net::SocketAddr::V4(server) => server,
            std::net::SocketAddr::V6(_) => panic!("IPv4-only legacy test context"),
        };
        let outbounds = prepare_client_outbounds(config.outbounds)?;
        let shutdown_grace = config.runtime.shutdown_grace;
        let listen_backlog = u32::from(config.runtime.listen_backlog.get());
        let max_connections = usize::from(config.runtime.max_connections.get());
        let udp = if public_udp_enabled || internal_udp_needed {
            let (max_sessions, max_buffered_bytes, idle_timeout) =
                udp_limits.expect("enabled UDP requires validated limits");
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::new(max_sessions, max_buffered_bytes, idle_timeout)
                        .map_err(|_| RunError::StartupProtocol)?,
                    registry.clone(),
                ),
                live_ids: Arc::new(std::sync::Mutex::new(HashSet::new())),
            })
        } else {
            None
        };
        #[cfg(all(windows, not(test)))]
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                egress::ManagedTcpDialer::new(underlay.clone()),
                application_resolver.clone(),
                config.runtime.connect_timeout,
            ));
        #[cfg(any(not(windows), test))]
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                application_resolver.clone(),
                config.runtime.connect_timeout,
            ));
        let egress = Arc::new(
            ClientEgressEngine::new_with_direct_resolvers(
                Arc::clone(&outbounds),
                connector,
                SystemClock::new(),
                SystemRandom,
                (
                    config.runtime.connect_timeout,
                    config.runtime.handshake_timeout,
                ),
                udp,
                application_resolver,
                direct_resolvers,
                #[cfg(test)]
                _udp_id_random,
            )
            .with_underlay(underlay.clone(), tun_auto_route),
        );
        let context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::clone(&egress),
            #[cfg(test)]
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                test_support::default_test_psk(),
            )),
            runtime: config.runtime,
            udp_associate_enabled: public_udp_enabled,
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
            dns: ordinary_dns.as_ref().map(Arc::clone),
            #[cfg(test)]
            test_udp_server,
        });
        let mut listens = Vec::with_capacity(config.inbounds.len());
        let tun_inbound = config.inbounds.len();
        let routing = Arc::new(ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
            selector,
        });
        // Probe caller-owned route scratch before any listener is prepared so
        // an allocation/capacity failure has a stable process-level category.
        let _ = routing
            .route_scratch()
            .map_err(run_error_for_rule_compile)?;
        #[cfg(test)]
        let dns_context = Arc::clone(&context);
        let dns_egress = Arc::clone(&egress);
        for inbound in &config.inbounds {
            listens.push(inbound.listen);
        }
        let tcp_registry = registry.clone();
        let tcp_context = Arc::clone(&context);
        let tcp_routing = Arc::clone(&routing);
        let mut roots = ClientProcessRoots::default();
        if let Some(prepared) = materialization_root.take() {
            roots.push(
                ClientRootName::Bootstrap,
                ProcessRoot::new(move || async move { Ok(prepared) }),
            );
        }
        if !listens.is_empty() {
            roots.push(
                ClientRootName::Socks,
                ProcessRoot::new(move || async move {
                    let mut listeners = Vec::with_capacity(listens.len());
                    for listen in listens {
                        listeners.push(bind_listener(listen, listen_backlog)?);
                    }
                    let supervisor = BoundedSupervisor::new(
                        ClientTcpListeners {
                            listeners,
                            next: AtomicUsize::new(0),
                            #[cfg(test)]
                            accept_errors: None,
                        },
                        max_connections,
                        shutdown_grace,
                        tcp_registry,
                    )
                    .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ClientTcpRoot {
                        supervisor: Some(supervisor),
                        context: tcp_context,
                        routing: tcp_routing,
                    })
                }),
            );
        }
        if let Some((inbounds, servers, route, policy, timeout, max_inflight, _, _)) = dns {
            let ordinary_dns = ordinary_dns.expect("validated DNS graph has an ordinary handle");
            let tagged_dns = Arc::clone(&tagged_dns);
            let addresses = inbounds.into_iter().map(|inbound| inbound.listen).collect();
            let route = Arc::new(route);
            roots.push(
                ClientRootName::Dns,
                ProcessRoot::new(move || async move {
                    let sockets = DnsProxySockets::bind(
                        addresses,
                        listen_backlog,
                        runtime.max_connections,
                        runtime.idle_timeout,
                    )
                    .await
                    .map_err(|_| RunError::StartupBind)?;
                    let egress =
                        Arc::new(dns_egress::ClientDnsEgress::new(Arc::clone(&dns_egress)));
                    let (resolver, owner) =
                        TaggedResolver::new(servers, timeout, max_inflight, egress)
                            .map_err(|_| RunError::StartupProtocol)?;
                    let resolver = Arc::new(resolver);
                    tagged_dns
                        .set(Arc::downgrade(&resolver))
                        .map_err(|_| RunError::StartupProtocol)?;
                    #[cfg(test)]
                    if let Some(observer) = dns_observer.take() {
                        let _ = observer.send((Arc::clone(&dns_context), Arc::clone(&resolver)));
                    }
                    let selection = Arc::clone(&route);
                    let policy_scratch = policy
                        .as_ref()
                        .filter(|policy| policy.has_compatibility_program())
                        .map(ferrum2_config::ClientDnsRoute::evaluation_scratch)
                        .transpose()
                        .map_err(run_error_for_rule_compile)?
                        .map(std::sync::Mutex::new);
                    let mut proxy = DnsProxy::new(
                        Arc::clone(&resolver),
                        move |ingress, transport, name, qtype| {
                            let network = match transport {
                                ProxyTransport::Udp => Network::Udp,
                                ProxyTransport::Tcp => Network::Tcp,
                            };
                            let Ok(target) = TargetAddr::domain(&name.to_ascii(), 53) else {
                                return Some(selection.final_action());
                            };
                            let qtype = dns_egress::dns_query_type(qtype);
                            match (&policy, ingress) {
                                (Some(policy), ProxyIngress::Listener(inbound)) => {
                                    let policy_scratch = policy_scratch.as_ref()?;
                                    let mut scratch = policy_scratch
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    policy.select_with_scratch(
                                        DnsIngressId::Listener(inbound),
                                        network,
                                        &target,
                                        qtype,
                                        &mut scratch,
                                    )
                                }
                                (Some(policy), ProxyIngress::Ordinary(inbound)) => {
                                    let policy_scratch = policy_scratch.as_ref()?;
                                    let mut scratch = policy_scratch
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    policy.select_with_scratch(
                                        DnsIngressId::Ordinary(inbound),
                                        network,
                                        &target,
                                        qtype,
                                        &mut scratch,
                                    )
                                }
                                (None, ProxyIngress::Listener(inbound)) => {
                                    Some(selection.select(inbound, network, &target))
                                }
                                (None, ProxyIngress::Ordinary(_)) => None,
                            }
                        },
                    );
                    if let Some(runtime) = dns_proxy_runtime {
                        proxy = runtime.bind(proxy);
                    }
                    let proxy = Arc::new(proxy);
                    ordinary_dns
                        .set(Arc::clone(&proxy))
                        .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ClientDnsRoot {
                        listeners: Some(sockets.with_proxy(proxy)),
                        resolver: Some(resolver),
                        owner: Some(owner),
                        #[cfg(test)]
                        readiness_gate: None,
                    })
                }),
            );
        }
        if let Some(metrics_config) = config.metrics {
            let metrics_registry = registry.clone();
            roots.push(
                ClientRootName::Metrics,
                ProcessRoot::new(move || async move {
                    let listener = bind_listener(metrics_config.listen, 16)?;
                    Ok(ClientMetricsRoot {
                        listener: Some(listener),
                        metrics,
                        registry: metrics_registry,
                    })
                }),
            );
        }
        if let Some(tun_config) = tun_config {
            roots.push(
                ClientRootName::Tun,
                tun::process_root(
                    tun_config,
                    tun_udp_idle_timeout.expect("TUN UDP idle retained"),
                    Arc::clone(&context),
                    routing,
                    tun_inbound,
                    underlay,
                    tun_direct,
                ),
            );
        }
        let (roots, root_names) = roots.into_parts();
        let owner_baseline = registry.snapshot();
        let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry.clone())
            .map_err(|_| RunError::StartupProtocol)?;
        let report = supervisor.run_until(shutdown).await;
        let owner_stopped = registry.snapshot();
        let diagnostic = ShutdownDiagnostic::classify(
            &report,
            &root_names,
            shutdown_grace,
            owner_baseline,
            owner_stopped,
        );
        // This record is closed over client enums, monotonic durations, and owner
        // counters: no config, addresses, payloads, keys, or error text can enter it.
        // Diagnostics must never replace the process result when stderr is closed.
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::Write::write_fmt(&mut stderr, format_args!("{diagnostic}\n"));
        report_result(report)
    }
    .await;
    if let Some(mut root) = materialization_root {
        let cleanup = root.cleanup().await;
        return result.and(cleanup);
    }
    result
}

const fn dns_strategy(strategy: ferrum2_config::DnsStrategy) -> DnsStrategy {
    match strategy {
        ferrum2_config::DnsStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        ferrum2_config::DnsStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        ferrum2_config::DnsStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        ferrum2_config::DnsStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}

fn client_direct_resolvers(
    outbounds: &[ClientOutboundConfig],
    tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
    metrics: &Arc<Metrics>,
) -> Arc<[Option<ApplicationResolverAdapter>]> {
    let system = Arc::new(observed_application_resolver(
        ApplicationResolver::system_default(),
        metrics,
    ));
    outbounds
        .iter()
        .map(|outbound| {
            let mode = outbound.direct_domain_resolver()?;
            let (resolver, strategy) = match mode {
                DirectDomainResolver::System => (Arc::clone(&system), DnsStrategy::PreferIpv4),
                DirectDomainResolver::DnsServer { server, strategy } => {
                    let resolver = ApplicationResolver::configured(Arc::new(
                        TaggedServerApplicationResolveBackend::new(Arc::clone(&tagged), server),
                    ));
                    (
                        Arc::new(observed_application_resolver(resolver, metrics)),
                        dns_strategy(strategy),
                    )
                }
            };
            Some(ApplicationResolverAdapter::new(resolver, 0, strategy))
        })
        .collect::<Vec<_>>()
        .into()
}

fn observed_application_resolver(
    resolver: ApplicationResolver,
    metrics: &Arc<Metrics>,
) -> ApplicationResolver {
    let metrics = Arc::clone(metrics);
    resolver.with_observer(Arc::new(move |mode, outcome| {
        let resolver = match mode {
            ApplicationResolverMode::System => {
                metrics.dns_explicit_system_resolve(
                    ferrum2_observability::DnsResolvePurpose::Application,
                );
                ferrum2_observability::DnsResolverKind::System
            }
            ApplicationResolverMode::Configured => {
                ferrum2_observability::DnsResolverKind::Configured
            }
        };
        let result = match outcome {
            ApplicationResolveOutcome::Success => ferrum2_observability::DnsResolveResult::Success,
            ApplicationResolveOutcome::Failure => ferrum2_observability::DnsResolveResult::Failure,
        };
        metrics.dns_resolve(
            resolver,
            ferrum2_observability::DnsResolvePurpose::Application,
            result,
        );
    }))
}

fn publish_rule_program_metadata(config: &ValidatedClientConfig, metrics: &Metrics) {
    if let Some(route) = config.route_program.as_ref() {
        metrics.set_rule_program_mode(RuleProgram::Route, rule_program_mode(route.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::Route, route.rule_count());
    }
    let Some(dns) = config.dns_route.as_ref() else {
        return;
    };
    if let Some(binding) = dns.policy_blueprint() {
        let blueprint = binding.blueprint();
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, blueprint.len());
        metrics.set_rule_program_mode(
            RuleProgram::DnsResponse,
            rule_program_mode(dns.program_mode()),
        );
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, blueprint.response_rule_count());
    } else {
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, dns.rule_count());
        metrics.set_rule_program_mode(RuleProgram::DnsResponse, RuleProgramMode::SmallLinear);
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, 0);
    }
}

const fn rule_program_mode(mode: ferrum2_rule::RuleProgramMode) -> RuleProgramMode {
    match mode {
        ferrum2_rule::RuleProgramMode::SmallLinear => RuleProgramMode::SmallLinear,
        ferrum2_rule::RuleProgramMode::Indexed => RuleProgramMode::Indexed,
    }
}

fn dns_policy_observer(metrics: &Arc<Metrics>) -> Arc<dyn DnsPolicyObserver> {
    let metrics = Arc::clone(metrics);
    Arc::new(move |observation| observe_dns_policy(&metrics, observation))
}

fn observe_dns_policy(metrics: &Metrics, observation: DnsPolicyObservation) {
    if observation.query_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsQuery,
            observation.query_candidates(),
        );
        metrics.observe_rule_program_match_ns(RuleProgram::DnsQuery, observation.query_match_ns());
    }
    if observation.response_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsResponse,
            observation.response_candidates(),
        );
        metrics.observe_rule_program_match_ns(
            RuleProgram::DnsResponse,
            observation.response_match_ns(),
        );
    }
    for stage in DnsPolicyStage::ALL {
        for source in DnsPolicyMatchSource::ALL {
            for r#type in DnsPolicyMatchType::ALL {
                for result in DnsPolicyMatchResult::ALL {
                    let count = observation.match_count(stage, source, r#type, result);
                    if count == 0 {
                        continue;
                    }
                    let source = match source {
                        DnsPolicyMatchSource::Inline => RuleSource::Inline,
                        DnsPolicyMatchSource::RuleSet => RuleSource::RuleSet,
                    };
                    let r#type = match r#type {
                        DnsPolicyMatchType::Domain => RuleMatchType::Domain,
                        DnsPolicyMatchType::DomainSuffix => RuleMatchType::DomainSuffix,
                        DnsPolicyMatchType::DomainKeyword => RuleMatchType::DomainKeyword,
                        DnsPolicyMatchType::IpCidr => RuleMatchType::IpCidr,
                        DnsPolicyMatchType::Scalar => RuleMatchType::Scalar,
                    };
                    let result = match result {
                        DnsPolicyMatchResult::Matched => RuleMatchResult::Matched,
                        DnsPolicyMatchResult::Missed => RuleMatchResult::Missed,
                    };
                    match stage {
                        DnsPolicyStage::Query => {
                            metrics.dns_rule_query_matches(source, r#type, result, count);
                        }
                        DnsPolicyStage::Response => {
                            metrics.dns_rule_response_matches(source, r#type, result, count);
                        }
                    }
                }
            }
        }
    }
}

struct ClientDnsProxyPolicy {
    program: Arc<DnsPolicyProgram>,
    registry: Arc<RuleEngineRegistry>,
    listener_count: usize,
    ordinary_count: usize,
}

struct ClientDnsProxyRuntime {
    policy: Option<ClientDnsProxyPolicy>,
    observer: Arc<dyn DnsPolicyObserver>,
    cache: Option<DnsCache>,
    generation: ResolverGeneration,
}

impl ClientDnsProxyRuntime {
    fn try_new(
        route: Option<&mut ferrum2_config::ClientDnsRoute>,
        runtime: ferrum2_config::DnsRuntimeConfig,
        materialized_cache: Option<DnsCache>,
        metrics: &Arc<Metrics>,
    ) -> Result<Self, RunError> {
        let policy = route
            .and_then(ferrum2_config::ClientDnsRoute::take_policy_blueprint)
            .map(|binding| {
                let (blueprint, registry, listener_count, ordinary_count) = binding.into_parts();
                let snapshot = registry.snapshot();
                let program = DnsPolicyProgram::try_from_blueprint(blueprint, &snapshot)
                    .map_err(run_error_for_dns_policy_compile)?;
                Ok::<ClientDnsProxyPolicy, RunError>(ClientDnsProxyPolicy {
                    program: Arc::new(program),
                    registry,
                    listener_count,
                    ordinary_count,
                })
            })
            .transpose()?;
        let generation = policy
            .as_ref()
            .map_or(ResolverGeneration::new(0), |policy| {
                ResolverGeneration::new(policy.registry.generation())
            });
        let cache_config = runtime.cache();
        let cache = if cache_config.enabled {
            match materialized_cache {
                Some(cache) => Some(cache),
                None => Some(
                    DnsCache::try_new(
                        std::num::NonZeroUsize::new(cache_config.max_entries)
                            .ok_or(RunError::StartupProtocol)?,
                    )
                    .map_err(|_| RunError::StartupProtocol)?,
                ),
            }
        } else {
            None
        };
        Ok(Self {
            policy,
            observer: dns_policy_observer(metrics),
            cache,
            generation,
        })
    }

    fn bind(self, mut proxy: DnsProxy) -> DnsProxy {
        if let Some(policy) = self.policy {
            proxy = proxy.with_policy(
                policy.program,
                policy.registry,
                policy.listener_count,
                policy.ordinary_count,
            );
            proxy = proxy.with_policy_observer(self.observer);
        }
        if let Some(cache) = self.cache {
            proxy = proxy.with_cache(cache, self.generation);
        }
        proxy
    }
}

fn report_result(report: ProcessReport<RunError>) -> Result<(), RunError> {
    if report.cleanup_failure().is_some() {
        return Err(RunError::ShutdownCleanup);
    }
    match report.cause() {
        ProcessCause::ExternalShutdown => Ok(()),
        ProcessCause::PreparationFailed { error, .. }
        | ProcessCause::ActivationFailed { error, .. } => Err(*error),
        ProcessCause::PreparationPanicked { .. } | ProcessCause::ActivationPanicked { .. } => {
            Err(RunError::StartupProtocol)
        }
        ProcessCause::RootStopped { exit, .. } => match exit {
            ProcessRootExit::Failed(error) => Err(*error),
            ProcessRootExit::Panicked | ProcessRootExit::JoinFailed => Err(RunError::RuntimeChild),
            ProcessRootExit::Completed => Err(RunError::RuntimeRoot),
        },
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
