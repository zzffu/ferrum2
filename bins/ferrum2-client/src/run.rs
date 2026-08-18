use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use ferrum2_config::{DnsConfig, DnsIngressId, ValidatedClientConfig};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
use ferrum2_crypto::{SecureRandom, SystemClock, SystemRandom};
use ferrum2_dns::{DnsProxy, DnsProxySockets, ProxyIngress, ProxyTransport, TaggedResolver};
use ferrum2_observability::{Metrics, Role, json_subscriber};
use ferrum2_runtime::{
    BoundedSupervisor, MAX_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT,
    MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry, OwnerSnapshot, ProcessCause, ProcessCleanupFailure,
    ProcessReport, ProcessRoot, ProcessRootEventPhase, ProcessRootExit, ProcessRootExitCategory,
    ProcessRootId, ProcessState, ProcessSupervisor, UdpRuntimeLimits, UdpSessionManager,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
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
            Self::RuntimeListener => "runtime.listener",
            Self::RuntimeChild => "runtime.child",
            Self::RuntimeRoot => "runtime.root",
            Self::ShutdownCleanup => "shutdown.cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientRootName {
    Socks,
    Dns,
    Metrics,
    Tun,
}

impl ClientRootName {
    const fn as_str(self) -> &'static str {
        match self {
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

pub(crate) fn run(config: ValidatedClientConfig) -> Result<(), RunError> {
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    let subscriber = json_subscriber(std::io::stderr, log_level(config.logging.level));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| RunError::StartupObservability)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(run_async(config, dns_specs))
}

async fn run_async(
    config: ValidatedClientConfig,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError> {
    run_with_registry_and_metrics_inner(
        config,
        OwnerRegistry::new(),
        shutdown_signal(),
        Arc::new(Metrics::new()),
        None,
        #[cfg(test)]
        None,
        dns_specs,
    )
    .await
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
        dns_specs,
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
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let tun_config = config.tun;
    let tun_auto_route = tun_config.as_ref().is_some_and(|tun| tun.auto_route);
    let tun_direct = tun_config.is_some()
        && config
            .outbounds
            .iter()
            .any(|outbound| matches!(outbound, ferrum2_config::ClientOutboundConfig::Direct));
    let underlay = ferrum2_tun::UnderlayPublisher::new();
    let dns = match (config.dns, config.dns_route, dns_specs) {
        (
            Some(DnsConfig {
                inbounds,
                servers,
                route,
                timeout,
                max_inflight,
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
                internal_udp_needed,
            ))
        }
        (None, None, None) => None,
        _ => return Err(RunError::StartupProtocol),
    };
    let ordinary_dns = dns.as_ref().map(|_| Arc::new(std::sync::OnceLock::new()));
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
    let internal_udp_needed = dns.as_ref().is_some_and(|dns| dns.6) || tun_udp_defaults.is_some();
    let udp_limits = if let Some(udp) = configured_udp {
        Some((udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout))
    } else if let Some(defaults) = tun_udp_defaults {
        Some(defaults)
    } else if let Some(dns) = dns.as_ref().filter(|dns| dns.6) {
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
    let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::with_adapters(
        ferrum2_runtime::SystemSocketInspector,
        egress::ManagedTcpDialer::new(underlay.clone()),
        config.runtime.connect_timeout,
    ));
    #[cfg(any(not(windows), test))]
    let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::new(
        config.runtime.connect_timeout,
    ));
    let egress = Arc::new(
        ClientEgressEngine::new(
            Arc::clone(&outbounds),
            connector,
            SystemClock::new(),
            SystemRandom,
            (
                config.runtime.connect_timeout,
                config.runtime.handshake_timeout,
            ),
            udp,
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
    });
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
    if let Some((inbounds, servers, route, policy, timeout, max_inflight, _)) = dns {
        let ordinary_dns = ordinary_dns.expect("validated DNS graph has an ordinary handle");
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
                let egress = Arc::new(dns_egress::ClientDnsEgress::new(Arc::clone(&dns_egress)));
                let (resolver, owner) = TaggedResolver::new(servers, timeout, max_inflight, egress)
                    .map_err(|_| RunError::StartupProtocol)?;
                let resolver = Arc::new(resolver);
                #[cfg(test)]
                if let Some(observer) = dns_observer.take() {
                    let _ = observer.send((Arc::clone(&dns_context), Arc::clone(&resolver)));
                }
                let selection = Arc::clone(&route);
                let proxy = Arc::new(DnsProxy::new(
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
                            (Some(policy), ProxyIngress::Listener(inbound)) => policy.select(
                                DnsIngressId::Listener(inbound),
                                network,
                                &target,
                                qtype,
                            ),
                            (Some(policy), ProxyIngress::Ordinary(inbound)) => policy.select(
                                DnsIngressId::Ordinary(inbound),
                                network,
                                &target,
                                qtype,
                            ),
                            (None, ProxyIngress::Listener(inbound)) => {
                                Some(selection.select(inbound, network, &target))
                            }
                            (None, ProxyIngress::Ordinary(_)) => None,
                        }
                    },
                ));
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
