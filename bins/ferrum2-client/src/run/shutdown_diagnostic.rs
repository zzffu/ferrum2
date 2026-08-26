use ferrum2_runtime::{
    OwnerSnapshot, ProcessCause, ProcessCleanupFailure, ProcessReport, ProcessRootEventPhase,
    ProcessRootExit, ProcessRootExitCategory, ProcessRootId, ProcessState,
};

use super::RunError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientRootName {
    Bootstrap,
    Socks,
    Dns,
    #[cfg(all(windows, not(test)))]
    Network,
    Metrics,
    Tun,
}

impl ClientRootName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Socks => "socks",
            Self::Dns => "dns",
            #[cfg(all(windows, not(test)))]
            Self::Network => "network",
            Self::Metrics => "metrics",
            Self::Tun => "tun",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ClientRootNames(Vec<ClientRootName>);

impl ClientRootNames {
    pub(super) fn new(names: Vec<ClientRootName>) -> Self {
        Self(names)
    }

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
            network_reset_hooks,
            network_runtime_owners,
            network_reset_drivers,
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
pub(super) struct ShutdownDiagnostic {
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
    pub(super) fn classify(
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

#[cfg(test)]
mod tests;
