use std::fmt;
use std::future::Future;
use std::time::Duration;

use ferrum2_runtime::{
    OwnerRegistry, ProcessCause, ProcessCleanupFailure, ProcessReport, ProcessResources,
    ProcessRoot, ProcessRootExit, ProcessRootId, ProcessSupervisor,
};

use super::RunError;
use super::error::EndpointAcquireError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootRole {
    TcpInbound,
    UdpInbound,
    Metrics,
    #[cfg(windows)]
    Network,
    Dns,
    Rules,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootDescriptor {
    pub(super) role: RootRole,
    pub(super) declaration_index: Option<usize>,
}

impl fmt::Display for RootDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = match self.role {
            RootRole::TcpInbound => "tcp_inbound",
            RootRole::UdpInbound => "udp_inbound",
            RootRole::Metrics => "metrics",
            #[cfg(windows)]
            RootRole::Network => "network",
            RootRole::Dns => "dns",
            RootRole::Rules => "rules",
        };
        match self.declaration_index {
            Some(index) => write!(formatter, "{role}[{index}]"),
            None => formatter.write_str(role),
        }
    }
}

/// Keeps diagnostic identity attached to roots through prepending and supervisor insertion order.
pub(super) struct ServerRoots {
    entries: Vec<(RootDescriptor, ProcessRoot<RunError>)>,
}

impl ServerRoots {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }
    pub(super) fn push(&mut self, descriptor: RootDescriptor, root: ProcessRoot<RunError>) {
        self.entries.push((descriptor, root));
    }
    pub(super) fn prepend(&mut self, descriptor: RootDescriptor, root: ProcessRoot<RunError>) {
        self.entries.insert(0, (descriptor, root));
    }

    pub(super) async fn run_until<S>(
        self,
        grace: Duration,
        registry: OwnerRegistry,
        resources: ProcessResources<RunError>,
        shutdown: S,
    ) -> Result<(), RunError>
    where
        S: Future<Output = ()> + Send,
    {
        let (descriptors, roots): (Vec<_>, Vec<_>) = self.entries.into_iter().unzip();
        let supervisor = ProcessSupervisor::new(roots, grace, registry)
            .map_err(|_| RunError::StartupProtocol)?
            .with_process_resources(resources);
        report_result(supervisor.run_until(shutdown).await, &descriptors)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RootFailure {
    descriptor: RootDescriptor,
    phase: &'static str,
    category: &'static str,
    acquisition: Option<EndpointAcquireError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupDiagnostic {
    kind: &'static str,
    root: Option<RootDescriptor>,
    error: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerRunFailure {
    primary: Option<RootFailure>,
    cleanup: Vec<CleanupDiagnostic>,
}

impl ServerRunFailure {
    pub(super) fn category(&self) -> &'static str {
        if self.cleanup.is_empty() {
            self.primary
                .as_ref()
                .expect("failure has a primary cause or cleanup failure")
                .category
        } else {
            "shutdown.cleanup"
        }
    }
}

impl fmt::Display for ServerRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "error[{}] process:", self.category())?;
        if let Some(primary) = &self.primary {
            write!(
                formatter,
                " root={} phase={} cause={}",
                primary.descriptor, primary.phase, primary.category
            )?;
            if let Some(acquisition) = primary.acquisition {
                write!(formatter, " acquisition={acquisition}")?;
            }
        } else {
            formatter.write_str(" phase=external_shutdown")?;
        }
        if self.cleanup.is_empty() {
            formatter.write_str(" cleanup=complete")?;
        }
        for failure in &self.cleanup {
            write!(formatter, " cleanup={}", failure.kind)?;
            if let Some(root) = failure.root {
                write!(formatter, " cleanup_root={root}")?;
            }
            if let Some(error) = failure.error {
                write!(formatter, " cleanup_cause={error}")?;
            }
        }
        Ok(())
    }
}

fn descriptor(roots: &[RootDescriptor], id: ProcessRootId) -> RootDescriptor {
    *roots
        .get(id.get())
        .expect("supervisor ids belong to this root plan")
}

fn root_failure(
    roots: &[RootDescriptor],
    id: ProcessRootId,
    phase: &'static str,
    error: &RunError,
) -> RootFailure {
    let (descriptor, acquisition) = if let RunError::StartupBind {
        descriptor,
        acquisition,
    } = error
    {
        (*descriptor, Some(*acquisition))
    } else {
        (descriptor(roots, id), None)
    };
    RootFailure {
        descriptor,
        phase,
        category: error.category(),
        acquisition,
    }
}

fn report_result(
    report: ProcessReport<RunError>,
    roots: &[RootDescriptor],
) -> Result<(), RunError> {
    let primary = match report.cause() {
        ProcessCause::ExternalShutdown => None,
        ProcessCause::PreparationFailed { root, error } => {
            Some(root_failure(roots, *root, "prepare", error))
        }
        ProcessCause::ActivationFailed { root, error } => {
            Some(root_failure(roots, *root, "activate", error))
        }
        ProcessCause::PreparationPanicked { root } => Some(root_failure(
            roots,
            *root,
            "prepare_panic",
            &RunError::StartupProtocol,
        )),
        ProcessCause::ActivationPanicked { root } => Some(root_failure(
            roots,
            *root,
            "activate_panic",
            &RunError::StartupProtocol,
        )),
        ProcessCause::RootStopped { root, exit } => Some(match exit {
            ProcessRootExit::Failed(error) => root_failure(roots, *root, "run", error),
            ProcessRootExit::Panicked => {
                root_failure(roots, *root, "run_panic", &RunError::RuntimeChild)
            }
            ProcessRootExit::JoinFailed => {
                root_failure(roots, *root, "run_join", &RunError::RuntimeChild)
            }
            ProcessRootExit::Completed => {
                root_failure(roots, *root, "run_completed", &RunError::RuntimeRoot)
            }
        }),
    };
    let mut cleanup = Vec::new();
    if let Some(failure) = report.cleanup_failure() {
        collect_cleanup(failure, roots, &mut cleanup);
    }
    if primary.is_none() && cleanup.is_empty() {
        return Ok(());
    }
    Err(RunError::ProcessFailure(Box::new(ServerRunFailure {
        primary,
        cleanup,
    })))
}

fn collect_cleanup(
    failure: &ProcessCleanupFailure<RunError>,
    roots: &[RootDescriptor],
    output: &mut Vec<CleanupDiagnostic>,
) {
    let diagnostic = match failure {
        ProcessCleanupFailure::FinalCleanupFailed { error, prior } => {
            if let Some(prior) = prior {
                collect_cleanup(prior, roots, output);
            }
            CleanupDiagnostic {
                kind: "final_failed",
                root: None,
                error: Some(error.category()),
            }
        }
        ProcessCleanupFailure::FinalCleanupPanicked { prior } => {
            if let Some(prior) = prior {
                collect_cleanup(prior, roots, output);
            }
            CleanupDiagnostic {
                kind: "final_panicked",
                root: None,
                error: None,
            }
        }
        ProcessCleanupFailure::RootFailed { root, error } => CleanupDiagnostic {
            kind: "root_failed",
            root: Some(descriptor(roots, *root)),
            error: Some(error.category()),
        },
        ProcessCleanupFailure::RootPanicked { root } => CleanupDiagnostic {
            kind: "root_panicked",
            root: Some(descriptor(roots, *root)),
            error: None,
        },
        ProcessCleanupFailure::RootJoinFailed { root } => CleanupDiagnostic {
            kind: "root_join_failed",
            root: Some(descriptor(roots, *root)),
            error: None,
        },
        ProcessCleanupFailure::OwnerMismatch { .. } => CleanupDiagnostic {
            kind: "owner_mismatch",
            root: None,
            error: None,
        },
        ProcessCleanupFailure::ForceReapTimedOut {
            roots: timed_out,
            prior,
        } => {
            if let Some(prior) = prior {
                collect_cleanup(prior, roots, output);
            }
            for root in timed_out {
                output.push(CleanupDiagnostic {
                    kind: "force_reap_timeout",
                    root: Some(descriptor(roots, *root)),
                    error: None,
                });
            }
            return;
        }
    };
    output.push(diagnostic);
}

#[cfg(test)]
mod tests;
