use crate::qualification::{
    CaseFailure, CaseSpec, CleanupState, DnsCaseSpec, DnsQualificationOps, DnsReference,
    QualificationOps, Reference,
};
use std::process::Child;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const CASE_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const CHILD_OUTPUT_CAP: usize = 256 * 1024;
const MAX_UDP_DATAGRAM: usize = 65_507;
const SESSION_DATAGRAMS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_millis(20);

static CLEANUP_STATE: OnceLock<Mutex<CleanupState>> = OnceLock::new();

type PendingOwners = (Vec<Child>, Vec<thread::JoinHandle<()>>);
static PENDING: OnceLock<Mutex<PendingOwners>> = OnceLock::new();

fn cleanup_state(operation: impl FnOnce(&mut CleanupState)) {
    operation(
        &mut CLEANUP_STATE
            .get_or_init(|| Mutex::new(CleanupState::default()))
            .lock()
            .expect("cleanup state lock"),
    );
}

fn pending() -> &'static Mutex<PendingOwners> {
    PENDING.get_or_init(|| Mutex::new((Vec::new(), Vec::new())))
}

fn retain_unconfirmed_worker(worker: thread::JoinHandle<()>) {
    pending().lock().expect("pending owner lock").1.push(worker);
}

pub struct HostedOperations;

impl HostedOperations {
    pub const fn new() -> Self {
        Self
    }
}

impl QualificationOps for HostedOperations {
    fn provision(&mut self, reference: Reference) -> Result<(), CaseFailure> {
        match catch_sanitized(|| provision_reference(reference)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification provision failed: reference={reference:?}, diagnostic={}",
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(reference.provision_root()))
            }
        }
    }

    fn run_case(&mut self, case: CaseSpec) -> Result<(), CaseFailure> {
        match catch_sanitized(|| run_case(case)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification case failed: case_id={}, diagnostic={}",
                    case.id,
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(case.case_root()))
            }
        }
    }

    fn finish_cleanup(&mut self) -> Result<(), CaseFailure> {
        let owners_finished = {
            let pending = pending().lock().expect("pending owner lock");
            pending.0.is_empty() && pending.1.is_empty()
        };
        let state = *CLEANUP_STATE
            .get_or_init(|| Mutex::new(CleanupState::default()))
            .lock()
            .expect("cleanup state lock");
        if owners_finished && state.success() {
            Ok(())
        } else {
            Err(CaseFailure::new("cleanup"))
        }
    }
}

impl DnsQualificationOps for HostedOperations {
    fn provision_dns(&mut self, reference: DnsReference) -> Result<(), CaseFailure> {
        match catch_sanitized(|| provision_dns_reference(reference)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification DNS provision failed: reference={reference:?}, diagnostic={}",
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(reference.provision_root()))
            }
        }
    }

    fn run_dns_case(&mut self, case: DnsCaseSpec) -> Result<(), CaseFailure> {
        match catch_sanitized(|| run_external_dns_case(case)) {
            Ok(()) => Ok(()),
            Err(payload) => {
                eprintln!(
                    "qualification DNS case failed: case_id={}, diagnostic={}",
                    case.id,
                    panic_diagnostic(payload)
                );
                Err(CaseFailure::new(case.case_root()))
            }
        }
    }

    fn finish_dns_cleanup(&mut self) -> Result<(), CaseFailure> {
        self.finish_cleanup()
    }
}

mod case_dispatch;
mod config;
mod dns_case;
mod pin_hash;
mod process_guard;
mod provider_artifact;
mod tcp_case;
mod udp_case;

use case_dispatch::run_case;
use dns_case::run_external_dns_case;
use process_guard::catch_sanitized;
use provider_artifact::{panic_diagnostic, provision_dns_reference, provision_reference};
