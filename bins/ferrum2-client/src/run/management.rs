use std::sync::{Arc, RwLock};
use std::time::Duration;

use ferrum2_dashboard::Dashboard;
use ferrum2_runtime::{OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture};
use serde_json::json;

use super::RunError;
use super::dashboard_control::ClientDashboardControl;

pub(crate) type ControlSlot = Arc<RwLock<Option<Arc<ClientDashboardControl>>>>;

/// One generation's observation and control publication lineage.
#[derive(Clone)]
pub(crate) struct Management {
    pub(crate) dashboard: Dashboard,
    pub(crate) controls: ControlSlot,
    pub(crate) log_level: Arc<std::sync::atomic::AtomicU8>,
}

pub(super) struct ManagementRoot {
    pub(super) management: Management,
    pub(super) control: Arc<ClientDashboardControl>,
    pub(super) registry: OwnerRegistry,
    pub(super) socks_count: usize,
    pub(super) dns_enabled: bool,
    pub(super) tun_enabled: bool,
    pub(super) recording_max_bytes: Option<u64>,
}

impl ManagementRoot {
    fn publish(&self) {
        let owners = self.registry.snapshot();
        self.management.dashboard.set_resources(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "socks_state": if self.socks_count == 0 { "disabled" } else { "running" },
            "dns_state": if self.dns_enabled { "running" } else { "disabled" },
            "tun_state": if self.tun_enabled { "running" } else { "disabled" },
            "rocom_state": if self.recording_max_bytes.is_some() { "configured" } else { "disabled" },
            "rocom_max_bytes": self.recording_max_bytes.map(|limit| limit.to_string()),
            "tcp_connections": owners.connection_tasks,
            "tun_tcp_flows": owners.active_tun_tcp_flows,
            "udp_sessions": owners.udp_sessions,
            "udp_buffered_bytes": owners.udp_buffered_bytes,
            "tun_udp_buffered_bytes": owners.tun_udp_buffered_bytes,
            "process_roots": owners.active_process_roots,
            "listeners": owners.listeners,
            "tun_handler_tasks": owners.active_tun_handler_tasks,
            "forced_shutdowns": owners.forced_shutdowns,
        }));
        self.management
            .dashboard
            .set_domains(self.control.snapshot());
    }

    fn retire(&self) {
        *self
            .management
            .controls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.management
            .dashboard
            .set_domains(json!({"capabilities":[]}));
    }
}

impl PreparedProcessRoot<RunError> for ManagementRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        // This is the last required root: every preceding activation succeeded.
        *self
            .management
            .controls
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&self.control));
        self.management.dashboard.set_runtime("running", None);
        self.publish();
        Ok(())
    }

    fn run(
        self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            let mut sample = tokio::time::interval(Duration::from_secs(1));
            sample.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = sample.tick() => self.publish(),
                }
            }
            self.retire();
            self.control.shutdown().await;
            Ok(())
        })
    }
    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            self.retire();
            self.control.shutdown().await;
            Ok(())
        })
    }
}
