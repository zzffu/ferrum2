#![cfg(all(windows, not(test)))]

use std::time::Duration;

use ferrum2_platform_windows::{NetworkChangeWaitOutcome, WindowsNetworkChangeMonitor};
use ferrum2_runtime::{RetainedMonitor, RetainedMonitorOwner, RetainedMonitorWait};

use super::RunError;

struct NativeMonitor(WindowsNetworkChangeMonitor);

impl RetainedMonitor for NativeMonitor {
    type Outcome = NetworkChangeWaitOutcome;
    type Error = ();
    type Stop = ferrum2_platform_windows::StopSignal;

    fn stop(&self) -> Self::Stop {
        self.0.stop_signal()
    }

    fn signal(stop: &Self::Stop) -> Result<(), Self::Error> {
        stop.signal().map_err(|_| ())
    }

    fn wait(&mut self, timeout: Duration) -> Result<Self::Outcome, Self::Error> {
        self.0.wait(timeout).map_err(|_| ())
    }

    fn close(self) -> Result<(), Self::Error> {
        self.0.close().map_err(|_| ())
    }
}

pub(super) struct NativeNetworkChangeOwner(RetainedMonitorOwner<NativeMonitor>);

#[derive(Clone)]
pub(super) struct NativeNetworkChangeWait(RetainedMonitorWait<NativeMonitor>);

impl NativeNetworkChangeOwner {
    pub(super) fn new(monitor: WindowsNetworkChangeMonitor) -> (Self, NativeNetworkChangeWait) {
        let (owner, waiter) = RetainedMonitorOwner::new(NativeMonitor(monitor));
        (Self(owner), NativeNetworkChangeWait(waiter))
    }

    pub(super) async fn shutdown(&mut self) -> Result<(), RunError> {
        self.0
            .shutdown()
            .await
            .map_err(|_| RunError::ShutdownCleanup)
    }
}

impl NativeNetworkChangeWait {
    pub(super) async fn wait(
        &self,
        timeout: Duration,
    ) -> Result<NetworkChangeWaitOutcome, RunError> {
        self.0
            .wait(timeout)
            .await
            .map_err(|_| RunError::RuntimeRoot)
    }
}
