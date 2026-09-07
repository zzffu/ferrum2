use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferrum2_net::{NetworkInterfaceCatalog, NetworkInterfaceResolver, NetworkSnapshot};
use tokio::sync::{oneshot, watch};

use super::monitor_owner::{
    NetworkSocketOwnerError, Registrar, TrackedTask, capture_accounting, lock,
};

struct CaptureWaiter(Arc<AtomicBool>);
impl Drop for CaptureWaiter {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

pub(super) async fn capture<C: NetworkInterfaceCatalog + 'static>(
    registrar: &Registrar,
    resolver: Arc<NetworkInterfaceResolver<C>>,
    generation: u64,
) -> Result<NetworkSnapshot, NetworkSocketOwnerError> {
    let shared = registrar.shared()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let _waiter = CaptureWaiter(Arc::clone(&cancelled));
    let (reply, result) = oneshot::channel();
    let task = {
        let mut state = lock(&shared.state);
        if !state.accepting {
            return Err(NetworkSocketOwnerError::Closed);
        }
        if state.capture.as_ref().is_some_and(|task| task.reap_ready()) {
            state.capture = None;
        }
        if state.capture.is_some() {
            return Err(NetworkSocketOwnerError::Busy);
        }
        let (stop, stopping) = watch::channel(false);
        let accounting = capture_accounting(&shared);
        let join = tokio::task::spawn_blocking(move || {
            if *stopping.borrow() || cancelled.load(Ordering::Acquire) {
                let _ = reply.send(Err(NetworkSocketOwnerError::Closed));
                return Ok(());
            }
            let snapshot = NetworkSnapshot::capture(generation, resolver.catalog())
                .map_err(|_| NetworkSocketOwnerError::Capture);
            let _ = reply.send(snapshot);
            Ok(())
        });
        let task = Arc::new(TrackedTask::new(
            join,
            accounting,
            stop,
            Arc::clone(&shared.failure),
        ));
        state.capture = Some(Arc::clone(&task));
        task
    };
    task.join().await;
    {
        let mut state = lock(&shared.state);
        if state
            .capture
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &task))
        {
            state.capture = None;
        }
    }
    result
        .await
        .map_err(|_| NetworkSocketOwnerError::WorkerFailed)?
}
