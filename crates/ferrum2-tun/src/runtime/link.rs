use std::sync::{Arc, Condvar, Mutex, PoisonError};

use ferrum2_net::NetworkSnapshot;
use tokio::sync::Notify;

use super::NetworkResetBridgeOutcome;
use crate::{OwnerWake, TunNetworkLifecycle};

#[derive(Clone, Default)]
pub(crate) struct LifecycleLink(Arc<Shared>);

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    notification: Notify,
}

#[derive(Default)]
struct State {
    closed: bool,
    busy: bool,
    request: Option<(Arc<NetworkSnapshot>, TunNetworkLifecycle)>,
    outcome: Option<NetworkResetBridgeOutcome>,
    prepared: Option<OwnerWake>,
}

pub(crate) enum LifecycleEvent {
    Request(NetworkResetRequest),
    Prepared(OwnerWake),
}

pub(crate) struct NetworkResetRequest {
    pub(crate) snapshot: Arc<NetworkSnapshot>,
    pub(crate) lifecycle: TunNetworkLifecycle,
    pub(crate) completion: ResponseLease,
}

/// A dequeued response still belongs to the closeable link. Dropping the
/// callback cannot strand its native waiter, and completion cannot reopen it.
pub(crate) struct ResponseLease(Option<LifecycleLink>);

impl ResponseLease {
    pub(crate) fn complete(mut self, outcome: NetworkResetBridgeOutcome) {
        self.0
            .take()
            .expect("response lease retained")
            .complete(outcome);
    }
}

impl Drop for ResponseLease {
    fn drop(&mut self) {
        if let Some(link) = self.0.take() {
            link.complete(NetworkResetBridgeOutcome::Stopped);
        }
    }
}

impl LifecycleLink {
    pub(crate) fn close(&self) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.closed = true;
        state.request = None;
        state.prepared = None;
        state.outcome = Some(NetworkResetBridgeOutcome::Stopped);
        drop(state);
        self.0.changed.notify_all();
        self.0.notification.notify_waiters();
    }

    pub(crate) fn request(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        lifecycle: TunNetworkLifecycle,
    ) -> NetworkResetBridgeOutcome {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed || state.busy {
            return NetworkResetBridgeOutcome::Stopped;
        }
        state.busy = true;
        state.request = Some((snapshot, lifecycle));
        state.outcome = None;
        self.0.notification.notify_one();
        while !state.closed && state.outcome.is_none() {
            state = self
                .0
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        let outcome = if state.closed {
            NetworkResetBridgeOutcome::Stopped
        } else {
            state.outcome.take().expect("completed lifecycle request")
        };
        state.busy = false;
        outcome
    }

    fn complete(&self, outcome: NetworkResetBridgeOutcome) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.closed && state.busy && state.outcome.is_none() {
            state.outcome = Some(outcome);
            self.0.changed.notify_all();
        }
    }

    pub(crate) fn prepared(&self, work: OwnerWake) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !state.closed {
            state.prepared = Some(work);
            self.0.notification.notify_one();
        }
    }

    pub(crate) async fn receive(&self) -> Option<LifecycleEvent> {
        loop {
            let notified = self.0.notification.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
                if state.closed {
                    return None;
                }
                if let Some(work) = state.prepared.take() {
                    return Some(LifecycleEvent::Prepared(work));
                }
                if let Some((snapshot, lifecycle)) = state.request.take() {
                    return Some(LifecycleEvent::Request(NetworkResetRequest {
                        snapshot,
                        lifecycle,
                        completion: ResponseLease(Some(self.clone())),
                    }));
                }
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeLifecycleOwner, OwnerControl, OwnerExit};
    use std::time::Duration;

    fn snapshot() -> Arc<NetworkSnapshot> {
        Arc::new(NetworkSnapshot::new(1, None, None).unwrap())
    }

    #[tokio::test]
    async fn closing_queued_or_dequeued_request_releases_native_cleanup() {
        for dequeue in [false, true] {
            let (entered, entering) = tokio::sync::oneshot::channel();
            let (owner, done) = NativeLifecycleOwner::spawn(
                OwnerControl::new(),
                Box::new(move |link, _| {
                    let _ = entered.send(());
                    assert_eq!(
                        link.request(snapshot(), TunNetworkLifecycle::Initialize),
                        NetworkResetBridgeOutcome::Stopped
                    );
                    OwnerExit::CleanupFailed
                }),
            )
            .unwrap();
            entering.await.unwrap();
            let completion = if dequeue {
                let Some(LifecycleEvent::Request(request)) = owner.link.receive().await else {
                    panic!("request");
                };
                Some(request.completion)
            } else {
                // Notification is retained when registration predates this waiter.
                owner.link.0.notification.notified().await;
                None
            };
            owner.link.close();
            if let Some(completion) = completion {
                completion.complete(NetworkResetBridgeOutcome::Completed);
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), done)
                    .await
                    .unwrap()
                    .unwrap(),
                OwnerExit::CleanupFailed
            );
            assert_eq!(owner.reap().await, OwnerExit::CleanupFailed);
        }
    }

    #[tokio::test]
    async fn response_drop_and_owner_drop_each_release_an_inflight_native_waiter() {
        for drop_owner in [false, true] {
            let (owner, done) = NativeLifecycleOwner::spawn(
                OwnerControl::new(),
                Box::new(|link, _| {
                    assert_eq!(
                        link.request(snapshot(), TunNetworkLifecycle::Initialize),
                        NetworkResetBridgeOutcome::Stopped
                    );
                    OwnerExit::Stopped
                }),
            )
            .unwrap();
            let Some(LifecycleEvent::Request(request)) = owner.link.receive().await else {
                panic!("request");
            };
            if drop_owner {
                drop(owner);
                request
                    .completion
                    .complete(NetworkResetBridgeOutcome::Completed);
            } else {
                drop(request);
                assert_eq!(owner.reap().await, OwnerExit::Stopped);
            }
            assert_eq!(done.await.unwrap(), OwnerExit::Stopped);
        }
    }

    #[tokio::test]
    async fn receive_registers_before_check_and_serial_requests_do_not_share_completions() {
        let (owner, done) = NativeLifecycleOwner::spawn(
            OwnerControl::new(),
            Box::new(|link, _| {
                for expected in [
                    NetworkResetBridgeOutcome::Retry,
                    NetworkResetBridgeOutcome::Completed,
                ] {
                    assert_eq!(
                        link.request(snapshot(), TunNetworkLifecycle::Initialize),
                        expected
                    );
                }
                link.prepared(OwnerWake::default());
                // Retain the prepared notification until the async owner closes admission.
                assert_eq!(
                    link.request(snapshot(), TunNetworkLifecycle::Initialize),
                    NetworkResetBridgeOutcome::Stopped
                );
                OwnerExit::Stopped
            }),
        )
        .unwrap();
        for expected in [
            NetworkResetBridgeOutcome::Retry,
            NetworkResetBridgeOutcome::Completed,
        ] {
            let Some(LifecycleEvent::Request(request)) = owner.link.receive().await else {
                panic!("request");
            };
            request.completion.complete(expected);
        }
        let Some(LifecycleEvent::Prepared(work)) = owner.link.receive().await else {
            panic!("prepared");
        };
        work.signal();
        assert_eq!(owner.reap().await, OwnerExit::Stopped);
        assert_eq!(done.await.unwrap(), OwnerExit::Stopped);
    }
}
