use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use ferrum2_runtime::{UdpSessionHandle, UdpSessionManager};
use ferrum2_shadowsocks::{ServerResponseCapability, UdpServer};

use crate::run::routing::ServerTerminalRoute;

#[derive(Default)]
pub(super) struct UdpMappingState {
    pub(super) by_capability: HashMap<ServerResponseCapability, BoundUdpSession>,
    pub(super) by_handle: BTreeMap<UdpSessionHandle, ServerResponseCapability>,
    pub(super) orphaned: HashMap<ServerResponseCapability, FrozenUdpIdentity>,
    pub(super) retired: BTreeSet<UdpSessionHandle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrozenUdpIdentity {
    pub(super) inbound: usize,
    pub(super) terminal: ServerTerminalRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BoundUdpSession {
    pub(super) handle: UdpSessionHandle,
    pub(super) inbound: usize,
    pub(super) terminal: ServerTerminalRoute,
}

pub(in crate::run) struct UdpMappings {
    pub(super) state: Mutex<UdpMappingState>,
    pub(super) published: tokio::sync::Notify,
    pub(super) limit: usize,
}

impl UdpMappings {
    pub(in crate::run) fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(UdpMappingState::default()),
            published: tokio::sync::Notify::new(),
            limit,
        }
    }

    pub(super) fn handle(&self, capability: ServerResponseCapability) -> Option<BoundUdpSession> {
        self.state
            .lock()
            .expect("UDP mapping lock poisoned")
            .by_capability
            .get(&capability)
            .copied()
    }

    pub(super) fn identity(
        &self,
        capability: ServerResponseCapability,
    ) -> Option<FrozenUdpIdentity> {
        let state = self.state.lock().expect("UDP mapping lock poisoned");
        state
            .by_capability
            .get(&capability)
            .map(|binding| FrozenUdpIdentity {
                inbound: binding.inbound,
                terminal: binding.terminal,
            })
            .or_else(|| state.orphaned.get(&capability).copied())
    }

    pub(super) async fn capability(
        &self,
        handle: UdpSessionHandle,
    ) -> Option<ServerResponseCapability> {
        loop {
            let notified = self.published.notified();
            {
                let state = self.state.lock().expect("UDP mapping lock poisoned");
                if let Some(capability) = state.by_handle.get(&handle).copied() {
                    return Some(capability);
                }
                if state.retired.contains(&handle) {
                    return None;
                }
            }
            notified.await;
        }
    }

    pub(super) fn publish(
        &self,
        capability: ServerResponseCapability,
        handle: UdpSessionHandle,
        inbound: usize,
        terminal: ServerTerminalRoute,
    ) -> Option<ServerResponseCapability> {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        if let Some(old) = state.by_capability.remove(&capability) {
            state.by_handle.remove(&old.handle);
            retire_mapping_handle(&mut state, old.handle, self.limit);
        }
        state.orphaned.remove(&capability);
        if let Some(old_capability) = state.by_handle.remove(&handle)
            && let Some(old) = state.by_capability.remove(&old_capability)
        {
            state.orphaned.insert(
                old_capability,
                FrozenUdpIdentity {
                    inbound: old.inbound,
                    terminal: old.terminal,
                },
            );
        }
        state.retired.remove(&handle);
        let evicted = if state.by_handle.len() == self.limit {
            state.by_handle.pop_first().map(|(old_handle, capability)| {
                if let Some(old) = state.by_capability.remove(&capability) {
                    state.orphaned.insert(
                        capability,
                        FrozenUdpIdentity {
                            inbound: old.inbound,
                            terminal: old.terminal,
                        },
                    );
                }
                retire_mapping_handle(&mut state, old_handle, self.limit);
                capability
            })
        } else {
            None
        };
        state.by_capability.insert(
            capability,
            BoundUdpSession {
                handle,
                inbound,
                terminal,
            },
        );
        state.by_handle.insert(handle, capability);
        drop(state);
        self.published.notify_waiters();
        evicted
    }

    pub(super) fn publish_rejected(&self, capability: ServerResponseCapability, inbound: usize) {
        self.state
            .lock()
            .expect("UDP mapping lock poisoned")
            .orphaned
            .insert(
                capability,
                FrozenUdpIdentity {
                    inbound,
                    terminal: ServerTerminalRoute::Reject,
                },
            );
    }

    pub(super) fn invalidate_handle(&self, handle: UdpSessionHandle) {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        if let Some(capability) = state.by_handle.remove(&handle)
            && let Some(old) = state.by_capability.remove(&capability)
        {
            state.orphaned.insert(
                capability,
                FrozenUdpIdentity {
                    inbound: old.inbound,
                    terminal: old.terminal,
                },
            );
        }
        retire_mapping_handle(&mut state, handle, self.limit);
        drop(state);
        self.published.notify_waiters();
    }

    #[cfg(any(windows, test))]
    pub(super) fn reset_runtime(&self) -> usize {
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        let mut active = std::mem::take(&mut state.by_capability);
        let handles = std::mem::take(&mut state.by_handle);
        let removed = active.len();
        for (handle, capability) in handles {
            if let Some(binding) = active.remove(&capability) {
                state.orphaned.insert(
                    capability,
                    FrozenUdpIdentity {
                        inbound: binding.inbound,
                        terminal: binding.terminal,
                    },
                );
            }
            retire_mapping_handle(&mut state, handle, self.limit);
        }
        for (capability, binding) in active {
            state.orphaned.insert(
                capability,
                FrozenUdpIdentity {
                    inbound: binding.inbound,
                    terminal: binding.terminal,
                },
            );
            retire_mapping_handle(&mut state, binding.handle, self.limit);
        }
        drop(state);
        if removed != 0 {
            self.published.notify_waiters();
        }
        removed
    }

    pub(super) fn reconcile_runtime(&self, sessions: &UdpSessionManager) {
        let candidates: Vec<_> = self
            .state
            .lock()
            .expect("UDP mapping lock poisoned")
            .by_handle
            .keys()
            .copied()
            .collect();
        let mut live = candidates.clone();
        sessions.retain_live_sessions(&mut live);
        for handle in candidates {
            if live.binary_search(&handle).is_err() {
                self.invalidate_handle(handle);
            }
        }
    }

    pub(super) fn prune_protocol(
        &self,
        protocol: &UdpServer,
        now: ferrum2_crypto::MonotonicInstant,
    ) {
        let candidates: Vec<_> = self
            .state
            .lock()
            .expect("UDP mapping lock poisoned")
            .orphaned
            .keys()
            .copied()
            .collect();
        let removed: Vec<_> = candidates
            .into_iter()
            .filter(|capability| protocol.remove_session(*capability, now).unwrap_or(false))
            .collect();
        if removed.is_empty() {
            return;
        }
        let mut state = self.state.lock().expect("UDP mapping lock poisoned");
        for capability in removed {
            state.orphaned.remove(&capability);
        }
    }
}

#[cfg(any(windows, test))]
pub(in crate::run) struct ServerUdpNetworkReset {
    pub(super) accepted_generation: std::sync::atomic::AtomicU64,
    pub(super) sessions: UdpSessionManager,
    pub(super) mappings: Arc<UdpMappings>,
    pub(super) admission: Arc<tokio::sync::Mutex<()>>,
}

#[cfg(any(windows, test))]
impl ServerUdpNetworkReset {
    pub(in crate::run) fn new(
        initial_generation: u64,
        sessions: UdpSessionManager,
        mappings: Arc<UdpMappings>,
        admission: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            accepted_generation: std::sync::atomic::AtomicU64::new(initial_generation),
            sessions,
            mappings,
            admission,
        }
    }
}

#[cfg(any(windows, test))]
impl ferrum2_runtime::ResetNetwork for ServerUdpNetworkReset {
    fn reset_network(
        &self,
        snapshot: Arc<ferrum2_net::NetworkSnapshot>,
    ) -> ferrum2_runtime::NetworkResetFuture<'_> {
        Box::pin(async move {
            let generation = snapshot.generation();
            let _admission = self.admission.lock().await;
            let current = self
                .accepted_generation
                .load(std::sync::atomic::Ordering::Acquire);
            if generation < current {
                return Err(ferrum2_runtime::NetworkResetError);
            }
            if generation == current {
                return Ok(());
            }
            self.sessions.reset_all();
            self.mappings.reset_runtime();
            self.accepted_generation
                .store(generation, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    }
}

pub(super) fn retire_mapping_handle(
    state: &mut UdpMappingState,
    handle: UdpSessionHandle,
    limit: usize,
) {
    if state.retired.len() == limit {
        state.retired.pop_first();
    }
    state.retired.insert(handle);
}
