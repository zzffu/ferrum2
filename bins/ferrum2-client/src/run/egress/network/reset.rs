use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::run::egress::udp::ClientUdpContext;

const MAX_TARGETS: usize = ferrum2_runtime::MAX_NETWORK_RESET_HOOKS;
const MAX_DNS_ACTIONS: usize = 8;

pub(in crate::run) struct ClientDnsResetAction {
    pub(in crate::run) fence: Box<dyn Fn(u64) -> Result<(), ()> + Send + Sync>,
    pub(in crate::run) retire: Box<dyn Fn(u64) -> Result<usize, ()> + Send + Sync>,
    pub(in crate::run) reopen: Box<dyn Fn(u64) -> Result<(), ()> + Send + Sync>,
}

pub(in crate::run) struct ClientEgressNetworkResetState {
    udp_manager: Option<ferrum2_runtime::UdpSessionManager>,
    dns_actions: Mutex<Vec<Weak<ClientDnsResetAction>>>,
    closed: AtomicBool,
}

impl ClientEgressNetworkResetState {
    pub(in crate::run) fn new(udp: Option<&ClientUdpContext>) -> Self {
        Self {
            udp_manager: udp.map(|udp| udp.manager.clone()),
            dns_actions: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }

    pub(in crate::run) fn register_dns_action(
        &self,
        action: &Arc<ClientDnsResetAction>,
    ) -> Result<(), ()> {
        let mut actions = self.dns_actions.lock().map_err(|_| ())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(());
        }
        actions.retain(|action| action.strong_count() != 0);
        if actions.len() == MAX_DNS_ACTIONS {
            return Err(());
        }
        actions.push(Arc::downgrade(action));
        Ok(())
    }

    fn actions(&self) -> Result<Vec<Arc<ClientDnsResetAction>>, ()> {
        Ok(self
            .dns_actions
            .lock()
            .map_err(|_| ())?
            .iter()
            .filter_map(Weak::upgrade)
            .collect())
    }

    fn fence(&self, generation: u64) -> Result<(), ()> {
        // Hold the registration lock across closing so a new pool cannot miss the fence.
        let actions = {
            let actions = self.dns_actions.lock().map_err(|_| ())?;
            self.closed.store(true, Ordering::Release);
            actions.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        if let Some(manager) = &self.udp_manager {
            manager
                .fence_network_generation(generation)
                .map_err(|_| ())?;
        }
        for action in actions {
            (action.fence)(generation)?;
        }
        Ok(())
    }

    fn retire(&self, generation: u64, removed: &mut usize) -> Result<(), ()> {
        for action in self.actions()? {
            *removed = removed.saturating_add((action.retire)(generation)?);
        }
        if let Some(manager) = &self.udp_manager {
            *removed = removed.saturating_add(
                manager
                    .retire_network_generation(generation)
                    .map_err(|_| ())?,
            );
        }
        Ok(())
    }

    fn reopen(&self, generation: u64) -> Result<(), ()> {
        for action in self.actions()? {
            (action.reopen)(generation)?;
        }
        if let Some(manager) = &self.udp_manager {
            manager
                .reopen_network_generation(generation)
                .map_err(|_| ())?;
        }
        self.closed.store(false, Ordering::Release);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(in crate::run) struct ClientNetworkResetHub {
    inner: Arc<Mutex<HubState>>,
    driver: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Default)]
struct HubState {
    next_id: u64,
    completed_generation: u64,
    targets: BTreeMap<u64, Weak<ClientEgressNetworkResetState>>,
    pending: Option<ResetCohort>,
    stopped: bool,
    cleanup_failed: bool,
}

struct ResetCohort {
    generation: u64,
    targets: Vec<Arc<ClientEgressNetworkResetState>>,
    retired: bool,
    removed: usize,
}

impl ClientNetworkResetHub {
    pub(in crate::run) fn pending_generation(&self) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .as_ref()
            .map(|cohort| cohort.generation)
    }
    pub(in crate::run) fn driver(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.driver)
    }

    pub(in crate::run) fn register(
        &self,
        target: &Arc<ClientEgressNetworkResetState>,
    ) -> Result<ClientNetworkResetTargetRegistration, ()> {
        let mut state = self.inner.lock().map_err(|_| ())?;
        if state.stopped || state.pending.is_some() {
            return Err(());
        }
        state.targets.retain(|_, target| target.strong_count() != 0);
        if state.targets.len() == MAX_TARGETS {
            return Err(());
        }
        let id = state.next_id;
        state.next_id = id.checked_add(1).ok_or(())?;
        state.targets.insert(id, Arc::downgrade(target));
        Ok(ClientNetworkResetTargetRegistration {
            hub: Arc::downgrade(&self.inner),
            id,
        })
    }

    pub(in crate::run) fn fence(&self, generation: u64) -> Result<(), ()> {
        let mut state = self.inner.lock().map_err(|_| ())?;
        if state.stopped || generation == 0 || generation < state.completed_generation {
            return Err(());
        }
        if state.pending.is_none() {
            if generation == state.completed_generation {
                return Ok(());
            }
            state.pending = Some(ResetCohort {
                generation,
                targets: state.targets.values().filter_map(Weak::upgrade).collect(),
                retired: false,
                removed: 0,
            });
        }
        let cohort = state.pending.as_ref().ok_or(())?;
        if cohort.generation != generation {
            return Err(());
        }
        for target in &cohort.targets {
            target.fence(generation)?;
        }
        Ok(())
    }

    pub(in crate::run) fn complete(&self, generation: u64) -> Result<usize, ()> {
        self.retire(generation)?;
        let mut state = self.inner.lock().map_err(|_| ())?;
        if state.stopped {
            return Err(());
        }
        let Some(cohort) = state.pending.as_mut() else {
            return if generation != 0 && generation == state.completed_generation {
                Ok(0)
            } else {
                Err(())
            };
        };
        if cohort.generation != generation {
            return Err(());
        }
        for target in &cohort.targets {
            target.reopen(generation)?;
        }
        let removed = cohort.removed;
        state.completed_generation = generation;
        let retired = state.pending.take();
        drop(state);
        drop(retired);
        Ok(removed)
    }

    pub(in crate::run) fn retire(&self, generation: u64) -> Result<(), ()> {
        let mut state = self.inner.lock().map_err(|_| ())?;
        let Some(cohort) = state.pending.as_mut() else {
            return if generation != 0 && generation == state.completed_generation {
                Ok(())
            } else {
                Err(())
            };
        };
        if cohort.generation != generation {
            return Err(());
        }
        if !cohort.retired {
            for target in &cohort.targets {
                target.retire(generation, &mut cohort.removed)?;
            }
            cohort.retired = true;
        }
        Ok(())
    }

    pub(in crate::run) fn stop(&self) -> Result<(), ()> {
        let mut state = self.inner.lock().map_err(|_| ())?;
        state.stopped = true;
        let mut failed = state.cleanup_failed;
        if let Some(cohort) = &mut state.pending {
            for target in &cohort.targets {
                failed |= target
                    .retire(cohort.generation, &mut cohort.removed)
                    .is_err();
            }
            cohort.retired = !failed;
        }
        state.cleanup_failed = failed;
        if failed { Err(()) } else { Ok(()) }
    }
}

pub(in crate::run) struct ClientNetworkResetTargetRegistration {
    hub: Weak<Mutex<HubState>>,
    id: u64,
}

impl Drop for ClientNetworkResetTargetRegistration {
    fn drop(&mut self) {
        if let Some(hub) = self.hub.upgrade() {
            hub.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .targets
                .remove(&self.id);
        }
    }
}
