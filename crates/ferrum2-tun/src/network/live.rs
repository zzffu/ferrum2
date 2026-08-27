use std::net::SocketAddr;
use std::sync::Arc;

use crate::{TunEvent, TunEventSink, TunRejectReason};

/// Generation-aware bridge from the current private Wintun session to client egress.
#[derive(Clone, Default)]
pub struct UnderlayPublisher {
    state: Arc<std::sync::RwLock<UnderlayState>>,
    events: Arc<std::sync::RwLock<TunEventSink>>,
}

#[derive(Default)]
struct UnderlayState {
    generation: u64,
    ready: bool,
    policy: Option<ferrum2_platform_windows::UnderlayPolicy>,
}

impl UnderlayPublisher {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_event_sink(&self, events: TunEventSink) {
        if let Ok(mut current) = self.events.write() {
            *current = events;
        }
    }

    fn emit_stale(&self) {
        if let Ok(events) = self.events.read() {
            events.emit(TunEvent::UnderlayBindStale);
            events.emit(TunEvent::PacketRejected(TunRejectReason::StaleGeneration));
        }
    }

    pub(crate) fn publish(
        &self,
        policy: Option<ferrum2_platform_windows::UnderlayPolicy>,
    ) -> Result<(), ()> {
        let mut state = self.state.write().map_err(|_| ())?;
        state.generation = state.generation.wrapping_add(1).max(1);
        state.ready = policy.is_some();
        state.policy = policy;
        Ok(())
    }

    pub(crate) fn invalidate(&self) -> Result<(), ()> {
        let mut state = self.state.write().map_err(|_| ())?;
        state.generation = state.generation.wrapping_add(1).max(1);
        state.ready = false;
        state.policy = None;
        Ok(())
    }

    pub fn bind_fixed<T: std::os::windows::io::AsRawSocket>(
        &self,
        socket: &T,
        endpoint: SocketAddr,
    ) -> Result<(), ferrum2_platform_windows::Error> {
        let (generation, policy) = self.policy_snapshot()?;
        if let Err(error) = policy.bind_fixed(socket, endpoint) {
            if !policy.generation_is_current() {
                self.emit_stale();
            }
            return Err(error);
        }
        self.require_generation(generation)
    }

    pub fn bind_target<T: std::os::windows::io::AsRawSocket>(
        &self,
        socket: &T,
        target: SocketAddr,
    ) -> Result<(), ferrum2_platform_windows::Error> {
        let (generation, policy) = self.policy_snapshot()?;
        if let Err(error) = policy.bind_target(socket, target) {
            if !policy.generation_is_current() {
                self.emit_stale();
            }
            return Err(error);
        }
        self.require_generation(generation)
    }

    fn policy_snapshot(
        &self,
    ) -> Result<(u64, ferrum2_platform_windows::UnderlayPolicy), ferrum2_platform_windows::Error>
    {
        let state = self.state.read().map_err(|_| {
            ferrum2_platform_windows::Error::new(
                ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
            )
        })?;
        if !state.ready {
            drop(state);
            self.emit_stale();
            return Err(ferrum2_platform_windows::Error::new(
                ferrum2_platform_windows::ErrorKind::RecoverableSession,
            ));
        }
        Ok((
            state.generation,
            state
                .policy
                .clone()
                .ok_or(ferrum2_platform_windows::Error::new(
                    ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
                ))?,
        ))
    }

    fn require_generation(&self, generation: u64) -> Result<(), ferrum2_platform_windows::Error> {
        let state = self.state.read().map_err(|_| {
            ferrum2_platform_windows::Error::new(
                ferrum2_platform_windows::ErrorKind::UnrecoverableCorruption,
            )
        })?;
        if state.ready && state.generation == generation {
            Ok(())
        } else {
            drop(state);
            self.emit_stale();
            Err(ferrum2_platform_windows::Error::new(
                ferrum2_platform_windows::ErrorKind::RecoverableSession,
            ))
        }
    }
}
