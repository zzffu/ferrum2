use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use crate::Error;

pub(in crate::windows) const fn managed_notification_family() -> u16 {
    windows_sys::Win32::Networking::WinSock::AF_UNSPEC
}

pub(in crate::windows) struct NotificationContext {
    pub(in crate::windows) generation: Arc<AtomicU64>,
    pub(in crate::windows) owned_luid: AtomicU64,
    provisional_luid: AtomicU64,
    callbacks_in_flight: AtomicU64,
    monitor_runtime: AtomicBool,
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(in crate::windows) drain_wait_observed: AtomicBool,
}

impl NotificationContext {
    pub(in crate::windows) fn new(wake: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(0)),
            owned_luid: AtomicU64::new(0),
            provisional_luid: AtomicU64::new(0),
            callbacks_in_flight: AtomicU64::new(0),
            monitor_runtime: AtomicBool::new(false),
            wake,
            drain_wait_observed: AtomicBool::new(false),
        }
    }

    pub(in crate::windows) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(in crate::windows) fn publish_owned_luid(
        &self,
        luid: u64,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        if luid == 0 {
            self.generation.fetch_add(1, Ordering::AcqRel);
            return Err(Error);
        }
        match self
            .owned_luid
            .compare_exchange(0, luid, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(current) if current == luid => {}
            Err(_) => {
                self.generation.fetch_add(1, Ordering::AcqRel);
                return Err(Error);
            }
        }
        while self.callbacks_in_flight.load(Ordering::SeqCst) != 0 {
            self.drain_wait_observed.store(true, Ordering::SeqCst);
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(Error);
            }
            std::thread::yield_now();
        }
        let provisional = self.provisional_luid.swap(0, Ordering::SeqCst);
        if provisional != 0 && provisional != luid {
            self.generation.fetch_add(1, Ordering::AcqRel);
            return Err(Error);
        }
        Ok(())
    }

    pub(in crate::windows) fn monitor_runtime(&self) {
        self.monitor_runtime.store(true, Ordering::Release);
    }

    fn wake_owner(&self) {
        if let Some(wake) = &self.wake {
            wake();
        }
    }
}

struct NotificationCallbackGuard<'a>(&'a AtomicU64);

impl<'a> NotificationCallbackGuard<'a> {
    fn enter(context: &'a NotificationContext) -> Self {
        context.callbacks_in_flight.fetch_add(1, Ordering::SeqCst);
        Self(&context.callbacks_in_flight)
    }
}

impl Drop for NotificationCallbackGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(in crate::windows) fn classify_notification_luid(
    context: &NotificationContext,
    luid: u64,
    after_unpublished_load: impl FnOnce(),
) {
    let _in_flight = NotificationCallbackGuard::enter(context);
    context.generation.fetch_add(1, Ordering::AcqRel);
    if context.monitor_runtime.load(Ordering::Acquire) || luid == 0 {
        context.wake_owner();
        return;
    }
    let owned = context.owned_luid.load(Ordering::SeqCst);
    if owned != 0 {
        if owned != luid {
            context.wake_owner();
        }
        return;
    }
    after_unpublished_load();
    let provisional_mismatch =
        match context
            .provisional_luid
            .compare_exchange(0, luid, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => false,
            Err(current) => current != luid,
        };
    if provisional_mismatch {
        context.wake_owner();
    }
}
