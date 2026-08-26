use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
use windows_sys::Win32::System::Threading::{ResetEvent, WaitForMultipleObjects};

use super::super::notification::{
    NetworkChangeWaitOperations, cancel_notification_handles, close_notification_handles,
    subscribe_notification_sequence, wait_for_network_change,
};
use super::loader::EventHandle;
use super::wintun::{StopSignal, require_windows_10};
use crate::{Error, NetworkChangeWaitOutcome};

pub(super) struct NotificationContext {
    pub(super) generation: Arc<AtomicU64>,
    pub(super) owned_luid: AtomicU64,
    provisional_luid: AtomicU64,
    callbacks_in_flight: AtomicU64,
    monitor_runtime: AtomicBool,
    wake: Option<StopSignal>,
    #[cfg(test)]
    pub(super) drain_wait_observed: AtomicBool,
}

impl NotificationContext {
    pub(super) fn new(wake: Option<StopSignal>) -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(0)),
            owned_luid: AtomicU64::new(0),
            provisional_luid: AtomicU64::new(0),
            callbacks_in_flight: AtomicU64::new(0),
            monitor_runtime: AtomicBool::new(false),
            wake,
            #[cfg(test)]
            drain_wait_observed: AtomicBool::new(false),
        }
    }

    fn observe_raw(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_owner(&self) {
        if let Some(wake) = &self.wake {
            let _ = wake.signal();
        }
    }

    pub(super) fn publish_owned_luid(
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
            #[cfg(test)]
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
}

pub(super) struct NotificationCallbackGuard<'a>(&'a AtomicU64);

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

pub(super) struct NotificationToken(HANDLE);

pub(super) struct NotificationOwners {
    pub(super) handles: Vec<NotificationToken>,
    pub(super) context: Option<Box<NotificationContext>>,
}

pub(super) const NOTIFICATION_QUIESCENCE: Duration = Duration::from_millis(350);
pub(super) const NOTIFICATION_QUIESCENCE_POLL: Duration = Duration::from_millis(25);

impl NotificationOwners {
    pub(super) fn generation(&self) -> u64 {
        self.context
            .as_ref()
            .expect("live notifications retain their callback context")
            .generation
            .load(Ordering::Acquire)
    }

    pub(super) fn generation_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(
            &self
                .context
                .as_ref()
                .expect("live notifications retain their callback context")
                .generation,
        )
    }

    pub(super) fn set_owned_luid(
        &self,
        luid: NET_LUID_LH,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        let context = self
            .context
            .as_ref()
            .expect("live notifications retain their callback context");
        context.publish_owned_luid(unsafe { luid.Value }, deadline, cancelled)
    }

    pub(super) fn monitor_runtime(&self) {
        self.context
            .as_ref()
            .expect("live notifications retain their callback context")
            .monitor_runtime
            .store(true, Ordering::Release);
    }

    pub(super) fn wait_until_quiescent(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        let mut observed = self.generation();
        let mut quiet_since = Instant::now();
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error);
            }
            let current = self.generation();
            if current != observed {
                observed = current;
                quiet_since = now;
            }
            let quiet_remaining =
                NOTIFICATION_QUIESCENCE.saturating_sub(now.saturating_duration_since(quiet_since));
            if quiet_remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(
                NOTIFICATION_QUIESCENCE_POLL
                    .min(quiet_remaining)
                    .min(deadline.saturating_duration_since(now)),
            );
        }
    }

    pub(super) fn cancel_all(&mut self) -> bool {
        cancel_notification_handles(
            &mut self.handles,
            &mut self.context,
            cancel_mib_notification,
        )
    }

    fn close(&mut self) -> Result<(), Error> {
        close_notification_handles(
            &mut self.handles,
            &mut self.context,
            cancel_mib_notification,
        )
    }
}

pub(super) fn cancel_mib_notification(token: &NotificationToken) -> bool {
    // SAFETY: every handle came from one successful Notify*Change registration owned by this
    // context. Ownership paths never run inside those callbacks, so synchronous cancellation
    // cannot deadlock by waiting for the callback that invoked it.
    unsafe { CancelMibChangeNotify2(token.0) == ERROR_SUCCESS }
}

impl Drop for NotificationOwners {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(super) unsafe extern "system" fn route_changed(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

pub(super) unsafe extern "system" fn interface_changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

pub(super) unsafe extern "system" fn address_changed(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

pub(super) fn classify_notification_luid(
    context: &NotificationContext,
    luid: u64,
    after_unpublished_load: impl FnOnce(),
) {
    let _in_flight = NotificationCallbackGuard::enter(context);
    context.observe_raw();
    if context.monitor_runtime.load(Ordering::Acquire) {
        context.wake_owner();
        return;
    }
    if luid == 0 {
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

pub struct WindowsNetworkChangeMonitor {
    stop: StopSignal,
    network_change: StopSignal,
    notifications: NotificationOwners,
    observed_generation: u64,
}

// SAFETY: notification handles are not thread-affine and both events are thread-safe kernel
// objects. The callback context stays at one stable heap address, and callbacks from the three
// registrations touch only atomics and `SetEvent`. A successful `CancelMibChangeNotify2` drains
// pending callbacks before the context is released; a failed cancellation leaks the still-live
// handles, callback context, and wake event together instead of freeing callback-reachable memory.
unsafe impl Send for WindowsNetworkChangeMonitor {}

pub(super) struct PlatformNetworkChangeWait<'a> {
    stop: &'a StopSignal,
    network_change: &'a StopSignal,
    notifications: &'a NotificationOwners,
}

impl NetworkChangeWaitOperations for PlatformNetworkChangeWait<'_> {
    fn stop_is_set(&mut self) -> Result<bool, Error> {
        let handles = [self.stop.0.raw()];
        // SAFETY: the slice contains exactly one live event handle retained by `self.stop`, and
        // its length matches the count passed to the API.
        match unsafe { WaitForMultipleObjects(1, handles.as_ptr(), 0, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(Error),
            _ => Err(Error),
        }
    }

    fn generation(&mut self) -> u64 {
        self.notifications.generation()
    }

    fn reset_network_change(&mut self) -> Result<(), Error> {
        // SAFETY: the handle is a live manual-reset event retained by `self.network_change`.
        if unsafe { ResetEvent(self.network_change.0.raw()) } == 0 {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn wait_for_signal(&mut self, timeout_millis: u32) -> Result<NetworkChangeWaitOutcome, Error> {
        let handles = [self.stop.0.raw(), self.network_change.0.raw()];
        // SAFETY: both entries are live event handles retained by the borrowed signals, and the
        // slice length matches the count. Stop is first so Windows gives it deterministic priority
        // when both manual-reset events are signalled.
        match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout_millis) } {
            WAIT_OBJECT_0 => Ok(NetworkChangeWaitOutcome::Stopped),
            value if value == WAIT_OBJECT_0 + 1 => Ok(NetworkChangeWaitOutcome::Changed),
            WAIT_TIMEOUT => Ok(NetworkChangeWaitOutcome::TimedOut),
            WAIT_FAILED => Err(Error),
            _ => Err(Error),
        }
    }
}

impl WindowsNetworkChangeMonitor {
    pub fn new() -> Result<Self, Error> {
        require_windows_10()?;
        let stop = StopSignal(Arc::new(EventHandle::new(true)?));
        let network_change = StopSignal(Arc::new(EventHandle::new(true)?));
        let notifications = subscribe_network_changes(network_change.clone())?;
        notifications.monitor_runtime();
        let observed_generation = notifications.generation();
        Ok(Self {
            stop,
            network_change,
            notifications,
            observed_generation,
        })
    }

    /// Returns a cloneable signal that interrupts a blocking wait during process shutdown.
    pub fn stop_signal(&self) -> StopSignal {
        self.stop.clone()
    }

    /// Waits for an ordinary network change without touching managed TUN state.
    ///
    /// Stop is a distinct, highest-priority outcome. The method may be called repeatedly from one
    /// blocking owner thread; callers should debounce [`NetworkChangeWaitOutcome::Changed`].
    pub fn wait(&mut self, timeout: Duration) -> Result<NetworkChangeWaitOutcome, Error> {
        let mut operations = PlatformNetworkChangeWait {
            stop: &self.stop,
            network_change: &self.network_change,
            notifications: &self.notifications,
        };
        wait_for_network_change(&mut self.observed_generation, timeout, &mut operations)
    }

    /// Explicitly deregisters all three notifications and proves callback-context release.
    ///
    /// If Windows cannot cancel any registration, its handle and callback context are leaked
    /// together to prevent use-after-free and a cleanup-classified error is returned.
    pub fn close(mut self) -> Result<(), Error> {
        self.notifications.close()
    }
}

pub(super) fn subscribe_network_changes(wake: StopSignal) -> Result<NotificationOwners, Error> {
    let context = Box::new(NotificationContext::new(Some(wake)));
    let context_pointer = (&raw const *context).cast::<c_void>();
    let (handles, context) = subscribe_notification_sequence(
        context,
        |ordinal| {
            let mut handle = null_mut();
            let status = match ordinal {
                0 => unsafe {
                    NotifyRouteChange2(
                        managed_notification_family(),
                        Some(route_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                1 => unsafe {
                    NotifyIpInterfaceChange(
                        managed_notification_family(),
                        Some(interface_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                2 => unsafe {
                    NotifyUnicastIpAddressChange(
                        managed_notification_family(),
                        Some(address_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                _ => return Err(Error),
            };
            if status != ERROR_SUCCESS || handle.is_null() {
                Err(Error)
            } else {
                Ok(NotificationToken(handle))
            }
        },
        cancel_mib_notification,
    )?;
    Ok(NotificationOwners {
        handles,
        context: Some(context),
    })
}

pub(super) const fn managed_notification_family() -> u16 {
    AF_UNSPEC
}
