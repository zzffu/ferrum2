use std::time::{Duration, Instant};

use crate::{Error, NetworkChangeWaitOutcome};

mod state;

pub(in crate::windows) use state::{
    NotificationContext, classify_notification_luid, managed_notification_family,
};

pub(in crate::windows) fn cancel_notification_handles<T, C>(
    handles: &mut Vec<T>,
    context: &mut Option<C>,
    mut cancel: impl FnMut(&T) -> bool,
) -> bool {
    let mut failed = Vec::new();
    while let Some(handle) = handles.pop() {
        if !cancel(&handle) {
            failed.push(handle);
        }
    }
    failed.reverse();
    handles.append(&mut failed);
    if handles.is_empty() {
        context.take();
    }
    !handles.is_empty()
}

pub(in crate::windows) fn leak_notification_owners<T, C>(
    handles: &mut Vec<T>,
    context: &mut Option<C>,
) {
    std::mem::forget(std::mem::take(handles));
    std::mem::forget(context.take());
}

pub(in crate::windows) fn close_notification_handles<T, C>(
    handles: &mut Vec<T>,
    context: &mut Option<C>,
    cancel: impl FnMut(&T) -> bool,
) -> Result<(), Error> {
    if cancel_notification_handles(handles, context, cancel) {
        leak_notification_owners(handles, context);
        Err(Error::cleanup())
    } else {
        Ok(())
    }
}

pub(in crate::windows) fn subscribe_notification_sequence<H, C>(
    context: C,
    mut subscribe: impl FnMut(usize) -> Result<H, Error>,
    mut cancel: impl FnMut(&H) -> bool,
) -> Result<(Vec<H>, C), Error> {
    let mut handles = Vec::with_capacity(3);
    let mut context = Some(context);
    for ordinal in 0..3 {
        match subscribe(ordinal) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                if cancel_notification_handles(&mut handles, &mut context, &mut cancel) {
                    leak_notification_owners(&mut handles, &mut context);
                    return Err(Error::cleanup());
                }
                return Err(error);
            }
        }
    }
    Ok((handles, context.take().ok_or(Error)?))
}

/// Places subscribed notifications in the adapter's rollback slot before further
/// fallible preparation. Failure leaves that slot owned; success transfers the
/// notifications only after preparation has completed.
pub(in crate::windows) fn prepare_notification_owner<N, S>(
    pending: &mut Option<N>,
    subscribe: impl FnOnce() -> Result<N, Error>,
    prepare: impl FnOnce(&N) -> Result<S, Error>,
) -> Result<(N, S), Error> {
    if pending.is_some() {
        return Err(Error);
    }
    *pending = Some(subscribe()?);
    let prepared = prepare(pending.as_ref().expect("subscribed notification owner"))?;
    Ok((
        pending.take().expect("prepared notification owner"),
        prepared,
    ))
}

/// Both adapter-owned notification locations visible to reverse cleanup.
pub(in crate::windows) struct NotificationStages<'a, N> {
    pub(in crate::windows) pending: Option<&'a mut N>,
    pub(in crate::windows) committed: Option<&'a mut N>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum NotificationCleanup {
    Absent,
    Cleaned,
    Failed,
}

/// Attempts pending and committed cancellation without short-circuiting. The
/// operation retains failed handles/context for its normal safe retry or Drop.
pub(in crate::windows) fn cancel_notification_stages<N>(
    stages: NotificationStages<'_, N>,
    mut cancel: impl FnMut(&mut N) -> bool,
) -> NotificationCleanup {
    let mut outcome = NotificationCleanup::Absent;
    for owner in [stages.pending, stages.committed].into_iter().flatten() {
        let stage_failed = cancel(owner);
        outcome = if stage_failed || outcome == NotificationCleanup::Failed {
            NotificationCleanup::Failed
        } else {
            NotificationCleanup::Cleaned
        };
    }
    outcome
}

/// Waits for an owned notification source. generation must observe callback publication; reset_network_change must not discard a generation racing the reset. Stop remains dominant, and wait must respect its bounded timeout without releasing callback ownership.
pub(in crate::windows) trait NetworkChangeWaitOperations {
    fn stop_is_set(&mut self) -> Result<bool, Error>;
    fn generation(&mut self) -> u64;
    fn reset_network_change(&mut self) -> Result<(), Error>;
    fn wait_for_signal(&mut self, timeout_millis: u32) -> Result<NetworkChangeWaitOutcome, Error>;
}

pub(in crate::windows) fn wait_for_network_change(
    observed_generation: &mut u64,
    timeout: Duration,
    operations: &mut impl NetworkChangeWaitOperations,
) -> Result<NetworkChangeWaitOutcome, Error> {
    let started = Instant::now();
    loop {
        if operations.stop_is_set()? {
            return Ok(NetworkChangeWaitOutcome::Stopped);
        }
        let current = operations.generation();
        if current != *observed_generation {
            operations.reset_network_change()?;
            *observed_generation = operations.generation();
            if operations.stop_is_set()? {
                return Ok(NetworkChangeWaitOutcome::Stopped);
            }
            return Ok(NetworkChangeWaitOutcome::Changed);
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Ok(NetworkChangeWaitOutcome::TimedOut);
        }
        let millis = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX - 1);
        if millis == 0 {
            return Ok(NetworkChangeWaitOutcome::TimedOut);
        }
        match operations.wait_for_signal(millis)? {
            NetworkChangeWaitOutcome::Stopped => return Ok(NetworkChangeWaitOutcome::Stopped),
            NetworkChangeWaitOutcome::Changed => operations.reset_network_change()?,
            NetworkChangeWaitOutcome::TimedOut => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_notification_cancellation_releases_context() {
        let mut handles = vec![1_u8, 2, 3];
        let mut context = Some(7_u8);
        assert!(!cancel_notification_handles(
            &mut handles,
            &mut context,
            |_| true
        ));
        assert!(handles.is_empty());
        assert!(context.is_none());
    }
}

#[cfg(test)]
mod staging_tests;
