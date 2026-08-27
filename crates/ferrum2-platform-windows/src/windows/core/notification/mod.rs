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
                }
                return Err(error);
            }
        }
    }
    Ok((handles, context.take().ok_or(Error)?))
}

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
