use crate::{CreateError, Error, ManagedNetworkConfig};

mod health;
mod state;
#[cfg(not(test))]
pub(in crate::windows) use health::ipv4_link_local_health;
pub(in crate::windows) use health::{ReadbackMatch, addresses_match, mtu_health};

#[cfg(test)]
pub(in crate::windows) use state::AdapterCreateFailure;
pub(in crate::windows) use state::{
    DadProgress, ManagedNetworkValidation, ManagedNetworkValidationOutcome,
    ManagedOwnershipLedgerView, classify_adapter_create_failure, dad_snapshot,
    managed_device_health, managed_ownership_ledger_exact, managed_state_health,
    revalidate_managed_network,
};

pub(in crate::windows) fn prepare_managed_intent<T>(
    config: Option<&ManagedNetworkConfig>,
    prepare: impl FnOnce(&ManagedNetworkConfig) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    config.map(prepare).transpose()
}

pub(in crate::windows) struct ManagedDnsLease<S> {
    pub(in crate::windows) previous: S,
    pub(in crate::windows) applied: S,
}

/// Reads and mutates one owned interface DNS family. A successful apply must report its exact applied settings so the caller immediately journals the lease before readback. Failures must never imply that unknown settings can be restored.
pub(in crate::windows) trait ManagedDnsOperations {
    type Settings: Clone + Eq;
    type Address: Copy;

    fn snapshot(&mut self) -> Result<Self::Settings, Error>;
    fn apply(&mut self, address: Self::Address) -> Result<Self::Settings, Error>;
    fn readback(&mut self) -> Result<Self::Settings, Error>;
    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error>;
}

pub(in crate::windows) fn install_managed_dns<O: ManagedDnsOperations>(
    address: O::Address,
    operations: &mut O,
    lease: &mut Option<ManagedDnsLease<O::Settings>>,
) -> Result<(), Error> {
    let previous = operations.snapshot()?;
    let applied = operations.apply(address)?;
    *lease = Some(ManagedDnsLease { previous, applied });
    if operations.readback()? == lease.as_ref().ok_or(Error)?.applied {
        Ok(())
    } else {
        Err(Error)
    }
}

pub(in crate::windows) fn managed_dns_matches<O: ManagedDnsOperations>(
    operations: &mut O,
    lease: &ManagedDnsLease<O::Settings>,
) -> Result<bool, Error> {
    Ok(operations.readback()? == lease.applied)
}

pub(in crate::windows) fn restore_managed_dns<O: ManagedDnsOperations>(
    operations: &mut O,
    lease: &ManagedDnsLease<O::Settings>,
) -> bool {
    let Ok(current) = operations.readback() else {
        return true;
    };
    if current != lease.applied || operations.restore(&lease.previous).is_err() {
        return true;
    }
    !matches!(operations.readback(), Ok(current) if current == lease.previous)
}

/// Installs owned capture routes. create_pending must journal any successfully created row before returning; commit_pending transfers that owner only after exact readback. Failures retain all pending owners for rollback.
pub(in crate::windows) trait ManagedRouteOperations {
    type Row: Copy;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error>;
    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error>;
    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error>;
    fn commit_pending(&mut self) -> Result<(), Error>;
}

pub(in crate::windows) fn install_managed_routes<O: ManagedRouteOperations>(
    rows: &[O::Row],
    operations: &mut O,
) -> Result<(), Error> {
    for row in rows {
        operations.require_absent(row)?;
    }
    for row in rows {
        operations.create_pending(*row)?;
        if !operations.readback_exact(row)? {
            return Err(Error);
        }
        operations.commit_pending()?;
    }
    Ok(())
}

pub(in crate::windows) enum ManagedAddressRead<R> {
    Absent,
    Present(R),
    Failed(Error),
}

/// Reads and deletes only an owned address. matches must establish exact journal ownership; absent is distinct from unavailable. Never delete a mismatched or unreadable row.
pub(in crate::windows) trait ManagedAddressCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedAddressRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

pub(in crate::windows) fn delete_managed_address<O: ManagedAddressCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedAddressRead::Absent => false,
        ManagedAddressRead::Present(current) if operations.matches(intended, &current) => {
            operations.delete(&current).is_err()
                | !matches!(operations.read(intended), ManagedAddressRead::Absent)
        }
        ManagedAddressRead::Present(_) | ManagedAddressRead::Failed(_) => true,
    }
}

pub(in crate::windows) enum ManagedRouteRead<R> {
    Absent,
    Present(R),
    Failed(Error),
}

/// Reads and deletes only an owned route. matches must establish exact journal ownership; absent is distinct from unavailable. Never delete a mismatched or unreadable row.
pub(in crate::windows) trait ManagedRouteCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedRouteRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

pub(in crate::windows) fn delete_managed_route<O: ManagedRouteCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedRouteRead::Absent => false,
        ManagedRouteRead::Present(current) if operations.matches(intended, &current) => {
            operations.delete(&current).is_err()
                | !matches!(operations.read(intended), ManagedRouteRead::Absent)
        }
        ManagedRouteRead::Present(_) | ManagedRouteRead::Failed(_) => true,
    }
}

pub(in crate::windows) fn managed_routes_match<O: ManagedRouteCleanupOperations>(
    intended: &[O::Row],
    operations: &mut O,
) -> ReadbackMatch {
    for row in intended {
        match operations.read(row) {
            ManagedRouteRead::Present(current) if operations.matches(row, &current) => {}
            ManagedRouteRead::Present(_) | ManagedRouteRead::Absent => {
                return ReadbackMatch::Mismatch;
            }
            ManagedRouteRead::Failed(error) => return ReadbackMatch::Unavailable(error),
        }
    }
    ReadbackMatch::Exact
}

pub(in crate::windows) fn take_last_owned_route<R>(
    pending: &mut Option<R>,
    journal: &mut Vec<R>,
) -> Option<R> {
    pending.take().or_else(|| journal.pop())
}

pub(in crate::windows) fn finish_setup_transaction(
    setup: Result<(), Error>,
    strict_route_install_failed: bool,
    cleanup: impl FnOnce() -> bool,
) -> Result<(), CreateError> {
    match setup {
        Ok(()) => Ok(()),
        Err(error) => {
            let outer_cleanup_failed = cleanup();
            let cleanup_failed = (error.kind() == crate::ErrorKind::Cleanup) | outer_cleanup_failed;
            if strict_route_install_failed {
                Err(CreateError::strict_route_install(cleanup_failed))
            } else if cleanup_failed {
                Err(CreateError::cleanup())
            } else {
                Err(CreateError::operation())
            }
        }
    }
}

/// Rolls back journaled resources in reverse order, continuing after individual failures. Each returned step consumes at most one owner and reports cleanup failure. Session idle must be established before teardown; EndSession must never overlap a wait. Unconfirmed notification cancellation must preserve callback context lifetime.
pub(in crate::windows) trait CleanupOperations {
    fn session_is_idle(&mut self) -> bool;
    fn cancel_notifications(&mut self) -> Option<bool> {
        None
    }
    fn close_strict_route(&mut self) -> Option<bool> {
        None
    }
    fn delete_last_route(&mut self) -> Option<bool> {
        None
    }
    fn restore_last_dns(&mut self) -> Option<bool> {
        None
    }
    fn end_session(&mut self) -> Option<bool>;
    fn delete_last_address(&mut self) -> Option<bool>;
    fn restore_ipv6_mtu(&mut self) -> Option<bool>;
    fn restore_ipv4_mtu(&mut self) -> Option<bool>;
    fn restore_ipv4_link_local(&mut self) -> Option<bool>;
    fn close_adapter(&mut self) -> Option<bool>;
}

pub(in crate::windows) fn cleanup_transaction(cleanup: &mut impl CleanupOperations) -> bool {
    if !cleanup.session_is_idle() {
        return true;
    }
    let mut failed = cleanup.cancel_notifications().unwrap_or(false);
    failed |= cleanup.close_strict_route().unwrap_or(false);
    while let Some(step_failed) = cleanup.restore_last_dns() {
        failed |= step_failed;
    }
    while let Some(step_failed) = cleanup.delete_last_route() {
        failed |= step_failed;
    }
    while let Some(step_failed) = cleanup.delete_last_address() {
        failed |= step_failed;
    }
    failed |= cleanup.restore_ipv6_mtu().unwrap_or(false);
    failed |= cleanup.restore_ipv4_mtu().unwrap_or(false);
    failed |= cleanup.restore_ipv4_link_local().unwrap_or(false);
    failed |= cleanup.end_session().unwrap_or(false);
    failed |= cleanup.close_adapter().unwrap_or(false);
    failed
}

/// Stages one adapter transaction. Every successful mutation must enter its rollback journal before another fallible step; failures must retain partial owners for cleanup. Cancellation and deadline checks must be nonmutating, and DAD may report ready only after every enabled address is preferred.
pub(in crate::windows) trait SetupOperations {
    fn check_cancelled(&mut self) -> Result<(), Error>;
    fn check_deadline(&mut self) -> Result<(), Error>;
    fn create_adapter(&mut self) -> Result<(), Error>;
    fn check_driver(&mut self) -> Result<(), Error>;
    fn start_session(&mut self) -> Result<(), Error>;
    fn identify_adapter(&mut self) -> Result<(), Error>;
    fn ipv4_enabled(&self) -> bool;
    fn ipv6_enabled(&self) -> bool;
    fn disable_ipv4_link_local(&mut self) -> Result<(), Error>;
    fn set_ipv4_mtu(&mut self) -> Result<(), Error>;
    fn set_ipv6_mtu(&mut self) -> Result<(), Error>;
    fn add_ipv4_address(&mut self) -> Result<(), Error>;
    fn add_ipv6_address(&mut self) -> Result<(), Error>;
    fn wait_for_dad(&mut self) -> Result<(), Error>;
}

pub(in crate::windows) fn setup_transaction(setup: &mut impl SetupOperations) -> Result<(), Error> {
    setup.check_cancelled()?;
    setup.check_deadline()?;
    setup.create_adapter()?;
    setup.check_driver()?;
    setup.start_session()?;
    setup.identify_adapter()?;
    if !setup.ipv4_enabled() {
        setup.disable_ipv4_link_local()?;
    }
    if setup.ipv4_enabled() {
        setup.set_ipv4_mtu()?;
    }
    if setup.ipv6_enabled() {
        setup.set_ipv6_mtu()?;
    }
    if setup.ipv4_enabled() {
        setup.add_ipv4_address()?;
    }
    if setup.ipv6_enabled() {
        setup.add_ipv6_address()?;
    }
    setup.wait_for_dad()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyCleanup;

    impl CleanupOperations for EmptyCleanup {
        fn session_is_idle(&mut self) -> bool {
            true
        }
        fn end_session(&mut self) -> Option<bool> {
            None
        }
        fn delete_last_address(&mut self) -> Option<bool> {
            None
        }
        fn restore_ipv6_mtu(&mut self) -> Option<bool> {
            None
        }
        fn restore_ipv4_mtu(&mut self) -> Option<bool> {
            None
        }
        fn restore_ipv4_link_local(&mut self) -> Option<bool> {
            None
        }
        fn close_adapter(&mut self) -> Option<bool> {
            None
        }
    }

    #[test]
    fn empty_cleanup_is_exact() {
        assert!(!cleanup_transaction(&mut EmptyCleanup));
    }
}
