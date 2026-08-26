use crate::{CreateError, Error, ManagedNetworkConfig};

pub(super) fn prepare_managed_intent<T>(
    config: Option<&ManagedNetworkConfig>,
    prepare: impl FnOnce(&ManagedNetworkConfig) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    config.map(prepare).transpose()
}

pub(super) struct ManagedDnsLease<S> {
    pub(super) previous: S,
    pub(super) applied: S,
}

pub(super) trait ManagedDnsOperations {
    type Settings: Clone + Eq;
    type Address: Copy;

    fn snapshot(&mut self) -> Result<Self::Settings, Error>;
    fn apply(&mut self, address: Self::Address) -> Result<Self::Settings, Error>;
    fn readback(&mut self) -> Result<Self::Settings, Error>;
    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error>;
}

pub(super) fn install_managed_dns<O: ManagedDnsOperations>(
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

pub(super) fn managed_dns_matches<O: ManagedDnsOperations>(
    operations: &mut O,
    lease: &ManagedDnsLease<O::Settings>,
) -> Result<bool, Error> {
    Ok(operations.readback()? == lease.applied)
}

pub(super) fn restore_managed_dns<O: ManagedDnsOperations>(
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

pub(super) trait ManagedRouteOperations {
    type Row: Copy;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error>;
    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error>;
    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error>;
    fn commit_pending(&mut self) -> Result<(), Error>;
}

pub(super) fn install_managed_routes<O: ManagedRouteOperations>(
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

pub(super) enum ManagedAddressRead<R> {
    Absent,
    Present(R),
    Failed,
}

pub(super) trait ManagedAddressCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedAddressRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

pub(super) fn delete_managed_address<O: ManagedAddressCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedAddressRead::Absent => false,
        ManagedAddressRead::Present(current) if operations.matches(intended, &current) => {
            operations.delete(&current).is_err()
                | !matches!(operations.read(intended), ManagedAddressRead::Absent)
        }
        ManagedAddressRead::Present(_) | ManagedAddressRead::Failed => true,
    }
}

pub(super) enum ManagedRouteRead<R> {
    Absent,
    Present(R),
    Failed,
}

pub(super) trait ManagedRouteCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedRouteRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

pub(super) fn delete_managed_route<O: ManagedRouteCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedRouteRead::Absent => false,
        ManagedRouteRead::Present(current) if operations.matches(intended, &current) => {
            operations.delete(&current).is_err()
                | !matches!(operations.read(intended), ManagedRouteRead::Absent)
        }
        ManagedRouteRead::Present(_) | ManagedRouteRead::Failed => true,
    }
}

pub(super) fn managed_routes_match<O: ManagedRouteCleanupOperations>(
    intended: &[O::Row],
    operations: &mut O,
) -> bool {
    intended.iter().all(|row| {
        matches!(
            operations.read(row),
            ManagedRouteRead::Present(current) if operations.matches(row, &current)
        )
    })
}

pub(super) fn take_last_owned_route<R>(pending: &mut Option<R>, journal: &mut Vec<R>) -> Option<R> {
    pending.take().or_else(|| journal.pop())
}

pub(super) fn finish_setup_transaction(
    setup: Result<(), Error>,
    strict_route_install_failed: bool,
    cleanup: impl FnOnce() -> bool,
) -> Result<(), CreateError> {
    match setup {
        Ok(()) => Ok(()),
        Err(_) => {
            let cleanup_failed = cleanup();
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

pub(super) trait CleanupOperations {
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
    fn close_adapter(&mut self) -> Option<bool>;
}

pub(super) fn cleanup_transaction(cleanup: &mut impl CleanupOperations) -> bool {
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
    failed |= cleanup.end_session().unwrap_or(false);
    failed |= cleanup.close_adapter().unwrap_or(false);
    failed
}

pub(super) trait SetupOperations {
    fn check_cancelled(&mut self) -> Result<(), Error>;
    fn check_deadline(&mut self) -> Result<(), Error>;
    fn create_adapter(&mut self) -> Result<(), Error>;
    fn check_driver(&mut self) -> Result<(), Error>;
    fn start_session(&mut self) -> Result<(), Error>;
    fn identify_adapter(&mut self) -> Result<(), Error>;
    fn ipv4_enabled(&self) -> bool;
    fn ipv6_enabled(&self) -> bool;
    fn set_ipv4_mtu(&mut self) -> Result<(), Error>;
    fn set_ipv6_mtu(&mut self) -> Result<(), Error>;
    fn add_ipv4_address(&mut self) -> Result<(), Error>;
    fn add_ipv6_address(&mut self) -> Result<(), Error>;
    fn wait_for_dad(&mut self) -> Result<(), Error>;
}

pub(super) fn setup_transaction(setup: &mut impl SetupOperations) -> Result<(), Error> {
    setup.check_cancelled()?;
    setup.check_deadline()?;
    setup.create_adapter()?;
    setup.check_driver()?;
    setup.start_session()?;
    setup.identify_adapter()?;
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
        fn close_adapter(&mut self) -> Option<bool> {
            None
        }
    }

    #[test]
    fn empty_cleanup_is_exact() {
        assert!(!cleanup_transaction(&mut EmptyCleanup));
    }
}
