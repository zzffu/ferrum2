use super::{ManagedAddressCleanupOperations, ManagedAddressRead};
use crate::{Error, ManagedStateDamage, ManagedTunHealth};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// A failed observation never proves owned state is damaged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::windows) enum ReadbackMatch {
    Exact,
    Mismatch,
    Unavailable(Error),
}

impl ReadbackMatch {
    pub(in crate::windows) fn is_exact(self) -> Result<bool, Error> {
        match self {
            Self::Exact => Ok(true),
            Self::Mismatch => Ok(false),
            Self::Unavailable(error) => Err(error),
        }
    }
}

/// Preserves absence, exactness and unavailable errors when reading owned addresses.
pub(in crate::windows) fn addresses_match<O: ManagedAddressCleanupOperations>(
    rows: &[O::Row],
    operations: &mut O,
) -> ReadbackMatch {
    for intended in rows {
        match operations.read(intended) {
            ManagedAddressRead::Present(current) if operations.matches(intended, &current) => {}
            ManagedAddressRead::Present(_) | ManagedAddressRead::Absent => {
                return ReadbackMatch::Mismatch;
            }
            ManagedAddressRead::Failed(error) => return ReadbackMatch::Unavailable(error),
        }
    }
    ReadbackMatch::Exact
}

/// Checks both journal slots before querying only owned interface families.
pub(in crate::windows) fn mtu_health(
    enabled: [bool; 2],
    configured: u32,
    journal: [Option<(u16, u32)>; 2],
    mut read: impl FnMut(u16) -> Result<Option<u32>, Error>,
) -> Result<ManagedTunHealth, Error> {
    for ((enabled, family), entry) in enabled.into_iter().zip([AF_INET, AF_INET6]).zip(journal) {
        if entry != enabled.then_some((family, configured)) {
            return Ok(ManagedTunHealth::Damaged(
                ManagedStateDamage::OwnershipLedger,
            ));
        }
    }
    for (family, configured) in journal.into_iter().flatten() {
        if read(family)? != Some(configured) {
            return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Mtu));
        }
    }
    Ok(ManagedTunHealth::Healthy)
}

/// Requires a link-local suppression lease exactly when IPv4 is not configured.
pub(in crate::windows) fn ipv4_link_local_health(
    ipv4_enabled: bool,
    policy_journaled: bool,
    mut read_disabled: impl FnMut() -> Result<Option<bool>, Error>,
) -> Result<ManagedTunHealth, Error> {
    if policy_journaled != !ipv4_enabled {
        return Ok(ManagedTunHealth::Damaged(
            ManagedStateDamage::OwnershipLedger,
        ));
    }
    if policy_journaled && read_disabled()? != Some(true) {
        return Ok(ManagedTunHealth::Damaged(
            ManagedStateDamage::InterfacePolicy,
        ));
    }
    Ok(ManagedTunHealth::Healthy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::core::managed::mtu_health;

    #[test]
    fn ipv4_link_local_health_requires_the_disabled_family_lease_and_exact_readback() {
        assert_eq!(
            ipv4_link_local_health(true, false, || panic!("enabled IPv4 queried")),
            Ok(ManagedTunHealth::Healthy)
        );
        for (enabled, journaled) in [(true, true), (false, false)] {
            assert_eq!(
                ipv4_link_local_health(enabled, journaled, || panic!("invalid journal queried")),
                Ok(ManagedTunHealth::Damaged(
                    ManagedStateDamage::OwnershipLedger
                ))
            );
        }
        assert_eq!(
            ipv4_link_local_health(false, true, || Ok(Some(true))),
            Ok(ManagedTunHealth::Healthy)
        );
        for current in [None, Some(false)] {
            assert_eq!(
                ipv4_link_local_health(false, true, || Ok(current)),
                Ok(ManagedTunHealth::Damaged(
                    ManagedStateDamage::InterfacePolicy
                ))
            );
        }
        for error in [
            Error::recoverable_session(),
            Error::invalid_input(),
            Error::cleanup(),
        ] {
            assert_eq!(
                ipv4_link_local_health(false, true, || Err(error)),
                Err(error)
            );
        }
    }
    #[test]
    fn mtu_readback_distinguishes_damage_unavailability_and_family_journal_conflicts() {
        for enabled in [[true, false], [false, true], [true, true]] {
            let journal = [
                enabled[0].then_some((AF_INET, 1400)),
                enabled[1].then_some((AF_INET6, 1400)),
            ];
            assert_eq!(
                mtu_health(enabled, 1400, journal, |_| Ok(Some(1400))),
                Ok(ManagedTunHealth::Healthy)
            );
            for value in [None, Some(1399)] {
                assert_eq!(
                    mtu_health(enabled, 1400, journal, |_| Ok(value)),
                    Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Mtu))
                );
            }
            for error in [
                Error::recoverable_session(),
                Error::invalid_input(),
                Error::cleanup(),
            ] {
                assert_eq!(
                    mtu_health(enabled, 1400, journal, |_| Err(error)),
                    Err(error)
                );
            }
            assert_eq!(
                mtu_health(enabled, 1400, [None, None], |_| panic!(
                    "invalid journal queried"
                )),
                Ok(ManagedTunHealth::Damaged(
                    ManagedStateDamage::OwnershipLedger
                ))
            );
        }
        for journal in [
            [Some((AF_INET6, 1400)), None],
            [Some((AF_INET, 1399)), None],
            [Some((AF_INET, 1400)), Some((AF_INET6, 1400))],
        ] {
            assert_eq!(
                mtu_health([true, false], 1400, journal, |_| panic!(
                    "invalid journal queried"
                )),
                Ok(ManagedTunHealth::Damaged(
                    ManagedStateDamage::OwnershipLedger
                ))
            );
        }
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;
    struct Reader(Option<ManagedAddressRead<u8>>);
    impl ManagedAddressCleanupOperations for Reader {
        type Row = u8;
        fn read(&mut self, _: &u8) -> ManagedAddressRead<u8> {
            self.0.take().unwrap()
        }
        fn matches(&self, intended: &u8, current: &u8) -> bool {
            intended == current
        }
        fn delete(&mut self, _: &u8) -> Result<(), Error> {
            panic!("health cannot delete")
        }
    }
    #[test]
    fn address_readback_preserves_unavailable_and_proven_damage() {
        for (read, expected) in [
            (ManagedAddressRead::Present(1), Ok(true)),
            (ManagedAddressRead::Present(2), Ok(false)),
            (ManagedAddressRead::Absent, Ok(false)),
            (
                ManagedAddressRead::Failed(Error::recoverable_session()),
                Err(Error::recoverable_session()),
            ),
            (
                ManagedAddressRead::Failed(Error::cleanup()),
                Err(Error::cleanup()),
            ),
        ] {
            assert_eq!(
                crate::windows::core::managed::addresses_match(&[1], &mut Reader(Some(read)))
                    .is_exact(),
                expected
            );
        }
    }
}
