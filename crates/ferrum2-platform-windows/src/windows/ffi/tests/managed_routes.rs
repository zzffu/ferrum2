use super::support::{
    Error, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
    MIB_UNICASTIPADDRESS_ROW, ManagedAddressCleanupOperations, ManagedAddressRead,
    ManagedRouteCleanupOperations, ManagedRouteOperations, ManagedRouteRead,
    delete_managed_address, delete_managed_route, initialize_managed_address,
    install_managed_routes, ipv4_sockaddr, ipv6_sockaddr, managed_address_matches,
    take_last_owned_route,
};

struct InjectedManagedRoutes {
    occupied: Option<u8>,
    preflight_error: Option<u8>,
    create_conflict: Option<u8>,
    readback_error: Option<u8>,
    readback_mismatch: Option<u8>,
    calls: Vec<(&'static str, u8)>,
    pending: Option<u8>,
    journal: Vec<u8>,
}

impl ManagedRouteOperations for InjectedManagedRoutes {
    type Row = u8;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error> {
        self.calls.push(("absent", *row));
        if self.occupied == Some(*row) || self.preflight_error == Some(*row) {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error> {
        self.calls.push(("create", row));
        if self.create_conflict == Some(row) {
            return Err(Error);
        }
        self.pending = Some(row);
        Ok(())
    }

    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error> {
        self.calls.push(("readback", *row));
        if self.readback_error == Some(*row) {
            return Err(Error);
        }
        Ok(self.readback_mismatch != Some(*row))
    }

    fn commit_pending(&mut self) -> Result<(), Error> {
        self.journal.push(self.pending.take().ok_or(Error)?);
        Ok(())
    }
}

#[test]
fn managed_route_preflights_every_key_before_first_create() {
    let make = || InjectedManagedRoutes {
        occupied: None,
        preflight_error: None,
        create_conflict: None,
        readback_error: None,
        readback_mismatch: None,
        calls: Vec::new(),
        pending: None,
        journal: Vec::new(),
    };
    for (conflict, expected_queries) in [(1, 1), (2, 2), (3, 3)] {
        let mut routes = make();
        routes.occupied = Some(conflict);
        assert!(install_managed_routes(&[1, 2, 3], &mut routes).is_err());
        assert_eq!(
            routes.calls,
            (1..=expected_queries)
                .map(|row| ("absent", row))
                .collect::<Vec<_>>()
        );
        assert!(routes.pending.is_none());
        assert!(routes.journal.is_empty());
    }

    let mut query_error = make();
    query_error.preflight_error = Some(2);
    assert!(install_managed_routes(&[1, 2, 3], &mut query_error).is_err());
    assert!(query_error.journal.is_empty());

    let mut late_conflict = make();
    late_conflict.create_conflict = Some(2);
    assert!(install_managed_routes(&[1, 2, 3], &mut late_conflict).is_err());
    assert_eq!(late_conflict.journal, [1]);
    assert!(late_conflict.pending.is_none());

    for readback_error in [true, false] {
        let mut failed = make();
        if readback_error {
            failed.readback_error = Some(2);
        } else {
            failed.readback_mismatch = Some(2);
        }
        assert!(install_managed_routes(&[1, 2, 3], &mut failed).is_err());
        assert_eq!(failed.journal, [1]);
        assert_eq!(failed.pending, Some(2));
        assert_eq!(
            take_last_owned_route(&mut failed.pending, &mut failed.journal),
            Some(2)
        );
        assert_eq!(
            take_last_owned_route(&mut failed.pending, &mut failed.journal),
            Some(1)
        );
    }

    let mut complete = make();
    install_managed_routes(&[1, 2, 3], &mut complete).unwrap();
    assert_eq!(
        std::iter::from_fn(|| {
            take_last_owned_route(&mut complete.pending, &mut complete.journal)
        })
        .collect::<Vec<_>>(),
        [3, 2, 1]
    );
}

pub(super) struct InjectedRouteCleanup {
    pub(super) reads: std::collections::VecDeque<ManagedRouteRead<u8>>,
    pub(super) delete_error: bool,
    pub(super) calls: Vec<&'static str>,
}

impl ManagedRouteCleanupOperations for InjectedRouteCleanup {
    type Row = u8;

    fn read(&mut self, _intended: &Self::Row) -> ManagedRouteRead<Self::Row> {
        self.calls.push("get");
        self.reads.pop_front().unwrap_or(ManagedRouteRead::Failed)
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        intended == current
    }

    fn delete(&mut self, _current: &Self::Row) -> Result<(), Error> {
        self.calls.push("delete");
        if self.delete_error {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

#[test]
fn managed_route_cleanup_preserves_replacements_and_audits_every_delete() {
    let run = |reads, delete_error| {
        let mut cleanup = InjectedRouteCleanup {
            reads: std::collections::VecDeque::from(reads),
            delete_error,
            calls: Vec::new(),
        };
        let failed = delete_managed_route(&mut cleanup, &1);
        (failed, cleanup.calls)
    };
    assert_eq!(
        run(vec![ManagedRouteRead::Absent], false),
        (false, vec!["get"])
    );
    assert_eq!(
        run(
            vec![ManagedRouteRead::Present(1), ManagedRouteRead::Absent],
            false,
        ),
        (false, vec!["get", "delete", "get"])
    );
    assert_eq!(
        run(vec![ManagedRouteRead::Present(2)], false),
        (true, vec!["get"]),
        "a third-party replacement is preserved"
    );
    assert_eq!(
        run(vec![ManagedRouteRead::Failed], false),
        (true, vec!["get"])
    );
    for (delete_error, final_read) in [
        (true, ManagedRouteRead::Absent),
        (false, ManagedRouteRead::Failed),
        (false, ManagedRouteRead::Present(1)),
    ] {
        assert_eq!(
            run(vec![ManagedRouteRead::Present(1), final_read], delete_error,),
            (true, vec!["get", "delete", "get"])
        );
    }
}

struct InjectedAddressCleanup {
    reads: std::collections::VecDeque<ManagedAddressRead<u8>>,
    delete_error: bool,
    calls: Vec<&'static str>,
}

impl ManagedAddressCleanupOperations for InjectedAddressCleanup {
    type Row = u8;

    fn read(&mut self, _intended: &Self::Row) -> ManagedAddressRead<Self::Row> {
        self.calls.push("get");
        self.reads.pop_front().unwrap_or(ManagedAddressRead::Failed)
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        intended == current
    }

    fn delete(&mut self, _current: &Self::Row) -> Result<(), Error> {
        self.calls.push("delete");
        if self.delete_error {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

#[test]
fn managed_address_readback_and_cleanup_are_exact_and_foreign_safe() {
    let run = |reads, delete_error| {
        let mut cleanup = InjectedAddressCleanup {
            reads: std::collections::VecDeque::from(reads),
            delete_error,
            calls: Vec::new(),
        };
        let failed = delete_managed_address(&mut cleanup, &1);
        (failed, cleanup.calls)
    };
    assert_eq!(
        run(vec![ManagedAddressRead::Absent], false),
        (false, vec!["get"])
    );
    assert_eq!(
        run(
            vec![ManagedAddressRead::Present(1), ManagedAddressRead::Absent,],
            false,
        ),
        (false, vec!["get", "delete", "get"])
    );
    assert_eq!(
        run(vec![ManagedAddressRead::Present(2)], false),
        (true, vec!["get"]),
        "a foreign replacement is preserved"
    );
    for (delete_error, final_read) in [
        (true, ManagedAddressRead::Absent),
        (false, ManagedAddressRead::Failed),
        (false, ManagedAddressRead::Present(1)),
    ] {
        assert_eq!(
            run(
                vec![ManagedAddressRead::Present(1), final_read],
                delete_error,
            ),
            (true, vec!["get", "delete", "get"])
        );
    }

    let mut expected = MIB_UNICASTIPADDRESS_ROW::default();
    initialize_managed_address(&mut expected);
    assert_eq!(expected.PrefixOrigin, IpPrefixOriginManual);
    assert_eq!(expected.SuffixOrigin, IpSuffixOriginManual);
    expected.InterfaceLuid.Value = 7;
    expected.InterfaceIndex = 17;
    expected.Address = ipv4_sockaddr("198.18.0.2".parse().unwrap());
    expected.OnLinkPrefixLength = 30;
    let mut actual = expected;
    actual.DadState = IpDadStatePreferred;
    actual.CreationTimeStamp = 123;
    assert!(managed_address_matches(&expected, &actual));

    let changed = [
        {
            let mut row = actual;
            unsafe { row.InterfaceLuid.Value += 1 };
            row
        },
        {
            let mut row = actual;
            row.InterfaceIndex += 1;
            row
        },
        {
            let mut row = actual;
            row.Address = ipv4_sockaddr("198.18.0.3".parse().unwrap());
            row
        },
        {
            let mut row = actual;
            row.OnLinkPrefixLength += 1;
            row
        },
        {
            let mut row = actual;
            row.SkipAsSource = !row.SkipAsSource;
            row
        },
        {
            let mut row = actual;
            row.ValidLifetime = row.ValidLifetime.saturating_sub(1);
            row
        },
    ];
    assert!(
        changed
            .iter()
            .all(|row| !managed_address_matches(&expected, row))
    );

    let mut ipv6 = expected;
    ipv6.Address = ipv6_sockaddr("fd00::2".parse().unwrap());
    ipv6.OnLinkPrefixLength = 126;
    assert!(managed_address_matches(&ipv6, &ipv6));
}
