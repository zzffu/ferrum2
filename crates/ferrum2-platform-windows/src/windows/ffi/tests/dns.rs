use super::support::{
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, DnsFamily, Error, IfOperStatusUp, InterfaceIdentity,
    IpPrefix, Ipv4DnsSettings, Ipv4Prefix, Ipv6DnsSettings, MIB_IF_ROW2, ManagedDnsLease,
    ManagedDnsOperations, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, RouteFingerprint,
    copy_bounded_wide, dns_settings_query_flags, eligible_interface_identity, install_managed_dns,
    ipv4_dns_settings_input, ipv6_dns_settings_input, managed_dns_matches, normalize_dns_settings,
    prepare_managed_intent, restore_managed_dns,
};

#[test]
fn disabled_managed_skips_every_platform_operation() {
    let mut calls = Vec::new();
    assert_eq!(
        prepare_managed_intent(None, |_| {
            calls.extend(["subscribe", "generation", "snapshot", "query", "mutation"]);
            Ok(())
        })
        .unwrap(),
        None
    );
    assert!(calls.is_empty());

    let manual_direct =
        crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
    assert_eq!(
        prepare_managed_intent(Some(&manual_direct), |config| {
            calls.extend(["subscribe", "generation", "default-snapshot"]);
            assert!(config.needs_target_binder());
            Ok(())
        })
        .unwrap(),
        Some(())
    );
    assert_eq!(calls, ["subscribe", "generation", "default-snapshot"]);
}

#[test]
fn m16_redaction_managed_identity_table_is_aggregate() {
    let adapter_name = "m16-adapter-sentinel";
    let interface_name = "m16-interface-sentinel";
    let endpoint: std::net::SocketAddrV4 = "203.0.113.211:49153".parse().unwrap();
    let dns_address = "198.18.0.1".parse().unwrap();
    let prefix = Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24).unwrap();
    let managed = crate::ManagedNetworkConfig::new(
        vec![IpPrefix::V4(prefix)],
        vec![endpoint.into()],
        true,
        Some(dns_address),
        None,
    )
    .unwrap();
    let config = crate::AdapterConfig::new(
        adapter_name.into(),
        Some(Ipv4Prefix::new("198.18.0.2".parse().unwrap(), 30).unwrap()),
        Some(crate::Ipv6Prefix::new("fd00::2".parse().unwrap(), 126).unwrap()),
        1420,
        8_388_608,
        std::time::Duration::from_secs(10),
    )
    .unwrap()
    .with_managed_network(managed)
    .unwrap();
    assert_eq!(config.name.as_ref(), adapter_name);

    let identity = InterfaceIdentity {
        luid: 0x1122_3344_5566_7788,
        index: 0x7f00_1234,
    };
    let mut raw = MIB_IF_ROW2::default();
    raw.InterfaceLuid.Value = identity.luid;
    raw.InterfaceIndex = identity.index;
    raw.InterfaceGuid = windows_sys::core::GUID {
        data1: 0x6fc7_2c11,
        data2: 0x4c9a,
        data3: 0x45c4,
        data4: [0x8f, 0x61, 0x49, 0x55, 0x72, 0x1a, 0x77, 0xe1],
    };
    raw.Type = 6;
    raw.OperStatus = IfOperStatusUp;
    raw.AdminStatus = NET_IF_ADMIN_STATUS_UP;
    raw.MediaConnectState = MediaConnectStateConnected;
    raw.InterfaceAndOperStatusFlags._bitfield = 1;
    for (slot, unit) in raw.Alias.iter_mut().zip(interface_name.encode_utf16()) {
        *slot = unit;
    }
    assert!(eligible_interface_identity(&raw, None) == Some(identity));

    let route = RouteFingerprint {
        interface_luid: identity.luid,
        interface_index: identity.index,
        destination: "203.0.113.0".parse().unwrap(),
        prefix_length: 24,
        next_hop: "192.0.2.137".parse().unwrap(),
        metric: 31337,
        source: Some("192.0.2.138".parse().unwrap()),
    };
    assert_eq!(route.interface_index, identity.index);

    let rendered = [
        format!("{Error:?}"),
        Error.to_string(),
        format!("{:?}", Err::<(), _>(Error)),
        format!("{:?}", crate::CreateError::operation()),
        crate::CreateError::operation().to_string(),
        format!("{:?}", crate::CreateError::cleanup()),
        crate::CreateError::cleanup().to_string(),
    ];
    let sentinels = [
        adapter_name.to_owned(),
        interface_name.to_owned(),
        endpoint.to_string(),
        dns_address.to_string(),
        "203.0.113.0/24".to_owned(),
        identity.index.to_string(),
        identity.luid.to_string(),
        "6fc72c11-4c9a-45c4-8f61-4955721a77e1".to_owned(),
        route.next_hop.to_string(),
        route.source.unwrap().to_string(),
        route.metric.to_string(),
    ];
    let leaks = |values: &[String]| {
        values
            .iter()
            .any(|value| sentinels.iter().any(|sentinel| value.contains(sentinel)))
    };
    assert!(!leaks(&rendered));
    assert!(leaks(&[format!("synthetic leak: {endpoint}")]));
}

struct InjectedManagedDns {
    current: u8,
    fail_at: Option<&'static str>,
    replace_on_read: Option<(usize, u8)>,
    readbacks: usize,
    calls: Vec<&'static str>,
}

impl ManagedDnsOperations for InjectedManagedDns {
    type Settings = u8;
    type Address = std::net::IpAddr;

    fn snapshot(&mut self) -> Result<Self::Settings, Error> {
        self.calls.push("snapshot");
        (self.fail_at != Some("snapshot"))
            .then_some(self.current)
            .ok_or(Error)
    }

    fn apply(&mut self, _address: Self::Address) -> Result<Self::Settings, Error> {
        self.calls.push("apply");
        if self.fail_at == Some("apply") {
            return Err(Error);
        }
        self.current = 2;
        Ok(2)
    }

    fn readback(&mut self) -> Result<Self::Settings, Error> {
        self.calls.push("readback");
        self.readbacks += 1;
        if self.fail_at == Some("readback") {
            return Err(Error);
        }
        if self
            .replace_on_read
            .is_some_and(|(read, _)| read == self.readbacks)
        {
            self.current = self.replace_on_read.take().unwrap().1;
        }
        Ok(self.current)
    }

    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
        self.calls.push("restore");
        if self.fail_at == Some("restore") {
            return Err(Error);
        }
        self.current = *settings;
        Ok(())
    }
}

#[test]
fn managed_dns_runtime_readback_detects_replacement_and_failure() {
    let lease = ManagedDnsLease {
        previous: 1,
        applied: 2,
    };
    let mut matching = InjectedManagedDns {
        current: 2,
        fail_at: None,
        replace_on_read: None,
        readbacks: 0,
        calls: Vec::new(),
    };
    assert!(managed_dns_matches(&mut matching, &lease).unwrap());
    matching.current = 3;
    assert!(!managed_dns_matches(&mut matching, &lease).unwrap());
    matching.fail_at = Some("readback");
    assert!(managed_dns_matches(&mut matching, &lease).is_err());
}

#[test]
fn managed_dns_snapshots_reads_back_and_conditionally_restores() {
    let address = std::net::IpAddr::V4("198.18.0.1".parse().unwrap());
    let ipv6_address = std::net::IpAddr::V6("fd00::1".parse().unwrap());
    let make = || InjectedManagedDns {
        current: 1,
        fail_at: None,
        replace_on_read: None,
        readbacks: 0,
        calls: Vec::new(),
    };

    for family_address in [address, ipv6_address] {
        let mut complete = make();
        let mut lease = None;
        install_managed_dns(family_address, &mut complete, &mut lease).unwrap();
        assert_eq!(complete.calls, ["snapshot", "apply", "readback"]);
        assert!(!restore_managed_dns(&mut complete, lease.as_ref().unwrap()));
        assert_eq!(complete.current, 1);
        assert_eq!(
            complete.calls,
            [
                "snapshot", "apply", "readback", "readback", "restore", "readback"
            ]
        );
    }

    for failure in ["snapshot", "apply", "readback"] {
        let mut injected = make();
        injected.fail_at = Some(failure);
        let mut lease = None;
        assert!(install_managed_dns(address, &mut injected, &mut lease).is_err());
        if failure == "readback" {
            assert!(lease.is_some(), "successful apply must be journaled");
            injected.fail_at = None;
            assert!(!restore_managed_dns(&mut injected, lease.as_ref().unwrap()));
            assert_eq!(injected.current, 1);
        } else {
            assert!(lease.is_none());
            assert_eq!(injected.current, 1);
        }
    }

    let mut replaced = make();
    let mut lease = None;
    install_managed_dns(address, &mut replaced, &mut lease).unwrap();
    replaced.current = 3;
    assert!(restore_managed_dns(&mut replaced, lease.as_ref().unwrap()));
    assert_eq!(replaced.current, 3, "external replacement is preserved");
    assert_eq!(replaced.calls.last(), Some(&"readback"));

    for (failure, replacement) in [(Some("restore"), None), (None, Some((3, 4)))] {
        let mut injected = make();
        let mut lease = None;
        install_managed_dns(address, &mut injected, &mut lease).unwrap();
        injected.fail_at = failure;
        injected.replace_on_read = replacement;
        assert!(restore_managed_dns(&mut injected, lease.as_ref().unwrap()));
    }

    for (settings, expected) in [
        (Ipv4DnsSettings(None), &[0_u16][..]),
        (
            Ipv4DnsSettings(Some(Box::from([b'1' as u16, b'.' as u16, b'1' as u16]))),
            &[b'1' as u16, b'.' as u16, b'1' as u16, 0][..],
        ),
    ] {
        let (name_server, raw) = ipv4_dns_settings_input(&settings);
        assert_eq!(raw.Flags, u64::from(DNS_SETTING_NAMESERVER));
        assert!(!raw.NameServer.is_null());
        assert_eq!(raw.NameServer, name_server.as_ptr().cast_mut());
        assert_eq!(name_server.as_ref(), expected);
    }

    assert_eq!(dns_settings_query_flags(DnsFamily::Ipv4), 0);
    assert_eq!(
        dns_settings_query_flags(DnsFamily::Ipv6),
        u64::from(DNS_SETTING_IPV6)
    );

    let ipv6_settings = Ipv6DnsSettings(Some("fd00::1".encode_utf16().collect::<Box<[u16]>>()));
    let (name_server, raw) = ipv6_dns_settings_input(&ipv6_settings);
    assert_eq!(
        raw.Flags,
        u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6)
    );
    assert_eq!(raw.NameServer, name_server.as_ptr().cast_mut());
    assert_eq!(name_server.last(), Some(&0));

    let mixed = "1.1.1.1, 2001:0db8::1 8.8.8.8,2001:db8::2"
        .encode_utf16()
        .collect::<Vec<_>>();
    let ipv4 = normalize_dns_settings(Some(&mixed), DnsFamily::Ipv4)
        .unwrap()
        .unwrap();
    let ipv6 = normalize_dns_settings(Some(&mixed), DnsFamily::Ipv6)
        .unwrap()
        .unwrap();
    assert_eq!(String::from_utf16(&ipv4).unwrap(), "1.1.1.1,8.8.8.8");
    assert_eq!(
        String::from_utf16(&ipv6).unwrap(),
        "2001:db8::1,2001:db8::2"
    );
    assert!(normalize_dns_settings(Some(&[b'x' as u16]), DnsFamily::Ipv4).is_err());

    assert_eq!(copy_bounded_wide(std::ptr::null_mut()).unwrap(), None);
    let mut empty = [0_u16];
    assert_eq!(copy_bounded_wide(empty.as_mut_ptr()).unwrap(), None);
    let mut value = [
        b'1' as u16,
        b'.' as u16,
        b'1' as u16,
        b'.' as u16,
        b'1' as u16,
        0,
    ];
    assert_eq!(
        copy_bounded_wide(value.as_mut_ptr()).unwrap().as_deref(),
        Some(&value[..5])
    );
    let mut unterminated = vec![1_u16; 4097];
    assert!(copy_bounded_wide(unterminated.as_mut_ptr()).is_err());
}
