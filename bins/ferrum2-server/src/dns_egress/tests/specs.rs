use super::*;

#[test]
fn dns_runtime_specs_preserve_validated_server_values() {
    let cases = [
        (DnsTransport::Udp, 5300, None, None, false),
        (DnsTransport::Udp, 5301, None, None, true),
        (DnsTransport::Tcp, 5302, None, None, false),
        (DnsTransport::Tcp, 5303, None, None, true),
        (
            DnsTransport::Dot,
            8530,
            Some("dot-direct.test"),
            None,
            false,
        ),
        (DnsTransport::Dot, 8531, Some("dot-detour.test"), None, true),
        (
            DnsTransport::Doh,
            4430,
            Some("doh-direct.test"),
            Some("/dns-query/direct"),
            false,
        ),
        (
            DnsTransport::Doh,
            4431,
            Some("doh-detour.test"),
            Some("/dns-query/detour"),
            true,
        ),
    ];
    let servers: Vec<_> = cases
        .iter()
        .enumerate()
        .map(
            |(index, &(transport, port, server_name, path, detoured))| DnsServerConfig {
                transport,
                target: TargetAddr::ip(SocketAddr::from(([192, 0, 2, 53], port)))
                    .expect("non-zero DNS target"),
                resolved_targets: Box::new([]),
                endpoint_mode: DnsEndpointMode::Numeric,
                server_name: server_name.map(Into::into),
                path: path.map(Into::into),
                detour: detoured.then(|| EgressPlanHandle::direct(index)),
            },
        )
        .collect();
    let configured_plan_ptrs: Vec<_> = servers
        .iter()
        .map(|server| {
            server
                .detour
                .as_ref()
                .map(|detour| detour.snapshot_owned().hops().as_ptr())
        })
        .collect();

    for (index, ((spec, (transport, port, server_name, path, detoured)), configured_plan_ptr)) in
        dns_runtime_specs(&servers)
            .into_iter()
            .zip(cases)
            .zip(configured_plan_ptrs)
            .enumerate()
    {
        assert_eq!(
            spec.target,
            TargetAddr::ip(SocketAddr::from(([192, 0, 2, 53], port))).expect("non-zero DNS target")
        );
        match (detoured, spec.detour.as_ref()) {
            (true, Some(detour)) => {
                let converted = detour.snapshot_owned();
                assert_eq!(converted.hops(), &[index]);
                assert_eq!(Some(converted.hops().as_ptr()), configured_plan_ptr);
            }
            (false, None) => {}
            _ => panic!("DNS runtime detour mapping drift"),
        }
        match (transport, spec.transport) {
            (DnsTransport::Udp, DnsUpstreamTransport::Udp)
            | (DnsTransport::Tcp, DnsUpstreamTransport::Tcp) => {
                assert_eq!((server_name, path), (None, None));
            }
            (
                DnsTransport::Dot,
                DnsUpstreamTransport::Dot {
                    server_name: actual,
                },
            ) => {
                assert_eq!(actual.as_ref(), server_name.expect("DoT name"));
                assert!(path.is_none());
            }
            (
                DnsTransport::Doh,
                DnsUpstreamTransport::Doh {
                    server_name: actual_name,
                    path: actual_path,
                },
            ) => {
                assert_eq!(actual_name.as_ref(), server_name.expect("DoH name"));
                assert_eq!(actual_path.as_ref(), path.expect("DoH path"));
            }
            _ => panic!("DNS runtime transport mapping drift"),
        }
    }
}
