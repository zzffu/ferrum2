use std::path::PathBuf;
use std::sync::Arc;

use ferrum2_config::{
    ClientV2Resources, CompiledRuleSetResource, DnsIngressId, ResolvedOutboundEndpoint,
    RouteAction, finish_client_v2, prepare_client,
};
use ferrum2_core::TargetAddr;
use ferrum2_rule::srs::decode_srs;
use ferrum2_rule::{
    DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, Network, RouteMetadata, RouteProgramAction,
};

const ADS_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/ads.srs");
const AI_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/ai.srs");
const CN_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/cn.srs");
const CNIP_SRS: &[u8] = include_bytes!("../../../tests/fixtures/srs/cnip.srs");

fn resources() -> ClientV2Resources {
    let rule_sets = [ADS_SRS, AI_SRS, CN_SRS, CNIP_SRS]
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let compiled = decode_srs(bytes)
                .expect("decode pinned SRS")
                .compile()
                .expect("compile pinned SRS");
            CompiledRuleSetResource::new(index as u32, Arc::new(compiled), 41)
        })
        .collect();
    ClientV2Resources::new(
        vec![],
        vec![ResolvedOutboundEndpoint::new(
            2,
            "198.51.100.10:8388".parse().expect("outbound endpoint"),
        )],
        rule_sets,
    )
}

fn terminal_route_hops(
    route: &ferrum2_config::CompiledRoute,
    target: &TargetAddr,
) -> Option<Vec<usize>> {
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(0, Network::Tcp, target, &mut scratch);
    match evaluation.next(RouteMetadata::new(None, None)) {
        Some(RouteProgramAction::Terminal(RouteAction::Route(plan))) => {
            Some(plan.snapshot_owned().hops().to_vec())
        }
        _ => None,
    }
}

#[test]
fn four_pinned_srs_finish_into_one_v2_route_and_dns_blueprint_snapshot() {
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/client-v2-dns-rulesets.toml");
    let prepared = prepare_client(example).expect("prepare tracked V2 example");
    let config = finish_client_v2(prepared, resources()).expect("finish real SRS resources");

    let route = &config.route;
    let registry = route.rule_registry().expect("shared RuleSet registry");
    assert_eq!(registry.generation(), 41);

    let ads = TargetAddr::domain("x.0.myikas.com", 443).expect("ads target");
    let mut scratch = route.evaluation_scratch().expect("route scratch");
    let mut evaluation = route.evaluate_with_scratch(0, Network::Tcp, &ads, &mut scratch);
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Terminal(RouteAction::Reject))
    ));

    let ai = TargetAddr::domain("api.openai.example", 443).expect("AI target");
    assert_eq!(
        terminal_route_hops(route, &ai).as_deref(),
        Some([2].as_slice())
    );

    let cn = TargetAddr::domain("x.0.zone", 443).expect("CN target");
    assert_eq!(
        terminal_route_hops(route, &cn).as_deref(),
        Some([0].as_slice())
    );

    let cnip = TargetAddr::ip("1.1.8.8:443".parse().expect("CN IP target"))
        .expect("validated CN IP target");
    assert_eq!(
        terminal_route_hops(route, &cnip).as_deref(),
        Some([0].as_slice())
    );

    let binding = config
        .dns_route
        .as_ref()
        .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
        .expect("DNS policy blueprint");
    let dns_registry = binding.registry();
    assert!(Arc::ptr_eq(&registry, &dns_registry));
    assert_eq!(binding.resolve_ingress(DnsIngressId::Listener(0)), Some(0));
    let blueprint = binding.blueprint();
    assert_eq!(blueprint.len(), 5);
    assert_eq!(blueprint.response_rule_count(), 1);
    assert_eq!(
        blueprint.rules()[0].action(),
        DnsPolicyActionDescriptor::Reject
    );
    for (index, server) in [(2, 1), (3, 0), (4, 0)] {
        assert_eq!(
            blueprint.rules()[index].action(),
            DnsPolicyActionDescriptor::Route(ferrum2_rule::DnsPolicyRouteDescriptor::new(
                server,
                DnsPolicyAddressStrategy::Ipv4Only,
            ))
        );
    }
    assert_eq!(blueprint.rules()[4].matcher().rule_sets()[0].raw(), 3);
    assert!(
        dns_registry
            .snapshot()
            .rule_set(ferrum2_rule::RuleSetId::from_raw(3))
            .expect("CNIP descriptor")
            .capabilities()
            .ip_cidr
    );
}
