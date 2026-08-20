use ferrum2_core::TargetAddr;
use ferrum2_rule::{
    Network, SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedRoute, compile_selector_route,
};

#[test]
fn configured_final_snapshot_is_stable_while_live_selection_follows_selector_switches() {
    let (route, control) = compile_selector_route(
        &[TaggedInbound::new("entry", 0)],
        &[TaggedOutbound::new("a", 7), TaggedOutbound::new("b", 8)],
        &[SelectorDefinition::new("manual", vec!["a", "b"], Some("a"))],
        TaggedRoute::Routed {
            rules: Vec::new(),
            final_outbound: Some("manual"),
        },
    )
    .unwrap();
    let target = TargetAddr::domain("selector.test", 443).unwrap();
    let configured = route.final_plan_snapshot();
    assert_eq!(route.select(0, Network::Tcp, &target), 7);
    control.switch("manual", "b").unwrap();
    assert_eq!(route.select(0, Network::Tcp, &target), 8);
    assert_eq!(configured.hops(), &[7]);
    assert_eq!(route.final_plan().hops(), &[7]);
}
