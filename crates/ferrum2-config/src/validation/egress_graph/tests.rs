use super::*;
use crate::prepared::ClientPreparationDraft;

fn client(extra: &str) -> RawClientRoot {
    crate::load::parse_v2_toml(&format!(
        r#"
schema_version = 2
[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "entry"
type = "shadowsocks"
[[outbounds]]
tag = "exit"
type = "shadowsocks"
{extra}
"#
    ))
    .expect("small graph fixture")
}

#[test]
fn shared_successors_produce_unique_physical_first_hops_and_domain_capability() {
    let raw = client(
        r#"
[[chains]]
tag = "pair"
hops = ["entry", "exit"]
[[selectors]]
tag = "root"
outbounds = ["left", "right"]
default = "left"
[[selectors]]
tag = "left"
outbounds = ["shared", "pair"]
default = "shared"
[[selectors]]
tag = "right"
outbounds = ["pair", "shared"]
default = "pair"
[[selectors]]
tag = "shared"
outbounds = ["direct", "pair"]
default = "direct"
"#,
    );
    let graph = AdmittedEgressGraph::client(&raw).expect("shared DAG");
    assert_eq!(graph.chain_hops(), &[vec![1, 2]]);
    assert_eq!(
        graph.selector_members(),
        &[
            vec![
                PreparedEgressRef::Selector(1),
                PreparedEgressRef::Selector(2)
            ],
            vec![PreparedEgressRef::Selector(3), PreparedEgressRef::Chain(0)],
            vec![PreparedEgressRef::Chain(0), PreparedEgressRef::Selector(3)],
            vec![PreparedEgressRef::Outbound(0), PreparedEgressRef::Chain(0)],
        ]
    );
    for tag in ["root", "left", "right", "shared"] {
        let node = graph.resolve(tag, ConfigField::SelectorsTag).expect("tag");
        assert_eq!(
            (graph.first_hops(node), graph.accepts_domain(node)),
            (0b011, true)
        );
    }
    assert_eq!(graph.first_hops(PreparedEgressRef::Chain(0)), 0b010);
}

#[test]
fn selector_cycle_retains_only_closed_node_indices() {
    let raw = client(
        r#"
[[selectors]]
tag = "first"
outbounds = ["second"]
default = "second"
[[selectors]]
tag = "second"
outbounds = ["first"]
default = "first"
"#,
    );
    let error = AdmittedEgressGraph::client(&raw).err().expect("cycle");
    assert_eq!(
        error.to_string(),
        "error[config.dependency_cycle] config.dependency_cycle: the configuration dependency graph contains a cycle: selector[0] -> selector[1] -> selector[0]"
    );
}

#[test]
fn all_sixty_four_outbound_bits_are_available_without_path_expansion() {
    let mut raw = client("");
    let outbounds = raw.outbounds.as_mut().expect("outbounds");
    outbounds.pop();
    for index in 2..64 {
        let outbound: crate::raw::RawClientOutbound =
            crate::load::parse_toml(&format!("tag = \"out-{index}\"\ntype = \"direct\""))
                .expect("bounded outbound");
        outbounds.push(outbound);
    }
    let graph = AdmittedEgressGraph::client(&raw).expect("64 outbounds");
    assert_eq!(
        graph.first_hops(PreparedEgressRef::Outbound(63)),
        1_u64 << 63
    );
}

#[test]
fn member_limit_is_checked_before_endpoint_preparation() {
    let mut raw = client("");
    raw.outbounds.as_mut().expect("outbounds")[1].server = Some("invalid endpoint".to_owned());
    raw.selectors = Some(vec![RawSelector {
        tag: "choice".to_owned(),
        outbounds: (0..65).map(|index| format!("member-{index}")).collect(),
        default: Some("member-0".to_owned()),
    }]);
    let error = ClientPreparationDraft::new(raw)
        .err()
        .expect("early admission");
    assert_eq!(error.field(), ConfigField::SelectorsOutbounds);
}

#[test]
fn selector_cohort_and_chain_hop_bounds_precede_endpoint_preparation() {
    let mut selectors = client("");
    selectors.outbounds.as_mut().expect("outbounds")[1].server =
        Some("invalid endpoint".to_owned());
    selectors.selectors = Some(
        (0..65)
            .map(|index| RawSelector {
                tag: format!("choice-{index}"),
                outbounds: vec!["direct".to_owned()],
                default: Some("direct".to_owned()),
            })
            .collect(),
    );
    let error = ClientPreparationDraft::new(selectors)
        .err()
        .expect("selector cohort admission");
    assert_eq!(error.field(), ConfigField::Selectors);

    let mut chain = client("[[chains]]\ntag = \"pair\"\nhops = [\"entry\"]");
    chain.outbounds.as_mut().expect("outbounds")[1].server = Some("invalid endpoint".to_owned());
    let error = ClientPreparationDraft::new(chain)
        .err()
        .expect("chain hop admission");
    assert_eq!(error.field(), ConfigField::ChainsHops);
}

#[test]
fn chain_hops_must_be_concrete_and_non_direct_before_derivation() {
    for hops in ["[\"entry\", \"direct\"]", "[\"entry\", \"choice\"]"] {
        let raw = client(&format!(
            "[[chains]]\ntag = \"pair\"\nhops = {hops}\n[[selectors]]\ntag = \"choice\"\noutbounds = [\"pair\"]\ndefault = \"pair\""
        ));
        let error = AdmittedEgressGraph::client(&raw)
            .err()
            .expect("invalid chain");
        assert_eq!(error.field(), ConfigField::ChainsHops);
    }
}
