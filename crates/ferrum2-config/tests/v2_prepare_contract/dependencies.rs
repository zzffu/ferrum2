use super::support::*;

#[test]
fn ruleset_tags_reject_cache_path_components() {
    for tag in [".", ".."] {
        let source = CLIENT_V2.replacen("tag = \"ads\"", &format!("tag = \"{tag}\""), 1);
        let file = TempConfig::new(&source);
        assert_eq!(
            prepare_client(&file.0).unwrap_err().field(),
            ConfigField::RouteRuleSetTag
        );
    }
}

#[test]
fn dependency_only_ruleset_detours_and_resolvers_are_reachability_roots() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "fallback"
type = "direct"

[[outbounds]]
tag = "download-hop"
type = "shadowsocks"
server = "edge.example.test:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
domain_resolver = "bootstrap"

[[outbounds]]
tag = "download-exit"
type = "shadowsocks"
server = "192.0.2.99:8388"
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[[chains]]
tag = "download-chain"
hops = ["download-hop", "download-exit"]

[route]
final = "fallback"

[[route.rule_set]]
tag = "download-only"
type = "remote"
url = "https://rules.example.test/download-only.srs"
download_resolver = "bootstrap"
download_detour = "download-chain"

[dns]

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "final-dns"
transport = "udp"
address = "192.0.2.1:53"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "192.0.2.2:53"

[dns.route]
final = "final-dns"

"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client(&file.0).expect("dependency-only roots prepare");
    assert_eq!(
        prepared.accepts_domain_target(PreparedEgressRef::Chain(0)),
        Some(true)
    );
    assert_eq!(
        prepared
            .download_detour_plan(0)
            .expect("dependency-only RuleSet detour")
            .snapshot()
            .hops(),
        &[1, 2]
    );
    assert_eq!(prepared.download_detour_is_direct(0), Some(false));
    let config = finish_client_v2(
        prepared,
        ClientV2Resources::new(
            vec![],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.20:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                1,
                &[("download-only", exact_match_set("download-only.example"))],
            )),
        ),
    )
    .expect("dependency-only roots finish");
    assert_eq!(
        config.outbounds[1].server(),
        Some("198.51.100.20:8388".parse().unwrap())
    );

    let cycle_source = source.replace(
        "address = \"192.0.2.2:53\"",
        concat!(
            "address = \"bootstrap.example.test:53\"\n",
            "domain_resolver = \"system\"\n",
            "detour = \"download-chain\"",
        ),
    );
    let file = TempConfig::new(&cycle_source);
    let error = prepare_client(&file.0).expect_err("dependency cycle reached preparation");
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);
}

#[test]
fn minimal_v2_finishes_without_a_registry_or_resources() {
    let source = r#"
schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#;
    let file = TempConfig::new(source);
    let prepared = prepare_client(&file.0).expect("prepare old V2");
    let config = finish_client_v2(prepared, ClientV2Resources::default()).expect("finish old V2");
    assert!(config.route.rule_registry().is_none());
    let target = TargetAddr::domain("ordinary.example", 443).unwrap();
    let mut scratch = config.route.evaluation_scratch().expect("route scratch");
    let mut evaluation = config
        .route
        .evaluate_with_scratch(0, Network::Tcp, &target, &mut scratch);
    assert!(matches!(
        evaluation.next(RouteMetadata::new(None, None)),
        Some(RouteProgramAction::Final(RouteAction::Route(_)))
    ));
}
