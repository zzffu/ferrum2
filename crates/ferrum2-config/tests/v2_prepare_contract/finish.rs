use super::support::*;

#[test]
fn finish_rejects_missing_extra_mistyped_and_misidentified_resources_redacted() {
    let file = TempConfig::new(CLIENT_V2);
    let invalid = [
        ClientV2Resources::default(),
        ClientV2Resources::new(
            vec![
                ResolvedDnsEndpoint::from_candidates(
                    1,
                    Box::new(["[2001:db8::53]:443".parse().unwrap()]),
                ),
                ResolvedDnsEndpoint::from_candidates(
                    0,
                    Box::new(["192.0.2.53:53".parse().unwrap()]),
                ),
            ],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                7,
                &[("ads", exact_match_set("blocked.example"))],
            )),
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(
                1,
                Box::new(["[2001:db8::53]:443".parse().unwrap()]),
            )],
            vec![ResolvedOutboundEndpoint::new(
                0,
                "198.51.100.10:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                7,
                &[("ads", exact_match_set("blocked.example"))],
            )),
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(
                1,
                Box::new(["[2001:db8::53]:443".parse().unwrap()]),
            )],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "198.51.100.10:9999".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                7,
                &[("ads", exact_match_set("blocked.example"))],
            )),
        ),
        ClientV2Resources::new(
            vec![ResolvedDnsEndpoint::from_candidates(
                1,
                Box::new(["[2001:db8::53]:443".parse().unwrap()]),
            )],
            vec![ResolvedOutboundEndpoint::new(
                1,
                "[2001:db8::10]:8388".parse().unwrap(),
            )],
            Some(compiled_rule_sets(
                7,
                &[("misidentified", exact_match_set("blocked.example"))],
            )),
        ),
    ];
    for (index, resources) in invalid.into_iter().enumerate() {
        let prepared = prepare_client(&file.0).expect("prepare invalid resource case");
        let error = finish_client_v2(prepared, resources)
            .err()
            .expect("resource mismatch must fail");
        assert_eq!(error.field(), ConfigField::ResourceMaterialization);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("example"), "case {index}");
        assert!(!rendered.contains("198.51"), "case {index}");
        assert!(!rendered.contains("2001:db8"), "case {index}");
    }
}

#[test]
fn finish_rejects_ruleset_registry_declaration_order_mismatch() {
    let second = r#"
[[route.rule_set]]
tag = "second"
type = "remote"
format = "binary"
url = "https://rules.example.test/second.srs"
download_resolver = "local"
download_detour = "main"
"#;
    let source = CLIENT_V2.replacen("[[route.rules]]", &format!("{second}\n[[route.rules]]"), 1);
    let file = TempConfig::new(&source);
    let prepared = prepare_client(&file.0).expect("prepare two RuleSets");
    assert!(std::ptr::eq(
        prepared.download_detour_plan(0).unwrap(),
        prepared.download_detour_plan(1).unwrap()
    ));
    assert_eq!(prepared.download_detour_is_direct(0), Some(true));
    assert_eq!(prepared.download_detour_is_direct(1), Some(true));
    let resources = ClientV2Resources::new(
        vec![ResolvedDnsEndpoint::from_candidates(
            1,
            Box::new(["[2001:db8::53]:443".parse().unwrap()]),
        )],
        vec![ResolvedOutboundEndpoint::new(
            1,
            "198.51.100.10:8388".parse().unwrap(),
        )],
        Some(compiled_rule_sets(
            7,
            &[
                ("second", exact_match_set("second.example")),
                ("ads", exact_match_set("first.example")),
            ],
        )),
    );
    assert_eq!(
        finish_client_v2(prepared, resources)
            .err()
            .expect("declaration-order mismatch")
            .field(),
        ConfigField::ResourceMaterialization
    );
}
