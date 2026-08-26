use super::support::*;

#[test]
fn endpoint_and_ruleset_failures_are_field_specific_and_redacted() {
    let cases = [
        (
            CLIENT_V2.replacen("domain_resolver = \"local\"\n", "", 1),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "server = \"edge.example.test:8388\"",
                "server = \"192.0.2.80:8388\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                concat!(
                    "domain_resolver = \"system\"\n",
                    "domain_strategy = \"ipv6_only\"\n",
                    "server_name = \"dns.example.test\"\n",
                    "path = \"/dns-query\"\n",
                    "detour = \"main\"\n",
                ),
                concat!(
                    "server_name = \"dns.example.test\"\n",
                    "path = \"/dns-query\"\n",
                ),
            ),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::DnsServersDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "address = \"192.0.2.53:53\"",
                "address = \"192.0.2.53:53\"\ndomain_resolver = \"system\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::DnsServersDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "type = \"direct\"",
                "type = \"direct\"\ndomain_resolver = \"system\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainResolver,
        ),
        (
            CLIENT_V2.replace(
                "type = \"direct\"",
                "type = \"direct\"\ndomain_strategy = \"ipv4_only\"",
            ),
            ConfigErrorKind::Semantic,
            ConfigField::OutboundsDomainStrategy,
        ),
        (
            CLIENT_V2.replace(
                "download_resolver = \"local\"\ndownload_detour = \"main\"\n",
                "",
            ),
            ConfigErrorKind::DnsResolverRequired,
            ConfigField::RouteRuleSetDownloadResolver,
        ),
        (
            CLIENT_V2.replacen(
                "[[route.rule_set]]\ntag = \"ads\"\n",
                "[[route.rule_set]]\n",
                1,
            ),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRuleSetTag,
        ),
        (
            CLIENT_V2.replace("https://rules.example.test", "http://secret.invalid"),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRuleSetUrl,
        ),
        (
            CLIENT_V2.replace("rule_set = \"ads\"", "rule_set = \"missing-secret\""),
            ConfigErrorKind::Semantic,
            ConfigField::RouteRulesRuleSet,
        ),
    ];
    for (index, (source, expected_kind, expected_field)) in cases.into_iter().enumerate() {
        let file = TempConfig::new(&source);
        let error = prepare_client(&file.0).expect_err("invalid prepared config");
        assert_eq!(error.kind(), expected_kind, "case {index}");
        assert_eq!(error.field(), expected_field, "case {index}");
        let display = error.to_string();
        assert!(!display.contains("secret"), "case {index}");
        assert!(!display.contains("example.test"), "case {index}");
    }
}

#[test]
fn duplicate_ruleset_tags_fail_closed() {
    let duplicate = r#"
[[route.rule_set]]
tag = "ads"
type = "remote"
format = "binary"
url = "https://duplicate.invalid/secret.srs"
download_resolver = "local"
download_detour = "main"
"#;
    let source = CLIENT_V2.replacen(
        "[[route.rules]]",
        &format!("{duplicate}\n[[route.rules]]"),
        1,
    );
    let file = TempConfig::new(&source);
    let error = prepare_client(&file.0).expect_err("duplicate RuleSet tag");
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::RouteRuleSetTag);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("duplicate.invalid"));
    assert!(!rendered.contains("secret"));
}

#[test]
fn system_is_reserved_and_dependency_cycles_fail_before_materialization() {
    let reserved = CLIENT_V2.replace("tag = \"local\"", "tag = \"system\"");
    let file = TempConfig::new(&reserved);
    let error = prepare_client(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsReservedResolverName);
    assert_eq!(error.field(), ConfigField::DnsServersTag);

    let self_cycle = CLIENT_V2.replace(
        "domain_resolver = \"system\"",
        "domain_resolver = \"bootstrap\"",
    );
    let file = TempConfig::new(&self_cycle);
    let error = prepare_client(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);

    let selector_cycle = CLIENT_V2.replace(
        "address = \"192.0.2.53:53\"",
        "address = \"192.0.2.53:53\"\ndetour = \"main\"",
    );
    let file = TempConfig::new(&selector_cycle);
    let error = prepare_client(&file.0).unwrap_err();
    assert_eq!(error.kind(), ConfigErrorKind::DnsDependencyCycle);
    assert_eq!(error.field(), ConfigField::DnsDependencyCycle);
}

#[test]
fn schema_v1_is_rejected_before_removed_root_fields_are_parsed() {
    let source = r#"
schema_version = 1
[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"
[rule_set_loader]
cache_dir = "./cache"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#;
    let file = TempConfig::new(source);
    let error = match prepare_client(&file.0) {
        Ok(_) => panic!("schema V1 produced a configuration"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ConfigErrorKind::Semantic);
    assert_eq!(error.field(), ConfigField::SchemaVersion);
}

#[test]
fn schema_v2_rejects_removed_client_and_server_root_shapes() {
    let client = TempConfig::new(
        r#"
schema_version = 2
[client]
listen = "127.0.0.1:1080"
server = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
    );
    assert_config_syntax_error(prepare_client(&client.0));
    assert_config_syntax_error(prepare_client(&client.0));

    let server = TempConfig::new(
        r#"
schema_version = 2
[server]
listen = "127.0.0.1:8388"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
    );
    assert_config_syntax_error(prepare_server(&server.0));
    assert_config_syntax_error(prepare_server(&server.0));
}
