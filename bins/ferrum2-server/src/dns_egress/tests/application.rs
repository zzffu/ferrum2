use super::*;

#[tokio::test]
async fn direct_application_observer_separates_system_and_missing_tagged_resolver_without_fallback()
{
    for (mode, expected) in [
        (DirectDomainResolver::System, "system"),
        (
            DirectDomainResolver::DnsServer {
                server: 0,
                strategy: ferrum2_config::DnsStrategy::Ipv4Only,
            },
            "configured",
        ),
    ] {
        let metrics = Arc::new(Metrics::new());
        let resolver = ServerDnsResolver::for_direct_inner(
            Arc::new(crate::run::test_support::TestApplicationBackend),
            mode,
            Arc::new(OnceLock::new()),
            Some(Arc::clone(&metrics)),
        );
        let result = TcpResolver::resolve(&resolver, "localhost", 443).await;
        assert_eq!(result.is_ok(), expected == "system");
        let encoded = metrics.encode_text().unwrap();
        let outcome = if result.is_ok() { "success" } else { "failure" };
        assert!(encoded.contains(&format!("ferrum2_dns_resolve_total{{resolver=\"{expected}\",purpose=\"application\",result=\"{outcome}\"}} 1")));
        assert_eq!(
            encoded
                .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1"),
            expected == "system"
        );
        assert!(encoded.contains("ferrum2_dns_implicit_system_fallback_total 0"));
    }
}
