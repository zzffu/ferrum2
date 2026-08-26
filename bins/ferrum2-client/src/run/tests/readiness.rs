use super::*;

#[tokio::test]
async fn application_resolver_observer_records_explicit_system_without_fallback() {
    struct OutcomeBackend(Result<Vec<std::net::SocketAddr>, ferrum2_dns::DnsError>);

    impl ferrum2_dns::ApplicationResolveBackend for OutcomeBackend {
        fn resolve<'a>(
            &'a self,
            _request: ferrum2_dns::ApplicationResolveRequest<'a>,
        ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
            let outcome = self.0.clone();
            Box::pin(async move { outcome })
        }
    }

    let metrics = Arc::new(Metrics::new());
    let system = observed_application_resolver(
        ferrum2_dns::ApplicationResolver::system(Arc::new(OutcomeBackend(Ok(vec![
            "192.0.2.10:443".parse().expect("test address"),
        ])))),
        &metrics,
    );
    let configured = observed_application_resolver(
        ferrum2_dns::ApplicationResolver::configured(Arc::new(OutcomeBackend(Err(
            ferrum2_dns::DnsError::NoData,
        )))),
        &metrics,
    );
    let domain = ferrum2_core::CanonicalDomain::new("application.example")
        .expect("canonical application domain");
    let request = ferrum2_dns::ApplicationResolveRequest::new(
        ferrum2_dns::ApplicationResolveContext::new(0, ferrum2_core::route::Network::Tcp),
        &domain,
        std::num::NonZeroU16::new(443).expect("non-zero port"),
        ferrum2_dns::DnsStrategy::Ipv4Only,
    );

    assert!(system.resolve(request).await.is_ok());
    assert_eq!(
        configured.resolve(request).await,
        Err(ferrum2_dns::DnsError::NoData)
    );
    let encoded = metrics
        .encode_text()
        .expect("encode application DNS metrics");
    for expected in [
        "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"application\",result=\"success\"} 1",
        "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"failure\"} 1",
        "ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1",
        "ferrum2_dns_implicit_system_fallback_total 0",
    ] {
        assert!(
            encoded.contains(expected),
            "missing `{expected}`\n{encoded}"
        );
    }
}
