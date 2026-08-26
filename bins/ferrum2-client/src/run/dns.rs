use std::sync::Arc;

use ferrum2_config::{ClientOutboundConfig, DirectDomainResolver};
use ferrum2_dns::{
    ApplicationResolveOutcome, ApplicationResolver, ApplicationResolverAdapter,
    ApplicationResolverMode, DnsCache, DnsPolicyCompileError, DnsPolicyObserver, DnsPolicyProgram,
    DnsProxy, DnsProxyListeners, DnsStrategy, TaggedResolver, TaggedResolverOwner,
    TaggedServerApplicationResolveBackend,
};
use ferrum2_observability::Metrics;
use ferrum2_rule::RuleEngineRegistry;
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};

use super::RunError;
use super::dns_strategy;
use super::observation::dns_policy_observer;

pub(super) struct ClientDnsRoot {
    pub(super) listeners: Option<DnsProxyListeners>,
    pub(super) resolver: Option<Arc<TaggedResolver>>,
    pub(super) owner: Option<TaggedResolverOwner>,
    #[cfg(test)]
    pub(super) readiness_gate: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl ClientDnsRoot {
    async fn close_resolver(&mut self) -> Result<(), RunError> {
        self.listeners.take();
        self.resolver.take();
        self.owner
            .as_mut()
            .expect("prepared DNS owner")
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| RunError::ShutdownCleanup)
    }
}

impl PreparedProcessRoot<RunError> for ClientDnsRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            #[cfg(test)]
            if let Some(readiness_gate) = self.readiness_gate.take() {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        self.close_resolver().await?;
                        return Ok(());
                    }
                    _ = readiness_gate => {}
                }
            }
            let ready = {
                let owner = self.owner.as_mut().expect("prepared DNS owner");
                tokio::select! {
                    _ = cancellation.cancelled() => None,
                    result = owner.ready() => Some(result),
                }
            };
            match ready {
                None => {
                    self.close_resolver().await?;
                    return Ok(());
                }
                Some(Err(_)) => {
                    self.close_resolver().await?;
                    return Err(RunError::StartupProtocol);
                }
                Some(Ok(())) => {}
            }
            let listeners = self.listeners.take().expect("prepared DNS listeners");
            let result = listeners.run(cancellation.cancelled()).await;
            self.close_resolver().await?;
            result.map_err(|_| RunError::RuntimeListener)
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.close_resolver().await })
    }
}

pub(super) fn run_error_for_dns_policy_compile(error: DnsPolicyCompileError) -> RunError {
    match error {
        DnsPolicyCompileError::Allocation | DnsPolicyCompileError::IndexOverflow => {
            RunError::RuleAllocation
        }
        DnsPolicyCompileError::EmptyRule
        | DnsPolicyCompileError::InvalidQueryMatchSet
        | DnsPolicyCompileError::DuplicateConstraint
        | DnsPolicyCompileError::InvalidPortRange
        | DnsPolicyCompileError::UnknownRuleSet
        | DnsPolicyCompileError::ResponseDependentReject
        | DnsPolicyCompileError::Internal => RunError::RuleCompile,
    }
}

pub(super) fn client_direct_resolvers(
    outbounds: &[ClientOutboundConfig],
    tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
    metrics: &Arc<Metrics>,
) -> Arc<[Option<ApplicationResolverAdapter>]> {
    let system = Arc::new(observed_application_resolver(
        ApplicationResolver::system_default(),
        metrics,
    ));
    outbounds
        .iter()
        .map(|outbound| {
            let mode = outbound.direct_domain_resolver()?;
            let (resolver, strategy) = match mode {
                DirectDomainResolver::System => (Arc::clone(&system), DnsStrategy::PreferIpv4),
                DirectDomainResolver::DnsServer { server, strategy } => {
                    let resolver = ApplicationResolver::configured(Arc::new(
                        TaggedServerApplicationResolveBackend::new(Arc::clone(&tagged), server),
                    ));
                    (
                        Arc::new(observed_application_resolver(resolver, metrics)),
                        dns_strategy(strategy),
                    )
                }
            };
            Some(ApplicationResolverAdapter::new(resolver, 0, strategy))
        })
        .collect::<Vec<_>>()
        .into()
}

pub(super) fn observed_application_resolver(
    resolver: ApplicationResolver,
    metrics: &Arc<Metrics>,
) -> ApplicationResolver {
    let metrics = Arc::clone(metrics);
    resolver.with_observer(Arc::new(move |mode, outcome| {
        let resolver = match mode {
            ApplicationResolverMode::System => {
                metrics.dns_explicit_system_resolve(
                    ferrum2_observability::DnsResolvePurpose::Application,
                );
                ferrum2_observability::DnsResolverKind::System
            }
            ApplicationResolverMode::Configured => {
                ferrum2_observability::DnsResolverKind::Configured
            }
        };
        let result = match outcome {
            ApplicationResolveOutcome::Success => ferrum2_observability::DnsResolveResult::Success,
            ApplicationResolveOutcome::Failure => ferrum2_observability::DnsResolveResult::Failure,
        };
        metrics.dns_resolve(
            resolver,
            ferrum2_observability::DnsResolvePurpose::Application,
            result,
        );
    }))
}

struct ClientDnsProxyPolicy {
    program: Arc<DnsPolicyProgram>,
    registry: Arc<RuleEngineRegistry>,
    listener_count: usize,
    ordinary_count: usize,
}

pub(super) struct ClientDnsProxyRuntime {
    policy: ClientDnsProxyPolicy,
    observer: Arc<dyn DnsPolicyObserver>,
    cache: Option<DnsCache>,
}

impl ClientDnsProxyRuntime {
    pub(super) fn try_new(
        route: &mut ferrum2_config::ClientDnsRoute,
        runtime: ferrum2_config::DnsRuntimeConfig,
        materialized_cache: Option<DnsCache>,
        metrics: &Arc<Metrics>,
    ) -> Result<Self, RunError> {
        let binding = route
            .take_policy_blueprint()
            .ok_or(RunError::StartupProtocol)?;
        let (blueprint, registry, listener_count, ordinary_count) = binding.into_parts();
        let snapshot = registry.snapshot();
        let program = DnsPolicyProgram::try_from_blueprint(blueprint, &snapshot)
            .map_err(run_error_for_dns_policy_compile)?;
        let policy = ClientDnsProxyPolicy {
            program: Arc::new(program),
            registry,
            listener_count,
            ordinary_count,
        };
        let cache_config = runtime.cache();
        let cache = if cache_config.enabled {
            match materialized_cache {
                Some(cache) => Some(cache),
                None => Some(
                    DnsCache::try_new(
                        std::num::NonZeroUsize::new(cache_config.max_entries)
                            .ok_or(RunError::StartupProtocol)?,
                    )
                    .map_err(|_| RunError::StartupProtocol)?,
                ),
            }
        } else {
            None
        };
        Ok(Self {
            policy,
            observer: dns_policy_observer(metrics),
            cache,
        })
    }

    pub(super) fn bind(self, resolver: Arc<TaggedResolver>) -> DnsProxy {
        let policy = self.policy;
        let mut proxy = DnsProxy::new(
            resolver,
            policy.program,
            policy.registry,
            policy.listener_count,
            policy.ordinary_count,
        )
        .with_policy_observer(self.observer);
        if let Some(cache) = self.cache {
            proxy = proxy.with_cache(cache);
        }
        proxy
    }

    #[cfg(test)]
    pub(in crate::run) fn contract_snapshot(&self) -> (u64, usize, usize, Option<usize>) {
        (
            self.policy.registry.generation(),
            self.policy.listener_count,
            self.policy.ordinary_count,
            self.cache.as_ref().and_then(|cache| cache.capacity().ok()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::report_result;
    use crate::run::test_support::*;

    #[tokio::test]
    async fn dns_proxy_prepare_cancellation_awaits_owner_and_rebinds() {
        let dns = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("readiness upstream");
        let upstream_address = upstream.local_addr().expect("readiness upstream address");
        let sockets = DnsProxySockets::bind(
            vec![SocketAddr::V4(dns)],
            16,
            std::num::NonZeroU16::new(1).expect("one DNS connection"),
            Duration::from_secs(1),
        )
        .await
        .expect("prepared paired DNS sockets");
        let (resolver, owner) = TaggedResolver::new(
            vec![ferrum2_dns::DnsUpstreamSpec {
                transport: ferrum2_dns::DnsUpstreamTransport::Udp,
                target: ferrum2_core::TargetAddr::ip(upstream_address).expect("numeric upstream"),
                resolved_targets: Box::new([]),
                detour: None,
            }],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(1).expect("one DNS query"),
            Arc::new(ferrum2_dns::SystemDnsEgress),
        )
        .expect("resolver owner handoff");
        let resolver = Arc::new(resolver);
        let snapshot = ferrum2_rule::RuleEngineSnapshotBuilder::new(1)
            .build()
            .expect("empty DNS rule snapshot");
        let policy = Arc::new(
            ferrum2_dns::DnsPolicyProgram::try_new(
                Vec::new(),
                ferrum2_dns::DnsPolicyRoute::new(
                    ferrum2_dns::DnsServerId::new(0),
                    ferrum2_dns::DnsStrategy::PreferIpv4,
                ),
                &snapshot,
            )
            .expect("final-only DNS policy"),
        );
        let proxy = Arc::new(ferrum2_dns::DnsProxy::new(
            Arc::clone(&resolver),
            policy,
            Arc::new(ferrum2_rule::RuleEngineRegistry::new(snapshot)),
            1,
            0,
        ));
        let (readiness_sender, readiness_gate) = tokio::sync::oneshot::channel();
        let root = ProcessRoot::new(move || async move {
            Ok(ClientDnsRoot {
                listeners: Some(sockets.with_proxy(proxy)),
                resolver: Some(resolver),
                owner: Some(owner),
                readiness_gate: Some(readiness_gate),
            })
        });
        let registry = OwnerRegistry::new();
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), registry.clone())
                .expect("readiness supervisor");
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            report_result(
                supervisor
                    .run_until(async move {
                        let _ = stopped.await;
                    })
                    .await,
            )
        });
        for _ in 0..100 {
            if registry.snapshot().active_process_roots == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.snapshot().active_process_roots, 1);
        stop.send(()).expect("cancel during readiness");
        assert_eq!(task.await.expect("readiness client join"), Ok(()));
        drop(readiness_sender);
        drop(upstream);
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
        drop(
            UdpSocket::bind(dns)
                .await
                .expect("readiness DNS UDP rebind"),
        );
        drop(
            TcpListener::bind(dns)
                .await
                .expect("readiness DNS TCP rebind"),
        );
        drop(
            UdpSocket::bind(upstream_address)
                .await
                .expect("readiness upstream rebind"),
        );

        let first_address = SocketAddr::V4(reserve_address());
        let occupied_address = SocketAddr::V4(reserve_address());
        let occupied = TcpListener::bind(occupied_address)
            .await
            .expect("rollback occupied TCP");
        assert!(
            DnsProxySockets::bind(
                vec![first_address, occupied_address],
                8,
                std::num::NonZeroU16::new(1).expect("rollback connection"),
                Duration::from_secs(1),
            )
            .await
            .is_err(),
            "paired DNS preparation unexpectedly succeeded"
        );
        drop(
            UdpSocket::bind(first_address)
                .await
                .expect("rollback first UDP rebind"),
        );
        drop(
            TcpListener::bind(first_address)
                .await
                .expect("rollback first TCP rebind"),
        );
        drop(
            UdpSocket::bind(occupied_address)
                .await
                .expect("rollback occupied UDP rebind"),
        );
        drop(occupied);
    }
}
