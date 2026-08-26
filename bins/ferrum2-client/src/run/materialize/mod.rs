mod endpoint;
mod outcome;
mod ruleset;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ferrum2_config::{
    ClientV2Resources, CompiledRuleSetResource, DirectDomainResolver, PreparedClientV2, ResolverRef,
};
use ferrum2_dns::{DnsCache, ResolverGeneration, materialize_fixed_endpoints};
use ferrum2_observability::{Metrics, RuleSetResult};
use ferrum2_ruleset::{RuleSetDownloader, materialize_rule_sets};

use super::RunError;
use endpoint::{
    BootstrapBlueprint, BootstrapEndpointBackend, fixed_endpoint_plan, materialization_cache,
};
use outcome::{
    MaterializedRuleSetPhase, classify_config_materialization_error, classify_fixed_endpoint_error,
    classify_rule_set_load_error,
};
use ruleset::{
    ActiveRuleSetTransport, PendingClientV2Runtime, PendingRuleSetTransport,
    ProductionRuleSetTransport, initial_rule_set_result, record_rule_set_snapshot_metrics,
    record_target_resolution_modes, rule_set_sources, runtime_loader_config, unix_timestamp_now,
};

pub(super) use outcome::{MaterializedClientV2 as Materialized, MaterializedRunParts};
pub(super) use ruleset::ClientV2RuntimeRoot;

const INITIAL_RULESET_GENERATION: u64 = 1;

const fn initial_resolver_generation(has_rule_sets: bool) -> ResolverGeneration {
    ResolverGeneration::new(if has_rule_sets {
        INITIAL_RULESET_GENERATION
    } else {
        0
    })
}
const UNRESOLVED_ENDPOINT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)), 9);

struct MaterializedClientResources {
    resources: ClientV2Resources,
    rule_sets: MaterializedRuleSetPhase,
    cache: Option<DnsCache>,
}

/// Production schema-v2 materializer. The context is single-use because a
/// successful materialization transfers its resolver and refresh ownership to
/// exactly one client process root.
pub(super) struct ClientV2Materializer {
    metrics: Arc<Metrics>,
    downloader: Option<Arc<dyn RuleSetDownloader>>,
    #[cfg(all(windows, not(test)))]
    network_socket_service: Arc<super::egress::ClientNetworkSocketService>,
}

impl ClientV2Materializer {
    pub(super) fn new(
        metrics: Arc<Metrics>,
        #[cfg(all(windows, not(test)))] network_socket_service: Arc<
            super::egress::ClientNetworkSocketService,
        >,
    ) -> Self {
        Self {
            metrics,
            downloader: None,
            #[cfg(all(windows, not(test)))]
            network_socket_service,
        }
    }

    #[cfg(test)]
    fn with_downloader(metrics: Arc<Metrics>, downloader: Arc<dyn RuleSetDownloader>) -> Self {
        Self {
            metrics,
            downloader: Some(downloader),
        }
    }

    async fn materialize_resources(
        self,
        prepared: &PreparedClientV2,
    ) -> Result<MaterializedClientResources, RunError> {
        record_target_resolution_modes(prepared, &self.metrics);

        let blueprint = Arc::new(BootstrapBlueprint::new(prepared)?);
        let (plan, targets) = fixed_endpoint_plan(prepared)?;
        let cache = materialization_cache(prepared, &self.metrics)?;
        let backend = BootstrapEndpointBackend::new(
            Arc::clone(&blueprint),
            targets,
            Arc::clone(&self.metrics),
            #[cfg(all(windows, not(test)))]
            Arc::clone(&self.network_socket_service),
        );
        materialize_fixed_endpoints(
            &plan,
            &backend,
            cache.as_ref(),
            initial_resolver_generation(!prepared.rule_sets().is_empty()),
        )
        .await
        .map_err(classify_fixed_endpoint_error)?;
        let (dns_endpoints, outbound_endpoints) = backend.finished_resources(prepared)?;

        let sources = rule_set_sources(prepared)?;
        if sources.is_empty() {
            return Ok(MaterializedClientResources {
                resources: ClientV2Resources::new(dns_endpoints, outbound_endpoints, None),
                rule_sets: MaterializedRuleSetPhase::Absent,
                cache,
            });
        }

        let loader_config = runtime_loader_config(prepared)?;
        let needs_tagged = prepared.rule_sets().iter().any(|rule_set| {
            matches!(
                rule_set.download_mode(),
                ferrum2_config::PreparedRuleSetDownloadMode::ClientResolved {
                    resolver: ResolverRef::DnsServer(_)
                }
            )
        }) || (0..prepared.outbound_count()).any(|index| {
            prepared
                .outbound(u32::try_from(index).expect("validated outbound count"))
                .and_then(|outbound| outbound.domain_resolver())
                .is_some_and(|resolver| matches!(resolver, DirectDomainResolver::DnsServer { .. }))
        });
        let addresses = backend.addresses();
        let pending_transport = match self.downloader.as_ref() {
            Some(downloader) => PendingRuleSetTransport::Injected {
                loader_config: loader_config.clone(),
                downloader: Arc::clone(downloader),
            },
            None => PendingRuleSetTransport::Production(ProductionRuleSetTransport {
                blueprint: Arc::clone(&blueprint),
                addresses: addresses.clone(),
                loader_config: loader_config.clone(),
                cache: cache.clone(),
                #[cfg(all(windows, not(test)))]
                network_socket_service: Arc::clone(&self.network_socket_service),
                needs_tagged,
                metrics: Arc::clone(&self.metrics),
            }),
        };
        // Initial materialization is deliberately isolated from the eventual
        // TUN route. It is completely joined before the prepared config is
        // exposed; the refresh transport is rebuilt only when the process root
        // is transferred to the supervisor.
        let initial_transport = match self.downloader.as_ref() {
            Some(downloader) => {
                ActiveRuleSetTransport::injected(loader_config, Arc::clone(downloader))
            }
            None => {
                ProductionRuleSetTransport {
                    blueprint: Arc::clone(&blueprint),
                    addresses,
                    loader_config,
                    cache: cache.clone(),
                    #[cfg(all(windows, not(test)))]
                    network_socket_service: Arc::clone(&self.network_socket_service),
                    needs_tagged,
                    metrics: Arc::clone(&self.metrics),
                }
                .activate(INITIAL_RULESET_GENERATION)
                .await?
            }
        };
        let initial = match materialize_rule_sets(
            initial_transport.loader.as_ref(),
            sources,
            INITIAL_RULESET_GENERATION,
        )
        .await
        {
            Ok(initial) => initial,
            Err(error) => {
                self.metrics.ruleset_load(RuleSetResult::Failure);
                initial_transport.shutdown().await?;
                return Err(classify_rule_set_load_error(error));
            }
        };
        for (&disposition, &degraded_failure) in initial
            .dispositions()
            .iter()
            .zip(initial.degraded_failures())
        {
            self.metrics
                .ruleset_load(initial_rule_set_result(disposition, degraded_failure));
        }
        self.metrics
            .set_ruleset_generation(INITIAL_RULESET_GENERATION);
        record_rule_set_snapshot_metrics(
            &self.metrics,
            &initial.registry().snapshot(),
            initial.rule_set_ids(),
        );
        self.metrics
            .set_ruleset_last_success_timestamp(unix_timestamp_now());
        let rule_sets = Some(CompiledRuleSetResource::from_shared(
            initial.shared_registry(),
            initial.shared_rule_set_ids(),
        ));
        initial_transport.shutdown().await?;
        let pending =
            PendingClientV2Runtime::new(pending_transport, initial, Arc::clone(&self.metrics));
        Ok(MaterializedClientResources {
            resources: ClientV2Resources::new(dns_endpoints, outbound_endpoints, rule_sets),
            rule_sets: MaterializedRuleSetPhase::Pending(Box::new(pending)),
            cache,
        })
    }

    pub(super) async fn materialize(
        self,
        prepared: PreparedClientV2,
    ) -> Result<Materialized, RunError> {
        let MaterializedClientResources {
            resources,
            rule_sets,
            cache,
        } = self.materialize_resources(&prepared).await?;
        let config = match ferrum2_config::finish_client_v2(prepared, resources) {
            Ok(config) => config,
            Err(error) => return Err(classify_config_materialization_error(error)),
        };
        Ok(Materialized::new(config, rule_sets, cache))
    }
}
