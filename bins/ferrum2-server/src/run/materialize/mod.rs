mod endpoint;
mod outcome;
mod ruleset;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ferrum2_config::{CompiledRuleSetResource, PreparedServerV2, ResolverRef, ServerV2Resources};
use ferrum2_dns::{DnsCache, ResolverGeneration, materialize_fixed_endpoints};
use ferrum2_observability::{Metrics, RuleSetResult};
use ferrum2_ruleset::{RuleSetDownloader, materialize_rule_sets};

use crate::run::RunError;
use crate::run::tcp::ServerNetworkSocketService;

use endpoint::{
    BootstrapBlueprint, BootstrapEndpointBackend, fixed_endpoint_plan, materialization_cache,
};
use outcome::{
    MaterializedRuleSetPhase, MaterializedServerV2, classify_config_materialization_error,
    classify_fixed_endpoint_error, classify_rule_set_load_error,
};
use ruleset::{
    ActiveRuleSetTransport, PendingRuleSetTransport, PendingServerV2Runtime,
    ProductionRuleSetTransport, initial_rule_set_result, record_rule_set_snapshot_metrics,
    record_target_resolution_modes, rule_set_sources, runtime_loader_config, unix_timestamp_now,
};

pub(super) use outcome::MaterializedRunParts;
pub(super) use ruleset::ServerV2RuntimeRoot;

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

struct MaterializedServerResources {
    resources: ServerV2Resources,
    rule_sets: MaterializedRuleSetPhase,
    cache: Option<DnsCache>,
}

/// Single-use schema-v2 materialization context. Initial resolver owners are
/// joined before the finished config becomes visible. Only a pure refresh
/// construction plan is retained until it is transferred to the supervisor.
pub(super) struct ServerV2Materializer {
    metrics: Arc<Metrics>,
    network_sockets: Arc<ServerNetworkSocketService>,
    downloader: Option<Arc<dyn RuleSetDownloader>>,
}

impl ServerV2Materializer {
    #[cfg(test)]
    pub(super) fn new(metrics: Arc<Metrics>) -> Self {
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let network_sockets =
            super::tcp::prepare_server_network_socket_service(&registry, &metrics)
                .expect("test materialization network socket service");
        Self::with_network_sockets(metrics, network_sockets)
    }

    pub(super) fn with_network_sockets(
        metrics: Arc<Metrics>,
        network_sockets: Arc<ServerNetworkSocketService>,
    ) -> Self {
        Self {
            metrics,
            network_sockets,
            downloader: None,
        }
    }

    #[cfg(test)]
    fn with_downloader(metrics: Arc<Metrics>, downloader: Arc<dyn RuleSetDownloader>) -> Self {
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let network_sockets =
            super::tcp::prepare_server_network_socket_service(&registry, &metrics)
                .expect("test materialization network socket service");
        Self {
            metrics,
            network_sockets,
            downloader: Some(downloader),
        }
    }

    async fn materialize_resources(
        self,
        prepared: &PreparedServerV2,
    ) -> Result<MaterializedServerResources, RunError> {
        record_target_resolution_modes(prepared, &self.metrics);

        let blueprint = Arc::new(BootstrapBlueprint::new(
            prepared,
            Arc::clone(&self.metrics),
            Arc::clone(&self.network_sockets),
        )?);
        let (plan, targets) = fixed_endpoint_plan(prepared)?;
        let cache = materialization_cache(prepared, &self.metrics)?;
        let backend = BootstrapEndpointBackend::new(
            Arc::clone(&blueprint),
            targets,
            Arc::clone(&self.metrics),
        );
        materialize_fixed_endpoints(
            &plan,
            &backend,
            cache.as_ref(),
            initial_resolver_generation(!prepared.rule_sets().is_empty()),
        )
        .await
        .map_err(classify_fixed_endpoint_error)?;
        let dns_endpoints = backend.finished_resources(prepared)?;

        let sources = rule_set_sources(prepared)?;
        if sources.is_empty() {
            return Ok(MaterializedServerResources {
                resources: ServerV2Resources::new(dns_endpoints, None),
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
        }) || blueprint.has_configured_direct_resolver();
        let addresses = backend.addresses();
        let pending_transport = match self.downloader.as_ref() {
            Some(downloader) => PendingRuleSetTransport::Injected {
                loader_config: loader_config.clone(),
                downloader: Arc::clone(downloader),
            },
            None => PendingRuleSetTransport::Production(ProductionRuleSetTransport::new(
                Arc::clone(&blueprint),
                addresses.clone(),
                loader_config.clone(),
                cache.clone(),
                needs_tagged,
            )),
        };
        let initial_transport = match self.downloader.as_ref() {
            Some(downloader) => {
                ActiveRuleSetTransport::injected(loader_config, Arc::clone(downloader))
            }
            None => {
                ProductionRuleSetTransport::new(
                    blueprint,
                    addresses,
                    loader_config,
                    cache.clone(),
                    needs_tagged,
                )
                .activate(INITIAL_RULESET_GENERATION)
                .await?
            }
        };
        let initial = match materialize_rule_sets(
            initial_transport.loader(),
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
            PendingServerV2Runtime::new(pending_transport, initial, Arc::clone(&self.metrics));
        Ok(MaterializedServerResources {
            resources: ServerV2Resources::new(dns_endpoints, rule_sets),
            rule_sets: MaterializedRuleSetPhase::Pending(Box::new(pending)),
            cache,
        })
    }

    pub(super) async fn materialize(
        self,
        prepared: PreparedServerV2,
    ) -> Result<MaterializedServerV2, RunError> {
        let MaterializedServerResources {
            resources,
            rule_sets,
            cache,
        } = self.materialize_resources(&prepared).await?;
        let config = match ferrum2_config::finish_server_v2(prepared, resources) {
            Ok(config) => config,
            Err(error) => return Err(classify_config_materialization_error(error)),
        };
        Ok(MaterializedServerV2::new(config, rule_sets, cache))
    }
}
