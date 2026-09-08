use super::*;
/// Fully materializes a prepared schema-v2 client before any listener or TUN
/// root is allowed to prepare. The returned process owns the bootstrap DNS,
/// RuleSet refresh, and egress bridge lifecycle for its entire run.
pub(crate) fn run_prepared(prepared: PreparedClientV2) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(run_generation(prepared, shutdown_signal(), None))
}

/// Runs one proxy generation to completion, retaining the existing cleanup owner.
pub(crate) async fn run_generation<S>(
    prepared: PreparedClientV2,
    shutdown: S,
    management: Option<management::Management>,
) -> Result<(), RunError>
where
    S: Future<Output = ()> + Send,
{
    let (system, mut system_owner) = ferrum2_dns::SystemResolution::start(
        prepared.dns_max_inflight().unwrap_or_else(|| {
            std::num::NonZeroU16::new(prepared.runtime().max_connections.get().min(4096))
                .expect("validated positive connection limit")
        }),
        prepared.runtime().connect_timeout,
    )
    .map_err(|_| RunError::StartupRuntime)?;
    let result = async {
        let metrics = Arc::new(Metrics::new());
        let registry = OwnerRegistry::new();
        #[cfg(all(windows, not(test)))]
        let mut network = network_owner::ClientNetworkRuntime::prepare_generation(
            registry.clone(),
            Arc::clone(&metrics),
            prepared.has_tun(),
        )?;
        let result = async {
            #[cfg(all(windows, not(test)))]
            let network_resources = network.resources();
            #[cfg(any(not(windows), test))]
            let network_resources = ClientNetworkResources::prepare(&registry)?;
            let materializer = materialize::ClientV2Materializer::new(
                system.clone(),
                Arc::clone(&metrics),
                #[cfg(all(windows, not(test)))]
                Arc::clone(&network_resources.sockets),
            );
            let materialized = match materializer.materialize(prepared).await {
                Ok(materialized) => materialized,
                Err(error) => {
                    return Err(error);
                }
            };
            let level = log_level(materialized.config().logging.level);
            if let Some(management) = &management {
                management
                    .log_level
                    .store(level as u8, std::sync::atomic::Ordering::Relaxed);
            }
            let subscriber = json_subscriber(std::io::stderr, move || level);
            if management.is_none() && tracing::subscriber::set_global_default(subscriber).is_err()
            {
                let materialized_cleanup = materialized.validate_only();
                materialized_cleanup?;
                return Err(RunError::StartupObservability);
            }
            let materialize::MaterializedRunParts {
                config,
                materialization_root,
                cache: materialized_cache,
            } = match materialized.into_run_parts().await {
                Ok(parts) => parts,
                Err(error) => {
                    return Err(error);
                }
            };
            let mut resources = ClientRunResources::new(network_resources);
            resources.management = management;
            resources.materialization_root = materialization_root;
            resources.materialized_cache = materialized_cache;
            run_with_registry_and_metrics_inner_using_system(
                system.clone(),
                config,
                registry,
                shutdown,
                metrics,
                #[cfg(test)]
                ClientTestOverrides::default(),
                resources,
            )
            .await
        }
        .await;
        #[cfg(all(windows, not(test)))]
        network.shutdown().await?;
        result
    }
    .await;
    system_owner
        .shutdown()
        .await
        .map_err(|_| RunError::ShutdownCleanup)?;
    result
}
