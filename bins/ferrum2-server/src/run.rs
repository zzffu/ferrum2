use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use ferrum2_config::{DnsConfig, PreparedServerV2, ValidatedServerConfig};
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::{DnsCache, TaggedResolver};
use ferrum2_observability::{Metrics, RuleProgram, RuleProgramMode, json_subscriber};
use ferrum2_rule::RuleCompileError;
use ferrum2_runtime::{
    BoundedSupervisor, OwnerRegistry, ProcessCause, ProcessReport, ProcessRoot, ProcessRootExit,
    ProcessSupervisor, UdpSessionManager,
};
use ferrum2_shadowsocks::{MethodKeyAdapter, TcpReplayStore, UdpServer};
use tokio::net::UdpSocket;

mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod materialize;
mod observation;
mod tcp;
#[path = "run/io.rs"]
mod tokio_io;
mod udp;

use dns::{ServerDnsDependentRoot, ServerDnsDrain, ServerDnsRoot};
use observation::{ServerMetricsRoot, log_level};
use tcp::{ServerContext, ServerRouting, ServerTcpListeners, ServerTcpRoot};
use tokio_io::{bind_listener, shutdown_signal};
use udp::{ServerUdpShared, UdpMappings, prepare_udp_server, udp_runtime_limits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
    ConfigResourceMaterialization,
    DnsResolve,
    RuleCompile,
    RuleAllocation,
    RuleSetDownload,
    RuleSetCache,
    RuleSetFormat,
    RuleSetUnsupportedMatcher,
    RuleSetCompile,
    RuntimeListener,
    RuntimeChild,
    RuntimeRoot,
    ShutdownCleanup,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StartupObservability => {
                "error[startup.observability] process: unable to initialize diagnostics"
            }
            Self::StartupRuntime => {
                "error[startup.runtime] process: unable to create asynchronous runtime"
            }
            Self::StartupBind => "error[startup.bind] process: unable to prepare required endpoint",
            Self::StartupProtocol => {
                "error[startup.protocol] process: unable to prepare protocol resources"
            }
            Self::ConfigResourceMaterialization => {
                "error[config.resource_materialization] configuration: supplied resources are invalid"
            }
            Self::DnsResolve => {
                "error[dns.resolve] materialization: fixed endpoint resolution failed"
            }
            Self::RuleCompile => {
                "error[rule.compile] materialization: rule compilation failed"
            }
            Self::RuleAllocation => {
                "error[rule.allocation] materialization: rule allocation failed"
            }
            Self::RuleSetDownload => {
                "error[ruleset.download] materialization: RuleSet download failed"
            }
            Self::RuleSetCache => {
                "error[ruleset.cache] materialization: RuleSet cache failed"
            }
            Self::RuleSetFormat => {
                "error[ruleset.format] materialization: RuleSet format is invalid"
            }
            Self::RuleSetUnsupportedMatcher => {
                "error[ruleset.unsupported_matcher] materialization: RuleSet matcher is unsupported"
            }
            Self::RuleSetCompile => {
                "error[ruleset.compile] materialization: RuleSet compilation failed"
            }
            Self::RuntimeListener => "error[runtime.listener] process: required listener failed",
            Self::RuntimeChild => "error[runtime.child] process: required child failed",
            Self::RuntimeRoot => "error[runtime.root] process: required root stopped",
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

/// Classifies rule scratch construction failures after configuration has
/// already passed semantic validation. Allocation and index-capacity failures
/// retain their operator-visible category; every other closed compiler failure
/// is an internal compilation failure at this production boundary.
const fn run_error_for_rule_compile(error: RuleCompileError) -> RunError {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => RunError::RuleAllocation,
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidId
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => RunError::RuleCompile,
    }
}

const fn run_error_for_dns_state(error: dns_egress::ServerDnsStateBuildError) -> RunError {
    match error {
        dns_egress::ServerDnsStateBuildError::CacheAllocation => RunError::RuleAllocation,
        dns_egress::ServerDnsStateBuildError::InvalidRuntime => RunError::StartupProtocol,
        dns_egress::ServerDnsStateBuildError::Rule(error) => run_error_for_rule_compile(error),
        dns_egress::ServerDnsStateBuildError::DnsPolicy(error) => {
            run_error_for_dns_policy_compile(error)
        }
    }
}

const fn run_error_for_dns_policy_compile(error: ferrum2_dns::DnsPolicyCompileError) -> RunError {
    match error {
        ferrum2_dns::DnsPolicyCompileError::Allocation
        | ferrum2_dns::DnsPolicyCompileError::IndexOverflow => RunError::RuleAllocation,
        ferrum2_dns::DnsPolicyCompileError::EmptyRule
        | ferrum2_dns::DnsPolicyCompileError::InvalidQueryMatchSet
        | ferrum2_dns::DnsPolicyCompileError::DuplicateConstraint
        | ferrum2_dns::DnsPolicyCompileError::InvalidPortRange
        | ferrum2_dns::DnsPolicyCompileError::UnknownRuleSet
        | ferrum2_dns::DnsPolicyCompileError::ResponseDependentReject
        | ferrum2_dns::DnsPolicyCompileError::Internal => RunError::RuleCompile,
    }
}

/// Fully materializes schema-v2 fixed endpoints and the initial RuleSet
/// snapshot before any listener root is allowed to prepare.
pub(crate) fn run_prepared(prepared: PreparedServerV2) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
        let metrics = Arc::new(Metrics::new());
        let context = materialize::ServerV2MaterializeContext::new(Arc::clone(&metrics));
        let materialized = materialize::materialize_prepared(prepared, &context).await?;
        let subscriber = json_subscriber(
            std::io::stderr,
            log_level(materialized.config().logging.level),
        );
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            materialized.validate_only_shutdown().await?;
            return Err(RunError::StartupObservability);
        }
        let (config, materialization_root, materialized_cache) =
            materialized.into_run_parts().await?;
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
        run_with_registry_prepared(
            config,
            OwnerRegistry::new(),
            shutdown_signal(),
            metrics,
            ServerRunResources {
                materialization_root,
                materialized_cache,
                dns_specs,
                materialized: true,
            },
        )
        .await
    })
}

/// Performs the opt-in networked validation pass without preparing listeners
/// or transferring a refresh loop to the process supervisor.
pub(crate) fn materialize_only(prepared: PreparedServerV2) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
        let context = materialize::ServerV2MaterializeContext::new(Arc::new(Metrics::new()));
        materialize::materialize_prepared(prepared, &context)
            .await?
            .validate_only_shutdown()
            .await
            .map(drop)
    })
}

struct ServerRunResources {
    materialization_root: Option<materialize::ServerV2RuntimeRoot>,
    materialized_cache: Option<DnsCache>,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
    materialized: bool,
}

impl ServerRunResources {
    #[cfg(test)]
    const fn test_unmaterialized(dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>) -> Self {
        Self {
            materialization_root: None,
            materialized_cache: None,
            dns_specs,
            materialized: false,
        }
    }
}

#[cfg(test)]
async fn run_with_registry<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    run_with_registry_prepared(
        config,
        registry,
        shutdown,
        Arc::new(Metrics::new()),
        ServerRunResources::test_unmaterialized(dns_specs),
    )
    .await
}

async fn run_with_registry_prepared<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    resources: ServerRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let ServerRunResources {
        mut materialization_root,
        materialized_cache,
        dns_specs,
        materialized,
    } = resources;
    let result = async {
        publish_rule_program_metadata(&config, &metrics);
        let dns = match (config.dns, config.dns_route, dns_specs) {
            (
                Some(DnsConfig {
                    inbounds: _,
                    servers: _,
                    route,
                    timeout,
                    max_inflight,
                    runtime,
                }),
                policy,
                Some(servers),
            ) => Some((servers, route, policy, timeout, max_inflight, runtime)),
            (None, None, None) => None,
            _ => return Err(RunError::StartupProtocol),
        };
        let dns_drain = dns.as_ref().map(|_| ServerDnsDrain::new());
        let replay = Arc::new(
            TcpReplayStore::new(config.replay.capacity).map_err(|_| RunError::StartupProtocol)?,
        );
        let keys = Arc::new(MethodKeyAdapter::new(MethodSinglePskProvider::new(
            config.psk,
        )));
        let udp_protocol = if config.udp.enabled {
            Some(Arc::new(
                UdpServer::new(keys.as_ref()).map_err(|_| RunError::StartupProtocol)?,
            ))
        } else {
            None
        };
        let listen_backlog = u32::from(config.runtime.listen_backlog.get());
        let max_connections = usize::from(config.runtime.max_connections.get());
        let shutdown_grace = config.runtime.shutdown_grace;
        let connect_timeout = config.runtime.connect_timeout;
        let udp_config = config.udp;
        let clock = Arc::new(SystemClock::new());
        let routing = Arc::new(ServerRouting {
            legacy: config.route,
            program: config.route_program,
            outbound_count: config.outbounds.len(),
        });
        // Probe caller-owned route scratch before any listener is prepared so
        // an allocation/capacity failure has a stable process-level category.
        let _ = routing
            .route_scratch()
            .map_err(run_error_for_rule_compile)?;
        let tagged_dns = Arc::new(OnceLock::new());
        let direct_resolvers: Arc<[dns_egress::ServerDnsResolver]> = config
            .outbounds
            .iter()
            .map(|outbound| {
                dns_egress::ServerDnsResolver::for_direct_observed(
                    outbound.domain_resolver,
                    Arc::clone(&tagged_dns),
                    Arc::clone(&metrics),
                )
            })
            .collect::<Vec<_>>()
            .into();
        let mut roots = Vec::with_capacity(
            config.inbounds.len() * usize::from(config.udp.enabled)
                + 1
                + usize::from(dns.is_some())
                + usize::from(config.metrics.is_some())
                + usize::from(materialization_root.is_some()),
        );
        let _dns = match dns {
            Some((servers, route, policy, timeout, max_inflight, runtime)) => {
                let state = if materialized {
                    dns_egress::ServerDnsState::try_new_with_cache(
                        route,
                        policy,
                        runtime,
                        materialized_cache,
                    )
                } else {
                    dns_egress::ServerDnsState::try_new(route, policy, runtime)
                }
                .map_err(run_error_for_dns_state)?
                .with_policy_observer(dns_egress::dns_policy_observer(&metrics));
                let state = Arc::new(state);
                let root_state = Arc::clone(&state);
                let outbound_count = routing.outbound_count;
                let root_direct_resolvers = Arc::clone(&direct_resolvers);
                let root_tagged_dns = Arc::clone(&tagged_dns);
                let root_dns_drain = dns_drain
                    .as_ref()
                    .cloned()
                    .ok_or(RunError::StartupProtocol)?;
                roots.push(ProcessRoot::new(move || async move {
                    let egress = Arc::new(
                        dns_egress::ServerDnsEgress::new(outbound_count).with_outbound_resolvers(
                            root_direct_resolvers.iter().cloned().collect(),
                        ),
                    );
                    let (resolver, mut owner) =
                        TaggedResolver::new(servers, timeout, max_inflight, egress)
                            .map_err(|_| RunError::StartupProtocol)?;
                    owner.ready().await.map_err(|_| RunError::StartupProtocol)?;
                    let resolver = Arc::new(resolver);
                    root_tagged_dns
                        .set(Arc::downgrade(&resolver))
                        .map_err(|_| RunError::StartupProtocol)?;
                    root_state
                        .install(resolver)
                        .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ServerDnsRoot {
                        state: root_state,
                        owner,
                        drain: root_dns_drain,
                    })
                }));
                Some(state)
            }
            None if materialized_cache.is_none() => None,
            None => return Err(RunError::StartupProtocol),
        };
        let mut tcp_listens = Vec::with_capacity(config.inbounds.len());
        let mut tcp_contexts = Vec::with_capacity(config.inbounds.len());
        for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
            let listen = inbound.listen;
            tcp_listens.push(listen);
            let context = Arc::new(ServerContext {
                inbound: inbound_id,
                routing: Arc::clone(&routing),
                keys: Arc::clone(&keys),
                clock: Arc::clone(&clock),
                random: SystemRandom,
                replay: Arc::clone(&replay),
                runtime: config.runtime,
                direct_resolvers: Arc::clone(&direct_resolvers),
                registry: registry.clone(),
                metrics: Arc::clone(&metrics),
            });
            tcp_contexts.push(context);
        }
        let tcp_registry = registry.clone();
        let tcp_dns_lease = dns_drain.as_ref().map(ServerDnsDrain::lease);
        roots.push(ProcessRoot::new(move || async move {
            let mut listeners = Vec::with_capacity(tcp_listens.len());
            for listen in tcp_listens {
                listeners.push(bind_listener(listen, listen_backlog)?);
            }
            let supervisor = BoundedSupervisor::new(
                ServerTcpListeners {
                    listeners,
                    next: AtomicUsize::new(0),
                },
                max_connections,
                shutdown_grace,
                tcp_registry,
            )
            .map_err(|_| RunError::StartupProtocol)?;
            Ok(ServerDnsDependentRoot::new(
                ServerTcpRoot {
                    supervisor: Some(supervisor),
                    contexts: Arc::new(tcp_contexts),
                },
                tcp_dns_lease,
            ))
        }));
        if let Some(protocol) = udp_protocol {
            let limits = udp_runtime_limits(&udp_config).ok_or(RunError::StartupProtocol)?;
            let sessions = UdpSessionManager::new(limits, registry.clone());
            let mappings = Arc::new(UdpMappings::new(udp_config.max_sessions));
            let admission = Arc::new(tokio::sync::Mutex::new(()));
            let shared = ServerUdpShared {
                routing: Arc::clone(&routing),
                protocol,
                clock: Arc::clone(&clock),
                config: udp_config,
                sessions,
                mappings,
                admission,
                connect_timeout,
                direct_resolvers: Arc::clone(&direct_resolvers),
                registry: registry.clone(),
                metrics: Arc::clone(&metrics),
            };
            for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
                let listen = inbound.listen;
                let shared = shared.clone();
                let udp_dns_lease = dns_drain.as_ref().map(ServerDnsDrain::lease);
                roots.push(ProcessRoot::new(move || async move {
                    let listener = Arc::new(
                        UdpSocket::bind(SocketAddr::V4(listen))
                            .await
                            .map_err(|_| RunError::StartupBind)?,
                    );
                    prepare_udp_server(inbound_id, listener, shared)
                        .map(|root| ServerDnsDependentRoot::new(root, udp_dns_lease))
                }));
            }
        }
        if let Some(metrics_config) = config.metrics {
            let metrics_registry = registry.clone();
            roots.push(ProcessRoot::new(move || async move {
                let listener = bind_listener(metrics_config.listen, 16)?;
                Ok(ServerMetricsRoot {
                    listener: Some(listener),
                    metrics,
                    registry: metrics_registry,
                })
            }));
        }
        // Transfer the already-prepared refresh owner only after every other
        // fallible composition step has completed. Once transferred, the
        // supervisor rolls it back if any listener root fails to prepare.
        if let Some(prepared) = materialization_root.take() {
            roots.insert(0, ProcessRoot::new(move || async move { Ok(prepared) }));
        }
        let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry)
            .map_err(|_| RunError::StartupProtocol)?;
        report_result(supervisor.run_until(shutdown).await)
    }
    .await;
    if let Some(mut root) = materialization_root {
        return result.and(root.cleanup().await);
    }
    result
}

fn publish_rule_program_metadata(config: &ValidatedServerConfig, metrics: &Metrics) {
    if let Some(route) = config.route_program.as_ref() {
        metrics.set_rule_program_mode(RuleProgram::Route, rule_program_mode(route.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::Route, route.rule_count());
    }
    let Some(dns) = config.dns_route.as_ref() else {
        return;
    };
    if let Some(binding) = dns.policy_blueprint() {
        let blueprint = binding.blueprint();
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, blueprint.len());
        metrics.set_rule_program_mode(
            RuleProgram::DnsResponse,
            rule_program_mode(dns.program_mode()),
        );
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, blueprint.response_rule_count());
    } else {
        metrics.set_rule_program_mode(RuleProgram::DnsQuery, rule_program_mode(dns.program_mode()));
        metrics.set_rule_program_rules(RuleProgram::DnsQuery, dns.rule_count());
        metrics.set_rule_program_mode(RuleProgram::DnsResponse, RuleProgramMode::SmallLinear);
        metrics.set_rule_program_rules(RuleProgram::DnsResponse, 0);
    }
}

const fn rule_program_mode(mode: ferrum2_rule::RuleProgramMode) -> RuleProgramMode {
    match mode {
        ferrum2_rule::RuleProgramMode::SmallLinear => RuleProgramMode::SmallLinear,
        ferrum2_rule::RuleProgramMode::Indexed => RuleProgramMode::Indexed,
    }
}

fn report_result(report: ProcessReport<RunError>) -> Result<(), RunError> {
    if report.cleanup_failure().is_some() {
        return Err(RunError::ShutdownCleanup);
    }
    match report.cause() {
        ProcessCause::ExternalShutdown => Ok(()),
        ProcessCause::PreparationFailed { error, .. }
        | ProcessCause::ActivationFailed { error, .. } => Err(*error),
        ProcessCause::PreparationPanicked { .. } | ProcessCause::ActivationPanicked { .. } => {
            Err(RunError::StartupProtocol)
        }
        ProcessCause::RootStopped { exit, .. } => match exit {
            ProcessRootExit::Failed(error) => Err(*error),
            ProcessRootExit::Panicked | ProcessRootExit::JoinFailed => Err(RunError::RuntimeChild),
            ProcessRootExit::Completed => Err(RunError::RuntimeRoot),
        },
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
