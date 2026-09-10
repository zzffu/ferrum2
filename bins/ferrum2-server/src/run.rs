use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};

use ferrum2_config::{DnsConfig, PreparedServerV2, ValidatedServerConfig};
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::TaggedResolver;
use ferrum2_net::{DialOptions, RouteNetworkOptions};
use ferrum2_observability::{Metrics, RuleProgram, RuleProgramMode, json_subscriber};
use ferrum2_rule::RuleCompileError;
use ferrum2_runtime::{AffineConnectionExecutor, OwnerRegistry, ProcessRoot, UdpSessionManager};
use ferrum2_shadowsocks::{MethodKeyAdapter, TcpReplayStore, UdpServer};

mod dns;
mod error;
mod report;
pub(crate) use error::RunError;
use report::{RootDescriptor, RootRole, ServerRoots};
#[path = "dns_egress.rs"]
mod dns_egress;
mod materialize;
mod network;
mod network_owner;
#[cfg(any(windows, test))]
mod network_wait;
mod observation;
mod routing;
mod tcp;
#[path = "run/io.rs"]
mod tokio_io;
mod udp;

use dns::{ServerDnsDependentRoot, ServerDnsDrain, ServerDnsRoot};
use observation::{ServerMetricsRoot, log_level};
use routing::ServerRouting;
use tcp::{ServerContext, ServerTcpListeners, ServerTcpRoot};
use tokio_io::{bind_datagram, bind_listener, shutdown_signal};
#[cfg(all(windows, not(test)))]
use udp::ServerUdpNetworkReset;
use udp::{ServerUdpShared, UdpMappings, prepare_udp_server_with_network, udp_runtime_limits};

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
        | RuleCompileError::ResourceLimit
        | RuleCompileError::Internal => RunError::RuleCompile,
    }
}

const fn run_error_for_dns_policy_compile(error: ferrum2_dns::DnsPolicyCompileError) -> RunError {
    match error {
        ferrum2_dns::DnsPolicyCompileError::Allocation
        | ferrum2_dns::DnsPolicyCompileError::IndexOverflow => RunError::RuleAllocation,
        ferrum2_dns::DnsPolicyCompileError::InvalidQueryMatchSet
        | ferrum2_dns::DnsPolicyCompileError::DuplicateConstraint
        | ferrum2_dns::DnsPolicyCompileError::InvalidPortRange
        | ferrum2_dns::DnsPolicyCompileError::UnknownRuleSet
        | ferrum2_dns::DnsPolicyCompileError::QueryModeCidrRuleSet
        | ferrum2_dns::DnsPolicyCompileError::ResponseModeRequiresCidrRuleSet
        | ferrum2_dns::DnsPolicyCompileError::ResponseMatchWithoutEvaluate
        | ferrum2_dns::DnsPolicyCompileError::RespondWithoutEvaluate
        | ferrum2_dns::DnsPolicyCompileError::Internal => RunError::RuleCompile,
    }
}

fn runtime_route_network(config: &ferrum2_config::RouteNetworkConfig) -> RouteNetworkOptions {
    RouteNetworkOptions::new(
        if config.auto_detect_interface {
            ferrum2_net::AutomaticInterfaceSelection::Enabled
        } else {
            ferrum2_net::AutomaticInterfaceSelection::Disabled
        },
        config.default_interface(),
    )
}

fn runtime_dial_options(config: &ferrum2_config::OutboundDialOptions) -> DialOptions {
    DialOptions::new(
        config.bind_interface(),
        config.inet4_bind_address(),
        config.inet6_bind_address(),
    )
}

/// Fully materializes schema-v2 fixed endpoints and the initial RuleSet
/// snapshot before any listener root is allowed to prepare.
pub(crate) fn run_prepared(prepared: PreparedServerV2) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
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
            let mut network = network_owner::ServerNetworkRuntime::prepare(&registry, &metrics)?;
            let network_sockets = Arc::clone(&network.sockets);
            let result = async {
                let materializer = materialize::ServerV2Materializer::with_network_sockets(
                    system.clone(),
                    Arc::clone(&metrics),
                    Arc::clone(&network_sockets),
                );
                let materialized = materializer.materialize(prepared).await?;
                let level = log_level(materialized.config().logging.level);
                let subscriber = json_subscriber(std::io::stderr, move || level);
                if tracing::subscriber::set_global_default(subscriber).is_err() {
                    drop(materialized.into_validated_config());
                    return Err(RunError::StartupObservability);
                }
                let materialize::MaterializedRunParts {
                    config,
                    materialization_root,
                } = materialized.into_run_parts().await?;
                let dns_specs = config
                    .dns
                    .as_ref()
                    .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
                run_with_registry_prepared_using_system(
                    system.clone(),
                    config,
                    registry,
                    shutdown_signal(),
                    metrics,
                    ServerRunResources {
                        materialization_root,
                        dns_specs,
                        network: Some(network.run_parts()),
                    },
                )
                .await
            }
            .await;
            network.shutdown().await?;
            result
        }
        .await;
        system_owner
            .shutdown()
            .await
            .map_err(|_| RunError::ShutdownCleanup)?;
        result
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
            let mut network = network_owner::ServerNetworkRuntime::prepare(&registry, &metrics)?;
            let network_sockets = Arc::clone(&network.sockets);
            let materializer = materialize::ServerV2Materializer::with_network_sockets(
                system.clone(),
                metrics,
                network_sockets,
            );
            let result = match materializer.materialize(prepared).await {
                Ok(materialized) => {
                    drop(materialized.into_validated_config());
                    Ok(())
                }
                Err(error) => Err(error),
            };
            network.shutdown().await?;
            result
        }
        .await;
        system_owner
            .shutdown()
            .await
            .map_err(|_| RunError::ShutdownCleanup)?;
        result
    })
}

struct ServerRunResources {
    materialization_root: Option<materialize::ServerV2RuntimeRoot>,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
    network: Option<network_owner::ServerNetworkRunParts>,
}

impl ServerRunResources {
    #[cfg(test)]
    const fn test_unmaterialized(dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>) -> Self {
        Self {
            materialization_root: None,
            dns_specs,
            network: None,
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

async fn run_with_registry_prepared_using_system<S>(
    system: ferrum2_dns::SystemResolver,
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
        dns_specs,
        network,
    } = resources;
    let result = async {
        publish_rule_program_metadata(&config, &metrics);
        let route_network = Arc::new(runtime_route_network(&config.route_network));
        let outbound_dial_options: Arc<[DialOptions]> = config
            .outbounds
            .iter()
            .map(|outbound| runtime_dial_options(outbound.dial_options()))
            .collect::<Vec<_>>()
            .into();
        let network_owner::ServerNetworkRunParts {
            sockets: network_sockets,
            process_resources,
            #[cfg(all(windows, not(test)))]
                waiter: network_change_monitor,
            #[cfg(all(windows, not(test)))]
            retirement,
        } = network.ok_or(RunError::StartupRuntime)?;
        let physical_sockets = Arc::new(dns_egress::ServerPhysicalSocketContext::new(
            Arc::clone(&network_sockets),
            Arc::clone(&outbound_dial_options),
            Arc::clone(&route_network),
            Arc::clone(&metrics),
        ));
        let dns = match (config.dns, config.dns_route, dns_specs) {
            (
                Some(DnsConfig {
                    inbounds: _,
                    servers: _,
                    timeout,
                    max_inflight,
                    runtime: _,
                }),
                Some(_policy),
                Some(servers),
            ) => Some((servers, timeout, max_inflight)),
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
            program: config.route,
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
                    system.clone(),
                    outbound.domain_resolver,
                    Arc::clone(&tagged_dns),
                    Arc::clone(&metrics),
                )
            })
            .collect::<Vec<_>>()
            .into();
        let mut roots = ServerRoots::with_capacity(
            config.inbounds.len() * usize::from(config.udp.enabled)
                + 2
                + usize::from(dns.is_some())
                + usize::from(config.metrics.is_some())
                + usize::from(materialization_root.is_some()),
        );
        #[cfg(all(windows, not(test)))]
        let network_change_metrics = Arc::clone(&metrics);
        #[cfg(all(windows, not(test)))]
        let mut udp_network_reset = None;
        if let Some((servers, timeout, max_inflight)) = dns {
            let root_direct_resolvers = Arc::clone(&direct_resolvers);
            let root_physical_sockets = Arc::clone(&physical_sockets);
            let root_tagged_dns = Arc::clone(&tagged_dns);
            let root_dns_drain = dns_drain
                .as_ref()
                .cloned()
                .ok_or(RunError::StartupProtocol)?;
            roots.push(
                RootDescriptor {
                    role: RootRole::Dns,
                    declaration_index: None,
                },
                ProcessRoot::new(move || async move {
                    let egress = Arc::new(
                        dns_egress::ServerDnsEgress::new(root_physical_sockets)
                            .with_outbound_resolvers(
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
                    Ok(ServerDnsRoot {
                        _resolver: resolver,
                        owner,
                        drain: root_dns_drain,
                    })
                }),
            );
        }

        let mut tcp_listens = Vec::with_capacity(config.inbounds.len());
        let mut tcp_contexts = Vec::with_capacity(config.inbounds.len());
        for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
            let listen = inbound.listen;
            tcp_listens.push(listen);
            let context = Arc::new(ServerContext {
                inbound: inbound_id,
                routing: Arc::clone(&routing),
                keys: Arc::clone(&keys),
                replay: Arc::clone(&replay),
                clock: Arc::clone(&clock),
                random: SystemRandom,
                runtime: config.runtime,
                direct_resolvers: Arc::clone(&direct_resolvers),
                outbound_dial_options: Arc::clone(&outbound_dial_options),
                route_network: Arc::clone(&route_network),
                network_sockets: Arc::clone(&network_sockets),
                registry: registry.clone(),
                metrics: Arc::clone(&metrics),
            });
            tcp_contexts.push(context);
        }
        // ProcessSupervisor prepares roots in insertion order. Acquire every UDP
        // listener before the TCP root exposes its kernel listen backlog so a
        // successful external TCP-connect readiness probe also orders after all
        // required UDP binds.
        if let Some(protocol) = udp_protocol {
            let limits = udp_runtime_limits(&udp_config).ok_or(RunError::StartupProtocol)?;
            let sessions = UdpSessionManager::new(limits, registry.clone());
            let mappings = Arc::new(UdpMappings::new(udp_config.max_sessions));
            let admission = Arc::new(tokio::sync::Mutex::new(()));
            #[cfg(all(windows, not(test)))]
            {
                udp_network_reset = Some(Arc::new(ServerUdpNetworkReset::new(
                    network_sockets
                        .coordinator()
                        .status()
                        .published_generation(),
                    sessions.clone(),
                    Arc::clone(&mappings),
                    Arc::clone(&admission),
                )));
            }
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
                let udp_network_sockets = Arc::clone(&network_sockets);
                let udp_outbound_dial_options = Arc::clone(&outbound_dial_options);
                let udp_route_network = Arc::clone(&route_network);
                let descriptor = RootDescriptor {
                    role: RootRole::UdpInbound,
                    declaration_index: Some(inbound_id),
                };
                roots.push(
                    descriptor,
                    ProcessRoot::new(move || async move {
                        let listener = Arc::new(bind_datagram(listen).map_err(|acquisition| {
                            RunError::StartupBind {
                                descriptor,
                                acquisition,
                            }
                        })?);
                        prepare_udp_server_with_network(
                            inbound_id,
                            listener,
                            shared,
                            udp_network_sockets,
                            udp_outbound_dial_options,
                            udp_route_network,
                        )
                        .map(|root| ServerDnsDependentRoot::new(root, udp_dns_lease))
                    }),
                );
            }
        }
        let tcp_registry = registry.clone();
        let tcp_dns_lease = dns_drain.as_ref().map(ServerDnsDrain::lease);
        roots.push(
            RootDescriptor {
                role: RootRole::TcpInbound,
                declaration_index: None,
            },
            ProcessRoot::new(move || async move {
                let mut listeners = Vec::with_capacity(tcp_listens.len());
                for (declaration_index, listen) in tcp_listens.into_iter().enumerate() {
                    let descriptor = RootDescriptor {
                        role: RootRole::TcpInbound,
                        declaration_index: Some(declaration_index),
                    };
                    listeners.push(bind_listener(listen, listen_backlog).map_err(
                        |acquisition| RunError::StartupBind {
                            descriptor,
                            acquisition,
                        },
                    )?);
                }
                let executor = AffineConnectionExecutor::new(
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
                        executor: Some(executor),
                        contexts: Arc::new(tcp_contexts),
                    },
                    tcp_dns_lease,
                ))
            }),
        );
        if let Some(metrics_config) = config.metrics {
            let metrics_registry = registry.clone();
            let descriptor = RootDescriptor {
                role: RootRole::Metrics,
                declaration_index: None,
            };
            roots.push(
                descriptor,
                ProcessRoot::new(move || async move {
                    let listener =
                        bind_listener(metrics_config.listen, 16).map_err(|acquisition| {
                            RunError::StartupBind {
                                descriptor,
                                acquisition,
                            }
                        })?;
                    Ok(ServerMetricsRoot {
                        listener: Some(listener),
                        metrics,
                        registry: metrics_registry,
                    })
                }),
            );
        }
        // Transfer the already-prepared refresh owner only after every other
        // fallible composition step has completed. Once transferred, the
        // supervisor rolls it back if any listener root fails to prepare.
        if let Some(prepared) = materialization_root.take() {
            roots.prepend(
                RootDescriptor {
                    role: RootRole::Rules,
                    declaration_index: None,
                },
                ProcessRoot::new(move || async move { Ok(prepared) }),
            );
        }
        // This must be the first required root. If any later root cannot prepare,
        // its rollback explicitly closes the pre-start network-change monitor.
        #[cfg(all(windows, not(test)))]
        roots.prepend(
            RootDescriptor {
                role: RootRole::Network,
                declaration_index: None,
            },
            network::network_change_process_root(
                network_change_monitor,
                Arc::clone(&network_sockets),
                retirement,
                network_change_metrics,
                udp_network_reset,
            ),
        );
        roots
            .run_until(shutdown_grace, registry, process_resources, shutdown)
            .await
    }
    .await;
    if let Some(mut root) = materialization_root {
        result.and(root.cleanup().await)
    } else {
        result
    }
}

fn publish_rule_program_metadata(config: &ValidatedServerConfig, metrics: &Metrics) {
    metrics.set_rule_program_mode(
        RuleProgram::Route,
        rule_program_mode(config.route.program_mode()),
    );
    metrics.set_rule_program_rules(RuleProgram::Route, config.route.rule_count());
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

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

#[cfg(test)]
async fn run_with_registry_prepared<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    mut resources: ServerRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    materialize::validate_server_dns_policy(&config)?;
    let (system, mut owner) = ferrum2_dns::SystemResolution::start(
        config.dns.as_ref().map_or_else(
            || {
                std::num::NonZeroU16::new(config.runtime.max_connections.get().min(4096))
                    .expect("validated positive connection limit")
            },
            |dns| dns.max_inflight,
        ),
        config.runtime.connect_timeout,
    )
    .map_err(|_| RunError::StartupRuntime)?;
    let mut network = network_owner::ServerNetworkRuntime::prepare(&registry, &metrics)?;
    resources.network = Some(network.run_parts());
    let result = run_with_registry_prepared_using_system(
        system, config, registry, shutdown, metrics, resources,
    )
    .await;
    let network_cleanup = network.shutdown().await;
    owner
        .shutdown()
        .await
        .map_err(|_| RunError::ShutdownCleanup)?;
    network_cleanup?;
    result
}
