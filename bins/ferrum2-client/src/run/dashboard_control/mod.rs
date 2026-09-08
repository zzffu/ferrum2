use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use ferrum2_config::RouteAction;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanHandle, Network};
use ferrum2_dashboard::wire::{
    Command, CommandResult, DnsAnswer, DnsPath, Measurement, QueryType, RefreshResult,
    RouteSelection,
};
use ferrum2_dns::{DnsCache, DnsProxy, ProxyIngress, ProxyTransport, TaggedResolver};
use ferrum2_observability::Metrics;
use ferrum2_rule::{RouteMetadata, RouteProgramAction};
use ferrum2_ruleset::{RuleSetDownloader, RuleSetRefreshOutcome, RuleSetRefreshService};
use ferrum2_runtime::OwnerRegistry;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::{RwLock, watch};

use super::context::ClientRouting;
use super::egress::{ClientEgressEngine, ClientRequestOrigin};

type Refresh = Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>;
const DEADLINE: Duration = Duration::from_secs(15);

/// Generation-bound domain owners; retirement cancels and joins admitted diagnostics.
pub(crate) struct ClientDashboardControl {
    routing: Arc<ClientRouting>,
    egress: Arc<ClientEgressEngine>,
    dns: Option<Arc<OnceLock<Arc<DnsProxy>>>>,
    tagged: Arc<OnceLock<Weak<TaggedResolver>>>,
    cache: Option<DnsCache>,
    refresh: Option<Refresh>,
    metrics: Arc<Metrics>,
    registry: OwnerRegistry,
    inbound_count: usize,
    retired: watch::Sender<bool>,
    lifetime: RwLock<()>,
}

impl ClientDashboardControl {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::run) fn new(
        routing: Arc<ClientRouting>,
        egress: Arc<ClientEgressEngine>,
        dns: Option<Arc<OnceLock<Arc<DnsProxy>>>>,
        tagged: Arc<OnceLock<Weak<TaggedResolver>>>,
        cache: Option<DnsCache>,
        refresh: Option<Refresh>,
        metrics: Arc<Metrics>,
        registry: OwnerRegistry,
        inbound_count: usize,
    ) -> Self {
        Self {
            routing,
            egress,
            dns,
            tagged,
            cache,
            refresh,
            metrics,
            registry,
            inbound_count,
            retired: watch::channel(false).0,
            lifetime: RwLock::new(()),
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.retired.send_replace(true);
        let _exclusive = self.lifetime.write().await;
    }

    pub(crate) fn snapshot(&self) -> Value {
        if *self.retired.borrow() {
            return json!({"available":false,"capabilities":[]});
        }
        let selectors: Vec<_> = self.routing.selector.snapshot().into_iter().enumerate().map(|(id, row)| {
            json!({"id":id,"name":row.name,"selected":row.selected,"members":row.members.into_iter().enumerate().map(|(id,name)|json!({"id":id,"name":name})).collect::<Vec<_>>()})
        }).collect();
        let rulesets: Vec<_> = self.refresh.as_ref().map(|refresh| refresh.snapshot().into_iter().map(|row| {
            json!({"index":row.index,"name":row.name,"generation":row.generation.to_string(),"initial":format!("{:?}",row.initial),"initial_failure":row.initial_failure.map(|failure|format!("{failure:?}")),"last_refresh":row.last_refresh.map(refresh_result)})
        }).collect()).unwrap_or_default();
        let mut capabilities = vec![
            "connections.close",
            "connections.close_all",
            "outbounds.probe",
            "routes.test",
        ];
        if !selectors.is_empty() {
            capabilities.push("selectors.select");
        }
        if !rulesets.is_empty() {
            capabilities.push("rulesets.refresh");
        }
        if self.cache.is_some() {
            capabilities.push("dns.clear");
        }
        if self.dns.as_ref().and_then(|slot| slot.get()).is_some()
            || self.tagged.get().and_then(Weak::upgrade).is_some()
        {
            capabilities.push("dns.query");
        }
        let cache = self.cache.as_ref().map(|cache| json!({"capacity":cache.capacity().ok(),"entries":cache.entry_count(Instant::now()).ok(),"clear_semantics":"inflight_queries_may_repopulate"}));
        json!({"available":true,"selectors":selectors,"rulesets":rulesets,"dns_cache":cache,"metrics":super::observation::render_client_metrics(&self.metrics, &self.registry),"capabilities":capabilities})
    }

    pub(crate) async fn command(&self, request: &Command) -> Result<CommandResult, &'static str> {
        let _lease = self.lifetime.read().await;
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err("unavailable");
        }
        tokio::select! {
            biased;
            _ = retired.changed() => Err("unavailable"),
            result = tokio::time::timeout(DEADLINE, self.dispatch(request)) => result.map_err(|_|"timeout")?,
        }
    }

    async fn dispatch(&self, request: &Command) -> Result<CommandResult, &'static str> {
        match request {
            Command::SelectorsSelect { selector, member } => {
                let rows = self.routing.selector.snapshot();
                let row = rows.get(*selector).ok_or("invalid_selector")?;
                let member_name = row.members.get(*member).ok_or("invalid_member")?;
                self.routing
                    .selector
                    .switch(&row.name, member_name)
                    .map_err(|_| "selection_failed")?;
                Ok(CommandResult::Selected {
                    selected: *member,
                    generation: self.routing.selector.generation().to_string(),
                })
            }
            Command::OutboundsProbe {
                outbound,
                host,
                port,
            } => {
                let outbound = *outbound;
                if outbound >= self.routing.outbounds.len() {
                    return Err("invalid_outbound");
                }
                let target = target(host, *port)?;
                let plan = EgressPlanHandle::direct(outbound).snapshot_owned();
                let started = Instant::now();
                let flow = self
                    .egress
                    .open_tcp_for_ingress(
                        ClientRequestOrigin::Socks,
                        0,
                        Some(plan),
                        &target,
                        Some(DEADLINE),
                        #[cfg(test)]
                        None,
                    )
                    .await
                    .map_err(|_| "probe_failed")?;
                let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                let mut io = ferrum2_shadowsocks::tokio::TokioFramed::new(flow);
                let closed = tokio::time::timeout(Duration::from_secs(1), io.shutdown()).await;
                drop(io);
                Ok(CommandResult::Probe {
                    outbound,
                    host: host.clone(),
                    port: target.port().get(),
                    measurement: Measurement::TransportConnect,
                    elapsed_ms: elapsed,
                    transport_closed: true,
                    graceful_shutdown: matches!(closed, Ok(Ok(()))),
                })
            }
            Command::RoutesTest {
                host,
                port,
                protocol,
                inbound,
            } => self.route_trial(host, *port, *protocol, *inbound),
            Command::RulesetsRefresh { index } => {
                let refresh = self.refresh.as_ref().ok_or("unavailable")?;
                let index = *index;
                if index >= refresh.snapshot().len() {
                    return Err("invalid_ruleset");
                }
                Ok(CommandResult::Refresh {
                    outcome: refresh_result(refresh.refresh_once(index).await),
                })
            }
            Command::DnsClear {} => {
                let removed = self
                    .cache
                    .as_ref()
                    .ok_or("unavailable")?
                    .clear()
                    .map_err(|_| "cache_unavailable")?;
                Ok(CommandResult::DnsCleared {
                    removed,
                    inflight_queries_may_repopulate: true,
                })
            }
            Command::DnsQuery {
                name,
                qtype,
                server,
            } => self.dns_query(name, *qtype, *server).await,
            _ => Err("invalid_action"),
        }
    }

    fn route_trial(
        &self,
        host: &str,
        port: u16,
        protocol: ferrum2_dashboard::wire::Network,
        inbound: usize,
    ) -> Result<CommandResult, &'static str> {
        let target = target(host, port)?;
        if inbound >= self.inbound_count {
            return Err("invalid_inbound");
        }
        let network = match protocol {
            ferrum2_dashboard::wire::Network::Tcp => Network::Tcp,
            ferrum2_dashboard::wire::Network::Udp => Network::Udp,
        };
        let mut scratch = self
            .routing
            .program
            .evaluation_scratch()
            .map_err(|_| "route_unavailable")?;
        let mut evaluation =
            self.routing
                .program
                .evaluate_with_scratch(inbound, network, &target, &mut scratch);
        let mut sniff_requested = false;
        loop {
            let action = evaluation
                .next(RouteMetadata::new(None, None))
                .ok_or("route_unavailable")?;
            let (action, final_action) = match action {
                RouteProgramAction::Continue(RouteAction::Sniff(_)) => {
                    sniff_requested = true;
                    continue;
                }
                RouteProgramAction::Continue(_) => return Err("route_unavailable"),
                RouteProgramAction::Terminal(action) => (action, false),
                RouteProgramAction::Final(action) => (action, true),
            };
            let selected = match action {
                RouteAction::Route(handle) => RouteSelection::Route {
                    hops: handle.snapshot_owned().hops().to_vec(),
                },
                RouteAction::HijackDns => RouteSelection::HijackDns {},
                RouteAction::Reject => RouteSelection::Reject {},
                RouteAction::Sniff(_) => return Err("route_unavailable"),
            };
            return Ok(CommandResult::Route {
                action: selected,
                final_action,
                rule_index: evaluation.selected_rule_index(),
                rule_generation: evaluation
                    .snapshot_generation()
                    .map(|generation| generation.to_string()),
                missing_metadata: vec![
                    "sniff_protocol".into(),
                    "sniff_domain".into(),
                    "dns_resolution".into(),
                ],
                sniff_requested,
                network_lookup: false,
            });
        }
    }

    async fn dns_query(
        &self,
        name: &str,
        qtype: QueryType,
        server: Option<usize>,
    ) -> Result<CommandResult, &'static str> {
        let name = text(name)?;
        ferrum2_core::CanonicalDomain::new(name).map_err(|_| "invalid_name")?;
        let name = Name::from_ascii(name).map_err(|_| "invalid_name")?;
        let qtype = match qtype {
            QueryType::A => RecordType::A,
            QueryType::Aaaa => RecordType::AAAA,
        };
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name, qtype));
        let (response, path) = if let Some(server) = server {
            let resolver = self
                .tagged
                .get()
                .and_then(Weak::upgrade)
                .ok_or("unavailable")?;
            (
                resolver
                    .query(server, query)
                    .await
                    .map_err(|_| "dns_query_failed")?,
                DnsPath::TaggedServer { server },
            )
        } else {
            if self.inbound_count == 0 {
                return Err("explicit_server_required");
            }
            let proxy = self
                .dns
                .as_ref()
                .and_then(|slot| slot.get())
                .ok_or("explicit_server_required")?;
            let wire = query.to_vec().map_err(|_| "invalid_query")?;
            let response = proxy
                .answer(ProxyIngress::Ordinary(0), ProxyTransport::Tcp, &wire)
                .await
                .ok_or("dns_query_failed")?;
            (
                Message::from_vec(&response).map_err(|_| "dns_query_failed")?,
                DnsPath::OrdinaryPolicy { inbound: 0 },
            )
        };
        let answers = response
            .answers
            .iter()
            .take(256)
            .map(|record| DnsAnswer {
                name: record.name.to_string(),
                ttl: record.ttl,
                record_type: record.data.record_type().to_string(),
                data: record.data.to_string(),
            })
            .collect();
        Ok(CommandResult::DnsQuery {
            path,
            response_code: response.metadata.response_code.to_string(),
            answers,
            truncated: response.metadata.truncation || response.answers.len() > 256,
        })
    }
}

fn text(value: &str) -> Result<&str, &'static str> {
    if value.is_empty() || value.len() > 255 {
        Err("invalid_input")
    } else {
        Ok(value)
    }
}
fn target(host: &str, port: u16) -> Result<TargetAddr, &'static str> {
    let host = text(host)?;
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => TargetAddr::ip(std::net::SocketAddr::new(ip, port)),
        Err(_) => {
            ferrum2_core::CanonicalDomain::new(host).map_err(|_| "invalid_host")?;
            TargetAddr::domain(host, port)
        }
    }
    .map_err(|_| "invalid_target")
}
fn refresh_result(outcome: RuleSetRefreshOutcome) -> RefreshResult {
    match outcome {
        RuleSetRefreshOutcome::Updated {
            previous_generation,
            generation,
        } => RefreshResult::Updated {
            previous_generation: previous_generation.to_string(),
            generation: generation.to_string(),
        },
        RuleSetRefreshOutcome::NotModified => RefreshResult::Unchanged {},
        RuleSetRefreshOutcome::RetainedCache(reason) => RefreshResult::Degraded {
            retained_previous: true,
            reason: format!("{reason:?}"),
        },
        RuleSetRefreshOutcome::Failed(reason) => RefreshResult::Failed {
            retained_previous: true,
            reason: format!("{reason:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::test_support::{default_test_psk, test_routing, udp_test_context_for_server};
    use ferrum2_runtime::{UdpDirection, UdpRuntimeLimits, UdpSessionManager};

    #[test]
    fn dashboard_metrics_follow_udp_ownership_without_prometheus_scrapes() {
        let registry = OwnerRegistry::new();
        let server = "127.0.0.1:9".parse().expect("loopback");
        let (path, context) = udp_test_context_for_server(registry.clone(), server);
        std::fs::remove_file(path).expect("remove fixture");
        let control = ClientDashboardControl::new(
            Arc::new(test_routing(server, default_test_psk())),
            Arc::clone(&context.egress),
            None,
            Arc::new(OnceLock::new()),
            None,
            None,
            Arc::clone(&context.metrics),
            registry.clone(),
            1,
        );
        let manager = UdpSessionManager::new(
            UdpRuntimeLimits::new(
                1,
                ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES,
                ferrum2_runtime::MIN_UDP_IDLE_TIMEOUT,
            )
            .expect("limits"),
            registry,
        );
        let session = manager
            .reserve_session(tokio::time::Instant::now())
            .expect("session");
        let datagram = session
            .reserve_datagram(UdpDirection::ToTarget, 777)
            .expect("buffer");
        let snapshot = control.snapshot();
        let metrics = snapshot["metrics"].as_str().expect("dashboard metrics");
        assert!(metrics.contains("ferrum2_udp_sessions_active{role=\"client\"} 1"));
        assert!(metrics.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 777"));
        drop(datagram);
        drop(session);
        let snapshot = control.snapshot();
        let metrics = snapshot["metrics"].as_str().expect("dashboard metrics");
        assert!(metrics.contains("ferrum2_udp_sessions_active{role=\"client\"} 0"));
        assert!(metrics.contains("ferrum2_udp_buffered_bytes{role=\"client\"} 0"));
    }
}
