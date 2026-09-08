use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use ferrum2_config::RouteAction;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanHandle, Network};
use ferrum2_dns::{DnsCache, DnsProxy, ProxyIngress, ProxyTransport, TaggedResolver};
use ferrum2_observability::Metrics;
use ferrum2_rule::{RouteMetadata, RouteProgramAction};
use ferrum2_ruleset::{RuleSetDownloader, RuleSetRefreshOutcome, RuleSetRefreshService};
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
        json!({"available":true,"selectors":selectors,"rulesets":rulesets,"dns_cache":cache,"metrics":self.metrics.encode_text().ok(),"capabilities":capabilities})
    }

    pub(crate) async fn command(&self, request: &Value) -> Result<Value, &'static str> {
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

    async fn dispatch(&self, request: &Value) -> Result<Value, &'static str> {
        match request
            .get("action")
            .and_then(Value::as_str)
            .ok_or("invalid_action")?
        {
            "selectors.select" => {
                let rows = self.routing.selector.snapshot();
                let row = rows
                    .get(index(request, "selector")?)
                    .ok_or("invalid_selector")?;
                let member = row
                    .members
                    .get(index(request, "member")?)
                    .ok_or("invalid_member")?;
                self.routing
                    .selector
                    .switch(&row.name, member)
                    .map_err(|_| "selection_failed")?;
                Ok(
                    json!({"selected":index(request,"member")?,"generation":self.routing.selector.generation().to_string()}),
                )
            }
            "outbounds.probe" => {
                let outbound = index(request, "outbound")?;
                if outbound >= self.routing.outbounds.len() {
                    return Err("invalid_outbound");
                }
                let target = target(request)?;
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
                Ok(
                    json!({"outbound":outbound,"host":text(request,"host")?,"port":target.port().get(),"measurement":"transport_connect","elapsed_ms":elapsed,"transport_closed":true,"graceful_shutdown":matches!(closed,Ok(Ok(())))}),
                )
            }
            "routes.test" => self.route_trial(request),
            "rulesets.refresh" => {
                let refresh = self.refresh.as_ref().ok_or("unavailable")?;
                let index = index(request, "index")?;
                if index >= refresh.snapshot().len() {
                    return Err("invalid_ruleset");
                }
                Ok(refresh_result(refresh.refresh_once(index).await))
            }
            "dns.clear" => {
                let removed = self
                    .cache
                    .as_ref()
                    .ok_or("unavailable")?
                    .clear()
                    .map_err(|_| "cache_unavailable")?;
                Ok(json!({"removed":removed,"inflight_queries_may_repopulate":true}))
            }
            "dns.query" => self.dns_query(request).await,
            _ => Err("invalid_action"),
        }
    }

    fn route_trial(&self, request: &Value) -> Result<Value, &'static str> {
        let target = target(request)?;
        let inbound = index(request, "inbound")?;
        if inbound >= self.inbound_count {
            return Err("invalid_inbound");
        }
        let network = match text(request, "protocol")? {
            "tcp" => Network::Tcp,
            "udp" => Network::Udp,
            _ => return Err("invalid_protocol"),
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
                RouteAction::Route(handle) => {
                    json!({"kind":"route","hops":handle.snapshot_owned().hops()})
                }
                RouteAction::HijackDns => json!({"kind":"hijack_dns"}),
                RouteAction::Reject => json!({"kind":"reject"}),
                RouteAction::Sniff(_) => return Err("route_unavailable"),
            };
            return Ok(
                json!({"action":selected,"final":final_action,"rule_index":evaluation.selected_rule_index(),"rule_generation":evaluation.snapshot_generation().map(|generation|generation.to_string()),"missing_metadata":["sniff_protocol","sniff_domain","dns_resolution"],"sniff_requested":sniff_requested,"network_lookup":false}),
            );
        }
    }

    async fn dns_query(&self, request: &Value) -> Result<Value, &'static str> {
        let name = text(request, "name")?;
        ferrum2_core::CanonicalDomain::new(name).map_err(|_| "invalid_name")?;
        let name = Name::from_ascii(name).map_err(|_| "invalid_name")?;
        let qtype = match text(request, "qtype")? {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            _ => return Err("invalid_qtype"),
        };
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name, qtype));
        let (response, path) = if request.get("server").is_some_and(|value| !value.is_null()) {
            let server = index(request, "server")?;
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
                json!({"kind":"tagged_server","server":server}),
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
                json!({"kind":"ordinary_policy","inbound":0}),
            )
        };
        let answers:Vec<_> = response.answers.iter().take(256).map(|record|json!({"name":record.name.to_string(),"ttl":record.ttl,"type":record.data.record_type().to_string(),"data":record.data.to_string()})).collect();
        Ok(
            json!({"path":path,"response_code":response.metadata.response_code.to_string(),"answers":answers,"truncated":response.metadata.truncation || response.answers.len()>256}),
        )
    }
}

fn text<'a>(request: &'a Value, field: &str) -> Result<&'a str, &'static str> {
    request
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or("invalid_input")
}
fn index(request: &Value, field: &str) -> Result<usize, &'static str> {
    request
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("invalid_input")
}
fn target(request: &Value) -> Result<TargetAddr, &'static str> {
    let host = text(request, "host")?;
    let port = u16::try_from(index(request, "port")?).map_err(|_| "invalid_port")?;
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => TargetAddr::ip(std::net::SocketAddr::new(ip, port)),
        Err(_) => {
            ferrum2_core::CanonicalDomain::new(host).map_err(|_| "invalid_host")?;
            TargetAddr::domain(host, port)
        }
    }
    .map_err(|_| "invalid_target")
}
fn refresh_result(outcome: RuleSetRefreshOutcome) -> Value {
    match outcome {
        RuleSetRefreshOutcome::Updated {
            previous_generation,
            generation,
        } => {
            json!({"status":"updated","previous_generation":previous_generation.to_string(),"generation":generation.to_string()})
        }
        RuleSetRefreshOutcome::NotModified => json!({"status":"unchanged"}),
        RuleSetRefreshOutcome::RetainedCache(reason) => {
            json!({"status":"degraded","retained_previous":true,"reason":format!("{reason:?}")})
        }
        RuleSetRefreshOutcome::Failed(reason) => {
            json!({"status":"failed","retained_previous":true,"reason":format!("{reason:?}")})
        }
    }
}
