//! Dashboard control wire types. This crate deliberately has no runtime dependencies.
//! The UI build derives its command/result declarations from this file.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub generation: String,
    pub command: Command,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum Command {
    #[serde(rename = "runtime.start")]
    RuntimeStart {},
    #[serde(rename = "runtime.stop")]
    RuntimeStop {},
    #[serde(rename = "runtime.restart")]
    RuntimeRestart {},
    #[serde(rename = "connections.close")]
    ConnectionsClose { ids: Vec<String> },
    #[serde(rename = "connections.close_all")]
    ConnectionsCloseAll {},
    #[serde(rename = "selectors.select")]
    SelectorsSelect { selector: usize, member: usize },
    #[serde(rename = "outbounds.probe")]
    OutboundsProbe {
        outbound: usize,
        host: String,
        port: u16,
    },
    #[serde(rename = "routes.test")]
    RoutesTest {
        host: String,
        port: u16,
        protocol: Network,
        inbound: usize,
    },
    #[serde(rename = "rulesets.refresh")]
    RulesetsRefresh { index: usize },
    #[serde(rename = "dns.clear")]
    DnsClear {},
    #[serde(rename = "dns.query")]
    DnsQuery {
        name: String,
        qtype: QueryType,
        server: Option<usize>,
    },
    #[serde(rename = "config.validate")]
    ConfigValidate { source: String },
    #[serde(rename = "config.save")]
    ConfigSave { source: String, revision: String },
    #[serde(rename = "config.apply")]
    ConfigApply { source: String, revision: String },
    #[serde(rename = "diagnostics.export")]
    DiagnosticsExport {},
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum QueryType {
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandResult {
    Runtime {
        state: RuntimeState,
    },
    Connections {
        requested: usize,
    },
    Validated {
        valid: bool,
        materialized: bool,
    },
    Config {
        revision: String,
        state: ConfigState,
    },
    Selected {
        selected: usize,
        generation: String,
    },
    Probe {
        outbound: usize,
        host: String,
        port: u16,
        measurement: Measurement,
        elapsed_ms: f64,
        transport_closed: bool,
        graceful_shutdown: bool,
    },
    Route {
        action: RouteSelection,
        final_action: bool,
        rule_index: Option<usize>,
        rule_generation: Option<String>,
        missing_metadata: Vec<String>,
        sniff_requested: bool,
        network_lookup: bool,
    },
    Refresh {
        outcome: RefreshResult,
    },
    DnsCleared {
        removed: usize,
        inflight_queries_may_repopulate: bool,
    },
    DnsQuery {
        path: DnsPath,
        response_code: String,
        answers: Vec<DnsAnswer>,
        truncated: bool,
    },
    Diagnostics {
        version: String,
        generation: serde_json::Value,
        state: serde_json::Value,
        error: serde_json::Value,
        traffic: serde_json::Value,
        resources: serde_json::Value,
        process: serde_json::Value,
        logs: serde_json::Value,
        metrics: serde_json::Value,
    },
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Starting,
    Stopped,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigState {
    Starting,
    Saved,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Measurement {
    TransportConnect,
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteSelection {
    Route { hops: Vec<usize> },
    HijackDns {},
    Reject {},
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DnsPath {
    TaggedServer { server: usize },
    OrdinaryPolicy { inbound: usize },
}
#[derive(Debug, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub ttl: u32,
    pub record_type: String,
    pub data: String,
}
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RefreshResult {
    Updated {
        previous_generation: String,
        generation: String,
    },
    Unchanged {},
    Degraded {
        retained_previous: bool,
        reason: String,
    },
    Failed {
        retained_previous: bool,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_admission_rejects_ambiguous_or_untyped_payloads() {
        for source in [
            r#"{"generation":"1","action":"runtime.stop"}"#,
            r#"{"generation":"1","command":{"action":"runtime.stop","source":"unexpected"}}"#,
            r#"{"generation":"1","command":{"action":"runtime.stop","action":"runtime.start"}}"#,
            r#"{"generation":"1","command":{"action":"dns.query","name":"example.test","qtype":"MX","server":null}}"#,
            r#"{"generation":"1","command":{"action":"selectors.select","selector":-1,"member":0}}"#,
            r#"{"generation":"1","command":{"action":"outbounds.probe","outbound":0,"host":"example.test","port":65536}}"#,
        ] {
            assert!(serde_json::from_str::<CommandRequest>(source).is_err());
        }
        let request: CommandRequest = serde_json::from_str(
            r#"{"generation":"18446744073709551615","command":{"action":"dns.query","name":"example.test","qtype":"AAAA","server":null}}"#,
        ).expect("typed query");
        assert_eq!(request.generation, u64::MAX.to_string());
        assert!(matches!(
            request.command,
            Command::DnsQuery {
                qtype: QueryType::Aaaa,
                server: None,
                ..
            }
        ));
    }
}
