// Generated from crates/ferrum2-dashboard/src/wire.rs; run bun scripts/wire.ts.
export interface CommandRequest { generation: string; command: Command; }
export type Command =
  { action: "runtime.start";  } |
  { action: "runtime.stop";  } |
  { action: "runtime.restart";  } |
  { action: "connections.close"; ids: Array<string>; } |
  { action: "connections.close_all";  } |
  { action: "selectors.select"; selector: number; member: number; } |
  { action: "outbounds.probe"; outbound: number; host: string; port: number; } |
  { action: "routes.test"; host: string; port: number; protocol: Network; inbound: number; } |
  { action: "rulesets.refresh"; index: number; } |
  { action: "dns.clear";  } |
  { action: "dns.query"; name: string; qtype: QueryType; server: number | null; } |
  { action: "config.validate"; source: string; } |
  { action: "config.save"; source: string; revision: string; } |
  { action: "config.apply"; source: string; revision: string; } |
  { action: "diagnostics.export";  };
export type Network =
  "tcp" |
  "udp";
export type QueryType =
  "A" |
  "AAAA";
export type CommandResult =
  { kind: "runtime"; state: RuntimeState; } |
  { kind: "connections"; requested: number; } |
  { kind: "validated"; valid: boolean; materialized: boolean; } |
  { kind: "config"; revision: string; state: ConfigState; } |
  { kind: "selected"; selected: number; generation: string; } |
  { kind: "probe"; outbound: number; host: string; port: number; measurement: Measurement; elapsed_ms: number; transport_closed: boolean; graceful_shutdown: boolean; } |
  { kind: "route"; action: RouteSelection; final_action: boolean; rule_index: number | null; rule_generation: string | null; missing_metadata: Array<string>; sniff_requested: boolean; network_lookup: boolean; } |
  { kind: "refresh"; outcome: RefreshResult; } |
  { kind: "dns_cleared"; removed: number; inflight_queries_may_repopulate: boolean; } |
  { kind: "dns_query"; path: DnsPath; response_code: string; answers: Array<DnsAnswer>; truncated: boolean; } |
  { kind: "diagnostics"; version: string; generation: unknown; state: unknown; error: unknown; traffic: unknown; resources: unknown; process: unknown; logs: unknown; metrics: unknown; };
export type RuntimeState =
  "starting" |
  "stopped";
export type ConfigState =
  "starting" |
  "saved";
export type Measurement =
  "transport_connect";
export type RouteSelection =
  { kind: "route"; hops: Array<number>; } |
  { kind: "hijack_dns";  } |
  { kind: "reject";  };
export type DnsPath =
  { kind: "tagged_server"; server: number; } |
  { kind: "ordinary_policy"; inbound: number; };
export interface DnsAnswer { name: string; ttl: number; record_type: string; data: string; }
export type RefreshResult =
  { status: "updated"; previous_generation: string; generation: string; } |
  { status: "unchanged";  } |
  { status: "degraded"; retained_previous: boolean; reason: string; } |
  { status: "failed"; retained_previous: boolean; reason: string; };
