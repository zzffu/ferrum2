import type { Command, ConnectionView, ConnectionCatalogView } from "./wire";
// Shared implementation contract. Decimal strings carry Rust u64 values.
export interface LogView {
  id: string;
  elapsed_ms: number;
  level: string;
  event: unknown;
}
export interface Catalog {
  inbounds: Record<string, unknown>[];
  outbounds: Record<string, unknown>[];
  selectors: Record<string, unknown>[];
  chains: Record<string, unknown>[];
  route: Record<string, unknown>;
  dns: Record<string, unknown> | null;
  tun: Record<string, unknown> | null;
  rocom: Record<string, unknown> | null;
}
export interface Snapshot {
  version: 2;
  generation: string;
  state: "stopped" | "starting" | "running" | "stopping" | "failed";
  error: string | null;
  details: boolean;
  uptime_ms: number;
  traffic: {
    upload_bytes: string;
    download_bytes: string;
    upload_rate: number;
    download_rate: number;
  };
  process: { cpu_percent: number | null; memory_bytes: string | null };
  connections: ConnectionView[];
  history: ConnectionView[];
  connection_catalogs: ConnectionCatalogView[];
  omitted_connections: number;
  active_connections: number;
  active_tcp: number;
  active_udp: number;
  logs: LogView[];
  resources: Record<string, number | string | null>;
  catalog: Catalog | null;
  domains: {
    selectors?: {
      id: number;
      name: string;
      selected: number;
      members: { id: number; name: string }[];
    }[];
    rulesets?: Record<string, unknown>[];
    dns_cache?: Record<string, unknown> | null;
    metrics?: string | null;
    capabilities?: Command["action"][];
  };
}
export type {
  Command,
  CommandRequest,
  CommandResult,
  ConnectionView,
  ConnectionCatalogView,
} from "./wire";
// HTTP: GET /api/snapshot, GET /api/config -> {source:string,revision:string,running_revision:string|null}
// POST /api/command: CommandRequest -> {result:CommandResult}.
// Failures -> {error:{code:string}}, status 400/401/403/409/413/429/500/503.
// All APIs require Authorization Bearer (token only in memory), same-origin.
// Runtime-only domain capabilities are published only while their real handle is available.
