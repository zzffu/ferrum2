import type {
  ConnectionCatalogView,
  ConnectionView,
  Snapshot,
} from "../protocol";
import type { ConnectionRuleView, ConnectionSniffStatus } from "../wire";

// Every interpretation travels with the immutable catalog captured for this row.
export interface ConnectionRecord {
  row: ConnectionView;
  catalog: ConnectionCatalogView | null;
  details: boolean;
}
export function capture(
  snapshot: Snapshot,
  history: boolean,
): ConnectionRecord[] {
  const catalogs = new Map(snapshot.connection_catalogs.map((c) => [c.id, c]));
  return (history ? snapshot.history : snapshot.connections).map((row) => ({
    row,
    catalog:
      row.catalog_id == null ? null : (catalogs.get(row.catalog_id) ?? null),
    details: snapshot.details && row.decision?.sniff.status !== "redacted",
  }));
}
export const key = ({ row }: ConnectionRecord) => `${row.generation}:${row.id}`;
export const sniffStatuses: Record<ConnectionSniffStatus, [string, string]> = {
  not_requested: ["未请求", "未到达嗅探动作；不表示载荷已被检查。"],
  not_executed: ["未执行", "到达嗅探动作，但此处理路径未执行载荷嗅探。"],
  matched: ["已识别", "识别到应用协议；即使没有域名，也不等于未匹配。"],
  no_match: ["未匹配", "已检查可用载荷，未识别到受支持协议。"],
  invalid: ["无效载荷", "嗅探载荷无效，不能据此声明应用协议或域名。"],
  timeout: ["超时", "已有嗅探时间预算耗尽。"],
  limit: ["达到上限", "已有嗅探载荷收集上限已达到。"],
  unavailable: ["资源不足", "嗅探缓冲预算不足，未取得载荷收集资源。"],
  cancelled: ["已取消", "载荷收集或连接处理被取消。"],
  read_error: ["读取失败", "载荷收集发生读取错误。"],
  redacted: ["详情已隐藏", "未授权详细观测；不是未匹配或没有域名。"],
};
export const decisionKinds = {
  route: "路由",
  reject: "拒绝",
  hijack_dns: "DNS 接管",
  tun_dns: "TUN DNS 接管",
  aborted: "处理终止",
};
export function missing(record: ConnectionRecord) {
  return record.details ? "未记录" : "详情已隐藏";
}
export function domain(
  record: ConnectionRecord,
): { name: string; provenance: string } | null {
  const c = record.row;
  if (c.requested_domain)
    return { name: c.requested_domain, provenance: "请求域名" };
  if (!c.decision?.sniff.domain) return null;
  const labels = {
    tls: "TLS SNI",
    http: "HTTP Host / CONNECT",
    dns: "DNS 首个普通查询",
  };
  return {
    name: c.decision.sniff.domain,
    provenance: c.decision.sniff.protocol
      ? labels[c.decision.sniff.protocol]
      : "嗅探域名（协议未记录）",
  };
}
export function association(record: ConnectionRecord) {
  return record.row.protocol.toLowerCase() === "udp"
    ? "UDP 关联：原始目标及首次普通决策证据；不代表后续每个数据报或所有流量的域名。"
    : "连接建立时的请求 / 嗅探证据，不表示每个数据包都包含该域名。";
}
export function hops(record: ConnectionRecord) {
  return (record.row.decision?.hops ?? []).map((index) => ({
    index,
    name:
      record.catalog?.outbounds.find((o) => o.index === index)?.tag ??
      `未知出站 #${index + 1}`,
  }));
}
export function pathAbsence(record: ConnectionRecord) {
  const kind = record.row.decision?.kind;
  if (!kind || kind === "route") return "未记录具体路径";
  return kind === "aborted" ? "未建立出站" : decisionKinds[kind];
}
export function rule(
  record: ConnectionRecord,
  index: number | null | undefined,
) {
  return index == null
    ? null
    : (record.catalog?.rules.find((r) => r.index === index) ?? null);
}
export function ruleText(value: ConnectionRuleView) {
  const conditions = value.conditions
    .map(
      (c) =>
        `${c.field}: ${typeof c.value === "string" ? c.value : JSON.stringify(c.value)}`,
    )
    .join(" · ");
  const label =
    value.origin === "inbound" ? "入口默认出站" : `规则 #${value.index + 1}`;
  return `${label} ${conditions || "无附加条件"} → ${value.action}${value.outbound ? ` · ${value.outbound}` : ""}${value.sniffers.length ? ` · ${value.sniffers.join(", ")}` : ""}`;
}
export function routeSummary(record: ConnectionRecord) {
  const d = record.row.decision;
  if (!d) return "决策未记录";
  if (!record.details) return `${decisionKinds[d.kind]} · 规则详情已隐藏`;
  if (d.rule_index == null)
    return d.kind === "route"
      ? "最终出站（无规则命中）"
      : decisionKinds[d.kind];
  const matched = rule(record, d.rule_index);
  return matched
    ? ruleText(matched)
    : `未知规则 #${d.rule_index + 1} · ${decisionKinds[d.kind]}`;
}
export function searchable(record: ConnectionRecord) {
  const d = record.row.decision;
  // Search every authorized row field and its referenced rules, independent of visible columns.
  return [
    JSON.stringify(record.row),
    domain(record)?.provenance,
    association(record),
    hops(record)
      .map((h) => h.name)
      .join(" "),
    routeSummary(record),
    d ? sniffStatuses[d.sniff.status].join(" ") : "决策未记录",
    JSON.stringify(rule(record, d?.sniff.rule_index)),
    d?.kind === "route" && d.rule_index == null
      ? record.catalog?.final_outbound
      : "",
  ]
    .join(" ")
    .toLowerCase();
}
