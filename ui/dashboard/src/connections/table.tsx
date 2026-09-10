import type { Preferences } from "../store";
import { bytes, duration } from "../components";
import {
  association,
  domain,
  hops,
  key,
  missing,
  pathAbsence,
  routeSummary,
  sniffStatuses,
  type ConnectionRecord,
} from "./model";

export function ConnectionTable({
  records,
  history,
  preferences,
  selected,
  canClose,
  detail,
  close,
  select,
}: {
  records: ConnectionRecord[];
  history: boolean;
  preferences: Preferences;
  selected: Set<string>;
  canClose: boolean;
  detail: (record: ConnectionRecord) => void;
  close: (record: ConnectionRecord) => void;
  select: (record: ConnectionRecord, checked: boolean) => void;
}) {
  return (
    <div className="table-scroll connection-table-scroll">
      <table className="connection-table">
        <thead>
          <tr>
            {!history && <th>选择</th>}
            <th>目标 / 域名</th>
            <th>协议 / 入口</th>
            {preferences.connectionSource && <th>源地址</th>}
            <th>实际出站 / 规则</th>
            <th>上传 / 下载</th>
            <th>持续 / 状态</th>
            {preferences.connectionDiagnostics && <th>诊断</th>}
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record) => {
            const c = record.row;
            const observed = domain(record);
            const path = hops(record);
            const summary = routeSummary(record);
            return (
              <tr key={key(record)}>
                {!history && (
                  <td data-label="选择">
                    <input
                      type="checkbox"
                      aria-label={`选择连接 ${c.id}`}
                      disabled={!canClose}
                      checked={selected.has(key(record))}
                      onChange={(e) => select(record, e.target.checked)}
                    />
                  </td>
                )}
                <td data-label="目标 / 域名" className="connection-target">
                  <button
                    className="connection-target-button"
                    title={observed?.name ?? c.target ?? missing(record)}
                    onClick={() => detail(record)}
                  >
                    {observed?.name ?? c.target ?? missing(record)}
                  </button>
                  <small
                    className="connection-origin"
                    title={association(record)}
                  >
                    {observed?.provenance ?? "原始目标"}
                    {c.protocol.toLowerCase() === "udp" && " · UDP 关联"}
                  </small>
                  {preferences.addresses && observed && (
                    <small
                      className="connection-address"
                      title={c.target ?? missing(record)}
                    >
                      原始目标 · {c.target ?? missing(record)}
                    </small>
                  )}
                </td>
                <td data-label="协议 / 入口">
                  <div className="connection-badges">
                    <span>{c.protocol.toUpperCase()}</span>
                    {c.decision?.sniff.protocol && (
                      <span className="observed">
                        {c.decision.sniff.protocol.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <small>
                    {c.inbound_tag ?? c.inbound}
                    {c.inbound_tag && ` · ${c.inbound}`}
                  </small>
                </td>
                {preferences.connectionSource && (
                  <td data-label="源地址" className="connection-address">
                    {c.source ?? missing(record)}
                  </td>
                )}
                <td
                  data-label="实际出站 / 规则"
                  className="connection-provenance"
                >
                  <strong
                    className="connection-outbound"
                    title={
                      path.length
                        ? path.map((h) => h.name).join(" → ")
                        : pathAbsence(record)
                    }
                  >
                    {path.length
                      ? path.map((h) => h.name).join(" → ")
                      : pathAbsence(record)}
                  </strong>
                  <small className="connection-route" title={summary}>
                    {summary}
                  </small>
                </td>
                <td data-label="上传 / 下载" className="connection-traffic">
                  <span className="up">↑ {bytes(c.upload_rate)}/s</span>
                  <small>累计 {bytes(c.upload_bytes)}</small>
                  <span className="down">↓ {bytes(c.download_rate)}/s</span>
                  <small>累计 {bytes(c.download_bytes)}</small>
                </td>
                <td data-label="持续 / 状态">
                  {duration(c.duration_ms)}
                  <small>{c.state}</small>
                </td>
                {preferences.connectionDiagnostics && (
                  <td data-label="诊断">
                    <span>
                      #{c.id} · 代 {c.generation}
                    </span>
                    <small>
                      {c.decision
                        ? sniffStatuses[c.decision.sniff.status][0]
                        : "决策未记录"}
                    </small>
                  </td>
                )}
                <td data-label="操作">
                  <button
                    onClick={() => detail(record)}
                    aria-label={`查看连接 ${c.id}`}
                  >
                    详情
                  </button>
                  {!history && (
                    <button disabled={!canClose} onClick={() => close(record)}>
                      关闭
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
