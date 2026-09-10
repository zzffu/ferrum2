import { useEffect, useMemo, useState } from "react";
import { preferences as savePreferences, useDashboard } from "../store";
import {
  Confirm,
  Empty,
  Pager,
  Panel,
  Structured,
  useAction,
} from "../components";
import {
  capture,
  domain,
  hops,
  key,
  searchable,
  type ConnectionRecord,
} from "./model";
import { ConnectionDetail } from "./detail";
import { ConnectionTable } from "./table";
import "./style.css";

export function Connections() {
  const { snapshot: s, busy, error, hidden, preferences } = useDashboard();
  const action = useAction();
  const [history, setHistory] = useState(false);
  const [frozen, setFrozen] = useState<{
    records: ConnectionRecord[];
    omitted: number;
  } | null>(null);
  const [search, setSearch] = useState("");
  const [transport, setTransport] = useState("all");
  const [application, setApplication] = useState("all");
  const [outbound, setOutbound] = useState("all");
  const [sort, setSort] = useState("duration");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<ConnectionRecord | null>(null);
  const [confirmation, setConfirmation] = useState<{
    ids: string[];
    generation: string;
    all?: boolean;
  } | null>(null);
  useEffect(() => {
    setSelected(new Set());
    setConfirmation(null);
  }, [s?.generation]);
  const records = useMemo(
    () => frozen?.records ?? (s ? capture(s, history) : []),
    [frozen, s, history],
  );
  const indexed = useMemo(
    () =>
      records.map((record) => ({
        record,
        search: searchable(record),
        hops: hops(record),
      })),
    [records],
  );
  const outbounds = useMemo(
    () =>
      [...new Set(indexed.flatMap((r) => r.hops.map((h) => h.name)))].sort(),
    [indexed],
  );
  const filtered = useMemo(() => {
    const query = search.toLowerCase();
    return indexed
      .filter(
        ({ record: { row: c }, search: text, hops: path }) =>
          (transport === "all" || c.protocol.toLowerCase() === transport) &&
          (application === "all" ||
            (application === "unrecorded"
              ? !c.decision?.sniff.protocol &&
                c.decision?.sniff.status !== "redacted"
              : application === "redacted"
                ? c.decision?.sniff.status === "redacted"
                : c.decision?.sniff.protocol === application)) &&
          (outbound === "all" || path.some((h) => h.name === outbound)) &&
          text.includes(query),
      )
      .map((r) => r.record)
      .sort((a, b) => {
        if (sort === "target")
          return (domain(a)?.name ?? a.row.target ?? "").localeCompare(
            domain(b)?.name ?? b.row.target ?? "",
          );
        if (sort === "bytes") {
          const left =
            BigInt(a.row.upload_bytes) + BigInt(a.row.download_bytes);
          const right =
            BigInt(b.row.upload_bytes) + BigInt(b.row.download_bytes);
          return left === right ? 0 : left > right ? -1 : 1;
        }
        return b.row.duration_ms - a.row.duration_ms;
      });
  }, [indexed, search, transport, application, outbound, sort]);
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(filtered.length / 50) - 1),
  );
  const liveIds = useMemo(
    () => new Set(s?.connections.map((c) => `${c.generation}:${c.id}`)),
    [s],
  );
  const canClose =
    !!s &&
    !error &&
    !hidden &&
    !busy &&
    !history &&
    s.state === "running" &&
    !records.some(
      (record) =>
        record.row.generation !== s.generation || !liveIds.has(key(record)),
    ) &&
    !!s.domains.capabilities?.includes("connections.close");
  const omitted = frozen?.omitted ?? s?.omitted_connections ?? 0;
  const selectable = records.filter((r) => selected.has(key(r)));
  function switchHistory(next: boolean) {
    if (next === history) return;
    setHistory(next);
    setFrozen(null);
    setPage(0);
    setSelected(new Set());
    setConfirmation(null);
  }
  function confirm(rows: ConnectionRecord[]) {
    if (canClose && s && rows.length)
      setConfirmation({
        ids: rows.map((r) => r.row.id),
        generation: s.generation,
      });
  }
  return (
    <>
      <Panel
        title="连接观测"
        action={
          <button
            onClick={() => setFrozen(frozen ? null : { records, omitted })}
          >
            {frozen ? "恢复实时显示" : "暂停显示"}
          </button>
        }
      >
        <div
          className="segments connection-modes"
          role="group"
          aria-label="连接记录类型"
        >
          <button aria-pressed={!history} onClick={() => switchHistory(false)}>
            活动连接 <span>{s?.connections.length ?? 0}</span>
          </button>
          <button aria-pressed={history} onClick={() => switchHistory(true)}>
            已关闭记录 <span>{s?.history.length ?? 0}</span>
          </button>
        </div>
        <div className="toolbar connection-filters">
          <input
            aria-label="搜索连接"
            placeholder="搜索域名、地址、出站、完整规则或 ID"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
          <select
            aria-label="传输协议筛选"
            value={transport}
            onChange={(e) => {
              setTransport(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部传输</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
          <select
            aria-label="应用协议筛选"
            value={application}
            onChange={(e) => {
              setApplication(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部应用</option>
            <option value="tls">TLS</option>
            <option value="http">HTTP</option>
            <option value="dns">DNS</option>
            <option value="unrecorded">应用未记录</option>
            <option value="redacted">详情已隐藏</option>
          </select>
          <select
            aria-label="出站筛选"
            value={outbound}
            onChange={(e) => {
              setOutbound(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部实际出站</option>
            {!outbounds.includes(outbound) && outbound !== "all" && (
              <option value={outbound}>{outbound}（当前无记录）</option>
            )}
            {outbounds.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <select
            aria-label="连接排序"
            value={sort}
            onChange={(e) => {
              setSort(e.target.value);
              setPage(0);
            }}
          >
            <option value="duration">持续时间 ↓</option>
            <option value="bytes">总流量 ↓</option>
            <option value="target">目标 A–Z</option>
          </select>
        </div>
        <div className="connection-list-meta">
          <p role="status">
            匹配 <strong>{filtered.length}</strong> / 已采集{" "}
            <strong>{records.length}</strong> · 活动观测遗漏{" "}
            <strong>{omitted}</strong>
            {history && " · 历史仅保留有限容量与时效内的记录"}
          </p>
          <details className="connection-columns">
            <summary>可选列</summary>
            <div>
              <label>
                <input
                  type="checkbox"
                  checked={preferences.addresses}
                  onChange={(e) =>
                    savePreferences({ addresses: e.target.checked })
                  }
                />
                原始目标地址
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={preferences.connectionSource}
                  onChange={(e) =>
                    savePreferences({ connectionSource: e.target.checked })
                  }
                />
                源地址
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={preferences.connectionDiagnostics}
                  onChange={(e) =>
                    savePreferences({ connectionDiagnostics: e.target.checked })
                  }
                />
                诊断（ID / 嗅探状态）
              </label>
              <small>仅保存列偏好；搜索始终覆盖全部已授权字段。</small>
            </div>
          </details>
        </div>
        {!history && (
          <div className="actions">
            <button
              disabled={!canClose || !selectable.length}
              onClick={() => confirm(selectable)}
            >
              关闭选中 ({selectable.length})
            </button>
            <button
              disabled={!canClose || !filtered.length}
              onClick={() => confirm(filtered)}
            >
              关闭当前筛选 ({filtered.length})
            </button>
            <button
              className="danger-button"
              disabled={
                !canClose ||
                !s?.domains.capabilities?.includes("connections.close_all")
              }
              onClick={() => {
                if (canClose && s)
                  setConfirmation({
                    ids: [],
                    generation: s.generation,
                    all: true,
                  });
              }}
            >
              关闭所有活动连接
            </button>
          </div>
        )}
        {!history && !canClose && (
          <p className="muted">
            关闭不可用：
            {busy
              ? "另一操作正在执行"
              : error || hidden
                ? "快照已过期"
                : "当前记录与运行代不匹配，或运行时未提供关闭能力"}
          </p>
        )}
        {frozen && (
          <p className="notice">
            仅暂停显示；后台快照、历史与流量采样继续更新。记录及目录已一起固定。
          </p>
        )}
        {s && !s.details && (
          <p className="notice">
            未开启敏感详情：地址、请求 /
            嗅探域名和规则条件已隐藏，不代表未匹配。不会自动启用嗅探或查询域名。
          </p>
        )}
        {omitted > 0 && (
          <p className="notice">
            观测达到容量上限；此列表不代表全部连接。全部关闭包括未展示的活动连接。
          </p>
        )}
        <ConnectionTable
          records={filtered.slice(currentPage * 50, currentPage * 50 + 50)}
          history={history}
          preferences={preferences}
          selected={selected}
          canClose={canClose}
          detail={setDetail}
          close={(r) => confirm([r])}
          select={(r, checked) =>
            setSelected((prev) => {
              const next = new Set(prev);
              if (checked) next.add(key(r));
              else next.delete(key(r));
              return next;
            })
          }
        />
        {!filtered.length && <Empty>当前筛选没有可显示的连接</Empty>}
        <Pager count={filtered.length} page={currentPage} setPage={setPage} />
        {action.feedback}
      </Panel>
      {detail && (
        <ConnectionDetail record={detail} close={() => setDetail(null)} />
      )}
      {confirmation &&
        canClose &&
        confirmation.generation === s?.generation && (
          <Confirm
            title={
              confirmation.all
                ? "确认关闭所有活动连接？"
                : `确认关闭 ${confirmation.ids.length} 条连接？`
            }
            busy={busy}
            close={() => setConfirmation(null)}
            accept={() => {
              const fixed = confirmation;
              setConfirmation(null);
              if (
                !canClose ||
                fixed.generation !== s?.generation ||
                (fixed.all &&
                  !s.domains.capabilities?.includes("connections.close_all"))
              )
                return;
              void action.run(
                fixed.all
                  ? { action: "connections.close_all" }
                  : { action: "connections.close", ids: fixed.ids },
                fixed.generation,
              );
            }}
          >
            <p>
              {confirmation.all
                ? "关闭执行时该运行代的全部活动连接，包括未展示及确认后新到达的连接。"
                : "仅发送以下固定 ID，不随刷新或筛选变化。"}
              运行代变化将拒绝请求；取消信号不代表清理已完成。
            </p>
            <Structured value={confirmation} />
          </Confirm>
        )}
    </>
  );
}
