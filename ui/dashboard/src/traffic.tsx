import { useEffect, useMemo, useState } from "react";
import { useDashboard } from "./store";
import type { ConnectionView } from "./protocol";
import {
  bytes,
  duration,
  Panel,
  Structured,
  Empty,
  Pager,
  Confirm,
  useAction,
} from "./components";

export function Overview() {
  const { snapshot: s, samples } = useDashboard();
  const [minutes, setMinutes] = useState(5);
  if (!s) return <Empty>等待首个运行时快照…</Empty>;
  const now = samples.at(-1)?.at ?? Date.now();
  const recent = samples.filter((p) => p.at >= now - minutes * 60000);
  const ceiling = Math.max(1, ...recent.map((p) => Math.max(p.up, p.down)));
  const points = (direction: "up" | "down") =>
    recent
      .map(
        (p) =>
          `${((p.at - now + minutes * 60000) / (minutes * 60000)) * 1000},${180 - (p[direction] / ceiling) * 160}`,
      )
      .join(" ");
  const cards = [
    [
      "实时上传",
      `${bytes(s.traffic.upload_rate)}/s`,
      `累计 ${bytes(s.traffic.upload_bytes)}`,
    ],
    [
      "实时下载",
      `${bytes(s.traffic.download_rate)}/s`,
      `累计 ${bytes(s.traffic.download_bytes)}`,
    ],
    [
      "活动连接",
      String(s.active_connections),
      `TCP ${s.active_tcp} / UDP ${s.active_udp}`,
    ],
    [
      "进程占用",
      s.process.cpu_percent == null
        ? "CPU 不可用"
        : `${s.process.cpu_percent.toFixed(1)}% CPU`,
      `内存 ${bytes(s.process.memory_bytes)}`,
    ],
  ];
  return (
    <>
      <div className="stats">
        {cards.map(([label, value, note]) => (
          <section className="stat" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
            <small>{note}</small>
          </section>
        ))}
      </div>
      <Panel
        title="流量趋势"
        action={
          <div className="segments">
            {[1, 5, 15].map((n) => (
              <button
                key={n}
                aria-pressed={minutes === n}
                onClick={() => setMinutes(n)}
              >
                {n} 分钟
              </button>
            ))}
          </div>
        }
      >
        <div className="chart-legend">
          <span className="up">上传</span>
          <span className="down">下载</span>
          <span>峰值刻度 {bytes(ceiling)}/s · 成功写入的有效载荷</span>
        </div>
        {recent.length < 2 ? (
          <Empty>正在采集流量趋势；仅显示本标签页收到的真实样本。</Empty>
        ) : (
          <svg
            className="chart"
            viewBox="0 0 1000 200"
            role="img"
            aria-label={`${minutes} 分钟上传及下载速率`}
            preserveAspectRatio="none"
          >
            <path d="M0 20H1000M0 100H1000M0 180H1000" className="gridline" />
            <polyline points={points("down")} className="download-line" />
            <polyline points={points("up")} className="upload-line" />
          </svg>
        )}
        <div className="chart-legend">
          <span>−{minutes} 分钟</span>
          <span>现在 · 隐藏标签页时暂停采样</span>
        </div>
      </Panel>
      <div className="two-col">
        <Panel title="进程与运行代">
          <dl>
            <dt>运行状态</dt>
            <dd>{s.state}</dd>
            <dt>运行代</dt>
            <dd>{s.generation}</dd>
            <dt>运行时间</dt>
            <dd>{duration(s.uptime_ms)}</dd>
            <dt>客户端版本</dt>
            <dd>{s.resources.version ?? "运行时未提供"}</dd>
            <dt>详细观测</dt>
            <dd>{s.details ? "已授权" : "关闭 · 地址保持隐藏"}</dd>
            <dt>观测遗漏</dt>
            <dd>{s.omitted_connections}</dd>
          </dl>
          {s.error && (
            <p role="alert" className="notice danger">
              {s.error}
            </p>
          )}
          <details>
            <summary>资源计数详情</summary>
            <Structured value={s.resources} />
          </details>
        </Panel>
        <Panel title="入口 / DNS / TUN">
          <dl>
            <dt>SOCKS5</dt>
            <dd>{s.state === "running" ? s.resources.socks_state : s.state}</dd>
            <dt>DNS</dt>
            <dd>{s.state === "running" ? s.resources.dns_state : s.state}</dd>
            <dt>TUN</dt>
            <dd>{s.state === "running" ? s.resources.tun_state : s.state}</dd>
          </dl>
          <details>
            <summary>查看配置摘要</summary>
            <Structured
              value={
                s.catalog
                  ? {
                      inbounds: s.catalog.inbounds,
                      dns: s.catalog.dns,
                      tun: s.catalog.tun,
                    }
                  : null
              }
            />
          </details>
        </Panel>
      </div>
      <Panel title="近期错误">
        <Structured
          value={s.logs
            .filter((l) => ["error", "warn"].includes(l.level.toLowerCase()))
            .slice(-5)}
          empty="暂无错误观测"
        />
      </Panel>
    </>
  );
}

export function Connections() {
  const { snapshot: s, busy, error, preferences } = useDashboard();
  const action = useAction();
  const [frozen, setFrozen] = useState<ConnectionView[] | null>(null);
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [history, setHistory] = useState(false);
  const [sort, setSort] = useState("duration");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<ConnectionView | null>(null);
  const [confirmation, setConfirmation] = useState<{
    ids: string[];
    generation: string;
    all?: boolean;
  } | null>(null);
  useEffect(() => {
    setSelected(new Set());
    setConfirmation(null);
  }, [s?.generation]);
  const rows = frozen ?? (history ? s?.history : s?.connections) ?? [];
  const filtered = useMemo(
    () =>
      rows
        .filter(
          (c) =>
            (protocol === "all" || c.protocol.toLowerCase() === protocol) &&
            `${c.id} ${c.inbound} ${c.source ?? ""} ${c.target ?? ""} ${c.route ?? ""} ${c.outbound ?? ""} ${c.state}`
              .toLowerCase()
              .includes(search.toLowerCase()),
        )
        .sort((a, b) =>
          sort === "target"
            ? (a.target ?? "").localeCompare(b.target ?? "")
            : sort === "bytes"
              ? BigInt(a.upload_bytes) + BigInt(a.download_bytes) >
                BigInt(b.upload_bytes) + BigInt(b.download_bytes)
                ? -1
                : 1
              : b.duration_ms - a.duration_ms,
        ),
    [rows, protocol, search, sort],
  );
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(filtered.length / 50) - 1),
  );
  const canClose =
    !!s &&
    !error &&
    !busy &&
    s.state === "running" &&
    !history &&
    !rows.some((c) => c.generation !== s.generation) &&
    s.domains.capabilities?.includes("connections.close");
  function confirm(ids: string[]) {
    if (s && ids.length)
      setConfirmation({ ids: [...ids], generation: s.generation });
  }
  return (
    <>
      <Panel
        title="连接观测"
        action={
          <button onClick={() => setFrozen(frozen ? null : [...rows])}>
            {frozen ? "恢复实时显示" : "暂停显示"}
          </button>
        }
      >
        <div className="toolbar">
          <input
            aria-label="搜索连接"
            placeholder="搜索目标、入口、路由或 ID"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
          <select
            aria-label="协议筛选"
            value={protocol}
            onChange={(e) => {
              setProtocol(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部协议</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
          <select
            aria-label="连接排序"
            value={sort}
            onChange={(e) => setSort(e.target.value)}
          >
            <option value="duration">持续时间 ↓</option>
            <option value="bytes">总流量 ↓</option>
            <option value="target">目标 A–Z</option>
          </select>
          <label>
            <input
              type="checkbox"
              checked={history}
              onChange={(e) => {
                setHistory(e.target.checked);
                setFrozen(null);
                setSelected(new Set());
                setPage(0);
              }}
            />
            关闭历史
          </label>
        </div>
        <div className="actions">
          <button
            disabled={!canClose || !selected.size}
            onClick={() =>
              confirm(
                rows
                  .filter((c) => selected.has(`${c.generation}:${c.id}`))
                  .map((c) => c.id),
              )
            }
          >
            关闭选中 ({selected.size})
          </button>
          <button
            disabled={!canClose || !filtered.length}
            onClick={() => confirm(filtered.map((c) => c.id))}
          >
            关闭当前筛选 ({filtered.length})
          </button>
          <button
            className="danger-button"
            disabled={
              !canClose ||
              !s?.domains.capabilities?.includes("connections.close_all")
            }
            onClick={() =>
              setConfirmation({ ids: [], generation: s!.generation, all: true })
            }
          >
            关闭所有活动连接
          </button>
        </div>
        {!canClose && (
          <p className="muted">
            关闭不可用：
            {history
              ? "历史连接已结束"
              : busy
                ? "另一操作正在执行"
                : error
                  ? "快照已过期"
                  : "当前运行代未提供连接关闭能力"}
          </p>
        )}
        {frozen && (
          <p className="notice">
            显示已冻结；后台仍在更新。关闭请求使用确认时固定的 ID 和运行代。
          </p>
        )}
        {s && !s.details && (
          <p className="notice">
            未开启敏感详情；源地址、目标与路由可能不可用。
          </p>
        )}
        {s && s.omitted_connections > 0 && (
          <p className="notice">
            观测达到容量上限：遗漏 {s.omitted_connections}{" "}
            条。当前列表不代表全部连接；全部关闭会覆盖未展示的活动连接。
          </p>
        )}
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>选择</th>
                <th>协议 / 入口</th>
                {preferences.addresses && <th>源 → 目标</th>}
                <th>出站 / 路由</th>
                <th>上传 / 下载</th>
                <th>持续 / 状态</th>
                <th>详情</th>
              </tr>
            </thead>
            <tbody>
              {filtered
                .slice(currentPage * 50, currentPage * 50 + 50)
                .map((c) => (
                  <tr key={`${c.generation}:${c.id}`}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`选择连接 ${c.id}`}
                        checked={selected.has(`${c.generation}:${c.id}`)}
                        onChange={(e) =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (e.target.checked)
                              next.add(`${c.generation}:${c.id}`);
                            else next.delete(`${c.generation}:${c.id}`);
                            return next;
                          })
                        }
                      />
                    </td>
                    <td>
                      <strong>{c.protocol}</strong>
                      <small>{c.inbound}</small>
                    </td>
                    {preferences.addresses && (
                      <td>
                        {c.source ?? "未提供"}
                        <small>→ {c.target ?? "未提供"}</small>
                      </td>
                    )}
                    <td>
                      {c.outbound ?? "未提供"}
                      <small>{c.route ?? "未提供"}</small>
                    </td>
                    <td>
                      {`${bytes(c.upload_bytes)} · ${bytes(c.upload_rate)}/s`}
                      <small>{`${bytes(c.download_bytes)} · ${bytes(c.download_rate)}/s`}</small>
                    </td>
                    <td>
                      {duration(c.duration_ms)}
                      <small>{c.state}</small>
                    </td>
                    <td>
                      <button onClick={() => setDetail(c)}>查看</button>
                      <button
                        disabled={!canClose}
                        onClick={() => confirm([c.id])}
                      >
                        关闭
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
        {!filtered.length && <Empty>当前筛选没有可显示的连接</Empty>}
        <Pager count={filtered.length} page={currentPage} setPage={setPage} />
        {action.feedback}
      </Panel>
      {detail && (
        <div className="modal-backdrop">
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="连接详情"
          >
            <div className="panel-head">
              <h2>连接详情 · 固定快照</h2>
              <button autoFocus onClick={() => setDetail(null)}>
                关闭
              </button>
            </div>
            <Structured value={detail} />
          </section>
        </div>
      )}
      {confirmation && (
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
            void action.run(
              fixed.all ? "connections.close_all" : "connections.close",
              fixed.all ? {} : { ids: fixed.ids },
              fixed.generation,
            );
          }}
        >
          <p>
            {confirmation.all
              ? "关闭执行时该运行代的全部活动连接，包括未展示的连接和确认后新到达的连接。"
              : "仅发送以下固定 ID。"}
            运行代变化将拒绝请求；取消信号不代表清理已经完成。
          </p>
          <Structured value={confirmation} />
        </Confirm>
      )}
    </>
  );
}
