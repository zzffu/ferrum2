import { useState } from "react";
import { useDashboard } from "./store";
import { bytes, duration, Panel, Structured, Empty } from "./components";

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
