import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  HashRouter,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import { login, logout, poll, useDashboard } from "./store";
import { Confirm, useAction } from "./components";
import { Overview, Connections } from "./traffic";
import { Outbounds, RoutesPage, DnsPage } from "./domains";
import { LogsPage, SettingsPage } from "./settings";
import "./style.css";

const pages = [
  ["/", "概览", "M3 13h7V3H3zm11 8h7V11h-7zM3 21h7v-4H3zm11-14h7V3h-7z"],
  ["/connections", "连接", "M4 7h16M4 17h16M7 4L4 7l3 3m10 4 3 3-3 3"],
  ["/outbounds", "出站", "M4 12h16m-6-6 6 6-6 6M4 4v16"],
  ["/routes", "路由", "M5 4v16m0-12h10l4-4m-4 4 4 4M5 16h10l4 4"],
  ["/dns", "DNS", "M3 5h18v6H3zm0 10h18v6H3zM7 8h1m-1 10h1"],
  ["/logs", "日志与诊断", "M5 3h14v18H5zm4 5h6m-6 4h6m-6 4h4"],
  ["/settings", "配置与设置", "M4 7h16M4 17h16M8 4v6m8 4v6"],
];
function Login() {
  const { loading, error } = useDashboard();
  const [value, setValue] = useState("");
  return (
    <main className="login">
      <section className="login-card">
        <div className="brand">
          <span className="brand-mark">F</span>
          <span>
            Ferrum2<small>本地运行控制台</small>
          </span>
        </div>
        <h1>连接你的运行时</h1>
        <p className="muted">
          输入管理令牌以访问当前进程。所有请求仅发送到当前站点；令牌只保留在本标签页内存。
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const entered = value.trim();
            setValue("");
            void login(entered);
          }}
        >
          <label>
            管理令牌
            <input
              type="password"
              required
              autoFocus
              autoComplete="off"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              maxLength={4096}
            />
          </label>
          <button className="primary" disabled={loading || !value.trim()}>
            {loading ? "正在连接…" : "解锁控制台"}
          </button>
        </form>
        {error && (
          <p role="alert" className="notice danger">
            {error}
          </p>
        )}
        <p className="footnote">不使用云服务 · 不存储凭据 · 无外部资源</p>
      </section>
    </main>
  );
}
function Shell() {
  const state = useDashboard();
  const action = useAction();
  const location = useLocation();
  const [confirmation, setConfirmation] = useState<{
    action: "runtime.stop" | "runtime.restart";
    generation: string;
  } | null>(null);
  const s = state.snapshot;
  const title =
    pages.find(([path]) => path === location.pathname)?.[1] ?? "概览";
  const states: Record<string, string> = {
    stopped: "已停止",
    starting: "正在启动",
    running: "运行中",
    stopping: "正在停止",
    failed: "失败",
  };
  const stale = !!state.error || state.hidden;
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">F</span>
          <span>
            Ferrum2<small>运行控制台</small>
          </span>
        </div>
        <div className="nav-label">工作空间</div>
        <nav>
          {pages.map(([path, label, icon]) => (
            <NavLink
              aria-label={label}
              title={label}
              end={path === "/"}
              to={path}
              key={path}
            >
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d={icon} />
              </svg>
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span
            className={`status-dot ${s?.state === "running" ? "online" : ""}`}
          />
          <span>本地管理 · 协议 v1</span>
          <button onClick={logout}>锁定</button>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">FERRUM2 / CONTROL CENTER</span>
            <h1>{title}</h1>
          </div>
          <div className="runtime-controls">
            <span className={`status ${stale ? "stale" : ""}`}>
              <span
                className={`status-dot ${s?.state === "running" ? "online" : ""}`}
              />
              {s ? states[s.state] : "正在连接"}
            </span>
            <button
              disabled={
                !s ||
                state.busy ||
                !!state.error ||
                !["stopped", "failed"].includes(s.state)
              }
              onClick={() => void action.run({ action: "runtime.start" })}
            >
              启动
            </button>
            <button
              disabled={
                !s || state.busy || !!state.error || s.state !== "running"
              }
              onClick={() =>
                setConfirmation({
                  action: "runtime.restart",
                  generation: s!.generation,
                })
              }
            >
              重启
            </button>
            <button
              disabled={
                !s || state.busy || !!state.error || s.state !== "running"
              }
              onClick={() =>
                setConfirmation({
                  action: "runtime.stop",
                  generation: s!.generation,
                })
              }
            >
              停止
            </button>
          </div>
        </header>
        <div className="syncbar">
          <span>
            {state.hidden
              ? "标签页隐藏 · 轮询暂停"
              : state.loading
                ? "正在同步…"
                : state.received
                  ? `最后接收 ${new Date(state.received).toLocaleTimeString("zh-CN")}`
                  : "等待数据"}
            {s && ` · 运行代 ${s.generation}`}
          </span>
          <button
            disabled={state.loading || state.hidden}
            onClick={() => void poll()}
          >
            刷新
          </button>
        </div>
        <main className="content">
          {state.error && (
            <div role="alert" className="notice danger">
              连接异常：{state.error}
              。保留上次快照，当前数据已过期；写入操作暂停。
            </div>
          )}
          {s?.error && (
            <div className="notice danger">运行时失败：{s.error}</div>
          )}
          {action.feedback}
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/connections" element={<Connections />} />
            <Route path="/outbounds" element={<Outbounds />} />
            <Route path="/routes" element={<RoutesPage />} />
            <Route path="/dns" element={<DnsPage />} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <footer>
            Ferrum2 · 数据来自当前本地进程。缺失观测不会替换为虚构测量。
          </footer>
        </main>
      </div>
      {confirmation && (
        <Confirm
          title={
            confirmation.action === "runtime.stop"
              ? "停止当前运行代？"
              : "重启当前运行代？"
          }
          busy={state.busy}
          close={() => setConfirmation(null)}
          accept={() => {
            void action.run(
              { action: confirmation.action },
              confirmation.generation,
            );
            setConfirmation(null);
          }}
        >
          <p>
            活动连接将中断。管理页面继续运行；旧运行代清理完成后才允许替换。
          </p>
        </Confirm>
      )}
    </div>
  );
}
function App() {
  const { authenticated, preferences } = useDashboard();
  useEffect(() => {
    document.documentElement.dataset.theme = preferences.theme;
    document.documentElement.dataset.dense = String(preferences.dense);
  }, [preferences.theme, preferences.dense]);
  return authenticated ? (
    <HashRouter>
      <Shell />
    </HashRouter>
  ) : (
    <Login />
  );
}
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
