import { useEffect, useRef, useState } from "react";
import { loadConfig, preferences, useDashboard } from "./store";
import type { LogView } from "./protocol";
import {
  Panel,
  Structured,
  Pager,
  download,
  useAction,
  Confirm,
  duration,
} from "./components";

export function LogsPage() {
  const { snapshot: s, busy, error } = useDashboard();
  const action = useAction();
  const [frozen, setFrozen] = useState<LogView[] | null>(null);
  const [level, setLevel] = useState("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const rows = (frozen ?? s?.logs ?? [])
    .filter(
      (l) =>
        (level === "all" || l.level.toLowerCase() === level) &&
        JSON.stringify(l.event).toLowerCase().includes(search.toLowerCase()),
    )
    .slice()
    .reverse();
  const currentPage = Math.min(
    page,
    Math.max(0, Math.ceil(rows.length / 50) - 1),
  );
  return (
    <>
      <Panel
        title="日志流"
        action={
          <button
            onClick={() => setFrozen(frozen ? null : [...(s?.logs ?? [])])}
          >
            {frozen ? "恢复实时显示" : "暂停显示"}
          </button>
        }
      >
        <div className="toolbar">
          <input
            aria-label="搜索日志"
            placeholder="搜索已脱敏事件"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
          />
          <select
            aria-label="日志级别"
            value={level}
            onChange={(e) => {
              setLevel(e.target.value);
              setPage(0);
            }}
          >
            <option value="all">全部级别</option>
            {["error", "warn", "info", "debug", "trace"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
          <button
            disabled={!rows.length}
            onClick={() => download("ferrum2-logs.json", rows)}
          >
            导出当前筛选
          </button>
        </div>
        <p className="muted">
          仅保留运行时有界日志窗口；不请求连接详情、配置、密钥或录制文件。
          {frozen && "显示已暂停。"}
        </p>
        <div className="log-list">
          {rows.slice(currentPage * 50, currentPage * 50 + 50).map((l) => (
            <article className="log-row" key={l.id}>
              <span>{duration(l.elapsed_ms)}</span>
              <span className={`level level-${l.level.toLowerCase()}`}>
                {l.level}
              </span>
              <Structured value={l.event} />
            </article>
          ))}
        </div>
        {!rows.length && <p className="empty">当前筛选没有日志事件</p>}
        <Pager count={rows.length} page={currentPage} setPage={setPage} />
      </Panel>
      <Panel title="运行诊断">
        <p className="muted">
          导出由后端生成的固定类别诊断；不包含配置源文、连接详情、捕获内容或密钥。
        </p>
        <button
          disabled={busy || !s || !!error}
          onClick={async () => {
            const result = await action.run({ action: "diagnostics.export" });
            if (result !== undefined)
              download("ferrum2-diagnostics.json", result);
          }}
        >
          导出诊断 JSON
        </button>
        {action.feedback}
        {s?.error && (
          <div className="notice danger">
            启动 / 材料化 / 清理失败：{s.error}
          </div>
        )}
        <Structured value={s?.domains.metrics} />
      </Panel>
      <div className="two-col">
        <Panel title="TUN 状态（只读）">
          <p className="muted">不修改主机 DNS、路由、防火墙或适配器。</p>
          <Structured value={s?.catalog?.tun} />
          <Structured
            value={
              s
                ? Object.fromEntries(
                    Object.entries(s.resources).filter(([k]) =>
                      k.toLowerCase().includes("tun"),
                    ),
                  )
                : null
            }
          />
        </Panel>
        <Panel title="rocom 录制诊断">
          <p className="muted">
            仅状态、容量和失败信息；不提供捕获或密钥下载。
          </p>
          <Structured value={s?.catalog?.rocom} />
          <Structured
            value={
              s
                ? Object.fromEntries(
                    Object.entries(s.resources).filter(([k]) =>
                      k.toLowerCase().includes("rocom"),
                    ),
                  )
                : null
            }
          />
        </Panel>
      </div>
    </>
  );
}

interface Editor {
  source: string;
  revision: string;
  running_revision: string | null;
}
export function SettingsPage() {
  const { snapshot: s, busy, error, preferences: p } = useDashboard();
  const action = useAction();
  const [editor, setEditor] = useState<Editor | null>(null);
  const [source, setSource] = useState("");
  const [reading, setReading] = useState(false);
  const [readError, setReadError] = useState("");
  const editorEpoch = useRef(0);
  useEffect(
    () => () => {
      editorEpoch.current++;
    },
    [],
  );
  const [confirm, setConfirm] = useState<{
    action: "config.save" | "config.apply";
    source: string;
    revision: string;
    generation: string;
  } | null>(null);
  function clearEditor() {
    editorEpoch.current++;
    setEditor(null);
    setSource("");
    setReading(false);
    setReadError("");
    setConfirm(null);
  }
  async function readSource() {
    const epoch = ++editorEpoch.current;
    setReading(true);
    setReadError("");
    try {
      const value = await loadConfig();
      if (epoch !== editorEpoch.current) return;
      setEditor(value);
      setSource(value.source);
    } catch (e) {
      if (epoch === editorEpoch.current)
        setReadError(e instanceof Error ? e.message : "读取失败");
    } finally {
      if (epoch === editorEpoch.current) setReading(false);
    }
  }
  async function commit() {
    if (!confirm) return;
    const fixed = confirm;
    const epoch = ++editorEpoch.current;
    setReadError("");
    setConfirm(null);
    const result = await action.run(
      { action: fixed.action, source: fixed.source, revision: fixed.revision },
      fixed.generation,
    );
    if (epoch !== editorEpoch.current) return;
    if (result?.kind === "config") {
      const { revision } = result;
      // Keep the saved source and its authoritative revision paired, even if disk changes again.
      setEditor((current) => ({
        source: fixed.source,
        revision,
        running_revision: current?.running_revision ?? null,
      }));
      setReading(true);
      try {
        const next = await loadConfig();
        if (epoch !== editorEpoch.current) return;
        setEditor({
          source: fixed.source,
          revision,
          running_revision: next.running_revision,
        });
        if (next.revision !== revision)
          setReadError(
            "磁盘配置已被外部修改；当前草稿未更新，请重新读取后再保存。",
          );
      } catch {
        if (epoch === editorEpoch.current)
          setReadError(
            "保存已成功，但无法读取最新运行修订信息；请重新读取配置。",
          );
      } finally {
        if (epoch === editorEpoch.current) setReading(false);
      }
    }
  }
  return (
    <>
      <Panel title="界面设置">
        <div className="settings-grid">
          <label>
            主题
            <select
              value={p.theme}
              onChange={(e) =>
                preferences({
                  theme: e.target.value as "system" | "dark" | "light",
                })
              }
            >
              <option value="system">跟随系统</option>
              <option value="dark">深色</option>
              <option value="light">浅色</option>
            </select>
          </label>
          <label>
            刷新间隔
            <select
              value={p.interval}
              onChange={(e) =>
                preferences({ interval: Number(e.target.value) })
              }
            >
              <option value="1000">1 秒</option>
              <option value="2000">2 秒</option>
              <option value="5000">5 秒</option>
            </select>
          </label>
          <label>
            <input
              type="checkbox"
              checked={p.dense}
              onChange={(e) => preferences({ dense: e.target.checked })}
            />
            紧凑表格
          </label>
          <label>
            <input
              type="checkbox"
              checked={p.addresses}
              onChange={(e) => preferences({ addresses: e.target.checked })}
            />
            显示连接地址列
          </label>
        </div>
        <p className="muted">
          仅以上无敏感信息的偏好保存在浏览器；令牌、配置与查询不写入本地存储。
        </p>
      </Panel>
      <Panel title="配置文件 · 敏感操作">
        <div className="notice">
          源配置可能包含凭据。显式读取后仅在内存编辑；不要在共享屏幕上打开。仅访问进程启动时指定的文件。
        </div>
        <div className="actions">
          <button
            disabled={reading || busy || !s}
            onClick={() => {
              if (
                !editor ||
                source === editor.source ||
                window.confirm("重新读取将丢弃未保存的编辑，继续？")
              )
                void readSource();
            }}
          >
            {reading ? "读取中…" : editor ? "重新读取磁盘配置" : "读取敏感配置"}
          </button>
          {editor && <button onClick={clearEditor}>清除编辑器内容</button>}
        </div>
        {readError && (
          <p role="alert" className="notice danger">
            {readError}
          </p>
        )}
        {editor && (
          <>
            <dl>
              <dt>编辑基准修订</dt>
              <dd className="mono">{editor.revision}</dd>
              <dt>运行修订（上次读取时）</dt>
              <dd className="mono">
                {editor.running_revision ?? "无运行配置"}
              </dd>
              <dt>状态</dt>
              <dd>
                {editor.revision === editor.running_revision
                  ? "编辑基准与运行修订一致"
                  : "编辑基准与运行修订不同"}
              </dd>
            </dl>
            <label className="editor-label">
              源配置
              <textarea
                spellCheck={false}
                autoComplete="off"
                className="editor"
                value={source}
                onChange={(e) => setSource(e.target.value)}
              />
            </label>
            <div className="actions">
              <button
                disabled={busy || reading || !s || !!error}
                onClick={() =>
                  void action.run({ action: "config.validate", source })
                }
              >
                离线校验
              </button>
              <button
                disabled={busy || reading || !s || !!error}
                onClick={() =>
                  setConfirm({
                    action: "config.save",
                    source,
                    revision: editor.revision,
                    generation: s!.generation,
                  })
                }
              >
                校验并保存
              </button>
              <button
                className="primary"
                disabled={busy || reading || !s || !!error}
                onClick={() =>
                  setConfirm({
                    action: "config.apply",
                    source,
                    revision: editor.revision,
                    generation: s!.generation,
                  })
                }
              >
                保存并应用
              </button>
            </div>
            <p className="muted">
              保存使用修订检查，拒绝覆盖外部修改。应用先校验，再停止旧运行代并重启；独占资源启动失败不保证无缝回滚。管理监听地址
              / 令牌变更需要重启整个进程。
            </p>
          </>
        )}
        {action.feedback}
      </Panel>
      {confirm && (
        <Confirm
          title={
            confirm.action === "config.apply"
              ? "保存并重启代理运行代？"
              : "原子替换磁盘配置？"
          }
          busy={busy}
          close={() => setConfirm(null)}
          accept={() => void commit()}
        >
          <p>
            {confirm.action === "config.apply"
              ? "当前连接会中断；将等待配置的关闭宽限期（最长 5 分钟）。TUN 配置可能改变宿主机网络，需要现有权限。新配置材料化或监听失败将显示为失败，不表示已应用。"
              : "校验通过后替换已配置的同一文件；运行代继续使用此前配置。"}
          </p>
          <p>
            预期磁盘修订：<code>{confirm.revision}</code>
          </p>
        </Confirm>
      )}
    </>
  );
}
