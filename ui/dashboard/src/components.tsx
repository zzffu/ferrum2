import { useEffect, useRef, useState, type ReactNode } from "react";
import { command, useDashboard } from "./store";
import type { Command, CommandResult } from "./protocol";

export function bytes(value: string | number | null | undefined) {
  if (value == null) return "不可用";
  const n = Number(value);
  if (!Number.isFinite(n)) return "不可用";
  const unit =
    n > 0
      ? Math.max(0, Math.min(4, Math.floor(Math.log(n) / Math.log(1024))))
      : 0;
  return `${(n / 1024 ** unit).toLocaleString("zh-CN", { maximumFractionDigits: 1 })} ${["B", "KiB", "MiB", "GiB", "TiB"][unit]}`;
}
export function duration(ms: number) {
  return `${Math.floor(ms / 3600000)}:${String(Math.floor(ms / 60000) % 60).padStart(2, "0")}:${String(Math.floor(ms / 1000) % 60).padStart(2, "0")}`;
}
export function download(name: string, value: unknown) {
  const url = URL.createObjectURL(
    new Blob(
      [typeof value === "string" ? value : JSON.stringify(value, null, 2)],
      { type: "application/json" },
    ),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function Structured({
  value,
  empty = "运行时未提供此项数据",
}: {
  value: unknown;
  empty?: string;
}) {
  if (value == null) return <p className="muted">{empty}</p>;
  return (
    <pre className="structured">
      {typeof value === "string" ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}
export function Panel({
  title,
  children,
  action,
}: {
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
export function Pager({
  count,
  page,
  setPage,
}: {
  count: number;
  page: number;
  setPage: (n: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(count / 50));
  return (
    <div className="pager">
      <span>{count.toLocaleString()} 条 · 每页最多 50 条</span>
      <button disabled={page <= 0} onClick={() => setPage(page - 1)}>
        上一页
      </button>
      <span>
        {Math.min(page + 1, pages)} / {pages}
      </span>
      <button disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>
        下一页
      </button>
    </div>
  );
}
export function useAction() {
  const [result, setResult] = useState<CommandResult | undefined>(undefined);
  const [error, setError] = useState("");
  async function run(request: Command, generation?: string) {
    setError("");
    setResult(undefined);
    try {
      const value = await command(request, generation);
      setResult(value);
      return value;
    } catch (e) {
      setError(e instanceof Error ? e.message : "操作失败");
      return undefined;
    }
  }
  return {
    run,
    result,
    error,
    feedback: (
      <>
        {error && (
          <div role="alert" className="notice danger">
            操作失败：{error}。冲突时请刷新数据，重新确认后再操作。
          </div>
        )}
        {result !== undefined && (
          <div className="result">
            <span className="eyebrow">操作结果</span>
            <Structured value={result} />
          </div>
        )}
      </>
    ),
  };
}
export function Capability({
  name,
  children,
}: {
  name: Command["action"];
  children: ReactNode;
}) {
  const { snapshot, error } = useDashboard();
  const available = snapshot?.domains.capabilities?.includes(name) && !error;
  return (
    <fieldset disabled={!available}>
      <legend className="sr-only">{name}</legend>
      {children}
      {!available && (
        <p className="muted">
          不可用：
          {error ? "快照已过期，请等待连接恢复" : "当前运行代未提供此能力"}
        </p>
      )}
    </fieldset>
  );
}
export function Confirm({
  title,
  children,
  accept,
  close,
  busy,
}: {
  title: string;
  children: ReactNode;
  accept: () => void;
  close: () => void;
  busy: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  return (
    <dialog
      ref={dialog}
      aria-label={title}
      className="modal"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) close();
      }}
    >
      <h2>{title}</h2>
      {children}
      <div className="actions">
        <button autoFocus onClick={close} disabled={busy}>
          取消
        </button>
        <button className="danger-button" disabled={busy} onClick={accept}>
          {busy ? "处理中…" : "确认执行"}
        </button>
      </div>
    </dialog>
  );
}
