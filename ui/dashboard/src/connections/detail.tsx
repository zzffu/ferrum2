import { Fragment, useEffect, useRef } from "react";
import { bytes, duration, Structured } from "../components";
import type { ConnectionConditionView } from "../wire";
import {
  association,
  decisionKinds,
  domain,
  hops,
  missing,
  pathAbsence,
  rule,
  ruleText,
  sniffStatuses,
  type ConnectionRecord,
} from "./model";

function Conditions({ values }: { values: ConnectionConditionView[] }) {
  if (!values.length) return <p className="muted">无附加匹配条件</p>;
  return (
    <dl>
      {values.map(({ field, value }) => (
        <Fragment key={field}>
          <dt>{field}</dt>
          <dd>
            {Array.isArray(value)
              ? value.map(String).join("、")
              : String(value)}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

export function ConnectionDetail({
  record,
  close,
}: {
  record: ConnectionRecord;
  close: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const node = dialog.current;
    node?.showModal();
    return () => node?.close();
  }, []);
  const c = record.row;
  const d = c.decision;
  const observed = domain(record);
  const finalRule = rule(record, d?.rule_index);
  const sniffRule = rule(record, d?.sniff.rule_index);
  const path = hops(record);
  return (
    <dialog
      ref={dialog}
      className="connection-detail"
      aria-labelledby="connection-detail-title"
      onCancel={close}
    >
      <header className="panel-head">
        <div>
          <h2 id="connection-detail-title">连接详情</h2>
          <small>固定快照 · 刷新 / 重载不会改写此记录或目录</small>
        </div>
        <button autoFocus onClick={close} aria-label="关闭连接详情">
          关闭
        </button>
      </header>
      <section>
        <h3>基本 · Basic</h3>
        <dl>
          <dt>ID / 运行代</dt>
          <dd>
            {c.id} / {c.generation}
          </dd>
          <dt>传输 / 应用</dt>
          <dd>
            {c.protocol.toUpperCase()} /{" "}
            {d?.sniff.protocol?.toUpperCase() ??
              (d?.sniff.status === "redacted" ? "详情已隐藏" : "未记录")}
          </dd>
          <dt>入口</dt>
          <dd>
            {c.inbound_tag ?? "名称未记录"} · {c.inbound}
          </dd>
          <dt>状态</dt>
          <dd>{c.state}</dd>
          <dt>开始时间</dt>
          <dd>{c.started_ms} ms（运行时计时）</dd>
          <dt>持续时间</dt>
          <dd>{duration(c.duration_ms)}</dd>
        </dl>
      </section>
      <section>
        <h3>端点 · Endpoints</h3>
        <dl>
          <dt>主显示域名</dt>
          <dd>
            {observed
              ? `${observed.name} · ${observed.provenance}`
              : missing(record)}
          </dd>
          <dt>请求域名</dt>
          <dd>{c.requested_domain ?? missing(record)}</dd>
          <dt>源地址</dt>
          <dd>{c.source ?? missing(record)}</dd>
          <dt>原始目标</dt>
          <dd>{c.target ?? missing(record)}</dd>
        </dl>
        <p className="muted">{association(record)}</p>
      </section>
      <section>
        <h3>嗅探 · Sniff</h3>
        <dl>
          <dt>状态</dt>
          <dd>{d ? sniffStatuses[d.sniff.status][0] : "决策未记录"}</dd>
          <dt>应用协议</dt>
          <dd>{d?.sniff.protocol?.toUpperCase() ?? missing(record)}</dd>
          <dt>观测域名</dt>
          <dd>
            {d?.sniff.domain ??
              (d?.sniff.status === "matched"
                ? "已识别协议，无域名"
                : missing(record))}
          </dd>
          <dt>域名来源</dt>
          <dd>
            {d?.sniff.protocol === "tls"
              ? "TLS SNI"
              : d?.sniff.protocol === "http"
                ? "HTTP Host / CONNECT（未区分）"
                : d?.sniff.protocol === "dns"
                  ? "DNS 首个普通查询"
                  : missing(record)}
          </dd>
          <dt>触发规则</dt>
          <dd>
            {sniffRule
              ? ruleText(sniffRule)
              : d?.sniff.rule_index != null
                ? `未知规则 #${d.sniff.rule_index + 1}`
                : missing(record)}
          </dd>
        </dl>
        {d && <p className="muted">{sniffStatuses[d.sniff.status][1]}</p>}
        {sniffRule && <Conditions values={sniffRule.conditions} />}
      </section>
      <section>
        <h3>路由 · Route</h3>
        <dl>
          <dt>决策</dt>
          <dd>{d ? decisionKinds[d.kind] : "未记录"}</dd>
          <dt>规则集代</dt>
          <dd>{d?.rule_generation ?? missing(record)}</dd>
          <dt>目录 ID</dt>
          <dd>
            {c.catalog_id ?? "未记录"}
            {c.catalog_id &&
              !record.catalog &&
              " · 目录不可用（不使用当前配置代替）"}
          </dd>
          <dt>最终规则</dt>
          <dd>
            {finalRule
              ? ruleText(finalRule)
              : d?.rule_index != null
                ? `未知规则 #${d.rule_index + 1}`
                : !record.details
                  ? "详情已隐藏"
                  : d?.kind === "route"
                    ? "最终出站（无规则命中）"
                    : "无已记录规则"}
          </dd>
          <dt>配置目标</dt>
          <dd>
            {finalRule?.outbound ??
              (d?.kind === "route" && d.rule_index == null
                ? (record.catalog?.final_outbound ?? missing(record))
                : "无已记录配置目标")}
          </dd>
          <dt>实际出站路径</dt>
          <dd>
            {path.length ? (
              <ol className="connection-hops">
                {path.map((h, i) => (
                  <li key={i}>
                    {h.name} <small>出站 #{h.index + 1}</small>
                  </li>
                ))}
              </ol>
            ) : (
              pathAbsence(record)
            )}
          </dd>
        </dl>
        {finalRule && (
          <>
            <h4>完整配置条件</h4>
            <Conditions values={finalRule.conditions} />
          </>
        )}
        <p className="muted">
          路径按实际遍历顺序展示；配置目标不等于实际路径。不推断规则集内部条目或选择器历史。
        </p>
      </section>
      <section>
        <h3>流量 · Traffic</h3>
        <dl>
          <dt>上传</dt>
          <dd>
            {bytes(c.upload_rate)}/s · {bytes(c.upload_bytes)}（{c.upload_bytes}{" "}
            bytes）
          </dd>
          <dt>下载</dt>
          <dd>
            {bytes(c.download_rate)}/s · {bytes(c.download_bytes)}（
            {c.download_bytes} bytes）
          </dd>
        </dl>
        <p className="muted">复用运行时成功 I/O 计数；关闭记录为最终值。</p>
      </section>
      <details>
        <summary>原始记录 · Raw（已授权字段）</summary>
        <Structured value={{ connection: c, catalog: record.catalog }} />
      </details>
    </dialog>
  );
}
