import { useState, type FormEvent } from "react";
import { useDashboard } from "./store";
import {
  Panel,
  Structured,
  Capability,
  useAction,
  Confirm,
} from "./components";

export function Outbounds() {
  const { snapshot: s, busy } = useDashboard();
  const action = useAction();
  const [outbound, setOutbound] = useState("0");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  function probe(e: FormEvent) {
    e.preventDefault();
    void action.run({
      action: "outbounds.probe",
      outbound: Number(outbound),
      host: host.trim(),
      port: Number(port),
    });
  }
  return (
    <>
      <Panel title="选择器">
        <p className="muted">
          仅新连接使用新出口；TUN UDP 会话可能因代次变化断开重建。
        </p>
        <Capability name="selectors.select">
          {s?.domains.selectors?.map((selector) => (
            <div className="selector-row" key={selector.id}>
              <div>
                <strong>{selector.name}</strong>
                <small>
                  #{selector.id} · 当前成员 {selector.selected}
                </small>
              </div>
              <select
                aria-label={`选择器 ${selector.name}`}
                value={selector.selected}
                disabled={busy}
                onChange={(e) => {
                  if (
                    window.confirm(
                      "确认切换出口？仅新连接使用新出口；TUN UDP 会话可能因代次变化断开重建。",
                    )
                  )
                    void action.run({
                      action: "selectors.select",
                      selector: selector.id,
                      member: Number(e.target.value),
                    });
                }}
              >
                {selector.members.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name} · #{m.id}
                  </option>
                ))}
              </select>
            </div>
          ))}
          {!s?.domains.selectors?.length && (
            <p className="muted">未提供运行时选择器</p>
          )}
        </Capability>
      </Panel>
      <Panel title="显式出站探测">
        <p className="muted">
          通过真实出站连接指定目标。仅测量 transport-connect，不是 HTTP
          请求延迟；不触发自动切换。
        </p>
        <Capability name="outbounds.probe">
          <form onSubmit={probe} className="toolbar">
            <label>
              出站 ID
              <input
                required
                type="number"
                min="0"
                step="1"
                value={outbound}
                onChange={(e) => setOutbound(e.target.value)}
              />
            </label>
            <label>
              目标主机
              <input
                required
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="输入要连接的主机"
              />
            </label>
            <label>
              端口
              <input
                required
                type="number"
                min="1"
                max="65535"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </label>
            <button className="primary" disabled={busy}>
              连接探测
            </button>
          </form>
        </Capability>
        {action.feedback}
      </Panel>
      <Panel title="出站目录">
        <div className="catalog-grid">
          {s?.catalog?.outbounds.map((o, i) => (
            <article className="catalog-item" key={i}>
              <span className="eyebrow">出站 · 目录序号 {i}</span>
              <Structured value={o} />
            </article>
          ))}
        </div>
        {!s?.catalog && <Structured value={null} />}
      </Panel>
      <div className="two-col">
        <Panel title="选择器配置">
          <Structured value={s?.catalog?.selectors} />
        </Panel>
        <Panel title="链路顺序">
          <p className="muted">
            以下数组保持配置顺序，不推断实际连接的最终路径。
          </p>
          <Structured value={s?.catalog?.chains} />
        </Panel>
      </div>
    </>
  );
}

export function RoutesPage() {
  const { snapshot: s, busy } = useDashboard();
  const action = useAction();
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [inbound, setInbound] = useState("0");
  const rules = s?.catalog?.route.rules;
  return (
    <>
      <Panel title="路由试算">
        <p className="muted">
          调用当前运行代的真实规则求值器；不隐式发起 DNS 查询。未输入的嗅探 /
          DNS 元数据缺失，由运行时报告。
        </p>
        <Capability name="routes.test">
          <form
            className="toolbar"
            onSubmit={(e) => {
              e.preventDefault();
              void action.run({
                action: "routes.test",
                host: host.trim(),
                port: Number(port),
                protocol,
                inbound: Number(inbound),
              });
            }}
          >
            <label>
              目标主机
              <input
                required
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </label>
            <label>
              端口
              <input
                required
                type="number"
                min="1"
                max="65535"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </label>
            <label>
              协议
              <select
                value={protocol}
                onChange={(e) =>
                  setProtocol(e.target.value === "udp" ? "udp" : "tcp")
                }
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </label>
            <label>
              入口 ID
              <input
                required
                type="number"
                min="0"
                value={inbound}
                onChange={(e) => setInbound(e.target.value)}
              />
            </label>
            <button className="primary" disabled={busy}>
              试算路由
            </button>
          </form>
        </Capability>
        {action.feedback}
      </Panel>
      <Panel title="有序规则">
        <p className="muted">按配置顺序展示；默认出口与完整策略见下方。</p>
        {Array.isArray(rules) ? (
          <ol className="rule-list">
            {rules.map((rule, i) => (
              <li key={i}>
                <Structured value={rule} />
              </li>
            ))}
          </ol>
        ) : (
          <Structured value={rules} />
        )}
        <details>
          <summary>完整路由策略 / 默认出口</summary>
          <Structured value={s?.catalog?.route} />
        </details>
      </Panel>
      <Panel title="RuleSet 运行状态">
        <p className="muted">
          刷新失败保留此前有效快照；以运行时返回的状态为准。
        </p>
        {s?.domains.rulesets?.map((ruleset, index) => (
          <article className="catalog-item" key={index}>
            <div className="panel-head">
              <h3>RuleSet #{index}</h3>
              <Capability name="rulesets.refresh">
                <button
                  disabled={busy}
                  onClick={() =>
                    void action.run({ action: "rulesets.refresh", index })
                  }
                >
                  刷新
                </button>
              </Capability>
            </div>
            <Structured value={ruleset} />
          </article>
        ))}
        {!s?.domains.rulesets?.length && (
          <Structured value={null} empty="未提供 RuleSet 运行状态" />
        )}
      </Panel>
    </>
  );
}

export function DnsPage() {
  const { snapshot: s, busy } = useDashboard();
  const action = useAction();
  const [name, setName] = useState("");
  const [qtype, setQtype] = useState<"A" | "AAAA">("A");
  const [server, setServer] = useState("");
  const [confirm, setConfirm] = useState<string | null>(null);
  return (
    <>
      <div className="two-col">
        <Panel title="DNS 配置与策略">
          <Structured value={s?.catalog?.dns} />
        </Panel>
        <Panel title="缓存状态">
          <Structured value={s?.domains.dns_cache} />
          <Capability name="dns.clear">
            <button disabled={busy} onClick={() => setConfirm(s!.generation)}>
              清空当前运行代缓存
            </button>
          </Capability>
        </Panel>
      </div>
      <Panel title="DNS 查询诊断">
        <p className="muted">
          使用当前 DNS 所有者执行查询。输入 /
          结果仅留在当前页面，不持久化查询历史。
        </p>
        <Capability name="dns.query">
          <form
            className="toolbar"
            onSubmit={(e) => {
              e.preventDefault();
              void action.run({
                action: "dns.query",
                name: name.trim(),
                qtype,
                server: server === "" ? null : Number(server),
              });
            }}
          >
            <label>
              域名
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="off"
              />
            </label>
            <label>
              记录类型
              <select
                value={qtype}
                onChange={(e) =>
                  setQtype(e.target.value === "AAAA" ? "AAAA" : "A")
                }
              >
                <option>A</option>
                <option>AAAA</option>
              </select>
            </label>
            <label>
              服务器 ID（空白 = 策略选择）
              <input
                type="number"
                min="0"
                value={server}
                onChange={(e) => setServer(e.target.value)}
              />
            </label>
            <button className="primary" disabled={busy}>
              执行查询
            </button>
          </form>
        </Capability>
        {action.feedback}
      </Panel>
      {confirm && (
        <Confirm
          title="清空 DNS 缓存？"
          busy={busy}
          close={() => setConfirm(null)}
          accept={() => {
            void action.run({ action: "dns.clear" }, confirm);
            setConfirm(null);
          }}
        >
          <p>仅清空运行代 {confirm} 的当前缓存。后续请求将重新解析。</p>
        </Confirm>
      )}
    </>
  );
}
