# Schema V2 DNS and RuleSet configuration

Ferrum2 keeps `schema_version = 2`. The DNS/RuleSet extension adds an offline
preparation phase and a networked materialization phase; it does not introduce
a third schema version.

Use the complete annotated example in
[`examples/client-v2-dns-rulesets.toml`](examples/client-v2-dns-rulesets.toml).
The example uses documentation endpoints and a synthetic key, so replace those
values before a real materialized start.

## Validation and startup

```text
ferrum2-client --config PATH --check-config
ferrum2-client --config PATH --check-config --materialize
ferrum2-client --config PATH
ferrum2-server --config PATH --check-config
ferrum2-server --config PATH --check-config --materialize
ferrum2-server --config PATH
```

- `--check-config` performs bounded TOML parsing, static reference validation,
  endpoint classification, and complete dependency-cycle detection. It does no
  DNS, HTTP, socket, cache-directory, or listener I/O.
- Adding `--materialize` resolves client-resolved fixed endpoints, preserves
  deferred domain targets for their detours, loads and strictly compiles every
  RuleSet, and builds one immutable rule snapshot without starting listeners.
- A normal start completes the same materialization before it prepares any
  listener.

The configuration layer finishes with a closed, runtime-neutral DNS policy
blueprint: numeric server/query-type identities, shared compiled match sets,
RuleSet IDs, and the exact `RuleEngineRegistry` are retained without Hickory or
resolver runtime types. The client/server composition root consumes that
blueprint through the DNS adapter to build the single execution program before
any listener is prepared. This keeps `ferrum2-config` and `ferrum2-dns` as
independent dependants of `ferrum2-rule` and prevents a configuration-to-DNS or
DNS-to-configuration dependency edge.

V1 continues to reject the new fields. In V2, an unconfigured Direct now has
the explicit, stable system-resolver behavior described below instead of
implicitly following the presence of `[dns]`.

## Domain resolution and detours

A fixed domain endpoint must state how it is bootstrapped:

```toml
server = "edge.example.net:8388"
domain_resolver = "local"
domain_strategy = "ipv4_only"
```

For fixed Shadowsocks endpoints, `domain_resolver = "system"` explicitly uses
the operating-system resolver; a DNS server tag selects that tagged server.
Numeric endpoints must omit both resolver fields.

A domain-valued `dns.servers.address` has two valid modes. With an explicit
`domain_resolver`, Ferrum2 resolves the address during materialization, retains
all bounded ordered IP candidates, and tries them sequentially under one
absolute query deadline. Without one, `detour` is required and the original
domain target is passed to that detour at query time. The detour must accept
domain targets. In both cases,
`server_name` and the DoH path independently supply TLS SNI, certificate
identity, HTTP authority, and request path; they are never inferred from the
dial target.

Direct outbounds may name one DNS server with `domain_resolver` and may pair it
with `domain_strategy`. Such a Direct resolves its application domains by
calling that exact tagged server, bypassing `dns.route`. When those fields are
omitted, Direct always uses the operating-system resolver, whether or not a
`[dns]` section exists. An explicit resolution failure is terminal and never
falls back to another resolver or detour.

Every referenced egress has a prepared domain-target capability. Shadowsocks
and Direct accept domains; a selector accepts them only when all members do; a
chain uses its terminal hop's capability. Static validation applies this rule
before any DNS, HTTP, socket, listener, or TUN I/O.

`dns.max_inflight` remains one aggregate limit on independent query chains.
When a DNS egress uses another tagged server through an explicit Direct
resolver, the acyclic child lookup shares its parent's admission and absolute
deadline; a lookup into a different resolver owner must acquire that owner's
own admission.

## RuleSets

RuleSet declarations live under `[[route.rule_set]]` and are shared by ordinary
Route and DNS Route rules. The current implementation accepts HTTPS remote
binary sing-box SRS files. `download_resolver`, when present, is either `system`
or a DNS server tag and resolves every URL host locally before dialing.
Alternatively, omit it and provide a domain-capable `download_detour`; Ferrum2
then passes each URL's domain and port unchanged to that fixed detour. Omitting
both fields is invalid. `download_detour` may name an outbound, selector, or
chain.

The strict decoder supports exact domains, domain suffixes, domain keywords,
and IPv4/IPv6 CIDRs. It rejects unknown versions, malformed or trailing data,
truncated zlib streams, regex, logical rules, inversion, and other unsupported
matchers before publishing a snapshot. Inline fields, synthetic sets, and SRS
sets all compile through the same `MatchSetBuilder` and `CompiledMatchSet`.

Values inside one RuleSet are ORed. Multiple names in one `rule_set = [...]`
field are also ORed, while different fields in the same rule remain ANDed.
RuleSets stay as stable snapshot references and are never expanded into tens of
thousands of ordinary route rows.

For DNS, domain categories are evaluated before an upstream query. An `ads`
reject can therefore return immediately. CIDRs are evaluated against A/AAAA
answers (including a CNAME chain in the same Answer section); a miss or empty
answer continues at the next rule. One evaluation captures one registry
generation, and repeated continuation through the same server/query reuses the
same server-scoped response.

## Cache and refresh

Each remote declaration uses `<tag>.srs` and `<tag>.meta` below
`rule_set_loader.cache_dir`. Metadata binds the URL, validators, digest, SRS
version, matcher capabilities, and generation. Downloads use one absolute
deadline, the selected resolution mode, and one fixed detour snapshot on every
redirect, plus conditional ETag/Last-Modified requests, a temporary file,
fsync, strict decode/compile, and an atomic replacement. Each redirect validates
its new HTTPS URL and uses that URL's host for the dial target, TLS SNI,
certificate identity, and HTTP authority. Deferred downloads perform no hidden
system or configured DNS lookup. A valid cache may serve an offline start. A
corrupt or partial cache never does. Refresh failures retain the old complete
snapshot.
The exact matcher-capability shape is part of snapshot compatibility: a
refresh that adds or removes domain/keyword/CIDR categories cannot bypass the
policy checks compiled at materialization, and leaves both cache and live
generation unchanged.
Cache reads and SRS decoding/compilation that run on blocking workers remain
owned by the refresh root; cancellation stops accepting new work and shutdown
joins every already-started worker before the root reports completion.

DNS A and AAAA entries are cached separately by DNS server, canonical name,
query type, and resolver generation. Positive and negative TTLs are honored.
TCP, UDP, fixed endpoints, and DNS response evaluation share this cache; UDP
associations retain only the last successful candidate index, never an address
TTL cache.

## Observability

Rule, DNS, cache, load, refresh, and resolver metrics use only closed bounded
labels. DNS upstream and RuleSet download observations distinguish numeric,
system-resolved, configured-resolved, and deferred-to-detour targets without
recording an identity. `route_match_total` describes matcher categories configured by the rule
selected in an evaluation step: each category is reported as `matched` or
`missed`; a final fallback with no selected rule emits neither, so Ferrum2 never
fabricates attribution from rejected candidates. RuleSet tags, DNS server tags,
domains, URLs, and endpoint identities are deliberately excluded by repository
redaction policy. A retained offline or stale cache is reported as a degraded
load/refresh failure while the prior valid snapshot remains active.

## Error catalog

Configuration diagnostics use a closed category and field path. They are
intentionally redacted: repository policy forbids echoing tags, endpoints,
URLs, keys, or other configuration values.

| Area | Stable field paths | Failure class |
|---|---|---|
| RuleSet declaration | `route.rule_set`, `.tag`, `.type`, `.format`, `.url`, `.download_resolver`, `.download_detour`, `.update_interval_seconds` | `config.semantic` |
| Loader | `rule_set_loader`, `.cache_dir`, `.download_timeout_ms`, `.max_redirects` | `config.semantic` |
| Ordinary route | `route.rules.domain_keyword`, `route.rules.rule_set` | `config.semantic`, `rule.compile`, `rule.allocation` |
| DNS policy | `dns.strategy`, `dns.cache.*`, `dns.route.rules.domain_keyword`, `.rule_set`, `.action`, `.strategy`, `.server` | `config.semantic` |
| Fixed endpoints | `outbounds.domain_resolver`, `outbounds.domain_strategy`, `dns.servers.domain_resolver`, `dns.servers.domain_strategy` | `config.semantic`, `dns.resolver_required` |
| Reserved DNS resolver name | `dns.servers.tag` | `dns.reserved_resolver_name` |
| Dependency graph | `config.dependency_cycle` | `config.dependency_cycle` |
| Supplied resources | `config.resource_materialization` | `config.resource_materialization` |

Materialized startup and `--check-config --materialize` expose the closed
`ruleset.download`, `ruleset.cache`, `ruleset.format`,
`ruleset.unsupported_matcher`, `ruleset.compile`, `rule.compile`, `rule.allocation`,
`dns.resolve`, and `config.resource_materialization` classes. They never echo
the affected tag, domain, URL, endpoint, or configuration value. Logs and
metrics likewise contain only bounded enums and never use those identities as
labels.

Dependency-cycle diagnostics include the complete closed resource path using
only resource kinds and declaration indices (for example, `dns-server[0] ->
outbound[1] -> dns-server[0]`); configured tags and endpoint values remain
redacted.
