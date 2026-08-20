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
- Adding `--materialize` resolves fixed domain endpoints through their explicit
  resolver, loads and strictly compiles every RuleSet, and builds one immutable
  rule snapshot without starting listeners.
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

Existing V1 and V2 configurations without the new fields keep their prior
behavior. New fields are rejected under V1.

## Explicit resolution

A fixed domain endpoint must state how it is bootstrapped:

```toml
server = "edge.example.net:8388"
domain_resolver = "local"
domain_strategy = "ipv4_only"
```

`domain_resolver = "system"` is an explicit request to use the operating-system
resolver. Omitting the resolver is an error; Ferrum2 never infers the default
DNS server, route final, detour DNS, or system resolver. Numeric endpoints must
omit both `domain_resolver` and `domain_strategy`.

The same rule applies to a domain-valued `dns.servers.address`. Its connection
IP is resolved first, while `server_name` and the DoH path continue to supply
TLS SNI, certificate identity, and HTTP authority. Direct outbounds do not
accept resolver fields.

After `[dns]` is configured, application domains from Direct TCP, Direct UDP,
and server egress use the configured DNS policy. A configured resolver error is
terminal and cannot fall back to system DNS. With no `[dns]` section, application
resolution deliberately uses system DNS.

## RuleSets

RuleSet declarations live under `[[route.rule_set]]` and are shared by ordinary
Route and DNS Route rules. The current implementation accepts HTTPS remote
binary sing-box SRS files. `download_resolver` is mandatory and is either
`system` or a DNS server tag; `download_detour` may name an outbound, selector,
or chain.

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
deadline, the configured resolver and detour on every redirect, conditional
ETag/Last-Modified requests, a temporary file, fsync, strict decode/compile, and
an atomic replacement. A valid cache may serve an offline start. A corrupt or
partial cache never does. Refresh failures retain the old complete snapshot.
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
labels. `route_match_total` describes matcher categories configured by the rule
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
| Dependency graph | `dns.dependency_cycle` | `dns.dependency_cycle` |
| Supplied resources | `config.resource_materialization` | `config.resource_materialization` |

Materialized startup and `--check-config --materialize` expose the closed
`ruleset.download`, `ruleset.cache`, `ruleset.format`,
`ruleset.unsupported_matcher`, `ruleset.compile`, `rule.compile`, `rule.allocation`,
`dns.resolve`, and `config.resource_materialization` classes. They never echo
the affected tag, domain, URL, endpoint, or configuration value. Logs and
metrics likewise contain only bounded enums and never use those identities as
labels.
