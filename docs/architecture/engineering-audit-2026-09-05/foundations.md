# Foundations static engineering audit — progress saved

Scope: ferrum2-core, ferrum2-rule, ferrum2-config. Review base supplied by root: HEAD 2fb0dd4a. No product edits or commits were made. Root and all three scoped AGENTS.md, root/package manifests, README.md and docs/README.md were read. docs/config-v2-dns-rulesets.md was consulted for the RuleSet contract. The earlier remediation document was not treated as complete coverage.

Coverage: 48 production Rust files were individually read through their production implementation. The companion foundations-coverage.json records each path. Test files were sampled (including selector concurrency contracts and SRS fixture tests), not exhaustively audited. A static read is not dynamic proof. No remaining src production file is marked unread in this assigned scope.

## Findings supported by static source

### FND-01 — P1: first-hop discovery expands shared selector paths repeatedly
Location: crates/ferrum2-config/src/validation/client.rs:387.
Contract: bounded selector/selector-member resources and fail-closed side-effect-free preparation; root requires input/resource/lifecycle review.
Trigger: a valid acyclic selector graph has shared nested successors. The first_hops closure puts every member into pending without a visited set and appends every encountered leaf to first. Deduplication occurs only after traversal. Repeated shared subgraphs therefore cost work proportional to paths, not nodes/edges; configured structural limits do not bound that amplification to a practical amount. This executes for ordinary roots even when TUN is absent.
Impact: preparation latency and temporary memory can grow sharply for small valid configuration graphs. This is a source-level complexity conclusion, not a measured CPU or memory result in this review.
Direction: compute reachable first-hop sets once per validated graph/node, or use a bounded visited traversal per root. Reuse the typed graph rather than reconstructing string-based traversal in client validation.
Verification after architecture design is complete: ordinary shared-DAG behavior test with a deterministic visit/work bound and identical physical first-hop results; paired qualification compilation/matching measurements. No resource-exhaustion input was created or run here.

### FND-02 — P1: recursive capability evaluation precedes the structural size check
Locations: crates/ferrum2-config/src/prepared/prepare/core.rs:135; crates/ferrum2-config/src/prepared/prepare/rule_egress.rs:261; core route validate_identities.
Trigger: parsed selector/chain counts and recursive depth reach EgressCapabilityEvaluator before validate_client/server_graph and core reject counts above 64. The evaluator memoizes shared nodes but uses native recursion and has no depth/count admission check. The 1 MiB source cap is not a 64-node/depth cap.
Impact: invalid over-limit configurations can perform substantial recursive work before a closed ConfigError; stack exhaustion is a plausible consequence dependent on build/platform stack size. It was not dynamically reproduced and is not claimed as an observed crash.
Direction: admit bounded identities/member/hop counts before capability/dependency work; prefer an iterative traversal using the already planned graph where appropriate.
Verification: bounded over-limit contract tests must return the precise field error before traversal, including long reference chains. Dynamic stress reproduction remains unperformed.

### FND-03 — P1: SRS decoding lacks complete byte/entry/work admission limits
Locations: crates/ferrum2-rule/src/srs/decode/primitives.rs:96; srs/decode/primitives.rs read_string_slice/read_u64_words; srs/decode/framing.rs; srs/decode/domain_set.rs; srs/decode/ip_set.rs read_ip_set.
Trigger: file-controlled lengths/counts directly request allocation before enough payload is known; strict zlib validates framing but has no total output/work budget; succinct expansion accumulates complete keys before validating normalized domain length.
Impact: a configured remote RuleSet or cache file can cause disproportionate allocations/decoding work. try_reserve converts some allocator failures to Allocation but is not a resource limit. Root supplied prior evidence: target/remediation-srs-bounds-red.log reportedly records a tiny truncated string declaration causing 1,108,640 allocated bytes, and u64::MAX collection reporting Allocation. That is inherited evidence, not a reproduction by this agent, and should retain its original provenance.
Direction: jointly design loader compressed-byte bounds and decoder decompressed-byte/entry/string/expanded-key/work bounds; reject before allocations and preserve the pinned real fixture cohort. Coordinate with runtime/RuleSet owner. Do not restore paused SRS work during the audit.
Verification: small deterministic malformed framing/length cases and exact closed errors, fixture equivalence, allocation accounting and paired decode/compile qualification after implementation.

### FND-04 — P2: valid IPv6 range ending at the maximum address is rejected
Location: crates/ferrum2-rule/src/srs/decode/ip_set.rs:114 (IPv6 branch).
Trigger: the final CIDR ends at u128::MAX and host_bits is below 128. checked_add computes the next address and errors before recognizing that the current block exhausted the range. Only the entire-address-space /0 special case bypasses this.
Impact: legal IPv6 RuleSet ranges ending at the maximum address cannot decode; refresh would retain the older snapshot or initial load would fail.
Evidence: arithmetic/source review only. Planned public decoder reproduction was not run.
Direction: recognize coverage of the inclusive end before incrementing, with explicit maximum-end handling. Verify /0, /1 and /128 upper-bound cases alongside adjacent non-maximum ranges through the public SRS decoder.

### FND-05 — P2: ordinary listeners and metrics do not share alias validation
Locations: crates/ferrum2-config/src/validation/client.rs:241; crates/ferrum2-config/src/validation/server.rs:194; crates/ferrum2-config/src/validation/common.rs:519. DNS already uses sockets_alias in common.rs.
Trigger: wildcard IPv4 listener and a concrete IPv4 listener on the same port, or metrics on loopback sharing a wildcard proxy port. contains checks equality, accepting overlap that sockets_alias already represents for DNS.
Impact: offline validation accepts a listener set with a bind conflict; failure is delayed until startup. Composition owner confirmed bind errors become StartupBind. No socket was bound during this review.
Direction: unify same-family listener overlap checks and use them across ordinary, DNS and metrics listeners. Keep cross-family dual-stack behavior explicit instead of assuming platform semantics.
Verification: prepare client/server fixtures for wildcard/concrete overlap and disjoint controls; zero listener I/O required.

### FND-06 — P2 contract: borrowed egress plan Debug reveals hop identities
Location: crates/ferrum2-core/src/route.rs:22 on EgressPlan.
Contract: core scoped AGENTS explicitly requires routes/selectors/plan snapshots redacted. EgressPlanSnapshot and EgressPlanHandle redact, but the borrowed EgressPlan derives Debug and exposes its hops slice.
Impact: formatting this public plan discloses internal outbound identities. No production logging call exposing peer addresses was demonstrated; do not elevate this to a proven key/address leak.
Direction: manual redacted Debug matching the owned snapshot. Verify the public direct-handle borrowed/owned formatting together.

### FND-07 — P2 API contract: empty domain fields compile successfully
Location: crates/ferrum2-rule/src/program/matcher.rs:384; adjacent DomainSuffix and DomainKeyword branches.
Trigger: public RouteMatcher::try_new receives one of these fields with an empty Vec. Those branches build an empty CompiledMatchSet, whereas IP/CIDR/scalar/MatchSet fields reject EmptyField.
Impact: a supposedly validated field silently becomes a never-matching predicate. Configuration parsing explicitly rejects empty arrays, so no configuration bypass is established.
Direction: enforce the same field nonempty contract before building each domain category. Verify all three through public API and both linear/indexed evaluation behavior.

## Engineering/design items, not demonstrated production faults

- crates/ferrum2-core/src/selector.rs:106: Allocation, RuleCompile, StaticBinding, RouteRules, RouteRuleInbound, RouteRuleOutbound and RouteFinal have no production construction sites in the reviewed core/rule implementation; repository search finds only config mapping arms. Remove obsolete vocabulary and mappings under the no-compatibility policy. This is API/ownership cleanup, not a runtime defect.
- crates/ferrum2-core/src/selector.rs:190: nested resolve loads each selected atomic independently. It always selects one complete immutable plan, but does not establish a common generation for the whole selector traversal. A concurrent outer switch followed by an inner switch can mix traversal observations. Composition owner read client routing and confirmed terminal snapshots have no universal generation retry; UDP exposes a separate generation/watch API. Decide whether cross-selector linearizability is required before changing synchronization. No deterministic concurrency reproduction was run; existing concurrency tests switch one inner selector and check membership, which does not establish cross-selector linearizability.
- Trait ValidatedRoute in prepared/finish.rs has no purpose/implementor-obligation documentation and wraps only two field accesses; prefer direct attachment or justify/document the trait. Core transport traits use native Send futures and retain runtime-neutral boundaries.
- model.rs exposes many mutable fields despite being described as validated state. This is an architectural invariant enforcement weakness for downstream Rust callers, not a demonstrated input path bypass. Design together with consumer ownership, avoid a mechanical getter-only rewrite.
- validation/v2.rs duplicates CIDR parsing/build work to get field-specific errors; DNS/ordinary validators separately implement several canonicalization/duplicate checks. Quadratic duplicate checking is bounded by source size but unmeasured; prefer a cohesive shared typed field compiler if profiling/large-config evidence warrants it.
- Core route/selector are public modules, and rule exports low-level candidate/building infrastructure used by DNS. Minimize exports with consumer evidence; do not mechanically hide intentional cross-crate seams.
- Several production modules approach/exceed the root guidance (config model/raw/common/v2 and prepared model; rule matcher/candidate/match_set). Their owner-specific responsibilities were reviewed. Line count alone is not treated as a finding requiring splitting.

## Actual verification and interruption

Ran cargo test -p ferrum2-core -p ferrum2-rule -p ferrum2-config --locked, redirected to target/remediation-audit/foundations-tests.log. The observed log ends with passing suite and doc-test summaries; this agent did not record the final process exit status before being instructed to stop. No new tests were added. Ordinary tests perform no privileged network mutation.

Dynamic verification of the new findings was not completed. Root reported that automatic content review interrupted the prior turn and explicitly instructed this agent not to retry/rewrite the blocked dynamic reproduction or create/run resource-exhaustion inputs. The exact automatic-review reason/action payload was not supplied to this agent, so it is not invented here. Work stopped at saving existing static evidence. No performance no-regression claim, qualification result or optimization is made.

Remaining work: root should triage findings against other crate reports; complete bounded behavioral validation only through an independently authorized safe plan; settle shared architecture; implement as a later phase; run affected gates and paired qualification before any CPU-profile-guided optimization. Product code and paused SRS changes remain untouched by this agent.
