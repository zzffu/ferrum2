+++
id = "M0-T10"
title = "Replace the self-auditing eleven-job workflow with an outcome profile"
milestone = "M0"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = ["M0-T09"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  ".github/workflows/m0.yml",
  "tests/m0-harness/tests/scope_audit.rs",
  "tests/platform/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "The initial hosted profile has four readable job definitions and six rendered results: one quality, one MSRV, three explicit platform matrix cells with fail-fast false, and one interoperability qualification; job count and names are not encoded as permanent product invariants",
  "Quality first builds workspace binaries once and then runs the four workflow.toml full commands once; it does not separately duplicate quick, security, lifecycle, local-E2E, or full suites",
  "MSRV preserves Rust 1.85.0 check --workspace --all-targets --locked and actual cargo test --workspace --locked execution; the Cargo-managed qualification binary is compiled but its external entry is not a libtest",
  "The Windows MSVC, Linux GNU, and Linux musl cells each build both locked release binaries and run the four native valid/invalid config smokes; GNU and Windows run the 47-row native detection outcome and musl asserts no PT_INTERP or DT_NEEDED",
  "The single interoperability job invokes only M0-T09's hosted qualification interface and succeeds only after explicit M0-INT-001 through M0-INT-004 results are all PASS",
  "The workflow retains the exact trigger allowlist, read-only permissions, full-SHA actions, fixed runner labels, clean exact-SHA checkout, no secrets, no cache dependency, no cross-run evidence, bounded timeouts, and FAIL/BLOCK semantics",
  "scope_audit workflow/YAML/blob/path-snapshot self-validation, rg dependency, filtered test counts, linker help probes, and duplicated Ubuntu command allocation are removed rather than repaired",
  "Every non-mechanical scope_audit claim is mapped before deletion to an existing focused policy/provenance test or to the exact-SHA Team Lead/Architect/QA review checklist; unsafe, secret, zeroize, fixture/reference provenance, license, dependency, generated-artifact, and non-goal conclusions are not silently dropped or rebuilt as another whole-workflow parser",
  "M0 close still requires all six rendered results from one separately authorized complete workflow run/attempt at the exact approved pushed SHA; old run 30322690937 remains failed and cannot be combined",
]
+++

# M0-T10: Replace the self-auditing eleven-job workflow with an outcome profile

## Outcome

把 GitHub Actions 收敛为直接验证结果的薄编排，并删除复刻 workflow 的
`scope_audit` 控制面。

## Context

当前 761-line workflow 与约 2,019-line scope audit相互冻结实现细节。第二次
hosted run暴露的 `rg`、filter和`link /?`失败都发生在产品结果之前。继续修探针会
保留根因。

## In scope

- 四个 job definitions / 六个 rendered results 的 initial profile。
- current quality binary build/full、MSRV check/test、三平台artifact smoke和
  M0-T09 interop entry。
- exact-SHA、permission/action pin、runner、timeout和failure semantics。
- 删除 workflow self-parser/snapshot/mutation、test-count/filter和linker-help probes。
- 保留 platform config fixtures、native detection与musl static assertions。

## Out of scope

- product/wire/runtime/config/reference变更。
- 新 task runner、Docker、自托管runner、cache、artifact publication或branch
  protection。
- remote push/rerun/PR/tag/release；hosted execution需要后续单独授权。
- M3完整平台资格与M4性能门。

## Implementation notes and constraints

- branch/worktree必须从Team Lead指定的exact accepted ADR-0017 planning commit
  创建；不得从当前stale `master`丢失`5969bfd`的M0 implementation。
- workflow只负责编排和可见的provider setup，不重写规格或解析自身YAML。
- matrix必须显式列出profile、runner和target，`fail-fast: false`。
- 实际 release build/native execution取代linker help探针。
- interop job不得重新使用ignored libtest、test filter或case count。
- 所有 generated config、reference和logs留在runner temp/target并脱敏。
- workflow syntax能否在GitHub实例化属于最终hosted gate；不得为此再建立第二套
  repository YAML interpreter。

## Validation commands

```bash
cargo build --workspace --bins --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo doc --workspace --all-features --no-deps --locked
cargo +1.85.0 check --workspace --all-targets --locked
cargo +1.85.0 test --workspace --locked
git diff --check
```

平台与external commands不在本机冒充provider evidence。Architect/QA逐项审阅
workflow mapping；实际 syntax/matrix/result evidence只由后续新 exact-SHA hosted
run建立。

## Risks

- workflow首次实例化前只能静态审阅，不能声称hosted PASS。
- 单 interop job减少VM隔离；M0-T09必须证明四案独立、全部尝试和4/4 aggregation。
- GitHub runner image仍会漂移；记录label、ImageOS/ImageVersion、toolchain和run
  identity用于追溯，不宣称M3资格。

## Blocker record

本票取代四个mechanical derivatives，不把旧run改为PASS。最终集成候选
`8318ef106d6cd4e029bd3b02aa64125fabdda462`完成local/review gates后，使用
一次性精确授权正常推送到`refs/heads/codex/integration/m0`。GitHub Actions
run `30331336772` attempt 1在同一SHA上完成quality、MSRV、Windows MSVC、
Linux GNU、Linux musl和interop六项success，整体workflow success。
`M0-CI-CONVERGENCE`及其MSRV derivative已据此关闭。

## Completion evidence

- Branch: `codex/ticket/m0-t10`
- Commit(s): `e06a7eac61b30f14a7b78176d0c4d7830c0a6ee1`,
  `ba874fa97c2929c6115d9181aaddf73360dd375b`,
  `3d76d225260c207252a2ced7085975e79e69dfcc`,
  `5ad65d6eaa9e1cbd6120d599cc5dead763287dfe`
- Required reviewer role/profile and verdict: Architect
  (`gpt-5.6-sol/max`) PASS；QA (`gpt-5.6-sol/high`) PASS；最终集成与托管
  evidence QA均PASS。均未使用fast-mode override；实际launch metadata不可观察，
  因此标记为unverified。
- Exact candidate SHA: `5ad65d6eaa9e1cbd6120d599cc5dead763287dfe`
- Integrated commits: `8ab6292`, `e4b68f3`, `f626ca5`, `e41dbd2`；
  最终exact integration SHA
  `8318ef106d6cd4e029bd3b02aa64125fabdda462`
- Validation: `cargo build --workspace --bins --locked`、authoritative quick
  3/3、full 4/4、fresh external target的Rust 1.85
  check→build binaries→workspace test、workflow unit 53/53、qualification
  pure-state 8/8、workspace policy 17/17、metadata/tree/diff-check/doctor/
  validate均exit 0。未在本机运行`m0-qualification`、reference、网络或WSL2
  interoperability。
- Hosted evidence:
  [run 30331336772 attempt 1](https://github.com/zzffu/ferrum2/actions/runs/30331336772/attempts/1)
  在exact integration SHA上整体success，六项required results全部success。
  匿名job-log下载的HTTP 403仅限制文本可见性；exact reviewed workflow中
  interop success必然要求两个provider setup为0、qualification exit为0且4/4。
