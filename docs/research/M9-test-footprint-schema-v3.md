# M9 test-footprint schema v3 升级说明

- **Status:** active control-plane policy；revision 2 corrects standalone Rust fixture coverage。
- **Exact base:** `78cc5cee00cb976a1d46ef7aa9c990eaf1f647dd`（M8 close）。
- **Baseline counts:** `code=15996`、`tests=26916`，来自 exact base 上用 pinned
  `rustloc 0.19.1` 分别扫描 Cargo workspace 与 `tests/fixtures/` 后去重合并；分类为
  `test_case_loc=22369`、`test_support_loc=3950`、`test_fixture_loc=597`。
- **Assumption:** 仓库尚无 M9 计划文件，因此新策略暂命名为 `M9`；正式规划时可在首张产品票
  之前用独立 control-only commit 改名或调整阈值。

## 目标

保留测试维护面治理，消除“为了通过行数门禁而压缩、删除必要测试”的错误激励：

1. 工具版本、精确基线、计数可复现性和 control-plane 防篡改继续 fail closed；
2. 行数阈值只产生 `PASS`、`WARN`、`REVIEW_REQUIRED`，均 exit `0`；
3. 将 Rustloc `Tests` 拆成 test case、test support、test fixture 三类；
4. 让 Codex 对新增证据的独立故障模式、测试层级和 helper 复用负责；
5. 允许在实现中发现新风险后受控 reforecast，而不是只允许缩小额度。

## 默认控制规则

所有阈值采用严格“大于”比较：

| 信号 | PASS | WARN | REVIEW_REQUIRED |
|---|---:|---:|---:|
| 仓库 `tests/code` | `<= 2.0` | `> 2.0` | `> 2.5` |
| 单 ticket / CI change-set 正测试增长 | `<= 240` | `> 240` | `> 600` |
| 新建或继续扩大的单测试文件 semantic test LOC | `<= 800` | `> 800` | `> 1200` |

单文件规则只对“相对 comparison base 发生增长”的文件升级状态。已有大文件仍在报告中显示，
但不会使每个无关提交永久 `REVIEW_REQUIRED`；继续扩大已有大文件则会触发审查。

机器无法可靠判断两个 helper 是否语义重复，因此“出现第三份同类 helper”保留为
Architect/QA 人工 `REVIEW_REQUIRED` 规则。

## Tests 三分类

脚本对 Cargo workspace 与 `tests/fixtures/` 两次 `rustloc --by-file` 扫描的合并结果进行
first-match 分类。独立 fixture 扫描的路径先统一加上 `tests/fixtures/` 前缀，重复路径会
fail closed：

1. `test_fixture_loc`
   - `tests/fixtures/**`；
   - 路径段 `test-fixtures`、`test_fixtures`、`snapshots`、`testdata`。
2. `test_support_loc`
   - `tests/<harness>/src/**`；
   - `*/tests/{common,support,helpers,fakes}/**`；
   - tests 路径中的 `common.rs`、`support.rs`、`helpers.rs`、`fakes.rs` 及
     `*_support.rs`、`*_helpers.rs`、`*_fakes.rs`。
3. `test_case_loc`
   - 其余全部 Rustloc test lines，包括产品文件里的 inline `#[cfg(test)]` 和普通 integration
     test 文件。

脚本强制：

```text
test_case_loc + test_support_loc + test_fixture_loc == tests
```

静态 JSON/TOML/二进制 fixture 不属于 Rustloc 的 Rust `Tests`，因此不进入上述等式；它们仍需
provenance、license、体积和 diff 审查。revision 1 的 workspace-only 扫描遗漏了 3 个独立
Rust fixture generator；revision 2 在不修改 Cargo workspace topology 的前提下纳入其 597 行。

## 状态与退出码

```text
PASS / WARN / REVIEW_REQUIRED  -> exit 0
BLOCKED                        -> exit 1
ERROR                          -> exit 2
```

`BLOCKED`/`ERROR` 仅用于无法可信执行的情况，例如：

- rustloc 缺失或不是 `0.19.1`；
- policy malformed、未知/重复字段、阈值顺序错误；
- exact base 不是 ancestor，或重算 code/tests 与 baseline 不同；
- product/config 与 control policy 混在同一提交；
- merge 产生了不继承任一 parent 的 control resolution；
- 里程碑内偷偷移动 base/counts，或改阈值但未增加 revision/理由。

## 受控 reforecast

同一 milestone 内允许提高或降低阈值，但必须：

1. exact base SHA、base code/tests 不变；
2. 独立 single-parent control-only commit；
3. `policy_revision` 恰好 `+1`；
4. `reforecast_ref` 改为批准该变化的 plan、test-plan 或 review 决策引用；
5. 不与 Rust 或其他实现/config 变更混合。

下一 milestone 的策略从新的 accepted exact base 启动，`policy_revision` 重置为 `1`，并且该
base 到 policy activation commit 之间不得包含 Rust 变更。

## 激活与旧 binding 迁移

当前压缩包中的 `branch.master.testBudgetBase` 仍可能指向 M8 计划基线。新脚本对 staged
control-plane 变更自动使用 `HEAD` 作为 comparison base，因此不会要求先破坏旧 binding 才能
提交 schema 3 activation commit。激活后执行：

```sh
sh scripts/test-budget.sh bind --base HEAD
```

当旧 `testBudgetBase` / `testFootprintBase` 已是新 policy exact base 的 ancestor 时，`bind` 会清理
旧 key 并写入新的 `testFootprintBase`，输出 `migrated_stale_binding=yes`。若旧 binding 来自分叉
历史而不是过期 ancestor，仍 fail closed。

## Codex 执行约束

新增测试前必须能说明：

1. 独立的 contract、threat、regression 或 failure mode；
2. 现有测试为什么没有证明它；
3. unit / integration / process / E2E 中最便宜且充分的层级；
4. 是否可以扩展现有 table，而不是复制 case；
5. 是否复制了 helper、fake、builder、oracle 或 harness。

Ticket 返回中记录：总 footprint 状态、`test_case_loc` / `test_support_loc` /
`test_fixture_loc` delta、最大增长文件以及未解决的 review decision。

## 验收命令

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh self-test
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify --candidate HEAD
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <ticket-base> --candidate <candidate>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration>
git diff --check
```

`verify --candidate HEAD` 需要先把本升级作为 control-only commit 提交，因为 baseline schema v3
必须存在于被验证的 Git tree 中。
