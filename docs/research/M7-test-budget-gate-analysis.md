# M6/M7 test-budget 门禁根因与治理提案

- **Status:** accepted；M7-T05 implements the approved control-plane change。
- **Scope:** 解释 M6、M7 连续出现的 Budget 阻塞，并给出下一张 control-plane ticket 的最小契约。
- **Non-goal:** 不把 M7 当前超限追认为 PASS，不删除/压缩独立测试，不用无意义产品代码换预算。

## 事实

当前策略把 M6 exact tree 的 `22853 / 15032` 固化为永久 tests/code ceiling，同时保留
M4 anchor `48383be` 的 `20878 / 14173` 非上行 ratchet 和每票 `ticket_debt <= 120`。

| checkpoint | code | tests | ratio | ceiling headroom / overflow | ticket delta code/tests/debt |
| --- | ---: | ---: | ---: | ---: | ---: |
| M6 close `0ab207c` | 15032 | 22853 | 1.520290 | 0 | — |
| M7-T01 `f6ee43f` | 15303 | 23232 | 1.518134 | +32 | +271 / +379 / 108 |
| M7-T02 `b864a40` | 15506 | 23534 | 1.517735 | +39 | +203 / +302 / 99 |
| M7-T03 `b3f7ff8` | 15529 | 23968 | 1.543435 | -360 | +23 / +434 / 411 |
| M7-T04 `953689a` | 15529 | 24619 | 1.585356 | -1011 | +0 / +651 / 651 |

最终树若只为满足现有比率而补产品代码，需要增加 `665` 行无意义 code。Hosted run
`30794873478/1` 的 Full step 成功后，Budget 以 `ratio_ceiling_exceeded` 退出，连带跳过
同一 job 后面的 focused IPv6 与 completion marker。

## 根因

1. **控制量错误：** tests/code ratio 把必要的安全、生命周期和负向证据视为债务，却允许
   增加无关产品代码、删除测试或重分类路径来“改善”结果；它不衡量测试价值或维护成本。
2. **上限没有规划语义：** M6-T04 以已完成 M6 的 exact ratio 建立永久 ceiling，初始余量为
   零，却没有为下一里程碑已批准的 evidence plan 分配空间。
3. **两层规则互相重复：** evidence-heavy ticket 同时面对固定 ratio 和 `120` 行 ticket debt；
   M7-T03/T04 即使符合已批准测试计划，也必然被第二层阻塞。
4. **anchor 无法自然前进：** 任何比 M4 anchor 更差的候选只能 `PASS_HOLD`，因此 accepted
   tree 不能成为新 anchor，比较基准长期失真。
5. **CI 故障域错误：** Budget 位于 quality job 中段，一个独立策略失败会阻止 Full marker 和
   focused evidence，令“产品质量失败”与“治理策略失败”无法区分。

## 推荐：schema v2 milestone test envelope

用现有 baseline 文件承载一个规划期的绝对测试增长 envelope，删除 ratio admission、
`PASS_HOLD/PASS_ADVANCE` ratchet 和 per-ticket hard block；不新增依赖或第二套计数器。

最小字段为：tool/版本/series、milestone、exact base SHA、base code/tests 和
`max_test_growth`。规划批准后、首张产品票之前，以 single-parent control-only commit 写入：

```text
test_growth = max(0, candidate_tests - base_tests)
PASS iff test_growth <= max_test_growth
```

- `code` 和 ratio 继续输出为趋势诊断，但不参与 admission，消除“加 code 买 tests”的激励。
- 每票增长超过 `120` 只发 warning / 强制 Architect+QA 解释，不再机器硬阻塞 evidence-only 票。
- exact base 必须是 candidate ancestor；工具版本、base counts、未知/重复字段、mixed control
  commit、merge 和 stale policy 仍 fail closed。
- envelope 从已接受的 milestone test plan 汇总，并包含一项明确的小额 contingency；里程碑内
  只可缩小，不可增加。下一里程碑用新 exact base 替换并归档旧值。
- 删除测试来腾额度仍由 test-plan traceability 与 blocking review 拦截；在出现真实规避案例前，
  不增加 gross-diff 或分类器复杂度。

## CI 解耦

把现有 quality 拆成两个独立 job：

1. `quality` 始终完成 Full、focused IPv6 和自己的 completion marker；marker 不再声明
   `test_budget=PASS`。
2. `budget` 只安装 pinned rustloc、校验 schema v2 并输出独立 marker。正常情况下仍可作为
   required check；显式 waiver 只影响该 check，不污染其他证据状态。

这不增加 provider、产品代码或测试框架，只移动现有 step 并收窄 marker 语义。

## Accepted activation

1. `953689a` 的历史 Budget 仍只记录为 waived `BLOCKED`，不得改写成 PASS。
2. M7-T05以该exact product SHA和counts `15529/24619`为新policy base；在首张后续Rust票
   T06之前分配其标准rustfmt输出的精确`max_test_growth=864`，无额外余量。
3. T05与T06改变新的exact SHA；M7保持open，任何新push和hosted qualification仍需另行授权。
4. 不采用单纯抬高 ceiling、删除/压缩测试、补 inert code 或路径重分类；这些只移动数字，保留
   同一激励缺陷。

## 实现验收

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify --candidate <exact-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-base> --candidate <exact-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <exact-sha>
cargo fmt --all -- --check
git diff --check
```

还必须以临时 commit/tree controls 证明：envelope equality PASS、`+1` BLOCKED、code padding
不改变结果、ticket `>120` 只 warning，以及 stale/malformed/mixed-control/错误 base count 全部
ERROR。Workflow fixture 必须证明 Budget 红灯时 quality 的 Full、focused marker 仍完整产生。

## 风险

- **估算偏松/偏紧：** 在 test-plan review 时逐项汇总并只给显式 contingency；里程碑中不扩容。
- **净计数可被删测试规避：** 继续以 approved evidence mapping 和 blocking review 保护；只有出现
  实际规避后才升级到更复杂的 gross-diff 规则。
- **迁移改变 exact SHA：** control change 与产品变更隔离，并按上述边界重新资格化。
