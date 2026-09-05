# CI / workflow 工程审查

基线2fb0dd4a。完整阅读 tools/ci 的8个Python生产文件、根/tools/ci/tests/ci AGENTS、
m0普通quality/platform/interop/required jobs、lifecycle与fuzz workflows；performance相关
workflow由candidate-tooling分组完整核对。检查了workspace manifests、toolchain、README和docs索引。
没有执行CI工作流、provider下载、fuzz campaign、特权网络或新动态故障输入。

## 已确认符合的边界

- changed-path discovery只接受完整SHA，使用参数数组、NUL分隔diff，PR用merge-base范围。
  缺失commit、空/未知event、不可确定diff均走昂贵门禁，而非跳过。
- required_gate为唯一typed终态表；精确依赖集合，分类器必须成功，true时全部SUCCESS，
  false时全部SKIPPED；missing/extra/cancelled/failed不会通过。
- fuzz ledger独立覆盖crate/build/executable输入，只有明确Markdown exclusion可排除；
  runtime预算由typed policy总计3600秒，各target有单次timeout/RSS及外层kill deadline。
  Corpus在RUNNER_TEMP复制，artifact/run attempt身份和最终tracked-clean检查保留。
- 四个workflow actions均为固定SHA，Rust/toolchain/外部provider版本明确；TUN普通safe库
  no-default-features/fuzzing且检查PE imports。client测试仅编译。provider setup逐行独立，
  setup helper退出0不等于资格通过：其状态经GITHUB_ENV流入qualification，最终interop_run
  要求transport和DNS两个组全部成功。没有将该聚合流程误报为吞失败。
- 当前fuzz concurrency的queue:max + cancel-in-progress:false是有效组合，已核对
  [GitHub官方并发规则](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)。
  不因记忆中的旧语法误报。该队列最多100个pending运行；未声称无限保留所有提交。

## 发现

### CI-01 / P2 — 子命令边界依赖外层job，局部timeout不拥有整个进程树

位置：tools/ci/git_changes.py::_git；interop_run.py::execute；interop_provision.py::run。
规则：tools/AGENTS和tools/ci/AGENTS要求有边界的effects与确定性控制。
事实：前两者同步subprocess.run捕获全部stdout/stderr，没有局部timeout或输出cap。
provision.run有timeout，但没有进程组owner；其make -j2/configure命令可以创建后代。
可能触发：native工具卡住、输出持续增长、直接子进程被timeout终止而后代仍持有输出管道。
影响：单provider/单组的预算和清理不能只依据直接子进程返回证明；整个CI job的5/60分钟
上限与provision外层timeout是实际缓解，不能描述为绝对无时限。
这是静态ownership缺口；未制造卡住命令/后代，也未测得实际CI泄漏。
后续：统一有界输出/绝对deadline/进程树退出与reap owner；以普通注入command结果和
可控短进程验证失败后仍有完整group结果，并明确external job kill能保证与不能保证的范围。

### CI-02 / P2 — 普通workspace test与Rule qualification compile-only规则冲突

位置：.github/workflows/m0.yml ordinary Rust tests约150行，根AGENTS同一cargo命令；
tools/ferrum2-rule-qualification/AGENTS规定ordinary只compile，package内部分#[test]
实际调用计时benchmark。由rule-tooling报告详细列出，统一归属该报告，避免重复计算。
后续设计必须让根命令、CI与package测试分类一致；不能以删除失败测试或放宽门禁解决。

### CI-03 / P3 — manifest schema数字类型没有严格闭合

位置：tools/ci/interop_manifest.py::parse_document，schema_version != 1。
事实：Python bool与int相等，这里未像positive_integer拒绝bool；TOML schema_version=true
在这一检查被当作1。影响仅当前本地reviewed manifest解析契约，后续provider字段仍验证，
不是远程执行路径。未生成/运行异常manifest。后续收紧精确类型，并用普通parser contract
验证合法schema与类型不符的拒绝。

## 仍需记录的可复现性与覆盖限制

BIND源码及archive身份固定，但apt安装的native library工具依赖未固定、未逐项写入
provider fingerprint；最终版本/来源检查证明相应工具身份，不能证明链接环境逐次相同。
这是环境证据限制，不能直接说现有interop结果无效。后续需要记录实际native依赖版本。

Windows native build step关闭PSNativeCommandUseErrorActionPreference后，对早期rustup/
rustc/cargo版本打印未逐条检查exit；后续locked构建/完整平台资格仍提供强失败门禁。
可作为低优先级命令诊断一致性整改，不升为已证明错误二进制被接受。

普通CI controller套件55项的历史结果已保留；本阶段未重复执行。测试契约涵盖typed
required状态、git差异失败闭合、fuzz impact新可执行输入及mock provider isolation，
不执行实际provider/fuzz/performance。当前平台资格和旧完整门禁不等价于上述失败边界已验证。
