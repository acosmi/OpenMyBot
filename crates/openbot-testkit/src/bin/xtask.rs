//! `xtask` —— 仓库闸门驱动器。
//!
//! 落点是 `openbot-testkit` 的 bin target 而不是第 11 个 crate：v3 §5.1 只允许四个理由建
//! crate（独立安全边界 / 独立发布单元 / 明显不同的 feature graph / 可单独复用的纯协议），
//! xtask 一个都不满足；而 §5.1 的 crate 表里 `openbot-testkit` 的职责原文就写着 "xtask"。
//! `required-features = ["xtask"]` 让它对 `cargo build --workspace` 完全透明。
//!
//! 子命令：
//!
//! - `parity-check` —— 默认要求完整 parity/overlay/fixtures；公开 checkout 须显式
//!   `--fixtures-only`，只校验 fixtures，不认证产品或完整迁移覆盖率。
//! - `recount`      —— 真跑每份台账 `recount` 数组里的复算命令，把 `expect` 与实得 stdout 逐条对账。
//! - `i18n-check`   —— 中英文键与插值占位符集合逐字相等。
//! - `design-lint`  —— GUI 反向视觉约束与图标 allowlist。
//! - `css-check`    —— Rust class 字面量必须存在于实际编译 CSS。
//! - `bundle-budget`—— WASM gzip、CSS 与字体体积预算。
//! - `golden`       —— 校清单、比较PNG并生成diff、拒绝缺失或占位的245张正式矩阵。
//! - `tools`        —— 获取并校验 GUI 构建期钉版二进制。
//! - `engine`       —— 获取并校验当前平台的钉版 Electron 官方 zip。
//! - `postgres`     —— 获取并校验 PGDG 17.11 官方 source archive；不作首次运行下载。
//! - `electron-shim-check` —— 在 P1 写 shim 前先锁定文件、LOC 与 API allowlist。
//! - `first-source-check` —— 只读核第一真源版本/R 行/PA/引擎/GUI 指针与冻结历史。
//! - `acceptance-check` —— 核 v5/macOS 与 v6 M0/M1/full_v6 收集记录；不认证产品或发行。
//! - `ci`           —— 按 v3 §16.3 的固定顺序跑本机可执行的那一段闸门。
//!
//! 用法（`.cargo/config.toml` 已配 alias）：
//!
//! ```text
//! cargo xtask parity-check
//! cargo xtask parity-check --json
//! cargo xtask recount
//! cargo xtask recount --json
//! cargo xtask recount --require-upstream
//! cargo xtask ci
//! ```

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;

// `test-inventory` 的实现落在 `crates/openbot-testkit/src/xtask/test_inventory.rs`。
// 用 `#[path]` 而不是把它挪进 `src/bin/xtask/`：模块源码归属 crate 的 `src/xtask/`（与它
// 服务的 xtask 同名目录），而 `required-features = ["xtask"]` 的隔离靠 bin target 本身 ——
// 挂在 lib 上会把五个 oxc crate 拖进不开 feature 的 `cargo build --workspace`。
#[path = "../xtask/test_inventory.rs"]
mod test_inventory;

#[path = "../xtask/ui_gates.rs"]
mod ui_gates;

#[path = "../xtask/ui_assets.rs"]
mod ui_assets;

#[path = "../xtask/ui_finalize.rs"]
mod ui_finalize;

#[path = "../xtask/golden_gate.rs"]
mod golden_gate;

#[path = "../xtask/tools.rs"]
mod tools;

#[path = "../xtask/engine.rs"]
mod engine;

#[path = "../xtask/engine_protocol.rs"]
mod engine_protocol;

#[path = "../xtask/engine_runsc.rs"]
mod engine_runsc;

#[path = "../xtask/engine_bundle.rs"]
mod engine_bundle;

#[path = "../xtask/electron_shim.rs"]
mod electron_shim;

#[path = "../xtask/parity_overlay.rs"]
mod parity_overlay;

#[path = "../xtask/postgres_source.rs"]
mod postgres_source;

#[path = "../xtask/postgres_maintenance.rs"]
mod postgres_maintenance;

#[path = "../xtask/checked_input.rs"]
mod checked_input;

#[path = "../xtask/first_source.rs"]
mod first_source;

#[path = "../xtask/acceptance.rs"]
mod acceptance;

// ---------------------------------------------------------------------------
// 契约常量
// ---------------------------------------------------------------------------

/// v3 §5.1 的十个 crate，同时也是 parity ledger `owner` 字段的封闭取值域（规则 3）。
const OWNERS: [&str; 10] = [
    "openbot-contracts",
    "openbot-domain",
    "openbot-application",
    "openbot-infra",
    "openbot-agent",
    "openbot-computer",
    "openbot-server",
    "openbot-ui",
    "openbot-desktop",
    "openbot-testkit",
];

/// R127's sole workspace member outside the parity-owner domain. It contains no migrated product
/// behavior and exists only because Win32 unsafe FFI is an independent security/feature boundary.
#[cfg(test)]
const NON_PARITY_WORKSPACE_MEMBERS: [&str; 1] = ["openbot-windows-sandbox"];

/// repository contract §4〈parity 与新增必须分开标注〉：三值封闭域，中文原样（规则 2）。
///
/// 把新增写成"当前行为"是 v2 审计里最重的一类错误（v3 §28.1 R1），所以这里不接受
/// 大小写变体、英文译名或第四个值。
const LABELS: [&str; 3] = ["parity", "新增", "替代"];

/// 统一 schema v1 的 `status` 封闭域。规则 4 依赖它 —— 如果 `status` 可以是任意字符串，
/// "status=done 当且仅当 done_evidence 非空"这条双向约束在 `status: blocked` 上会静默为真。
const STATUSES: [&str; 3] = ["todo", "in_progress", "done"];

/// 顶层键封闭集。reviewer裁决："不得自行增删顶层键"。
const TOP_LEVEL_KEYS: [&str; 6] = [
    "schema",
    "schema_version",
    "upstream_commit",
    "generated_by",
    "recount",
    "entries",
];

/// entry 的必填键（规则 1）。
const ENTRY_REQUIRED_KEYS: [&str; 9] = [
    "id",
    "upstream",
    "label",
    "target",
    "owner",
    "test_id",
    "migration_rule",
    "status",
    "evidence",
];

/// entry 的可选键（规则 1 的两个豁免）。
const ENTRY_OPTIONAL_KEYS: [&str; 2] = ["notes", "done_evidence"];

/// `recount` 条目的键集合（规则 8）。
const RECOUNT_KEYS: [&str; 3] = ["command", "cwd", "expect"];

/// `recount[].cwd` 的封闭域：`upstream` = 上游只读克隆，`repo` = 本仓根。
const RECOUNT_CWD: [&str; 2] = ["upstream", "repo"];

/// v3 §1.2 固定源码基线里的 CopilotKit/OpenBot commit。
/// 只用于**告警**，不是 8 条硬规则之一。
const EXPECTED_UPSTREAM_COMMIT: &str = "891df72f1827454d8b353d108fe5dd2313b7e30d";

/// v3 §19.3 + 设计系统文档 §11 列出的 ledger 名。只用于**告警**，不是硬规则。
const KNOWN_SCHEMAS: [&str; 9] = [
    "api",
    "routes",
    "tables",
    "env",
    "events",
    "components",
    "browser-operations",
    "ui",
    "tests",
];

/// `fixtures/MANIFEST.yaml` 相对仓根的固定路径。
///
/// 它的头注释自称"顶层键集合与校验器的八条规则逐条对齐，因此 CI 可以用同一个校验器处理它"
/// —— 在此之前没有任何代码兑现这句话，`parity-check` 只扫 `parity/` 目录。现在它被纳入
/// **同一套 8 条规则**，但**刻意不进 parity ledger 的计数**（见 [`ParityReport`]）。
const FIXTURES_MANIFEST_RELPATH: &str = "fixtures/MANIFEST.yaml";

/// fixtures 台账的 `schema` 取值。它不属于 [`KNOWN_SCHEMAS`] 的九个 parity ledger 名，
/// 所以必须单列 —— 否则每次 `parity-check` 都会为它刷一条"schema 不在名单里"的假告警，
/// 而假告警多了就没人看真告警。
const FIXTURES_SCHEMAS: [&str; 1] = ["fixtures"];

/// 台账的两个种类。决定 `schema` 字段的合法取值域（其余 8 条规则两类完全一致）。
///
/// 分成两类而不是把 `fixtures` 直接塞进 [`KNOWN_SCHEMAS`]：那样 `parity/api.yaml` 写成
/// `schema: fixtures` 也不会有任何提示，等于把两个不同的东西合并成一个名字空间。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerKind {
    /// `parity/*.yaml` —— v3 §19.3 的九份 parity ledger。
    Parity,
    /// `fixtures/MANIFEST.yaml` —— fixtures 台账，不是第 10 份 parity ledger。
    Fixtures,
}

impl LedgerKind {
    /// 本类台账允许的 `schema` 取值（超出只告警，不判红 —— 与原有行为一致）。
    fn allowed_schemas(self) -> &'static [&'static str] {
        match self {
            Self::Parity => &KNOWN_SCHEMAS,
            Self::Fixtures => &FIXTURES_SCHEMAS,
        }
    }
}

/// `migration_rule` 的已知前缀（允许 `preserve: 说明` 这种英文冒号后缀）。
/// 只用于**告警**，不是硬规则。
const MIGRATION_RULE_PREFIXES: [&str; 4] = ["preserve", "rename", "remove", "n/a"];

/// 8 条规则的原文，违规时原样打印，避免"规则 5"这种只有编号没有内容的报错。
const RULES: [&str; 8] = [
    "规则 1：除 notes / done_evidence 外每个键都必须存在且非空字符串（顶层键集合固定，不得自行增删）",
    "规则 2：label 只能是 parity / 新增 / 替代 三个值之一",
    "规则 3：owner 必须是 v3 §5.1 十个 crate 之一",
    "规则 4：status=done 当且仅当 done_evidence 存在且非空（status 本身限 todo / in_progress / done）",
    "规则 5：id 在文件内唯一；test_id 在全部 ledger 内唯一",
    "规则 6：test_id 匹配 ^T-[A-Z]+-[0-9]{4}$",
    "规则 7：upstream 字段禁止裸行号（禁止以 :<数字> 结尾）",
    "规则 8：recount 至少一条，且每条 command 非空",
];

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let subcommand = args.first().map(String::as_str);

    let result = match subcommand {
        Some("parity-check") => cmd_parity_check(&args[1..]),
        Some("recount") => cmd_recount(&args[1..]),
        Some("test-inventory") => cmd_test_inventory(&args[1..]),
        Some("i18n-check") => workspace_root().and_then(|root| ui_gates::i18n_check(&root)),
        Some("design-lint") => workspace_root().and_then(|root| ui_gates::design_lint(&root)),
        Some("css-check") => {
            workspace_root().and_then(|root| ui_gates::css_check(&root, &args[1..]))
        }
        Some("bundle-budget") => {
            workspace_root().and_then(|root| ui_gates::bundle_budget(&root, &args[1..]))
        }
        Some("golden") => workspace_root().and_then(|root| golden_gate::run(&root, &args[1..])),
        Some("ui-assets") => workspace_root().and_then(|root| ui_assets::run(&root)),
        Some("ui-finalize") => ui_finalize::run(),
        Some("tools") => workspace_root().and_then(|root| tools::run(&root, &args[1..])),
        Some("engine") => workspace_root().and_then(|root| engine::run(&root, &args[1..])),
        Some("postgres") => {
            workspace_root().and_then(|root| postgres_source::run(&root, &args[1..]))
        }
        Some("postgres-maintenance") => {
            workspace_root().and_then(|root| postgres_maintenance::run(&root, &args[1..]))
        }
        Some("electron-shim-check") => {
            workspace_root().and_then(|root| electron_shim::run(&root, &args[1..]))
        }
        Some("first-source-check") => first_source::run(&args[1..]),
        Some("acceptance-check") => acceptance::run(&args[1..]),
        Some("ci") => cmd_ci(),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("xtask: 未知子命令 `{other}`");
            print_usage();
            Err(anyhow!("未知子命令"))
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("\nxtask 失败：{err:#}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "\
xtask —— OpenBot 仓库闸门驱动器

用法：
  cargo xtask parity-check [--fixtures-only] [--json]
                                      默认要求九份 parity/overlay/fixtures，缺项失败。
                                      --fixtures-only 只校 fixtures，不校 parity/overlay。
                                      （统一 schema v1 的 8 条规则；fixtures 台账不进 parity 合计）
  cargo xtask recount [--fixtures-only] [--json] [--require-upstream]
                                      真跑每份台账 recount 数组里的复算命令并与 expect 对账。
                                      cwd: upstream 的项需要环境变量 OPENBOT_UPSTREAM_DIR 指向上游克隆；
                                      未设置时这些项报告为 SKIPPED（计数并打印，不当成通过）。
                                      --require-upstream 把 SKIPPED 也判红，供已备好上游克隆的 CI 使用。
  cargo xtask test-inventory --upstream <上游干净克隆路径> [--dry-run]
                                      用 oxc_parser 做 AST 级 test inventory（v3 §24 G0 / G8），
                                      产出 parity/tests.yaml 与 fixtures/tests/upstream-ast-inventory.json
  cargo xtask i18n-check             中英文叶子键与每键插值占位符集合逐字相等
  cargo xtask design-lint            执行 GUI §12.6 反向约束与图标 allowlist 两向检查
  cargo xtask css-check [--css <实际编译 CSS>]
                                      断言每个 Rust class 字面量都出现在编译 CSS
  cargo xtask bundle-budget [--dist <Trunk dist 目录>]
                                      检查 app.wasm gzip、CSS 与随包字体预算
  cargo xtask golden check-manifest | compare | verify
                                      校验visual manifest；比较PNG/生成diff；正式矩阵缺件或占位即红
  cargo xtask ui-assets               同源生成 ignored tokens.css，并用固定 Tailwind 编译 ignored app.css
  cargo xtask ui-finalize             仅供 Trunk post-build 生成外部 WASM bootstrap
  cargo xtask tools fetch            获取当前平台的钉版 Tailwind/wasm-opt，并按 lock 安装
                                      trunk/wasm-bindgen CLI 到 target/tools/bin
  cargo xtask tools verify           校验四个工具的 sha256（下载件）、版本输出与退出码
  cargo xtask engine fetch|verify    获取/校验当前平台 Electron zip、sha256、版本与已存在 bundle
  cargo xtask engine protocol [--check]
                                      从 contracts descriptor 生成/核对 shim protocol 与 hash
  cargo xtask engine bundle          Rust-only 组装 ASAR、fuses、rebrand、integrity 与 manifest
  cargo xtask postgres fetch-source|verify-source
                                      获取/校验PGDG 17.11官方source；只作release build输入
  cargo xtask electron-shim-check    校验 shim 文件/LOC/API allowlist；P1 代码未落时校验规则与空目录
  cargo xtask first-source-check --root <repo> --baseline <manifest> [--json]
                                      只读核第一真源结构/入口/引擎/GUI/冻结 R 行；不认证产品或发行
  cargo xtask acceptance-check --record <json> --candidate <manifest> --evidence-root <dir> [--spec <first-source.md>] [--json]
                                      核 v5/macOS 与 v6 M0/M1/full_v6 收集集合；v6 必须绑定 --spec，
                                      full_v5 及 full_v6 聚合关闭准入明确未支持
  cargo xtask ci                      按 v3 §16.3 顺序跑本机可执行的闸门段
  cargo xtask help                    打印本帮助
"
    );
}

// ---------------------------------------------------------------------------
// test-inventory
// ---------------------------------------------------------------------------

/// v3 §19.3 的 `parity/tests.yaml` 与 §24 G0 的"上游基线测试原始结果归档"。
/// 实现在 [`test_inventory`]；这里只负责定位仓根并透传参数。
fn cmd_test_inventory(args: &[String]) -> Result<()> {
    let root = workspace_root()?;
    test_inventory::run(args, &root)
}

// ---------------------------------------------------------------------------
// 仓库根定位
// ---------------------------------------------------------------------------

/// 从当前目录向上找带 `[workspace]` 的 `Cargo.toml`；找不到时退回编译期的
/// `CARGO_MANIFEST_DIR/../..`（`crates/openbot-testkit` 的祖父目录 = 仓根）。
///
/// 不写死绝对路径：`cargo xtask` 可能在任意子目录里被调用。
fn workspace_root() -> Result<PathBuf> {
    let start = std::env::current_dir().context("读取当前工作目录失败")?;
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            let text = std::fs::read_to_string(&manifest)
                .with_context(|| format!("读取 {} 失败", manifest.display()))?;
            if text.contains("[workspace]") {
                return Ok(dir.to_path_buf());
            }
        }
    }

    let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("无法从 CARGO_MANIFEST_DIR 推出仓库根"))?;
    if fallback.join("Cargo.toml").is_file() {
        return Ok(fallback);
    }
    bail!(
        "从 {} 向上没有找到含 [workspace] 的 Cargo.toml，且编译期兜底路径 {} 也不成立",
        start.display(),
        fallback.display()
    )
}

// ---------------------------------------------------------------------------
// parity-check
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LedgerReport {
    file: String,
    schema: String,
    entries: usize,
    /// status -> 计数。BTreeMap 保证输出顺序稳定，diff 才有意义。
    status_counts: BTreeMap<String, usize>,
    recount_commands: usize,
}

#[derive(Serialize)]
struct ParityReport {
    scope: CheckScope,
    /// Completeness here concerns input identities, not evidence validity or product admission.
    required_inputs_present: bool,
    product_certified: bool,
    parity_checked: bool,
    overlay_checked: bool,
    /// `parity/*.yaml` 的九份 parity ledger。
    ledgers: Vec<LedgerReport>,
    /// `fixtures/MANIFEST.yaml`（0 或 1 条）。**刻意与 `ledgers` 分开**：
    /// `ledgers.len()` = 9 与 `total_entries` = 1641 这两个数被写进了多处文档与 PR 正文，
    /// 把 fixtures 并进去会让那些计数全部对不上 —— 而"计数悄悄变了"正是台账最难查的一类漂移。
    fixtures: Vec<LedgerReport>,
    /// 只统计 `ledgers`，不含 `fixtures`。
    total_entries: usize,
    /// 只统计 `ledgers`，不含 `fixtures`。
    total_status_counts: BTreeMap<String, usize>,
    /// R124 的 exception-only v4 overlay；单列报告，不污染九份 parity ledger 的合计。
    overlay: parity_overlay::OverlayReport,
    violations: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckScope {
    Full,
    FixturesOnly,
}

impl CheckScope {
    fn from_args(args: &[String]) -> Self {
        if args.iter().any(|a| a == "--fixtures-only") {
            Self::FixturesOnly
        } else {
            Self::Full
        }
    }
}

/// 一份待校验的台账：文件路径 + 它属于哪一类。
struct LedgerSource {
    path: PathBuf,
    kind: LedgerKind,
}

/// Collect yaml/yml ledger candidates. Full scope rejects names outside the exact yaml set.
fn collect_parity_ledgers(root: &Path, warnings: &mut Vec<String>) -> Result<Vec<PathBuf>> {
    let parity_dir = root.join("parity");
    let mut files = Vec::new();
    if !parity_dir.is_dir() {
        return Ok(files);
    }
    for entry in walkdir::WalkDir::new(&parity_dir)
        .max_depth(1)
        .sort_by_file_name()
    {
        let entry = entry.with_context(|| format!("遍历 {} 失败", parity_dir.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        match entry.path().extension().and_then(|e| e.to_str()) {
            // 只认 .yaml。
            Some("yaml") => files.push(entry.into_path()),
            Some("yml") => {
                warnings.push(format!(
                    "{}：扩展名是 .yml，不属于必需的 .yaml 台账集合",
                    rel(root, entry.path())
                ));
                files.push(entry.into_path());
            }
            _ => {}
        }
    }
    Ok(files)
}

/// 组装本次要校验的全部台账：九份 parity ledger + fixtures 台账。
///
/// The fixture manifest is required in either scope. Only full scope reads migration ledgers.
fn collect_ledger_sources(
    root: &Path,
    scope: CheckScope,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<Vec<LedgerSource>> {
    let parity_files = if scope == CheckScope::Full {
        collect_parity_ledgers(root, warnings)?
    } else {
        Vec::new()
    };
    let mut sources: Vec<LedgerSource> = parity_files
        .into_iter()
        .map(|path| LedgerSource {
            path,
            kind: LedgerKind::Parity,
        })
        .collect();

    let fixtures_manifest = root.join(FIXTURES_MANIFEST_RELPATH);
    if fixtures_manifest.is_file() {
        sources.push(LedgerSource {
            path: fixtures_manifest,
            kind: LedgerKind::Fixtures,
        });
    } else {
        violations.push(format!(
            "{FIXTURES_MANIFEST_RELPATH}：必需台账不存在，不能按零项通过"
        ));
    }

    Ok(sources)
}

fn cmd_parity_check(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    for a in args {
        if a != "--json" && a != "--fixtures-only" {
            bail!("parity-check: 未知参数 `{a}`（只接受 --json / --fixtures-only）");
        }
    }

    let root = workspace_root()?;
    let report = build_parity_report(&root, CheckScope::from_args(args))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_parity_report(&report);
    }

    if report.violations.is_empty() {
        Ok(())
    } else {
        bail!("parity-check: {} 条违反", report.violations.len())
    }
}

/// 组装完整的校验报告。**只读、不打印、不决定退出码** —— 这样单测可以拿一个临时目录
/// 当仓根，直接断言"fixtures 台账确实被纳入了 8 条规则"以及"它没有污染 parity 的合计"。
fn build_parity_report(root: &Path, scope: CheckScope) -> Result<ParityReport> {
    let mut violations: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let sources = collect_ledger_sources(root, scope, &mut violations, &mut warnings)?;
    if scope == CheckScope::Full {
        let expected = KNOWN_SCHEMAS
            .iter()
            .map(|schema| format!("parity/{schema}.yaml"))
            .collect::<BTreeSet<_>>();
        let actual = sources
            .iter()
            .filter(|source| source.kind == LedgerKind::Parity)
            .map(|source| rel(root, &source.path))
            .collect::<BTreeSet<_>>();
        for missing in expected.difference(&actual) {
            violations.push(format!("full scope: 缺少必需台账 {missing}"));
        }
        for unexpected in actual.difference(&expected) {
            violations.push(format!("full scope: 未登记台账 {unexpected}"));
        }
        if !root.join("parity/overlay/v4.yaml").is_file() {
            violations.push("full scope: 缺少必需 overlay parity/overlay/v4.yaml".into());
        }
    } else {
        warnings.push("fixtures_only：parity/overlay 未检查；不认证产品、发布或完整完成率".into());
    }
    let required_inputs_present = violations.is_empty();

    let mut ledgers: Vec<LedgerReport> = Vec::new();
    let mut fixtures: Vec<LedgerReport> = Vec::new();
    // 规则 5 的跨文件那一半：test_id -> 首次出现的 "文件#id"。
    // fixtures 台账**也**进这张表：规则 5 的原文是"test_id 在全部 ledger 内唯一"，
    // 把 fixtures 排除在外就等于给 T-FIX-* 开了一个不受唯一性约束的后门。
    let mut global_test_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut parity_test_ids = BTreeSet::new();
    let mut done_targets = BTreeMap::new();

    for source in &sources {
        let display = rel(root, &source.path);
        let text = std::fs::read_to_string(&source.path)
            .with_context(|| format!("读取 {} 失败", source.path.display()))?;
        let doc: serde_yaml::Value = match serde_yaml::from_str(&text) {
            Ok(v) => v,
            Err(err) => {
                violations.push(format!("{display}：YAML 解析失败：{err}"));
                continue;
            }
        };

        if source.kind == LedgerKind::Parity {
            collect_document_test_ids(&doc, &mut parity_test_ids);
            collect_done_targets(&doc, &mut done_targets);
        }

        if let Some(report) = check_ledger(
            &display,
            source.kind,
            &doc,
            &mut violations,
            &mut warnings,
            &mut global_test_ids,
        ) {
            let expected_schema = match source.kind {
                LedgerKind::Parity => source
                    .path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(""),
                LedgerKind::Fixtures => "fixtures",
            };
            if report.schema != expected_schema {
                violations.push(format!(
                    "{display}: schema 必须为 {expected_schema}，实际为 {}",
                    report.schema
                ));
            }
            if report.entries == 0 {
                violations.push(format!("{display}: 必需生产台账 entries 不能为空"));
            }
            match source.kind {
                LedgerKind::Parity => ledgers.push(report),
                LedgerKind::Fixtures => fixtures.push(report),
            }
        }
    }

    // 合计只覆盖 parity ledger。见 `ParityReport::fixtures` 的注释。
    let total_entries = ledgers.iter().map(|l| l.entries).sum();
    let mut total_status_counts: BTreeMap<String, usize> = BTreeMap::new();
    for ledger in &ledgers {
        for (status, count) in &ledger.status_counts {
            *total_status_counts.entry(status.clone()).or_insert(0) += count;
        }
    }
    let overlay_path = root.join("parity/overlay/v4.yaml");
    let overlay_checked = scope == CheckScope::Full && overlay_path.is_file();
    let overlay = if overlay_checked {
        parity_overlay::validate(
            root,
            &parity_test_ids,
            &done_targets,
            total_entries,
            &mut violations,
        )
    } else {
        parity_overlay::OverlayReport::empty(total_entries)
    };

    Ok(ParityReport {
        scope,
        required_inputs_present,
        product_certified: false,
        parity_checked: scope == CheckScope::Full && !ledgers.is_empty(),
        overlay_checked,
        ledgers,
        fixtures,
        total_entries,
        total_status_counts,
        overlay,
        violations,
        warnings,
    })
}

fn format_status_dist(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "（无 entry）".to_string();
    }
    counts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_ledger_line(ledger: &LedgerReport) {
    println!(
        "  {:<32} schema={:<20} entries={:<5} recount={:<3} status: {}",
        ledger.file,
        ledger.schema,
        ledger.entries,
        ledger.recount_commands,
        format_status_dist(&ledger.status_counts)
    );
}

fn print_parity_report(report: &ParityReport) {
    println!(
        "parity-check: scope={:?}; {} parity ledger + {} fixtures 台账（不认证产品/发布）",
        report.scope,
        report.ledgers.len(),
        report.fixtures.len()
    );
    for ledger in &report.ledgers {
        print_ledger_line(ledger);
    }
    println!(
        "  合计: entries={} status: {}（只统计上面的 parity ledger）",
        report.total_entries,
        format_status_dist(&report.total_status_counts)
    );

    // fixtures 台账单独一行、单独一段，不进上面的合计。
    if !report.fixtures.is_empty() {
        println!("\nfixtures 台账（同样过 8 条规则，但不是第 10 份 parity ledger，不进合计）：");
        for ledger in &report.fixtures {
            print_ledger_line(ledger);
        }
    }

    if report.overlay_checked {
        let overlay = &report.overlay.disposition_counts;
        println!(
            "\nv4 overlay（carry 隐含；显式 exceptions={}；git diff 要求 revalidate={}）：carry={} revalidate={} split={} superseded={}",
            report.overlay.explicit_entries,
            report.overlay.diff_required_revalidations,
            overlay.get("carry").copied().unwrap_or_default(),
            overlay.get("revalidate").copied().unwrap_or_default(),
            overlay.get("split").copied().unwrap_or_default(),
            overlay.get("superseded").copied().unwrap_or_default(),
        );
    } else {
        println!("\nv4 overlay：未检查");
    }

    if !report.warnings.is_empty() {
        println!("\n告警（不影响退出码）：");
        for w in &report.warnings {
            println!("  ! {w}");
        }
    }

    if report.violations.is_empty() {
        println!("\nparity-check: 通过（0 违反）");
    } else {
        println!("\n违反的规则原文：");
        for rule in RULES {
            println!("  {rule}");
        }
        println!("\n违反明细（{} 条）：", report.violations.len());
        for v in &report.violations {
            println!("  x {v}");
        }
    }
}

/// 从已解析的统一 ledger schema 中提取 test_id，供 R124 overlay 做存在性 join。
/// 结构错误仍由八条规则报告；这里刻意只收可读的字符串，不重复制造第二套 schema 错误。
fn collect_document_test_ids(document: &serde_yaml::Value, ids: &mut BTreeSet<String>) {
    let Some(entries) = document
        .as_mapping()
        .and_then(|map| map.get(serde_yaml::Value::from("entries")))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return;
    };
    for entry in entries {
        let Some(test_id) = entry
            .as_mapping()
            .and_then(|map| map.get(serde_yaml::Value::from("test_id")))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        ids.insert(test_id.to_owned());
    }
}

fn collect_done_targets(document: &serde_yaml::Value, targets: &mut BTreeMap<String, String>) {
    let Some(entries) = document
        .as_mapping()
        .and_then(|map| map.get(serde_yaml::Value::from("entries")))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return;
    };
    for entry in entries {
        let Some(entry) = entry.as_mapping() else {
            continue;
        };
        if entry
            .get(serde_yaml::Value::from("status"))
            .and_then(serde_yaml::Value::as_str)
            != Some("done")
        {
            continue;
        }
        let Some(test_id) = entry
            .get(serde_yaml::Value::from("test_id"))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        let Some(target) = entry
            .get(serde_yaml::Value::from("target"))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        targets.insert(test_id.to_owned(), target.to_owned());
    }
}

/// 校验单个台账。返回 `None` 表示文件结构坏到无法统计（违反已记入 `violations`）。
///
/// `kind` 只影响 `schema` 字段的合法取值域（[`LedgerKind::allowed_schemas`]）；
/// 8 条规则本身对 parity ledger 与 fixtures 台账**逐条相同** —— 这正是
/// `fixtures/MANIFEST.yaml` 头注释所声称、而在此之前没有代码兑现的那件事。
fn check_ledger(
    file: &str,
    kind: LedgerKind,
    doc: &serde_yaml::Value,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
    global_test_ids: &mut BTreeMap<String, String>,
) -> Option<LedgerReport> {
    let map = match doc.as_mapping() {
        Some(m) => m,
        None => {
            violations.push(format!("{file} [规则 1]：顶层不是 mapping"));
            return None;
        }
    };

    // --- 规则 1：顶层键封闭集，缺一不可、多一不可 -------------------------
    let present: BTreeSet<String> = map
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .collect();
    for required in TOP_LEVEL_KEYS {
        if !present.contains(required) {
            violations.push(format!("{file} [规则 1]：缺顶层键 `{required}`"));
        }
    }
    for got in &present {
        if !TOP_LEVEL_KEYS.contains(&got.as_str()) {
            violations.push(format!(
                "{file} [规则 1]：出现未定义的顶层键 `{got}`（统一 schema v1 的顶层键固定为 {TOP_LEVEL_KEYS:?}，不得自行增删）"
            ));
        }
    }

    let schema_name = nonempty_str(map, "schema").unwrap_or_default();
    if schema_name.is_empty() && present.contains("schema") {
        violations.push(format!("{file} [规则 1]：`schema` 不是非空字符串"));
    }
    let allowed_schemas = kind.allowed_schemas();
    if !schema_name.is_empty() && !allowed_schemas.contains(&schema_name.as_str()) {
        warnings.push(format!(
            "{file}：schema=`{schema_name}` 不在本类台账允许的取值域 {allowed_schemas:?} 里"
        ));
    }

    // 1.98.0 的 clippy::collapsible_match 要求这里用 match guard 而不是嵌套 if。
    match map.get(serde_yaml::Value::from("schema_version")) {
        Some(v) if v.as_u64() != Some(1) => {
            violations.push(format!(
                "{file} [规则 1]：`schema_version` 必须是整数 1，实得 {v:?}"
            ));
        }
        // 缺键上面已按规则 1 记过；合法值无需处理。
        _ => {}
    }

    let upstream_commit = nonempty_str(map, "upstream_commit").unwrap_or_default();
    if upstream_commit.is_empty() && present.contains("upstream_commit") {
        violations.push(format!("{file} [规则 1]：`upstream_commit` 不是非空字符串"));
    }
    if !upstream_commit.is_empty() && upstream_commit != EXPECTED_UPSTREAM_COMMIT {
        warnings.push(format!(
            "{file}：upstream_commit=`{upstream_commit}` 不等于 v3 §1.2 固定基线 `{EXPECTED_UPSTREAM_COMMIT}`"
        ));
    }

    if nonempty_str(map, "generated_by").is_none() && present.contains("generated_by") {
        violations.push(format!("{file} [规则 1]：`generated_by` 不是非空字符串"));
    }

    // --- 规则 8：recount ---------------------------------------------------
    let recount_commands = check_recount(file, map, violations, warnings);

    // --- entries -----------------------------------------------------------
    let entries = match map.get(serde_yaml::Value::from("entries")) {
        Some(serde_yaml::Value::Sequence(seq)) => seq.clone(),
        Some(other) => {
            violations.push(format!(
                "{file} [规则 1]：`entries` 必须是序列，实得 {}",
                type_name(other)
            ));
            return None;
        }
        None => return None,
    };

    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut local_ids: BTreeMap<String, ()> = BTreeMap::new();
    let test_id_re = regex::Regex::new(r"^T-[A-Z]+-[0-9]{4}$").expect("test_id 正则是常量");
    let bare_line_re = regex::Regex::new(r":[0-9]+$").expect("裸行号正则是常量");

    for (index, entry) in entries.iter().enumerate() {
        let emap = match entry.as_mapping() {
            Some(m) => m,
            None => {
                violations.push(format!("{file} entry#{index} [规则 1]：entry 不是 mapping"));
                continue;
            }
        };

        // entry 的 id 先取出来做定位标签；取不到就用序号。
        let id = nonempty_str(emap, "id");
        let tag = match &id {
            Some(v) => format!("entry `{v}`"),
            None => format!("entry#{index}（id 缺失或为空）"),
        };

        // 规则 1：必填键非空 + 键集合封闭
        for key in ENTRY_REQUIRED_KEYS {
            if nonempty_str(emap, key).is_none() {
                violations.push(format!(
                    "{file} {tag} [规则 1]：`{key}` 缺失或不是非空字符串"
                ));
            }
        }
        for key in emap.keys() {
            let Some(k) = key.as_str() else {
                violations.push(format!("{file} {tag} [规则 1]：entry 里出现非字符串键"));
                continue;
            };
            if !ENTRY_REQUIRED_KEYS.contains(&k) && !ENTRY_OPTIONAL_KEYS.contains(&k) {
                violations.push(format!(
                    "{file} {tag} [规则 1]：出现未定义的 entry 键 `{k}`（允许集合 = {ENTRY_REQUIRED_KEYS:?} + {ENTRY_OPTIONAL_KEYS:?}）"
                ));
            }
        }

        // 规则 2：label
        if let Some(label) = nonempty_str(emap, "label")
            && !LABELS.contains(&label.as_str())
        {
            violations.push(format!(
                "{file} {tag} [规则 2]：label=`{label}` 不在 {LABELS:?} 内"
            ));
        }

        // 规则 3：owner
        if let Some(owner) = nonempty_str(emap, "owner")
            && !OWNERS.contains(&owner.as_str())
        {
            violations.push(format!(
                "{file} {tag} [规则 3]：owner=`{owner}` 不是 v3 §5.1 十个 crate 之一"
            ));
        }

        // 规则 4：status ⟺ done_evidence
        let status = nonempty_str(emap, "status");
        let done_evidence = nonempty_str(emap, "done_evidence");
        let has_done_key = emap.contains_key(serde_yaml::Value::from("done_evidence"));
        if let Some(s) = &status {
            if !STATUSES.contains(&s.as_str()) {
                violations.push(format!(
                    "{file} {tag} [规则 4]：status=`{s}` 不在 {STATUSES:?} 内（status 域不封闭则规则 4 的双向约束形同虚设）"
                ));
            }
            if s == "done" && done_evidence.is_none() {
                violations.push(format!(
                    "{file} {tag} [规则 4]：status=done 但 done_evidence 缺失或为空"
                ));
            }
            if s != "done" && has_done_key {
                violations.push(format!(
                    "{file} {tag} [规则 4]：status=`{s}` 却带了 done_evidence 键（非 done 时该键必须不出现）"
                ));
            }
            *status_counts.entry(s.clone()).or_insert(0) += 1;
        } else {
            *status_counts.entry("<缺失>".to_string()).or_insert(0) += 1;
        }

        // 规则 5：id 文件内唯一
        if let Some(v) = &id
            && local_ids.insert(v.clone(), ()).is_some()
        {
            violations.push(format!("{file} {tag} [规则 5]：id `{v}` 在本文件内重复"));
        }

        // 规则 5 + 6：test_id
        if let Some(test_id) = nonempty_str(emap, "test_id") {
            if !test_id_re.is_match(&test_id) {
                violations.push(format!(
                    "{file} {tag} [规则 6]：test_id=`{test_id}` 不匹配 ^T-[A-Z]+-[0-9]{{4}}$"
                ));
            }
            let owner_tag = format!(
                "{file}#{}",
                id.clone().unwrap_or_else(|| format!("#{index}"))
            );
            if let Some(first) = global_test_ids.insert(test_id.clone(), owner_tag.clone()) {
                violations.push(format!(
                    "{file} {tag} [规则 5]：test_id `{test_id}` 与 {first} 重复（test_id 必须全仓唯一）"
                ));
                // 保留首次出现者，让后续重复都指向同一个"首犯"。
                global_test_ids.insert(test_id, first);
            }
        }

        // 规则 7：upstream 禁裸行号
        if let Some(upstream) = nonempty_str(emap, "upstream")
            && bare_line_re.is_match(&upstream)
        {
            violations.push(format!(
                "{file} {tag} [规则 7]：upstream=`{upstream}` 以裸行号结尾；位置引用只用符号名（`path::symbol`）"
            ));
        }

        // 以下两条是告警，不在 8 条硬规则里，但 schema 正文写明了。
        if let Some(target) = nonempty_str(emap, "target")
            && (target.contains("TBD") || target.contains("未定"))
        {
            warnings.push(format!(
                "{file} {tag}：target=`{target}` 含 TBD/未定，schema 正文要求 target 是确定落点"
            ));
        }
        if let Some(rule) = nonempty_str(emap, "migration_rule") {
            let head = rule.split(':').next().unwrap_or("").trim();
            if !MIGRATION_RULE_PREFIXES.contains(&head) {
                warnings.push(format!(
                    "{file} {tag}：migration_rule=`{rule}` 的前缀不在 {MIGRATION_RULE_PREFIXES:?} 内"
                ));
            }
        }
    }

    Some(LedgerReport {
        file: file.to_string(),
        schema: if schema_name.is_empty() {
            "<缺失>".to_string()
        } else {
            schema_name
        },
        entries: entries.len(),
        status_counts,
        recount_commands,
    })
}

/// 规则 8。返回 recount 条数（用于报表）。
fn check_recount(
    file: &str,
    map: &serde_yaml::Mapping,
    violations: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> usize {
    let items = match map.get(serde_yaml::Value::from("recount")) {
        Some(serde_yaml::Value::Sequence(seq)) => seq.clone(),
        Some(other) => {
            violations.push(format!(
                "{file} [规则 8]：`recount` 必须是序列，实得 {}",
                type_name(other)
            ));
            return 0;
        }
        None => return 0,
    };

    if items.is_empty() {
        violations.push(format!("{file} [规则 8]：`recount` 至少要有一条"));
        return 0;
    }

    for (index, item) in items.iter().enumerate() {
        let imap = match item.as_mapping() {
            Some(m) => m,
            None => {
                violations.push(format!("{file} recount#{index} [规则 8]：不是 mapping"));
                continue;
            }
        };
        if nonempty_str(imap, "command").is_none() {
            violations.push(format!(
                "{file} recount#{index} [规则 8]：`command` 缺失或为空"
            ));
        }
        match nonempty_str(imap, "cwd") {
            Some(cwd) if RECOUNT_CWD.contains(&cwd.as_str()) => {}
            Some(cwd) => violations.push(format!(
                "{file} recount#{index} [规则 8]：cwd=`{cwd}` 不在 {RECOUNT_CWD:?} 内"
            )),
            None => violations.push(format!("{file} recount#{index} [规则 8]：`cwd` 缺失或为空")),
        }
        if !imap.contains_key(serde_yaml::Value::from("expect")) {
            violations.push(format!(
                "{file} recount#{index} [规则 8]：缺 `expect`（复算命令没有期望值就无法被重跑核对）"
            ));
        }
        for key in imap.keys() {
            let Some(k) = key.as_str() else { continue };
            if !RECOUNT_KEYS.contains(&k) {
                warnings.push(format!(
                    "{file} recount#{index}：出现未定义的键 `{k}`（允许集合 = {RECOUNT_KEYS:?}）"
                ));
            }
        }
    }

    items.len()
}

// ---------------------------------------------------------------------------
// recount —— 真跑台账里的复算命令
// ---------------------------------------------------------------------------

/// 指向上游只读克隆的环境变量。
///
/// 刻意**不**在代码里猜路径：上游克隆在不同机器上落在不同地方，猜出来的默认值只会让
/// "跑没跑过 upstream 那批"这个问题变得不可判定。未设置 = SKIPPED 并计数，不是通过。
const UPSTREAM_DIR_ENV: &str = "OPENBOT_UPSTREAM_DIR";

/// Windows 上 Git for Windows 自带的 POSIX shell 候选路径。
///
/// **必须用绝对路径**：本机 `PATH` 上的裸 `bash` 可能落到 `System32` 的 WSL bash，
/// 那是另一个文件系统命名空间，`cd repo` 会直接找不到目录，而失败形态是"命令输出为空"
/// —— 与"计数真的是 0"不可区分。
const WINDOWS_SHELL_CANDIDATES: [&str; 2] = [
    r"C:\Program Files\Git\usr\bin\bash.exe",
    r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
];

/// 非 Windows 上的 shell 候选路径。
const UNIX_SHELL_CANDIDATES: [&str; 2] = ["/bin/bash", "/usr/bin/bash"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RecountCwd {
    Repo,
    Upstream,
}

impl RecountCwd {
    fn as_str(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Upstream => "upstream",
        }
    }
}

/// 台账 `recount` 数组里的一项，已经过结构校验。
#[derive(Debug, Clone)]
struct RecountItem {
    /// 相对仓根的台账路径，例如 `parity/api.yaml`。
    file: String,
    /// 在该台账 `recount` 数组里的下标，用于把报错定位到具体一条。
    index: usize,
    command: String,
    cwd: RecountCwd,
    /// `expect` 的字符串形式（数字 `53` 与字符串 `"ok"` 统一成字符串比）。
    expect: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RecountStatus {
    /// 实得 stdout 与 `expect` 相等。
    Pass,
    /// 实得 stdout 与 `expect` 不等。**唯一判红的形态。**
    Mismatch,
    /// 没跑。目前唯一来源 = `cwd: upstream` 但上游克隆不可用。
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
struct RecountOutcome {
    status: RecountStatus,
    /// 实得 stdout（首尾空白已去除）。`Skipped` 时为 `None`。
    actual: Option<String>,
    /// 命令退出码。**不参与判定** —— `grep -c` 在计数为 0 时退出码是 1 却打印了正确的 `0`。
    /// 留在报告里只为诊断"是不是 grep 根本没跑起来"。
    exit_code: Option<i32>,
    /// 只在 `Mismatch` 时填，且截断。
    stderr: Option<String>,
    /// 只在 `Skipped` 时填。
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RecountItemReport {
    file: String,
    index: usize,
    command: String,
    cwd: &'static str,
    expect: String,
    executor: &'static str,
    #[serde(flatten)]
    outcome: RecountOutcome,
}

#[derive(Debug, Clone, Serialize)]
struct RecountReport {
    scope: CheckScope,
    product_certified: bool,
    /// 实际使用的 shell 绝对路径 —— 换了 shell 就是换了一批工具，必须写进报告。
    shell: String,
    /// `OPENBOT_UPSTREAM_DIR` 的实际取值；`None` = 未设置。
    upstream_dir: Option<String>,
    items: Vec<RecountItemReport>,
    passed: usize,
    mismatched: usize,
    skipped: usize,
}

/// 一次命令执行的原始产物。
#[derive(Debug, Clone)]
struct RawOutput {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

/// 执行 recount 命令的缝。
///
/// 抽成 trait 是为了让 [`evaluate_recount`] 的比对逻辑能在**不起进程**的前提下被单测覆盖 ——
/// 否则"比较函数恒返回 true"这种失效模式只能靠肉眼看输出发现。
trait RecountRunner {
    fn run(&self, command: &str, cwd: &Path) -> Result<RawOutput>;
}

/// 真执行器：把命令串交给 POSIX shell 的 `-c`。
struct ShellRunner {
    shell: PathBuf,
    /// 追加到子进程 `PATH` 最前面的目录（Windows 上 = Git Bash 自带的 `usr/bin` 与 `mingw64/bin`）。
    path_prefix: Vec<PathBuf>,
}

impl RecountRunner for ShellRunner {
    fn run(&self, command: &str, cwd: &Path) -> Result<RawOutput> {
        let mut cmd = Command::new(&self.shell);
        cmd.arg("-c").arg(command).current_dir(cwd);
        if !self.path_prefix.is_empty() {
            let existing = std::env::var_os("PATH").unwrap_or_default();
            let joined = std::env::join_paths(
                self.path_prefix
                    .iter()
                    .cloned()
                    .chain(std::env::split_paths(&existing)),
            )
            .context("拼接子进程 PATH 失败")?;
            cmd.env("PATH", joined);
        }
        let output = cmd.output().with_context(|| {
            format!(
                "在 {} 里用 {} 执行命令失败",
                cwd.display(),
                self.shell.display()
            )
        })?;
        Ok(RawOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
        })
    }
}

/// 定位 POSIX shell，找不到就报错并列出试过的路径 —— **不静默降级到 `cmd.exe` 或裸 `bash`**。
///
/// `cfg!` 是运行期求值的宏（不是 `#[cfg]` 属性），所以两个分支在两个平台上都会被编译，
/// 不会出现"这段代码在另一个平台上一行都没编译过"的盲区。
fn locate_shell() -> Result<ShellRunner> {
    let candidates: &[&str] = if cfg!(windows) {
        &WINDOWS_SHELL_CANDIDATES
    } else {
        &UNIX_SHELL_CANDIDATES
    };

    let shell = candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| {
            anyhow!(
                "找不到可用的 POSIX shell —— recount 里的命令全是 grep / sed / wc 这类 POSIX 工具，\
                 没有 shell 就没法执行。试过的路径：{candidates:?}。\
                 Windows 上请安装 Git for Windows（它自带 usr/bin/bash.exe）。\
                 刻意不退回 cmd.exe，也刻意不用 PATH 上的裸 `bash`（可能是 System32 的 WSL bash，\
                 那是另一个文件系统命名空间，失败形态是命令输出为空 —— 与真的数出 0 不可区分）。"
            )
        })?;

    // Windows 上把 Git Bash 自带的工具目录顶到 PATH 最前面。
    // 不这么做的话，答案就取决于"从哪个 shell 启动了 cargo"：Git Bash 里 PATH 有 /usr/bin，
    // PowerShell 里通常没有 —— 同一份台账在两个终端给两个答案的东西不是闸门。
    let mut path_prefix = Vec::new();
    if cfg!(windows)
        && let Some(usr_bin) = shell.parent()
    {
        path_prefix.push(usr_bin.to_path_buf());
        if let Some(git_root) = usr_bin.parent().and_then(Path::parent) {
            let mingw = git_root.join("mingw64").join("bin");
            if mingw.is_dir() {
                path_prefix.push(mingw);
            }
        }
    }

    Ok(ShellRunner { shell, path_prefix })
}

/// 把 YAML 标量转成用于比对的字符串。数字 `53` 与字符串 `"ok"` 统一走字符串比。
fn scalar_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// 从全部台账里收集 recount 项。
///
/// 结构性问题（缺 `command` / `cwd` 非法 / `expect` 不是标量）这里**不修补也不跳过**，
/// 而是收集起来一次性报错并指向 `parity-check` —— 那才是这些规则的归属地，
/// 在两个地方各写一份判据必然漂移。
fn collect_recount_items(root: &Path, scope: CheckScope) -> Result<Vec<RecountItem>> {
    let mut ignored_violations = Vec::new();
    let mut ignored_warnings = Vec::new();
    let sources =
        collect_ledger_sources(root, scope, &mut ignored_violations, &mut ignored_warnings)?;

    let mut items = Vec::new();
    let mut structural: Vec<String> = Vec::new();

    for source in &sources {
        let display = rel(root, &source.path);
        let text = std::fs::read_to_string(&source.path)
            .with_context(|| format!("读取 {} 失败", source.path.display()))?;
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&text).with_context(|| format!("{display}：YAML 解析失败"))?;
        let Some(map) = doc.as_mapping() else {
            structural.push(format!("{display}：顶层不是 mapping"));
            continue;
        };
        let Some(serde_yaml::Value::Sequence(seq)) = map.get(serde_yaml::Value::from("recount"))
        else {
            structural.push(format!("{display}：`recount` 缺失或不是序列"));
            continue;
        };

        for (index, item) in seq.iter().enumerate() {
            let Some(imap) = item.as_mapping() else {
                structural.push(format!("{display} recount#{index}：不是 mapping"));
                continue;
            };
            let Some(command) = nonempty_str(imap, "command") else {
                structural.push(format!("{display} recount#{index}：`command` 缺失或为空"));
                continue;
            };
            let cwd = match nonempty_str(imap, "cwd").as_deref() {
                Some("repo") => RecountCwd::Repo,
                Some("upstream") => RecountCwd::Upstream,
                Some(other) => {
                    structural.push(format!(
                        "{display} recount#{index}：cwd=`{other}` 不在 {RECOUNT_CWD:?} 内"
                    ));
                    continue;
                }
                None => {
                    structural.push(format!("{display} recount#{index}：`cwd` 缺失或为空"));
                    continue;
                }
            };
            let Some(expect) = imap
                .get(serde_yaml::Value::from("expect"))
                .and_then(scalar_to_string)
            else {
                structural.push(format!(
                    "{display} recount#{index}：`expect` 缺失或不是标量（只支持字符串 / 数字 / 布尔）"
                ));
                continue;
            };

            items.push(RecountItem {
                file: display.clone(),
                index,
                command,
                cwd,
                expect,
            });
        }
    }

    if !structural.is_empty() {
        bail!(
            "recount: {} 条台账结构问题，先跑 `cargo xtask parity-check` 修好规则 8：\n  {}",
            structural.len(),
            structural.join("\n  ")
        );
    }

    Ok(items)
}

/// 比对判据：两侧都去首尾空白后按字符串相等。
///
/// **两侧都 trim** 而不是只 trim stdout：`parity/ui.yaml` 里那条 `for … printf '%s '` 循环的
/// 真实 stdout 是 `13 8 4 3 1 32 `（尾随一个空格、且没有换行），作者把这个尾随空格原样写进了
/// `expect`。只 trim 一侧会把这条判成失配 —— 而尾随空白既不携带计数信息，又在 YAML 引号、
/// 编辑器和格式化工具之间不稳定，让它当判据只会制造无法解释的红。
fn recount_matches(expect: &str, stdout: &str) -> bool {
    expect.trim() == stdout.trim()
}

/// 截断诊断文本，避免一条 stderr 刷满整屏。按 `char` 截而不是按字节 —— 台账里有中文。
fn truncate_chars(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(max).collect();
    format!("{head}…（已截断）")
}

/// 判定单条 recount。
///
/// **安全性**：`command` 直接交给 shell 执行。这是可接受的，因为这些命令来自**仓内受控文件**
/// （`parity/*.yaml` 与 `fixtures/MANIFEST.yaml`），两者都在 code review 与 git 历史的覆盖下，
/// 与仓里任何一个 build script 的信任级别相同。
/// **它不适用于校验不可信来源的台账** —— 对外部投稿、自动抓取或用户上传的 YAML 跑本函数
/// 等价于任意命令执行。真要支持那种输入，必须换成白名单化的结构化查询，而不是放宽这里。
fn evaluate_recount(
    item: &RecountItem,
    repo_root: &Path,
    upstream: Option<&Path>,
    runner: &dyn RecountRunner,
) -> Result<RecountOutcome> {
    let cwd = match item.cwd {
        RecountCwd::Repo => repo_root.to_path_buf(),
        RecountCwd::Upstream => match upstream {
            Some(dir) => dir.to_path_buf(),
            // 这里是本命令最容易被做成假闸门的一点：把"没跑"报告成通过，
            // 整批 upstream 判据就会在每台没有克隆的机器上永久静默绿掉。
            None => {
                return Ok(RecountOutcome {
                    status: RecountStatus::Skipped,
                    actual: None,
                    exit_code: None,
                    stderr: None,
                    reason: Some(format!(
                        "cwd=upstream 但环境变量 {UPSTREAM_DIR_ENV} 未设置 —— 没有上游克隆就无法复算，这条**没有跑**"
                    )),
                });
            }
        },
    };

    let raw = runner.run(&item.command, &cwd)?;
    if recount_matches(&item.expect, &raw.stdout) {
        Ok(RecountOutcome {
            status: RecountStatus::Pass,
            actual: Some(raw.stdout.trim().to_string()),
            exit_code: raw.exit_code,
            stderr: None,
            reason: None,
        })
    } else {
        Ok(RecountOutcome {
            status: RecountStatus::Mismatch,
            actual: Some(raw.stdout.trim().to_string()),
            exit_code: raw.exit_code,
            stderr: Some(truncate_chars(&raw.stderr, 400)),
            reason: None,
        })
    }
}

/// 解析 `OPENBOT_UPSTREAM_DIR`。
///
/// 设了但不是目录 ⇒ **报错**而不是 SKIPPED：路径写错却被当成"没配上游"静默跳过，
/// 会让人以为自己跑过了那 81 条 upstream 判据。
fn resolve_upstream_dir() -> Result<Option<PathBuf>> {
    let Some(raw) = std::env::var_os(UPSTREAM_DIR_ENV) else {
        return Ok(None);
    };
    let path = PathBuf::from(&raw);
    if path.as_os_str().is_empty() {
        return Ok(None);
    }
    if !path.is_dir() {
        bail!(
            "{UPSTREAM_DIR_ENV}={} 不是一个存在的目录 —— 路径写错不会被当成\"没配上游\"静默跳过",
            path.display()
        );
    }
    Ok(Some(path))
}

fn cmd_recount(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    let require_upstream = args.iter().any(|a| a == "--require-upstream");
    for a in args {
        if a != "--json" && a != "--require-upstream" && a != "--fixtures-only" {
            bail!(
                "recount: 未知参数 `{a}`（只接受 --json / --require-upstream / --fixtures-only）"
            );
        }
    }
    let scope = CheckScope::from_args(args);
    if scope == CheckScope::FixturesOnly && require_upstream {
        bail!("recount: --fixtures-only 不消费上游输入，不能与 --require-upstream 混用");
    }
    run_recount(json, require_upstream, scope).map(|_| ())
}

// Exact equivalents of the six reviewed MANIFEST queries. Do not execute Python or
// interpret arbitrary source text. Unknown, missing or duplicated queries require review.
const FIXTURE_QUERY_PREFIX: &str = "python3 -c \"import yaml,io;d=yaml.safe_load(io.open('fixtures/MANIFEST.yaml',encoding='utf-8'));";
const FIXTURE_QUERIES: [&str; 6] = [
    "print(len(d['entries']))",
    "print(sum(1 for e in d['entries'] if e['status']=='todo'))",
    "print(sum(1 for e in d['entries'] if e['status']=='done'))",
    "e=d['entries'];assert all(('done_evidence' in x)==(x['status']=='done') for x in e);print('ok')",
    "t=[x['test_id'] for x in d['entries']];print(len(t),len(set(t)))",
    "print(sum(1 for e in d['entries'] if e['label']=='parity'),sum(1 for e in d['entries'] if e['label']=='新增'),sum(1 for e in d['entries'] if e['label']=='替代'))",
];

fn fixture_query_index(item: &RecountItem) -> Result<usize> {
    if item.file != FIXTURES_MANIFEST_RELPATH || item.cwd != RecountCwd::Repo {
        bail!("fixture recount requires the reviewed repo manifest");
    }
    let query = item
        .command
        .strip_prefix(FIXTURE_QUERY_PREFIX)
        .and_then(|s| s.strip_suffix('"'));
    FIXTURE_QUERIES
        .iter()
        .position(|known| Some(*known) == query)
        .ok_or_else(|| {
            anyhow!(
                "{} recount#{}: unknown fixture query; no shell/Python fallback",
                item.file,
                item.index
            )
        })
}

fn fixture_recount_values(root: &Path, items: &[RecountItem]) -> Result<Vec<String>> {
    let mut queries = BTreeSet::new();
    for item in items
        .iter()
        .filter(|item| item.file == FIXTURES_MANIFEST_RELPATH)
    {
        if !queries.insert(fixture_query_index(item)?) {
            bail!("fixture recount: duplicate query");
        }
    }
    if queries.len() != FIXTURE_QUERIES.len() {
        bail!("fixture recount: all six reviewed queries are required");
    }
    let document: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(
        root.join(FIXTURES_MANIFEST_RELPATH),
    )?)?;
    let entries = document
        .get("entries")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| anyhow!("fixture recount: entries must be a sequence"))?;
    let count = |field: &str, value: &str| {
        entries
            .iter()
            .filter(|e| e.get(field).and_then(serde_yaml::Value::as_str) == Some(value))
            .count()
    };
    let ids = entries
        .iter()
        .map(|e| {
            e.get("test_id")
                .and_then(serde_yaml::Value::as_str)
                .ok_or_else(|| anyhow!("fixture recount: missing test_id"))
        })
        .collect::<Result<Vec<_>>>()?;
    if !entries.iter().all(|e| {
        e.get("done_evidence").is_some()
            == (e.get("status").and_then(serde_yaml::Value::as_str) == Some("done"))
    }) {
        bail!("fixture recount: done_evidence/status equivalence failed");
    }
    Ok(vec![
        entries.len().to_string(),
        count("status", "todo").to_string(),
        count("status", "done").to_string(),
        "ok".into(),
        format!(
            "{} {}",
            ids.len(),
            ids.iter().collect::<BTreeSet<_>>().len()
        ),
        format!(
            "{} {} {}",
            count("label", "parity"),
            count("label", "新增"),
            count("label", "替代")
        ),
    ])
}

fn evaluate_fixture_recount(item: &RecountItem, values: &[String]) -> Result<RecountOutcome> {
    let actual = values
        .get(fixture_query_index(item)?)
        .ok_or_else(|| anyhow!("fixture recount value missing"))?;
    Ok(RecountOutcome {
        status: if recount_matches(&item.expect, actual) {
            RecountStatus::Pass
        } else {
            RecountStatus::Mismatch
        },
        actual: Some(actual.clone()),
        exit_code: None,
        stderr: None,
        reason: None,
    })
}

/// `recount` 的本体。返回报告，让 `ci` 能在自己的收尾行里如实转述跳过条数。
fn run_recount(json: bool, require_upstream: bool, scope: CheckScope) -> Result<RecountReport> {
    let root = workspace_root()?;
    let parity = build_parity_report(&root, scope)?;
    if !parity.violations.is_empty() {
        bail!(
            "recount: required inputs/structure failed; run parity-check with the same scope:\n{}",
            parity.violations.join("\n")
        );
    }
    let items = collect_recount_items(&root, scope)?;
    let fixture_values = fixture_recount_values(&root, &items)?;
    let uses_shell = items
        .iter()
        .any(|item| item.file != FIXTURES_MANIFEST_RELPATH);
    let upstream = if uses_shell {
        resolve_upstream_dir()?
    } else {
        None
    };
    let runner = if uses_shell {
        Some(locate_shell()?)
    } else {
        None
    };
    let shell = runner
        .as_ref()
        .map(|runner| runner.shell.display().to_string())
        .unwrap_or_else(|| "not used; Rust fixture queries".into());

    if !json {
        println!(
            "recount: scope={scope:?}; {} 条复算（不认证产品/发布）",
            items.len()
        );
        println!("  shell        = {shell}");
        println!(
            "  {UPSTREAM_DIR_ENV} = {}",
            upstream
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<未设置 —— cwd:upstream 的项会被跳过>".to_string())
        );
        println!();
    }

    let mut reports: Vec<RecountItemReport> = Vec::new();
    for item in &items {
        let (outcome, executor) = if item.file == FIXTURES_MANIFEST_RELPATH {
            (
                evaluate_fixture_recount(item, &fixture_values)?,
                "rust_fixture_query",
            )
        } else {
            (
                evaluate_recount(
                    item,
                    &root,
                    upstream.as_deref(),
                    runner
                        .as_ref()
                        .ok_or_else(|| anyhow!("shell runner missing"))?,
                )?,
                "shell",
            )
        };
        if !json {
            let marker = match outcome.status {
                RecountStatus::Pass => "ok",
                RecountStatus::Mismatch => "x ",
                RecountStatus::Skipped => "- ",
            };
            println!(
                "  {marker} {}#{:<2} [{}] {}",
                item.file,
                item.index,
                item.cwd.as_str(),
                truncate_chars(&item.command, 96)
            );
        }
        reports.push(RecountItemReport {
            file: item.file.clone(),
            index: item.index,
            command: item.command.clone(),
            cwd: item.cwd.as_str(),
            expect: item.expect.clone(),
            executor,
            outcome,
        });
    }

    let passed = reports
        .iter()
        .filter(|r| r.outcome.status == RecountStatus::Pass)
        .count();
    let mismatched = reports
        .iter()
        .filter(|r| r.outcome.status == RecountStatus::Mismatch)
        .count();
    let skipped = reports
        .iter()
        .filter(|r| r.outcome.status == RecountStatus::Skipped)
        .count();

    let report = RecountReport {
        scope,
        product_certified: false,
        shell,
        upstream_dir: upstream.as_ref().map(|p| p.display().to_string()),
        items: reports,
        passed,
        mismatched,
        skipped,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_recount_report(&report);
    }

    if report.mismatched > 0 {
        bail!(
            "recount: {} 条失配（通过 {} / 失配 {} / 跳过 {}）",
            report.mismatched,
            report.passed,
            report.mismatched,
            report.skipped
        );
    }
    if require_upstream && report.skipped > 0 {
        bail!(
            "recount: --require-upstream 生效，但有 {} 条被跳过（设置 {UPSTREAM_DIR_ENV} 指向上游克隆后重跑）",
            report.skipped
        );
    }
    Ok(report)
}

fn print_recount_report(report: &RecountReport) {
    let mismatches: Vec<&RecountItemReport> = report
        .items
        .iter()
        .filter(|r| r.outcome.status == RecountStatus::Mismatch)
        .collect();
    if !mismatches.is_empty() {
        println!("\n失配明细（{} 条）：", mismatches.len());
        for r in &mismatches {
            println!("  x {}#{} [{}]", r.file, r.index, r.cwd);
            println!("      命令: {}", r.command);
            println!("      期望: {:?}", r.expect);
            println!(
                "      实得: {:?}",
                r.outcome.actual.as_deref().unwrap_or("")
            );
            if let Some(code) = r.outcome.exit_code {
                println!("      退出码: {code}（不参与判定，只用于诊断）");
            }
            match r.outcome.stderr.as_deref() {
                Some(s) if !s.is_empty() => println!("      stderr: {s}"),
                _ => {}
            }
        }
    }

    // 跳过必须被**看见**。"静默跳过"与"打印了跳过数"是两回事，后者可以被人查。
    if report.skipped > 0 {
        println!(
            "\n跳过明细（{} 条，全部因为 {UPSTREAM_DIR_ENV} 未设置；这些判据本轮**没有被验证**）：",
            report.skipped
        );
        let mut by_file: BTreeMap<&str, usize> = BTreeMap::new();
        for r in report
            .items
            .iter()
            .filter(|r| r.outcome.status == RecountStatus::Skipped)
        {
            *by_file.entry(r.file.as_str()).or_insert(0) += 1;
        }
        for (file, count) in &by_file {
            println!("  - {file}: {count} 条");
        }
        println!(
            "  设置 {UPSTREAM_DIR_ENV}=<上游克隆路径> 后重跑即可覆盖它们；\
             要把跳过也判红请加 --require-upstream。"
        );
    }

    println!(
        "\nrecount: 通过 {} / 失配 {} / 跳过 {}（共 {} 条）",
        report.passed,
        report.mismatched,
        report.skipped,
        report.items.len()
    );
}

// ---------------------------------------------------------------------------
// ci
// ---------------------------------------------------------------------------

/// `cargo xtask ci` 的驱动器与它驱动的构建**必须落在两棵互不包含的 target 树**。
///
/// 根因是构造性的：第 3 步 `cargo test --workspace --all-features` 会重新链接
/// **驱动器自己**（xtask 的 `required-features = ["xtask"]` 恰好被 `--all-features`
/// 满足）。Windows 不允许删除正在运行的 exe，cargo 的 uplift 于是报
/// `failed to remove file <target>/debug/xtask.exe: 拒绝访问 (os error 5)`。
/// 也就是说这条闸门在 Windows 上**构造性地永远跑不绿**，在 Linux 上却恒绿 ——
/// 答案取决于跑在哪台机器上的命令不是闸门。
///
/// 不能靠"把自己复制到临时目录再 re-exec"绕：占住那个文件的是**父进程自己**，
/// 复制出一个子进程不会释放父进程的镜像锁（本轮实测，第 3 步照旧 os error 5）。
///
/// 所以 `.cargo/config.toml` 的 alias 用 `--target-dir target-xtask` 把驱动器整棵挪到
/// `target/` 之外，[`cmd_ci`] 再把子进程显式钉回 `<root>/target`。本函数是那条不变量的判据。
///
/// 判据取"包含"而不是"就是那个文件"：后者要枚举 profile 与 `deps/` 的全部落点，
/// 而多出来的严格度只会禁掉我们自己选的目录名 —— 严在安全的一侧。
fn driver_conflicts_with_child_target(exe: &Path, child_target: &Path) -> bool {
    // 两边都尽力规范化：Windows 上 `current_exe()` 给的是 `\\?\` 前缀的规范路径，
    // 而 `<root>/target` 是拼出来的；不规范化的话前缀比较必然假阴性 —— 也就是
    // 这条判据恰好在真正该报警的那台机器上失灵。
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let Ok(child) = child_target.canonicalize() else {
        // 目录还不存在 => 里面不可能有正在运行的驱动器。
        return false;
    };
    exe.starts_with(&child)
}

fn cmd_ci() -> Result<()> {
    let root = workspace_root()?;
    let child_target = root.join("target");
    let exe = std::env::current_exe().context("读取当前可执行文件路径失败")?;
    if driver_conflicts_with_child_target(&exe, &child_target) {
        bail!(
            "驱动器自己就落在子构建的 target 树里，第 3 步 `cargo test` 会去重链它：\n\
             \x20 驱动器      = {}\n\
             \x20 子构建 target = {}\n\
             Windows 上这必然报 `failed to remove file ...: 拒绝访问 (os error 5)`，\n\
             Linux 上却会静默通过 —— 同一条命令两台机器两种答案。\n\
             用 `cargo xtask ci`（.cargo/config.toml 的 alias 已把驱动器建到 target-xtask/），\n\
             不要用 `cargo run -p openbot-testkit --features xtask --bin xtask -- ci`。",
            exe.display(),
            child_target.display()
        );
    }
    run_ci_steps(&root, &child_target)
}

fn run_ci_steps(root: &Path, child_target: &Path) -> Result<()> {
    // 顺序 = v3 §16.3〈Supply chain〉固定清单的前三条、W-7 safe-dialer/SAML 两条依赖 guard，
    // 加上 v3 §19.3 的 parity/recount 闸门。
    //
    // 后面几条（cargo deny / cargo audit / cargo vet / OSV / secret scan /
    // license-NOTICE-provenance / SBOM / 可复现构建 / 签名校验）刻意**不**在这里跑：
    // 它们各自需要一份本仓此刻还不存在的基线（`supply-chain/` 目录、SBOM 工具链、
    // Electron shim 产物、签名密钥），塞进来只会得到一条恒红的闸门 —— 恒红等于没有闸门。
    // 它们在 .github/workflows/ci.yml 里以独立 job 编排，并在那里写明解除条件。
    let steps: [(&str, &str, &[&str]); 5] = [
        (
            "cargo fmt --check",
            "cargo",
            &["fmt", "--all", "--", "--check"],
        ),
        (
            "cargo clippy --all-targets --all-features -D warnings",
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
        ),
        (
            "cargo test --locked",
            "cargo",
            &["test", "--workspace", "--all-features", "--locked"],
        ),
        (
            "safe dialer dependency guard",
            "bash",
            &["tools/check-safe-dialer-dependencies.sh"],
        ),
        (
            "SAML/xmlsec dependency guard",
            "bash",
            &["tools/check-saml-dependencies.sh"],
        ),
    ];

    for (index, (label, program, args)) in steps.iter().enumerate() {
        let step_no = index + 1;
        println!("\n=== xtask ci [{step_no}/7] {label} ===");
        // 显式钉死子构建的 target 目录，不靠继承：alias 那侧的 `--target-dir` 会不会
        // 经环境变量传下来是 cargo 的实现细节，而不变量不能建在实现细节上。
        let status = Command::new(program)
            .args(*args)
            .current_dir(root)
            .env("CARGO_TARGET_DIR", child_target)
            .status()
            .with_context(|| format!("启动 `{program} {}` 失败", args.join(" ")))?;
        if !status.success() {
            bail!(
                "第 {step_no} 步失败：{label}（退出码 {}）",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "被信号终止".to_string())
            );
        }
    }

    println!("\n=== xtask ci [6/7] parity-check ===");
    // 进程内调用而不是再 spawn 一次 cargo：避免把刚跑完的 4 分钟编译再等一遍，
    // 也让 parity 违规的退出码来源唯一。
    cmd_parity_check(&[]).context("第 6 步失败：parity-check")?;

    // 最后一步 = recount。裁决与理由：
    //
    // **判红口径 = 任何失配都判红，不分 repo / upstream；SKIPPED 不判红但必须打印条数。**
    //
    // 1) 不按 `cwd` 区分判红：失配就是失配。上游克隆在场时它给出的答案与 repo 侧同样确定，
    //    只对 `cwd: repo` 判红等于在克隆可用时主动放弃 81 条判据 —— 那正好是本轮要补的洞。
    // 2) 缺上游克隆不判红：那是**环境条件**，不是台账缺陷。CI 与多数开发机没有这份克隆，
    //    判红会得到一条在每台机器上恒红的闸门 —— 恒红的闸门等于没有闸门。
    // 3) 但 SKIPPED 绝不当成通过：`print_recount_report` 会按文件打印跳过条数与"这些判据
    //    本轮没有被验证"的原文，下面再单独重复一次总数。"静默跳过"与"打印了跳过数"是两回事。
    // 4) 想把跳过也变成硬闸门的场合（CI 里已经 checkout 了上游克隆）用
    //    `cargo xtask recount --require-upstream` —— 这是一条真正的杠杆，不是装饰。
    println!("\n=== xtask ci [7/7] recount ===");
    let recount = run_recount(false, false, CheckScope::Full).context("第 7 步失败：recount")?;

    if recount.skipped > 0 {
        println!(
            "\nxtask ci: 7/7 通过，但 recount 有 {} 条**没有跑**（{}/{} 条实跑）。\n\
             这 {} 条是 cwd:upstream 的判据，本机没有上游克隆。要覆盖它们：\n\
             设 {UPSTREAM_DIR_ENV}=<上游克隆路径> 后 `cargo xtask recount`；\n\
             要让跳过直接判红，用 `cargo xtask recount --require-upstream`。",
            recount.skipped,
            recount.passed + recount.mismatched,
            recount.items.len(),
            recount.skipped
        );
    } else {
        println!(
            "\nxtask ci: 7/7 全绿（recount {} 条全部实跑）",
            recount.passed
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// 取一个必须是"非空字符串"的字段。空串、非字符串、缺键一律返回 `None`。
fn nonempty_str(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(serde_yaml::Value::from(key))
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn type_name(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "bool",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
}

/// 相对仓根的路径，且统一成 `/` 分隔 —— Windows 与 Linux 上的报错文本必须逐字相同，
/// 否则 CI 日志和本机日志没法直接对比。
fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// 自检：8 条规则各自的正向 + 负向对照
// ---------------------------------------------------------------------------
//
// 为什么必须成对写：一个"从不报错"的校验器和一个"没有违规"的仓库，输出完全一样。
// 只测"坏输入报红"证明不了它在好输入上不误报；只测"好输入放行"在"规则压根没实现"的
// 世界里同样成立。两边都钉住，这份闸门才有判别力。
#[cfg(test)]
mod tests {
    use super::*;

    /// 一条各字段都合法的 entry。各用例用 `replace` 只改**一个**字段来隔离被测规则。
    const VALID_ENTRY: &str = "  - id: get-thread\n    upstream: server/src/routes/thread.ts::getThread\n    label: parity\n    target: openbot-server::routes::thread::get\n    owner: openbot-server\n    test_id: T-API-0001\n    migration_rule: preserve\n    status: todo\n    evidence: rg -n getThread server/src/routes/thread.ts\n";

    /// 合法的 recount 段。刻意不含反斜杠：被测的是规则，不是转义。
    const VALID_RECOUNT: &str =
        "recount:\n  - command: rg -c app server/src/index.ts\n    cwd: upstream\n    expect: 95\n";

    fn doc(entries: &str) -> String {
        format!(
            "schema: api\nschema_version: 1\nupstream_commit: {EXPECTED_UPSTREAM_COMMIT}\ngenerated_by: manual\n{VALID_RECOUNT}entries:\n{entries}"
        )
    }

    /// 跑一遍校验，返回 (违规, 告警)。
    fn run(yaml: &str) -> (Vec<String>, Vec<String>) {
        run_as("parity/test.yaml", LedgerKind::Parity, yaml)
    }

    /// 指定文件名与台账种类跑一遍校验。
    fn run_as(file: &str, kind: LedgerKind, yaml: &str) -> (Vec<String>, Vec<String>) {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();
        let mut global = BTreeMap::new();
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(yaml).expect("测试用例 YAML 必须可解析");
        check_ledger(
            file,
            kind,
            &parsed,
            &mut violations,
            &mut warnings,
            &mut global,
        );
        (violations, warnings)
    }

    /// 断言恰好命中某条规则，且没有别的规则被顺带点亮
    /// —— 否则"测规则 7"的用例可能其实是被规则 1 判红的，等于没测。
    fn assert_only_rule(violations: &[String], rule_tag: &str) {
        assert!(
            !violations.is_empty(),
            "期望命中 {rule_tag}，实际零违规 —— 规则没有生效"
        );
        for v in violations {
            assert!(
                v.contains(rule_tag),
                "期望只命中 {rule_tag}，却出现了别的违规：{v}"
            );
        }
    }

    // --- 全局正向对照 ------------------------------------------------------

    #[test]
    fn valid_ledger_has_zero_violations() {
        let (violations, warnings) = run(&doc(VALID_ENTRY));
        assert!(
            violations.is_empty(),
            "合法 ledger 不该有违规：{violations:?}"
        );
        assert!(warnings.is_empty(), "合法 ledger 不该有告警：{warnings:?}");
    }

    // --- 规则 1 ------------------------------------------------------------

    #[test]
    fn rule1_missing_required_entry_key() {
        let entry = VALID_ENTRY.replace(
            "    evidence: rg -n getThread server/src/routes/thread.ts\n",
            "",
        );
        assert_only_rule(&run(&doc(&entry)).0, "[规则 1]");
    }

    #[test]
    fn rule1_empty_required_entry_value() {
        // 空串与"只有空白"都必须判红：`target: "   "` 在 YAML 里是完全合法的字符串。
        let entry = VALID_ENTRY.replace(
            "    target: openbot-server::routes::thread::get\n",
            "    target: \"   \"\n",
        );
        assert_only_rule(&run(&doc(&entry)).0, "[规则 1]");
    }

    #[test]
    fn rule1_unknown_top_level_key_is_rejected() {
        let yaml = format!("{}extra_key: 随手加的\n", doc(VALID_ENTRY));
        assert_only_rule(&run(&yaml).0, "[规则 1]");
    }

    #[test]
    fn rule1_unknown_entry_key_is_rejected() {
        let entry = format!("{VALID_ENTRY}    owner_note: 随手加的\n");
        assert_only_rule(&run(&doc(&entry)).0, "[规则 1]");
    }

    #[test]
    fn rule1_missing_top_level_key() {
        let yaml = doc(VALID_ENTRY).replace("generated_by: manual\n", "");
        assert_only_rule(&run(&yaml).0, "[规则 1]");
    }

    #[test]
    fn rule1_wrong_schema_version() {
        let yaml = doc(VALID_ENTRY).replace("schema_version: 1\n", "schema_version: 2\n");
        assert_only_rule(&run(&yaml).0, "[规则 1]");
    }

    // --- 规则 2 ------------------------------------------------------------

    #[test]
    fn rule2_rejects_label_outside_three_values() {
        for bad in ["Parity", "new", "新增功能", "替换"] {
            let entry = VALID_ENTRY.replace("    label: parity\n", &format!("    label: {bad}\n"));
            assert_only_rule(&run(&doc(&entry)).0, "[规则 2]");
        }
    }

    #[test]
    fn rule2_accepts_all_three_values() {
        for good in LABELS {
            let entry = VALID_ENTRY.replace("    label: parity\n", &format!("    label: {good}\n"));
            let (violations, _) = run(&doc(&entry));
            assert!(
                violations.is_empty(),
                "label={good} 应当合法：{violations:?}"
            );
        }
    }

    // --- 规则 3 ------------------------------------------------------------

    #[test]
    fn rule3_rejects_owner_outside_ten_crates() {
        // `openbot-core` 不在 v3 §5.1 的十个 crate 里；建第 11 个 crate 要过四条理由的评审。
        let entry = VALID_ENTRY.replace("    owner: openbot-server\n", "    owner: openbot-core\n");
        assert_only_rule(&run(&doc(&entry)).0, "[规则 3]");
    }

    #[test]
    fn rule3_accepts_all_ten_crates() {
        for owner in OWNERS {
            let entry = VALID_ENTRY.replace(
                "    owner: openbot-server\n",
                &format!("    owner: {owner}\n"),
            );
            let (violations, _) = run(&doc(&entry));
            assert!(
                violations.is_empty(),
                "owner={owner} 应当合法：{violations:?}"
            );
        }
    }

    // --- 规则 4 ------------------------------------------------------------

    #[test]
    fn rule4_done_without_done_evidence() {
        let entry = VALID_ENTRY.replace("    status: todo\n", "    status: done\n");
        assert_only_rule(&run(&doc(&entry)).0, "[规则 4]");
    }

    #[test]
    fn rule4_done_with_empty_done_evidence() {
        let entry = format!(
            "{}    done_evidence: \"\"\n",
            VALID_ENTRY.replace("    status: todo\n", "    status: done\n")
        );
        assert_only_rule(&run(&doc(&entry)).0, "[规则 4]");
    }

    #[test]
    fn rule4_done_with_evidence_is_accepted() {
        let entry = format!(
            "{}    done_evidence: cargo test -p openbot-server thread_get\n",
            VALID_ENTRY.replace("    status: todo\n", "    status: done\n")
        );
        let (violations, _) = run(&doc(&entry));
        assert!(violations.is_empty(), "done + 证据应当合法：{violations:?}");
    }

    #[test]
    fn rule4_non_done_must_not_carry_done_evidence() {
        // 双向约束的另一半：todo 却带着 done_evidence，说明有人把 status 改回去却没删证据，
        // 下一次误读就会当成"已完成"。
        let entry = format!("{VALID_ENTRY}    done_evidence: 早先跑过\n");
        assert_only_rule(&run(&doc(&entry)).0, "[规则 4]");
    }

    #[test]
    fn rule4_rejects_status_outside_three_values() {
        let entry = VALID_ENTRY.replace("    status: todo\n", "    status: blocked\n");
        assert_only_rule(&run(&doc(&entry)).0, "[规则 4]");
    }

    // --- 规则 5 ------------------------------------------------------------

    #[test]
    fn rule5_duplicate_id_within_file() {
        let entries = format!(
            "{VALID_ENTRY}{}",
            VALID_ENTRY.replace("    test_id: T-API-0001\n", "    test_id: T-API-0002\n")
        );
        assert_only_rule(&run(&doc(&entries)).0, "[规则 5]");
    }

    #[test]
    fn rule5_duplicate_test_id_across_ledgers() {
        // 跨文件那一半：同一个 global map 连续喂两个文件。
        let mut violations = Vec::new();
        let mut warnings = Vec::new();
        let mut global = BTreeMap::new();
        for file in ["parity/api.yaml", "parity/routes.yaml"] {
            let parsed: serde_yaml::Value =
                serde_yaml::from_str(&doc(VALID_ENTRY)).expect("测试用例 YAML 必须可解析");
            check_ledger(
                file,
                LedgerKind::Parity,
                &parsed,
                &mut violations,
                &mut warnings,
                &mut global,
            );
        }
        assert_only_rule(&violations, "[规则 5]");
        assert!(
            violations[0].contains("parity/api.yaml"),
            "重复报告应指回首次出现的文件：{violations:?}"
        );
    }

    #[test]
    fn rule5_distinct_test_ids_across_ledgers_are_fine() {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();
        let mut global = BTreeMap::new();
        for (file, test_id) in [
            ("parity/api.yaml", "T-API-0001"),
            ("parity/routes.yaml", "T-ROUTE-0001"),
        ] {
            let entry = VALID_ENTRY.replace(
                "    test_id: T-API-0001\n",
                &format!("    test_id: {test_id}\n"),
            );
            let parsed: serde_yaml::Value =
                serde_yaml::from_str(&doc(&entry)).expect("测试用例 YAML 必须可解析");
            check_ledger(
                file,
                LedgerKind::Parity,
                &parsed,
                &mut violations,
                &mut warnings,
                &mut global,
            );
        }
        assert!(
            violations.is_empty(),
            "不同 test_id 不该冲突：{violations:?}"
        );
    }

    // --- 规则 6 ------------------------------------------------------------

    #[test]
    fn rule6_rejects_malformed_test_id() {
        for bad in [
            "T-api-0001",  // 小写
            "T-API-001",   // 三位数字
            "T-API-00001", // 五位数字
            "T_API_0001",  // 下划线
            "API-0001",    // 缺前缀
            "T-API-0001x", // 尾巴
        ] {
            let entry = VALID_ENTRY.replace(
                "    test_id: T-API-0001\n",
                &format!("    test_id: {bad}\n"),
            );
            assert_only_rule(&run(&doc(&entry)).0, "[规则 6]");
        }
    }

    #[test]
    fn rule6_accepts_wellformed_test_id() {
        for good in ["T-API-0001", "T-BROWSEROPS-9999", "T-UI-0042"] {
            let entry = VALID_ENTRY.replace(
                "    test_id: T-API-0001\n",
                &format!("    test_id: {good}\n"),
            );
            let (violations, _) = run(&doc(&entry));
            assert!(
                violations.is_empty(),
                "test_id={good} 应当合法：{violations:?}"
            );
        }
    }

    // --- 规则 7 ------------------------------------------------------------

    #[test]
    fn rule7_rejects_bare_line_number_in_upstream() {
        let entry = VALID_ENTRY.replace(
            "    upstream: server/src/routes/thread.ts::getThread\n",
            "    upstream: server/src/routes/thread.ts:142\n",
        );
        assert_only_rule(&run(&doc(&entry)).0, "[规则 7]");
    }

    #[test]
    fn rule7_accepts_symbol_reference_and_dash() {
        // 正向对照含三种合法形态：`::符号名`、纯路径、无上游对应物的 `-`。
        // 顺带钉住"`::getThread` 里的双冒号不能被误判成行号"。
        for good in [
            "server/src/routes/thread.ts::getThread",
            "server/src/routes/thread.ts",
            "-",
            "app/routes/_index.tsx::Component",
        ] {
            let entry = VALID_ENTRY.replace(
                "    upstream: server/src/routes/thread.ts::getThread\n",
                &format!("    upstream: \"{good}\"\n"),
            );
            let (violations, _) = run(&doc(&entry));
            assert!(
                violations.is_empty(),
                "upstream={good} 应当合法：{violations:?}"
            );
        }
    }

    // --- 规则 8 ------------------------------------------------------------

    #[test]
    fn rule8_rejects_empty_recount_list() {
        let yaml = doc(VALID_ENTRY).replace(VALID_RECOUNT, "recount: []\n");
        assert_only_rule(&run(&yaml).0, "[规则 8]");
    }

    #[test]
    fn rule8_rejects_empty_command() {
        let yaml = doc(VALID_ENTRY).replace(
            "  - command: rg -c app server/src/index.ts\n",
            "  - command: \"\"\n",
        );
        assert_only_rule(&run(&yaml).0, "[规则 8]");
    }

    #[test]
    fn rule8_rejects_unknown_cwd() {
        let yaml = doc(VALID_ENTRY).replace("    cwd: upstream\n", "    cwd: /tmp\n");
        assert_only_rule(&run(&yaml).0, "[规则 8]");
    }

    #[test]
    fn rule8_rejects_missing_expect() {
        let yaml = doc(VALID_ENTRY).replace("    expect: 95\n", "");
        assert_only_rule(&run(&yaml).0, "[规则 8]");
    }

    #[test]
    fn rule8_accepts_string_expect_and_both_cwds() {
        for cwd in RECOUNT_CWD {
            let yaml = doc(VALID_ENTRY)
                .replace("    cwd: upstream\n", &format!("    cwd: {cwd}\n"))
                .replace("    expect: 95\n", "    expect: \"95 = 91 + 4\"\n");
            let (violations, _) = run(&yaml);
            assert!(
                violations.is_empty(),
                "cwd={cwd} + 字符串 expect 应当合法：{violations:?}"
            );
        }
    }

    // --- 告警（不影响退出码，但必须真的会响）-------------------------------

    #[test]
    fn warns_on_upstream_commit_drift() {
        let yaml = doc(VALID_ENTRY).replace(
            EXPECTED_UPSTREAM_COMMIT,
            "0000000000000000000000000000000000000000",
        );
        let (violations, warnings) = run(&yaml);
        assert!(
            violations.is_empty(),
            "commit 漂移是告警不是违规：{violations:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("upstream_commit")),
            "commit 漂移必须出告警：{warnings:?}"
        );
    }

    #[test]
    fn warns_on_tbd_target() {
        let entry = VALID_ENTRY.replace(
            "    target: openbot-server::routes::thread::get\n",
            "    target: TBD\n",
        );
        let (violations, warnings) = run(&doc(&entry));
        assert!(violations.is_empty(), "TBD 是告警不是违规：{violations:?}");
        assert!(
            warnings.iter().any(|w| w.contains("TBD")),
            "target=TBD 必须出告警：{warnings:?}"
        );
    }

    #[test]
    fn warns_on_unknown_migration_rule_prefix() {
        let entry = VALID_ENTRY.replace(
            "    migration_rule: preserve\n",
            "    migration_rule: 保留\n",
        );
        let (violations, warnings) = run(&doc(&entry));
        assert!(
            violations.is_empty(),
            "migration_rule 前缀是告警不是违规：{violations:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("migration_rule")),
            "未知 migration_rule 前缀必须出告警：{warnings:?}"
        );
    }

    #[test]
    fn accepts_migration_rule_with_colon_suffix() {
        let entry = VALID_ENTRY.replace(
            "    migration_rule: preserve\n",
            "    migration_rule: \"rename: OPENBOT_ 前缀统一\"\n",
        );
        let (violations, warnings) = run(&doc(&entry));
        assert!(violations.is_empty(), "带冒号后缀应当合法：{violations:?}");
        assert!(warnings.is_empty(), "带冒号后缀不该告警：{warnings:?}");
    }

    // --- 常量自洽 ----------------------------------------------------------

    #[test]
    fn owners_match_workspace_members() {
        // 十个 parity OWNERS + R127 唯一窄化安全边界必须恰好覆盖 workspace；新增第二个
        // 例外或把安全边界误列成产品迁移 owner 都会判红。
        let manifest = include_str!("../../../../Cargo.toml");
        for owner in OWNERS {
            // The UI directory was renamed; the Cargo package and parity owner stay stable.
            let directory = if owner == "openbot-ui" {
                "wrokbot-ui"
            } else {
                owner
            };
            assert!(
                manifest.contains(&format!("\"crates/{directory}\"")),
                "OWNERS 里的 {owner} 不在 workspace members 里"
            );
        }
        for member in NON_PARITY_WORKSPACE_MEMBERS {
            assert!(
                manifest.contains(&format!("\"crates/{member}\"")),
                "R127 安全边界 {member} 不在 workspace members 里"
            );
            assert!(!OWNERS.contains(&member));
        }
        let member_count = manifest
            .lines()
            .filter(|l| {
                let line = l.trim_start();
                line.starts_with("\"crates/openbot-") || line.starts_with("\"crates/wrokbot-ui\"")
            })
            .count();
        assert_eq!(
            member_count,
            OWNERS.len() + NON_PARITY_WORKSPACE_MEMBERS.len(),
            "workspace 必须恰为十个 parity owner + R127 一个安全边界"
        );
    }

    // -----------------------------------------------------------------------
    // fixtures 台账被纳入同一套 8 条规则
    // -----------------------------------------------------------------------

    /// 一条各字段都合法的 fixtures entry。
    const VALID_FIXTURES_ENTRY: &str = "  - id: policy-cel-corpus\n    upstream: server/src/computer/policy.ts::POLICY_FUNCTIONS\n    label: parity\n    target: fixtures/policy/cel-corpus.json\n    owner: openbot-domain\n    test_id: T-FIX-0001\n    migration_rule: preserve\n    status: todo\n    evidence: node gen-corpus.mjs\n";

    fn fixtures_doc(entries: &str) -> String {
        format!(
            "schema: fixtures\nschema_version: 1\nupstream_commit: {EXPECTED_UPSTREAM_COMMIT}\ngenerated_by: manual\nrecount:\n  - command: \"grep -c '^  - id: ' fixtures/MANIFEST.yaml\"\n    cwd: repo\n    expect: 1\nentries:\n{entries}"
        )
    }

    /// 一份最小但合法的 parity ledger，供临时仓根用例当"另一半"。
    fn minimal_parity_doc() -> String {
        doc(VALID_ENTRY)
    }

    /// 用完即删的临时仓根。本 crate 没有 `tempfile` 依赖，所以自带一个最小实现。
    pub(crate) struct TempRepo {
        pub(crate) root: PathBuf,
    }

    impl TempRepo {
        pub(crate) fn new(tag: &str) -> Self {
            // 目录名带 pid + 纳秒：`cargo test` 默认并行，固定名字会让两个用例互相踩。
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("系统时钟早于 UNIX 纪元")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "openbot-xtask-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).expect("建临时目录失败");
            Self { root }
        }

        pub(crate) fn write(&self, relpath: &str, content: &str) {
            let path = self.root.join(relpath);
            let parent = path.parent().expect("相对路径必须有父目录");
            std::fs::create_dir_all(parent).expect("建父目录失败");
            std::fs::write(&path, content).expect("写临时文件失败");
        }

        fn mkdir(&self, relpath: &str) {
            std::fs::create_dir_all(self.root.join(relpath)).expect("建目录失败");
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            // 清不掉也不要把断言失败盖过去 —— 临时目录残留不是被测行为。
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn fixtures_schema_value_is_accepted_without_warning() {
        // 正向对照：schema=fixtures 在 fixtures 台账上既不判红也不刷告警。
        // 没有这条，下面那条"parity 台账写 fixtures 会告警"在"白名单压根没生效"的世界里同样成立。
        let (violations, warnings) = run_as(
            FIXTURES_MANIFEST_RELPATH,
            LedgerKind::Fixtures,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );
        assert!(
            violations.is_empty(),
            "fixtures 台账不该有违规：{violations:?}"
        );
        assert!(
            warnings.is_empty(),
            "schema=fixtures 是 fixtures 台账的合法取值，不该告警：{warnings:?}"
        );
    }

    #[test]
    fn parity_ledger_declaring_fixtures_schema_still_warns() {
        // 负向对照：白名单是**按台账种类**分的，不是全局多加一个名字。
        let yaml = minimal_parity_doc().replace("schema: api\n", "schema: fixtures\n");
        let (violations, warnings) = run_as("parity/api.yaml", LedgerKind::Parity, &yaml);
        assert!(
            violations.is_empty(),
            "schema 是告警不是违规：{violations:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("schema=`fixtures`")),
            "parity ledger 写 schema=fixtures 必须告警：{warnings:?}"
        );
    }

    #[test]
    fn fixtures_ledger_is_subject_to_the_same_eight_rules() {
        // fixtures/MANIFEST.yaml 的头注释声称"顶层键集合与校验器的八条规则逐条对齐"。
        // 这条把这句声明变成可执行判据：随便违反一条规则，fixtures 台账照样判红。
        let entry = VALID_FIXTURES_ENTRY.replace("    label: parity\n", "    label: 新功能\n");
        let (violations, _) = run_as(
            FIXTURES_MANIFEST_RELPATH,
            LedgerKind::Fixtures,
            &fixtures_doc(&entry),
        );
        assert_only_rule(&violations, "[规则 2]");
        assert!(
            violations[0].contains(FIXTURES_MANIFEST_RELPATH),
            "报错必须点名是哪个文件：{violations:?}"
        );
    }

    #[test]
    fn fixtures_manifest_is_actually_collected_by_parity_check() {
        // 上一条测的是"规则能作用在 fixtures 文档上"，这一条测的是**接线** ——
        // 也就是本轮真正要补的洞：`parity-check` 之前压根没去读这个文件。
        let repo = TempRepo::new("wired");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write("parity/api.yaml", &minimal_parity_doc());
        let bad = VALID_FIXTURES_ENTRY.replace(
            "    test_id: T-FIX-0001\n",
            "    test_id: T-fix-0001\n", // 小写，违反规则 6
        );
        repo.write(FIXTURES_MANIFEST_RELPATH, &fixtures_doc(&bad));

        let report = build_parity_report(&repo.root, CheckScope::Full).expect("组装报告不该出错");
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains(FIXTURES_MANIFEST_RELPATH) && v.contains("[规则 6]")),
            "fixtures 台账违反规则 6 必须被 parity-check 抓到：{:?}",
            report.violations
        );
    }

    #[test]
    fn fixtures_entries_do_not_leak_into_parity_totals() {
        // "9 ledger / entries=1641" 被写进了多处文档与 PR 正文。把 fixtures 并进合计
        // 会让那些计数全部对不上，所以这条钉死：合计只数 parity ledger。
        let repo = TempRepo::new("totals");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write("parity/api.yaml", &minimal_parity_doc());
        repo.write(
            FIXTURES_MANIFEST_RELPATH,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );

        let report = build_parity_report(&repo.root, CheckScope::Full).expect("组装报告不该出错");
        assert!(
            !report.required_inputs_present,
            "partial inputs must not pass full scope"
        );
        assert!(
            report
                .violations
                .iter()
                .all(|v| v.starts_with("full scope:")),
            "the supplied entries themselves are valid: {:?}",
            report.violations
        );
        assert_eq!(report.ledgers.len(), 1, "parity ledger 只有一份");
        assert_eq!(report.fixtures.len(), 1, "fixtures 台账单列一份");
        assert_eq!(report.fixtures[0].entries, 1, "fixtures 那份确实有 entry");
        assert_eq!(
            report.total_entries, 1,
            "合计必须只等于 parity ledger 的 entry 数（1），不是 1 + 1"
        );
        assert_eq!(
            report.total_status_counts.get("todo").copied(),
            Some(1),
            "status 合计同样不含 fixtures：{:?}",
            report.total_status_counts
        );
    }

    #[test]
    fn missing_fixtures_manifest_with_existing_dir_is_a_violation() {
        // fixtures 语料还在、台账没了 = 这批文件重新变成没人记账的散文件。
        let repo = TempRepo::new("nomanifest");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write("parity/api.yaml", &minimal_parity_doc());
        repo.mkdir("fixtures/policy");

        let report = build_parity_report(&repo.root, CheckScope::Full).expect("组装报告不该出错");
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains(FIXTURES_MANIFEST_RELPATH)),
            "fixtures/ 在而台账不在必须判红：{:?}",
            report.violations
        );
    }

    #[test]
    fn missing_fixtures_dir_fails_in_both_scopes() {
        let repo = TempRepo::new("nodir");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write("parity/api.yaml", &minimal_parity_doc());

        for scope in [CheckScope::Full, CheckScope::FixturesOnly] {
            let report = build_parity_report(&repo.root, scope).expect("report");
            assert!(!report.required_inputs_present);
            assert!(
                report
                    .violations
                    .iter()
                    .any(|v| v.contains(FIXTURES_MANIFEST_RELPATH))
            );
        }
    }

    #[test]
    fn real_repo_fixtures_only_does_not_certify_missing_parity() {
        // 对真仓跑一遍。断言用不变式而不是硬编码 1641：ledger 条目会随实施推进增长，
        // 而"合计恰好等于九份 parity ledger 之和、且 fixtures 那份不在里面"永远该成立。
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/openbot-testkit 的祖父目录 = 仓根")
            .to_path_buf();
        let report =
            build_parity_report(&root, CheckScope::FixturesOnly).expect("组装报告不该出错");

        assert!(
            report.violations.is_empty(),
            "真仓台账必须零违反：{:?}",
            report.violations
        );
        assert!(
            report.ledgers.is_empty(),
            "public repository has no internal migration ledgers"
        );
        assert_eq!(
            report.total_entries, 0,
            "fixture counts must not become migration totals"
        );
        assert_eq!(report.fixtures.len(), 1, "fixtures 台账恰好一份");
        assert_eq!(report.scope, CheckScope::FixturesOnly);
        assert!(!report.parity_checked && !report.overlay_checked && !report.product_certified);

        let fixtures_entries = report.fixtures[0].entries;
        assert!(
            fixtures_entries > 0,
            "fixtures 台账必须有 entry —— 否则下面那条\"没有并进合计\"在空台账上恒真"
        );
        let parity_sum: usize = report.ledgers.iter().map(|l| l.entries).sum();
        assert_eq!(report.total_entries, parity_sum, "合计 = 九份之和");
        assert_ne!(
            report.total_entries,
            parity_sum + fixtures_entries,
            "合计里不得混入 fixtures 的 {fixtures_entries} 条"
        );
    }

    #[test]
    fn full_scope_missing_migration_inputs_fails_while_explicit_fixtures_pass() {
        let repo = TempRepo::new("scopes");
        repo.write(
            FIXTURES_MANIFEST_RELPATH,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );
        let full = build_parity_report(&repo.root, CheckScope::Full).expect("full report");
        assert!(!full.required_inputs_present);
        assert_eq!(full.violations.len(), KNOWN_SCHEMAS.len() + 1);
        let fixtures =
            build_parity_report(&repo.root, CheckScope::FixturesOnly).expect("fixture report");
        assert!(fixtures.required_inputs_present && fixtures.violations.is_empty());
        assert!(!fixtures.parity_checked && !fixtures.overlay_checked);
        // Explicit scope must not even parse a private ledger, including malformed input.
        repo.write("parity/api.yaml", "{broken yaml");
        assert!(
            build_parity_report(&repo.root, CheckScope::FixturesOnly)
                .unwrap()
                .violations
                .is_empty()
        );
        assert!(
            !build_parity_report(&repo.root, CheckScope::Full)
                .unwrap()
                .violations
                .is_empty()
        );
    }

    #[test]
    fn full_scope_rejects_renamed_mislabelled_and_empty_migration_inputs() {
        let repo = TempRepo::new("identity");
        repo.write(
            FIXTURES_MANIFEST_RELPATH,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );
        repo.write("parity/not-api.yaml", &minimal_parity_doc());
        repo.write("parity/api.yml", &minimal_parity_doc());
        repo.write("parity/routes.yaml", &minimal_parity_doc());
        repo.write(
            "parity/env.yaml",
            &doc("")
                .replace("schema: api", "schema: env")
                .replace("entries:\n", "entries: []\n"),
        );
        let report = build_parity_report(&repo.root, CheckScope::Full).unwrap();
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("缺少必需台账 parity/api.yaml"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("未登记台账 parity/not-api.yaml"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("未登记台账 parity/api.yml"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("schema 必须为 routes"))
        );
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("entries 不能为空"))
        );
    }

    #[test]
    fn all_nine_ledger_identities_still_require_an_overlay() {
        let repo = TempRepo::new("complete-identities");
        repo.write(
            FIXTURES_MANIFEST_RELPATH,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );
        for (index, schema) in KNOWN_SCHEMAS.iter().enumerate() {
            let entry = VALID_ENTRY.replace("T-API-0001", &format!("T-API-{:04}", index + 1));
            let yaml = doc(&entry).replace("schema: api", &format!("schema: {schema}"));
            repo.write(&format!("parity/{schema}.yaml"), &yaml);
        }
        let missing = build_parity_report(&repo.root, CheckScope::Full).unwrap();
        assert_eq!(missing.ledgers.len(), 9);
        assert_eq!(missing.violations.len(), 1, "{:?}", missing.violations);
        assert!(missing.violations[0].contains("缺少必需 overlay"));
        repo.write("parity/overlay/v4.yaml", "{not valid");
        let bad = build_parity_report(&repo.root, CheckScope::Full).unwrap();
        assert!(bad.required_inputs_present && bad.overlay_checked);
        assert!(
            bad.violations
                .iter()
                .any(|v| v.contains("overlay/v4.yaml") && v.contains("YAML"))
        );
    }

    #[test]
    fn fixture_recount_uses_rust_for_all_six_queries_and_rejects_drift() {
        let repo = TempRepo::new("native-fixture-recount");
        let manifest = include_str!("../../../../fixtures/MANIFEST.yaml");
        repo.write(FIXTURES_MANIFEST_RELPATH, manifest);
        let mut items = collect_recount_items(&repo.root, CheckScope::FixturesOnly).unwrap();
        let values = fixture_recount_values(&repo.root, &items).unwrap();
        assert_eq!(items.len(), 6);
        for item in &items {
            let outcome = evaluate_fixture_recount(item, &values).unwrap();
            assert_eq!(outcome.status, RecountStatus::Pass);
            assert_eq!(outcome.exit_code, None, "no external process was run");
        }
        items[0].expect = "0".into();
        assert_eq!(
            evaluate_fixture_recount(&items[0], &values).unwrap().status,
            RecountStatus::Mismatch
        );
        items[0].command.push_str("; echo unexpected");
        assert!(fixture_recount_values(&repo.root, &items).is_err());
        assert!(fixture_recount_values(&repo.root, &items[1..]).is_err());
        let duplicate = vec![items[1].clone(); 6];
        assert!(fixture_recount_values(&repo.root, &duplicate).is_err());
    }

    // -----------------------------------------------------------------------
    // recount
    // -----------------------------------------------------------------------

    /// 假执行器：不起进程，记录被调用的 (命令, cwd)。
    struct FakeRunner {
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
        calls: std::cell::RefCell<Vec<(String, PathBuf)>>,
    }

    impl FakeRunner {
        fn with_stdout(stdout: &str) -> Self {
            Self {
                stdout: stdout.to_string(),
                stderr: String::new(),
                exit_code: Some(0),
                calls: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl RecountRunner for FakeRunner {
        fn run(&self, command: &str, cwd: &Path) -> Result<RawOutput> {
            self.calls
                .borrow_mut()
                .push((command.to_string(), cwd.to_path_buf()));
            Ok(RawOutput {
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
                exit_code: self.exit_code,
            })
        }
    }

    fn item(cwd: RecountCwd, expect: &str) -> RecountItem {
        RecountItem {
            file: "parity/tables.yaml".to_string(),
            index: 2,
            command: "grep -c '^  - id: ' parity/tables.yaml".to_string(),
            cwd,
            expect: expect.to_string(),
        }
    }

    #[test]
    fn recount_matches_accepts_equal_values() {
        assert!(recount_matches("53", "53\n"));
        assert!(recount_matches("ok", "ok\n"));
        assert!(recount_matches("27 27", "27 27\n"));
    }

    #[test]
    fn recount_matches_rejects_different_values() {
        // 负向对照。没有它，一个 `fn recount_matches(..) -> bool { true }` 也能让上面那条通过。
        assert!(!recount_matches("53", "54\n"));
        assert!(!recount_matches("ok", "\n"));
        assert!(!recount_matches("27 27", "27 28\n"));
        // 内部空白是有意义的：`27 27` 与 `2727` 不是同一个答案。
        assert!(!recount_matches("27 27", "2727\n"));
    }

    #[test]
    fn recount_matches_trims_both_sides() {
        // parity/ui.yaml 那条 `for … printf '%s '` 循环的真实 stdout 是 `13 8 4 3 1 32 `
        // （尾随一个空格、且没有换行），作者把这个尾随空格原样写进了 expect。
        // 只 trim 一侧会把这条判成失配，而尾随空白既不携带计数信息又在 YAML / 编辑器之间不稳定。
        assert!(recount_matches("13 8 4 3 1 32 ", "13 8 4 3 1 32 "));
        assert!(recount_matches("13 8 4 3 1 32 ", "13 8 4 3 1 32"));
        assert!(recount_matches("13 8 4 3 1 32", "13 8 4 3 1 32 "));
    }

    #[test]
    fn evaluate_recount_passes_when_stdout_equals_expect() {
        let runner = FakeRunner::with_stdout("53\n");
        let outcome = evaluate_recount(
            &item(RecountCwd::Repo, "53"),
            Path::new("/repo"),
            None,
            &runner,
        )
        .expect("假执行器不会失败");
        assert_eq!(outcome.status, RecountStatus::Pass);
        assert_eq!(outcome.actual.as_deref(), Some("53"));
        assert_eq!(runner.call_count(), 1, "repo 项必须真的被执行");
        assert_eq!(
            runner.calls.borrow()[0].1,
            PathBuf::from("/repo"),
            "cwd=repo 必须落在仓根"
        );
    }

    #[test]
    fn evaluate_recount_flags_mismatch_when_expect_is_wrong() {
        // 负向对照：期望值故意写错就必须判红，并把期望/实得都带出来。
        let runner = FakeRunner::with_stdout("53\n");
        let outcome = evaluate_recount(
            &item(RecountCwd::Repo, "999"),
            Path::new("/repo"),
            None,
            &runner,
        )
        .expect("假执行器不会失败");
        assert_eq!(outcome.status, RecountStatus::Mismatch);
        assert_eq!(outcome.actual.as_deref(), Some("53"));
    }

    #[test]
    fn evaluate_recount_ignores_exit_code_when_stdout_matches() {
        // `grep -c` 在计数为 0 时打印正确的 `0` 却返回退出码 1。
        // 拿退出码当判据会把这条判成失败 —— 判据只能是 stdout。
        let runner = FakeRunner {
            stdout: "0\n".to_string(),
            stderr: String::new(),
            exit_code: Some(1),
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let outcome = evaluate_recount(
            &item(RecountCwd::Repo, "0"),
            Path::new("/repo"),
            None,
            &runner,
        )
        .expect("假执行器不会失败");
        assert_eq!(outcome.status, RecountStatus::Pass);
        assert_eq!(outcome.exit_code, Some(1), "退出码仍要留在报告里供诊断");
    }

    #[test]
    fn evaluate_recount_skips_upstream_when_dir_is_absent() {
        // 本命令最容易被做成假闸门的一点：把"没跑"报告成通过。
        let runner = FakeRunner::with_stdout("95\n");
        let outcome = evaluate_recount(
            &item(RecountCwd::Upstream, "95"),
            Path::new("/repo"),
            None,
            &runner,
        )
        .expect("跳过不该出错");
        assert_eq!(
            outcome.status,
            RecountStatus::Skipped,
            "上游目录缺失必须是 SKIPPED，不是 PASS"
        );
        assert_ne!(outcome.status, RecountStatus::Pass);
        assert!(outcome.actual.is_none(), "没跑就没有实得值");
        assert!(
            outcome
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains(UPSTREAM_DIR_ENV),
            "跳过原因必须点名环境变量：{:?}",
            outcome.reason
        );
        assert_eq!(runner.call_count(), 0, "跳过时一条命令都不该被执行");
    }

    #[test]
    fn evaluate_recount_runs_upstream_when_dir_is_present() {
        // 上一条的正向对照：上游目录在场时同一条 item 会被真的执行，且 cwd 落在上游。
        // 没有它，"跳过"那条在 `evaluate_recount` 恒返回 Skipped 的世界里同样成立。
        let runner = FakeRunner::with_stdout("95\n");
        let outcome = evaluate_recount(
            &item(RecountCwd::Upstream, "95"),
            Path::new("/repo"),
            Some(Path::new("/upstream")),
            &runner,
        )
        .expect("假执行器不会失败");
        assert_eq!(outcome.status, RecountStatus::Pass);
        assert_eq!(runner.call_count(), 1);
        assert_eq!(
            runner.calls.borrow()[0].1,
            PathBuf::from("/upstream"),
            "cwd=upstream 必须落在上游克隆"
        );
    }

    #[test]
    fn scalar_to_string_normalizes_numbers_strings_and_bools() {
        assert_eq!(
            scalar_to_string(&serde_yaml::Value::from(53i64)).as_deref(),
            Some("53")
        );
        assert_eq!(
            scalar_to_string(&serde_yaml::Value::from("ok")).as_deref(),
            Some("ok")
        );
        assert_eq!(
            scalar_to_string(&serde_yaml::Value::from(true)).as_deref(),
            Some("true")
        );
        // 负向对照：序列 / 映射不是标量，必须被拒绝而不是 Debug 打印出一个假答案。
        assert!(scalar_to_string(&serde_yaml::Value::Sequence(vec![])).is_none());
        assert!(
            scalar_to_string(&serde_yaml::Value::Mapping(serde_yaml::Mapping::new())).is_none()
        );
        assert!(scalar_to_string(&serde_yaml::Value::Null).is_none());
    }

    #[test]
    fn collect_recount_items_covers_parity_and_fixtures() {
        let repo = TempRepo::new("collect");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write("parity/api.yaml", &minimal_parity_doc());
        repo.write(
            FIXTURES_MANIFEST_RELPATH,
            &fixtures_doc(VALID_FIXTURES_ENTRY),
        );

        let items = collect_recount_items(&repo.root, CheckScope::Full).expect("收集不该出错");
        assert_eq!(items.len(), 2, "两份台账各一条 recount：{items:?}");
        assert!(
            items.iter().any(|i| i.file == "parity/api.yaml"
                && i.cwd == RecountCwd::Upstream
                && i.expect == "95"),
            "parity ledger 的 recount 必须被收上来：{items:?}"
        );
        assert!(
            items.iter().any(|i| i.file == FIXTURES_MANIFEST_RELPATH
                && i.cwd == RecountCwd::Repo
                && i.expect == "1"),
            "fixtures 台账的 recount 必须被收上来：{items:?}"
        );
    }

    #[test]
    fn collect_recount_items_rejects_structurally_broken_recount() {
        // 负向对照：结构坏了要报错并指向 parity-check，不是静默少跑几条。
        let repo = TempRepo::new("broken");
        repo.write("Cargo.toml", "[workspace]\n");
        repo.write(
            "parity/api.yaml",
            &minimal_parity_doc().replace("    cwd: upstream\n", "    cwd: /tmp\n"),
        );

        let err =
            collect_recount_items(&repo.root, CheckScope::Full).expect_err("cwd 非法必须报错");
        let text = format!("{err:#}");
        assert!(text.contains("parity-check"), "报错要指向归属地：{text}");
        assert!(text.contains("/tmp"), "报错要点名坏值：{text}");
    }

    #[test]
    fn shell_candidates_are_rooted_paths_never_bare_names() {
        // 刻意不断言"这台机器上装了 Git Bash" —— 那是对不受控全机状态的断言，
        // 换台机器就翻，测的不是代码。能断言的是代码本身：每个候选都必须是**带根的路径**，
        // 绝不能退化成 PATH 上的裸 `bash`（可能是 System32 的 WSL bash，
        // 落在另一个文件系统命名空间里，失败形态是"命令输出为空"，与真的数出 0 不可区分）。
        //
        // 不能直接用 `Path::is_absolute()`：它按**当前平台**的语义判，
        // `/bin/bash` 在 Windows 上会被判成非绝对路径 —— 那正是"答案取决于跑在哪台机器上"。
        for candidate in UNIX_SHELL_CANDIDATES.iter() {
            assert!(
                candidate.starts_with('/'),
                "{candidate} 不是以 / 开头的绝对路径"
            );
        }
        for candidate in WINDOWS_SHELL_CANDIDATES.iter() {
            let mut chars = candidate.chars();
            let drive = chars.next().unwrap_or(' ');
            let rest: String = chars.collect();
            assert!(
                drive.is_ascii_alphabetic() && rest.starts_with(":\\"),
                "{candidate} 不是 `X:\\…` 形态的绝对路径"
            );
        }
        // 共同的负向对照：一个都不能是裸命令名。
        for candidate in WINDOWS_SHELL_CANDIDATES
            .iter()
            .chain(UNIX_SHELL_CANDIDATES.iter())
        {
            assert!(
                candidate.contains('/') || candidate.contains('\\'),
                "{candidate} 是裸命令名，会走 PATH 解析"
            );
        }
    }

    #[test]
    fn truncate_chars_respects_utf8_boundaries() {
        // 台账里有中文，按字节截会 panic。
        let text = "规则 8：recount 至少一条，且每条 command 非空";
        let cut = truncate_chars(text, 5);
        assert!(cut.starts_with("规则 8："), "{cut}");
        assert!(cut.ends_with("（已截断）"), "{cut}");
        assert_eq!(truncate_chars("短", 5), "短", "不超长时原样返回");
    }

    // -----------------------------------------------------------------------
    // ci 的 target 树不变量
    // -----------------------------------------------------------------------

    #[test]
    fn driver_inside_child_target_is_detected() {
        // 正向对照：判据必须在**真正会出事的那个摆放**下为真。
        // 造一棵真目录树而不是拼字符串 —— canonicalize 在 Windows 上会把 `D:\...`
        // 变成 `\\?\D:\...`，只比字符串的实现恰好在该报警的那台机器上失灵。
        let repo = TempRepo::new("driver-conflict");
        repo.write("target/debug/xtask.exe", "not really an exe");
        let target = repo.root.join("target");
        let exe = target.join("debug").join("xtask.exe");

        assert!(
            driver_conflicts_with_child_target(&exe, &target),
            "驱动器就在子构建 target 树里，判据却说没冲突"
        );
    }

    #[test]
    fn driver_in_a_sibling_tree_is_not_a_conflict() {
        // 负向对照：alias 选的那个摆放（驱动器在 target-xtask/，子构建在 target/）
        // **不得**被判成冲突 —— 否则这条判据会把唯一正确的用法一并堵死，
        // 而那种"恒真"的守卫在功能压根没接通的世界里表现完全相同。
        let repo = TempRepo::new("driver-sibling");
        repo.write("target/debug/openbot-server.exe", "child build output");
        repo.write("target-xtask/debug/xtask.exe", "driver");
        let target = repo.root.join("target");
        let driver = repo
            .root
            .join("target-xtask")
            .join("debug")
            .join("xtask.exe");

        assert!(target.is_dir(), "前提自检：子构建 target 必须真的存在");
        assert!(
            !driver_conflicts_with_child_target(&driver, &target),
            "驱动器在兄弟树里，判据却报了冲突"
        );
    }

    #[test]
    fn missing_child_target_is_not_a_conflict() {
        // 干净 checkout 上 `target/` 还不存在。这时 canonicalize 会失败，
        // 而"取不到路径"绝不能当成"有冲突"—— 那会让首次 `cargo xtask ci` 直接拒跑。
        let repo = TempRepo::new("driver-missing-target");
        repo.write("elsewhere/xtask.exe", "driver");
        let target = repo.root.join("target");
        let exe = repo.root.join("elsewhere").join("xtask.exe");

        assert!(!target.exists(), "前提自检：target 本该不存在");
        assert!(!driver_conflicts_with_child_target(&exe, &target));
    }
}
