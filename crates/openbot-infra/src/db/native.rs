//! 本项目自有的 native schema 增量施加器。
//!
//! 上游的 13 条 Drizzle migration 与本项目的增量有两条不同的职责边界：
//!
//! - [`crate::db::baseline`] 把空库一次建成上游 0012 终态；
//! - [`crate::db::compat`] 只读 `drizzle.__drizzle_migrations`，确认旧库至少到 0012；
//! - 本模块从 0012 往后施加 Rust-owned migration，schema 只允许 expand，**绝不写上游账本**；
//! - 唯一数据覆写例外是具名、可审计的隐私保留期清除；它只能把已终态 run 的 reasoning
//!   payload 收敛为固定无内容标记，不能改业务身份、序列或 terminal 事实。
//!
//! # 自有账本与并发
//!
//! 自有账本是 [`NATIVE_LEDGER_TABLE`]。每条记录绑定 version、名字与 migration SQL 的
//! SHA-256；同版本字节漂移会 fail-closed，不会因为对象“看起来已存在”就跳过。施加全过程在
//! 一个事务里，并先取固定的 transaction-scoped advisory lock，因此多个 replica 同时启动时
//! 恰好一个施加，随后者读到账本后返回 [`ApplyOutcome::AlreadyApplied`]。
//!
//! 真实 migration SQL 刻意没有 `IF NOT EXISTS`：账本缺失而对象已存在是 drift，必须让 DDL
//! 报错并整体回滚。只有账本自身的 bootstrap 使用 `IF NOT EXISTS`，且随后立刻按列读它；一个
//! 同名异形表不会被当作正常账本。
//!
//! # Fresh install 与 upgrade 是同一条终态
//!
//! Fresh install 只走 [`crate::db::fresh::apply`]，把 baseline 与本模块的事务内核心/账本同批
//! 提交；既有库先过 compat，再调用 [`apply`]。这样 0012 fixture 始终只表达固定上游 oracle，
//! 每个 native 边界另有自己的 post fixture，事实不会互相污染。

use openbot_domain::audit::hash::Sha256Digest;
use tokio_postgres::Client;

use crate::db::{InfraError, RowDecodeError};

/// 自有 migration 账本。它不在 `public`，也不是上游 Drizzle 的账本。
pub const NATIVE_LEDGER_TABLE: &str = "openbot_internal.schema_migrations";

/// 第一条 Rust-owned 增量的版本号。
pub const NATIVE_0013_VERSION: i32 = 13;

/// 第一条 Rust-owned 增量的稳定名字。
pub const NATIVE_0013_NAME: &str = "native_0013_audit_tool_pipeline";

/// 第一条 Rust-owned 增量的 SQL 原文。
pub const NATIVE_0013_SQL: &str = include_str!("../../sql/native_0013.sql");

/// 持久化 user auth generation 的版本号。
pub const NATIVE_0014_VERSION: i32 = 14;

/// 0014 的稳定名字。
pub const NATIVE_0014_NAME: &str = "native_0014_user_auth_generation";

/// 0014 SQL 原文。
pub const NATIVE_0014_SQL: &str = include_str!("../../sql/native_0014.sql");

/// Rust session 签发代际的版本号。
pub const NATIVE_0015_VERSION: i32 = 15;

/// 0015 的稳定名字。
pub const NATIVE_0015_NAME: &str = "native_0015_session_auth_generation";

/// 0015 SQL 原文。
pub const NATIVE_0015_SQL: &str = include_str!("../../sql/native_0015.sql");

/// Native thread/realtime/memory 地基版本号。
pub const NATIVE_0016_VERSION: i32 = 16;

/// 0016 的稳定名字。
pub const NATIVE_0016_NAME: &str = "native_0016_thread_realtime_memory_base";

/// 0016 SQL 原文。
pub const NATIVE_0016_SQL: &str = include_str!("../../sql/native_0016.sql");

/// MCP catalog/stale-grant/callback sequence version.
pub const NATIVE_0017_VERSION: i32 = 17;

/// 0017 stable name.
pub const NATIVE_0017_NAME: &str = "native_0017_mcp_catalog_callback_sequence";

/// 0017 SQL source.
pub const NATIVE_0017_SQL: &str = include_str!("../../sql/native_0017.sql");

/// MCP credential-generation identity version.
pub const NATIVE_0018_VERSION: i32 = 18;

/// 0018 stable name.
pub const NATIVE_0018_NAME: &str = "native_0018_mcp_credential_generation";

/// 0018 SQL source.
pub const NATIVE_0018_SQL: &str = include_str!("../../sql/native_0018.sql");

/// Explicit MCP/Drive vendor transport identity version.
pub const NATIVE_0019_VERSION: i32 = 19;

/// 0019 stable name.
pub const NATIVE_0019_NAME: &str = "native_0019_vendor_transport_identity";

/// 0019 SQL source.
pub const NATIVE_0019_SQL: &str = include_str!("../../sql/native_0019.sql");

/// Durable tool-approval request version.
pub const NATIVE_0020_VERSION: i32 = 20;

/// 0020 stable name.
pub const NATIVE_0020_NAME: &str = "native_0020_tool_approvals";

/// 0020 SQL source.
pub const NATIVE_0020_SQL: &str = include_str!("../../sql/native_0020.sql");

/// Actor-scoped Server UI preference version.
pub const NATIVE_0021_VERSION: i32 = 21;

/// 0021 stable name.
pub const NATIVE_0021_NAME: &str = "native_0021_user_ui_preferences";

/// 0021 SQL source.
pub const NATIVE_0021_SQL: &str = include_str!("../../sql/native_0021.sql");

/// Actor-scoped runtime memory control version.
pub const NATIVE_0022_VERSION: i32 = 22;

/// 0022 stable name.
pub const NATIVE_0022_NAME: &str = "native_0022_user_memory_controls";

/// 0022 SQL source.
pub const NATIVE_0022_SQL: &str = include_str!("../../sql/native_0022.sql");

/// Durable compiled-component human-decision version.
pub const NATIVE_0023_VERSION: i32 = 23;

/// 0023 stable name.
pub const NATIVE_0023_NAME: &str = "native_0023_component_human_decisions";

/// 0023 SQL source.
pub const NATIVE_0023_SQL: &str = include_str!("../../sql/native_0023.sql");

/// Durable run-wide normalized provider token accounting version.
pub const NATIVE_0024_VERSION: i32 = 24;

/// 0024 stable name.
pub const NATIVE_0024_NAME: &str = "native_0024_run_token_usage";

/// 0024 SQL source.
pub const NATIVE_0024_SQL: &str = include_str!("../../sql/native_0024.sql");

/// Durable operator-attested provider cost accounting version.
pub const NATIVE_0025_VERSION: i32 = 25;

/// 0025 stable name.
pub const NATIVE_0025_NAME: &str = "native_0025_run_provider_cost_upper_bound";

/// 0025 SQL source.
pub const NATIVE_0025_SQL: &str = include_str!("../../sql/native_0025.sql");

/// Actor-scoped per-run cost-cap and immutable snapshot version.
pub const NATIVE_0026_VERSION: i32 = 26;

/// 0026 stable name.
pub const NATIVE_0026_NAME: &str = "native_0026_user_run_cost_budgets";

/// 0026 SQL source.
pub const NATIVE_0026_SQL: &str = include_str!("../../sql/native_0026.sql");

/// Terminal-run reasoning retention redaction version.
pub const NATIVE_0027_VERSION: i32 = 27;

/// 0027 stable name.
pub const NATIVE_0027_NAME: &str = "native_0027_terminal_reasoning_retention";

/// 0027 SQL source.
pub const NATIVE_0027_SQL: &str = include_str!("../../sql/native_0027.sql");

/// Durable remote AG-UI interrupt/resume version.
pub const NATIVE_0028_VERSION: i32 = 28;

/// 0028 stable name.
pub const NATIVE_0028_NAME: &str = "native_0028_remote_agent_interrupts";

/// 0028 SQL source.
pub const NATIVE_0028_SQL: &str = include_str!("../../sql/native_0028.sql");

/// Explicit custom-MCP private-egress authority version.
pub const NATIVE_0029_VERSION: i32 = 29;

/// 0029 stable name.
pub const NATIVE_0029_NAME: &str = "native_0029_mcp_private_egress";

/// 0029 SQL source.
pub const NATIVE_0029_SQL: &str = include_str!("../../sql/native_0029.sql");

/// Personal custom-model connection/credential authority version.
pub const NATIVE_0030_VERSION: i32 = 30;
/// 0030 stable name.
pub const NATIVE_0030_NAME: &str = "native_0030_personal_model_connections";
/// 0030 SQL source.
pub const NATIVE_0030_SQL: &str = include_str!("../../sql/native_0030.sql");

/// 当前二进制认识的最新 native schema 版本。
pub const NATIVE_LATEST_VERSION: i32 = NATIVE_0053_VERSION;

/// Immutable explicit custom-model run binding version.
pub const NATIVE_0031_VERSION: i32 = 31;
/// 0031 stable migration name.
pub const NATIVE_0031_NAME: &str = "native_0031_run_model_selections";
/// 0031 expand-only SQL source.
pub const NATIVE_0031_SQL: &str = include_str!("../../sql/native_0031.sql");

/// Dataset-bound Desktop Vault canary version.
pub const NATIVE_0032_VERSION: i32 = 32;
/// 0032 stable migration name.
pub const NATIVE_0032_NAME: &str = "native_0032_desktop_vault_canary";
/// 0032 expand-only SQL source.
pub const NATIVE_0032_SQL: &str = include_str!("../../sql/native_0032.sql");

/// SDK Gateway PG/Vault credential authority version.
pub const NATIVE_0033_VERSION: i32 = 33;
/// 0033 stable migration name.
pub const NATIVE_0033_NAME: &str = "native_0033_sdk_gateway_authority";
/// 0033 expand-only SQL source.
pub const NATIVE_0033_SQL: &str = include_str!("../../sql/native_0033.sql");
/// Durable MCP/Drive refresh-operation schema.
pub const NATIVE_0034_VERSION: i32 = 34;
/// Stable name; old migration bytes remain immutable.
pub const NATIVE_0034_NAME: &str = "native_0034_oauth_refresh_operations";
/// Expand-only operation records.
pub const NATIVE_0034_SQL: &str = include_str!("../../sql/native_0034.sql");
/// Immutable same-transaction remember business receipts.
pub const NATIVE_0035_VERSION: i32 = 35;
/// Stable migration identity; historical migration bytes remain unchanged.
pub const NATIVE_0035_NAME: &str = "native_0035_remember_effect_receipts";
/// Expand-only evidence table and mutation guards.
pub const NATIVE_0035_SQL: &str = include_str!("../../sql/native_0035.sql");

/// Compatibility foreground occupancy projection; reconciliation remains blocked.
pub const NATIVE_0036_VERSION: i32 = 36;
/// Stable migration identity.
pub const NATIVE_0036_NAME: &str = "native_0036_thread_run_occupancy";
/// New projection, exact binding and run-maintenance guards.
pub const NATIVE_0036_SQL: &str = include_str!("../../sql/native_0036.sql");

/// Immutable source facts for existing explicit Memory retention paths.
pub const NATIVE_0037_VERSION: i32 = 37;
/// Stable migration identity; no historical migration bytes change.
pub const NATIVE_0037_NAME: &str = "native_0037_memory_provenance";
/// Nullable source run and authorization evidence, with no legacy backfill.
pub const NATIVE_0037_SQL: &str = include_str!("../../sql/native_0037.sql");

/// Independent sandbox editing CAS and retired stable names.
pub const NATIVE_0038_VERSION: i32 = 38;
/// Registered migration identity.
pub const NATIVE_0038_NAME: &str = "native_0038_sandbox_editing_revision";
/// Expand-only sandbox editing schema.
pub const NATIVE_0038_SQL: &str = include_str!("../../sql/native_0038.sql");

/// Editing CAS and permanently retired skill slugs, including owner FK cascades.
pub const NATIVE_0039_VERSION: i32 = 39;
/// Registered migration identity.
pub const NATIVE_0039_NAME: &str = "native_0039_skill_editing_revision";
/// Expand-only skill editing schema.
pub const NATIVE_0039_SQL: &str = include_str!("../../sql/native_0039.sql");

/// Actor-scoped UI preference CAS and audit version.
pub const NATIVE_0040_VERSION: i32 = 40;
/// Stable expand-only identity.
pub const NATIVE_0040_NAME: &str = "native_0040_ui_preferences_revision";
/// Nullable editing revision, with no historical rewrite.
pub const NATIVE_0040_SQL: &str = include_str!("../../sql/native_0040.sql");

/// Immutable internal artifact dataset registry; public schema stays at0040.
pub const NATIVE_0041_VERSION: i32 = 41;
/// Registered migration identity.
pub const NATIVE_0041_NAME: &str = "native_0041_artifact_dataset_binding";
/// Exact internal expansion, with no artifact/quota placeholder tables.
pub const NATIVE_0041_SQL: &str = include_str!("../../sql/native_0041.sql");

/// Actual internal artifact store, durable operation, quota, record and receipt expansion.
pub const NATIVE_0042_VERSION: i32 = 42;
/// Registered real registration migration identity.
pub const NATIVE_0042_NAME: &str = "native_0042_artifact_registration";
/// Exact schema; business source deletion does not cascade into saved artifacts.
pub const NATIVE_0042_SQL: &str = include_str!("../../sql/native_0042.sql");

/// Internal remember preference schema; no permission or CAS repository is exposed here.
pub const NATIVE_0043_VERSION: i32 = 43;
/// Stable native ledger name for the internal preference foundation.
pub const NATIVE_0043_NAME: &str = "native_0043_approval_preferences";
/// Additive bounded keys, immutable record identity and exact revision advancement.
pub const NATIVE_0043_SQL: &str = include_str!("../../sql/native_0043.sql");

/// Existing-record durable cleanup fence foundation; no physical deletion is performed.
pub const NATIVE_0044_VERSION: i32 = 44;
/// Stable ledger identity for the additive cleanup fence migration.
pub const NATIVE_0044_NAME: &str = "native_0044_artifact_cleanup_fences";
/// Immutable cleanup intent, original record-pair key and closed phase guard.
pub const NATIVE_0044_SQL: &str = include_str!("../../sql/native_0044.sql");

/// Additive validation of an existing original saved receipt at cleanup completion.
pub const NATIVE_0045_VERSION: i32 = 45;
/// Stable ledger identity; earlier migration bytes and guards stay unchanged.
pub const NATIVE_0045_NAME: &str = "native_0045_artifact_cleanup_saved_receipts";
/// Null-safe original receipt guard; no cleanup producer or receipt backfill.
pub const NATIVE_0045_SQL: &str = include_str!("../../sql/native_0045.sql");

/// Durable custom-model catalog foundation; no inventory or send authority is exposed here.
pub const NATIVE_0046_VERSION: i32 = 46;
/// Stable ledger identity for the additive catalog migration.
pub const NATIVE_0046_NAME: &str = "native_0046_custom_model_catalogs";
/// Exact catalog schema, legacy backfill and original-transaction synchronization trigger.
pub const NATIVE_0046_SQL: &str = include_str!("../../sql/native_0046.sql");

/// Immutable private custom-V2 snapshots, additive after the original catalog.
pub const NATIVE_0047_VERSION: i32 = 47;
/// Stable migration ledger identity.
pub const NATIVE_0047_NAME: &str = "native_0047_run_model_selection_v2_snapshots";
/// Exact immutable V2 snapshot DDL; no historical selection backfill.
pub const NATIVE_0047_SQL: &str = include_str!("../../sql/native_0047.sql");

/// Independent SDK authorization-attempt storage; no SDK or send authority.
pub const NATIVE_0048_VERSION: i32 = 48;
/// Stable migration ledger identity.
pub const NATIVE_0048_NAME: &str = "native_0048_gateway_authorization_attempts";
/// Exact additive journal DDL, applied on the original native transaction.
pub const NATIVE_0048_SQL: &str = include_str!("../../sql/native_0048.sql");

/// Immutable historical Thread origin facts; no current authority or backfill.
pub const NATIVE_0049_VERSION: i32 = 49;
/// Stable migration ledger identity.
pub const NATIVE_0049_NAME: &str = "native_0049_thread_origins";
/// Exact additive origin DDL, applied on the original native transaction.
pub const NATIVE_0049_SQL: &str = include_str!("../../sql/native_0049.sql");

/// Durable one-J history-state and Thread identity retention; no writer or ACK producer.
pub const NATIVE_0050_VERSION: i32 = 50;
/// Stable additive migration ledger identity.
pub const NATIVE_0050_NAME: &str = "native_0050_thread_history_state";
/// Exact history-state expansion on the original native transaction.
pub const NATIVE_0050_SQL: &str = include_str!("../../sql/native_0050.sql");

/// Complete durable body-writer admission and canonical channel source closure.
pub const NATIVE_0051_VERSION: i32 = 51;
/// Stable additive migration ledger identity.
pub const NATIVE_0051_NAME: &str = "native_0051_thread_history_writer";
/// Exact writer expansion on the caller's original transaction.
pub const NATIVE_0051_SQL: &str = include_str!("../../sql/native_0051.sql");

/// Same-transaction bounded history tombstones and immutable clearing completion version.
pub const NATIVE_0052_VERSION: i32 = 52;
/// 0052 stable migration name.
pub const NATIVE_0052_NAME: &str = "native_0052_thread_history_clear";
/// 0052 SQL source.
pub const NATIVE_0052_SQL: &str = include_str!("../../sql/native_0052.sql");

/// Append-only restore retirement and current-binding reconfirmation facts.
pub const NATIVE_0053_VERSION: i32 = 53;
/// 0053 stable migration name; schema facts alone grant no restore authority.
pub const NATIVE_0053_NAME: &str = "native_0053_restore_pg_reconfirmation";
/// Exact additive 0053 SQL source.
pub const NATIVE_0053_SQL: &str = include_str!("../../sql/native_0053.sql");

/// 当前二进制钉住的 native migration 数量。
pub const NATIVE_MIGRATION_COUNT: usize = MIGRATIONS.len();

/// 全部署共用的 migration advisory lock key（ASCII `OPENBOT1`）。
const MIGRATION_LOCK_KEY: i64 = 0x4f50_454e_424f_5431;

const LEDGER_ROW_LABEL: &str = "(openbot_internal.schema_migrations)";

struct MigrationSpec {
    version: i32,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[MigrationSpec] = &[
    MigrationSpec {
        version: NATIVE_0013_VERSION,
        name: NATIVE_0013_NAME,
        sql: NATIVE_0013_SQL,
    },
    MigrationSpec {
        version: NATIVE_0014_VERSION,
        name: NATIVE_0014_NAME,
        sql: NATIVE_0014_SQL,
    },
    MigrationSpec {
        version: NATIVE_0015_VERSION,
        name: NATIVE_0015_NAME,
        sql: NATIVE_0015_SQL,
    },
    MigrationSpec {
        version: NATIVE_0016_VERSION,
        name: NATIVE_0016_NAME,
        sql: NATIVE_0016_SQL,
    },
    MigrationSpec {
        version: NATIVE_0017_VERSION,
        name: NATIVE_0017_NAME,
        sql: NATIVE_0017_SQL,
    },
    MigrationSpec {
        version: NATIVE_0018_VERSION,
        name: NATIVE_0018_NAME,
        sql: NATIVE_0018_SQL,
    },
    MigrationSpec {
        version: NATIVE_0019_VERSION,
        name: NATIVE_0019_NAME,
        sql: NATIVE_0019_SQL,
    },
    MigrationSpec {
        version: NATIVE_0020_VERSION,
        name: NATIVE_0020_NAME,
        sql: NATIVE_0020_SQL,
    },
    MigrationSpec {
        version: NATIVE_0021_VERSION,
        name: NATIVE_0021_NAME,
        sql: NATIVE_0021_SQL,
    },
    MigrationSpec {
        version: NATIVE_0022_VERSION,
        name: NATIVE_0022_NAME,
        sql: NATIVE_0022_SQL,
    },
    MigrationSpec {
        version: NATIVE_0023_VERSION,
        name: NATIVE_0023_NAME,
        sql: NATIVE_0023_SQL,
    },
    MigrationSpec {
        version: NATIVE_0024_VERSION,
        name: NATIVE_0024_NAME,
        sql: NATIVE_0024_SQL,
    },
    MigrationSpec {
        version: NATIVE_0025_VERSION,
        name: NATIVE_0025_NAME,
        sql: NATIVE_0025_SQL,
    },
    MigrationSpec {
        version: NATIVE_0026_VERSION,
        name: NATIVE_0026_NAME,
        sql: NATIVE_0026_SQL,
    },
    MigrationSpec {
        version: NATIVE_0027_VERSION,
        name: NATIVE_0027_NAME,
        sql: NATIVE_0027_SQL,
    },
    MigrationSpec {
        version: NATIVE_0028_VERSION,
        name: NATIVE_0028_NAME,
        sql: NATIVE_0028_SQL,
    },
    MigrationSpec {
        version: NATIVE_0029_VERSION,
        name: NATIVE_0029_NAME,
        sql: NATIVE_0029_SQL,
    },
    MigrationSpec {
        version: NATIVE_0030_VERSION,
        name: NATIVE_0030_NAME,
        sql: NATIVE_0030_SQL,
    },
    MigrationSpec {
        version: NATIVE_0031_VERSION,
        name: NATIVE_0031_NAME,
        sql: NATIVE_0031_SQL,
    },
    MigrationSpec {
        version: NATIVE_0032_VERSION,
        name: NATIVE_0032_NAME,
        sql: NATIVE_0032_SQL,
    },
    MigrationSpec {
        version: NATIVE_0033_VERSION,
        name: NATIVE_0033_NAME,
        sql: NATIVE_0033_SQL,
    },
    MigrationSpec {
        version: NATIVE_0034_VERSION,
        name: NATIVE_0034_NAME,
        sql: NATIVE_0034_SQL,
    },
    MigrationSpec {
        version: NATIVE_0035_VERSION,
        name: NATIVE_0035_NAME,
        sql: NATIVE_0035_SQL,
    },
    MigrationSpec {
        version: NATIVE_0036_VERSION,
        name: NATIVE_0036_NAME,
        sql: NATIVE_0036_SQL,
    },
    MigrationSpec {
        version: NATIVE_0037_VERSION,
        name: NATIVE_0037_NAME,
        sql: NATIVE_0037_SQL,
    },
    MigrationSpec {
        version: NATIVE_0038_VERSION,
        name: NATIVE_0038_NAME,
        sql: NATIVE_0038_SQL,
    },
    MigrationSpec {
        version: NATIVE_0039_VERSION,
        name: NATIVE_0039_NAME,
        sql: NATIVE_0039_SQL,
    },
    MigrationSpec {
        version: NATIVE_0040_VERSION,
        name: NATIVE_0040_NAME,
        sql: NATIVE_0040_SQL,
    },
    MigrationSpec {
        version: NATIVE_0041_VERSION,
        name: NATIVE_0041_NAME,
        sql: NATIVE_0041_SQL,
    },
    MigrationSpec {
        version: NATIVE_0042_VERSION,
        name: NATIVE_0042_NAME,
        sql: NATIVE_0042_SQL,
    },
    MigrationSpec {
        version: NATIVE_0043_VERSION,
        name: NATIVE_0043_NAME,
        sql: NATIVE_0043_SQL,
    },
    MigrationSpec {
        version: NATIVE_0044_VERSION,
        name: NATIVE_0044_NAME,
        sql: NATIVE_0044_SQL,
    },
    MigrationSpec {
        version: NATIVE_0045_VERSION,
        name: NATIVE_0045_NAME,
        sql: NATIVE_0045_SQL,
    },
    MigrationSpec {
        version: NATIVE_0046_VERSION,
        name: NATIVE_0046_NAME,
        sql: NATIVE_0046_SQL,
    },
    MigrationSpec {
        version: NATIVE_0047_VERSION,
        name: NATIVE_0047_NAME,
        sql: NATIVE_0047_SQL,
    },
    MigrationSpec {
        version: NATIVE_0048_VERSION,
        name: NATIVE_0048_NAME,
        sql: NATIVE_0048_SQL,
    },
    MigrationSpec {
        version: NATIVE_0049_VERSION,
        name: NATIVE_0049_NAME,
        sql: NATIVE_0049_SQL,
    },
    MigrationSpec {
        version: NATIVE_0050_VERSION,
        name: NATIVE_0050_NAME,
        sql: NATIVE_0050_SQL,
    },
    MigrationSpec {
        version: NATIVE_0051_VERSION,
        name: NATIVE_0051_NAME,
        sql: NATIVE_0051_SQL,
    },
    MigrationSpec {
        version: NATIVE_0052_VERSION,
        name: NATIVE_0052_NAME,
        sql: NATIVE_0052_SQL,
    },
    MigrationSpec {
        version: NATIVE_0053_VERSION,
        name: NATIVE_0053_NAME,
        sql: NATIVE_0053_SQL,
    },
];

const LEDGER_BOOTSTRAP_SQL: &str = r#"
CREATE SCHEMA IF NOT EXISTS openbot_internal;
CREATE TABLE IF NOT EXISTS openbot_internal.schema_migrations (
    version integer PRIMARY KEY,
    name text NOT NULL,
    checksum text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT schema_migrations_checksum_lower_hex
        CHECK (checksum ~ '^[0-9a-f]{64}$')
);
"#;

/// 一次施加的可观察结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 本次事务施加并记账。
    Applied,
    /// 同字节的 migration 已经记账，本次零 DDL。
    AlreadyApplied,
}

/// 自有 migration 账本的构造性违例。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeMigrationViolation {
    /// 同版本已经存在，但名字或 SQL 摘要不同。
    #[error(
        "native migration {version} 账本漂移：期望 name={expected_name} checksum={expected_checksum}，实际 name={actual_name} checksum={actual_checksum}"
    )]
    LedgerDrift {
        /// 版本号。
        version: i32,
        /// 当前二进制钉死的名字。
        expected_name: &'static str,
        /// 当前二进制钉死的 SQL 摘要。
        expected_checksum: String,
        /// 数据库账本里的名字。
        actual_name: String,
        /// 数据库账本里的摘要。
        actual_checksum: String,
    },
    /// 账本已经有更晚版本，却缺当前版本；不能倒序补写。
    #[error(
        "native migration 账本有版本 {future_version}，却缺前置版本 {missing_version}；拒绝倒序施加"
    )]
    MissingBeforeFuture {
        /// 缺失的当前版本。
        missing_version: i32,
        /// 已经存在的更晚版本。
        future_version: i32,
    },
}

/// 0013 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0013_checksum() -> String {
    Sha256Digest::of(NATIVE_0013_SQL.as_bytes()).to_hex()
}

/// 当前 0014 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0014_checksum() -> String {
    Sha256Digest::of(NATIVE_0014_SQL.as_bytes()).to_hex()
}

/// 当前 0015 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0015_checksum() -> String {
    Sha256Digest::of(NATIVE_0015_SQL.as_bytes()).to_hex()
}

/// 当前 0016 SQL 的小写 SHA-256。
#[must_use]
pub fn native_0016_checksum() -> String {
    Sha256Digest::of(NATIVE_0016_SQL.as_bytes()).to_hex()
}

/// Current 0017 SQL lowercase SHA-256.
#[must_use]
pub fn native_0017_checksum() -> String {
    Sha256Digest::of(NATIVE_0017_SQL.as_bytes()).to_hex()
}

/// Current 0018 SQL lowercase SHA-256.
#[must_use]
pub fn native_0018_checksum() -> String {
    Sha256Digest::of(NATIVE_0018_SQL.as_bytes()).to_hex()
}

/// Current 0019 SQL lowercase SHA-256.
#[must_use]
pub fn native_0019_checksum() -> String {
    Sha256Digest::of(NATIVE_0019_SQL.as_bytes()).to_hex()
}

/// Current 0020 SQL lowercase SHA-256.
#[must_use]
pub fn native_0020_checksum() -> String {
    Sha256Digest::of(NATIVE_0020_SQL.as_bytes()).to_hex()
}

/// Current 0021 SQL lowercase SHA-256.
#[must_use]
pub fn native_0021_checksum() -> String {
    Sha256Digest::of(NATIVE_0021_SQL.as_bytes()).to_hex()
}

/// Current 0022 SQL lowercase SHA-256.
#[must_use]
pub fn native_0022_checksum() -> String {
    Sha256Digest::of(NATIVE_0022_SQL.as_bytes()).to_hex()
}

/// Current 0023 SQL lowercase SHA-256.
#[must_use]
pub fn native_0023_checksum() -> String {
    Sha256Digest::of(NATIVE_0023_SQL.as_bytes()).to_hex()
}

/// Current 0024 SQL lowercase SHA-256.
#[must_use]
pub fn native_0024_checksum() -> String {
    Sha256Digest::of(NATIVE_0024_SQL.as_bytes()).to_hex()
}

/// Current 0025 SQL lowercase SHA-256.
#[must_use]
pub fn native_0025_checksum() -> String {
    Sha256Digest::of(NATIVE_0025_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0026 SQL bytes.
#[must_use]
pub fn native_0026_checksum() -> String {
    Sha256Digest::of(NATIVE_0026_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0027 SQL bytes.
#[must_use]
pub fn native_0027_checksum() -> String {
    Sha256Digest::of(NATIVE_0027_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0028 SQL bytes.
#[must_use]
pub fn native_0028_checksum() -> String {
    Sha256Digest::of(NATIVE_0028_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0029 SQL bytes.
#[must_use]
pub fn native_0029_checksum() -> String {
    Sha256Digest::of(NATIVE_0029_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0030 SQL bytes.
#[must_use]
pub fn native_0030_checksum() -> String {
    Sha256Digest::of(NATIVE_0030_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0031 SQL bytes.
#[must_use]
pub fn native_0031_checksum() -> String {
    Sha256Digest::of(NATIVE_0031_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0032 SQL bytes.
#[must_use]
pub fn native_0032_checksum() -> String {
    Sha256Digest::of(NATIVE_0032_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0034 SQL bytes.
#[must_use]
pub fn native_0034_checksum() -> String {
    Sha256Digest::of(NATIVE_0034_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0035 SQL bytes.
#[must_use]
pub fn native_0035_checksum() -> String {
    Sha256Digest::of(NATIVE_0035_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0036 SQL bytes.
#[must_use]
pub fn native_0036_checksum() -> String {
    Sha256Digest::of(NATIVE_0036_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact provenance migration SQL bytes.
#[must_use]
pub fn native_0037_checksum() -> String {
    Sha256Digest::of(NATIVE_0037_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact native 0033 SQL bytes.
#[must_use]
pub fn native_0033_checksum() -> String {
    Sha256Digest::of(NATIVE_0033_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the registered skill-editing expansion.
#[must_use]
pub fn native_0039_checksum() -> String {
    Sha256Digest::of(NATIVE_0039_SQL.as_bytes()).to_hex()
}

/// Digest of the preference editing migration.
pub fn native_0040_checksum() -> String {
    Sha256Digest::of(NATIVE_0040_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact immutable artifact namespace expansion.
#[must_use]
pub fn native_0041_checksum() -> String {
    Sha256Digest::of(NATIVE_0041_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the exact real artifact registration expansion.
#[must_use]
pub fn native_0042_checksum() -> String {
    Sha256Digest::of(NATIVE_0042_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact additive approval preference migration bytes.
#[must_use]
pub fn native_0043_checksum() -> String {
    Sha256Digest::of(NATIVE_0043_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact existing-record cleanup fence expansion.
#[must_use]
pub fn native_0044_checksum() -> String {
    Sha256Digest::of(NATIVE_0044_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact additive saved-receipt completion guard.
#[must_use]
pub fn native_0045_checksum() -> String {
    Sha256Digest::of(NATIVE_0045_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact additive custom-model catalog migration bytes.
#[must_use]
pub fn native_0046_checksum() -> String {
    Sha256Digest::of(NATIVE_0046_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact additive private V2 snapshot migration bytes.
#[must_use]
pub fn native_0047_checksum() -> String {
    Sha256Digest::of(NATIVE_0047_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact additive authorization-attempt journal bytes.
#[must_use]
pub fn native_0048_checksum() -> String {
    Sha256Digest::of(NATIVE_0048_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact immutable historical Thread origin migration bytes.
#[must_use]
pub fn native_0049_checksum() -> String {
    Sha256Digest::of(NATIVE_0049_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact one-J state and Thread identity-retention migration bytes.
#[must_use]
pub fn native_0050_checksum() -> String {
    Sha256Digest::of(NATIVE_0050_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact complete body-writer admission migration bytes.
#[must_use]
pub fn native_0051_checksum() -> String {
    Sha256Digest::of(NATIVE_0051_SQL.as_bytes()).to_hex()
}

/// Checksum of the exact registered 0052 SQL bytes.
#[must_use]
pub fn native_0052_checksum() -> String {
    Sha256Digest::of(NATIVE_0052_SQL.as_bytes()).to_hex()
}

/// Checksum of the actual registered 0053 SQL bytes.
#[must_use]
pub fn native_0053_checksum() -> String {
    Sha256Digest::of(NATIVE_0053_SQL.as_bytes()).to_hex()
}

/// SHA-256 of the registered sandbox editing migration.
#[must_use]
pub fn native_0038_checksum() -> String {
    Sha256Digest::of(NATIVE_0038_SQL.as_bytes()).to_hex()
}

mod bootstrap_client_private {
    pub trait Sealed {}

    impl Sealed for tokio_postgres::Client {}
    impl Sealed for crate::db::pool::PooledClient {}
}

/// The two owned client types that can construct an atomic database bootstrap transaction.
///
/// This sealed bridge preserves existing raw PostgreSQL callers and accepts the supervised pool
/// facade without exposing a mutable client or stock pool object. The opaque builder retains the
/// original client borrow; it does not grant current application or host authorization.
pub trait BootstrapTransactionClient: bootstrap_client_private::Sealed {
    /// Start configuring a transaction on this exact client without lending the mutable client.
    fn bootstrap_transaction_builder(&mut self) -> tokio_postgres::TransactionBuilder<'_>;
}

impl BootstrapTransactionClient for tokio_postgres::Client {
    fn bootstrap_transaction_builder(&mut self) -> tokio_postgres::TransactionBuilder<'_> {
        self.build_transaction()
    }
}

impl BootstrapTransactionClient for crate::db::pool::PooledClient {
    fn bootstrap_transaction_builder(&mut self) -> tokio_postgres::TransactionBuilder<'_> {
        self.build_postgres_transaction()
    }
}

/// 在一个已到 0012 的数据库上施加当前二进制认识的全部 Rust-owned migrations。
///
/// # Errors
///
/// - 连接/DDL/账本查询失败返回脱敏的 [`InfraError::Query`]；
/// - 同版本账本漂移或出现版本空洞返回 [`InfraError::NativeMigration`]；
/// - commit 失败同样返回查询错误，事务由 PostgreSQL 回滚。
pub async fn apply(
    client: &mut impl BootstrapTransactionClient,
) -> Result<ApplyOutcome, InfraError> {
    apply_through(client, NATIVE_LATEST_VERSION).await
}

/// 只施加到给定版本（含）；历史 fixture 测试用它固定 0013 边界。
///
/// 生产启动应调用 [`apply`]。本入口仍走同一账本/锁/摘要校验，不是绕过 migration 的测试后门。
pub async fn apply_through(
    client: &mut impl BootstrapTransactionClient,
    max_version: i32,
) -> Result<ApplyOutcome, InfraError> {
    let transaction = client
        .bootstrap_transaction_builder()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|source| InfraError::query("开始 native schema migration 事务", source))?;

    let outcome = apply_through_in_transaction(&transaction, max_version).await?;
    transaction
        .commit()
        .await
        .map_err(|source| InfraError::query("提交 native schema migrations", source))?;
    Ok(outcome)
}

/// 自有账本表是否存在；存在只代表“应走 native 校验”，不代表内容已经可信。
///
/// 调用方随后必须调用 [`apply`]，由名字/版本/checksum/空洞四项验证内容。
pub async fn ledger_exists(client: &Client) -> Result<bool, InfraError> {
    client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&NATIVE_LEDGER_TABLE],
        )
        .await
        .map_err(|source| InfraError::query("探测 native schema migration 账本", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column("(to_regclass)", "exists", source).into())
}

/// Read-only proof that the database contains one exact, contiguous prefix of the migrations known
/// to this binary. Missing known tail migrations are allowed; unknown rows and holes are not.
/// This proof describes storage facts only and does not authorize applying a migration.
pub struct ValidatedNativeLedger {
    latest_version: i32,
}

impl ValidatedNativeLedger {
    /// Highest exact migration version present in the validated ledger prefix.
    #[must_use]
    pub const fn latest_version(&self) -> i32 {
        self.latest_version
    }
}

impl core::fmt::Debug for ValidatedNativeLedger {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ValidatedNativeLedger")
            .field("latest_version", &self.latest_version)
            .finish()
    }
}

/// Validate an exact known ledger prefix at or beyond `required_through`, without DDL or locks.
/// The bounded extra row makes an appended unknown version observable instead of truncating it.
pub async fn validate_known_prefix(
    client: &Client,
    required_through: i32,
) -> Result<ValidatedNativeLedger, InfraError> {
    if !MIGRATIONS
        .iter()
        .any(|migration| migration.version == required_through)
    {
        return Err(InfraError::repository_invariant(
            "native_migration_floor_unknown",
        ));
    }
    if !ledger_exists(client).await? {
        return Err(InfraError::repository_invariant(
            "native_migration_ledger_missing",
        ));
    }

    let limit = MIGRATIONS
        .len()
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| {
            InfraError::repository_invariant("native_migration_validation_limit_invalid")
        })?;
    let rows = client
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 native migration 前缀", source))?;
    if rows.is_empty() {
        return Err(InfraError::repository_invariant(
            "native_migration_ledger_incomplete",
        ));
    }

    let mut latest_version = None;
    for (index, row) in rows.iter().enumerate() {
        let actual_version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let actual_name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let actual_checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let Some(expected) = MIGRATIONS.get(index) else {
            return Err(InfraError::repository_invariant(
                "native_migration_ledger_unknown_row",
            ));
        };
        let expected_contiguous_version = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| {
                InfraError::repository_invariant("native_migration_registry_invalid")
            })?)
            .ok_or_else(|| InfraError::repository_invariant("native_migration_registry_invalid"))?;
        if expected.version != expected_contiguous_version {
            return Err(InfraError::repository_invariant(
                "native_migration_registry_invalid",
            ));
        }
        if actual_version > expected.version {
            return Err(NativeMigrationViolation::MissingBeforeFuture {
                missing_version: expected.version,
                future_version: actual_version,
            }
            .into());
        }
        if actual_version != expected.version {
            return Err(InfraError::repository_invariant(
                "native_migration_ledger_unknown_row",
            ));
        }
        let expected_checksum = Sha256Digest::of(expected.sql.as_bytes()).to_hex();
        if actual_name != expected.name || actual_checksum != expected_checksum {
            return Err(NativeMigrationViolation::LedgerDrift {
                version: expected.version,
                expected_name: expected.name,
                expected_checksum,
                actual_name,
                actual_checksum,
            }
            .into());
        }
        latest_version = Some(actual_version);
    }

    let latest_version = latest_version
        .ok_or_else(|| InfraError::repository_invariant("native_migration_ledger_incomplete"))?;
    if latest_version < required_through || latest_version > NATIVE_LATEST_VERSION {
        return Err(InfraError::repository_invariant(
            "native_migration_ledger_incomplete",
        ));
    }
    Ok(ValidatedNativeLedger { latest_version })
}

/// Read-only verification that every currently known native migration is present with exact
/// name/checksum and that no future version is recorded.
pub async fn validate_current(client: &Client) -> Result<(), InfraError> {
    if !ledger_exists(client).await? {
        return Err(InfraError::repository_invariant(
            "native_migration_ledger_missing",
        ));
    }
    for migration in MIGRATIONS {
        let row = client
            .query_opt(
                "SELECT name,checksum FROM openbot_internal.schema_migrations WHERE version=$1",
                &[&migration.version],
            )
            .await
            .map_err(|source| InfraError::query("只读核验 native migration", source))?
            .ok_or_else(|| {
                InfraError::repository_invariant("native_migration_ledger_incomplete")
            })?;
        let name: String = row
            .try_get(0)
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get(1)
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        if name != migration.name || checksum != Sha256Digest::of(migration.sql.as_bytes()).to_hex()
        {
            return Err(NativeMigrationViolation::LedgerDrift {
                version: migration.version,
                expected_name: migration.name,
                expected_checksum: Sha256Digest::of(migration.sql.as_bytes()).to_hex(),
                actual_name: name,
                actual_checksum: checksum,
            }
            .into());
        }
    }
    let ledger_count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM openbot_internal.schema_migrations",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 native migration 数量", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "count", source))?;
    if ledger_count != NATIVE_MIGRATION_COUNT as i64 {
        return Err(InfraError::repository_invariant(
            "native_migration_ledger_unknown_row",
        ));
    }
    let future: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.schema_migrations WHERE version>$1)",
            &[&NATIVE_LATEST_VERSION],
        )
        .await
        .map_err(|source| InfraError::query("只读核验 future native migration", source))?
        .try_get(0)
        .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "future", source))?;
    if future {
        return Err(InfraError::repository_invariant(
            "future_native_migration_present",
        ));
    }
    Ok(())
}

pub(crate) async fn apply_through_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    max_version: i32,
) -> Result<ApplyOutcome, InfraError> {
    if max_version > NATIVE_LATEST_VERSION {
        return Err(InfraError::repository_invariant(
            "native_migration_target_unknown",
        ));
    }
    lock_migrations(transaction).await?;

    transaction
        .batch_execute(LEDGER_BOOTSTRAP_SQL)
        .await
        .map_err(|source| InfraError::query("初始化 native schema migration 账本", source))?;

    let mut applied = 0usize;
    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= max_version)
    {
        let checksum = Sha256Digest::of(migration.sql.as_bytes()).to_hex();
        let existing = transaction
            .query_opt(
                "SELECT name, checksum FROM openbot_internal.schema_migrations WHERE version = $1",
                &[&migration.version],
            )
            .await
            .map_err(|source| InfraError::query("读取 native schema migration 账本", source))?;

        if let Some(row) = existing {
            let actual_name: String = row
                .try_get("name")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
            let actual_checksum: String = row
                .try_get("checksum")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
            if actual_name != migration.name || actual_checksum != checksum {
                return Err(NativeMigrationViolation::LedgerDrift {
                    version: migration.version,
                    expected_name: migration.name,
                    expected_checksum: checksum,
                    actual_name,
                    actual_checksum,
                }
                .into());
            }
            continue;
        }

        let future = transaction
            .query_opt(
                "SELECT version FROM openbot_internal.schema_migrations \
                 WHERE version > $1 ORDER BY version LIMIT 1",
                &[&migration.version],
            )
            .await
            .map_err(|source| InfraError::query("检查 native schema migration 版本空洞", source))?;
        if let Some(row) = future {
            let future_version: i32 = row
                .try_get("version")
                .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
            return Err(NativeMigrationViolation::MissingBeforeFuture {
                missing_version: migration.version,
                future_version,
            }
            .into());
        }

        transaction
            .batch_execute(migration.sql)
            .await
            .map_err(|source| InfraError::query(format!("应用 {}", migration.name), source))?;
        transaction
            .execute(
                "INSERT INTO openbot_internal.schema_migrations (version, name, checksum) \
                 VALUES ($1, $2, $3)",
                &[&migration.version, &migration.name, &checksum],
            )
            .await
            .map_err(|source| InfraError::query(format!("记录 {} 账本", migration.name), source))?;
        applied += 1;
    }

    if max_version >= NATIVE_0036_VERSION {
        // Even an exact ledger replay must reject a missing or misbound projection. Never repair.
        super::occupancy::validate_all(transaction).await?;
    }
    if max_version >= NATIVE_0046_VERSION {
        validate_custom_model_catalog_in_transaction(transaction).await?;
    }
    if max_version == NATIVE_0047_VERSION {
        // Only this explicit migration target may observe the real pre-upgrade prefix.
        validate_custom_model_v2_legacy_0047_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0048_VERSION {
        validate_custom_model_v2_legacy_0048_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0049_VERSION {
        validate_custom_model_v2_legacy_0049_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0050_VERSION {
        validate_custom_model_v2_legacy_0050_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0051_VERSION {
        validate_custom_model_v2_legacy_0051_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0052_VERSION {
        validate_custom_model_v2_legacy_0052_in_transaction(transaction).await?;
    } else if max_version == NATIVE_0053_VERSION {
        validate_custom_model_v2_in_transaction(transaction).await?;
    }
    Ok(if applied == 0 {
        ApplyOutcome::AlreadyApplied
    } else {
        ApplyOutcome::Applied
    })
}

/// Prove the complete known ledger prefix and catalog facts on the original migration transaction.
/// An exact replay has the same proof; no separate connection, repair or commit occurs here.
pub(crate) async fn validate_custom_model_catalog_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_catalog_schema_invalid");
    let limit = NATIVE_MIGRATION_COUNT
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = transaction
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|_| invalid())?;
    if rows.is_empty() {
        return Err(invalid());
    }

    let mut latest_version = None;
    for (index, row) in rows.iter().enumerate() {
        let actual_version: i32 = row.try_get("version").map_err(|_| invalid())?;
        let actual_name: String = row.try_get("name").map_err(|_| invalid())?;
        let actual_checksum: String = row.try_get("checksum").map_err(|_| invalid())?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let expected_contiguous_version = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        let expected_checksum = Sha256Digest::of(expected.sql.as_bytes()).to_hex();
        if expected.version != expected_contiguous_version
            || actual_version != expected.version
            || actual_name != expected.name
            || actual_checksum != expected_checksum
        {
            return Err(invalid());
        }
        latest_version = Some(actual_version);
    }
    let latest_version = latest_version.ok_or_else(invalid)?;
    if !(NATIVE_0046_VERSION..=NATIVE_LATEST_VERSION).contains(&latest_version) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(transaction)
        .await
        .map_err(|_| invalid())
}

/// Explicit pre-upgrade 0013--0052 prefix and all original model/history schemas.
/// Only the exact migration target52 calls this observer; it grants no current admission.
async fn validate_custom_model_v2_legacy_0052_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT 41",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务 legacy0052 native 前缀", source))?;
    if NATIVE_MIGRATION_COUNT != 41 || rows.len() != 40 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(39).map(|migration| migration.version) != Some(NATIVE_0052_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_in_transaction(tx).await
}

/// Exact current53 prefix, original complete graphs and additive restore catalog.
/// No client checkout, migration, repair, commit or rollback occurs in this observer.
pub(crate) async fn validate_custom_model_v2_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let limit = NATIVE_MIGRATION_COUNT
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 native 前缀", source))?;
    if NATIVE_MIGRATION_COUNT != 41 || rows.len() != NATIVE_MIGRATION_COUNT {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.last().map(|migration| migration.version) != Some(NATIVE_0053_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_in_transaction(tx).await?;
    super::restore_reconfirmation_schema::verify_in_transaction(tx).await
}
/// Exact current 0013--0053 ledger, journal, origin, writer and additive restore schemas.
/// This observer never checks out a client or migrates, repairs or closes a transaction.
#[cfg(feature = "server-runtime")]
pub(crate) async fn validate_gateway_authorization_journal_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid =
        || InfraError::repository_invariant("gateway_authorization_journal_native_prefix_invalid");
    let limit = NATIVE_MIGRATION_COUNT
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务授权 journal native 前缀", source))?;
    if NATIVE_MIGRATION_COUNT != 41 || rows.len() != NATIVE_MIGRATION_COUNT {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.last().map(|migration| migration.version) != Some(NATIVE_0053_VERSION) {
        return Err(invalid());
    }
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_in_transaction(tx).await?;
    super::restore_reconfirmation_schema::verify_in_transaction(tx).await
}

/// Explicit pre-upgrade 0013--0051 branch. It grants no current0052 clearing admission.
async fn validate_custom_model_v2_legacy_0051_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT 40",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 历史0051前缀", source))?;
    if rows.len() != 39 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(38).map(|migration| migration.version) != Some(NATIVE_0051_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_legacy0051_in_transaction(tx).await
}

/// Explicit pre-upgrade 0013--0050 branch. It grants no current body-writer admission.
async fn validate_custom_model_v2_legacy_0050_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let limit = 38usize
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 native 前缀", source))?;
    if rows.len() != 38 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(37).map(|migration| migration.version) != Some(NATIVE_0050_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_admission_schema::verify_legacy0050_in_transaction(tx).await
}

/// Only the explicit original migration target47 may use this exact historical prefix.
/// Ordinary runtime V2 consumers always use the complete current52 entry above.
async fn validate_custom_model_v2_legacy_0047_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let limit = 35usize
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 native 前缀", source))?;
    if rows.len() != 35 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(34).map(|migration| migration.version) != Some(NATIVE_0047_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await
}

/// Exact current native prefix and complete historical origin schema on the original transaction.
/// No checkout, migration, authority grant or transaction close occurs here.
#[cfg(any(feature = "server-runtime", feature = "desktop-local-vault"))]
pub(crate) async fn validate_thread_origin_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("thread_origin_native_prefix_invalid");
    let limit = NATIVE_MIGRATION_COUNT
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务历史来源 native 前缀", source))?;
    if NATIVE_MIGRATION_COUNT != 41 || rows.len() != NATIVE_MIGRATION_COUNT {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.last().map(|migration| migration.version) != Some(NATIVE_0053_VERSION) {
        return Err(invalid());
    }
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_in_transaction(tx).await?;
    super::restore_reconfirmation_schema::verify_in_transaction(tx).await
}

/// Only the explicit original migration target49 may observe this exact historical prefix.
/// Ordinary current consumers require51 and the complete independent writer schema.
async fn validate_custom_model_v2_legacy_0049_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let limit = 37usize
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 native 前缀", source))?;
    if rows.len() != 37 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(36).map(|migration| migration.version) != Some(NATIVE_0049_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await?;
    super::thread_origin_schema::verify_in_transaction(tx).await
}
/// Only the explicit original migration target48 may observe this exact historical prefix.
async fn validate_custom_model_v2_legacy_0048_in_transaction(
    tx: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    let invalid = || InfraError::repository_invariant("custom_model_v2_native_prefix_invalid");
    let limit = 36usize
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(invalid)?;
    let rows = tx
        .query(
            "SELECT version,name,checksum FROM openbot_internal.schema_migrations ORDER BY version,name,checksum LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|source| InfraError::query("核验原事务模型 V2 native 前缀", source))?;
    if rows.len() != 36 {
        return Err(invalid());
    }
    for (index, row) in rows.iter().enumerate() {
        let version: i32 = row
            .try_get("version")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "version", source))?;
        let name: String = row
            .try_get("name")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "name", source))?;
        let checksum: String = row
            .try_get("checksum")
            .map_err(|source| RowDecodeError::column(LEDGER_ROW_LABEL, "checksum", source))?;
        let expected = MIGRATIONS.get(index).ok_or_else(invalid)?;
        let contiguous = NATIVE_0013_VERSION
            .checked_add(i32::try_from(index).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        if version != contiguous
            || expected.version != contiguous
            || name != expected.name
            || checksum != Sha256Digest::of(expected.sql.as_bytes()).to_hex()
        {
            return Err(invalid());
        }
    }
    if MIGRATIONS.get(35).map(|migration| migration.version) != Some(NATIVE_0048_VERSION) {
        return Err(invalid());
    }
    super::custom_model_catalog_schema::verify_in_transaction(tx)
        .await
        .map_err(|error| match error {
            super::custom_model_catalog_schema::CustomModelCatalogSchemaError::Unavailable => {
                InfraError::repository_invariant("custom_model_v2_schema_observation_unavailable")
            }
            _ => InfraError::repository_invariant("custom_model_v2_catalog_schema_invalid"),
        })?;
    super::custom_model_v2_schema::verify_in_transaction(tx).await?;
    super::gateway_authorization_schema::verify_in_transaction(tx).await
}

pub(crate) async fn lock_migrations(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<(), InfraError> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map(|_| ())
        .map_err(|source| InfraError::query("获取 native schema migration 锁", source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_lines(sql: &'static str) -> impl Iterator<Item = &'static str> {
        sql.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("--"))
    }

    #[test]
    fn schema_migration_sql_is_mechanically_expand_only() {
        let forbidden_prefixes = ["DROP ", "TRUNCATE ", "DELETE ", "UPDATE "];
        let catalog_sql_parts = NATIVE_0046_SQL
            .split("$custom_model_catalog_sync$")
            .collect::<Vec<_>>();
        assert_eq!(catalog_sql_parts.len(), 3);
        assert_eq!(catalog_sql_parts[1].len(), 2738);
        assert_eq!(
            Sha256Digest::of(catalog_sql_parts[1].as_bytes()).to_hex(),
            "dd3033fd6fb82953088844a2649c83ab60bbb163318f02dbaac42fc2b25a921b",
        );
        for line in statement_lines(NATIVE_0013_SQL)
            .chain(statement_lines(NATIVE_0014_SQL))
            .chain(statement_lines(NATIVE_0015_SQL))
            .chain(statement_lines(NATIVE_0016_SQL))
            .chain(statement_lines(NATIVE_0017_SQL))
            .chain(statement_lines(NATIVE_0018_SQL))
            .chain(statement_lines(NATIVE_0019_SQL))
            .chain(statement_lines(NATIVE_0020_SQL))
            .chain(statement_lines(NATIVE_0021_SQL))
            .chain(statement_lines(NATIVE_0022_SQL))
            .chain(statement_lines(NATIVE_0023_SQL))
            .chain(statement_lines(NATIVE_0024_SQL))
            .chain(statement_lines(NATIVE_0025_SQL))
            .chain(statement_lines(NATIVE_0026_SQL))
            .chain(statement_lines(NATIVE_0030_SQL))
            .chain(statement_lines(NATIVE_0031_SQL))
            .chain(statement_lines(NATIVE_0032_SQL))
            .chain(statement_lines(NATIVE_0033_SQL))
            .chain(statement_lines(NATIVE_0034_SQL))
            .chain(statement_lines(NATIVE_0035_SQL))
            .chain(statement_lines(NATIVE_0037_SQL))
            .chain(statement_lines(NATIVE_0038_SQL))
            .chain(statement_lines(NATIVE_0045_SQL))
            .chain(statement_lines(NATIVE_0047_SQL))
            .chain(statement_lines(NATIVE_0048_SQL))
            .chain(statement_lines(NATIVE_0049_SQL))
            .chain(
                NATIVE_0050_SQL
                    .split("$$")
                    .step_by(2)
                    .flat_map(statement_lines),
            )
            .chain(
                NATIVE_0051_SQL
                    .split("$$")
                    .step_by(2)
                    .flat_map(statement_lines),
            )
            .chain(
                NATIVE_0052_SQL
                    .split("$$")
                    .step_by(2)
                    .flat_map(statement_lines)
                    // Only the registered widening of this original Q CHECK is re-added below.
                    .filter(|line| {
                        *line != "DROP CONSTRAINT thread_history_clear_intents_kind_check;"
                    }),
            )
            // Only the exact registered catalog trigger body is excluded from top-level checks.
            .chain(
                catalog_sql_parts
                    .into_iter()
                    .step_by(2)
                    .flat_map(statement_lines),
            )
            // Stored trigger bodies contain the specifically authorized exact-slot DELETE.
            // The migration's top-level DDL still has the same expand-only check.
            .chain(
                NATIVE_0036_SQL
                    .split("$$")
                    .step_by(2)
                    .flat_map(statement_lines),
            )
        {
            let uppercase = line.to_ascii_uppercase();
            assert!(
                !forbidden_prefixes
                    .iter()
                    .any(|prefix| uppercase.starts_with(prefix)),
                "0013 出现 destructive 语句：{line}",
            );
            for forbidden in [" RENAME ", "ALTER COLUMN", "SET NOT NULL"] {
                assert!(
                    !uppercase.contains(forbidden),
                    "0013 出现兼容期禁令 `{forbidden}`：{line}",
                );
            }
        }

        assert_eq!(NATIVE_0013_SQL.matches("CREATE TABLE public.").count(), 3);
        assert_eq!(
            NATIVE_0013_SQL
                .matches("ALTER TABLE public.audit_events\n    ADD COLUMN")
                .count(),
            2,
        );
        assert!(NATIVE_0013_SQL.contains("ADD COLUMN prev_hash text"));
        assert!(NATIVE_0013_SQL.contains("ADD COLUMN row_hash text"));
        assert!(NATIVE_0014_SQL.contains("ADD COLUMN auth_generation bigint"));
        assert!(!statement_lines(NATIVE_0014_SQL).any(|line| line.contains("SET NOT NULL")));
        assert!(NATIVE_0015_SQL.contains("ADD COLUMN auth_generation bigint"));
        assert!(!statement_lines(NATIVE_0015_SQL).any(|line| line.contains("SET NOT NULL")));
        assert_eq!(NATIVE_0016_SQL.matches("CREATE TABLE public.").count(), 10);
        assert!(NATIVE_0016_SQL.contains("ADD CONSTRAINT tool_calls_run_id_fkey"));
        assert!(NATIVE_0016_SQL.contains("NOT VALID"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN next_tool_call_seq bigint"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN catalog_generation bigint"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN catalog_transport_fingerprint text"));
        assert!(NATIVE_0017_SQL.contains("ADD COLUMN transport_fingerprint text"));
        assert!(NATIVE_0017_SQL.contains("suspended_missing"));
        assert!(NATIVE_0018_SQL.contains("ADD COLUMN credential_generation bigint"));
        assert!(NATIVE_0019_SQL.contains("ADD COLUMN transport text"));
        assert!(NATIVE_0019_SQL.contains("google_drive_rest"));
        assert!(NATIVE_0020_SQL.contains("CREATE TABLE public.tool_approvals"));
        assert!(NATIVE_0020_SQL.contains("tool_approvals_decision_shape"));
        assert!(NATIVE_0021_SQL.contains("CREATE TABLE public.user_ui_preferences"));
        assert!(NATIVE_0021_SQL.contains("user_ui_preferences_nonempty"));
        assert!(NATIVE_0022_SQL.contains("CREATE TABLE public.user_memory_controls"));
        assert!(NATIVE_0022_SQL.contains("user_memory_controls_identity_nonempty"));
        assert!(NATIVE_0023_SQL.contains("CREATE TABLE public.component_human_decisions"));
        assert!(NATIVE_0023_SQL.contains("component_human_decisions_answer_shape"));
        assert!(NATIVE_0024_SQL.contains("ADD COLUMN budget_max_output_tokens bigint"));
        assert!(NATIVE_0024_SQL.contains("runs_usage_last_shape"));
        assert!(NATIVE_0025_SQL.contains("ADD COLUMN cost_currency text"));
        assert!(NATIVE_0025_SQL.contains("runs_cost_accounting_shape"));
        assert!(NATIVE_0026_SQL.contains("CREATE TABLE public.user_run_cost_budgets"));
        assert!(NATIVE_0026_SQL.contains("ADD COLUMN budget_cost_currency text"));
        assert!(NATIVE_0026_SQL.contains("runs_cost_budget_shape"));
        assert!(NATIVE_0028_SQL.contains("CREATE TABLE public.remote_agent_interrupts"));
        assert!(NATIVE_0028_SQL.contains("remote_agent_interrupts_state_shape"));
        assert!(NATIVE_0029_SQL.contains("ADD COLUMN egress_allow_cidrs text[]"));
        assert!(NATIVE_0029_SQL.contains("provenance = 'custom'"));
        assert_eq!(NATIVE_0033_SQL.matches("CREATE TABLE public.").count(), 3);
        assert!(NATIVE_0033_SQL.contains("sdk_gateway_connections_state_shape"));
        assert!(NATIVE_0033_SQL.contains("sdk_gateway_operations_state_shape"));
    }

    #[test]
    fn terminal_reasoning_retention_is_the_only_narrow_data_redaction() {
        let statements = statement_lines(NATIVE_0027_SQL).collect::<Vec<_>>();
        let statement_sql = statements.join("\n");
        assert_eq!(statement_sql.matches(';').count(), 1);
        assert_eq!(
            statements
                .iter()
                .filter(|line| line.to_ascii_uppercase().starts_with("UPDATE "))
                .count(),
            1
        );
        assert!(statements[0].starts_with("UPDATE public.run_events AS reasoning_event"));
        assert!(NATIVE_0027_SQL.contains(
            "SET payload = jsonb_build_object(\n    'channel', 'reasoning',\n    'delta', '',\n    'retained', false\n)"
        ));
        assert!(NATIVE_0027_SQL.contains("reasoning_event.event_type = 'semantic_chunk'"));
        assert!(NATIVE_0027_SQL.contains(
            "run.status IN ('completed', 'failed', 'cancelled', 'reconciliation_required')"
        ));
        assert!(NATIVE_0027_SQL.contains("reasoning_event.payload->>'channel' = 'reasoning'"));
        for forbidden in [
            "DROP ",
            "TRUNCATE ",
            "DELETE ",
            "ALTER ",
            "CREATE ",
            "INSERT ",
            " RENAME ",
            "SET NOT NULL",
        ] {
            assert!(
                !statement_sql.to_ascii_uppercase().contains(forbidden),
                "0027 privacy redaction escaped its DML boundary: {forbidden}"
            );
        }
    }

    #[test]
    fn real_migration_uses_the_ledger_not_object_existence_as_idempotency() {
        // Exclude only these exact registered metadata postconditions, not migration DDL.
        // Their catalog snapshots and assertions contain non-DDL IF NOT EXISTS text.
        let writer_postcondition_parts = NATIVE_0051_SQL
            .split("$thread_history_writer_postcondition$")
            .collect::<Vec<_>>();
        assert_eq!(writer_postcondition_parts.len(), 3);
        assert_eq!(writer_postcondition_parts[1].len(), 450_383);
        assert_eq!(
            Sha256Digest::of(writer_postcondition_parts[1].as_bytes()).to_hex(),
            "b3914b2ea4e2940b46ef4be6573db9483c9551fd0f2f476e7a2a8e636bbe9224",
        );
        let clear_postcondition_parts = NATIVE_0052_SQL
            .split("$clear_postcondition$")
            .collect::<Vec<_>>();
        assert_eq!(clear_postcondition_parts.len(), 3);
        assert_eq!(clear_postcondition_parts[1].len(), 16_753);
        assert_eq!(
            Sha256Digest::of(clear_postcondition_parts[1].as_bytes()).to_hex(),
            "839c0e93ccc218b0d9104d1e41ad7c8883e3e80b9dafbd144132d47083f7c323",
        );
        assert!(
            !statement_lines(NATIVE_0013_SQL)
                .chain(statement_lines(NATIVE_0014_SQL))
                .chain(statement_lines(NATIVE_0015_SQL))
                .chain(statement_lines(NATIVE_0016_SQL))
                .chain(statement_lines(NATIVE_0017_SQL))
                .chain(statement_lines(NATIVE_0018_SQL))
                .chain(statement_lines(NATIVE_0019_SQL))
                .chain(statement_lines(NATIVE_0020_SQL))
                .chain(statement_lines(NATIVE_0021_SQL))
                .chain(statement_lines(NATIVE_0022_SQL))
                .chain(statement_lines(NATIVE_0023_SQL))
                .chain(statement_lines(NATIVE_0024_SQL))
                .chain(statement_lines(NATIVE_0025_SQL))
                .chain(statement_lines(NATIVE_0026_SQL))
                .chain(statement_lines(NATIVE_0027_SQL))
                .chain(statement_lines(NATIVE_0028_SQL))
                .chain(statement_lines(NATIVE_0029_SQL))
                .chain(statement_lines(NATIVE_0030_SQL))
                .chain(statement_lines(NATIVE_0031_SQL))
                .chain(statement_lines(NATIVE_0032_SQL))
                .chain(statement_lines(NATIVE_0033_SQL))
                .chain(statement_lines(NATIVE_0034_SQL))
                .chain(statement_lines(NATIVE_0035_SQL))
                .chain(statement_lines(NATIVE_0037_SQL))
                .chain(statement_lines(NATIVE_0038_SQL))
                .chain(statement_lines(NATIVE_0047_SQL))
                .chain(statement_lines(NATIVE_0048_SQL))
                .chain(statement_lines(NATIVE_0049_SQL))
                .chain(
                    NATIVE_0050_SQL
                        .split("$$")
                        .step_by(2)
                        .flat_map(statement_lines)
                )
                .chain(
                    writer_postcondition_parts
                        .into_iter()
                        .step_by(2)
                        .flat_map(|sql| sql.split("$$").step_by(2))
                        .flat_map(statement_lines)
                )
                .chain(
                    clear_postcondition_parts
                        .into_iter()
                        .step_by(2)
                        .flat_map(|sql| sql.split("$$").step_by(2))
                        .flat_map(statement_lines)
                )
                .chain(
                    NATIVE_0036_SQL
                        .split("$$")
                        .step_by(2)
                        .flat_map(statement_lines)
                )
                .any(|line| line.contains("IF NOT EXISTS"))
        );
        assert!(LEDGER_BOOTSTRAP_SQL.contains("IF NOT EXISTS"));
        assert!(!LEDGER_BOOTSTRAP_SQL.contains("drizzle"));
        assert_eq!(NATIVE_LEDGER_TABLE, "openbot_internal.schema_migrations");
    }

    #[test]
    fn checksum_is_lowercase_sha256_and_changes_with_the_sql() {
        let checksum = native_0013_checksum();
        assert_eq!(checksum.len(), 64);
        assert!(
            checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        );
        assert_ne!(checksum, Sha256Digest::of(b"different migration").to_hex());
        let next = native_0014_checksum();
        assert_eq!(next.len(), 64);
        assert_ne!(checksum, next);
        let latest = native_0015_checksum();
        assert_eq!(latest.len(), 64);
        assert_ne!(next, latest);
        let native_thread = native_0016_checksum();
        assert_eq!(native_thread.len(), 64);
        assert_ne!(latest, native_thread);
        let native_mcp = native_0017_checksum();
        assert_eq!(native_mcp.len(), 64);
        assert_ne!(native_thread, native_mcp);
        let native_credential_generation = native_0018_checksum();
        assert_eq!(native_credential_generation.len(), 64);
        assert_ne!(native_mcp, native_credential_generation);
        let native_transport = native_0019_checksum();
        assert_eq!(native_transport.len(), 64);
        assert_ne!(native_credential_generation, native_transport);
        let native_approval = native_0020_checksum();
        assert_eq!(native_approval.len(), 64);
        assert_ne!(native_transport, native_approval);
        let native_ui_preferences = native_0021_checksum();
        assert_eq!(native_ui_preferences.len(), 64);
        assert_ne!(native_approval, native_ui_preferences);
        let native_memory_controls = native_0022_checksum();
        assert_eq!(native_memory_controls.len(), 64);
        assert_ne!(native_ui_preferences, native_memory_controls);
        let native_component_decisions = native_0023_checksum();
        assert_eq!(native_component_decisions.len(), 64);
        assert_ne!(native_memory_controls, native_component_decisions);
        let native_run_usage = native_0024_checksum();
        assert_eq!(native_run_usage.len(), 64);
        assert_ne!(native_component_decisions, native_run_usage);
        let native_run_cost = native_0025_checksum();
        assert_eq!(native_run_cost.len(), 64);
        assert_ne!(native_run_usage, native_run_cost);
        let native_run_cost_budget = native_0026_checksum();
        assert_eq!(native_run_cost_budget.len(), 64);
        assert_ne!(native_run_cost, native_run_cost_budget);
        let native_reasoning_retention = native_0027_checksum();
        assert_eq!(native_reasoning_retention.len(), 64);
        assert_ne!(native_run_cost_budget, native_reasoning_retention);
        let native_remote_interrupts = native_0028_checksum();
        assert_eq!(native_remote_interrupts.len(), 64);
        assert_ne!(native_reasoning_retention, native_remote_interrupts);
        let native_mcp_private_egress = native_0029_checksum();
        assert_eq!(native_mcp_private_egress.len(), 64);
        assert_ne!(native_remote_interrupts, native_mcp_private_egress);
        let personal_model_connections = native_0030_checksum();
        assert_eq!(personal_model_connections.len(), 64);
        assert_ne!(native_mcp_private_egress, personal_model_connections);
        let run_model_selections = native_0031_checksum();
        assert_eq!(run_model_selections.len(), 64);
        assert_ne!(personal_model_connections, run_model_selections);
        let desktop_vault_canary = native_0032_checksum();
        assert_eq!(desktop_vault_canary.len(), 64);
        assert_ne!(run_model_selections, desktop_vault_canary);
        let sdk_gateway_authority = native_0033_checksum();
        assert_eq!(sdk_gateway_authority.len(), 64);
        assert_ne!(desktop_vault_canary, sdk_gateway_authority);
        assert_eq!(native_0035_checksum().len(), 64);
        assert_ne!(native_0034_checksum(), native_0035_checksum());
        assert_eq!(native_0036_checksum().len(), 64);
        assert_ne!(native_0035_checksum(), native_0036_checksum());
        assert_eq!(native_0037_checksum().len(), 64);
        assert_ne!(native_0036_checksum(), native_0037_checksum());
        assert_eq!(MIGRATIONS.len(), 41);
        assert_eq!(native_0038_checksum().len(), 64);
        assert_ne!(native_0037_checksum(), native_0038_checksum());
        assert_eq!(native_0039_checksum().len(), 64);
        assert_ne!(native_0038_checksum(), native_0039_checksum());
        assert_eq!(native_0040_checksum().len(), 64);
        assert_ne!(native_0039_checksum(), native_0040_checksum());
        assert_eq!(native_0041_checksum().len(), 64);
        assert_ne!(native_0040_checksum(), native_0041_checksum());
        assert_eq!(native_0042_checksum().len(), 64);
        assert_ne!(native_0041_checksum(), native_0042_checksum());
        assert_eq!(native_0043_checksum().len(), 64);
        assert_ne!(native_0042_checksum(), native_0043_checksum());
        assert_eq!(native_0044_checksum().len(), 64);
        assert_ne!(native_0043_checksum(), native_0044_checksum());
        assert_eq!(native_0045_checksum().len(), 64);
        assert_ne!(native_0044_checksum(), native_0045_checksum());
        assert_eq!(native_0046_checksum().len(), 64);
        assert_ne!(native_0045_checksum(), native_0046_checksum());
        assert_eq!(
            native_0046_checksum(),
            "ec9cdbb01b2a09524b92fe6494f160df58c68f976a6ba1163dc41515c0495ed8",
        );
        assert_eq!(native_0047_checksum().len(), 64);
        assert_ne!(native_0046_checksum(), native_0047_checksum());
        assert_eq!(MIGRATIONS[34].version, NATIVE_0047_VERSION);
        assert_eq!(native_0048_checksum().len(), 64);
        assert_ne!(native_0047_checksum(), native_0048_checksum());
        assert_eq!(MIGRATIONS[35].version, NATIVE_0048_VERSION);
        assert_eq!(native_0049_checksum().len(), 64);
        assert_ne!(native_0048_checksum(), native_0049_checksum());
        assert_eq!(MIGRATIONS[36].version, NATIVE_0049_VERSION);
        assert_eq!(native_0050_checksum().len(), 64);
        assert_ne!(native_0049_checksum(), native_0050_checksum());
        assert_eq!(MIGRATIONS[37].version, NATIVE_0050_VERSION);
        assert_eq!(native_0051_checksum().len(), 64);
        assert_ne!(native_0050_checksum(), native_0051_checksum());
        assert_eq!(MIGRATIONS[38].version, NATIVE_0051_VERSION);
        assert_eq!(native_0052_checksum().len(), 64);
        assert_ne!(native_0051_checksum(), native_0052_checksum());
        assert_eq!(MIGRATIONS[39].version, NATIVE_0052_VERSION);
        assert_eq!(native_0053_checksum().len(), 64);
        assert_ne!(native_0052_checksum(), native_0053_checksum());
        assert_eq!(
            native_0053_checksum(),
            "865c13ccbae7e53f642df010221c29e648c775c3aa26e1014e130e53778c8988",
        );
        assert_eq!(NATIVE_MIGRATION_COUNT, 41);
        assert_eq!(MIGRATIONS[40].version, NATIVE_LATEST_VERSION);
        assert_eq!(NATIVE_0052_SQL.matches("$$").count(), 22);
        assert_eq!(NATIVE_0052_SQL.matches("ALTER TABLE openbot_internal.thread_history_clear_intents\n DROP CONSTRAINT thread_history_clear_intents_kind_check;").count(), 1);
        assert_eq!(NATIVE_0052_SQL.matches("ADD CONSTRAINT thread_history_clear_intents_kind_check CHECK(intent_kind IN('stop_clear','maintenance_clear'));").count(), 1);
        assert_eq!(NATIVE_0051_SQL.matches("$$").count(), 30);
        assert_eq!(NATIVE_0050_SQL.matches("$$").count(), 14);
    }
}
