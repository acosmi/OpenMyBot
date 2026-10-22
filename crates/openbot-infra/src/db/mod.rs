//! PostgreSQL 数据库层（v3 §14）。
//!
//! 各子模块各管一件事，互不越界：
//!
//! | 模块 | 职责 |
//! | --- | --- |
//! | [`tables`] | 上游 28 张表的类型化行结构与列台账 |
//! | [`baseline`] | fresh install 的 baseline DDL（把空库直接建成 0012 终态） |
//! | [`compat`] | 迁移边界检查：拒绝没迁到 0012 的库 |
//! | [`desktop_local`] | exact loopback/SCRAM admin typestate、固定业务库核验与Desktop pool |
//! | [`fresh`] | 空库 baseline + native + 自有账本的原子 bootstrap |
//! | [`initialization`] | Server/Desktop 共用的来源识别与启动 migration 路径 |
//! | [`native`] | 从 0012 往后施加 Rust-owned、expand-only 的自有增量 |
//! | [`schema_facts`] | 从活库提取 schema 事实（与 `fixtures/db/schema-0012.json` 同构） |
//! | [`pool`] | `deadpool-postgres` 连接池 |
//!
//! 「0012 终态」指上游 `CopilotKit/openbot@891df72f1827454d8b353d108fe5dd2313b7e30d` 的
//! `server/drizzle/0000..0012` 共 13 条 migration 全部跑完之后的 schema：
//! 28 张表 / 204 列 / 59 个非 NOT-NULL 约束 / 44 个索引 / 2 个触发器 /
//! 4 个 enum / 1 个函数 / 0 个 extension（NOT NULL 另由 153 个列事实表达）。
//!
//! 本层刻意**不**实现 downgrade：v3 §14.3 逐字「无 downgrade migration」。

pub mod approval_preference_schema;
pub mod artifact_cleanup_schema;
pub mod baseline;
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub mod capture_materials;
pub mod compat;
pub mod custom_model_catalog_schema;
pub mod custom_model_v2_schema;
pub mod desktop_local;
pub mod desktop_vault_canary;
pub mod fresh;
pub mod gateway_authorization_schema;
pub mod initialization;
pub mod native;
pub(crate) mod occupancy;
pub mod pool;
pub mod schema_facts;
pub mod tables;
pub mod thread_history_admission_schema;
pub(crate) mod thread_history_writer_schema;
pub mod thread_origin_schema;
pub mod types;

mod error;

#[cfg(test)]
mod testdata;

pub use error::{
    InfraError, JsonErrorSummary, PostgresErrorSummary, RowDecodeCause, RowDecodeError, error_chain,
};
