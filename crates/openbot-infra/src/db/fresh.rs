//! Fresh Rust 数据库的原子 bootstrap。
//!
//! baseline 与 native migrations 不能是两个提交：进程若恰在二者之间退出，重启只看见一套
//! 无 Drizzle/native 账本的 0012 schema，无法与“运维手工迁过但 0003 是否执行未知”的库区分。
//! 本入口让 baseline、0013–0016 与自有账本在一个事务里一起出现或一起消失。

use crate::db::InfraError;
use crate::db::native::{self, ApplyOutcome, BootstrapTransactionClient};

/// fresh bootstrap 在锁内重检后的结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshApplyOutcome {
    /// 本事务完成 baseline + native。
    Applied(ApplyOutcome),
    /// 等锁期间另一 replica 已完成；调用方应转走 existing/native 校验路径。
    AlreadyInitialized,
}

/// 在已确认 public schema 为空的数据库上原子施加 baseline + 全部 native migration。
///
/// # Errors
///
/// 开事务、任一 DDL/账本步骤或 commit 失败时返回脱敏 [`InfraError`]；事务整体回滚。
pub async fn apply(
    client: &mut impl BootstrapTransactionClient,
) -> Result<FreshApplyOutcome, InfraError> {
    let transaction = client
        .bootstrap_transaction_builder()
        .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(|source| InfraError::query("开始 fresh database bootstrap 事务", source))?;
    native::lock_migrations(&transaction).await?;
    let public_tables: i64 = transaction
        .query_one(
            "SELECT count(*)::bigint FROM information_schema.tables \
             WHERE table_schema='public' AND table_type='BASE TABLE'",
            &[],
        )
        .await
        .map_err(|source| InfraError::query("锁内重检 fresh public schema", source))?
        .try_get(0)
        .map_err(|source| {
            crate::db::RowDecodeError::column("(information_schema.tables)", "count", source)
        })?;
    if public_tables != 0 {
        transaction.rollback().await.map_err(|source| {
            InfraError::query("结束已由另一 replica 初始化的 fresh 事务", source)
        })?;
        return Ok(FreshApplyOutcome::AlreadyInitialized);
    }
    let outcome = apply_in_transaction(&transaction).await?;
    transaction
        .commit()
        .await
        .map_err(|source| InfraError::query("提交 fresh database bootstrap", source))?;
    Ok(FreshApplyOutcome::Applied(outcome))
}

/// Baseline plus every native migration inside the caller's transaction; the
/// caller owns BEGIN, the empty-schema recheck, ROLLBACK and COMMIT.
pub(crate) async fn apply_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<ApplyOutcome, InfraError> {
    super::baseline::apply_in_transaction(transaction).await?;
    native::apply_through_in_transaction(transaction, native::NATIVE_LATEST_VERSION).await
}
