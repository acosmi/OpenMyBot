//! 类型化 repository 的公共机械层。
//!
//! 本模块不对外公开自由 SQL。predicate / order_by 只由同 crate 的具名 repo 以字面量传入；
//! 调用者只能调用 `find_by_*` / `list_all` / `insert` / `delete` 这类类型化方法。行值全部走
//! `$n` 绑定，表名与列名来自 [`crate::db::tables::TableRow`] 的编译期台账。

use core::marker::PhantomData;

use crate::db::pool::DatabasePool as Pool;
use tokio_postgres::types::ToSql;

use crate::db::InfraError;
use crate::db::tables::TableRow;

#[derive(Clone)]
pub(crate) struct RepoCore<R> {
    pool: Pool,
    row: PhantomData<fn() -> R>,
}

impl<R> RepoCore<R>
where
    R: TableRow,
{
    pub(crate) fn new(pool: Pool) -> Self {
        Self {
            pool,
            row: PhantomData,
        }
    }

    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }

    pub(crate) async fn insert(&self, row: &R) -> Result<R, InfraError> {
        let sql = insert_sql::<R>();
        let mut client = self.client().await?;
        let params = row.as_sql_params();
        if matches!(
            R::TABLE_NAME,
            "threads" | "messages" | "runs" | "run_events"
        ) {
            let transaction = client
                .build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
                .start()
                .await
                .map_err(|source| InfraError::query("建立类型化正文insert原事务", source))?;
            let schema =
                crate::thread_history_writer::CurrentWriterSchema::observe(&transaction).await?;
            if R::TABLE_NAME != "threads" {
                let thread_index = R::COLUMNS
                    .iter()
                    .position(|column| *column == "thread_id")
                    .ok_or_else(|| {
                        InfraError::repository_invariant(
                            "thread_history_writer_row_mapping_invalid",
                        )
                    })?;
                let thread_param = *params.get(thread_index).ok_or_else(|| {
                    InfraError::repository_invariant("thread_history_writer_row_mapping_invalid")
                })?;
                let binding=if matches!(R::TABLE_NAME,"messages"|"run_events") {
                    let run_index=R::COLUMNS.iter().position(|column|*column=="run_id")
                        .ok_or_else(||InfraError::repository_invariant("thread_history_writer_row_mapping_invalid"))?;
                    let run_param=*params.get(run_index)
                        .ok_or_else(||InfraError::repository_invariant("thread_history_writer_row_mapping_invalid"))?;
                    transaction.query_opt(
                        "SELECT t.thread_id FROM public.threads t LEFT JOIN public.runs r ON r.run_id=$2::text WHERE t.thread_id=$1::text AND (($2::text IS NULL AND $3::boolean) OR r.thread_id=t.thread_id)",
                        &[thread_param,run_param,&(R::TABLE_NAME=="messages")],
                    ).await
                } else {
                    transaction.query_opt("SELECT thread_id FROM public.threads WHERE thread_id=$1::text",&[thread_param]).await
                }.map_err(|source|crate::thread_history_writer::query_error("核类型化正文实际Run/Thread来源",source))?
                    .ok_or_else(||InfraError::repository_invariant("thread_history_writer_binding_invalid"))?;
                let actual: String = binding.try_get("thread_id").map_err(|source| {
                    crate::db::RowDecodeError::column("(typed_body_insert)", "thread_id", source)
                })?;
                schema
                    .require_open(&transaction, &openbot_contracts::ids::ThreadId::new(actual))
                    .await?;
            }
            let inserted = transaction
                .query_one(&sql, &params)
                .await
                .map_err(|source| {
                    crate::thread_history_writer::query_error("插入类型化正文真实行", source)
                })?;
            let decoded = R::try_from_pg(&inserted)?;
            transaction
                .commit()
                .await
                .map_err(|source| InfraError::query("提交类型化正文insert原事务", source))?;
            return Ok(decoded);
        }
        let inserted = client
            .query_one(&sql, &params)
            .await
            .map_err(|source| InfraError::query(format!("插入 {}", R::TABLE_NAME), source))?;
        R::try_from_pg(&inserted).map_err(Into::into)
    }

    pub(crate) async fn list(&self, order_by: &'static str) -> Result<Vec<R>, InfraError> {
        let sql = format!(
            "SELECT {} FROM public.\"{}\" ORDER BY {order_by}",
            columns_sql::<R>(),
            R::TABLE_NAME,
        );
        let client = self.client().await?;
        let rows = client
            .query(&sql, &[])
            .await
            .map_err(|source| InfraError::query(format!("列出 {}", R::TABLE_NAME), source))?;
        rows.iter()
            .map(R::try_from_pg)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    pub(crate) async fn find(
        &self,
        predicate: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<R>, InfraError> {
        let sql = format!(
            "SELECT {} FROM public.\"{}\" WHERE {predicate}",
            columns_sql::<R>(),
            R::TABLE_NAME,
        );
        let client = self.client().await?;
        let row = client
            .query_opt(&sql, params)
            .await
            .map_err(|source| InfraError::query(format!("按主键读取 {}", R::TABLE_NAME), source))?;
        row.as_ref()
            .map(R::try_from_pg)
            .transpose()
            .map_err(Into::into)
    }

    pub(crate) async fn list_where(
        &self,
        predicate: &'static str,
        params: &[&(dyn ToSql + Sync)],
        order_by: &'static str,
    ) -> Result<Vec<R>, InfraError> {
        let sql = format!(
            "SELECT {} FROM public.\"{}\" WHERE {predicate} ORDER BY {order_by}",
            columns_sql::<R>(),
            R::TABLE_NAME,
        );
        let client = self.client().await?;
        let rows = client
            .query(&sql, params)
            .await
            .map_err(|source| InfraError::query(format!("筛选 {}", R::TABLE_NAME), source))?;
        rows.iter()
            .map(R::try_from_pg)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    pub(crate) async fn delete(
        &self,
        predicate: &'static str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<bool, InfraError> {
        let sql = format!("DELETE FROM public.\"{}\" WHERE {predicate}", R::TABLE_NAME);
        let client = self.client().await?;
        let affected = client
            .execute(&sql, params)
            .await
            .map_err(|source| InfraError::query(format!("删除 {}", R::TABLE_NAME), source))?;
        Ok(affected == 1)
    }

    async fn client(&self) -> Result<crate::db::pool::PooledClient, InfraError> {
        self.pool
            .get()
            .await
            .map_err(|source| InfraError::connect(format!("为 {} 获取连接", R::TABLE_NAME), source))
    }
}

impl<R> core::fmt::Debug for RepoCore<R>
where
    R: TableRow,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RepoCore")
            .field("table", &R::TABLE_NAME)
            .finish_non_exhaustive()
    }
}

pub(crate) fn columns_sql<R: TableRow>() -> String {
    R::COLUMNS
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// 用编译期 alias 限定全部列；用于 `UPDATE ... FROM ... RETURNING` 消除同名列歧义。
pub(crate) fn qualified_columns_sql<R: TableRow>(alias: &'static str) -> String {
    R::COLUMNS
        .iter()
        .map(|column| format!("{alias}.\"{column}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn insert_sql<R: TableRow>() -> String {
    let columns = columns_sql::<R>();
    let placeholders = (1..=R::COLUMNS.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO public.\"{}\" ({columns}) VALUES ({placeholders}) RETURNING {columns}",
        R::TABLE_NAME,
    )
}

/// 展开一个有类型主键的基础 repository。
macro_rules! define_table_repo {
    (
        $(#[$meta:meta])*
        $name:ident,
        table = $table:ident,
        order_by = $order_by:literal,
        find = $find:ident($($arg:ident : $ty:ty),+ $(,)?) where $predicate:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            core: $crate::repo::common::RepoCore<$crate::db::tables::$table::Row>,
        }

        impl $name {
            /// 用调用方提供的连接池构造；repository 自己不读环境变量。
            #[must_use]
            pub fn new(pool: crate::db::pool::DatabasePool) -> Self {
                Self {
                    core: $crate::repo::common::RepoCore::new(pool),
                }
            }

            /// 插入完整类型化行并读回数据库实际保存的值。
            pub async fn insert(
                &self,
                row: &$crate::db::tables::$table::Row,
            ) -> Result<$crate::db::tables::$table::Row, $crate::db::InfraError> {
                self.core.insert(row).await
            }

            /// 按主键读取；不存在返回 `None`。
            pub async fn $find(
                &self,
                $($arg: $ty),+
            ) -> Result<Option<$crate::db::tables::$table::Row>, $crate::db::InfraError> {
                self.core.find($predicate, &[$(&$arg),+]).await
            }

            /// 按主键稳定排序列出全部行。
            pub async fn list_all(
                &self,
            ) -> Result<Vec<$crate::db::tables::$table::Row>, $crate::db::InfraError> {
                self.core.list($order_by).await
            }

            /// 按主键删除；存在并删除返回 true，不存在返回 false。
            pub async fn delete(
                &self,
                $($arg: $ty),+
            ) -> Result<bool, $crate::db::InfraError> {
                self.core.delete($predicate, &[$(&$arg),+]).await
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

pub(crate) use define_table_repo;
