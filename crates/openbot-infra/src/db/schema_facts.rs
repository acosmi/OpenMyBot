//! 从活库提取 schema 事实。
//!
//! 类型与 `fixtures/db/schema-0012.json` 逐字段同构，所以「baseline 建出来的库」与「参照库」
//! 可以直接结构化比较，不必靠字符串 diff。字段声明顺序刻意按字母排（`enums` / `extensions` /
//! `functions` / `tables`，表里是 `columns` / `constraints` / `indexes` / `name` / `triggers`），
//! 与那份 fixture 的 `sort_keys=True` 归一化一致 —— 序列化出来连键序都对得上。
//!
//! 提取用的 SQL 是 [`SCHEMA_FACTS_SQL`]，与生成那份 fixture 时跑的是同一个文件。

use serde::{Deserialize, Serialize};

use crate::db::{InfraError, RowDecodeError};

/// 提取 schema 事实的 SQL，返回一行一列的 JSON 文本。
pub const SCHEMA_FACTS_SQL: &str = include_str!("../../sql/schema_facts.sql");

/// [`RowDecodeError`] 里用来指代这条查询的"表名"位。它不是一张真表，所以带括号。
const SCHEMA_FACTS_LABEL: &str = "(schema_facts.sql)";

/// 一个库在某一时刻的 schema 事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaFacts {
    /// `public` 下的 enum 类型，按类型名升序。
    pub enums: Vec<EnumFacts>,
    /// 已安装的 extension 名（排除 `plpgsql`），按名升序。
    pub extensions: Vec<String>,
    /// `public` 下的函数，按函数名升序。
    pub functions: Vec<FunctionFacts>,
    /// `public` 下的普通表，按表名升序。
    pub tables: Vec<TableFacts>,
}

impl SchemaFacts {
    /// 按表名找一张表。
    pub fn table(&self, name: &str) -> Option<&TableFacts> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// 按类型名找一个 enum。
    pub fn enum_type(&self, name: &str) -> Option<&EnumFacts> {
        self.enums.iter().find(|e| e.name == name)
    }
}

/// 一张表的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableFacts {
    /// 列，按 `pg_attribute.attnum` 升序。
    pub columns: Vec<ColumnFacts>,
    /// 约束，按约束名升序。
    pub constraints: Vec<ConstraintFacts>,
    /// 索引，按索引名升序（含主键 / 唯一约束隐含的索引）。
    pub indexes: Vec<IndexFacts>,
    /// 表名。
    pub name: String,
    /// 非内部触发器，按触发器名升序。
    pub triggers: Vec<TriggerFacts>,
}

impl TableFacts {
    /// 按列名找一列。
    pub fn column(&self, name: &str) -> Option<&ColumnFacts> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// 一列的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnFacts {
    /// `pg_get_expr(adbin, adrelid)` 的默认值表达式；无默认值为 `None`。
    pub default: Option<String>,
    /// 列名。
    pub name: String,
    /// 是否 `NOT NULL`。
    pub notnull: bool,
    /// `pg_attribute.attnum`。
    pub ordinal: i32,
    /// `format_type(atttypid, atttypmod)` 的输出文本。
    #[serde(rename = "type")]
    pub sql_type: String,
}

/// 一个约束的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintFacts {
    /// `pg_get_constraintdef()` 的输出。
    pub def: String,
    /// 约束名。
    pub name: String,
    /// `pg_constraint.contype`：`p` 主键 / `u` 唯一 / `f` 外键 / `c` 检查。
    ///
    /// `n`（NOT NULL）刻意不在这里：它由 [`ColumnFacts::notnull`] 表达；PG18 会额外把它
    /// 放进 `pg_constraint`，PG17 不会，双记会让同一份 DDL 的事实随服务端版本漂移。
    #[serde(rename = "type")]
    pub kind: String,
}

/// 一个索引的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexFacts {
    /// `pg_get_indexdef()` 的输出。
    pub def: String,
    /// 索引名。
    pub name: String,
}

/// 一个触发器的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerFacts {
    /// `pg_get_triggerdef()` 的输出。
    pub def: String,
    /// 触发器名。
    pub name: String,
}

/// 一个 enum 类型的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumFacts {
    /// 类型名。
    pub name: String,
    /// 标签，按 `pg_enum.enumsortorder` 升序。
    pub values: Vec<String>,
}

/// 一个函数的事实。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionFacts {
    /// `pg_get_functiondef()` 的输出。
    pub def: String,
    /// 函数名。
    pub name: String,
}

/// 在给定连接上跑 [`SCHEMA_FACTS_SQL`] 并解析结果。
///
/// 只读：整条语句都是对 `pg_catalog` 的 `SELECT`。
///
/// The observation is rendered in UTC like the other catalog captures:
/// `pg_get_constraintdef` and `pg_get_expr` print timestamptz literals in the
/// session TimeZone, which a cluster inherits from its host at initdb.
pub async fn fetch(client: &tokio_postgres::Client) -> Result<SchemaFacts, InfraError> {
    // One simple-query message runs as one implicit transaction: the SET LOCAL
    // ends with it, and neither a failed statement nor a dropped future leaves
    // a transaction open on a pooled client.
    let messages = client
        .simple_query(&format!("SET LOCAL timezone='UTC';\n{SCHEMA_FACTS_SQL}"))
        .await
        .map_err(|source| InfraError::query("提取 schema 事实", source))?;
    let payload = messages
        .iter()
        .find_map(|message| match message {
            tokio_postgres::SimpleQueryMessage::Row(row) => Some(row.try_get(0)),
            _ => None,
        })
        .transpose()
        .map_err(|source| RowDecodeError::column(SCHEMA_FACTS_LABEL, "jsonb_pretty", source))?
        .flatten()
        .unwrap_or_default();
    serde_json::from_str(payload)
        .map_err(|source| RowDecodeError::json(SCHEMA_FACTS_LABEL, "jsonb_pretty", source).into())
}

#[cfg(test)]
mod tests {
    use crate::db::testdata::{REFERENCE_FACTS_JSON, reference_facts};

    #[test]
    fn reference_fixture_parses_into_the_documented_shape() {
        let facts = reference_facts();
        assert_eq!(facts.tables.len(), 28);
        assert_eq!(
            facts.tables.iter().map(|t| t.columns.len()).sum::<usize>(),
            204,
        );
        assert_eq!(
            facts
                .tables
                .iter()
                .map(|t| t.constraints.len())
                .sum::<usize>(),
            59,
        );
        assert_eq!(
            facts
                .tables
                .iter()
                .flat_map(|t| &t.columns)
                .filter(|column| column.notnull)
                .count(),
            153,
        );
        assert!(
            facts
                .tables
                .iter()
                .flat_map(|t| &t.constraints)
                .all(|constraint| constraint.kind != "n"),
        );
        assert_eq!(
            facts.tables.iter().map(|t| t.indexes.len()).sum::<usize>(),
            44
        );
        assert_eq!(
            facts.tables.iter().map(|t| t.triggers.len()).sum::<usize>(),
            2
        );
        assert_eq!(facts.enums.len(), 4);
        assert_eq!(facts.functions.len(), 1);
        assert!(facts.extensions.is_empty());
    }

    /// 反序列化再序列化必须回到同一棵 JSON 树。
    ///
    /// 这是"结构一致"这条要求的可判定形式：漏一个字段、把 `type` 写成 `sql_type`、
    /// 把 `default: null` 吃掉，都会让往返结果与原文不等。
    #[test]
    fn schema_facts_round_trips_through_the_reference_fixture() {
        let facts = reference_facts();
        let reserialized: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&facts).expect("序列化应当成功"))
                .expect("重新解析应当成功");
        let original: serde_json::Value =
            serde_json::from_str(REFERENCE_FACTS_JSON).expect("原文应当能解析");
        assert_eq!(reserialized, original);
    }

    /// 正向对照：上一条往返测试若因为 `serde_json::Value` 比较过于宽松而恒真，这里会露馅 ——
    /// 改一个字节之后两棵树必须不等。
    #[test]
    fn round_trip_comparison_is_not_vacuous() {
        let mut facts = reference_facts();
        facts.tables[0].columns[0].name.push('x');
        let mutated: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&facts).expect("序列化应当成功"))
                .expect("重新解析应当成功");
        let original: serde_json::Value =
            serde_json::from_str(REFERENCE_FACTS_JSON).expect("原文应当能解析");
        assert_ne!(mutated, original);
    }
}
