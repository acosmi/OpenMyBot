//! `ChannelRepo` —— `openbot_application::ChannelReader` 的 PostgreSQL 实现。
//!
//! 落点由 `parity/tables.yaml::tbl-channels` 的 notes 里 `repo=openbot-infra::repo::channels`
//! 钉死，逐字兑现。
//!
//! # 可见性判据只有一个：materialized membership（v3 §6.5 条 5 / §28.1 R22）
//!
//! 本实现**只** `JOIN channel_memberships`，**绝不** join `intelligence_channel_mappings`。
//! 上游 `server/src/channels/routes.ts::list` 的分页段只 join membership，
//! 而 hydration 段额外 join 了 mapping（外加 `channel_agents` 与 `agent_profiles` 两个
//! INNER JOIN），两处判据不一致 —— 于是 `nextCursor` 可以非空而本页为空，
//! 客户端看到"还有下一页"，翻过去什么都没有。Intelligence 已按 §4.1 退役、该表按 §14.2
//! 降级为只读 legacy provenance，继续 join 会把 §6.5 刚补上 membership 的包 channel
//! 原样过滤回不可达。
//!
//! **分页与 hydration 在这里是同一条 SQL 的两个部分**（`page` CTE + `LATERAL`），
//! 判据只写了一次，所以两者在构造上不可能再漂开。集成测试
//! `a_channel_without_an_intelligence_mapping_is_still_visible` 正面钉死这一条。
//!
//! # 限的是 channel 数，不是行数
//!
//! `LIMIT` 落在 `page` CTE 里，作用于 channel；agent 由 `LATERAL` 子查询在**每个** channel
//! 上聚合，所以一个挂了 N 个 agent 的 channel 永远整个返回，不会被劈成两页。
//! 上游用两段查询达到同一目的，注释里写明了理由（"a limit on rows would cut a channel in
//! half"）；这里用一条语句，少一次往返，且"限的是什么"由 SQL 结构本身承载。
//!
//! # 参数绑定
//!
//! actor、游标、limit 全部走 `$n` 绑定，SQL 文本是编译期常量，零字符串拼接
//! （v3 §5.2：transport 不得传任意 query；actor 与 cursor 同样是外部值）。

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{
    ChannelAdministration, ChannelAdministrationError, ChannelCreateRequest, ChannelCursor,
    ChannelReadScope, ChannelReader, PortError,
};
use openbot_contracts::agent::AgentVisibility;
use openbot_contracts::command::{ChannelDetail, ChannelSummary};
use openbot_contracts::ids::{ActorId, BotId, ChannelId};
use openbot_contracts::text::trim_ecmascript;
use openbot_domain::agent::profile_policy::{AgentActor, AgentProfileFacts, can_access_agent};
use openbot_domain::channel::{PRIVATE_AGENT_CHANNEL_DESCRIPTION, derive_channel_name};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::thread_id::mint_thread_id;

/// `PortError` 里的依赖名。与 `AppError::DependencyUnavailable::dependency` 同域。
const DEPENDENCY: &str = "database";

/// 一次查询拿到一页 channel 及其 agent。
///
/// 结构：
///
/// - `page` CTE 做**可见性 + 游标 + 定序 + 限流**，`LIMIT` 作用于 channel 行；
/// - `LATERAL` 子查询按 channel 聚合 `channel_agents`，`array_agg(... ORDER BY agent_id)`
///   兑现上游的 `asc(channelAgents.agentId)`；
/// - `agent_profiles` 是 **LEFT** JOIN，上游那里是 INNER JOIN。**在任何由上游代码产生的库上
///   两者行为等价**，实证两条：① `agent_profiles` 从不硬删 —— `delete(agentProfiles)` 在
///   `server/src` 零命中，而同一条 grep 在同目录能查到 `delete(userRoles)` /
///   `delete(ssoProviders)` / `delete(skills)` / `delete(sessions)`，所以零命中不是 grep
///   失效；删除走软删（`deleted_at`）。② `agents` 与 `agent_profiles` 同事务创建 ——
///   `server/src/agents/profile-store.ts` 的两条创建路径都在同一个 `database.transaction`
///   块里先 `insert(agents)` 再 `insert(agentProfiles)`，`tenant-package.ts` 同理。
///   于是每个 `agents` 行都有 profile 行，且 profile 只软删不消失。
///
///   等价时选 LEFT，理由是**不变量被破坏时要失败得看得见**：真出现缺 profile 的 agent 时，
///   INNER JOIN 会静默把它从 `agent_ids` 里删掉。两种结构的后果不同，别混为一谈：
///   上游那条**扁平** INNER JOIN 会让"全部 agent 都缺 profile"的 channel 整个从结果里消失
///   （与 R22 同族：页面已经许诺了这个 channel，hydration 却把它删掉）；本实现的
///   `LEFT JOIN LATERAL` 会保住 channel 本身，但把它的 `agent_ids` **静默清空**
///   —— 实测把这里的 LEFT 改成 INNER，`c-orphan` 仍在结果里，`agent_ids` 却变成 `[]`。
///   两者都是无声的数据丢失，只是丢的粒度不同。LEFT 两样都不丢。
///   `active` 的语义也自洽：profile 缺失时 `deleted_at IS NULL` 为真 ⇒ active，
///   与上游 `rows.every()` 在零行上取真（vacuous truth）一致。
///   行为由集成测试 `an_agent_without_a_profile_row_still_appears_and_keeps_its_channel`
///   钉住 —— 不钉的话，下一个人改成 INNER 不会有任何东西变红。
///
///   **失效条件**：若将来 `agent_profiles` 出现**硬删**路径，上面的等价性就不再成立，
///   这处 LEFT/INNER 的取舍需要重新评估（届时"缺 profile"会变成常态而非异常）。
/// - `bool_and(...)` 兑现上游 `rows.every(row => row.deletedAt === null)`；零个 agent 时
///   聚合返回 NULL，`coalesce(..., true)` 把它变回 `true`，与 JS 的 `[].every(...) === true`
///   一致。`array_agg` 同理 coalesce 成空数组。
const LIST_VISIBLE_CHANNELS_SQL: &str = "\
WITH page AS (
    SELECT c.id,
           c.name,
           c.last_message,
           c.last_message_at,
           c.last_message_agent_id,
           c.created_at
    FROM public.channels c
    JOIN public.channel_memberships m
      ON m.channel_id = c.id
     AND m.user_id = $1
    WHERE $2::timestamptz IS NULL
       OR (coalesce(c.last_message_at, c.created_at), c.id) < ($2::timestamptz, $3::text)
    ORDER BY coalesce(c.last_message_at, c.created_at) DESC, c.id DESC
    LIMIT $4
)
SELECT p.id,
       p.name,
       p.last_message,
       p.last_message_at,
       p.last_message_agent_id,
       p.created_at,
       coalesce(a.agent_ids, '{}'::text[]) AS agent_ids,
       coalesce(a.active, true)            AS active,
       NULL::text                          AS thread_id
FROM page p
LEFT JOIN LATERAL (
    SELECT array_agg(ca.agent_id ORDER BY ca.agent_id) AS agent_ids,
           bool_and(pr.deleted_at IS NULL)             AS active
    FROM public.channel_agents ca
    LEFT JOIN public.agent_profiles pr ON pr.agent_id = ca.agent_id
    WHERE ca.channel_id = p.id
) a ON true
ORDER BY coalesce(p.last_message_at, p.created_at) DESC, p.id DESC";

/// Production list: same roster semantics plus a deployment/tenant/member-scoped native thread.
const LIST_VISIBLE_CHANNELS_SCOPED_SQL: &str = "\
WITH page AS (
    SELECT c.id,
           c.name,
           c.last_message,
           c.last_message_at,
           c.last_message_agent_id,
           c.created_at
    FROM public.channels c
    JOIN public.channel_memberships m
      ON m.channel_id = c.id
     AND m.user_id = $1
    WHERE $4::timestamptz IS NULL
       OR (coalesce(c.last_message_at, c.created_at), c.id) < ($4::timestamptz, $5::text)
    ORDER BY coalesce(c.last_message_at, c.created_at) DESC, c.id DESC
    LIMIT $6
)
SELECT p.id,
       p.name,
       p.last_message,
       p.last_message_at,
       p.last_message_agent_id,
       p.created_at,
       coalesce(a.agent_ids, '{}'::text[]) AS agent_ids,
       coalesce(a.active, true)            AS active,
       t.thread_id
FROM page p
LEFT JOIN LATERAL (
    SELECT array_agg(ca.agent_id ORDER BY ca.agent_id) AS agent_ids,
           bool_and(pr.deleted_at IS NULL)             AS active
    FROM public.channel_agents ca
    LEFT JOIN public.agent_profiles pr ON pr.agent_id = ca.agent_id
    WHERE ca.channel_id = p.id
) a ON true
LEFT JOIN LATERAL (
    SELECT th.thread_id
    FROM public.threads th
    WHERE th.deployment_id = $2
      AND th.tenant_id = $3
      AND th.anchor_kind = 'channel'
      AND th.anchor_id = p.id
      AND th.status <> 'deleted'
    ORDER BY th.updated_at DESC, th.thread_id DESC
    LIMIT 1
) t ON true
ORDER BY coalesce(p.last_message_at, p.created_at) DESC, p.id DESC";

/// One membership-visible channel with the same scoped native-thread projection as the list.
const GET_VISIBLE_CHANNEL_SQL: &str = "\
SELECT c.id,
       c.name,
       c.last_message,
       c.last_message_at,
       c.last_message_agent_id,
       c.created_at,
       coalesce(a.agent_ids, '{}'::text[]) AS agent_ids,
       coalesce(a.active, true)            AS active,
       t.thread_id
FROM public.channels c
JOIN public.channel_memberships m
  ON m.channel_id = c.id
 AND m.user_id = $1
LEFT JOIN LATERAL (
    SELECT array_agg(ca.agent_id ORDER BY ca.agent_id) AS agent_ids,
           bool_and(pr.deleted_at IS NULL)             AS active
    FROM public.channel_agents ca
    LEFT JOIN public.agent_profiles pr ON pr.agent_id = ca.agent_id
    WHERE ca.channel_id = c.id
) a ON true
LEFT JOIN LATERAL (
    SELECT th.thread_id
    FROM public.threads th
    WHERE th.deployment_id = $2
      AND th.tenant_id = $3
      AND th.anchor_kind = 'channel'
      AND th.anchor_id = c.id
      AND th.status <> 'deleted'
    ORDER BY th.updated_at DESC, th.thread_id DESC
    LIMIT 1
) t ON true
WHERE c.id = $4";

/// channel 的读取实现。
///
/// 持 [`Pool`] 而不是单个连接：每次调用取一条连接，用完即还，不跨调用持有。
#[derive(Clone)]
pub struct ChannelRepo {
    pool: Pool,
}

impl ChannelRepo {
    /// 用一个已经建好的连接池构造。
    ///
    /// 池由调用方（启动层）提供 —— 本 crate 不读环境变量，也不自己决定连谁。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

impl std::fmt::Debug for ChannelRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 不打印池内部状态：`deadpool` 的 Debug 会带上连接配置。
        f.debug_struct("ChannelRepo").finish_non_exhaustive()
    }
}

#[async_trait]
impl ChannelAdministration for ChannelRepo {
    async fn create_channel(
        &self,
        request: ChannelCreateRequest,
    ) -> Result<ChannelDetail, ChannelAdministrationError> {
        if request.agent_ids.is_empty()
            || request.agent_ids.windows(2).any(|pair| pair[0] >= pair[1])
            || request.agent_ids.iter().any(|agent_id| {
                let value = agent_id.as_str();
                value.is_empty()
                    || value.len() > 512
                    || value.chars().any(char::is_control)
                    || trim_ecmascript(value) != value
            })
        {
            return Err(ChannelAdministrationError::Corrupt { field: "agent_ids" });
        }
        let channel_id = ChannelId::new(format!("channel_{}", Uuid::now_v7()));
        let thread_id = mint_thread_id(&request.scope.deployment)
            .map_err(|_| ChannelAdministrationError::Unavailable)?;
        let mut client = self.pool.get().await.map_err(|error| {
            tracing::error!(error = %error, "channel create pool unavailable");
            ChannelAdministrationError::Unavailable
        })?;
        let transaction = client.transaction().await.map_err(|error| {
            tracing::error!(error = %error, "begin channel create transaction failed");
            ChannelAdministrationError::Unavailable
        })?;
        let result = async {
            crate::db::native::validate_thread_origin_in_transaction(&transaction)
                .await
                .map_err(channel_origin_error)?;
            let current_admin = crate::thread_origin::current_native_actor(
                &transaction,
                request.scope.actor.as_str(),
                request.scope.auth_generation,
            )
            .await
            .map_err(channel_origin_error)?
            .ok_or(ChannelAdministrationError::NotVisible)?;
            if current_admin != request.scope.admin {
                return Err(ChannelAdministrationError::NotVisible);
            }
            let actor = AgentActor {
                id: request.scope.actor.as_str(),
                admin: request.scope.admin,
            };
            let mut names = Vec::with_capacity(request.agent_ids.len());
            for agent_id in &request.agent_ids {
                let row = transaction
                    .query_opt(
                        "SELECT a.name,p.owner_user_id,p.visibility::text, \
                                (a.package_id IS NOT NULL) AS system_owned, \
                                (p.deleted_at IS NOT NULL) AS deleted, \
                                (a.package_id IS NULL OR dp.tenant_id=$2) AS tenant_visible \
                         FROM public.agents a \
                         JOIN public.agent_profiles p ON p.agent_id=a.id \
                         LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id \
                         WHERE a.id=$1 FOR UPDATE OF a,p",
                        &[&agent_id.as_str(), &request.scope.tenant.as_str()],
                    )
                    .await
                    .map_err(|error| channel_admin_query("lock Agent profile", error))?;
                let Some(row) = row else {
                    return Err(ChannelAdministrationError::NotVisible);
                };
                let visibility = match admin_decode::<String>(&row, "visibility")?.as_str() {
                    "public" => AgentVisibility::Public,
                    "private" => AgentVisibility::Private,
                    _ => {
                        return Err(ChannelAdministrationError::Corrupt {
                            field: "visibility",
                        });
                    }
                };
                let owner: Option<String> = admin_decode(&row, "owner_user_id")?;
                let facts = AgentProfileFacts {
                    owner_user_id: owner.as_deref(),
                    visibility,
                    system_owned: admin_decode(&row, "system_owned")?,
                    deleted: admin_decode(&row, "deleted")?,
                };
                let tenant_visible: bool = admin_decode(&row, "tenant_visible")?;
                if !tenant_visible || !can_access_agent(&actor, &facts) {
                    return Err(ChannelAdministrationError::NotVisible);
                }
                names.push(admin_decode(&row, "name")?);
            }
            let name = derive_channel_name(&names).map_err(|_| {
                ChannelAdministrationError::Corrupt {
                    field: "agent_ids",
                }
            })?;
            let now: OffsetDateTime = transaction
                .query_one("SELECT clock_timestamp()", &[])
                .await
                .map_err(|error| channel_admin_query("read database clock", error))?
                .try_get(0)
                .map_err(|_| ChannelAdministrationError::Corrupt {
                    field: "database_clock",
                })?;
            transaction
                .execute(
                    "INSERT INTO public.channels( \
                       id,name,description,created_at,updated_at \
                     ) VALUES($1,$2,$3,$4,$4)",
                    &[
                        &channel_id.as_str(),
                        &name,
                        &PRIVATE_AGENT_CHANNEL_DESCRIPTION,
                        &now,
                    ],
                )
                .await
                .map_err(|error| channel_admin_query("insert channel", error))?;
            transaction
                .execute(
                    "INSERT INTO public.channel_memberships(channel_id,user_id,created_at) \
                     VALUES($1,$2,$3)",
                    &[&channel_id.as_str(), &request.scope.actor.as_str(), &now],
                )
                .await
                .map_err(|error| channel_admin_query("insert channel membership", error))?;
            for agent_id in &request.agent_ids {
                transaction
                    .execute(
                        "INSERT INTO public.channel_agents(channel_id,agent_id,created_at) \
                         VALUES($1,$2,$3)",
                        &[&channel_id.as_str(), &agent_id.as_str(), &now],
                    )
                    .await
                    .map_err(|error| channel_admin_query("insert channel Agent", error))?;
            }
            transaction
                .execute(
                    "INSERT INTO public.threads( \
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id, \
                       title,status,next_message_seq,next_event_seq,created_at,updated_at,deleted_at \
                     ) VALUES($1,$2,$3,$4,'channel',$5,NULL,'active',0,0,$6,$6,NULL)",
                    &[
                        &thread_id.as_str(),
                        &request.scope.tenant.as_str(),
                        &request.scope.deployment.as_str(),
                        &request.scope.actor.as_str(),
                        &channel_id.as_str(),
                        &now,
                    ],
                )
                .await
                .map_err(|error| channel_admin_query("insert channel thread", error))?;
            crate::thread_origin::record_new_native(
                &transaction,
                thread_id.as_str(),
                crate::thread_origin::NativeOriginKind::PrivateAgentChannel,
            )
            .await
            .map_err(channel_origin_error)?;
            Ok(ChannelDetail {
                id: channel_id,
                name,
                agent_ids: request.agent_ids,
                thread_id: Some(thread_id),
                active: true,
            })
        }
        .await;
        match result {
            Ok(channel) => {
                transaction.commit().await.map_err(|error| {
                    tracing::error!(error = %error, "commit channel create transaction failed");
                    ChannelAdministrationError::Unavailable
                })?;
                Ok(channel)
            }
            Err(error) => Err(error),
        }
    }
}

fn channel_origin_error(error: crate::db::InfraError) -> ChannelAdministrationError {
    tracing::warn!(error = %error, "channel Thread origin verification failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            ChannelAdministrationError::Unavailable
        }
        _ => ChannelAdministrationError::Corrupt {
            field: "thread_origin",
        },
    }
}

fn channel_admin_query(
    context: &'static str,
    error: tokio_postgres::Error,
) -> ChannelAdministrationError {
    tracing::error!(context, error = %error, "channel create query failed");
    ChannelAdministrationError::Unavailable
}

fn admin_decode<'a, T>(
    row: &'a tokio_postgres::Row,
    field: &'static str,
) -> Result<T, ChannelAdministrationError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(field)
        .map_err(|_| ChannelAdministrationError::Corrupt { field })
}

#[async_trait]
impl ChannelReader for ChannelRepo {
    async fn list_visible_channels(
        &self,
        actor: &ActorId,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(
                dependency = DEPENDENCY,
                error = %error,
                "取数据库连接失败"
            );
            PortError::Unavailable {
                dependency: DEPENDENCY,
            }
        })?;

        // 游标拆成两个可空参数：`None` 时两者都是 NULL，SQL 里的 `$2::timestamptz IS NULL`
        // 分支放行全部行。这样"有没有游标"不改变 SQL 文本，只改变绑定值。
        let (cursor_recency, cursor_id): (Option<OffsetDateTime>, Option<&str>) = match &cursor {
            Some(cursor) => (Some(cursor.recency), Some(cursor.id.as_str())),
            None => (None, None),
        };
        // `LIMIT` 要 i64；`u32` 到 `i64` 是无损扩宽，不可能溢出。
        let limit = i64::from(limit);

        let rows = client
            .query(
                LIST_VISIBLE_CHANNELS_SQL,
                &[&actor.as_str(), &cursor_recency, &cursor_id, &limit],
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    dependency = DEPENDENCY,
                    error = %crate::db::PostgresErrorSummary::from_error(&error),
                    "查询可见 channel 失败"
                );
                PortError::Unavailable {
                    dependency: DEPENDENCY,
                }
            })?;

        rows.iter().map(summary_from_row).collect()
    }

    async fn list_visible_channels_scoped(
        &self,
        scope: &ChannelReadScope,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(dependency = DEPENDENCY, error = %error, "取数据库连接失败");
            PortError::Unavailable {
                dependency: DEPENDENCY,
            }
        })?;
        let (cursor_recency, cursor_id): (Option<OffsetDateTime>, Option<&str>) = match &cursor {
            Some(cursor) => (Some(cursor.recency), Some(cursor.id.as_str())),
            None => (None, None),
        };
        let limit = i64::from(limit);
        let rows = client
            .query(
                LIST_VISIBLE_CHANNELS_SCOPED_SQL,
                &[
                    &scope.actor.as_str(),
                    &scope.deployment.as_str(),
                    &scope.tenant.as_str(),
                    &cursor_recency,
                    &cursor_id,
                    &limit,
                ],
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    dependency = DEPENDENCY,
                    error = %crate::db::PostgresErrorSummary::from_error(&error),
                    "查询 scoped 可见 channel 失败"
                );
                PortError::Unavailable {
                    dependency: DEPENDENCY,
                }
            })?;
        rows.iter().map(summary_from_row).collect()
    }

    async fn get_visible_channel(
        &self,
        scope: &ChannelReadScope,
        channel_id: &ChannelId,
    ) -> Result<Option<ChannelSummary>, PortError> {
        let client = self.pool.get().await.map_err(|error| {
            tracing::error!(dependency = DEPENDENCY, error = %error, "取数据库连接失败");
            PortError::Unavailable {
                dependency: DEPENDENCY,
            }
        })?;
        let row = client
            .query_opt(
                GET_VISIBLE_CHANNEL_SQL,
                &[
                    &scope.actor.as_str(),
                    &scope.deployment.as_str(),
                    &scope.tenant.as_str(),
                    &channel_id.as_str(),
                ],
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    dependency = DEPENDENCY,
                    error = %crate::db::PostgresErrorSummary::from_error(&error),
                    "查询 channel detail 失败"
                );
                PortError::Unavailable {
                    dependency: DEPENDENCY,
                }
            })?;
        row.as_ref().map(summary_from_row).transpose()
    }
}

/// 把一行翻成 [`ChannelSummary`]。
///
/// 解不开就是 [`PortError::Corrupt`]，只报**字段名**不报取值 —— 端口文档逐字要求，
/// 而且这些行里可能有用户内容（`last_message`）。
fn summary_from_row(row: &tokio_postgres::Row) -> Result<ChannelSummary, PortError> {
    let id: String = get(row, "id")?;
    let name: String = get(row, "name")?;
    let last_message: Option<String> = get(row, "last_message")?;
    let last_message_at: Option<OffsetDateTime> = get(row, "last_message_at")?;
    let last_message_agent_id: Option<String> = get(row, "last_message_agent_id")?;
    let created_at: OffsetDateTime = get(row, "created_at")?;
    let active: bool = get(row, "active")?;
    let thread_id: Option<String> = get(row, "thread_id")?;

    // `channel_agents.agent_id` 是 NOT NULL，所以 `array_agg` 不该产出 NULL 元素。
    // 但 PostgreSQL 的数组**元素**天然可空，类型系统不替我们保证这一点：解成
    // `Vec<Option<String>>` 再逐个校验，遇到 NULL 就 fail-closed，而不是 `unwrap_or_default`
    // 悄悄塞一个空字符串 agent id 进去。
    let raw_agent_ids: Vec<Option<String>> = get(row, "agent_ids")?;
    let mut agent_ids = Vec::with_capacity(raw_agent_ids.len());
    for agent_id in raw_agent_ids {
        let Some(agent_id) = agent_id else {
            tracing::error!(
                dependency = DEPENDENCY,
                field = "agent_ids",
                "agent_ids 里出现 NULL 元素"
            );
            return Err(PortError::Corrupt {
                dependency: DEPENDENCY,
                field: "agent_ids",
            });
        };
        agent_ids.push(BotId::new(agent_id));
    }

    Ok(ChannelSummary {
        id: ChannelId::new(id),
        name,
        agent_ids,
        last_message,
        last_message_at,
        last_message_agent_id: last_message_agent_id.map(BotId::new),
        created_at,
        thread_id: thread_id.map(openbot_contracts::ids::ThreadId::new),
        active,
    })
}

/// 按列名取值，失败翻成 [`PortError::Corrupt`]。
///
/// 列名是代码里的字面量，所以能当 `&'static str` 塞进错误；取值一个字都不进。
fn get<'a, T>(row: &'a tokio_postgres::Row, column: &'static str) -> Result<T, PortError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(column).map_err(|error| {
        tracing::error!(
            dependency = DEPENDENCY,
            field = column,
            error = %crate::db::PostgresErrorSummary::from_error(&error),
            "channel 行解码失败"
        );
        PortError::Corrupt {
            dependency: DEPENDENCY,
            field: column,
        }
    })
}

use crate::repo::common::define_table_repo;

define_table_repo!(
    /// `channel_memberships` repository；可见性业务查询仍由 [`ChannelRepo`] 承担。
    ChannelMembershipRepo,
    table = channel_memberships,
    order_by = "\"channel_id\", \"user_id\"",
    find = find_by_key(channel_id: &str, user_id: &str) where "\"channel_id\" = $1 AND \"user_id\" = $2"
);

define_table_repo!(
    /// `channel_agents` repository。
    ChannelAgentRepo,
    table = channel_agents,
    order_by = "\"channel_id\", \"agent_id\"",
    find = find_by_key(channel_id: &str, agent_id: &str) where "\"channel_id\" = $1 AND \"agent_id\" = $2"
);

/// `intelligence_channel_mappings` 的只读 legacy provenance repository。
///
/// 刻意没有 insert/delete：v3 §14.2 已把它降成历史来源，native 请求路径不得再制造或消费
/// live mapping。导入器只读它，最终过保留期后的删除属于独立 destructive migration。
#[derive(Clone)]
pub struct LegacyIntelligenceMappingRepo {
    core: crate::repo::common::RepoCore<crate::db::tables::intelligence_channel_mappings::Row>,
}

impl LegacyIntelligenceMappingRepo {
    /// 用调用方提供的连接池构造。
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            core: crate::repo::common::RepoCore::new(pool),
        }
    }

    /// 按旧复合主键读取。
    pub async fn find_by_key(
        &self,
        user_id: &str,
        channel_id: &str,
    ) -> Result<Option<crate::db::tables::intelligence_channel_mappings::Row>, crate::db::InfraError>
    {
        self.core
            .find(
                "\"user_id\" = $1 AND \"channel_id\" = $2",
                &[&user_id, &channel_id],
            )
            .await
    }

    /// 稳定列出全部 legacy provenance。
    pub async fn list_all(
        &self,
    ) -> Result<Vec<crate::db::tables::intelligence_channel_mappings::Row>, crate::db::InfraError>
    {
        self.core.list("\"user_id\", \"channel_id\"").await
    }
}

impl core::fmt::Debug for LegacyIntelligenceMappingRepo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LegacyIntelligenceMappingRepo")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SQL 文本是编译期常量，且**不含**任何拼接痕迹。
    ///
    /// 判据：外部值只能以 `$n` 出现。`format!` / `push_str` 在这条链路上一次都没有 ——
    /// 这条断言在 SQL 变成运行期拼接的那一刻会红。
    #[test]
    fn the_query_binds_every_external_value_as_a_parameter() {
        for placeholder in ["$1", "$2", "$3", "$4"] {
            assert!(
                LIST_VISIBLE_CHANNELS_SQL.contains(placeholder),
                "缺少绑定参数 {placeholder}",
            );
        }
        assert!(
            !LIST_VISIBLE_CHANNELS_SQL.contains("$5"),
            "多了未使用的参数占位"
        );
        // 正向对照：确实存在一个不在 SQL 里的占位符，说明上一条不是恒真。
        assert!(!LIST_VISIBLE_CHANNELS_SQL.contains("$9"));
    }

    /// R22：可见性只 join membership，绝不 join intelligence_channel_mappings。
    #[test]
    fn the_query_never_joins_the_intelligence_mapping_table() {
        assert!(
            !LIST_VISIBLE_CHANNELS_SQL.contains("intelligence_channel_mappings"),
            "可见性判据混进了 intelligence_channel_mappings（§28.1 R22）",
        );
        // 正向对照：它确实 join 了 membership，所以上一条不是在一条空 SQL 上成立的。
        assert!(LIST_VISIBLE_CHANNELS_SQL.contains("public.channel_memberships"));
    }

    #[test]
    fn scoped_list_and_detail_share_membership_and_native_thread_scope() {
        for sql in [LIST_VISIBLE_CHANNELS_SCOPED_SQL, GET_VISIBLE_CHANNEL_SQL] {
            assert!(sql.contains("public.channel_memberships"));
            assert!(sql.contains("public.threads"));
            assert!(sql.contains("th.deployment_id = $2"));
            assert!(sql.contains("th.tenant_id = $3"));
            assert!(sql.contains("th.anchor_kind = 'channel'"));
            assert!(!sql.contains("intelligence_channel_mappings"));
            assert!(!sql.contains("JOIN public.thread_memberships"));
        }
    }

    /// 限流必须落在 channel 上：`LIMIT` 在 `page` CTE 内，而 agent 在 CTE 之外聚合。
    #[test]
    fn the_limit_applies_to_channels_not_to_channel_agent_pairs() {
        let page_start = LIST_VISIBLE_CHANNELS_SQL
            .find("WITH page AS (")
            .expect("应当有 page CTE");
        let limit = LIST_VISIBLE_CHANNELS_SQL
            .find("LIMIT $4")
            .expect("应当有 LIMIT");
        let lateral = LIST_VISIBLE_CHANNELS_SQL
            .find("LEFT JOIN LATERAL")
            .expect("应当有 LATERAL 聚合");
        assert!(page_start < limit, "LIMIT 必须在 page CTE 内");
        assert!(
            limit < lateral,
            "LIMIT 必须先于 agent 聚合，否则限的就是 channel-agent 对而不是 channel",
        );
    }

    /// 定序与游标判据逐字对齐端口文档。
    #[test]
    fn the_query_orders_and_seeks_by_the_documented_key() {
        assert!(
            LIST_VISIBLE_CHANNELS_SQL
                .contains("ORDER BY coalesce(c.last_message_at, c.created_at) DESC, c.id DESC"),
            "分页段定序不对",
        );
        assert!(
            LIST_VISIBLE_CHANNELS_SQL
                .contains("ORDER BY coalesce(p.last_message_at, p.created_at) DESC, p.id DESC"),
            "外层定序不对：CTE 的顺序不保证穿透到最终结果",
        );
        assert!(
            LIST_VISIBLE_CHANNELS_SQL.contains(
                "(coalesce(c.last_message_at, c.created_at), c.id) < ($2::timestamptz, $3::text)"
            ),
            "keyset 游标判据不对",
        );
        assert!(
            LIST_VISIBLE_CHANNELS_SQL.contains("array_agg(ca.agent_id ORDER BY ca.agent_id)"),
            "agent_ids 必须按 agent_id 升序（上游 asc(channelAgents.agentId)）",
        );
    }
}
