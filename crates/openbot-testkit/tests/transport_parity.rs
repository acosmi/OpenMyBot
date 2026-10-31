//! **G1 判据第 2 条的执行面**：v3 §24 G1 逐字「ApplicationService 经 Axum/Tauri 结果一致」。
//!
//! # 这条测试到底在证明什么
//!
//! 不是"两个 transport 都能跑通"，而是 v3 §5.2 那句话的反面：
//!
//! > 「Axum、Tauri、测试和迁移工具只做认证、framing、输入大小限制和错误映射，
//! >   不各自实现业务规则。」
//!
//! 所以被测命题是：**没有任何业务规则住在 transport 里**。可见性、分页、`limit` 钳制、
//! 游标解析、错误分类，全部只有一份实现，而两条 transport 只是它的两个入口。
//!
//! # 两条腿共用**同一个实例**，不是两个等价实例
//!
//! [`Fixture`] 只造一个 `Arc<dyn ApplicationService>`，Axum 腿与 in-process 腿各拿一份
//! `Arc::clone`。每次调用都当场重新证明这件事：
//!
//! - in-process 腿：[`InProcessTransport::service`] 交出 `&Arc<…>`，用 [`Arc::ptr_eq`] 断言；
//! - Axum 腿：[`ServerState::application`] 只交出 `&dyn ApplicationService`（它不持有可借出的
//!   `Arc`），所以退一步用 [`core::ptr::addr_eq`] 断言两者指着同一块分配。
//!
//! 少了这一步，"结果一致"可能只是因为两个实例碰巧行为相同 —— 那样的话，业务规则真被抄进
//! 某条 transport 时，这份对拍照样全绿。
//!
//! # 比较什么、不比较什么
//!
//! **必须相同**（[`Outcome`] 承载的就恰好是这些）：
//!
//! | 项 | 形态 |
//! | --- | --- |
//! | 成功应答的语义内容 | `AppReply` —— channel 列表逐字段、`next_cursor` 逐字符 |
//! | 失败的**稳定码** | `ErrorCode::as_str()`（§15.3 的契约面） |
//!
//! 额外还比了一样**不属于判据、但更强**的东西：两条腿递到
//! [`ChannelReader`] 上的调用（actor / limit / cursor）必须逐字段相同（[`PortCall`]）。
//! 它直接照住"transport 偷偷改写了命令"这一类失效 —— 例如自己把 `limit` 钳一次。
//! 这一半有没有牙口由 `the_matrix_goes_red_when_a_transport_substitutes_the_page_size`
//! 单独证明（那条构造的差异**只**落在入参上，结果完全相同）。
//!
//! **允许不同，且在这里显式承认**：
//!
//! | 项 | 只属于哪一侧 | 为什么允许不同 |
//! | --- | --- | --- |
//! | HTTP 状态码 | Axum | §5.2 把"错误映射"列为 transport 的活，映射目标由通道决定 |
//! | HTTP 响应头（`content-type` …） | Axum | framing |
//! | JSON 文本形态 | Axum | framing；in-process 那头压根没有文本 |
//! | 应答外壳 | Axum 返回**裸** `ChannelPage`，in-process 返回 `AppReply::Channels(page)` | 前者是 parity 台账定的线上形状（§15.1），后者是 typed 边界 |
//!
//! `the_comparison_normalizes_away_transport_shape_on_purpose` 把这四条从注释变成断言。
//!
//! ## 归一的方向是**向内**，不是向外
//!
//! 两条腿都归一到 `AppReply` / `ErrorCode` 这一层再比：HTTP 的字节被**反序列化回**
//! typed 值，in-process 的 typed 值原样使用。
//!
//! 刻意**不**做的是反过来 —— 把 in-process 的结果序列化成 JSON 再跟 HTTP 的文本比。
//! 那样做等于在 in-process 这条腿上凭空造出一个编解码器，而 v3 §13.2 的标题就是
//! 「typed in-process，**不复制 JSON-RPC**」；`openbot-desktop` 的依赖图里连
//! `serde` 都没有（由该 crate 的 `the_in_process_lane_has_no_json_codec` 读 `Cargo.toml`
//! 钉住）。为了让对拍"看起来整齐"就把那条禁令绕过去，是拿判据换整齐。
//!
//! # 数据源：确定性内存 fake
//!
//! [`FakeChannels`] 实现 [`ChannelReader`]，不需要数据库。理由：本条判据测的是 **transport
//! 等价性**，不是 SQL 正确性 —— 后者已由 `openbot-infra` 的 `tests/channel_repo.rs`
//! （真 PostgreSQL、`#[ignore]` + `OPENBOT_TEST_DATABASE_URL`）覆盖。
//!
//! fake 刻意**模拟数据库该有的行为**（按排序键定序、按 keyset 裁剪、按 `limit` 截断），
//! 而不是"把我准备好的那几行原样吐回去" —— 后者会让分页对拍在翻页逻辑写反时照样绿。
//!
//! # G1 只有一条命令能同时走两条腿
//!
//! [`http_route_of`] 是这件事的台账：`AppCommand::Health` 在 Axum 侧**没有**落点
//! （`GET /health` 是运维存活探针，恒 200、不碰 `ApplicationService`，见
//! `openbot_server::http::health`），所以矩阵覆盖的是 `ListVisibleChannels` 一条。
//! 那个 match 无通配 —— 新增 `AppCommand` 变体会在这里编译失败，逼作者当场说明它有没有
//! HTTP 腿，而不是让对拍矩阵静默漏掉它。

use core::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{StatusCode, Uri};
use axum::middleware::Next;
use axum::response::Response;
use openbot_application::{
    ApplicationService, ChannelCursor, ChannelReadScope, ChannelReader, DEFAULT_CHANNEL_PAGE,
    OpenBotApplication, PortError, channel_recency,
};
use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::{
    AppCommand, AppReply, ChannelDetailResponse, ChannelPage, ChannelSummary, MAX_CHANNEL_PAGE,
};
use openbot_contracts::error::ErrorCode;
use openbot_contracts::ids::{ActorId, ChannelId, DeploymentId, TenantId};
use openbot_desktop::InProcessTransport;
use openbot_server::auth::FixedAuthResolver;
use openbot_server::{ServerBuilder, ServerState, router};
use time::OffsetDateTime;
use time::macros::datetime;
use tower::ServiceExt as _;

// ===========================================================================
// 夹具数据
// ===========================================================================

/// 有 membership 的第一个 actor：5 行，`last_message_at` 有 NULL 与非 NULL 交错。
const ACTOR_A: &str = "actor-a";
/// 有 membership 的第二个 actor：2 行，与 A 完全不相交。
const ACTOR_B: &str = "actor-b";
/// 一行 membership 都没有的 actor。
const ACTOR_EMPTY: &str = "actor-empty";

/// `auth_generation` 的哨兵值。取一个显眼的数，免得别的断言被普通数字偶然满足。
const SENTINEL_AUTH_GENERATION: u64 = 424_242;

/// 造一行"有过消息"的 channel。
///
/// `created_at` 刻意比 `last_message_at` 早一天：两个时间戳相同的话，排序键取错字段也
/// 测不出来。
fn with_message(id: &str, last_message_at: OffsetDateTime) -> ChannelSummary {
    ChannelSummary {
        id: ChannelId::new(id),
        name: format!("channel {id}"),
        agent_ids: Vec::new(),
        last_message: Some("hi".to_owned()),
        last_message_at: Some(last_message_at),
        last_message_agent_id: None,
        created_at: last_message_at - time::Duration::days(1),
        // G1 还没有 native `threads` 表，本字段恒 None（见 contracts 的字段文档）。
        thread_id: None,
        active: true,
    }
}

/// 造一行"从未有过消息"的 channel —— 排序键回落到 `created_at`。
fn without_message(id: &str, created_at: OffsetDateTime) -> ChannelSummary {
    ChannelSummary {
        id: ChannelId::new(id),
        name: format!("channel {id}"),
        agent_ids: Vec::new(),
        last_message: None,
        last_message_at: None,
        last_message_agent_id: None,
        created_at,
        thread_id: None,
        active: true,
    }
}

/// 夹具全集。
///
/// A 的 5 行 recency 严格递减且 NULL 与非 NULL **交错**（`c-a3` / `c-a5` 没有消息），
/// 于是"排序键取的是 `coalesce(last_message_at, created_at)`"这件事在翻页顺序上可观察 ——
/// 如果哪一层把 NULL 行排到末尾，页边界立刻错位。
fn dataset() -> Vec<(ActorId, ChannelSummary)> {
    let a_rows = [
        with_message("c-a1", datetime!(2026-08-22 04:05:00 UTC)),
        with_message("c-a2", datetime!(2026-08-22 04:04:00 UTC)),
        without_message("c-a3", datetime!(2026-08-22 04:03:00 UTC)),
        with_message("c-a4", datetime!(2026-08-22 04:02:00 UTC)),
        without_message("c-a5", datetime!(2026-08-22 04:01:00 UTC)),
    ];
    let b_rows = [
        with_message("c-b1", datetime!(2026-08-22 09:00:00 UTC)),
        without_message("c-b2", datetime!(2026-08-22 08:00:00 UTC)),
    ];

    let mut rows = Vec::new();
    for (actor, owned) in [(ACTOR_A, a_rows.as_slice()), (ACTOR_B, b_rows.as_slice())] {
        let actor = ActorId::new(actor);
        rows.extend(owned.iter().map(|row| (actor.clone(), row.clone())));
    }
    rows
}

/// A 可见的 5 个 id，按 `coalesce(last_message_at, created_at) DESC, id DESC` 排好。
const A_IDS: &[&str] = &["c-a1", "c-a2", "c-a3", "c-a4", "c-a5"];
/// B 可见的 2 个 id。
const B_IDS: &[&str] = &["c-b1", "c-b2"];

fn auth_for(actor: &str) -> AuthContext {
    AuthContext::for_test(
        DeploymentId::new("dep-g1"),
        TenantId::new("tenant-g1"),
        ActorId::new(actor),
        [Role::Admin, Role::User],
        openbot_contracts::auth::AuthGeneration::new(SENTINEL_AUTH_GENERATION),
        false,
    )
}

// ===========================================================================
// 端口替身
// ===========================================================================

/// 一次落到端口上的调用。
///
/// 记录它是为了回答一个比"结果一样吗"更锋利的问题：**两条 transport 递给 application 的
/// 是不是同一件事**。结果相同而入参不同，说明有一层在替 application 做决定，只是这次
/// 恰好殊途同归。
#[derive(Clone, Debug, PartialEq, Eq)]
struct PortCall {
    actor: ActorId,
    limit: u32,
    cursor: Option<ChannelCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DetailCall {
    scope: ChannelReadScope,
    channel_id: ChannelId,
}

struct FakeState {
    rows: Vec<(ActorId, ChannelSummary)>,
    failure: Mutex<Option<PortError>>,
    calls: Mutex<Vec<PortCall>>,
    detail_calls: Mutex<Vec<DetailCall>>,
}

/// 确定性内存 [`ChannelReader`]。
///
/// `Clone` 共享同一份状态（`Arc`），所以夹具可以一手把它交给 [`OpenBotApplication`]、
/// 一手留着读调用记录 —— 不需要给外部类型实现外部 trait。
#[derive(Clone)]
struct FakeChannels(Arc<FakeState>);

impl FakeChannels {
    fn new(rows: Vec<(ActorId, ChannelSummary)>) -> Self {
        Self(Arc::new(FakeState {
            rows,
            failure: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
            detail_calls: Mutex::new(Vec::new()),
        }))
    }

    /// 让端口恒定失败（`None` = 恢复正常）。
    ///
    /// 做成可切换而不是"另建一个恒失败的 reader"，是为了让**故障用例也跑在同一个
    /// `ApplicationService` 实例上** —— 换实例就等于放弃了本文件最核心的那条前提。
    fn set_failure(&self, failure: Option<PortError>) {
        *self.0.failure.lock().expect("fake 的互斥锁不会中毒") = failure;
    }

    /// 取走并清空迄今为止的调用记录。
    fn drain_calls(&self) -> Vec<PortCall> {
        core::mem::take(&mut *self.0.calls.lock().expect("fake 的互斥锁不会中毒"))
    }

    fn drain_detail_calls(&self) -> Vec<DetailCall> {
        core::mem::take(
            &mut *self
                .0
                .detail_calls
                .lock()
                .expect("fake detail lock is healthy"),
        )
    }
}

#[async_trait]
impl ChannelReader for FakeChannels {
    async fn list_visible_channels(
        &self,
        actor: &ActorId,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        self.0
            .calls
            .lock()
            .expect("fake 的互斥锁不会中毒")
            .push(PortCall {
                actor: actor.clone(),
                limit,
                cursor: cursor.clone(),
            });

        if let Some(failure) = *self.0.failure.lock().expect("fake 的互斥锁不会中毒") {
            return Err(failure);
        }

        // 一、可见性：只认关联表（= materialized membership，§6.5 条 5 / §28.1 R22）。
        let mut visible: Vec<ChannelSummary> = self
            .0
            .rows
            .iter()
            .filter(|(owner, _)| owner == actor)
            .map(|(_, row)| row.clone())
            .collect();

        // 二、定序：coalesce(last_message_at, created_at) DESC, id DESC。
        visible.sort_by(|a, b| (channel_recency(b), &b.id).cmp(&(channel_recency(a), &a.id)));

        // 三、keyset 裁剪：(recency, id) < (cursor.recency, cursor.id)。
        if let Some(cursor) = cursor {
            visible.retain(|row| (channel_recency(row), &row.id) < (cursor.recency, &cursor.id));
        }

        // 四、截断到调用方要的行数（调用方已经把探测用的 +1 算进来了）。
        visible.truncate(limit as usize);
        Ok(visible)
    }

    async fn get_visible_channel(
        &self,
        scope: &ChannelReadScope,
        channel_id: &ChannelId,
    ) -> Result<Option<ChannelSummary>, PortError> {
        self.0
            .detail_calls
            .lock()
            .expect("fake detail lock is healthy")
            .push(DetailCall {
                scope: scope.clone(),
                channel_id: channel_id.clone(),
            });
        if let Some(failure) = *self.0.failure.lock().expect("fake 的互斥锁不会中毒") {
            return Err(failure);
        }
        Ok(self
            .0
            .rows
            .iter()
            .find(|(owner, row)| owner == &scope.actor && &row.id == channel_id)
            .map(|(_, row)| row.clone()))
    }
}

// ===========================================================================
// 归一后的可比结果
// ===========================================================================

/// 两条腿归一之后**唯一**参与比较的东西。
///
/// 它的字段表本身就是"比什么"的定义：没有状态码、没有头部、没有 JSON 文本的位置，
/// 所以那三样**不可能**被偷偷比进来。
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// 成功：typed 应答。
    Reply(Box<AppReply>),
    /// 失败：只有 §15.3 的稳定码。
    Failure { code: String },
}

impl Outcome {
    /// 把 in-process 腿的 `Result` 归一。
    fn from_typed(result: Result<AppReply, openbot_contracts::error::AppError>) -> Self {
        match result {
            Ok(reply) => Self::Reply(Box::new(reply)),
            Err(error) => Self::Failure {
                code: error.code().as_str().to_owned(),
            },
        }
    }

    /// 把 Axum 腿的响应归一。
    ///
    /// 200 的 body 是**裸** `ChannelPage`（parity 台账定的线上形状，没有信封），这里把它
    /// 装回 `AppReply::Channels` —— 那一层外壳是 framing 差异，不是语义差异。
    fn from_http(status: StatusCode, body: &str) -> Self {
        if status == StatusCode::OK {
            if body.starts_with("{\"channel\":") {
                let detail: ChannelDetailResponse = serde_json::from_str(body)
                    .unwrap_or_else(|e| panic!("200 detail body must decode: {e}; source {body}"));
                return Self::Reply(Box::new(AppReply::Channel(detail.channel)));
            }
            let page: ChannelPage = serde_json::from_str(body)
                .unwrap_or_else(|e| panic!("200 的 body 必须能解回 ChannelPage：{e}；原文 {body}"));
            return Self::Reply(Box::new(AppReply::Channels(page)));
        }

        let envelope: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("错误 body 必须是 JSON：{e}；原文 {body}"));
        let code = envelope
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("错误信封必须有 code：{body}"));
        Self::Failure {
            code: code.to_owned(),
        }
    }

    /// 取出 channel id 列表（正向对照用）。
    fn channel_ids(&self) -> Vec<&str> {
        match self {
            Self::Reply(reply) => match reply.as_ref() {
                AppReply::Channels(page) => {
                    page.channels.iter().map(|row| row.id.as_str()).collect()
                }
                _ => panic!("不是一页 channel：{self:?}"),
            },
            _ => panic!("不是一页 channel：{self:?}"),
        }
    }

    fn next_cursor(&self) -> Option<&str> {
        match self {
            Self::Reply(reply) => match reply.as_ref() {
                AppReply::Channels(page) => page.next_cursor.as_deref(),
                _ => panic!("不是一页 channel：{self:?}"),
            },
            _ => panic!("不是一页 channel：{self:?}"),
        }
    }
}

/// Axum 腿的完整观察 —— 除了 [`Outcome`]，还带着**只属于 HTTP 的那几样**。
struct HttpLeg {
    status: StatusCode,
    content_type: Option<String>,
    body: String,
    outcome: Outcome,
}

// ===========================================================================
// 命令 → Axum 落点的台账
// ===========================================================================

/// 每个 [`AppCommand`] 变体在 Axum 侧的落点。
///
/// **穷举 match 无通配**：新增变体会在这里编译失败，逼作者当场说明它有没有 HTTP 腿。
/// 少了它，一条新命令可以悄无声息地只走 in-process，而这份对拍仍然全绿。
fn http_route_of(command: &AppCommand) -> Option<String> {
    match command {
        // `GET /health` 是运维**存活**探针：恒 200、不取 `ServerState`、不经
        // `ApplicationService`（见 `openbot_server::http::health`）。所以
        // `AppCommand::Health` 在 Axum 侧没有落点，不进对拍矩阵。
        AppCommand::Health => None,
        AppCommand::ListVisibleChannels { limit, cursor } => {
            let mut uri = String::from("/api/channels");
            let mut sep = '?';
            if let Some(limit) = limit {
                write!(uri, "{sep}limit={limit}").expect("写进 String 不会失败");
                sep = '&';
            }
            if let Some(cursor) = cursor {
                // 游标是 base64url（`URL_SAFE_NO_PAD`），落在 URI unreserved 字符集里，
                // 不需要百分号编码。这条断言不是仪式：哪天游标换了形态（例如带上 `=`
                // padding 或 `+`），这里必须当场红，而不是拼出一个坏 URI 之后让对拍
                // 在"两条腿都 400"的世界里假绿。
                assert!(
                    cursor
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                    "游标必须是 URL-safe 的，否则本 URI 拼装失效：{cursor}"
                );
                write!(uri, "{sep}cursor={cursor}").expect("写进 String 不会失败");
            }
            Some(uri)
        }
        AppCommand::GetVisibleChannel { channel_id } => {
            assert!(
                channel_id
                    .as_str()
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
                "matrix channel id must be one URI-safe segment"
            );
            Some(format!("/api/channels/{}", channel_id.as_str()))
        }
        // People/audit/policy/thread/MCP/approval/UI preference/model-connection 的 HTTP 腿
        // 由同目录专项 transport parity 或各自 handler framing 测试覆盖；本文件只维护
        // channel 专项矩阵。ModelConnection 的 5 个变体由
        // `openbot-server/tests/model_connections_http_postgres.rs` 的真实 PG+HTTP 旅程
        // （`GET/POST /api/me/model-connections`、`GET/PUT/DELETE
        // /api/me/model-connections/{connection_id}`）覆盖。
        // Artifact has dedicated transport_artifact_parity.rs framing evidence.
        // Runtime capabilities have separate current-host fact transport tests.
        // Custom catalog uses dedicated Server/Local custom_model_catalog_tests; this
        // channel-only matrix does not claim its current-host delivery acceptance.
        // InvokeTool 尚无公开 HTTP 路由。仍逐变体列出且无 wildcard：新增命令必须在这里明确
        // 选择“channel 矩阵有 route”或“由哪一份专项证据承担”。
        AppCommand::GetCurrentUser
        | AppCommand::ListModelConnections(_)
        | AppCommand::ListCustomModelCatalog(_)
        | AppCommand::GetModelConnection { .. }
        | AppCommand::CreateModelConnection(_)
        | AppCommand::UpdateModelConnection { .. }
        | AppCommand::DeleteModelConnection { .. }
        | AppCommand::CreateChannel { .. }
        | AppCommand::RouteChannelMessage { .. }
        | AppCommand::ListVisibleAgents { .. }
        | AppCommand::GetVisibleAgent { .. }
        | AppCommand::CreateAgent(_)
        | AppCommand::UpdateAgent { .. }
        | AppCommand::DuplicateAgent { .. }
        | AppCommand::SetAgentHidden { .. }
        | AppCommand::DeleteAgent { .. }
        | AppCommand::TestAgentConnection(_)
        | AppCommand::ListComponents
        | AppCommand::SyncComponentCatalogue(_)
        | AppCommand::UpdateComponentGovernance(_)
        | AppCommand::ListComponentsForAgent { .. }
        | AppCommand::DecideComponent { .. }
        | AppCommand::ListComponentDataFunctions
        | AppCommand::CallComponentFunction { .. }
        | AppCommand::AwaitComponentHumanDecision(_)
        | AppCommand::ListPendingComponentHumanDecisions
        | AppCommand::ResolveComponentHumanDecision { .. }
        | AppCommand::ListSandboxedComponents
        | AppCommand::ListPublishedSandboxedComponents
        | AppCommand::SaveSandboxedComponent(_)
        | AppCommand::PublishSandboxedComponent { .. }
        | AppCommand::DeleteSandboxedComponent { .. }
        | AppCommand::AuthorizeSandboxedComponent { .. }
        | AppCommand::AdminStatus
        | AppCommand::ListPeople { .. }
        | AppCommand::ChangePersonRole { .. }
        | AppCommand::ChangePersonAccess { .. }
        | AppCommand::ListAuditEvents { .. }
        | AppCommand::GetActionPolicy
        | AppCommand::SetActionPolicy { .. }
        | AppCommand::InvokeTool(_)
        | AppCommand::MintThreadId
        | AppCommand::GetThreadStatus { .. }
        | AppCommand::BeginThreadRun(_)
        | AppCommand::BeginThreadRunV2(_)
        | AppCommand::CancelThreadRun(_)
        | AppCommand::DeleteThreadHistory { .. }
        | AppCommand::GetThreadHistory { .. }
        | AppCommand::GetThreadConversation { .. }
        | AppCommand::GetRunReconciliation { .. }
        | AppCommand::GetRunEffectReceipts { .. }
        | AppCommand::SaveRunMessageTextArtifact(_)
        | AppCommand::GetArtifactMetadata(_)
        | AppCommand::GetSourceRunArtifactIds(_)
        | AppCommand::GetArtifactSaveReceipt(_)
        | AppCommand::OpenArtifactRead(_)
        | AppCommand::ReadArtifactReadBlock(_)
        | AppCommand::AcknowledgeArtifactReadBlock(_)
        | AppCommand::CloseArtifactRead(_)
        | AppCommand::GetRuntimeCapabilities
        | AppCommand::RememberMemory(_)
        | AppCommand::GetMemoryControl
        | AppCommand::UpdateMemoryControl(_)
        | AppCommand::ListMemories { .. }
        | AppCommand::CorrectMemory { .. }
        | AppCommand::MutateMemory { .. }
        | AppCommand::RecallMemories(_)
        | AppCommand::IssueAgentCallbackToken { .. }
        | AppCommand::RevokeAgentCallbackToken { .. }
        | AppCommand::ListMcpConnections
        | AppCommand::ListCredentials(_)
        | AppCommand::CreateCredential(_)
        | AppCommand::RotateCredential { .. }
        | AppCommand::RevokeCredential { .. }
        | AppCommand::ListMcpAdminPage
        | AppCommand::BeginMcpOAuth { .. }
        | AppCommand::DisconnectMcpConnection { .. }
        | AppCommand::RegisterMcpOAuthClient { .. }
        | AppCommand::AddCuratedMcpServer { .. }
        | AppCommand::AddCustomMcpServer(_)
        | AppCommand::RemoveMcpServer { .. }
        | AppCommand::RefreshMcpServer { .. }
        | AppCommand::SavePluginSkill(_)
        | AppCommand::RemovePluginSkill { .. }
        | AppCommand::GrantPlugin(_)
        | AppCommand::RevokePlugin(_)
        | AppCommand::ListPluginsForAgent { .. }
        | AppCommand::ListPendingToolApprovals
        | AppCommand::DecideToolApproval { .. }
        | AppCommand::GetUiPreferences
        | AppCommand::UpdateUiPreferences(_)
        | AppCommand::GetRunCostBudget
        | AppCommand::ReplaceRunCostBudget(_)
        | AppCommand::IssueScreenSession(_)
        | AppCommand::ListPendingRemoteInterrupts
        | AppCommand::ResolveRemoteInterrupt { .. } => None,
    }
}

// ===========================================================================
// 夹具：一个 service，两条腿
// ===========================================================================

struct Fixture {
    /// **唯一**的业务实例。两条腿各持一份 `Arc::clone`。
    service: Arc<dyn ApplicationService>,
    reader: FakeChannels,
    transport: InProcessTransport,
}

impl Fixture {
    fn new() -> Self {
        let reader = FakeChannels::new(dataset());
        let service: Arc<dyn ApplicationService> =
            Arc::new(OpenBotApplication::new(reader.clone()));
        let transport = InProcessTransport::new(Arc::clone(&service));
        Self {
            service,
            reader,
            transport,
        }
    }

    /// 给某个 actor 组一份 Axum state。
    ///
    /// 每个 actor 一份是因为 [`FixedAuthResolver`] 恒定放行成**一个**身份；变的只有认证层，
    /// 业务实例始终是 [`Self::service`] 那一个。
    fn server_state_for(&self, actor: &str) -> ServerState {
        ServerBuilder::new(
            Arc::clone(&self.service),
            Arc::new(FixedAuthResolver::granting(auth_for(actor))),
        )
        .build()
    }

    /// Axum 腿：`tower::ServiceExt::oneshot` 在内存里打 router，不监听端口。
    async fn via_http(&self, actor: &str, command: &AppCommand) -> HttpLeg {
        let state = self.server_state_for(actor);

        // 每次调用都重新证明"Axum 腿指着的就是那一个实例"。`ServerState` 只交出
        // `&dyn ApplicationService`（它不持有可借出的 `Arc`），所以用 `addr_eq` 比
        // 分配地址；in-process 腿那边能拿到 `Arc`，用的是 `Arc::ptr_eq`。
        assert!(
            core::ptr::addr_eq(Arc::as_ptr(&self.service), state.application()),
            "Axum 腿必须指向同一个 ApplicationService 实例，否则'结果一致'不构成证据"
        );

        let uri = http_route_of(command).expect("矩阵里的命令必须有 Axum 落点");
        let request = Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .expect("请求构造合法");
        Self::send(router(state), request).await
    }

    /// 带自定义中间件的 Axum 腿（只给负向对照用，见
    /// `the_matrix_goes_red_when_a_business_rule_moves_into_the_transport`）。
    async fn via_tampered_http(&self, actor: &str, command: &AppCommand) -> HttpLeg {
        let state = self.server_state_for(actor);
        let uri = http_route_of(command).expect("矩阵里的命令必须有 Axum 落点");
        let tampered = router(state).layer(axum::middleware::from_fn(clamp_limit_in_transport));
        let request = Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .expect("请求构造合法");
        Self::send(tampered, request).await
    }

    async fn send(router: Router, request: Request) -> HttpLeg {
        let response = router
            .oneshot(request)
            .await
            .expect("Axum service 不会失败");
        let status = response.status();
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("响应体读得完");
        let body = String::from_utf8(bytes.to_vec()).expect("响应体是 UTF-8");
        let outcome = Outcome::from_http(status, &body);
        HttpLeg {
            status,
            content_type,
            body,
            outcome,
        }
    }

    /// in-process 腿：经 [`InProcessTransport`] 直接 typed 调用，全程零序列化。
    async fn via_in_process(&self, actor: &str, command: &AppCommand) -> Outcome {
        assert!(
            Arc::ptr_eq(&self.service, self.transport.service()),
            "in-process 腿必须指向同一个 ApplicationService 实例"
        );
        Outcome::from_typed(
            self.transport
                .execute(auth_for(actor), command.clone())
                .await,
        )
    }

    /// 跑一个用例：两条腿各跑一次，顺带各自抓一份端口调用记录。
    async fn run(&self, actor: &str, command: &AppCommand) -> LegPair {
        // 先清干净，免得上一个用例的记录混进来。
        self.reader.drain_calls();
        self.reader.drain_detail_calls();
        let http = self.via_http(actor, command).await;
        let http_calls = self.reader.drain_calls();
        let http_detail_calls = self.reader.drain_detail_calls();
        let in_process = self.via_in_process(actor, command).await;
        let in_process_calls = self.reader.drain_calls();
        let in_process_detail_calls = self.reader.drain_detail_calls();
        LegPair {
            http,
            http_calls,
            http_detail_calls,
            in_process,
            in_process_calls,
            in_process_detail_calls,
        }
    }
}

struct LegPair {
    http: HttpLeg,
    http_calls: Vec<PortCall>,
    http_detail_calls: Vec<DetailCall>,
    in_process: Outcome,
    in_process_calls: Vec<PortCall>,
    in_process_detail_calls: Vec<DetailCall>,
}

/// 对拍本体。**矩阵里每一条、以及负向对照，用的都是这一个函数。**
///
/// 负向对照之所以有意义，正是因为它调用的不是另一个"演示用"的比较器，而是这一个。
#[track_caller]
fn assert_legs_agree(case: &str, pair: &LegPair) {
    assert_eq!(
        pair.http.outcome, pair.in_process,
        "[{case}] Axum 腿与 in-process 腿归一后的结果必须逐字段相等"
    );
    assert_eq!(
        pair.http_calls, pair.in_process_calls,
        "[{case}] 两条腿递到 ChannelReader 上的调用必须逐字段相同 —— \
         不同即说明有一层 transport 在替 application 改写命令"
    );
    assert_eq!(
        pair.http_detail_calls, pair.in_process_detail_calls,
        "[{case}] both legs must pass the same authoritative detail scope and channel id"
    );
}

// ===========================================================================
// 期望（正向对照）
// ===========================================================================

/// 每条用例的**期望**。
///
/// 它的存在理由只有一个：只断言"两条腿相同"的测试，在"两条腿都返回空 / 都不执行"的
/// 世界里同样通过。所以每条用例都additionally 对**两条腿各自**断言一次它到底拿到了什么。
enum Expect {
    /// 成功：期望的 id 序列（逐字逐序），以及 `next_cursor` 是否非空。
    Channels {
        ids: &'static [&'static str],
        has_next_cursor: bool,
    },
    /// 失败：期望的稳定码。
    Failure(ErrorCode),
}

#[track_caller]
fn assert_expectation(case: &str, side: &str, outcome: &Outcome, expect: &Expect) {
    match expect {
        Expect::Channels {
            ids,
            has_next_cursor,
        } => {
            assert_eq!(
                outcome.channel_ids(),
                *ids,
                "[{case}/{side}] channel 序列必须逐字逐序相符"
            );
            assert_eq!(
                outcome.next_cursor().is_some(),
                *has_next_cursor,
                "[{case}/{side}] next_cursor 的有无必须相符"
            );
        }
        Expect::Failure(code) => {
            assert_eq!(
                outcome,
                &Outcome::Failure {
                    code: code.as_str().to_owned()
                },
                "[{case}/{side}] 必须以这个稳定码失败"
            );
        }
    }
}

// ===========================================================================
// 1. 同一实例
// ===========================================================================

/// 两条腿共用**同一个** `Arc<dyn ApplicationService>`，不是两个等价实例。
///
/// 负向对照在同一条里：另造一个实例，断言指针**不**相等 —— 否则本断言在
/// "`ptr_eq` / `addr_eq` 恒真"的世界里同样通过。
#[tokio::test]
async fn both_legs_share_one_application_instance() {
    let fx = Fixture::new();

    assert!(
        Arc::ptr_eq(&fx.service, fx.transport.service()),
        "in-process 腿必须持有同一个 Arc"
    );

    let state = fx.server_state_for(ACTOR_A);
    assert!(
        core::ptr::addr_eq(Arc::as_ptr(&fx.service), state.application()),
        "Axum 腿必须指向同一块分配"
    );

    // 负向对照：另一个实例确实比不相等。
    let other: Arc<dyn ApplicationService> =
        Arc::new(OpenBotApplication::new(FakeChannels::new(dataset())));
    assert!(!Arc::ptr_eq(&other, fx.transport.service()));
    assert!(!core::ptr::addr_eq(
        Arc::as_ptr(&other),
        state.application()
    ));
}

#[tokio::test]
async fn channel_detail_has_the_same_typed_result_and_port_scope_on_both_legs() {
    let fx = Fixture::new();
    let command = AppCommand::GetVisibleChannel {
        channel_id: ChannelId::new("c-a1"),
    };
    let pair = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("channel detail", &pair);
    for outcome in [&pair.http.outcome, &pair.in_process] {
        match outcome {
            Outcome::Reply(reply) => match reply.as_ref() {
                AppReply::Channel(detail) if detail.id == ChannelId::new("c-a1") => {}
                other => panic!("channel detail reply drifted: {other:?}"),
            },
            other => panic!("channel detail unexpectedly failed: {other:?}"),
        }
    }
    assert_eq!(
        pair.http_detail_calls,
        vec![DetailCall {
            scope: ChannelReadScope {
                deployment: DeploymentId::new("dep-g1"),
                tenant: TenantId::new("tenant-g1"),
                actor: ActorId::new(ACTOR_A),
            },
            channel_id: ChannelId::new("c-a1"),
        }]
    );
}

// ===========================================================================
// 2. 对拍矩阵
// ===========================================================================

/// 一个坏游标：合法 base64url（长度 18、字符全在 URL-safe 字母表里），解出来不是 JSON。
const TAMPERED_GARBAGE: &str = "not-a-valid-cursor";

/// 矩阵主体 —— 每一项两条腿都跑。
///
/// 覆盖清单（与 v3 §24 G1 判据第 2 条的验收面逐条对应）：
///
/// 1. 空结果（零 channel）
/// 2. 非空结果（多条，`last_message_at` NULL 与非 NULL 交错）
/// 3. `limit` 越界（`999999`）⇒ 两条腿被 application 截断到同一个数
/// 4. 篡改游标（两种形态）⇒ 两条腿都 400 `malformed_payload`
/// 5. port 故障 ⇒ 两条腿都 503 `dependency_unavailable`
/// 6. 可见性：A 与 B 各自只看到自己的
///
/// 分页与末页在 [`pagination_walks_identically_on_both_legs`]（它必须按序走，塞不进
/// 这张平表）。
#[tokio::test]
async fn transport_parity_matrix() {
    let fx = Fixture::new();

    // --- 1. 空结果 -------------------------------------------------------
    let command = AppCommand::ListVisibleChannels {
        limit: None,
        cursor: None,
    };
    let pair = fx.run(ACTOR_EMPTY, &command).await;
    assert_legs_agree("空结果", &pair);
    assert_expectation(
        "空结果",
        "http",
        &pair.http.outcome,
        &Expect::Channels {
            ids: &[],
            has_next_cursor: false,
        },
    );
    assert_expectation(
        "空结果",
        "in-process",
        &pair.in_process,
        &Expect::Channels {
            ids: &[],
            has_next_cursor: false,
        },
    );

    // --- 2. 非空结果（NULL 与非 NULL 交错）--------------------------------
    //
    // 这一条同时是上一条的正向对照：数据源确实不是空的，"两条腿都空所以相等"这个
    // 平凡世界被排除掉。
    let pair = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("非空结果", &pair);
    let non_empty = Expect::Channels {
        ids: A_IDS,
        has_next_cursor: false,
    };
    assert_expectation("非空结果", "http", &pair.http.outcome, &non_empty);
    assert_expectation("非空结果", "in-process", &pair.in_process, &non_empty);
    // 交错确实存在：`c-a3` / `c-a5` 没有 `last_message_at`，却排在中间而不是末尾。
    assert!(matches!(
        &pair.http.outcome,
        Outcome::Reply(reply)
            if matches!(reply.as_ref(), AppReply::Channels(page)
                if page.channels[2].last_message_at.is_none()
                    && page.channels[4].last_message_at.is_none()
                    && page.channels[0].last_message_at.is_some())
    ));

    // --- 3. limit 越界 ---------------------------------------------------
    //
    // 判据不只是"结果一样"，更是"两条腿把**同一个**被钳过的数递给了端口"：
    // 期望 `MAX_CHANNEL_PAGE + 1`（那个 +1 是 application 的下一页探针）。
    let out_of_range = AppCommand::ListVisibleChannels {
        limit: Some(999_999),
        cursor: None,
    };
    let pair = fx.run(ACTOR_A, &out_of_range).await;
    assert_legs_agree("limit 越界", &pair);
    assert_expectation("limit 越界", "http", &pair.http.outcome, &non_empty);
    assert_expectation("limit 越界", "in-process", &pair.in_process, &non_empty);
    let clamped = MAX_CHANNEL_PAGE + 1;
    assert_eq!(pair.http_calls.len(), 1);
    assert_eq!(
        pair.http_calls[0].limit, clamped,
        "Axum 腿必须把 999999 原样交给 application，由 application 钳到 {MAX_CHANNEL_PAGE}"
    );
    assert_eq!(pair.in_process_calls[0].limit, clamped);
    // 负向对照：那个数既不是调用方要的，也不是默认页大小 —— 说明钳制真的发生了，
    // 而且发生在 application 而不是某条 transport 上。
    assert_ne!(pair.http_calls[0].limit, 999_999 + 1);
    assert_ne!(pair.http_calls[0].limit, 51);

    // --- 4. 篡改游标 ------------------------------------------------------
    let good_cursor = {
        let paged = fx
            .run(
                ACTOR_A,
                &AppCommand::ListVisibleChannels {
                    limit: Some(2),
                    cursor: None,
                },
            )
            .await;
        paged
            .in_process
            .next_cursor()
            .expect("limit=2 必须给出下一页游标")
            .to_owned()
    };
    for (label, tampered) in [
        ("坏游标/非 JSON", TAMPERED_GARBAGE.to_owned()),
        // 合法 base64url，但解出来在 `}` 之后多了 3 个字节 —— serde_json 拒绝尾随内容。
        ("坏游标/尾随字节", format!("{good_cursor}AAAA")),
    ] {
        let command = AppCommand::ListVisibleChannels {
            limit: None,
            cursor: Some(tampered),
        };
        let pair = fx.run(ACTOR_A, &command).await;
        assert_legs_agree(label, &pair);
        let expect = Expect::Failure(ErrorCode::MALFORMED_PAYLOAD);
        assert_expectation(label, "http", &pair.http.outcome, &expect);
        assert_expectation(label, "in-process", &pair.in_process, &expect);
        // §15.3：malformed payload 不产生 acting decision —— 端口一次都没被碰。
        assert!(pair.http_calls.is_empty(), "[{label}] Axum 腿不该碰端口");
        assert!(pair.in_process_calls.is_empty());
        // 只属于 HTTP 那一侧的信息（不参与对拍，但确实是 400 而不是 500）。
        assert_eq!(pair.http.status, StatusCode::BAD_REQUEST);
    }
    // 正向对照：同一个**未被篡改**的游标确实能用 —— 上面两条不是在
    // "任何游标都会被拒"的世界里成立的。
    let pair = fx
        .run(
            ACTOR_A,
            &AppCommand::ListVisibleChannels {
                limit: None,
                cursor: Some(good_cursor),
            },
        )
        .await;
    assert_legs_agree("好游标", &pair);
    assert_eq!(pair.in_process.channel_ids(), ["c-a3", "c-a4", "c-a5"]);

    // --- 5. port 故障 -----------------------------------------------------
    fx.reader.set_failure(Some(PortError::Unavailable {
        dependency: "database",
    }));
    let pair = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("port 故障", &pair);
    let expect = Expect::Failure(ErrorCode::DEPENDENCY_UNAVAILABLE);
    assert_expectation("port 故障", "http", &pair.http.outcome, &expect);
    assert_expectation("port 故障", "in-process", &pair.in_process, &expect);
    assert_eq!(pair.http.status, StatusCode::SERVICE_UNAVAILABLE);
    // 依赖名不出边界（§15.3 的投影面只有 code / rule）。
    assert!(!pair.http.body.contains("database"), "{}", pair.http.body);
    fx.reader.set_failure(None);
    // 正向对照：故障确实被解除了，同一条腿又能出数 —— 免得后面的用例在
    // "端口恒失败"的世界里假绿。
    let pair = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("故障解除", &pair);
    assert_eq!(pair.in_process.channel_ids(), A_IDS);

    // --- 6. 可见性 --------------------------------------------------------
    let pair_a = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("可见性/A", &pair_a);
    let pair_b = fx.run(ACTOR_B, &command).await;
    assert_legs_agree("可见性/B", &pair_b);
    for (case, pair, ids) in [("可见性/A", &pair_a, A_IDS), ("可见性/B", &pair_b, B_IDS)] {
        let expect = Expect::Channels {
            ids,
            has_next_cursor: false,
        };
        assert_expectation(case, "http", &pair.http.outcome, &expect);
        assert_expectation(case, "in-process", &pair.in_process, &expect);
    }
    // 两个 actor 各自都**非空**且互不相交 —— 「各自只看到自己的」不是靠"谁都看不到"成立的。
    let a_ids = pair_a.in_process.channel_ids();
    let b_ids = pair_b.in_process.channel_ids();
    assert!(!a_ids.is_empty() && !b_ids.is_empty());
    assert!(a_ids.iter().all(|id| !b_ids.contains(id)));
    // 权威 actor 来自 `AuthContext`，两条腿递下去的都是它。
    assert_eq!(pair_a.http_calls[0].actor, ActorId::new(ACTOR_A));
    assert_eq!(pair_b.http_calls[0].actor, ActorId::new(ACTOR_B));
}

// ===========================================================================
// 3. 分页 / 末页
// ===========================================================================

/// `limit=2` 逐页走完 A 的 5 行：两条腿**每一页**的内容、游标、端口调用都相同，
/// 末页的 `next_cursor` 两条腿都是 `None`。
///
/// 这条必须按序走（第 N 页的游标来自第 N-1 页的应答），所以塞不进上面那张平表。
#[tokio::test]
async fn pagination_walks_identically_on_both_legs() {
    let fx = Fixture::new();

    let expected_pages: [&[&str]; 3] = [&["c-a1", "c-a2"], &["c-a3", "c-a4"], &["c-a5"]];
    let mut cursor: Option<String> = None;
    let mut collected: Vec<String> = Vec::new();

    for (index, expected) in expected_pages.iter().enumerate() {
        let case = format!("第 {} 页", index + 1);
        let command = AppCommand::ListVisibleChannels {
            limit: Some(2),
            cursor: cursor.clone(),
        };
        let pair = fx.run(ACTOR_A, &command).await;
        assert_legs_agree(&case, &pair);

        let last_page = index + 1 == expected_pages.len();
        let expect = Expect::Channels {
            ids: expected,
            has_next_cursor: !last_page,
        };
        assert_expectation(&case, "http", &pair.http.outcome, &expect);
        assert_expectation(&case, "in-process", &pair.in_process, &expect);

        // 两条腿拿到的是**同一个**游标（逐字符），而不只是"都非空"。
        assert_eq!(
            pair.http.outcome.next_cursor(),
            pair.in_process.next_cursor(),
            "[{case}] nextCursor 必须逐字符相同"
        );
        // 端口那侧看到的翻页锚点也必须是同一个（typed 二元组，不是字符串）。
        assert_eq!(pair.http_calls[0].cursor, pair.in_process_calls[0].cursor);

        collected.extend(
            pair.in_process
                .channel_ids()
                .iter()
                .map(|s| (*s).to_owned()),
        );
        cursor = pair.in_process.next_cursor().map(str::to_owned);
    }

    // 末页：`next_cursor` 两条腿都是 None（上面 `has_next_cursor: false` 已断言），
    // 且整趟翻页不重不漏 —— keyset 分页的正向对照。
    assert!(cursor.is_none(), "末页之后不该再有游标");
    assert_eq!(collected, A_IDS);
}

// ===========================================================================
// 4. 命令台账
// ===========================================================================

/// 每个 [`AppCommand`] 变体在 Axum 侧有没有落点，必须有明确答案。
///
/// 这条把 [`http_route_of`] 的穷举 match 从"编译期强制"补成"行为可读"：G1 的两个变体
/// 各自的答案写在断言里，`Health` 没有 HTTP 腿这件事是**登记过的事实**，不是遗漏。
#[test]
fn every_command_variant_is_accounted_for() {
    assert_eq!(
        http_route_of(&AppCommand::Health),
        None,
        "GET /health 不经 ApplicationService，所以 AppCommand::Health 没有 Axum 落点"
    );
    assert_eq!(
        http_route_of(&AppCommand::ListVisibleChannels {
            limit: None,
            cursor: None
        })
        .as_deref(),
        Some("/api/channels")
    );
    assert_eq!(
        http_route_of(&AppCommand::ListVisibleChannels {
            limit: Some(7),
            cursor: Some("abc-_".to_owned())
        })
        .as_deref(),
        Some("/api/channels?limit=7&cursor=abc-_")
    );
    assert_eq!(
        http_route_of(&AppCommand::ListVisibleChannels {
            limit: None,
            cursor: Some("abc".to_owned())
        })
        .as_deref(),
        Some("/api/channels?cursor=abc")
    );
}

// ===========================================================================
// 5. 显式承认两条腿"允许不同"的那部分
// ===========================================================================

/// 归一之前，两条腿**本来就不一样**；对拍把这些差异挡在门外是刻意的，不是疏忽。
#[tokio::test]
async fn the_comparison_normalizes_away_transport_shape_on_purpose() {
    let fx = Fixture::new();
    let command = AppCommand::ListVisibleChannels {
        limit: Some(2),
        cursor: None,
    };
    let pair = fx.run(ACTOR_A, &command).await;

    // (a) HTTP 有状态码。in-process 没有 —— 它的成功与失败由 `Result` 承载。
    assert_eq!(pair.http.status, StatusCode::OK);

    // (b) HTTP 有响应头。
    assert!(
        pair.http
            .content_type
            .as_deref()
            .is_some_and(|value| value.starts_with("application/json")),
        "content-type 实际是 {:?}",
        pair.http.content_type
    );

    // (c) HTTP 有 JSON **文本**形态，且是 parity 台账定的裸 `ChannelPage`（camelCase、
    //     无信封）。in-process 那头一个字节的文本都没有。
    assert!(pair.http.body.starts_with('{'));
    assert!(pair.http.body.contains("\"channels\""));
    assert!(pair.http.body.contains("\"nextCursor\""));
    assert!(
        !pair.http.body.contains("\"kind\""),
        "线上形状是裸 ChannelPage，不带 AppReply 的 tag：{}",
        pair.http.body
    );

    // (d) in-process 是 typed 值，带着 `AppReply` 的外壳。
    assert!(matches!(
        &pair.in_process,
        Outcome::Reply(reply) if matches!(reply.as_ref(), AppReply::Channels(_))
    ));

    // 归一之后（HTTP 的字节**反序列化回** typed 值，in-process 的 typed 值原样使用），
    // 两者相等。注意方向：从来没有把 in-process 的结果序列化成 JSON 去凑 HTTP 的文本 ——
    // 那会在这条腿上凭空造出 §13.2 逐字禁止的 JSON 编解码。
    assert_eq!(pair.http.outcome, pair.in_process);

    // 错误路径同理：HTTP 额外有一个 400，in-process 只有稳定码，对拍只看后者。
    let bad = AppCommand::ListVisibleChannels {
        limit: None,
        cursor: Some(TAMPERED_GARBAGE.to_owned()),
    };
    let pair = fx.run(ACTOR_A, &bad).await;
    assert_eq!(pair.http.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        pair.in_process,
        Outcome::Failure {
            code: ErrorCode::MALFORMED_PAYLOAD.as_str().to_owned()
        }
    );
    assert_eq!(pair.http.outcome, pair.in_process);
}

// ===========================================================================
// 6. 负向对照：这套装置真的能照出"业务规则漏进 transport"
// ===========================================================================

/// 一条**故意把业务规则搬进 transport** 的中间件：它自作主张把查询串改写成 `limit=1`。
///
/// 这正是 §5.2 逐字禁止的形态 —— transport 替 application 决定了分页大小。
async fn clamp_limit_in_transport(mut request: Request, next: Next) -> Response {
    *request.uri_mut() = "/api/channels?limit=1"
        .parse::<Uri>()
        .expect("字面量是合法 URI");
    next.run(request).await
}

/// 把 [`catch_unwind`] 收到的 payload 还原成人能读的文本。
///
/// `assert_eq!` 的 payload 是 `String`；手写 `panic!("字面量")` 的是 `&'static str`。
/// 两种都要取，否则"判红了"这件事会在其中一种形态下退化成 `<非字符串 panic>`。
fn panic_message(payload: &(dyn core::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    "<非字符串 panic>".to_owned()
}

/// **判据不是恒真**：把一条业务规则搬进 Axum 腿，对拍必须当场判红。
///
/// 只断言"两条腿相同"的测试，在"两条腿都返回空 / 都不执行"的世界里同样通过。这一条
/// 用的是矩阵里那个**同一个** [`assert_legs_agree`]，所以它证明的是那个函数真的有牙口，
/// 而不是另造一个演示用的比较器。
///
/// 篡改的作用域被构造性地限死：中间件只挂在 [`Fixture::via_tampered_http`] 现造的那个
/// router 上，而每次 HTTP 调用都新造一个 router。最后一段把同一条用例再走一遍普通腿，
/// 断言它又绿了 —— 这就是"跑完还原"的证据。
#[tokio::test]
async fn the_matrix_goes_red_when_a_business_rule_moves_into_the_transport() {
    let fx = Fixture::new();
    let command = AppCommand::ListVisibleChannels {
        limit: None,
        cursor: None,
    };

    // 先确认这条用例在**没有**篡改时是绿的（正向对照）。
    let clean = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("负向对照/篡改前", &clean);
    assert_eq!(clean.in_process.channel_ids(), A_IDS);

    // 现在让 Axum 腿"自己实现业务规则"。
    fx.reader.drain_calls();
    let http = fx.via_tampered_http(ACTOR_A, &command).await;
    let http_calls = fx.reader.drain_calls();
    let in_process = fx.via_in_process(ACTOR_A, &command).await;
    let in_process_calls = fx.reader.drain_calls();
    let tampered = LegPair {
        http,
        http_calls,
        http_detail_calls: Vec::new(),
        in_process,
        in_process_calls,
        in_process_detail_calls: Vec::new(),
    };

    // 篡改确实生效了（否则下面的"判红"会在"什么都没变"的世界里失败，那是另一回事）。
    assert_eq!(
        tampered.http.outcome.channel_ids(),
        ["c-a1"],
        "中间件必须真的把 limit 改成了 1"
    );
    assert_eq!(tampered.in_process.channel_ids(), A_IDS);

    let red = catch_unwind(AssertUnwindSafe(|| {
        assert_legs_agree("负向对照/业务规则漏进 transport", &tampered);
    }))
    .expect_err("对拍装置必须当场判红 —— 它没判红就说明这套装置照不出这类缺陷");

    let message = panic_message(red.as_ref());
    println!("--- 负向对照：对拍装置的真实判红输出 ---\n{message}\n--- 判红输出结束 ---");
    assert!(
        message.contains("归一后的结果必须逐字段相等"),
        "判红必须来自对拍断言本身，实际是：{message}"
    );

    // 还原：中间件从来没有被装进 `Fixture` 的常规腿上（每次 HTTP 调用现造 router），
    // 所以同一条用例立刻又是绿的。
    let restored = fx.run(ACTOR_A, &command).await;
    assert_legs_agree("负向对照/还原后", &restored);
    assert_eq!(restored.in_process.channel_ids(), A_IDS);
    assert_eq!(restored.http.outcome.channel_ids(), A_IDS);
}

/// **第二条负向对照**：结果一模一样，但 transport 替 application 填了页大小 ——
/// 只比结果的对拍会放它过去，端口调用那一半必须把它拦下来。
///
/// 为什么需要这一条：[`assert_legs_agree`] 有两半，上一条负向对照只证明了**第一半**
/// （结果）有牙口。第二半（端口调用）如果是装饰性的，没有任何现有测试会发现 ——
/// 它在两条腿结果相同的世界里恒真。
///
/// 构造：夹具恰好有 5 行，所以"默认 50"与"被替换成 5"给出**完全相同**的一页
/// （5 行、`next_cursor` 为 `None`）。差异只留在递给 [`ChannelReader`] 的 `limit` 上：
/// 51（50 + 探针）对 6（5 + 探针）。
#[tokio::test]
async fn the_matrix_goes_red_when_a_transport_substitutes_the_page_size() {
    let fx = Fixture::new();
    let honest = AppCommand::ListVisibleChannels {
        limit: None,
        cursor: None,
    };
    // in-process 腿"自作主张"把默认页大小定成 5，而不是把 `None` 原样交给 application。
    let substituted = AppCommand::ListVisibleChannels {
        limit: Some(5),
        cursor: None,
    };

    fx.reader.drain_calls();
    let http = fx.via_http(ACTOR_A, &honest).await;
    let http_calls = fx.reader.drain_calls();
    let in_process = fx.via_in_process(ACTOR_A, &substituted).await;
    let in_process_calls = fx.reader.drain_calls();
    let pair = LegPair {
        http,
        http_calls,
        http_detail_calls: Vec::new(),
        in_process,
        in_process_calls,
        in_process_detail_calls: Vec::new(),
    };

    // 结果那一半确实**相等** —— 这正是本条存在的理由。
    assert_eq!(pair.http.outcome, pair.in_process);
    assert_eq!(pair.in_process.channel_ids(), A_IDS);
    // 入参那一半不同。
    assert_eq!(pair.http_calls[0].limit, DEFAULT_CHANNEL_PAGE + 1);
    assert_eq!(pair.in_process_calls[0].limit, 5 + 1);

    let red = catch_unwind(AssertUnwindSafe(|| {
        assert_legs_agree("负向对照/页大小被 transport 替换", &pair);
    }))
    .expect_err("端口调用对拍必须当场判红 —— 否则它就是一条装饰性断言");

    let message = panic_message(red.as_ref());
    println!("--- 负向对照 2：端口调用对拍的真实判红输出 ---\n{message}\n--- 判红输出结束 ---");
    assert!(
        message.contains("必须逐字段相同"),
        "判红必须来自端口调用那一半，实际是：{message}"
    );

    // 还原：`substituted` 只是本条测试自己造的一个命令，从来没有进过 `Fixture` 的常规腿。
    let restored = fx.run(ACTOR_A, &honest).await;
    assert_legs_agree("负向对照 2/还原后", &restored);
}
