//! `AppError` → HTTP 的**投影**（v3 §15.3）。
//!
//! # 投影，不是序列化
//!
//! `AppError` 是**服务端**的类型：它带着 dependency 名、vendor 名、lease holder 的
//! `ActorId`、policy decision id。这些是给日志与审计的，不是给客户端的。所以本模块做的
//! 事是**挑出可以出边界的那几样**，而不是把错误 serde 出去。
//!
//! 普通错误出边界为稳定码与 policy rule；artifact gone 另带封闭 deleted/expired status。
//! 配置 CAS 冲突另投影封闭的当前版本快照：
//! `{currentRevision, currentSha256, updatedAt}`，由已授权的 Application 路径构造。
//!
//! | 字段 | 为什么可以出去 |
//! | --- | --- |
//! | `code` | §15.3 逐字要求它是稳定契约；GUI 按 code 本地化文案（repository contract §4a） |
//! | `rule`（仅 `PolicyRefused`） | §15.3 逐字要求「policy refusal 403 + stable error code/rule ID」；它是管理员编写的**标识符**，不随 locale 变化 |
//! | `status`（仅 `ArtifactGone`） | R424 的封闭 deleted/expired 状态，不带内容或来源身份 |
//!
//! 逐条说明**没有**出去的：
//!
//! - `dependency` / `vendor`：依赖名泄漏部署拓扑（`openbot_contracts::command::HealthReport`
//!   的类型文档为同一理由拒绝在探活应答里列依赖明细）。
//! - `holder`（`LeaseConflict`）：contracts 的字段文档逐字写着「**transport 不得把它回给
//!   调用方** —— 那会泄漏同租户内其他 actor 的存在；它只进受控日志」。
//! - `decision`（`PolicyRefused`）：durable decision 的 id 属于审计面，客户端拿它没有用途，
//!   而它能被用来探测服务端到底写没写决策行。
//! - `required`（`ForbiddenRole`）与 `field`（`MalformedPayload`）：两者都是取值有界的
//!   `&'static str`，回给客户端**并不危险**，甚至对调试友好。但它们一旦出现在响应里就是
//!   契约（客户端会开始依赖），而 §15.3 没有要求它们。**扩投影面是一次要立 ledger 条目的
//!   决定，不由 transport 顺手做** —— 所以这里刻意不投影，留给需要它的那条 ledger。
//! - `expected` / `observed`（`StaleGeneration`）：同上，且它们会泄漏权威方的代际进度。
//!
//! # 文案一个字都没有
//!
//! 本模块产出的 body 里不存在任何自然语言。repository contract §4a：文案不进 domain / application，
//! 错误以 code 穿越边界后在 GUI 本地化。`AppError` 的 `Display` **只进日志**。

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use openbot_contracts::artifacts::ArtifactGoneStatus;
use openbot_contracts::error::AppError;
use serde::Serialize;

/// `AppError` 的 HTTP 外壳。
///
/// 单字段 newtype 而不是直接给 `AppError` 实现 `IntoResponse`：`AppError` 住在
/// `openbot-contracts`，而 contracts 必须 wasm 可编、不许依赖 axum。孤儿规则也不允许
/// 在本 crate 给外部类型实现外部 trait。
#[derive(Debug)]
pub struct HttpError(AppError);

impl HttpError {
    /// 借出被包裹的错误（日志与测试用）。
    #[must_use]
    pub const fn inner(&self) -> &AppError {
        &self.0
    }
}

impl From<AppError> for HttpError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

/// 出边界的错误载荷：code，或 policy rule，或 artifact 的封闭 gone status。
///
/// `deny_unknown_fields` 在这里没有意义（它只出不进），但字段的**私有性**有：本结构体
/// 不 `pub`，外部无法在别处构造一个多带几项的变体。
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    /// 稳定错误码（§15.3）。
    code: &'static str,
    /// policy 规则 ID，仅 `PolicyRefused` 有。
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    /// Only a current-authorized deleted/expired artifact exposes this closed state.
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<ArtifactGoneStatus>,
}

/// 把 §15.3 的状态码值域翻译成 `StatusCode`。
///
/// `AppError::http_status` 返回 `u16` 且值域由 `HTTP_STATUS_DOMAIN` 固定，所以
/// `from_u16` 在每个变体上都成功 —— 由 `every_app_error_status_is_a_valid_status_code`
/// 逐变体钉住，那条测试让下面的 `unwrap_or` 分支成为**可证明不可达**的兜底，而不是
/// 一条没人知道会不会触发的静默降级。
///
/// 兜底取 500 而不是 panic：一个错误映射把进程打死，比多回一个状态码糟糕得多。
fn status_of(error: &AppError) -> StatusCode {
    StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = status_of(&self.0);

        // 完整错误只进受控日志。`Display` 会带上 dependency / vendor / holder / rule ——
        // contracts 的类型文档明说它「供日志用，**不供 UI 直接显示**」，这里就是那个"日志"。
        tracing::warn!(
            error.code = self.0.code().as_str(),
            error.detail = %self.0,
            http.status_code = status.as_u16(),
            "请求以 AppError 收场"
        );

        if let AppError::StaleGeneration {
            subject: openbot_contracts::error::StaleGenerationSubject::Configuration { snapshot },
        } = self.0
        {
            let mut response = (status, Json(snapshot)).into_response();
            response.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            return response;
        }

        if let AppError::ThreadNotIdle {
            foreground,
            pending_inputs,
        } = &self.0
        {
            let mut response = (status, Json(serde_json::json!({"code":self.0.code().as_str(),"foreground":foreground,"pendingInputs":pending_inputs}))).into_response();
            response.headers_mut().insert(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_static("no-store"),
            );
            return response;
        }
        let (rule, gone_status) = match &self.0 {
            AppError::PolicyRefused { rule, .. } => (Some(rule.as_str()), None),
            AppError::ArtifactGone { status } => (None, Some(*status)),
            AppError::Unauthenticated
            | AppError::ForbiddenRole { .. }
            | AppError::NotVisible
            | AppError::MalformedPayload { .. }
            | AppError::AnchorUnsupported
            | AppError::PendingInputLimit
            | AppError::PendingInputState
            | AppError::ThreadNotIdle { .. }
            | AppError::DependencyUnavailable { .. }
            | AppError::VendorFailure { .. }
            | AppError::StaleGeneration { .. }
            | AppError::RequestConflict { .. }
            | AppError::LeaseConflict { .. }
            | AppError::IdentityConflict { .. }
            | AppError::SensitiveWriteRefused { .. }
            | AppError::ReconciliationRequired { .. } => (None, None),
        };

        let body = ErrorBody {
            code: self.0.code().as_str(),
            rule,
            status: gone_status,
        };
        let mut response = (status, Json(body)).into_response();
        response.headers_mut().insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use openbot_contracts::auth::Role;
    use openbot_contracts::error::{ErrorCode, StaleGenerationSubject};
    use openbot_contracts::ids::{ActorId, ComputerGeneration, PolicyDecisionId};

    #[tokio::test]
    async fn authorized_revision_conflict_has_the_closed_snapshot_body() {
        let snapshot = openbot_contracts::revision::RevisionSnapshot::from_public(
            2,
            time::OffsetDateTime::UNIX_EPOCH,
            &serde_json::json!({"revision":2}),
        )
        .unwrap();
        let (status, body) = render(AppError::StaleGeneration {
            subject: openbot_contracts::error::StaleGenerationSubject::Configuration { snapshot },
        })
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::to_value(snapshot).unwrap()
        );
    }

    /// 本模块的变体台账。与 contracts 里那份是**两份独立台账**，刻意不共享：
    /// contracts 的那份是 `#[cfg(test)]` 私有的，跨 crate 借不到。新增变体会在
    /// `into_response` 的穷举 match 里先编译失败，这里只负责断言运行期行为。
    fn all_variants() -> Vec<AppError> {
        vec![
            AppError::ThreadNotIdle {
                foreground: None,
                pending_inputs: 1,
            },
            AppError::Unauthenticated,
            AppError::ForbiddenRole {
                required: Role::Admin,
            },
            AppError::NotVisible,
            AppError::ArtifactGone {
                status: ArtifactGoneStatus::Deleted,
            },
            AppError::ArtifactGone {
                status: ArtifactGoneStatus::Expired,
            },
            AppError::MalformedPayload { field: "cursor" },
            AppError::PolicyRefused {
                rule: "browser.navigate.deny_private_hosts".to_owned(),
                decision: Some(PolicyDecisionId::new("pd-secret-1")),
            },
            AppError::DependencyUnavailable {
                dependency: "database",
            },
            AppError::VendorFailure {
                vendor: "some_provider",
            },
            AppError::StaleGeneration {
                subject: StaleGenerationSubject::Computer {
                    expected: ComputerGeneration::new(7),
                    observed: ComputerGeneration::new(6),
                },
            },
            AppError::RequestConflict { resource: "run" },
            AppError::LeaseConflict {
                holder: Some(ActorId::new("actor-other-tenant-user")),
            },
            AppError::IdentityConflict {
                reason: openbot_contracts::error::IdentityConflictReason::RoleLastAdmin,
            },
            AppError::SensitiveWriteRefused {
                reason: openbot_contracts::error::SensitiveWriteReason::OriginUntrusted,
            },
            AppError::ReconciliationRequired { accepted: true },
            AppError::ReconciliationRequired { accepted: false },
        ]
    }

    async fn render(error: AppError) -> (StatusCode, String) {
        let response = HttpError::from(error).into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("错误响应体必然读得完");
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("响应体是 UTF-8"),
        )
    }

    /// §15.3 的状态码值域全部能翻译成合法 `StatusCode` —— `status_of` 的 500 兜底不可达。
    #[test]
    fn every_app_error_status_is_a_valid_status_code() {
        for error in all_variants() {
            let raw = error.http_status();
            let status = StatusCode::from_u16(raw)
                .unwrap_or_else(|_| panic!("{} 的状态码 {raw} 不是合法 HTTP 状态码", error.code()));
            assert_eq!(status.as_u16(), raw);
            assert_eq!(status_of(&error), status);
            assert_ne!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{} 落到了 500 兜底 —— §15.3 的值域里没有 500",
                error.code()
            );
        }
    }

    /// 每个变体的 body 都**恰好**带自己的稳定码（正向对照：body 不是空的）。
    #[tokio::test]
    async fn every_variant_body_carries_its_stable_code() {
        for error in all_variants() {
            let expected = error.code().as_str().to_owned();
            let (_, body) = render(error).await;
            assert!(
                body.contains(&format!(r#""code":"{expected}""#)),
                "{expected} 的 body 里没有稳定码：{body}"
            );
        }
    }

    /// 负向：内部细节一个都不出边界。
    ///
    /// **正向对照就在同一条里** —— 每次断言"没有 X"的同时断言"有稳定码"。没有它，
    /// 这些 `assert!(!contains)` 在"body 恒为空"的世界里全部通过。
    #[tokio::test]
    async fn internal_details_never_reach_the_client() {
        // 依赖名（部署拓扑）。
        let (status, body) = render(AppError::DependencyUnavailable {
            dependency: "database",
        })
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!body.contains("database"), "依赖名泄漏了部署拓扑：{body}");
        assert!(body.contains("dependency_unavailable"), "{body}");

        // vendor 名。
        let (_, body) = render(AppError::VendorFailure {
            vendor: "some_provider",
        })
        .await;
        assert!(!body.contains("some_provider"), "{body}");
        assert!(body.contains("vendor_failure"), "{body}");

        // lease holder —— contracts 逐字禁止回给调用方。
        let (status, body) = render(AppError::LeaseConflict {
            holder: Some(ActorId::new("actor-other-tenant-user")),
        })
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            !body.contains("actor-other-tenant-user"),
            "lease holder 泄漏了同租户内其他 actor 的存在：{body}"
        );
        assert!(body.contains("lease_conflict"), "{body}");

        // 代际进度。
        let (_, body) = render(AppError::StaleGeneration {
            subject: StaleGenerationSubject::Computer {
                expected: ComputerGeneration::new(7),
                observed: ComputerGeneration::new(6),
            },
        })
        .await;
        assert!(!body.contains('7'), "{body}");
        assert!(body.contains("stale_generation"), "{body}");

        // 角色要求与畸形字段名 —— 见模块文档：不是危险，是"不扩投影面"。
        let (_, body) = render(AppError::ForbiddenRole {
            required: Role::Admin,
        })
        .await;
        assert!(!body.contains("admin"), "{body}");
        assert!(body.contains("forbidden_role"), "{body}");

        let (_, body) = render(AppError::MalformedPayload { field: "cursor" }).await;
        assert!(!body.contains("cursor"), "{body}");
        assert!(body.contains("malformed_payload"), "{body}");
    }

    /// `PolicyRefused` 的 rule 出去，decision 不出去。
    #[tokio::test]
    async fn policy_refusal_projects_the_rule_id_but_not_the_decision_id() {
        let (status, body) = render(AppError::PolicyRefused {
            rule: "browser.navigate.deny_private_hosts".to_owned(),
            decision: Some(PolicyDecisionId::new("pd-secret-1")),
        })
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // 正向：§15.3 逐字要求 rule id 出边界。
        assert!(
            body.contains("browser.navigate.deny_private_hosts"),
            "{body}"
        );
        assert!(body.contains(ErrorCode::POLICY_REFUSED.as_str()), "{body}");
        // 负向：decision id 属于审计面。
        assert!(!body.contains("pd-secret-1"), "{body}");
    }

    #[tokio::test]
    async fn artifact_gone_projects_only_closed_state_and_no_store() {
        for status in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
            let response = HttpError::from(AppError::ArtifactGone { status }).into_response();
            assert_eq!(response.status(), StatusCode::GONE);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
            let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                serde_json::json!({"code":"artifact_gone","status":status})
            );
        }
    }

    /// 只有 `PolicyRefused` 带 `rule` 键；其余变体连键都不出现（不是 `"rule":null`）。
    #[tokio::test]
    async fn rule_key_is_absent_for_every_other_variant() {
        let (_, refused) = render(AppError::PolicyRefused {
            rule: "r-1".to_owned(),
            decision: None,
        })
        .await;
        assert!(refused.contains(r#""rule":"r-1""#), "{refused}");

        for error in all_variants() {
            if matches!(error, AppError::PolicyRefused { .. }) {
                continue;
            }
            let code = error.code();
            let (_, body) = render(error).await;
            assert!(!body.contains("rule"), "{code} 不该带 rule 键：{body}");
        }
    }

    /// `ReconciliationRequired` 的两态状态码不同 —— §15.3「不伪装 500 或 success」。
    #[tokio::test]
    async fn reconciliation_keeps_its_two_statuses() {
        let (accepted, _) = render(AppError::ReconciliationRequired { accepted: true }).await;
        assert_eq!(accepted, StatusCode::ACCEPTED);
        let (rejected, _) = render(AppError::ReconciliationRequired { accepted: false }).await;
        assert_eq!(rejected, StatusCode::CONFLICT);
        assert_ne!(accepted, rejected);
    }

    /// body 是 JSON，且 Content-Type 是 `application/json`。
    #[tokio::test]
    async fn error_body_is_json() {
        let response = HttpError::from(AppError::NotVisible).into_response();
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let bytes = to_bytes(response.into_body(), 1024).await.expect("读得完");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("body 必须是 JSON");
        assert_eq!(value, serde_json::json!({ "code": "not_visible" }));
    }
}
