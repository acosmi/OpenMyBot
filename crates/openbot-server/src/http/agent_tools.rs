//! Remote Agent tool-callback framing and credential boundary.
//!
//! The handler authenticates both callback credentials, then delegates to the same governed Agent
//! gateway and ApplicationService pipeline used by built-in runs. It owns no alternate executor.

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use http::HeaderMap;
use openbot_agent::AgentToolInvokeError;
use openbot_contracts::error::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::HttpError;
use crate::http::ServerState;

/// Callback request compatible with the fixed upstream route, with unknown fields rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackBody {
    /// Offered tool name; validation occurs after credential verification.
    pub name: Option<String>,
    /// Tool arguments. It must be an object once a real granted tool is connected.
    pub args: Option<Value>,
    /// Opaque signed assertion; non-string/missing receives the same 401 as a bad token.
    pub run: Option<Value>,
}

impl core::fmt::Debug for CallbackBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallbackBody")
            .field("name", &self.name)
            .field("args", &"[redacted]")
            .field("run", &"[redacted]")
            .finish()
    }
}

/// Future success shape retained now so clients do not need another wire change when RMCP lands.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackResult {
    /// Redacted model-visible text.
    pub text: String,
    /// Whether the governed executor reported an error.
    pub is_error: bool,
}

/// `POST /api/agent-tools/call`.
pub async fn call(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: Result<Json<CallbackBody>, JsonRejection>,
) -> Result<Json<CallbackResult>, HttpError> {
    let Json(body) = body.map_err(|rejection| {
        tracing::debug!(rejection = %rejection, "remote callback body 解析失败");
        AppError::MalformedPayload { field: "body" }
    })?;
    let authenticator =
        state
            .remote_callback_authenticator()
            .ok_or(AppError::DependencyUnavailable {
                dependency: "remote_callback_auth",
            })?;
    let token = headers
        .get("x-openbot-agent-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let null = Value::Null;
    let run = body.run.as_ref().unwrap_or(&null);
    let tool_name = body.name.as_deref().unwrap_or("");
    let authorization = authenticator
        .authorize(token, run, tool_name)
        .await
        .map_err(|error| error.into_app_error())?;
    let tools = state
        .remote_callback_tools()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "remote_callback_executor",
        })?;
    let arguments = body.args.unwrap_or_else(|| serde_json::json!({}));
    let reply = tools
        .invoke_callback(authorization, tool_name, arguments)
        .await
        .map_err(|error| match error {
            AgentToolInvokeError::DelegationNotCurrent => AppError::PolicyRefused {
                rule: "delegation_not_current".to_owned(),
                decision: None,
            },
            AgentToolInvokeError::Unavailable => AppError::DependencyUnavailable {
                dependency: "remote_callback_executor",
            },
            AgentToolInvokeError::ReconciliationRequired => {
                AppError::ReconciliationRequired { accepted: true }
            }
        })?;
    Ok(Json(CallbackResult {
        text: reply.content().to_owned(),
        is_error: reply.error_code().is_some(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use http::{Request, StatusCode};
    use openbot_application::{
        ChannelCursor, ChannelReader, OpenBotApplication, PortError, RemoteCallbackAuthError,
        RemoteCallbackAuthenticator, RemoteCallbackAuthorization,
    };
    use openbot_contracts::auth::{AuthContext, AuthGeneration, Role};
    use openbot_contracts::command::ChannelSummary;
    use openbot_contracts::ids::{ActorId, DeploymentId, TenantId};
    use tower::ServiceExt as _;

    use super::*;
    use crate::auth::FixedAuthResolver;
    use crate::http::{ServerBuilder, router};

    #[derive(Clone, Copy)]
    struct EmptyChannels;

    #[async_trait]
    impl ChannelReader for EmptyChannels {
        async fn list_visible_channels(
            &self,
            _actor: &ActorId,
            _limit: u32,
            _cursor: Option<ChannelCursor>,
        ) -> Result<Vec<ChannelSummary>, PortError> {
            Ok(Vec::new())
        }
    }

    struct FakeAuthenticator {
        error: RemoteCallbackAuthError,
        calls: Mutex<Vec<(usize, Value, String)>>,
    }

    #[async_trait]
    impl RemoteCallbackAuthenticator for FakeAuthenticator {
        async fn authorize(
            &self,
            token: &str,
            run: &Value,
            tool: &str,
        ) -> Result<RemoteCallbackAuthorization, RemoteCallbackAuthError> {
            self.calls
                .lock()
                .unwrap()
                .push((token.len(), run.clone(), tool.to_owned()));
            Err(self.error)
        }
    }

    fn context() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::Admin],
            AuthGeneration::new(0),
            true,
        )
    }

    fn app(authenticator: Option<Arc<FakeAuthenticator>>) -> axum::Router {
        let mut builder = ServerBuilder::new(
            Arc::new(OpenBotApplication::new(EmptyChannels)),
            Arc::new(FixedAuthResolver::granting(context())),
        );
        if let Some(authenticator) = authenticator {
            builder = builder.with_remote_callback_authenticator(authenticator);
        }
        router(builder.build())
    }

    async fn send(router: axum::Router, token: Option<&str>, body: &str) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/agent-tools/call")
            .header(http::header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            request = request.header("x-openbot-agent-token", token);
        }
        let response = router
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn callback_http_maps_auth_classes_without_echoing_credentials() {
        for (error, expected) in [
            (
                RemoteCallbackAuthError::Unauthenticated,
                StatusCode::UNAUTHORIZED,
            ),
            (RemoteCallbackAuthError::BotMismatch, StatusCode::FORBIDDEN),
            (
                RemoteCallbackAuthError::ToolNotVisible,
                StatusCode::NOT_FOUND,
            ),
            (
                RemoteCallbackAuthError::InvalidInput { field: "name" },
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let authenticator = Arc::new(FakeAuthenticator {
                error,
                calls: Mutex::new(Vec::new()),
            });
            let token = "obot_agt_secret-that-must-not-return";
            let assertion = "signed-run-that-must-not-return";
            let (status, body) = send(
                app(Some(authenticator.clone())),
                Some(token),
                &serde_json::json!({"name":"mcp__drive__search","args":{},"run":assertion})
                    .to_string(),
            )
            .await;
            assert_eq!(status, expected);
            let rendered = body.to_string();
            assert!(!rendered.contains(token));
            assert!(!rendered.contains(assertion));
            assert_eq!(authenticator.calls.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn malformed_body_stops_before_auth_and_missing_authenticator_is_503() {
        let authenticator = Arc::new(FakeAuthenticator {
            error: RemoteCallbackAuthError::Unauthenticated,
            calls: Mutex::new(Vec::new()),
        });
        let (status, _) = send(app(Some(authenticator.clone())), None, "not-json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(authenticator.calls.lock().unwrap().is_empty());

        let (status, _) = send(app(None), None, r#"{"name":"x","args":{},"run":null}"#).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn callback_body_debug_redacts_args_and_run() {
        let body = CallbackBody {
            name: Some("x".to_owned()),
            args: Some(serde_json::json!({"secret":"ARG-CANARY"})),
            run: Some(Value::String("RUN-CANARY".to_owned())),
        };
        let rendered = format!("{body:?}");
        assert!(!rendered.contains("ARG-CANARY"));
        assert!(!rendered.contains("RUN-CANARY"));
    }
}
