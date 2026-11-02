//! 匿名 auth framing：capabilities、OIDC start、OIDC callback。
//!
//! handler 不做协议判定；全部顺序在 `openbot-infra::auth::oidc::OidcLoginCoordinator`。

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, LOCATION, ORIGIN, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use openbot_contracts::auth::{
    ApplicationRuntimeMode, AuthProviderId, AuthenticationCapabilities, AuthenticationStartResponse,
};
use openbot_infra::auth::oidc::coordinator::DYNAMIC_SSO_LOGIN_BUDGET;
use openbot_infra::auth::oidc::session_issuer::OriginalLoginRequest;
use openbot_infra::auth::oidc::{OidcLoginError, ProviderId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::SESSION_COOKIE_NAME;
use crate::http::ServerState;

/// 未认证能力面；动态企业 IdP 只贡献布尔值。
pub(crate) async fn capabilities(State(state): State<ServerState>) -> Response {
    let surface = state.preauth_surface();
    let dynamic_sso = match state.dynamic_sso() {
        Some(service) => match service.has_any_provider().await {
            Ok(value) => value,
            Err(_) => {
                return auth_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                );
            }
        },
        None => false,
    };
    let auth_providers = match surface
        .provider_ids()
        .iter()
        .map(|provider| provider.parse::<AuthProviderId>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(providers) => providers,
        Err(_) => {
            return auth_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    let capabilities = AuthenticationCapabilities {
        mode: ApplicationRuntimeMode::Rust,
        durable_history: true,
        auth_providers,
        sso_configured: surface.enterprise_sso_available() || dynamic_sso,
    };
    if !capabilities.is_canonical() {
        return auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    }
    let mut response = Json(capabilities).into_response();
    no_store(response.headers_mut());
    response
}

/// 铸造 state/nonce/PKCE 并返回 IdP URL。只接受可信 Origin 的 POST。
pub(crate) async fn start(
    State(state): State<ServerState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
) -> Response {
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return auth_failure(StatusCode::FORBIDDEN, "authentication_origin_rejected");
    };
    if !state.trusts_login_origin(origin) {
        return auth_failure(StatusCode::FORBIDDEN, "authentication_origin_rejected");
    }
    let Some(coordinator) = state.oidc_login() else {
        return auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    let Ok(provider) = ProviderId::parse(&provider_id) else {
        return auth_failure(StatusCode::BAD_REQUEST, "authentication_failed");
    };
    let peer_ip = address.ip().to_string();
    match coordinator
        .start(&provider, OffsetDateTime::now_utc(), &peer_ip)
        .await
    {
        Ok(url) => {
            let mut response = Json(AuthenticationStartResponse {
                url: url.to_string(),
            })
            .into_response();
            no_store(response.headers_mut());
            response
        }
        Err(error) => login_error(error),
    }
}

#[derive(Deserialize)]
/// OAuth/OIDC 标准 callback 参数；描述/URI 字段只接收后丢弃，绝不回显。
pub(crate) struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default, rename = "error_description")]
    _error_description: Option<String>,
    #[serde(default, rename = "error_uri")]
    _error_uri: Option<String>,
    #[serde(default)]
    _iss: Option<String>,
    #[serde(default)]
    _session_state: Option<String>,
}

/// IdP callback：成功写 host-only HttpOnly/Lax cookie，再 303 到应用根。
pub(crate) async fn callback(
    State(state): State<ServerState>,
    Path(provider_id): Path<String>,
    Query(query): Query<CallbackQuery>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let cancel = tokio_util::sync::CancellationToken::new();
    let request = OriginalLoginRequest::new(
        std::time::Instant::now() + DYNAMIC_SSO_LOGIN_BUDGET,
        cancel.clone(),
    );
    let _cancel_on_drop = cancel.drop_guard();
    if query.error.is_some() {
        return auth_failure(StatusCode::BAD_REQUEST, "authentication_failed");
    }
    let (Some(code), Some(csrf_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return auth_failure(StatusCode::BAD_REQUEST, "authentication_failed");
    };
    let Ok(provider) = ProviderId::parse(&provider_id) else {
        return auth_failure(StatusCode::BAD_REQUEST, "authentication_failed");
    };
    let now = OffsetDateTime::now_utc();
    let peer = address.ip().to_string();
    let user_agent = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok());
    if let Some(coordinator) = state.oidc_login()
        && let Some(callback_uri) = coordinator.callback_uri(&provider).map(str::to_owned)
    {
        return match coordinator
            .callback(
                &provider,
                csrf_state,
                code,
                &callback_uri,
                now,
                &peer,
                user_agent,
                request,
            )
            .await
        {
            Ok(issued) => issued_session_response(&state, &issued, now),
            Err(error) => login_error(error),
        };
    }
    let Some(dynamic) = state.dynamic_sso() else {
        return auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    match dynamic
        .oidc_callback(&provider, csrf_state, code, now, &peer, user_agent, request)
        .await
    {
        Ok(issued) => issued_session_response(&state, &issued, now),
        Err(error) => dynamic_login_error(error),
    }
}

pub(crate) fn issued_session_response(
    state: &ServerState,
    issued: &openbot_infra::auth::oidc::IssuedSession,
    now: OffsetDateTime,
) -> Response {
    let Ok(cookie) = session_cookie_header(
        issued.token().expose(),
        issued.expires_at(),
        now,
        state.secure_session_cookie(),
    ) else {
        return auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        );
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_static("/"));
    no_store(response.headers_mut());
    response
}

#[derive(Serialize)]
struct AuthenticationErrorBody {
    code: &'static str,
}

fn login_error(error: OidcLoginError) -> Response {
    if error.rate_limited() {
        auth_failure(StatusCode::TOO_MANY_REQUESTS, "authentication_rate_limited")
    } else if error.dependency_unavailable() {
        auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        )
    } else if error.provider_failure() {
        auth_failure(StatusCode::BAD_GATEWAY, "authentication_unavailable")
    } else if error.access_revoked() {
        auth_failure(StatusCode::FORBIDDEN, "authentication_failed")
    } else {
        auth_failure(StatusCode::BAD_REQUEST, "authentication_failed")
    }
}

pub(crate) fn dynamic_login_error(error: openbot_infra::auth::sso::DynamicSsoError) -> Response {
    if error.rate_limited() {
        auth_failure(StatusCode::TOO_MANY_REQUESTS, "authentication_rate_limited")
    } else if error.dependency_unavailable() {
        auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        )
    } else if error.provider_failure() {
        auth_failure(StatusCode::BAD_GATEWAY, "authentication_unavailable")
    } else if error.conflict() {
        auth_failure(
            StatusCode::CONFLICT,
            "authentication_configuration_conflict",
        )
    } else if error.unknown() {
        auth_failure(StatusCode::NOT_FOUND, "authentication_failed")
    } else {
        auth_failure(StatusCode::BAD_REQUEST, "authentication_failed")
    }
}

fn auth_failure(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(AuthenticationErrorBody { code })).into_response();
    no_store(response.headers_mut());
    response
}

pub(crate) fn no_store(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn session_cookie_header(
    token: &str,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
    secure: bool,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    let max_age = (expires_at - now).whole_seconds().max(0);
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_infra::auth::oidc::OidcError;

    #[test]
    fn cookie_is_host_only_http_only_lax_and_secure_iff_configured() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let secure =
            session_cookie_header("safe_token-123", now + time::Duration::hours(1), now, true)
                .unwrap();
        let secure = secure.to_str().unwrap();
        assert_eq!(
            secure,
            "openbot_session=safe_token-123; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure"
        );
        assert!(!secure.contains("Domain="), "无 Domain 才是 host-only");

        let plain =
            session_cookie_header("safe_token-123", now + time::Duration::hours(1), now, false)
                .unwrap();
        assert!(!plain.to_str().unwrap().contains("Secure"));
        assert!(
            session_cookie_header("line\nbreak", now, now, true).is_err(),
            "header injection 必须在签发侧失败"
        );
    }

    #[test]
    fn token_transport_provider_and_client_failures_keep_distinct_http_classes() {
        assert_eq!(
            login_error(OidcLoginError::Protocol(OidcError::TransportUnavailable)).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            login_error(OidcLoginError::Protocol(OidcError::ProviderResponseInvalid)).status(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            login_error(OidcLoginError::Protocol(OidcError::TokenExchangeRejected)).status(),
            StatusCode::BAD_REQUEST
        );
    }
}
