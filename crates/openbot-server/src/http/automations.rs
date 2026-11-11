//! Owner-scoped automation HTTP framing; commands retain all persistence and authority decisions.

use crate::{
    auth::{Authenticated, FreshOriginAuthenticated, OriginAuthenticated, SensitiveAuthenticated},
    error::HttpError,
    http::ServerState,
};
use axum::{
    Json,
    body::Body,
    extract::{Path, Query, RawQuery, State, rejection::QueryRejection},
};
use futures_core::Stream as _;
use http::{
    HeaderMap, StatusCode,
    header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, HeaderValue, ORIGIN},
};
use openbot_contracts::{
    automation::*,
    command::{AppCommand, AppReply},
    error::AppError,
};
use serde::{
    Deserialize,
    de::{DeserializeOwned, IgnoredAny},
};

/// Register only the delivered management/manual/read surface in this Server process.
pub(crate) fn routes(state: ServerState) -> axum::Router {
    use axum::routing::{MethodFilter, on, post};
    axum::Router::new()
        .route(
            "/api/automations",
            on(MethodFilter::GET, list)
                .post(create)
                .on(MethodFilter::HEAD, head_not_allowed),
        )
        .route(
            "/api/automations/{id}",
            on(MethodFilter::GET, get)
                .patch(update)
                .delete(tombstone)
                .on(MethodFilter::HEAD, head_not_allowed),
        )
        .route("/api/automations/{id}/runs", post(trigger))
        .route(
            "/api/automations/{id}/occurrences",
            on(MethodFilter::GET, occurrences).on(MethodFilter::HEAD, head_not_allowed),
        )
        .route(
            "/api/automations/{id}/deliveries",
            on(MethodFilter::GET, deliveries).on(MethodFilter::HEAD, head_not_allowed),
        )
        .route(
            "/api/automation-deliveries/{id}",
            on(MethodFilter::GET, receipt).on(MethodFilter::HEAD, head_not_allowed),
        )
        .route("/api/automations/{id}/receivers", post(create_receiver))
        .route(
            "/api/automation-receivers/{id}/rotate-key",
            post(rotate_receiver_key),
        )
        .route(
            "/api/automation-receivers/{id}",
            axum::routing::delete(revoke_receiver),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn(bounded_request))
}

async fn head_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

pub(super) async fn bounded_request(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut response =
        match tokio::time::timeout(std::time::Duration::from_secs(5), next.run(request)).await {
            Ok(response) => response,
            Err(_) => HttpError::from(AppError::DependencyUnavailable {
                dependency: "automation_request",
            })
            .into_response(),
        };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

const MAX_MANAGEMENT_BODY_BYTES: usize = 64 * 1024;
const MAX_JSON_DEPTH: usize = 16;

/// List only the current owner's definitions under a closed keyset query.
pub async fn list(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    query: Result<Query<ListAutomationDefinitions>, QueryRejection>,
) -> Result<Json<AutomationDefinitionPage>, HttpError> {
    let Query(query) = query.map_err(|_| malformed("query"))?;
    match state
        .application()
        .execute(auth, AppCommand::ListAutomationDefinitions(query))
        .await?
    {
        AppReply::AutomationDefinitions(page) => Ok(Json(page)),
        _ => Err(contract_error()),
    }
}

/// Create a paused definition, or return the same original creation without claiming a new write.
pub async fn create(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    RawQuery(query): RawQuery,
    request_headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<AutomationDefinition>), HttpError> {
    reject_query(query)?;
    let input = json_input::<CreateAutomationDefinition>(&request_headers, body).await?;
    match state
        .application()
        .execute(auth, AppCommand::CreateAutomationDefinition(input))
        .await?
    {
        AppReply::AutomationDefinitionCreated(row) => Ok((StatusCode::CREATED, Json(row))),
        AppReply::AutomationDefinition(row) => Ok((StatusCode::OK, Json(row))),
        _ => Err(contract_error()),
    }
}

/// Read one current-owner definition; a candidate ID never grants access.
pub async fn get(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
) -> Result<Json<AutomationDefinition>, HttpError> {
    reject_query(query)?;
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let reply = state
        .application()
        .execute(auth, AppCommand::GetAutomationDefinition { automation_id })
        .await?;
    Ok(Json(definition(reply)?))
}

/// Resolve the real session once; enable additionally requires its existing fresh-Origin guard.
pub async fn update(
    State(state): State<ServerState>,
    SensitiveAuthenticated(resolved): SensitiveAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<Json<AutomationDefinition>, HttpError> {
    let origin = request_headers
        .get(ORIGIN)
        .map(|v| v.to_str().unwrap_or(""));
    state
        .inner
        .sensitive_write
        .as_ref()
        .ok_or(AppError::DependencyUnavailable {
            dependency: "sensitive_write_security",
        })?
        .authorize_origin(origin)?;
    reject_query(query)?;
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let input = json_input::<UpdateAutomationDefinition>(&request_headers, body).await?;
    if matches!(&input, UpdateAutomationDefinition::Enable { .. }) {
        state
            .authorize_fresh_origin_write(&resolved, origin)
            .await?;
    } else {
        state.inner.auth.touch(&resolved).await?;
    }
    let reply = state
        .application()
        .execute(
            resolved.into_context(),
            AppCommand::UpdateAutomationDefinition {
                automation_id,
                input,
            },
        )
        .await?;
    Ok(Json(definition(reply)?))
}

/// Retire the namespace using the owner's observed revision; receipts remain readable.
pub async fn tombstone(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<Json<AutomationDefinition>, HttpError> {
    reject_query(query)?;
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let input = json_input::<TombstoneAutomationDefinition>(&request_headers, body).await?;
    let reply = state
        .application()
        .execute(
            auth,
            AppCommand::TombstoneAutomationDefinition {
                automation_id,
                input,
            },
        )
        .await?;
    Ok(Json(definition(reply)?))
}

/// Accept only manual intent from the current owner, with no event data or model override.
pub async fn trigger(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<AutomationReceipt>), HttpError> {
    reject_query(query)?;
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let input = json_input::<ManualInput>(&request_headers, body).await?;
    if input.supersedes_receipt_id {
        return Err(AppError::UnknownDispositionUnavailable.into());
    }
    let input = TriggerAutomationDefinition {
        operation_id: input.operation_id,
        expected_revision: input.expected_revision,
    };
    match state
        .application()
        .execute(
            auth,
            AppCommand::TriggerAutomationDefinition {
                automation_id,
                input,
            },
        )
        .await?
    {
        AppReply::AutomationReceiptAccepted(row) => Ok((StatusCode::ACCEPTED, Json(row))),
        AppReply::AutomationReceipt(row) => Ok((StatusCode::OK, Json(row))),
        _ => Err(contract_error()),
    }
}

/// Read the exact accepted manual/cron/event occurrence projections without creating work.
pub async fn occurrences(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(id): Path<String>,
    query: Result<Query<AutomationPageQuery>, QueryRejection>,
) -> Result<Json<AutomationOccurrencePage>, HttpError> {
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let Query(query) = query.map_err(|_| malformed("query"))?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::ListAutomationOccurrences {
                automation_id,
                query,
            },
        )
        .await?
    {
        AppReply::AutomationOccurrences(page) => Ok(Json(page)),
        _ => Err(contract_error()),
    }
}

/// List only real external deliveries; manual occurrences are never relabeled as a source.
pub async fn deliveries(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    Path(id): Path<String>,
    query: Result<Query<AutomationPageQuery>, QueryRejection>,
) -> Result<Json<AutomationDeliveryPage>, HttpError> {
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let Query(query) = query.map_err(|_| malformed("query"))?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::ListAutomationDeliveries {
                automation_id,
                query,
            },
        )
        .await?
    {
        AppReply::AutomationDeliveries(page) => Ok(Json(page)),
        _ => Err(contract_error()),
    }
}

/// Locate an accepted receipt by prefix, then require current owner visibility in the application.
pub async fn receipt(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
) -> Result<Json<AutomationReceipt>, HttpError> {
    reject_query(query)?;
    let receipt_id = AutomationReceiptId::try_from(id).map_err(|_| malformed("receipt_id"))?;
    match state
        .application()
        .execute(auth, AppCommand::GetAutomationReceipt { receipt_id })
        .await?
    {
        AppReply::AutomationReceipt(row) => Ok(Json(row)),
        _ => Err(contract_error()),
    }
}

/// Create a sender-key receiver under a fresh same-origin session; its key is shown only here.
pub async fn create_receiver(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<AutomationReceiverSecret>), HttpError> {
    reject_query(query)?;
    let automation_id = AutomationId::try_from(id).map_err(|_| malformed("automation_id"))?;
    let input = json_input::<CreateAutomationReceiver>(&request_headers, body).await?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::CreateAutomationReceiver {
                automation_id,
                input,
            },
        )
        .await?
    {
        AppReply::AutomationReceiverSecret(row) => Ok((StatusCode::CREATED, Json(row))),
        _ => Err(contract_error()),
    }
}

/// Rotate the current key with no overlap; a lost response is recovered by rotating again.
pub async fn rotate_receiver_key(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<Json<AutomationReceiverSecret>, HttpError> {
    reject_query(query)?;
    let receiver_id = AutomationReceiverId::try_from(id).map_err(|_| malformed("receiver_id"))?;
    let input = json_input::<RotateAutomationReceiverKey>(&request_headers, body).await?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::RotateAutomationReceiverKey { receiver_id, input },
        )
        .await?
    {
        AppReply::AutomationReceiverSecret(row) => Ok(Json(row)),
        _ => Err(contract_error()),
    }
}

/// Revoke a receiver; its receipts and key namespace remain.
pub async fn revoke_receiver(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    RawQuery(query): RawQuery,
    Path(id): Path<String>,
    request_headers: HeaderMap,
    body: Body,
) -> Result<Json<AutomationReceiver>, HttpError> {
    reject_query(query)?;
    let receiver_id = AutomationReceiverId::try_from(id).map_err(|_| malformed("receiver_id"))?;
    let input = json_input::<RevokeAutomationReceiver>(&request_headers, body).await?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::RevokeAutomationReceiver { receiver_id, input },
        )
        .await?
    {
        AppReply::AutomationReceiver(row) => Ok(Json(row)),
        _ => Err(contract_error()),
    }
}

// A forbidden disposition field is consumed only to return its registered refusal, even for null.
// It is never retained in the command, accepted intent or database.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManualInput {
    operation_id: AutomationOperationId,
    expected_revision: AutomationRevision,
    #[serde(default, deserialize_with = "disposition_present")]
    supersedes_receipt_id: bool,
}

fn disposition_present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    IgnoredAny::deserialize(d).map(|_| true)
}

async fn json_input<T: DeserializeOwned>(headers: &HeaderMap, body: Body) -> Result<T, HttpError> {
    let json = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    let compressed = headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
    if !json || compressed {
        return Err(malformed("body").into());
    }
    let mut bytes = Vec::new();
    let mut chunks = std::pin::pin!(body.into_data_stream());
    while let Some(data) = std::future::poll_fn(|cx| chunks.as_mut().poll_next(cx)).await {
        let data = data.map_err(|_| malformed("body"))?;
        if data.len() > MAX_MANAGEMENT_BODY_BYTES - bytes.len() {
            return Err(AppError::PayloadTooLarge.into());
        }
        bytes.extend_from_slice(&data);
    }
    // This byte scan enforces only the nesting budget. Serde performs the sole typed JSON parse.
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in &bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match *byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_JSON_DEPTH {
                        return Err(malformed("body").into());
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| malformed("body").into())
}

fn definition(reply: AppReply) -> Result<AutomationDefinition, HttpError> {
    match reply {
        AppReply::AutomationDefinition(row) => Ok(row),
        _ => Err(contract_error()),
    }
}

fn reject_query(query: Option<String>) -> Result<(), AppError> {
    match query {
        None => Ok(()),
        Some(raw) if raw.is_empty() => Ok(()),
        Some(_) => Err(malformed("query")),
    }
}
fn malformed(field: &'static str) -> AppError {
    AppError::MalformedPayload { field }
}
fn contract_error() -> HttpError {
    AppError::DependencyUnavailable {
        dependency: "automation_application",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_headers() -> HeaderMap {
        HeaderMap::from_iter([(CONTENT_TYPE, HeaderValue::from_static("application/json"))])
    }

    #[tokio::test]
    async fn closed_management_body_keeps_stream_byte_and_depth_limits() {
        let input = br#"{"operationId":"manual:one","expectedRevision":1}"#;
        let mut exact = input.to_vec();
        exact.resize(MAX_MANAGEMENT_BODY_BYTES, b' ');
        assert!(
            json_input::<ManualInput>(&json_headers(), Body::from(exact.clone()))
                .await
                .is_ok()
        );
        exact.push(b' ');
        assert_eq!(
            json_input::<ManualInput>(&json_headers(), Body::from(exact))
                .await
                .unwrap_err()
                .inner(),
            &AppError::PayloadTooLarge
        );
        for (depth, accepted) in [(16, true), (17, false)] {
            let data = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            let result = json_input::<serde_json::Value>(&json_headers(), Body::from(data)).await;
            assert_eq!(result.is_ok(), accepted);
        }
        let mut compressed = json_headers();
        compressed.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(
            json_input::<ManualInput>(&compressed, Body::from(input.to_vec()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn manual_framing_rejects_authority_and_marks_unavailable_disposition() {
        for body in [
            r#"{"operationId":"one","expectedRevision":1,"actorId":"other"}"#,
            r#"{"operationId":"one","operationId":"two","expectedRevision":1}"#,
            r#"{"operationId":"one","expectedRevision":1,"data":{"instruction":"act"}}"#,
        ] {
            assert!(
                json_input::<ManualInput>(&json_headers(), Body::from(body))
                    .await
                    .is_err()
            );
        }
        let with_null = json_input::<ManualInput>(
            &json_headers(),
            Body::from(r#"{"operationId":"one","expectedRevision":1,"supersedesReceiptId":null}"#),
        )
        .await
        .unwrap();
        assert!(
            with_null.supersedes_receipt_id,
            "a present null must not bypass the unavailable-disposition refusal"
        );
    }
}
