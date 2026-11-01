//! Explicit user-message saves, current metadata and saved-owner deletions through the one
//! ApplicationService.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use http::{HeaderMap, HeaderValue, StatusCode, Uri, header::CACHE_CONTROL};
use openbot_contracts::artifacts::{
    ArtifactDeletionReceipt, ArtifactDeletionState, ArtifactMetadata, ArtifactRegistrationReceipt,
    GetArtifactMetadata, GetSourceRunArtifactIds, SaveRunMessageTextArtifact, SourceRunArtifactIds,
};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{RunId, ThreadId};

use crate::auth::{Authenticated, FreshOriginAuthenticated};
use crate::error::HttpError;
use crate::http::ServerState;

/// Authenticated sensitive explicit save. Neither the body nor the route accepts byte paths.
pub async fn save(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    uri: Uri,
    input: Result<Json<SaveRunMessageTextArtifact>, JsonRejection>,
) -> Result<(HeaderMap, Json<ArtifactRegistrationReceipt>), HttpError> {
    closed_query(&uri)?;
    let Json(input) = input.map_err(|_| AppError::MalformedPayload { field: "body" })?;
    match state
        .application()
        .execute(auth, AppCommand::SaveRunMessageTextArtifact(input))
        .await?
    {
        AppReply::ArtifactRegistrationReceipt(receipt) => Ok((no_store(), Json(receipt))),
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

/// Metadata observation; actual bytes and current source permission are separate later facts.
pub async fn metadata(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    id: Result<Path<String>, PathRejection>,
    uri: Uri,
    body: Bytes,
) -> Result<(HeaderMap, Json<ArtifactMetadata>), HttpError> {
    closed_query(&uri)?;
    if !body.is_empty() {
        return Err(AppError::MalformedPayload { field: "body" }.into());
    }
    let Path(artifact_id) = id.map_err(|_| AppError::MalformedPayload {
        field: "artifact_id",
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetArtifactMetadata(GetArtifactMetadata { artifact_id }),
        )
        .await?
    {
        AppReply::ArtifactMetadata(metadata) => Ok((no_store(), Json(metadata))),
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

/// `DELETE /api/artifacts/{artifact_id}`: one bounded step of the saving owner's deletion, a
/// sensitive write like the save. A pending deletion is 202 and resumed by resending the same
/// request; a deleted one is 200, after which a resend is 409 for the owner.
pub async fn delete(
    State(state): State<ServerState>,
    FreshOriginAuthenticated(auth): FreshOriginAuthenticated,
    id: Result<Path<String>, PathRejection>,
    uri: Uri,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Json<ArtifactDeletionReceipt>), HttpError> {
    closed_query(&uri)?;
    if !body.is_empty() {
        return Err(AppError::MalformedPayload { field: "body" }.into());
    }
    let Path(artifact_id) = id.map_err(|_| AppError::MalformedPayload {
        field: "artifact_id",
    })?;
    match state
        .application()
        .execute(auth, AppCommand::DeleteArtifact { artifact_id })
        .await?
    {
        AppReply::ArtifactDeletion(receipt) => {
            let status = match receipt.state {
                ArtifactDeletionState::Pending => StatusCode::ACCEPTED,
                ArtifactDeletionState::Deleted => StatusCode::OK,
            };
            Ok((status, no_store(), Json(receipt)))
        }
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

/// Lists IDs materialized from one currently visible source Run in the current host scope.
pub async fn source_run_ids(
    State(state): State<ServerState>,
    Authenticated(auth): Authenticated,
    source: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    body: Bytes,
) -> Result<(HeaderMap, Json<SourceRunArtifactIds>), HttpError> {
    if uri.query().is_some() {
        return Err(AppError::MalformedPayload { field: "query" }.into());
    }
    if !body.is_empty() {
        return Err(AppError::MalformedPayload { field: "body" }.into());
    }
    let mut raw_path = uri.path().bytes();
    while let Some(byte) = raw_path.next() {
        if byte == b'%'
            && (!raw_path.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !raw_path.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(AppError::MalformedPayload {
                field: "source_run",
            }
            .into());
        }
    }
    let Path((thread_id, run_id)) = source.map_err(|_| AppError::MalformedPayload {
        field: "source_run",
    })?;
    match state
        .application()
        .execute(
            auth,
            AppCommand::GetSourceRunArtifactIds(GetSourceRunArtifactIds {
                source_thread_id: ThreadId::new(thread_id),
                source_run_id: RunId::new(run_id),
            }),
        )
        .await?
    {
        AppReply::SourceRunArtifactIds(ids) => Ok((no_store(), Json(ids))),
        _ => Err(AppError::DependencyUnavailable {
            dependency: "application",
        }
        .into()),
    }
}

fn closed_query(uri: &Uri) -> Result<(), AppError> {
    if uri.query().is_some_and(|query| !query.is_empty()) {
        return Err(AppError::MalformedPayload { field: "query" });
    }
    Ok(())
}
fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}
