//! Original-session ephemeral readers. Control JSON never authorizes the byte body.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_core::Stream;
use http::{HeaderMap, HeaderValue, Uri, header::CACHE_CONTROL};
use openbot_application::{
    PublicArtifactReadControlDelivery, PublicArtifactReadDelivery, PublicArtifactReadTransportBlock,
};
use openbot_contracts::artifact_read_protocol::{
    AcknowledgeArtifactReadBlock, ArtifactReadChunkDescriptor, CloseArtifactRead, OpenArtifactRead,
    ReadArtifactReadBlock, is_canonical_artifact_read_handle,
};
use openbot_contracts::artifacts::MAX_ARTIFACT_READ_CHUNK_BYTES;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::AppError;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::auth::OriginAuthenticated;
use crate::error::HttpError;
use crate::http::ServerState;

const PREFIX: &str = "/api/artifact-reads";

/// Closed sequence selector for one original reader block; it grants no byte authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceBody {
    sequence: u32,
}

/// The policy encloses routing, authentication and body-limit failures, including 404/405.
pub async fn response_policy(request: Request, next: Next) -> Response {
    let belongs =
        request.uri().path() == PREFIX || request.uri().path().starts_with("/api/artifact-reads/");
    let mut response = next.run(request).await;
    if belongs {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Open a reader under current host and source authority, returning only control JSON.
pub async fn open(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    uri: Uri,
    input: Result<Json<OpenArtifactRead>, JsonRejection>,
) -> Result<Response, HttpError> {
    closed_uri(&uri)?;
    let Json(input) = input.map_err(|_| malformed("body"))?;
    match state
        .application()
        .execute(auth.clone(), AppCommand::OpenArtifactRead(input))
        .await?
    {
        reply @ AppReply::ArtifactReadOpened(_) => control_response(&state, auth, reply),
        _ => Err(unavailable().into()),
    }
}

/// Deliver one original block through a body that rechecks authority at its first poll.
pub async fn next(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    handle: Result<Path<String>, PathRejection>,
    uri: Uri,
    input: Result<Json<SequenceBody>, JsonRejection>,
) -> Result<Response, HttpError> {
    let handle_id = original_path(handle, &uri, "/next")?;
    let Json(input) = input.map_err(|_| malformed("body"))?;
    let input = ReadArtifactReadBlock {
        handle_id,
        sequence: input.sequence,
    };
    let descriptor = match state
        .application()
        .execute(
            auth.clone(),
            AppCommand::ReadArtifactReadBlock(input.clone()),
        )
        .await?
    {
        AppReply::ArtifactReadChunkDescriptor(descriptor) => descriptor,
        _ => return Err(unavailable().into()),
    };
    let delivery = state
        .application()
        .take_artifact_read_delivery(auth.clone(), input.clone())?;
    check_descriptor(&descriptor, &input)?;
    if delivery.descriptor() != &descriptor {
        // Dropping a mismatched real delivery closes its original pending owner.
        return Err(unavailable().into());
    }
    let headers = block_headers(&descriptor)?;
    // No raw Vec or body clone escapes. The actual first poll performs the current handoff;
    // an abandoned/unpolled body drops the same real pending delivery.
    let body = Body::from_stream(ArtifactReadBody {
        auth,
        delivery: Some(delivery),
        carrier: None,
        terminal_observed: false,
    });
    Ok((headers, body).into_response())
}

/// Acknowledge the matching original sequence under its current control proof.
pub async fn acknowledge(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    handle: Result<Path<String>, PathRejection>,
    uri: Uri,
    input: Result<Json<SequenceBody>, JsonRejection>,
) -> Result<Response, HttpError> {
    let handle_id = original_path(handle, &uri, "/ack")?;
    let Json(input) = input.map_err(|_| malformed("body"))?;
    let expected = AcknowledgeArtifactReadBlock {
        handle_id,
        sequence: input.sequence,
    };
    match state
        .application()
        .execute(
            auth.clone(),
            AppCommand::AcknowledgeArtifactReadBlock(expected.clone()),
        )
        .await?
    {
        AppReply::ArtifactReadAcknowledged(ack)
            if ack.handle_id == expected.handle_id && ack.sequence == expected.sequence =>
        {
            control_response(&state, auth, AppReply::ArtifactReadAcknowledged(ack))
        }
        _ => Err(unavailable().into()),
    }
}

/// Close the original reader without granting a new byte operation.
pub async fn close(
    State(state): State<ServerState>,
    OriginAuthenticated(auth): OriginAuthenticated,
    handle: Result<Path<String>, PathRejection>,
    uri: Uri,
    body: Bytes,
) -> Result<Response, HttpError> {
    let handle_id = original_path(handle, &uri, "")?;
    if !body.is_empty() {
        return Err(malformed("body").into());
    }
    let expected = CloseArtifactRead { handle_id };
    match state
        .application()
        .execute(
            auth.clone(),
            AppCommand::CloseArtifactRead(expected.clone()),
        )
        .await?
    {
        AppReply::ArtifactReadClosed(closed) if closed.handle_id == expected.handle_id => {
            control_response(&state, auth, AppReply::ArtifactReadClosed(closed))
        }
        _ => Err(unavailable().into()),
    }
}

struct ArtifactReadBody {
    auth: AuthContext,
    delivery: Option<PublicArtifactReadDelivery>,
    carrier: Option<Arc<PublicArtifactReadTransportBlock>>,
    terminal_observed: bool,
}

struct HttpBytesOwner(Arc<PublicArtifactReadTransportBlock>);
impl AsRef<[u8]> for HttpBytesOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}
impl Drop for ArtifactReadBody {
    fn drop(&mut self) {
        if !self.terminal_observed
            && let Some(carrier) = &self.carrier
        {
            // Only an observable pre-terminal cancellation stops this own reader.
            // Actual Bytes owners still hold the original allocation until their real Drop.
            carrier.close();
        }
        // Before the first poll, the same real unconsumed delivery's Drop stops its owner.
    }
}

struct ArtifactReadControlBody {
    auth: AuthContext,
    delivery: Option<PublicArtifactReadControlDelivery>,
    encoded: Zeroizing<Vec<u8>>,
}
impl Stream for ArtifactReadControlBody {
    type Item = Result<Bytes, AppError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(delivery) = self.delivery.take() else {
            return Poll::Ready(None);
        };
        if let Err(error) = delivery.verify_current_tail(&self.auth) {
            return Poll::Ready(Some(Err(error)));
        }
        // This copy is only bounded control JSON. Its real current witness stays live until
        // this exact poll; the scalar reply cannot reconstruct or bypass that witness.
        Poll::Ready(Some(Ok(Bytes::from(std::mem::take(&mut *self.encoded)))))
    }
}

fn control_response(
    state: &ServerState,
    auth: AuthContext,
    reply: AppReply,
) -> Result<Response, HttpError> {
    let delivery = state
        .application()
        .take_artifact_read_control_delivery(auth.clone(), reply)?;
    let encoded = match delivery.reply() {
        AppReply::ArtifactReadOpened(value) => serde_json::to_vec(value),
        AppReply::ArtifactReadAcknowledged(value) => serde_json::to_vec(value),
        AppReply::ArtifactReadClosed(value) => serde_json::to_vec(value),
        _ => return Err(unavailable().into()),
    }
    .map_err(|_| unavailable())?;
    let mut headers = no_store();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let body = Body::from_stream(ArtifactReadControlBody {
        auth,
        delivery: Some(delivery),
        encoded: Zeroizing::new(encoded),
    });
    Ok((headers, body).into_response())
}
impl Stream for ArtifactReadBody {
    type Item = Result<Bytes, AppError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(delivery) = self.delivery.take() else {
            self.terminal_observed = true;
            drop(self.carrier.take());
            return Poll::Ready(None);
        };
        match delivery.handoff(&self.auth) {
            Ok(Some(block)) => {
                let carrier = Arc::new(block);
                self.carrier = Some(Arc::clone(&carrier));
                Poll::Ready(Some(Ok(Bytes::from_owner(HttpBytesOwner(carrier)))))
            }
            // This is a genuine zero observation and completed original inventory, followed
            // by the same final current control tail. No empty Full can skip this handoff.
            Ok(None) => {
                self.terminal_observed = true;
                Poll::Ready(None)
            }
            Err(error) => Poll::Ready(Some(Err(error))),
        }
    }
}

fn check_descriptor(
    descriptor: &ArtifactReadChunkDescriptor,
    input: &ReadArtifactReadBlock,
) -> Result<(), AppError> {
    if descriptor.handle_id != input.handle_id
        || descriptor.sequence != input.sequence
        || descriptor.byte_length as usize > MAX_ARTIFACT_READ_CHUNK_BYTES
        || descriptor.eof != (descriptor.byte_length == 0)
    {
        return Err(unavailable());
    }
    Ok(())
}

fn block_headers(descriptor: &ArtifactReadChunkDescriptor) -> Result<HeaderMap, AppError> {
    let mut headers = no_store();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    for (name, value) in [
        ("x-artifact-read-handle", descriptor.handle_id.clone()),
        ("x-artifact-read-sequence", descriptor.sequence.to_string()),
        ("x-artifact-read-length", descriptor.byte_length.to_string()),
        ("x-artifact-read-eof", descriptor.eof.to_string()),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(&value).map_err(|_| unavailable())?,
        );
    }
    // Do not set Content-Length: 0: an HTTP carrier may then optimize away an EOF poll.
    Ok(headers)
}

fn original_path(
    handle: Result<Path<String>, PathRejection>,
    uri: &Uri,
    suffix: &str,
) -> Result<String, AppError> {
    closed_uri(uri)?;
    let Path(handle) = handle.map_err(|_| malformed("handle_id"))?;
    if !is_canonical_artifact_read_handle(&handle)
        || uri.path() != format!("{PREFIX}/{handle}{suffix}")
    {
        return Err(malformed("handle_id"));
    }
    Ok(handle)
}

fn closed_uri(uri: &Uri) -> Result<(), AppError> {
    if uri.query().is_some() || uri.path().contains('%') {
        return Err(malformed("query"));
    }
    Ok(())
}

fn no_store() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

const fn malformed(field: &'static str) -> AppError {
    AppError::MalformedPayload { field }
}

const fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "artifact_reads",
    }
}

#[cfg(all(test, unix))]
#[path = "artifact_reads_tests.rs"]
pub(super) mod tests;
