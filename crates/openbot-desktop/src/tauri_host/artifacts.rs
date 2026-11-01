//! Current host-bound explicit save, metadata and saved-owner deletion framing; no filesystem
//! path ingress.

use http::{Method, Request, Response, StatusCode};
use openbot_contracts::artifacts::{
    ArtifactDeletionState, GetArtifactMetadata, GetSourceRunArtifactIds, SaveRunMessageTextArtifact,
};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::error::{AppError, SensitiveWriteReason};
use openbot_contracts::ids::{RunId, ThreadId};

use super::{
    CHANNEL_THREAD_BODY_MAX_BYTES, DesktopTauriProtocol, WindowAuthority, dependency_response,
    empty_response, error_response, json_response, json_response_with_status, parse_sensitive_body,
    payload_too_large, percent_decode_segment, sensitive_body_error_response,
};

impl DesktopTauriProtocol {
    pub(super) async fn artifacts(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if request.uri().path() == "/api/artifacts/save-requests"
            || request
                .uri()
                .path()
                .starts_with("/api/artifacts/save-requests/")
        {
            return self.artifact_save_receipt(label, request, authority).await;
        }
        if request.uri().path() == "/api/artifacts/source-runs"
            || request
                .uri()
                .path()
                .starts_with("/api/artifacts/source-runs/")
        {
            return self
                .source_run_artifact_ids(label, request, authority)
                .await;
        }
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if request.body().len() > CHANNEL_THREAD_BODY_MAX_BYTES {
            request.body_mut().fill(0);
            return payload_too_large();
        }
        if request.uri().query().is_some_and(|query| !query.is_empty()) {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        let path = request.uri().path().to_owned();
        let save = path == "/api/artifacts/save-run-message-text";
        // Deletion is irreversible: a sensitive write like the save.
        let write = save || request.method() == Method::DELETE;
        if write && !authority.is_fresh() {
            request.body_mut().fill(0);
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        let command = if save {
            if request.method() != Method::POST {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            match parse_sensitive_body::<SaveRunMessageTextArtifact>(
                &mut request,
                CHANNEL_THREAD_BODY_MAX_BYTES,
            ) {
                Ok(input) => AppCommand::SaveRunMessageTextArtifact(input),
                Err(error) => return sensitive_body_error_response(error),
            }
        } else {
            let Some(segment) = path
                .strip_prefix("/api/artifacts/")
                .filter(|id| !id.is_empty() && !id.contains('/'))
            else {
                request.body_mut().fill(0);
                return empty_response(StatusCode::NOT_FOUND);
            };
            if !write && request.method() != Method::GET {
                request.body_mut().fill(0);
                return empty_response(StatusCode::METHOD_NOT_ALLOWED);
            }
            if !request.body().is_empty() {
                request.body_mut().fill(0);
                return error_response(AppError::MalformedPayload { field: "body" });
            }
            let Some(artifact_id) = percent_decode_segment(segment) else {
                return error_response(AppError::MalformedPayload {
                    field: "artifact_id",
                });
            };
            if write {
                AppCommand::DeleteArtifact { artifact_id }
            } else {
                AppCommand::GetArtifactMetadata(GetArtifactMetadata { artifact_id })
            }
        };
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            return error_response(error);
        }
        if write && !authority.is_fresh() {
            return error_response(AppError::SensitiveWriteRefused {
                reason: SensitiveWriteReason::SessionNotFresh,
            });
        }
        // Never cancel admitted IO on window closure or send the result to a replacement owner.
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        if let Err(error) = self.artifact_binding_current(label, &authority) {
            return if write {
                error_response(AppError::DependencyUnavailable {
                    dependency: "artifacts",
                })
            } else {
                error_response(error)
            };
        }
        match (write, result) {
            (true, Ok(AppReply::ArtifactRegistrationReceipt(receipt))) => json_response(&receipt),
            (true, Ok(AppReply::ArtifactDeletion(receipt))) => {
                let status = match receipt.state {
                    ArtifactDeletionState::Pending => StatusCode::ACCEPTED,
                    ArtifactDeletionState::Deleted => StatusCode::OK,
                };
                json_response_with_status(&receipt, status)
            }
            (false, Ok(AppReply::ArtifactMetadata(metadata))) => json_response(&metadata),
            (_, Err(error)) => error_response(error),
            (_, Ok(_)) => dependency_response(),
        }
    }

    async fn source_run_artifact_ids(
        &self,
        label: &str,
        mut request: Request<Vec<u8>>,
        authority: WindowAuthority,
    ) -> Response<Vec<u8>> {
        if let Err(error) = self.source_run_artifact_ids_binding_current(label, &authority) {
            request.body_mut().fill(0);
            return error_response(error);
        }
        if request.method() != Method::GET {
            request.body_mut().fill(0);
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        if request.uri().query().is_some() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "query" });
        }
        if !request.body().is_empty() {
            request.body_mut().fill(0);
            return error_response(AppError::MalformedPayload { field: "body" });
        }
        let Some(source) = request
            .uri()
            .path()
            .strip_prefix("/api/artifacts/source-runs/")
        else {
            return error_response(AppError::MalformedPayload {
                field: "source_run",
            });
        };
        let mut segments = source.split('/');
        let (Some(thread), Some(run), None) = (segments.next(), segments.next(), segments.next())
        else {
            return error_response(AppError::MalformedPayload {
                field: "source_run",
            });
        };
        let (Some(thread), Some(run)) =
            (percent_decode_segment(thread), percent_decode_segment(run))
        else {
            return error_response(AppError::MalformedPayload {
                field: "source_run",
            });
        };
        let command = AppCommand::GetSourceRunArtifactIds(GetSourceRunArtifactIds {
            source_thread_id: ThreadId::new(thread),
            source_run_id: RunId::new(run),
        });
        if let Err(error) = self.source_run_artifact_ids_binding_current(label, &authority) {
            return error_response(error);
        }
        let result = self
            .transport
            .execute(authority.auth.clone(), command)
            .await;
        // Keep the original window's bounded synchronous tail after Application handoff.
        if let Err(error) = self.source_run_artifact_ids_binding_current(label, &authority) {
            return error_response(error);
        }
        match result {
            Ok(AppReply::SourceRunArtifactIds(ids)) => json_response(&ids),
            Err(error) => error_response(error),
            Ok(_) => dependency_response(),
        }
    }

    fn source_run_artifact_ids_binding_current(
        &self,
        label: &str,
        original: &WindowAuthority,
    ) -> Result<(), AppError> {
        if !self.request_binding_issuer.observation().is_current() || original.closed.is_cancelled()
        {
            return Err(AppError::Unauthenticated);
        }
        let binding = original
            .auth
            .request_binding()
            .ok_or(AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            })?;
        if !self.request_binding_issuer.matches_desktop_window_epoch(
            binding.identity(),
            label,
            original.binding_id,
        ) {
            return Err(AppError::Unauthenticated);
        }
        let windows = self.window_registry.windows.try_read().map_err(|_| {
            AppError::DependencyUnavailable {
                dependency: "host_request_binding",
            }
        })?;
        match windows.get(label) {
            Some(current)
                if current.binding_id == original.binding_id
                    && !current.closed.is_cancelled()
                    && current.auth == original.auth
                    && current
                        .auth
                        .request_binding()
                        .is_some_and(|current_binding| {
                            binding.identity().same_binding(current_binding.identity())
                        }) =>
            {
                Ok(())
            }
            _ => Err(AppError::Unauthenticated),
        }
    }

    #[cfg(test)]
    pub(super) fn source_run_artifact_ids_binding_current_for_test(
        &self,
        label: &str,
        original: &WindowAuthority,
    ) -> Result<(), AppError> {
        self.source_run_artifact_ids_binding_current(label, original)
    }

    fn artifact_binding_current(
        &self,
        label: &str,
        admitted: &WindowAuthority,
    ) -> Result<(), AppError> {
        match self.authority(label) {
            Ok(Some(current))
                if current.binding_id == admitted.binding_id && !admitted.closed.is_cancelled() =>
            {
                Ok(())
            }
            Ok(_) => Err(AppError::Unauthenticated),
            Err(_) => Err(AppError::DependencyUnavailable {
                dependency: "desktop_window_authority",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_contracts::artifacts::ArtifactGoneStatus;

    #[test]
    fn gone_and_fixed_artifact_quota_errors_keep_closed_no_store_framing() {
        for status in [ArtifactGoneStatus::Deleted, ArtifactGoneStatus::Expired] {
            let response = error_response(AppError::ArtifactGone { status });
            assert_eq!(response.status(), StatusCode::GONE);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
                serde_json::json!({"code":"artifact_gone","status":status})
            );
        }
        for rule in ["artifact_disk_space", "artifact_quota"] {
            let response = error_response(AppError::PolicyRefused {
                rule: rule.to_owned(),
                decision: Some(openbot_contracts::ids::PolicyDecisionId::new(
                    "private-decision",
                )),
            });
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
                serde_json::json!({"code":"policy_refused","rule":rule})
            );
        }
    }

    #[test]
    fn preexisting_nonartifact_policy_error_projection_is_preserved() {
        let response = error_response(AppError::PolicyRefused {
            rule: "memory_writes_disabled".into(),
            decision: None,
        });
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            serde_json::json!({"code":"policy_refused"})
        );
    }
}
