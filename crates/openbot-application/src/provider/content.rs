use openbot_domain::content_governance::{contains_known_secret, value_contains_known_secret};

use super::{ProviderPortError, ProviderRequest, ProviderRoute};

impl ProviderRequest {
    /// Reject high-confidence secrets in model-visible business input before transport starts.
    /// Rust-owned route credentials and signed run assertions are separate authentication inputs.
    /// No field name in an untrusted message/schema/resume can exempt its value from this check.
    pub fn validate_business_content(&self) -> Result<(), ProviderPortError> {
        let messages = self.messages.iter().any(|message| {
            contains_known_secret(&message.content)
                || message
                    .tool_call_id
                    .as_deref()
                    .is_some_and(contains_known_secret)
                || message
                    .tool_name
                    .as_deref()
                    .is_some_and(contains_known_secret)
                || message.tool_calls.iter().any(|call| {
                    contains_known_secret(&call.call_id)
                        || contains_known_secret(&call.name)
                        || value_contains_known_secret(&call.arguments)
                })
        });
        let tools = self.tools.iter().any(|tool| {
            contains_known_secret(&tool.name)
                || contains_known_secret(&tool.description)
                || value_contains_known_secret(&tool.input_schema)
        });
        let route_content = match &self.route {
            ProviderRoute::RemoteAgUi(route) => {
                [
                    route.thread_id(),
                    route.run_id(),
                    route.local_run_id(),
                    route.bot_id(),
                ]
                .into_iter()
                .any(contains_known_secret)
                    || route
                        .parent_protocol_run_id()
                        .is_some_and(contains_known_secret)
                    || route.resume().is_some_and(|resume| {
                        resume
                            .wire_entries()
                            .iter()
                            .any(value_contains_known_secret)
                    })
            }
            ProviderRoute::CustomModel(binding) => contains_known_secret(binding.model()),
            ProviderRoute::Extension(key) => contains_known_secret(key.as_str()),
            ProviderRoute::Managed | ProviderRoute::PackageOpenAi => false,
        };
        if messages || tools || route_content {
            return Err(ProviderPortError::InvalidRequest {
                field: "content_secret",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{ProviderMessage, ProviderMessageRole, ProviderToolCall, ProviderToolDefinition};

    fn request() -> ProviderRequest {
        ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: vec![ProviderMessage {
                role: ProviderMessageRole::User,
                content: "Explain password rotation".into(),
                tool_call_id: None,
                tool_name: None,
                tool_calls: vec![],
            }],
            tools: vec![ProviderToolDefinition {
                name: "password_help".into(),
                description: "Explain how an API key works".into(),
                input_schema: json!({"type":"object","properties":{"password":{"type":"string"}}}),
            }],
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        }
    }

    #[test]
    fn schemas_and_discussion_of_credentials_are_not_credentials() {
        assert!(request().validate_business_content().is_ok());
    }

    #[test]
    fn every_message_role_and_tool_schema_reject_known_secret_content_without_echo() {
        for role in [
            ProviderMessageRole::System,
            ProviderMessageRole::User,
            ProviderMessageRole::Assistant,
            ProviderMessageRole::Tool,
        ] {
            let mut request = request();
            request.messages[0].role = role;
            request.messages[0].content = "result SECRET-CANARY-private-input".into();
            let error = request.validate_business_content().unwrap_err();
            assert_eq!(
                error,
                ProviderPortError::InvalidRequest {
                    field: "content_secret"
                }
            );
            assert!(!format!("{error:?} {error}").contains("private-input"));
        }
        for field in ["name", "description", "schema"] {
            let mut request = request();
            match field {
                "name" => request.tools[0].name = "SECRET-CANARY-name".into(),
                "description" => request.tools[0].description = "OPENBOT_SECRET_CANARY".into(),
                _ => request.tools[0].input_schema = json!({"default":"SECRET-CANARY-default"}),
            }
            assert!(request.validate_business_content().is_err());
        }
    }

    #[test]
    fn untrusted_auth_named_field_cannot_exempt_a_secret() {
        let mut request = request();
        request.messages[0].tool_calls.push(ProviderToolCall {
            call_id: "call-1".into(),
            name: "work".into(),
            arguments: json!({"forwardedProps":{"openbotRun":"SECRET-CANARY-forged"}}),
        });
        assert!(request.validate_business_content().is_err());
    }
}
