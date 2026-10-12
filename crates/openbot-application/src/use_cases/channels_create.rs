//! User-created channel transaction orchestration.

use openbot_contracts::auth::{AuthContext, Role};
use openbot_contracts::command::ChannelDetail;
use openbot_contracts::error::AppError;
use openbot_contracts::ids::BotId;
use openbot_contracts::text::trim_ecmascript;

use crate::ports::{ChannelAdministration, ChannelCreateRequest, ChannelCreateScope};

/// Validate and canonicalize selected Agent IDs, then delegate one atomic create transaction.
pub async fn create_channel(
    administration: &dyn ChannelAdministration,
    auth: &AuthContext,
    agent_ids: Vec<BotId>,
) -> Result<ChannelDetail, AppError> {
    if agent_ids.is_empty() {
        return Err(AppError::MalformedPayload { field: "agent_ids" });
    }
    let mut canonical = Vec::with_capacity(agent_ids.len());
    for agent_id in agent_ids {
        let trimmed = trim_ecmascript(agent_id.as_str());
        if trimmed.is_empty() || trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
            return Err(AppError::MalformedPayload { field: "agent_ids" });
        }
        canonical.push(BotId::new(trimmed));
    }
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AppError::MalformedPayload { field: "agent_ids" });
    }
    administration
        .create_channel(ChannelCreateRequest {
            scope: ChannelCreateScope {
                deployment: auth.deployment().clone(),
                tenant: auth.tenant().clone(),
                actor: auth.actor().clone(),
                auth_generation: auth.auth_generation(),
                admin: auth.has_role(Role::Admin),
            },
            agent_ids: canonical,
        })
        .await
        .map_err(|error| error.into_app_error())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openbot_contracts::auth::AuthGeneration;
    use openbot_contracts::ids::{ActorId, ChannelId, DeploymentId, TenantId, ThreadId};

    use super::*;
    use crate::ports::ChannelAdministrationError;

    struct FakeChannels {
        calls: Mutex<Vec<ChannelCreateRequest>>,
    }

    #[async_trait]
    impl ChannelAdministration for FakeChannels {
        async fn create_channel(
            &self,
            request: ChannelCreateRequest,
        ) -> Result<ChannelDetail, ChannelAdministrationError> {
            self.calls.lock().unwrap().push(request.clone());
            Ok(ChannelDetail {
                id: ChannelId::new("channel-1"),
                name: "Agent One, Agent Two".to_owned(),
                agent_ids: request.agent_ids,
                thread_id: Some(ThreadId::new("550e8400-e29b-81d4-a716-446655440000")),
                active: true,
            })
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            ActorId::new("actor"),
            [Role::User],
            AuthGeneration::new(1),
            false,
        )
    }

    #[tokio::test]
    async fn create_uses_authoritative_scope_and_canonical_agent_ids() {
        let channels = FakeChannels {
            calls: Mutex::new(Vec::new()),
        };
        let created = create_channel(
            &channels,
            &auth(),
            vec![BotId::new(" bot-2 "), BotId::new("bot-1")],
        )
        .await
        .unwrap();
        assert_eq!(
            created
                .agent_ids
                .iter()
                .map(BotId::as_str)
                .collect::<Vec<_>>(),
            ["bot-1", "bot-2"]
        );
        assert_eq!(
            channels.calls.lock().unwrap().as_slice(),
            [ChannelCreateRequest {
                scope: ChannelCreateScope {
                    deployment: DeploymentId::new("dep"),
                    tenant: TenantId::new("tenant"),
                    actor: ActorId::new("actor"),
                    auth_generation: AuthGeneration::new(1),
                    admin: false,
                },
                agent_ids: vec![BotId::new("bot-1"), BotId::new("bot-2")],
            }]
        );
    }

    #[tokio::test]
    async fn invalid_or_duplicate_agent_ids_never_reach_the_transaction() {
        let channels = FakeChannels {
            calls: Mutex::new(Vec::new()),
        };
        for ids in [
            Vec::new(),
            vec![BotId::new(" ")],
            vec![BotId::new("bot-1"), BotId::new(" bot-1 ")],
            vec![BotId::new("bad\nagent")],
        ] {
            assert_eq!(
                create_channel(&channels, &auth(), ids).await,
                Err(AppError::MalformedPayload { field: "agent_ids" })
            );
        }
        assert!(channels.calls.lock().unwrap().is_empty());
    }
}
