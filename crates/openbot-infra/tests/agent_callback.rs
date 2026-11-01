//! PostgreSQL callback-token rotation/revocation/audit boundary.

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use harness::{admin_config, with_temp_database};
use openbot_application::{
    AgentCallbackTokenAdministration, AgentCallbackTokenError, RemoteCallbackAuthError,
    RemoteCallbackAuthenticator,
};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_domain::remote_callback::{
    RUN_ASSERTION_TTL_MILLIS, RemoteRunAssertionSigner, RemoteRunScope, RemoteToolSet,
    callback_token_hash, looks_like_callback_token,
};
use openbot_infra::agent_callback::{
    PostgresAgentCallbackTokens, PostgresRemoteCallbackAuthenticator,
};
use openbot_infra::db::{baseline, native, pool};

fn auth(actor: &str, role: Role, generation: u64) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new("deployment-a"),
        TenantId::new("tenant-a"),
        ActorId::new(actor),
        AuthGeneration::new(generation),
        false,
    )
    .with_role(role)
    .build()
}

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email,auth_generation) VALUES
               ('owner-a','owner@example.test',0),
               ('other-a','other@example.test',0),
               ('admin-a','admin@example.test',0);
             INSERT INTO public.user_roles(user_id,role) VALUES
               ('owner-a','user'),('other-a','user'),('admin-a','admin');
             INSERT INTO public.deployment_packages(tenant_id,source_path,checksum) VALUES
               ('tenant-a','/tenant-a',repeat('a',64)),
               ('tenant-b','/tenant-b',repeat('b',64));
             INSERT INTO public.agents(id,name,type,configuration,package_id)
               SELECT 'remote-package-a','Package A','remote_ag_ui','{\"endpoint\":\"https://a.invalid\"}',id
                 FROM public.deployment_packages WHERE tenant_id='tenant-a';
             INSERT INTO public.agents(id,name,type,configuration,package_id)
               SELECT 'remote-package-b','Package B','remote_ag_ui','{\"endpoint\":\"https://b.invalid\"}',id
                 FROM public.deployment_packages WHERE tenant_id='tenant-b';
             INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
               ('remote-owner','Owner Remote','remote_ag_ui','{\"endpoint\":\"https://owner.invalid\"}',NULL),
               ('remote-deleted','Deleted Remote','remote_ag_ui','{\"endpoint\":\"https://deleted.invalid\"}',NULL),
               ('built-in-owner','Built In','built_in','{\"systemPrompt\":\"x\"}',NULL),
               ('remote-audit-fail','Audit Fail','remote_ag_ui','{\"endpoint\":\"https://fail.invalid\"}',NULL);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES
               ('remote-package-a',NULL,'Package A','role','a','public',NULL),
               ('remote-package-b',NULL,'Package B','role','b','public',NULL),
               ('remote-owner','owner-a','Owner Remote','role','c','private',NULL),
               ('remote-deleted','owner-a','Deleted','role','d','private',clock_timestamp()),
               ('built-in-owner','owner-a','Built In','role','e','private',NULL),
               ('remote-audit-fail','owner-a','Audit Fail','role','f','private',NULL);",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn callback_token_is_one_time_hash_only_scope_checked_and_atomic_with_audit() {
    let admin =
        admin_config("callback_token_is_one_time_hash_only_scope_checked_and_atomic_with_audit");
    with_temp_database(&admin, "agentcallback", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let store = PostgresAgentCallbackTokens::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                vec![0x77; 32],
            )
            .map_err(|error| error.to_string())?;
            let owner = auth("owner-a", Role::User, 0);
            let admin = auth("admin-a", Role::Admin, 0);
            let other = auth("other-a", Role::User, 0);

            let first = store
                .issue(&owner, &BotId::new("remote-owner"))
                .await
                .map_err(|error| error.to_string())?;
            if !looks_like_callback_token(first.expose()) {
                return Err("issued callback token shape drift".to_owned());
            }
            let first_text = first.expose().to_owned();
            let first_hash = callback_token_hash(&first_text)
                .map_err(|error| error.to_string())?
                .to_hex();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT callback_token_hash,callback_token_issued_at \
                       FROM public.agent_profiles WHERE agent_id='remote-owner'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let stored: Option<String> = row.try_get(0).map_err(|error| error.to_string())?;
            let issued_at: Option<time::OffsetDateTime> =
                row.try_get(1).map_err(|error| error.to_string())?;
            if stored.as_deref() != Some(first_hash.as_str())
                || stored.as_deref() == Some(first_text.as_str())
                || issued_at.is_none()
            {
                return Err("callback token was not stored hash-only".to_owned());
            }
            let leaked: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events \
                      WHERE event_type='bot.callback_token_issued' \
                        AND (payload::text LIKE '%' || $1 || '%' OR target_id=$1)",
                    &[&first_text],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            if leaked != 0 {
                return Err("callback cleartext leaked into audit".to_owned());
            }
            drop(client);

            let second = store
                .issue(&owner, &BotId::new("remote-owner"))
                .await
                .map_err(|error| error.to_string())?;
            if first.expose() == second.expose() {
                return Err("callback rotation reused cleartext".to_owned());
            }
            store
                .revoke(&owner, &BotId::new("remote-owner"))
                .await
                .map_err(|error| error.to_string())?;

            if store
                .issue(&admin, &BotId::new("remote-package-a"))
                .await
                .is_err()
            {
                return Err("admin could not credential package remote Agent".to_owned());
            }
            for (who, target) in [
                (&owner, "remote-package-a"),
                (&other, "remote-owner"),
                (&owner, "remote-package-b"),
                (&owner, "remote-deleted"),
                (&owner, "built-in-owner"),
            ] {
                if store.issue(who, &BotId::new(target)).await
                    != Err(AgentCallbackTokenError::NotVisible)
                {
                    return Err(format!("unauthorized callback token target was visible: {target}"));
                }
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "UPDATE public.users SET auth_generation=1 WHERE id='owner-a'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if store
                .issue(&owner, &BotId::new("remote-owner"))
                .await
                != Err(AgentCallbackTokenError::NotVisible)
            {
                return Err("stale auth generation issued callback token".to_owned());
            }

            let fresh_owner = auth("owner-a", Role::User, 1);
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "CREATE FUNCTION fail_callback_audit() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN
                         IF NEW.event_type='bot.callback_token_issued' THEN
                           RAISE EXCEPTION 'forced callback audit failure';
                         END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER fail_callback_audit BEFORE INSERT ON public.audit_events
                       FOR EACH ROW EXECUTE FUNCTION fail_callback_audit();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if store
                .issue(&fresh_owner, &BotId::new("remote-audit-fail"))
                .await
                != Err(AgentCallbackTokenError::Unavailable)
            {
                return Err("audit failure did not fail token issue".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let state = client
                .query_one(
                    "SELECT callback_token_hash IS NULL,callback_token_issued_at IS NULL, \
                            (SELECT count(*)::bigint FROM public.audit_events \
                              WHERE event_type='bot.callback_token_issued' \
                                AND target_id='remote-owner'), \
                            (SELECT count(*)::bigint FROM public.audit_events \
                              WHERE event_type='bot.callback_token_revoked' \
                                AND target_id='remote-owner') \
                       FROM public.agent_profiles WHERE agent_id='remote-audit-fail'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let hash_null: bool = state.try_get(0).map_err(|error| error.to_string())?;
            let issued_null: bool = state.try_get(1).map_err(|error| error.to_string())?;
            let issued_count: i64 = state.try_get(2).map_err(|error| error.to_string())?;
            let revoked_count: i64 = state.try_get(3).map_err(|error| error.to_string())?;
            if !hash_null || !issued_null || issued_count != 2 || revoked_count != 1 {
                return Err(format!(
                    "callback transaction/audit drift: hash_null={hash_null} issued_null={issued_null} issued={issued_count} revoked={revoked_count}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn callback_pair_binds_active_run_bot_actor_and_empty_authoritative_tool_set() {
    let admin =
        admin_config("callback_pair_binds_active_run_bot_actor_and_empty_authoritative_tool_set");
    with_temp_database(&admin, "callbackauth", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let signer = std::sync::Arc::new(
                RemoteRunAssertionSigner::new(b"callback-auth-master".to_vec())
                    .map_err(|error| error.to_string())?,
            );
            let token_store = PostgresAgentCallbackTokens::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                vec![0x55; 32],
            )
            .map_err(|error| error.to_string())?;
            let authenticator = PostgresRemoteCallbackAuthenticator::new(
                pool.clone(),
                DeploymentId::new("deployment-a"),
                TenantId::new("tenant-a"),
                false,
                signer.clone(),
                vec![0x55; 32],
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?;
            let owner = auth("owner-a", Role::User, 0);
            let admin_auth = auth("admin-a", Role::Admin, 0);
            let owner_token = token_store
                .issue(&owner, &BotId::new("remote-owner"))
                .await
                .map_err(|error| error.to_string())?;
            let package_token = token_store
                .issue(&admin_auth, &BotId::new("remote-package-a"))
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,
                       next_message_seq,next_event_seq,created_at,updated_at
                     ) VALUES(
                       'thread-callback','tenant-a','deployment-a','owner-a','direct_bot',
                       'remote-owner','active',0,0,clock_timestamp(),clock_timestamp()
                     );
                     INSERT INTO public.thread_memberships(thread_id,user_id)
                       VALUES('thread-callback','owner-a');
                     INSERT INTO public.runs(
                       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,
                       next_event_seq,created_at,started_at
                     ) VALUES(
                       'run-callback','thread-callback','remote-owner','owner-a',true,'running',1,
                       0,clock_timestamp(),clock_timestamp()
                     );
                     INSERT INTO public.thread_leases(
                       thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
                     ) VALUES(
                       'thread-callback','runtime-a',1,clock_timestamp(),
                       clock_timestamp()+interval '10 minutes',clock_timestamp()
                     );",
                )
                .await
                .map_err(|error| error.to_string())?;
            let now_millis: i64 = client
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            let scope = RemoteRunScope {
                deployment: DeploymentId::new("deployment-a"),
                tenant: TenantId::new("tenant-a"),
                bot: BotId::new("remote-owner"),
                actor: ActorId::new("owner-a"),
                run: openbot_contracts::ids::RunId::new("run-callback"),
            };
            let assertion = signer
                .mint(scope.clone(), &RemoteToolSet::empty(), now_millis)
                .map_err(|error| error.to_string())?;

            if authenticator
                .authorize(
                    owner_token.expose(),
                    &serde_json::Value::String(assertion.clone()),
                    "mcp__drive__search",
                )
                .await
                != Err(RemoteCallbackAuthError::ToolNotVisible)
            {
                return Err("empty authoritative set did not refuse callback tool".to_owned());
            }
            let unknown = openbot_domain::remote_callback::callback_token_from_entropy([9; 32]);
            if authenticator
                .authorize(
                    &unknown,
                    &serde_json::Value::String(assertion.clone()),
                    "mcp__drive__search",
                )
                .await
                != Err(RemoteCallbackAuthError::Unauthenticated)
            {
                return Err("unknown callback token was not 401-equivalent".to_owned());
            }
            if authenticator
                .authorize(
                    package_token.expose(),
                    &serde_json::Value::String(assertion.clone()),
                    "mcp__drive__search",
                )
                .await
                != Err(RemoteCallbackAuthError::BotMismatch)
            {
                return Err("another Agent borrowed a signed Bot assertion".to_owned());
            }
            let expired = signer
                .mint(
                    scope,
                    &RemoteToolSet::empty(),
                    now_millis - RUN_ASSERTION_TTL_MILLIS - 1,
                )
                .map_err(|error| error.to_string())?;
            if authenticator
                .authorize(
                    owner_token.expose(),
                    &serde_json::Value::String(expired),
                    "mcp__drive__search",
                )
                .await
                != Err(RemoteCallbackAuthError::Unauthenticated)
            {
                return Err("expired callback assertion was accepted".to_owned());
            }
            if authenticator
                .authorize(owner_token.expose(), &serde_json::Value::Null, "x")
                .await
                != Err(RemoteCallbackAuthError::Unauthenticated)
            {
                return Err("missing callback assertion was accepted".to_owned());
            }
            token_store
                .revoke(&owner, &BotId::new("remote-owner"))
                .await
                .map_err(|error| error.to_string())?;
            if authenticator
                .authorize(
                    owner_token.expose(),
                    &serde_json::Value::String(assertion),
                    "x",
                )
                .await
                != Err(RemoteCallbackAuthError::Unauthenticated)
            {
                return Err("revoked callback token was accepted".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let audit = client
                .query_one(
                    "SELECT count(*)::bigint,
                            count(*) FILTER (WHERE actor_user_id IS NOT NULL)::bigint,
                            count(*) FILTER (WHERE target_id IS NOT NULL)::bigint,
                            count(*) FILTER (WHERE payload::text LIKE '%' || $1 || '%')::bigint,
                            count(*) FILTER (WHERE payload::text LIKE '%run-callback%')::bigint
                       FROM public.audit_events WHERE event_type='mcp.callback_refused'",
                    &[&owner_token.expose()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let total: i64 = audit.try_get(0).map_err(|error| error.to_string())?;
            let actor_rows: i64 = audit.try_get(1).map_err(|error| error.to_string())?;
            let target_rows: i64 = audit.try_get(2).map_err(|error| error.to_string())?;
            let token_leaks: i64 = audit.try_get(3).map_err(|error| error.to_string())?;
            let run_leaks: i64 = audit.try_get(4).map_err(|error| error.to_string())?;
            if total != 6
                || actor_rows != 0
                || target_rows != 0
                || token_leaks != 0
                || run_leaks != 0
            {
                return Err(format!(
                    "callback refusal audit drift: total={total} actors={actor_rows} targets={target_rows} token_leaks={token_leaks} run_leaks={run_leaks}"
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
