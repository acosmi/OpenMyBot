//! Batch100: skills/grants/for-Agent authority and audit semantics against real PostgreSQL 17.

mod harness;

use std::collections::BTreeMap;
use std::sync::Arc;

use harness::{admin_config, with_temp_database};
use openbot_application::{McpConnectionAdministration, McpConnectionError};
use openbot_contracts::auth::{AuthContext, AuthContextBuilder, AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId};
use openbot_contracts::mcp::{PluginGrantKind, PluginGrantMutation, PluginSkillMutation};
use openbot_domain::audit::hash::{CanonicalWriter, Sha256Digest};
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::mcp::SafeRmcpClient;
use openbot_infra::mcp_catalog::PostgresMcpCatalog;
use openbot_infra::mcp_connections::PostgresMcpConnections;
use openbot_infra::mcp_oauth::McpOAuthClient;
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer, SchemePolicy};
use openbot_infra::vault::CredentialRecordVault;
use serde_json::{Value, json};

const DEPLOYMENT: &str = "plugin-admin-deployment";
const TENANT: &str = "plugin-admin-tenant";
const ADMIN: &str = "plugin-admin";
const USER_A: &str = "plugin-user-a";
const USER_B: &str = "plugin-user-b";
const AUDIT_KEY: &[u8] = b"plugin-admin-runtime-audit-key-at-least-32";
const INSTRUCTION_CANARY: &str = "SECRET_INSTRUCTION_CANARY";

fn auth(actor: &str, role: Role) -> AuthContext {
    AuthContextBuilder::from_verified_session(
        DeploymentId::new(DEPLOYMENT),
        TenantId::new(TENANT),
        ActorId::new(actor),
        AuthGeneration::new(0),
        false,
    )
    .with_roles([role])
    .build()
}

fn transport_fingerprint(endpoint: &str) -> String {
    let mut writer = CanonicalWriter::new("openbot:mcp-transport:v2");
    writer.str(endpoint);
    writer.str("notes.example.test");
    writer.str("custom");
    writer.str("mcp");
    writer.u64(0);
    writer.str("2026-07-28");
    writer.digest_of_written().to_hex()
}

fn personal_skill(slug: &str, title: &str) -> PluginSkillMutation {
    PluginSkillMutation {
        slug: slug.to_owned(),
        title: title.to_owned(),
        summary: "Bounded summary".to_owned(),
        instructions: format!("Use this instruction without logging {INSTRUCTION_CANARY}."),
        deployment_wide: false,
        expected_revision: None,
    }
}

fn skill_grant(reference: &str, agent_id: &str) -> PluginGrantMutation {
    PluginGrantMutation {
        kind: PluginGrantKind::Skill,
        reference: reference.to_owned(),
        agent_id: agent_id.to_owned(),
    }
}

fn mcp_grant(agent_id: &str) -> PluginGrantMutation {
    PluginGrantMutation {
        kind: PluginGrantKind::Mcp,
        reference: "notes/search".to_owned(),
        agent_id: agent_id.to_owned(),
    }
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn skills_grants_and_actor_specific_projection_are_transactional_and_audited() {
    let admin =
        admin_config("skills_grants_and_actor_specific_projection_are_transactional_and_audited");
    with_temp_database(&admin, "pluginadmin", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&pg)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut pg)
                .await
                .map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.users(id,email,name,email_verified,auth_generation) VALUES
                   ('plugin-admin','admin@plugins.test','Admin',true,0),
                   ('plugin-user-a','a@plugins.test','User A',true,0),
                   ('plugin-user-b','b@plugins.test','User B',true,0);
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('plugin-admin','admin'),('plugin-user-a','user'),('plugin-user-b','user');
                 INSERT INTO public.agents(id,name,type,configuration) VALUES
                   ('agent-owned','Owned','remote_ag_ui','{}'),
                   ('agent-other','Other','remote_ag_ui','{}'),
                   ('agent-public','Public','remote_ag_ui','{}'),
                   ('agent-deleted','Deleted','remote_ag_ui','{}');
                 INSERT INTO public.deployment_packages(tenant_id,source_path,checksum)
                   VALUES('other-plugin-tenant','/other-fixture',repeat('f',64));
                 INSERT INTO public.agents(id,name,type,configuration,package_id)
                   SELECT 'agent-cross-tenant','Cross tenant','built_in','{}',id
                     FROM public.deployment_packages WHERE tenant_id='other-plugin-tenant';
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
                 ) VALUES
                   ('agent-owned','plugin-user-a','Owned','Owned role','owned','private',NULL),
                   ('agent-other','plugin-user-b','Other','Other role','other','private',NULL),
                   ('agent-public','plugin-user-b','Public','Public role','public','public',NULL),
                   ('agent-deleted','plugin-user-a','Deleted','Deleted role','deleted','public',clock_timestamp()),
                   ('agent-cross-tenant',NULL,'Cross tenant','Cross role','cross','public',NULL);",
            )
            .await
            .map_err(|error| error.to_string())?;

            let endpoint = "https://notes.example.test/mcp";
            let fingerprint = transport_fingerprint(endpoint);
            let schema = json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            });
            let schema_hash = Sha256Digest::of(
                &serde_json::to_vec(&schema).map_err(|error| error.to_string())?,
            )
            .to_hex();
            pg.execute(
                "INSERT INTO public.mcp_servers(
                   id,title,vendor,url,provenance,catalog_generation,catalog_hash,
                   catalog_transport_fingerprint,credential_generation,transport,
                   egress_allow_cidrs)
                 VALUES('notes','Notes','notes.example.test',$1,'custom',1,repeat('c',64),$2,0,'mcp',
                        ARRAY[]::text[])",
                &[&endpoint, &fingerprint],
            )
            .await
            .map_err(|error| error.to_string())?;
            pg.execute(
                "INSERT INTO public.mcp_tools(
                   server_id,name,description,input_schema,schema_hash,effect,catalog_generation,
                   first_seen_at,last_seen_at,available)
                 VALUES('notes','search','Search notes',$1,$2,'read',1,clock_timestamp(),
                        clock_timestamp(),true)",
                &[&schema, &schema_hash],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let dialer = SafeDialer::new(EgressPolicy::default());
            let catalog = Arc::new(
                PostgresMcpCatalog::new(
                    pool.clone(),
                    SafeRmcpClient::new(
                        dialer.clone(),
                        SchemePolicy::HttpsOnly,
                        Some(std::time::Duration::from_secs(1)),
                    ),
                    AUDIT_KEY.to_vec(),
                )
                .map_err(|error| error.to_string())?,
            );
            let vault = CredentialRecordVault::single_key(
                TenantId::new(TENANT),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x62; 32]).map_err(|error| error.to_string())?,
            );
            let connections = PostgresMcpConnections::new(
                pool.clone(),
                vault,
                McpOAuthClient::new(dialer, SchemePolicy::HttpsOnly),
                catalog,
                DeploymentId::new(DEPLOYMENT),
                TenantId::new(TENANT),
                vec![0x63; 32],
                AUDIT_KEY.to_vec(),
                None,
                None,
                SchemePolicy::HttpsOnly,
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|error| error.to_string())?;
            let admin = auth(ADMIN, Role::Admin);
            let user_a = auth(USER_A, Role::User);
            let user_b = auth(USER_B, Role::User);

            let mut review = personal_skill("review-notes", "Review notes");
            let saved = connections
                .save_skill(&user_a, &review)
                .await
                .map_err(|error| error.to_string())?;
            require(
                saved.skills.len() == 1 && saved.skills[0].owner_user_id.as_deref() == Some(USER_A),
                format!("personal skill response drift: {saved:?}"),
            )?;

            let mut forbidden_global = personal_skill("user-global", "User global");
            forbidden_global.deployment_wide = true;
            require(
                matches!(
                    connections.save_skill(&user_a, &forbidden_global).await,
                    Err(McpConnectionError::NotVisible)
                ),
                "non-admin deployment skill was not refused",
            )?;
            require(
                matches!(
                    connections
                        .save_skill(&user_b, &personal_skill("review-notes", "Hijacked"))
                        .await,
                    Err(McpConnectionError::NotVisible)
                ),
                "another actor overwrote a personal skill",
            )?;
            require(
                matches!(
                    connections.remove_skill(&user_b, "review-notes", 1).await,
                    Err(McpConnectionError::NotVisible)
                ),
                "another actor removed a personal skill",
            )?;
            require(
                matches!(
                    connections.remove_skill(&user_a, "missing-skill", 1).await,
                    Err(McpConnectionError::NotVisible)
                ),
                "non-admin received an idempotent delete oracle for an unknown skill",
            )?;

            review.title = "Admin-reviewed notes".to_owned();
            review.deployment_wide = true;
            review.expected_revision = Some(1);
            connections
                .save_skill(&admin, &review)
                .await
                .map_err(|error| error.to_string())?;
            connections
                .save_skill(
                    &user_b,
                    &personal_skill("other-private", "Other private"),
                )
                .await
                .map_err(|error| error.to_string())?;
            let mut global = personal_skill("global-guide", "Global guide");
            global.deployment_wide = true;
            connections
                .save_skill(&admin, &global)
                .await
                .map_err(|error| error.to_string())?;

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let preserved_owner: Option<String> = pg
                .query_one(
                    "SELECT owner_user_id FROM public.skills WHERE slug='review-notes'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            require(
                preserved_owner.as_deref() == Some(USER_A),
                "admin edit changed the existing skill owner",
            )?;
            drop(pg);

            let user_page = connections
                .list_admin_page(&user_a)
                .await
                .map_err(|error| error.to_string())?;
            let user_slugs = user_page
                .skills
                .iter()
                .map(|skill| skill.slug.as_str())
                .collect::<Vec<_>>();
            require(
                user_slugs.contains(&"review-notes")
                    && user_slugs.contains(&"global-guide")
                    && !user_slugs.contains(&"other-private"),
                format!("actor-scoped skill page drift: {user_slugs:?}"),
            )?;
            let admin_page = connections
                .list_admin_page(&admin)
                .await
                .map_err(|error| error.to_string())?;
            require(
                admin_page.skills.len() == 3,
                format!("admin skill page drift: {:?}", admin_page.skills),
            )?;
            require(
                admin_page.servers.len() == 1
                    && admin_page.servers[0].authentication
                        == openbot_contracts::mcp::McpAdminAuthentication::None
                    && !admin_page.servers[0].has_credential,
                "anonymous MCP server authentication was guessed from presentation",
            )?;

            let owned_skill_grant = skill_grant("review-notes", "agent-owned");
            connections
                .set_grant(&user_a, &owned_skill_grant, true)
                .await
                .map_err(|error| error.to_string())?;
            require(
                matches!(
                    connections
                        .set_grant(
                            &user_a,
                            &skill_grant("review-notes", "agent-public"),
                            true,
                        )
                        .await,
                    Err(McpConnectionError::NotVisible)
                ),
                "personal skill was granted to a Bot the actor does not own",
            )?;
            connections
                .set_grant(
                    &admin,
                    &skill_grant("global-guide", "agent-public"),
                    true,
                )
                .await
                .map_err(|error| error.to_string())?;
            connections
                .set_grant(
                    &admin,
                    &skill_grant("global-guide", "agent-other"),
                    true,
                )
                .await
                .map_err(|error| error.to_string())?;

            let mcp = mcp_grant("agent-owned");
            require(
                matches!(
                    connections.set_grant(&user_a, &mcp, true).await,
                    Err(McpConnectionError::NotVisible)
                ),
                "non-admin MCP grant was not refused",
            )?;
            connections
                .set_grant(&admin, &mcp, true)
                .await
                .map_err(|error| error.to_string())?;
            connections
                .set_grant(&admin, &mcp_grant("agent-other"), true)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.batch_execute(
                "INSERT INTO public.plugin_grants(
                   kind,ref,agent_id,granted_by,created_at,updated_at,state,catalog_generation,
                   schema_hash,effect,transport_fingerprint,credential_generation)
                 SELECT kind,ref,'agent-cross-tenant',granted_by,created_at,updated_at,state,
                        catalog_generation,schema_hash,effect,transport_fingerprint,
                        credential_generation
                   FROM public.plugin_grants
                  WHERE kind='mcp' AND ref='notes/search' AND agent_id='agent-owned';
                 INSERT INTO public.plugin_grants(
                   kind,ref,agent_id,granted_by,created_at,updated_at,state,catalog_generation,
                   schema_hash,effect,transport_fingerprint,credential_generation)
                 SELECT kind,ref,'agent-cross-tenant',granted_by,created_at,updated_at,state,
                        catalog_generation,schema_hash,effect,transport_fingerprint,
                        credential_generation
                   FROM public.plugin_grants
                  WHERE kind='skill' AND ref='global-guide' AND agent_id='agent-public';",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            let scoped_page = connections
                .list_admin_page(&user_a)
                .await
                .map_err(|error| error.to_string())?;
            let scoped_tool = scoped_page.servers[0]
                .tools
                .iter()
                .find(|tool| tool.reference == "notes/search")
                .ok_or_else(|| "scoped admin page omitted current MCP tool".to_owned())?;
            require(
                scoped_tool.granted_to == ["agent-owned"],
                format!(
                    "ordinary actor learned private Agent MCP grants: {:?}",
                    scoped_tool.granted_to
                ),
            )?;
            let scoped_global = scoped_page
                .skills
                .iter()
                .find(|skill| skill.slug == "global-guide")
                .ok_or_else(|| "scoped admin page omitted deployment skill".to_owned())?;
            require(
                scoped_global.granted_to == ["agent-public"],
                format!(
                    "ordinary actor learned private Agent skill grants: {:?}",
                    scoped_global.granted_to
                ),
            )?;
            let governing_page = connections
                .list_admin_page(&admin)
                .await
                .map_err(|error| error.to_string())?;
            let governing_tool = governing_page.servers[0]
                .tools
                .iter()
                .find(|tool| tool.reference == "notes/search")
                .ok_or_else(|| "admin page omitted current MCP tool".to_owned())?;
            require(
                governing_tool.granted_to == ["agent-other", "agent-owned"],
                format!("admin MCP grant governance drift: {governing_tool:?}"),
            )?;
            let governing_global = governing_page
                .skills
                .iter()
                .find(|skill| skill.slug == "global-guide")
                .ok_or_else(|| "admin page omitted deployment skill".to_owned())?;
            require(
                governing_global.granted_to == ["agent-other", "agent-public"],
                format!("admin skill grant governance drift: {governing_global:?}"),
            )?;

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let row = pg
                .query_one(
                    "SELECT state,catalog_generation,schema_hash,effect,transport_fingerprint,
                            credential_generation
                       FROM public.plugin_grants
                      WHERE kind='mcp' AND ref='notes/search' AND agent_id='agent-owned'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            require(
                row.try_get::<_, String>("state").map_err(|error| error.to_string())? == "active"
                    && row
                        .try_get::<_, i64>("catalog_generation")
                        .map_err(|error| error.to_string())?
                        == 1
                    && row
                        .try_get::<_, String>("schema_hash")
                        .map_err(|error| error.to_string())?
                        == schema_hash
                    && row
                        .try_get::<_, String>("effect")
                        .map_err(|error| error.to_string())?
                        == "read"
                    && row
                        .try_get::<_, String>("transport_fingerprint")
                        .map_err(|error| error.to_string())?
                        == fingerprint
                    && row
                        .try_get::<_, i64>("credential_generation")
                        .map_err(|error| error.to_string())?
                        == 0,
                "MCP grant did not bind the exact current catalog identity",
            )?;
            drop(pg);

            let offered = connections
                .list_for_agent(&user_a, &BotId::new("agent-owned"))
                .await
                .map_err(|error| error.to_string())?;
            require(
                offered.tools.len() == 1
                    && offered.tools[0].reference == "notes/search"
                    && offered.tools[0].tool_name == "mcp__notes__search"
                    && offered.skills.len() == 1
                    && offered.skills[0].slug == "review-notes",
                format!("actor-specific plugin projection drift: {offered:?}"),
            )?;
            let public = connections
                .list_for_agent(&user_a, &BotId::new("agent-public"))
                .await
                .map_err(|error| error.to_string())?;
            require(
                public.tools.is_empty()
                    && public.skills.len() == 1
                    && public.skills[0].slug == "global-guide",
                format!("public Agent projection drift: {public:?}"),
            )?;
            for invisible in [
                "agent-other",
                "agent-deleted",
                "agent-cross-tenant",
                "missing-agent",
            ] {
                require(
                    matches!(
                        connections
                            .list_for_agent(&user_a, &BotId::new(invisible))
                            .await,
                        Err(McpConnectionError::NotVisible)
                    ),
                    format!("invisible Agent {invisible} projected plugins"),
                )?;
            }
            require(
                matches!(
                    connections
                        .list_for_agent(&admin, &BotId::new("agent-cross-tenant"))
                        .await,
                    Err(McpConnectionError::NotVisible)
                ),
                "admin crossed the configured tenant boundary",
            )?;

            let mut pg = pool.get().await.map_err(|error| error.to_string())?;
            let transaction = pg.transaction().await.map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.mcp_servers
                        SET catalog_generation=2,catalog_hash=repeat('d',64)
                      WHERE id='notes'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .execute(
                    "UPDATE public.mcp_tools SET catalog_generation=2
                      WHERE server_id='notes' AND name='search'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .commit()
                .await
                .map_err(|error| error.to_string())?;
            drop(pg);
            require(
                connections
                    .list_for_agent(&user_a, &BotId::new("agent-owned"))
                    .await
                    .map_err(|error| error.to_string())?
                    .tools
                    .is_empty(),
                "catalog-generation drift did not suspend the old grant",
            )?;
            connections
                .set_grant(&admin, &mcp, true)
                .await
                .map_err(|error| error.to_string())?;

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers SET credential_generation=1 WHERE id='notes'",
                &[],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            require(
                connections
                    .list_for_agent(&user_a, &BotId::new("agent-owned"))
                    .await
                    .map_err(|error| error.to_string())?
                    .tools
                    .is_empty(),
                "credential-generation drift did not suspend the old grant",
            )?;
            connections
                .set_grant(&admin, &mcp, true)
                .await
                .map_err(|error| error.to_string())?;

            let endpoint_v2 = "https://notes.example.test/mcp-v2";
            let fingerprint_v2 = transport_fingerprint(endpoint_v2);
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.execute(
                "UPDATE public.mcp_servers
                    SET url=$1,catalog_transport_fingerprint=$2 WHERE id='notes'",
                &[&endpoint_v2, &fingerprint_v2],
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            require(
                connections
                    .list_for_agent(&user_a, &BotId::new("agent-owned"))
                    .await
                    .map_err(|error| error.to_string())?
                    .tools
                    .is_empty(),
                "transport drift did not suspend the old grant",
            )?;
            connections
                .set_grant(&admin, &mcp, true)
                .await
                .map_err(|error| error.to_string())?;
            require(
                connections
                    .list_for_agent(&user_a, &BotId::new("agent-owned"))
                    .await
                    .map_err(|error| error.to_string())?
                    .tools
                    .len()
                    == 1,
                "current MCP re-grant was not offered",
            )?;

            let pg = pool.get().await.map_err(|error| error.to_string())?;
            pg.batch_execute(
                "UPDATE public.mcp_tools SET available=false
                   WHERE server_id='notes' AND name='search';
                 UPDATE public.agent_profiles SET deleted_at=clock_timestamp()
                   WHERE agent_id='agent-owned';",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);

            connections
                .set_grant(&admin, &mcp, false)
                .await
                .map_err(|error| error.to_string())?;
            connections
                .set_grant(&admin, &mcp, false)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let remaining_mcp_grants: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.plugin_grants
                      WHERE kind='mcp' AND ref='notes/search' AND agent_id='agent-owned'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            require(
                remaining_mcp_grants == 0,
                "admin could not idempotently revoke a stale grant from a soft-deleted Agent",
            )?;
            drop(pg);

            connections
                .remove_skill(&user_a, "review-notes", 2)
                .await
                .map_err(|error| error.to_string())?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let dangling: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint
                       FROM public.plugin_grants
                      WHERE kind='skill' AND ref='review-notes'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            require(dangling == 0, "skill deletion left dangling grants")?;
            pg.batch_execute(
                "CREATE FUNCTION public.reject_rollback_skill_audit() RETURNS trigger
                   LANGUAGE plpgsql AS $$
                   BEGIN
                     IF NEW.target_type='skill' AND NEW.target_id='rollback-skill' THEN
                       RAISE EXCEPTION 'test audit refusal';
                     END IF;
                     RETURN NEW;
                   END
                   $$;
                 CREATE TRIGGER reject_rollback_skill_audit
                   BEFORE INSERT ON public.audit_events
                   FOR EACH ROW EXECUTE FUNCTION public.reject_rollback_skill_audit();",
            )
            .await
            .map_err(|error| error.to_string())?;
            drop(pg);
            require(
                matches!(
                    connections
                        .save_skill(
                            &user_a,
                            &personal_skill("rollback-skill", "Rollback skill"),
                        )
                        .await,
                    Err(McpConnectionError::Unavailable)
                ),
                "audit refusal did not fail the mutation closed",
            )?;
            let pg = pool.get().await.map_err(|error| error.to_string())?;
            let rolled_back: i64 = pg
                .query_one(
                    "SELECT count(*)::bigint FROM public.skills WHERE slug='rollback-skill'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            require(rolled_back == 0, "audit failure committed the skill mutation")?;
            pg.batch_execute(
                "DROP TRIGGER reject_rollback_skill_audit ON public.audit_events;
                 DROP FUNCTION public.reject_rollback_skill_audit();",
            )
            .await
            .map_err(|error| error.to_string())?;

            let audit_rows = pg
                .query(
                    "SELECT target_type,target_id,payload,prev_hash,row_hash
                       FROM public.audit_events
                      WHERE event_type='configuration.changed'
                      ORDER BY created_at,id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            require(
                audit_rows.len() == 15,
                format!("plugin audit count drift: {}", audit_rows.len()),
            )?;
            let mut changes = BTreeMap::<String, usize>::new();
            let mut previous: Option<String> = None;
            for row in audit_rows {
                let target_type: String = row
                    .try_get("target_type")
                    .map_err(|error| error.to_string())?;
                let target_id: String = row
                    .try_get("target_id")
                    .map_err(|error| error.to_string())?;
                let payload: Value = row
                    .try_get("payload")
                    .map_err(|error| error.to_string())?;
                let prev_hash: Option<String> = row
                    .try_get("prev_hash")
                    .map_err(|error| error.to_string())?;
                let row_hash: String = row
                    .try_get("row_hash")
                    .map_err(|error| error.to_string())?;
                require(
                    prev_hash == previous,
                    format!("audit chain broke before {target_type}/{target_id}"),
                )?;
                require(
                    row_hash.len() == 64
                        && row_hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                    "audit row hash is not canonical lowercase SHA-256",
                )?;
                previous = Some(row_hash);

                let object = payload
                    .as_object()
                    .ok_or_else(|| "plugin audit payload is not an object".to_owned())?;
                let change = object
                    .get("change")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "plugin audit is missing its closed change".to_owned())?;
                *changes.entry(change.to_owned()).or_default() += 1;
                let editing = matches!(change, "skill_saved" | "skill_removed");
                require(
                    object.keys().all(|key| key == "change" || key == "bot"
                        || (editing && key == "skill_revision"))
                        && object.len() == 1 + usize::from(object.contains_key("bot"))
                            + usize::from(editing)
                        && (if editing {
                            target_type == "skill" && object.get("skill_revision")
                                .and_then(Value::as_u64).is_some_and(|revision| revision > 0)
                        } else { !object.contains_key("skill_revision") }),
                    format!("plugin audit payload escaped its allowlist: {payload}"),
                )?;
                require(
                    !payload.to_string().contains(INSTRUCTION_CANARY),
                    "skill instructions leaked into audit payload",
                )?;
            }
            require(
                changes.get("skill_saved") == Some(&4)
                    && changes.get("plugin_granted") == Some(&8)
                    && changes.get("plugin_revoked") == Some(&2)
                    && changes.get("skill_removed") == Some(&1),
                format!("closed plugin audit vocabulary drift: {changes:?}"),
            )?;
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
