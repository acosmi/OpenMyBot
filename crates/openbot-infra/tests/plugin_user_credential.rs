//! W-5 G2 ledger batch 6：per-user credential 选择、拒绝与孤儿退役的 PG17 真库矩阵。

mod harness;

use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use harness::{admin_config, with_temp_database};
use openbot_application::PeopleAdministration;
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::vault::{
    KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use openbot_infra::store::plugin_user_credential::{
    OAuthRefreshExchange, OAuthTokenExchangeError, PluginUserCredentialStore,
    PostgresOwnedCredentialRetirer, RotatingOAuthGrant, RotatingOAuthTokenExchanger,
    UserCredentialRefusal, UserCredentialSelectionError, UserOAuthAccessError,
};
use openbot_infra::vault::CredentialRecordVault;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ASKER: &str = "credential-asker";
const OTHER: &str = "credential-other";
const ADMIN: &str = "credential-admin";
const DRIVE: &str = "google-drive";
const CALENDAR: &str = "google-calendar";
const SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
// 全部是固定测试明文，只在每用例的临时 PG 数据库里被 v2 加密；从不用于网络请求。
const ASKER_REFRESH: &[u8] = b"refresh-token-for-asker";
const OTHER_REFRESH: &[u8] = b"refresh-token-for-other";
const OAUTH_CLIENT: &[u8] = br#"{"clientId":"client-id","clientSecret":"client-secret"}"#;
const AUDIT_KEY: &[u8] = b"plugin-user-credential-audit-key-at-least-32";

#[derive(Clone)]
struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    store: PluginUserCredentialStore,
    retirer: PostgresOwnedCredentialRetirer,
}

async fn with_fixture<F, Fut>(test_name: &'static str, tag: &'static str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(test_name);
    with_temp_database(&admin, tag, move |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| format!("连接临时库失败：{error}"))?;
        let outcome = async {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "INSERT INTO public.users(id,email,name,email_verified,auth_generation) VALUES
                     ('credential-admin','admin@openbot.test','Admin',true,0),
                     ('credential-asker','asker@openbot.test','Asker',true,0),
                     ('credential-other','other@openbot.test','Other',true,0);
                     INSERT INTO public.user_roles(user_id,role) VALUES
                     ('credential-admin','admin'),('credential-asker','user'),('credential-other','user');
                     INSERT INTO public.mcp_servers(id,title,vendor,url,provenance) VALUES
                     ('google-drive','Google Drive','Google','https://www.googleapis.com/drive/v3','first-party'),
                     ('google-calendar','Google Calendar','Google','https://www.googleapis.com/calendar/v3','first-party');",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let vault = CredentialRecordVault::single_key(
                TenantId::new("tenant-credential-tests"),
                KeyVersion::new(1),
                WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
            );
            let fixture = Fixture {
                pool: pool.clone(),
                store: PluginUserCredentialStore::new(pool.clone(), vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")))
                    .with_rotation_audit_key(AUDIT_KEY.to_vec())
                    .map_err(|error| error.to_string())?,
                retirer: PostgresOwnedCredentialRetirer::new(pool.clone(), AUDIT_KEY.to_vec(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")))
                    .map_err(|error| error.to_string())?,
                vault,
            };
            body(fixture).await
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

async fn insert_user_token(
    fixture: &Fixture,
    server: &str,
    actor: &str,
    plaintext: &[u8],
) -> Result<Uuid, String> {
    let id = Uuid::new_v4();
    let secret = SecretBytes::new(plaintext.to_vec());
    let encrypted = fixture
        .vault
        .seal(
            &id,
            SecretKind::McpUserToken,
            SecretPrincipal::Actor(ActorId::new(actor)),
            SecretPrincipal::Service(ServiceId::new(server)),
            &secret,
        )
        .map_err(|error| error.to_string())?;
    fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .execute(
            "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata) \
             VALUES($1,'mcp_user_token',$2,$3,$4,'{}')",
            &[&id, &server, &encrypted, &actor],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(id)
}

async fn connect(
    fixture: &Fixture,
    server: &str,
    actor: &str,
    plaintext: &[u8],
) -> Result<Uuid, String> {
    let id = insert_user_token(fixture, server, actor, plaintext).await?;
    fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .execute(
            "INSERT INTO public.mcp_user_credentials(server_id,user_id,credential_id,scope) \
             VALUES($1,$2,$3,$4) ON CONFLICT(server_id,user_id) DO UPDATE SET \
             credential_id=excluded.credential_id,scope=excluded.scope,updated_at=clock_timestamp()",
            &[&server, &actor, &id, &SCOPE],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(id)
}

async fn register_client(fixture: &Fixture, server: &str) -> Result<Uuid, String> {
    let id = Uuid::new_v4();
    let secret = SecretBytes::new(OAUTH_CLIENT.to_vec());
    let encrypted = fixture
        .vault
        .seal(
            &id,
            SecretKind::McpOauthClient,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new(server)),
            &secret,
        )
        .map_err(|error| error.to_string())?;
    let client = fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata) \
             VALUES($1,'mcp_oauth_client',$2,$3,'oauth-client','{}')",
            &[&id, &server, &encrypted],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "UPDATE public.mcp_servers SET credential_id=$2 WHERE id=$1",
            &[&server, &id],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(id)
}

async fn revoke(fixture: &Fixture, id: Uuid) -> Result<(), String> {
    fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .execute(
            "UPDATE public.credentials SET revoked_at=clock_timestamp() WHERE id=$1",
            &[&id],
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

async fn scalar(fixture: &Fixture, sql: &str, value: &str) -> Result<i64, String> {
    fixture
        .pool
        .get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(sql, &[&value])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExchangeObservation {
    refresh: [u8; 32],
    client: [u8; 32],
}

#[derive(Default)]
struct RecordingExchanger {
    calls: Mutex<Vec<ExchangeObservation>>,
}

impl RecordingExchanger {
    fn calls(&self) -> Vec<ExchangeObservation> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RotatingOAuthTokenExchanger for RecordingExchanger {
    fn requires_refresh_rotation(&self) -> bool {
        false
    }

    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        self.calls.lock().unwrap().push(ExchangeObservation {
            refresh: digest(request.expose_refresh_token()),
            client: digest(request.expose_oauth_client()),
        });
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(format!("access-token-for-{}", request.server_id()).into_bytes()),
            None,
            None,
        ))
    }
}

struct EchoExchanger;

#[async_trait]
impl RotatingOAuthTokenExchanger for EchoExchanger {
    fn requires_refresh_rotation(&self) -> bool {
        false
    }

    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(request.expose_refresh_token().to_vec()),
            None,
            None,
        ))
    }
}

struct EmptyExchanger;

#[async_trait]
impl RotatingOAuthTokenExchanger for EmptyExchanger {
    fn requires_refresh_rotation(&self) -> bool {
        false
    }

    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(Vec::new()),
            None,
            None,
        ))
    }
}

struct EgressDriftExchanger {
    pool: openbot_infra::db::pool::DatabasePool,
}

#[async_trait]
impl RotatingOAuthTokenExchanger for EgressDriftExchanger {
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        if request.server_id() != "private-oauth"
            || request.transport() != "mcp"
            || request.egress_allowlist().len() != 1
        {
            return Err(OAuthTokenExchangeError::InvalidResponse);
        }
        self.pool
            .get()
            .await
            .map_err(|_| OAuthTokenExchangeError::Unavailable)?
            .execute(
                "UPDATE public.mcp_servers
                    SET egress_allow_cidrs=ARRAY['10.1.0.0/16'] WHERE id='private-oauth'",
                &[],
            )
            .await
            .map_err(|_| OAuthTokenExchangeError::Unavailable)?;
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(b"access-after-egress-drift".to_vec()),
            Some(SecretBytes::new(b"refresh-after-egress-drift".to_vec())),
            Some("private:read".to_owned()),
        ))
    }
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

async fn successful_exchange(
    fixture: &Fixture,
    server: &str,
    actor: &str,
) -> Result<([u8; 32], Vec<ExchangeObservation>), String> {
    let exchanger = RecordingExchanger::default();
    let access = fixture
        .store
        .fresh_user_access_token(server, &ActorId::new(actor), &exchanger)
        .await
        .map_err(|error| error.to_string())?;
    Ok((digest(access.expose_for_vendor()), exchanger.calls()))
}

fn refusal(
    error: UserCredentialSelectionError,
    expected: UserCredentialRefusal,
) -> Result<(), String> {
    if error == UserCredentialSelectionError::Refused(expected)
        && error.to_string() == expected.code()
    {
        Ok(())
    } else {
        Err(format!("拒绝分类不符：{error:?}"))
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn is_refused_and_told_to_connect_rather_than_told_it_broke() {
    with_fixture(
        "is_refused_and_told_to_connect_rather_than_told_it_broke",
        "credential_missing",
        |fixture| async move {
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ConnectionRequired,
            )?;
            register_client(&fixture, DRIVE).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn is_not_quietly_served_the_deployment_s_own_credential() {
    with_fixture(
        "is_not_quietly_served_the_deployment_s_own_credential",
        "credential_no_fallback",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ConnectionRequired,
            )?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn cannot_borrow_a_connected_person_s_access() {
    with_fixture(
        "cannot_borrow_a_connected_person_s_access",
        "credential_anonymous",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(""))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ActorRequired,
            )?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn is_told_plainly_when_the_deployment_has_registered_no_client() {
    with_fixture(
        "is_told_plainly_when_the_deployment_has_registered_no_client",
        "credential_no_client",
        |fixture| async move {
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::DeploymentClientRequired,
            )?;
            register_client(&fixture, DRIVE).await?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn goes_out_with_their_own_token_and_nobody_else_s() {
    with_fixture(
        "goes_out_with_their_own_token_and_nobody_else_s",
        "credential_owners",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            connect(&fixture, DRIVE, OTHER, OTHER_REFRESH).await?;

            let (_, asker_calls) = successful_exchange(&fixture, DRIVE, ASKER).await?;
            let (_, other_calls) = successful_exchange(&fixture, DRIVE, OTHER).await?;
            if asker_calls.len() != 1
                || other_calls.len() != 1
                || asker_calls[0].refresh != digest(ASKER_REFRESH)
                || other_calls[0].refresh != digest(OTHER_REFRESH)
                || asker_calls[0].refresh == other_calls[0].refresh
                || asker_calls[0].client != digest(OAUTH_CLIENT)
                || other_calls[0].client != digest(OAUTH_CLIENT)
            {
                return Err("(server, actor) 没有精确选择各自 refresh token/client".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn never_sends_the_refresh_token_itself_to_the_vendor() {
    with_fixture(
        "never_sends_the_refresh_token_itself_to_the_vendor",
        "credential_no_passthrough",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            let prepared = fixture
                .store
                .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                .await
                .map_err(|error| error.to_string())?;
            let debug = format!("{prepared:?}");
            if debug.contains("refresh-token") || debug.contains("client-secret") {
                return Err("prepared credential Debug 泄露秘密".to_owned());
            }
            if fixture
                .store
                .fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &EchoExchanger)
                .await
                .unwrap_err()
                != UserOAuthAccessError::Exchange(OAuthTokenExchangeError::RefreshTokenPassthrough)
            {
                return Err("refresh token echo 没有在 VendorAccessToken 铸造前被拒绝".to_owned());
            }
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            if fixture
                .store
                .fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &EmptyExchanger)
                .await
                .unwrap_err()
                != UserOAuthAccessError::Exchange(OAuthTokenExchangeError::InvalidResponse)
            {
                return Err("空 access token 没有在 VendorAccessToken 铸造前被拒绝".to_owned());
            }
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            let (access_hash, calls) = successful_exchange(&fixture, DRIVE, ASKER).await?;
            if calls.len() != 1
                || calls[0].refresh != digest(ASKER_REFRESH)
                || access_hash == digest(ASKER_REFRESH)
            {
                return Err("vendor access token 与 refresh token 的类型/值边界失效".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn egress_drift_after_token_response_prevents_rotation_and_access_release() {
    with_fixture(
        "egress_drift_after_token_response_prevents_rotation_and_access_release",
        "credential_egress_drift",
        |fixture| async move {
            fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .execute(
                    "INSERT INTO public.mcp_servers(
                       id,title,vendor,url,provenance,transport,egress_allow_cidrs)
                     VALUES('private-oauth','Private OAuth','private.test',
                            'https://private.test/mcp','custom','mcp',
                            ARRAY['10.0.0.0/8'])",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            register_client(&fixture, "private-oauth").await?;
            let credential = connect(
                &fixture,
                "private-oauth",
                ASKER,
                b"private-refresh-before-drift",
            )
            .await?;
            let before: String = fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT encrypted_value FROM public.credentials WHERE id=$1",
                    &[&credential],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let outcome = fixture
                .store
                .fresh_user_access_token(
                    "private-oauth",
                    &ActorId::new(ASKER),
                    &EgressDriftExchanger {
                        pool: fixture.pool.clone(),
                    },
                )
                .await;
            if !matches!(
                &outcome,
                Err(UserOAuthAccessError::Selection(
                    UserCredentialSelectionError::Conflict
                ))
            ) {
                return Err(format!(
                    "egress drift outcome was not conflict: {outcome:?}"
                ));
            }
            let evidence = fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .query_one(
                    "SELECT c.encrypted_value=$2,
                            (SELECT count(*)::bigint FROM public.audit_events
                              WHERE event_type='credential.rotated' AND target_id=$3)
                       FROM public.credentials c WHERE c.id=$1",
                    &[&credential, &before, &credential.to_string()],
                )
                .await
                .map_err(|error| error.to_string())?;
            let unchanged: bool = evidence.try_get(0).map_err(|error| error.to_string())?;
            let audits: i64 = evidence.try_get(1).map_err(|error| error.to_string())?;
            if !unchanged || audits != 0 {
                return Err("egress drift rotated credential or wrote success audit".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn is_refused_once_their_credential_is_revoked_and_told_to_reconnect() {
    with_fixture(
        "is_refused_once_their_credential_is_revoked_and_told_to_reconnect",
        "credential_revoked",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            let old = connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            revoke(&fixture, old).await?;
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ReconnectRequired,
            )?;
            connect(&fixture, DRIVE, ASKER, b"refresh-after-reconnect").await?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn does_not_gain_access_to_a_server_they_connected_a_different_one_for() {
    with_fixture(
        "does_not_gain_access_to_a_server_they_connected_a_different_one_for",
        "credential_server_pair",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            register_client(&fixture, CALENDAR).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(CALENDAR, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ConnectionRequired,
            )?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn the_vault_stops_holding_a_usable_secret_and_the_connection_is_gone() {
    with_fixture(
        "the_vault_stops_holding_a_usable_secret_and_the_connection_is_gone",
        "credential_people_retire",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            let credential = connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            successful_exchange(&fixture, DRIVE, ASKER).await?;

            let people = PostgresPeopleAdministration::new(
                fixture.pool.clone(),
                None,
                AUDIT_KEY.to_vec(),
            )
            .map_err(|error| error.to_string())?
            .with_owned_credential_retirer(Arc::new(fixture.retirer.clone()));
            let person = people
                .change_access(&ActorId::new(ADMIN), &ActorId::new(ASKER), true)
                .await
                .map_err(|error| error.to_string())?;
            if !person.revoked {
                return Err("people access 没有先完成移除".to_owned());
            }
            let client = fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?;
            let revoked: bool = client
                .query_one(
                    "SELECT revoked_at IS NOT NULL FROM public.credentials WHERE id=$1",
                    &[&credential],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let audit_count: i64 = client
                .query_one(
                    "SELECT count(*)::bigint FROM public.audit_events WHERE \
                     event_type='mcp.account_disconnected' AND target_id=$1 AND \
                     payload->>'credential_owner'=$2 AND payload->>'revocation_reason'='person_removed' AND \
                     payload->>'vendor_revoked'='false'",
                    &[&DRIVE, &ASKER],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            if !revoked
                || audit_count != 1
                || !fixture
                    .store
                    .connections_for(&ActorId::new(ASKER))
                    .await
                    .map_err(|error| error.to_string())?
                    .is_empty()
                || scalar(
                    &fixture,
                    "SELECT count(*)::bigint FROM public.credentials WHERE \
                     kind='mcp_user_token' AND key_id=$1 AND revoked_at IS NULL",
                    ASKER,
                )
                .await?
                    != 0
            {
                return Err("people→vault 退役、connection 清理或 typed audit 不完整".to_owned());
            }
            refusal(
                fixture
                    .store
                    .prepare_user_oauth_call(DRIVE, &ActorId::new(ASKER))
                    .await
                    .unwrap_err(),
                UserCredentialRefusal::ConnectionRequired,
            )?;
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn a_credential_orphaned_by_a_deleted_user_row_is_still_retired() {
    with_fixture(
        "a_credential_orphaned_by_a_deleted_user_row_is_still_retired",
        "credential_orphan",
        |fixture| async move {
            let credential = connect(&fixture, DRIVE, OTHER, OTHER_REFRESH).await?;
            fixture
                .pool
                .get()
                .await
                .map_err(|error| error.to_string())?
                .execute("DELETE FROM public.users WHERE id=$1", &[&OTHER])
                .await
                .map_err(|error| error.to_string())?;
            if scalar(
                &fixture,
                "SELECT count(*)::bigint FROM public.mcp_user_credentials WHERE user_id=$1",
                OTHER,
            )
            .await?
                != 0
                || scalar(
                    &fixture,
                    "SELECT count(*)::bigint FROM public.credentials WHERE id::text=$1 AND revoked_at IS NULL",
                    &credential.to_string(),
                )
                .await?
                    != 1
            {
                return Err("user delete 没有造出预期的 join-gone/vault-live 孤儿".to_owned());
            }
            let retired = fixture
                .retirer
                .retire_connections_for(&ActorId::new(OTHER), &ActorId::new(ADMIN))
                .await
                .map_err(|error| error.to_string())?;
            if retired != 1
                || scalar(
                    &fixture,
                    "SELECT count(*)::bigint FROM public.credentials WHERE id::text=$1 AND revoked_at IS NULL",
                    &credential.to_string(),
                )
                .await?
                    != 0
            {
                return Err("没有经 credentials.kind+key_id 找回并退役孤儿".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn retiring_twice_is_quiet_and_nobody_owns_nothing() {
    with_fixture(
        "retiring_twice_is_quiet_and_nobody_owns_nothing",
        "credential_idempotent",
        |fixture| async move {
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            insert_user_token(&fixture, CALENDAR, ASKER, b"second-orphan-token").await?;
            let first = fixture
                .retirer
                .retire_connections_for(&ActorId::new(ASKER), &ActorId::new(ADMIN))
                .await
                .map_err(|error| error.to_string())?;
            let second = fixture
                .retirer
                .retire_connections_for(&ActorId::new(ASKER), &ActorId::new(ADMIN))
                .await
                .map_err(|error| error.to_string())?;
            let nobody = fixture
                .retirer
                .retire_connections_for(&ActorId::new(""), &ActorId::new(ADMIN))
                .await
                .map_err(|error| error.to_string())?;
            if first != 2 || second != 0 || nobody != 0 {
                return Err("退役计数不满足 all-active / idempotent / anonymous-zero".to_owned());
            }
            Ok(())
        },
    )
    .await;
}

#[path = "plugin_user_credential/refresh_tests.rs"]
mod refresh_tests;

#[path = "plugin_user_credential/commit_proxy.rs"]
mod commit_proxy;
