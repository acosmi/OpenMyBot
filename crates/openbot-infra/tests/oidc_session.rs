//! W-7 OIDC attempt/session/group 的 PostgreSQL 17 真库矩阵。

mod harness;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use harness::{admin_config, with_temp_database};
use hmac::{Hmac, Mac};
use openbot_contracts::ids::TenantId;
use openbot_domain::identity::groups::{
    GroupClaimPath, GroupNormalization, IdentityProviderId, IdpGroupMapping,
};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::vault::SecretBytes;
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::oidc::claims::{
    DirectoryIdTokenClaims, build_verifier, verify_with_group_mapping,
};
use openbot_infra::auth::oidc::provider::parse_issuer;
use openbot_infra::auth::oidc::{
    CanonicalRedirectUri, FetchBudget, LoginAttempt, OidcLoginCoordinator, OidcProviderConfig,
    OidcProviderRuntime, OidcRateLimitBucket, PostgresAttemptError, PostgresLoginAttemptStore,
    PostgresOidcRateLimiter, PostgresOidcSessionIssuer, ProviderId, ProviderKind, ProviderOrigin,
    RateLimitPolicy, SessionIssueError,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::net::safe_http::{
    CidrAllowlist, DnsResolver, DnsUnavailable, EgressPolicy, SafeDialer,
};
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};
use openidconnect::{ClientId, ClientSecret, JsonWebKeySet, Nonce};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HASH_KEY: &[u8] = b"oidc-session-integration-hash-key-32bytes";
const AUDIT_KEY: &[u8] = b"oidc-session-integration-audit-key";
const HMAC_SECRET: &str = "oidc-hmac-id-token-test-secret";
const NOW: i64 = 1_800_000_000;
const FAR_FUTURE: i64 = 9_999_999_999;

const TLS_CA_DER: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TLS_LEAF_DER: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TLS_LEAF_KEY_DER: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
const RSA_KEY_DER: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOwlECHGhbCo0GavhO8G+w5qxQc1+PdpBsgdd6two0pwvxo8u2mMry42lAhYJbrVUiqQjKBmCIHJ/+a0LfN/jrGPJtmTjzeGXmL4qRNWj/bSprl1xFcTKdM+B36xMFNS3xLc7LtnWrCGH+30h/vCZAqq21lajUypEs8tBYB/JDRm5BXM8GwMOV9UXhOmRn9QaV4a7/0hxPb3yGwejXpE9lNVU2P1LqTe+p8ArFMbJAxKGZRlkpWZNROej/pd9jrdh+s2WrmqXEahy4P1ztBMM6dO1DDOw9+aHzp9iWEs0LuMBfLRtJGC492Be5EFuZ0lP9K2AADRrXhgmHTI9XAQmTAgMBAAECggEAIr3dUwMwzj8iFNbBeQyAUe/BLY72SYaUHSP4GZAj9q5UdMjk0ZobgcKgIaicEc1784RpdCjbIyS8NwFJc+M+O5CFpvBr8KxzN/KH6VCzLb4WXbqnJOsoYyN11BksNs87T/9S3TaZKjdPCeSy0wsp0AD5Z0B1pttpOyQYWeQNLBvButokgPE0tvL8FotCiTLciAXkj0LLzJX28L5NGsEEdXLnQ/3MC7iLxd2c4Zi9k0bP+eAuKtNSFvMrbKSei5Cbby0SadAuv5S4r4GQ+XCemnvSaEnwWQucrE5dgvyVDeDenhi+DOl1OWXMCkKVxng69LkZvPLnfYKMCoDVbywVIQKBgQC/742drVx41MfQu4Gk6nqtAwSAzVlkJqhWdwJPOxSv+r9EmIiHPtH7owlEaYi0AtpDjS3vwfi0fYuVBRJEMFQWklFhzwsaKFEL0aLtoWTuwmnjpqsmcIKvnRVfjsR04qoeQAexBp0kzKCNTU5/zBnOrY24RMLqSSIUZI+SSXgf0QKBgQC+aLuCIiHcm+leM6YD2D2qLzpEkewP44l4vukw6LCShPCWiFlUPasvEpSc7TfYgVsz91KYtN2W3Xvr370D5j0GpFIx+nh0a2xZ6fYzgTWqt9sP9yEwSUixE1EyE6XayxxlsIgkty4yocFdcdSjTXjOjZ7eINGz3TeVU1O99KWwIwKBgD9PE+YrlbHhdZs7DhNIqHhC44xcr5yiR6pljOR3d2ZojghhS79YkEixSVBAgy/lNPtNKRbJY3CdbJoV1yWYz1O2pZNeiKnzHHCKkHRTZQiAJg9KHXALcn/cj306iUCIt1ZNBnx00wadXGPfWQI8X1LV2kYqoCRJRS120giNpUrRAoGANcXGDn4tKewt/5h+bd+HqqQjxHGhROtxS1Q+7r0IAJjiiOCAubWgvm504cxsVQxTAV37SXzqh0yNTpOlAZDn8xQ80jh2BArCUrIsAWegDFJX3y5fhQ9tI/TcnVPHJv7tShqMmDHTLiFYRld7QZMDZvG/x+Nk1XLH27fokmCg2hkCgYASbp3+tgJ51j3Ci+2nXJ8ISJIfx2I10pbXAsIXNqIqZ7AR3TV5Ezhde6Sb1fg2AoZZmuAxHbJ9/w6tib2nGp8VaNN+dkiyekbLIgfUMH8gQr3bCiMio1wFVWj/ptuioPbiHvEsC092HFJiUiUp9H/PwmVb42UzpznxmfCgSca6Wg==";
const RSA_N: &str = "jsJRAhxoWwqNBmr4TvBvsOasUHNfj3aQbIHXercKNKcL8aPLtpjK8uNpQIWCW61VIqkIygZgiByf_mtC3zf46xjybZk483hl5i-KkTVo_20qa5dcRXEynTPgd-sTBTUt8S3Oy7Z1qwhh_t9If7wmQKqttZWo1MqRLPLQWAfyQ0ZuQVzPBsDDlfVF4TpkZ_UGleGu_9IcT298hsHo16RPZTVVNj9S6k3vqfAKxTGyQMShmUZZKVmTUTno_6XfY63YfrNlq5qlxGocuD9c7QTDOnTtQwzsPfmh86fYlhLNC7jAXy0bSRguPdgXuRBbmdJT_StgAA0a14YJh0yPVwEJkw";

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
            r#"
            INSERT INTO public.channels(id,name,description,allowed_groups) VALUES
              ('channel-all','All','all audience',ARRAY['all']),
              ('channel-risk','Risk','risk audience',ARRAY['risk']),
              ('channel-finance','Finance','finance audience',ARRAY['finance']);
            "#,
        )
        .await
        .map_err(|error| error.to_string())
}

fn provider(id: &str, issuer: &str) -> OidcProviderConfig {
    OidcProviderConfig::new(
        ProviderId::parse(id).unwrap(),
        ProviderKind::DeploymentOwned {
            issuer: parse_issuer(issuer).unwrap(),
        },
        ProviderOrigin::EnvironmentConfigured,
        ClientId::new(format!("{id}-client")),
        CanonicalRedirectUri::parse(
            "https://app.example.com/auth/callback",
            openbot_infra::auth::oidc::redirect::HTTPS_ONLY,
        )
        .unwrap(),
        BTreeSet::new(),
        None,
    )
}

fn identity(
    provider: &OidcProviderConfig,
    email: &str,
    subject: &str,
    groups_json: &str,
) -> openbot_infra::auth::oidc::VerifiedIdentity {
    let claims = format!(
        r#"{{"iss":"{}","aud":["{}"],"exp":{},"iat":{},"sub":"{}","nonce":"nonce-1","email":"{}","groups":{}}}"#,
        provider.issuer().as_str(),
        provider.client_id().as_str(),
        FAR_FUTURE,
        NOW,
        subject,
        email,
        groups_json,
    );
    let raw = sign_raw(&claims);
    let anchor: DirectoryIdTokenClaims = serde_json::from_str(&format!(
        r#"{{"iss":"{}","aud":["{}"],"exp":{},"iat":{},"sub":"anchor","email":"anchor@example.com"}}"#,
        provider.issuer().as_str(),
        provider.client_id().as_str(),
        NOW,
        NOW,
    ))
    .unwrap();
    let fixed_now = anchor.expiration();
    let verifier = build_verifier(
        provider,
        Some(&ClientSecret::new(HMAC_SECRET.to_owned())),
        JsonWebKeySet::<CoreJsonWebKey>::new(Vec::new()),
        &[CoreJwsSigningAlgorithm::HmacSha256],
    )
    .set_time_fn(move || fixed_now);
    let mapping = IdpGroupMapping::new(
        IdentityProviderId::new(provider.id().as_str()),
        GroupClaimPath::from_dotted("groups").unwrap(),
        GroupNormalization::TrimLowercase,
    );
    verify_with_group_mapping(
        &raw,
        &verifier,
        provider,
        &Nonce::new("nonce-1".to_owned()),
        Some(&mapping),
    )
    .unwrap()
}

fn sign_raw(claims_json: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
    let input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(HMAC_SECRET.as_bytes()).unwrap();
    mac.update(input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{input}.{signature}")
}

fn issuer(pool: &openbot_infra::db::pool::DatabasePool) -> PostgresOidcSessionIssuer {
    PostgresOidcSessionIssuer::new(
        pool.clone(),
        HASH_KEY,
        default_session_lifetime(),
        AdminFloor::from_configured(["admin@example.com"]).unwrap(),
        AUDIT_KEY,
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
            pool,
            &openbot_contracts::ids::DeploymentId::new("oidc-session"),
            &TenantId::new("tenant-1"),
        ),
    )
    .unwrap()
}

async fn scalar(pool: &openbot_infra::db::pool::DatabasePool, sql: &str) -> Result<i64, String> {
    pool.get()
        .await
        .map_err(|error| error.to_string())?
        .query_one(sql, &[])
        .await
        .map_err(|error| error.to_string())?
        .try_get(0)
        .map_err(|error| error.to_string())
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn attempt_is_cross_replica_single_use_and_every_failure_burns_state() {
    let admin = admin_config("attempt_is_cross_replica_single_use_and_every_failure_burns_state");
    with_temp_database(&admin, "oidc_attempt", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let tenant = TenantId::new("tenant-1");
            let first = PostgresLoginAttemptStore::new(pool.clone(), HASH_KEY, &tenant, 8)
                .map_err(|error| error.to_string())?;
            let second = PostgresLoginAttemptStore::new(pool.clone(), HASH_KEY, &tenant, 8)
                .map_err(|error| error.to_string())?;
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            let provider = ProviderId::parse("okta").unwrap();

            let attempt = LoginAttempt::begin(
                provider.clone(),
                CanonicalRedirectUri::parse(
                    "https://app.example.com/auth/callback",
                    openbot_infra::auth::oidc::redirect::HTTPS_ONLY,
                )
                .unwrap(),
                now,
                Duration::minutes(10),
            );
            let state = attempt.state().secret().clone();
            first
                .insert(attempt, now)
                .await
                .map_err(|error| error.to_string())?;
            let (left, right) = tokio::join!(
                first.consume(&state, &provider, now),
                second.consume(&state, &provider, now)
            );
            if usize::from(left.is_ok()) + usize::from(right.is_ok()) != 1
                || !matches!(
                    left.as_ref().err().or(right.as_ref().err()),
                    Some(PostgresAttemptError::Unknown)
                )
            {
                return Err(format!(
                    "并发 consume 不是 1 success + 1 unknown: {left:?} {right:?}"
                ));
            }

            let mismatch = LoginAttempt::begin(
                provider.clone(),
                CanonicalRedirectUri::parse(
                    "https://app.example.com/auth/callback",
                    openbot_infra::auth::oidc::redirect::HTTPS_ONLY,
                )
                .unwrap(),
                now,
                Duration::minutes(10),
            );
            let mismatch_state = mismatch.state().secret().clone();
            first
                .insert(mismatch, now)
                .await
                .map_err(|error| error.to_string())?;
            if first
                .consume(&mismatch_state, &ProviderId::parse("other").unwrap(), now)
                .await
                .unwrap_err()
                != PostgresAttemptError::ProviderMismatch
                || first
                    .consume(&mismatch_state, &provider, now)
                    .await
                    .unwrap_err()
                    != PostgresAttemptError::Unknown
            {
                return Err("provider mismatch 没有烧掉 state".to_owned());
            }

            let expired = LoginAttempt::begin(
                provider.clone(),
                CanonicalRedirectUri::parse(
                    "https://app.example.com/auth/callback",
                    openbot_infra::auth::oidc::redirect::HTTPS_ONLY,
                )
                .unwrap(),
                now,
                Duration::seconds(1),
            );
            let expired_state = expired.state().secret().clone();
            first
                .insert(expired, now)
                .await
                .map_err(|error| error.to_string())?;
            if first
                .consume(&expired_state, &provider, now + Duration::seconds(2))
                .await
                .unwrap_err()
                != PostgresAttemptError::Expired
            {
                return Err("过期 state 未被精确拒绝".to_owned());
            }
            if scalar(&pool, "SELECT count(*)::bigint FROM public.verifications").await? != 0 {
                return Err("consume 后 verification 行未归零".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn rate_limit_is_cross_replica_atomic_and_database_sees_only_hmac_buckets() {
    let admin =
        admin_config("rate_limit_is_cross_replica_atomic_and_database_sees_only_hmac_buckets");
    with_temp_database(&admin, "oidc_rate", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let tenant = TenantId::new("tenant-1");
            let left = PostgresOidcRateLimiter::new(pool.clone(), HASH_KEY, &tenant)
                .map_err(|error| error.to_string())?;
            let right = PostgresOidcRateLimiter::new(pool.clone(), HASH_KEY, &tenant)
                .map_err(|error| error.to_string())?;
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            let one = RateLimitPolicy::new(1, Duration::minutes(1));
            let (a, b) = tokio::join!(
                left.evaluate(OidcRateLimitBucket::LoginStartIp, "203.0.113.7", one, now),
                right.evaluate(OidcRateLimitBucket::LoginStartIp, "203.0.113.7", one, now)
            );
            let a = a.map_err(|error| error.to_string())?;
            let b = b.map_err(|error| error.to_string())?;
            if usize::from(a.allowed()) + usize::from(b.allowed()) != 1
                || a.counter().count().max(b.counter().count()) != 2
            {
                return Err(format!("并发限速不是 1 allow + 1 deny: {a:?} {b:?}"));
            }
            let independent = left
                .evaluate(
                    OidcRateLimitBucket::EmailRouteEmail,
                    "person@example.com",
                    one,
                    now,
                )
                .await
                .map_err(|error| error.to_string())?;
            if !independent.allowed() {
                return Err("不同 namespace/key 没有独立额度".to_owned());
            }
            let next = left
                .evaluate(
                    OidcRateLimitBucket::LoginStartIp,
                    "203.0.113.7",
                    one,
                    now + Duration::minutes(1),
                )
                .await
                .map_err(|error| error.to_string())?;
            if !next.allowed() || next.counter().count() != 1 {
                return Err("新窗口没有恢复额度".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let rows = client
                .query(
                    "SELECT id,value FROM public.verifications WHERE identifier='oidc-rate-limit'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let persisted = rows
                .iter()
                .map(|row| {
                    Ok(format!(
                        "{} {}",
                        row.try_get::<_, String>(0)
                            .map_err(|error| error.to_string())?,
                        row.try_get::<_, String>(1)
                            .map_err(|error| error.to_string())?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?
                .join("\n");
            if persisted.contains("203.0.113.7") || persisted.contains("person@example.com") {
                return Err("数据库泄漏了原始 IP/email bucket key".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn session_issue_links_accounts_refreshes_groups_revokes_old_generation_and_audits() {
    let admin = admin_config(
        "session_issue_links_accounts_refreshes_groups_revokes_old_generation_and_audits",
    );
    with_temp_database(&admin, "oidc_issue", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let issuer = issuer(&pool);
            let okta = provider("okta", "https://idp-one.example");
            let entra = provider("entra", "https://idp-two.example");
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();

            let first_identity = identity(&okta, "Admin@Example.com", "subject-okta", r#"[" Risk "]"#);
            let first = issuer
                .issue(&first_identity, &okta, now, Some("127.0.0.1"), Some("test-agent"))
                .await
                .map_err(|error| error.to_string())?;
            let first_token = first.token().expose().to_owned();
            if first.email().as_str() != "admin@example.com"
                || first.path() != openbot_domain::identity::revocation::SignInPath::NewAccount
            {
                return Err(format!("首次签发身份/path 不符: {first:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT u.id,u.auth_generation,s.token,s.auth_generation AS session_generation, \
                            array_agg(m.channel_id ORDER BY m.channel_id) AS memberships \
                     FROM public.users u JOIN public.sessions s ON s.user_id=u.id \
                     LEFT JOIN public.channel_memberships m ON m.user_id=u.id \
                     GROUP BY u.id,s.id",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let user_id: String = row.try_get("id").map_err(|error| error.to_string())?;
            let stored_token: String = row.try_get("token").map_err(|error| error.to_string())?;
            let memberships: Vec<Option<String>> =
                row.try_get("memberships").map_err(|error| error.to_string())?;
            if stored_token == first_token
                || !stored_token.starts_with("sh1_")
                || memberships != [Some("channel-all".to_owned()), Some("channel-risk".to_owned())]
            {
                return Err("keyed token 或首轮 group membership 不符".to_owned());
            }
            drop(client);
            if scalar(&pool, "SELECT count(*)::bigint FROM public.users").await? != 1
                || scalar(&pool, "SELECT count(*)::bigint FROM public.accounts").await? != 1
                || scalar(&pool, "SELECT count(*)::bigint FROM public.user_roles WHERE role='admin'").await? != 1
                || scalar(&pool, "SELECT count(*)::bigint FROM public.audit_events").await? != 2
            {
                return Err("首次 user/account/admin/audit 计数不符".to_owned());
            }

            let linked_identity = identity(&entra, "admin@example.com", "subject-entra", r#"["risk"]"#);
            issuer
                .issue(&linked_identity, &entra, now + Duration::minutes(1), None, None)
                .await
                .map_err(|error| error.to_string())?;
            if scalar(&pool, "SELECT count(*)::bigint FROM public.users").await? != 1
                || scalar(&pool, "SELECT count(*)::bigint FROM public.accounts").await? != 2
            {
                return Err("跨 provider 同 email 未链接到同一 user".to_owned());
            }

            let removed_group = identity(&okta, "admin@example.com", "subject-okta", "[]");
            let latest = issuer
                .issue(
                    &removed_group,
                    &okta,
                    now + Duration::minutes(2),
                    None,
                    None,
                )
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let generation: i64 = client
                .query_one("SELECT auth_generation FROM public.users WHERE id=$1", &[&user_id])
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let memberships: Vec<String> = client
                .query(
                    "SELECT channel_id FROM public.channel_memberships WHERE user_id=$1 ORDER BY channel_id",
                    &[&user_id],
                )
                .await
                .map_err(|error| error.to_string())?
                .iter()
                .map(|row| row.try_get(0).map_err(|error| error.to_string()))
                .collect::<Result<_, _>>()?;
            drop(client);
            if generation != 1
                || memberships != ["channel-all"]
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 1
                || latest.token().expose() == first_token
            {
                return Err("撤组未原子撤 membership/推进 generation/清旧 session".to_owned());
            }

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let revoked_at = now + Duration::minutes(3);
            client
                .execute(
                    "INSERT INTO public.revoked_access(email,revoked_at,revoked_by) VALUES($1,$2,$3)",
                    &[&"admin@example.com", &revoked_at, &user_id],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if issuer
                .issue(
                    &removed_group,
                    &okta,
                    now + Duration::minutes(4),
                    None,
                    None,
                )
                .await
                .unwrap_err()
                != SessionIssueError::AccessRevoked
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.audit_events WHERE event_type='session.refused'",
                )
                .await?
                    != 1
            {
                return Err("撤权登录未拒绝并留 audit".to_owned());
            }

            // `seed_role` 的另一半：不在 admin floor 的新身份必须只拿 user，不能因
            // 单用户模式的固定 admin 规则而被静默提升。
            let member_identity = identity(&okta, "member@example.com", "subject-member", "[]");
            issuer
                .issue(
                    &member_identity,
                    &okta,
                    now + Duration::minutes(5),
                    None,
                    None,
                )
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let roles: Vec<String> = client
                .query(
                    "SELECT ur.role::text FROM public.user_roles ur \
                     JOIN public.users u ON u.id=ur.user_id \
                     WHERE u.email='member@example.com' ORDER BY ur.role",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            if roles != ["user"] {
                return Err(format!("非 floor 新身份的 seed role 不符：{roles:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn audit_chain_failure_rolls_back_new_identity_account_membership_and_session() {
    let admin =
        admin_config("audit_chain_failure_rolls_back_new_identity_account_membership_and_session");
    with_temp_database(&admin, "oidc_audit_rollback", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let issuer = issuer(&pool);
            let idp = provider("okta", "https://idp.example");
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            issuer
                .issue(
                    &identity(&idp, "admin@example.com", "subject-1", "[]"),
                    &idp,
                    now,
                    None,
                    None,
                )
                .await
                .map_err(|error| error.to_string())?;

            let client = pool.get().await.map_err(|error| error.to_string())?;
            let corrupt_at = now + Duration::hours(1);
            client
                .execute(
                    "INSERT INTO public.audit_events(id,actor_user_id,event_type,target_type,target_id,payload,created_at,prev_hash,row_hash) \
                     VALUES(gen_random_uuid(),NULL,'session.refused','person',NULL,'{}'::jsonb,$1,NULL,NULL)",
                    &[&corrupt_at],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);

            let result = issuer
                .issue(
                    &identity(&idp, "second@example.com", "subject-2", r#"["finance"]"#),
                    &idp,
                    now + Duration::minutes(1),
                    None,
                    None,
                )
                .await;
            if result.unwrap_err() != SessionIssueError::DependencyUnavailable
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.users WHERE email='second@example.com'",
                )
                .await?
                    != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.accounts WHERE account_id='subject-2'",
                )
                .await?
                    != 0
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 1
            {
                return Err("audit 红灯没有 rollback 全部登录副作用".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

#[derive(Clone)]
struct LocalResolver(SocketAddr);

#[async_trait::async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        Ok(vec![self.0])
    }
}

#[derive(Clone)]
struct AuthorizationParams {
    nonce: String,
    challenge: String,
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn real_tls_discovery_pkce_token_jwks_claims_and_session_is_one_replay_safe_flow() {
    let admin = admin_config(
        "real_tls_discovery_pkce_token_jwks_claims_and_session_is_one_replay_safe_flow",
    );
    with_temp_database(&admin, "oidc_real_flow", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let auth_params = Arc::new(Mutex::new(None));
            let calls = Arc::new(AtomicUsize::new(0));
            let (address, root, server) =
                spawn_test_idp(auth_params.clone(), calls.clone()).await?;
            let allowlist = CidrAllowlist::parse_exact(["127.0.0.1/32"])
                .map_err(|error| error.to_string())?;
            let dialer = SafeDialer::with_extra_roots(
                EgressPolicy::new(allowlist),
                Arc::new(LocalResolver(address)),
                [root],
            )
            .map_err(|error| error.to_string())?;
            let issuer_url = format!("https://idp.test:{}", address.port());
            let idp = OidcProviderConfig::new(
                ProviderId::parse("test-idp").unwrap(),
                ProviderKind::DeploymentOwned {
                    issuer: parse_issuer(&issuer_url).unwrap(),
                },
                ProviderOrigin::EnvironmentConfigured,
                ClientId::new("test-idp-client".to_owned()),
                CanonicalRedirectUri::parse(
                    "https://app.example.com/api/auth/oidc/test-idp/callback",
                    openbot_infra::auth::oidc::redirect::HTTPS_ONLY,
                )
                .unwrap(),
                BTreeSet::new(),
                None,
            );
            let mapping = IdpGroupMapping::new(
                IdentityProviderId::new("test-idp"),
                GroupClaimPath::from_dotted("groups").unwrap(),
                GroupNormalization::TrimLowercase,
            );
            let runtime = OidcProviderRuntime::discover(
                idp,
                Some(SecretBytes::new(b"test-idp-secret".to_vec())),
                Some(mapping),
                &dialer,
                FetchBudget::new(256 * 1024, core::time::Duration::from_secs(5)),
            )
            .await
            .map_err(|error| error.to_string())?;
            let tenant = TenantId::new("tenant-1");
            let attempts = PostgresLoginAttemptStore::new(pool.clone(), HASH_KEY, &tenant, 32)
                .map_err(|error| error.to_string())?;
            let sessions = issuer(&pool);
            let limiter = PostgresOidcRateLimiter::new(pool.clone(), HASH_KEY, &tenant)
                .map_err(|error| error.to_string())?;
            let coordinator = OidcLoginCoordinator::new(
                [runtime],
                attempts,
                sessions,
                limiter,
                dialer,
            )
            .map_err(|error| error.to_string())?;
            let provider_id = ProviderId::parse("test-idp").unwrap();
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            let authorization = coordinator
                .start(&provider_id, now, "203.0.113.9")
                .await
                .map_err(|error| error.to_string())?;
            let query: std::collections::BTreeMap<String, String> =
                authorization.query_pairs().into_owned().collect();
            let state = query.get("state").cloned().ok_or("缺 state")?;
            let callback_uri = coordinator
                .callback_uri(&provider_id)
                .ok_or("缺 callback URI")?
                .to_owned();
            let unknown_provider = ProviderId::parse("unregistered").unwrap();
            let mismatched = coordinator
                .callback(
                    &unknown_provider,
                    &state,
                    "never-sent",
                    &callback_uri,
                    now + Duration::milliseconds(100),
                    "203.0.113.9",
                    None,
                    openbot_infra::auth::oidc::session_issuer::OriginalLoginRequest::new(
                        std::time::Instant::now() + openbot_infra::auth::oidc::coordinator::DYNAMIC_SSO_LOGIN_BUDGET,
                        tokio_util::sync::CancellationToken::new(),
                    ),
                )
                .await;
            if !matches!(
                mismatched,
                Err(openbot_infra::auth::oidc::OidcLoginError::Attempt(
                    PostgresAttemptError::ProviderMismatch
                ))
            ) {
                return Err(format!(
                    "未注册 provider 没有先烧掉已有 state: {mismatched:?}"
                ));
            }
            let burned = coordinator
                .callback(
                    &provider_id,
                    &state,
                    "never-sent",
                    &callback_uri,
                    now + Duration::milliseconds(200),
                    "203.0.113.9",
                    None,
                    openbot_infra::auth::oidc::session_issuer::OriginalLoginRequest::new(
                        std::time::Instant::now() + openbot_infra::auth::oidc::coordinator::DYNAMIC_SSO_LOGIN_BUDGET,
                        tokio_util::sync::CancellationToken::new(),
                    ),
                )
                .await;
            if !matches!(
                burned,
                Err(openbot_infra::auth::oidc::OidcLoginError::Attempt(
                    PostgresAttemptError::Unknown
                ))
            ) {
                return Err(format!("provider mismatch 后 state 仍可重用: {burned:?}"));
            }

            let authorization = coordinator
                .start(&provider_id, now + Duration::milliseconds(300), "203.0.113.9")
                .await
                .map_err(|error| error.to_string())?;
            let query: std::collections::BTreeMap<String, String> =
                authorization.query_pairs().into_owned().collect();
            let state = query.get("state").cloned().ok_or("缺 state")?;
            *auth_params.lock().unwrap() = Some(AuthorizationParams {
                nonce: query.get("nonce").cloned().ok_or("缺 nonce")?,
                challenge: query
                    .get("code_challenge")
                    .cloned()
                    .ok_or("缺 challenge")?,
            });
            let issued = coordinator
                .callback(
                    &provider_id,
                    &state,
                    "valid-code",
                    &callback_uri,
                    now + Duration::seconds(1),
                    "203.0.113.9",
                    Some("integration-agent"),
                    openbot_infra::auth::oidc::session_issuer::OriginalLoginRequest::new(
                        std::time::Instant::now() + openbot_infra::auth::oidc::coordinator::DYNAMIC_SSO_LOGIN_BUDGET,
                        tokio_util::sync::CancellationToken::new(),
                    ),
                )
                .await
                .map_err(|error| error.to_string())?;
            if issued.email().as_str() != "person@example.com"
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.channel_memberships WHERE channel_id='channel-risk'",
                )
                .await?
                    != 1
            {
                return Err("真实 TLS OIDC flow 没有落成 identity/session/group".to_owned());
            }
            let replay = coordinator
                .callback(
                    &provider_id,
                    &state,
                    "valid-code",
                    &callback_uri,
                    now + Duration::seconds(2),
                    "203.0.113.9",
                    None,
                    openbot_infra::auth::oidc::session_issuer::OriginalLoginRequest::new(
                        std::time::Instant::now() + openbot_infra::auth::oidc::coordinator::DYNAMIC_SSO_LOGIN_BUDGET,
                        tokio_util::sync::CancellationToken::new(),
                    ),
                )
                .await;
            if !matches!(
                replay,
                Err(openbot_infra::auth::oidc::OidcLoginError::Attempt(
                    PostgresAttemptError::Unknown
                ))
            ) {
                return Err(format!("重放没有在 IdP 前被拒: {replay:?}"));
            }
            server.await.map_err(|error| error.to_string())??;
            if calls.load(Ordering::SeqCst) != 3 {
                return Err(format!(
                    "discovery/token/JWKS 应恰三次，实际 {}",
                    calls.load(Ordering::SeqCst)
                ));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}

async fn spawn_test_idp(
    auth_params: Arc<Mutex<Option<AuthorizationParams>>>,
    calls: Arc<AtomicUsize>,
) -> Result<
    (
        SocketAddr,
        CertificateDer<'static>,
        tokio::task::JoinHandle<Result<(), String>>,
    ),
    String,
> {
    let root = CertificateDer::from(
        BASE64_STANDARD
            .decode(TLS_CA_DER)
            .map_err(|error| error.to_string())?,
    );
    let leaf = CertificateDer::from(
        BASE64_STANDARD
            .decode(TLS_LEAF_DER)
            .map_err(|error| error.to_string())?,
    );
    let key = PrivateKeyDer::try_from(
        BASE64_STANDARD
            .decode(TLS_LEAF_KEY_DER)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .map_err(|error| error.to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let origin = format!("https://idp.test:{}", address.port());
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let mut tls = acceptor
                .accept(stream)
                .await
                .map_err(|error| error.to_string())?;
            let request = read_http_request(&mut tls).await?;
            calls.fetch_add(1, Ordering::SeqCst);
            let (status, content_type, body) = if request.path
                == "/.well-known/openid-configuration"
            {
                (
                    "200 OK",
                    "application/json",
                    serde_json::json!({
                        "issuer": origin,
                        "authorization_endpoint": format!("{origin}/authorize"),
                        "token_endpoint": format!("{origin}/token"),
                        "jwks_uri": format!("{origin}/jwks"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"]
                    })
                    .to_string(),
                )
            } else if request.path == "/token" {
                if !request
                    .headers
                    .to_ascii_lowercase()
                    .contains("authorization: basic ")
                {
                    return Err("token POST 缺 Basic auth".to_owned());
                }
                let form: std::collections::BTreeMap<String, String> =
                    url::form_urlencoded::parse(&request.body)
                        .into_owned()
                        .collect();
                if form.get("code").map(String::as_str) != Some("valid-code") {
                    return Err("token POST code 不符".to_owned());
                }
                let verifier = form.get("code_verifier").ok_or("缺 code_verifier")?;
                let actual_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
                let params = auth_params
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or("start 尚未提供 nonce/challenge")?;
                if actual_challenge != params.challenge {
                    return Err("PKCE verifier 与 start challenge 不匹配".to_owned());
                }
                let token = sign_rs256(&serde_json::json!({
                    "iss": origin,
                    "aud": ["test-idp-client"],
                    "exp": FAR_FUTURE,
                    "iat": NOW,
                    "sub": "subject-real",
                    "nonce": params.nonce,
                    "email": "person@example.com",
                    "groups": [" Risk "]
                }))?;
                (
                    "200 OK",
                    "application/json",
                    serde_json::json!({
                        "access_token": "ephemeral-access-token",
                        "token_type": "Bearer",
                        "id_token": token
                    })
                    .to_string(),
                )
            } else if request.path == "/jwks" {
                (
                    "200 OK",
                    "application/jwk-set+json",
                    serde_json::json!({
                        "keys": [{
                            "kty": "RSA", "use": "sig", "kid": "key-1", "alg": "RS256",
                            "n": RSA_N, "e": "AQAB"
                        }]
                    })
                    .to_string(),
                )
            } else {
                ("404 Not Found", "text/plain", "not found".to_owned())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(response.as_bytes())
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    Ok((address, root, server))
}

struct TestHttpRequest {
    path: String,
    headers: String,
    body: Vec<u8>,
}

async fn read_http_request<S>(stream: &mut S) -> Result<TestHttpRequest, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("HTTP request 在 header 前 EOF".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers =
        String::from_utf8(bytes[..header_end].to_vec()).map_err(|error| error.to_string())?;
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("坏 request line")?
        .to_owned();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while bytes.len() - header_end < content_length {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("HTTP request body 提前 EOF".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(TestHttpRequest {
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn sign_rs256(claims: &serde_json::Value) -> Result<String, String> {
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"key-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?);
    let input = format!("{header}.{payload}");
    let key = RsaKeyPair::from_pkcs8(
        &BASE64_STANDARD
            .decode(RSA_KEY_DER)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut signature = vec![0u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| "RS256 signing failed".to_owned())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
