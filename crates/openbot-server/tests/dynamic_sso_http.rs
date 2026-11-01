//! W-7b 动态 IdP 管理真 Axum 路由 + PG17 原子 store。

#[path = "support/transport_fixture.rs"]
mod transport_fixture;

mod harness {
    include!("../../../test-support/postgres_harness.rs");
}

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use harness::{admin_config, with_temp_database};
use http::{Request, StatusCode};
use openbot_application::OpenBotApplication;
use openbot_contracts::ids::{DeploymentId, TenantId};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::identity::session::{
    SessionHashKey, SessionToken, SessionTokenHash, TrustedOrigins,
};
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::sso::DynamicSsoService;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use openbot_infra::repo::ChannelRepo;
use openbot_server::{PostgresSessionAuthResolver, SensitiveWriteSecurity, ServerBuilder};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

const RAW_TOKEN: &str = "dynamic-sso-http-session-token-001";
const PLAIN_TOKEN: &str = "dynamic-sso-http-plain-session-token-001";
const STALE_TOKEN: &str = "dynamic-sso-http-stale-session-token-001";
const SESSION_KEY: &[u8] = b"dynamic-sso-http-session-key-at-least-32";
const AUDIT_KEY: &[u8] = b"dynamic-sso-http-audit-key-at-least-32";
const CERT_DER_BASE64: &str = "MIIDIzCCAgugAwIBAgIUX4VCIW1pLys81pciNp1/JOQoi4QwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UEAwwVT3BlbkJvdCBTQU1MIFRlc3QgSWRQMCAXDTI2MDgyMzE5NDEzNloYDzIxMjYwNzMwMTk0MTM2WjAgMR4wHAYDVQQDDBVPcGVuQm90IFNBTUwgVGVzdCBJZFAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6H3yHJdqdNCah3hVBs6//CoHo5GcYluT90b9+A8Jy5jyjCk+WFTvb3cGAuH9MMZCEAvXmMJr0pD3XFOHeguXzLXz+vkQTyb3fw/6QTI6wi2zYchdLajsUSXGujDUdKTfwWn7S7Q3vfaVYZymt69kdG/JhXa8tZ1dPzJKGLsthaKfMx8DQ0/AG9lXSKBrJtY39muVbRi4gCZHnxemQIMRaE7FDr83Jn6Ixugi0XG2MTY3XMT1lITALd3UMqkxs5PxrLMyt5wbxPzNFw3ZjcNIPSngxvtDBgeK3iMoARk/wOINqm+Kel9PXRI77By/hTtJPshRpSqCke4KBPPbGP7qfAgMBAAGjUzBRMB0GA1UdDgQWBBRiEZ5u2WJHOQeOrautNPOahGlEDTAfBgNVHSMEGDAWgBRiEZ5u2WJHOQeOrautNPOahGlEDTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA4VkmWF6Q/Eb255tJWnlg3rot5RBNihPY9YL9TLtxdhkCzq+0KsFoafrdQLR2tzMZ6fKzBgGf1XPiciHLfapddQRIvm5AgId87Taeo6hBfqzsv8kJEBgEkT5XTwjsxXcG++a+RRKCweOBx2hhcd0lWpC905KaAbOcw3EOkpjjGPVjXqIQ/9OiPus2ILuQPJJH3zTGXUPO0wIxEINOBmBCFnp1/xNJl5UzHbIfifrVY0n5VPg4FCC8TSQr950YapOr2eAbbVr4sRtyrAYaYBdKgAnpqllB7Uh0dIESP+JyE07YNBUdBQCxzrF0na5GqJALXyL/YlLfTKoRSgbQJv+xW";

async fn setup(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    let now = OffsetDateTime::now_utc();
    client
        .execute(
            "INSERT INTO public.users(id,email,name,image,email_verified,groups,created_at,updated_at,auth_generation) \
             VALUES('admin','admin@example.com','Admin',NULL,true,'{}',$1,$1,0)",
            &[&now],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.users(id,email,name,image,email_verified,groups,created_at,updated_at,auth_generation) \
             VALUES('plain','plain@example.com','Plain',NULL,true,'{}',$1,$1,0)",
            &[&now],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.user_roles(user_id,role,created_at) VALUES('plain','user',$1)",
            &[&now],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .execute(
            "INSERT INTO public.user_roles(user_id,role,created_at) VALUES('admin','admin',$1)",
            &[&now],
        )
        .await
        .map_err(|error| error.to_string())?;
    let plain_hash = SessionTokenHash::compute(
        SessionToken::new(PLAIN_TOKEN.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    client
        .execute(
            "INSERT INTO public.sessions( \
               id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
             VALUES('plain-session','plain',$1,$2,$3,$3,0)",
            &[&(plain_hash), &(now + Duration::hours(1)), &now],
        )
        .await
        .map_err(|error| error.to_string())?;
    let hash = SessionTokenHash::compute(
        SessionToken::new(RAW_TOKEN.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    client
        .execute(
            "INSERT INTO public.sessions( \
               id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
             VALUES('admin-session','admin',$1,$2,$3,$3,0)",
            &[&(hash), &(now + Duration::hours(1)), &now],
        )
        .await
        .map_err(|error| error.to_string())?;
    let stale_hash = SessionTokenHash::compute(
        SessionToken::new(STALE_TOKEN.as_bytes()),
        SessionHashKey::new(SESSION_KEY),
    )
    .to_column_value();
    client
        .execute(
            "INSERT INTO public.sessions( \
               id,user_id,token,expires_at,created_at,updated_at,auth_generation) \
             VALUES('stale-session','admin',$1,$2,$3,$4,0)",
            &[
                &(stale_hash),
                &(now + Duration::hours(1)),
                &(now - Duration::minutes(16)),
                &now,
            ],
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn metadata() -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{CERT_DER_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

fn request(method: &str, path: &str, body: String, origin: bool) -> Request<Body> {
    request_for(Some(RAW_TOKEN), method, path, body, origin)
}

fn request_for(
    token: Option<&str>,
    method: &str,
    path: &str,
    body: String,
    origin: bool,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header(http::header::COOKIE, format!("openbot_session={token}"));
    }
    if !body.is_empty() {
        builder = builder.header(http::header::CONTENT_TYPE, "application/json");
    }
    if origin {
        builder = builder.header(http::header::ORIGIN, "https://app.example");
    }
    builder.body(Body::from(body)).unwrap()
}

fn anonymous_route_request(email: &str) -> Request<Body> {
    request_for(
        None,
        "POST",
        "/api/auth/sso/start",
        serde_json::json!({ "email": email }).to_string(),
        true,
    )
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL + xmlsec1：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored"]
async fn admin_routes_require_fresh_origin_and_never_project_saml_material() {
    let admin = admin_config("admin_routes_require_fresh_origin_and_never_project_saml_material");
    with_temp_database(&admin, "dynamic_sso_http", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let outcome = async {
            setup(&pool).await?;
            let resolver = PostgresSessionAuthResolver::new(
                pool.clone(),
                SESSION_KEY,
                default_session_lifetime(),
                DeploymentId::new("dep-1"),
                TenantId::new("tenant-1"),
            )
            .map_err(|error| error.to_string())?;
            let dynamic = DynamicSsoService::new(
                pool.clone(),
                &TenantId::new("tenant-1"),
                SESSION_KEY,
                SESSION_KEY,
                AUDIT_KEY,
                WrappingKey::from_bytes(vec![0x42; 32]).unwrap(),
                KeyVersion::new(1),
                default_session_lifetime(),
                AdminFloor::from_configured(["admin@example.com"]).unwrap(),
                [
                    "google".to_owned(),
                    "microsoft".to_owned(),
                    "okta".to_owned(),
                ],
                SafeDialer::new(EgressPolicy::default()),
                "https://app.example".to_owned(),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(
                    &pool,
                    &DeploymentId::new("dep-1"),
                    &TenantId::new("tenant-1"),
                ),
            )
            .map_err(|error| error.to_string())?;
            let app = Arc::new(OpenBotApplication::new(ChannelRepo::new(pool.clone())));
            let router = transport_fixture::loopback_router(
                ServerBuilder::new(app, Arc::new(resolver))
                    .with_transport_policy(transport_fixture::loopback_policy())
                    .with_sensitive_write_security(SensitiveWriteSecurity::new(
                        default_session_lifetime(),
                        TrustedOrigins::from_configured(["https://app.example"]).unwrap(),
                    ))
                    .with_login_security(
                        TrustedOrigins::from_configured(["https://app.example"]).unwrap(),
                        true,
                    )
                    .with_dynamic_sso(Arc::new(dynamic))
                    .build(),
            );
            let body = serde_json::json!({
                "providerId":"acme-saml",
                "issuer":"https://idp.example/entity",
                "domain":"example.com",
                "samlConfig":{
                    "entryPoint":"https://idp.example/sso",
                    "idpMetadata":{"metadata":metadata()}
                }
            })
            .to_string();
            let admin_only_routes = [
                "/api/auth/sso/register",
                "/api/auth/sso/update-provider",
                "/api/auth/sso/delete-provider",
            ];
            for path in admin_only_routes {
                for (token, expected) in [
                    (None, StatusCode::UNAUTHORIZED),
                    (Some(PLAIN_TOKEN), StatusCode::FORBIDDEN),
                ] {
                    let denied = router
                        .clone()
                        .oneshot(request_for(token, "POST", path, String::new(), true))
                        .await
                        .map_err(|error| error.to_string())?;
                    if denied.status() != expected {
                        return Err(format!(
                            "admin-only guard {path} {:?} != {expected}",
                            denied.status()
                        ));
                    }
                }
            }
            let stale = router
                .clone()
                .oneshot(request_for(
                    Some(STALE_TOKEN),
                    "POST",
                    "/api/auth/sso/register",
                    body.clone(),
                    true,
                ))
                .await
                .map_err(|error| error.to_string())?;
            let stale_status = stale.status();
            let stale_body = to_bytes(stale.into_body(), 64 * 1024)
                .await
                .map_err(|error| error.to_string())?;
            if stale_status != StatusCode::UNAUTHORIZED
                || stale_body.as_ref()
                    != br#"{"code":"identity_sensitive_write_session_not_fresh"}"#
            {
                return Err(format!(
                    "stale admin session status={stale_status} body={}",
                    String::from_utf8_lossy(&stale_body)
                ));
            }
            let missing_origin = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/auth/sso/register",
                    body.clone(),
                    false,
                ))
                .await
                .map_err(|error| error.to_string())?;
            if missing_origin.status() != StatusCode::FORBIDDEN {
                return Err("register 缺 Origin 未拒绝".to_owned());
            }
            let registered = router
                .clone()
                .oneshot(request("POST", "/api/auth/sso/register", body, true))
                .await
                .map_err(|error| error.to_string())?;
            if registered.status() != StatusCode::OK {
                return Err(format!("register status={}", registered.status()));
            }
            let updated = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/auth/sso/update-provider",
                    serde_json::json!({
                        "providerId":"acme-saml",
                        "issuer":"https://idp.example/entity",
                        "domain":"example.com",
                        "samlConfig":{
                            "entryPoint":"https://idp.example/sso",
                            "idpMetadata":{"metadata":metadata()},
                            "emailAttribute":"mail"
                        }
                    })
                    .to_string(),
                    true,
                ))
                .await
                .map_err(|error| error.to_string())?;
            if updated.status() != StatusCode::OK {
                return Err(format!("update status={}", updated.status()));
            }
            let removed_compat = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/auth/sso/delete-provider",
                    serde_json::json!({ "providerId": "acme-saml" }).to_string(),
                    true,
                ))
                .await
                .map_err(|error| error.to_string())?;
            if removed_compat.status() != StatusCode::OK {
                return Err(format!("compat delete status={}", removed_compat.status()));
            }
            let registered_again = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/auth/sso/register",
                    serde_json::json!({
                        "providerId":"acme-saml",
                        "issuer":"https://idp.example/entity",
                        "domain":"example.com",
                        "samlConfig":{
                            "entryPoint":"https://idp.example/sso",
                            "idpMetadata":{"metadata":metadata()}
                        }
                    })
                    .to_string(),
                    true,
                ))
                .await
                .map_err(|error| error.to_string())?;
            if registered_again.status() != StatusCode::OK {
                return Err(format!("re-register status={}", registered_again.status()));
            }
            let anonymous_start = router
                .clone()
                .oneshot(anonymous_route_request("person@example.com"))
                .await
                .map_err(|error| error.to_string())?;
            if anonymous_start.status() != StatusCode::ACCEPTED {
                return Err(format!(
                    "anonymous SSO start 被 admin guard 误伤: {}",
                    anonymous_start.status()
                ));
            }
            for (token, expected) in [
                (None, StatusCode::UNAUTHORIZED),
                (Some(PLAIN_TOKEN), StatusCode::FORBIDDEN),
            ] {
                let denied_list = router
                    .clone()
                    .oneshot(request_for(
                        token,
                        "GET",
                        "/api/admin/identity-providers",
                        String::new(),
                        false,
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                if denied_list.status() != expected {
                    return Err(format!(
                        "admin list guard {:?} != {expected}",
                        denied_list.status()
                    ));
                }
                let denied_delete = router
                    .clone()
                    .oneshot(request_for(
                        token,
                        "DELETE",
                        "/api/admin/identity-providers/acme-saml",
                        String::new(),
                        true,
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                if denied_delete.status() != expected {
                    return Err(format!(
                        "admin delete guard {:?} != {expected}",
                        denied_delete.status()
                    ));
                }
            }
            let listed = router
                .clone()
                .oneshot(request(
                    "GET",
                    "/api/admin/identity-providers",
                    String::new(),
                    false,
                ))
                .await
                .map_err(|error| error.to_string())?;
            let status = listed.status();
            let cache_control = listed
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let bytes = to_bytes(listed.into_body(), 1024 * 1024)
                .await
                .map_err(|error| error.to_string())?;
            let body = String::from_utf8(bytes.to_vec()).map_err(|error| error.to_string())?;
            if status != StatusCode::OK
                || cache_control.as_deref() != Some("no-store")
                || !body.contains("acme-saml")
                || body.contains("X509Certificate")
                || body.contains("samlConfig")
            {
                return Err(format!("admin list 泄漏/漂移: {status} {body}"));
            }
            let removed = router
                .oneshot(request(
                    "DELETE",
                    "/api/admin/identity-providers/acme-saml",
                    String::new(),
                    true,
                ))
                .await
                .map_err(|error| error.to_string())?;
            if removed.status() != StatusCode::OK {
                return Err(format!("delete status={}", removed.status()));
            }
            Ok(())
        }
        .await;
        pool.close();
        outcome
    })
    .await;
}
