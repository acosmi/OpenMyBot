//! W-7b 动态 SAML/SSO vault、routing、replay、account cleanup 的 PG17 真库闭环。
#![cfg(feature = "server-sso")]

mod harness;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use harness::{admin_config, with_temp_database};
use openbot_contracts::ids::{ActorId, TenantId};
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::sso::{
    DynamicSsoService, DynamicSsoStart, RegisterIdentityProviderInput, SamlStart,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::net::safe_http::{CidrAllowlist, DnsResolver, DnsUnavailable};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use samael::crypto::{Crypto, CryptoProvider};
use samael::schema::AuthnRequest;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const NOW: i64 = 1_800_000_000;
const HASH_KEY: &[u8] = b"dynamic-sso-ephemeral-key-at-least-32";
const SESSION_KEY: &[u8] = b"dynamic-sso-session-key-at-least-32bytes";
const AUDIT_KEY: &[u8] = b"dynamic-sso-audit-key-at-least-32-bytes";
const TEST_KEY_DER_BASE64: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6H3yHJdqdNCah3hVBs6//CoHo5GcYluT90b9+A8Jy5jyjCk+WFTvb3cGAuH9MMZCEAvXmMJr0pD3XFOHeguXzLXz+vkQTyb3fw/6QTI6wi2zYchdLajsUSXGujDUdKTfwWn7S7Q3vfaVYZymt69kdG/JhXa8tZ1dPzJKGLsthaKfMx8DQ0/AG9lXSKBrJtY39muVbRi4gCZHnxemQIMRaE7FDr83Jn6Ixugi0XG2MTY3XMT1lITALd3UMqkxs5PxrLMyt5wbxPzNFw3ZjcNIPSngxvtDBgeK3iMoARk/wOINqm+Kel9PXRI77By/hTtJPshRpSqCke4KBPPbGP7qfAgMBAAECggEAAVwBg4CEnD6pRD1kV6/W9TyVE6e3aQ07wZl/6zezz+Bb86+Q7T5dIDn6aSpFI7/+QjiTUInCV/nAdIsJK0rhdb6QpHusm525mUzL1dn5S34j3rYr8re6lBIFQTUc84g9ia/fhULd+zB7vgLi4bZQm6R8nLbGdMUbH3trBo0znGktarBW9BzSC3VbTNNAD0ffWiaC3JMWRY5dzwlmFE15nnzD89uotfyaWqTM3LEjT1bp+xRZllLE9K8OjwI+mCpGNkHIVMAEgGc8XKLa7Z8cOIADvE9NwUfeCcSE0jID8jEYGXpJKNP6Za+2azYC3KkVDiePMVHzp0BccGZ8LjIQIQKBgQDf5wZfhM6dk4YVGKpXFv/SrkklNMYMufKYyn1hgPJufbE7SBqV25W5wjeHG2WqrnZs+7jgu5FRTRL4XIu6StbInWVK1IfqGpIS3Y1QG8GBzTfB0vVv1qta5AfEM3all6xzTEuqs4LWS8Ou+0v7OeFbF0la3o3fBRJN+XuAIygWowKBgQDUzf9A90igB15gXCNxDU8Qgxdy6Y8CZFJ/2fakYtngOIY8mhjWEbQnly6gLO4z/iqRLDqt84hpYEHzYfZ+Tc13Q3FD4b3/YHGH37dzwIiIzQALxI86GQjPr+h2cXHRdIO05LQRLBP6g/UNf9ucw0SdbCLVmGMZZxGpEfU1YbbX1QKBgALjCqz+nF9hwI/TEpcu37uKrbzCEm+lkiAwNC+mpvmPu1JFWrpl62dKvsaKLuRlfXdoQ3j6UiRXNxBmuRJ81oodpWmyldIJ56pAmwrWYMdYqwhfvPRlMy5n1EXOWBBIhVuzNyKLT/uNXIeMC+3AUEyJX1PBnNisSxEgT1xWl7S7AoGAFn7wTN3XP5OH1ofm9zyA7y3sfKlUBNy2G+3etOH+RkWzaxSfK4ITmVvSAfy98aEcvtv+GAV2li0my6O/evqejc0DXDmw7B414jc0HXhs9ok1SAkvWuTqmYnu+RZlAc9fXPAQWQBf3Eu2zAaIILpDtqCHziydzUGoDEdptIrv2UECgYAH/bT70ViUbuVU/KHYCqR/9VJ11fkQoQegQw+JSQIkuyvMsaTNR/E3Kr0G31z6zq8/06Gwdj4rnjlqyr9+U6hLquHdGAwwJ4ZVCfhpSK5KMHGvV93UzhGLMfYSg2ir3+siUZ08ZMB5BG43ujXy6zjXGuGhJxU+5lW/IKO/QttV/g==";
const TEST_CERT_DER_BASE64: &str = "MIIDIzCCAgugAwIBAgIUX4VCIW1pLys81pciNp1/JOQoi4QwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UEAwwVT3BlbkJvdCBTQU1MIFRlc3QgSWRQMCAXDTI2MDgyMzE5NDEzNloYDzIxMjYwNzMwMTk0MTM2WjAgMR4wHAYDVQQDDBVPcGVuQm90IFNBTUwgVGVzdCBJZFAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6H3yHJdqdNCah3hVBs6//CoHo5GcYluT90b9+A8Jy5jyjCk+WFTvb3cGAuH9MMZCEAvXmMJr0pD3XFOHeguXzLXz+vkQTyb3fw/6QTI6wi2zYchdLajsUSXGujDUdKTfwWn7S7Q3vfaVYZymt69kdG/JhXa8tZ1dPzJKGLsthaKfMx8DQ0/AG9lXSKBrJtY39muVbRi4gCZHnxemQIMRaE7FDr83Jn6Ixugi0XG2MTY3XMT1lITALd3UMqkxs5PxrLMyt5wbxPzNFw3ZjcNIPSngxvtDBgeK3iMoARk/wOINqm+Kel9PXRI77By/hTtJPshRpSqCke4KBPPbGP7qfAgMBAAGjUzBRMB0GA1UdDgQWBBRiEZ5u2WJHOQeOrautNPOahGlEDTAfBgNVHSMEGDAWgBRiEZ5u2WJHOQeOrautNPOahGlEDTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA4VkmWF6Q/Eb255tJWnlg3rot5RBNihPY9YL9TLtxdhkCzq+0KsFoafrdQLR2tzMZ6fKzBgGf1XPiciHLfapddQRIvm5AgId87Taeo6hBfqzsv8kJEBgEkT5XTwjsxXcG++a+RRKCweOBx2hhcd0lWpC905KaAbOcw3EOkpjjGPVjXqIQ/9OiPus2ILuQPJJH3zTGXUPO0wIxEINOBmBCFnp1/xNJl5UzHbIfifrVY0n5VPg4FCC8TSQr950YapOr2eAbbVr4sRtyrAYaYBdKgAnpqllB7Uh0dIESP+JyE07YNBUdBQCxzrF0na5GqJALXyL/YlLfTKoRSgbQJv+xW";
const TLS_CA_DER: &str = "MIIBYTCCAROgAwIBAgIUV2Gyaxvee9eFEK3h9B3MJM3RdHMwBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owHTEbMBkGA1UEAwwST3BlbkJvdCBXNyBUZXN0IENBMCowBQYDK2VwAyEApgBzSV/LoqKcnUaH8XyHAyeVHmSdWzs/pG1QLsZtLXujYzBhMB0GA1UdDgQWBBRGuULlFEmfV4B1pDoFKLlyG87ckjAfBgNVHSMEGDAWgBRGuULlFEmfV4B1pDoFKLlyG87ckjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAhZqm1u2PwIPUkIhbQpjQhEbNUYoF2Abyx+fdXyy5b0QRLqnEK/8DY350B6fiQHd7a6BEa+qN+qhUQNauulgwB";
const TLS_LEAF_DER: &str = "MIIBgDCCATKgAwIBAgIUWFITT9Bap6fPTrUyiQds6m7YbW4wBQYDK2VwMB0xGzAZBgNVBAMMEk9wZW5Cb3QgVzcgVGVzdCBDQTAgFw0yNjA4MjMxNzIxNTNaGA8yMTI2MDczMDE3MjE1M1owEzERMA8GA1UEAwwIaWRwLnRlc3QwKjAFBgMrZXADIQDUfQYU3Rio5WectHhNXvjIzi67mD9xT6HD7WzyBqMdIKOBizCBiDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAKgghpZHAudGVzdDAdBgNVHQ4EFgQU7WAFDj1TPql991Rys+6HvGt+f2kwHwYDVR0jBBgwFoAURrlC5RRJn1eAdaQ6BSi5chvO3JIwBQYDK2VwA0EAhqOV0ZqpgZsjy3YMiwb4D94mGVQmVikza22FtbWfcC2F4b1GV0YKYCOwdIN9ruFVxguKPy//7tlCnuSzoUzkBQ==";
const TLS_LEAF_KEY_DER: &str = "MC4CAQAwBQYDK2VwBCIEIIhvzdQUg5xdTDZfBbx3RK3yTMHjMv2r8AJ5/hgshUDa";
const OIDC_RSA_KEY_DER: &str = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOwlECHGhbCo0GavhO8G+w5qxQc1+PdpBsgdd6two0pwvxo8u2mMry42lAhYJbrVUiqQjKBmCIHJ/+a0LfN/jrGPJtmTjzeGXmL4qRNWj/bSprl1xFcTKdM+B36xMFNS3xLc7LtnWrCGH+30h/vCZAqq21lajUypEs8tBYB/JDRm5BXM8GwMOV9UXhOmRn9QaV4a7/0hxPb3yGwejXpE9lNVU2P1LqTe+p8ArFMbJAxKGZRlkpWZNROej/pd9jrdh+s2WrmqXEahy4P1ztBMM6dO1DDOw9+aHzp9iWEs0LuMBfLRtJGC492Be5EFuZ0lP9K2AADRrXhgmHTI9XAQmTAgMBAAECggEAIr3dUwMwzj8iFNbBeQyAUe/BLY72SYaUHSP4GZAj9q5UdMjk0ZobgcKgIaicEc1784RpdCjbIyS8NwFJc+M+O5CFpvBr8KxzN/KH6VCzLb4WXbqnJOsoYyN11BksNs87T/9S3TaZKjdPCeSy0wsp0AD5Z0B1pttpOyQYWeQNLBvButokgPE0tvL8FotCiTLciAXkj0LLzJX28L5NGsEEdXLnQ/3MC7iLxd2c4Zi9k0bP+eAuKtNSFvMrbKSei5Cbby0SadAuv5S4r4GQ+XCemnvSaEnwWQucrE5dgvyVDeDenhi+DOl1OWXMCkKVxng69LkZvPLnfYKMCoDVbywVIQKBgQC/742drVx41MfQu4Gk6nqtAwSAzVlkJqhWdwJPOxSv+r9EmIiHPtH7owlEaYi0AtpDjS3vwfi0fYuVBRJEMFQWklFhzwsaKFEL0aLtoWTuwmnjpqsmcIKvnRVfjsR04qoeQAexBp0kzKCNTU5/zBnOrY24RMLqSSIUZI+SSXgf0QKBgQC+aLuCIiHcm+leM6YD2D2qLzpEkewP44l4vukw6LCShPCWiFlUPasvEpSc7TfYgVsz91KYtN2W3Xvr370D5j0GpFIx+nh0a2xZ6fYzgTWqt9sP9yEwSUixE1EyE6XayxxlsIgkty4yocFdcdSjTXjOjZ7eINGz3TeVU1O99KWwIwKBgD9PE+YrlbHhdZs7DhNIqHhC44xcr5yiR6pljOR3d2ZojghhS79YkEixSVBAgy/lNPtNKRbJY3CdbJoV1yWYz1O2pZNeiKnzHHCKkHRTZQiAJg9KHXALcn/cj306iUCIt1ZNBnx00wadXGPfWQI8X1LV2kYqoCRJRS120giNpUrRAoGANcXGDn4tKewt/5h+bd+HqqQjxHGhROtxS1Q+7r0IAJjiiOCAubWgvm504cxsVQxTAV37SXzqh0yNTpOlAZDn8xQ80jh2BArCUrIsAWegDFJX3y5fhQ9tI/TcnVPHJv7tShqMmDHTLiFYRld7QZMDZvG/x+Nk1XLH27fokmCg2hkCgYASbp3+tgJ51j3Ci+2nXJ8ISJIfx2I10pbXAsIXNqIqZ7AR3TV5Ezhde6Sb1fg2AoZZmuAxHbJ9/w6tib2nGp8VaNN+dkiyekbLIgfUMH8gQr3bCiMio1wFVWj/ptuioPbiHvEsC092HFJiUiUp9H/PwmVb42UzpznxmfCgSca6Wg==";
const OIDC_RSA_N: &str = "jsJRAhxoWwqNBmr4TvBvsOasUHNfj3aQbIHXercKNKcL8aPLtpjK8uNpQIWCW61VIqkIygZgiByf_mtC3zf46xjybZk483hl5i-KkTVo_20qa5dcRXEynTPgd-sTBTUt8S3Oy7Z1qwhh_t9If7wmQKqttZWo1MqRLPLQWAfyQ0ZuQVzPBsDDlfVF4TpkZ_UGleGu_9IcT298hsHo16RPZTVVNj9S6k3vqfAKxTGyQMShmUZZKVmTUTno_6XfY63YfrNlq5qlxGocuD9c7QTDOnTtQwzsPfmh86fYlhLNC7jAXy0bSRguPdgXuRBbmdJT_StgAA0a14YJh0yPVwEJkw";

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
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
            "INSERT INTO public.user_roles(user_id,role,created_at) VALUES('admin','admin',$1)",
            &[&now],
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.channels(id,name,description,allowed_groups) VALUES \
             ('channel-all','All','all',ARRAY['all']),('channel-risk','Risk','risk',ARRAY['risk']);",
        )
        .await
        .map_err(|error| error.to_string())
}

fn metadata() -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:example:idp:directory"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERT_DER_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

fn registration(provider: &str, domain: &str) -> RegisterIdentityProviderInput {
    serde_json::from_value(serde_json::json!({
        "providerId": provider,
        "issuer": "urn:example:idp:directory",
        "domain": domain,
        "samlConfig": {
            "entryPoint": "https://idp.example/sso",
            "idpMetadata": {"metadata": metadata()},
            "emailAttribute": "email",
            "groupAttribute": "groups",
            "groupNormalization": "trim_lowercase"
        }
    }))
    .unwrap()
}

fn service(pool: &openbot_infra::db::pool::DatabasePool) -> DynamicSsoService {
    service_with_dialer(pool, SafeDialer::new(EgressPolicy::default()))
}

fn service_with_dialer(
    pool: &openbot_infra::db::pool::DatabasePool,
    dialer: SafeDialer,
) -> DynamicSsoService {
    DynamicSsoService::new(
        pool.clone(),
        &TenantId::new("tenant-1"),
        HASH_KEY,
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
        dialer,
        "https://app.example".to_owned(),
    )
    .unwrap()
}

fn response(request_id: &str, assertion_id: &str) -> String {
    let template = format!(
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="response-{request_id}" Version="2.0" IssueInstant="2027-01-15T08:00:00Z" Destination="https://app.example/api/auth/sso/saml2/sp/acs/acme-saml" InResponseTo="{request_id}"><saml:Issuer>urn:example:idp:directory</saml:Issuer><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#response-{request_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="2027-01-15T08:00:00Z"><saml:Issuer>urn:example:idp:directory</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">directory-person-1</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2027-01-15T08:10:00Z" Recipient="https://app.example/api/auth/sso/saml2/sp/acs/acme-saml" InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="2027-01-15T08:10:00Z"><saml:AudienceRestriction><saml:Audience>https://app.example/api/auth/sso/saml2/sp/metadata/acme-saml</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2027-01-15T08:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>person@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue> Risk </saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"##
    );
    let key = BASE64_STANDARD.decode(TEST_KEY_DER_BASE64).unwrap();
    let signed = Crypto::sign_xml(template.as_bytes(), &key).unwrap();
    BASE64_STANDARD.encode(signed.as_bytes())
}

async fn start(
    service: &DynamicSsoService,
    email: &str,
    now: OffsetDateTime,
) -> Result<(String, String), String> {
    let receipt = service
        .route_email(email, "203.0.113.9", now)
        .await
        .map_err(|error| error.to_string())?;
    match service
        .continue_route(receipt.ticket(), "203.0.113.9", now)
        .await
        .map_err(|error| error.to_string())?
    {
        DynamicSsoStart::Saml(SamlStart::Post {
            saml_request,
            relay_state,
            ..
        }) => {
            let xml = BASE64_STANDARD
                .decode(saml_request)
                .map_err(|error| error.to_string())?;
            let request: AuthnRequest = String::from_utf8(xml)
                .map_err(|error| error.to_string())?
                .parse()
                .map_err(|error| format!("{error:?}"))?;
            Ok((request.id, relay_state))
        }
        _ => Err("SAML POST binding 没有产出 POST plan".to_owned()),
    }
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
#[ignore = "需要真实 PostgreSQL + xmlsec1：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored"]
async fn dynamic_saml_is_encrypted_replay_safe_and_delete_cleans_account_anchors() {
    let admin =
        admin_config("dynamic_saml_is_encrypted_replay_safe_and_delete_cleans_account_anchors");
    with_temp_database(&admin, "dynamic_sso", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let service = service(&pool);
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            let actor = ActorId::new("admin");
            service
                .register(registration("acme-saml", "example.com"), &actor, now)
                .await
                .map_err(|error| error.to_string())?;
            let (audience_providers, audience_mappings) = service
                .group_audience_inputs()
                .await
                .map_err(|error| error.to_string())?;
            if audience_providers.len() != 1
                || audience_providers[0].as_str() != "acme-saml"
                || audience_mappings.len() != 1
                || audience_mappings[0].provider().as_str() != "acme-saml"
            {
                return Err("动态 SAML group mapping 没有进入 package audience 输入".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let encrypted: String = client
                .query_one(
                    "SELECT saml_config FROM public.sso_providers WHERE provider_id='acme-saml'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?
                .try_get(0)
                .map_err(|error| error.to_string())?;
            drop(client);
            if !encrypted.starts_with(r#"{"version":2"#)
                || encrypted.contains("X509Certificate")
                || service.list().await.map_err(|error| error.to_string())?.len() != 1
            {
                return Err("SAML config 未以 v2 AAD 信封落库或公开投影漂移".to_owned());
            }

            let unmatched = service
                .route_email("nobody@unmatched.example", "203.0.113.9", now)
                .await
                .map_err(|error| error.to_string())?;
            let unmatched_error = service
                .continue_route(unmatched.ticket(), "203.0.113.9", now)
                .await
                .err()
                .ok_or("未命中 route 竟返回 start")?;
            if !unmatched_error.unknown() {
                return Err("未命中 route ticket 没有统一落到 unknown".to_owned());
            }

            let (request_id, relay_state) = start(&service, "person@example.com", now).await?;
            let issued = service
                .saml_callback(
                    &openbot_infra::auth::oidc::ProviderId::parse("acme-saml").unwrap(),
                    &relay_state,
                    &response(&request_id, "assertion-stable"),
                    now,
                    "203.0.113.9",
                    Some("integration-agent"),
                )
                .await
                .map_err(|error| error.to_string())?;
            if issued.email().as_str() != "person@example.com"
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.verifications \
                     WHERE identifier='saml-assertion-replay' \
                       AND expires_at=to_timestamp(1800000720)",
                )
                .await?
                    != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.channel_memberships WHERE channel_id='channel-risk'",
                )
                .await?
                    != 1
            {
                return Err("SAML identity/group/session 未闭合".to_owned());
            }

            let (second_request, second_relay) =
                start(&service, "person@example.com", now).await?;
            let replay = service
                .saml_callback(
                    &openbot_infra::auth::oidc::ProviderId::parse("acme-saml").unwrap(),
                    &second_relay,
                    &response(&second_request, "assertion-stable"),
                    now,
                    "203.0.113.9",
                    None,
                )
                .await
                .unwrap_err();
            if !replay.assertion_replayed() {
                return Err(format!("同 assertion ID 未被 replay store 拒绝: {replay}"));
            }

            service
                .remove(
                    &openbot_infra::auth::oidc::ProviderId::parse("acme-saml").unwrap(),
                    &actor,
                )
                .await
                .map_err(|error| error.to_string())?;
            if scalar(&pool, "SELECT count(*)::bigint FROM public.sso_providers").await? != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.accounts WHERE provider_id='acme-saml'",
                )
                .await?
                    != 0
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 0
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.audit_events WHERE event_type IN ('identity_provider.registered','identity_provider.removed')",
                )
                .await?
                    != 2
            {
                return Err("删除 provider 未原子清 provider/account/session/audit".to_owned());
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
#[ignore = "需要真实 PostgreSQL + xmlsec1：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored"]
async fn legacy_plaintext_saml_config_is_read_verified_and_resealed_as_v2() {
    let admin = admin_config("legacy_plaintext_saml_config_is_read_verified_and_resealed_as_v2");
    with_temp_database(&admin, "dynamic_sso_legacy", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let legacy = serde_json::json!({
                "entryPoint": "https://idp.example/sso",
                "idpMetadata": {"metadata": metadata()},
                "emailAttribute": "email",
                "groupAttribute": "groups",
                "groupNormalization": "trim_lowercase"
            })
            .to_string();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.sso_providers( \
                       id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) \
                     VALUES('legacy','urn:example:idp:directory',NULL,$1,'admin','legacy-saml',NULL,' Legacy.Example ')",
                    &[&legacy],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            service(&pool)
                .preflight_all(OffsetDateTime::from_unix_timestamp(NOW).unwrap())
                .await
                .map_err(|error| error.to_string())?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT saml_config,domain FROM public.sso_providers WHERE provider_id='legacy-saml'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let resealed: String = row
                .try_get(0)
                .map_err(|error| error.to_string())?;
            let canonical_domain: String = row.try_get(1).map_err(|error| error.to_string())?;
            if !resealed.starts_with(r#"{"version":2"#)
                || resealed.contains("entryPoint")
                || canonical_domain != "legacy.example"
            {
                return Err("legacy plaintext/domain 没有经读验后迁成 canonical v2".to_owned());
            }
            client
                .execute(
                    "INSERT INTO public.sso_providers( \
                       id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) \
                     VALUES('legacy-reserved','urn:example:idp:directory',NULL,$1,'admin','google',NULL,'reserved.example')",
                    &[&legacy],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let reserved = service(&pool)
                .preflight_all(OffsetDateTime::from_unix_timestamp(NOW).unwrap())
                .await
                .expect_err("历史动态 provider 不得占用环境 google ID");
            if !reserved.dependency_unavailable() {
                return Err(format!("保留 provider ID 未按 corrupt startup state 拒绝: {reserved}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "DELETE FROM public.sso_providers WHERE provider_id='google'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.sso_providers( \
                       id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) \
                     VALUES('legacy-org','urn:example:idp:directory',NULL,$1,'admin','org-saml','org-1','org.example')",
                    &[&legacy],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let organization_scoped = service(&pool)
                .preflight_all(OffsetDateTime::from_unix_timestamp(NOW).unwrap())
                .await
                .expect_err("organization-scoped legacy provider 不得被放大成 deployment-owned");
            if !organization_scoped.dependency_unavailable() {
                return Err(format!(
                    "organization-scoped provider 未按 corrupt startup state 拒绝: {organization_scoped}"
                ));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "DELETE FROM public.sso_providers WHERE provider_id='org-saml'",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            for (id, provider, domain) in [
                ("legacy-dup-a", "dup-a", "Dup.Example"),
                ("legacy-dup-b", "dup-b", "dup.example"),
            ] {
                client
                    .execute(
                        "INSERT INTO public.sso_providers( \
                           id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) \
                         VALUES($1,'urn:example:idp:directory',NULL,$2,'admin',$3,NULL,$4)",
                        &[&id, &legacy, &provider, &domain],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
            }
            drop(client);
            let duplicate_domain = service(&pool)
                .preflight_all(OffsetDateTime::from_unix_timestamp(NOW).unwrap())
                .await
                .expect_err("规范化后重叠的历史 domain 必须在启动期拒绝");
            if !duplicate_domain.dependency_unavailable() {
                return Err(format!(
                    "规范化 domain 冲突未按 corrupt startup state 拒绝: {duplicate_domain}"
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

#[derive(Clone)]
struct LocalResolver(SocketAddr);

#[async_trait::async_trait]
impl DnsResolver for LocalResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, DnsUnavailable> {
        Ok(vec![self.0])
    }
}

#[derive(Clone)]
struct OidcAuthorizationParams {
    nonce: String,
    challenge: String,
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL + 本机 TLS：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored"]
async fn dynamic_oidc_registration_start_and_cross_replica_callback_share_the_safe_flow() {
    let admin = admin_config(
        "dynamic_oidc_registration_start_and_cross_replica_callback_share_the_safe_flow",
    );
    with_temp_database(&admin, "dynamic_oidc", |config| async move {
        let pool = pool::connect(&config).await.map_err(|error| error.to_string())?;
        let outcome = async {
            provision(&pool).await?;
            let auth_params = Arc::new(Mutex::new(None));
            let calls = Arc::new(AtomicUsize::new(0));
            let (address, root, server) =
                spawn_oidc_idp(auth_params.clone(), calls.clone()).await?;
            let dialer = SafeDialer::with_extra_roots(
                EgressPolicy::new(
                    CidrAllowlist::parse_exact(["127.0.0.1/32"])
                        .map_err(|error| error.to_string())?,
                ),
                Arc::new(LocalResolver(address)),
                [root],
            )
            .map_err(|error| error.to_string())?;
            let first = service_with_dialer(&pool, dialer.clone());
            let second = service_with_dialer(&pool, dialer);
            let issuer = format!("https://idp.test:{}", address.port());
            let input: RegisterIdentityProviderInput = serde_json::from_value(serde_json::json!({
                "providerId": "acme-oidc",
                "issuer": issuer,
                "domain": "oidc.example",
                "oidcConfig": {
                    "clientId": "acme-client",
                    "clientSecret": "acme-secret",
                    "discoveryEndpoint": format!("{issuer}/.well-known/openid-configuration"),
                    "groupClaimPath": "groups",
                    "groupNormalization": "trim_lowercase"
                }
            }))
            .unwrap();
            let now = OffsetDateTime::from_unix_timestamp(NOW).unwrap();
            first
                .register(input, &ActorId::new("admin"), now)
                .await
                .map_err(|error| error.to_string())?;
            let receipt = first
                .route_email("person@oidc.example", "203.0.113.7", now)
                .await
                .map_err(|error| error.to_string())?;
            let authorization = match first
                .continue_route(receipt.ticket(), "203.0.113.7", now)
                .await
                .map_err(|error| error.to_string())?
            {
                DynamicSsoStart::Oidc(url) => url,
                _ => return Err("dynamic OIDC route 没有产出授权 URL".to_owned()),
            };
            let query: std::collections::BTreeMap<String, String> =
                authorization.query_pairs().into_owned().collect();
            let state = query.get("state").cloned().ok_or("缺 state")?;
            *auth_params.lock().unwrap() = Some(OidcAuthorizationParams {
                nonce: query.get("nonce").cloned().ok_or("缺 nonce")?,
                challenge: query
                    .get("code_challenge")
                    .cloned()
                    .ok_or("缺 challenge")?,
            });
            let provider = openbot_infra::auth::oidc::ProviderId::parse("acme-oidc").unwrap();
            let issued = second
                .oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    Some("integration-agent"),
                )
                .await
                .map_err(|error| error.to_string())?;
            if issued.email().as_str() != "person@oidc.example"
                || scalar(&pool, "SELECT count(*)::bigint FROM public.sessions").await? != 1
                || scalar(
                    &pool,
                    "SELECT count(*)::bigint FROM public.channel_memberships WHERE channel_id='channel-risk'",
                )
                .await?
                    != 1
            {
                return Err("dynamic OIDC 跨 replica 未签成 session/group".to_owned());
            }
            let replay = first
                .oidc_callback(
                    &provider,
                    &state,
                    "valid-code",
                    now,
                    "203.0.113.7",
                    None,
                )
                .await;
            if replay.is_ok() {
                return Err("dynamic OIDC state 被重放".to_owned());
            }
            server.await.map_err(|error| error.to_string())??;
            if calls.load(Ordering::SeqCst) != 5 {
                return Err(format!(
                    "注册/start/callback discovery + token/JWKS 应 5 次，实得 {}",
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

async fn spawn_oidc_idp(
    auth_params: Arc<Mutex<Option<OidcAuthorizationParams>>>,
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
        for _ in 0..5 {
            let (stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let mut tls = acceptor
                .accept(stream)
                .await
                .map_err(|error| error.to_string())?;
            let request = read_http_request(&mut tls).await?;
            calls.fetch_add(1, Ordering::SeqCst);
            let (status, content_type, body) =
                if request.path == "/.well-known/openid-configuration" {
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
                    let form: std::collections::BTreeMap<String, String> =
                        url::form_urlencoded::parse(&request.body)
                            .into_owned()
                            .collect();
                    if form.get("code").map(String::as_str) != Some("valid-code")
                        || !request
                            .headers
                            .to_ascii_lowercase()
                            .contains("authorization: basic ")
                    {
                        return Err("dynamic token POST 不符".to_owned());
                    }
                    let verifier = form.get("code_verifier").ok_or("缺 verifier")?;
                    let actual = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(Sha256::digest(verifier.as_bytes()));
                    let params = auth_params
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or("尚未捕获 authorize params")?;
                    if actual != params.challenge {
                        return Err("dynamic PKCE 不匹配".to_owned());
                    }
                    let token = sign_oidc_rs256(&serde_json::json!({
                        "iss": origin,
                        "aud": ["acme-client"],
                        "exp": 9_999_999_999_i64,
                        "iat": NOW,
                        "sub": "dynamic-subject",
                        "nonce": params.nonce,
                        "email": "person@oidc.example",
                        "groups": [" Risk "]
                    }))?;
                    (
                        "200 OK",
                        "application/json",
                        serde_json::json!({
                            "access_token":"ephemeral", "token_type":"Bearer", "id_token":token
                        })
                        .to_string(),
                    )
                } else if request.path == "/jwks" {
                    (
                        "200 OK",
                        "application/jwk-set+json",
                        serde_json::json!({"keys":[{
                            "kty":"RSA","use":"sig","kid":"key-1","alg":"RS256",
                            "n":OIDC_RSA_N,"e":"AQAB"
                        }]})
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
            return Err("OIDC request header EOF".to_owned());
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
            return Err("OIDC request body EOF".to_owned());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(TestHttpRequest {
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn sign_oidc_rs256(claims: &serde_json::Value) -> Result<String, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"key-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?);
    let input = format!("{header}.{payload}");
    let key = RsaKeyPair::from_pkcs8(
        &BASE64_STANDARD
            .decode(OIDC_RSA_KEY_DER)
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
