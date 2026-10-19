//! Bounded account identity reads through the reviewed Gateway transport.
//!
//! These values prove only that one injected transport returned protocol-shaped metadata and an
//! account identity. They are not Wrok authorization, a token store, or permission to send a model
//! request.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use acosmi::{
    HttpContext, HttpPurpose, HttpRequest, HttpResponse, HttpTransport, ServerMetadata,
    TransportError,
};
use futures_util::StreamExt as _;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use openbot_domain::vault::SecretBytes;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_MAX_BYTES: usize = 64 * 1024;
const URL_MAX_BYTES: usize = 2048;
const LIST_MAX_ITEMS: usize = 64;
const LIST_ITEM_MAX_BYTES: usize = 128;
const IDENTIFIER_MAX_BYTES: usize = 256;
const AUTHORIZATION_MAX_BYTES: usize = 16 * 1024;

const DISCOVERY_PATH: &str = "/.well-known/oauth-authorization-server/desktop";
const PROFILE_PATH: &str = "/api/oauth/profile";
const AUTHORIZATION_PATH: &str = "/oauth/desktop/authorize";
const TOKEN_PATH: &str = "/oauth/desktop/token";
const REGISTRATION_PATH: &str = "/oauth/desktop/register";
const REVOCATION_PATH: &str = "/oauth/desktop/revoke";

/// Closed, payload-free account reader failures. Only a safe HTTP status number is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GatewayAccountError {
    /// Base URL, metadata binding, or credential header shape was invalid before a request.
    #[error("gateway_account_configuration_invalid")]
    Configuration,
    /// The caller cancelled the operation.
    #[error("gateway_account_cancelled")]
    Cancelled,
    /// The complete ten-second operation budget elapsed.
    #[error("gateway_account_timeout")]
    Timeout,
    /// The injected transport failed without a safe response.
    #[error("gateway_account_transport_failed")]
    Transport,
    /// The server returned a non-success status.
    #[error("gateway_account_http_status_{0}")]
    HttpStatus(u16),
    /// The response did not have exactly one supported JSON content type.
    #[error("gateway_account_content_type_invalid")]
    ContentType,
    /// The response body exceeded the fixed bound.
    #[error("gateway_account_body_too_large")]
    BodyTooLarge,
    /// The response body stream did not complete normally.
    #[error("gateway_account_body_failed")]
    Body,
    /// OAuth metadata was malformed, duplicated, incomplete, or outside the fixed contract.
    #[error("gateway_account_metadata_invalid")]
    MetadataInvalid,
    /// The account profile was malformed, duplicated, incomplete, or internally inconsistent.
    #[error("gateway_account_profile_invalid")]
    ProfileInvalid,
}

/// Verified Desktop OAuth metadata. This value is not authority and is deliberately not Clone or
/// serializable.
pub struct GatewayDesktopMetadata {
    issuer: String,
    sdk_metadata: ServerMetadata,
}

impl GatewayDesktopMetadata {
    /// Borrow the SDK metadata only after the additional contract fields were independently
    /// verified by this module.
    #[must_use]
    pub const fn sdk_metadata(&self) -> &ServerMetadata {
        &self.sdk_metadata
    }
}

impl fmt::Debug for GatewayDesktopMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayDesktopMetadata([redacted])")
    }
}

/// Stable account identity returned by the authenticated profile endpoint. It does not grant any
/// Wrok role or resource access and is deliberately not Clone or serializable.
pub struct GatewayAccountIdentity {
    issuer: String,
    account_id: String,
    organization_id: Option<String>,
}

impl GatewayAccountIdentity {
    /// OAuth issuer that authenticated this profile response.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Stable opaque account identifier. Its field name does not imply UUID syntax.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Optional stable opaque organization identifier.
    #[must_use]
    pub fn organization_id(&self) -> Option<&str> {
        self.organization_id.as_deref()
    }
}

impl fmt::Debug for GatewayAccountIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayAccountIdentity([redacted])")
    }
}

/// Read-only client over a host-constructed, fenced SDK transport.
pub struct GatewayAccountClient {
    origin: String,
    discovery_url: Url,
    profile_url: Url,
    transport: Arc<dyn HttpTransport>,
}

impl GatewayAccountClient {
    /// Bind one HTTPS origin (or its exact `/api/v4[/]` spelling) to an injected transport.
    pub fn new(base: &str, transport: Arc<dyn HttpTransport>) -> Result<Self, GatewayAccountError> {
        let origin = normalize_origin(base)?;
        let discovery_url = fixed_url(&origin, DISCOVERY_PATH)?;
        let profile_url = fixed_url(&origin, PROFILE_PATH)?;
        Ok(Self {
            origin,
            discovery_url,
            profile_url,
            transport,
        })
    }

    /// Read and verify Desktop OAuth metadata. Unknown ordinary metadata fields are ignored and do
    /// not enlarge the allowed target or scope set.
    pub async fn fetch_metadata(
        &self,
        cancel: CancellationToken,
    ) -> Result<GatewayDesktopMetadata, GatewayAccountError> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let request = HttpRequest {
            method: Method::GET,
            url: self.discovery_url.clone(),
            headers,
            body: Vec::new(),
            context: HttpContext::buffered(HttpPurpose::OAuthDiscovery, 10_000),
        };
        let body = self.execute_json(request, cancel).await?;
        let raw: RawMetadata =
            serde_json::from_slice(&body).map_err(|_| GatewayAccountError::MetadataInvalid)?;
        validate_metadata(raw, &self.origin)
    }

    /// Read the stable account identity using one bearer access token. Metadata and credential
    /// shape are checked before the transport is invoked.
    pub async fn fetch_profile(
        &self,
        metadata: &GatewayDesktopMetadata,
        access_token: &SecretBytes,
        cancel: CancellationToken,
    ) -> Result<GatewayAccountIdentity, GatewayAccountError> {
        let request = self.profile_request(metadata, access_token)?;
        let body = self.execute_json(request, cancel).await?;
        self.decode_profile(&body)
    }

    fn profile_request(
        &self,
        metadata: &GatewayDesktopMetadata,
        access_token: &SecretBytes,
    ) -> Result<HttpRequest, GatewayAccountError> {
        if metadata.issuer != self.origin || metadata.sdk_metadata.issuer != self.origin {
            return Err(GatewayAccountError::Configuration);
        }
        let token = access_token.expose();
        if token.is_empty()
            || token.len() > AUTHORIZATION_MAX_BYTES.saturating_sub("Bearer ".len())
            || !token.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(GatewayAccountError::Configuration);
        }
        let mut bearer = Zeroizing::new(Vec::with_capacity("Bearer ".len() + token.len()));
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(token);
        let mut authorization = HeaderValue::from_bytes(bearer.as_slice())
            .map_err(|_| GatewayAccountError::Configuration)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, authorization);
        let request = HttpRequest {
            method: Method::GET,
            url: self.profile_url.clone(),
            headers,
            body: Vec::new(),
            context: HttpContext::buffered(HttpPurpose::Api, 10_000),
        };
        Ok(request)
    }

    fn decode_profile(&self, body: &[u8]) -> Result<GatewayAccountIdentity, GatewayAccountError> {
        let raw: RawProfile =
            serde_json::from_slice(body).map_err(|_| GatewayAccountError::ProfileInvalid)?;
        let id = raw.id.ok_or(GatewayAccountError::ProfileInvalid)?;
        let uuid = raw.uuid.ok_or(GatewayAccountError::ProfileInvalid)?;
        let account = raw.account.ok_or(GatewayAccountError::ProfileInvalid)?;
        let account_uuid = account.uuid.ok_or(GatewayAccountError::ProfileInvalid)?;
        if !valid_identifier(&id)
            || !valid_identifier(&uuid)
            || !valid_identifier(&account_uuid)
            || id != uuid
            || id != account_uuid
        {
            return Err(GatewayAccountError::ProfileInvalid);
        }
        let organization = raw
            .organization
            .ok_or(GatewayAccountError::ProfileInvalid)?;
        let organization_uuid = organization
            .uuid
            .ok_or(GatewayAccountError::ProfileInvalid)?;
        let organization_id = match organization_uuid {
            value if value.is_empty() => None,
            value if valid_identifier(&value) => Some(value),
            _ => return Err(GatewayAccountError::ProfileInvalid),
        };
        Ok(GatewayAccountIdentity {
            issuer: self.origin.clone(),
            account_id: id,
            organization_id,
        })
    }

    pub(crate) async fn fetch_metadata_for_enrollment(
        &self,
        current: &crate::gateway_authorization::journal::enrollment::EnrollmentCurrent<'_>,
    ) -> Result<GatewayDesktopMetadata, EnrollmentAccountReadError> {
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let request = HttpRequest {
            method: Method::GET,
            url: self.discovery_url.clone(),
            headers,
            body: Vec::new(),
            context: HttpContext::buffered(HttpPurpose::OAuthDiscovery, 10_000),
        };
        let body = self.execute_json_for_enrollment(request, current).await?;
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        let raw: RawMetadata = serde_json::from_slice(&body).map_err(|_| {
            EnrollmentAccountReadError::Account(GatewayAccountError::MetadataInvalid)
        })?;
        let result =
            validate_metadata(raw, &self.origin).map_err(EnrollmentAccountReadError::Account);
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        result
    }

    pub(crate) async fn fetch_profile_for_enrollment(
        &self,
        metadata: &GatewayDesktopMetadata,
        access_token: &SecretBytes,
        current: &crate::gateway_authorization::journal::enrollment::EnrollmentCurrent<'_>,
    ) -> Result<GatewayAccountIdentity, EnrollmentAccountReadError> {
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        let request = self
            .profile_request(metadata, access_token)
            .map_err(EnrollmentAccountReadError::Account)?;
        let body = self.execute_json_for_enrollment(request, current).await?;
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        let result = self
            .decode_profile(&body)
            .map_err(EnrollmentAccountReadError::Account);
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        result
    }

    async fn execute_json_for_enrollment(
        &self,
        request: HttpRequest,
        current: &crate::gateway_authorization::journal::enrollment::EnrollmentCurrent<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, EnrollmentAccountReadError> {
        current
            .check()
            .map_err(EnrollmentAccountReadError::Current)?;
        let deadline = current
            .deadline()
            .map_err(EnrollmentAccountReadError::Current)?
            .min(Instant::now().checked_add(REQUEST_TIMEOUT).ok_or(
                EnrollmentAccountReadError::Account(GatewayAccountError::Timeout),
            )?);
        let cancel = current.original_parent().clone();
        let execute = self.transport.execute(request, cancel.clone());
        let mut execute = std::pin::pin!(execute);
        let observed = std::future::poll_fn(|cx| {
            enrollment_poll_bookended(
                || enrollment_check(current, deadline),
                || execute.as_mut().poll(cx),
            )
        });
        let mut response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(EnrollmentAccountReadError::Account(GatewayAccountError::Cancelled)),
            () = tokio::time::sleep_until(deadline) => return Err(EnrollmentAccountReadError::Account(GatewayAccountError::Timeout)),
            result = observed => result?.map_err(|e| EnrollmentAccountReadError::Account(map_transport(e)))?,
        };
        enrollment_check(current, deadline)?;
        if response.status != StatusCode::OK {
            return Err(EnrollmentAccountReadError::Account(
                GatewayAccountError::HttpStatus(response.status.as_u16()),
            ));
        }
        validate_json_content_type(&response.headers)
            .map_err(EnrollmentAccountReadError::Account)?;
        enrollment_check(current, deadline)?;
        let mut body = Zeroizing::new(Vec::with_capacity(RESPONSE_MAX_BYTES));
        loop {
            // One closure performs exactly one original body.poll_next. Every result,
            // including Pending/Err/EOF, is postchecked before it leaves this closure.
            let observed = std::future::poll_fn(|cx| {
                enrollment_poll_bookended(
                    || enrollment_check(current, deadline),
                    || futures_util::Stream::poll_next(response.body.as_mut(), cx),
                )
            });
            let next = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(EnrollmentAccountReadError::Account(GatewayAccountError::Cancelled)),
                () = tokio::time::sleep_until(deadline) => return Err(EnrollmentAccountReadError::Account(GatewayAccountError::Timeout)),
                result = observed => result?,
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|e| EnrollmentAccountReadError::Account(map_transport(e)))?;
            let next_len =
                body.len()
                    .checked_add(chunk.len())
                    .ok_or(EnrollmentAccountReadError::Account(
                        GatewayAccountError::BodyTooLarge,
                    ))?;
            if next_len > RESPONSE_MAX_BYTES {
                return Err(EnrollmentAccountReadError::Account(
                    GatewayAccountError::BodyTooLarge,
                ));
            }
            body.extend_from_slice(chunk.as_ref());
        }
        enrollment_check(current, deadline)?;
        Ok(body)
    }

    async fn execute_json(
        &self,
        request: HttpRequest,
        cancel: CancellationToken,
    ) -> Result<Zeroizing<Vec<u8>>, GatewayAccountError> {
        if cancel.is_cancelled() {
            return Err(GatewayAccountError::Cancelled);
        }
        let deadline = Instant::now()
            .checked_add(REQUEST_TIMEOUT)
            .ok_or(GatewayAccountError::Timeout)?;
        let response = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(GatewayAccountError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(GatewayAccountError::Timeout),
            result = self.transport.execute(request, cancel.clone()) => result.map_err(map_transport)?,
        };
        read_json_response(response, &cancel, deadline).await
    }
}

impl fmt::Debug for GatewayAccountClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayAccountClient([redacted])")
    }
}

#[derive(Debug)]
pub(crate) enum EnrollmentAccountReadError {
    Account(GatewayAccountError),
    Current(crate::gateway_authorization::journal::GatewayAuthorizationJournalError),
}
fn enrollment_check(
    current: &crate::gateway_authorization::journal::enrollment::EnrollmentCurrent<'_>,
    deadline: Instant,
) -> Result<(), EnrollmentAccountReadError> {
    current
        .check()
        .map_err(EnrollmentAccountReadError::Current)?;
    if Instant::now() >= deadline {
        return Err(EnrollmentAccountReadError::Account(
            GatewayAccountError::Timeout,
        ));
    }
    Ok(())
}
// Private pure lemma. Production reaches it only through the sealed current readers above.
fn enrollment_poll_bookended<T, E>(
    mut check: impl FnMut() -> Result<(), E>,
    poll: impl FnOnce() -> std::task::Poll<T>,
) -> std::task::Poll<Result<T, E>> {
    use std::task::Poll;
    if let Err(error) = check() {
        return Poll::Ready(Err(error));
    }
    let result = poll();
    if let Err(error) = check() {
        return Poll::Ready(Err(error));
    }
    result.map(Ok)
}

async fn read_json_response(
    mut response: HttpResponse,
    cancel: &CancellationToken,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, GatewayAccountError> {
    if response.status != StatusCode::OK {
        return Err(GatewayAccountError::HttpStatus(response.status.as_u16()));
    }
    validate_json_content_type(&response.headers)?;
    let mut body = Zeroizing::new(Vec::with_capacity(RESPONSE_MAX_BYTES));
    loop {
        let next = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(GatewayAccountError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(GatewayAccountError::Timeout),
            value = response.body.next() => value,
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(map_transport)?;
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .ok_or(GatewayAccountError::BodyTooLarge)?;
        if next_len > RESPONSE_MAX_BYTES {
            return Err(GatewayAccountError::BodyTooLarge);
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

fn map_transport(error: TransportError) -> GatewayAccountError {
    match error {
        TransportError::Cancelled => GatewayAccountError::Cancelled,
        TransportError::Timeout => GatewayAccountError::Timeout,
        TransportError::Body => GatewayAccountError::Body,
        TransportError::Connection
        | TransportError::Rejected
        | TransportError::InvalidRequest
        | TransportError::UnsupportedBody
        | TransportError::UnsupportedWebSocket => GatewayAccountError::Transport,
    }
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), GatewayAccountError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or(GatewayAccountError::ContentType)?;
    if values.next().is_some() {
        return Err(GatewayAccountError::ContentType);
    }
    let value = value
        .to_str()
        .map_err(|_| GatewayAccountError::ContentType)?;
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(GatewayAccountError::ContentType);
    }
    let mut charset = false;
    for parameter in parts {
        let (name, value) = parameter
            .trim()
            .split_once('=')
            .ok_or(GatewayAccountError::ContentType)?;
        if charset
            || !name.trim().eq_ignore_ascii_case("charset")
            || !value.trim().eq_ignore_ascii_case("utf-8")
        {
            return Err(GatewayAccountError::ContentType);
        }
        charset = true;
    }
    Ok(())
}

fn normalize_origin(base: &str) -> Result<String, GatewayAccountError> {
    if base.is_empty()
        || base.len() > URL_MAX_BYTES
        || base.trim() != base
        || base.chars().any(char::is_control)
    {
        return Err(GatewayAccountError::Configuration);
    }
    let url = Url::parse(base).map_err(|_| GatewayAccountError::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | "/api/v4" | "/api/v4/")
    {
        return Err(GatewayAccountError::Configuration);
    }
    let origin = url.origin().ascii_serialization();
    if origin.len() > URL_MAX_BYTES {
        return Err(GatewayAccountError::Configuration);
    }
    Ok(origin)
}

fn fixed_url(origin: &str, path: &str) -> Result<Url, GatewayAccountError> {
    let raw = format!("{origin}{path}");
    if raw.len() > URL_MAX_BYTES {
        return Err(GatewayAccountError::Configuration);
    }
    Url::parse(&raw).map_err(|_| GatewayAccountError::Configuration)
}

fn expected_url(origin: &str, path: &str) -> Result<String, GatewayAccountError> {
    fixed_url(origin, path).map(|url| url.to_string())
}

fn valid_identifier(value: &str) -> bool {
    (1..=IDENTIFIER_MAX_BYTES).contains(&value.len())
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_advertised_list(values: &[String]) -> bool {
    if values.len() > LIST_MAX_ITEMS {
        return false;
    }
    let mut seen = std::collections::BTreeSet::new();
    values.iter().all(|value| {
        (1..=LIST_ITEM_MAX_BYTES).contains(&value.len())
            && !value.chars().any(char::is_control)
            && seen.insert(value.as_str())
    })
}

fn validate_metadata(
    raw: RawMetadata,
    origin: &str,
) -> Result<GatewayDesktopMetadata, GatewayAccountError> {
    let issuer = raw.issuer.ok_or(GatewayAccountError::MetadataInvalid)?;
    let authorization_endpoint = raw
        .authorization_endpoint
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let token_endpoint = raw
        .token_endpoint
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let registration_endpoint = raw
        .registration_endpoint
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let revocation_endpoint = raw
        .revocation_endpoint
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let scopes_supported = raw
        .scopes_supported
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let response_types_supported = raw
        .response_types_supported
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let code_challenge_methods_supported = raw
        .code_challenge_methods_supported
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let token_endpoint_auth_methods_supported = raw
        .token_endpoint_auth_methods_supported
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    let grant_types_supported = raw
        .grant_types_supported
        .ok_or(GatewayAccountError::MetadataInvalid)?;
    if raw.crabcode_auth_contract_version != Some(2)
        || raw.gateway_error_contract_version != Some(1)
        || issuer != origin
        || authorization_endpoint != expected_url(origin, AUTHORIZATION_PATH)?
        || token_endpoint != expected_url(origin, TOKEN_PATH)?
        || registration_endpoint != expected_url(origin, REGISTRATION_PATH)?
        || revocation_endpoint != expected_url(origin, REVOCATION_PATH)?
        || ![
            &scopes_supported,
            &response_types_supported,
            &code_challenge_methods_supported,
            &token_endpoint_auth_methods_supported,
            &grant_types_supported,
        ]
        .into_iter()
        .all(|values| valid_advertised_list(values))
        || !supports(&scopes_supported, &["ai", "account"])
        || !supports(&response_types_supported, &["code"])
        || !supports(&code_challenge_methods_supported, &["S256"])
        || !supports(&token_endpoint_auth_methods_supported, &["none"])
        || !supports(
            &grant_types_supported,
            &["authorization_code", "refresh_token"],
        )
    {
        return Err(GatewayAccountError::MetadataInvalid);
    }
    let sdk_metadata = ServerMetadata {
        issuer: issuer.clone(),
        authorization_endpoint,
        token_endpoint,
        revocation_endpoint,
        registration_endpoint,
        scopes_supported,
    };
    Ok(GatewayDesktopMetadata {
        issuer,
        sdk_metadata,
    })
}

fn supports(values: &[String], required: &[&str]) -> bool {
    required
        .iter()
        .all(|required| values.iter().any(|value| value == required))
}

#[derive(Default)]
struct RawMetadata {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    scopes_supported: Option<Vec<String>>,
    response_types_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<Vec<String>>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    grant_types_supported: Option<Vec<String>>,
    crabcode_auth_contract_version: Option<u64>,
    gateway_error_contract_version: Option<u64>,
}

impl<'de> Deserialize<'de> for RawMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawMetadataVisitor;
        impl<'de> Visitor<'de> for RawMetadataVisitor {
            type Value = RawMetadata;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("gateway OAuth metadata object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut value = RawMetadata::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "issuer" => set_once::<_, M::Error>(&mut value.issuer, map.next_value()?)?,
                        "authorization_endpoint" => set_once::<_, M::Error>(
                            &mut value.authorization_endpoint,
                            map.next_value()?,
                        )?,
                        "token_endpoint" => {
                            set_once::<_, M::Error>(&mut value.token_endpoint, map.next_value()?)?
                        }
                        "revocation_endpoint" => set_once::<_, M::Error>(
                            &mut value.revocation_endpoint,
                            map.next_value()?,
                        )?,
                        "registration_endpoint" => set_once::<_, M::Error>(
                            &mut value.registration_endpoint,
                            map.next_value()?,
                        )?,
                        "scopes_supported" => {
                            set_once::<_, M::Error>(&mut value.scopes_supported, map.next_value()?)?
                        }
                        "response_types_supported" => set_once::<_, M::Error>(
                            &mut value.response_types_supported,
                            map.next_value()?,
                        )?,
                        "code_challenge_methods_supported" => set_once::<_, M::Error>(
                            &mut value.code_challenge_methods_supported,
                            map.next_value()?,
                        )?,
                        "token_endpoint_auth_methods_supported" => set_once::<_, M::Error>(
                            &mut value.token_endpoint_auth_methods_supported,
                            map.next_value()?,
                        )?,
                        "grant_types_supported" => set_once::<_, M::Error>(
                            &mut value.grant_types_supported,
                            map.next_value()?,
                        )?,
                        "crabcode_auth_contract_version" => set_once::<_, M::Error>(
                            &mut value.crabcode_auth_contract_version,
                            map.next_value()?,
                        )?,
                        "gateway_error_contract_version" => set_once::<_, M::Error>(
                            &mut value.gateway_error_contract_version,
                            map.next_value()?,
                        )?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(RawMetadataVisitor)
    }
}

#[derive(Default)]
struct RawProfile {
    id: Option<String>,
    uuid: Option<String>,
    account: Option<RawIdentityObject>,
    organization: Option<RawIdentityObject>,
}

impl<'de> Deserialize<'de> for RawProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawProfileVisitor;
        impl<'de> Visitor<'de> for RawProfileVisitor {
            type Value = RawProfile;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("gateway account profile object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut value = RawProfile::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "id" => set_once::<_, M::Error>(&mut value.id, map.next_value()?)?,
                        "uuid" => set_once::<_, M::Error>(&mut value.uuid, map.next_value()?)?,
                        "account" => {
                            set_once::<_, M::Error>(&mut value.account, map.next_value()?)?
                        }
                        "organization" => {
                            set_once::<_, M::Error>(&mut value.organization, map.next_value()?)?
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(RawProfileVisitor)
    }
}

#[derive(Default)]
struct RawIdentityObject {
    uuid: Option<String>,
}

impl<'de> Deserialize<'de> for RawIdentityObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawIdentityVisitor;
        impl<'de> Visitor<'de> for RawIdentityVisitor {
            type Value = RawIdentityObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("gateway profile identity object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut value = RawIdentityObject::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "uuid" {
                        set_once::<_, M::Error>(&mut value.uuid, map.next_value()?)?;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(value)
            }
        }
        deserializer.deserialize_map(RawIdentityVisitor)
    }
}

fn set_once<T, E>(slot: &mut Option<T>, value: T) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.replace(value).is_some() {
        return Err(E::custom("duplicate selected gateway field"));
    }
    Ok(())
}

#[cfg(test)]
mod enrollment_bookend_tests {
    use super::enrollment_poll_bookended;
    use std::cell::Cell;
    use std::task::Poll;

    #[test]
    fn p05_body_pending_ready_error_eof_bookends() {
        // Pure per-poll lemma only; no real HTTP/body/Host/PG acceptance credit.
        let polls = Cell::new(0);
        let refused: Poll<Result<Option<Result<&[u8], ()>>, &str>> = enrollment_poll_bookended(
            || Err("before"),
            || {
                polls.set(polls.get() + 1);
                Poll::Pending
            },
        );
        assert_eq!(refused, Poll::Ready(Err("before")));
        assert_eq!(polls.get(), 0);
        for raw in [
            Poll::Pending,
            Poll::Ready(Some(Ok(&b"owned"[..]))),
            Poll::Ready(Some(Err(()))),
            Poll::Ready(None),
        ] {
            let checks = Cell::new(0);
            let result = enrollment_poll_bookended(
                || {
                    let n = checks.get();
                    checks.set(n + 1);
                    if n == 0 { Ok(()) } else { Err("after") }
                },
                || {
                    polls.set(polls.get() + 1);
                    raw
                },
            );
            assert_eq!(result, Poll::Ready(Err("after")));
            assert_eq!(checks.get(), 2);
        }
        assert_eq!(polls.get(), 4);
        let checks = Cell::new(0);
        let chunks: [Option<Result<&[u8], ()>>; 3] =
            [Some(Ok(&b"a"[..])), Some(Ok(&b"b"[..])), None];
        for raw in chunks {
            let result: Poll<Result<_, ()>> = enrollment_poll_bookended(
                || {
                    checks.set(checks.get() + 1);
                    Ok(())
                },
                || Poll::Ready(raw),
            );
            assert_eq!(result, Poll::Ready(Ok(raw)));
        }
        assert_eq!(checks.get(), 6);
    }
}
