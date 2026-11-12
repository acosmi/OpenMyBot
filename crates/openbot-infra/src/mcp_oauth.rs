//! MCP OAuth 2.1 protected-resource discovery and refresh-token exchange.
//!
//! The adapter follows the first source §9.4 and the MCP 2026-07-28 authorization profile:
//! protected-resource metadata selects the authorization server, authorization-server metadata
//! must repeat the exact issuer, PKCE S256 support is mandatory, and every token request carries
//! the exact RFC 8707 resource. Network access is exclusively through [`SafeDialer`].

use std::borrow::Cow;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http::header::{HeaderName, HeaderValue, WWW_AUTHENTICATE};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use openbot_domain::vault::SecretBytes;

use crate::net::safe_http::{
    AuthorizationValue, CidrAllowlist, EgressPolicy, McpHttpMethod, SafeDialer, SafeHttpBudget,
    SafeHttpRequest, SchemePolicy,
};
use crate::store::plugin_user_credential::{
    OAuthRefreshExchange, OAuthTokenExchangeError, RotatingOAuthGrant, RotatingOAuthTokenExchanger,
};

/// First-source parity timeout for an OAuth token exchange.
pub const MCP_OAUTH_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);
const MCP_OAUTH_METADATA_TIMEOUT: Duration = Duration::from_secs(10);
/// One bounded authorization-server round of this client: discovery (one
/// challenge probe, then at most four protected-resource and four
/// authorization-server metadata fetches) plus one token or revocation request.
/// Recovery admission deadlines add it once per round.
pub(crate) const MCP_OAUTH_ROUND_BUDGET: Duration = MCP_OAUTH_METADATA_TIMEOUT
    .saturating_mul(9)
    .saturating_add(MCP_OAUTH_TOKEN_TIMEOUT);
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_OAUTH_SERVERS: usize = 16;
const MAX_SCOPES: usize = 256;
const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// Stable discovery/refresh failure. Remote URLs, headers, bodies and token values never cross it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum McpOAuthError {
    /// DNS/TLS/HTTP dependency is temporarily unavailable.
    #[error("mcp_oauth_unavailable")]
    Unavailable,
    /// Stored client registration is incomplete or violates the closed schema.
    #[error("mcp_oauth_client_invalid")]
    InvalidClient,
    /// Protected-resource or authorization-server metadata is missing/inconsistent.
    #[error("mcp_oauth_metadata_invalid")]
    InvalidMetadata,
    /// Authorization server rejected the refresh grant or client.
    #[error("mcp_oauth_auth_required")]
    AuthRequired,
    /// Authorization server requires a wider interactive grant.
    #[error("mcp_oauth_insufficient_scope")]
    InsufficientScope,
    /// Token response is malformed or violates the rotation boundary.
    #[error("mcp_oauth_token_invalid")]
    InvalidTokenResponse,
}

impl From<McpOAuthError> for OAuthTokenExchangeError {
    fn from(value: McpOAuthError) -> Self {
        match value {
            McpOAuthError::Unavailable => Self::Unavailable,
            McpOAuthError::AuthRequired => Self::AuthRequired,
            McpOAuthError::InsufficientScope => Self::InsufficientScope,
            McpOAuthError::InvalidClient
            | McpOAuthError::InvalidMetadata
            | McpOAuthError::InvalidTokenResponse => Self::InvalidResponse,
        }
    }
}

/// Validated authorization-server facts useful to connect/callback orchestration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpOAuthDiscovery {
    resource: String,
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    revocation_endpoint: Option<Url>,
    scopes: Vec<String>,
    offline_access_supported: bool,
    authorization_response_iss_parameter_supported: bool,
}

impl McpOAuthDiscovery {
    /// Exact RFC 8707 protected-resource identifier.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Exact issuer selected by protected-resource metadata.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Validated user-agent authorization endpoint.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Validated refresh/code token endpoint.
    #[must_use]
    pub const fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Optional validated RFC 7009 revocation endpoint.
    #[must_use]
    pub const fn revocation_endpoint(&self) -> Option<&Url> {
        self.revocation_endpoint.as_ref()
    }

    /// Minimal protected-resource scopes advertised by the MCP server.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Whether callback `iss` is mandatory for this authorization server.
    #[must_use]
    pub const fn requires_callback_issuer(&self) -> bool {
        self.authorization_response_iss_parameter_supported
    }
}

/// Browser authorization plan derived only from validated metadata and registered client data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpOAuthAuthorizationPlan {
    authorization_url: Url,
    issuer: String,
    requested_scope: String,
    authorization_response_iss_parameter_supported: bool,
}

impl McpOAuthAuthorizationPlan {
    /// Complete URL containing state, S256 challenge and RFC 8707 resource.
    #[must_use]
    pub const fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Exact issuer to bind into the one-time callback attempt.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Exact requested scope used when the token response omits `scope`.
    #[must_use]
    pub fn requested_scope(&self) -> &str {
        &self.requested_scope
    }

    /// Whether callback `iss` is mandatory rather than merely checked when present.
    #[must_use]
    pub const fn requires_callback_issuer(&self) -> bool {
        self.authorization_response_iss_parameter_supported
    }
}

/// Authorization-code token response. Access is short-lived; refresh is persisted by the caller.
pub struct McpOAuthCodeGrant {
    access_token: SecretBytes,
    refresh_token: SecretBytes,
    scope: String,
}

impl McpOAuthCodeGrant {
    /// Consume the response into zeroizing secrets plus exact granted scope.
    #[must_use]
    pub fn into_parts(self) -> (SecretBytes, SecretBytes, String) {
        (self.access_token, self.refresh_token, self.scope)
    }
}

impl core::fmt::Debug for McpOAuthCodeGrant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("McpOAuthCodeGrant")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope_bytes", &self.scope.len())
            .finish()
    }
}

/// SafeDialer-backed production MCP OAuth adapter. It never caches access or refresh tokens.
#[derive(Clone, Debug)]
pub struct McpOAuthClient {
    dialer: SafeDialer,
    scheme_policy: SchemePolicy,
}

impl McpOAuthClient {
    /// Construct from an explicit network and scheme policy. Production must pass `HttpsOnly`;
    /// `HttpOrHttps` exists for CIDR-allowlisted local conformance servers.
    #[must_use]
    pub const fn new(dialer: SafeDialer, scheme_policy: SchemePolicy) -> Self {
        Self {
            dialer,
            scheme_policy,
        }
    }

    /// Scope one OAuth operation to the exact private destinations authorized on its MCP server.
    /// Resolver and TLS roots are retained and every redirect is still re-resolved.
    #[must_use]
    pub(crate) fn with_egress_allowlist(&self, allowlist: CidrAllowlist) -> Self {
        Self {
            dialer: self.dialer.with_egress_policy(EgressPolicy::new(allowlist)),
            scheme_policy: self.scheme_policy,
        }
    }

    /// Validate a retained client registration without performing discovery or any network I/O.
    /// Admin server removal uses this before deciding that automatic RFC 7009 compensation is
    /// possible; malformed retained material must become operator work instead of an endless
    /// retry loop.
    pub(crate) fn validate_stored_client(&self, oauth_client: &[u8]) -> Result<(), McpOAuthError> {
        ParsedOAuthClient::parse(oauth_client, self.scheme_policy).map(|_| ())
    }

    /// Discover and validate PRM + AS metadata for a stored client registration.
    pub async fn discover(
        &self,
        resource: &str,
        oauth_client: &[u8],
    ) -> Result<McpOAuthDiscovery, McpOAuthError> {
        let client = ParsedOAuthClient::parse(oauth_client, self.scheme_policy)?;
        self.discover_with_client(resource, &client).await
    }

    /// Build one authorization-code URL after PRM/AS discovery and PKCE capability validation.
    pub async fn authorization_plan(
        &self,
        resource: &str,
        oauth_client: &[u8],
        redirect_uri: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<McpOAuthAuthorizationPlan, McpOAuthError> {
        if !valid_oauth_ascii(state, 512)
            || !valid_oauth_ascii(code_challenge, 128)
            || !code_challenge
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(McpOAuthError::InvalidClient);
        }
        let redirect = validated_redirect_uri(redirect_uri, self.scheme_policy)?;
        let client = ParsedOAuthClient::parse(oauth_client, self.scheme_policy)?;
        let discovery = self.discover_with_client(resource, &client).await?;
        let mut scopes = discovery.scopes.clone();
        if discovery.offline_access_supported
            && !scopes.iter().any(|scope| scope == "offline_access")
        {
            scopes.push("offline_access".to_owned());
        }
        let requested_scope = scopes.join(" ");
        let mut authorization_url = discovery.authorization_endpoint.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", redirect.as_str())
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", resource);
        if !requested_scope.is_empty() {
            authorization_url
                .query_pairs_mut()
                .append_pair("scope", &requested_scope);
        }
        Ok(McpOAuthAuthorizationPlan {
            authorization_url,
            issuer: discovery.issuer,
            requested_scope,
            authorization_response_iss_parameter_supported: discovery
                .authorization_response_iss_parameter_supported,
        })
    }

    /// Redeem one authorization code. Refresh token is mandatory; no access-only connection exists.
    pub async fn exchange_authorization_code(
        &self,
        resource: &str,
        oauth_client: &[u8],
        code: &[u8],
        redirect_uri: &str,
        code_verifier: &[u8],
        requested_scope: &str,
    ) -> Result<McpOAuthCodeGrant, McpOAuthError> {
        if code.is_empty()
            || code.len() > 16 * 1024
            || code.contains(&0)
            || !valid_pkce_verifier(code_verifier)
            || requested_scope.len() > 16 * 1024
            || requested_scope.as_bytes().contains(&0)
        {
            return Err(McpOAuthError::InvalidTokenResponse);
        }
        let code = core::str::from_utf8(code).map_err(|_| McpOAuthError::InvalidTokenResponse)?;
        let verifier =
            core::str::from_utf8(code_verifier).map_err(|_| McpOAuthError::InvalidTokenResponse)?;
        let redirect = validated_redirect_uri(redirect_uri, self.scheme_policy)?;
        let client = ParsedOAuthClient::parse(oauth_client, self.scheme_policy)?;
        let discovery = self.discover_with_client(resource, &client).await?;
        let (body, authorization) = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("grant_type", "authorization_code");
            serializer.append_pair("code", code);
            serializer.append_pair("redirect_uri", redirect.as_str());
            serializer.append_pair("code_verifier", verifier);
            serializer.append_pair("resource", resource);
            let authorization = apply_client_auth(&mut serializer, &client)?;
            let form = Zeroizing::new(serializer.finish());
            (form.as_bytes().to_vec(), authorization)
        };
        let (access_token, refresh_token, scope) = execute_token_request(
            &self.dialer,
            self.scheme_policy,
            discovery.token_endpoint,
            body,
            authorization,
        )
        .await?;
        Ok(McpOAuthCodeGrant {
            access_token,
            refresh_token,
            scope: scope.unwrap_or_else(|| requested_scope.to_owned()),
        })
    }

    /// RFC 7009 revoke for an already locally tombstoned refresh token.
    pub async fn revoke_refresh_token(
        &self,
        resource: &str,
        oauth_client: &[u8],
        refresh_token: &[u8],
    ) -> Result<(), McpOAuthError> {
        if refresh_token.is_empty()
            || refresh_token.len() > MAX_TOKEN_BYTES
            || refresh_token.contains(&0)
        {
            return Err(McpOAuthError::InvalidClient);
        }
        let token =
            core::str::from_utf8(refresh_token).map_err(|_| McpOAuthError::InvalidClient)?;
        let client = ParsedOAuthClient::parse(oauth_client, self.scheme_policy)?;
        let discovery = self.discover_with_client(resource, &client).await?;
        let endpoint = discovery
            .revocation_endpoint
            .ok_or(McpOAuthError::InvalidMetadata)?;
        let (body, authorization) = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("token", token);
            serializer.append_pair("token_type_hint", "refresh_token");
            let authorization = apply_client_auth(&mut serializer, &client)?;
            let form = Zeroizing::new(serializer.finish());
            (form.as_bytes().to_vec(), authorization)
        };
        let budget = SafeHttpBudget::new(MAX_TOKEN_RESPONSE_BYTES, MCP_OAUTH_TOKEN_TIMEOUT)
            .map_err(|_| McpOAuthError::InvalidClient)?;
        let plan = SafeHttpRequest::post_form_with_scheme(
            endpoint,
            self.scheme_policy,
            body,
            authorization,
            budget,
        )
        .map_err(|_| McpOAuthError::InvalidClient)?;
        let response = self
            .dialer
            .execute(plan)
            .await
            .map_err(|_| McpOAuthError::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else if response.status().is_server_error()
            || response.status() == StatusCode::TOO_MANY_REQUESTS
        {
            Err(McpOAuthError::Unavailable)
        } else {
            Err(McpOAuthError::AuthRequired)
        }
    }

    async fn discover_with_client(
        &self,
        resource: &str,
        client: &ParsedOAuthClient,
    ) -> Result<McpOAuthDiscovery, McpOAuthError> {
        let resource_url = validated_url(resource, self.scheme_policy)?;
        let mut resource_candidates = Vec::new();
        if let Ok(Some(challenged)) = self.probe_resource_metadata(&resource_url).await {
            resource_candidates.push(challenged);
        }
        if let Some(explicit) = &client.resource_metadata_url
            && !resource_candidates.contains(explicit)
        {
            resource_candidates.push(explicit.clone());
        }
        for candidate in protected_resource_candidates(&resource_url)? {
            if !resource_candidates.contains(&candidate) {
                resource_candidates.push(candidate);
            }
        }
        let protected: ProtectedResourceMetadata = self
            .fetch_first_metadata(&resource_candidates, MetadataKind::ProtectedResource)
            .await?;
        validate_protected_resource(&protected, resource, &client.issuer)?;

        let issuer_url = validated_url(&client.issuer, self.scheme_policy)?;
        let authorization_candidates = authorization_server_candidates(&issuer_url)?;
        let metadata: AuthorizationServerMetadata = self
            .fetch_first_metadata(&authorization_candidates, MetadataKind::AuthorizationServer)
            .await?;
        validate_authorization_server(&metadata, client, self.scheme_policy)?;

        let authorization_endpoint =
            validated_url(&metadata.authorization_endpoint, self.scheme_policy)?;
        let token_endpoint = validated_url(&metadata.token_endpoint, self.scheme_policy)?;
        let revocation_endpoint = metadata
            .revocation_endpoint
            .as_deref()
            .map(|value| validated_url(value, self.scheme_policy))
            .transpose()?;
        Ok(McpOAuthDiscovery {
            resource: resource.to_owned(),
            issuer: client.issuer.clone(),
            authorization_endpoint,
            token_endpoint,
            revocation_endpoint,
            scopes: protected.scopes_supported.unwrap_or_default(),
            offline_access_supported: metadata
                .scopes_supported
                .as_ref()
                .is_some_and(|scopes| scopes.iter().any(|scope| scope == "offline_access")),
            authorization_response_iss_parameter_supported: metadata
                .authorization_response_iss_parameter_supported
                .unwrap_or(false),
        })
    }

    async fn probe_resource_metadata(&self, resource: &Url) -> Result<Option<Url>, McpOAuthError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc":"2.0",
            "id":"openbot-oauth-discovery",
            "method":"initialize",
            "params":{
                "protocolVersion":"2026-07-28",
                "capabilities":{},
                "clientInfo":{"name":"openbot","version":env!("CARGO_PKG_VERSION")}
            }
        }))
        .map_err(|_| McpOAuthError::InvalidMetadata)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("mcp-protocol-version"),
            HeaderValue::from_static("2026-07-28"),
        );
        let budget = SafeHttpBudget::new(MAX_METADATA_BYTES, MCP_OAUTH_METADATA_TIMEOUT)
            .map_err(|_| McpOAuthError::InvalidMetadata)?;
        let request = SafeHttpRequest::mcp(
            resource.clone(),
            self.scheme_policy,
            McpHttpMethod::Post,
            body,
            None,
            headers,
            budget,
        )
        .map_err(|_| McpOAuthError::InvalidMetadata)?;
        let response = self
            .dialer
            .execute(request)
            .await
            .map_err(|_| McpOAuthError::Unavailable)?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(None);
        }
        let Some(challenge) = response
            .header(&WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
        else {
            return Ok(None);
        };
        let Some(metadata) = bearer_parameter(challenge, "resource_metadata") else {
            return Ok(None);
        };
        validated_url(&metadata, self.scheme_policy).map(Some)
    }

    async fn fetch_first_metadata<T: for<'de> Deserialize<'de>>(
        &self,
        candidates: &[Url],
        kind: MetadataKind,
    ) -> Result<T, McpOAuthError> {
        if candidates.is_empty() || candidates.len() > 4 {
            return Err(McpOAuthError::InvalidMetadata);
        }
        for candidate in candidates {
            let budget = SafeHttpBudget::new(MAX_METADATA_BYTES, MCP_OAUTH_METADATA_TIMEOUT)
                .map_err(|_| McpOAuthError::InvalidMetadata)?;
            let request = SafeHttpRequest::get(candidate.clone(), self.scheme_policy, budget)
                .map_err(|_| McpOAuthError::InvalidMetadata)?;
            let response = self
                .dialer
                .execute(request)
                .await
                .map_err(|_| McpOAuthError::Unavailable)?;
            if matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::GONE) {
                continue;
            }
            if !response.status().is_success() {
                return Err(McpOAuthError::InvalidMetadata);
            }
            let parsed = serde_json::from_slice(response.body())
                .map_err(|_| McpOAuthError::InvalidMetadata)?;
            // A syntactically valid document with the wrong issuer/resource is terminal; callers
            // must never fall through from attacker-controlled metadata to another authority.
            let _ = kind;
            return Ok(parsed);
        }
        Err(McpOAuthError::InvalidMetadata)
    }

    async fn refresh(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, McpOAuthError> {
        let client = ParsedOAuthClient::parse(request.expose_oauth_client(), self.scheme_policy)?;
        let discovery = self
            .discover_with_client(request.endpoint(), &client)
            .await?;
        if discovery.resource != request.endpoint() {
            return Err(McpOAuthError::InvalidMetadata);
        }
        let (body, authorization) = refresh_form(&client, &discovery, request)?;
        let budget = SafeHttpBudget::new(MAX_TOKEN_RESPONSE_BYTES, MCP_OAUTH_TOKEN_TIMEOUT)
            .map_err(|_| McpOAuthError::InvalidClient)?;
        let plan = SafeHttpRequest::oauth_refresh_form(
            discovery.token_endpoint,
            self.scheme_policy,
            body,
            authorization,
            budget,
        )
        .map_err(|_| McpOAuthError::InvalidClient)?;
        request
            .admit_token_send()
            .await
            .map_err(|_| McpOAuthError::Unavailable)?;
        let response = self
            .dialer
            .execute(plan)
            .await
            .map_err(|_| McpOAuthError::Unavailable)?;
        let (status, _, raw_body) = response.into_parts();
        let body = Zeroizing::new(raw_body);
        // A redirect cannot prove whether the admitted refresh was consumed. Keep the durable
        // operation unresolved; never interpret its body as a grant or terminal OAuth error.
        if status.is_redirection() {
            return Err(McpOAuthError::Unavailable);
        }
        if !status.is_success() {
            return Err(classify_token_error(status, &body));
        }
        let mut wire: TokenResponse<'_> =
            serde_json::from_slice(&body).map_err(|_| McpOAuthError::InvalidTokenResponse)?;
        if !wire.token_type.eq_ignore_ascii_case("bearer")
            || wire.access_token.is_empty()
            || wire.access_token.len() > MAX_TOKEN_BYTES
            || wire.access_token.as_bytes().contains(&0)
        {
            zeroize_token_response(&mut wire);
            return Err(McpOAuthError::InvalidTokenResponse);
        }
        let Some(refresh_token) = wire.refresh_token.as_ref() else {
            zeroize_token_response(&mut wire);
            return Err(McpOAuthError::InvalidTokenResponse);
        };
        if refresh_token.is_empty()
            || refresh_token.len() > MAX_TOKEN_BYTES
            || refresh_token.as_bytes().contains(&0)
        {
            zeroize_token_response(&mut wire);
            return Err(McpOAuthError::InvalidTokenResponse);
        }
        if wire
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > 16 * 1024 || scope.as_bytes().contains(&0))
        {
            zeroize_token_response(&mut wire);
            return Err(McpOAuthError::InvalidTokenResponse);
        }
        let access = SecretBytes::new(wire.access_token.as_bytes().to_vec());
        let refresh = SecretBytes::new(refresh_token.as_bytes().to_vec());
        let scope = wire.scope.as_ref().map(|value| value.to_string());
        zeroize_token_response(&mut wire);
        Ok(RotatingOAuthGrant::new(access, Some(refresh), scope))
    }
}

#[async_trait]
impl RotatingOAuthTokenExchanger for McpOAuthClient {
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        if request.transport() != "mcp" {
            return Err(OAuthTokenExchangeError::InvalidResponse);
        }
        self.with_egress_allowlist(request.egress_allowlist().clone())
            .refresh(request)
            .await
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy)]
enum MetadataKind {
    ProtectedResource,
    AuthorizationServer,
}

#[derive(Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OAuthClientWire<'a> {
    #[serde(borrow)]
    client_id: Cow<'a, str>,
    #[serde(default, borrow)]
    client_secret: Option<Cow<'a, str>>,
    #[serde(borrow)]
    issuer: Cow<'a, str>,
    #[serde(default, borrow)]
    token_endpoint_auth_method: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    resource_metadata_url: Option<Cow<'a, str>>,
}

struct ParsedOAuthClient {
    client_id: String,
    client_secret: Option<SecretBytes>,
    issuer: String,
    auth_method: ClientAuthMethod,
    resource_metadata_url: Option<Url>,
}

impl ParsedOAuthClient {
    fn parse(raw: &[u8], scheme_policy: SchemePolicy) -> Result<Self, McpOAuthError> {
        if raw.is_empty() || raw.len() > 64 * 1024 {
            return Err(McpOAuthError::InvalidClient);
        }
        let mut wire: OAuthClientWire<'_> =
            serde_json::from_slice(raw).map_err(|_| McpOAuthError::InvalidClient)?;
        if !valid_client_component(&wire.client_id, 4 * 1024)
            || !valid_client_component(&wire.issuer, 8 * 1024)
        {
            zeroize_client_secret(&mut wire);
            return Err(McpOAuthError::InvalidClient);
        }
        let issuer = wire.issuer.to_string();
        if let Err(error) = validated_url(&issuer, scheme_policy) {
            zeroize_client_secret(&mut wire);
            return Err(error);
        }
        let client_secret = wire.client_secret.as_ref().map(|secret| {
            if !valid_client_component(secret, 16 * 1024) {
                return Err(McpOAuthError::InvalidClient);
            }
            Ok(SecretBytes::new(secret.as_bytes().to_vec()))
        });
        let client_secret = match client_secret.transpose() {
            Ok(secret) => secret,
            Err(error) => {
                zeroize_client_secret(&mut wire);
                return Err(error);
            }
        };
        let auth_method = match wire.token_endpoint_auth_method.as_deref() {
            None if client_secret.is_some() => ClientAuthMethod::ClientSecretBasic,
            None => ClientAuthMethod::None,
            Some("client_secret_basic") => ClientAuthMethod::ClientSecretBasic,
            Some("client_secret_post") => ClientAuthMethod::ClientSecretPost,
            Some("none") => ClientAuthMethod::None,
            Some(_) => {
                zeroize_client_secret(&mut wire);
                return Err(McpOAuthError::InvalidClient);
            }
        };
        if matches!(auth_method, ClientAuthMethod::None) != client_secret.is_none() {
            zeroize_client_secret(&mut wire);
            return Err(McpOAuthError::InvalidClient);
        }
        let resource_metadata_url = wire
            .resource_metadata_url
            .as_deref()
            .map(|value| validated_url(value, scheme_policy))
            .transpose();
        let resource_metadata_url = match resource_metadata_url {
            Ok(value) => value,
            Err(error) => {
                zeroize_client_secret(&mut wire);
                return Err(error);
            }
        };
        let client_id = wire.client_id.to_string();
        zeroize_client_secret(&mut wire);
        Ok(Self {
            client_id,
            client_secret,
            issuer,
            auth_method,
            resource_metadata_url,
        })
    }
}

impl core::fmt::Debug for ParsedOAuthClient {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ParsedOAuthClient")
            .field("client_id_bytes", &self.client_id.len())
            .field("client_secret", &self.client_secret.is_some())
            .field("issuer", &"<redacted-origin>")
            .field("auth_method", &self.auth_method)
            .field(
                "resource_metadata_url",
                &self.resource_metadata_url.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

impl ClientAuthMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::None => "none",
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse<'a> {
    #[serde(borrow)]
    access_token: Cow<'a, str>,
    #[serde(borrow)]
    token_type: Cow<'a, str>,
    #[serde(default, borrow)]
    refresh_token: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    scope: Option<Cow<'a, str>>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse<'a> {
    #[serde(borrow)]
    error: Cow<'a, str>,
}

fn validated_url(value: &str, scheme_policy: SchemePolicy) -> Result<Url, McpOAuthError> {
    if value.is_empty() || value.len() > 8 * 1024 || value.trim() != value {
        return Err(McpOAuthError::InvalidMetadata);
    }
    let url = Url::parse(value).map_err(|_| McpOAuthError::InvalidMetadata)?;
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(McpOAuthError::InvalidMetadata);
    }
    let budget = SafeHttpBudget::new(1, Duration::from_secs(1))
        .map_err(|_| McpOAuthError::InvalidMetadata)?;
    SafeHttpRequest::get(url.clone(), scheme_policy, budget)
        .map_err(|_| McpOAuthError::InvalidMetadata)?;
    Ok(url)
}

fn protected_resource_candidates(resource: &Url) -> Result<Vec<Url>, McpOAuthError> {
    let mut root = origin_root(resource)?;
    let path = resource.path().trim_start_matches('/');
    let mut result = Vec::new();
    if !path.is_empty() {
        root.set_path(&format!("/.well-known/oauth-protected-resource/{path}"));
        result.push(root.clone());
    }
    root.set_path("/.well-known/oauth-protected-resource");
    if !result.contains(&root) {
        result.push(root);
    }
    Ok(result)
}

fn authorization_server_candidates(issuer: &Url) -> Result<Vec<Url>, McpOAuthError> {
    let mut root = origin_root(issuer)?;
    let path = issuer.path().trim_matches('/');
    let mut result = Vec::new();
    if path.is_empty() {
        root.set_path("/.well-known/oauth-authorization-server");
        result.push(root.clone());
        root.set_path("/.well-known/openid-configuration");
        result.push(root);
    } else {
        root.set_path(&format!("/.well-known/oauth-authorization-server/{path}"));
        result.push(root.clone());
        root.set_path(&format!("/.well-known/openid-configuration/{path}"));
        result.push(root);
        let mut appended = issuer.clone();
        appended.set_query(None);
        appended.set_fragment(None);
        let base = appended.path().trim_end_matches('/');
        appended.set_path(&format!("{base}/.well-known/openid-configuration"));
        result.push(appended);
    }
    Ok(result)
}

fn origin_root(url: &Url) -> Result<Url, McpOAuthError> {
    let host = url.host_str().ok_or(McpOAuthError::InvalidMetadata)?;
    let mut origin = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Url::parse(&origin).map_err(|_| McpOAuthError::InvalidMetadata)
}

fn validate_protected_resource(
    metadata: &ProtectedResourceMetadata,
    expected_resource: &str,
    expected_issuer: &str,
) -> Result<(), McpOAuthError> {
    if metadata.resource != expected_resource
        || metadata.authorization_servers.is_empty()
        || metadata.authorization_servers.len() > MAX_OAUTH_SERVERS
        || !metadata
            .authorization_servers
            .iter()
            .any(|issuer| issuer == expected_issuer)
        || metadata.authorization_servers.iter().any(|issuer| {
            issuer.is_empty() || issuer.len() > 8 * 1024 || issuer.as_bytes().contains(&0)
        })
        || metadata.scopes_supported.as_ref().is_some_and(|scopes| {
            scopes.len() > MAX_SCOPES
                || scopes.iter().any(|scope| {
                    scope.is_empty() || scope.len() > 4 * 1024 || scope.as_bytes().contains(&0)
                })
        })
    {
        return Err(McpOAuthError::InvalidMetadata);
    }
    Ok(())
}

fn validate_authorization_server(
    metadata: &AuthorizationServerMetadata,
    client: &ParsedOAuthClient,
    scheme_policy: SchemePolicy,
) -> Result<(), McpOAuthError> {
    if metadata.issuer != client.issuer
        || !metadata
            .code_challenge_methods_supported
            .as_ref()
            .is_some_and(|methods| methods.len() <= 32 && methods.iter().any(|item| item == "S256"))
        || metadata.scopes_supported.as_ref().is_some_and(|scopes| {
            scopes.len() > MAX_SCOPES
                || scopes.iter().any(|scope| {
                    scope.is_empty() || scope.len() > 4 * 1024 || scope.as_bytes().contains(&0)
                })
        })
    {
        return Err(McpOAuthError::InvalidMetadata);
    }
    validated_url(&metadata.authorization_endpoint, scheme_policy)?;
    validated_url(&metadata.token_endpoint, scheme_policy)?;
    if let Some(endpoint) = &metadata.revocation_endpoint {
        validated_url(endpoint, scheme_policy)?;
    }
    match &metadata.token_endpoint_auth_methods_supported {
        Some(methods)
            if methods.len() <= 32
                && methods
                    .iter()
                    .any(|method| method == client.auth_method.as_str()) =>
        {
            Ok(())
        }
        // RFC 8414 default when omitted is client_secret_basic.
        None if client.auth_method == ClientAuthMethod::ClientSecretBasic => Ok(()),
        Some(_) | None => Err(McpOAuthError::InvalidMetadata),
    }
}

fn refresh_form(
    client: &ParsedOAuthClient,
    discovery: &McpOAuthDiscovery,
    request: OAuthRefreshExchange<'_>,
) -> Result<(Vec<u8>, Option<AuthorizationValue>), McpOAuthError> {
    if request.granted_scope().len() > 16 * 1024
        || request.granted_scope().as_bytes().contains(&0)
        || request.expose_refresh_token().is_empty()
        || request.expose_refresh_token().len() > MAX_TOKEN_BYTES
    {
        return Err(McpOAuthError::InvalidClient);
    }
    let refresh = core::str::from_utf8(request.expose_refresh_token())
        .map_err(|_| McpOAuthError::InvalidClient)?;
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", "refresh_token");
    serializer.append_pair("refresh_token", refresh);
    serializer.append_pair("resource", discovery.resource());
    if !request.granted_scope().is_empty() {
        serializer.append_pair("scope", request.granted_scope());
    }
    let authorization = apply_client_auth(&mut serializer, client)?;
    let form = Zeroizing::new(serializer.finish());
    Ok((form.as_bytes().to_vec(), authorization))
}

fn apply_client_auth(
    serializer: &mut url::form_urlencoded::Serializer<'_, String>,
    client: &ParsedOAuthClient,
) -> Result<Option<AuthorizationValue>, McpOAuthError> {
    match client.auth_method {
        ClientAuthMethod::ClientSecretBasic => Ok(Some(client_basic_authorization(client)?)),
        ClientAuthMethod::ClientSecretPost => {
            serializer.append_pair("client_id", &client.client_id);
            let secret = client
                .client_secret
                .as_ref()
                .ok_or(McpOAuthError::InvalidClient)?;
            let secret =
                core::str::from_utf8(secret.expose()).map_err(|_| McpOAuthError::InvalidClient)?;
            serializer.append_pair("client_secret", secret);
            Ok(None)
        }
        ClientAuthMethod::None => {
            serializer.append_pair("client_id", &client.client_id);
            Ok(None)
        }
    }
}

fn client_basic_authorization(
    client: &ParsedOAuthClient,
) -> Result<AuthorizationValue, McpOAuthError> {
    let secret = client
        .client_secret
        .as_ref()
        .ok_or(McpOAuthError::InvalidClient)?;
    let encoded_id = Zeroizing::new(
        url::form_urlencoded::byte_serialize(client.client_id.as_bytes()).collect::<String>(),
    );
    let encoded_secret =
        Zeroizing::new(url::form_urlencoded::byte_serialize(secret.expose()).collect::<String>());
    let mut credentials = Zeroizing::new(String::with_capacity(
        encoded_id.len() + encoded_secret.len() + 1,
    ));
    credentials.push_str(&encoded_id);
    credentials.push(':');
    credentials.push_str(&encoded_secret);
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(credentials.as_bytes()));
    let mut header = Zeroizing::new(String::with_capacity(encoded.len() + 6));
    header.push_str("Basic ");
    header.push_str(&encoded);
    AuthorizationValue::parse(&header).map_err(|_| McpOAuthError::InvalidClient)
}

fn classify_token_error(status: StatusCode, body: &[u8]) -> McpOAuthError {
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        return McpOAuthError::Unavailable;
    }
    let parsed = serde_json::from_slice::<OAuthErrorResponse<'_>>(body).ok();
    match parsed.as_ref().map(|value| value.error.as_ref()) {
        Some("invalid_grant" | "invalid_client" | "unauthorized_client") => {
            McpOAuthError::AuthRequired
        }
        Some("insufficient_scope") => McpOAuthError::InsufficientScope,
        _ => McpOAuthError::InvalidTokenResponse,
    }
}

fn bearer_parameter(header: &str, name: &str) -> Option<String> {
    if header.len() > 16 * 1024 || name.is_empty() || !header.is_ascii() {
        return None;
    }
    let lower = header.to_ascii_lowercase();
    let bearer = lower.match_indices("bearer").find_map(|(start, _)| {
        let before = start == 0
            || lower.as_bytes()[start - 1].is_ascii_whitespace()
            || lower.as_bytes()[start - 1] == b',';
        let after = start + "bearer".len();
        let after = after < lower.len() && lower.as_bytes()[after].is_ascii_whitespace();
        (before && after).then_some(start)
    })?;
    let pattern = format!("{}=", name.to_ascii_lowercase());
    let mut search = bearer + "bearer".len();
    while let Some(relative) = lower[search..].find(&pattern) {
        let start = search + relative;
        let boundary = start == 0
            || lower.as_bytes()[start - 1].is_ascii_whitespace()
            || lower.as_bytes()[start - 1] == b',';
        if !boundary {
            search = start + pattern.len();
            continue;
        }
        let value = &header[start + pattern.len()..];
        if let Some(quoted) = value.strip_prefix('"') {
            let end = quoted.find('"')?;
            let result = &quoted[..end];
            return (!result.is_empty()
                && !result.as_bytes().contains(&b'\\')
                && !result.bytes().any(|byte| byte.is_ascii_control()))
            .then(|| result.to_owned());
        }
        let end = value
            .find(|character: char| character == ',' || character.is_ascii_whitespace())
            .unwrap_or(value.len());
        let result = &value[..end];
        return (!result.is_empty() && !result.bytes().any(|byte| byte.is_ascii_control()))
            .then(|| result.to_owned());
    }
    None
}

async fn execute_token_request(
    dialer: &SafeDialer,
    scheme_policy: SchemePolicy,
    endpoint: Url,
    body: Vec<u8>,
    authorization: Option<AuthorizationValue>,
) -> Result<(SecretBytes, SecretBytes, Option<String>), McpOAuthError> {
    let budget = SafeHttpBudget::new(MAX_TOKEN_RESPONSE_BYTES, MCP_OAUTH_TOKEN_TIMEOUT)
        .map_err(|_| McpOAuthError::InvalidClient)?;
    let plan = SafeHttpRequest::post_form_with_scheme(
        endpoint,
        scheme_policy,
        body,
        authorization,
        budget,
    )
    .map_err(|_| McpOAuthError::InvalidClient)?;
    let response = dialer
        .execute(plan)
        .await
        .map_err(|_| McpOAuthError::Unavailable)?;
    let (status, _, raw_body) = response.into_parts();
    let body = Zeroizing::new(raw_body);
    if !status.is_success() {
        return Err(classify_token_error(status, &body));
    }
    let mut wire: TokenResponse<'_> =
        serde_json::from_slice(&body).map_err(|_| McpOAuthError::InvalidTokenResponse)?;
    if !wire.token_type.eq_ignore_ascii_case("bearer")
        || wire.access_token.is_empty()
        || wire.access_token.len() > MAX_TOKEN_BYTES
        || wire.access_token.as_bytes().contains(&0)
    {
        zeroize_token_response(&mut wire);
        return Err(McpOAuthError::InvalidTokenResponse);
    }
    let Some(refresh_token) = wire.refresh_token.as_ref() else {
        zeroize_token_response(&mut wire);
        return Err(McpOAuthError::InvalidTokenResponse);
    };
    if refresh_token.is_empty()
        || refresh_token.len() > MAX_TOKEN_BYTES
        || refresh_token.as_bytes().contains(&0)
        || refresh_token.as_bytes() == wire.access_token.as_bytes()
        || wire
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > 16 * 1024 || scope.as_bytes().contains(&0))
    {
        zeroize_token_response(&mut wire);
        return Err(McpOAuthError::InvalidTokenResponse);
    }
    let access = SecretBytes::new(wire.access_token.as_bytes().to_vec());
    let refresh = SecretBytes::new(refresh_token.as_bytes().to_vec());
    let scope = wire.scope.as_ref().map(|value| value.to_string());
    zeroize_token_response(&mut wire);
    Ok((access, refresh, scope))
}

fn validated_redirect_uri(value: &str, scheme_policy: SchemePolicy) -> Result<Url, McpOAuthError> {
    let url = validated_url(value, scheme_policy)?;
    if url.scheme() == "http" {
        let loopback = match url.host() {
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        if !loopback {
            return Err(McpOAuthError::InvalidClient);
        }
    }
    Ok(url)
}

fn valid_oauth_ascii(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
}

fn valid_pkce_verifier(value: &[u8]) -> bool {
    (43..=128).contains(&value.len())
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

fn valid_client_component(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.as_bytes().contains(&0)
}

fn zeroize_client_secret(wire: &mut OAuthClientWire<'_>) {
    if let Some(Cow::Owned(secret)) = wire.client_secret.as_mut() {
        secret.zeroize();
    }
}

fn zeroize_token_response(response: &mut TokenResponse<'_>) {
    if let Cow::Owned(access) = &mut response.access_token {
        access.zeroize();
    }
    if let Some(Cow::Owned(refresh)) = &mut response.refresh_token {
        refresh.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_candidates_follow_rfc_path_priority() {
        let resource = Url::parse("https://mcp.example/public/mcp").unwrap();
        assert_eq!(
            protected_resource_candidates(&resource)
                .unwrap()
                .into_iter()
                .map(|url| url.to_string())
                .collect::<Vec<_>>(),
            vec![
                "https://mcp.example/.well-known/oauth-protected-resource/public/mcp",
                "https://mcp.example/.well-known/oauth-protected-resource",
            ]
        );
        let issuer = Url::parse("https://auth.example/tenant1").unwrap();
        assert_eq!(
            authorization_server_candidates(&issuer)
                .unwrap()
                .into_iter()
                .map(|url| url.to_string())
                .collect::<Vec<_>>(),
            vec![
                "https://auth.example/.well-known/oauth-authorization-server/tenant1",
                "https://auth.example/.well-known/openid-configuration/tenant1",
                "https://auth.example/tenant1/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn registration_requires_exact_issuer_and_matching_client_auth() {
        let valid = br#"{"clientId":"client","clientSecret":"CLIENT-SECRET-CANARY","issuer":"https://auth.example","tokenEndpointAuthMethod":"client_secret_basic"}"#;
        let client = ParsedOAuthClient::parse(valid, SchemePolicy::HttpsOnly).unwrap();
        assert_eq!(client.issuer, "https://auth.example");
        assert!(!format!("{client:?}").contains("CLIENT-SECRET-CANARY"));

        let invalid = br#"{"clientId":"client","issuer":"http://auth.example","tokenEndpointAuthMethod":"client_secret_basic"}"#;
        assert_eq!(
            ParsedOAuthClient::parse(invalid, SchemePolicy::HttpsOnly).unwrap_err(),
            McpOAuthError::InvalidMetadata
        );
    }

    #[test]
    fn bearer_challenge_extracts_only_the_resource_metadata_parameter() {
        assert_eq!(
            bearer_parameter(
                r#"Bearer realm="mcp", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource", scope="notes:read""#,
                "resource_metadata"
            )
            .as_deref(),
            Some("https://mcp.example/.well-known/oauth-protected-resource")
        );
        assert_eq!(
            bearer_parameter(
                r#"Bearer error_description="resource_metadata=https://attacker.example""#,
                "resource_metadata"
            ),
            None
        );
        assert_eq!(bearer_parameter("Basic abc", "resource_metadata"), None);
    }
}
