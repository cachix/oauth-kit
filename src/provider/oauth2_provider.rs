//! Generic OAuth2 provider for providers that don't support OIDC.
//!
//! Use this for providers like GitHub, Discord, Spotify, etc. that use
//! standard OAuth2 but require fetching user profile from a separate endpoint.

use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::User;

use super::AuthorizationRequest;

/// Profile normalization function type.
pub type ProfileNormalizer = fn(serde_json::Value) -> Result<User>;

/// Async profile normalizer that can make additional API calls.
pub type AsyncProfileNormalizer = for<'a> fn(
    &'a reqwest::Client,
    &'a str,
    Option<serde_json::Value>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<User>> + Send + 'a>,
>;

/// How the provider normalizes the raw profile into a `User`.
enum Normalizer {
    /// Synchronous normalization from a JSON profile.
    Sync(ProfileNormalizer),
    /// Async normalization that can make additional API calls.
    Async(AsyncProfileNormalizer),
}

/// Build an HTTP client with redirect protection against SSRF.
pub(crate) fn build_http_client() -> Result<oauth2::reqwest::Client> {
    oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Config(e.to_string()))
}

/// Generate an OAuth2 authorization URL with PKCE.
fn oauth2_authorization_url(
    client_id: &str,
    client_secret: &str,
    authorization_url: &str,
    token_url: &str,
    redirect_url: &str,
    scopes: &[String],
) -> Result<AuthorizationRequest> {
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(authorization_url.to_string())?)
        .set_token_uri(TokenUrl::new(token_url.to_string())?)
        .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = client.authorize_url(CsrfToken::new_random);

    for scope in scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

    Ok(AuthorizationRequest {
        url: url.to_string(),
        csrf_state: csrf_state.secret().to_string(),
        pkce_verifier: Some(pkce_verifier.secret().to_string()),
        nonce: None,
    })
}

/// Exchange an authorization code for an access token and optionally fetch userinfo.
async fn oauth2_exchange_token(
    client_id: &str,
    client_secret: &str,
    authorization_url: &str,
    token_url: &str,
    redirect_url: &str,
    http_client: &oauth2::reqwest::Client,
    code: &str,
    pkce_verifier: Option<&str>,
    userinfo_url: Option<&str>,
) -> Result<(String, Option<serde_json::Value>)> {
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(AuthUrl::new(authorization_url.to_string())?)
        .set_token_uri(TokenUrl::new(token_url.to_string())?)
        .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

    let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

    if let Some(verifier) = pkce_verifier {
        token_request =
            token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
    }

    let token_response = token_request
        .request_async(http_client)
        .await
        .map_err(|e| Error::TokenExchange(e.to_string()))?;

    let access_token = token_response.access_token().secret().to_string();

    let userinfo = if let Some(url) = userinfo_url {
        Some(fetch_json::<serde_json::Value>(http_client, url, &access_token).await?)
    } else {
        None
    };

    Ok((access_token, userinfo))
}

/// Generic OAuth2 provider configuration.
///
/// Use this for providers that don't support OIDC and require fetching
/// user profile from a separate API endpoint.
///
/// Supports both synchronous profile normalization (via [`OAuth2Provider::new`])
/// and async normalization that can make additional API calls (via
/// [`OAuth2Provider::new_with_extra`]).
pub struct OAuth2Provider {
    id: String,
    name: String,
    authorization_url: String,
    token_url: String,
    userinfo_url: Option<String>,
    scopes: Vec<String>,
    client_id: String,
    client_secret: String,
    normalizer: Normalizer,
}

impl OAuth2Provider {
    /// Create a new OAuth2 provider with synchronous profile normalization.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
        userinfo_url: Option<impl Into<String>>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        normalize_profile: ProfileNormalizer,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            userinfo_url: userinfo_url.map(|u| u.into()),
            scopes: scopes.into_iter().map(|s| s.into()).collect(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            normalizer: Normalizer::Sync(normalize_profile),
        }
    }

    /// Create a new OAuth2 provider that needs extra API calls for profile normalization.
    ///
    /// Some providers (like GitHub) require additional API calls to get
    /// email or other profile information.
    pub fn new_with_extra(
        id: impl Into<String>,
        name: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
        userinfo_url: Option<impl Into<String>>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        normalize_profile: AsyncProfileNormalizer,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            userinfo_url: userinfo_url.map(|u| u.into()),
            scopes: scopes.into_iter().map(|s| s.into()).collect(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            normalizer: Normalizer::Async(normalize_profile),
        }
    }

    /// Set a custom provider ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set a custom display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set custom scopes.
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Add additional scopes to the default set.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }
}

#[async_trait]
impl super::OAuthProvider for OAuth2Provider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn authorization_url(&self, redirect_url: &str) -> Result<AuthorizationRequest> {
        oauth2_authorization_url(
            &self.client_id,
            &self.client_secret,
            &self.authorization_url,
            &self.token_url,
            redirect_url,
            &self.scopes,
        )
    }

    async fn exchange_code(
        &self,
        redirect_url: &str,
        code: &str,
        pkce_verifier: Option<&str>,
        _nonce: Option<&str>,
    ) -> Result<(User, String)> {
        let http_client = build_http_client()?;
        let (access_token, userinfo) = oauth2_exchange_token(
            &self.client_id,
            &self.client_secret,
            &self.authorization_url,
            &self.token_url,
            redirect_url,
            &http_client,
            code,
            pkce_verifier,
            self.userinfo_url.as_deref(),
        )
        .await?;

        let user = match &self.normalizer {
            Normalizer::Sync(normalize) => {
                let profile = userinfo
                    .ok_or_else(|| Error::ProfileFetch("No userinfo response".to_string()))?;
                normalize(profile)?
            }
            Normalizer::Async(normalize) => {
                normalize(&http_client, &access_token, userinfo).await?
            }
        };

        Ok((user, access_token))
    }
}

/// Helper to extract a string field from JSON.
pub fn json_string(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Helper to extract a string field, trying multiple field names.
pub fn json_string_any(value: &serde_json::Value, fields: &[&str]) -> Option<String> {
    for field in fields {
        if let Some(s) = json_string(value, field) {
            return Some(s);
        }
    }
    None
}

/// Helper to extract a boolean field from JSON.
pub fn json_bool(value: &serde_json::Value, field: &str) -> Option<bool> {
    value.get(field).and_then(|v| v.as_bool())
}

/// Helper to extract a numeric ID field as a string.
pub fn json_id(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field).and_then(|v| {
        v.as_str()
            .map(|s| s.to_string())
            .or_else(|| v.as_i64().map(|n| n.to_string()))
    })
}

/// Helper to build a full name from first and last name fields.
pub fn full_name(value: &serde_json::Value, first_field: &str, last_field: &str) -> Option<String> {
    let first = json_string(value, first_field).unwrap_or_default();
    let last = json_string(value, last_field).unwrap_or_default();
    let name = format!("{} {}", first, last);
    let name = name.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Helper to strip protocol prefix from a domain string and prepend https.
pub fn normalize_domain(domain: &str) -> String {
    let domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!("https://{}", domain)
}

/// Helper to fetch JSON from an API endpoint.
pub async fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    access_token: &str,
) -> Result<T> {
    client
        .get(url)
        .bearer_auth(access_token)
        .header("User-Agent", "oauth-kit")
        .send()
        .await
        .map_err(|e| Error::ProfileFetch(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::ProfileFetch(e.to_string()))
}
