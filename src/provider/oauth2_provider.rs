//! Generic OAuth2 provider for providers that don't support OIDC.
//!
//! Use this for providers like GitHub, Discord, Spotify, etc. that use
//! standard OAuth2 but require fetching user profile from a separate endpoint.

use async_trait::async_trait;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::User;

/// Profile normalization function type.
pub type ProfileNormalizer = fn(serde_json::Value) -> Result<User>;

/// Generic OAuth2 provider configuration.
///
/// Use this for providers that don't support OIDC and require fetching
/// user profile from a separate API endpoint.
pub struct OAuth2Provider {
    id: String,
    name: String,
    authorization_url: String,
    token_url: String,
    userinfo_url: Option<String>,
    scopes: Vec<String>,
    client_id: String,
    client_secret: String,
    normalize_profile: ProfileNormalizer,
}

impl OAuth2Provider {
    /// Create a new OAuth2 provider with the given configuration.
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
            normalize_profile,
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

    fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn userinfo_url(&self) -> Option<&str> {
        self.userinfo_url.as_deref()
    }

    fn scopes(&self) -> Vec<&str> {
        self.scopes.iter().map(|s| s.as_str()).collect()
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    async fn normalize_profile(
        &self,
        _http_client: &reqwest::Client,
        _access_token: &str,
        userinfo: Option<serde_json::Value>,
    ) -> Result<User> {
        let profile = userinfo.ok_or_else(|| {
            Error::ProfileFetch("No userinfo response".to_string())
        })?;
        (self.normalize_profile)(profile)
    }
}

/// OAuth2 provider that needs additional API calls for complete profile.
///
/// Some providers (like GitHub) require additional API calls to get
/// email or other profile information.
pub struct OAuth2ProviderWithExtra {
    id: String,
    name: String,
    authorization_url: String,
    token_url: String,
    userinfo_url: Option<String>,
    scopes: Vec<String>,
    client_id: String,
    client_secret: String,
    normalize_profile: for<'a> fn(
        &'a reqwest::Client,
        &'a str,
        Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<User>> + Send + 'a>>,
}

impl OAuth2ProviderWithExtra {
    /// Create a new OAuth2 provider that needs extra API calls.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
        userinfo_url: Option<impl Into<String>>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        normalize_profile: for<'a> fn(
            &'a reqwest::Client,
            &'a str,
            Option<serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<User>> + Send + 'a>>,
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
            normalize_profile,
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
impl super::OAuthProvider for OAuth2ProviderWithExtra {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    fn token_url(&self) -> &str {
        &self.token_url
    }

    fn userinfo_url(&self) -> Option<&str> {
        self.userinfo_url.as_deref()
    }

    fn scopes(&self) -> Vec<&str> {
        self.scopes.iter().map(|s| s.as_str()).collect()
    }

    fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> &str {
        &self.client_secret
    }

    async fn normalize_profile(
        &self,
        http_client: &reqwest::Client,
        access_token: &str,
        userinfo: Option<serde_json::Value>,
    ) -> Result<User> {
        (self.normalize_profile)(http_client, access_token, userinfo).await
    }
}

/// Helper to extract a string field from JSON.
pub fn json_string(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field).and_then(|v| v.as_str()).map(|s| s.to_string())
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
