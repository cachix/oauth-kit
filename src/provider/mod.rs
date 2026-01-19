use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::User;

pub mod oauth2_provider;

#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "oidc")]
pub mod providers;

pub use self::oauth2_provider::{OAuth2Provider, OAuth2ProviderWithExtra};

#[cfg(feature = "oidc")]
pub use self::oidc::{OidcAuthorizationRequest, OidcProvider};

/// Trait defining an OAuth provider's behavior.
#[async_trait]
pub trait OAuthProvider: Send + Sync + 'static {
    /// Unique identifier for this provider (e.g., "github", "google")
    fn id(&self) -> &str;

    /// Human-readable name (e.g., "GitHub", "Google")
    fn name(&self) -> &str;

    /// OAuth authorization endpoint URL
    fn authorization_url(&self) -> &str;

    /// OAuth token endpoint URL
    fn token_url(&self) -> &str;

    /// Userinfo endpoint URL (if provider has one)
    fn userinfo_url(&self) -> Option<&str>;

    /// Default scopes to request
    fn scopes(&self) -> Vec<&str>;

    /// Whether this provider requires PKCE
    fn requires_pkce(&self) -> bool {
        true
    }

    /// Client ID for this provider
    fn client_id(&self) -> &str;

    /// Client secret for this provider
    fn client_secret(&self) -> &str;

    /// Normalize the provider's profile response into a User.
    async fn normalize_profile(
        &self,
        http_client: &reqwest::Client,
        access_token: &str,
        userinfo: Option<serde_json::Value>,
    ) -> Result<User>;
}

/// Authorization URL with associated state for OAuth flow.
pub struct AuthorizationRequest {
    pub url: String,
    pub csrf_state: String,
    pub pkce_verifier: Option<String>,
}

/// Builds OAuth authorization URLs and handles token exchange.
pub struct OAuthClient {
    provider: Arc<dyn OAuthProvider>,
    redirect_url: String,
    http_client: ::oauth2::reqwest::Client,
}

impl OAuthClient {
    pub fn new(provider: Arc<dyn OAuthProvider>, redirect_url: &str) -> Result<Self> {
        let http_client = ::oauth2::reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities
            .redirect(::oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;

        Ok(Self {
            provider,
            redirect_url: redirect_url.to_string(),
            http_client,
        })
    }

    /// Generate an authorization URL for the OAuth flow.
    pub fn authorization_url(&self) -> Result<AuthorizationRequest> {
        let client = BasicClient::new(ClientId::new(self.provider.client_id().to_string()))
            .set_client_secret(ClientSecret::new(self.provider.client_secret().to_string()))
            .set_auth_uri(AuthUrl::new(self.provider.authorization_url().to_string())?)
            .set_token_uri(TokenUrl::new(self.provider.token_url().to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);

        let mut auth_request = client.authorize_url(CsrfToken::new_random);

        // Add scopes
        for scope in self.provider.scopes() {
            auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
        }

        // Add PKCE if required
        let pkce_verifier = if self.provider.requires_pkce() {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            auth_request = auth_request.set_pkce_challenge(challenge);
            Some(verifier.secret().to_string())
        } else {
            None
        };

        let (url, csrf_state) = auth_request.url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            csrf_state: csrf_state.secret().to_string(),
            pkce_verifier,
        })
    }

    /// Exchange an authorization code for user information.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<(User, String)> {
        let client = BasicClient::new(ClientId::new(self.provider.client_id().to_string()))
            .set_client_secret(ClientSecret::new(self.provider.client_secret().to_string()))
            .set_auth_uri(AuthUrl::new(self.provider.authorization_url().to_string())?)
            .set_token_uri(TokenUrl::new(self.provider.token_url().to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.redirect_url.clone())?);

        let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

        if let Some(verifier) = pkce_verifier {
            token_request =
                token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
        }

        let token_response = token_request
            .request_async(&self.http_client)
            .await
            .map_err(|e| Error::TokenExchange(e.to_string()))?;

        let access_token = token_response.access_token().secret().to_string();

        // Fetch userinfo if endpoint exists
        let userinfo = if let Some(url) = self.provider.userinfo_url() {
            let response = self
                .http_client
                .get(url)
                .bearer_auth(&access_token)
                .header("User-Agent", "oauth-kit")
                .send()
                .await
                .map_err(|e| Error::ProfileFetch(e.to_string()))?
                .json()
                .await
                .map_err(|e| Error::ProfileFetch(e.to_string()))?;
            Some(response)
        } else {
            None
        };

        let user = self
            .provider
            .normalize_profile(&self.http_client, &access_token, userinfo)
            .await?;

        Ok((user, access_token))
    }

    pub fn provider(&self) -> &Arc<dyn OAuthProvider> {
        &self.provider
    }
}

/// Registry of OAuth providers.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a provider.
    pub fn register<P: OAuthProvider>(&mut self, provider: P) -> &mut Self {
        self.providers
            .insert(provider.id().to_string(), Arc::new(provider));
        self
    }

    /// Get a provider by ID.
    pub fn get(&self, id: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.providers.get(id).cloned()
    }

    /// List all registered provider IDs.
    pub fn provider_ids(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }
}
