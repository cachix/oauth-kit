//! OAuth/OIDC provider traits and implementations.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::User;

pub mod oauth2_provider;
pub mod oidc;
pub mod providers;

pub use self::oauth2_provider::OAuth2Provider;
pub use self::oidc::OidcProvider;

/// Authorization request data returned by providers.
///
/// Contains all the state needed to complete the OAuth flow.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// URL to redirect the user to for authorization.
    pub url: String,
    /// CSRF state token - must be verified in callback.
    pub csrf_state: String,
    /// PKCE verifier - store in session, pass to exchange_code.
    pub pkce_verifier: Option<String>,
    /// Nonce for OIDC ID token verification - None for OAuth2, Some for OIDC.
    pub nonce: Option<String>,
}

/// Unified trait for OAuth2 and OIDC providers.
///
/// This trait abstracts over both OAuth2 and OIDC providers, allowing
/// the same axum integration to work with all provider types.
#[async_trait]
pub trait OAuthProvider: Send + Sync + 'static {
    /// Unique identifier for this provider (e.g., "github", "google").
    fn id(&self) -> &str;

    /// Human-readable name (e.g., "GitHub", "Google").
    fn name(&self) -> &str;

    /// Generate an authorization URL for the OAuth/OIDC flow.
    ///
    /// For OIDC providers, this may perform discovery to find the authorization endpoint.
    async fn authorization_url(&self, redirect_url: &str) -> Result<AuthorizationRequest>;

    /// Exchange an authorization code for user information.
    ///
    /// # Arguments
    /// * `redirect_url` - The callback URL (must match what was used in authorization_url)
    /// * `code` - The authorization code from the callback
    /// * `pkce_verifier` - The PKCE verifier from the authorization request
    /// * `nonce` - The nonce for OIDC ID token verification (None for OAuth2)
    ///
    /// # Returns
    /// A tuple of (User, access_token)
    async fn exchange_code(
        &self,
        redirect_url: &str,
        code: &str,
        pkce_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(User, String)>;
}

/// Registry of OAuth providers.
#[derive(Default, Clone)]
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
