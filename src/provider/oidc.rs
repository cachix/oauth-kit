//! Generic OIDC provider for any OpenID Connect compliant identity provider.
//!
//! This provider uses OIDC discovery to automatically configure endpoints
//! and properly verifies ID tokens (signature, issuer, audience, expiry, nonce).

use async_trait::async_trait;
use openidconnect::{
    core::{CoreClient, CoreIdTokenClaims, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use tokio::sync::OnceCell;

use crate::error::{Error, Result};
use crate::User;

use super::AuthorizationRequest;

/// Generic OIDC provider that works with any OpenID Connect compliant identity provider.
///
/// Uses OIDC discovery to automatically configure endpoints from the issuer's
/// `.well-known/openid-configuration`.
///
/// # Example
///
/// ```rust,ignore
/// use oauth_kit::provider::providers;
///
/// // Google
/// let google = providers::google("client_id", "client_secret");
///
/// // Auth0
/// let auth0 = providers::auth0("tenant.auth0.com", "client_id", "client_secret");
///
/// // Generic OIDC
/// let custom = providers::oidc("https://issuer.example.com", "client_id", "client_secret");
/// ```
pub struct OidcProvider {
    id: String,
    name: String,
    issuer_url: String,
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    discovery: OnceCell<CoreProviderMetadata>,
}

impl OidcProvider {
    /// Create a new OIDC provider with the given issuer URL and credentials.
    ///
    /// The issuer URL should be the base URL of your identity provider, e.g.:
    /// - Google: `https://accounts.google.com`
    /// - Auth0: `https://your-tenant.auth0.com`
    /// - Okta: `https://your-org.okta.com`
    /// - Keycloak: `https://keycloak.example.com/realms/myrealm`
    /// - Azure AD: `https://login.microsoftonline.com/{tenant}/v2.0`
    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            id: "oidc".to_string(),
            name: "OIDC".to_string(),
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            discovery: OnceCell::new(),
        }
    }

    /// Set a custom provider ID (used in routes like `/auth/signin/{id}`).
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set a custom display name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set custom scopes (must include "openid" for OIDC).
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Add additional scopes to the default set.
    pub fn add_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Get the issuer URL.
    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    /// Get the client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    async fn get_provider_metadata(&self) -> Result<&CoreProviderMetadata> {
        self.discovery
            .get_or_try_init(|| async {
                let http_client = oauth2::reqwest::ClientBuilder::new()
                    // Following redirects opens the client up to SSRF vulnerabilities
                    .redirect(oauth2::reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|e| Error::Config(e.to_string()))?;

                let issuer_url = IssuerUrl::new(self.issuer_url.clone())
                    .map_err(|e| Error::Config(format!("Invalid issuer URL: {}", e)))?;

                CoreProviderMetadata::discover_async(issuer_url, &http_client)
                    .await
                    .map_err(|e| Error::Config(format!("OIDC discovery failed: {}", e)))
            })
            .await
    }

    // Convenience constructors for common providers

    /// Create a Google OIDC provider.
    pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self::new("https://accounts.google.com", client_id, client_secret)
            .with_id("google")
            .with_name("Google")
    }

    /// Create an Auth0 provider.
    pub fn auth0(
        domain: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            format!("https://{}", domain.as_ref()),
            client_id,
            client_secret,
        )
        .with_id("auth0")
        .with_name("Auth0")
    }

    /// Create an Okta provider.
    pub fn okta(
        domain: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            format!("https://{}", domain.as_ref()),
            client_id,
            client_secret,
        )
        .with_id("okta")
        .with_name("Okta")
    }

    /// Create a Keycloak provider.
    pub fn keycloak(
        base_url: impl AsRef<str>,
        realm: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            format!(
                "{}/realms/{}",
                base_url.as_ref().trim_end_matches('/'),
                realm.as_ref()
            ),
            client_id,
            client_secret,
        )
        .with_id("keycloak")
        .with_name("Keycloak")
    }

    /// Create an Azure AD / Microsoft Entra ID provider.
    pub fn azure_ad(
        tenant: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            format!("https://login.microsoftonline.com/{}/v2.0", tenant.as_ref()),
            client_id,
            client_secret,
        )
        .with_id("azure")
        .with_name("Microsoft")
    }

    /// Create an AWS Cognito provider.
    pub fn cognito(
        user_pool_id: impl AsRef<str>,
        region: impl AsRef<str>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            format!(
                "https://cognito-idp.{}.amazonaws.com/{}",
                region.as_ref(),
                user_pool_id.as_ref()
            ),
            client_id,
            client_secret,
        )
        .with_id("cognito")
        .with_name("Cognito")
    }
}

#[async_trait]
impl super::OAuthProvider for OidcProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn authorization_url(&self, redirect_url: &str) -> Result<AuthorizationRequest> {
        let metadata = self.get_provider_metadata().await?;

        let client = CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url.to_string()).map_err(|e| Error::Config(e.to_string()))?,
        );

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut auth_request = client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        for scope in &self.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (url, csrf_state, nonce) = auth_request.set_pkce_challenge(pkce_challenge).url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            csrf_state: csrf_state.secret().to_string(),
            pkce_verifier: Some(pkce_verifier.secret().to_string()),
            nonce: Some(nonce.secret().to_string()),
        })
    }

    async fn exchange_code(
        &self,
        redirect_url: &str,
        code: &str,
        pkce_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(User, String)> {
        let nonce = nonce
            .ok_or_else(|| Error::TokenExchange("Missing nonce for OIDC provider".to_string()))?;
        let pkce_verifier = pkce_verifier
            .ok_or_else(|| Error::TokenExchange("Missing PKCE verifier".to_string()))?;

        let metadata = self.get_provider_metadata().await?;

        let client = CoreClient::from_provider_metadata(
            metadata.clone(),
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url.to_string()).map_err(|e| Error::Config(e.to_string()))?,
        );

        let http_client = oauth2::reqwest::ClientBuilder::new()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| Error::TokenExchange(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&http_client)
            .await
            .map_err(|e| Error::TokenExchange(e.to_string()))?;

        let access_token = token_response.access_token().secret().to_string();

        // Verify ID token - this validates signature, issuer, audience, expiry, nonce
        let id_token = token_response
            .id_token()
            .ok_or_else(|| Error::TokenExchange("No ID token in response".to_string()))?;

        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_string()))
            .map_err(|e| Error::TokenExchange(format!("ID token verification failed: {}", e)))?;

        let user = user_from_claims(claims)?;

        Ok((user, access_token))
    }
}

fn user_from_claims(claims: &CoreIdTokenClaims) -> Result<User> {
    Ok(User {
        id: claims.subject().to_string(),
        email: claims.email().map(|e| e.to_string()),
        email_verified: claims.email_verified().unwrap_or(false),
        name: claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string()),
        image: claims
            .picture()
            .and_then(|p| p.get(None))
            .map(|p| p.to_string()),
        raw: serde_json::to_value(claims).unwrap_or_default(),
    })
}
