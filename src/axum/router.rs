use axum::{routing::get, Router};
use std::sync::Arc;

use super::handlers;
use crate::provider::{OAuthProvider, ProviderRegistry};
use crate::store::UserStore;

/// Session keys used by the auth router.
pub mod session_keys {
    pub const USER_ID: &str = "oauth_kit_user_id";
    pub const CSRF_STATE: &str = "oauth_kit_csrf_state";
    pub const PKCE_VERIFIER: &str = "oauth_kit_pkce_verifier";
    pub const NONCE: &str = "oauth_kit_nonce";
    pub const PROVIDER: &str = "oauth_kit_provider";
}

/// Builder for creating OAuth authentication routes.
pub struct AuthRouter<S: UserStore + Clone> {
    providers: ProviderRegistry,
    store: Arc<S>,
    base_url: String,
    path_prefix: String,
    signin_redirect: String,
    signout_redirect: String,
}

impl<S: UserStore + Clone> AuthRouter<S> {
    /// Create a new AuthRouter with the given user store.
    ///
    /// # Arguments
    /// * `store` - The user store for persisting authentication data
    /// * `base_url` - The base URL of your application (e.g., "http://localhost:3000")
    pub fn new(store: S, base_url: impl Into<String>) -> Self {
        Self {
            providers: ProviderRegistry::new(),
            store: Arc::new(store),
            base_url: base_url.into(),
            path_prefix: "/auth".to_string(),
            signin_redirect: "/".to_string(),
            signout_redirect: "/".to_string(),
        }
    }

    /// Set the path prefix for auth routes.
    ///
    /// Default is "/auth", which creates routes like:
    /// - `/auth/signin/{provider}`
    /// - `/auth/callback/{provider}`
    /// - `/auth/signout`
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = prefix.into();
        self
    }

    /// Set the redirect URL after successful sign-in.
    pub fn with_signin_redirect(mut self, url: impl Into<String>) -> Self {
        self.signin_redirect = url.into();
        self
    }

    /// Set the redirect URL after sign-out.
    pub fn with_signout_redirect(mut self, url: impl Into<String>) -> Self {
        self.signout_redirect = url.into();
        self
    }

    /// Register an OAuth provider.
    pub fn with_provider<P: OAuthProvider>(mut self, provider: P) -> Self {
        self.providers.register(provider);
        self
    }

    /// Build the router with all configured routes.
    pub fn build(self) -> Router {
        let state = AuthState {
            providers: Arc::new(self.providers),
            store: self.store,
            base_url: self.base_url,
            path_prefix: self.path_prefix.clone(),
            signin_redirect: self.signin_redirect,
            signout_redirect: self.signout_redirect,
        };

        Router::new()
            .route(
                &format!("{}/signin/{{provider}}", self.path_prefix),
                get(handlers::signin::<S>),
            )
            .route(
                &format!("{}/callback/{{provider}}", self.path_prefix),
                get(handlers::callback::<S>),
            )
            .route(
                &format!("{}/signout", self.path_prefix),
                get(handlers::signout::<S>),
            )
            .with_state(state)
    }
}

/// Shared state for auth handlers.
#[derive(Clone)]
pub struct AuthState<S: UserStore + Clone> {
    pub providers: Arc<ProviderRegistry>,
    pub store: Arc<S>,
    pub base_url: String,
    pub path_prefix: String,
    pub signin_redirect: String,
    pub signout_redirect: String,
}

impl<S: UserStore + Clone> AuthState<S> {
    pub fn callback_url(&self, provider_id: &str) -> String {
        format!(
            "{}{}/callback/{}",
            self.base_url, self.path_prefix, provider_id
        )
    }
}
