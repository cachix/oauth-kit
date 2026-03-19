//! # oauth-kit
//!
//! A batteries-included OAuth client library for Rust with normalized user profiles
//! and plug-and-play axum integration.
//!
//! ## Features
//!
//! - **Pre-configured providers**: GitHub, Google, Discord, and 70+ more
//! - **Normalized user profiles**: Consistent `User` struct across all providers
//! - **Axum integration**: Ready-to-use router with session management
//! - **OIDC support**: Full OpenID Connect with ID token verification
//! - **Extensible**: Easy to add custom providers
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use oauth_kit::{
//!     axum::{AuthRouter, AuthUser},
//!     provider::providers,
//!     store::MemoryStore,
//! };
//! use axum::Router;
//! use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};
//!
//! #[tokio::main]
//! async fn main() {
//!     let session_store = SessionStore::default();
//!     let session_layer = SessionManagerLayer::new(session_store);
//!
//!     // OAuth2 providers (GitHub, Discord, etc.)
//!     let github = providers::github_from_env().unwrap();
//!
//!     // OIDC providers (Google, Auth0, etc.) - requires "oidc" feature
//!     // let google = providers::google_from_env().unwrap();
//!
//!     let auth = AuthRouter::new(MemoryStore::new(), "http://localhost:3000")
//!         .with_provider(github)
//!         .build();
//!
//!     let app = Router::new()
//!         .merge(auth)
//!         .layer(session_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! ## Providers
//!
//! All providers are available through `oauth_kit::provider::providers`:
//!
//! ### OAuth2 Providers
//! - GitHub, GitLab, Bitbucket
//! - Discord, Slack, Twitch
//! - Spotify, Strava, Patreon
//! - Twitter/X, Facebook, Instagram, TikTok
//! - LinkedIn, Reddit, Medium
//! - Dropbox, Box, Notion, Figma
//! - And many more...
//!
//! ### OIDC Providers (requires "oidc" feature)
//! - Google, Microsoft/Azure AD
//! - Auth0, Okta, Keycloak
//! - AWS Cognito, FusionAuth
//! - OneLogin, Zitadel, Kinde
//! - Any OIDC-compliant provider via `oidc()`
//!
//! ## Routes
//!
//! The `AuthRouter` creates the following routes:
//!
//! - `GET /auth/signin/:provider` - Initiates OAuth flow
//! - `GET /auth/callback/:provider` - Handles OAuth callback
//! - `GET /auth/signout` - Signs out the user
//!
//! ## Extractors
//!
//! Use the provided extractors in your route handlers:
//!
//! ```rust,ignore
//! use oauth_kit::axum::{AuthUser, MaybeAuthUser};
//!
//! // Requires authentication (returns 401 if not authenticated)
//! async fn protected(AuthUser(user_id): AuthUser<String>) -> String {
//!     format!("Hello, {}!", user_id)
//! }
//!
//! // Optional authentication
//! async fn public(MaybeAuthUser(user_id): MaybeAuthUser<String>) -> String {
//!     match user_id {
//!         Some(id) => format!("Hello, {}!", id),
//!         None => "Hello, guest!".to_string(),
//!     }
//! }
//! ```

pub mod error;
pub mod provider;
pub mod store;
pub mod user;

#[cfg(feature = "axum-integration")]
pub mod axum;

pub use error::{Error, Result};
pub use store::UserStore;
pub use user::User;

pub use provider::OAuth2Provider;
pub use provider::{AuthorizationRequest, OAuthProvider, ProviderRegistry};

#[cfg(feature = "oidc")]
pub use provider::OidcProvider;

#[cfg(feature = "oidc")]
pub use provider::providers;
