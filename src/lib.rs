//! # oauth-kit
//!
//! A batteries-included OAuth client library for Rust with normalized user profiles
//! and plug-and-play axum integration.
//!
//! ## Features
//!
//! - **Pre-configured providers**: GitHub, Google, Discord, and 90+ more
//! - **Normalized user profiles**: Consistent `User` struct across all providers
//! - **Axum integration**: Ready-to-use router with session management
//! - **OIDC support**: Full OpenID Connect with ID token verification
//! - **Extensible**: Easy to add custom providers
//!
//! ## Quick Start
//!
//! Build a provider, hand it to an `AuthRouter`, and merge the result into
//! your app. The [`axum`] module documents the whole setup, including the
//! session layer the router requires.
//!
//! ## Providers
//!
//! All providers are available through [`provider::providers`].
//!
//! ### OAuth2 Providers
//! - GitHub, GitLab, Bitbucket
//! - Discord, Spotify, TikTok
//! - Twitter/X, Facebook, Reddit
//! - Dropbox, Notion, Figma, Zoom
//! - And many more...
//!
//! ### OIDC Providers
//! - Google, Microsoft/Azure AD, Apple
//! - Auth0, Okta, Keycloak, WorkOS
//! - AWS Cognito, FusionAuth, Authentik
//! - LinkedIn, Slack, Twitch, Salesforce
//! - Any OIDC-compliant provider via [`provider::providers::oidc`]
//!
//! A handful of providers also have a `*_from_env()` constructor. For the
//! rest, read the credentials yourself and pass them in.
//!
//! ## Routes
//!
//! The `AuthRouter` creates the following routes:
//!
//! - `GET /auth/signin/{provider}` - Initiates OAuth flow
//! - `GET /auth/callback/{provider}` - Handles OAuth callback
//! - `GET`/`POST /auth/signout` - Signs out the user
//!
//! ## Extractors
//!
//! Route handlers read the signed-in user with [`axum::AuthUser`], which
//! rejects unauthenticated requests with a 401, or [`axum::MaybeAuthUser`],
//! which yields `None` instead.
pub mod error;
pub mod provider;
pub mod store;
pub mod user;

#[cfg(feature = "axum-integration")]
pub mod axum;

pub use error::{Error, Result};
pub use store::UserStore;
pub use user::User;

pub use provider::providers;
pub use provider::OAuth2Provider;
pub use provider::OidcProvider;
pub use provider::{AuthorizationRequest, OAuthProvider, ProviderRegistry};
