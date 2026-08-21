//! Axum integration: a ready-made router, handlers and extractors.
//!
//! [`AuthRouter`] builds three routes under a configurable prefix (`/auth` by
//! default):
//!
//! - `GET /auth/signin/{provider}` - starts the OAuth flow
//! - `GET /auth/callback/{provider}` - completes it
//! - `GET`/`POST /auth/signout` - clears the session
//!
//! The router stores the in-flight flow and the signed-in user in the session,
//! so it **must** be layered with a [`tower_sessions::SessionManagerLayer`].
//! Without one, every route answers 500.
//!
//! ```rust,no_run
//! use axum::Router;
//! use oauth_kit::{axum::AuthRouter, provider::providers, store::MemoryStore};
//! use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};
//!
//! # async fn run() {
//! let github = providers::github_from_env().unwrap();
//!
//! let auth = AuthRouter::new(MemoryStore::new(), "http://localhost:3000")
//!     .with_provider(github)
//!     .with_signin_redirect("/")
//!     .build();
//!
//! let app = Router::new()
//!     .merge(auth)
//!     .layer(SessionManagerLayer::new(SessionStore::default()));
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//! axum::serve(listener, app).await.unwrap();
//! # }
//! ```
//!
//! `base_url` must match the callback URL registered with the provider:
//! [`AuthRouter::callback_url`] returns exactly what to register.

mod extractors;
mod handlers;
mod router;

pub use extractors::{AuthUser, MaybeAuthUser};
pub use router::AuthRouter;
