# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build                     # Build the library
cargo build --all-features      # Build with all features
cargo run --example basic       # Run the basic example (requires GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
cargo test                      # Run tests
cargo doc --open                # Generate and view documentation
```

Development environment uses devenv with Rust enabled (`devenv shell`).

## Architecture

oauth-kit is a batteries-included OAuth/OIDC client library for Rust with axum integration.

### Core Components

- **`OAuthProvider` trait** (`src/provider/mod.rs`): Unified async trait for both OAuth2 and OIDC providers. All providers implement `authorization_url()` and `exchange_code()`.

- **`User` struct** (`src/user.rs`): Normalized user profile with builder pattern. Contains: `id`, `email`, `email_verified`, `name`, `image`, and `raw` (original provider response).

- **`UserStore` trait** (`src/store.rs`): Interface for persisting users. Implement `find_or_create()` to integrate with your database. `MemoryStore` provided for development.

- **`ProviderRegistry`** (`src/provider/mod.rs`): HashMap-based registry mapping provider IDs to provider instances.

### Provider Types

Two provider implementations under `src/provider/`:

1. **`OAuth2Provider`** (`oauth2_provider.rs`): Standard OAuth2 flow with PKCE. Fetches user profile from userinfo endpoint.

2. **`OidcProvider`** (`oidc.rs`): OpenID Connect with discovery and ID token verification. Requires `oidc` feature.

Pre-configured providers are in `src/provider/providers.rs` with factory functions like `github()`, `google()`, `auth0()`.

### Axum Integration

Under `src/axum/` (requires `axum-integration` feature):

- **`AuthRouter`** (`router.rs`): Builder that creates `/auth/signin/:provider`, `/auth/callback/:provider`, `/auth/signout` routes.

- **`AuthUser<T>` / `MaybeAuthUser<T>`** (`extractors.rs`): Axum extractors for authenticated/optional user from session.

- **`AuthState`** (`router.rs`): Shared state holding providers, store, and redirect URLs.

### Feature Flags

- `axum-integration` (default): Axum router, handlers, extractors
- `oidc` (default): OpenID Connect support via `openidconnect` crate

## Code Conventions

- Use `thiserror` for error types (`src/error.rs`)
- Builder pattern with `with_*` methods for configuration
- Providers return `Result<(User, access_token)>` from `exchange_code()`
- Session keys namespaced with `oauth_kit_` prefix
