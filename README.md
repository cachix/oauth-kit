# oauth-kit

Batteries-included OAuth/OIDC client library for Rust with normalized user profiles and plug-and-play axum integration.

## Features

- **90+ pre-configured providers** - GitHub, Google, Discord, Apple, Auth0, Okta, Azure AD, and many more
- **Normalized user profiles** - Consistent `User` struct across all providers
- **OIDC support** - Full OpenID Connect with ID token verification
- **Axum integration** - Ready-to-use router with session management
- **Runtime configuration** - Custom URLs for self-hosted providers (GitLab, Mastodon, Mattermost, etc.)

## Quick Start

```toml
[dependencies]
oauth-kit = "0.1"
tower-sessions = { version = "0.14", features = ["memory-store"] }
```

```rust
use oauth_kit::{
    axum::AuthRouter,
    provider::providers,
    store::MemoryStore,
};
use axum::Router;
use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};

#[tokio::main]
async fn main() {
    let session_store = SessionStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    let auth = AuthRouter::new(MemoryStore::new(), "http://localhost:3000")
        .with_provider(providers::github_from_env().unwrap())
        .with_provider(providers::google_from_env().unwrap())
        .build();

    let app = Router::new()
        .merge(auth)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

The `AuthRouter` keeps the in-flight OAuth flow and the signed-in user in the
session, so it must be layered with a `SessionManagerLayer` as above. Without
one, every route answers 500.

`base_url` has to match the callback URL you registered with the provider.
`AuthRouter::callback_url("github")` returns exactly what to register.

## Routes

The `AuthRouter` creates:

| Route | Description |
|-------|-------------|
| `GET /auth/signin/{provider}` | Initiates OAuth flow |
| `GET /auth/callback/{provider}` | Handles OAuth callback |
| `GET` / `POST /auth/signout` | Signs out the user |

Sign-out accepts POST so it can be triggered from a form without being
reachable by cross-site GET.

## What the callback checks

Before a code is ever exchanged, the callback requires that:

- a sign-in is actually in progress in this session,
- it was started for the same provider the callback is for,
- the returned `state` matches the one stored at sign-in (compared in
  constant time).

The stored flow is single-use, so a callback URL cannot be replayed, and the
session ID is cycled once the user is known, so a cookie planted before
sign-in cannot be used afterwards.

## Account linking

Completing a flow while already signed in calls `UserStore::link_account`
instead of `find_or_create`, so a second provider attaches to the current
account rather than switching to another one:

```text
signed out  + /auth/signin/github  ->  find_or_create(github)  ->  user 1
user 1      + /auth/signin/google  ->  link_account(user 1, google)
signed out  + /auth/signin/google  ->  find_or_create(google)   ->  user 1
```

To switch accounts instead, sign out first.

The identity being linked may already belong to a *different* account, and
linking it anyway would hand the current user that account. Your store should
detect this and return an error; the callback then answers 500 and no link is
made. `MemoryStore` keeps it simple and just ignores a conflicting link, so
the identity stays with its original owner but nobody is told.

The default `link_account` does nothing at all, so a store that does not
override it accepts links and silently forgets them.

## Extractors

```rust
use oauth_kit::axum::{AuthUser, MaybeAuthUser};

// Requires authentication (returns 401 if not authenticated)
async fn protected(AuthUser(user_id): AuthUser<String>) -> String {
    format!("Hello, {}!", user_id)
}

// Optional authentication
async fn public(MaybeAuthUser(user_id): MaybeAuthUser<String>) -> String {
    match user_id {
        Some(id) => format!("Hello, {}!", id),
        None => "Hello, guest!".to_string(),
    }
}
```

## Providers

### OIDC Providers

Full OpenID Connect with automatic discovery and ID token verification:

```rust
use oauth_kit::provider::providers;

// Google
let google = providers::google(client_id, client_secret);
let google = providers::google_from_env()?; // GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

// Microsoft / Azure AD
let ms = providers::azure_ad("tenant-id", client_id, client_secret);
let ms = providers::microsoft_entra_id("tenant-id", client_id, client_secret);
let b2c = providers::azure_ad_b2c("tenant-name", "user-flow", client_id, client_secret);

// Auth0
let auth0 = providers::auth0("tenant.auth0.com", client_id, client_secret);

// Okta
let okta = providers::okta("org.okta.com", client_id, client_secret);

// Keycloak
let kc = providers::keycloak("https://kc.example.com", "realm", client_id, client_secret);

// AWS Cognito
let cognito = providers::cognito("user-pool-id", "region", client_id, client_secret);

// Other OIDC identity providers
let zitadel = providers::zitadel(issuer, client_id, client_secret);
let logto = providers::logto(issuer, client_id, client_secret);
let kinde = providers::kinde(issuer, client_id, client_secret);
let descope = providers::descope(issuer, client_id, client_secret);
let frontegg = providers::frontegg(domain, client_id, client_secret);
let asgardeo = providers::asgardeo(organization, client_id, client_secret);

// Self-hosted OIDC
let ory_hydra = providers::ory_hydra(issuer, client_id, client_secret);
let duende = providers::duende_identity_server(issuer, client_id, client_secret);

// Generic OIDC (any compliant provider)
let custom = providers::oidc("https://issuer.example.com", client_id, client_secret);
```

### OAuth2 Providers

Standard OAuth2 with profile fetched from userinfo endpoint:

```rust
// Social
let github = providers::github(client_id, client_secret);
let discord = providers::discord(client_id, client_secret);
let twitter = providers::twitter(client_id, client_secret);
let facebook = providers::facebook(client_id, client_secret);
let reddit = providers::reddit(client_id, client_secret);

// Developer platforms
let gitlab = providers::gitlab(client_id, client_secret);
let bitbucket = providers::bitbucket(client_id, client_secret);
let figma = providers::figma(client_id, client_secret);
let notion = providers::notion(client_id, client_secret);
let azure_devops = providers::azure_devops(client_id, client_secret);

// Entertainment
let spotify = providers::spotify(client_id, client_secret);
let tiktok = providers::tiktok(client_id, client_secret);

// Productivity
let zoom = providers::zoom(client_id, client_secret);
let dropbox = providers::dropbox(client_id, client_secret);

// International
let wechat = providers::wechat(client_id, client_secret);
let yandex = providers::yandex(client_id, client_secret);
let mailru = providers::mailru(client_id, client_secret);

// And 60+ more...
```

### Additional OIDC Providers

These providers use OpenID Connect for enhanced security:

```rust
// Social/Productivity (OIDC)
let linkedin = providers::linkedin(client_id, client_secret);
let slack = providers::slack(client_id, client_secret);
let twitch = providers::twitch(client_id, client_secret);
let apple = providers::apple(client_id, client_secret);

// Gaming (OIDC)
let battlenet = providers::battlenet_us(client_id, client_secret);
let roblox = providers::roblox(client_id, client_secret);
let line = providers::line(client_id, client_secret);

// Enterprise (OIDC)
let salesforce = providers::salesforce(client_id, client_secret);
let huggingface = providers::huggingface(client_id, client_secret);
let simplelogin = providers::simplelogin(client_id, client_secret);

// Identity platforms (OIDC)
let passage = providers::passage(issuer, client_id, client_secret);
let beyondidentity = providers::beyondidentity(issuer, client_id, client_secret);
let vipps = providers::vipps(client_id, client_secret);
```

### Self-Hosted Providers

Custom URLs for self-hosted instances:

```rust
// Self-hosted GitLab
let gitlab = providers::gitlab_with_url(
    "https://gitlab.mycompany.com",
    client_id,
    client_secret,
);

// Mastodon instance
let mastodon = providers::mastodon(
    "https://mastodon.social",
    client_id,
    client_secret,
);

// Mattermost
let mm = providers::mattermost(
    "https://mattermost.mycompany.com",
    client_id,
    client_secret,
);

// Nextcloud
let nc = providers::nextcloud(
    "https://cloud.mycompany.com",
    client_id,
    client_secret,
);
```

## Custom User Store

`MemoryStore` is for development only: it keeps users in a `HashMap` and
forgets them on restart. For anything real, implement `UserStore` against your
database:

```rust
use oauth_kit::{User, UserStore};
use async_trait::async_trait;

struct PostgresStore { /* ... */ }

#[async_trait]
impl UserStore for PostgresStore {
    type UserId = i64;
    type Error = sqlx::Error;

    async fn find_or_create(
        &self,
        user: &User,
        provider: &str,
    ) -> std::result::Result<Self::UserId, Self::Error> {
        // Insert or update user in database
        // Return the user ID
    }

    async fn link_account(
        &self,
        user_id: &Self::UserId,
        user: &User,
        provider: &str,
    ) -> std::result::Result<(), Self::Error> {
        // Attach (provider, user.id) to user_id.
        // Return an error if it already belongs to a different account.
    }
}
```

## Feature Flags

```toml
[dependencies]
# Default: axum integration
oauth-kit = "0.1"

# Without axum (just the providers)
oauth-kit = { version = "0.1", default-features = false }
```

| Feature | Description |
|---------|-------------|
| `axum-integration` (default) | Axum router, handlers, and extractors |

## Generic OAuth2 Provider

For providers not included in the library, use the generic `oauth2()` function:

```rust
let custom = providers::oauth2(
    "my-provider",                              // id
    "My Provider",                              // name
    "https://provider.com/oauth/authorize",     // authorization_url
    "https://provider.com/oauth/token",         // token_url
    Some("https://provider.com/api/userinfo"),  // userinfo_url
    vec!["profile", "email"],                   // scopes
    client_id,
    client_secret,
);
```

## Environment Variables

A few providers ship a `*_from_env()` constructor. For everything else, read
the credentials yourself and pass them to the provider function.

| Provider | Variables |
|----------|-----------|
| GitHub | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| Discord | `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET` |
| Apple | `APPLE_CLIENT_ID`, `APPLE_CLIENT_SECRET` |
| Auth0 | `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET` |
| Azure AD | `AZURE_AD_TENANT`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET` |
| Okta | `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET` |
| Keycloak | `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET` |
| Cognito | `COGNITO_USER_POOL_ID`, `COGNITO_REGION`, `COGNITO_CLIENT_ID`, `COGNITO_CLIENT_SECRET` |
| Slack | `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` |
| LinkedIn | `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET` |

## License

Apache-2.0
