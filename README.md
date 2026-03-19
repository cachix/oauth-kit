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

## Routes

The `AuthRouter` creates:

| Route | Description |
|-------|-------------|
| `GET /auth/signin/:provider` | Initiates OAuth flow |
| `GET /auth/callback/:provider` | Handles OAuth callback |
| `GET /auth/signout` | Signs out the user |

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

Implement `UserStore` for your database:

```rust
use oauth_kit::{User, UserStore, Result};
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

Each provider has a `*_from_env()` function. Common patterns:

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
