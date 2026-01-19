//! Pre-configured OAuth/OIDC providers.
//!
//! This module contains factory functions for all supported identity providers,
//! matching the providers available in NextAuth.js.
//!
//! Providers are organized into two categories:
//! - **OIDC providers**: Use OpenID Connect with automatic discovery and ID token verification
//! - **OAuth2 providers**: Use standard OAuth2 with profile fetched from userinfo endpoint

use crate::error::{Error, Result};
use crate::User;

use super::oauth2_provider::{
    fetch_json, json_bool, json_string, json_string_any, OAuth2Provider, OAuth2ProviderWithExtra,
};
use super::oidc::OidcProvider;

// ============================================================================
// OIDC Providers
// ============================================================================
// These providers support OpenID Connect and use automatic discovery.
// ID tokens are cryptographically verified.

/// Google - OIDC provider
pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://accounts.google.com", client_id, client_secret)
        .with_id("google")
        .with_name("Google")
}

/// Google from environment variables (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
pub fn google_from_env() -> Result<OidcProvider> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .map_err(|_| Error::Config("GOOGLE_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .map_err(|_| Error::Config("GOOGLE_CLIENT_SECRET not set".to_string()))?;
    Ok(google(client_id, client_secret))
}

/// Auth0 - OIDC provider
pub fn auth0(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::auth0(domain, client_id, client_secret)
}

/// Auth0 from environment variables (AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET)
pub fn auth0_from_env() -> Result<OidcProvider> {
    let domain = std::env::var("AUTH0_DOMAIN")
        .map_err(|_| Error::Config("AUTH0_DOMAIN not set".to_string()))?;
    let client_id = std::env::var("AUTH0_CLIENT_ID")
        .map_err(|_| Error::Config("AUTH0_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("AUTH0_CLIENT_SECRET")
        .map_err(|_| Error::Config("AUTH0_CLIENT_SECRET not set".to_string()))?;
    Ok(auth0(domain, client_id, client_secret))
}

/// Okta - OIDC provider
pub fn okta(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::okta(domain, client_id, client_secret)
}

/// Okta from environment variables (OKTA_DOMAIN, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET)
pub fn okta_from_env() -> Result<OidcProvider> {
    let domain = std::env::var("OKTA_DOMAIN")
        .map_err(|_| Error::Config("OKTA_DOMAIN not set".to_string()))?;
    let client_id = std::env::var("OKTA_CLIENT_ID")
        .map_err(|_| Error::Config("OKTA_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("OKTA_CLIENT_SECRET")
        .map_err(|_| Error::Config("OKTA_CLIENT_SECRET not set".to_string()))?;
    Ok(okta(domain, client_id, client_secret))
}

/// Keycloak - OIDC provider
pub fn keycloak(
    base_url: impl AsRef<str>,
    realm: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::keycloak(base_url, realm, client_id, client_secret)
}

/// Keycloak from environment variables (KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET)
pub fn keycloak_from_env() -> Result<OidcProvider> {
    let base_url = std::env::var("KEYCLOAK_URL")
        .map_err(|_| Error::Config("KEYCLOAK_URL not set".to_string()))?;
    let realm = std::env::var("KEYCLOAK_REALM")
        .map_err(|_| Error::Config("KEYCLOAK_REALM not set".to_string()))?;
    let client_id = std::env::var("KEYCLOAK_CLIENT_ID")
        .map_err(|_| Error::Config("KEYCLOAK_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("KEYCLOAK_CLIENT_SECRET")
        .map_err(|_| Error::Config("KEYCLOAK_CLIENT_SECRET not set".to_string()))?;
    Ok(keycloak(base_url, realm, client_id, client_secret))
}

/// Azure AD / Microsoft Entra ID - OIDC provider
pub fn azure_ad(
    tenant: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::azure_ad(tenant, client_id, client_secret)
}

/// Azure AD from environment variables (AZURE_AD_TENANT, AZURE_AD_CLIENT_ID, AZURE_AD_CLIENT_SECRET)
pub fn azure_ad_from_env() -> Result<OidcProvider> {
    let tenant = std::env::var("AZURE_AD_TENANT")
        .map_err(|_| Error::Config("AZURE_AD_TENANT not set".to_string()))?;
    let client_id = std::env::var("AZURE_AD_CLIENT_ID")
        .map_err(|_| Error::Config("AZURE_AD_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("AZURE_AD_CLIENT_SECRET")
        .map_err(|_| Error::Config("AZURE_AD_CLIENT_SECRET not set".to_string()))?;
    Ok(azure_ad(tenant, client_id, client_secret))
}

/// Microsoft Entra ID (same as Azure AD)
pub fn microsoft_entra_id(
    tenant: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    azure_ad(tenant, client_id, client_secret)
        .with_id("microsoft-entra-id")
        .with_name("Microsoft Entra ID")
}

/// AWS Cognito - OIDC provider
pub fn cognito(
    user_pool_id: impl AsRef<str>,
    region: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://cognito-idp.{}.amazonaws.com/{}",
        region.as_ref(),
        user_pool_id.as_ref()
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("cognito")
        .with_name("Cognito")
}

/// Cognito from environment variables
pub fn cognito_from_env() -> Result<OidcProvider> {
    let user_pool_id = std::env::var("COGNITO_USER_POOL_ID")
        .map_err(|_| Error::Config("COGNITO_USER_POOL_ID not set".to_string()))?;
    let region = std::env::var("COGNITO_REGION")
        .or_else(|_| std::env::var("AWS_REGION"))
        .map_err(|_| Error::Config("COGNITO_REGION or AWS_REGION not set".to_string()))?;
    let client_id = std::env::var("COGNITO_CLIENT_ID")
        .map_err(|_| Error::Config("COGNITO_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("COGNITO_CLIENT_SECRET")
        .map_err(|_| Error::Config("COGNITO_CLIENT_SECRET not set".to_string()))?;
    Ok(cognito(user_pool_id, region, client_id, client_secret))
}

/// FusionAuth - OIDC provider
pub fn fusionauth(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("fusionauth")
        .with_name("FusionAuth")
}

/// Authentik - OIDC provider
pub fn authentik(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}/application/o/{}",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://"),
        "default" // application slug
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("authentik")
        .with_name("Authentik")
}

/// OneLogin - OIDC provider
pub fn onelogin(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!("https://{}/oidc/2", domain.as_ref());
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("onelogin")
        .with_name("OneLogin")
}

/// Zitadel - OIDC provider
pub fn zitadel(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("zitadel")
        .with_name("Zitadel")
}

/// Logto - OIDC provider
pub fn logto(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}/oidc",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("logto")
        .with_name("Logto")
}

/// Kinde - OIDC provider
pub fn kinde(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("kinde")
        .with_name("Kinde")
}

/// Descope - OIDC provider
pub fn descope(
    project_id: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!("https://api.descope.com/{}", project_id.as_ref());
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("descope")
        .with_name("Descope")
}

/// WorkOS - OIDC provider
pub fn workos(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://api.workos.com", client_id, client_secret)
        .with_id("workos")
        .with_name("WorkOS")
}

/// Generic OIDC provider - use for any OIDC-compliant identity provider
pub fn oidc(
    issuer_url: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer_url, client_id, client_secret)
}

// ============================================================================
// OAuth2 Providers
// ============================================================================
// These providers use standard OAuth2 without OIDC.
// User profile is fetched from a separate userinfo endpoint.

/// GitHub - OAuth2 provider
pub fn github(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2ProviderWithExtra {
    OAuth2ProviderWithExtra::new(
        "github",
        "GitHub",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        Some("https://api.github.com/user"),
        vec!["read:user", "user:email"],
        client_id,
        client_secret,
        |client, token, userinfo| Box::pin(normalize_github(client, token, userinfo)),
    )
}

/// GitHub from environment variables (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET)
pub fn github_from_env() -> Result<OAuth2ProviderWithExtra> {
    let client_id = std::env::var("GITHUB_CLIENT_ID")
        .map_err(|_| Error::Config("GITHUB_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET")
        .map_err(|_| Error::Config("GITHUB_CLIENT_SECRET not set".to_string()))?;
    Ok(github(client_id, client_secret))
}

async fn normalize_github(
    client: &reqwest::Client,
    access_token: &str,
    userinfo: Option<serde_json::Value>,
) -> Result<User> {
    let profile = userinfo.ok_or_else(|| Error::ProfileFetch("No profile".to_string()))?;

    // GitHub requires separate API call for email if not public
    let email = if json_string(&profile, "email").is_none() {
        let emails: Vec<serde_json::Value> =
            fetch_json(client, "https://api.github.com/user/emails", access_token).await?;
        emails
            .iter()
            .find(|e| e.get("primary").and_then(|v| v.as_bool()).unwrap_or(false))
            .and_then(|e| json_string(e, "email"))
    } else {
        json_string(&profile, "email")
    };

    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_else(|| json_string(&profile, "login").unwrap_or_default()),
        email,
        email_verified: true, // GitHub verifies emails
        name: json_string(&profile, "name").or_else(|| json_string(&profile, "login")),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// GitLab - OAuth2 provider
pub fn gitlab(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "gitlab",
        "GitLab",
        "https://gitlab.com/oauth/authorize",
        "https://gitlab.com/oauth/token",
        Some("https://gitlab.com/api/v4/user"),
        vec!["read_user"],
        client_id,
        client_secret,
        normalize_gitlab,
    )
}

/// GitLab with custom instance URL
pub fn gitlab_with_url(
    base_url: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    let base = base_url.as_ref().trim_end_matches('/');
    OAuth2Provider::new(
        "gitlab",
        "GitLab",
        format!("{}/oauth/authorize", base),
        format!("{}/oauth/token", base),
        Some(format!("{}/api/v4/user", base)),
        ["read_user"],
        client_id,
        client_secret,
        normalize_gitlab,
    )
}

fn normalize_gitlab(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_else(|| json_string(&profile, "username").unwrap_or_default()),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "confirmed_at").is_some(),
        name: json_string(&profile, "name").or_else(|| json_string(&profile, "username")),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// Discord - OAuth2 provider
pub fn discord(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "discord",
        "Discord",
        "https://discord.com/api/oauth2/authorize",
        "https://discord.com/api/oauth2/token",
        Some("https://discord.com/api/users/@me"),
        vec!["identify", "email"],
        client_id,
        client_secret,
        normalize_discord,
    )
}

/// Discord from environment variables
pub fn discord_from_env() -> Result<OAuth2Provider> {
    let client_id = std::env::var("DISCORD_CLIENT_ID")
        .map_err(|_| Error::Config("DISCORD_CLIENT_ID not set".to_string()))?;
    let client_secret = std::env::var("DISCORD_CLIENT_SECRET")
        .map_err(|_| Error::Config("DISCORD_CLIENT_SECRET not set".to_string()))?;
    Ok(discord(client_id, client_secret))
}

fn normalize_discord(profile: serde_json::Value) -> Result<User> {
    let id = json_string(&profile, "id").unwrap_or_default();
    let avatar = json_string(&profile, "avatar");
    let image = avatar.map(|hash| {
        let ext = if hash.starts_with("a_") { "gif" } else { "png" };
        format!("https://cdn.discordapp.com/avatars/{}/{}.{}", id, hash, ext)
    });

    Ok(User {
        id: id.clone(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "verified").unwrap_or(false),
        name: json_string(&profile, "global_name").or_else(|| json_string(&profile, "username")),
        image,
        raw: profile,
    })
}

/// Spotify - OAuth2 provider
pub fn spotify(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "spotify",
        "Spotify",
        "https://accounts.spotify.com/authorize",
        "https://accounts.spotify.com/api/token",
        Some("https://api.spotify.com/v1/me"),
        vec!["user-read-email", "user-read-private"],
        client_id,
        client_secret,
        normalize_spotify,
    )
}

fn normalize_spotify(profile: serde_json::Value) -> Result<User> {
    let images = profile.get("images").and_then(|v| v.as_array());
    let image = images
        .and_then(|arr| arr.first())
        .and_then(|img| json_string(img, "url"));

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true, // Spotify verifies emails
        name: json_string(&profile, "display_name"),
        image,
        raw: profile,
    })
}

/// Twitch - OIDC provider
pub fn twitch(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://id.twitch.tv/oauth2", client_id, client_secret)
        .with_id("twitch")
        .with_name("Twitch")
        .with_scopes(vec!["openid".to_string(), "user:read:email".to_string()])
}

/// Slack - OIDC provider
pub fn slack(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://slack.com", client_id, client_secret)
        .with_id("slack")
        .with_name("Slack")
}

/// LinkedIn - OIDC provider
pub fn linkedin(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://www.linkedin.com/oauth", client_id, client_secret)
        .with_id("linkedin")
        .with_name("LinkedIn")
}

/// Facebook - OAuth2 provider
pub fn facebook(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "facebook",
        "Facebook",
        "https://www.facebook.com/v19.0/dialog/oauth",
        "https://graph.facebook.com/oauth/access_token",
        Some("https://graph.facebook.com/me?fields=id,name,email,picture"),
        vec!["email"],
        client_id,
        client_secret,
        normalize_facebook,
    )
}

fn normalize_facebook(profile: serde_json::Value) -> Result<User> {
    let picture = profile
        .get("picture")
        .and_then(|p| p.get("data"))
        .and_then(|d| json_string(d, "url"));

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true, // Facebook verifies emails
        name: json_string(&profile, "name"),
        image: picture,
        raw: profile,
    })
}

/// Twitter/X - OAuth2 provider
pub fn twitter(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "twitter",
        "X",
        "https://x.com/i/oauth2/authorize",
        "https://api.x.com/2/oauth2/token",
        Some("https://api.x.com/2/users/me?user.fields=profile_image_url"),
        vec!["users.read", "tweet.read", "offline.access"],
        client_id,
        client_secret,
        normalize_twitter,
    )
}

fn normalize_twitter(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&data, "id").unwrap_or_default(),
        email: None, // Twitter doesn't provide email through this scope
        email_verified: false,
        name: json_string(&data, "name").or_else(|| json_string(&data, "username")),
        image: json_string(&data, "profile_image_url"),
        raw: profile,
    })
}

/// Reddit - OAuth2 provider
pub fn reddit(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "reddit",
        "Reddit",
        "https://www.reddit.com/api/v1/authorize",
        "https://www.reddit.com/api/v1/access_token",
        Some("https://oauth.reddit.com/api/v1/me"),
        vec!["identity"],
        client_id,
        client_secret,
        normalize_reddit,
    )
}

fn normalize_reddit(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: None, // Reddit doesn't provide email
        email_verified: false,
        name: json_string(&profile, "name"),
        image: json_string(&profile, "icon_img")
            .map(|url| url.split('?').next().unwrap_or(&url).to_string()),
        raw: profile,
    })
}

/// Bitbucket - OAuth2 provider
pub fn bitbucket(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "bitbucket",
        "Bitbucket",
        "https://bitbucket.org/site/oauth2/authorize",
        "https://bitbucket.org/site/oauth2/access_token",
        Some("https://api.bitbucket.org/2.0/user"),
        vec!["account", "email"],
        client_id,
        client_secret,
        normalize_bitbucket,
    )
}

fn normalize_bitbucket(profile: serde_json::Value) -> Result<User> {
    let links = profile.get("links");
    let avatar = links
        .and_then(|l| l.get("avatar"))
        .and_then(|a| json_string(a, "href"));

    Ok(User {
        id: json_string(&profile, "uuid").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true,
        name: json_string(&profile, "display_name").or_else(|| json_string(&profile, "username")),
        image: avatar,
        raw: profile,
    })
}

/// Dropbox - OAuth2 provider
pub fn dropbox(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "dropbox",
        "Dropbox",
        "https://www.dropbox.com/oauth2/authorize",
        "https://api.dropboxapi.com/oauth2/token",
        Some("https://api.dropboxapi.com/2/users/get_current_account"),
        vec!["account_info.read"],
        client_id,
        client_secret,
        normalize_dropbox,
    )
}

fn normalize_dropbox(profile: serde_json::Value) -> Result<User> {
    let name = profile.get("name");
    let display_name = name.and_then(|n| json_string(n, "display_name"));

    Ok(User {
        id: json_string(&profile, "account_id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: display_name,
        image: json_string(&profile, "profile_photo_url"),
        raw: profile,
    })
}

/// Atlassian - OAuth2 provider
pub fn atlassian(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "atlassian",
        "Atlassian",
        "https://auth.atlassian.com/authorize",
        "https://auth.atlassian.com/oauth/token",
        Some("https://api.atlassian.com/me"),
        vec!["read:me"],
        client_id,
        client_secret,
        normalize_atlassian,
    )
}

fn normalize_atlassian(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "account_id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: json_string(&profile, "name"),
        image: json_string(&profile, "picture"),
        raw: profile,
    })
}

/// Notion - OAuth2 provider
pub fn notion(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "notion",
        "Notion",
        "https://api.notion.com/v1/oauth/authorize",
        "https://api.notion.com/v1/oauth/token",
        Option::<String>::None, // Notion returns user info in token response
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_notion,
    )
}

fn normalize_notion(profile: serde_json::Value) -> Result<User> {
    // Notion returns owner info in the token response
    let owner = profile.get("owner").and_then(|o| o.get("user")).cloned();
    let user = owner.unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&user, "id").unwrap_or_default(),
        email: json_string(&user, "person").and_then(|_| {
            profile
                .get("owner")
                .and_then(|o| o.get("user"))
                .and_then(|u| u.get("person"))
                .and_then(|p| json_string(p, "email"))
        }),
        email_verified: true,
        name: json_string(&user, "name"),
        image: json_string(&user, "avatar_url"),
        raw: profile,
    })
}

/// Figma - OAuth2 provider
pub fn figma(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "figma",
        "Figma",
        "https://www.figma.com/oauth",
        "https://api.figma.com/v1/oauth/token",
        Some("https://api.figma.com/v1/me"),
        vec!["files:read"],
        client_id,
        client_secret,
        normalize_figma,
    )
}

fn normalize_figma(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true,
        name: json_string(&profile, "handle"),
        image: json_string(&profile, "img_url"),
        raw: profile,
    })
}

/// Zoom - OAuth2 provider
pub fn zoom(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "zoom",
        "Zoom",
        "https://zoom.us/oauth/authorize",
        "https://zoom.us/oauth/token",
        Some("https://api.zoom.us/v2/users/me"),
        vec!["user:read"],
        client_id,
        client_secret,
        normalize_zoom,
    )
}

fn normalize_zoom(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "verified").unwrap_or(false),
        name: json_string_any(&profile, &["display_name", "first_name"]),
        image: json_string(&profile, "pic_url"),
        raw: profile,
    })
}

/// Strava - OAuth2 provider
pub fn strava(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "strava",
        "Strava",
        "https://www.strava.com/api/v3/oauth/authorize",
        "https://www.strava.com/api/v3/oauth/token",
        Some("https://www.strava.com/api/v3/athlete"),
        vec!["read"],
        client_id,
        client_secret,
        normalize_strava,
    )
}

fn normalize_strava(profile: serde_json::Value) -> Result<User> {
    let first = json_string(&profile, "firstname").unwrap_or_default();
    let last = json_string(&profile, "lastname").unwrap_or_default();
    let name = if !first.is_empty() || !last.is_empty() {
        Some(format!("{} {}", first, last).trim().to_string())
    } else {
        None
    };

    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true,
        name,
        image: json_string(&profile, "profile"),
        raw: profile,
    })
}

/// Patreon - OAuth2 provider
pub fn patreon(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "patreon",
        "Patreon",
        "https://www.patreon.com/oauth2/authorize",
        "https://www.patreon.com/api/oauth2/token",
        Some("https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=email,full_name,image_url"),
        vec!["identity", "identity[email]"],
        client_id,
        client_secret,
        normalize_patreon,
    )
}

fn normalize_patreon(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());
    let attributes = data.get("attributes").cloned().unwrap_or(data.clone());

    Ok(User {
        id: json_string(&data, "id").unwrap_or_default(),
        email: json_string(&attributes, "email"),
        email_verified: json_bool(&attributes, "is_email_verified").unwrap_or(false),
        name: json_string(&attributes, "full_name"),
        image: json_string(&attributes, "image_url"),
        raw: profile,
    })
}

/// Battle.net - OIDC provider (defaults to US region)
pub fn battlenet(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    battlenet_region("us", client_id, client_secret)
}

/// Battle.net with specific region (us, eu, kr, tw, cn)
pub fn battlenet_region(
    region: &str,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = match region {
        "cn" => "https://www.battlenet.com.cn/oauth",
        "eu" => "https://eu.battle.net/oauth",
        "kr" => "https://kr.battle.net/oauth",
        "tw" => "https://tw.battle.net/oauth",
        _ => "https://oauth.battle.net", // US default
    };

    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("battlenet")
        .with_name("Battle.net")
}

/// LINE - OIDC provider
pub fn line(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://access.line.me", client_id, client_secret)
        .with_id("line")
        .with_name("LINE")
}

/// Kakao - OAuth2 provider
pub fn kakao(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "kakao",
        "Kakao",
        "https://kauth.kakao.com/oauth/authorize",
        "https://kauth.kakao.com/oauth/token",
        Some("https://kapi.kakao.com/v2/user/me"),
        vec!["profile_nickname", "profile_image", "account_email"],
        client_id,
        client_secret,
        normalize_kakao,
    )
}

fn normalize_kakao(profile: serde_json::Value) -> Result<User> {
    let kakao_account = profile.get("kakao_account");
    let kakao_profile = kakao_account.and_then(|a| a.get("profile"));

    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: kakao_account.and_then(|a| json_string(a, "email")),
        email_verified: kakao_account
            .and_then(|a| json_bool(a, "is_email_verified"))
            .unwrap_or(false),
        name: kakao_profile.and_then(|p| json_string(p, "nickname")),
        image: kakao_profile.and_then(|p| json_string(p, "profile_image_url")),
        raw: profile,
    })
}

/// Naver - OAuth2 provider
pub fn naver(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "naver",
        "Naver",
        "https://nid.naver.com/oauth2.0/authorize",
        "https://nid.naver.com/oauth2.0/token",
        Some("https://openapi.naver.com/v1/nid/me"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_naver,
    )
}

fn normalize_naver(profile: serde_json::Value) -> Result<User> {
    let response = profile.get("response").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&response, "id").unwrap_or_default(),
        email: json_string(&response, "email"),
        email_verified: true,
        name: json_string(&response, "name").or_else(|| json_string(&response, "nickname")),
        image: json_string(&response, "profile_image"),
        raw: profile,
    })
}

/// VK - OAuth2 provider
pub fn vk(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "vk",
        "VK",
        "https://oauth.vk.com/authorize",
        "https://oauth.vk.com/access_token",
        Some("https://api.vk.com/method/users.get?fields=photo_100&v=5.131"),
        vec!["email"],
        client_id,
        client_secret,
        normalize_vk,
    )
}

fn normalize_vk(profile: serde_json::Value) -> Result<User> {
    let response = profile
        .get("response")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or(profile.clone());

    let first = json_string(&response, "first_name").unwrap_or_default();
    let last = json_string(&response, "last_name").unwrap_or_default();
    let name = if !first.is_empty() || !last.is_empty() {
        Some(format!("{} {}", first, last).trim().to_string())
    } else {
        None
    };

    Ok(User {
        id: response
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: json_string(&profile, "email"), // Email comes from token response
        email_verified: true,
        name,
        image: json_string(&response, "photo_100"),
        raw: profile,
    })
}

/// Yandex - OAuth2 provider
pub fn yandex(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "yandex",
        "Yandex",
        "https://oauth.yandex.ru/authorize",
        "https://oauth.yandex.ru/token",
        Some("https://login.yandex.ru/info?format=json"),
        vec!["login:email", "login:info", "login:avatar"],
        client_id,
        client_secret,
        normalize_yandex,
    )
}

fn normalize_yandex(profile: serde_json::Value) -> Result<User> {
    let avatar_id = json_string(&profile, "default_avatar_id");
    let image =
        avatar_id.map(|id| format!("https://avatars.yandex.net/get-yapic/{}/islands-200", id));

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "default_email"),
        email_verified: true,
        name: json_string(&profile, "display_name").or_else(|| json_string(&profile, "real_name")),
        image,
        raw: profile,
    })
}

/// Coinbase - OAuth2 provider
pub fn coinbase(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "coinbase",
        "Coinbase",
        "https://login.coinbase.com/oauth2/auth",
        "https://login.coinbase.com/oauth2/token",
        Some("https://api.coinbase.com/v2/user"),
        vec!["wallet:user:read", "wallet:user:email"],
        client_id,
        client_secret,
        normalize_coinbase,
    )
}

fn normalize_coinbase(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&data, "id").unwrap_or_default(),
        email: json_string(&data, "email"),
        email_verified: true,
        name: json_string(&data, "name"),
        image: json_string(&data, "avatar_url"),
        raw: profile,
    })
}

/// Box - OAuth2 provider
pub fn box_provider(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "box",
        "Box",
        "https://account.box.com/api/oauth2/authorize",
        "https://api.box.com/oauth2/token",
        Some("https://api.box.com/2.0/users/me"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_box,
    )
}

fn normalize_box(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "login"),
        email_verified: true,
        name: json_string(&profile, "name"),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// Hubspot - OAuth2 provider
pub fn hubspot(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "hubspot",
        "HubSpot",
        "https://app.hubspot.com/oauth/authorize",
        "https://api.hubapi.com/oauth/v1/token",
        Some("https://api.hubapi.com/oauth/v1/access-tokens"),
        vec!["oauth"],
        client_id,
        client_secret,
        normalize_hubspot,
    )
}

fn normalize_hubspot(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "user_id")
            .or_else(|| json_string(&profile, "hub_id"))
            .unwrap_or_default(),
        email: json_string(&profile, "user"),
        email_verified: true,
        name: None,
        image: None,
        raw: profile,
    })
}

/// Instagram - OAuth2 provider
pub fn instagram(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "instagram",
        "Instagram",
        "https://api.instagram.com/oauth/authorize",
        "https://api.instagram.com/oauth/access_token",
        Some("https://graph.instagram.com/me?fields=id,username,account_type"),
        vec!["user_profile"],
        client_id,
        client_secret,
        normalize_instagram,
    )
}

fn normalize_instagram(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: None, // Instagram doesn't provide email
        email_verified: false,
        name: json_string(&profile, "username"),
        image: None,
        raw: profile,
    })
}

/// TikTok - OAuth2 provider
pub fn tiktok(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "tiktok",
        "TikTok",
        "https://www.tiktok.com/v2/auth/authorize",
        "https://open.tiktokapis.com/v2/oauth/token/",
        Some("https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_url,display_name,username"),
        vec!["user.info.basic"],
        client_id,
        client_secret,
        normalize_tiktok,
    )
}

fn normalize_tiktok(profile: serde_json::Value) -> Result<User> {
    let data = profile
        .get("data")
        .and_then(|d| d.get("user"))
        .cloned()
        .unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&data, "open_id").unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&data, "display_name").or_else(|| json_string(&data, "username")),
        image: json_string(&data, "avatar_url"),
        raw: profile,
    })
}

/// Salesforce - OIDC provider
pub fn salesforce(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://login.salesforce.com", client_id, client_secret)
        .with_id("salesforce")
        .with_name("Salesforce")
}

/// Zoho - OAuth2 provider
pub fn zoho(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "zoho",
        "Zoho",
        "https://accounts.zoho.com/oauth/v2/auth",
        "https://accounts.zoho.com/oauth/v2/token",
        Some("https://accounts.zoho.com/oauth/user/info"),
        vec!["AaaServer.profile.Read"],
        client_id,
        client_secret,
        normalize_zoho,
    )
}

fn normalize_zoho(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "ZUID").unwrap_or_default(),
        email: json_string(&profile, "Email"),
        email_verified: true,
        name: json_string(&profile, "Display_Name").or_else(|| {
            let first = json_string(&profile, "First_Name").unwrap_or_default();
            let last = json_string(&profile, "Last_Name").unwrap_or_default();
            if !first.is_empty() || !last.is_empty() {
                Some(format!("{} {}", first, last).trim().to_string())
            } else {
                None
            }
        }),
        image: None,
        raw: profile,
    })
}

/// Webex - OAuth2 provider
pub fn webex(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "webex",
        "Webex",
        "https://webexapis.com/v1/authorize",
        "https://webexapis.com/v1/access_token",
        Some("https://webexapis.com/v1/people/me"),
        vec!["spark:people_read"],
        client_id,
        client_secret,
        normalize_webex,
    )
}

fn normalize_webex(profile: serde_json::Value) -> Result<User> {
    let emails = profile.get("emails").and_then(|e| e.as_array());
    let email = emails
        .and_then(|arr| arr.first())
        .and_then(|e| e.as_str())
        .map(|s| s.to_string());

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email,
        email_verified: true,
        name: json_string(&profile, "displayName"),
        image: json_string(&profile, "avatar"),
        raw: profile,
    })
}

/// Pinterest - OAuth2 provider
pub fn pinterest(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "pinterest",
        "Pinterest",
        "https://www.pinterest.com/oauth/",
        "https://api.pinterest.com/v5/oauth/token",
        Some("https://api.pinterest.com/v5/user_account"),
        vec!["user_accounts:read"],
        client_id,
        client_secret,
        normalize_pinterest,
    )
}

fn normalize_pinterest(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&profile, "username"),
        image: json_string(&profile, "profile_image"),
        raw: profile,
    })
}

/// osu! - OAuth2 provider
pub fn osu(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "osu",
        "osu!",
        "https://osu.ppy.sh/oauth/authorize",
        "https://osu.ppy.sh/oauth/token",
        Some("https://osu.ppy.sh/api/v2/me"),
        vec!["identify"],
        client_id,
        client_secret,
        normalize_osu,
    )
}

fn normalize_osu(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&profile, "username"),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// EVE Online - OAuth2 provider
pub fn eveonline(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "eveonline",
        "EVE Online",
        "https://login.eveonline.com/v2/oauth/authorize",
        "https://login.eveonline.com/v2/oauth/token",
        Some("https://esi.evetech.net/verify/"),
        vec!["publicData"],
        client_id,
        client_secret,
        normalize_eveonline,
    )
}

fn normalize_eveonline(profile: serde_json::Value) -> Result<User> {
    let character_id = json_string(&profile, "CharacterID")
        .or_else(|| {
            profile
                .get("CharacterID")
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string())
        })
        .unwrap_or_default();
    let image = if !character_id.is_empty() {
        Some(format!(
            "https://images.evetech.net/characters/{}/portrait",
            character_id
        ))
    } else {
        None
    };

    Ok(User {
        id: character_id,
        email: None,
        email_verified: false,
        name: json_string(&profile, "CharacterName"),
        image,
        raw: profile,
    })
}

/// Bungie - OAuth2 provider
pub fn bungie(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "bungie",
        "Bungie",
        "https://www.bungie.net/en/OAuth/Authorize",
        "https://www.bungie.net/platform/app/oauth/token/",
        Some("https://www.bungie.net/platform/User/GetMembershipsForCurrentUser/"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_bungie,
    )
}

fn normalize_bungie(profile: serde_json::Value) -> Result<User> {
    let response = profile.get("Response").cloned().unwrap_or(profile.clone());
    let bungie_user = response
        .get("bungieNetUser")
        .cloned()
        .unwrap_or(response.clone());

    let membership_id = json_string(&bungie_user, "membershipId")
        .or_else(|| {
            bungie_user
                .get("membershipId")
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string())
        })
        .unwrap_or_default();

    let icon_path = json_string(&bungie_user, "profilePicturePath");
    let image = icon_path.map(|path| format!("https://www.bungie.net{}", path));

    Ok(User {
        id: membership_id,
        email: None,
        email_verified: false,
        name: json_string(&bungie_user, "displayName"),
        image,
        raw: profile,
    })
}

/// Mastodon - OAuth2 provider (requires instance URL)
pub fn mastodon(
    instance_url: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    let base = instance_url.as_ref().trim_end_matches('/');
    OAuth2Provider::new(
        "mastodon",
        "Mastodon",
        format!("{}/oauth/authorize", base),
        format!("{}/oauth/token", base),
        Some(format!("{}/api/v1/accounts/verify_credentials", base)),
        ["read:accounts"],
        client_id,
        client_secret,
        normalize_mastodon,
    )
}

fn normalize_mastodon(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: None, // Mastodon doesn't provide email by default
        email_verified: false,
        name: json_string(&profile, "display_name").or_else(|| json_string(&profile, "username")),
        image: json_string(&profile, "avatar"),
        raw: profile,
    })
}

/// Mattermost - OAuth2 provider
pub fn mattermost(
    base_url: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    let base = base_url.as_ref().trim_end_matches('/');
    OAuth2Provider::new(
        "mattermost",
        "Mattermost",
        format!("{}/oauth/authorize", base),
        format!("{}/oauth/access_token", base),
        Some(format!("{}/api/v4/users/me", base)),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_mattermost,
    )
}

fn normalize_mattermost(profile: serde_json::Value) -> Result<User> {
    let first = json_string(&profile, "first_name").unwrap_or_default();
    let last = json_string(&profile, "last_name").unwrap_or_default();
    let name = if !first.is_empty() || !last.is_empty() {
        Some(format!("{} {}", first, last).trim().to_string())
    } else {
        json_string(&profile, "username")
    };

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name,
        image: None, // Mattermost avatar requires base URL
        raw: profile,
    })
}

/// Medium - OAuth2 provider
pub fn medium(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "medium",
        "Medium",
        "https://medium.com/m/oauth/authorize",
        "https://api.medium.com/v1/tokens",
        Some("https://api.medium.com/v1/me"),
        vec!["basicProfile"],
        client_id,
        client_secret,
        normalize_medium,
    )
}

fn normalize_medium(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&data, "id").unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&data, "name").or_else(|| json_string(&data, "username")),
        image: json_string(&data, "imageUrl"),
        raw: profile,
    })
}

/// Dribbble - OAuth2 provider
pub fn dribbble(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "dribbble",
        "Dribbble",
        "https://dribbble.com/oauth/authorize",
        "https://dribbble.com/oauth/token",
        Some("https://api.dribbble.com/v2/user"),
        vec!["public"],
        client_id,
        client_secret,
        normalize_dribbble,
    )
}

fn normalize_dribbble(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&profile, "name").or_else(|| json_string(&profile, "login")),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// Foursquare - OAuth2 provider
pub fn foursquare(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "foursquare",
        "Foursquare",
        "https://foursquare.com/oauth2/authenticate",
        "https://foursquare.com/oauth2/access_token",
        Some("https://api.foursquare.com/v2/users/self?v=20230131"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_foursquare,
    )
}

fn normalize_foursquare(profile: serde_json::Value) -> Result<User> {
    let response = profile
        .get("response")
        .and_then(|r| r.get("user"))
        .cloned()
        .unwrap_or(profile.clone());

    let first = json_string(&response, "firstName").unwrap_or_default();
    let last = json_string(&response, "lastName").unwrap_or_default();
    let name = if !first.is_empty() || !last.is_empty() {
        Some(format!("{} {}", first, last).trim().to_string())
    } else {
        None
    };

    let photo = response.get("photo");
    let image = photo.and_then(|p| {
        let prefix = json_string(p, "prefix")?;
        let suffix = json_string(p, "suffix")?;
        Some(format!("{}original{}", prefix, suffix))
    });

    Ok(User {
        id: json_string(&response, "id").unwrap_or_default(),
        email: response
            .get("contact")
            .and_then(|c| json_string(c, "email")),
        email_verified: true,
        name,
        image,
        raw: profile,
    })
}

/// Trakt - OAuth2 provider
pub fn trakt(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "trakt",
        "Trakt",
        "https://trakt.tv/oauth/authorize",
        "https://api.trakt.tv/oauth/token",
        Some("https://api.trakt.tv/users/me?extended=full"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_trakt,
    )
}

fn normalize_trakt(profile: serde_json::Value) -> Result<User> {
    let ids = profile.get("ids");
    let id = ids
        .and_then(|i| json_string(i, "slug"))
        .or_else(|| json_string(&profile, "username"))
        .unwrap_or_default();

    let images = profile.get("images");
    let image = images
        .and_then(|i| i.get("avatar"))
        .and_then(|a| json_string(a, "full"));

    Ok(User {
        id,
        email: None,
        email_verified: false,
        name: json_string(&profile, "name").or_else(|| json_string(&profile, "username")),
        image,
        raw: profile,
    })
}

/// Todoist - OAuth2 provider
pub fn todoist(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "todoist",
        "Todoist",
        "https://todoist.com/oauth/authorize",
        "https://todoist.com/oauth/access_token",
        Some("https://api.todoist.com/sync/v9/sync?resource_types=[\"user\"]"),
        vec!["data:read"],
        client_id,
        client_secret,
        normalize_todoist,
    )
}

fn normalize_todoist(profile: serde_json::Value) -> Result<User> {
    let user = profile.get("user").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: user
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .or_else(|| json_string(&user, "id"))
            .unwrap_or_default(),
        email: json_string(&user, "email"),
        email_verified: true,
        name: json_string(&user, "full_name"),
        image: json_string(&user, "avatar_big").or_else(|| json_string(&user, "avatar_medium")),
        raw: profile,
    })
}

/// ClickUp - OAuth2 provider
pub fn clickup(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "clickup",
        "ClickUp",
        "https://app.clickup.com/api",
        "https://api.clickup.com/api/v2/oauth/token",
        Some("https://api.clickup.com/api/v2/user"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_clickup,
    )
}

fn normalize_clickup(profile: serde_json::Value) -> Result<User> {
    let user = profile.get("user").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: user
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .or_else(|| json_string(&user, "id"))
            .unwrap_or_default(),
        email: json_string(&user, "email"),
        email_verified: true,
        name: json_string(&user, "username"),
        image: json_string(&user, "profilePicture"),
        raw: profile,
    })
}

/// Pipedrive - OAuth2 provider
pub fn pipedrive(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "pipedrive",
        "Pipedrive",
        "https://oauth.pipedrive.com/oauth/authorize",
        "https://oauth.pipedrive.com/oauth/token",
        Some("https://api.pipedrive.com/v1/users/me"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_pipedrive,
    )
}

fn normalize_pipedrive(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: data
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .or_else(|| json_string(&data, "id"))
            .unwrap_or_default(),
        email: json_string(&data, "email"),
        email_verified: json_bool(&data, "activated").unwrap_or(false),
        name: json_string(&data, "name"),
        image: json_string(&data, "icon_url"),
        raw: profile,
    })
}

/// FreshBooks - OAuth2 provider
pub fn freshbooks(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "freshbooks",
        "FreshBooks",
        "https://auth.freshbooks.com/service/auth/oauth/authorize",
        "https://api.freshbooks.com/auth/oauth/token",
        Some("https://api.freshbooks.com/auth/api/v1/users/me"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_freshbooks,
    )
}

fn normalize_freshbooks(profile: serde_json::Value) -> Result<User> {
    let response = profile.get("response").cloned().unwrap_or(profile.clone());

    let first = json_string(&response, "first_name").unwrap_or_default();
    let last = json_string(&response, "last_name").unwrap_or_default();
    let name = if !first.is_empty() || !last.is_empty() {
        Some(format!("{} {}", first, last).trim().to_string())
    } else {
        None
    };

    Ok(User {
        id: response
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .or_else(|| json_string(&response, "id"))
            .unwrap_or_default(),
        email: json_string(&response, "email"),
        email_verified: json_bool(&response, "confirmed_at").is_some(),
        name,
        image: None,
        raw: profile,
    })
}

/// Mailchimp - OAuth2 provider
pub fn mailchimp(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "mailchimp",
        "Mailchimp",
        "https://login.mailchimp.com/oauth2/authorize",
        "https://login.mailchimp.com/oauth2/token",
        Some("https://login.mailchimp.com/oauth2/metadata"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_mailchimp,
    )
}

fn normalize_mailchimp(profile: serde_json::Value) -> Result<User> {
    let login = profile.get("login").cloned().unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&login, "login_id")
            .or_else(|| json_string(&profile, "user_id"))
            .unwrap_or_default(),
        email: json_string(&login, "email"),
        email_verified: true,
        name: json_string(&login, "login_name"),
        image: json_string(&login, "avatar"),
        raw: profile,
    })
}

/// WordPress.com - OAuth2 provider
pub fn wordpress(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "wordpress",
        "WordPress.com",
        "https://public-api.wordpress.com/oauth2/authorize",
        "https://public-api.wordpress.com/oauth2/token",
        Some("https://public-api.wordpress.com/rest/v1/me"),
        vec!["auth"],
        client_id,
        client_secret,
        normalize_wordpress,
    )
}

fn normalize_wordpress(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: profile
            .get("ID")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .or_else(|| json_string(&profile, "ID"))
            .unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: json_string(&profile, "display_name").or_else(|| json_string(&profile, "username")),
        image: json_string(&profile, "avatar_URL"),
        raw: profile,
    })
}

/// Wikimedia - OAuth2 provider
pub fn wikimedia(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "wikimedia",
        "Wikimedia",
        "https://meta.wikimedia.org/w/rest.php/oauth2/authorize",
        "https://meta.wikimedia.org/w/rest.php/oauth2/access_token",
        Some("https://meta.wikimedia.org/w/rest.php/oauth2/resource/profile"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_wikimedia,
    )
}

fn normalize_wikimedia(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "sub")
            .or_else(|| {
                profile
                    .get("sub")
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string())
            })
            .unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: json_string(&profile, "username"),
        image: None,
        raw: profile,
    })
}

/// Netlify - OAuth2 provider
pub fn netlify(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "netlify",
        "Netlify",
        "https://app.netlify.com/authorize",
        "https://api.netlify.com/oauth/token",
        Some("https://api.netlify.com/api/v1/user"),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_netlify,
    )
}

fn normalize_netlify(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "confirmed_at").is_some(),
        name: json_string(&profile, "full_name"),
        image: json_string(&profile, "avatar_url"),
        raw: profile,
    })
}

/// Nextcloud - OAuth2 provider
pub fn nextcloud(
    base_url: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    let base = base_url.as_ref().trim_end_matches('/');
    OAuth2Provider::new(
        "nextcloud",
        "Nextcloud",
        format!("{}/apps/oauth2/authorize", base),
        format!("{}/apps/oauth2/api/v1/token", base),
        Some(format!("{}/ocs/v2.php/cloud/user?format=json", base)),
        Vec::<String>::new(),
        client_id,
        client_secret,
        normalize_nextcloud,
    )
}

fn normalize_nextcloud(profile: serde_json::Value) -> Result<User> {
    let ocs = profile
        .get("ocs")
        .and_then(|o| o.get("data"))
        .cloned()
        .unwrap_or(profile.clone());

    Ok(User {
        id: json_string(&ocs, "id").unwrap_or_default(),
        email: json_string(&ocs, "email"),
        email_verified: json_bool(&ocs, "email_verified").unwrap_or(false),
        name: json_string(&ocs, "displayname").or_else(|| json_string(&ocs, "display-name")),
        image: None,
        raw: profile,
    })
}

/// Threads - OAuth2 provider (Meta)
pub fn threads(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "threads",
        "Threads",
        "https://threads.net/oauth/authorize",
        "https://graph.threads.net/oauth/access_token",
        Some("https://graph.threads.net/v1.0/me?fields=id,username,threads_profile_picture_url,threads_biography"),
        vec!["threads_basic"],
        client_id,
        client_secret,
        normalize_threads,
    )
}

fn normalize_threads(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: None,
        email_verified: false,
        name: json_string(&profile, "username"),
        image: json_string(&profile, "threads_profile_picture_url"),
        raw: profile,
    })
}

/// Roblox - OIDC provider
pub fn roblox(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://apis.roblox.com/oauth/", client_id, client_secret)
        .with_id("roblox")
        .with_name("Roblox")
        .with_scopes(vec!["openid".to_string(), "profile".to_string()])
}

/// HuggingFace - OIDC provider
pub fn huggingface(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://huggingface.co", client_id, client_secret)
        .with_id("huggingface")
        .with_name("Hugging Face")
        .with_scopes(vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ])
}

// ============================================================================
// Additional Providers (matching NextAuth.js)
// ============================================================================

/// Apple - OIDC provider
/// Note: Apple requires HTTPS and doesn't support localhost.
/// The client secret must be a JWT.
pub fn apple(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://appleid.apple.com", client_id, client_secret)
        .with_id("apple")
        .with_name("Apple")
        .with_scopes(vec!["name".to_string(), "email".to_string()])
}

/// 42 School - OAuth2 provider
pub fn fortytwo_school(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "42-school",
        "42 School",
        "https://api.intra.42.fr/oauth/authorize",
        "https://api.intra.42.fr/oauth/token",
        Some("https://api.intra.42.fr/v2/me"),
        vec!["public"],
        client_id,
        client_secret,
        normalize_fortytwo_school,
    )
}

fn normalize_fortytwo_school(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: profile
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true,
        name: json_string(&profile, "usual_full_name").or_else(|| json_string(&profile, "login")),
        image: profile.get("image").and_then(|i| json_string(i, "link")),
        raw: profile,
    })
}

/// Azure AD B2C - OIDC provider
pub fn azure_ad_b2c(
    tenant_name: impl AsRef<str>,
    user_flow: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}.b2clogin.com/{}.onmicrosoft.com/{}/v2.0",
        tenant_name.as_ref(),
        tenant_name.as_ref(),
        user_flow.as_ref()
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("azure-ad-b2c")
        .with_name("Azure AD B2C")
}

/// Azure DevOps - OAuth2 provider
/// Note: Microsoft recommends using Microsoft Entra ID instead.
pub fn azure_devops(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "azure-devops",
        "Azure DevOps",
        "https://app.vssps.visualstudio.com/oauth2/authorize",
        "https://app.vssps.visualstudio.com/oauth2/token",
        Some("https://app.vssps.visualstudio.com/_apis/profile/profiles/me?details=true&coreAttributes=Avatar&api-version=6.0"),
        vec!["vso.profile"],
        client_id,
        client_secret,
        normalize_azure_devops,
    )
}

fn normalize_azure_devops(profile: serde_json::Value) -> Result<User> {
    let avatar = profile
        .get("coreAttributes")
        .and_then(|c| c.get("Avatar"))
        .and_then(|a| a.get("value"))
        .and_then(|v| json_string(v, "value"));

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "emailAddress"),
        email_verified: true,
        name: json_string(&profile, "displayName"),
        image: avatar,
        raw: profile,
    })
}

/// Eventbrite - OAuth2 provider
pub fn eventbrite(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "eventbrite",
        "Eventbrite",
        "https://www.eventbrite.com/oauth/authorize",
        "https://www.eventbrite.com/oauth/token",
        Some("https://www.eventbriteapi.com/v3/users/me/"),
        vec!["user.profile"],
        client_id,
        client_secret,
        normalize_eventbrite,
    )
}

fn normalize_eventbrite(profile: serde_json::Value) -> Result<User> {
    let emails = profile.get("emails").and_then(|e| e.as_array());
    let email = emails
        .and_then(|arr| {
            arr.iter()
                .find(|e| e.get("primary").and_then(|p| p.as_bool()).unwrap_or(false))
        })
        .and_then(|e| json_string(e, "email"))
        .or_else(|| {
            emails
                .and_then(|arr| arr.first())
                .and_then(|e| json_string(e, "email"))
        });

    let image_id = json_string(&profile, "image_id");
    let image = image_id.map(|id| {
        format!(
            "https://img.evbuc.com/https%3A%2F%2Fcdn.evbuc.com%2Fimages%2F{}%2F",
            id
        )
    });

    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email,
        email_verified: true,
        name: json_string(&profile, "name"),
        image,
        raw: profile,
    })
}

/// FACEIT - OAuth2 provider
pub fn faceit(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "faceit",
        "FACEIT",
        "https://accounts.faceit.com/accounts?redirect_popup=true",
        "https://api.faceit.com/auth/v1/oauth/token",
        Some("https://api.faceit.com/auth/v1/resources/userinfo"),
        vec!["openid", "email", "profile"],
        client_id,
        client_secret,
        normalize_faceit,
    )
}

fn normalize_faceit(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "guid").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: true,
        name: json_string(&profile, "name").or_else(|| json_string(&profile, "nickname")),
        image: json_string(&profile, "picture"),
        raw: profile,
    })
}

/// Mail.ru - OAuth2 provider
pub fn mailru(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "mailru",
        "Mail.ru",
        "https://oauth.mail.ru/login",
        "https://oauth.mail.ru/token",
        Some("https://oauth.mail.ru/userinfo"),
        vec!["userinfo"],
        client_id,
        client_secret,
        normalize_mailru,
    )
}

fn normalize_mailru(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "id").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: json_string(&profile, "name"),
        image: json_string(&profile, "picture"),
        raw: profile,
    })
}

/// SimpleLogin - OIDC provider
pub fn simplelogin(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new("https://app.simplelogin.io", client_id, client_secret)
        .with_id("simplelogin")
        .with_name("SimpleLogin")
}

/// Vipps - OIDC provider (Norwegian payment/identity)
pub fn vipps(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new(
        "https://api.vipps.no/access-management-1.0/access/",
        client_id,
        client_secret,
    )
    .with_id("vipps")
    .with_name("Vipps")
    .with_scopes(vec![
        "openid".to_string(),
        "name".to_string(),
        "email".to_string(),
    ])
}

/// Vipps test environment
pub fn vipps_test(client_id: impl Into<String>, client_secret: impl Into<String>) -> OidcProvider {
    OidcProvider::new(
        "https://apitest.vipps.no/access-management-1.0/access/",
        client_id,
        client_secret,
    )
    .with_id("vipps")
    .with_name("Vipps")
    .with_scopes(vec![
        "openid".to_string(),
        "name".to_string(),
        "email".to_string(),
    ])
}

/// Passage by 1Password - OIDC provider
pub fn passage(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("passage")
        .with_name("Passage")
}

/// Beyond Identity - OIDC provider
pub fn beyondidentity(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("beyondidentity")
        .with_name("Beyond Identity")
}

/// WeChat - OAuth2 provider
pub fn wechat(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    wechat_official_account(client_id, client_secret)
}

/// WeChat Official Account - OAuth2 provider
pub fn wechat_official_account(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "wechat",
        "WeChat",
        "https://open.weixin.qq.com/connect/oauth2/authorize",
        "https://api.weixin.qq.com/sns/oauth2/access_token",
        Some("https://api.weixin.qq.com/sns/userinfo"),
        vec!["snsapi_userinfo"],
        client_id,
        client_secret,
        normalize_wechat,
    )
}

/// WeChat Website App - OAuth2 provider (uses QR code login)
pub fn wechat_website(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        "wechat",
        "WeChat",
        "https://open.weixin.qq.com/connect/qrconnect",
        "https://api.weixin.qq.com/sns/oauth2/access_token",
        Some("https://api.weixin.qq.com/sns/userinfo"),
        vec!["snsapi_login"],
        client_id,
        client_secret,
        normalize_wechat,
    )
}

fn normalize_wechat(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "unionid")
            .or_else(|| json_string(&profile, "openid"))
            .unwrap_or_default(),
        email: None, // WeChat doesn't provide email
        email_verified: false,
        name: json_string(&profile, "nickname"),
        image: json_string(&profile, "headimgurl"),
        raw: profile,
    })
}

/// Asgardeo - OIDC provider (WSO2)
pub fn asgardeo(
    organization: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!("https://api.asgardeo.io/t/{}", organization.as_ref());
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("asgardeo")
        .with_name("Asgardeo")
}

/// Frontegg - OIDC provider
pub fn frontegg(
    domain: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    let issuer = format!(
        "https://{}",
        domain
            .as_ref()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    );
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("frontegg")
        .with_name("Frontegg")
}

/// Ory Hydra - OIDC provider
pub fn ory_hydra(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("ory-hydra")
        .with_name("Ory Hydra")
}

/// Duende IdentityServer - OIDC provider
pub fn duende_identity_server(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("duende-identity-server")
        .with_name("Duende IdentityServer")
}

/// IdentityServer4 - OIDC provider (legacy)
pub fn identity_server4(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("identity-server4")
        .with_name("IdentityServer4")
}

/// United Effects - OIDC provider
pub fn united_effects(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("united-effects")
        .with_name("United Effects")
}

/// BankID Norway - OIDC provider
pub fn bankid_no(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("bankid-no")
        .with_name("BankID Norway")
}

/// Ping Identity - OIDC provider
pub fn ping_id(
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OidcProvider {
    OidcProvider::new(issuer, client_id, client_secret)
        .with_id("ping-id")
        .with_name("Ping Identity")
}

/// NetSuite - OAuth2 provider
pub fn netsuite(
    account_id: impl AsRef<str>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    let account = account_id.as_ref().to_lowercase().replace('_', "-");
    OAuth2Provider::new(
        "netsuite",
        "NetSuite",
        format!(
            "https://{}.app.netsuite.com/app/login/oauth2/authorize.nl",
            account
        ),
        format!(
            "https://{}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
            account
        ),
        Some(format!(
            "https://{}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/userinfo",
            account
        )),
        vec!["restlets", "rest_webservices"],
        client_id,
        client_secret,
        normalize_netsuite,
    )
}

fn normalize_netsuite(profile: serde_json::Value) -> Result<User> {
    Ok(User {
        id: json_string(&profile, "sub").unwrap_or_default(),
        email: json_string(&profile, "email"),
        email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
        name: json_string(&profile, "name"),
        image: None,
        raw: profile,
    })
}

/// Concept2 - OAuth2 provider (rowing/fitness)
pub fn concept2(client_id: impl Into<String>, client_secret: impl Into<String>) -> OAuth2Provider {
    OAuth2Provider::new(
        "concept2",
        "Concept2",
        "https://log.concept2.com/oauth/authorize",
        "https://log.concept2.com/oauth/access_token",
        Some("https://log.concept2.com/api/users/me"),
        vec!["user:read"],
        client_id,
        client_secret,
        normalize_concept2,
    )
}

fn normalize_concept2(profile: serde_json::Value) -> Result<User> {
    let data = profile.get("data").cloned().unwrap_or(profile.clone());
    Ok(User {
        id: data
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        email: json_string(&data, "email"),
        email_verified: true,
        name: json_string(&data, "username").or_else(|| {
            let first = json_string(&data, "first_name").unwrap_or_default();
            let last = json_string(&data, "last_name").unwrap_or_default();
            if !first.is_empty() || !last.is_empty() {
                Some(format!("{} {}", first, last).trim().to_string())
            } else {
                None
            }
        }),
        image: None,
        raw: profile,
    })
}

/// Generic OAuth2 provider - use for any OAuth2-compliant identity provider
pub fn oauth2(
    id: impl Into<String>,
    name: impl Into<String>,
    authorization_url: impl Into<String>,
    token_url: impl Into<String>,
    userinfo_url: Option<impl Into<String>>,
    scopes: impl IntoIterator<Item = impl Into<String>>,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Provider {
    OAuth2Provider::new(
        id,
        name,
        authorization_url,
        token_url,
        userinfo_url.map(|u| u.into()),
        scopes,
        client_id,
        client_secret,
        |profile| {
            Ok(User {
                id: json_string(&profile, "sub")
                    .or_else(|| json_string(&profile, "id"))
                    .unwrap_or_default(),
                email: json_string(&profile, "email"),
                email_verified: json_bool(&profile, "email_verified").unwrap_or(false),
                name: json_string(&profile, "name"),
                image: json_string(&profile, "picture")
                    .or_else(|| json_string(&profile, "avatar_url")),
                raw: profile,
            })
        },
    )
}
