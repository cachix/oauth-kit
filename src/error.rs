use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Failed to fetch user profile: {0}")]
    ProfileFetch(String),

    #[error("Invalid CSRF state")]
    InvalidCsrfState,

    #[error("Missing CSRF state")]
    MissingCsrfState,

    #[error("Missing authorization code")]
    MissingCode,

    #[error("Session error: {0}")]
    Session(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parsing error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("User store error: {0}")]
    Store(String),
}

pub type Result<T> = std::result::Result<T, Error>;
