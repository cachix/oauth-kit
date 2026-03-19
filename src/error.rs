use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Failed to fetch user profile: {0}")]
    ProfileFetch(String),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parsing error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
