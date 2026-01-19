use serde::{Deserialize, Serialize};

/// Normalized user profile from OAuth providers.
///
/// This struct provides a consistent interface for user data
/// regardless of which OAuth provider was used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Provider-specific user ID
    pub id: String,

    /// User's email address (if available)
    pub email: Option<String>,

    /// Whether the email has been verified by the provider
    pub email_verified: bool,

    /// User's display name
    pub name: Option<String>,

    /// URL to the user's avatar/profile picture
    pub image: Option<String>,

    /// Raw profile data from the provider
    #[serde(default)]
    pub raw: serde_json::Value,
}

impl User {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            email: None,
            email_verified: false,
            name: None,
            image: None,
            raw: serde_json::Value::Null,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_email_verified(mut self, verified: bool) -> Self {
        self.email_verified = verified;
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    pub fn with_raw(mut self, raw: serde_json::Value) -> Self {
        self.raw = raw;
        self
    }
}
