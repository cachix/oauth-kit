use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

use crate::User;

/// Trait for persisting user data from OAuth authentication.
///
/// Implement this trait to integrate oauth-kit with your database.
#[async_trait]
pub trait UserStore: Send + Sync + 'static {
    /// The type used to identify users in your system
    type UserId: Send + Sync + Clone + Debug + Serialize + DeserializeOwned + 'static;

    /// Error type for store operations
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find or create a user from an OAuth profile.
    ///
    /// This is called after a successful OAuth callback. The implementation
    /// should either find an existing user with matching provider ID or create
    /// a new user record.
    async fn find_or_create(
        &self,
        user: &User,
        provider: &str,
    ) -> Result<Self::UserId, Self::Error>;

    /// Link an additional OAuth provider to an existing user.
    ///
    /// This allows users to sign in with multiple providers.
    /// Default implementation does nothing.
    async fn link_account(
        &self,
        _user_id: &Self::UserId,
        _user: &User,
        _provider: &str,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A simple in-memory user store for testing and development.
///
/// This store does not persist data between restarts.
#[derive(Debug, Clone)]
pub struct MemoryStore {
    /// Maps (provider, provider_user_id) to internal user ID.
    users: std::sync::Arc<std::sync::RwLock<HashMap<(String, String), String>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            users: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Memory store error: {0}")]
pub struct MemoryStoreError(String);

#[async_trait]
impl UserStore for MemoryStore {
    type UserId = String;
    type Error = MemoryStoreError;

    async fn find_or_create(
        &self,
        user: &User,
        provider: &str,
    ) -> Result<Self::UserId, Self::Error> {
        let mut users = self
            .users
            .write()
            .map_err(|e| MemoryStoreError(e.to_string()))?;

        let key = (provider.to_string(), user.id.clone());
        let next_id = users.len() + 1;
        let id = users
            .entry(key)
            .or_insert_with(|| format!("user_{}", next_id));

        Ok(id.clone())
    }
}
