use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
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
    users: std::sync::Arc<std::sync::RwLock<Vec<StoredUser>>>,
}

#[derive(Debug, Clone)]
struct StoredUser {
    id: String,
    provider: String,
    provider_user_id: String,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            users: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
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

        // Check if user exists
        if let Some(stored) = users
            .iter()
            .find(|u| u.provider == provider && u.provider_user_id == user.id)
        {
            return Ok(stored.id.clone());
        }

        // Create new user
        let id = format!("user_{}", users.len() + 1);
        users.push(StoredUser {
            id: id.clone(),
            provider: provider.to_string(),
            provider_user_id: user.id.clone(),
        });

        Ok(id)
    }
}
