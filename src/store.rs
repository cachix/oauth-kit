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
    /// Called instead of [`UserStore::find_or_create`] when a callback
    /// completes for a session that is already signed in, so that signing in
    /// with a second provider attaches it to the current account rather than
    /// switching accounts.
    ///
    /// # Rejecting a conflicting link
    ///
    /// `user` may be a provider identity that already belongs to a *different*
    /// account. Linking it anyway would give `user_id` access to that other
    /// account, so an implementation that can detect the conflict should
    /// return an error; the callback answers 500 and the link does not happen.
    /// [`MemoryStore`] does not: it ignores such a link, which keeps the
    /// identity with its owner but reports success.
    ///
    /// The default implementation does nothing, which means a store that does
    /// not override it accepts links and silently forgets them.
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

    /// Records the link if the identity is unclaimed, and ignores it otherwise.
    ///
    /// A real store should reject a link to an identity that already belongs
    /// to someone else rather than dropping it silently; leaving it claimed by
    /// its original owner is enough to keep this one safe.
    async fn link_account(
        &self,
        user_id: &Self::UserId,
        user: &User,
        provider: &str,
    ) -> Result<(), Self::Error> {
        let mut users = self
            .users
            .write()
            .map_err(|e| MemoryStoreError(e.to_string()))?;

        users
            .entry((provider.to_string(), user.id.clone()))
            .or_insert_with(|| user_id.clone());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_same_provider_identity_maps_to_one_user() {
        let store = MemoryStore::new();
        let user = User::new("123").with_email("a@example.com");

        let first = store.find_or_create(&user, "github").await.unwrap();
        let again = store.find_or_create(&user, "github").await.unwrap();
        assert_eq!(first, again);
    }

    #[tokio::test]
    async fn the_same_id_at_a_different_provider_is_a_different_user() {
        let store = MemoryStore::new();
        let user = User::new("123");

        let github = store.find_or_create(&user, "github").await.unwrap();
        let gitlab = store.find_or_create(&user, "gitlab").await.unwrap();
        assert_ne!(github, gitlab);
    }

    #[tokio::test]
    async fn a_linked_account_signs_in_as_the_same_user() {
        let store = MemoryStore::new();
        let github = User::new("gh-1");
        let gitlab = User::new("gl-9");

        let id = store.find_or_create(&github, "github").await.unwrap();
        store.link_account(&id, &gitlab, "gitlab").await.unwrap();

        // Signing in through the linked provider lands on the same account.
        assert_eq!(store.find_or_create(&gitlab, "gitlab").await.unwrap(), id);
    }

    #[tokio::test]
    async fn linking_the_same_account_twice_is_a_no_op() {
        let store = MemoryStore::new();
        let id = store
            .find_or_create(&User::new("gh-1"), "github")
            .await
            .unwrap();
        let gitlab = User::new("gl-9");

        store.link_account(&id, &gitlab, "gitlab").await.unwrap();
        store.link_account(&id, &gitlab, "gitlab").await.unwrap();

        assert_eq!(store.find_or_create(&gitlab, "gitlab").await.unwrap(), id);
    }

    #[tokio::test]
    async fn linking_an_identity_owned_by_another_user_does_not_steal_it() {
        let store = MemoryStore::new();
        let gitlab = User::new("gl-9");

        let owner = store.find_or_create(&gitlab, "gitlab").await.unwrap();
        let other = store
            .find_or_create(&User::new("gh-1"), "github")
            .await
            .unwrap();
        assert_ne!(owner, other);

        // This store ignores the conflict rather than reporting it, so the
        // link reads as successful.
        store.link_account(&other, &gitlab, "gitlab").await.unwrap();

        // What matters is that the identity still signs in as its owner, not
        // as the account that tried to claim it.
        assert_eq!(
            store.find_or_create(&gitlab, "gitlab").await.unwrap(),
            owner
        );
    }
}
