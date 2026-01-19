use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;
use tower_sessions::Session;

use super::router::session_keys;

/// Extractor for authenticated users.
///
/// This extractor will reject requests from unauthenticated users
/// with a 401 Unauthorized response.
///
/// # Example
///
/// ```rust,ignore
/// async fn protected_route(AuthUser(user_id): AuthUser<String>) -> impl IntoResponse {
///     format!("Hello, user {}!", user_id)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthUser<T>(pub T);

impl<S, T> FromRequestParts<S> for AuthUser<T>
where
    S: Send + Sync,
    T: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| AuthError::SessionError)?;

        let user_id: T = session
            .get(session_keys::USER_ID)
            .await
            .map_err(|_| AuthError::SessionError)?
            .ok_or(AuthError::Unauthorized)?;

        Ok(AuthUser(user_id))
    }
}

/// Extractor for optionally authenticated users.
///
/// This extractor will return `None` for unauthenticated users
/// instead of rejecting the request.
///
/// # Example
///
/// ```rust,ignore
/// async fn maybe_protected(MaybeAuthUser(user_id): MaybeAuthUser<String>) -> impl IntoResponse {
///     match user_id {
///         Some(id) => format!("Hello, user {}!", id),
///         None => "Hello, guest!".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MaybeAuthUser<T>(pub Option<T>);

impl<S, T> FromRequestParts<S> for MaybeAuthUser<T>
where
    S: Send + Sync,
    T: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| AuthError::SessionError)?;

        let user_id: Option<T> = session
            .get(session_keys::USER_ID)
            .await
            .map_err(|_| AuthError::SessionError)?;

        Ok(MaybeAuthUser(user_id))
    }
}

/// Authentication error type.
#[derive(Debug)]
pub enum AuthError {
    Unauthorized,
    SessionError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::Unauthorized => {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
            AuthError::SessionError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Session error").into_response()
            }
        }
    }
}
