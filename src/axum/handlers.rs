use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, info};

use super::router::{session_keys, AuthState};
use crate::store::UserStore;

/// Insert a value into the session, returning an error response on failure.
async fn session_insert(
    session: &Session,
    key: &str,
    value: &impl Serialize,
    label: &str,
) -> Option<Response> {
    if let Err(e) = session.insert(key, value).await {
        error!("Failed to store {}: {}", label, e);
        Some(
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Session error",
            )
                .into_response(),
        )
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Handler for initiating OAuth sign-in.
pub async fn signin<S: UserStore + Clone>(
    Path(provider_id): Path<String>,
    State(state): State<AuthState<S>>,
    session: Session,
) -> Response {
    let provider = match state.providers.get(&provider_id) {
        Some(p) => p,
        None => {
            error!("Provider not found: {}", provider_id);
            return (
                axum::http::StatusCode::NOT_FOUND,
                format!("Provider '{}' not found", provider_id),
            )
                .into_response();
        }
    };

    let callback_url = state.callback_url(&provider_id);

    let auth_request = match provider.authorization_url(&callback_url).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to generate authorization URL: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate authorization URL",
            )
                .into_response();
        }
    };

    // Store OAuth state in session
    if let Some(r) =
        session_insert(&session, session_keys::CSRF_STATE, &auth_request.csrf_state, "CSRF state")
            .await
    {
        return r;
    }
    if let Some(ref verifier) = auth_request.pkce_verifier {
        if let Some(r) =
            session_insert(&session, session_keys::PKCE_VERIFIER, verifier, "PKCE verifier").await
        {
            return r;
        }
    }
    if let Some(ref nonce) = auth_request.nonce {
        if let Some(r) = session_insert(&session, session_keys::NONCE, nonce, "nonce").await {
            return r;
        }
    }
    if let Some(r) =
        session_insert(&session, session_keys::PROVIDER, &provider_id, "provider").await
    {
        return r;
    }

    info!("Redirecting to {} for OAuth", provider_id);
    Redirect::to(&auth_request.url).into_response()
}

/// Handler for OAuth callback.
pub async fn callback<S: UserStore + Clone>(
    Path(provider_id): Path<String>,
    Query(params): Query<CallbackParams>,
    State(state): State<AuthState<S>>,
    session: Session,
) -> Response {
    // Check for OAuth errors
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        error!(
            "OAuth error from {}: {} - {}",
            provider_id, error, description
        );
        return (
            axum::http::StatusCode::BAD_REQUEST,
            format!("OAuth error: {} - {}", error, description),
        )
            .into_response();
    }

    // Validate CSRF state
    let stored_state: Option<String> = session.get(session_keys::CSRF_STATE).await.ok().flatten();
    let received_state = params.state;

    match (stored_state, received_state) {
        (Some(stored), Some(received)) if stored == received => {
            // Valid state, continue
        }
        (None, _) => {
            error!("Missing stored CSRF state");
            return (axum::http::StatusCode::BAD_REQUEST, "Missing CSRF state").into_response();
        }
        (_, None) => {
            error!("Missing received CSRF state");
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Missing state parameter",
            )
                .into_response();
        }
        (Some(stored), Some(received)) => {
            error!("CSRF state mismatch: {} != {}", stored, received);
            return (axum::http::StatusCode::BAD_REQUEST, "Invalid CSRF state").into_response();
        }
    }

    // Get authorization code
    let code = match params.code {
        Some(c) => c,
        None => {
            error!("Missing authorization code");
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Missing authorization code",
            )
                .into_response();
        }
    };

    // Get PKCE verifier if stored
    let pkce_verifier: Option<String> = session
        .get(session_keys::PKCE_VERIFIER)
        .await
        .ok()
        .flatten();

    // Get nonce if stored (for OIDC)
    let nonce: Option<String> = session.get(session_keys::NONCE).await.ok().flatten();

    // Get provider
    let provider = match state.providers.get(&provider_id) {
        Some(p) => p,
        None => {
            error!("Provider not found: {}", provider_id);
            return (
                axum::http::StatusCode::NOT_FOUND,
                format!("Provider '{}' not found", provider_id),
            )
                .into_response();
        }
    };

    // Exchange code for user info
    let callback_url = state.callback_url(&provider_id);
    let (user, _access_token) = match provider
        .exchange_code(
            &callback_url,
            &code,
            pkce_verifier.as_deref(),
            nonce.as_deref(),
        )
        .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Token exchange failed: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Authentication failed: {}", e),
            )
                .into_response();
        }
    };

    info!(
        "Successfully authenticated user {} via {}",
        user.id, provider_id
    );

    // Store user in database
    let user_id = match state.store.find_or_create(&user, &provider_id).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to store user: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to store user",
            )
                .into_response();
        }
    };

    // Clear OAuth session data
    let _ = session.remove::<String>(session_keys::CSRF_STATE).await;
    let _ = session.remove::<String>(session_keys::PKCE_VERIFIER).await;
    let _ = session.remove::<String>(session_keys::NONCE).await;
    let _ = session.remove::<String>(session_keys::PROVIDER).await;

    // Store user ID in session
    if let Some(r) = session_insert(&session, session_keys::USER_ID, &user_id, "user ID").await {
        return r;
    }

    Redirect::to(&state.signin_redirect).into_response()
}

/// Handler for signing out.
pub async fn signout<S: UserStore + Clone>(
    State(state): State<AuthState<S>>,
    session: Session,
) -> Response {
    // Clear all session data
    if let Err(e) = session.flush().await {
        error!("Failed to flush session: {}", e);
    }

    info!("User signed out");
    Redirect::to(&state.signout_redirect).into_response()
}
