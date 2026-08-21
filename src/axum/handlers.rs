use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, info, warn};

use super::router::{session_keys, AuthState};
use crate::store::UserStore;

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The in-flight OAuth flow, held in the session between signin and callback.
///
/// Kept as a single value so the CSRF state, PKCE verifier and nonce can never
/// drift apart, and so a callback can only ever consume the flow that started it.
#[derive(Debug, Serialize, Deserialize)]
struct PendingFlow {
    provider: String,
    csrf_state: String,
    pkce_verifier: Option<String>,
    nonce: Option<String>,
}

/// Compare two secrets without leaking where they first differ.
fn secrets_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn bad_request(message: &'static str) -> Response {
    (axum::http::StatusCode::BAD_REQUEST, message).into_response()
}

fn server_error(message: &'static str) -> Response {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message).into_response()
}

fn provider_not_found(provider_id: &str) -> Response {
    error!("Provider not found: {}", provider_id);
    (
        axum::http::StatusCode::NOT_FOUND,
        format!("Provider '{}' not found", provider_id),
    )
        .into_response()
}

/// Handler for initiating OAuth sign-in.
pub async fn signin<S: UserStore + Clone>(
    Path(provider_id): Path<String>,
    State(state): State<AuthState<S>>,
    session: Session,
) -> Response {
    let provider = match state.providers.get(&provider_id) {
        Some(p) => p,
        None => return provider_not_found(&provider_id),
    };

    let callback_url = state.callback_url(&provider_id);

    let auth_request = match provider.authorization_url(&callback_url).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to generate authorization URL: {}", e);
            return server_error("Failed to generate authorization URL");
        }
    };

    let flow = PendingFlow {
        provider: provider_id.clone(),
        csrf_state: auth_request.csrf_state,
        pkce_verifier: auth_request.pkce_verifier,
        nonce: auth_request.nonce,
    };

    // Replaces any flow already in flight, so only the most recent signin can
    // be completed.
    if let Err(e) = session.insert(session_keys::FLOW, &flow).await {
        error!("Failed to store OAuth flow in session: {}", e);
        return server_error("Session error");
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
    // Take the pending flow out of the session up front: it is single-use, so
    // a failed or replayed callback cannot retry against the same state.
    let flow: Option<PendingFlow> = session.remove(session_keys::FLOW).await.ok().flatten();

    if let Some(error) = params.error {
        warn!(
            "OAuth error from {}: {} - {}",
            provider_id,
            error,
            params.error_description.unwrap_or_default()
        );
        return bad_request("Authorization was denied or failed");
    }

    let flow = match flow {
        Some(flow) => flow,
        None => {
            warn!("Callback for {} without a pending flow", provider_id);
            return bad_request("No sign-in is in progress");
        }
    };

    if flow.provider != provider_id {
        warn!(
            "Callback provider mismatch: flow started for {}, callback for {}",
            flow.provider, provider_id
        );
        return bad_request("Provider mismatch");
    }

    let received_state = match params.state {
        Some(state) => state,
        None => {
            warn!("Callback for {} without a state parameter", provider_id);
            return bad_request("Missing state parameter");
        }
    };

    if !secrets_match(&flow.csrf_state, &received_state) {
        warn!("CSRF state mismatch on callback for {}", provider_id);
        return bad_request("Invalid CSRF state");
    }

    let code = match params.code {
        Some(code) => code,
        None => {
            warn!("Callback for {} without an authorization code", provider_id);
            return bad_request("Missing authorization code");
        }
    };

    let provider = match state.providers.get(&provider_id) {
        Some(p) => p,
        None => return provider_not_found(&provider_id),
    };

    let callback_url = state.callback_url(&provider_id);
    let (user, _access_token) = match provider
        .exchange_code(
            &callback_url,
            &code,
            flow.pkce_verifier.as_deref(),
            flow.nonce.as_deref(),
        )
        .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Token exchange failed for {}: {}", provider_id, e);
            return server_error("Authentication failed");
        }
    };

    info!(
        "Successfully authenticated user {} via {}",
        user.id, provider_id
    );

    let user_id = match state.store.find_or_create(&user, &provider_id).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to store user: {}", e);
            return server_error("Failed to store user");
        }
    };

    // Issue a fresh session ID now that the session is authenticated, so a
    // session cookie planted before sign-in cannot be used afterwards.
    if let Err(e) = session.cycle_id().await {
        error!("Failed to cycle session ID: {}", e);
        return server_error("Session error");
    }

    if let Err(e) = session.insert(session_keys::USER_ID, &user_id).await {
        error!("Failed to store user ID in session: {}", e);
        return server_error("Session error");
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

#[cfg(test)]
mod tests {
    use super::secrets_match;

    #[test]
    fn secrets_match_only_on_equal_values() {
        assert!(secrets_match("abc123", "abc123"));
        assert!(secrets_match("", ""));
        assert!(!secrets_match("abc123", "abc124"));
        assert!(!secrets_match("abc123", "abc1234"));
        assert!(!secrets_match("abc123", ""));
    }
}
