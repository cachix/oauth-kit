#![cfg(feature = "axum-integration")]

//! Integration tests for the axum router wiring.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use oauth_kit::{axum::AuthRouter, provider::providers, store::MemoryStore};
use tower::ServiceExt;
use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};

fn app() -> Router {
    app_with_prefix(None)
}

fn app_with_prefix(prefix: Option<&str>) -> Router {
    let mut router = AuthRouter::new(MemoryStore::new(), "http://localhost:3000")
        .with_provider(providers::github("client-id", "client-secret"));
    if let Some(prefix) = prefix {
        router = router.with_path_prefix(prefix);
    }
    router
        .build()
        .layer(SessionManagerLayer::new(SessionStore::default()))
}

async fn get(app: Router, uri: &str) -> (StatusCode, Option<String>) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .map(|v| v.to_str().unwrap().to_string());
    (response.status(), location)
}

#[tokio::test]
async fn signin_redirects_to_the_provider() {
    let (status, location) = get(app(), "/auth/signin/github").await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("redirect has a Location header");
    assert!(
        location.starts_with("https://github.com/login/oauth/authorize?"),
        "unexpected redirect target: {location}"
    );
    assert!(location.contains("client_id=client-id"), "{location}");
    assert!(location.contains("state="), "{location}");
    assert!(location.contains("code_challenge="), "{location}");
    assert!(
        location.contains("redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback%2Fgithub"),
        "{location}"
    );
}

#[tokio::test]
async fn signin_with_unknown_provider_is_not_found() {
    let (status, _) = get(app(), "/auth/signin/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn callback_without_state_is_rejected() {
    let (status, _) = get(app(), "/auth/callback/github?code=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_with_unknown_state_is_rejected() {
    let (status, _) = get(app(), "/auth/callback/github?code=abc&state=forged").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_surfaces_provider_errors() {
    let (status, _) = get(app(), "/auth/callback/github?error=access_denied").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signout_redirects_home() {
    let (status, location) = get(app(), "/auth/signout").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location.as_deref(), Some("/"));
}

#[tokio::test]
async fn custom_path_prefix_is_honoured() {
    let (status, _) = get(app_with_prefix(Some("/oauth")), "/oauth/signin/github").await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let (status, _) = get(app_with_prefix(Some("/oauth")), "/auth/signin/github").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
