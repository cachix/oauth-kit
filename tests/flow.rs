#![cfg(feature = "axum-integration")]

//! End-to-end tests of the signin -> callback flow against a stub provider,
//! so the session handling is exercised without touching the network.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    Router,
};
use oauth_kit::{
    axum::AuthRouter,
    provider::{AuthorizationRequest, OAuthProvider},
    store::MemoryStore,
    Result, User,
};
use tower::ServiceExt;
use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};

/// What `exchange_code` was called with, so tests can assert the callback
/// forwarded the values it stashed at signin time.
#[derive(Debug, Clone, PartialEq)]
struct Exchange {
    code: String,
    pkce_verifier: Option<String>,
    nonce: Option<String>,
}

struct StubProvider {
    id: &'static str,
    csrf_state: &'static str,
    subject: String,
    exchanges: Arc<Mutex<Vec<Exchange>>>,
}

impl StubProvider {
    fn new(id: &'static str, csrf_state: &'static str) -> Self {
        Self {
            id,
            csrf_state,
            subject: "stub-user-1".to_string(),
            exchanges: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait]
impl OAuthProvider for StubProvider {
    fn id(&self) -> &str {
        self.id
    }

    fn name(&self) -> &str {
        self.id
    }

    async fn authorization_url(&self, redirect_url: &str) -> Result<AuthorizationRequest> {
        Ok(AuthorizationRequest {
            url: format!("https://stub.test/authorize?redirect_uri={redirect_url}"),
            csrf_state: self.csrf_state.to_string(),
            pkce_verifier: Some(format!("verifier-for-{}", self.id)),
            nonce: Some(format!("nonce-for-{}", self.id)),
        })
    }

    async fn exchange_code(
        &self,
        _redirect_url: &str,
        code: &str,
        pkce_verifier: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<(User, String)> {
        self.exchanges.lock().unwrap().push(Exchange {
            code: code.to_string(),
            pkce_verifier: pkce_verifier.map(str::to_string),
            nonce: nonce.map(str::to_string),
        });
        Ok((
            User::new(self.subject.clone()).with_email("user@stub.test"),
            "access-token".to_string(),
        ))
    }
}

fn app(providers: Vec<StubProvider>) -> Router {
    let mut router = AuthRouter::new(MemoryStore::new(), "http://localhost:3000");
    for provider in providers {
        router = router.with_provider(provider);
    }
    router
        .build()
        .layer(SessionManagerLayer::new(SessionStore::default()))
}

async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> Response<Body> {
    let mut request = Request::builder().uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn session_cookie(response: &Response<Body>) -> Option<String> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
}

fn location(response: &Response<Body>) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("redirect has a Location header")
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn signin_then_callback_authenticates_the_session() {
    let provider = StubProvider::new("stub", "state-abc");
    let exchanges = provider.exchanges.clone();
    let app = app(vec![provider]);

    let signin = get(&app, "/auth/signin/stub", None).await;
    assert_eq!(signin.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&signin),
        "https://stub.test/authorize?redirect_uri=http://localhost:3000/auth/callback/stub"
    );
    let cookie = session_cookie(&signin).expect("signin sets a session cookie");

    let callback = get(
        &app,
        "/auth/callback/stub?code=the-code&state=state-abc",
        Some(&cookie),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&callback), "/");

    // The verifier and nonce stashed at signin must reach the exchange.
    assert_eq!(
        *exchanges.lock().unwrap(),
        vec![Exchange {
            code: "the-code".to_string(),
            pkce_verifier: Some("verifier-for-stub".to_string()),
            nonce: Some("nonce-for-stub".to_string()),
        }]
    );

    // The session ID is cycled on sign-in, so the pre-auth cookie is replaced.
    let authenticated = session_cookie(&callback).expect("callback re-issues the session cookie");
    assert_ne!(authenticated, cookie);
}

#[tokio::test]
async fn a_callback_cannot_be_replayed() {
    let provider = StubProvider::new("stub", "state-abc");
    let exchanges = provider.exchanges.clone();
    let app = app(vec![provider]);

    let signin = get(&app, "/auth/signin/stub", None).await;
    let cookie = session_cookie(&signin).unwrap();
    let uri = "/auth/callback/stub?code=the-code&state=state-abc";

    assert_eq!(
        get(&app, uri, Some(&cookie)).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        get(&app, uri, Some(&cookie)).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(exchanges.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_flow_started_for_one_provider_cannot_finish_at_another() {
    let one = StubProvider::new("one", "state-one");
    let two = StubProvider::new("two", "state-two");
    let two_exchanges = two.exchanges.clone();
    let app = app(vec![one, two]);

    let signin = get(&app, "/auth/signin/one", None).await;
    let cookie = session_cookie(&signin).unwrap();

    // "one"'s state replayed against "two" must not exchange anything, even
    // though a flow is genuinely in progress.
    let callback = get(
        &app,
        "/auth/callback/two?code=the-code&state=state-one",
        Some(&cookie),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert!(two_exchanges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_forged_state_is_rejected() {
    let provider = StubProvider::new("stub", "state-abc");
    let exchanges = provider.exchanges.clone();
    let app = app(vec![provider]);

    let signin = get(&app, "/auth/signin/stub", None).await;
    let cookie = session_cookie(&signin).unwrap();

    let callback = get(
        &app,
        "/auth/callback/stub?code=the-code&state=state-forged",
        Some(&cookie),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    assert!(exchanges.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provider_errors_are_not_reflected_back_to_the_browser() {
    let app = app(vec![StubProvider::new("stub", "state-abc")]);

    let callback = get(
        &app,
        "/auth/callback/stub?error=access_denied&error_description=%3Cscript%3E",
        None,
    )
    .await;

    assert_eq!(callback.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(callback.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body.contains("script"), "provider text leaked: {body}");
}

#[tokio::test]
async fn signout_clears_the_session() {
    let app = app(vec![StubProvider::new("stub", "state-abc")]);

    let signin = get(&app, "/auth/signin/stub", None).await;
    let cookie = session_cookie(&signin).unwrap();
    get(
        &app,
        "/auth/callback/stub?code=the-code&state=state-abc",
        Some(&cookie),
    )
    .await;

    let signout = get(&app, "/auth/signout", Some(&cookie)).await;
    assert_eq!(signout.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&signout), "/");
}

#[tokio::test]
async fn signout_also_accepts_post() {
    let app = app(vec![StubProvider::new("stub", "state-abc")]);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/signout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}
