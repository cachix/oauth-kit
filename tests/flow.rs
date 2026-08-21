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
    axum::{AuthRouter, AuthUser},
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

    /// Set the provider-side user ID this stub authenticates as.
    fn with_subject(mut self, subject: &str) -> Self {
        self.subject = subject.to_string();
        self
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
/// Records which store method each callback took, so the tests can tell
/// linking apart from a fresh sign-in.
#[derive(Debug, Clone, PartialEq)]
enum StoreCall {
    FindOrCreate { provider: String, subject: String },
    Link { user_id: String, provider: String },
}

#[derive(Clone)]
struct RecordingStore {
    calls: Arc<Mutex<Vec<StoreCall>>>,
    link_fails: bool,
}

impl RecordingStore {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            link_fails: false,
        }
    }

    fn failing_to_link() -> Self {
        Self {
            link_fails: true,
            ..Self::new()
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("store rejected the link")]
struct RecordingStoreError;

#[async_trait]
impl oauth_kit::UserStore for RecordingStore {
    type UserId = String;
    type Error = RecordingStoreError;

    async fn find_or_create(
        &self,
        user: &User,
        provider: &str,
    ) -> std::result::Result<String, Self::Error> {
        self.calls.lock().unwrap().push(StoreCall::FindOrCreate {
            provider: provider.to_string(),
            subject: user.id.clone(),
        });
        Ok(format!("account-for-{}", user.id))
    }

    async fn link_account(
        &self,
        user_id: &String,
        _user: &User,
        provider: &str,
    ) -> std::result::Result<(), Self::Error> {
        self.calls.lock().unwrap().push(StoreCall::Link {
            user_id: user_id.clone(),
            provider: provider.to_string(),
        });
        if self.link_fails {
            return Err(RecordingStoreError);
        }
        Ok(())
    }
}

/// Two providers whose stub users have different subjects, so a switch would
/// be visible as a different account ID.
///
/// `/whoami` reports the account the session is signed in as.
fn linking_app(store: RecordingStore) -> Router {
    let auth = AuthRouter::new(store, "http://localhost:3000")
        .with_provider(StubProvider::new("one", "state-one").with_subject("subject-one"))
        .with_provider(StubProvider::new("two", "state-two").with_subject("subject-two"))
        .build();

    Router::new()
        .route("/whoami", axum::routing::get(whoami))
        .merge(auth)
        .layer(SessionManagerLayer::new(SessionStore::default()))
}

async fn whoami(AuthUser(user_id): AuthUser<String>) -> String {
    user_id
}

async fn body_of(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn sign_in(
    app: &Router,
    provider: &str,
    state: &str,
    cookie: Option<&str>,
) -> Response<Body> {
    let signin = get(app, &format!("/auth/signin/{provider}"), cookie).await;
    let cookie = session_cookie(&signin)
        .or_else(|| cookie.map(str::to_string))
        .expect("a session cookie");
    get(
        app,
        &format!("/auth/callback/{provider}?code=the-code&state={state}"),
        Some(&cookie),
    )
    .await
}

#[tokio::test]
async fn a_second_provider_links_to_the_signed_in_account() {
    let store = RecordingStore::new();
    let calls = store.calls.clone();
    let app = linking_app(store);

    let first = sign_in(&app, "one", "state-one", None).await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let cookie = session_cookie(&first).expect("sign-in re-issues the cookie");

    let second = sign_in(&app, "two", "state-two", Some(&cookie)).await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);

    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            StoreCall::FindOrCreate {
                provider: "one".to_string(),
                subject: "subject-one".to_string(),
            },
            // Linked to the account from the first sign-in, not looked up
            // afresh under provider "two".
            StoreCall::Link {
                user_id: "account-for-subject-one".to_string(),
                provider: "two".to_string(),
            },
        ]
    );
}

#[tokio::test]
async fn linking_leaves_the_signed_in_user_in_place() {
    let store = RecordingStore::new();
    let app = linking_app(store);

    let first = sign_in(&app, "one", "state-one", None).await;
    let cookie = session_cookie(&first).unwrap();
    assert_eq!(
        body_of(get(&app, "/whoami", Some(&cookie)).await).await,
        "account-for-subject-one"
    );

    sign_in(&app, "two", "state-two", Some(&cookie)).await;

    // Still the original account: linking must not switch identities, even
    // though provider "two" authenticated a different subject.
    assert_eq!(
        body_of(get(&app, "/whoami", Some(&cookie)).await).await,
        "account-for-subject-one"
    );
}

#[tokio::test]
async fn a_rejected_link_does_not_sign_anyone_in() {
    let store = RecordingStore::failing_to_link();
    let calls = store.calls.clone();
    let app = linking_app(store);

    let first = sign_in(&app, "one", "state-one", None).await;
    let cookie = session_cookie(&first).unwrap();

    let second = sign_in(&app, "two", "state-two", Some(&cookie)).await;
    assert_eq!(second.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // The rejected link must not fall back to creating a second account.
    assert!(!calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| matches!(call, StoreCall::FindOrCreate { provider, .. } if provider == "two")));
}

#[tokio::test]
async fn signing_out_first_switches_accounts_instead_of_linking() {
    let store = RecordingStore::new();
    let calls = store.calls.clone();
    let app = linking_app(store);

    let first = sign_in(&app, "one", "state-one", None).await;
    let cookie = session_cookie(&first).unwrap();

    let signout = get(&app, "/auth/signout", Some(&cookie)).await;
    let cookie = session_cookie(&signout).unwrap_or(cookie);

    sign_in(&app, "two", "state-two", Some(&cookie)).await;

    let calls = calls.lock().unwrap();
    assert!(
        matches!(&calls[1], StoreCall::FindOrCreate { provider, .. } if provider == "two"),
        "after signout the second provider should sign in on its own: {calls:?}"
    );
}
