//! Basic example demonstrating OAuth authentication with GitHub.
//!
//! To run this example:
//!
//! 1. Create a GitHub OAuth App at https://github.com/settings/developers
//! 2. Set the callback URL to http://localhost:3000/auth/callback/github
//! 3. Set environment variables:
//!    ```
//!    export GITHUB_CLIENT_ID=your_client_id
//!    export GITHUB_CLIENT_SECRET=your_client_secret
//!    ```
//! 4. Run the example:
//!    ```
//!    cargo run --example basic
//!    ```
//! 5. Visit http://localhost:3000

use axum::{response::Html, routing::get, Router};
use oauth_kit::{
    axum::{AuthRouter, AuthUser, MaybeAuthUser},
    provider::providers,
    store::MemoryStore,
};
use tower_sessions::{MemoryStore as SessionStore, SessionManagerLayer};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Create session store
    let session_store = SessionStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    // Create the auth router with GitHub provider
    let github = providers::github_from_env()
        .expect("Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables");

    let auth = AuthRouter::new(MemoryStore::new(), "http://localhost:3000")
        .with_provider(github)
        .with_signin_redirect("/")
        .with_signout_redirect("/")
        .build();

    // Build the application
    let app = Router::new()
        .route("/", get(home))
        .route("/protected", get(protected))
        .merge(auth)
        .layer(session_layer);

    println!("Server running at http://localhost:3000");
    println!("Sign in at http://localhost:3000/auth/signin/github");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn home(MaybeAuthUser(user_id): MaybeAuthUser<String>) -> Html<String> {
    let content = match user_id {
        Some(id) => format!(
            r#"
            <h1>Welcome!</h1>
            <p>You are logged in as user: <strong>{}</strong></p>
            <p><a href="/protected">Visit protected page</a></p>
            <p><a href="/auth/signout">Sign out</a></p>
            "#,
            id
        ),
        None => r#"
            <h1>Welcome!</h1>
            <p>You are not logged in.</p>
            <p><a href="/auth/signin/github">Sign in with GitHub</a></p>
            "#
        .to_string(),
    };

    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>oauth-kit Example</title>
            <style>
                body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                a {{ color: #0066cc; }}
            </style>
        </head>
        <body>
            {}
        </body>
        </html>
        "#,
        content
    ))
}

async fn protected(AuthUser(user_id): AuthUser<String>) -> Html<String> {
    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Protected Page</title>
            <style>
                body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                a {{ color: #0066cc; }}
            </style>
        </head>
        <body>
            <h1>Protected Page</h1>
            <p>This page is only visible to authenticated users.</p>
            <p>Your user ID: <strong>{}</strong></p>
            <p><a href="/">Back to home</a></p>
            <p><a href="/auth/signout">Sign out</a></p>
        </body>
        </html>
        "#,
        user_id
    ))
}
