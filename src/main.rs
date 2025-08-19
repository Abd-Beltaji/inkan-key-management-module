mod api;
mod key_generation;
mod key_storage;
mod key_verification;
mod models;
mod utils;

use axum::{
    extract::{Json, Path, State},
    routing::{get, post, put},
    Router,
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber;
use serde_json;

use crate::api::AppState;
use crate::key_storage::create_default_storage;
use crate::models::{
    GenerateKeyRequest, SignDocumentRequest, VerifySignatureRequest, UpdateKeyRequest, RevokeKeyRequest,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("🚀 Starting Inkan Key Management Module...");

    // Create and initialize storage
    let storage = create_default_storage();
    storage.load_from_disk().await?;
    info!("📁 Storage initialized with {} keys", storage.key_count().await);

    // Create application state
    let state = Arc::new(AppState {
        storage: Arc::new(storage),
    });

    // Create CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create router with all endpoints
    let app = Router::new()
        .route("/health", get(|| async { "OK" }))

        .route("/keys/generate", post(|state: State<Arc<AppState>>, json: Json<GenerateKeyRequest>| async move {
            tracing::info!("DEBUG: Route handler called with request: {:?}", json.0);
            
            // Simple test response to see if the route works
            let test_response = serde_json::json!({
                "success": true,
                "message": "Test response - route working",
                "request": json.0
            });
            
            tracing::info!("DEBUG: Returning test response");
            Json(test_response)
        }))
        .route("/keys", get(|state: State<Arc<AppState>>, query: axum::extract::Query<crate::api::ListKeysQuery>| async move {
            crate::api::list_keys(state, query).await
        }))
        .route("/keys/search", get(|state: State<Arc<AppState>>, query: axum::extract::Query<crate::api::ListKeysQuery>| async move {
            crate::api::search_keys(state, query).await
        }))
        .route("/keys/stats", get(|state: State<Arc<AppState>>| async move {
            crate::api::get_key_stats(state).await
        }))
        .route("/keys/:key_id", get(|state: State<Arc<AppState>>, Path(key_id): Path<uuid::Uuid>| async move {
            match crate::api::get_public_key(state, Path(key_id)).await {
                Ok(response) => response.into_response(),
                Err(status) => status.into_response(),
            }
        }))
        .route("/keys/:key_id", put(|state: State<Arc<AppState>>, Path(key_id): Path<uuid::Uuid>, json: Json<UpdateKeyRequest>| async move {
            match crate::api::update_key(state, Path(key_id), json).await {
                Ok(response) => response.into_response(),
                Err(status) => status.into_response(),
            }
        }))
        .route("/keys/:key_id/revoke", post(|state: State<Arc<AppState>>, Path(key_id): Path<uuid::Uuid>, json: Json<RevokeKeyRequest>| async move {
            match crate::api::revoke_key(state, Path(key_id), json).await {
                Ok(response) => response.into_response(),
                Err(status) => status.into_response(),
            }
        }))
        .route("/keys/:key_id/public", get(|state: State<Arc<AppState>>, Path(key_id): Path<uuid::Uuid>| async move {
            match crate::api::get_public_key(state, Path(key_id)).await {
                Ok(response) => response.into_response(),
                Err(status) => status.into_response(),
            }
        }))
        .route("/sign", post(|state: State<Arc<AppState>>, json: Json<SignDocumentRequest>| async move {
            match crate::api::sign_document(state, json).await {
                Ok(response) => response.into_response(),
                Err(status) => status.into_response(),
            }
        }))
        .route("/verify", post(|_state: State<Arc<AppState>>, json: Json<VerifySignatureRequest>| async move {
            crate::api::verify_signature(json).await
        }))
        .with_state(state)
        .layer(cors);

    // Bind and serve
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3002").await?;
    info!("🌐 Key management server listening on http://localhost:3002");
    info!("📚 Available endpoints:");
    info!("   POST /keys/generate - Generate new key pair");
    info!("   GET  /keys - List all keys");
    info!("   GET  /keys/search - Search keys");
    info!("   GET  /keys/stats - Get key statistics");
    info!("   GET  /keys/:id - Get key information");
    info!("   PUT  /keys/:id - Update key information");
    info!("   POST /keys/:id/revoke - Revoke a key");
    info!("   GET  /keys/:id/public - Get public key");
    info!("   POST /sign - Sign document with private key");
    info!("   POST /verify - Verify document signature");
    info!("   GET  /health - Health check");

    axum::serve(listener, app).await?;

    Ok(())
}
