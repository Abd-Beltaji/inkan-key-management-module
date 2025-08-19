use axum::{
    extract::{Path, State, Query},
    response::Json,
    http::StatusCode,
};
use std::sync::Arc;
use uuid::Uuid;
use serde::Deserialize;

use crate::{
    key_generation::generate_key_pair,
    key_storage::KeyStorage,
    key_verification::{sign_document as sign_doc, verify_signature as verify_sig, sign_document_content},
    models::*,
};

/// Shared state for the application
pub struct AppState {
    pub storage: Arc<KeyStorage>,
}

/// Query parameters for listing keys
#[derive(Debug, Deserialize)]
pub struct ListKeysQuery {
    pub active_only: Option<bool>,
    pub key_type: Option<String>,
    pub tags: Option<String>,
    pub search: Option<String>,
}

/// Generate a new key pair
pub async fn generate_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Json<GenerateKeyResponse>, StatusCode> {
    tracing::info!("DEBUG: generate_keys called with request: {:?}", request);
    
    // Validate request
    if request.name.trim().is_empty() {
        tracing::warn!("DEBUG: Key name is empty");
        return Ok(Json(GenerateKeyResponse {
            success: false,
            key_pair: None,
            message: "Key name cannot be empty".to_string(),
            warnings: vec![],
        }));
    }

    // Generate the key pair
    tracing::info!("DEBUG: About to call generate_key_pair");
    let key_pair = match generate_key_pair(request) {
        Ok(kp) => {
            tracing::info!("DEBUG: Key pair generated successfully");
            kp
        },
        Err(e) => {
            tracing::error!("DEBUG: Key pair generation failed: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Store the key pair
    tracing::info!("DEBUG: About to store key pair");
    if let Err(e) = state.storage.store_key(key_pair.clone()).await {
        tracing::error!("DEBUG: Failed to store key pair: {:?}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    tracing::info!("DEBUG: Key pair stored successfully");

    let warnings = if key_pair.salt.is_none() {
        vec!["Private key is not encrypted - not recommended for production".to_string()]
    } else {
        vec![]
    };

    tracing::info!("DEBUG: Creating response with key pair");
    let response = GenerateKeyResponse {
        success: true,
        key_pair: Some(key_pair),
        message: "Key pair generated successfully".to_string(),
        warnings,
    };
    tracing::info!("DEBUG: Response created successfully: {:?}", response);
    Ok(Json(response))
}

/// List all keys (public information only)
pub async fn list_keys(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListKeysQuery>,
) -> Json<ListKeysResponse> {
    let keys = if let Some(search) = &query.search {
        state.storage.search_keys(search).await
    } else {
        state.storage.list_keys().await
    };
    
    let (total, active, expired, _) = state.storage.get_key_stats().await;
    
    Json(ListKeysResponse {
        success: true,
        keys: keys.clone(),
        message: format!("Found {} keys", keys.len()),
        total_count: total,
        active_count: active,
        expired_count: expired,
    })
}

/// Get public key information
pub async fn get_public_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<PublicKeyResponse>, StatusCode> {
    match state.storage.get_key(key_id).await {
        Ok(key_pair) => {
            let key_info = KeyInfo {
                id: key_pair.id,
                name: key_pair.name,
                description: key_pair.description,
                public_key: key_pair.public_key,
                created_at: key_pair.created_at,
                last_used: key_pair.last_used,
                expires_at: key_pair.expires_at,
                is_active: key_pair.is_active,
                tags: key_pair.tags,
                key_type: key_pair.key_type,
                key_strength: key_pair.key_strength,
            };

            Ok(Json(PublicKeyResponse {
                success: true,
                key_info: Some(key_info),
                message: "Public key retrieved successfully".to_string(),
            }))
        }
        Err(_) => Ok(Json(PublicKeyResponse {
            success: false,
            key_info: None,
            message: "Key not found".to_string(),
        })),
    }
}

/// Sign a document with a private key
pub async fn sign_document(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SignDocumentRequest>,
) -> Result<Json<SignDocumentResponse>, StatusCode> {
    // Get the key pair
    let key_pair = match state.storage.get_key(request.key_id).await {
        Ok(kp) => kp,
        Err(_) => {
            return Ok(Json(SignDocumentResponse {
                success: false,
                signature: None,
                message: "Key not found or invalid".to_string(),
                key_id: None,
                document_hash: None,
                signing_time: None,
            }));
        }
    };

    // Check if key is active
    if !key_pair.is_active {
        return Ok(Json(SignDocumentResponse {
            success: false,
            signature: None,
            message: "Key is not active".to_string(),
            key_id: Some(request.key_id),
            document_hash: None,
            signing_time: None,
        }));
    }

    // Sign the document
    let signature = if let Some(content) = &request.document_content {
        // Sign document content directly
        match sign_document_content(&request, &key_pair.private_key, key_pair.salt.as_deref(), content) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(Json(SignDocumentResponse {
                    success: false,
                    signature: None,
                    message: "Failed to sign document content".to_string(),
                    key_id: Some(request.key_id),
                    document_hash: None,
                    signing_time: None,
                }));
            }
        }
    } else if let Some(hash) = &request.document_hash {
        // Sign document hash
        let modified_request = SignDocumentRequest {
            key_id: request.key_id,
            document_hash: Some(hash.clone()),
            password: request.password.clone(),
            document_content: None,
        };
        
        match crate::key_verification::sign_document(&modified_request, &key_pair.private_key, key_pair.salt.as_deref()) {
            Ok(sig) => sig,
            Err(_) => {
                return Ok(Json(SignDocumentResponse {
                    success: false,
                    signature: None,
                    message: "Failed to sign document".to_string(),
                    key_id: Some(request.key_id),
                    document_hash: None,
                    signing_time: None,
                }));
            }
        }
    } else {
        return Ok(Json(SignDocumentResponse {
            success: false,
            signature: None,
            message: "Either document_hash or document_content must be provided".to_string(),
            key_id: Some(request.key_id),
            document_hash: None,
            signing_time: None,
        }));
    };

    // Update last used timestamp
    let _ = state.storage.update_last_used(request.key_id).await;

    let document_hash = if let Some(content) = &request.document_content {
        crate::key_verification::create_document_hash(content)
    } else if let Some(hash) = &request.document_hash {
        hash.clone()
    } else {
        return Ok(Json(SignDocumentResponse {
            success: false,
            signature: None,
            message: "Either document_hash or document_content must be provided".to_string(),
            key_id: Some(request.key_id),
            document_hash: None,
            signing_time: None,
        }));
    };

    Ok(Json(SignDocumentResponse {
        success: true,
        signature: Some(signature),
        message: "Document signed successfully".to_string(),
        key_id: Some(request.key_id),
        document_hash: Some(document_hash.clone()),
        signing_time: Some(chrono::Utc::now()),
    }))
}

/// Verify a document signature
pub async fn verify_signature(
    Json(request): Json<VerifySignatureRequest>,
) -> Json<VerifySignatureResponse> {
    // Handle document content if provided
    let document_hash = if let Some(content) = &request.document_content {
        crate::key_verification::create_document_hash(content)
    } else if let Some(hash) = &request.document_hash {
        hash.clone()
    } else {
        return Json(VerifySignatureResponse {
            success: false,
            is_valid: false,
            message: "Either document_hash or document_content must be provided".to_string(),
            key_info: None,
            verification_time: Some(chrono::Utc::now()),
            document_hash: None,
        });
    };

    // Create modified request with the hash
    let modified_request = VerifySignatureRequest {
        document_hash: Some(document_hash.clone()),
        public_key: request.public_key,
        signature: request.signature,
        document_content: None,
    };

    // Verify the signature
    let is_valid = match crate::key_verification::verify_signature(&modified_request) {
        Ok(valid) => valid,
        Err(_) => false,
    };

    let message = if is_valid {
        "Signature is valid".to_string()
    } else {
        "Signature is invalid".to_string()
    };

    Json(VerifySignatureResponse {
        success: true,
        is_valid,
        message,
        key_info: None, // We don't have key info in this context
        verification_time: Some(chrono::Utc::now()),
        document_hash: Some(document_hash),
    })
}

/// Update key information
pub async fn update_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<Uuid>,
    Json(request): Json<UpdateKeyRequest>,
) -> Result<Json<UpdateKeyResponse>, StatusCode> {
    match state.storage.update_key(key_id, request).await {
        Ok(key_pair) => {
            let key_info = KeyInfo {
                id: key_pair.id,
                name: key_pair.name,
                description: key_pair.description,
                public_key: key_pair.public_key,
                created_at: key_pair.created_at,
                last_used: key_pair.last_used,
                expires_at: key_pair.expires_at,
                is_active: key_pair.is_active,
                tags: key_pair.tags,
                key_type: key_pair.key_type,
                key_strength: key_pair.key_strength,
            };

            Ok(Json(UpdateKeyResponse {
                success: true,
                key_info: Some(key_info),
                message: "Key updated successfully".to_string(),
            }))
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// Revoke a key
pub async fn revoke_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<Uuid>,
    Json(request): Json<RevokeKeyRequest>,
) -> Result<Json<RevokeKeyResponse>, StatusCode> {
    match state.storage.revoke_key(key_id, request.reason).await {
        Ok(()) => {
            // Get the updated key info
            match state.storage.get_key(key_id).await {
                Ok(key_pair) => {
                    let key_info = KeyInfo {
                        id: key_pair.id,
                        name: key_pair.name,
                        description: key_pair.description,
                        public_key: key_pair.public_key,
                        created_at: key_pair.created_at,
                        last_used: key_pair.last_used,
                        expires_at: key_pair.expires_at,
                        is_active: key_pair.is_active,
                        tags: key_pair.tags,
                        key_type: key_pair.key_type,
                        key_strength: key_pair.key_strength,
                    };

                    Ok(Json(RevokeKeyResponse {
                        success: true,
                        key_info: Some(key_info),
                        message: "Key revoked successfully".to_string(),
                        revocation_time: Some(chrono::Utc::now()),
                    }))
                }
                Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            }
        }
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// Get key statistics
pub async fn get_key_stats(
    State(state): State<Arc<AppState>>,
) -> Json<KeyStatsResponse> {
    let (total, active, expired, revoked) = state.storage.get_key_stats().await;
    let expiring_soon = state.storage.get_keys_expiring_soon(30).await.len();

    Json(KeyStatsResponse {
        success: true,
        total_keys: total,
        active_keys: active,
        expired_keys: expired,
        revoked_keys: revoked,
        keys_expiring_soon: expiring_soon,
        message: format!("Retrieved statistics for {} keys", total),
    })
}

/// Search keys
pub async fn search_keys(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListKeysQuery>,
) -> Json<ListKeysResponse> {
    let keys = if let Some(search) = &query.search {
        state.storage.search_keys(search).await
    } else {
        state.storage.list_keys().await
    };
    
    let (total, active, expired, _) = state.storage.get_key_stats().await;
    
    Json(ListKeysResponse {
        success: true,
        keys: keys.clone(),
        message: format!("Found {} matching keys", keys.len()),
        total_count: total,
        active_count: active,
        expired_count: expired,
    })
}
