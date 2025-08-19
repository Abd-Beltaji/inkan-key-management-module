use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Key pair information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub public_key: String, // Base64 encoded
    pub private_key: String, // Base64 encoded (encrypted in production)
    pub salt: Option<String>, // Salt for encrypted private keys
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub tags: Vec<String>,
    pub key_type: KeyType,
    pub key_strength: KeyStrength,
}

/// Type of cryptographic key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    Ed25519,
    Ed25519Encrypted,
    #[serde(other)]
    Unknown,
}

/// Cryptographic strength of the key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyStrength {
    Standard,    // 256-bit
    High,        // 384-bit
    Ultra,       // 512-bit
    #[serde(other)]
    Unknown,
}

/// Request to generate a new key pair
#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub password: Option<String>, // For encrypting private key
    pub expires_at: Option<DateTime<Utc>>, // Key expiration date
    pub tags: Option<Vec<String>>, // Key tags for organization
    pub key_strength: Option<KeyStrength>, // Desired key strength
}

/// Response for key generation
#[derive(Debug, Serialize)]
pub struct GenerateKeyResponse {
    pub success: bool,
    pub key_pair: Option<KeyPair>,
    pub message: String,
    pub warnings: Vec<String>, // Any warnings about the generated key
}

/// Request to sign a document
#[derive(Debug, Deserialize)]
pub struct SignDocumentRequest {
    pub key_id: Uuid,
    pub document_hash: Option<String>, // SHA256 hash of the document (optional if document_content provided)
    pub password: Option<String>, // If private key is encrypted
    pub document_content: Option<String>, // Alternative: provide content directly
}

/// Response for document signing
#[derive(Debug, Serialize)]
pub struct SignDocumentResponse {
    pub success: bool,
    pub signature: Option<String>,
    pub message: String,
    pub key_id: Option<Uuid>,
    pub document_hash: Option<String>, // The hash that was signed
    pub signing_time: Option<DateTime<Utc>>,
}

/// Request to verify a signature
#[derive(Debug, Deserialize)]
pub struct VerifySignatureRequest {
    pub public_key: String, // Base64 encoded public key
    pub document_hash: Option<String>, // SHA256 hash of the document (optional if document_content provided)
    pub signature: String, // Base64 encoded signature
    pub document_content: Option<String>, // Alternative: provide content directly
}

/// Response for signature verification
#[derive(Debug, Serialize)]
pub struct VerifySignatureResponse {
    pub success: bool,
    pub is_valid: bool,
    pub message: String,
    pub key_info: Option<KeyInfo>,
    pub verification_time: Option<DateTime<Utc>>,
    pub document_hash: Option<String>, // The hash that was verified
}

/// Public key information (safe to share)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub tags: Vec<String>,
    pub key_type: KeyType,
    pub key_strength: KeyStrength,
}

/// List of keys response
#[derive(Debug, Serialize)]
pub struct ListKeysResponse {
    pub success: bool,
    pub keys: Vec<KeyInfo>,
    pub message: String,
    pub total_count: usize,
    pub active_count: usize,
    pub expired_count: usize,
}

/// Public key response
#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub success: bool,
    pub key_info: Option<KeyInfo>,
    pub message: String,
}

/// Request to update key information
#[derive(Debug, Deserialize)]
pub struct UpdateKeyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: Option<bool>,
}

/// Response for key update
#[derive(Debug, Serialize)]
pub struct UpdateKeyResponse {
    pub success: bool,
    pub key_info: Option<KeyInfo>,
    pub message: String,
}

/// Request to rotate a key
#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub old_key_id: Uuid,
    pub new_key_name: String,
    pub new_key_description: Option<String>,
    pub new_key_password: Option<String>,
    pub new_key_tags: Option<Vec<String>>,
    pub new_key_expires_at: Option<DateTime<Utc>>,
}

/// Response for key rotation
#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub success: bool,
    pub old_key_info: Option<KeyInfo>,
    pub new_key_info: Option<KeyInfo>,
    pub message: String,
}

/// Request to revoke a key
#[derive(Debug, Deserialize)]
pub struct RevokeKeyRequest {
    pub key_id: Uuid,
    pub reason: Option<String>,
    pub immediate: bool, // If true, revoke immediately; if false, mark for expiration
}

/// Response for key revocation
#[derive(Debug, Serialize)]
pub struct RevokeKeyResponse {
    pub success: bool,
    pub key_info: Option<KeyInfo>,
    pub message: String,
    pub revocation_time: Option<DateTime<Utc>>,
}

/// Key statistics response
#[derive(Debug, Serialize)]
pub struct KeyStatsResponse {
    pub success: bool,
    pub total_keys: usize,
    pub active_keys: usize,
    pub expired_keys: usize,
    pub revoked_keys: usize,
    pub keys_expiring_soon: usize, // Within 30 days
    pub message: String,
}

/// Error types for the key management system
#[derive(Debug, thiserror::Error)]
pub enum KeyManagementError {
    #[error("Key not found: {0}")]
    KeyNotFound(Uuid),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    
    #[error("Private key decryption failed: {0}")]
    PrivateKeyDecryptionFailed(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Key expired: {0}")]
    KeyExpired(Uuid),
    
    #[error("Key revoked: {0}")]
    KeyRevoked(Uuid),
    
    #[error("Insufficient permissions: {0}")]
    InsufficientPermissions(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
}

impl From<KeyManagementError> for axum::http::StatusCode {
    fn from(err: KeyManagementError) -> Self {
        match err {
            KeyManagementError::KeyNotFound(_) => axum::http::StatusCode::NOT_FOUND,
            KeyManagementError::InvalidKeyFormat(_) => axum::http::StatusCode::BAD_REQUEST,
            KeyManagementError::SignatureVerificationFailed(_) => axum::http::StatusCode::BAD_REQUEST,
            KeyManagementError::PrivateKeyDecryptionFailed(_) => axum::http::StatusCode::UNAUTHORIZED,
            KeyManagementError::StorageError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            KeyManagementError::InvalidRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            KeyManagementError::InternalError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            KeyManagementError::KeyExpired(_) => axum::http::StatusCode::GONE,
            KeyManagementError::KeyRevoked(_) => axum::http::StatusCode::GONE,
            KeyManagementError::InsufficientPermissions(_) => axum::http::StatusCode::FORBIDDEN,
            KeyManagementError::RateLimitExceeded(_) => axum::http::StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::Ed25519
    }
}

impl Default for KeyStrength {
    fn default() -> Self {
        KeyStrength::Standard
    }
}
