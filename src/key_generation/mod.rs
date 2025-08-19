use crate::models::{GenerateKeyRequest, KeyPair, KeyManagementError, KeyType, KeyStrength};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use rand::Rng;
use uuid::Uuid;
use aes_gcm::{
    aead::{Aead, KeyInit, AeadCore},
    Aes256Gcm, Key, Nonce,
};
use sha2::Sha256;

/// Generates a new Ed25519 key pair for document signing
pub fn generate_key_pair(
    request: GenerateKeyRequest,
) -> Result<KeyPair, KeyManagementError> {
    // Generate a cryptographically secure Ed25519 key pair
    let mut rng = OsRng;
    tracing::info!("DEBUG: About to generate signing key");
    
    let signing_key = SigningKey::generate(&mut rng);
    
    tracing::info!("DEBUG: Signing key generated successfully");
    let verifying_key = signing_key.verifying_key();
    tracing::info!("DEBUG: Verifying key extracted successfully");
    
    // Convert keys to bytes
    let private_key_bytes = signing_key.to_keypair_bytes();
    let public_key_bytes = verifying_key.to_bytes();
    tracing::info!("DEBUG: Keys converted to bytes successfully");
    
    // Encrypt private key if password is provided
    tracing::info!("DEBUG: About to handle private key encryption");
    let (encrypted_private_key, salt) = if let Some(password) = &request.password {
        tracing::info!("DEBUG: Encrypting private key with password");
        match encrypt_private_key(&private_key_bytes, password) {
            Ok(result) => {
                tracing::info!("DEBUG: Private key encrypted successfully");
                result
            },
            Err(e) => {
                tracing::error!("DEBUG: Failed to encrypt private key: {:?}", e);
                return Err(e);
            }
        }
    } else {
        tracing::info!("DEBUG: Storing private key unencrypted");
        // For development, store unencrypted (not recommended for production)
        (base64::engine::general_purpose::STANDARD.encode(&private_key_bytes), None)
    };
    
    // Convert to base64 for storage
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);
    
    // Determine key type and strength
    let key_type = if request.password.is_some() {
        KeyType::Ed25519Encrypted
    } else {
        KeyType::Ed25519
    };
    
    let key_strength = request.key_strength.unwrap_or(KeyStrength::Standard);
    
    // Create key pair record
    let key_pair = KeyPair {
        id: Uuid::new_v4(),
        name: request.name,
        description: request.description,
        public_key: public_key_b64,
        private_key: encrypted_private_key,
        salt,
        created_at: Utc::now(),
        last_used: None,
        expires_at: request.expires_at,
        is_active: true,
        tags: request.tags.unwrap_or_default(),
        key_type,
        key_strength,
    };
    
    Ok(key_pair)
}

/// Encrypts a private key using AES-256-GCM with a password-derived key
fn encrypt_private_key(
    private_key: &[u8],
    password: &str,
) -> Result<(String, Option<String>), KeyManagementError> {
    // Generate a random salt
    let salt = rand::random::<[u8; 32]>();
    
    // Derive key from password using PBKDF2
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password.as_bytes(),
        &salt,
        100_000, // 100k iterations
        &mut key,
    ).map_err(|_| KeyManagementError::InternalError("PBKDF2 key derivation failed".to_string()))?;
    
    // Create AES-256-GCM cipher
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    
    // Generate random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the private key
    let encrypted_data = cipher
        .encrypt(&nonce, private_key)
        .map_err(|e| KeyManagementError::InternalError(format!("Encryption failed: {}", e)))?;
    
    // Combine nonce and encrypted data
    let mut combined = Vec::new();
    combined.extend_from_slice(nonce.as_slice());
    combined.extend_from_slice(&encrypted_data);
    
    // Encode as base64
    let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&combined);
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(&salt);
    
    Ok((encrypted_b64, Some(salt_b64)))
}

/// Decrypts a private key using the provided password
pub fn decrypt_private_key(
    encrypted_private_key: &str,
    password: &str,
    salt: Option<&str>,
) -> Result<Vec<u8>, KeyManagementError> {
    // Decode the encrypted data
    let encrypted_data = base64::engine::general_purpose::STANDARD.decode(encrypted_private_key)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid encrypted key encoding".to_string()))?;
    
    if encrypted_data.len() < 12 {
        return Err(KeyManagementError::InvalidKeyFormat("Encrypted data too short".to_string()));
    }
    
    // Extract nonce (first 12 bytes) and encrypted content
    let nonce_bytes = &encrypted_data[..12];
    let encrypted_content = &encrypted_data[12..];
    
    // Get salt (required for password-based decryption)
    let salt_bytes = if let Some(salt_str) = salt {
        base64::engine::general_purpose::STANDARD.decode(salt_str)
            .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid salt encoding".to_string()))?
    } else {
        return Err(KeyManagementError::InvalidRequest("Salt required for encrypted keys".to_string()));
    };
    
    // Derive key from password
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password.as_bytes(),
        &salt_bytes,
        100_000, // 100k iterations
        &mut key,
    ).map_err(|_| KeyManagementError::InternalError("PBKDF2 key derivation failed".to_string()))?;
    
    // Create AES-256-GCM cipher
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    
    // Create nonce
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the private key
    let decrypted_data = cipher
        .decrypt(nonce, encrypted_content)
        .map_err(|_| KeyManagementError::PrivateKeyDecryptionFailed("Invalid password or corrupted data".to_string()))?;
    
    Ok(decrypted_data)
}

/// Validates a key pair to ensure it's properly formatted
pub fn validate_key_pair(key_pair: &KeyPair) -> Result<(), KeyManagementError> {
    // Validate public key format
    let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_pair.public_key)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid public key encoding".to_string()))?;
    
    if public_key_bytes.len() != 32 {
        return Err(KeyManagementError::InvalidKeyFormat(
            "Public key must be 32 bytes".to_string()
        ));
    }
    
    // Try to parse as Ed25519 public key
    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid public key length".to_string()))?;
    
    VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid Ed25519 public key".to_string()))?;
    
    // Validate private key format (encrypted or unencrypted)
    let private_key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_pair.private_key)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid private key encoding".to_string()))?;
    
    // Check if it's encrypted (should be longer than 64 bytes due to nonce + encrypted data)
    if private_key_bytes.len() < 64 {
        return Err(KeyManagementError::InvalidKeyFormat(
            "Private key data too short".to_string()
        ));
    }
    
    Ok(())
}

/// Generates a key pair with additional metadata
pub fn generate_key_pair_with_metadata(
    name: String,
    description: Option<String>,
    password: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<KeyPair, KeyManagementError> {
    let request = GenerateKeyRequest {
        name,
        description,
        password,
        expires_at: None,
        tags,
        key_strength: None,
    };
    
    let key_pair = generate_key_pair(request)?;
    
    // TODO: Add tags support to KeyPair model
    // For now, we'll just return the basic key pair
    
    Ok(key_pair)
}

/// Generates a key pair for testing purposes (unencrypted)
#[cfg(test)]
pub fn generate_test_key_pair(name: &str) -> Result<KeyPair, KeyManagementError> {
    let request = GenerateKeyRequest {
        name: name.to_string(),
        description: None,
        password: None,
        expires_at: None,
        tags: None,
        key_strength: None,
    };
    
    generate_key_pair(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_key_pair() {
        let request = GenerateKeyRequest {
            name: "Test Key".to_string(),
            description: Some("Test key for unit testing".to_string()),
            password: None,
            expires_at: None,
            tags: None,
            key_strength: None,
        };
        
        let key_pair = generate_key_pair(request).unwrap();
        
        assert_eq!(key_pair.name, "Test Key");
        assert_eq!(key_pair.description, Some("Test key for unit testing".to_string()));
        assert!(key_pair.is_active);
        assert!(key_pair.last_used.is_none());
        
        // Validate the generated key pair
        validate_key_pair(&key_pair).unwrap();
    }
    
    #[test]
    fn test_generate_encrypted_key_pair() {
        let request = GenerateKeyRequest {
            name: "Encrypted Key".to_string(),
            description: None,
            password: Some("test_password_123".to_string()),
            expires_at: None,
            tags: None,
            key_strength: None,
        };
        
        let key_pair = generate_key_pair(request).unwrap();
        
        // Validate the generated key pair
        validate_key_pair(&key_pair).unwrap();
        
        // The private key should be encrypted (longer than 64 bytes due to nonce + encrypted data)
        let private_key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_pair.private_key).unwrap();
        assert!(private_key_bytes.len() > 64);
    }
    
    #[test]
    fn test_validate_key_pair() {
        let request = GenerateKeyRequest {
            name: "Valid Key".to_string(),
            description: None,
            password: None,
            expires_at: None,
            tags: None,
            key_strength: None,
        };
        
        let key_pair = generate_key_pair(request).unwrap();
        assert!(validate_key_pair(&key_pair).is_ok());
    }
    
    #[test]
    fn test_encrypt_decrypt_private_key() {
        let test_data = b"test private key data";
        let password = "test_password";
        
        let (encrypted, salt) = encrypt_private_key(test_data, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password, salt.as_deref()).unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }
}
