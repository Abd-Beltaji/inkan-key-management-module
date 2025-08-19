use crate::models::{KeyManagementError, SignDocumentRequest, VerifySignatureRequest};
use crate::key_generation::decrypt_private_key;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Signs a document hash with a private key
pub fn sign_document(
    request: &SignDocumentRequest,
    private_key_b64: &str,
    salt_b64: Option<&str>,
) -> Result<String, KeyManagementError> {
    // Decode the private key
    let private_key_bytes = base64::engine::general_purpose::STANDARD.decode(private_key_b64)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid private key encoding".to_string()))?;
    
    // Check if the private key is encrypted (longer than 64 bytes due to nonce + encrypted data)
    let signing_key = if private_key_bytes.len() > 64 {
        // Key is encrypted, need password to decrypt
        if let Some(password) = &request.password {
            let decrypted_bytes = decrypt_private_key(private_key_b64, password, salt_b64)?;
            SigningKey::from_keypair_bytes(&decrypted_bytes.try_into().unwrap())
                .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid decrypted private key format".to_string()))?
        } else {
            return Err(KeyManagementError::InvalidRequest(
                "Password required for encrypted private key".to_string()
            ));
        }
    } else {
        // Key is unencrypted (development mode)
        SigningKey::from_keypair_bytes(&private_key_bytes.try_into().unwrap())
            .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid private key format".to_string()))?
    };
    
    // Get the document hash to sign
    let document_hash = if let Some(hash) = &request.document_hash {
        if hash.len() == 64 {
            // Already a SHA256 hash
            hash.clone()
        } else {
            // Hash the document content
            let mut hasher = Sha256::new();
            hasher.update(hash.as_bytes());
            hex::encode(hasher.finalize())
        }
    } else {
        return Err(KeyManagementError::InvalidRequest(
            "Document hash or content must be provided".to_string()
        ));
    };
    
    // Convert hash to bytes
    let hash_bytes = hex::decode(&document_hash)
        .map_err(|_| KeyManagementError::InvalidRequest("Invalid document hash format".to_string()))?;
    
    // Sign the hash
    let signature = signing_key.sign(&hash_bytes);
    
    // Encode signature as base64
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    
    Ok(signature_b64)
}

/// Verifies a document signature using a public key
pub fn verify_signature(
    request: &VerifySignatureRequest,
) -> Result<bool, KeyManagementError> {
    // Decode the public key
    let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(&request.public_key)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid public key encoding".to_string()))?;
    
    // Create public key from bytes
    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid public key length".to_string()))?;
    
    let public_key = VerifyingKey::from_bytes(&public_key_array)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid public key format".to_string()))?;
    
    // Decode the signature
    let signature_bytes = base64::engine::general_purpose::STANDARD.decode(&request.signature)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid signature encoding".to_string()))?;
    
    // Create signature from bytes
    let signature_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid signature length".to_string()))?;
    
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    
    // Get the document hash to verify
    let document_hash = if let Some(hash) = &request.document_hash {
        if hash.len() == 64 {
            // Already a SHA256 hash
            hash.clone()
        } else {
            // Hash the document content
            let mut hasher = Sha256::new();
            hasher.update(hash.as_bytes());
            hex::encode(hasher.finalize())
        }
    } else {
        return Err(KeyManagementError::InvalidRequest(
            "Document hash or content must be provided".to_string()
        ));
    };
    
    // Convert hash to bytes
    let hash_bytes = hex::decode(&document_hash)
        .map_err(|_| KeyManagementError::InvalidRequest("Invalid document hash format".to_string()))?;
    
    // Verify the signature
    let is_valid = public_key.verify(&hash_bytes, &signature).is_ok();
    
    Ok(is_valid)
}

/// Creates a document hash from content
pub fn create_document_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validates a signature format without verifying
pub fn validate_signature_format(signature: &str) -> Result<(), KeyManagementError> {
    let signature_bytes = base64::engine::general_purpose::STANDARD.decode(signature)
        .map_err(|_| KeyManagementError::InvalidKeyFormat("Invalid signature encoding".to_string()))?;
    
    if signature_bytes.len() != 64 {
        return Err(KeyManagementError::InvalidKeyFormat(
            "Signature must be 64 bytes".to_string()
        ));
    }
    
    Ok(())
}

/// Validates a public key format without using it
pub fn validate_public_key_format(public_key: &str) -> Result<(), KeyManagementError> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(public_key)
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
    
    Ok(())
}

/// Batch verifies multiple signatures
pub fn batch_verify_signatures(
    verifications: Vec<VerifySignatureRequest>,
) -> Result<HashMap<usize, bool>, KeyManagementError> {
    let mut results = HashMap::new();
    
    for (index, verification) in verifications.into_iter().enumerate() {
        let is_valid = verify_signature(&verification)?;
        results.insert(index, is_valid);
    }
    
    Ok(results)
}

/// Creates a signature for a document content (convenience function)
pub fn sign_document_content(
    request: &SignDocumentRequest,
    private_key_b64: &str,
    salt_b64: Option<&str>,
    document_content: &str,
) -> Result<String, KeyManagementError> {
    // Create hash from content
    let document_hash = create_document_hash(document_content);
    
    // Create a modified request with the hash
    let modified_request = SignDocumentRequest {
        document_hash: Some(document_hash),
        key_id: request.key_id,
        password: request.password.clone(),
        document_content: None,
    };
    
    // Sign the document
    sign_document(&modified_request, private_key_b64, salt_b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generation::generate_test_key_pair;
    use crate::models::{GenerateKeyRequest, SignDocumentRequest, VerifySignatureRequest};
    
    #[test]
    fn test_sign_and_verify_document() {
        // Generate a key pair
        let request = GenerateKeyRequest {
            name: "Test Key".to_string(),
            description: None,
            password: None,
            expires_at: None,
            tags: None,
            key_strength: None,
        };
        
        let key_pair = generate_test_key_pair("Test Key").unwrap();
        
        // Create a test document
        let document_content = "Hello, World!";
        let document_hash = create_document_hash(document_content);
        
        // Sign the document
        let sign_request = SignDocumentRequest {
            key_id: key_pair.id,
            document_hash: document_hash.clone(),
            password: None,
            document_content: None,
        };
        
        let signature = sign_document(&sign_request, &key_pair.private_key).unwrap();
        
        // Verify the signature
        let verify_request = VerifySignatureRequest {
            public_key: key_pair.public_key,
            document_hash,
            signature,
            document_content: None,
        };
        
        let is_valid = verify_signature(&verify_request).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_sign_and_verify_with_encrypted_key() {
        // Generate an encrypted key pair
        let request = GenerateKeyRequest {
            name: "Encrypted Test Key".to_string(),
            description: None,
            password: Some("test_password_123".to_string()),
            expires_at: None,
            tags: None,
            key_strength: None,
        };
        
        let key_pair = generate_test_key_pair("Encrypted Test Key").unwrap();
        
        // Create a test document
        let document_content = "Hello, Encrypted World!";
        let document_hash = create_document_hash(document_content);
        
        // Sign the document with password
        let sign_request = SignDocumentRequest {
            key_id: key_pair.id,
            document_hash: document_hash.clone(),
            password: Some("test_password_123".to_string()),
            document_content: None,
        };
        
        let signature = sign_document(&sign_request, &key_pair.private_key).unwrap();
        
        // Verify the signature
        let verify_request = VerifySignatureRequest {
            public_key: key_pair.public_key,
            document_hash,
            signature,
            document_content: None,
        };
        
        let is_valid = verify_signature(&verify_request).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_invalid_signature() {
        // Generate a key pair
        let key_pair = generate_test_key_pair("Test Key").unwrap();
        
        // Create a test document
        let document_content = "Hello, World!";
        let document_hash = create_document_hash(document_content);
        
        // Create a fake signature
        let fake_signature = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64]);
        
        // Verify the fake signature
        let verify_request = VerifySignatureRequest {
            public_key: key_pair.public_key,
            document_hash,
            signature: fake_signature,
            document_content: None,
        };
        
        let is_valid = verify_signature(&verify_request).unwrap();
        assert!(!is_valid);
    }
    
    #[test]
    fn test_document_hash_creation() {
        let content = "Test document content";
        let hash = create_document_hash(content);
        
        assert_eq!(hash.len(), 64); // SHA256 produces 32 bytes = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_validate_signature_format() {
        let valid_signature = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 64]);
        assert!(validate_signature_format(&valid_signature).is_ok());
        
        let invalid_signature = "invalid";
        assert!(validate_signature_format(invalid_signature).is_err());
    }
    
    #[test]
    fn test_validate_public_key_format() {
        let valid_public_key = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 32]);
        assert!(validate_public_key_format(&valid_public_key).is_ok());
        
        let invalid_public_key = "invalid";
        assert!(validate_public_key_format(invalid_public_key).is_err());
    }
    
    #[test]
    fn test_sign_document_content() {
        let key_pair = generate_test_key_pair("Content Test Key").unwrap();
        let document_content = "Test document content for signing";
        
        let sign_request = SignDocumentRequest {
            key_id: key_pair.id,
            document_hash: "".to_string(), // Will be ignored
            password: None,
            document_content: None,
        };
        
        let signature = sign_document_content(&sign_request, &key_pair.private_key, document_content).unwrap();
        
        // Verify the signature
        let document_hash = create_document_hash(document_content);
        let verify_request = VerifySignatureRequest {
            public_key: key_pair.public_key,
            document_hash,
            signature,
            document_content: None,
        };
        
        let is_valid = verify_signature(&verify_request).unwrap();
        assert!(is_valid);
    }
}
