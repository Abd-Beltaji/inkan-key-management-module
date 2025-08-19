use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Converts a public key to a fingerprint for easy identification
pub fn public_key_to_fingerprint(public_key_b64: &str) -> Result<String, String> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(public_key_b64)
        .map_err(|_| "Invalid public key encoding".to_string())?;
    
    let mut hasher = Sha256::new();
    hasher.update(&public_key_bytes);
    let hash = hasher.finalize();
    
    // Take first 16 bytes and format as hex
    let fingerprint = hex::encode(&hash[..16]);
    
    // Format as groups of 4 with colons
    let mut formatted = String::new();
    for (i, chunk) in fingerprint.as_bytes().chunks(4).enumerate() {
        if i > 0 {
            formatted.push(':');
        }
        formatted.push_str(&hex::encode(chunk));
    }
    
    Ok(formatted)
}

/// Validates a base64 string
pub fn is_valid_base64(input: &str) -> bool {
    base64::engine::general_purpose::STANDARD.decode(input).is_ok()
}

/// Creates a secure random string
pub fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    let mut rng = rand::thread_rng();
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Formats a timestamp for display
pub fn format_timestamp(timestamp: chrono::DateTime<chrono::Utc>) -> String {
    timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// Validates a UUID string
pub fn is_valid_uuid(input: &str) -> bool {
    uuid::Uuid::parse_str(input).is_ok()
}

/// Creates a document hash from various input types
pub fn create_document_hash_from_input(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validates key pair compatibility
pub fn validate_key_pair_compatibility(
    public_key_b64: &str,
    private_key_b64: &str,
) -> Result<bool, String> {
    let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(public_key_b64)
        .map_err(|_| "Invalid public key encoding".to_string())?;
    
    let private_key_bytes = base64::engine::general_purpose::STANDARD.decode(private_key_b64)
        .map_err(|_| "Invalid private key encoding".to_string())?;
    
    // Try to create the keys
    let public_key = VerifyingKey::from_bytes(&public_key_bytes.try_into().unwrap())
        .map_err(|_| "Invalid public key format".to_string())?;
    
    // Create signing key from the private key bytes
    let signing_key = SigningKey::from_keypair_bytes(&private_key_bytes.try_into().unwrap())
        .map_err(|_| "Invalid signing key".to_string())?;
    
    // Check if they correspond to each other
    let derived_public = signing_key.verifying_key();
    
    Ok(derived_public == public_key)
}

/// Sanitizes a key name for safe storage
pub fn sanitize_key_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_')
        .collect::<String>()
        .replace("  ", " ")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_public_key_to_fingerprint() {
        // Create a dummy public key (32 bytes)
        let dummy_key = vec![0u8; 32];
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&dummy_key);
        
        let fingerprint = public_key_to_fingerprint(&public_key_b64).unwrap();
        
        // Should be 16 bytes = 32 hex chars, formatted with colons
        assert!(fingerprint.contains(':'));
        assert_eq!(fingerprint.matches(':').count(), 3); // 4 groups
    }
    
    #[test]
    fn test_is_valid_base64() {
        assert!(is_valid_base64("SGVsbG8gV29ybGQ=")); // "Hello World"
        assert!(!is_valid_base64("Invalid base64!"));
    }
    
    #[test]
    fn test_generate_random_string() {
        let random = generate_random_string(10);
        assert_eq!(random.len(), 10);
        assert!(random.chars().all(|c| c.is_alphanumeric()));
    }
    
    #[test]
    fn test_is_valid_uuid() {
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(is_valid_uuid(valid_uuid));
        
        let invalid_uuid = "not-a-uuid";
        assert!(!is_valid_uuid(invalid_uuid));
    }
    
    #[test]
    fn test_create_document_hash_from_input() {
        let input = "Hello, World!";
        let hash = create_document_hash_from_input(input);
        
        assert_eq!(hash.len(), 64); // SHA256 produces 32 bytes = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_sanitize_key_name() {
        let dirty_name = "  My Key Name!@#$%^&*()  ";
        let clean_name = sanitize_key_name(dirty_name);
        
        assert_eq!(clean_name, "My Key Name");
    }
}
