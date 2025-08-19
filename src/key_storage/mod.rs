use crate::models::{KeyPair, KeyInfo, KeyManagementError, UpdateKeyRequest, KeyType, KeyStrength};
use chrono::{Utc, Duration};
use serde_json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;
use uuid::Uuid;

/// In-memory storage for key pairs (in production, use a proper database)
pub struct KeyStorage {
    keys: Arc<Mutex<HashMap<Uuid, KeyPair>>>,
    storage_path: String,
}

impl KeyStorage {
    /// Creates a new key storage instance
    pub fn new(storage_path: &str) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            storage_path: storage_path.to_string(),
        }
    }
    
    /// Stores a key pair
    pub async fn store_key(&self, key_pair: KeyPair) -> Result<(), KeyManagementError> {
        let key_id = key_pair.id;
        
        // Store in memory
        {
            let mut keys = self.keys.lock().await;
            keys.insert(key_id, key_pair.clone());
        }
        
        // Store on disk
        self.save_to_disk().await?;
        
        Ok(())
    }
    
    /// Retrieves a key pair by ID
    pub async fn get_key(&self, key_id: Uuid) -> Result<KeyPair, KeyManagementError> {
        let keys = self.keys.lock().await;
        let key_pair = keys.get(&key_id)
            .cloned()
            .ok_or(KeyManagementError::KeyNotFound(key_id))?;
        
        // Check if key is expired
        if let Some(expires_at) = key_pair.expires_at {
            if Utc::now() > expires_at {
                return Err(KeyManagementError::KeyExpired(key_id));
            }
        }
        
        // Check if key is active
        if !key_pair.is_active {
            return Err(KeyManagementError::KeyRevoked(key_id));
        }
        
        Ok(key_pair)
    }
    
    /// Lists all keys (returns only public information)
    pub async fn list_keys(&self) -> Vec<KeyInfo> {
        let keys = self.keys.lock().await;
        let now = Utc::now();
        
        keys.values()
            .map(|key_pair| {
                let is_expired = key_pair.expires_at.map_or(false, |exp| now > exp);
                let is_active = key_pair.is_active && !is_expired;
                
                KeyInfo {
                    id: key_pair.id,
                    name: key_pair.name.clone(),
                    description: key_pair.description.clone(),
                    public_key: key_pair.public_key.clone(),
                    created_at: key_pair.created_at,
                    last_used: key_pair.last_used,
                    expires_at: key_pair.expires_at,
                    is_active,
                    tags: key_pair.tags.clone(),
                    key_type: key_pair.key_type.clone(),
                    key_strength: key_pair.key_strength.clone(),
                }
            })
            .collect()
    }
    
    /// Lists keys with filtering options
    pub async fn list_keys_filtered(
        &self,
        active_only: Option<bool>,
        key_type: Option<KeyType>,
        tags: Option<Vec<String>>,
    ) -> Vec<KeyInfo> {
        let keys = self.list_keys().await;
        
        keys.into_iter()
            .filter(|key| {
                // Filter by active status
                if let Some(active) = active_only {
                    if key.is_active != active {
                        return false;
                    }
                }
                
                // Filter by key type
                if let Some(ref kt) = key_type {
                    if key.key_type != *kt {
                        return false;
                    }
                }
                
                // Filter by tags
                if let Some(ref required_tags) = tags {
                    if !required_tags.iter().all(|tag| key.tags.contains(tag)) {
                        return false;
                    }
                }
                
                true
            })
            .collect()
    }
    
    /// Updates the last used timestamp for a key
    pub async fn update_last_used(&self, key_id: Uuid) -> Result<(), KeyManagementError> {
        let mut keys = self.keys.lock().await;
        if let Some(key_pair) = keys.get_mut(&key_id) {
            key_pair.last_used = Some(Utc::now());
            Ok(())
        } else {
            Err(KeyManagementError::KeyNotFound(key_id))
        }
    }
    
    /// Updates key information
    pub async fn update_key(&self, key_id: Uuid, update: UpdateKeyRequest) -> Result<KeyPair, KeyManagementError> {
        let mut keys = self.keys.lock().await;
        if let Some(key_pair) = keys.get_mut(&key_id) {
            if let Some(name) = update.name {
                key_pair.name = name;
            }
            if let Some(description) = update.description {
                key_pair.description = Some(description);
            }
            if let Some(tags) = update.tags {
                key_pair.tags = tags;
            }
            if let Some(expires_at) = update.expires_at {
                key_pair.expires_at = Some(expires_at);
            }
            if let Some(is_active) = update.is_active {
                key_pair.is_active = is_active;
            }
            
            let updated_key_pair = key_pair.clone();
            drop(keys);
            
            // Save to disk
            self.save_to_disk().await?;
            
            Ok(updated_key_pair)
        } else {
            Err(KeyManagementError::KeyNotFound(key_id))
        }
    }
    
    /// Deactivates a key
    pub async fn deactivate_key(&self, key_id: Uuid) -> Result<(), KeyManagementError> {
        let mut keys = self.keys.lock().await;
        if let Some(key_pair) = keys.get_mut(&key_id) {
            key_pair.is_active = false;
            Ok(())
        } else {
            Err(KeyManagementError::KeyNotFound(key_id))
        }
    }
    
    /// Revokes a key (marks as inactive and sets expiration to now)
    pub async fn revoke_key(&self, key_id: Uuid, _reason: Option<String>) -> Result<(), KeyManagementError> {
        let mut keys = self.keys.lock().await;
        if let Some(key_pair) = keys.get_mut(&key_id) {
            key_pair.is_active = false;
            key_pair.expires_at = Some(Utc::now());
            // TODO: Store revocation reason
            Ok(())
        } else {
            Err(KeyManagementError::KeyNotFound(key_id))
        }
    }
    
    /// Rotates a key by creating a new one and deactivating the old one
    pub async fn rotate_key(&self, old_key_id: Uuid) -> Result<(), KeyManagementError> {
        // First deactivate the old key
        self.deactivate_key(old_key_id).await?;
        
        // TODO: Implement key rotation logic
        // This would typically involve:
        // 1. Creating a new key pair
        // 2. Migrating any necessary data
        // 3. Updating references
        // 4. Setting a grace period for the old key
        
        Ok(())
    }
    
    /// Gets keys that are expiring soon (within specified days)
    pub async fn get_keys_expiring_soon(&self, days: u32) -> Vec<KeyInfo> {
        let keys = self.list_keys().await;
        let threshold = Utc::now() + Duration::days(days as i64);
        
        keys.into_iter()
            .filter(|key| {
                if let Some(expires_at) = key.expires_at {
                    expires_at <= threshold && expires_at > Utc::now()
                } else {
                    false
                }
            })
            .collect()
    }
    
    /// Gets key statistics
    pub async fn get_key_stats(&self) -> (usize, usize, usize, usize) {
        let keys = self.list_keys().await;
        let now = Utc::now();
        
        let total = keys.len();
        let active = keys.iter().filter(|k| k.is_active).count();
        let expired = keys.iter().filter(|k| {
            k.expires_at.map_or(false, |exp| now > exp)
        }).count();
        let revoked = keys.iter().filter(|k| !k.is_active).count();
        
        (total, active, expired, revoked)
    }
    
    /// Loads keys from disk on startup
    pub async fn load_from_disk(&self) -> Result<(), KeyManagementError> {
        let path = Path::new(&self.storage_path);
        if !path.exists() {
            // Create directory if it doesn't exist
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await
                    .map_err(|e| KeyManagementError::StorageError(format!("Failed to create directory: {}", e)))?;
            }
            return Ok(());
        }
        
        let content = fs::read_to_string(path).await
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to read storage file: {}", e)))?;
        
        if content.is_empty() {
            return Ok(());
        }
        
        let keys: Vec<KeyPair> = serde_json::from_str(&content)
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to parse storage file: {}", e)))?;
        
        let mut key_map = self.keys.lock().await;
        for key_pair in keys {
            key_map.insert(key_pair.id, key_pair);
        }
        
        Ok(())
    }
    
    /// Saves keys to disk
    async fn save_to_disk(&self) -> Result<(), KeyManagementError> {
        let keys = self.keys.lock().await;
        let keys_vec: Vec<&KeyPair> = keys.values().collect();
        
        let content = serde_json::to_string_pretty(&keys_vec)
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to serialize keys: {}", e)))?;
        
        fs::write(&self.storage_path, content).await
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to write storage file: {}", e)))?;
        
        Ok(())
    }
    
    /// Gets the count of stored keys
    pub async fn key_count(&self) -> usize {
        let keys = self.keys.lock().await;
        keys.len()
    }
    
    /// Checks if a key exists
    pub async fn key_exists(&self, key_id: Uuid) -> bool {
        let keys = self.keys.lock().await;
        keys.contains_key(&key_id)
    }
    
    /// Searches keys by name or tags
    pub async fn search_keys(&self, query: &str) -> Vec<KeyInfo> {
        let keys = self.list_keys().await;
        let query_lower = query.to_lowercase();
        
        keys.into_iter()
            .filter(|key| {
                key.name.to_lowercase().contains(&query_lower) ||
                key.description.as_ref().map_or(false, |desc| desc.to_lowercase().contains(&query_lower)) ||
                key.tags.iter().any(|tag| tag.to_lowercase().contains(&query_lower))
            })
            .collect()
    }
    
    /// Creates a backup of the current keys
    pub async fn create_backup(&self, backup_path: &str) -> Result<(), KeyManagementError> {
        let keys = self.keys.lock().await;
        let keys_vec: Vec<&KeyPair> = keys.values().collect();
        
        let content = serde_json::to_string_pretty(&keys_vec)
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to serialize keys for backup: {}", e)))?;
        
        fs::write(backup_path, content).await
            .map_err(|e| KeyManagementError::StorageError(format!("Failed to write backup file: {}", e)))?;
        
        Ok(())
    }
}

/// Creates a default key storage instance
pub fn create_default_storage() -> KeyStorage {
    let storage_path = std::env::var("STORAGE_PATH").unwrap_or_else(|_| "keys.json".to_string());
    KeyStorage::new(&storage_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_generation::generate_test_key_pair;
    use crate::models::{GenerateKeyRequest, UpdateKeyRequest};
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_store_and_retrieve_key() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("test_keys.json");
        let storage = KeyStorage::new(storage_path.to_str().unwrap());
        
        let key_pair = generate_test_key_pair("Test Key").unwrap();
        let key_id = key_pair.id;
        
        // Store the key
        storage.store_key(key_pair.clone()).await.unwrap();
        
        // Retrieve the key
        let retrieved = storage.get_key(key_id).await.unwrap();
        assert_eq!(retrieved.id, key_id);
        assert_eq!(retrieved.name, "Test Key");
    }
    
    #[tokio::test]
    async fn test_list_keys() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("test_keys.json");
        let storage = KeyStorage::new(storage_path.to_str().unwrap());
        
        let key_pair = generate_test_key_pair("Test Key").unwrap();
        storage.store_key(key_pair).await.unwrap();
        
        let keys = storage.list_keys().await;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "Test Key");
    }
    
    #[tokio::test]
    async fn test_update_key() {
        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("test_keys.json");
        let storage = KeyStorage::new(storage_path.to_str().unwrap());
        
        let key_pair = generate_test_key_pair("Test Key").unwrap();
        let key_id = key_pair.id;
        storage.store_key(key_pair).await.unwrap();
        
        let update = UpdateKeyRequest {
            name: Some("Updated Key".to_string()),
            description: Some("Updated description".to_string()),
            tags: Some(vec!["updated".to_string()]),
            expires_at: None,
            is_active: None,
        };
        
        let updated = storage.update_key(key_id, update).await.unwrap();
        assert_eq!(updated.name, "Updated Key");
        assert_eq!(updated.description, Some("Updated description".to_string()));
        assert_eq!(updated.tags, vec!["updated"]);
    }
}
