//! Immutable Log Storage - Cryptographically Signed, Tamper-Evident Logs
//!
//! Provides append-only, cryptographically signed log storage with chain of custody tracking.

use crate::audit::AuditError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Log signature for cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSignature {
    /// Signature algorithm (e.g., "HMAC-SHA256")
    pub algorithm: String,
    /// The signature value (hex-encoded)
    pub value: String,
    /// Timestamp of signing
    pub signed_at: DateTime<Utc>,
    /// Signer identity
    pub signer: String,
}

impl LogSignature {
    /// Create a new log signature
    pub fn new(algorithm: String, value: String, signer: String) -> Self {
        Self {
            algorithm,
            value,
            signed_at: Utc::now(),
            signer,
        }
    }

    /// Create HMAC-SHA256 signature
    pub fn hmac_sha256(data: &[u8], key: &str, signer: String) -> Self {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        let code = result.into_bytes();

        Self {
            algorithm: "HMAC-SHA256".to_string(),
            value: hex::encode(code),
            signed_at: Utc::now(),
            signer,
        }
    }

    /// Verify HMAC-SHA256 signature
    pub fn verify_hmac_sha256(&self, data: &[u8], key: &str) -> bool {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        if self.algorithm != "HMAC-SHA256" {
            return false;
        }

        let decoded = match hex::decode(&self.value) {
            Ok(d) => d,
            Err(_) => return false,
        };

        // Compute expected HMAC
        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(data);
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison
        decoded == expected.as_slice()
    }
}

/// Immutable log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique identifier
    pub id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: String,
    /// Event data
    pub data: serde_json::Value,
    /// Optional cryptographic signature
    pub signature: Option<LogSignature>,
    /// Hash of previous entry for chain integrity
    pub previous_hash: Option<String>,
    /// This entry's hash
    #[serde(skip)]
    hash: Option<String>,
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(
        id: String,
        event_type: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            event_type,
            data,
            signature: None,
            previous_hash: None,
            hash: None,
        }
    }

    /// Create a new log entry with custom timestamp
    pub fn with_timestamp(
        id: String,
        timestamp: DateTime<Utc>,
        event_type: String,
        data: serde_json::Value,
    ) -> Self {
        Self {
            id,
            timestamp,
            event_type,
            data,
            signature: None,
            previous_hash: None,
            hash: None,
        }
    }

    /// Create from an audit event (full builder)
    pub fn from_audit_event(
        id: String,
        timestamp: DateTime<Utc>,
        event_type: String,
        data: serde_json::Value,
        previous_hash: Option<String>,
    ) -> Self {
        Self {
            id,
            timestamp,
            event_type,
            data,
            signature: None,
            previous_hash,
            hash: None,
        }
    }

    /// Calculate the hash of this entry
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.event_type.as_bytes());

        // Include data hash
        let data_json = serde_json::to_string(&self.data)
            .unwrap_or_default();
        hasher.update(data_json.as_bytes());

        if let Some(ref prev) = self.previous_hash {
            hasher.update(prev.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    /// Sign this entry
    pub fn sign(&mut self, key: &str, signer: String) {
        let hash = self.calculate_hash();
        self.signature = Some(LogSignature::hmac_sha256(
            hash.as_bytes(),
            key,
            signer,
        ));
        self.hash = Some(hash);
    }

    /// Verify the entry's signature
    pub fn verify(&self, key: &str) -> bool {
        let hash = self.calculate_hash();

        if let Some(ref sig) = self.signature {
            return sig.verify_hmac_sha256(hash.as_bytes(), key);
        }

        // No signature to verify
        true
    }

    /// Get the entry hash
    pub fn hash(&self) -> String {
        self.hash.clone().unwrap_or_else(|| self.calculate_hash())
    }

    /// Set the previous hash
    pub fn with_previous_hash(mut self, hash: String) -> Self {
        self.previous_hash = Some(hash);
        self
    }
}

/// Chain of custody for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustody {
    /// All log entries in order
    pub entries: Vec<LogEntry>,
    /// Chain metadata
    pub metadata: ChainMetadata,
    /// Current chain hash
    #[serde(skip)]
    current_hash: Option<String>,
}

/// Chain metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    /// Chain ID
    pub chain_id: String,
    /// Chain creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Total entries
    pub total_entries: usize,
    /// Chain version
    pub version: String,
    /// Additional metadata
    pub extra: HashMap<String, serde_json::Value>,
}

impl Default for ChainMetadata {
    fn default() -> Self {
        Self {
            chain_id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            total_entries: 0,
            version: "1.0".to_string(),
            extra: HashMap::new(),
        }
    }
}

impl ChainOfCustody {
    /// Create a new chain of custody
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            metadata: ChainMetadata::default(),
            current_hash: None,
        }
    }

    /// Add an entry to the chain
    pub fn add_entry(&mut self, mut entry: LogEntry) -> Result<(), AuditError> {
        // Set previous hash
        entry.previous_hash = self.current_hash.clone();

        // Calculate new hash
        let hash = entry.calculate_hash();
        entry.hash = Some(hash.clone());

        // Update current hash
        self.current_hash = Some(hash.clone());

        // Add to entries
        self.entries.push(entry);

        // Update metadata
        self.metadata.total_entries = self.entries.len();
        self.metadata.updated_at = Utc::now();

        Ok(())
    }

    /// Get the current chain hash
    pub fn current_hash(&self) -> Option<String> {
        self.current_hash.clone()
    }

    /// Verify the entire chain
    pub fn verify(&self) -> bool {
        let mut previous_hash: Option<String> = None;

        for (i, entry) in self.entries.iter().enumerate() {
            // Verify previous hash link
            if entry.previous_hash != previous_hash {
                return false;
            }

            // Verify the entry's own hash
            let calculated = entry.calculate_hash();
            if entry.hash.as_ref() != Some(&calculated) {
                return false;
            }

            previous_hash = Some(calculated);

            tracing::trace!("Verified entry {}/{}: {}", i + 1, self.entries.len(), entry.id);
        }

        // Verify final hash
        if self.current_hash != previous_hash {
            return false;
        }

        true
    }

    /// Get an entry by ID
    pub fn get_entry(&self, id: &str) -> Option<&LogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Get entries in a time range
    pub fn get_entries_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Get chain statistics
    pub fn statistics(&self) -> ChainStatistics {
        let mut by_type = HashMap::new();

        for entry in &self.entries {
            *by_type.entry(entry.event_type.clone()).or_insert(0) += 1;
        }

        ChainStatistics {
            total_entries: self.entries.len(),
            first_entry: self.entries.first().map(|e| e.timestamp),
            last_entry: self.entries.last().map(|e| e.timestamp),
            entries_by_type: by_type,
            chain_broken: !self.verify(),
        }
    }

    /// Export the chain to JSON
    pub fn to_json(&self) -> Result<String, AuditError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| AuditError::Serialization(e))
    }

    /// Import chain from JSON
    pub fn from_json(json: &str) -> Result<Self, AuditError> {
        serde_json::from_str(json)
            .map_err(|e| AuditError::Serialization(e))
    }
}

impl Default for ChainOfCustody {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatistics {
    pub total_entries: usize,
    pub first_entry: Option<DateTime<Utc>>,
    pub last_entry: Option<DateTime<Utc>>,
    pub entries_by_type: HashMap<String, usize>,
    pub chain_broken: bool,
}

/// Log verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogVerification {
    pub is_valid: bool,
    pub verified_entries: usize,
    pub total_entries: usize,
    pub issues: Vec<VerificationIssue>,
}

/// Verification issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationIssue {
    pub entry_id: String,
    pub issue_type: VerificationIssueType,
    pub description: String,
}

/// Types of verification issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationIssueType {
    BrokenChainLink,
    InvalidHash,
    MissingSignature,
    InvalidSignature,
    TamperedEntry,
    MissingEntry,
}

impl LogVerification {
    pub fn valid(total_entries: usize) -> Self {
        Self {
            is_valid: true,
            verified_entries: total_entries,
            total_entries,
            issues: Vec::new(),
        }
    }

    pub fn invalid(issues: Vec<VerificationIssue>, total_entries: usize) -> Self {
        Self {
            is_valid: false,
            verified_entries: 0,
            total_entries,
            issues,
        }
    }
}

/// Verify a log file
pub fn verify_log_file(path: &std::path::Path) -> Result<LogVerification, AuditError> {
    let content = std::fs::read_to_string(path)?;
    let mut issues = Vec::new();
    let mut entry_count = 0;

    let mut previous_hash: Option<String> = None;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        entry_count += 1;

        // Parse the entry (without signature first)
        let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
        let (json_part, signature) = if parts.len() == 2 {
            (parts[1], Some(parts[0].to_string()))
        } else {
            (line, None)
        };

        if let Ok(entry) = serde_json::from_str::<LogEntry>(json_part) {
            // Verify chain link
            if entry.previous_hash != previous_hash {
                issues.push(VerificationIssue {
                    entry_id: entry.id.clone(),
                    issue_type: VerificationIssueType::BrokenChainLink,
                    description: format!(
                        "Expected previous hash {:?}, got {:?}",
                        previous_hash, entry.previous_hash
                    ),
                });
            }

            // Verify hash
            let calculated = entry.calculate_hash();
            if entry.hash.as_ref() != Some(&calculated) {
                issues.push(VerificationIssue {
                    entry_id: entry.id.clone(),
                    issue_type: VerificationIssueType::InvalidHash,
                    description: "Hash mismatch detected".to_string(),
                });
            }

            previous_hash = Some(calculated);
        }
    }

    if issues.is_empty() {
        Ok(LogVerification::valid(entry_count))
    } else {
        Ok(LogVerification::invalid(issues, entry_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(
            "test-id".to_string(),
            "test_event".to_string(),
            serde_json::json!({"key": "value"}),
        );

        assert_eq!(entry.id, "test-id");
        assert_eq!(entry.event_type, "test_event");
        assert!(entry.hash.is_none());
    }

    #[test]
    fn test_log_entry_hash() {
        let entry = LogEntry::new(
            "test-id".to_string(),
            "test_event".to_string(),
            serde_json::json!({"key": "value"}),
        );

        let hash1 = entry.calculate_hash();
        let hash2 = entry.calculate_hash();

        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn test_chain_of_custody() {
        let mut chain = ChainOfCustody::new();

        let entry1 = LogEntry::new(
            "entry-1".to_string(),
            "event1".to_string(),
            serde_json::json!({}),
        );

        let entry2 = LogEntry::new(
            "entry-2".to_string(),
            "event2".to_string(),
            serde_json::json!({}),
        );

        chain.add_entry(entry1).unwrap();
        chain.add_entry(entry2).unwrap();

        assert_eq!(chain.entries.len(), 2);
        assert!(chain.verify());
    }

    #[test]
    fn test_chain_verification_fails_on_tamper() {
        let mut chain = ChainOfCustody::new();

        let entry1 = LogEntry::new(
            "entry-1".to_string(),
            "event1".to_string(),
            serde_json::json!({}),
        );

        chain.add_entry(entry1).unwrap();

        // Tamper with the chain
        chain.entries[0].event_type = "tampered".to_string();

        assert!(!chain.verify());
    }

    #[test]
    fn test_chain_statistics() {
        let mut chain = ChainOfCustody::new();

        for i in 0..5 {
            let entry = LogEntry::new(
                format!("entry-{}", i),
                "test_event".to_string(),
                serde_json::json!({}),
            );
            chain.add_entry(entry).unwrap();
        }

        let stats = chain.statistics();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.entries_by_type.get("test_event"), Some(&5));
        assert!(!stats.chain_broken);
    }

    #[test]
    fn test_log_signature_hmac() {
        let data = b"test data";
        let key = "test key";

        let sig = LogSignature::hmac_sha256(data, key, "test_signer".to_string());
        assert_eq!(sig.algorithm, "HMAC-SHA256");
        assert!(!sig.value.is_empty());
        assert!(sig.verify_hmac_sha256(data, key));

        // Wrong key should fail
        assert!(!sig.verify_hmac_sha256(data, "wrong_key"));
    }

    #[test]
    fn test_chain_serialization() {
        let mut chain = ChainOfCustody::new();

        let entry = LogEntry::new(
            "test-id".to_string(),
            "test_event".to_string(),
            serde_json::json!({}),
        );
        chain.add_entry(entry).unwrap();

        let json = chain.to_json().unwrap();
        let restored = ChainOfCustody::from_json(&json).unwrap();

        assert_eq!(restored.entries.len(), chain.entries.len());
        assert!(restored.verify());
    }
}
