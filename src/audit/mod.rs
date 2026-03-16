//! Audit Logging Module for Warden v0.8.0 Enterprise Edition
//!
//! This module provides comprehensive audit logging capabilities for SOC2/ISO27001 compliance:
//! - Event logging (scans, configuration changes, user actions)
//! - Immutable, cryptographically signed logs
//! - SIEM export (Splunk, ELK Stack, Syslog)
//! - Configurable retention policies
//! - Real-time alerting on critical events
//!
//! # Example
//!
//! ```no_run
//! use warden::audit::{AuditLogger, AuditEvent, EventType};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let logger = AuditLogger::new("./audit_logs").await?;
//!
//!     logger.log(AuditEvent::scan_started(
//!         "user123",
//!         "http://example.com",
//!         "active"
//!     )).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod logger;
pub mod retention;
pub mod siem;
pub mod alerting;
pub mod immutable;

pub use logger::{AuditLogger, AuditConfig, AuditEvent, EventType, EventSeverity, EventResult, AuditFilter, AuditStatistics};
pub use retention::{RetentionPolicy, RetentionConfig, RetentionAction, ArchiveLocation, RetentionManager};
pub use siem::{SiemExporter, SiemConfig, SiemDestination, SiemFormat, SyslogConfig};
pub use alerting::{AlertManager, AlertConfig, AlertRule, AlertThreshold, NotificationChannel, AlertNotification};
pub use immutable::{LogSignature, ChainOfCustody, LogEntry, LogVerification, ChainMetadata, ChainStatistics};

/// Current version of the audit log format
pub const AUDIT_LOG_VERSION: &str = "1.0";

/// Default audit log directory name
pub const DEFAULT_AUDIT_DIR: &str = ".warden/audit";

/// Default index file for the audit log chain
pub const CHAIN_INDEX_FILE: &str = "chain_index.json";

/// Maximum log entry size (10 MB)
pub const MAX_ENTRY_SIZE_BYTES: usize = 10 * 1024 * 1024;

/// Audit error types
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Log verification failed: {0}")]
    VerificationFailed(String),

    #[error("SIEM export failed: {0}")]
    SiemExportFailed(String),

    #[error("Retention policy error: {0}")]
    RetentionError(String),

    #[error("Alerting error: {0}")]
    AlertError(String),

    #[error("Log entry too large: {size} bytes (max: {max} bytes)")]
    EntryTooLarge { size: usize, max: usize },

    #[error("Chain of custody broken: {0}")]
    ChainOfCustodyBroken(String),

    #[error("Audit log not found: {0}")]
    LogNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type for audit operations
pub type AuditResult<T> = Result<T, AuditError>;

/// Metadata about an audit log entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditMetadata {
    /// Unique identifier for this entry
    pub id: String,
    /// Timestamp when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event type
    pub event_type: String,
    /// Event severity
    pub severity: String,
    /// User or system that initiated the event
    pub actor: String,
    /// IP address of the actor (if applicable)
    pub actor_ip: Option<String>,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Additional tags for filtering
    pub tags: Vec<String>,
    /// Checksum for integrity verification
    pub checksum: String,
}

impl AuditMetadata {
    /// Create new audit metadata
    pub fn new(
        event_type: EventType,
        severity: EventSeverity,
        actor: String,
    ) -> Self {
        use uuid::Uuid;
        use sha2::Digest;

        let id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();

        let mut metadata = Self {
            id: id.clone(),
            timestamp,
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            actor,
            actor_ip: None,
            session_id: None,
            tags: Vec::new(),
            checksum: String::new(),
        };

        // Calculate initial checksum (without checksum field)
        let checksum = Self::calculate_checksum(&metadata);
        metadata.checksum = checksum;

        metadata
    }

    /// Calculate SHA-256 checksum of metadata
    fn calculate_checksum(metadata: &AuditMetadata) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(metadata.id.as_bytes());
        hasher.update(metadata.timestamp.to_rfc3339().as_bytes());
        hasher.update(metadata.event_type.as_bytes());
        hasher.update(metadata.severity.as_bytes());
        hasher.update(metadata.actor.as_bytes());
        if let Some(ref ip) = metadata.actor_ip {
            hasher.update(ip.as_bytes());
        }
        if let Some(ref sid) = metadata.session_id {
            hasher.update(sid.as_bytes());
        }
        for tag in &metadata.tags {
            hasher.update(tag.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Add a tag to the metadata
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the actor IP
    pub fn with_actor_ip(mut self, ip: impl Into<String>) -> Self {
        self.actor_ip = Some(ip.into());
        self
    }

    /// Set the session ID
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Verify the checksum integrity
    pub fn verify_checksum(&self) -> bool {
        self.checksum == Self::calculate_checksum(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = AuditMetadata::new(
            EventType::ScanStarted,
            EventSeverity::Info,
            "test_user".to_string(),
        );

        assert_eq!(metadata.event_type, "scan_started");
        assert_eq!(metadata.severity, "info");
        assert_eq!(metadata.actor, "test_user");
        assert!(metadata.verify_checksum());
    }

    #[test]
    fn test_metadata_with_tags() {
        let metadata = AuditMetadata::new(
            EventType::ScanStarted,
            EventSeverity::Info,
            "test_user".to_string(),
        )
        .with_tag("http")
        .with_tag("active");

        assert_eq!(metadata.tags.len(), 2);
        assert!(metadata.tags.contains(&"http".to_string()));
        assert!(metadata.tags.contains(&"active".to_string()));
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = AuditMetadata::new(
            EventType::ConfigChanged,
            EventSeverity::Info,
            "admin".to_string(),
        );

        let serialized = serde_json::to_string(&metadata).unwrap();
        let deserialized: AuditMetadata = serde_json::from_str(&serialized).unwrap();

        assert_eq!(metadata.id, deserialized.id);
        assert_eq!(metadata.event_type, deserialized.event_type);
    }
}
