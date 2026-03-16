//! Retention Policy Management
//!
//! Manages log retention, archival, and cleanup according to configurable policies.

use crate::audit::AuditError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::BufWriter;

/// Retention policy for audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// How long to keep logs (days)
    pub retention_days: u32,
    /// Minimum retention period (for compliance)
    pub min_retention_days: Option<u32>,
    /// Action to take when retention period expires
    pub action: RetentionAction,
    /// Archive location before deletion
    pub archive_location: Option<ArchiveLocation>,
    /// Specific event types to retain longer
    pub event_type_overrides: Vec<EventTypeRetention>,
    /// Enable compression for archived logs
    pub compress_archives: bool,
    /// Archive format
    pub archive_format: ArchiveFormat,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default retention policy".to_string(),
            retention_days: 90,
            min_retention_days: Some(30),
            action: RetentionAction::Archive,
            archive_location: Some(ArchiveLocation::Local {
                path: PathBuf::from(".warden/audit/archive"),
            }),
            event_type_overrides: Vec::new(),
            compress_archives: true,
            archive_format: ArchiveFormat::TarGz,
        }
    }
}

impl RetentionPolicy {
    /// Create a new retention policy
    pub fn new(name: String, retention_days: u32) -> Self {
        Self {
            name,
            description: String::new(),
            retention_days,
            min_retention_days: None,
            action: RetentionAction::Delete,
            archive_location: None,
            event_type_overrides: Vec::new(),
            compress_archives: true,
            archive_format: ArchiveFormat::TarGz,
        }
    }

    /// SOC2 compliant policy (minimum 90 days)
    pub fn soc2_compliant() -> Self {
        Self {
            name: "soc2_compliant".to_string(),
            description: "SOC2 compliant retention - 90 days minimum".to_string(),
            retention_days: 90,
            min_retention_days: Some(90),
            action: RetentionAction::Archive,
            archive_location: Some(ArchiveLocation::Local {
                path: PathBuf::from(".warden/audit/archive/soc2"),
            }),
            event_type_overrides: vec![
                EventTypeRetention {
                    event_type: "security_violation".to_string(),
                    retention_days: 255, // ~7 years for security events
                },
                EventTypeRetention {
                    event_type: "security_incident".to_string(),
                    retention_days: 255,
                },
            ],
            compress_archives: true,
            archive_format: ArchiveFormat::TarGz,
        }
    }

    /// ISO27001 compliant policy (minimum 3 years)
    pub fn iso27001_compliant() -> Self {
        Self {
            name: "iso27001_compliant".to_string(),
            description: "ISO27001 compliant retention - 3 years minimum".to_string(),
            retention_days: 1095, // 3 years
            min_retention_days: Some(1095),
            action: RetentionAction::Archive,
            archive_location: Some(ArchiveLocation::Local {
                path: PathBuf::from(".warden/audit/archive/iso27001"),
            }),
            event_type_overrides: vec![
                EventTypeRetention {
                    event_type: "security_violation".to_string(),
                    retention_days: 3650, // 10 years for security events
                },
                EventTypeRetention {
                    event_type: "security_incident".to_string(),
                    retention_days: 3650,
                },
                EventTypeRetention {
                    event_type: "compliance_violation".to_string(),
                    retention_days: 3650,
                },
            ],
            compress_archives: true,
            archive_format: ArchiveFormat::TarGz,
        }
    }

    /// GDPR compliant policy (right to erasure)
    pub fn gdpr_compliant() -> Self {
        Self {
            name: "gdpr_compliant".to_string(),
            description: "GDPR compliant retention with erasure support".to_string(),
            retention_days: 365,
            min_retention_days: None,
            action: RetentionAction::SecureDelete,
            archive_location: None,
            event_type_overrides: Vec::new(),
            compress_archives: false,
            archive_format: ArchiveFormat::TarGz,
        }
    }

    /// Get retention period for a specific event type
    pub fn retention_for_event(&self, event_type: &str) -> Duration {
        for override_rule in &self.event_type_overrides {
            if event_type.contains(&override_rule.event_type) {
                return Duration::days(override_rule.retention_days as i64);
            }
        }
        Duration::days(self.retention_days as i64)
    }

    /// Check if a log entry should be retained
    pub fn should_retain(&self, event_type: &str, timestamp: DateTime<Utc>) -> bool {
        let retention = self.retention_for_event(event_type);
        let cutoff = Utc::now() - retention;
        timestamp > cutoff
    }

    /// Get the cutoff date for retention
    pub fn cutoff_date(&self, event_type: &str) -> DateTime<Utc> {
        let retention = self.retention_for_event(event_type);
        Utc::now() - retention
    }

    /// Validate the policy
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.retention_days == 0 {
            return Err(AuditError::RetentionError(
                "Retention period cannot be zero".to_string()
            ));
        }

        if let Some(min_days) = self.min_retention_days {
            if self.retention_days < min_days {
                return Err(AuditError::RetentionError(format!(
                    "Retention period ({} days) is less than minimum required ({} days)",
                    self.retention_days, min_days
                )));
            }
        }

        Ok(())
    }

    /// Builder method to set min_retention_days
    pub fn with_min_retention_days(mut self, days: u32) -> Self {
        self.min_retention_days = Some(days);
        self
    }

    /// Builder method to add an event type override
    pub fn with_event_type_override(mut self, override_rule: EventTypeRetention) -> Self {
        self.event_type_overrides.push(override_rule);
        self
    }
}

/// Action to take when retention period expires
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAction {
    /// Delete logs immediately
    Delete,
    /// Archive to cold storage before deletion
    Archive,
    /// Secure delete (overwrite data)
    SecureDelete,
    /// Move to offline storage
    OfflineStorage,
    /// Keep indefinitely
    Keep,
}

/// Archive location configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveLocation {
    /// Local filesystem path
    Local { path: PathBuf },
    /// S3-compatible storage
    S3 {
        bucket: String,
        prefix: Option<String>,
        region: Option<String>,
    },
    /// Azure Blob Storage
    AzureBlob {
        container: String,
        prefix: Option<String>,
    },
    /// Google Cloud Storage
    Gcs {
        bucket: String,
        prefix: Option<String>,
    },
    /// Custom endpoint
    Custom {
        endpoint: String,
        credentials_path: Option<PathBuf>,
    },
}

/// Archive format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    Tar,
    TarGz,
    Zip,
    Plain,
}

/// Event type specific retention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeRetention {
    pub event_type: String,
    pub retention_days: u32,
}

/// Retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Active retention policy
    pub policy: RetentionPolicy,
    /// Run retention cleanup every N hours
    pub cleanup_interval_hours: u32,
    /// Enable dry-run mode (no actual deletion)
    pub dry_run: bool,
    /// Notify before deletion
    pub notify_before_delete: bool,
    /// Days before deletion to notify
    pub notification_days_before: u32,
    /// Enable retention metrics
    pub enable_metrics: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            policy: RetentionPolicy::default(),
            cleanup_interval_hours: 24,
            dry_run: false,
            notify_before_delete: false,
            notification_days_before: 7,
            enable_metrics: true,
        }
    }
}

impl RetentionConfig {
    pub fn new(policy: RetentionPolicy) -> Self {
        Self {
            policy,
            ..Default::default()
        }
    }

    pub fn with_cleanup_interval(mut self, hours: u32) -> Self {
        self.cleanup_interval_hours = hours;
        self
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_notification(mut self, enabled: bool, days_before: u32) -> Self {
        self.notify_before_delete = enabled;
        self.notification_days_before = days_before;
        self
    }
}

/// Retention manager for handling log lifecycle
pub struct RetentionManager {
    config: RetentionConfig,
    log_directory: PathBuf,
}

impl RetentionManager {
    /// Create a new retention manager
    pub fn new(config: RetentionConfig, log_directory: PathBuf) -> Self {
        Self {
            config,
            log_directory,
        }
    }

    /// Run retention cleanup
    pub async fn run_cleanup(&self) -> Result<RetentionReport, AuditError> {
        let mut report = RetentionReport::new();

        // Validate policy
        self.config.policy.validate()?;

        // Scan log directory
        let entries = self.scan_logs().await?;

        for entry in entries {
            let cutoff = self.config.policy.cutoff_date(&entry.event_type);

            if entry.timestamp < cutoff {
                // Handle based on action
                match self.config.policy.action {
                    RetentionAction::Delete => {
                        if !self.config.dry_run {
                            self.delete_log(&entry.path).await?;
                        }
                        report.deleted.push(entry);
                    }
                    RetentionAction::Archive => {
                        if let Some(ref archive_location) = self.config.policy.archive_location {
                            if !self.config.dry_run {
                                self.archive_log(&entry.path, archive_location).await?;
                            }
                            report.archived.push(entry);
                        } else {
                            // No archive location, delete
                            if !self.config.dry_run {
                                self.delete_log(&entry.path).await?;
                            }
                            report.deleted.push(entry);
                        }
                    }
                    RetentionAction::SecureDelete => {
                        if !self.config.dry_run {
                            self.secure_delete_log(&entry.path).await?;
                        }
                        report.secure_deleted.push(entry);
                    }
                    RetentionAction::OfflineStorage => {
                        // Move to offline storage
                        if !self.config.dry_run {
                            self.move_to_offline(&entry.path).await?;
                        }
                        report.offlined.push(entry);
                    }
                    RetentionAction::Keep => {
                        // Keep indefinitely
                        report.retained.push(entry);
                    }
                }
            } else {
                report.retained.push(entry);
            }
        }

        report.dry_run = self.config.dry_run;
        report.run_at = Utc::now();

        Ok(report)
    }

    /// Scan logs for retention processing
    async fn scan_logs(&self) -> Result<Vec<LogEntryInfo>, AuditError> {
        let mut entries = Vec::new();

        if !self.log_directory.exists() {
            return Ok(entries);
        }

        let mut dir = tokio::fs::read_dir(&self.log_directory).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                continue;
            }

            // Only process log files
            if path.extension().map_or(false, |e| e == "log") {
                if let Ok(info) = self.analyze_log_file(&path).await {
                    entries.push(info);
                }
            }
        }

        Ok(entries)
    }

    /// Analyze a log file to get event information
    async fn analyze_log_file(&self, path: &PathBuf) -> Result<LogEntryInfo, AuditError> {
        let metadata = tokio::fs::metadata(path).await?;
        let modified = metadata.modified()?.into();
        let size = metadata.len();

        // Read first line to get event type
        let event_type = tokio::fs::read_to_string(path)
            .await?
            .lines()
            .next()
            .and_then(|line| {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    value.get("event_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        Ok(LogEntryInfo {
            path: path.clone(),
            timestamp: modified,
            event_type,
            size_bytes: size,
        })
    }

    /// Delete a log file
    async fn delete_log(&self, path: &PathBuf) -> Result<(), AuditError> {
        tokio::fs::remove_file(path).await?;
        Ok(())
    }

    /// Archive a log file
    async fn archive_log(
        &self,
        path: &PathBuf,
        location: &ArchiveLocation,
    ) -> Result<(), AuditError> {
        match location {
            ArchiveLocation::Local { path: archive_path } => {
                // Create archive directory
                tokio::fs::create_dir_all(archive_path).await?;

                // Determine archive file name
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| AuditError::RetentionError(
                        "Invalid log file name".to_string()
                    ))?;

                let archive_file = archive_path.join(format!(
                    "{}.{}",
                    filename,
                    if self.config.policy.compress_archives {
                        "gz"
                    } else {
                        "log"
                    }
                ));

                // Read and compress if needed
                let content = tokio::fs::read(path).await?;

                if self.config.policy.compress_archives {
                    use flate2::write::GzEncoder;
                    use flate2::Compression;
                    use std::io::Write;

                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&content)?;
                    let compressed = encoder.finish()?;
                    tokio::fs::write(&archive_file, compressed).await?;
                } else {
                    tokio::fs::write(&archive_file, content).await?;
                }

                // Remove original
                tokio::fs::remove_file(path).await?;
            }
            ArchiveLocation::S3 { .. } => {
                // S3 upload would be implemented here
                return Err(AuditError::RetentionError(
                    "S3 archive not yet implemented".to_string()
                ));
            }
            ArchiveLocation::AzureBlob { .. } => {
                return Err(AuditError::RetentionError(
                    "Azure Blob archive not yet implemented".to_string()
                ));
            }
            ArchiveLocation::Gcs { .. } => {
                return Err(AuditError::RetentionError(
                    "GCS archive not yet implemented".to_string()
                ));
            }
            ArchiveLocation::Custom { .. } => {
                return Err(AuditError::RetentionError(
                    "Custom archive endpoint not yet implemented".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Secure delete by overwriting data
    async fn secure_delete_log(&self, path: &PathBuf) -> Result<(), AuditError> {
        // Get file size
        let metadata = tokio::fs::metadata(path).await?;
        let size = metadata.len() as usize;

        // Overwrite with random data multiple times
        let mut overwrite_data = vec![0u8; size.min(1024 * 1024)]; // Max 1MB chunk

        for _round in 0..3 {
            // Fill with random pattern
            for byte in &mut overwrite_data {
                *byte = rand::random::<u8>();
            }

            // Write over the file
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .await?;

            let mut writer = BufWriter::new(file);
            let mut pos = 0;

            use tokio::io::AsyncWriteExt;
            while pos < size {
                let chunk_size = overwrite_data.len().min(size - pos);
                writer.write_all(&overwrite_data[..chunk_size]).await?;
                pos += chunk_size;
            }

            writer.flush().await?;
            drop(writer);
        }

        // Finally remove the file
        tokio::fs::remove_file(path).await?;

        Ok(())
    }

    /// Move log to offline storage
    async fn move_to_offline(&self, path: &PathBuf) -> Result<(), AuditError> {
        let offline_dir = self.log_directory.join("offline");
        tokio::fs::create_dir_all(&offline_dir).await?;

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| AuditError::RetentionError(
                "Invalid log file name".to_string()
            ))?;

        let offline_path = offline_dir.join(filename);
        tokio::fs::rename(path, &offline_path).await?;

        Ok(())
    }

    /// Get retention statistics
    pub async fn statistics(&self) -> Result<RetentionStatistics, AuditError> {
        let logs = self.scan_logs().await?;

        let mut total_size = 0u64;
        let mut event_type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for log in &logs {
            total_size += log.size_bytes;
            *event_type_counts.entry(log.event_type.clone()).or_insert(0) += 1;
        }

        let expiring_soon = logs.iter()
            .filter(|log| {
                let cutoff = Utc::now() + Duration::days(self.config.notification_days_before as i64);
                let retention_cutoff = self.config.policy.cutoff_date(&log.event_type);
                retention_cutoff < cutoff
            })
            .count();

        Ok(RetentionStatistics {
            total_logs: logs.len(),
            total_size_bytes: total_size,
            event_type_counts,
            expiring_soon,
            retention_days: self.config.policy.retention_days,
        })
    }
}

/// Information about a log entry for retention processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntryInfo {
    pub path: PathBuf,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub size_bytes: u64,
}

/// Retention cleanup report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionReport {
    pub run_at: DateTime<Utc>,
    pub dry_run: bool,
    pub retained: Vec<LogEntryInfo>,
    pub deleted: Vec<LogEntryInfo>,
    pub archived: Vec<LogEntryInfo>,
    pub secure_deleted: Vec<LogEntryInfo>,
    pub offlined: Vec<LogEntryInfo>,
    pub errors: Vec<String>,
}

impl RetentionReport {
    pub fn new() -> Self {
        Self {
            run_at: Utc::now(),
            dry_run: false,
            retained: Vec::new(),
            deleted: Vec::new(),
            archived: Vec::new(),
            secure_deleted: Vec::new(),
            offlined: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn total_processed(&self) -> usize {
        self.retained.len() + self.deleted.len() + self.archived.len()
            + self.secure_deleted.len() + self.offlined.len()
    }

    pub fn space_freed_bytes(&self) -> u64 {
        let mut total = 0u64;
        for entry in &self.deleted {
            total += entry.size_bytes;
        }
        for entry in &self.secure_deleted {
            total += entry.size_bytes;
        }
        total
    }
}

impl Default for RetentionReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Retention statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionStatistics {
    pub total_logs: usize,
    pub total_size_bytes: u64,
    pub event_type_counts: std::collections::HashMap<String, usize>,
    pub expiring_soon: usize,
    pub retention_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_policy_default() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.retention_days, 90);
        assert!(policy.min_retention_days.is_some());
    }

    #[test]
    fn test_soc2_policy() {
        let policy = RetentionPolicy::soc2_compliant();
        assert_eq!(policy.retention_days, 90);
        assert_eq!(policy.min_retention_days, Some(90));
        assert_eq!(policy.event_type_overrides.len(), 2);
    }

    #[test]
    fn test_iso27001_policy() {
        let policy = RetentionPolicy::iso27001_compliant();
        assert_eq!(policy.retention_days, 1095);
        assert_eq!(policy.min_retention_days, Some(1095));
    }

    #[test]
    fn test_retention_for_event() {
        let policy = RetentionPolicy::new("test".to_string(), 30)
            .with_event_type_override(EventTypeRetention {
                event_type: "security".to_string(),
                retention_days: 365,
            });

        let normal_retention = policy.retention_for_event("scan_started");
        let security_retention = policy.retention_for_event("security_violation");

        assert_eq!(normal_retention.num_days(), 30);
        assert_eq!(security_retention.num_days(), 365);
    }

    #[test]
    fn test_should_retain() {
        let policy = RetentionPolicy::new("test".to_string(), 7);

        let old_timestamp = Utc::now() - Duration::days(10);
        let recent_timestamp = Utc::now() - Duration::days(1);

        assert!(!policy.should_retain("scan_started", old_timestamp));
        assert!(policy.should_retain("scan_started", recent_timestamp));
    }

    #[test]
    fn test_policy_validation() {
        let policy = RetentionPolicy::new("test".to_string(), 0);
        assert!(policy.validate().is_err());

        let valid_policy = RetentionPolicy::new("test".to_string(), 90)
            .with_min_retention_days(30);
        assert!(valid_policy.validate().is_ok());
    }

    #[test]
    fn test_retention_config() {
        let policy = RetentionPolicy::default();
        let config = RetentionConfig::new(policy)
            .with_cleanup_interval(12)
            .with_dry_run(true)
            .with_notification(true, 14);

        assert_eq!(config.cleanup_interval_hours, 12);
        assert!(config.dry_run);
        assert!(config.notify_before_delete);
        assert_eq!(config.notification_days_before, 14);
    }
}
