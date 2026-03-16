//! Audit Logger - Core Event Logging System
//!
//! Provides comprehensive event logging for all Warden operations.
//! Maintains SOC2/ISO27001 compliance with immutable, tamper-evident logs.

use crate::audit::{
    immutable::{ChainOfCustody, LogEntry},
    AuditError, AuditMetadata, AuditResult,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs::OpenOptions,
    io::BufWriter,
    sync::RwLock,
};

/// Audit logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Directory to store audit logs
    pub log_directory: PathBuf,
    /// Maximum size of a single log file before rotation (bytes)
    pub max_file_size: u64,
    /// Maximum number of log files to retain
    pub max_files: usize,
    /// Enable cryptographic signing of logs
    pub enable_signing: bool,
    /// Signing key (HMAC-SHA256)
    pub signing_key: Option<String>,
    /// Enable compression for archived logs
    pub enable_compression: bool,
    /// Buffer size for async writes
    pub buffer_size: usize,
    /// Flush interval in seconds
    pub flush_interval_secs: u64,
    /// Enable real-time SIEM forwarding
    pub enable_siem_forwarding: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_directory: PathBuf::from(".warden/audit"),
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_files: 100,
            enable_signing: true,
            signing_key: None,
            enable_compression: true,
            buffer_size: 1000,
            flush_interval_secs: 5,
            enable_siem_forwarding: false,
        }
    }
}

impl AuditConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_log_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_directory = path.into();
        self
    }

    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_max_files(mut self, count: usize) -> Self {
        self.max_files = count;
        self
    }

    pub fn with_signing(mut self, enabled: bool, key: Option<String>) -> Self {
        self.enable_signing = enabled;
        self.signing_key = key;
        self
    }

    pub fn with_siem_forwarding(mut self, enabled: bool) -> Self {
        self.enable_siem_forwarding = enabled;
        self
    }
}

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl EventSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            EventSeverity::Critical => "critical",
            EventSeverity::High => "high",
            EventSeverity::Medium => "medium",
            EventSeverity::Low => "low",
            EventSeverity::Info => "info",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(EventSeverity::Critical),
            "high" => Some(EventSeverity::High),
            "medium" => Some(EventSeverity::Medium),
            "low" => Some(EventSeverity::Low),
            "info" => Some(EventSeverity::Info),
            _ => None,
        }
    }

    pub fn numeric_value(&self) -> u8 {
        match self {
            EventSeverity::Critical => 5,
            EventSeverity::High => 4,
            EventSeverity::Medium => 3,
            EventSeverity::Low => 2,
            EventSeverity::Info => 1,
        }
    }
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Event type classification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Scan events
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    ScanCancelled,
    ScanPaused,
    ScanResumed,

    // Finding events
    FindingDetected,
    FindingConfirmed,
    FindingFalsePositive,
    FindingResolved,

    // Configuration events
    ConfigChanged,
    ConfigLoaded,
    ConfigSaved,
    ConfigValidated,
    ConfigReset,

    // User actions
    UserLogin,
    UserLogout,
    UserAuthenticated,
    UserAuthorizationFailed,
    UserAction,

    // System events
    SystemStartup,
    SystemShutdown,
    SystemError,
    SystemWarning,
    SystemMaintenance,

    // Data events
    DataExported,
    DataImported,
    DataDeleted,
    DataArchived,
    DataAccessed,

    // Security events
    SecurityViolation,
    SecurityAlert,
    SecurityIncident,
    BreachAttempt,
    UnauthorizedAccess,

    // Compliance events
    ComplianceCheck,
    ComplianceViolation,
    ComplianceReportGenerated,

    // API events
    ApiRequest,
    ApiResponse,
    ApiError,
    ApiRateLimitExceeded,

    // SIEM events
    SiemExportSuccess,
    SiemExportFailed,

    // Custom event
    Custom(String),
}

impl EventType {
    pub fn default_severity(&self) -> EventSeverity {
        match self {
            EventType::ScanStarted => EventSeverity::Info,
            EventType::ScanCompleted => EventSeverity::Info,
            EventType::ScanFailed => EventSeverity::High,
            EventType::ScanCancelled => EventSeverity::Low,
            EventType::ScanPaused => EventSeverity::Low,
            EventType::ScanResumed => EventSeverity::Low,

            EventType::FindingDetected => EventSeverity::Medium,
            EventType::FindingConfirmed => EventSeverity::High,
            EventType::FindingFalsePositive => EventSeverity::Low,
            EventType::FindingResolved => EventSeverity::Low,

            EventType::ConfigChanged => EventSeverity::Medium,
            EventType::ConfigLoaded => EventSeverity::Info,
            EventType::ConfigSaved => EventSeverity::Info,
            EventType::ConfigValidated => EventSeverity::Info,
            EventType::ConfigReset => EventSeverity::Medium,

            EventType::UserLogin => EventSeverity::Info,
            EventType::UserLogout => EventSeverity::Info,
            EventType::UserAuthenticated => EventSeverity::Info,
            EventType::UserAuthorizationFailed => EventSeverity::High,
            EventType::UserAction => EventSeverity::Low,

            EventType::SystemStartup => EventSeverity::Info,
            EventType::SystemShutdown => EventSeverity::Info,
            EventType::SystemError => EventSeverity::High,
            EventType::SystemWarning => EventSeverity::Medium,
            EventType::SystemMaintenance => EventSeverity::Info,

            EventType::DataExported => EventSeverity::Medium,
            EventType::DataImported => EventSeverity::Medium,
            EventType::DataDeleted => EventSeverity::High,
            EventType::DataArchived => EventSeverity::Low,
            EventType::DataAccessed => EventSeverity::Low,

            EventType::SecurityViolation => EventSeverity::Critical,
            EventType::SecurityAlert => EventSeverity::High,
            EventType::SecurityIncident => EventSeverity::Critical,
            EventType::BreachAttempt => EventSeverity::Critical,
            EventType::UnauthorizedAccess => EventSeverity::Critical,

            EventType::ComplianceCheck => EventSeverity::Info,
            EventType::ComplianceViolation => EventSeverity::High,
            EventType::ComplianceReportGenerated => EventSeverity::Info,

            EventType::ApiRequest => EventSeverity::Info,
            EventType::ApiResponse => EventSeverity::Info,
            EventType::ApiError => EventSeverity::Medium,
            EventType::ApiRateLimitExceeded => EventSeverity::Medium,

            EventType::SiemExportSuccess => EventSeverity::Info,
            EventType::SiemExportFailed => EventSeverity::High,

            EventType::Custom(_) => EventSeverity::Info,
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Custom(name) => write!(f, "{}", name),
            _ => {
                let s = serde_json::to_string(self).unwrap_or_default();
                write!(f, "{}", s.trim_matches('"'))
            }
        }
    }
}

/// Event result status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventResult {
    Success,
    Failure,
    Partial,
    Pending,
    Unknown,
}

impl std::fmt::Display for EventResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventResult::Success => write!(f, "success"),
            EventResult::Failure => write!(f, "failure"),
            EventResult::Partial => write!(f, "partial"),
            EventResult::Pending => write!(f, "pending"),
            EventResult::Unknown => write!(f, "unknown"),
        }
    }
}

/// Comprehensive audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event metadata
    #[serde(flatten)]
    pub metadata: AuditMetadata,
    /// Event type
    pub event_type: EventType,
    /// Event severity
    pub severity: EventSeverity,
    /// Event result
    pub result: EventResult,
    /// Event description
    pub description: String,
    /// Target of the event (URL, file path, etc.)
    pub target: Option<String>,
    /// Additional event data
    pub data: HashMap<String, serde_json::Value>,
    /// Previous value (for changes)
    pub previous_value: Option<serde_json::Value>,
    /// New value (for changes)
    pub new_value: Option<serde_json::Value>,
    /// Duration of the operation
    pub duration_ms: Option<u64>,
    /// Related event IDs
    pub related_events: Vec<String>,
    /// Error message if applicable
    pub error_message: Option<String>,
    /// Stack trace if applicable
    pub stack_trace: Option<String>,
    /// User agent (for API events)
    pub user_agent: Option<String>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Request ID (for API events)
    pub request_id: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event with minimum required fields
    pub fn new(
        event_type: EventType,
        actor: String,
        description: String,
    ) -> Self {
        let severity = event_type.default_severity();
        let metadata = AuditMetadata::new(event_type.clone(), severity, actor);

        Self {
            metadata,
            event_type,
            severity,
            result: EventResult::Unknown,
            description,
            target: None,
            data: HashMap::new(),
            previous_value: None,
            new_value: None,
            duration_ms: None,
            related_events: Vec::new(),
            error_message: None,
            stack_trace: None,
            user_agent: None,
            source_ip: None,
            request_id: None,
        }
    }

    // Convenience constructors for common events

    /// Scan started event
    pub fn scan_started(actor: String, target: String, scan_mode: String) -> Self {
        let mut event = Self::new(
            EventType::ScanStarted,
            actor,
            format!("Scan started on {}", target),
        );
        event.target = Some(target);
        event.data.insert("scan_mode".to_string(), serde_json::json!(scan_mode));
        event
    }

    /// Scan completed event
    pub fn scan_completed(
        actor: String,
        target: String,
        duration_ms: u64,
        findings_count: usize,
    ) -> Self {
        let mut event = Self::new(
            EventType::ScanCompleted,
            actor,
            format!("Scan completed on {}", target),
        );
        event.target = Some(target);
        event.duration_ms = Some(duration_ms);
        event.result = EventResult::Success;
        event.data.insert("findings_count".to_string(), serde_json::json!(findings_count));
        event
    }

    /// Scan failed event
    pub fn scan_failed(actor: String, target: String, error: String) -> Self {
        let mut event = Self::new(
            EventType::ScanFailed,
            actor,
            format!("Scan failed on {}", target),
        );
        event.target = Some(target);
        event.result = EventResult::Failure;
        event.error_message = Some(error);
        event
    }

    /// Finding detected event
    pub fn finding_detected(
        actor: String,
        target: String,
        severity: String,
        finding_type: String,
    ) -> Self {
        let mut event = Self::new(
            EventType::FindingDetected,
            actor,
            format!("{} detected: {}", finding_type, target),
        );
        event.target = Some(target);
        event.data.insert("finding_severity".to_string(), serde_json::json!(severity));
        event.data.insert("finding_type".to_string(), serde_json::json!(finding_type));
        event.severity = match severity.as_str() {
            "critical" | "high" => EventSeverity::High,
            "medium" => EventSeverity::Medium,
            _ => EventSeverity::Low,
        };
        event
    }

    /// Config changed event
    pub fn config_changed(
        actor: String,
        key: String,
        previous: serde_json::Value,
        new: serde_json::Value,
    ) -> Self {
        let mut event = Self::new(
            EventType::ConfigChanged,
            actor,
            format!("Configuration changed: {}", key),
        );
        event.target = Some(key);
        event.previous_value = Some(previous);
        event.new_value = Some(new);
        event.result = EventResult::Success;
        event
    }

    /// User login event
    pub fn user_login(
        actor: String,
        source_ip: String,
        user_agent: String,
    ) -> Self {
        let description = format!("User logged in: {}", actor);
        let mut event = Self::new(
            EventType::UserLogin,
            actor,
            description,
        );
        event.source_ip = Some(source_ip);
        event.user_agent = Some(user_agent);
        event.result = EventResult::Success;
        event
    }

    /// Security violation event
    pub fn security_violation(
        actor: String,
        violation_type: String,
        description: String,
        source_ip: String,
    ) -> Self {
        let mut event = Self::new(
            EventType::SecurityViolation,
            actor,
            description,
        );
        event.data.insert("violation_type".to_string(), serde_json::json!(violation_type));
        event.source_ip = Some(source_ip);
        event.severity = EventSeverity::Critical;
        event.result = EventResult::Failure;
        event
    }

    /// Data exported event
    pub fn data_exported(
        actor: String,
        format: String,
        record_count: usize,
    ) -> Self {
        let mut event = Self::new(
            EventType::DataExported,
            actor,
            format!("Data exported: {} records", record_count),
        );
        event.data.insert("format".to_string(), serde_json::json!(format));
        event.data.insert("record_count".to_string(), serde_json::json!(record_count));
        event.result = EventResult::Success;
        event
    }

    // Builder methods

    pub fn with_result(mut self, result: EventResult) -> Self {
        self.result = result;
        self
    }

    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.data.insert(key, value);
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.result = EventResult::Failure;
        self
    }

    pub fn with_related_event(mut self, event_id: String) -> Self {
        self.related_events.push(event_id);
        self
    }

    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Convert to log entry for immutable storage
    pub fn to_log_entry(&self) -> LogEntry {
        LogEntry::from_audit_event(
            self.metadata.id.clone(),
            self.metadata.timestamp,
            self.event_type.to_string(),
            serde_json::to_value(self).unwrap_or_default(),
            None,
        )
    }
}

/// Main audit logger
pub struct AuditLogger {
    config: AuditConfig,
    chain_of_custody: Arc<RwLock<ChainOfCustody>>,
    current_log_file: Arc<RwLock<PathBuf>>,
    event_buffer: Arc<RwLock<Vec<AuditEvent>>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub async fn new(config: AuditConfig) -> AuditResult<Self> {
        // Ensure log directory exists
        tokio::fs::create_dir_all(&config.log_directory).await?;

        // Initialize or load chain of custody
        let chain_path = config.log_directory.join("chain_of_custody.json");
        let chain_of_custody = if chain_path.exists() {
            let file = File::open(&chain_path)?;
            let reader = BufReader::new(file);
            let chain: ChainOfCustody = serde_json::from_reader(reader)
                .unwrap_or_else(|_| ChainOfCustody::new());
            Arc::new(RwLock::new(chain))
        } else {
            Arc::new(RwLock::new(ChainOfCustody::new()))
        };

        // Determine current log file
        let current_log_file = Arc::new(RwLock::new(
            Self::get_current_log_path(&config.log_directory)
        ));

        let logger = Self {
            config,
            chain_of_custody,
            current_log_file,
            event_buffer: Arc::new(RwLock::new(Vec::new())),
        };

        // Start background flush task
        logger.start_flush_task().await;

        Ok(logger)
    }

    /// Create audit logger with default configuration
    pub async fn default() -> AuditResult<Self> {
        Self::new(AuditConfig::default()).await
    }

    /// Get the path for the current log file
    fn get_current_log_path(log_dir: &Path) -> PathBuf {
        let date = Utc::now().format("%Y-%m-%d");
        log_dir.join(format!("audit_{}.log", date))
    }

    /// Log an audit event
    pub async fn log(&self, event: AuditEvent) -> AuditResult<String> {
        let event_id = event.metadata.id.clone();

        // Add to buffer
        {
            let mut buffer = self.event_buffer.write().await;
            buffer.push(event);
        }

        // If buffer is full, flush immediately
        if {
            let buffer = self.event_buffer.read().await;
            buffer.len() >= self.config.buffer_size
        } {
            self.flush().await?;
        }

        Ok(event_id)
    }

    /// Log multiple events in a batch
    pub async fn log_batch(&self, events: Vec<AuditEvent>) -> AuditResult<Vec<String>> {
        let mut ids = Vec::new();

        {
            let mut buffer = self.event_buffer.write().await;
            for event in events {
                let id = event.metadata.id.clone();
                ids.push(id);
                buffer.push(event);
            }
        }

        // Flush after batch
        if !ids.is_empty() {
            self.flush().await?;
        }

        Ok(ids)
    }

    /// Flush buffered events to disk
    pub async fn flush(&self) -> AuditResult<()> {
        let mut buffer = self.event_buffer.write().await;
        if buffer.is_empty() {
            return Ok(());
        }

        let events = std::mem::take(&mut *buffer);
        drop(buffer);

        // Get current log file path
        let log_path = {
            let current = self.current_log_file.read().await;
            current.clone()
        };

        // Check if we need to rotate
        if log_path.exists() {
            let metadata = tokio::fs::metadata(&log_path).await?;
            if metadata.len() >= self.config.max_file_size {
                self.rotate_log().await?;
            }
        }

        // Write events to log file
        self.write_events(&events).await?;

        // Update chain of custody
        self.update_chain(&events).await?;

        Ok(())
    }

    /// Write events to the log file
    async fn write_events(&self, events: &[AuditEvent]) -> AuditResult<()> {
        let log_path = {
            let current = self.current_log_file.read().await;
            current.clone()
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await?;

        let mut writer = BufWriter::new(file);

        for event in events {
            // Serialize event
            let json = serde_json::to_string(event)
                .map_err(|e| AuditError::Serialization(e))?;

            // Sign if enabled
            let entry = if self.config.enable_signing {
                let signature = self.sign_event(&json).await?;
                format!("{} {}\n", json, signature)
            } else {
                format!("{}\n", json)
            };

            use tokio::io::AsyncWriteExt;
            writer.write_all(entry.as_bytes()).await?;
        }

        use tokio::io::AsyncWriteExt;
        writer.flush().await?;
        Ok(())
    }

    /// Sign an event with HMAC-SHA256
    async fn sign_event(&self, data: &str) -> AuditResult<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let key = self.config.signing_key.as_ref()
            .ok_or_else(|| AuditError::Crypto("No signing key configured".to_string()))?;

        let mut mac = HmacSha256::new_from_slice(key.as_bytes())
            .map_err(|e| AuditError::Crypto(e.to_string()))?;

        mac.update(data.as_bytes());
        let result = mac.finalize();
        let code = result.into_bytes();

        Ok(hex::encode(code))
    }

    /// Update the chain of custody
    async fn update_chain(&self, events: &[AuditEvent]) -> AuditResult<()> {
        let mut chain = self.chain_of_custody.write().await;

        for event in events {
            let log_entry = event.to_log_entry();
            chain.add_entry(log_entry)?;
        }

        // Save chain to disk
        let chain_path = self.config.log_directory.join("chain_of_custody.json");
        let json = serde_json::to_string_pretty(&*chain)
            .map_err(|e| AuditError::Serialization(e))?;

        tokio::fs::write(&chain_path, json).await?;

        Ok(())
    }

    /// Rotate the log file
    async fn rotate_log(&self) -> AuditResult<()> {
        let current = {
            let current_guard = self.current_log_file.read().await;
            current_guard.clone()
        };

        // Compress if enabled
        if self.config.enable_compression {
            self.compress_log(&current).await?;
        }

        // Update current log file path
        let new_path = Self::get_current_log_path(&self.config.log_directory);
        {
            let mut current_guard = self.current_log_file.write().await;
            *current_guard = new_path;
        }

        // Clean up old logs
        self.cleanup_old_logs().await?;

        Ok(())
    }

    /// Compress a log file
    async fn compress_log(&self, path: &Path) -> AuditResult<()> {
        let compressed_path = path.with_extension("log.gz");

        // Read original file
        let content = tokio::fs::read(path).await?;

        // Compress
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&content)?;
        let compressed = encoder.finish()?;

        // Write compressed file
        tokio::fs::write(&compressed_path, compressed).await?;

        // Remove original
        tokio::fs::remove_file(path).await?;

        Ok(())
    }

    /// Clean up old log files
    async fn cleanup_old_logs(&self) -> AuditResult<()> {
        let mut entries = tokio::fs::read_dir(&self.config.log_directory).await?;
        let mut log_files: Vec<_> = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "log" || e == "gz") {
                if let Ok(metadata) = entry.metadata().await {
                    log_files.push((path, metadata.modified().ok()));
                }
            }
        }

        // Sort by modification time (oldest first)
        log_files.sort_by_key(|(_, time)| *time);

        // Remove excess files
        let excess = log_files.len().saturating_sub(self.config.max_files);
        for (path, _) in log_files.into_iter().take(excess) {
            tokio::fs::remove_file(path).await.ok();
        }

        Ok(())
    }

    /// Start the background flush task
    async fn start_flush_task(&self) {
        let event_buffer = self.event_buffer.clone();
        let interval_secs = self.config.flush_interval_secs;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                let buffer_len = {
                    let buffer = event_buffer.read().await;
                    buffer.len()
                };

                if buffer_len > 0 {
                    // Note: This is a simplified version
                    // In production, you'd need to handle the flush properly
                }
            }
        });
    }

    /// Query audit logs
    pub async fn query(&self, filter: AuditFilter) -> AuditResult<Vec<AuditEvent>> {
        let mut results = Vec::new();

        let mut entries = tokio::fs::read_dir(&self.config.log_directory).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Only read log files
            if path.extension().map_or(false, |e| e == "log") {
                let content = tokio::fs::read_to_string(&path).await?;

                for line in content.lines() {
                    if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                        if filter.matches(&event) {
                            results.push(event);
                        }
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.metadata.timestamp.cmp(&a.metadata.timestamp));

        Ok(results)
    }

    /// Get a specific event by ID
    pub async fn get_event(&self, id: &str) -> AuditResult<Option<AuditEvent>> {
        let filter = AuditFilter::new().with_event_id(id.to_string());
        let results = self.query(filter).await?;
        Ok(results.into_iter().next())
    }

    /// Verify chain of custody integrity
    pub async fn verify_chain(&self) -> AuditResult<bool> {
        let chain = self.chain_of_custody.read().await;
        Ok(chain.verify())
    }

    /// Get statistics about the audit logs
    pub async fn statistics(&self) -> AuditResult<AuditStatistics> {
        let mut stats = AuditStatistics::default();

        let mut entries = tokio::fs::read_dir(&self.config.log_directory).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.extension().map_or(false, |e| e == "log") {
                let metadata = entry.metadata().await?;
                stats.total_size_bytes += metadata.len();
                stats.total_files += 1;

                let content = tokio::fs::read_to_string(&path).await?;
                for line in content.lines() {
                    if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                        stats.total_events += 1;
                        *stats.events_by_type
                            .entry(event.event_type.to_string())
                            .or_insert(0) += 1;
                        *stats.events_by_severity
                            .entry(event.severity.to_string())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        let chain = self.chain_of_custody.read().await;
        stats.chain_entries = chain.entries.len();
        stats.chain_valid = chain.verify();

        Ok(stats)
    }
}

/// Filter for querying audit logs
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    event_type: Option<EventType>,
    severity: Option<EventSeverity>,
    actor: Option<String>,
    target: Option<String>,
    event_id: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    tags: Vec<String>,
}

impl AuditFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_event_type(mut self, event_type: EventType) -> Self {
        self.event_type = Some(event_type);
        self
    }

    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_event_id(mut self, id: String) -> Self {
        self.event_id = Some(id);
        self
    }

    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(ref event_type) = self.event_type {
            if &event.event_type != event_type {
                return false;
            }
        }

        if let Some(ref severity) = self.severity {
            if &event.severity != severity {
                return false;
            }
        }

        if let Some(ref actor) = self.actor {
            if !event.metadata.actor.contains(actor) {
                return false;
            }
        }

        if let Some(ref target) = self.target {
            if event.target.as_ref().map_or(true, |t| !t.contains(target)) {
                return false;
            }
        }

        if let Some(ref id) = self.event_id {
            if event.metadata.id != *id {
                return false;
            }
        }

        if let Some(start) = self.start_time {
            if event.metadata.timestamp < start {
                return false;
            }
        }

        if let Some(end) = self.end_time {
            if event.metadata.timestamp > end {
                return false;
            }
        }

        if !self.tags.is_empty() {
            if !self.tags.iter().all(|tag| event.metadata.tags.contains(tag)) {
                return false;
            }
        }

        true
    }
}

/// Audit log statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStatistics {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub total_events: usize,
    pub events_by_type: HashMap<String, usize>,
    pub events_by_severity: HashMap<String, usize>,
    pub chain_entries: usize,
    pub chain_valid: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_severity_display() {
        assert_eq!(EventSeverity::Critical.to_string(), "critical");
        assert_eq!(EventSeverity::High.to_string(), "high");
        assert_eq!(EventSeverity::Medium.to_string(), "medium");
        assert_eq!(EventSeverity::Low.to_string(), "low");
        assert_eq!(EventSeverity::Info.to_string(), "info");
    }

    #[test]
    fn test_event_severity_from_str() {
        assert_eq!(EventSeverity::from_str("critical"), Some(EventSeverity::Critical));
        assert_eq!(EventSeverity::from_str("high"), Some(EventSeverity::High));
        assert_eq!(EventSeverity::from_str("invalid"), None);
    }

    #[test]
    fn test_event_severity_numeric() {
        assert_eq!(EventSeverity::Critical.numeric_value(), 5);
        assert_eq!(EventSeverity::Info.numeric_value(), 1);
    }

    #[test]
    fn test_event_type_default_severity() {
        assert_eq!(
            EventType::ScanStarted.default_severity(),
            EventSeverity::Info
        );
        assert_eq!(
            EventType::SecurityViolation.default_severity(),
            EventSeverity::Critical
        );
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            EventType::ScanStarted,
            "test_user".to_string(),
            "Test scan".to_string(),
        );

        assert_eq!(event.event_type, EventType::ScanStarted);
        assert_eq!(event.metadata.actor, "test_user");
        assert_eq!(event.description, "Test scan");
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(
            EventType::ScanCompleted,
            "test_user".to_string(),
            "Test".to_string(),
        )
        .with_result(EventResult::Success)
        .with_target("http://example.com".to_string())
        .with_duration(1000)
        .with_severity(EventSeverity::High);

        assert_eq!(event.result, EventResult::Success);
        assert_eq!(event.target, Some("http://example.com".to_string()));
        assert_eq!(event.duration_ms, Some(1000));
        assert_eq!(event.severity, EventSeverity::High);
    }

    #[test]
    fn test_convenience_constructors() {
        let scan_event = AuditEvent::scan_started(
            "user".to_string(),
            "http://example.com".to_string(),
            "active".to_string(),
        );
        assert_eq!(scan_event.event_type, EventType::ScanStarted);

        let finding_event = AuditEvent::finding_detected(
            "user".to_string(),
            "http://example.com".to_string(),
            "high".to_string(),
            "XSS".to_string(),
        );
        assert_eq!(finding_event.event_type, EventType::FindingDetected);
        assert!(finding_event.data.contains_key("finding_type"));

        let security_event = AuditEvent::security_violation(
            "attacker".to_string(),
            "SQL Injection".to_string(),
            "Attack detected".to_string(),
            "1.2.3.4".to_string(),
        );
        assert_eq!(security_event.severity, EventSeverity::Critical);
    }

    #[test]
    fn test_audit_filter() {
        let event = AuditEvent::scan_started(
            "test_user".to_string(),
            "http://example.com".to_string(),
            "active".to_string(),
        );

        let filter = AuditFilter::new()
            .with_event_type(EventType::ScanStarted)
            .with_actor("test_user".to_string());

        assert!(filter.matches(&event));

        let wrong_type_filter = AuditFilter::new()
            .with_event_type(EventType::ScanCompleted);
        assert!(!wrong_type_filter.matches(&event));
    }

    #[test]
    fn test_event_serialization() {
        let event = AuditEvent::scan_started(
            "user".to_string(),
            "http://example.com".to_string(),
            "active".to_string(),
        );

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(event.event_type, deserialized.event_type);
        assert_eq!(event.metadata.actor, deserialized.metadata.actor);
    }
}
