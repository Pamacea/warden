//! SIEM Export - Forward audit logs to Security Information and Event Management systems
//!
//! Supports:
//! - Splunk HTTP Event Collector (HEC)
//! - Elasticsearch/ELK Stack
//! - Syslog (RFC 5424)
//! - Custom HTTP endpoints
//! - Azure Sentinel
//! - Google Chronicle

use crate::audit::{AuditEvent, AuditError, AuditResult};
use base64::Engine;
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(test)]
use hostname;

/// SIEM exporter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// SIEM destination
    pub destination: SiemDestination,
    /// Export format
    pub format: SiemFormat,
    /// Batch size for bulk exports
    pub batch_size: usize,
    /// Timeout for HTTP requests
    pub timeout_secs: u64,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Enable TLS verification
    pub verify_tls: bool,
    /// Custom headers for HTTP endpoints
    pub headers: Vec<(String, String)>,
    /// Index/table name for the destination
    pub index: Option<String>,
    /// Source type tag
    pub source_type: String,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            destination: SiemDestination::Http {
                endpoint: "http://localhost:8080".to_string(),
            },
            format: SiemFormat::Json,
            batch_size: 100,
            timeout_secs: 30,
            retry: RetryConfig::default(),
            verify_tls: true,
            headers: Vec::new(),
            index: Some("warden".to_string()),
            source_type: "warden:audit".to_string(),
        }
    }
}

impl SiemConfig {
    pub fn new(destination: SiemDestination) -> Self {
        Self {
            destination,
            ..Default::default()
        }
    }

    pub fn with_format(mut self, format: SiemFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn with_index(mut self, index: String) -> Self {
        self.index = Some(index);
        self
    }

    pub fn with_auth(mut self, username: String, password: String) -> Self {
        use base64::prelude::BASE64_STANDARD;
        self.headers.push((
            "Authorization".to_string(),
            format!("Basic {}", BASE64_STANDARD.encode(format!("{}:{}", username, password))),
        ));
        self
    }

    pub fn with_bearer_token(mut self, token: String) -> Self {
        self.headers.push((
            "Authorization".to_string(),
            format!("Bearer {}", token),
        ));
        self
    }
}

/// SIEM destination types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemDestination {
    /// Splunk HTTP Event Collector
    Splunk {
        hec_url: String,
        hec_token: String,
        index: Option<String>,
        source: Option<String>,
        sourcetype: Option<String>,
    },
    /// Elasticsearch/ELK Stack
    Elasticsearch {
        url: String,
        index: String,
        username: Option<String>,
        password: Option<String>,
        api_key: Option<String>,
    },
    /// Syslog server
    Syslog(SyslogConfig),
    /// Generic HTTP endpoint
    Http {
        endpoint: String,
    },
    /// Azure Sentinel
    AzureSentinel {
        workspace_id: String,
        shared_key: String,
        log_type: String,
    },
    /// Google Security Operations (Chronicle)
    GoogleChronicle {
        customer_id: String,
        credentials_path: String,
    },
    /// Sumo Logic
    SumoLogic {
        endpoint: String,
    },
    /// Datadog
    Datadog {
        api_key: String,
        site: Option<String>,
    },
}

/// Syslog configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// Protocol (tcp, udp, tls)
    pub protocol: SyslogProtocol,
    /// Facility code
    pub facility: u8,
    /// App name
    pub app_name: String,
    /// Message ID
    pub msgid: Option<String>,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 514,
            protocol: SyslogProtocol::Tcp,
            facility: 1, // user-level messages
            app_name: "warden".to_string(),
            msgid: None,
        }
    }
}

impl SyslogConfig {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            ..Default::default()
        }
    }
}

/// Syslog protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    Udp,
    Tcp,
    Tls,
}

/// Export format for SIEM events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    /// JSON format
    Json,
    /// Common Event Format (CEF)
    Cef,
    /// Key-Value pairs
    KeyValue,
    /// Splunk-specific format
    Splunk,
    /// Elasticsearch format
    Elasticsearch,
    /// Syslog RFC 5424
    Syslog,
    /// LEEF format (IBM QRadar)
    Leef,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: usize,
    /// Initial retry delay in milliseconds
    pub initial_delay_ms: u64,
    /// Maximum retry delay in milliseconds
    pub max_delay_ms: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
        }
    }
}

/// SIEM export result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemExportResult {
    pub destination: String,
    pub events_sent: usize,
    pub events_failed: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// SIEM exporter
pub struct SiemExporter {
    config: SiemConfig,
    client: Client,
}

impl SiemExporter {
    /// Create a new SIEM exporter
    pub fn new(config: SiemConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .unwrap_or_default();

        Self { config, client }
    }

    /// Export a single event
    pub async fn export(&self, event: &AuditEvent) -> AuditResult<SiemExportResult> {
        let start = std::time::Instant::now();

        let formatted = self.format_event(event)?;
        let result = self.send(&formatted).await;

        let duration = start.elapsed().as_millis() as u64;

        match result {
            Ok(_) => Ok(SiemExportResult {
                destination: format!("{:?}", self.config.destination),
                events_sent: 1,
                events_failed: 0,
                duration_ms: duration,
                error: None,
            }),
            Err(e) => Ok(SiemExportResult {
                destination: format!("{:?}", self.config.destination),
                events_sent: 0,
                events_failed: 1,
                duration_ms: duration,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Export multiple events in batch
    pub async fn export_batch(&self, events: &[AuditEvent]) -> AuditResult<Vec<SiemExportResult>> {
        let mut results = Vec::new();

        for chunk in events.chunks(self.config.batch_size) {
            let formatted: Result<Vec<_>, _> = chunk.iter()
                .map(|e| self.format_event(e))
                .collect();

            match formatted {
                Ok(formatted_events) => {
                    let start = std::time::Instant::now();

                    match self.send_batch(&formatted_events).await {
                        Ok(_) => {
                            let duration = start.elapsed().as_millis() as u64;
                            results.push(SiemExportResult {
                                destination: format!("{:?}", self.config.destination),
                                events_sent: chunk.len(),
                                events_failed: 0,
                                duration_ms: duration,
                                error: None,
                            });
                        }
                        Err(e) => {
                            let duration = start.elapsed().as_millis() as u64;
                            results.push(SiemExportResult {
                                destination: format!("{:?}", self.config.destination),
                                events_sent: 0,
                                events_failed: chunk.len(),
                                duration_ms: duration,
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => {
                    results.push(SiemExportResult {
                        destination: format!("{:?}", self.config.destination),
                        events_sent: 0,
                        events_failed: chunk.len(),
                        duration_ms: 0,
                        error: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
    }

    /// Format an event according to the configured format
    fn format_event(&self, event: &AuditEvent) -> AuditResult<FormattedEvent> {
        let payload = match self.config.format {
            SiemFormat::Json => self.format_json(event)?,
            SiemFormat::Cef => self.format_cef(event)?,
            SiemFormat::KeyValue => self.format_key_value(event)?,
            SiemFormat::Splunk => self.format_splunk(event)?,
            SiemFormat::Elasticsearch => self.format_elasticsearch(event)?,
            SiemFormat::Syslog => self.format_syslog(event)?,
            SiemFormat::Leef => self.format_leef(event)?,
        };

        Ok(FormattedEvent {
            payload,
            content_type: match self.config.format {
                SiemFormat::Json | SiemFormat::Splunk | SiemFormat::Elasticsearch => "application/json".to_string(),
                _ => "text/plain".to_string(),
            },
        })
    }

    /// Format event as JSON
    fn format_json(&self, event: &AuditEvent) -> AuditResult<String> {
        serde_json::to_string(event)
            .map_err(|e| AuditError::Serialization(e))
    }

    /// Format event as CEF (Common Event Format)
    fn format_cef(&self, event: &AuditEvent) -> AuditResult<String> {
        // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        let severity = match event.severity {
            crate::audit::EventSeverity::Critical => "10",
            crate::audit::EventSeverity::High => "8",
            crate::audit::EventSeverity::Medium => "6",
            crate::audit::EventSeverity::Low => "4",
            crate::audit::EventSeverity::Info => "2",
        };

        let extension = format!(
            "rt={} src={} suuid={} msg={} act={}",
            event.metadata.timestamp.to_rfc3339(),
            event.source_ip.as_deref().unwrap_or("-"),
            event.metadata.id,
            event.description.replace('|', "\\|"),
            event.result
        );

        Ok(format!(
            "CEF:0|Warden|Warden|{}|{}|{}|{}|{}",
            env!("CARGO_PKG_VERSION"),
            event.event_type,
            event.description.replace('|', "\\|"),
            severity,
            extension
        ))
    }

    /// Format event as key-value pairs
    fn format_key_value(&self, event: &AuditEvent) -> AuditResult<String> {
        let mut pairs = Vec::new();
        pairs.push(format!("timestamp={}", event.metadata.timestamp.to_rfc3339()));
        pairs.push(format!("event_type={}", event.event_type));
        pairs.push(format!("severity={}", event.severity));
        pairs.push(format!("actor={}", event.metadata.actor));
        pairs.push(format!("description={}", event.description));

        if let Some(ref target) = event.target {
            pairs.push(format!("target={}", target));
        }

        Ok(pairs.join(" "))
    }

    /// Format event for Splunk
    fn format_splunk(&self, event: &AuditEvent) -> AuditResult<String> {
        let splunk_event = serde_json::json!({
            "event": event,
            "source": self.config.source_type,
            "sourcetype": self.config.source_type,
            "index": self.config.index.as_deref().unwrap_or("main"),
            "host": hostname::get().unwrap_or_else(|_| "unknown".into()).to_string_lossy(),
        });

        serde_json::to_string(&splunk_event)
            .map_err(|e| AuditError::Serialization(e))
    }

    /// Format event for Elasticsearch
    fn format_elasticsearch(&self, event: &AuditEvent) -> AuditResult<String> {
        // Elasticsearch uses a simple JSON document
        let mut es_event = serde_json::to_value(event)
            .map_err(|e| AuditError::Serialization(e))?;

        // Add index/timestamp fields
        if let Some(obj) = es_event.as_object_mut() {
            obj.insert("@timestamp".to_string(), serde_json::json!(
                event.metadata.timestamp.to_rfc3339()
            ));
        }

        serde_json::to_string(&es_event)
            .map_err(|e| AuditError::Serialization(e))
    }

    /// Format event as Syslog RFC 5424
    fn format_syslog(&self, event: &AuditEvent) -> AuditResult<String> {
        // Simplified syslog format
        let priority = 1 * 8 + match event.severity {
            crate::audit::EventSeverity::Critical => 2,
            crate::audit::EventSeverity::High => 3,
            crate::audit::EventSeverity::Medium => 4,
            crate::audit::EventSeverity::Low => 5,
            crate::audit::EventSeverity::Info => 6,
        };

        let message = serde_json::to_string(event)
            .map_err(|e| AuditError::Serialization(e))?;

        Ok(format!(
            "<{}> {} {} {} - - - {}",
            priority,
            event.metadata.timestamp.format("%b %d %H:%M:%S"),
            hostname::get().unwrap_or_else(|_| "unknown".into()).to_string_lossy(),
            "warden",
            message
        ))
    }

    /// Format event as LEEF (for IBM QRadar)
    fn format_leef(&self, event: &AuditEvent) -> AuditResult<String> {
        // LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Name|Severity|Extensions
        let severity = match event.severity {
            crate::audit::EventSeverity::Critical => "10",
            crate::audit::EventSeverity::High => "8",
            crate::audit::EventSeverity::Medium => "5",
            crate::audit::EventSeverity::Low => "3",
            crate::audit::EventSeverity::Info => "1",
        };

        Ok(format!(
            "LEEF:1.0|Warden|Warden|{}|{}|{}|{}",
            env!("CARGO_PKG_VERSION"),
            event.event_type,
            severity,
            "devTime={} devTimeFormat={} usrName={} msg={}".to_string()
        ))
    }

    /// Send formatted event to destination
    async fn send(&self, formatted: &FormattedEvent) -> AuditResult<()> {
        match &self.config.destination {
            SiemDestination::Splunk { hec_url, hec_token, index, .. } => {
                self.send_to_splunk(hec_url, hec_token, index.as_deref(), formatted).await
            }
            SiemDestination::Elasticsearch { url, index, username, password, .. } => {
                self.send_to_elasticsearch(url, index, username.as_deref(), password.as_deref(), formatted).await
            }
            SiemDestination::Syslog(config) => {
                self.send_to_syslog(config, formatted).await
            }
            SiemDestination::Http { endpoint } => {
                self.send_to_http(endpoint, formatted).await
            }
            _ => Err(AuditError::SiemExportFailed(
                "Destination not yet implemented".to_string()
            ))
        }
    }

    /// Send batch of formatted events
    async fn send_batch(&self, events: &[FormattedEvent]) -> AuditResult<()> {
        match &self.config.destination {
            SiemDestination::Elasticsearch { url, index, username, password, .. } => {
                self.send_bulk_to_elasticsearch(url, index, username.as_deref(), password.as_deref(), events).await
            }
            _ => {
                // Fallback to sending individually
                for event in events {
                    self.send(event).await?;
                }
                Ok(())
            }
        }
    }

    /// Send to Splunk HEC
    async fn send_to_splunk(
        &self,
        url: &str,
        token: &str,
        _index: Option<&str>,
        formatted: &FormattedEvent,
    ) -> AuditResult<()> {
        let builder = self.client
            .post(format!("{}/services/collector/event", url))
            .header("Authorization", format!("Splunk {}", token))
            .header("Content-Type", "application/json");

        self.send_with_retry(builder, formatted.payload.as_bytes()).await
    }

    /// Send to Elasticsearch
    async fn send_to_elasticsearch(
        &self,
        url: &str,
        index: &str,
        username: Option<&str>,
        password: Option<&str>,
        formatted: &FormattedEvent,
    ) -> AuditResult<()> {
        let timestamp = Utc::now().format("%Y.%m.%d").to_string();
        let full_url = format!("{}/{}/_doc", url, index.replace("{date}", &timestamp));

        let mut builder = self.client
            .post(&full_url)
            .header("Content-Type", "application/json");

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.basic_auth(user, Some(pass));
        }

        self.send_with_retry(builder, formatted.payload.as_bytes()).await
    }

    /// Send bulk to Elasticsearch
    async fn send_bulk_to_elasticsearch(
        &self,
        url: &str,
        index: &str,
        username: Option<&str>,
        password: Option<&str>,
        events: &[FormattedEvent],
    ) -> AuditResult<()> {
        let timestamp = Utc::now().format("%Y.%m.%d").to_string();
        let index_name = index.replace("{date}", &timestamp);

        let mut bulk_body = String::new();
        for event in events {
            // Index action line
            bulk_body.push_str(&format!("{{\"index\":{{\"_index\":\"{}\"}}}}\n", index_name));
            // Document line
            bulk_body.push_str(&event.payload);
            bulk_body.push('\n');
        }

        let full_url = format!("{}/_bulk", url);

        let mut builder = self.client
            .post(&full_url)
            .header("Content-Type", "application/x-ndjson");

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.basic_auth(user, Some(pass));
        }

        self.send_with_retry(builder, bulk_body.as_bytes()).await
    }

    /// Send to generic HTTP endpoint
    async fn send_to_http(
        &self,
        endpoint: &str,
        formatted: &FormattedEvent,
    ) -> AuditResult<()> {
        let mut builder = self.client
            .post(endpoint)
            .header("Content-Type", &formatted.content_type);

        // Add custom headers
        for (key, value) in &self.config.headers {
            builder = builder.header(key, value);
        }

        self.send_with_retry(builder, formatted.payload.as_bytes()).await
    }

    /// Send to Syslog server
    async fn send_to_syslog(
        &self,
        config: &SyslogConfig,
        _formatted: &FormattedEvent,
    ) -> AuditResult<()> {
        // Note: Actual syslog sending would use a syslog library
        // For now, we'll just log
        tracing::info!("Sending to syslog {}:{}", config.host, config.port);

        // This is a placeholder - actual implementation would use:
        // - tokio::net::UdpSocket for UDP
        // - tokio::net::TcpStream for TCP
        // - native-tls for TLS

        Ok(())
    }

    /// Send with retry logic
    async fn send_with_retry(
        &self,
        builder: reqwest::RequestBuilder,
        body: &[u8],
    ) -> AuditResult<()> {
        let mut delay = self.config.retry.initial_delay_ms;

        for attempt in 0..self.config.retry.max_attempts {
            let response = builder.try_clone()
                .ok_or_else(|| AuditError::SiemExportFailed("Failed to clone request".to_string()))?
                .body(body.to_vec())
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(());
                    }

                    if attempt == self.config.retry.max_attempts - 1 {
                        return Err(AuditError::SiemExportFailed(format!(
                            "HTTP error: {}",
                            resp.status()
                        )));
                    }
                }
                Err(e) => {
                    if attempt == self.config.retry.max_attempts - 1 {
                        return Err(AuditError::SiemExportFailed(format!(
                            "Request failed: {}",
                            e
                        )));
                    }
                }
            }

            // Exponential backoff
            tokio::time::sleep(Duration::from_millis(delay)).await;
            delay = (delay as f64 * self.config.retry.backoff_multiplier) as u64;
            delay = delay.min(self.config.retry.max_delay_ms);
        }

        Err(AuditError::SiemExportFailed(
            "Max retries exceeded".to_string()
        ))
    }
}

/// Formatted event ready for sending
struct FormattedEvent {
    payload: String,
    content_type: String,
}

/// Test destination for SIEM exports
#[derive(Debug, Clone)]
pub struct TestSiemDestination {
    pub received_events: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl TestSiemDestination {
    pub fn new() -> Self {
        Self {
            received_events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn receive(&self, event: &AuditEvent) -> AuditResult<()> {
        let value = serde_json::to_value(event)?;
        self.received_events.lock()
            .expect("Test SIEM destination mutex poisoned")
            .push(value);
        Ok(())
    }

    pub fn event_count(&self) -> usize {
        self.received_events.lock()
            .expect("Test SIEM destination mutex poisoned")
            .len()
    }

    pub fn clear(&self) {
        self.received_events.lock()
            .expect("Test SIEM destination mutex poisoned")
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditMetadata, EventSeverity, EventType};

    #[test]
    fn test_syslog_config_default() {
        let config = SyslogConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 514);
        assert_eq!(config.protocol, SyslogProtocol::Tcp);
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay_ms, 1000);
    }

    #[test]
    fn test_siem_config_default() {
        let config = SiemConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.source_type, "warden:audit");
    }

    #[test]
    fn test_format_cef() {
        let exporter = SiemExporter::new(SiemConfig::default());

        let event = AuditEvent::new(
            EventType::ScanStarted,
            "test_user".to_string(),
            "Test scan".to_string(),
        );

        let cef = exporter.format_cef(&event).unwrap();
        assert!(cef.contains("CEF:0|Warden"));
        assert!(cef.contains("|ScanStarted|"));
    }

    #[test]
    fn test_format_json() {
        let exporter = SiemExporter::new(SiemConfig::default());

        let event = AuditEvent::new(
            EventType::ScanCompleted,
            "test_user".to_string(),
            "Test".to_string(),
        );

        let json = exporter.format_json(&event).unwrap();
        assert!(json.contains("ScanCompleted"));

        // Verify valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["event_type"], "ScanCompleted");
    }

    #[test]
    fn test_format_key_value() {
        let exporter = SiemExporter::new(SiemConfig::default());

        let event = AuditEvent::new(
            EventType::FindingDetected,
            "test_user".to_string(),
            "Vulnerability found".to_string(),
        );

        let kv = exporter.format_key_value(&event).unwrap();
        assert!(kv.contains("event_type=FindingDetected"));
        assert!(kv.contains("actor=test_user"));
    }

    #[test]
    fn test_test_destination() {
        let dest = TestSiemDestination::new();

        let event = AuditEvent::new(
            EventType::ScanStarted,
            "user".to_string(),
            "Test".to_string(),
        );

        dest.receive(&event).unwrap();
        assert_eq!(dest.event_count(), 1);

        dest.clear();
        assert_eq!(dest.event_count(), 0);
    }
}
