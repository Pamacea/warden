//! Alerting Module - Real-time Notifications for Critical Events
//!
//! Provides configurable alerting based on event severity, thresholds,
//! and custom rules with multiple notification channels.

use crate::audit::{AuditEvent, AuditError, AuditResult, EventSeverity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Alert manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Alert rules
    pub rules: Vec<AlertRule>,
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    /// Cooldown period between alerts (seconds)
    pub cooldown_secs: u64,
    /// Enable alerting
    pub enabled: bool,
    /// Maximum alerts per hour
    pub rate_limit_per_hour: Option<usize>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            rules: vec![
                AlertRule::critical_events(),
                AlertRule::high_severity_events(),
                AlertRule::security_violations(),
            ],
            channels: Vec::new(),
            cooldown_secs: 300, // 5 minutes
            enabled: true,
            rate_limit_per_hour: Some(100),
        }
    }
}

impl AlertConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rules(mut self, rules: Vec<AlertRule>) -> Self {
        self.rules = rules;
        self
    }

    pub fn with_channels(mut self, channels: Vec<NotificationChannel>) -> Self {
        self.channels = channels;
        self
    }

    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.cooldown_secs = secs;
        self
    }

    pub fn with_rate_limit(mut self, limit: usize) -> Self {
        self.rate_limit_per_hour = Some(limit);
        self
    }
}

/// Alert rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Event types to match
    pub event_types: Vec<String>,
    /// Minimum severity to trigger
    pub min_severity: Option<EventSeverity>,
    /// Alert threshold
    pub threshold: AlertThreshold,
    /// Notification channels for this rule
    pub channels: Vec<String>,
    /// Enable/disable rule
    pub enabled: bool,
    /// Custom filter (JSON path expression)
    pub filter: Option<String>,
}

impl AlertRule {
    /// Create a new alert rule
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            event_types: Vec::new(),
            min_severity: None,
            threshold: AlertThreshold::SingleEvent,
            channels: Vec::new(),
            enabled: true,
            filter: None,
        }
    }

    /// Rule for critical events
    pub fn critical_events() -> Self {
        Self {
            name: "critical_events".to_string(),
            description: "Alert on all critical events".to_string(),
            event_types: vec!["*".to_string()],
            min_severity: Some(EventSeverity::Critical),
            threshold: AlertThreshold::SingleEvent,
            channels: vec!["default".to_string()],
            enabled: true,
            filter: None,
        }
    }

    /// Rule for high severity events
    pub fn high_severity_events() -> Self {
        Self {
            name: "high_severity_events".to_string(),
            description: "Alert on high severity events".to_string(),
            event_types: vec!["*".to_string()],
            min_severity: Some(EventSeverity::High),
            threshold: AlertThreshold::Count { events: 5, within_secs: 60 },
            channels: vec!["default".to_string()],
            enabled: true,
            filter: None,
        }
    }

    /// Rule for security violations
    pub fn security_violations() -> Self {
        Self {
            name: "security_violations".to_string(),
            description: "Alert on security violations".to_string(),
            event_types: vec![
                "security_violation".to_string(),
                "security_incident".to_string(),
                "breach_attempt".to_string(),
                "unauthorized_access".to_string(),
            ],
            min_severity: None,
            threshold: AlertThreshold::SingleEvent,
            channels: vec!["default".to_string()],
            enabled: true,
            filter: None,
        }
    }

    /// Rule for failed login attempts
    pub fn failed_logins() -> Self {
        Self {
            name: "failed_logins".to_string(),
            description: "Alert on multiple failed login attempts".to_string(),
            event_types: vec!["user_authorization_failed".to_string()],
            min_severity: None,
            threshold: AlertThreshold::Count { events: 3, within_secs: 300 },
            channels: vec!["default".to_string()],
            enabled: true,
            filter: Some(r#"$.actor == "login""#.to_string()),
        }
    }

    /// Rule for scan failures
    pub fn scan_failures() -> Self {
        Self {
            name: "scan_failures".to_string(),
            description: "Alert on scan failures".to_string(),
            event_types: vec!["scan_failed".to_string()],
            min_severity: Some(EventSeverity::High),
            threshold: AlertThreshold::SingleEvent,
            channels: vec!["default".to_string()],
            enabled: true,
            filter: None,
        }
    }

    /// Check if an event matches this rule
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if !self.enabled {
            return false;
        }

        // Check event type
        let type_match = self.event_types.iter().any(|t| {
            t == "*" || event.event_type.to_string().contains(t)
        });
        if !type_match {
            return false;
        }

        // Check severity
        if let Some(min_severity) = self.min_severity {
            if event.severity.numeric_value() < min_severity.numeric_value() {
                return false;
            }
        }

        // Check custom filter (simplified)
        if let Some(ref filter) = self.filter {
            // In production, this would use a proper JSON path evaluator
            if !self.check_filter(event, filter) {
                return false;
            }
        }

        true
    }

    /// Check custom filter
    fn check_filter(&self, event: &AuditEvent, filter: &str) -> bool {
        // Simplified filter check - in production use jsonpath-rs or similar
        if filter.contains("$.actor") {
            let expected = filter.split('"').last().unwrap_or("");
            return event.metadata.actor == expected.trim_end_matches('"');
        }
        true
    }

    /// Build from parts
    pub fn with_event_types(mut self, types: Vec<String>) -> Self {
        self.event_types = types;
        self
    }

    pub fn with_min_severity(mut self, severity: EventSeverity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    pub fn with_threshold(mut self, threshold: AlertThreshold) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn with_channels(mut self, channels: Vec<String>) -> Self {
        self.channels = channels;
        self
    }

    pub fn with_filter(mut self, filter: String) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertThreshold {
    /// Alert on single event
    SingleEvent,
    /// Alert on event count
    Count { events: usize, within_secs: u64 },
    /// Alert on rate
    Rate { events_per_min: f64 },
    /// Custom threshold expression
    Custom { expression: String },
}

/// Notification channel
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Console/stderr output
    Console,
    /// Email notification
    Email {
        smtp_server: String,
        from: String,
        to: Vec<String>,
        subject_prefix: String,
    },
    /// Webhook (Slack, Discord, etc.)
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
        template: String,
    },
    /// Slack webhook
    Slack { webhook_url: String, channel: Option<String> },
    /// Microsoft Teams webhook
    Teams { webhook_url: String },
    /// Discord webhook
    Discord { webhook_url: String },
    /// PagerDuty
    PagerDuty { integration_key: String, severity: String },
    /// SMS (Twilio)
    Sms {
        account_sid: String,
        auth_token: String,
        from: String,
        to: Vec<String>,
    },
    /// Custom script
    Script { command: String, args: Vec<String> },
}

impl NotificationChannel {
    /// Get channel name
    pub fn name(&self) -> String {
        match self {
            NotificationChannel::Console => "console".to_string(),
            NotificationChannel::Email { .. } => "email".to_string(),
            NotificationChannel::Webhook { .. } => "webhook".to_string(),
            NotificationChannel::Slack { .. } => "slack".to_string(),
            NotificationChannel::Teams { .. } => "teams".to_string(),
            NotificationChannel::Discord { .. } => "discord".to_string(),
            NotificationChannel::PagerDuty { .. } => "pagerduty".to_string(),
            NotificationChannel::Sms { .. } => "sms".to_string(),
            NotificationChannel::Script { .. } => "script".to_string(),
        }
    }
}

/// Alert notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotification {
    /// Alert ID
    pub id: String,
    /// Rule that triggered
    pub rule_name: String,
    /// Severity
    pub severity: EventSeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Triggering events
    pub events: Vec<AuditEvent>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AlertNotification {
    /// Create a new alert notification
    pub fn new(
        rule_name: String,
        severity: EventSeverity,
        title: String,
        description: String,
        events: Vec<AuditEvent>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            rule_name,
            severity,
            title,
            description,
            events,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Format for Slack
    pub fn format_slack(&self) -> String {
        let color = match self.severity {
            EventSeverity::Critical => "#FF0000",
            EventSeverity::High => "#FF6600",
            EventSeverity::Medium => "#FFCC00",
            EventSeverity::Low => "#00CCFF",
            EventSeverity::Info => "#00CC00",
        };

        let attachment = serde_json::json!({
            "color": color,
            "title": self.title,
            "text": self.description,
            "fields": [
                {
                    "title": "Severity",
                    "value": self.severity.to_string(),
                    "short": true
                },
                {
                    "title": "Events",
                    "value": self.events.len().to_string(),
                    "short": true
                },
                {
                    "title": "Rule",
                    "value": self.rule_name,
                    "short": true
                },
                {
                    "title": "Time",
                    "value": self.timestamp.to_rfc3339(),
                    "short": true
                }
            ]
        });

        serde_json::json!({
            "text": format!("{} Alert", self.severity),
            "attachments": vec![attachment]
        }).to_string()
    }

    /// Format for email
    pub fn format_email(&self) -> (String, String) {
        let subject = format!("[{}] {} - {}",
            self.severity.to_string().to_uppercase(),
            self.title,
            self.rule_name
        );

        let body = format!(
            "Alert: {}\n\
             Severity: {}\n\
             Rule: {}\n\
             Time: {}\n\
             Events: {}\n\n\
             Description:\n{}\n\n\
             Details:\n{}",
            self.title,
            self.severity,
            self.rule_name,
            self.timestamp.to_rfc3339(),
            self.events.len(),
            self.description,
            self.events.iter()
                .map(|e| format!("  - {} | {}", e.event_type, e.description))
                .collect::<Vec<_>>()
                .join("\n")
        );

        (subject, body)
    }

    /// Format for console
    pub fn format_console(&self) -> String {
        let icon = match self.severity {
            EventSeverity::Critical => "",
            EventSeverity::High => "",
            EventSeverity::Medium => "",
            EventSeverity::Low => "",
            EventSeverity::Info => "",
        };

        format!(
            "{} ALERT [{}] {}\n\
             Severity: {}\n\
             Events: {}\n\
             {}",
            icon,
            self.rule_name,
            self.title,
            self.severity,
            self.events.len(),
            self.description
        )
    }
}

/// Alert state tracking
#[derive(Debug, Clone)]
struct AlertState {
    last_alert: Option<DateTime<Utc>>,
    event_count: usize,
    window_start: DateTime<Utc>,
    hourly_count: usize,
    hour_start: DateTime<Utc>,
}

impl Default for AlertState {
    fn default() -> Self {
        Self {
            last_alert: None,
            event_count: 0,
            window_start: Utc::now(),
            hourly_count: 0,
            hour_start: Utc::now(),
        }
    }
}

/// Alert manager
pub struct AlertManager {
    config: AlertConfig,
    state: Arc<RwLock<HashMap<String, AlertState>>>,
    channels: HashMap<String, NotificationChannel>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(config: AlertConfig) -> Self {
        let mut channels = HashMap::new();

        for channel in &config.channels {
            channels.insert(channel.name(), channel.clone());
        }

        // Add default console channel if none configured
        if channels.is_empty() {
            channels.insert("console".to_string(), NotificationChannel::Console);
        }

        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
            channels,
        }
    }

    /// Process an event and trigger alerts if needed
    pub async fn process_event(&self, event: AuditEvent) -> AuditResult<Vec<AlertNotification>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let mut notifications = Vec::new();

        for rule in &self.config.rules {
            if rule.matches(&event) {
                if let Some(notification) = self.evaluate_rule(rule, &event).await? {
                    for channel_name in &rule.channels {
                        if let Some(channel) = self.channels.get(channel_name) {
                            self.send_notification(channel, &notification).await?;
                        }
                    }
                    notifications.push(notification);
                }
            }
        }

        Ok(notifications)
    }

    /// Evaluate a rule against an event
    async fn evaluate_rule(
        &self,
        rule: &AlertRule,
        event: &AuditEvent,
    ) -> AuditResult<Option<AlertNotification>> {
        let mut state = self.state.write().await;
        let rule_state = state.entry(rule.name.clone())
            .or_insert_with(AlertState::default);

        let now = Utc::now();

        // Reset counters if needed
        if (now - rule_state.window_start).num_seconds() > 3600 {
            rule_state.window_start = now;
            rule_state.event_count = 0;
        }

        if (now - rule_state.hour_start).num_seconds() > 3600 {
            rule_state.hour_start = now;
            rule_state.hourly_count = 0;
        }

        rule_state.event_count += 1;
        rule_state.hourly_count += 1;

        // Check rate limit
        if let Some(limit) = self.config.rate_limit_per_hour {
            if rule_state.hourly_count >= limit {
                return Ok(None);
            }
        }

        // Check cooldown
        if let Some(last_alert) = rule_state.last_alert {
            if (now - last_alert).num_seconds() < self.config.cooldown_secs as i64 {
                return Ok(None);
            }
        }

        // Check threshold
        let should_alert = match rule.threshold {
            AlertThreshold::SingleEvent => true,
            AlertThreshold::Count { events, within_secs } => {
                rule_state.event_count >= events
                    && (now - rule_state.window_start).num_seconds() <= within_secs as i64
            }
            AlertThreshold::Rate { events_per_min } => {
                let elapsed_min = (now - rule_state.window_start).num_seconds() as f64 / 60.0;
                if elapsed_min > 0.0 {
                    (rule_state.event_count as f64 / elapsed_min) >= events_per_min
                } else {
                    false
                }
            }
            AlertThreshold::Custom { .. } => false,
        };

        if should_alert {
            rule_state.last_alert = Some(now);

            let notification = AlertNotification::new(
                rule.name.clone(),
                event.severity,
                format!("Alert: {}", rule.name),
                rule.description.clone(),
                vec![event.clone()],
            );

            Ok(Some(notification))
        } else {
            Ok(None)
        }
    }

    /// Send notification to channel
    async fn send_notification(
        &self,
        channel: &NotificationChannel,
        notification: &AlertNotification,
    ) -> AuditResult<()> {
        match channel {
            NotificationChannel::Console => {
                eprintln!("{}", notification.format_console());
            }
            NotificationChannel::Slack { webhook_url, .. } => {
                self.send_slack(webhook_url, notification).await?;
            }
            NotificationChannel::Discord { webhook_url } => {
                self.send_discord(webhook_url, notification).await?;
            }
            NotificationChannel::Teams { webhook_url } => {
                self.send_teams(webhook_url, notification).await?;
            }
            NotificationChannel::Webhook { url, method, headers, .. } => {
                self.send_webhook(url, method, headers, notification).await?;
            }
            NotificationChannel::Email { .. } => {
                // Email sending would be implemented here
                tracing::info!("Email alert: {}", notification.title);
            }
            NotificationChannel::PagerDuty { .. } => {
                // PagerDuty integration would be implemented here
                tracing::info!("PagerDuty alert: {}", notification.title);
            }
            NotificationChannel::Sms { .. } => {
                // SMS sending would be implemented here
                tracing::info!("SMS alert: {}", notification.title);
            }
            NotificationChannel::Script { command, args } => {
                self.send_script(command, args, notification).await?;
            }
        }

        Ok(())
    }

    /// Send to Slack
    async fn send_slack(&self, url: &str, notification: &AlertNotification) -> AuditResult<()> {
        let client = reqwest::Client::new();
        let payload = notification.format_slack();

        client.post(url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| AuditError::AlertError(format!("Slack error: {}", e)))?;

        Ok(())
    }

    /// Send to Discord
    async fn send_discord(&self, url: &str, notification: &AlertNotification) -> AuditResult<()> {
        let client = reqwest::Client::new();

        let color = match notification.severity {
            EventSeverity::Critical => 0xFF0000,
            EventSeverity::High => 0xFF6600,
            EventSeverity::Medium => 0xFFCC00,
            EventSeverity::Low => 0x00CCFF,
            EventSeverity::Info => 0x00CC00,
        };

        let payload = serde_json::json!({
            "embeds": [{
                "title": notification.title,
                "description": notification.description,
                "color": color,
                "fields": [
                    {"name": "Severity", "value": notification.severity.to_string(), "inline": true},
                    {"name": "Events", "value": notification.events.len().to_string(), "inline": true},
                    {"name": "Rule", "value": notification.rule_name, "inline": true},
                ]
            }]
        });

        client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AuditError::AlertError(format!("Discord error: {}", e)))?;

        Ok(())
    }

    /// Send to Teams
    async fn send_teams(&self, url: &str, notification: &AlertNotification) -> AuditResult<()> {
        let client = reqwest::Client::new();

        let color = match notification.severity {
            EventSeverity::Critical => "FF0000",
            EventSeverity::High => "FF6600",
            EventSeverity::Medium => "FFCC00",
            EventSeverity::Low => "00CCFF",
            EventSeverity::Info => "00CC00",
        };

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": notification.title,
            "themeColor": color,
            "title": notification.title,
            "text": notification.description,
            "sections": [{
                "facts": [
                    {"name": "Severity", "value": notification.severity.to_string()},
                    {"name": "Events", "value": notification.events.len().to_string()},
                    {"name": "Rule", "value": notification.rule_name},
                ]
            }]
        });

        client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| AuditError::AlertError(format!("Teams error: {}", e)))?;

        Ok(())
    }

    /// Send to generic webhook
    async fn send_webhook(
        &self,
        url: &str,
        method: &str,
        headers: &HashMap<String, String>,
        notification: &AlertNotification,
    ) -> AuditResult<()> {
        let client = reqwest::Client::new();
        let payload = serde_json::to_string(notification)
            .map_err(|e| AuditError::Serialization(e))?;

        let mut request = client.request(
            method.parse().unwrap_or(reqwest::Method::POST),
            url,
        );

        for (key, value) in headers {
            request = request.header(key, value);
        }

        request.header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
            .map_err(|e| AuditError::AlertError(format!("Webhook error: {}", e)))?;

        Ok(())
    }

    /// Send via script
    async fn send_script(
        &self,
        command: &str,
        args: &[String],
        notification: &AlertNotification,
    ) -> AuditResult<()> {
        let mut cmd = tokio::process::Command::new(command);

        for arg in args {
            cmd.arg(arg.replace("{alert_id}", &notification.id));
        }

        cmd.stdin(std::process::Stdio::piped());

        let mut child = cmd.spawn()
            .map_err(|e| AuditError::AlertError(format!("Script error: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            let json = serde_json::to_string(notification)
                .map_err(|e| AuditError::Serialization(e))?;
            tokio::io::AsyncWriteExt::write_all(&mut stdin, json.as_bytes()).await?;
        }

        child.wait()
            .await
            .map_err(|e| AuditError::AlertError(format!("Script execution error: {}", e)))?;

        Ok(())
    }

    /// Add a notification channel
    pub fn add_channel(&mut self, channel: NotificationChannel) {
        self.channels.insert(channel.name(), channel);
    }

    /// Remove a notification channel
    pub fn remove_channel(&mut self, name: &str) {
        self.channels.remove(name);
    }

    /// Get alert statistics
    pub async fn statistics(&self) -> AlertStatistics {
        let _state = self.state.read().await;

        let total_rules = self.config.rules.len();
        let enabled_rules = self.config.rules.iter()
            .filter(|r| r.enabled)
            .count();

        AlertStatistics {
            total_rules,
            enabled_rules,
            total_channels: self.channels.len(),
            rate_limit: self.config.rate_limit_per_hour,
        }
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub total_channels: usize,
    pub rate_limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditMetadata, EventType};

    #[test]
    fn test_alert_rule_critical_events() {
        let rule = AlertRule::critical_events();

        let event = AuditEvent::new(
            EventType::SecurityViolation,
            "test_user".to_string(),
            "Test".to_string(),
        );

        // The event should match because it's a critical security violation
        // This test verifies the rule structure
        assert_eq!(rule.name, "critical_events");
        assert!(rule.enabled);
    }

    #[test]
    fn test_alert_rule_failed_logins() {
        let rule = AlertRule::failed_logins();

        let event = AuditEvent::new(
            EventType::UserAuthorizationFailed,
            "attacker".to_string(),
            "Failed login".to_string(),
        );

        assert_eq!(rule.name, "failed_logins");
    }

    #[test]
    fn test_alert_threshold_serialization() {
        let threshold = AlertThreshold::Count { events: 5, within_secs: 60 };

        let serialized = serde_json::to_string(&threshold).unwrap();
        let deserialized: AlertThreshold = serde_json::from_str(&serialized).unwrap();

        match deserialized {
            AlertThreshold::Count { events, within_secs } => {
                assert_eq!(events, 5);
                assert_eq!(within_secs, 60);
            }
            _ => panic!("Wrong threshold type"),
        }
    }

    #[test]
    fn test_notification_channel_name() {
        assert_eq!(NotificationChannel::Console.name(), "console");
        assert_eq!(NotificationChannel::Slack { webhook_url: "test".to_string(), channel: None }.name(), "slack");
    }

    #[test]
    fn test_alert_notification_format_console() {
        let notification = AlertNotification::new(
            "test_rule".to_string(),
            EventSeverity::High,
            "Test Alert".to_string(),
            "Test description".to_string(),
            vec![],
        );

        let formatted = notification.format_console();
        assert!(formatted.contains("ALERT"));
        assert!(formatted.contains("Test Alert"));
        assert!(formatted.contains("high"));
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert_eq!(config.rules.len(), 3);
        assert!(config.enabled);
        assert_eq!(config.cooldown_secs, 300);
    }
}
