//! Webhook Integration
//!
//! Supports sending notifications to various platforms:
//! - Slack
//! - Discord
//! - Mattermost
//! - Email (via SMTP)
//! - Generic webhooks

use anyhow::{Context, Result};
use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

use crate::scanners::{ScanReport, VulnSeverity};

use super::continuous::ScanJob;

/// Types of supported webhooks
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookType {
    /// Slack webhook
    Slack,
    /// Discord webhook
    Discord,
    /// Mattermost webhook
    Mattermost,
    /// Microsoft Teams webhook
    Teams,
    /// Generic webhook
    Generic,
    /// Email notification
    Email,
}

impl std::fmt::Display for WebhookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookType::Slack => write!(f, "Slack"),
            WebhookType::Discord => write!(f, "Discord"),
            WebhookType::Mattermost => write!(f, "Mattermost"),
            WebhookType::Teams => write!(f, "Microsoft Teams"),
            WebhookType::Generic => write!(f, "Generic"),
            WebhookType::Email => write!(f, "Email"),
        }
    }
}

impl std::str::FromStr for WebhookType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "slack" => Ok(WebhookType::Slack),
            "discord" => Ok(WebhookType::Discord),
            "mattermost" => Ok(WebhookType::Mattermost),
            "teams" | "msteams" => Ok(WebhookType::Teams),
            "generic" => Ok(WebhookType::Generic),
            "email" => Ok(WebhookType::Email),
            _ => Err(format!("Unknown webhook type: {}", s)),
        }
    }
}

/// Notification severity level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationLevel {
    /// Info only
    Info,
    /// Low severity findings
    Low,
    /// Medium severity findings
    Medium,
    /// High severity findings
    High,
    /// Critical severity findings
    Critical,
}

impl NotificationLevel {
    /// Get the corresponding color for this level
    pub fn color(&self) -> &'static str {
        match self {
            NotificationLevel::Info => "gray",
            NotificationLevel::Low => "blue",
            NotificationLevel::Medium => "yellow",
            NotificationLevel::High => "orange",
            NotificationLevel::Critical => "red",
        }
    }

    /// Get emoji for this level
    pub fn emoji(&self) -> &'static str {
        match self {
            NotificationLevel::Info => "",
            NotificationLevel::Low => "",
            NotificationLevel::Medium => "⚠️",
            NotificationLevel::High => "🔶",
            NotificationLevel::Critical => "🚨",
        }
    }

    /// Convert from VulnSeverity
    pub fn from_vuln_severity(severity: VulnSeverity) -> Self {
        match severity {
            VulnSeverity::Critical => NotificationLevel::Critical,
            VulnSeverity::High => NotificationLevel::High,
            VulnSeverity::Medium => NotificationLevel::Medium,
            VulnSeverity::Low => NotificationLevel::Low,
            VulnSeverity::Info => NotificationLevel::Info,
        }
    }
}

/// Webhook configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Type of webhook
    pub webhook_type: WebhookType,
    /// Webhook URL
    pub url: String,
    /// Optional username/bot name
    pub username: Option<String>,
    /// Optional icon URL
    pub icon_url: Option<String>,
    /// Optional channel (for Slack/Mattermost)
    pub channel: Option<String>,
    /// Custom message template
    pub template: Option<String>,
    /// Enable notifications for specific severity levels
    pub notify_levels: Vec<NotificationLevel>,
    /// Only send notifications if vulnerabilities are found
    pub only_on_findings: bool,
    /// Include full report in notification
    pub include_full_report: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            webhook_type: WebhookType::Generic,
            url: String::new(),
            username: None,
            icon_url: None,
            channel: None,
            template: None,
            notify_levels: vec![
                NotificationLevel::Critical,
                NotificationLevel::High,
                NotificationLevel::Medium,
            ],
            only_on_findings: true,
            include_full_report: false,
        }
    }
}

impl WebhookConfig {
    /// Create a new webhook config
    pub fn new(webhook_type: WebhookType, url: String) -> Self {
        Self {
            webhook_type,
            url,
            ..Default::default()
        }
    }

    /// Create a Slack webhook
    pub fn slack(url: String) -> Self {
        Self::new(WebhookType::Slack, url)
            .with_username("Warden Security Scanner")
    }

    /// Create a Discord webhook
    pub fn discord(url: String) -> Self {
        Self::new(WebhookType::Discord, url)
            .with_username("Warden Security Scanner")
    }

    /// Create a Mattermost webhook
    pub fn mattermost(url: String, channel: String) -> Self {
        Self::new(WebhookType::Mattermost, url)
            .with_channel(channel)
    }

    /// Set the username
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    /// Set the icon URL
    pub fn with_icon_url(mut self, icon_url: String) -> Self {
        self.icon_url = Some(icon_url);
        self
    }

    /// Set the channel
    pub fn with_channel(mut self, channel: String) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Check if a notification level should be sent
    pub fn should_notify(&self, level: NotificationLevel) -> bool {
        self.notify_levels.contains(&level)
    }
}

/// Webhook client for sending notifications
pub struct WebhookClient {
    configs: Vec<WebhookConfig>,
    client: Client,
}

impl WebhookClient {
    /// Create a new webhook client
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| panic!("Failed to build HTTP client for webhook: {}", e));

        Self { configs, client }
    }

    /// Check if any webhooks are configured
    pub fn is_configured(&self) -> bool {
        !self.configs.is_empty()
            && self.configs.iter().any(|c| !c.url.is_empty())
    }

    /// Add a webhook configuration
    pub fn add_config(&mut self, config: WebhookConfig) {
        self.configs.push(config);
    }

    /// Send a scan notification
    pub async fn send_scan_notification(
        &self,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        for config in &self.configs {
            if !config.should_notify(level) {
                continue;
            }

            if config.only_on_findings && report.summary.total == 0 {
                continue;
            }

            match config.webhook_type {
                WebhookType::Slack => {
                    self.send_slack_notification(config, job, report, level).await?;
                }
                WebhookType::Discord => {
                    self.send_discord_notification(config, job, report, level).await?;
                }
                WebhookType::Mattermost => {
                    self.send_mattermost_notification(config, job, report, level).await?;
                }
                WebhookType::Teams => {
                    self.send_teams_notification(config, job, report, level).await?;
                }
                WebhookType::Generic => {
                    self.send_generic_notification(config, job, report, level).await?;
                }
                WebhookType::Email => {
                    // Email notifications require separate SMTP configuration
                    eprintln!("{} Email notifications not yet implemented", "⚠".yellow());
                }
            }
        }

        Ok(())
    }

    /// Send an error notification
    pub async fn send_error_notification(&self, job: &ScanJob, error: &str) -> Result<()> {
        for config in &self.configs {
            // Send errors regardless of notify level
            match config.webhook_type {
                WebhookType::Slack => {
                    self.send_slack_error(config, job, error).await?;
                }
                WebhookType::Discord => {
                    self.send_discord_error(config, job, error).await?;
                }
                _ => {
                    // Generic error notification
                    let payload = json!({
                        "text": format!("Scan Failed: {}", error),
                        "job_id": job.id.to_string(),
                        "target": job.target.to_string(),
                        "trigger": job.trigger.to_string(),
                    });

                    let _ = self.client.post(&config.url)
                        .json(&payload)
                        .send()
                        .await;
                }
            }
        }

        Ok(())
    }

    /// Send a Slack notification
    async fn send_slack_notification(
        &self,
        config: &WebhookConfig,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        let color = level.color();
        let emoji = level.emoji();

        let mut fields = vec![
            json!({"title": "Target", "value": job.target.to_string(), "short": true}),
            json!({"title": "Trigger", "value": job.trigger.to_string(), "short": true}),
            json!({"title": "Total Findings", "value": report.summary.total, "short": true}),
        ];

        if report.summary.critical > 0 {
            fields.push(json!({"title": "Critical", "value": report.summary.critical, "short": true}));
        }
        if report.summary.high > 0 {
            fields.push(json!({"title": "High", "value": report.summary.high, "short": true}));
        }
        if report.summary.medium > 0 {
            fields.push(json!({"title": "Medium", "value": report.summary.medium, "short": true}));
        }
        if report.summary.low > 0 {
            fields.push(json!({"title": "Low", "value": report.summary.low, "short": true}));
        }

        let mut payload = json!({
            "username": config.username.as_deref().unwrap_or("Warden"),
            "icon_url": config.icon_url,
            "attachments": [{
                "color": color,
                "title": format!("{} Security Scan Complete", emoji),
                "fields": fields,
                "footer": "Warden Security Scanner",
                "ts": job.completed_at.map(|t| t.timestamp()).unwrap_or_else(|| chrono::Utc::now().timestamp())
            }]
        });

        if let Some(channel) = &config.channel {
            payload["channel"] = json!(channel);
        }

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Slack notification")?;

        Ok(())
    }

    /// Send a Slack error notification
    async fn send_slack_error(&self, config: &WebhookConfig, job: &ScanJob, error: &str) -> Result<()> {
        let payload = json!({
            "username": config.username.as_deref().unwrap_or("Warden"),
            "icon_url": config.icon_url,
            "attachments": [{
                "color": "red",
                "title": "Security Scan Failed",
                "text": error,
                "fields": [
                    {"title": "Target", "value": job.target.to_string(), "short": true},
                    {"title": "Trigger", "value": job.trigger.to_string(), "short": true}
                ],
                "footer": "Warden Security Scanner"
            }]
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .ok();

        Ok(())
    }

    /// Send a Discord notification
    async fn send_discord_notification(
        &self,
        config: &WebhookConfig,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        let emoji = level.emoji();
        let color = match level {
            NotificationLevel::Critical => 0xFF0000,
            NotificationLevel::High => 0xFF6600,
            NotificationLevel::Medium => 0xFFFF00,
            NotificationLevel::Low => 0x0066FF,
            NotificationLevel::Info => 0x808080,
        };

        let mut fields = vec![
            json!({"name": "Target", "value": job.target.to_string(), "inline": true}),
            json!({"name": "Trigger", "value": job.trigger.to_string(), "inline": true}),
            json!({"name": "Total", "value": report.summary.total.to_string(), "inline": true}),
        ];

        if report.summary.critical > 0 {
            fields.push(json!({"name": "Critical", "value": report.summary.critical.to_string(), "inline": true}));
        }
        if report.summary.high > 0 {
            fields.push(json!({"name": "High", "value": report.summary.high.to_string(), "inline": true}));
        }
        if report.summary.medium > 0 {
            fields.push(json!({"name": "Medium", "value": report.summary.medium.to_string(), "inline": true}));
        }

        let payload = json!({
            "username": config.username.as_deref().unwrap_or("Warden"),
            "avatar_url": config.icon_url,
            "embeds": [{
                "title": format!("{} Security Scan Complete", emoji),
                "color": color,
                "fields": fields,
                "timestamp": job.completed_at.map(|t| t.to_rfc3339()).unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
                "footer": {"text": "Warden Security Scanner"}
            }]
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Discord notification")?;

        Ok(())
    }

    /// Send a Discord error notification
    async fn send_discord_error(&self, config: &WebhookConfig, job: &ScanJob, error: &str) -> Result<()> {
        let payload = json!({
            "username": config.username.as_deref().unwrap_or("Warden"),
            "embeds": [{
                "title": "Security Scan Failed",
                "description": error,
                "color": 0xFF0000,
                "fields": [
                    {"name": "Target", "value": job.target.to_string(), "inline": true},
                    {"name": "Trigger", "value": job.trigger.to_string(), "inline": true}
                ]
            }]
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .ok();

        Ok(())
    }

    /// Send a Mattermost notification
    async fn send_mattermost_notification(
        &self,
        config: &WebhookConfig,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        let emoji = level.emoji();

        let text = format!(
            "{} **Security Scan Complete**\n\n\
            **Target:** {}\n\
            **Trigger:** {}\n\
            **Findings:** {} total ({} critical, {} high, {} medium, {} low)",
            emoji,
            job.target,
            job.trigger,
            report.summary.total,
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low
        );

        let payload = json!({
            "username": config.username.as_deref().unwrap_or("Warden"),
            "icon_url": config.icon_url,
            "channel": config.channel,
            "text": text,
            "props": {
                "card": {
                    "sections": [{
                        "fields": [
                            {"title": "Target", "value": job.target.to_string()},
                            {"title": "Trigger", "value": job.trigger.to_string()},
                            {"title": "Total", "value": report.summary.total},
                        ]
                    }]
                }
            }
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Mattermost notification")?;

        Ok(())
    }

    /// Send a Microsoft Teams notification
    async fn send_teams_notification(
        &self,
        config: &WebhookConfig,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        let emoji = level.emoji();
        let color = level.color();

        let payload = json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": format!("{} Security Scan Complete", emoji),
            "themeColor": color,
            "title": format!("{} Security Scan Complete", emoji),
            "sections": [{
                "facts": [
                    {"name": "Target", "value": job.target.to_string()},
                    {"name": "Trigger", "value": job.trigger.to_string()},
                    {"name": "Total Findings", "value": report.summary.total.to_string()},
                    {"name": "Critical", "value": report.summary.critical.to_string()},
                    {"name": "High", "value": report.summary.high.to_string()},
                    {"name": "Medium", "value": report.summary.medium.to_string()},
                ]
            }]
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send Teams notification")?;

        Ok(())
    }

    /// Send a generic webhook notification
    async fn send_generic_notification(
        &self,
        config: &WebhookConfig,
        job: &ScanJob,
        report: &ScanReport,
        level: NotificationLevel,
    ) -> Result<()> {
        let payload = json!({
            "job_id": job.id.to_string(),
            "target": job.target.to_string(),
            "trigger": job.trigger.to_string(),
            "status": "completed",
            "level": format!("{:?}", level),
            "findings": {
                "total": report.summary.total,
                "critical": report.summary.critical,
                "high": report.summary.high,
                "medium": report.summary.medium,
                "low": report.summary.low,
                "info": report.summary.info
            },
            "timestamp": job.completed_at
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send generic notification")?;

        Ok(())
    }

    /// Send a test notification to verify webhook configuration
    pub async fn send_test(&self, config: &WebhookConfig) -> Result<()> {
        let payload = json!({
            "text": "Test notification from Warden Security Scanner",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });

        self.client.post(&config.url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send test notification")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_type_from_str() {
        assert_eq!(WebhookType::Slack, "slack".parse().unwrap());
        assert_eq!(WebhookType::Discord, "discord".parse().unwrap());
        assert_eq!(WebhookType::Mattermost, "mattermost".parse().unwrap());
        assert_eq!(WebhookType::Teams, "teams".parse().unwrap());
        assert_eq!(WebhookType::Email, "email".parse().unwrap());
    }

    #[test]
    fn test_webhook_config_builder() {
        let config = WebhookConfig::slack("https://hooks.slack.com/test".to_string())
            .with_channel("#security".to_string())
            .with_username("Security Bot");

        assert_eq!(config.webhook_type, WebhookType::Slack);
        assert_eq!(config.channel, Some("#security".to_string()));
        assert_eq!(config.username, Some("Security Bot".to_string()));
    }

    #[test]
    fn test_notification_level_from_vuln() {
        assert_eq!(
            NotificationLevel::from_vuln_severity(VulnSeverity::Critical),
            NotificationLevel::Critical
        );
        assert_eq!(
            NotificationLevel::from_vuln_severity(VulnSeverity::High),
            NotificationLevel::High
        );
        assert_eq!(
            NotificationLevel::from_vuln_severity(VulnSeverity::Medium),
            NotificationLevel::Medium
        );
        assert_eq!(
            NotificationLevel::from_vuln_severity(VulnSeverity::Low),
            NotificationLevel::Low
        );
        assert_eq!(
            NotificationLevel::from_vuln_severity(VulnSeverity::Info),
            NotificationLevel::Info
        );
    }

    #[test]
    fn test_cron_parse_every_minute() {
        let cron = super::super::scheduler::CronExpression::parse("* * * * *").unwrap();
        assert_eq!(cron.minutes().len(), 60);
    }

    #[test]
    fn test_cron_parse_specific() {
        let cron = super::super::scheduler::CronExpression::parse("30 9 * * 1").unwrap();
        assert_eq!(cron.minutes(), &[30]);
        assert_eq!(cron.hours(), &[9]);
        assert_eq!(cron.days_of_week(), &[1]);
    }
}
