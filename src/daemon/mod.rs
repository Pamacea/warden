//! Continuous Scanning Daemon Module
//!
//! This module provides the daemon functionality for Warden v0.8.0 Enterprise Edition.
//! It includes:
//! - Background process management
//! - Continuous Git repository monitoring
//! - Webhook integration (Slack, Discord, Mattermost, Email)
//! - Scheduled scanning (cron-like)
//! - Real-time monitoring and notifications
//! - YAML-based configuration

pub mod continuous;
pub mod scheduler;
pub mod webhook;
pub mod monitor;
pub mod config;

pub use continuous::{ContinuousDaemon, DaemonStatus, DaemonStatistics, ScanJob, ScanJobStatus, ScanTrigger};
pub use scheduler::{Scheduler, ScheduledScan, ScanPriority};
pub use webhook::{WebhookClient, WebhookConfig, WebhookType, NotificationLevel};
pub use monitor::{ScanMonitor, MonitorEvent, ScanMetrics};
pub use config::{DaemonConfig, RepositoryConfig, TriggersConfig};
