//! Daemon Configuration
//!
//! YAML-based configuration for the continuous scanning daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::scanners::ScannerConfig;
use super::scheduler::{Schedule, ScanPriority};
use super::webhook::WebhookConfig;

/// Daemon configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// General daemon settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// List of repositories to monitor
    #[serde(default)]
    pub repositories: Vec<RepositoryConfig>,

    /// Scheduled scans
    #[serde(default)]
    pub schedules: Vec<Schedule>,

    /// Webhook configurations
    #[serde(default)]
    pub webhook: Vec<WebhookConfig>,

    /// Scanner configuration (not serialized - created from other settings)
    #[serde(skip)]
    pub scanner_config: ScannerConfig,

    /// Maximum concurrent scans
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_scans: usize,

    /// How many completed jobs to keep in history
    #[serde(default = "default_job_history")]
    pub completed_job_history: usize,

    /// Monitoring settings
    #[serde(default)]
    pub monitoring: MonitoringConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            repositories: Vec::new(),
            schedules: Vec::new(),
            webhook: Vec::new(),
            scanner_config: ScannerConfig::default(),
            max_concurrent_scans: default_max_concurrent(),
            completed_job_history: default_job_history(),
            monitoring: MonitoringConfig::default(),
        }
    }
}

/// General daemon configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Daemon log file path
    pub log_file: Option<PathBuf>,

    /// PID file path
    pub pid_file: Option<PathBuf>,

    /// Working directory
    pub work_dir: Option<PathBuf>,

    /// Daemon name
    #[serde(default = "default_daemon_name")]
    pub name: String,

    /// Whether to start in paused mode
    #[serde(default)]
    pub paused: bool,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_file: None,
            pid_file: None,
            work_dir: None,
            name: default_daemon_name(),
            paused: false,
            log_level: default_log_level(),
        }
    }
}

/// Repository monitoring configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepositoryConfig {
    /// Unique repository identifier
    pub id: String,

    /// Repository path (local)
    pub path: PathBuf,

    /// Repository name (for display)
    pub name: String,

    /// Repository description
    pub description: Option<String>,

    /// Scan triggers
    #[serde(default)]
    pub triggers: TriggersConfig,

    /// Branches to monitor (empty = all)
    #[serde(default)]
    pub branches: Vec<String>,

    /// Paths to include (empty = all)
    #[serde(default)]
    pub include_paths: Vec<String>,

    /// Paths to exclude
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Scan profile to use
    #[serde(default = "default_scan_profile")]
    pub profile: String,

    /// Priority for scans from this repo
    #[serde(default)]
    pub priority: ScanPriority,

    /// Tags/labels for this repository
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Scan triggers configuration
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TriggersConfig {
    /// Trigger on Git commit
    #[serde(default)]
    pub on_commit: bool,

    /// Trigger on Git push
    #[serde(default)]
    pub on_push: bool,

    /// Trigger on pull request
    #[serde(default)]
    pub on_pr: bool,

    /// Trigger on branch merge
    #[serde(default)]
    pub on_merge: bool,

    /// Trigger on tag creation
    #[serde(default)]
    pub on_tag: bool,

    /// Trigger on file changes
    #[serde(default)]
    pub on_file_change: bool,

    /// Watched file patterns (for on_file_change)
    #[serde(default)]
    pub file_patterns: Vec<String>,

    /// Minimum interval between scans (seconds)
    #[serde(default = "default_min_interval")]
    pub min_interval: u64,
}

/// Monitoring configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable real-time monitoring
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics update interval (seconds)
    #[serde(default = "default_metrics_interval")]
    pub metrics_interval: u64,

    /// Enable prometheus metrics endpoint
    #[serde(default)]
    pub prometheus: bool,

    /// Prometheus metrics port
    #[serde(default = "default_prometheus_port")]
    pub prometheus_port: u16,

    /// Enable dashboard
    #[serde(default)]
    pub dashboard: bool,

    /// Dashboard port
    #[serde(default = "default_dashboard_port")]
    pub dashboard_port: u16,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            metrics_interval: default_metrics_interval(),
            prometheus: false,
            prometheus_port: default_prometheus_port(),
            dashboard: false,
            dashboard_port: default_dashboard_port(),
        }
    }
}

impl DaemonConfig {
    /// Load configuration from a YAML file
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: DaemonConfig = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse YAML config: {}", path.as_ref().display()))?;

        Ok(config)
    }

    /// Save configuration to a YAML file
    pub fn to_yaml_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)
            .context("Failed to serialize config to YAML")?;

        std::fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;

        Ok(())
    }

    /// Create a default configuration file
    pub fn create_default_config<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = Self::default();
        config.to_yaml_file(path.as_ref())?;
        Ok(config)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check repositories
        for repo in &self.repositories {
            if !repo.path.exists() {
                anyhow::bail!("Repository path does not exist: {}", repo.path.display());
            }
        }

        // Validate webhook URLs
        for webhook in &self.webhook {
            if webhook.url.is_empty() {
                anyhow::bail!("Webhook URL is empty");
            }

            if !webhook.url.starts_with("http://") && !webhook.url.starts_with("https://") {
                anyhow::bail!("Invalid webhook URL: {}", webhook.url);
            }
        }

        // Validate schedules
        for schedule in &self.schedules {
            if schedule.targets.is_empty() {
                anyhow::bail!("Schedule '{}' has no targets", schedule.name);
            }

            // Validate cron expression
            super::scheduler::CronExpression::parse(&schedule.cron_expression)
                .map_err(|e| anyhow::anyhow!("Invalid cron expression for schedule '{}': {}",
                    schedule.name, e))?;
        }

        Ok(())
    }

    /// Get repository by ID
    pub fn get_repository(&self, id: &str) -> Option<&RepositoryConfig> {
        self.repositories.iter().find(|r| r.id == id)
    }

    /// Get repositories by tag
    pub fn get_repositories_by_tag(&self, tag: &str) -> Vec<&RepositoryConfig> {
        self.repositories.iter()
            .filter(|r| r.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Get schedule by ID
    pub fn get_schedule(&self, id: &str) -> Option<&Schedule> {
        self.schedules.iter().find(|s| s.id == id)
    }

    /// Convert schedules to the internal format
    pub fn to_schedules(&self) -> Vec<Schedule> {
        self.schedules.clone()
    }
}

/// Builder for creating daemon configurations
pub struct DaemonConfigBuilder {
    config: DaemonConfig,
}

impl DaemonConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            config: DaemonConfig::default(),
        }
    }

    /// Set the daemon name
    pub fn with_name(mut self, name: String) -> Self {
        self.config.general.name = name;
        self
    }

    /// Set the working directory
    pub fn with_work_dir(mut self, dir: PathBuf) -> Self {
        self.config.general.work_dir = Some(dir);
        self
    }

    /// Add a repository
    pub fn with_repository(mut self, repo: RepositoryConfig) -> Self {
        self.config.repositories.push(repo);
        self
    }

    /// Add a schedule
    pub fn with_schedule(mut self, schedule: Schedule) -> Self {
        self.config.schedules.push(schedule);
        self
    }

    /// Add a webhook
    pub fn with_webhook(mut self, webhook: WebhookConfig) -> Self {
        self.config.webhook.push(webhook);
        self
    }

    /// Set max concurrent scans
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.config.max_concurrent_scans = max;
        self
    }

    /// Enable monitoring
    pub fn with_monitoring(mut self, enabled: bool) -> Self {
        self.config.monitoring.enabled = enabled;
        self
    }

    /// Build the configuration
    pub fn build(self) -> DaemonConfig {
        self.config
    }
}

impl Default for DaemonConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for repository configurations
pub struct RepositoryConfigBuilder {
    repo: RepositoryConfig,
}

impl RepositoryConfigBuilder {
    /// Create a new builder
    pub fn new(id: String, path: PathBuf, name: String) -> Self {
        Self {
            repo: RepositoryConfig {
                id,
                path,
                name,
                description: None,
                triggers: TriggersConfig::default(),
                branches: Vec::new(),
                include_paths: Vec::new(),
                exclude_paths: Vec::new(),
                profile: default_scan_profile(),
                priority: ScanPriority::Normal,
                tags: Vec::new(),
            },
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: String) -> Self {
        self.repo.description = Some(desc);
        self
    }

    /// Enable commit trigger
    pub fn on_commit(mut self, enabled: bool) -> Self {
        self.repo.triggers.on_commit = enabled;
        self
    }

    /// Enable push trigger
    pub fn on_push(mut self, enabled: bool) -> Self {
        self.repo.triggers.on_push = enabled;
        self
    }

    /// Enable PR trigger
    pub fn on_pr(mut self, enabled: bool) -> Self {
        self.repo.triggers.on_pr = enabled;
        self
    }

    /// Add branches to monitor
    pub fn with_branches(mut self, branches: Vec<String>) -> Self {
        self.repo.branches = branches;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: ScanPriority) -> Self {
        self.repo.priority = priority;
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.repo.tags = tags;
        self
    }

    /// Build the repository config
    pub fn build(self) -> RepositoryConfig {
        self.repo
    }
}

// Default value functions
fn default_max_concurrent() -> usize { 3 }
fn default_job_history() -> usize { 100 }
fn default_daemon_name() -> String { "warden-daemon".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_scan_profile() -> String { "default".to_string() }
fn default_min_interval() -> u64 { 60 }
fn default_true() -> bool { true }
fn default_metrics_interval() -> u64 { 30 }
fn default_prometheus_port() -> u16 { 9090 }
fn default_dashboard_port() -> u16 { 8080 }

/// Example configuration template
pub fn example_config() -> String {
    String::from("# Warden Continuous Scanning Daemon Configuration\n\
# Version: 0.8.0 Enterprise Edition\n\
\n\
general:\n\
  name: warden-daemon\n\
  log_file: /var/log/warden/daemon.log\n\
  pid_file: /var/run/warden/daemon.pid\n\
  work_dir: /var/lib/warden\n\
  paused: false\n\
  log_level: info\n\
\n\
repositories:\n\
  - id: myapp\n\
    name: My Application\n\
    path: /path/to/repo\n\
    description: Main application repository\n\
    triggers:\n\
      on_commit: true\n\
      on_push: true\n\
      on_pr: true\n\
      on_merge: true\n\
      on_tag: false\n\
      on_file_change: false\n\
      file_patterns: []\n\
      min_interval: 60\n\
    branches:\n\
      - main\n\
      - develop\n\
    include_paths: []\n\
    exclude_paths:\n\
      - vendor/*\n\
      - node_modules/*\n\
    profile: default\n\
    priority: normal\n\
    tags:\n\
      - production\n\
      - web\n\
\n\
schedules:\n\
  - id: daily-scan\n\
    name: Daily Security Scan\n\
    description: Run a full security scan every day at 2 AM\n\
    cron_expression: '0 2 * * *'\n\
    targets:\n\
      - Path: /path/to/repo\n\
    profile: thorough\n\
    enabled: true\n\
    priority: normal\n\
\n\
webhook:\n\
  - type: slack\n\
    url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL\n\
    username: Warden\n\
    icon_url: https://warden.dev/icon.png\n\
    channel: security\n\
    notify_levels:\n\
      - critical\n\
      - high\n\
      - medium\n\
    only_on_findings: true\n\
    include_full_report: false\n\
\n\
scanner:\n\
  scan_mode: active\n\
  timeout: 10\n\
  concurrency: 50\n\
\n\
max_concurrent_scans: 3\n\
completed_job_history: 100\n\
\n\
monitoring:\n\
  enabled: true\n\
  metrics_interval: 30\n\
  prometheus: false\n\
  prometheus_port: 9090\n\
  dashboard: false\n\
  dashboard_port: 8080\n\
")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_default() {
        let config = DaemonConfig::default();
        assert_eq!(config.general.name, "warden-daemon");
        assert_eq!(config.max_concurrent_scans, 3);
        assert_eq!(config.completed_job_history, 100);
    }

    #[test]
    fn test_repository_config_builder() {
        let repo = RepositoryConfigBuilder::new(
            "test".to_string(),
            PathBuf::from("/tmp/test"),
            "Test Repo".to_string()
        )
        .on_commit(true)
        .with_priority(ScanPriority::High)
        .build();

        assert_eq!(repo.id, "test");
        assert!(repo.triggers.on_commit);
        assert_eq!(repo.priority, ScanPriority::High);
    }

    #[test]
    fn test_daemon_config_builder() {
        let config = DaemonConfigBuilder::new()
            .with_name("test-daemon".to_string())
            .with_max_concurrent(5)
            .build();

        assert_eq!(config.general.name, "test-daemon");
        assert_eq!(config.max_concurrent_scans, 5);
    }

    #[test]
    fn test_example_config_is_valid_yaml() {
        let yaml = example_config();
        let config: DaemonConfig = serde_yaml::from_str(&yaml)
            .unwrap_or_else(|e| panic!("Failed to parse example config YAML: {}", e));
        assert_eq!(config.general.name, "warden-daemon");
    }

    #[test]
    fn test_triggers_config_default() {
        let triggers = TriggersConfig::default();
        assert!(!triggers.on_commit);
        assert!(!triggers.on_push);
        assert_eq!(triggers.min_interval, 60);
    }

    #[test]
    fn test_monitoring_config_default() {
        let config = MonitoringConfig::default();
        assert!(config.enabled);
        assert_eq!(config.metrics_interval, 30);
        assert_eq!(config.prometheus_port, 9090);
        assert_eq!(config.dashboard_port, 8080);
    }
}
