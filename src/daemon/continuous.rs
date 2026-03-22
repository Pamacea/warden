//! Continuous Scanning Daemon
//!
//! Provides background process management for continuous security scanning.
//! Monitors Git repositories and triggers scans on changes, schedules,
//! or external events.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::interval;
use uuid::Uuid;

use crate::scanners::{ScanReport, ScannerConfig, ScannerEngine, Target};
use super::config::DaemonConfig;
use super::monitor::ScanMonitor;
use super::scheduler::{Scheduler, ScheduledScan, ScanPriority};
use super::webhook::{WebhookClient, NotificationLevel};

/// Status of the daemon
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonStatus {
    /// Daemon is starting up
    Starting,
    /// Daemon is running and monitoring
    Running,
    /// Daemon is paused (not accepting new scans)
    Paused,
    /// Daemon is shutting down
    ShuttingDown,
    /// Daemon has stopped
    Stopped,
}

/// What triggered a scan
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTrigger {
    /// Manual trigger via CLI/API
    Manual,
    /// Git commit detected
    GitCommit(String),
    /// Git push detected
    GitPush(String),
    /// Scheduled scan (cron-like)
    Scheduled(String),
    /// Periodic scan
    Periodic,
    /// Webhook trigger (GitHub, GitLab, etc.)
    Webhook(String),
    /// File system change detected
    FileChange(PathBuf),
}

impl std::fmt::Display for ScanTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanTrigger::Manual => write!(f, "Manual"),
            ScanTrigger::GitCommit(ref sha) => write!(f, "Commit: {}", &sha[..8.min(sha.len())]),
            ScanTrigger::GitPush(ref branch) => write!(f, "Push to {}", branch),
            ScanTrigger::Scheduled(ref name) => write!(f, "Schedule: {}", name),
            ScanTrigger::Periodic => write!(f, "Periodic"),
            ScanTrigger::Webhook(ref source) => write!(f, "Webhook: {}", source),
            ScanTrigger::FileChange(ref path) => write!(f, "File: {}", path.display()),
        }
    }
}

/// Information about a scan job
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanJob {
    /// Unique job ID
    pub id: Uuid,
    /// Target being scanned
    pub target: Target,
    /// What triggered this scan
    pub trigger: ScanTrigger,
    /// When the job was created
    pub created_at: DateTime<Utc>,
    /// When the job started
    pub started_at: Option<DateTime<Utc>>,
    /// When the job completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Current status
    pub status: ScanJobStatus,
    /// The scan report (when complete)
    pub report: Option<ScanReport>,
    /// Priority of this job
    pub priority: ScanPriority,
    /// Number of retries
    pub retries: usize,
}

/// Status of a scan job
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanJobStatus {
    /// Job is queued
    Queued,
    /// Job is running
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed
    Failed(String),
    /// Job was cancelled
    Cancelled,
}

/// Result of a scan operation
#[derive(Clone, Debug)]
pub struct ScanResult {
    /// The job that was executed
    pub job: ScanJob,
    /// Whether critical vulnerabilities were found
    pub has_critical: bool,
    /// Whether high vulnerabilities were found
    pub has_high: bool,
    /// Total findings count
    pub total_findings: usize,
}

/// Continuous scanning daemon
///
/// Runs in the background, monitoring repositories and triggering scans
/// based on configuration.
pub struct ContinuousDaemon {
    /// Daemon configuration
    config: DaemonConfig,
    /// Current status
    status: Arc<RwLock<DaemonStatus>>,
    /// Scan scheduler
    scheduler: Arc<RwLock<Scheduler>>,
    /// Webhook client for notifications
    webhook_client: Arc<WebhookClient>,
    /// Scan monitor for metrics
    monitor: Arc<ScanMonitor>,
    /// Pending scan jobs
    pending_jobs: Arc<RwLock<Vec<ScanJob>>>,
    /// Active scan jobs
    active_jobs: Arc<RwLock<Vec<ScanJob>>>,
    /// Completed jobs (limited history)
    completed_jobs: Arc<RwLock<Vec<ScanJob>>>,
    /// Channel for receiving scan requests
    scan_tx: mpsc::Sender<ScheduledScan>,
    /// Channel for stopping the daemon
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Semaphore to limit concurrent scans
    scan_semaphore: Arc<Semaphore>,
}

impl ContinuousDaemon {
    /// Create a new continuous daemon
    pub fn new(config: DaemonConfig) -> Self {
        let max_concurrent = config.max_concurrent_scans;
        let (scan_tx, scan_rx) = mpsc::channel(100);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        let webhook_client = Arc::new(WebhookClient::new(config.webhook.clone()));
        let scheduler = Arc::new(RwLock::new(Scheduler::new(config.schedules.clone())));
        let monitor = Arc::new(ScanMonitor::new());

        let daemon = Self {
            config,
            status: Arc::new(RwLock::new(DaemonStatus::Starting)),
            scheduler,
            webhook_client,
            monitor,
            pending_jobs: Arc::new(RwLock::new(Vec::new())),
            active_jobs: Arc::new(RwLock::new(Vec::new())),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            scan_tx,
            shutdown_tx: Some(shutdown_tx),
            scan_semaphore: Arc::new(Semaphore::new(max_concurrent)),
        };

        // Start the scan processor task
        let processor = ScanProcessor {
            scan_rx,
            pending_jobs: daemon.pending_jobs.clone(),
            active_jobs: daemon.active_jobs.clone(),
            completed_jobs: daemon.completed_jobs.clone(),
            monitor: daemon.monitor.clone(),
            webhook_client: daemon.webhook_client.clone(),
            scan_semaphore: daemon.scan_semaphore.clone(),
            scanner_config: daemon.config.scanner_config.clone(),
            max_history: daemon.config.completed_job_history,
        };

        tokio::spawn(async move {
            processor.run().await;
        });

        // Start the shutdown listener
        let status = daemon.status.clone();
        tokio::spawn(async move {
            shutdown_rx.recv().await;
            *status.write().await = DaemonStatus::ShuttingDown;
        });

        daemon
    }

    /// Start the daemon
    pub async fn start(&self) -> Result<()> {
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Running;
        }

        // Start periodic monitoring
        self.start_monitoring().await?;

        // Start scheduled scans
        self.start_scheduler().await?;

        println!("{}", "✓ Daemon started successfully".green().bold());
        println!("  Monitoring {} repositories", self.config.repositories.len());
        println!("  Max concurrent scans: {}", self.config.max_concurrent_scans);

        Ok(())
    }

    /// Stop the daemon gracefully
    pub async fn stop(&self) -> Result<()> {
        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::ShuttingDown;
        }

        // Send shutdown signal
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }

        // Wait for active jobs to complete (with timeout)
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let active = self.active_jobs.read().await;
            if active.is_empty() {
                break;
            }
            drop(active);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        {
            let mut status = self.status.write().await;
            *status = DaemonStatus::Stopped;
        }

        println!("{}", "✓ Daemon stopped".yellow());
        Ok(())
    }

    /// Pause the daemon (stop accepting new scans)
    pub async fn pause(&self) -> Result<()> {
        let mut status = self.status.write().await;
        *status = DaemonStatus::Paused;
        println!("{}", "✓ Daemon paused".yellow());
        Ok(())
    }

    /// Resume the daemon
    pub async fn resume(&self) -> Result<()> {
        let mut status = self.status.write().await;
        *status = DaemonStatus::Running;
        println!("{}", "✓ Daemon resumed".green());
        Ok(())
    }

    /// Get current status
    pub async fn status(&self) -> DaemonStatus {
        self.status.read().await.clone()
    }

    /// Get all pending jobs
    pub async fn pending_jobs(&self) -> Vec<ScanJob> {
        self.pending_jobs.read().await.clone()
    }

    /// Get all active jobs
    pub async fn active_jobs(&self) -> Vec<ScanJob> {
        self.active_jobs.read().await.clone()
    }

    /// Get completed jobs (limited history)
    pub async fn completed_jobs(&self) -> Vec<ScanJob> {
        self.completed_jobs.read().await.clone()
    }

    /// Trigger a manual scan
    pub async fn trigger_scan(&self, target: Target, trigger: ScanTrigger) -> Result<Uuid> {
        let job_id = Uuid::new_v4();

        // Check if daemon is running
        let status = self.status.read().await;
        if *status != DaemonStatus::Running {
            anyhow::bail!("Daemon is not running (current status: {:?})", *status);
        }
        drop(status);

        let job = ScanJob {
            id: job_id,
            target: target.clone(),
            trigger: trigger.clone(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            status: ScanJobStatus::Queued,
            report: None,
            priority: ScanPriority::Normal,
            retries: 0,
        };

        // Add to pending queue
        {
            let mut pending = self.pending_jobs.write().await;
            pending.push(job.clone());
        }

        // Send to scan processor
        let scheduled = ScheduledScan {
            id: job_id,
            target,
            scheduled_at: Utc::now(),
            priority: ScanPriority::Normal,
            trigger: Some(trigger),
        };

        self.scan_tx.send(scheduled).await
            .context("Failed to queue scan")?;

        println!("{} Scan job queued: {}", "✓".green(), job_id);

        Ok(job_id)
    }

    /// Cancel a pending or running job
    pub async fn cancel_job(&self, job_id: Uuid) -> Result<bool> {
        // Check pending jobs
        {
            let mut pending = self.pending_jobs.write().await;
            if let Some(pos) = pending.iter().position(|j| j.id == job_id) {
                let mut job = pending.remove(pos);
                job.status = ScanJobStatus::Cancelled;
                job.completed_at = Some(Utc::now());
                let mut completed = self.completed_jobs.write().await;
                completed.push(job);
                return Ok(true);
            }
        }

        // Check active jobs (mark for cancellation)
        {
            let mut active = self.active_jobs.write().await;
            if let Some(job) = active.iter_mut().find(|j| j.id == job_id) {
                job.status = ScanJobStatus::Cancelled;
                job.completed_at = Some(Utc::now());
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get daemon statistics
    pub async fn statistics(&self) -> DaemonStatistics {
        let pending = self.pending_jobs.read().await.len();
        let active = self.active_jobs.read().await.len();
        let completed = self.completed_jobs.read().await.len();
        let metrics = self.monitor.get_metrics().await;

        DaemonStatistics {
            status: self.status.read().await.clone(),
            pending_jobs: pending,
            active_jobs: active,
            completed_jobs: completed,
            total_scans: metrics.total_scans,
            successful_scans: metrics.successful_scans,
            failed_scans: metrics.failed_scans,
            avg_scan_duration: metrics.avg_duration,
            last_scan_time: metrics.last_scan_time,
        }
    }

    /// Start repository monitoring
    async fn start_monitoring(&self) -> Result<()> {
        // For each repository, start a file watcher
        // This is a simplified version - a full implementation would use
        // notify crate or similar for actual file system monitoring

        for repo in &self.config.repositories {
            let repo_path = repo.path.clone();
            let scan_tx = self.scan_tx.clone();
            let triggers = repo.triggers.clone();

            // Spawn a monitoring task for this repository
            tokio::spawn(async move {
                let mut check_interval = interval(Duration::from_secs(60));

                loop {
                    check_interval.tick().await;

                    // Check for Git changes (simplified)
                    if let Ok(git_changes) = Self::check_git_changes(&repo_path).await {
                        if git_changes.has_changes && triggers.on_commit {
                            // Trigger scan for each changed branch
                            for branch in &git_changes.branches {
                                let target = Target::Path(repo_path.clone());

                                let scheduled = ScheduledScan {
                                    id: Uuid::new_v4(),
                                    target,
                                    scheduled_at: Utc::now(),
                                    priority: ScanPriority::Normal,
                                    trigger: Some(ScanTrigger::GitCommit(branch.clone())),
                                };

                                let _ = scan_tx.send(scheduled).await;
                            }
                        }
                    }
                }
            });
        }

        Ok(())
    }

    /// Start the scheduled scan processor
    async fn start_scheduler(&self) -> Result<()> {
        let scheduler = self.scheduler.clone();
        let scan_tx = self.scan_tx.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let due_scans = {
                    let mut sched = scheduler.write().await;
                    sched.get_due_scans()
                };

                for scheduled in due_scans {
                    let _ = scan_tx.send(scheduled).await;
                }
            }
        });

        Ok(())
    }

    /// Check for Git changes in a repository
    async fn check_git_changes(_path: &PathBuf) -> Result<GitChanges> {
        // This is a simplified implementation
        // A full version would use git2 crate to properly check for changes

        // For now, return no changes
        Ok(GitChanges {
            has_changes: false,
            branches: Vec::new(),
            commits: Vec::new(),
        })
    }
}

/// Scan processor - handles the actual execution of scan jobs
struct ScanProcessor {
    scan_rx: mpsc::Receiver<ScheduledScan>,
    pending_jobs: Arc<RwLock<Vec<ScanJob>>>,
    active_jobs: Arc<RwLock<Vec<ScanJob>>>,
    completed_jobs: Arc<RwLock<Vec<ScanJob>>>,
    monitor: Arc<ScanMonitor>,
    webhook_client: Arc<WebhookClient>,
    scan_semaphore: Arc<Semaphore>,
    scanner_config: ScannerConfig,
    max_history: usize,
}

impl ScanProcessor {
    async fn run(mut self) {
        while let Some(scheduled) = self.scan_rx.recv().await {
            // Acquire semaphore (limit concurrent scans)
            let permit = self.scan_semaphore.acquire().await
                .expect("Semaphore acquire failed - daemon shutting down");

            // Move job from pending to active
            let (job, target) = {
                let mut pending = self.pending_jobs.write().await;
                let pos = pending.iter().position(|j| j.id == scheduled.id);

                if let Some(pos) = pos {
                    let mut job = pending.remove(pos);
                    job.status = ScanJobStatus::Running;
                    job.started_at = Some(Utc::now());
                    let target = job.target.clone();

                    let mut active = self.active_jobs.write().await;
                    active.push(job.clone());

                    (job, target)
                } else {
                    // Create a new job
                    let job = ScanJob {
                        id: scheduled.id,
                        target: scheduled.target.clone(),
                        trigger: scheduled.trigger.clone().unwrap_or(ScanTrigger::Manual),
                        created_at: Utc::now(),
                        started_at: Some(Utc::now()),
                        completed_at: None,
                        status: ScanJobStatus::Running,
                        report: None,
                        priority: scheduled.priority,
                        retries: 0,
                    };

                    let target = job.target.clone();
                    let mut active = self.active_jobs.write().await;
                    active.push(job.clone());

                    (job, target)
                }
            };

            // Execute the scan
            let result = self.execute_scan(job.clone(), target).await;

            // Process the result
            self.handle_scan_result(job, result).await;

            // Release permit
            drop(permit);
        }
    }

    async fn execute_scan(&self, job: ScanJob, target: Target) -> Result<ScanReport> {
        // Record start in monitor
        self.monitor.scan_started(job.id).await;

        // Create scanner engine
        let mut engine = ScannerEngine::new(self.scanner_config.clone());

        // Execute appropriate scan based on target
        let report = match &target {
            Target::Url(url) => {
                engine.scan_http(url).await?
            }
            Target::Path(path) => {
                engine.scan_static(path).await?
            }
        };

        Ok(report)
    }

    async fn handle_scan_result(&self, mut job: ScanJob, result: Result<ScanReport>) {
        let (report, status) = match result {
            Ok(report) => {
                let has_critical = report.summary.critical > 0;
                let has_high = report.summary.high > 0;

                // Send webhook notification
                let notification_level = if has_critical {
                    NotificationLevel::Critical
                } else if has_high {
                    NotificationLevel::High
                } else if report.summary.medium > 0 {
                    NotificationLevel::Medium
                } else {
                    NotificationLevel::Low
                };

                if self.webhook_client.is_configured() {
                    let _ = self.webhook_client
                        .send_scan_notification(&job, &report, notification_level)
                        .await;
                }

                // Record in monitor
                let start_time = job.started_at.unwrap_or(job.created_at);
                self.monitor.scan_completed(
                    job.id,
                    true,
                    start_time,
                    report.summary.total,
                ).await;

                (Some(report), ScanJobStatus::Completed)
            }
            Err(e) => {
                eprintln!("{} Scan failed: {}", "✗".red(), e);

                // Send failure notification
                if self.webhook_client.is_configured() {
                    let _ = self.webhook_client
                        .send_error_notification(&job, &e.to_string())
                        .await;
                }

                // Record in monitor
                self.monitor.scan_failed(job.id).await;

                (None, ScanJobStatus::Failed(e.to_string()))
            }
        };

        // Update job
        job.status = status;
        job.report = report.clone();
        job.completed_at = Some(Utc::now());

        // Move from active to completed
        {
            let mut active = self.active_jobs.write().await;
            if let Some(pos) = active.iter().position(|j| j.id == job.id) {
                active.remove(pos);
            }
        }

        {
            let mut completed = self.completed_jobs.write().await;
            completed.push(job.clone());

            // Keep only recent history
            if completed.len() > self.max_history {
                completed.remove(0);
            }
        }
    }
}

/// Git changes detected
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct GitChanges {
    has_changes: bool,
    branches: Vec<String>,
    commits: Vec<String>,
}

/// Daemon statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStatistics {
    pub status: DaemonStatus,
    pub pending_jobs: usize,
    pub active_jobs: usize,
    pub completed_jobs: usize,
    pub total_scans: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub avg_scan_duration: Option<f64>,
    pub last_scan_time: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_trigger_display() {
        assert_eq!(ScanTrigger::Manual.to_string(), "Manual");
        assert_eq!(
            ScanTrigger::GitCommit("abc123def456".to_string()).to_string(),
            "Commit: abc123de"
        );
        assert_eq!(
            ScanTrigger::GitPush("main".to_string()).to_string(),
            "Push to main"
        );
        assert_eq!(
            ScanTrigger::Scheduled("daily".to_string()).to_string(),
            "Schedule: daily"
        );
        assert_eq!(ScanTrigger::Periodic.to_string(), "Periodic");
        assert_eq!(
            ScanTrigger::Webhook("github".to_string()).to_string(),
            "Webhook: github"
        );
    }

    #[test]
    fn test_daemon_status_serialization() {
        let status = DaemonStatus::Running;
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: DaemonStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(status, deserialized);
    }
}
