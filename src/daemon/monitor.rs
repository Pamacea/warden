//! Scan Monitoring
//!
//! Real-time monitoring of scan jobs with metrics and event tracking.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Monitoring event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MonitorEvent {
    /// Scan started
    ScanStarted { job_id: Uuid, timestamp: DateTime<Utc> },
    /// Scan completed
    ScanCompleted { job_id: Uuid, timestamp: DateTime<Utc>, findings: usize },
    /// Scan failed
    ScanFailed { job_id: Uuid, timestamp: DateTime<Utc>, error: String },
    /// Vulnerability found
    VulnerabilityFound { job_id: Uuid, severity: String },
    /// Repository changed
    RepositoryChanged { repo: String, branch: String, commit: String },
    /// Scheduled scan triggered
    ScheduleTriggered { schedule_id: String, timestamp: DateTime<Utc> },
}

/// Scan metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanMetrics {
    /// Total number of scans
    pub total_scans: usize,
    /// Number of successful scans
    pub successful_scans: usize,
    /// Number of failed scans
    pub failed_scans: usize,
    /// Average scan duration in seconds
    pub avg_duration: Option<f64>,
    /// Total scan time (for calculating average)
    pub total_scan_time: f64,
    /// Last scan timestamp
    pub last_scan_time: Option<DateTime<Utc>>,
    /// Scans in last hour
    pub scans_last_hour: usize,
    /// Scans in last 24 hours
    pub scans_last_24h: usize,
    /// Findings by severity
    pub findings_by_severity: HashMap<String, usize>,
    /// Active scan count
    pub active_scans: usize,
}

impl Default for ScanMetrics {
    fn default() -> Self {
        Self {
            total_scans: 0,
            successful_scans: 0,
            failed_scans: 0,
            avg_duration: None,
            total_scan_time: 0.0,
            last_scan_time: None,
            scans_last_hour: 0,
            scans_last_24h: 0,
            findings_by_severity: HashMap::new(),
            active_scans: 0,
        }
    }
}

/// Per-job metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobMetrics {
    /// Job ID
    pub job_id: Uuid,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time (if completed)
    pub ended_at: Option<DateTime<Utc>>,
    /// Duration in seconds
    pub duration: Option<f64>,
    /// Number of findings
    pub findings: usize,
    /// Status
    pub status: JobStatus,
    /// Progress percentage (0-100)
    pub progress: u8,
}

/// Job status for monitoring
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

/// Scan monitor - tracks metrics and events
pub struct ScanMonitor {
    /// Overall metrics
    metrics: Arc<RwLock<ScanMetrics>>,
    /// Per-job metrics
    job_metrics: Arc<RwLock<HashMap<Uuid, JobMetrics>>>,
    /// Event log (limited history)
    events: Arc<RwLock<Vec<MonitorEvent>>>,
    /// Max events to keep in memory
    max_events: usize,
    /// Scan history (completed jobs)
    scan_history: Arc<RwLock<Vec<ScanHistoryEntry>>>,
    /// Max history to keep
    max_history: usize,
}

/// Entry in scan history
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ScanHistoryEntry {
    job_id: Uuid,
    timestamp: DateTime<Utc>,
    duration: f64,
    findings: usize,
    success: bool,
}

impl ScanMonitor {
    /// Create a new scan monitor
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(ScanMetrics::default())),
            job_metrics: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: 1000,
            scan_history: Arc::new(RwLock::new(Vec::new())),
            max_history: 1000,
        }
    }

    /// Record that a scan has started
    pub async fn scan_started(&self, job_id: Uuid) {
        let now = Utc::now();

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_scans += 1;
            metrics.active_scans += 1;
            metrics.last_scan_time = Some(now);
        }

        // Create job metrics
        let job_metric = JobMetrics {
            job_id,
            started_at: now,
            ended_at: None,
            duration: None,
            findings: 0,
            status: JobStatus::Running,
            progress: 0,
        };

        {
            let mut job_metrics = self.job_metrics.write().await;
            job_metrics.insert(job_id, job_metric);
        }

        // Log event
        self.log_event(MonitorEvent::ScanStarted {
            job_id,
            timestamp: now,
        }).await;
    }

    /// Record that a scan has completed
    pub async fn scan_completed(&self, job_id: Uuid, success: bool, start_time: DateTime<Utc>, findings: usize) {
        let now = Utc::now();
        let duration = (now - start_time).num_seconds().max(0) as f64;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.active_scans -= 1;

            if success {
                metrics.successful_scans += 1;
            } else {
                metrics.failed_scans += 1;
            }

            // Update average duration
            metrics.total_scan_time += duration;
            metrics.avg_duration = Some(metrics.total_scan_time / metrics.total_scans as f64);

            // Update periodic counts
            self.update_periodic_counts(&mut metrics).await;
        }

        // Update job metrics
        {
            let mut job_metrics = self.job_metrics.write().await;
            if let Some(job_metric) = job_metrics.get_mut(&job_id) {
                job_metric.ended_at = Some(now);
                job_metric.duration = Some(duration);
                job_metric.findings = findings;
                job_metric.status = JobStatus::Completed;
                job_metric.progress = 100;
            }
        }

        // Add to history
        {
            let mut history = self.scan_history.write().await;
            history.push(ScanHistoryEntry {
                job_id,
                timestamp: now,
                duration,
                findings,
                success,
            });

            // Trim history if needed
            if history.len() > self.max_history {
                history.remove(0);
            }
        }

        // Log event
        self.log_event(MonitorEvent::ScanCompleted {
            job_id,
            timestamp: now,
            findings,
        }).await;
    }

    /// Record that a scan has failed
    pub async fn scan_failed(&self, job_id: Uuid) {
        let now = Utc::now();

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.active_scans -= 1;
            metrics.failed_scans += 1;
        }

        // Update job metrics
        {
            let mut job_metrics = self.job_metrics.write().await;
            if let Some(job_metric) = job_metrics.get_mut(&job_id) {
                job_metric.ended_at = Some(now);
                let start = job_metric.started_at;
                job_metric.duration = Some((now - start).num_seconds().max(0) as f64);
                job_metric.status = JobStatus::Failed;
            }
        }

        // Log event
        self.log_event(MonitorEvent::ScanFailed {
            job_id,
            timestamp: now,
            error: "Scan failed".to_string(),
        }).await;
    }

    /// Update progress for a running scan
    pub async fn update_progress(&self, job_id: Uuid, progress: u8) {
        let mut job_metrics = self.job_metrics.write().await;
        if let Some(job_metric) = job_metrics.get_mut(&job_id) {
            job_metric.progress = progress.min(100);
        }
    }

    /// Record a vulnerability finding
    pub async fn vulnerability_found(&self, job_id: Uuid, severity: String) {
        {
            let mut metrics = self.metrics.write().await;
            *metrics.findings_by_severity.entry(severity.clone()).or_insert(0) += 1;
        }

        self.log_event(MonitorEvent::VulnerabilityFound { job_id, severity }).await;
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> ScanMetrics {
        self.metrics.read().await.clone()
    }

    /// Get metrics for a specific job
    pub async fn get_job_metrics(&self, job_id: Uuid) -> Option<JobMetrics> {
        self.job_metrics.read().await.get(&job_id).cloned()
    }

    /// Get all recent events
    pub async fn get_events(&self, limit: Option<usize>) -> Vec<MonitorEvent> {
        let events = self.events.read().await;
        let limit = limit.unwrap_or(self.max_events);

        events.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get scan history
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<ScanHistoryEntry> {
        let history = self.scan_history.read().await;
        let limit = limit.unwrap_or(self.max_history);

        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get dashboard data
    pub async fn get_dashboard_data(&self) -> DashboardData {
        let metrics = self.get_metrics().await;
        let recent_scans = self.get_history(Some(10)).await;
        let active_jobs: Vec<_> = {
            let job_metrics = self.job_metrics.read().await;
            job_metrics.values()
                .filter(|j| j.status == JobStatus::Running)
                .cloned()
                .collect()
        };

        DashboardData {
            metrics,
            recent_scans,
            active_jobs,
            timestamp: Utc::now(),
        }
    }

    /// Log an event
    async fn log_event(&self, event: MonitorEvent) {
        let mut events = self.events.write().await;
        events.push(event);

        // Trim if needed
        if events.len() > self.max_events {
            events.remove(0);
        }
    }

    /// Update periodic scan counts
    async fn update_periodic_counts(&self, metrics: &mut ScanMetrics) {
        let now = Utc::now();
        let hour_ago = now - Duration::hours(1);
        let day_ago = now - Duration::days(1);

        let history = self.scan_history.read().await;

        metrics.scans_last_hour = history.iter()
            .filter(|e| e.timestamp > hour_ago)
            .count();

        metrics.scans_last_24h = history.iter()
            .filter(|e| e.timestamp > day_ago)
            .count();
    }

    /// Calculate statistics for a time period
    pub async fn get_period_stats(&self, hours: i64) -> PeriodStats {
        let cutoff = Utc::now() - Duration::hours(hours);
        let history = self.scan_history.read().await;

        let period_scans: Vec<_> = history.iter()
            .filter(|e| e.timestamp > cutoff)
            .collect();

        let total = period_scans.len();
        let successful = period_scans.iter().filter(|e| e.success).count();
        let failed = period_scans.iter().filter(|e| !e.success).count();
        let total_findings = period_scans.iter().map(|e| e.findings).sum();
        let avg_duration = if total > 0 {
            Some(period_scans.iter().map(|e| e.duration).sum::<f64>() / total as f64)
        } else {
            None
        };

        PeriodStats {
            period_hours: hours,
            total_scans: total,
            successful_scans: successful,
            failed_scans: failed,
            total_findings,
            avg_duration,
        }
    }
}

/// Dashboard data for monitoring UI
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardData {
    pub metrics: ScanMetrics,
    pub recent_scans: Vec<ScanHistoryEntry>,
    pub active_jobs: Vec<JobMetrics>,
    pub timestamp: DateTime<Utc>,
}

/// Statistics for a time period
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeriodStats {
    pub period_hours: i64,
    pub total_scans: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub total_findings: usize,
    pub avg_duration: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitor_scan_lifecycle() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();
        let start_time = Utc::now();

        // Start scan
        monitor.scan_started(job_id).await;

        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.total_scans, 1);
        assert_eq!(metrics.active_scans, 1);

        // Complete scan
        monitor.scan_completed(job_id, true, start_time, 5).await;

        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.active_scans, 0);
        assert_eq!(metrics.successful_scans, 1);
        assert!(metrics.avg_duration.is_some());
    }

    #[tokio::test]
    async fn test_monitor_failed_scan() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();

        monitor.scan_started(job_id).await;
        monitor.scan_failed(job_id).await;

        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.failed_scans, 1);
    }

    #[tokio::test]
    async fn test_job_metrics() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();
        let start_time = Utc::now();

        monitor.scan_started(job_id).await;

        let job_metrics = monitor.get_job_metrics(job_id).await;
        assert!(job_metrics.is_some());
        assert_eq!(job_metrics.unwrap().status, JobStatus::Running);

        monitor.scan_completed(job_id, true, start_time, 10).await;

        let job_metrics = monitor.get_job_metrics(job_id).await;
        assert!(job_metrics.is_some());
        assert_eq!(job_metrics.unwrap().status, JobStatus::Completed);
    }

    #[tokio::test]
    async fn test_vulnerability_tracking() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();

        monitor.vulnerability_found(job_id, "Critical".to_string()).await;
        monitor.vulnerability_found(job_id, "High".to_string()).await;
        monitor.vulnerability_found(job_id, "Critical".to_string()).await;

        let metrics = monitor.get_metrics().await;
        assert_eq!(metrics.findings_by_severity.get("Critical"), Some(&2));
        assert_eq!(metrics.findings_by_severity.get("High"), Some(&1));
    }

    #[tokio::test]
    async fn test_events() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();

        monitor.scan_started(job_id).await;

        let events = monitor.get_events(Some(10)).await;
        assert!(!events.is_empty());

        match &events[0] {
            MonitorEvent::ScanStarted { job_id: id, .. } => {
                assert_eq!(*id, job_id);
            }
            _ => panic!("Expected ScanStarted event"),
        }
    }

    #[tokio::test]
    async fn test_dashboard_data() {
        let monitor = ScanMonitor::new();
        let job_id = Uuid::new_v4();

        monitor.scan_started(job_id).await;

        let dashboard = monitor.get_dashboard_data().await;
        assert_eq!(dashboard.metrics.active_scans, 1);
        assert!(!dashboard.active_jobs.is_empty());
    }
}
