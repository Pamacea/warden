//! Stress testing scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

pub struct StressScanner {
    client: Client,
    config: ScannerConfig,
}

impl StressScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(60);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to create HTTP client for Stress scanner");

        Self { client, config }
    }

    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                report.merge(self.test_response_time(url).await?);
                report.merge(self.test_concurrent_load(url).await?);
            }
            Target::Path(_) => {
                // Skip stress testing for local paths
            }
        }

        Ok(report)
    }

    async fn test_response_time(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let iterations = 10;
        let mut total_time = Duration::ZERO;
        let mut max_time = Duration::ZERO;

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = self.client.head(url).send().await;
            let elapsed = start.elapsed();

            total_time += elapsed;
            if elapsed > max_time {
                max_time = elapsed;
            }
        }

        let avg_time = total_time / iterations;

        if avg_time > Duration::from_millis(1000) {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Slow response time".to_string(),
                description: format!("Average response time: {:?}", avg_time),
                location: Some(url.to_string()),
                recommendation: Some("Consider optimizing or caching responses".to_string()),
                cwe: None,
                owasp: None,
            });
        }

        Ok(report)
    }

    async fn test_concurrent_load(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let concurrency = if self.config.aggressive { 50 } else { 10 };
        let mut tasks = JoinSet::new();

        let start = Instant::now();

        for _ in 0..concurrency {
            let client = self.client.clone();
            let url = url.to_string();

            tasks.spawn(async move {
                let req_start = Instant::now();
                let _ = client.get(&url).send().await;
                req_start.elapsed()
            });
        }

        let mut times = Vec::new();

        while let Some(result) = tasks.join_next().await {
            if let Ok(time) = result {
                times.push(time);
            }
        }

        let total_time = start.elapsed();

        if total_time > Duration::from_secs(10) {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: "Slow under concurrent load".to_string(),
                description: format!(
                    "{} concurrent requests took {:?}",
                    concurrency, total_time
                ),
                location: Some(url.to_string()),
                recommendation: Some("Consider scaling or optimizing".to_string()),
                cwe: None,
                owasp: None,
            });
        }

        Ok(report)
    }
}
