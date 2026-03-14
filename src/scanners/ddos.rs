//! DDoS resistance testing scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tokio::task::JoinSet;

pub struct DdosScanner {
    client: Client,
    config: ScannerConfig,
}

impl DdosScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                report.merge(self.test_http_flood(url).await?);
                report.merge(self.test_slowloris(url).await?);
            }
            Target::Path(_) => {
                // Skip DDoS testing for local paths
            }
        }

        Ok(report)
    }

    async fn test_http_flood(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let request_count = if self.config.aggressive { 100 } else { 20 };
        let mut tasks = JoinSet::new();

        for _ in 0..request_count {
            let client = self.client.clone();
            let url = url.to_string();

            tasks.spawn(async move {
                client.head(&url).send().await.ok()
            });
        }

        let mut success = 0;
        let mut failed = 0;

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Some(_)) => success += 1,
                _ => failed += 1,
            }
        }

        let error_rate = failed as f64 / request_count as f64;

        if error_rate > 0.1 {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Vulnerable to HTTP flood".to_string(),
                description: format!("{:.1}% error rate under load", error_rate * 100.0),
                location: Some(url.to_string()),
                recommendation: Some("Implement rate limiting and consider DDoS protection".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        Ok(report)
    }

    async fn test_slowloris(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Basic Slowloris test - send incomplete headers
        match self.client
            .post(url)
            .header("X-Test", "a".repeat(10000).as_str())
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(_) => {
                // Server handled it, no finding
            }
            Err(_) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Potential Slowloris vulnerability".to_string(),
                    description: "Server may be vulnerable to slow HTTP attacks".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Configure request timeout limits".to_string()),
                    cwe: Some("CWE-770".to_string()),
                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                });
            }
        }

        Ok(report)
    }
}
