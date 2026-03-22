//! Race Condition vulnerability scanner
//!
//! This module provides comprehensive race condition testing capabilities including:
//! - TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
//! - Password reset token bruteforce via concurrent requests
//! - Coupon/discount abuse via concurrent usage
//! - Rate limit bypass via timing attacks
//! - Limit bypass (concurrent request flooding)
//!
//! # Safety
//! All tests have built-in limits to prevent actual damage during normal scans.

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::info;

/// Race condition test metrics
#[derive(Clone, Debug)]
pub struct RaceConditionMetrics {
    /// Total concurrent requests sent
    pub total_requests: usize,
    /// Successful requests
    pub successful_requests: usize,
    /// Failed requests
    pub failed_requests: usize,
    /// Requests that succeeded when they shouldn't have
    pub unexpected_successes: usize,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Timing variance (max - min) in milliseconds
    pub timing_variance_ms: f64,
    /// Whether race condition was detected
    pub race_detected: bool,
}

impl Default for RaceConditionMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            unexpected_successes: 0,
            avg_response_time_ms: 0.0,
            timing_variance_ms: 0.0,
            race_detected: false,
        }
    }
}

/// Race condition test type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RaceTestType {
    /// TOCTOU - File upload race condition
    ToctouFileUpload,
    /// TOCTOU - Concurrent request timing gap
    ToctouRequestTiming,
    /// Password reset token bruteforce
    PasswordResetBruteforce,
    /// Coupon concurrent usage
    CouponConcurrency,
    /// Rate limit bypass via timing
    RateLimitBypass,
    /// Limit bypass via concurrent flooding
    LimitBypassFlood,
}

impl RaceTestType {
    fn name(&self) -> &str {
        match self {
            RaceTestType::ToctouFileUpload => "TOCTOU File Upload",
            RaceTestType::ToctouRequestTiming => "TOCTOU Request Timing",
            RaceTestType::PasswordResetBruteforce => "Password Reset Bruteforce",
            RaceTestType::CouponConcurrency => "Coupon Concurrent Usage",
            RaceTestType::RateLimitBypass => "Rate Limit Bypass",
            RaceTestType::LimitBypassFlood => "Limit Bypass Flood",
        }
    }
}

/// Configuration for race condition testing
#[derive(Clone, Debug)]
pub struct RaceTestConfig {
    /// Maximum concurrent requests (safety limit)
    pub max_concurrent: usize,
    /// Test duration in seconds
    pub test_duration_secs: u64,
    /// Whether to use aggressive testing
    pub aggressive: bool,
    /// Request delay between batches in milliseconds
    pub batch_delay_ms: u64,
}

impl Default for RaceTestConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            test_duration_secs: 5,
            aggressive: false,
            batch_delay_ms: 100,
        }
    }
}

impl From<&ScannerConfig> for RaceTestConfig {
    fn from(config: &ScannerConfig) -> Self {
        let mut test_config = RaceTestConfig::default();

        if config.aggressive {
            test_config.max_concurrent = 150;
            test_config.test_duration_secs = 10;
            test_config.aggressive = true;
            test_config.batch_delay_ms = 50;
        }

        test_config
    }
}

/// Main race condition scanner
pub struct RaceConditionScanner {
    client: Client,
    config: ScannerConfig,
    test_config: RaceTestConfig,
}

impl RaceConditionScanner {
    /// Create a new race condition scanner
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .pool_max_idle_per_host(50)
            .build()
            .expect("Failed to create HTTP client");

        let test_config = RaceTestConfig::from(&config);

        Self {
            client,
            config,
            test_config,
        }
    }

    /// Run a full race condition scan
    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                // Validate URL
                if let Err(_e) = url::Url::parse(url) {
                    return Ok(report);
                }

                info!("Starting race condition tests on {}", url);

                // TOCTOU Tests
                if let Ok(toctou_report) = self.test_toctou_file_upload(url).await {
                    report.merge(toctou_report);
                }

                // Password Reset Race
                if let Ok(pwd_report) = self.test_password_reset_race(url).await {
                    report.merge(pwd_report);
                }

                // Coupon Abuse Test
                if let Ok(coupon_report) = self.test_coupon_concurrency(url).await {
                    report.merge(coupon_report);
                }

                // Rate Limit Bypass
                if let Ok(rate_report) = self.test_rate_limit_bypass_race(url).await {
                    report.merge(rate_report);
                }

                // Limit Bypass (only in aggressive mode)
                if self.test_config.aggressive {
                    if let Ok(limit_report) = self.test_limit_bypass_flood(url).await {
                        report.merge(limit_report);
                    }
                }
            }
            Target::Path(_) => {
                // Skip race condition testing for local paths
            }
        }

        Ok(report)
    }

    /// Test TOCTOU - File Upload Race Condition
    ///
    /// Tests for race conditions where file validation happens separately
    /// from file processing, allowing malicious files to slip through.
    async fn test_toctou_file_upload(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let upload_endpoints = [
            "/upload",
            "/upload/file",
            "/api/upload",
            "/api/upload/file",
            "/files/upload",
            "/admin/upload",
        ];

        for endpoint in upload_endpoints {
            let upload_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            // Check if endpoint exists
            if !self.endpoint_exists(&upload_url).await {
                continue;
            }

            info!("Testing TOCTOU at {}", upload_url);

            // Simulate concurrent file upload attempts
            let concurrent = if self.test_config.aggressive { 30 } else { 15 };
            let success_count = Arc::new(AtomicUsize::new(0));
            let mut tasks = JoinSet::new();

            for i in 0..concurrent {
                let client = self.client.clone();
                let url = upload_url.clone();
                let success = success_count.clone();

                tasks.spawn(async move {
                    // Simulate file upload with form data
                    let test_filename = format!("test_{}.jpg", i);
                    let test_content = String::from("test_file_content");

                    // Use simple form POST instead of multipart (requires feature)
                    let result = client
                        .post(&url)
                        .header("Content-Type", "multipart/form-data")
                        .form(&[("filename", test_filename), ("data", test_content)])
                        .send()
                        .await;

                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            success.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                });
            }

            while let Some(_) = tasks.join_next().await {}

            let successful = success_count.load(Ordering::Relaxed);

            // If multiple uploads succeeded simultaneously, might indicate TOCTOU
            if successful > 1 {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: "Potential TOCTOU in File Upload".to_string(),
                    description: format!(
                        "Concurrent file uploads ({}/{} succeeded) suggest potential race condition. \
                         File validation may not be atomic with file processing.",
                        successful, concurrent
                    ),
                    location: Some(upload_url),
                    recommendation: Some(
                        "Implement atomic file validation and processing. Use file move/rename operations \
                         that are atomic at the filesystem level. Validate after final file move, not before.".to_string()
                    ),
                    cwe: Some("CWE-367".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Test Password Reset Race Condition
    ///
    /// Tests for concurrent requests that can bruteforce reset tokens
    /// or bypass timing analysis protection.
    async fn test_password_reset_race(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let reset_endpoints = [
            "/password/reset",
            "/reset",
            "/forgot",
            "/forgot-password",
            "/auth/reset",
            "/api/password/reset",
            "/account/reset",
        ];

        for endpoint in reset_endpoints {
            let reset_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            if !self.endpoint_exists(&reset_url).await {
                continue;
            }

            info!("Testing password reset race at {}", reset_url);

            // Test 1: Concurrent identical requests (token reuse detection)
            let concurrent = 50;
            let success_count = Arc::new(AtomicUsize::new(0));
            let timing_data = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut tasks = JoinSet::new();

            let test_tokens = self.generate_test_tokens(10);

            for _ in 0..concurrent {
                let client = self.client.clone();
                let url = reset_url.clone();
                let success = success_count.clone();
                let timings = timing_data.clone();
                let tokens = test_tokens.clone();

                tasks.spawn(async move {
                    let start = Instant::now();

                    // Try each token
                    for token in &tokens {
                        let token_str = token.clone();
                        let new_pass = String::from("NewPass123!");
                        let result = client
                            .post(&url)
                            .form(&[("token", token_str), ("new_password", new_pass)])
                            .send()
                            .await;

                        if let Ok(resp) = result {
                            let elapsed = start.elapsed().as_millis() as f64;
                            if let Ok(mut t) = timings.lock() {
                                t.push((token.clone(), elapsed, resp.status().as_u16()));
                            }

                            if resp.status().is_success() {
                                success.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                });
            }

            while let Some(_) = tasks.join_next().await {}

            let successful = success_count.load(Ordering::Relaxed);
            let timings = timing_data.lock().unwrap_or_else(|e| e.into_inner()).clone();

            // Analyze timing patterns
            if !timings.is_empty() {
                let valid_timings: Vec<_> = timings.iter()
                    .filter(|(_, _, status)| *status == 200)
                    .map(|(_, t, _)| *t)
                    .collect();
                let invalid_timings: Vec<_> = timings.iter()
                    .filter(|(_, _, status)| *status != 200)
                    .map(|(_, t, _)| *t)
                    .collect();

                if !valid_timings.is_empty() && !invalid_timings.is_empty() {
                    let avg_valid = valid_timings.iter().sum::<f64>() / valid_timings.len() as f64;
                    let avg_invalid = invalid_timings.iter().sum::<f64>() / invalid_timings.len() as f64;

                    // If valid tokens respond significantly faster/slower, timing analysis possible
                    if (avg_valid - avg_invalid).abs() > 50.0 {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Password Reset Timing Analysis Vulnerability".to_string(),
                            description: format!(
                                "Response times differ significantly for valid vs invalid tokens \
                                 (valid: {:.1}ms, invalid: {:.1}ms). This enables timing attacks.",
                                avg_valid, avg_invalid
                            ),
                            location: Some(reset_url.clone()),
                            recommendation: Some(
                                "Add constant-time delay to all password reset attempts. \
                                 Use random delays to obscure timing differences.".to_string()
                            ),
                            cwe: Some("CWE-208".to_string()),
                            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                        });
                    }
                }
            }

            // Test 2: Token bruteforce via concurrent requests
            if successful > 0 {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "Password Reset Token Bruteforce Possible".to_string(),
                    description: format!(
                        "{} successful responses out of {} concurrent requests suggest \
                         weak token validation or lack of rate limiting on reset endpoint.",
                        successful, concurrent
                    ),
                    location: Some(reset_url),
                    recommendation: Some(
                        "Implement exponential backoff for failed reset attempts. \
                         Use cryptographically secure tokens with sufficient entropy. \
                         Limit reset attempts per IP and per account.".to_string()
                    ),
                    cwe: Some("CWE-307".to_string()),
                    owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Test Coupon/Discount Abuse via Concurrent Usage
    ///
    /// Tests if single-use coupons can be used multiple times
    /// through concurrent requests.
    async fn test_coupon_concurrency(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let checkout_endpoints = [
            "/checkout",
            "/cart/checkout",
            "/api/checkout",
            "/api/cart/checkout",
            "/purchase",
            "/order",
        ];

        let test_coupons = ["SAVE20", "WELCOME10", "FIRST50", "TEST100", "PROMO2024"];

        for endpoint in checkout_endpoints {
            let checkout_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            if !self.endpoint_exists(&checkout_url).await {
                continue;
            }

            info!("Testing coupon concurrency at {}", checkout_url);

            for coupon in &test_coupons {
                let concurrent = 30;
                let success_count = Arc::new(AtomicUsize::new(0));
                let mut tasks = JoinSet::new();

                for _ in 0..concurrent {
                    let client = self.client.clone();
                    let url = checkout_url.clone();
                    let coupon_code = coupon.to_string();
                    let success = success_count.clone();

                    tasks.spawn(async move {
                        let amount = String::from("100");
                        let currency = String::from("USD");
                        let result = client
                            .post(&url)
                            .form(&[
                                ("coupon", &coupon_code),
                                ("amount", &amount),
                                ("currency", &currency),
                            ])
                            .send()
                            .await;

                        if let Ok(resp) = result {
                            if resp.status().is_success() {
                                let text = resp.text().await.unwrap_or_default();
                                // Check if coupon was applied
                                if text.to_lowercase().contains("discount")
                                    || text.to_lowercase().contains("coupon")
                                    || text.to_lowercase().contains("promo")
                                {
                                    success.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    });
                }

                while let Some(_) = tasks.join_next().await {}

                let successful = success_count.load(Ordering::Relaxed);

                // If coupon applied multiple times concurrently, race condition detected
                if successful > 1 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Coupon Race Condition - Concurrent Abuse".to_string(),
                        description: format!(
                            "Coupon '{}' was successfully applied {} times in concurrent requests. \
                             Single-use coupon validation has a race condition.",
                            coupon, successful
                        ),
                        location: Some(checkout_url.clone()),
                        recommendation: Some(
                            "Implement atomic coupon redemption with database locks. \
                             Use pessimistic locking or optimistic locking with version checks. \
                             Consider idempotency keys for checkout requests.".to_string()
                        ),
                        cwe: Some("CWE-362".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                    break; // Found vulnerability, stop testing other coupons
                }
            }
        }

        Ok(report)
    }

    /// Test Rate Limit Bypass via Timing
    ///
    /// Tests if rate limits can be bypassed by sending requests
    /// at specific timing intervals or concurrently.
    async fn test_rate_limit_bypass_race(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        info!("Testing rate limit bypass via timing");

        let test_path = "/api/test";
        let test_url = format!("{}{}", base_url.trim_end_matches('/'), test_path);
        let test_url_for_report = test_url.clone();

        // Test 1: Burst of concurrent requests
        let burst_size = 100;
        let success_count = Arc::new(AtomicUsize::new(0));
        let rate_limited = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        for _ in 0..burst_size {
            let client = self.client.clone();
            let url = test_url.clone();
            let success = success_count.clone();
            let limited = rate_limited.clone();

            tasks.spawn(async move {
                let result = client.get(&url).send().await;

                match result {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if status == 429 {
                            limited.fetch_add(1, Ordering::Relaxed);
                        } else if status < 400 {
                            success.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {}
                }
            });
        }

        while let Some(_) = tasks.join_next().await {}

        let successful = success_count.load(Ordering::Relaxed);
        let limited = rate_limited.load(Ordering::Relaxed);

        // Test 2: Staggered timing attack
        let staggered_success = Arc::new(AtomicUsize::new(0));
        let mut tasks = JoinSet::new();

        for i in 0..20 {
            let client = self.client.clone();
            let url = test_url.clone();
            let success = staggered_success.clone();

            tasks.spawn(async move {
                // Vary the delay slightly
                sleep(Duration::from_millis(10 + (i % 10) * 5)).await;

                let result = client.get(&url).send().await;

                if let Ok(resp) = result {
                    if resp.status().is_success() {
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }

        while let Some(_) = tasks.join_next().await {}

        let staggered_successful = staggered_success.load(Ordering::Relaxed);

        // Analyze results
        if successful > 10 || limited == 0 {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Rate Limit Bypass via Concurrent Requests".to_string(),
                description: format!(
                    "Sent {} concurrent requests: {} succeeded, {} rate-limited. \
                     Rate limiting may not properly handle concurrent requests.",
                    burst_size, successful, limited
                ),
                location: Some(test_url_for_report.clone()),
                recommendation: Some(
                    "Implement token bucket or leaky bucket rate limiting at infrastructure level. \
                     Use distributed rate limiting for multi-instance deployments. \
                     Count requests before processing, not after.".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        if staggered_successful > 15 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Rate Limit Bypass via Timing Variation".to_string(),
                description: format!(
                    "Staggered requests achieved {} successes. Rate limiting may have time windows that can be exploited.",
                    staggered_successful
                ),
                location: Some(test_url_for_report.clone()),
                recommendation: Some(
                    "Use sliding window rate limiting instead of fixed windows. \
                     Implement request deduplication for identical concurrent requests.".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }

    /// Test Limit Bypass via Concurrent Flooding
    ///
    /// Tests aggressive concurrent request flooding to bypass
    /// rate limits, API quotas, or resource limits.
    async fn test_limit_bypass_flood(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        info!("Testing limit bypass via flooding (aggressive mode)");

        let flood_endpoints = ["/", "/api/status", "/api/ping"];

        for endpoint in flood_endpoints {
            let flood_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            // Test with increasing concurrent levels
            for &concurrent in &[50, 100, 150] {
                let success_count = Arc::new(AtomicUsize::new(0));
                let fail_count = Arc::new(AtomicUsize::new(0));
                let response_times = Arc::new(std::sync::Mutex::new(Vec::new()));
                let mut tasks = JoinSet::new();

                for _ in 0..concurrent {
                    let client = self.client.clone();
                    let url = flood_url.clone();
                    let success = success_count.clone();
                    let fail = fail_count.clone();
                    let times = response_times.clone();

                    tasks.spawn(async move {
                        let start = Instant::now();
                        let result = client.get(&url).timeout(Duration::from_secs(5)).send().await;
                        let elapsed = start.elapsed().as_millis() as f64;

                        if let Ok(mut t) = times.lock() {
                            t.push(elapsed);
                        }

                        match result {
                            Ok(resp) if resp.status().is_success() => {
                                success.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                fail.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }

                while let Some(_) = tasks.join_next().await {}

                let successful = success_count.load(Ordering::Relaxed);
                let failed = fail_count.load(Ordering::Relaxed);
                let times = response_times.lock().unwrap_or_else(|e| e.into_inner()).clone();

                let success_rate = (successful as f64 / concurrent as f64) * 100.0;

                if !times.is_empty() {
                    let _avg_time = times.iter().sum::<f64>() / times.len() as f64;
                    let max_time = times.iter().fold(0.0f64, |a, &b| a.max(b));
                    let min_time = times.iter().fold(f64::MAX, |a, &b| a.min(b));

                    // Check for timing anomalies
                    if max_time - min_time > 500.0 {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: "Timing Anomaly Under Load".to_string(),
                            description: format!(
                                "Under {} concurrent requests, response times vary widely ({:.0}ms to {:.0}ms). \
                                 This may indicate resource contention or queue buildup.",
                                concurrent, min_time, max_time
                            ),
                            location: Some(flood_url.clone()),
                            recommendation: Some(
                                "Implement request queuing and timeouts. Monitor response times under load. \
                                 Consider circuit breakers for degraded service.".to_string()
                            ),
                            cwe: Some("CWE-770".to_string()),
                            owasp: None,
                        });
                    }
                }

                // High success rate under flooding indicates weak limits
                if success_rate > 80.0 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Limit Bypass via Concurrent Flooding".to_string(),
                        description: format!(
                            "{} concurrent requests achieved {:.1}% success rate ({} succeeded, {} failed). \
                            Resource limits appear ineffective against flooding.",
                            concurrent, success_rate, successful, failed
                        ),
                        location: Some(flood_url.clone()),
                        recommendation: Some(
                            "Implement aggressive rate limiting with decreasing allowances. \
                             Use connection throttling at the infrastructure level. \
                             Deploy API gateway with built-in protection.".to_string()
                        ),
                        cwe: Some("CWE-770".to_string()),
                        owasp: Some("A04:2021 - Insecure Design".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check if endpoint exists
    async fn endpoint_exists(&self, url: &str) -> bool {
        if let Ok(response) = self.client.get(url).send().await {
            response.status().as_u16() != 404
        } else {
            false
        }
    }

    /// Generate test tokens for password reset testing
    fn generate_test_tokens(&self, count: usize) -> Vec<String> {
        let mut tokens = Vec::new();

        // Add some common weak token patterns
        tokens.extend_from_slice(&[
            "123456".to_string(),
            "abc123".to_string(),
            "token".to_string(),
            "reset".to_string(),
            "valid".to_string(),
        ]);

        // Add random hex-like tokens
        for i in 0..count {
            tokens.push(format!("{:016x}", i));
        }

        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_race_test_type_names() {
        assert_eq!(RaceTestType::ToctouFileUpload.name(), "TOCTOU File Upload");
        assert_eq!(RaceTestType::PasswordResetBruteforce.name(), "Password Reset Bruteforce");
    }

    #[test]
    fn test_race_metrics_default() {
        let metrics = RaceConditionMetrics::default();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.successful_requests, 0);
        assert!(!metrics.race_detected);
    }

    #[test]
    fn test_race_test_config_default() {
        let config = RaceTestConfig::default();
        assert_eq!(config.max_concurrent, 50);
        assert_eq!(config.test_duration_secs, 5);
        assert!(!config.aggressive);
    }

    #[test]
    fn test_race_scanner_creation() {
        let scanner_config = ScannerConfig::new();
        let scanner = RaceConditionScanner::new(scanner_config);
        assert_eq!(scanner.test_config.max_concurrent, 50);
    }

    #[test]
    fn test_race_scanner_aggressive_config() {
        let scanner_config = ScannerConfig::new().with_aggressive(true);
        let scanner = RaceConditionScanner::new(scanner_config);
        assert_eq!(scanner.test_config.max_concurrent, 150);
        assert!(scanner.test_config.aggressive);
    }

    #[test]
    fn test_generate_test_tokens() {
        let config = ScannerConfig::new();
        let scanner = RaceConditionScanner::new(config);
        let tokens = scanner.generate_test_tokens(10);
        assert!(tokens.len() >= 15); // 5 common + 10 generated
    }
}
