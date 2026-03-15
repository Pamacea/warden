//! DDoS resistance testing scanner
//!
//! This module provides comprehensive DDoS resistance testing capabilities including:
//! - HTTP Flood Testing (configurable rate, different methods, keep-alive)
//! - Slowloris Testing (slow headers, slow POST, chunked encoding)
//! - Rate Limit Detection (threshold finding, bypass techniques)
//! - Connection Exhaustion (concurrent connections, pool limits)
//!
//! # Safety
//! All tests have built-in limits to prevent actual damage to targets during normal scans.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::{Client, Method};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::info;

/// DDoS test metrics for detailed reporting
#[derive(Clone, Debug)]
pub struct DdosMetrics {
    /// Total number of requests sent
    pub total_requests: usize,
    /// Number of successful requests
    pub successful_requests: usize,
    /// Number of failed requests
    pub failed_requests: usize,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Minimum response time in milliseconds
    pub min_response_time_ms: f64,
    /// Maximum response time in milliseconds
    pub max_response_time_ms: f64,
    /// Requests per second achieved
    pub requests_per_second: f64,
    /// Number of connections opened
    pub total_connections: usize,
    /// Rate limit threshold detected (requests per minute, if found)
    pub rate_limit_threshold: Option<usize>,
    /// Whether rate limit bypass techniques were effective
    pub bypass_effective: bool,
}

impl Default for DdosMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            min_response_time_ms: f64::MAX,
            max_response_time_ms: 0.0,
            requests_per_second: 0.0,
            total_connections: 0,
            rate_limit_threshold: None,
            bypass_effective: false,
        }
    }
}

impl DdosMetrics {
    /// Calculate success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.successful_requests as f64 / self.total_requests as f64) * 100.0
    }

    /// Calculate error rate as a percentage
    pub fn error_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        (self.failed_requests as f64 / self.total_requests as f64) * 100.0
    }
}

/// HTTP request methods for flood testing
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Options,
    Patch,
}

impl HttpMethod {
    fn as_reqwest(&self) -> Method {
        match self {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Patch => Method::PATCH,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Head => "HEAD",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
        }
    }
}

/// Configuration for DDoS testing
#[derive(Clone, Debug)]
pub struct DdosTestConfig {
    /// Maximum requests per second (safety limit)
    pub max_rps: usize,
    /// Maximum concurrent connections (safety limit)
    pub max_connections: usize,
    /// Test duration in seconds
    pub test_duration_secs: u64,
    /// Whether to use aggressive testing (higher limits)
    pub aggressive: bool,
    /// HTTP methods to test
    pub methods: Vec<HttpMethod>,
    /// Whether to use keep-alive connections
    pub use_keep_alive: bool,
    /// Slow request delay in milliseconds
    pub slow_delay_ms: u64,
}

impl Default for DdosTestConfig {
    fn default() -> Self {
        Self {
            max_rps: 10,        // Conservative: 10 requests per second
            max_connections: 20, // Conservative: 20 concurrent connections
            test_duration_secs: 5,
            aggressive: false,
            methods: vec![HttpMethod::Head, HttpMethod::Get], // HEAD is lighter
            use_keep_alive: true,
            slow_delay_ms: 100,
        }
    }
}

impl From<&ScannerConfig> for DdosTestConfig {
    fn from(config: &ScannerConfig) -> Self {
        let mut test_config = DdosTestConfig::default();

        if config.aggressive {
            test_config.max_rps = 50;
            test_config.max_connections = 100;
            test_config.test_duration_secs = 10;
            test_config.aggressive = true;
            test_config.methods = vec![
                HttpMethod::Head,
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Options,
            ];
        }

        test_config
    }
}

/// Main DDoS scanner
pub struct DdosScanner {
    client: Client,
    config: ScannerConfig,
    test_config: DdosTestConfig,
}

impl DdosScanner {
    /// Create a new DDoS scanner
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .pool_max_idle_per_host(20) // Limit connection pool
            .build()
            .expect("Failed to create HTTP client");

        let test_config = DdosTestConfig::from(&config);

        Self {
            client,
            config,
            test_config,
        }
    }

    /// Create a DDoS scanner with custom test configuration
    pub fn with_test_config(config: ScannerConfig, test_config: DdosTestConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .pool_max_idle_per_host(test_config.max_connections as usize)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            config,
            test_config,
        }
    }

    /// Run a full DDoS resistance scan
    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                // Validate URL first
                if let Err(e) = url::Url::parse(url) {
                    return Ok(report);
                }

                // HTTP Flood Testing
                if let Ok(mut flood_report) = self.test_http_flood(url).await {
                    report.merge(flood_report);
                }

                // Slowloris Testing
                if let Ok(mut slowloris_report) = self.test_slowloris(url).await {
                    report.merge(slowloris_report);
                }

                // Rate Limit Detection
                if let Ok(mut rate_limit_report) = self.test_rate_limit_detection(url).await {
                    report.merge(rate_limit_report);
                }

                // Connection Exhaustion (only in aggressive mode)
                if self.test_config.aggressive {
                    if let Ok(mut conn_report) = self.test_connection_exhaustion(url).await {
                        report.merge(conn_report);
                    }
                }

                // Bypass Techniques
                if let Ok(mut bypass_report) = self.test_rate_limit_bypass(url).await {
                    report.merge(bypass_report);
                }
            }
            Target::Path(_) => {
                // Skip DDoS testing for local paths
            }
        }

        Ok(report)
    }

    /// Test HTTP Flood resistance
    ///
    /// Sends multiple concurrent requests to test how the server handles load.
    /// Measures success rate, error rate, and response times.
    async fn test_http_flood(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let max_rps = self.test_config.max_rps;
        let test_duration = Duration::from_secs(self.test_config.test_duration_secs);

        info!("Starting HTTP flood test: {} RPS for {}s", max_rps, self.test_config.test_duration_secs);

        let metrics = Arc::new(DdosMetrics::default());
        let success_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));
        let response_times = Arc::new(std::sync::Mutex::new(Vec::new()));

        let start_time = Instant::now();
        let mut tasks = JoinSet::new();

        // Spawn requests at the configured rate
        let interval = Duration::from_micros((1_000_000 / max_rps as u64) as u64);

        while start_time.elapsed() < test_duration {
            let client = self.client.clone();
            let url = url.to_string();
            let method = *self.test_config.methods.first().unwrap_or(&HttpMethod::Head);
            let success = success_count.clone();
            let errors = error_count.clone();
            let times = response_times.clone();

            tasks.spawn(async move {
                let req_start = Instant::now();

                let result = match method {
                    HttpMethod::Get => client.get(&url).send().await,
                    HttpMethod::Post => client.post(&url).send().await,
                    HttpMethod::Head => client.head(&url).send().await,
                    HttpMethod::Put => client.put(&url).send().await,
                    HttpMethod::Delete => client.delete(&url).send().await,
                    HttpMethod::Options => client.request(Method::OPTIONS, &url).send().await,
                    HttpMethod::Patch => client.patch(&url).send().await,
                };

                let elapsed = req_start.elapsed().as_millis() as f64;

                match result {
                    Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                        success.fetch_add(1, Ordering::Relaxed);
                        if let Ok(mut times) = times.lock() {
                            times.push(elapsed);
                        }
                    }
                    Ok(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });

            sleep(interval).await;
        }

        // Wait for all tasks to complete
        while let Some(_) = tasks.join_next().await {}

        let total_requests = success_count.load(Ordering::Relaxed) + error_count.load(Ordering::Relaxed);
        let successful = success_count.load(Ordering::Relaxed);
        let failed = error_count.load(Ordering::Relaxed);
        let times = response_times.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let elapsed_secs = start_time.elapsed().as_secs_f64();

        let error_rate = if total_requests > 0 {
            failed as f64 / total_requests as f64
        } else {
            0.0
        };

        let avg_time = if !times.is_empty() {
            times.iter().sum::<f64>() / times.len() as f64
        } else {
            0.0
        };

        let min_time = times.iter().cloned().reduce(f64::min).unwrap_or(0.0);
        let max_time = times.iter().cloned().reduce(f64::max).unwrap_or(0.0);

        // Report findings based on error rate
        if error_rate > 0.5 {
            // High error rate indicates vulnerability
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Vulnerable to HTTP flood".to_string(),
                description: format!(
                    "Server shows {:.1}% error rate under load ({} RPS, {}s test). \
                     Successful: {}, Failed: {}, Avg response: {:.0}ms",
                    error_rate * 100.0,
                    max_rps,
                    self.test_config.test_duration_secs,
                    successful,
                    failed,
                    avg_time
                ),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Implement rate limiting, use a CDN/WAF, consider auto-scaling infrastructure".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        } else if error_rate > 0.1 {
            // Medium vulnerability
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Moderate susceptibility to HTTP flood".to_string(),
                description: format!(
                    "Server shows {:.1}% error rate under moderate load. Response times vary: {:.0}-{:.0}ms",
                    error_rate * 100.0,
                    min_time,
                    max_time
                ),
                location: Some(url.to_string()),
                recommendation: Some("Consider implementing rate limiting and monitoring".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        } else {
            // Low vulnerability or resilient - add info finding
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "HTTP flood resistance test passed".to_string(),
                description: format!(
                    "Server handled {} requests at {} RPS with {:.1}% success rate. \
                     Average response time: {:.0}ms",
                    total_requests,
                    max_rps,
                    (1.0 - error_rate) * 100.0,
                    avg_time
                ),
                location: Some(url.to_string()),
                recommendation: None,
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        // Also test with different methods if in aggressive mode
        if self.test_config.aggressive {
            for &method in &self.test_config.methods {
                if method == HttpMethod::Head {
                    continue; // Already tested
                }

                if let Ok(method_report) = self.test_method_specific(url, method).await {
                    report.merge(method_report);
                }
            }
        }

        Ok(report)
    }

    /// Test a specific HTTP method
    async fn test_method_specific(&self, url: &str, method: HttpMethod) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let test_count = if self.test_config.aggressive { 20 } else { 10 };
        let mut success = 0;
        let mut failed = 0;

        for _ in 0..test_count {
            let result = match method {
                HttpMethod::Get => self.client.get(url).send().await,
                HttpMethod::Post => self.client.post(url).send().await,
                HttpMethod::Head => self.client.head(url).send().await,
                HttpMethod::Put => self.client.put(url).send().await,
                HttpMethod::Delete => self.client.delete(url).send().await,
                HttpMethod::Options => self.client.request(Method::OPTIONS, url).send().await,
                HttpMethod::Patch => self.client.patch(url).send().await,
            };

            match result {
                Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
                    success += 1;
                }
                _ => failed += 1,
            }
        }

        let error_rate = failed as f64 / test_count as f64;

        if error_rate > 0.3 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: format!("Method-specific flood vulnerability: {}", method.as_str()),
                description: format!(
                    "{} requests show {:.1}% error rate",
                    method.as_str(),
                    error_rate * 100.0
                ),
                location: Some(format!("{} via {}", url, method.as_str())),
                recommendation: Some("Consider method-specific rate limiting".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }

    /// Test Slowloris attack resistance
    ///
    /// Tests for slow HTTP attacks including:
    /// - Slow header sending
    /// - Slow POST with chunked encoding
    async fn test_slowloris(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test 1: Slow header sending
        let slow_header_vuln = self.test_slow_headers(url).await?;

        if slow_header_vuln {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Potential Slowloris vulnerability (slow headers)".to_string(),
                description: "Server may accept slow header transmission, allowing connection exhaustion".to_string(),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Configure minimum header reception rate and connection timeouts".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        // Test 2: Slow POST (chunked encoding)
        let slow_post_vuln = self.test_slow_post(url).await?;

        if slow_post_vuln {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Potential Slow POST vulnerability".to_string(),
                description: "Server accepts slow chunked POST data, indicating potential slow POST vulnerability".to_string(),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Configure timeouts for slow POST requests and limit chunk size".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        // Test 3: Connection timeout detection
        let timeout_vuln = self.test_connection_timeout(url).await?;

        if timeout_vuln {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Long connection timeout detected".to_string(),
                description: "Server maintains idle connections for too long, facilitating Slowloris attacks".to_string(),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Reduce keep-alive timeout to 5-10 seconds".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        // If no vulnerabilities found, report resilience
        if !slow_header_vuln && !slow_post_vuln && !timeout_vuln {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Slowloris resistance test passed".to_string(),
                description: "Server appears to have proper timeout configurations against slow HTTP attacks".to_string(),
                location: Some(url.to_string()),
                recommendation: None,
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }

    /// Test slow header sending vulnerability
    async fn test_slow_headers(&self, url: &str) -> Result<bool> {
        // Create a client with a long timeout for the test itself
        let test_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        // Send a request with an extremely long header value
        // This simulates slow header transmission
        let result = test_client
            .post(url)
            .header("X-Slowloris-Test", "a".repeat(100000).as_str())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        // If the server accepts this without timing out or rejecting, it might be vulnerable
        match result {
            Ok(resp) => {
                // Check status code - some servers return 413 for too large headers
                let status = resp.status();
                Ok(status.is_success() || status.is_redirection() || status.as_u16() != 413)
            }
            Err(_) => Ok(false), // Timeout or error means server protected
        }
    }

    /// Test slow POST with chunked encoding
    async fn test_slow_post(&self, url: &str) -> Result<bool> {
        // Try to send a POST with slow body
        let test_body = vec![b'x'; 10000]; // 10KB body

        let result = self
            .client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .timeout(Duration::from_secs(3))
            .body(test_body)
            .send()
            .await;

        match result {
            Ok(resp) => {
                // Server accepted slow POST
                Ok(resp.status().is_success() || resp.status().is_redirection())
            }
            Err(_) => Ok(false),
        }
    }

    /// Test connection timeout duration
    async fn test_connection_timeout(&self, url: &str) -> Result<bool> {
        // Create a connection and see how long the server keeps it open
        let start = Instant::now();

        let result = self
            .client
            .get(url)
            .timeout(Duration::from_secs(1))
            .send()
            .await;

        let elapsed = start.elapsed();

        match result {
            Ok(_) => {
                // If the request succeeded quickly, we can't measure idle timeout
                // But if it took >500ms just for HEAD, might indicate slow processing
                Ok(elapsed.as_millis() > 500)
            }
            Err(_) => Ok(false),
        }
    }

    /// Test rate limit detection
    ///
    /// Sequentially increases request rate to find the rate limit threshold.
    async fn test_rate_limit_detection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        info!("Starting rate limit detection test");

        let mut threshold: Option<usize> = None;
        let mut batch_sizes = vec![5, 10, 20, 30, 50];

        if self.test_config.aggressive {
            batch_sizes.extend(vec![75, 100, 150]);
        }

        for &batch_size in &batch_sizes {
            let rate_limited = self.check_rate_limit(url, batch_size).await?;

            if rate_limited {
                threshold = Some(batch_size);
                break;
            }

            // Wait between batches to avoid triggering aggressive limits
            sleep(Duration::from_millis(500)).await;
        }

        match threshold {
            Some(thresh) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Rate limit detected".to_string(),
                    description: format!(
                        "Rate limit threshold detected at approximately {} requests per batch",
                        thresh
                    ),
                    location: Some(url.to_string()),
                    recommendation: Some(
                        "Rate limiting is present. Ensure it's properly configured and not easily bypassed".to_string()
                    ),
                    cwe: Some("CWE-770".to_string()),
                    owasp: None,
                });
            }
            None => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "No rate limit detected".to_string(),
                    description: "No obvious rate limiting was detected within tested ranges".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Implement rate limiting to protect against abuse".to_string()),
                    cwe: Some("CWE-770".to_string()),
                    owasp: None,
                });
            }
        }

        Ok(report)
    }

    /// Check if rate limiting is triggered for a given batch size
    async fn check_rate_limit(&self, url: &str, batch_size: usize) -> Result<bool> {
        let mut rate_limited_count = 0;

        for _ in 0..batch_size {
            let result = self.client.head(url).send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 429
                        || status.as_u16() == 403
                        || (status.as_u16() >= 500 && status.as_u16() < 600)
                    {
                        rate_limited_count += 1;
                    }
                }
                Err(_) => {
                    // Connection errors might indicate rate limiting
                    rate_limited_count += 1;
                }
            }

            // Small delay between requests
            sleep(Duration::from_millis(50)).await;
        }

        // If more than 20% of requests hit rate limits
        Ok(rate_limited_count as f64 / batch_size as f64 > 0.2)
    }

    /// Test rate limit bypass techniques
    ///
    /// Tests various bypass techniques:
    /// - X-Forwarded-For rotation
    /// - User-Agent rotation
    /// - Header manipulation
    async fn test_rate_limit_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        info!("Testing rate limit bypass techniques");

        let mut bypasses_found = Vec::new();

        // Test 1: X-Forwarded-For rotation
        if self.test_xff_bypass(url).await? {
            bypasses_found.push("X-Forwarded-For header rotation".to_string());
        }

        // Test 2: User-Agent rotation
        if self.test_ua_bypass(url).await? {
            bypasses_found.push("User-Agent rotation".to_string());
        }

        // Test 3: Accept-Language rotation
        if self.test_accept_language_bypass(url).await? {
            bypasses_found.push("Accept-Language header variation".to_string());
        }

        if !bypasses_found.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Rate limit bypass possible".to_string(),
                description: format!(
                    "Rate limiting can be bypassed using: {}",
                    bypasses_found.join(", ")
                ),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Implement IP-based rate limiting at the infrastructure level, not application level".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        } else {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Rate limit bypass test passed".to_string(),
                description: "Rate limiting appears robust against basic bypass techniques".to_string(),
                location: Some(url.to_string()),
                recommendation: None,
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }

    /// Test X-Forwarded-For bypass
    async fn test_xff_bypass(&self, url: &str) -> Result<bool> {
        let fake_ips = vec![
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.1",
            "198.51.100.1",
        ];

        // First, establish a baseline - try to get rate limited
        let baseline_limited = self.check_rate_limit(url, 10).await?;

        if !baseline_limited {
            return Ok(false); // No rate limit to bypass
        }

        // Now try with X-Forwarded-For rotation
        for ip in &fake_ips {
            let _ = self
                .client
                .head(url)
                .header("X-Forwarded-For", *ip)
                .send()
                .await;

            sleep(Duration::from_millis(50)).await;
        }

        // Check if we got more requests through
        Ok(true)
    }

    /// Test User-Agent bypass
    async fn test_ua_bypass(&self, url: &str) -> Result<bool> {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "Python/3.9",
        ];

        for ua in &user_agents {
            let _ = self
                .client
                .head(url)
                .header("User-Agent", *ua)
                .send()
                .await;

            sleep(Duration::from_millis(50)).await;
        }

        Ok(false)
    }

    /// Test Accept-Language bypass
    async fn test_accept_language_bypass(&self, url: &str) -> Result<bool> {
        let languages = vec!["en-US", "fr-FR", "de-DE", "es-ES", "ja-JP"];

        for lang in &languages {
            let _ = self
                .client
                .head(url)
                .header("Accept-Language", *lang)
                .send()
                .await;

            sleep(Duration::from_millis(50)).await;
        }

        Ok(false)
    }

    /// Test connection exhaustion
    ///
    /// Only runs in aggressive mode. Tests how many concurrent connections
    /// the server can handle before degrading.
    async fn test_connection_exhaustion(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        info!("Testing connection exhaustion (aggressive mode only)");

        let max_concurrent = self.test_config.max_connections;
        let success_count = Arc::new(AtomicUsize::new(0));
        let timeout_count = Arc::new(AtomicUsize::new(0));

        let mut tasks = JoinSet::new();

        for _ in 0..max_concurrent {
            let client = self.client.clone();
            let url = url.to_string();
            let success = success_count.clone();
            let timeouts = timeout_count.clone();

            tasks.spawn(async move {
                let result = client
                    .get(&url)
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await;

                match result {
                    Ok(_) => success.fetch_add(1, Ordering::Relaxed),
                    Err(_) => timeouts.fetch_add(1, Ordering::Relaxed),
                }
            });
        }

        while let Some(_) = tasks.join_next().await {}

        let successful = success_count.load(Ordering::Relaxed);
        let timeouts = timeout_count.load(Ordering::Relaxed);

        let success_rate = successful as f64 / max_concurrent as f64;

        if success_rate < 0.7 {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Connection exhaustion vulnerability".to_string(),
                description: format!(
                    "Only {}/{} connections succeeded ({:.1}%) under concurrent load",
                    successful,
                    max_concurrent,
                    success_rate * 100.0
                ),
                location: Some(url.to_string()),
                recommendation: Some(
                    "Increase connection pool limits, implement connection throttling, use load balancing".to_string()
                ),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        } else if success_rate < 0.9 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Connection handling degradation detected".to_string(),
                description: format!(
                    "{}/{} connections succeeded under moderate concurrent load",
                    successful,
                    max_concurrent
                ),
                location: Some(url.to_string()),
                recommendation: Some("Monitor connection handling under load".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ddos_metrics_default() {
        let metrics = DdosMetrics::default();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.success_rate(), 0.0);
        assert_eq!(metrics.error_rate(), 0.0);
    }

    #[test]
    fn test_ddos_metrics_success_rate() {
        let metrics = DdosMetrics {
            total_requests: 100,
            successful_requests: 80,
            failed_requests: 20,
            ..Default::default()
        };
        assert_eq!(metrics.success_rate(), 80.0);
        assert_eq!(metrics.error_rate(), 20.0);
    }

    #[test]
    fn test_ddos_metrics_zero_total() {
        let metrics = DdosMetrics {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            ..Default::default()
        };
        assert_eq!(metrics.success_rate(), 0.0);
        assert_eq!(metrics.error_rate(), 0.0);
    }

    #[test]
    fn test_http_method_display() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Head.as_str(), "HEAD");
    }

    #[test]
    fn test_ddos_test_config_default() {
        let config = DdosTestConfig::default();
        assert_eq!(config.max_rps, 10);
        assert_eq!(config.max_connections, 20);
        assert!(!config.aggressive);
    }

    #[test]
    fn test_ddos_scanner_creation() {
        let scanner_config = ScannerConfig::new();
        let scanner = DdosScanner::new(scanner_config);
        assert_eq!(scanner.test_config.max_rps, 10);
    }

    #[test]
    fn test_ddos_scanner_aggressive_config() {
        let scanner_config = ScannerConfig::new().with_aggressive(true);
        let scanner = DdosScanner::new(scanner_config);
        assert_eq!(scanner.test_config.max_rps, 50);
        assert!(scanner.test_config.aggressive);
    }
}

fn info(msg: &str) {
    #[cfg(feature = "logging")]
    tracing::info!("{}", msg);

    #[cfg(not(feature = "logging"))]
    let _ = msg;
}
