//! User Enumeration vulnerability scanner
//!
//! Detects user enumeration vulnerabilities through timing analysis,
//! response diffing, and behavioral patterns at authentication endpoints.
//! Uses comprehensive username wordlist.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::{Duration, Instant};

/// Common usernames for enumeration testing from wordlist
const ENUM_USERNAMES: &[&str] = &[
    // Common admin usernames
    "admin", "administrator", "root", "superadmin", "sysadmin",
    // Common service accounts
    "test", "user", "guest", "demo", "api", "service", "bot", "system",
    // Likely existing
    "webmaster", "support", "info", "contact", "admin1", "admin123",
    // Likely NOT existing
    "nonexistent_xyz_123", "fake_user_999_abc", "invalid_qwerty_999",
];

/// Login endpoints to test
const LOGIN_ENDPOINTS: &[&str] = &[
    "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
    "/account/login", "/user/login", "/sessions", "/auth/signin",
];

/// Login parameter names to test
const LOGIN_PARAMS: &[&str] = &[
    "username", "user", "email", "login", "id", "name", "uid",
];

pub struct EnumerationScanner {
    client: Client,
    config: ScannerConfig,
}

impl EnumerationScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(20);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Always perform basic enumeration checks
        report.merge(self.check_login_enumeration(url).await?);
        report.merge(self.check_registration_enumeration(url).await?);

        // Aggressive mode: advanced timing and response analysis
        if self.config.aggressive {
            report.merge(self.check_timing_analysis(url).await?);
            report.merge(self.check_user_profile_enumeration(url).await?);
        }

        Ok(report)
    }

    /// Check for user enumeration at login endpoints
    async fn check_login_enumeration(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for endpoint in LOGIN_ENDPOINTS {
            let login_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            // Test if endpoint exists
            if !self.endpoint_exists(&login_url).await {
                continue;
            }

            // Collect signatures for each username
            let mut signatures: Vec<(String, LoginSignature)> = Vec::new();

            for username in ENUM_USERNAMES.iter() {
                if let Some(sig) = self.test_login_endpoint(&login_url, username).await {
                    signatures.push((username.to_string(), sig));
                }
            }

            // Analyze signatures for enumeration
            let vulnerabilities = self.analyze_login_signatures(&signatures, &login_url);

            for vuln in vulnerabilities {
                report.add_finding(vuln);
            }

            // Don't test multiple endpoints if one found vulnerabilities
            if !report.findings.is_empty() && !self.config.aggressive {
                break;
            }
        }

        Ok(report)
    }

    /// Test a login endpoint with a username
    async fn test_login_endpoint(&self, url: &str, username: &str) -> Option<LoginSignature> {
        // Try POST request first
        for param in LOGIN_PARAMS.iter() {
            let param_str: &str = *param;
            let form_data: [(&str, &str); 2] = [
                (param_str, username),
                ("password", "Test123!@#"),
            ];

            if let Ok(response) = self.client.post(url).form(&form_data).send().await {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                return Some(self.extract_login_signature(&text, status.as_u16()));
            }
        }

        // Try GET request
        for param in LOGIN_PARAMS.iter() {
            let param_str: &str = *param;
            let test_url = format!("{}?{}={}&password=Test123", url, param_str, username);

            if let Ok(response) = self.client.get(&test_url).send().await {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                return Some(self.extract_login_signature(&text, status.as_u16()));
            }
        }

        None
    }

    /// Extract signature from login response
    fn extract_login_signature(&self, text: &str, status: u16) -> LoginSignature {
        let text_lower = text.to_lowercase();

        let keywords: Vec<String> = vec![
            if text_lower.contains("invalid") || text_lower.contains("not found") {
                "invalid".to_string()
            } else {
                String::new()
            },
            if text_lower.contains("incorrect") || text_lower.contains("wrong") {
                "incorrect".to_string()
            } else {
                String::new()
            },
            if text_lower.contains("does not exist") || text_lower.contains("doesn't exist") {
                "not_exist".to_string()
            } else {
                String::new()
            },
            if text_lower.contains("no user") || text_lower.contains("user not") {
                "no_user".to_string()
            } else {
                String::new()
            },
            if text_lower.contains("account") {
                "account".to_string()
            } else {
                String::new()
            },
            if text_lower.contains("success") || text_lower.contains("welcome") {
                "success".to_string()
            } else {
                String::new()
            },
        ].into_iter().filter(|s| !s.is_empty()).collect();

        LoginSignature {
            status_code: status,
            content_length: text.len(),
            keywords,
            contains_error: text_lower.contains("error") || text_lower.contains("invalid"),
            contains_success: text_lower.contains("success") || text_lower.contains("welcome"),
        }
    }

    /// Analyze login signatures for enumeration vulnerabilities
    fn analyze_login_signatures(&self, signatures: &[(String, LoginSignature)], url: &str) -> Vec<Vuln> {
        let mut vulnerabilities = Vec::new();

        if signatures.is_empty() {
            return vulnerabilities;
        }

        // Check for status code differences
        let status_codes: Vec<u16> = signatures.iter().map(|(_, s)| s.status_code).collect();
        let unique_statuses: std::collections::HashSet<u16> = status_codes.iter().cloned().collect();

        if unique_statuses.len() > 1 {
            vulnerabilities.push(Vuln {
                severity: VulnSeverity::High,
                title: "User Enumeration via Status Code".to_string(),
                description: format!(
                    "Different HTTP status codes returned for valid vs invalid usernames at {}. This allows username enumeration.",
                    url
                ),
                location: Some(url.to_string()),
                recommendation: Some("Return the same status code for both valid and invalid usernames. Use generic error messages.".to_string()),
                cwe: Some("CWE-204".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for response length differences
        let lengths: Vec<usize> = signatures.iter().map(|(_, s)| s.content_length).collect();
        if !lengths.is_empty() {
            let min_len = *lengths.iter().min()
                .expect("lengths is non-empty, min() should return Some");
            let max_len = *lengths.iter().max()
                .expect("lengths is non-empty, max() should return Some");

            if max_len.saturating_sub(min_len) > 100 {
                vulnerabilities.push(Vuln {
                    severity: VulnSeverity::High,
                    title: "User Enumeration via Response Length".to_string(),
                    description: format!(
                        "Significant response length differences ({} vs {} bytes) detected at {}. This indicates username enumeration.",
                        min_len, max_len, url
                    ),
                    location: Some(url.to_string()),
                    recommendation: Some("Normalize response lengths for all authentication outcomes. Add random padding to obscure differences.".to_string()),
                    cwe: Some("CWE-204".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        // Check for different error messages
        let mut all_keywords = std::collections::HashSet::new();
        for (_, sig) in signatures {
            for keyword in &sig.keywords {
                all_keywords.insert(keyword.clone());
            }
        }

        if all_keywords.len() > 1 {
            vulnerabilities.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "User Enumeration via Error Messages".to_string(),
                description: format!(
                    "Different error messages returned for authentication attempts at {}. Messages: {:?}",
                    url, all_keywords
                ),
                location: Some(url.to_string()),
                recommendation: Some("Use generic error messages that don't reveal whether a user exists. Example: 'Invalid credentials' for all cases.".to_string()),
                cwe: Some("CWE-209".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        vulnerabilities
    }

    /// Check for user enumeration at registration endpoints
    async fn check_registration_enumeration(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let registration_endpoints = &[
            "/register", "/signup", "/auth/register", "/api/register",
            "/api/auth/register", "/account/register", "/user/register",
        ];

        for endpoint in registration_endpoints {
            let reg_url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

            if !self.endpoint_exists(&reg_url).await {
                continue;
            }

            let reg_url_clone = reg_url.clone();

            for (email, _desc) in [
                ("admin@example.com", "Likely existing"),
                ("test_nonexistent_xyz_999@example.com", "Likely new"),
            ] {
                if let Ok(response) = self
                    .client
                    .post(&reg_url_clone)
                    .form(&[("email", email), ("username", "testuser"), ("password", "Test123!")])
                    .send()
                    .await
                {
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Check for revealing messages
                    if text_lower.contains("already exists")
                        || text_lower.contains("already taken")
                        || text_lower.contains("unavailable")
                        || text_lower.contains("in use")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "User Enumeration via Registration".to_string(),
                            description: format!(
                                "Registration endpoint reveals whether email/username is already registered. Tested with: {}",
                                email
                            ),
                            location: Some(reg_url.clone()),
                            recommendation: Some("Do not reveal if an email is already registered. Send a verification email to both cases with different messaging.".to_string()),
                            cwe: Some("CWE-204".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for timing-based user enumeration
    async fn check_timing_analysis(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let login_url = format!("{}{}", base_url.trim_end_matches('/'), "/login");

        if !self.endpoint_exists(&login_url).await {
            return Ok(report);
        }

        let mut timings: Vec<TimingResult> = Vec::new();

        for username in ENUM_USERNAMES.iter() {
            let start = Instant::now();

            if let Ok(response) = self
                .client
                .post(&login_url)
                .form(&[("username", *username), ("password", "test123")])
                .send()
                .await
            {
                let duration = start.elapsed();
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                let len = text.len();

                timings.push(TimingResult {
                    username: username.to_string(),
                    duration,
                    status_code: status,
                    response_length: len,
                });
            }

            // Small delay to avoid rate limiting
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Analyze timing patterns
        if timings.len() >= 3 {
            let durations: Vec<Duration> = timings.iter().map(|t| t.duration).collect();
            let max_duration = *durations.iter().max()
                .expect("durations is non-empty, max() should return Some");
            let min_duration = *durations.iter().min()
                .expect("durations is non-empty, min() should return Some");

            if max_duration.saturating_sub(min_duration) > Duration::from_millis(200) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "User Enumeration via Timing Analysis".to_string(),
                    description: format!(
                        "Significant timing variations detected in authentication responses ({}ms to {}ms). This may enable timing-based username enumeration.",
                        min_duration.as_millis(),
                        max_duration.as_millis()
                    ),
                    location: Some(login_url),
                    recommendation: Some("Add random delay to all authentication attempts to normalize timing. Use constant-time comparison for sensitive operations.".to_string()),
                    cwe: Some("CWE-208".to_string()),
                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Check for user enumeration at user profile endpoints
    async fn check_user_profile_enumeration(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let profile_patterns = &[
            "/user/", "/users/", "/u/", "/profile/", "/account/", "/api/users/",
            "/api/user/", "/member/", "/api/member/",
        ];

        for prefix in profile_patterns {
            for username in ENUM_USERNAMES.iter() {
                let profile_url = format!("{}{}{}", base_url.trim_end_matches('/'), prefix, username);

                if let Ok(response) = self.client.get(&profile_url).send().await {
                    let status = response.status().as_u16();
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Found a user profile
                    if status == 200 && !text_lower.contains("not found") && !text_lower.contains("404") {
                        let severity = if *username == "admin" || *username == "administrator" {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        };

                        report.add_finding(Vuln {
                            severity,
                            title: "User Enumeration via Profile Endpoint".to_string(),
                            description: format!(
                                "User profile accessible at {}. Username '{}' is confirmed to exist.",
                                profile_url, username
                            ),
                            location: Some(profile_url),
                            recommendation: Some("Consider using UUIDs instead of usernames in URLs. Require authentication for profile access.".to_string()),
                            cwe: Some("CWE-200".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check if endpoint exists (returns non-404 status)
    async fn endpoint_exists(&self, url: &str) -> bool {
        if let Ok(response) = self.client.get(url).send().await {
            response.status().as_u16() != 404
        } else {
            false
        }
    }
}

/// Login response signature for comparison
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LoginSignature {
    status_code: u16,
    content_length: usize,
    keywords: Vec<String>,
    contains_error: bool,
    contains_success: bool,
}

/// Timing result for analysis
#[derive(Debug)]
#[allow(dead_code)]
struct TimingResult {
    username: String,
    duration: Duration,
    status_code: u16,
    response_length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = EnumerationScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_usernames_loaded() {
        assert!(!ENUM_USERNAMES.is_empty());
        assert!(ENUM_USERNAMES.len() >= 10);
    }

    #[test]
    fn test_signature_extraction() {
        let config = ScannerConfig::new();
        let scanner = EnumerationScanner::new(config);

        let sig = scanner.extract_login_signature("Invalid username or password", 401);
        assert!(sig.contains_error);
        assert_eq!(sig.status_code, 401);
    }
}
