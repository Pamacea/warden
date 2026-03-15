//! Open Redirect vulnerability scanner
//!
//! Detects open redirect vulnerabilities through various redirect parameters
//! and payloads. Uses comprehensive payload wordlist.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Comprehensive redirect payloads from wordlist
const REDIRECT_PAYLOADS: &[(&str, &str)] = &[
    // (payload, technique)
    // Basic external URLs
    ("https://evil.com", "basic_https"),
    ("http://evil.com", "basic_http"),
    ("https://evil.com/path", "with_path"),
    ("https://evil.com/path?query=1", "with_query"),
    ("//evil.com", "protocol_relative"),
    ("//evil.com/path", "protocol_relative_path"),
    ("///evil.com", "triple_slash"),
    ("\\\\evil.com", "double_backslash"),
    ("\\evil.com", "single_backslash"),

    // URL encoding variations
    ("%2f%2fevil.com", "url_encoded_slashes"),
    ("%252f%252fevil.com", "double_url_encoded"),
    ("%2F%2Fevil.com", "uppercase_encoded"),
    ("%5c%5cevil.com", "backslash_encoded"),
    ("%255c%255cevil.com", "double_backslash_encoded"),

    // Unicode and special characters
    ("€evil.com", "euro_bypass"),
    ("%E2%82%ACevil.com", "euro_encoded"),
    ("http://%00evil.com", "null_byte_http"),
    ("https://evil.com%00.example.com", "null_byte_injection"),

    // Subdomain bypass attempts
    ("https://example.com@evil.com", "credential_at"),
    ("https://example.com:password@evil.com", "credential_full"),
    ("//evil.com@example.com", "subdomain_confusion"),
    ("https://evil.com@example.com", "https_subdomain_confusion"),

    // Fragment-based redirects
    ("https://example.com#//evil.com", "fragment_bypass"),
    ("#//evil.com", "fragment_only"),
    ("#https://evil.com", "fragment_protocol"),

    // Data and javascript URLs
    ("data:text/html,<script>alert(1)</script>", "data_url"),
    ("javascript:alert(1)", "javascript_url"),
    ("vbscript:alert(1)", "vbscript_url"),

    // Casing and variations
    ("HTTPS://evil.com", "uppercase"),
    ("HtTpS://eViL.cOm", "mixed_case"),
    ("hTTps://evil.com", "partial_case"),

    // Common redirect parameters
    ("https://evil.com@", "trailing_at"),
    ("https://evil.com\\@example.com", "escaped_at"),

    // Dot variations
    ("https://.evil.com", "leading_dot"),
    ("https://evil.com.", "trailing_dot"),
    ("https://..evil.com", "double_dot"),
    ("https://evil..com", "double_dot_com"),

    // Whitespace variations
    (" https://evil.com", "leading_space"),
    ("https://evil.com ", "trailing_space"),
    ("https://evil.com%20", "space_encoded"),
    ("https://evil.com%09", "tab_encoded"),

    // Common TLD variations
    ("https://evil.com.evil.com", "double_tld"),
    ("https://evil.com/", "trailing_slash"),
    ("https://evil.com//", "double_trailing"),

    // Additional bypass techniques
    ("/\\/evil.com", "mixed_slashes"),
    ("//evil.com%00.example.com", "null_subdomain"),
    ("https://example.com.evil.com", "fake_subdomain"),
    ("https://example.com//evil.com", "double_slash_bypass"),
];

/// Common redirect parameter names
const REDIRECT_PARAMS: &[&str] = &[
    "redirect", "url", "next", "goto", "return", "target", "destination", "uri",
    "path", "continue", "route", "forward", "link", "referrer", "redirect_uri",
    "redirect_url", "return_to", "returnurl", "checkout_url", "success_url",
    "cancel_url", "callback", "callback_url", "action", "action_url", "link_uri",
    "next_url", "redir", "redirect_to", "redirecturl", "rurl", "location",
    "goto_url", "back", "go", "return_path", "view", "logout", "log_out",
    "signout", "sign_out", "exit", "quit", "send", "sendto", "to", "out",
    "u", "return_url", "ctoken", "dest", "destination_url", "redirect_target",
    "user_return", "user_return_to", "referer", "referer_url", "ref", "reference",
    "origin", "o", "redirect_uri_error", "_next", "origin_url", "bounce",
    "bounce_url", "redirect_after", "url_redirect", "redirect_final", "forward_url",
    "follow", "follow_url", "jump", "jump_url", "target_url", "target_uri",
];

pub struct OpenRedirectScanner {
    client: Client,
    config: ScannerConfig,
}

impl OpenRedirectScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test all payloads from wordlist
        for (payload, technique) in REDIRECT_PAYLOADS {
            if self.config.aggressive || technique.contains("basic") || technique.contains("protocol") {
                report.merge(self.test_redirect_payload(url, payload, technique).await?);
            }
        }

        // Additional checks in aggressive mode
        if self.config.aggressive {
            report.merge(self.check_header_injection(url).await?);
            report.merge(self.check_parameter_pollution(url).await?);
        }

        Ok(report)
    }

    /// Test a single payload against all common parameters
    async fn test_redirect_payload(&self, base_url: &str, payload: &str, technique: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test with GET requests
        for param in REDIRECT_PARAMS {
            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if self.check_redirect_indicators(response, payload).await {
                    let severity = self.determine_severity(technique, payload);

                    report.add_finding(Vuln {
                        severity,
                        title: format!("Open Redirect: {}", technique),
                        description: format!(
                            "Open redirect vulnerability in parameter '{}'. Successfully redirects to external URL using '{}' technique.",
                            param, technique
                        ),
                        location: Some(test_url),
                        recommendation: Some("Use a whitelist of allowed redirect URLs. Do not accept user-supplied redirect URLs. Use indirect references (tokens/IDs) instead of direct URLs.".to_string()),
                        cwe: Some("CWE-601".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });

                    // Don't report the same vulnerability multiple times
                    break;
                }
            }
        }

        // Test with POST requests for form-based redirects
        for param in REDIRECT_PARAMS.iter().take(5) {
            let form_data = &[(param, payload)];

            if let Ok(response) = self.client.post(base_url).form(form_data).send().await {
                if self.check_redirect_indicators(response, payload).await {
                    let severity = self.determine_severity(technique, payload);

                    report.add_finding(Vuln {
                        severity,
                        title: format!("Open Redirect (POST): {}", technique),
                        description: format!(
                            "Open redirect vulnerability via POST parameter '{}'. Successfully redirects using '{}' technique.",
                            param, technique
                        ),
                        location: Some(format!("{} POST: {}={}", base_url, param, payload)),
                        recommendation: Some("Use a whitelist of allowed redirect URLs. Do not accept user-supplied redirect URLs in POST forms.".to_string()),
                        cwe: Some("CWE-601".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check if response indicates successful open redirect
    async fn check_redirect_indicators(&self, response: reqwest::Response, payload: &str) -> bool {
        let status = response.status();

        // Check for redirect status codes
        if status.is_redirection() {
            if let Some(location) = response.headers().get("Location")
                .and_then(|v| v.to_str().ok())
            {
                let location_lower = location.to_lowercase();

                // Check if Location header contains evil.com or our payload
                if location_lower.contains("evil.com") {
                    return true;
                }

                // Check for protocol-relative URLs in Location
                if location_lower.starts_with("//") {
                    return true;
                }

                // Check if Location exactly matches our payload (decoded)
                if location_lower.contains(&payload.to_lowercase().replace("%2f", "/").replace("%5c", "\\")) {
                    return true;
                }
            }
        }

        // Check response body for redirect indicators
        if let Ok(text) = response.text().await {
            let text_lower = text.to_lowercase();

            // Check for evil.com in response
            if text_lower.contains("evil.com") {
                return true;
            }

            // Check for redirect-related messages
            if text_lower.contains("redirecting") || text_lower.contains("you will be redirected") {
                if text_lower.contains("evil.com") {
                    return true;
                }
            }

            // Check for meta refresh redirects
            if text_lower.contains("http-equiv=\"refresh\"") || text_lower.contains("content=\"0;url=") {
                if text_lower.contains("evil.com") {
                    return true;
                }
            }

            // Check for JavaScript redirects
            if text_lower.contains("location.href") || text_lower.contains("window.location") {
                if text_lower.contains("evil.com") {
                    return true;
                }
            }
        }

        false
    }

    /// Determine severity based on technique
    fn determine_severity(&self, technique: &str, _payload: &str) -> VulnSeverity {
        // Critical: Credential harvesting, XSS via redirect
        if technique.contains("javascript") || technique.contains("data") {
            return VulnSeverity::Critical;
        }

        // Critical: Subdomain confusion, credential bypass
        if technique.contains("credential") || technique.contains("subdomain") {
            return VulnSeverity::High;
        }

        // High: Protocol-relative, encoding bypasses
        if technique.contains("protocol_relative") || technique.contains("encoded") {
            return VulnSeverity::High;
        }

        // High: Backslash variations (Windows bypass)
        if technique.contains("backslash") {
            return VulnSeverity::High;
        }

        // Medium: Basic redirects
        if technique.contains("basic") {
            return VulnSeverity::Medium;
        }

        VulnSeverity::Medium
    }

    /// Check for header-based redirect injection
    async fn check_header_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test CRLF injection in URL parameter
        let crlf_payloads = &[
            ("?url=%0d%0alocation:%20https://evil.com", "crlf_location"),
            ("?redirect=%0d%0aSet-Cookie:%20test=evil", "crlf_cookie"),
            ("?next=%0d%0aRefresh:%200;url=https://evil.com", "crlf_refresh"),
        ];

        for (payload, desc) in crlf_payloads {
            let test_url = format!("{}{}", base_url.trim_end_matches('/'), payload);

            if let Ok(response) = self.client.get(&test_url).send().await {
                let headers = response.headers();

                // Check for injected headers
                if headers.get("Location").is_some()
                    || headers.get("Set-Cookie").is_some()
                    || headers.get("Refresh").is_some()
                {
                    let location = headers.get("Location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if location.contains("evil.com") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("Header Injection: {}", desc),
                            description: format!(
                                "CRLF injection allows adding arbitrary HTTP headers. Injected header contains 'evil.com'.",
                            ),
                            location: Some(test_url),
                            recommendation: Some("Sanitize all user input before using in HTTP headers. Reject input containing CRLF characters (%0d%0a).".to_string()),
                            cwe: Some("CWE-93".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for parameter pollution bypass
    async fn check_parameter_pollution(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test with duplicate parameters
        let pollution_tests = &[
            ("?redirect=/safe&redirect=https://evil.com", "basic_pollution"),
            ("?url=/home&url=//evil.com", "protocol_pollution"),
            ("?next=/dashboard&next=http://evil.com", "http_pollution"),
        ];

        for (payload, desc) in pollution_tests {
            let test_url = if base_url.contains('?') {
                format!("{}&{}", base_url.trim_end_matches('&'), &payload[1..])
            } else {
                format!("{}{}", base_url.trim_end_matches('/'), payload)
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();
                    if text_lower.contains("evil.com") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Open Redirect: Parameter Pollution ({})", desc),
                            description: "Parameter pollution allows bypassing validation. The first or last parameter takes precedence.".to_string(),
                            location: Some(test_url),
                            recommendation: Some("Handle duplicate parameters properly. Use only the first or last value consistently. Validate all values.".to_string()),
                            cwe: Some("CWE-601".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = OpenRedirectScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_payloads_loaded() {
        assert!(!REDIRECT_PAYLOADS.is_empty());
        assert!(REDIRECT_PAYLOADS.len() > 30);
    }

    #[test]
    fn test_params_loaded() {
        assert!(!REDIRECT_PARAMS.is_empty());
        assert!(REDIRECT_PARAMS.contains(&"redirect"));
        assert!(REDIRECT_PARAMS.contains(&"url"));
        assert!(REDIRECT_PARAMS.contains(&"next"));
    }

    #[test]
    fn test_severity_determination() {
        let config = ScannerConfig::new();
        let scanner = OpenRedirectScanner::new(config);

        // Critical techniques
        assert_eq!(scanner.determine_severity("javascript_url", "javascript:alert(1)"), VulnSeverity::Critical);
        assert_eq!(scanner.determine_severity("data_url", "data:text/html,<script>"), VulnSeverity::Critical);

        // High techniques
        assert_eq!(scanner.determine_severity("protocol_relative", "//evil.com"), VulnSeverity::High);
        assert_eq!(scanner.determine_severity("credential_at", "https://example.com@evil.com"), VulnSeverity::High);

        // Medium techniques
        assert_eq!(scanner.determine_severity("basic_https", "https://evil.com"), VulnSeverity::Medium);
    }
}
