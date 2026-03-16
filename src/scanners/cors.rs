//! CORS Misconfiguration scanner
//!
//! Detects CORS security issues including:
//! - Arbitrary origin reflection
//! - Null origin bypass
//! - AC-Allow-Origin: * with credentials
//! - Subdomain bypass techniques

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::header::{HeaderMap, ORIGIN};
use reqwest::Client;
use std::time::Duration;

#[derive(Debug)]
#[allow(dead_code)]
struct CorsTest {
    origin: &'static str,
    description: &'static str,
    severity: VulnSeverity,
}

#[derive(Debug)]
#[allow(dead_code)]
struct CorsHeaders {
    allow_origin: Option<String>,
    allow_credentials: bool,
    allow_methods: Option<String>,
    allow_headers: Option<String>,
    expose_headers: Option<String>,
    max_age: Option<String>,
    allow_private_network: bool,
}

pub struct CorsScanner {
    client: Client,
    config: ScannerConfig,
}

impl CorsScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
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

        // Always perform basic CORS checks
        report.merge(self.check_arbitrary_origin(url).await?);
        report.merge(self.check_null_origin(url).await?);

        // Aggressive mode: advanced bypass techniques
        if self.config.aggressive {
            report.merge(self.check_subdomain_bypass(url).await?);
            report.merge(self.check_origin_reflection(url).await?);
            report.merge(self.check_regex_bypass(url).await?);
            report.merge(self.check_post_message_bypass(url).await?);
            report.merge(self.check_cors_header_consistency(url).await?);
        }

        Ok(report)
    }

    /// Parse CORS headers from response
    fn parse_cors_headers(&self, headers: &HeaderMap) -> CorsHeaders {
        CorsHeaders {
            allow_origin: headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            allow_credentials: headers
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            allow_methods: headers
                .get("access-control-allow-methods")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            allow_headers: headers
                .get("access-control-allow-headers")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            expose_headers: headers
                .get("access-control-expose-headers")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            max_age: headers
                .get("access-control-max-age")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            allow_private_network: headers
                .get("access-control-allow-private-network")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }

    /// Check for arbitrary origin reflection (CRITICAL when credentials enabled)
    async fn check_arbitrary_origin(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let evil_origins = &[
            ("https://evil.com", "Standard evil domain"),
            ("https://attacker.com", "Attacker controlled domain"),
            ("https://malicious.evil.com", "Subdomain evil domain"),
            ("http://evil.com", "HTTP evil domain"),
            ("https://evil.com:443", "Evil domain with port"),
            ("https://evil.evil.com", "Multi-level subdomain"),
        ];

        for (origin, desc) in evil_origins {
            if let Ok(response) = self
                .client
                .get(url)
                .header(ORIGIN, *origin)
                .send()
                .await
            {
                let cors = self.parse_cors_headers(response.headers());

                // Check if origin is reflected
                if let Some(reflected) = &cors.allow_origin {
                    if reflected == origin || reflected == "*" {
                        // CRITICAL: Credentials enabled with reflected origin
                        if cors.allow_credentials {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: "CORS Misconfiguration: Arbitrary Origin with Credentials".to_string(),
                                description: format!(
                                    "The application reflects '{}' in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. \
                                    This allows any origin to access sensitive data including cookies and authentication tokens.",
                                    origin
                                ),
                                location: Some(format!("{} with Origin: {}", url, origin)),
                                recommendation: Some(
                                        "Never combine Access-Control-Allow-Origin: * (or reflected origin) with \
                                        Access-Control-Allow-Credentials: true. Use a whitelist of trusted origins only.".to_string()
                                    ),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        } else if reflected == "*" {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "CORS Misconfiguration: Wildcard Origin".to_string(),
                                description: format!(
                                    "The application sets Access-Control-Allow-Origin: *. This allows any website to make requests and read responses.",
                                ),
                                location: Some(format!("{} with Origin: {}", url, origin)),
                                recommendation: Some("Replace wildcard with a whitelist of trusted origins. If credentials are needed, never use wildcard.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        } else {
                            // Origin reflected without wildcard
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("CORS Misconfiguration: Origin Reflection ({})", desc),
                                description: format!(
                                    "The application reflects the Origin header without validation. '{}' is returned as-is in Access-Control-Allow-Origin.",
                                    origin
                                ),
                                location: Some(format!("{} with Origin: {}", url, origin)),
                                recommendation: Some("Implement strict origin validation. Only accept origins from a predefined whitelist. Regex validation is insufficient.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for null origin bypass (common in local file redirects)
    async fn check_null_origin(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let null_origins = &["null", "Null", "NULL"];

        for origin in null_origins {
            if let Ok(response) = self
                .client
                .get(url)
                .header(ORIGIN, *origin)
                .send()
                .await
            {
                let cors = self.parse_cors_headers(response.headers());

                if let Some(reflected) = &cors.allow_origin {
                    if reflected == "null" || reflected.to_lowercase().contains("null") {
                        if cors.allow_credentials {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: "CORS Misconfiguration: Null Origin with Credentials".to_string(),
                                description: format!(
                                    "The application accepts 'null' origin with Access-Control-Allow-Credentials: true. \
                                    This can be exploited via redirects or local files to access sensitive data."
                                ),
                                location: Some(format!("{} with Origin: null", url)),
                                recommendation: Some("Explicitly reject 'null' origin. Do not allow credentials for null origin. Validate that origin starts with http:// or https://.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        } else {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "CORS Misconfiguration: Null Origin Accepted".to_string(),
                                description: "The application accepts 'null' origin. This can be exploited via redirect chains or local HTML files.".to_string(),
                                location: Some(format!("{} with Origin: null", url)),
                                recommendation: Some("Reject 'null' origin explicitly. Only allow http:// and https:// origins from trusted domains.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for subdomain bypass techniques
    async fn check_subdomain_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Extract domain from URL for subdomain tests
        let base_domain = url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("example.com");

        let bypass_tests = &[
            (format!("https://evil.{base_domain}"), "Subdomain takeover"),
            (format!("https://{}.evil.com", base_domain.replace("www.", "")), "Suffix bypass"),
            (format!("https://{base_domain}.evil.com"), "Append bypass"),
            (format!("https://evil{}.com", base_domain.replace('.', "")), "Partial match"),
            (format!("https://{base_domain}evil.com"), "No separator bypass"),
            (format!("https://ev{base_domain}il.com"), "Injection bypass"),
        ];

        for (origin, desc) in bypass_tests {
            if let Ok(response) = self
                .client
                .get(url)
                .header(ORIGIN, origin.as_str())
                .send()
                .await
            {
                let cors = self.parse_cors_headers(response.headers());

                if let Some(reflected) = &cors.allow_origin {
                    if reflected.contains("evil") || reflected == origin {
                        if cors.allow_credentials {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("CORS Bypass: Subdomain ({})", desc),
                                description: format!(
                                    "The application's origin validation can be bypassed using '{}'. This may allow subdomain takeover attacks.",
                                    origin
                                ),
                                location: Some(format!("{} with Origin: {}", url, origin)),
                                recommendation: Some("Use exact domain matching, not substring matching. Validate the entire origin including protocol and port. Consider using a list of allowed full origins.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for origin reflection patterns and timing attacks
    async fn check_origin_reflection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let reflection_tests = &[
            ("https://a.b.c.d.e.f.com", "Deep subdomain"),
            ("https://[::1]", "IPv6 localhost"),
            ("https://0x7f.0.0.1", "Hex encoded IP"),
            ("https://0177.0.0.1", "Octal encoded IP"),
            ("https://2130706433", "Decimal IP"),
            ("https://127.0.1", "Partial IP"),
        ];

        for (origin, desc) in reflection_tests {
            if let Ok(response) = self
                .client
                .get(url)
                .header(ORIGIN, *origin)
                .send()
                .await
            {
                let cors = self.parse_cors_headers(response.headers());

                if let Some(reflected) = &cors.allow_origin {
                    if reflected == origin {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("CORS Reflection: {}", desc),
                            description: format!(
                                "Origin header is reflected without proper validation: '{}'",
                                origin
                            ),
                            location: Some(format!("{} with Origin: {}", url, origin)),
                            recommendation: Some("Parse and validate origins properly using URL parsing libraries. Reject non-standard origin formats.".to_string()),
                            cwe: Some("CWE-942".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for regex bypass in origin validation
    async fn check_regex_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Regex bypass payloads
        let regex_bypasses = &[
            ("https://evil.com@example.com", "Credential bypass"),
            ("https://evil.com@www.example.com", "Credential subdomain"),
            ("https://example.com.evil.com", "Domain confusion"),
            ("https://example-com.evil.com", "Hyphen bypass"),
            ("https://example.com@evil.com", "Reverse credential"),
            ("https://example.evil.com", "Partial match"),
        ];

        for (origin, desc) in regex_bypasses {
            if let Ok(response) = self
                .client
                .get(url)
                .header(ORIGIN, *origin)
                .send()
                .await
            {
                let cors = self.parse_cors_headers(response.headers());

                if let Some(reflected) = &cors.allow_origin {
                    if reflected.contains("evil") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("CORS Bypass: Regex ({})", desc),
                            description: format!(
                                "Origin validation can be bypassed using regex evasion: '{}'",
                                origin
                            ),
                            location: Some(format!("{} with Origin: {}", url, origin)),
                            recommendation: Some("Don't use regex for origin validation. Use exact string comparison against a whitelist. Parse origins with proper URL parsers.".to_string()),
                            cwe: Some("CWE-942".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for postMessage-based CORS bypass
    async fn check_post_message_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        if let Ok(response) = self.client.get(url).send().await {
            if let Ok(text) = response.text().await {
                let text_lower = text.to_lowercase();

                // Check for dangerous postMessage patterns
                let dangerous_patterns = &[
                    "postmessage",
                    "window.postmessage",
                    "window.parent",
                    "window.top",
                    "frames[0]",
                    "addeventlistener('message'",
                    "onmessage",
                ];

                for pattern in dangerous_patterns {
                    if text_lower.contains(pattern) {
                        // Check if origin validation is present
                        let has_origin_check = text_lower.contains("origin")
                            || text_lower.contains("event.origin")
                            || text_lower.contains("messageevent");

                        if !has_origin_check || text_lower.contains("'*'") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "CORS/PostMessage Misconfiguration".to_string(),
                                description: format!(
                                    "The application uses postMessage {} proper origin validation. This could lead to data leakage via postMessage bypass.",
                                    if !has_origin_check { "without" } else { "with weak" }
                                ),
                                location: Some(url.to_string()),
                                recommendation: Some("Always validate event.origin in postMessage handlers. Use exact origin matching, not indexOf or regex. Never use '*' as origin.".to_string()),
                                cwe: Some("CWE-942".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for CORS header consistency issues
    async fn check_cors_header_consistency(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test preflight vs simple request
        let test_origin = "https://test.example.com";

        // Simple request
        let simple_headers = if let Ok(response) = self
            .client
            .get(url)
            .header(ORIGIN, test_origin)
            .send()
            .await
        {
            self.parse_cors_headers(response.headers())
        } else {
            CorsHeaders {
                allow_origin: None,
                allow_credentials: false,
                allow_methods: None,
                allow_headers: None,
                expose_headers: None,
                max_age: None,
                allow_private_network: false,
            }
        };

        // Preflight request
        let preflight_headers = if let Ok(response) = self
            .client
            .request(
                reqwest::Method::OPTIONS,
                url,
            )
            .header(ORIGIN, test_origin)
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await
        {
            self.parse_cors_headers(response.headers())
        } else {
            CorsHeaders {
                allow_origin: None,
                allow_credentials: false,
                allow_methods: None,
                allow_headers: None,
                expose_headers: None,
                max_age: None,
                allow_private_network: false,
            }
        };

        // Check for inconsistencies
        if simple_headers.allow_origin.is_some() && preflight_headers.allow_origin.is_none() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "CORS Inconsistency: Preflight Missing".to_string(),
                description: "CORS headers present in simple requests but missing in preflight responses. May cause unexpected behavior.".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Ensure CORS headers are consistent between simple and preflight requests. Handle OPTIONS requests properly.".to_string()),
                cwe: Some("CWE-942".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check AC-Allow-Credentials without AC-Allow-Origin
        if simple_headers.allow_credentials && simple_headers.allow_origin.is_none() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "CORS Misconfiguration: Credentials without Origin".to_string(),
                description: "Access-Control-Allow-Credentials is set but no Access-Control-Allow-Origin header found.".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Ensure Access-Control-Allow-Origin is set when using credentials. CORS headers should be complete and consistent.".to_string()),
                cwe: Some("CWE-942".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check for AC-Allow-Private-Network
        if preflight_headers.allow_private_network {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "CORS: Private Network Access Enabled".to_string(),
                description: "Access-Control-Allow-Private-Network header detected. This allows public websites to access local network resources.".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Disable private network access unless absolutely required. Implement strict origin validation for private network requests.".to_string()),
                cwe: Some("CWE-942".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for overly permissive methods
        if let Some(methods) = &preflight_headers.allow_methods {
            let methods_lower = methods.to_lowercase();
            if methods_lower.contains("*") || methods_lower.contains("delete,put,patch") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "CORS: Overly Permissive Methods".to_string(),
                    description: format!("Access-Control-Allow-Methods allows dangerous methods: {}", methods),
                    location: Some(url.to_string()),
                    recommendation: Some("Limit allowed methods to only those necessary (typically GET, POST, HEAD). Avoid wildcard methods.".to_string()),
                    cwe: Some("CWE-942".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
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
        let scanner = CorsScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_cors_headers_parsing() {
        let config = ScannerConfig::new();
        let scanner = CorsScanner::new(config);

        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", HeaderValue::from_static("https://example.com"));
        headers.insert("access-control-allow-credentials", HeaderValue::from_static("true"));

        let cors = scanner.parse_cors_headers(&headers);

        assert_eq!(cors.allow_origin, Some("https://example.com".to_string()));
        assert!(cors.allow_credentials);
    }
}
