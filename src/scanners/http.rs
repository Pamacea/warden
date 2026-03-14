//! HTTP-based vulnerability scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

pub struct HttpScanner {
    client: Client,
    config: ScannerConfig,
}

impl HttpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Security headers check
        report.merge(self.check_security_headers(url).await?);

        // XSS check (if aggressive)
        if self.config.aggressive {
            report.merge(self.check_xss(url).await?);
        }

        Ok(report)
    }

    async fn check_security_headers(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        match self.client.head(url).send().await {
            Ok(response) => {
                let headers = response.headers();

                // Check for important security headers
                let required_headers = vec![
                    ("X-Frame-Options", "Clickjacking protection", "CWE-1021"),
                    ("X-Content-Type-Options", "MIME-sniffing protection", "CWE-1021"),
                    ("Strict-Transport-Security", "HTTPS enforcement", "CWE-523"),
                    ("Content-Security-Policy", "XSS and injection protection", "CWE-1021"),
                    ("X-XSS-Protection", "XSS filter", "CWE-79"),
                    ("Referrer-Policy", "Referrer information leakage", "CWE-359"),
                ];

                for (header, description, cwe) in required_headers {
                    if headers.get(header).is_none() {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Missing security header: {}", header),
                            description: format!("{} header is not set", description),
                            location: Some(url.to_string()),
                            recommendation: Some(format!("Add the {} header to your responses", header)),
                            cwe: Some(cwe.to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
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

    async fn check_xss(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Simple XSS payload test
        let payloads = vec![
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"'><script>alert(String.fromCharCode(88,83,83))</script>",
        ];

        let base_url = if url.contains('?') {
            url.to_string()
        } else {
            format!("{}/", url.trim_end_matches('/'))
        };

        for payload in payloads {
            let test_url = if base_url.contains('?') {
                format!("{}&xss={}", base_url, urlencoding::encode(payload))
            } else {
                format!("{}?xss={}", base_url, urlencoding::encode(payload))
            };

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    if let Ok(text) = response.text().await {
                        if text.contains(payload) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: "Potential XSS vulnerability".to_string(),
                                description: "Reflected XSS detected in query parameter".to_string(),
                                location: Some(test_url),
                                recommendation: Some("Sanitize and escape user input in responses".to_string()),
                                cwe: Some("CWE-79".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }
}
