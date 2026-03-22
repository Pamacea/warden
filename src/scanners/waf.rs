//! WAF (Web Application Firewall) Detection Scanner
//!
//! Identifies and fingerprints WAF/CDN solutions including Cloudflare, AWS WAF,
//! Akamai, ModSecurity, F5 BIG-IP, Imperva, Fortinet, and others.
//!
//! This scanner performs passive detection only and does NOT attempt bypass techniques.
//! Bypass techniques are documented for informational purposes in recommendations.

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Detected WAF product with metadata
#[derive(Debug, Clone)]
struct WafProduct {
    name: &'static str,
    vendor: &'static str,
    description: &'static str,
    headers: &'static [&'static str],
    body_patterns: &'static [&'static str],
    status_indicators: &'static [u16],
}

/// Known bypass techniques for documentation
#[derive(Debug)]
struct BypassTechnique {
    category: &'static str,
    technique: &'static str,
    description: &'static str,
    examples: &'static [&'static str],
}

/// All documented bypass techniques
const BYPASS_TECHNIQUES: &[BypassTechnique] = &[
    BypassTechnique {
        category: "SQL Injection",
        technique: "Comment-based evasion",
        description: "Use SQL comments to break keywords and confuse WAF signatures",
        examples: &["/*COMMENT*/", "/**/", "/*!00000*/", "%0A", "--", "#"],
    },
    BypassTechnique {
        category: "SQL Injection",
        technique: "Case variation",
        description: "Vary case of SQL keywords (many WAFs are case-sensitive)",
        examples: &["UNION", "union", "UnIoN", "SeLeCt", "sElEcT"],
    },
    BypassTechnique {
        category: "SQL Injection",
        technique: "Encoding variants",
        description: "Use URL encoding, double encoding, or Unicode encoding",
        examples: &["%27", "%2527", "%u0027", "0x27", "&apos;", "%A0%27"],
    },
    BypassTechnique {
        category: "SQL Injection",
        technique: "Whitespace alternatives",
        description: "Replace spaces with alternative whitespace characters",
        examples: &["%09", "%0A", "%0B", "%0C", "%0D", "%A0", "/**/"],
    },
    BypassTechnique {
        category: "SQL Injection",
        technique: "Logical operator alternatives",
        description: "Use alternative logical operators",
        examples: &["&&", "||", "&", "|", "AND", "OR", "XOR", "&&=", "||="],
    },
    BypassTechnique {
        category: "XSS",
        technique: "Unicode/HTML encoding",
        description: "Use Unicode or HTML entity encoding",
        examples: &["&lt;", "&gt;", "&#x3C;", "&#60;", "%u003C", "%u003E"],
    },
    BypassTechnique {
        category: "XSS",
        technique: "JavaScript obfuscation",
        description: "Obfuscate JavaScript payloads",
        examples: &["\\x00", "\\u0000", "String.fromCharCode", "eval", "atob"],
    },
    BypassTechnique {
        category: "XSS",
        technique: "Event handler variations",
        description: "Use alternative event handlers",
        examples: &["onerror", "onload", "onmouseover", "onfocus", "onclick"],
    },
    BypassTechnique {
        category: "XSS",
        technique: "Tag variations",
        description: "Use alternative HTML tags",
        examples: &["<svg>", "<math>", "<iframe>", "<body>", "<details>"],
    },
    BypassTechnique {
        category: "Path Traversal",
        technique: "Unicode encoding",
        description: "Use Unicode characters to bypass path filters",
        examples: &["%c0%af", "%c1%9c", "%e0%80%af", "%f0%80%80%af"],
    },
    BypassTechnique {
        category: "Path Traversal",
        technique: "Double encoding",
        description: "Double-encode the path traversal sequence",
        examples: &["%252e%252e%252f", "%252e%252e%255c", "..%c0%af..", "..%255c"],
    },
    BypassTechnique {
        category: "Path Traversal",
        technique: "Path variations",
        description: "Use alternative path traversal sequences",
        examples: &["....//", "././", "..\\", "%2e%2e%5c", "..%5c"],
    },
    BypassTechnique {
        category: "Headers",
        technique: "X-Forwarded-For spoofing",
        description: "Spoof client IP using X-Forwarded-For header",
        examples: &["X-Forwarded-For: 127.0.0.1", "X-Forwarded-For: ::1", "X-Forwarded-For: localhost"],
    },
    BypassTechnique {
        category: "Headers",
        technique: "X-Original-URL override",
        description: "Override the requested URL path",
        examples: &["X-Original-URL: /admin", "X-Rewrite-URL: /admin"],
    },
    BypassTechnique {
        category: "Headers",
        technique: "Host header injection",
        description: "Manipulate Host header for routing bypass",
        examples: &["Host: evil.com", "Host: localhost@target.com", "Host: target.com.evil.com"],
    },
    BypassTechnique {
        category: "General",
        technique: "Parameter pollution",
        description: "Send multiple parameters with same name",
        examples: &["id=1&id=2", "id[]=1&id[]=2", "id=1&id=UNION SELECT"],
    },
    BypassTechnique {
        category: "General",
        technique: "Method override",
        description: "Override HTTP method using headers",
        examples: &["X-HTTP-Method-Override: PUT", "X-Method-Override: DELETE"],
    },
    BypassTechnique {
        category: "General",
        technique: "Content-Type manipulation",
        description: "Use alternative content types to bypass filters",
        examples: &["application/x-www-form-urlencoded", "multipart/form-data", "text/xml"],
    },
];

/// WAF product signatures
const WAF_SIGNATURES: &[WafProduct] = &[
    WafProduct {
        name: "Cloudflare",
        vendor: "Cloudflare, Inc.",
        description: "Cloud-distributed WAF and CDN service. Known for challenge pages and DDoS protection.",
        headers: &["cf-ray", "cf-request-id", "cf-connecting-ip", "cf-ipcountry", "cf-visitor", "cf-cache-status"],
        body_patterns: &["cloudflare", "cf-challenge", "cf_error", "challenge-platform", "__cf_bm", "cf_clearance"],
        status_indicators: &[403, 503],
    },
    WafProduct {
        name: "AWS WAF",
        vendor: "Amazon Web Services",
        description: "Managed WAF service for AWS. Often paired with ALB/CloudFront.",
        headers: &["x-amzn-request-id", "x-amz-cf-id", "x-amz-cf-pop", "x-amzn-trace-id", "x-cache"],
        body_patterns: &["aws waf", "request blocked", "access denied", "blocked by waf"],
        status_indicators: &[403, 406],
    },
    WafProduct {
        name: "Akamai",
        vendor: "Akamai Technologies",
        description: "Enterprise CDN and WAF solution. Known for high-security environments.",
        headers: &["akamai-origin-hop", "x-akamai-transformed", "akamai-true-cache-key"],
        body_patterns: &["akamai", "akamaighost", "cookie_check", "incident id"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "ModSecurity",
        vendor: "Trustwave / Open Source",
        description: "Open-source WAF engine used by many solutions (OWASP CRS).",
        headers: &["modsecurity", "x-modsecurity-rule", "x-waf-status"],
        body_patterns: &["mod_security", "modsecurity", "not acceptable", "request rejected", "blocked by modsecurity"],
        status_indicators: &[403, 406],
    },
    WafProduct {
        name: "F5 BIG-IP ASM",
        vendor: "F5 Networks",
        description: "Hardware/virtual appliance WAF with advanced traffic inspection.",
        headers: &["x-waf-info", "bigip", "bigipserver", "f5-lw", "x-iinfo", "x-ua-compatible"],
        body_patterns: &["big-ip", "bigip", "asm", "blocked by", "request denied", "traffic protected"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Imperva (Incapsula)",
        vendor: "Imperva / Thales",
        description: "Enterprise WAF with DDoS protection. Known for distinct error pages.",
        headers: &["x-iinfo", "x-cdn", "incap_ses", "incap_ip", "visid_incap"],
        body_patterns: &["incapsula", "imperva", "blocked by incapsula", "incident id"],
        status_indicators: &[403, 503],
    },
    WafProduct {
        name: "Fortinet FortiWeb",
        vendor: "Fortinet",
        description: "Web application firewall from Fortinet security appliance.",
        headers: &["fortigate", "fgd-waf-session", "f5_big_ip"],
        body_patterns: &["fortinet", "fortiweb", "fortigate", "blocked by fortigate"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Barracuda",
        vendor: "Barracuda Networks",
        description: "Security appliance WAF with signature-based detection.",
        headers: &["barra_counter_session", "bni_iitrackid", "bni__iitrackid"],
        body_patterns: &["barracuda", "bni_", "blocked by barracuda", "requested url"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Sucuri (GoDaddy)",
        vendor: "Sucuri / GoDaddy",
        description: "Cloud-based WAF popular for WordPress sites.",
        headers: &["x-sucuri-id", "x-sucuri-cache", "x-sucuri-proxy"],
        body_patterns: &["sucuri", "access denied", "request blocked", "website is protected"],
        status_indicators: &[403, 503],
    },
    WafProduct {
        name: "Fastly (Signal Sciences)",
        vendor: "Fastly",
        description: "Edge cloud platform with WAF capabilities.",
        headers: &["fastly-debug-digest", "fastly-ff", "x-served-by", "x-fastly-request-id"],
        body_patterns: &["fastly", "signal sciences", "blocked by", "request blocked"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Azure Front Door",
        vendor: "Microsoft",
        description: "Microsoft's cloud WAF and CDN service.",
        headers: &["x-azn", "x-azure-ref", "x-arr-affinity", "x-arr-log-id", "x-ms-request-id"],
        body_patterns: &["azure", "front door", "blocked by", "waf"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Google Cloud Armor",
        vendor: "Google Cloud",
        description: "DDoS protection and WAF for GCP load balancers.",
        headers: &["x-cloud-trace-context", "x-gcp-project-id"],
        body_patterns: &["cloud armor", "blocked by", "request blocked", "gcp"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Wordfence",
        vendor: "Defiant / Automattic",
        description: "WordPress plugin-based WAF, very common on WP sites.",
        headers: &[],
        body_patterns: &["wordfence", "blocked by wordfence", "security by wordfence"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Aqqua Trustwave",
        vendor: "Trustwave",
        description: "Managed WAF service from Trustwave.",
        headers: &["x-waf-info", "x-waf-event-id"],
        body_patterns: &["trustwave", "aqqua", "waf blocked"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Radware",
        vendor: "Radware",
        description: "Network security and DDoS protection with WAF.",
        headers: &["x-rw-cinfo", "x-rw-cookies"],
        body_patterns: &["radware", "request blocked", "security policy"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Citrix (NetScaler)",
        vendor: "Citrix Systems",
        description: "ADC/WAF appliance common in enterprise environments.",
        headers: &["ns-iwx", "citrix", "netscaler", "viacache"],
        body_patterns: &["citrix", "netscaler", "adc", "blocked"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "StackPath",
        vendor: "StackPath",
        description: "Edge computing platform with WAF.",
        headers: &["x-stackpath", "x-cache", "x-helix"],
        body_patterns: &["stackpath", "blocked by"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "DDoS-Guard",
        vendor: "DDoS-Guard",
        description: "Russian DDoS protection and WAF service.",
        headers: &["ddos-guard", "x-ddos-guard"],
        body_patterns: &["ddos-guard", "checking your browser", "ddos protection"],
        status_indicators: &[403, 429],
    },
    WafProduct {
        name: "Reblaze",
        vendor: "Reblaze",
        description: "Cloud-based WAF with behavioral analysis.",
        headers: &["x-reblaze", "x-rb-info"],
        body_patterns: &["reblaze", "blocked by reblaze", "request blocked"],
        status_indicators: &[403],
    },
    WafProduct {
        name: "Wallarm",
        vendor: "Wallarm",
        description: "AI-powered WAF with virtual patching.",
        headers: &["nginx-wallarm", "x-wallarm", "wallarm-an"],
        body_patterns: &["wallarm", "blocked by wallarm", "wallarm detected"],
        status_indicators: &[403],
    },
];

pub struct WafScanner {
    client: Client,
    config: ScannerConfig,
}

impl WafScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for WAF scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Always perform passive WAF detection
        report.merge(self.detect_by_headers(url).await?);
        report.merge(self.detect_by_error_page(url).await?);

        // Aggressive mode: test with malicious payloads (non-destructive)
        if self.config.aggressive {
            report.merge(self.test_waf_response(url).await?);
            report.merge(self.detect_by_timing(url).await?);
            report.merge(self.detect_challenge_page(url).await?);
        }

        // Add bypass documentation if WAF detected
        if report.findings.iter().any(|v| v.title.contains("WAF Detected")) {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "WAF Bypass Techniques (Documentation)".to_string(),
                description: self.format_bypass_documentation(),
                location: None,
                recommendation: Some("The bypass techniques listed above are for authorized security testing only. Always obtain proper authorization before testing.".to_string()),
                cwe: Some("CWE-693".to_string()),
                owasp: Some("A00:2021 - Automated Testing Documentation".to_string()),
            });
        }

        Ok(report)
    }

    /// Detect WAF by analyzing response headers
    async fn detect_by_headers(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        if let Ok(response) = self.client.head(url).send().await {
            let headers = response.headers();

            for waf in WAF_SIGNATURES {
                let mut detected_headers = Vec::new();

                for header_name in waf.headers {
                    if let Some(value) = headers.get(*header_name) {
                        detected_headers.push(format!("{}: {:?}", header_name, value));
                    }
                }

                if !detected_headers.is_empty() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: format!("WAF Detected: {} (Header Analysis)", waf.name),
                        description: format!(
                            "{}\n\nDetected headers:\n- {}",
                            waf.description,
                            detected_headers.join("\n- ")
                        ),
                        location: Some(url.to_string()),
                        recommendation: Some(self.get_waf_recommendation(waf)),
                        cwe: Some("CWE-693".to_string()),
                        owasp: None,
                    });
                }
            }

            // Check for generic security headers indicating WAF
            let security_headers = &[
                ("X-WAF-Status", "Generic WAF status header"),
                ("X-Sucuri-ID", "Sucuri WAF"),
                ("X-FireWall-Protection", "Generic firewall protection"),
            ];

            for (header, desc) in security_headers {
                if headers.get(*header).is_some() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: format!("Security Header Detected: {}", header),
                        description: format!("{} header present. {}", header, desc),
                        location: Some(url.to_string()),
                        recommendation: Some("Security headers indicate active protection. Review configuration for proper rule sets.".to_string()),
                        cwe: None,
                        owasp: None,
                    });
                }
            }
        }

        Ok(report)
    }

    /// Detect WAF by analyzing error page content
    async fn detect_by_error_page(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Try accessing a path that might trigger WAF
        let test_paths = &["/admin", "/wp-admin", "/console", "/manager", "/administrator"];

        for path in test_paths {
            let test_url = if url.ends_with('/') {
                format!("{}{}", url.trim_end_matches('/'), path)
            } else {
                format!("{}{}", url, path)
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                let status = response.status().as_u16();

                // Check for WAF-specific status codes
                if status == 403 || status == 406 || status == 503 {
                    if let Ok(text) = response.text().await {
                        let text_lower = text.to_lowercase();

                        for waf in WAF_SIGNATURES {
                            let mut matches = Vec::new();

                            for pattern in waf.body_patterns {
                                if text_lower.contains(&pattern.to_lowercase()) {
                                    matches.push(*pattern);
                                }
                            }

                            if !matches.is_empty() {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Info,
                                    title: format!("WAF Detected: {} (Error Page Analysis)", waf.name),
                                    description: format!(
                                        "{}\n\nStatus: {}\nDetected patterns:\n- {}",
                                        waf.description,
                                        status,
                                        matches.join("\n- ")
                                    ),
                                    location: Some(test_url.clone()),
                                    recommendation: Some(self.get_waf_recommendation(waf)),
                                    cwe: Some("CWE-693".to_string()),
                                    owasp: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test WAF response with benign payloads (non-destructive testing)
    async fn test_waf_response(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Benign tests that won't trigger bans but may reveal WAF behavior
        let benign_tests = &[
            ("?id=<test>", "XSS-like pattern (benign)"),
            ("?id=1' OR '1'='2", "SQLi-like pattern (safe value)"),
            ("?path=../test", "Path traversal pattern (benign)"),
        ];

        for (payload, description) in benign_tests {
            let test_url = format!("{}{}", url.trim_end_matches('/'), payload);

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();

                    // 403 with benign payload often indicates WAF
                    if status == 403 {
                        if let Ok(text) = response.text().await {
                            let text_lower = text.to_lowercase();

                            // Check for WAF-specific messages
                            let waf_detected = text_lower.contains("blocked")
                                || text_lower.contains("waf")
                                || text_lower.contains("security")
                                || text_lower.contains("firewall")
                                || text_lower.contains("mod_security")
                                || text_lower.contains("request rejected")
                                || text_lower.contains("access denied");

                            if waf_detected {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Info,
                                    title: "WAF Behavior Detected".to_string(),
                                    description: format!(
                                        "WAF-like response to benign payload '{}'. Status: {}.\n\nResponse indicates active filtering.",
                                        description, status
                                    ),
                                    location: Some(test_url),
                                    recommendation: Some("WAF is actively filtering requests. Review rules to ensure legitimate traffic is not blocked.".to_string()),
                                    cwe: Some("CWE-693".to_string()),
                                    owasp: None,
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    // Connection errors might indicate rate limiting or blocking
                }
            }

            // Rate limiting: delay between requests
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(report)
    }

    /// Detect WAF through timing analysis (some WAFs add significant delay)
    async fn detect_by_timing(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let start = std::time::Instant::now();
        let _ = self.client.get(url).send().await;
        let normal_time = start.elapsed();

        // Test with parameter that might trigger inspection
        let test_url = format!("{}?id=test&param=value", url.trim_end_matches('/'));
        let start = std::time::Instant::now();
        let _ = self.client.get(&test_url).send().await;
        let inspect_time = start.elapsed();

        // If inspection takes significantly longer, might indicate WAF analysis
        if inspect_time.as_millis() > normal_time.as_millis() + 200 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Possible WAF Detected (Timing Analysis)".to_string(),
                description: format!(
                    "Request with parameters took {}ms vs {}ms for normal request. \
                    This difference may indicate WAF request inspection.",
                    inspect_time.as_millis(),
                    normal_time.as_millis()
                ),
                location: Some(url.to_string()),
                recommendation: Some("Timing analysis suggests request inspection. Further testing needed for confirmation.".to_string()),
                cwe: None,
                owasp: None,
            });
        }

        Ok(report)
    }

    /// Detect WAF challenge pages (Cloudflare, DDos-Guard, etc.)
    async fn detect_challenge_page(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        if let Ok(response) = self.client.get(url).send().await {
            if let Ok(text) = response.text().await {
                let text_lower = text.to_lowercase();

                let challenge_indicators = &[
                    ("checking your browser", "Browser challenge page"),
                    ("challenge platform", "Cloudflare challenge"),
                    ("cf-challenge", "Cloudflare challenge"),
                    ("ddos-guard", "DDoS-Guard protection"),
                    ("javascript challenge", "JS-based challenge"),
                    ("please wait while we verify", "Verification challenge"),
                    ("enable javascript", "JS requirement"),
                    ("captcha", "CAPTCHA challenge"),
                    ("human verification", "Human verification"),
                ];

                for (indicator, desc) in challenge_indicators {
                    if text_lower.contains(indicator) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("Challenge Page Detected: {}", desc),
                            description: format!(
                                "Challenge page detected at URL. This typically indicates a WAF/CDN with bot protection."
                            ),
                            location: Some(url.to_string()),
                            recommendation: Some("Challenge pages indicate active protection. Legitimate bots may need to be whitelisted.".to_string()),
                            cwe: None,
                            owasp: None,
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Get specific recommendations for a detected WAF
    fn get_waf_recommendation(&self, waf: &WafProduct) -> String {
        format!(
            "WAF Detected: {} ({})\n\n\
            Recommendations:\n\
            1. Review and tune WAF rules to reduce false positives\n\
            2. Implement proper whitelisting for legitimate traffic\n\
            3. Configure rate limiting appropriately\n\
            4. Regularly update WAF signatures\n\
            5. Monitor WAF logs for blocked legitimate requests\n\
            6. Test bypass techniques only with proper authorization",
            waf.name, waf.vendor
        )
    }

    /// Format bypass techniques documentation
    fn format_bypass_documentation(&self) -> String {
        let mut doc = String::from(
            "WAF Bypass Techniques (Documentation Only)\n\
            ===========================================\n\n\
            WARNING: These techniques are for authorized security testing only.\n\
            Always obtain written permission before testing.\n\n"
        );

        for bypass in BYPASS_TECHNIQUES {
            doc.push_str(&format!(
                "\n[{}]\n\
                Technique: {}\n\
                Description: {}\n\
                Examples:\n",
                bypass.category, bypass.technique, bypass.description
            ));

            for example in bypass.examples {
                doc.push_str(&format!("  - {}\n", example));
            }
        }

        doc.push_str(
            "\n\nAdditional Notes:\n\
            - Bypass success depends on WAF configuration and rule sets\n\
            - Modern WAFs use ML/AI and are harder to bypass\n\
            - Always combine techniques for better results\n\
            - Rate limiting may prevent extensive testing"
        );

        doc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = WafScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_waf_signatures_count() {
        assert!(!WAF_SIGNATURES.is_empty());
        assert!(WAF_SIGNATURES.len() >= 15); // We should have at least 15 WAF signatures
    }

    #[test]
    fn test_bypass_techniques_count() {
        assert!(!BYPASS_TECHNIQUES.is_empty());
        assert!(BYPASS_TECHNIQUES.len() >= 15);
    }

    #[test]
    fn test_bypass_documentation_format() {
        let config = ScannerConfig::new();
        let scanner = WafScanner::new(config);
        let doc = scanner.format_bypass_documentation();

        assert!(doc.contains("WAF Bypass Techniques"));
        assert!(doc.contains("WARNING"));
        assert!(doc.contains("SQL Injection"));
        assert!(doc.contains("XSS"));
        assert!(doc.contains("Path Traversal"));
    }
}
