//! Terraform/TFSec Scanner
//!
//! Detects security misconfigurations in Terraform infrastructure-as-code files:
//! - Hardcoded secrets in .tf files
//! - IAM misconfigurations and overly permissive policies
//! - Storage security issues (unencrypted S3, EBS, RDS)
//! - Network security issues (open security groups)
//! - Resource tagging compliance
//! - CIS and NIST compliance checks

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Directories to exclude from Terraform scanning
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "coverage",
    ".terraform",
    ".terraform.lock.hcl",
    "terraform.tfstate",
    "terraform.tfstate.backup",
];

/// Terraform file extensions to scan
const TF_EXTENSIONS: &[&str] = &["tf", "tfvars", "hcl"];

/// Required tags for compliance
const REQUIRED_TAGS: &[&str] = &[
    "Environment",
    "Owner",
    "CostCenter",
    "Project",
    "Compliance",
];

/// High-risk ports that should not be exposed to 0.0.0.0/0
const HIGH_RISK_PORTS: &[&str] = &[
    "22",   // SSH
    "3389", // RDP
    "3306", // MySQL
    "5432", // PostgreSQL
    "1433", // MSSQL
    "6379", // Redis
    "27017", // MongoDB
    "5672", // RabbitMQ
    "9200", // Elasticsearch
    "9300", // Elasticsearch
];

/// Check if a path should be excluded from scanning
fn should_exclude_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check if any component matches excluded directories
    if path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .any(|component| EXCLUDED_DIRS.contains(&component))
    {
        return true;
    }

    // Exclude state files
    if path_str.contains("tfstate") || path_str.contains("terraform.lock") {
        return true;
    }

    false
}

/// Check if a finding is a false positive
fn is_false_positive(match_str: &str) -> bool {
    let upper = match_str.to_uppercase();
    let false_positive_patterns = &[
        "DEMO_KEY",
        "TEST_SECRET",
        "EXAMPLE_KEY",
        "PLACEHOLDER",
        "YOUR_KEY_HERE",
        "REPLACE_WITH_YOUR",
        "CHANGEME",
        "NOT_A_REAL",
        "FAKE",
        "DUMMY",
        "SAMPLE",
        "MOCK",
        "XXX",
        "TODO:",
        "FIXME:",
        "<your",
        "<insert",
        "var.",
        "local.",
    ];

    false_positive_patterns.iter().any(|pattern| upper.contains(pattern))
}

pub struct TerraformScanner {
    config: ScannerConfig,
    required_tags: HashSet<String>,
    high_risk_ports: HashSet<String>,
}

impl TerraformScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let required_tags: HashSet<String> = REQUIRED_TAGS
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let high_risk_ports: HashSet<String> = HIGH_RISK_PORTS
            .iter()
            .map(|s| s.to_string())
            .collect();

        Self {
            config,
            required_tags,
            high_risk_ports,
        }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Find all Terraform files
        let tf_files = self.find_terraform_files(path)?;

        if tf_files.is_empty() {
            return Ok(report);
        }

        // Scan for secrets
        report.merge(self.scan_secrets(&tf_files)?);

        // Scan for IAM misconfigurations
        report.merge(self.scan_iam_security(&tf_files)?);

        // Scan for storage security issues
        report.merge(self.scan_storage_security(&tf_files)?);

        // Scan for network security issues
        report.merge(self.scan_network_security(&tf_files)?);

        // Scan for tagging compliance
        report.merge(self.scan_tagging_compliance(&tf_files)?);

        // Scan for general compliance issues
        report.merge(self.scan_compliance(&tf_files)?);

        // Aggressive mode: additional checks
        if self.config.aggressive {
            report.merge(self.scan_aggressive_checks(&tf_files)?);
        }

        Ok(report)
    }

    /// Find all Terraform files in the given path
    fn find_terraform_files(&self, path: &Path) -> Result<Vec<String>> {
        let mut tf_files = Vec::new();

        let entries = WalkDir::new(path)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|s| TF_EXTENSIONS.contains(&s.to_string_lossy().as_ref()))
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path().display().to_string();
            tf_files.push(file_path);
        }

        Ok(tf_files)
    }

    /// Scan for hardcoded secrets in Terraform files
    fn scan_secrets(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_content_for_secrets(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan content for secret patterns
    fn scan_content_for_secrets(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        for (pattern_name, pattern, severity) in self.get_secret_patterns() {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let match_str = mat.as_str();

                    // Skip false positives
                    if is_false_positive(match_str) {
                        continue;
                    }

                    // Skip variable references
                    if match_str.contains("var.") || match_str.contains("local.") {
                        continue;
                    }

                    let line_num = self.line_number(content, mat.start());

                    findings.push(Vuln {
                        severity,
                        title: format!("Hardcoded Secret in Terraform: {}", pattern_name),
                        description: format!(
                            "Potential {} exposed in Terraform configuration at line {}",
                            pattern_name, line_num
                        ),
                        location: Some(format!("{}:{}", file_path, line_num)),
                        recommendation: Some(
                            "Use Terraform variables, environment variables, or a secret management system (AWS Secrets Manager, Parameter Store, Vault). Never hardcode secrets in .tf files.".to_string(),
                        ),
                        cwe: Some("CWE-798".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        findings
    }

    /// Scan for IAM security misconfigurations
    fn scan_iam_security(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_iam_policies(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan IAM policies for overly permissive configurations
    fn scan_iam_policies(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // Check for wildcard actions
        let wildcard_action_patterns = &[
            (r#"Action\s*=\s*\[\s*"\*"\s*\]"#, "Wildcard Action in IAM Policy"),
            (r#"Action\s*=\s*"\*""#, "Wildcard Action in IAM Policy"),
            (r#"actions\s*=\s*\[\s*"\*"\s*\]"#, "Wildcard Action in IAM Policy"),
        ];

        for (pattern, title) in wildcard_action_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = self.line_number(content, mat.start());

                    // Check if wildcard is actually used for legitimate purpose
                    let context_before = &content[mat.start().saturating_sub(200)..mat.start()];
                    if context_before.contains("Condition")
                        || context_before.contains("NotAction")
                        || context_before.contains("comment")
                        || context_before.contains("#")
                    {
                        continue;
                    }

                    findings.push(Vuln {
                        severity: VulnSeverity::High,
                        title: title.to_string(),
                        description: "IAM policy allows all actions (\"Action\": \"*\"). This grants excessive permissions and violates the principle of least privilege.".to_string(),
                        location: Some(format!("{}:{}", file_path, line_num)),
                        recommendation: Some("Restrict actions to only those required. Use specific action prefixes like 's3:Get*' instead of '*'.".to_string()),
                        cwe: Some("CWE-269".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        // Check for wildcard resources
        let wildcard_resource_patterns = &[
            (r#"Resource\s*=\s*\[\s*"\*"\s*\]"#, "Wildcard Resource in IAM Policy"),
            (r#"Resource\s*=\s*"\*""#, "Wildcard Resource in IAM Policy"),
            (r#"resources\s*=\s*\[\s*"\*"\s*\]"#, "Wildcard Resource in IAM Policy"),
        ];

        for (pattern, title) in wildcard_resource_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = self.line_number(content, mat.start());
                    findings.push(Vuln {
                        severity: VulnSeverity::Medium,
                        title: title.to_string(),
                        description: "IAM policy applies to all resources (\"Resource\": \"*\"). Consider limiting to specific resource ARNs.".to_string(),
                        location: Some(format!("{}:{}", file_path, line_num)),
                        recommendation: Some("Specify exact resource ARNs or use ARN patterns with constraints (e.g., 'arn:aws:s3:::my-bucket/*').".to_string()),
                        cwe: Some("CWE-269".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        // Check for administrator access policies
        let admin_policy_patterns = &[
            (r"arn:aws:iam::aws:policy/AdministratorAccess", "AdministratorAccess Policy Attached"),
            (r"arn:aws:iam::aws:policy/PowerUserAccess", "PowerUserAccess Policy Attached"),
            (r#"PolicyName\s*=\s*"[Aa]dministrator"#, "Administrator-named Policy"),
            (r#"name\s*=\s*"[Aa]dministrator"#, "Administrator-named Policy"),
        ];

        for (pattern, title) in admin_policy_patterns {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let line_num = self.line_number(content, mat.start());
                    findings.push(Vuln {
                        severity: VulnSeverity::High,
                        title: title.to_string(),
                        description: "Administrator access policy detected. This grants full administrative permissions and should only be used in emergency cases.".to_string(),
                        location: Some(format!("{}:{}", file_path, line_num)),
                        recommendation: Some("Use specific IAM policies with limited permissions. Implement role-based access control (RBAC) with least privilege.".to_string()),
                        cwe: Some("CWE-269".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        findings
    }

    /// Scan for storage security issues
    fn scan_storage_security(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_storage_configs(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan storage configurations for security issues
    fn scan_storage_configs(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // S3 bucket public ACL
        if content.contains(r#"acl = "public-read""#) {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "S3 Bucket with Public Read ACL".to_string(),
                description: "S3 bucket configured with public-read ACL. This exposes the bucket contents to the entire internet.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Remove public ACL. Enable 'Block Public Access' settings. Use presigned URLs or CloudFront for controlled access.".to_string()),
                cwe: Some("CWE-732".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        if content.contains(r#"acl = "public-read-write""#) {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "S3 Bucket with Public Read-Write ACL".to_string(),
                description: "S3 bucket configured with public-read-write ACL. This allows anyone to read and write to the bucket.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Remove public ACL immediately. Enable 'Block Public Access' settings.".to_string()),
                cwe: Some("CWE-732".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // S3 block public access disabled
        if content.contains("block_public_acls = false")
            || content.contains("block_public_policy = false") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "S3 Bucket Block Public Access Disabled".to_string(),
                description: "S3 bucket has Block Public Access settings disabled. This may allow unintended public access.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Enable all Block Public Access settings on S3 buckets unless public access is explicitly required.".to_string()),
                cwe: Some("CWE-732".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // S3 bucket policy allowing public access
        if content.contains(r#"Principal = "*""#) || content.contains(r#""Principal": "*""#) {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "S3 Policy with Wildcard Principal".to_string(),
                description: "S3 bucket policy allows wildcard principal (*). This may expose data to the entire internet.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Remove wildcard principals from S3 policies. Use specific AWS accounts or IAM principals.".to_string()),
                cwe: Some("CWE-732".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        findings
    }

    /// Scan for network security issues
    fn scan_network_security(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_network_configs(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan network configurations for security issues
    fn scan_network_configs(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // Check for 0.0.0.0/0 in security groups
        let has_0_0_0_0 = content.contains("0.0.0.0/0") || content.contains("::/0");

        if has_0_0_0_0 {
            // Check if it's for high-risk ports
            for port in &self.high_risk_ports {
                if content.contains(format!("from_port = {}", port).as_str())
                    || content.contains(format!("to_port = {}", port).as_str())
                    || content.contains(format!("from_port={}", port).as_str())
                    || content.contains(format!("to_port={}", port).as_str())
                {
                    findings.push(Vuln {
                        severity: VulnSeverity::Critical,
                        title: format!("Security Group Allows Public Access on High-Risk Port {}", port),
                        description: format!("Security group allows 0.0.0.0/0 access on port {} ({}). This exposes sensitive services to the entire internet.",
                            port,
                            self.get_port_description(port)
                        ),
                        location: Some(file_path.to_string()),
                        recommendation: Some("Restrict ingress to specific IP ranges (CIDR blocks) or use a VPN/bastion host for administrative access.".to_string()),
                        cwe: Some("CWE-285".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }

            // Check for all ports exposed
            if (content.contains("from_port = 0") || content.contains("from_port=0"))
                && (content.contains("to_port = 65535") || content.contains("to_port=65535"))
            {
                findings.push(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "Security Group Allows All Ports (0-65535)".to_string(),
                    description: "Security group allows all ports (0-65535) from specified source. This is overly permissive.".to_string(),
                    location: Some(file_path.to_string()),
                    recommendation: Some("Restrict to only the specific ports required for the service. Use specific port ranges.".to_string()),
                    cwe: Some("CWE-285".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }

            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Security Group Allows Public Access (0.0.0.0/0)".to_string(),
                description: "Security group allows access from 0.0.0.0/0 (entire internet). This should be restricted unless absolutely necessary.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Restrict to specific CIDR blocks. Use security group references instead of CIDR where possible.".to_string()),
                cwe: Some("CWE-285".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check for SSH specifically
        if has_0_0_0_0 && content.contains("22") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "CIS 3.1: SSH (Port 22) Exposed to Internet".to_string(),
                description: "Security group allows SSH (port 22) from 0.0.0.0/0. CIS Benchmark prohibits unrestricted SSH access.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager for secure access without SSH.".to_string()),
                cwe: Some("CWE-285".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for RDP specifically
        if has_0_0_0_0 && content.contains("3389") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "CIS 3.2: RDP (Port 3389) Exposed to Internet".to_string(),
                description: "Security group allows RDP (port 3389) from 0.0.0.0/0. CIS Benchmark prohibits unrestricted RDP access.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Restrict RDP access to specific IP ranges or use AWS Workspace for secure remote access.".to_string()),
                cwe: Some("CWE-285".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        findings
    }

    /// Scan for tagging compliance issues
    fn scan_tagging_compliance(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_tags(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan for missing required tags
    fn scan_tags(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // Find resource blocks
        let resource_pattern = Regex::new(r#"resource\s+"([^"]+)"\s+"([^"]+)""#)
            .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e)).unwrap();

        for mat in resource_pattern.find_iter(content) {
            let resource_start = mat.start();
            let resource_end = resource_start.saturating_add(3000).min(content.len());
            let resource_content = &content[resource_start..resource_end];

            // Check if resource has tags block
            if !resource_content.contains("tags") {
                // Skip certain resource types that don't typically need tags
                let resource_line = content[resource_start..]
                    .lines()
                    .next()
                    .unwrap_or("");

                if resource_line.contains("aws_security_group_rule")
                    || resource_line.contains("aws_route")
                    || resource_line.contains("aws_route_table_association")
                {
                    continue;
                }

                let line_num = self.line_number(content, resource_start);
                findings.push(Vuln {
                    severity: VulnSeverity::Low,
                    title: "Resource Missing Tags".to_string(),
                    description: "Resource is defined without any tags. Tags are important for cost allocation, compliance, and resource management.".to_string(),
                    location: Some(format!("{}:{}", file_path, line_num)),
                    recommendation: Some("Add tags including at minimum: Environment, Owner, CostCenter, Project, Compliance.".to_string()),
                    cwe: Some("CWE-1050".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }
        }

        findings
    }

    /// Scan for general compliance issues
    fn scan_compliance(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_cis_compliance(&content, file_path);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan for CIS AWS Foundations Benchmark compliance
    fn scan_cis_compliance(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // CIS 1.1: Avoid the use of the default security group
        if content.contains("aws_default_vpc") || content.contains("aws_default_security_group") {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "CIS 1.1: Use of Default VPC/Security Group".to_string(),
                description: "Resources using default VPC or security group. CIS recommends avoiding default security groups.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Create and use custom VPCs and security groups with least privilege access.".to_string()),
                cwe: Some("CWE-285".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // CIS 2.3: S3 bucket policy should prohibit public read/write
        if Regex::new(r#"acl\s*=\s*"public"#)
            .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))
            .unwrap_or_else(|_| Regex::new(r"x^").unwrap())
            .is_match(content) {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "CIS 2.3: S3 Bucket with Public Access".to_string(),
                description: "S3 bucket configured with public ACL. CIS Benchmark prohibits public S3 buckets.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Remove public ACLs. Enable 'Block Public Access' on all S3 buckets.".to_string()),
                cwe: Some("CWE-732".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        findings
    }

    /// Additional aggressive mode checks
    fn scan_aggressive_checks(&self, tf_files: &[String]) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(".".into()));

        for file_path in tf_files {
            if let Ok(content) = fs::read_to_string(file_path) {
                // Check for sensitive data in outputs
                let output_patterns = &[
                    (r#"output\s+"[^"]*password[^"]*""#, "Sensitive Data in Output: Password"),
                    (r#"output\s+"[^"]*secret[^"]*""#, "Sensitive Data in Output: Secret"),
                    (r#"output\s+"[^"]*key[^"]*""#, "Sensitive Data in Output: Key"),
                    (r#"output\s+"[^"]*token[^"]*""#, "Sensitive Data in Output: Token"),
                ];

                for (pattern, title) in output_patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        for mat in re.find_iter(&content) {
                            let line_num = self.line_number(&content, mat.start());
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: title.to_string(),
                                description: "Terraform output appears to expose sensitive data. Outputs are visible in state files and logs.".to_string(),
                                location: Some(format!("{}:{}", file_path, line_num)),
                                recommendation: Some("Remove sensitive data from outputs. Use secure note-taking or secret management systems instead.".to_string()),
                                cwe: Some("CWE-312".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                        }
                    }
                }

                // Check for hardcoded AMI IDs
                if Regex::new(r"ami-[a-f0-9]{17}")
                    .map_err(|e| anyhow::anyhow!("Invalid regex pattern: {}", e))
                    .unwrap_or_else(|_| Regex::new(r"x^").unwrap())
                    .is_match(&content) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Hardcoded AMI ID Detected".to_string(),
                        description: "AMI ID is hardcoded. This can cause issues across regions and becomes outdated.".to_string(),
                        location: Some(file_path.to_string()),
                        recommendation: Some("Use data sources like 'data.aws_ami' to dynamically fetch the latest AMI.".to_string()),
                        cwe: Some("CWE-1057".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Get line number from byte offset
    fn line_number(&self, content: &str, offset: usize) -> usize {
        content[..offset].chars().filter(|&c| c == '\n').count() + 1
    }

    /// Get description for port number
    fn get_port_description(&self, port: &str) -> &'static str {
        match port {
            "22" => "SSH",
            "3389" => "RDP",
            "3306" => "MySQL",
            "5432" => "PostgreSQL",
            "1433" => "MSSQL",
            "6379" => "Redis",
            "27017" => "MongoDB",
            "5672" => "RabbitMQ",
            "9200" | "9300" => "Elasticsearch",
            _ => "Unknown Service",
        }
    }

    /// Get regex patterns for detecting secrets in Terraform files
    fn get_secret_patterns(&self) -> Vec<(&'static str, &'static str, VulnSeverity)> {
        vec![
            // AWS Secrets
            (
                "AWS Access Key ID",
                r"\bAKIA[0-9A-Z]{16}\b",
                VulnSeverity::Critical,
            ),
            (
                "AWS Secret Access Key",
                r"\b[A-Za-z0-9/+=]{40}\b",
                VulnSeverity::Critical,
            ),
            (
                "AWS Session Token",
                r"\b[A-Za-z0-9/+=]{170,}\b",
                VulnSeverity::High,
            ),
            // Azure Secrets
            (
                "Azure Client Secret",
                r#"(?:client_secret|client-secret|clientSecret)\s*=\s*"[a-zA-Z0-9_\-\.]{34,}""#,
                VulnSeverity::Critical,
            ),
            (
                "Azure Storage Key",
                r"\b[a-zA-Z0-9/+]{88}==\b",
                VulnSeverity::Critical,
            ),
            // Google Cloud Secrets
            (
                "Google Cloud Service Account",
                r#""type":\s*"service_account""#,
                VulnSeverity::Critical,
            ),
            (
                "Google API Key",
                r"\bAIza[0-9A-Za-z\-_]{35}\b",
                VulnSeverity::High,
            ),
            (
                "Google OAuth Access Token",
                r"\bya29\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
                VulnSeverity::High,
            ),
            // Database Credentials
            (
                "Database Password in Variable",
                r#"(?:password|passwd|pwd)\s*=\s*"[^"]{8,}""#,
                VulnSeverity::High,
            ),
            (
                "MySQL Connection String",
                r#"mysql://[^\s"]+:[^\s"]+@"#,
                VulnSeverity::Critical,
            ),
            (
                "PostgreSQL Connection String",
                r#"postgres://[^\s"]+:[^\s"]+@"#,
                VulnSeverity::Critical,
            ),
            (
                "MongoDB Connection String",
                r#"mongodb://[^\s"]+:[^\s"]+@"#,
                VulnSeverity::Critical,
            ),
            (
                "Redis Connection String",
                r#"redis://[^\s"]+:[^\s"]+@"#,
                VulnSeverity::High,
            ),
            // API Keys
            (
                "Stripe API Key",
                r"\bsk_(live|test)_[a-zA-Z0-9]{24,}\b",
                VulnSeverity::Critical,
            ),
            (
                "GitHub Token",
                r"\bghp_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            (
                "Slack Token",
                r"\bxox[baprs]-[0-9]-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}\b",
                VulnSeverity::High,
            ),
            (
                "Slack Webhook",
                r"\bhttps://hooks\.slack\.com/services/[A-Z0-9]{8}/[A-Z0-9]{8}/[a-zA-Z0-9]{24}\b",
                VulnSeverity::High,
            ),
            // Private Keys
            (
                "RSA Private Key",
                r"-----BEGIN RSA PRIVATE KEY-----",
                VulnSeverity::Critical,
            ),
            (
                "Private Key",
                r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
                VulnSeverity::Critical,
            ),
            (
                "SSH Private Key",
                r"-----BEGIN OPENSSH PRIVATE KEY-----",
                VulnSeverity::Critical,
            ),
            // Generic Secret Patterns
            (
                "API Key Assignment",
                r#"(?:api_key|apikey|api-key)\s*=\s*"[a-zA-Z0-9_\-]{20,}""#,
                VulnSeverity::High,
            ),
            (
                "Secret Key Assignment",
                r#"(?:secret_key|secretkey|secret-key)\s*=\s*"[a-zA-Z0-9_\-]{20,}""#,
                VulnSeverity::High,
            ),
            (
                "Access Token Assignment",
                r#"(?:access_token|access-token|accesstoken)\s*=\s*"[a-zA-Z0-9_\-]{20,}""#,
                VulnSeverity::High,
            ),
            (
                "Bearer Token",
                r#"bearer\s+"[a-zA-Z0-9_\-\.]{20,}""#,
                VulnSeverity::High,
            ),
            // JWT Tokens
            (
                "JWT Token",
                r"\beyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b",
                VulnSeverity::High,
            ),
            // Additional Cloud Provider Secrets
            (
                "Heroku API Key",
                r"\bheroku-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
                VulnSeverity::High,
            ),
            (
                "Datadog API Key",
                r"\b[a-z]{32}\b",
                VulnSeverity::Medium,
            ),
            (
                "SendGrid API Key",
                r"\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b",
                VulnSeverity::High,
            ),
            (
                "NPM Token",
                r"\bnpm_[a-zA-Z0-9\-_]{36}\b",
                VulnSeverity::High,
            ),
            (
                "PyPI Token",
                r"\bpypi-[A-Za-z0-9\-_]{20,}",
                VulnSeverity::High,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terraform_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = TerraformScanner::new(config);
        assert!(!scanner.required_tags.is_empty());
        assert!(!scanner.high_risk_ports.is_empty());
    }

    #[test]
    fn test_should_exclude_path() {
        assert!(should_exclude_path(Path::new("node_modules/main.tf")));
        assert!(should_exclude_path(Path::new(".terraform/test.tf")));
        assert!(should_exclude_path(Path::new("terraform.tfstate")));
        assert!(!should_exclude_path(Path::new("main.tf")));
        assert!(!should_exclude_path(Path::new("terraform/main.tf")));
    }

    #[test]
    fn test_port_description() {
        let config = ScannerConfig::new();
        let scanner = TerraformScanner::new(config);

        assert_eq!(scanner.get_port_description("22"), "SSH");
        assert_eq!(scanner.get_port_description("3389"), "RDP");
        assert_eq!(scanner.get_port_description("3306"), "MySQL");
        assert_eq!(scanner.get_port_description("5432"), "PostgreSQL");
        assert_eq!(scanner.get_port_description("unknown"), "Unknown Service");
    }

    #[test]
    fn test_line_number() {
        let content = "line1\nline2\nline3\nline4";
        let config = ScannerConfig::new();
        let scanner = TerraformScanner::new(config);

        assert_eq!(scanner.line_number(content, 0), 1);
        assert_eq!(scanner.line_number(content, 6), 2);
        assert_eq!(scanner.line_number(content, 12), 3);
        assert_eq!(scanner.line_number(content, 18), 4);
    }

    #[test]
    fn test_high_risk_ports() {
        let config = ScannerConfig::new();
        let scanner = TerraformScanner::new(config);

        assert!(scanner.high_risk_ports.contains("22"));
        assert!(scanner.high_risk_ports.contains("3389"));
        assert!(scanner.high_risk_ports.contains("3306"));
        assert!(scanner.high_risk_ports.contains("5432"));
        assert!(scanner.high_risk_ports.contains("27017"));
    }

    #[test]
    fn test_required_tags() {
        let config = ScannerConfig::new();
        let scanner = TerraformScanner::new(config);

        assert!(scanner.required_tags.contains("environment"));
        assert!(scanner.required_tags.contains("owner"));
        assert!(scanner.required_tags.contains("costcenter"));
        assert!(scanner.required_tags.contains("project"));
        assert!(scanner.required_tags.contains("compliance"));
    }

    #[test]
    fn test_is_false_positive() {
        assert!(is_false_positive("DEMO_KEY"));
        assert!(is_false_positive("TEST_SECRET"));
        assert!(is_false_positive("var.password"));
        assert!(is_false_positive("local.api_key"));
        assert!(!is_false_positive("AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_false_positive("STRIPE_LIVE_KEY_EXAMPLE_ONLY"));
    }
}
