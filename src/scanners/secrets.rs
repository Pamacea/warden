//! Secrets Leak Scanner
//!
//! Detects exposed secrets, credentials, and sensitive data in code and configuration files.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Directories to exclude from secrets scanning
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "vendor",
    "vendor/bundle",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".nuxt",
    "out",
    ".terraform",
    ".nox",
    ".hypothesis",
    "mypy_cache",
    ".pytest_cache",
    ".eggs",
    "*.egg-info",
];

/// File extensions to scan for secrets
const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "toml", "yaml", "yml", "json", "xml", "conf", "config", "ini",
    "js", "jsx", "ts", "tsx", "py", "go", "java", "php", "rb", "cs",
    "cpp", "c", "h", "hpp", "sh", "bash", "zsh", "fish", "ps1", "yaml",
    "env", "example", "template", "key", "pem", "crt", "der", "p12", "pfx",
    "sql", "db", "sqlitedb", "md", "txt", "gradle", "properties",
];

/// Sensitive filenames that should always be flagged
const SENSITIVE_FILENAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    ".env.dist",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.defaults",
    "secrets.yml",
    "secrets.yaml",
    "secrets.json",
    "secrets.toml",
    "config/secrets.yml",
    "config/secrets.yaml",
    "config/secrets.json",
    "credentials",
    ".aws/credentials",
    ".aws/config",
    ".pgpass",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".gitconfig",
    ".dockercfg",
    ".docker/config.json",
    ".kube/config",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_dsa",
    "id_dsa.pub",
    "keystore.jks",
    ".keystore",
    "truststore.jks",
    "oauth_credentials.json",
    "client_secret.json",
    "service_account.json",
    "firebase.json",
    "awscredentials.csv",
    "credentials.db",
    "accesstokens.csv",
];

/// False positive patterns to exclude
const FALSE_POSITIVE_PATTERNS: &[&str] = &[
    "DEMO_KEY",
    "TEST_SECRET",
    "EXAMPLE_KEY",
    "PLACEHOLDER",
    "YOUR_KEY_HERE",
    "REPLACE_WITH_YOUR",
    "XXX",
    "xxx",
    "TODO: replace",
    "FIXME: replace",
    "<your",
    "<insert",
    "CHANGEME",
    "NOT_A_REAL",
    "FAKE",
    "DUMMY",
    "SAMPLE",
    "MOCK",
];

/// Check if a path should be excluded from scanning
fn should_exclude_path(path: &Path) -> bool {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .any(|component| EXCLUDED_DIRS.contains(&component))
}

/// Check if a finding is a false positive
fn is_false_positive(match_str: &str) -> bool {
    let upper = match_str.to_uppercase();
    FALSE_POSITIVE_PATTERNS.iter().any(|pattern| upper.contains(pattern))
}

pub struct SecretsScanner {
    config: ScannerConfig,
}

impl SecretsScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Scan for sensitive files
        report.merge(self.scan_sensitive_files(path)?);

        // Scan file contents for secret patterns
        report.merge(self.scan_file_contents(path)?);

        // Git history scan (mode aggressive)
        if self.config.aggressive {
            if let Ok(git_report) = self.scan_git_history(path) {
                report.merge(git_report);
            }
        }

        Ok(report)
    }

    /// Scan for sensitive filenames
    fn scan_sensitive_files(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(Self::get_max_depth())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();
            let full_path = entry.path().display().to_string();

            // Check if filename matches sensitive patterns
            for sensitive_name in SENSITIVE_FILENAMES {
                if file_name.ends_with(*sensitive_name)
                    || file_name.as_ref() == *sensitive_name
                    || full_path.ends_with(*sensitive_name)
                {
                    // Check file extension for keys/certs
                    let severity = if file_name.ends_with(".key")
                        || file_name.ends_with(".pem")
                        || file_name.ends_with(".p12")
                        || file_name.ends_with(".jks")
                        || file_name.contains("id_rsa")
                        || file_name.contains("id_ed25519")
                        || file_name.contains("id_ecdsa")
                    {
                        VulnSeverity::Critical
                    } else if file_name.contains(".env")
                        || file_name.contains("secrets.")
                        || file_name.contains("credentials")
                    {
                        VulnSeverity::High
                    } else {
                        VulnSeverity::Medium
                    };

                    report.add_finding(Vuln {
                        severity,
                        title: format!("Sensitive file detected: {}", file_name),
                        description: format!(
                            "File {} may contain sensitive credentials or secrets",
                            full_path
                        ),
                        location: Some(full_path.clone()),
                        recommendation: Some(
                            "Ensure this file is not committed to version control. \
                            Use .gitignore to exclude sensitive files. \
                            Consider using environment variables or secret management systems."
                                .to_string(),
                        ),
                        cwe: Some("CWE-312".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                    break;
                }
            }

            // Check for certificate/key files by extension
            if let Some(ext) = entry.path().extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if matches!(
                    ext_str.as_str(),
                    "key" | "pem" | "crt" | "der" | "p12" | "pfx" | "jks" | "keystore"
                ) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Certificate or key file detected: {}", file_name),
                        description: format!(
                            "File {} may contain cryptographic keys or certificates",
                            full_path
                        ),
                        location: Some(full_path.clone()),
                        recommendation: Some(
                            "Ensure private keys are not committed to version control. \
                            Use .gitignore to exclude key files."
                                .to_string(),
                        ),
                        cwe: Some("CWE-312".to_string()),
                        owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Scan file contents for secret patterns
    fn scan_file_contents(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(Self::get_max_depth())
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|s| TEXT_EXTENSIONS.contains(&s.to_string_lossy().as_ref()))
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            // Skip if file is too large (> 1MB)
            if let Ok(metadata) = file_path.metadata() {
                if metadata.len() > 1_000_000 {
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.scan_content(&content, &file_path_str);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Scan content for secret patterns
    fn scan_content(&self, content: &str, file_path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        for (pattern_name, pattern, severity) in self.get_secret_patterns() {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    let match_str = mat.as_str();

                    // Skip false positives
                    if is_false_positive(match_str) {
                        continue;
                    }

                    // Skip very short matches (< 8 chars) - likely not real secrets
                    if match_str.len() < 8 {
                        continue;
                    }

                    let line_num = self.line_number(content, mat.start());

                    findings.push(Vuln {
                        severity,
                        title: format!("Hardcoded Secret: {}", pattern_name),
                        description: format!(
                            "Potential {} exposed in source code at line {}",
                            pattern_name, line_num
                        ),
                        location: Some(format!("{}:{}", file_path, line_num)),
                        recommendation: Some(
                            "Remove hardcoded credentials. Use environment variables, \
                            secret management systems, or configuration files excluded from version control."
                                .to_string(),
                        ),
                        cwe: Some("CWE-798".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        findings
    }

    /// Scan git history for secrets (aggressive mode)
    fn scan_git_history(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Check if directory is a git repository
        let git_dir = path.join(".git");
        if !git_dir.exists() {
            return Ok(report);
        }

        // Use git log to scan history
        // This is a simplified scan - in production, you'd use a git library
        // for more comprehensive scanning
        let output = std::process::Command::new("git")
            .args(["-C", &path.to_string_lossy()])
            .args(["log", "-p", "--all", "-S", "AKIA"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.is_empty() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Potential AWS Access Key in Git History".to_string(),
                        description: "AWS Access Key pattern found in git history. Even if removed from current code, it may still be accessible in history.".to_string(),
                        location: Some(format!("{} (git history)", path.display())),
                        recommendation: Some(
                            "Rotate the exposed AWS credentials immediately. \
                            Consider using git-filter-repo or BFG Repo-Cleaner to remove sensitive data from history."
                                .to_string(),
                        ),
                        cwe: Some("CWE-312".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        // Check for other common secret patterns in git history
        for (pattern_name, _pattern, _) in self.get_secret_patterns() {
            let search_pattern = if pattern_name.contains("API") {
                "api"
            } else if pattern_name.contains("Key") {
                "key"
            } else if pattern_name.contains("Secret") {
                "secret"
            } else if pattern_name.contains("Token") {
                "token"
            } else {
                continue;
            };

            let output = std::process::Command::new("git")
                .args(["-C", &path.to_string_lossy()])
                .args(["log", "-p", "--all", "-S", search_pattern])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if !stdout.is_empty() && stdout.len() > 100 {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Potential {} in Git History", pattern_name),
                            description: format!(
                                "{} pattern found in git history. Consider checking if secrets are exposed.",
                                pattern_name
                            ),
                            location: Some(format!("{} (git history)", path.display())),
                            recommendation: Some(
                                "Review git history for exposed secrets and rotate if necessary."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-312".to_string()),
                            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Get line number from byte offset
    fn line_number(&self, content: &str, offset: usize) -> usize {
        content[..offset].chars().filter(|&c| c == '\n').count() + 1
    }

    /// Get maximum depth for directory traversal
    fn get_max_depth() -> usize {
        10
    }

    /// Get regex patterns for detecting secrets
    fn get_secret_patterns(&self) -> Vec<(&'static str, &'static str, VulnSeverity)> {
        vec![
            // AWS
            (
                "AWS Access Key ID",
                r"\bAKIA[0-9A-Z]{16}\b",
                VulnSeverity::Critical,
            ),
            (
                "AWS Secret Key",
                r"\b[A-Za-z0-9/+=]{40}\b", // AWS secret key pattern (context-dependent)
                VulnSeverity::High,
            ),
            (
                "AWS Session Token",
                r"\b[A-Za-z0-9/+=]{170,}\b", // Session tokens are longer
                VulnSeverity::High,
            ),
            // Stripe
            (
                "Stripe Live Key",
                r"\bsk_live_[a-zA-Z0-9]{24,}\b",
                VulnSeverity::Critical,
            ),
            (
                "Stripe Publishable Key",
                r"\bpk_live_[a-zA-Z0-9]{24,}\b",
                VulnSeverity::Medium,
            ),
            (
                "Stripe Test Key",
                r"\bsk_test_[a-zA-Z0-9]{24,}\b",
                VulnSeverity::Medium,
            ),
            // Google
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
            (
                "Google Cloud Platform Service Account",
                r#""type":\s*"service_account""#,
                VulnSeverity::High,
            ),
            // GitHub
            (
                "GitHub Personal Access Token",
                r"\bghp_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            (
                "GitHub OAuth Access Token",
                r"\bgho_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            (
                "GitHub App Token",
                r"\bghu_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            (
                "GitHub Server Token",
                r"\bghs_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            (
                "GitHub Refresh Token",
                r"\bghr_[a-zA-Z0-9]{36}\b",
                VulnSeverity::High,
            ),
            // Slack
            (
                "Slack Token",
                r"\bxox[baprs]-[0-9]-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}\b",
                VulnSeverity::High,
            ),
            (
                "Slack Webhook",
                r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}\b",
                VulnSeverity::Medium,
            ),
            // JWT
            (
                "JWT Token",
                r"\beyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\b",
                VulnSeverity::Medium,
            ),
            // Auth0
            (
                "Auth0 Token",
                r"\b[a-zA-Z0-9\-_]{43}\.auth0\.com\b",
                VulnSeverity::Medium,
            ),
            // Twilio
            (
                "Twilio Account SID",
                r"\bAC[a-zA-Z0-9]{32}\b",
                VulnSeverity::Medium,
            ),
            (
                "Twilio Auth Token",
                r"\b[a-zA-Z0-9]{32}\b",
                VulnSeverity::Medium,
            ),
            // SendGrid
            (
                "SendGrid API Key",
                r"\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b",
                VulnSeverity::High,
            ),
            // PayPal
            (
                "PayPal Braintree Token",
                r"\baccess_token\$production\$[a-zA-Z0-9]{24}\b",
                VulnSeverity::High,
            ),
            // Stripe (additional)
            (
                "Stripe API Key",
                r"\brk_live_[a-zA-Z0-9]{32}\b",
                VulnSeverity::High,
            ),
            // Docker Hub
            (
                "Docker Hub Password",
                r#"[d]ocker-hub[\s"][^"]*["\s][^"]*password["\s:][^"]*["']?[a-zA-Z0-9]{20,}"#,
                VulnSeverity::Medium,
            ),
            // NPM
            (
                "NPM Token",
                r"\bnpm_[a-zA-Z0-9\-_]{36}\b",
                VulnSeverity::High,
            ),
            // PyPI
            (
                "PyPI Token",
                r"\bpypi-[A-Za-z0-9\-_]{20,}",
                VulnSeverity::High,
            ),
            // Generic API Key patterns
            (
                "API Key",
                r#"(?i)(api[_-]?key|apikey|api-key)[\s"'::=]{1,5}["']?[a-zA-Z0-9_-]{20,}"#,
                VulnSeverity::Medium,
            ),
            (
                "Secret Key",
                r#"(?i)(secret[_-]?key|secretkey|secret-key)[\s"'::=]{1,5}["']?[a-zA-Z0-9_-]{20,}"#,
                VulnSeverity::Medium,
            ),
            (
                "Access Token",
                r#"(?i)(access[_-]?token|accesstoken|access-token)[\s"'::=]{1,5}["']?[a-zA-Z0-9_-]{20,}"#,
                VulnSeverity::Medium,
            ),
            (
                "Auth Token",
                r#"(?i)(auth[_-]?token|authtoken|auth-token)[\s"'::=]{1,5}["']?[a-zA-Z0-9_-]{20,}"#,
                VulnSeverity::Medium,
            ),
            (
                "Bearer Token",
                r"(?i)bearer[\s]+[a-zA-Z0-9\-_\.]{20,}",
                VulnSeverity::Medium,
            ),
            // Database connection strings
            (
                "Database Connection String",
                r#"(?i)(mongodb|mysql|postgres|redis|cassandra)://[^\s"'<>]{10,}"#,
                VulnSeverity::High,
            ),
            (
                "MySQL Connection",
                r#"(?i)mysql://[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+"#,
                VulnSeverity::High,
            ),
            (
                "PostgreSQL Connection",
                r#"(?i)postgres://[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+"#,
                VulnSeverity::High,
            ),
            (
                "MongoDB Connection",
                r#"(?i)mongodb://[^\s"'<>:]+:[^\s"'<>@]+@[^\s"'<>]+"#,
                VulnSeverity::High,
            ),
            (
                "Redis Connection",
                r#"(?i)redis://[^\s"'<>:]*:[^\s"'<>@]+@[^\s"'<>]+"#,
                VulnSeverity::High,
            ),
            // Heroku
            (
                "Heroku API Key",
                r"\bheroku-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b",
                VulnSeverity::High,
            ),
            // Firebase
            (
                "Firebase Database Secret",
                r"\b[a-z0-9\-_]{40}\b",
                VulnSeverity::Medium,
            ),
            // Private keys (RSA, SSH, etc.)
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
            (
                "PGP Private Key",
                r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                VulnSeverity::Critical,
            ),
            // Base64 encoded secrets (likely)
            (
                "Base64 Encoded Secret",
                r#"["']?[A-Za-z0-9+/]{60,}={0,2}["']?"#,
                VulnSeverity::Low,
            ),
            // Mailgun
            (
                "Mailgun API Key",
                r"\bkey-[a-f0-9]{32}\b",
                VulnSeverity::Medium,
            ),
            // Datadog
            (
                "Datadog API Key",
                r"\b[a-z]{32}\b",
                VulnSeverity::Medium,
            ),
            // New Relic
            (
                "New Relic License Key",
                r"\b[a-z0-9]{40}\b",
                VulnSeverity::Medium,
            ),
            // PagerDuty
            (
                "PagerDuty API Key",
                r"\b[a-zA-Z0-9]{30,}\b",
                VulnSeverity::Medium,
            ),
            // CircleCI
            (
                "CircleCI Token",
                r"\b[a-z0-9\-_]{40}\b",
                VulnSeverity::Medium,
            ),
            // Travis CI
            (
                "Travis CI Token",
                r"\b[a-z0-9\-_]{22}\b",
                VulnSeverity::Medium,
            ),
            // Atlassian/Bitbucket
            (
                "Atlassian API Token",
                r"\b[a-zA-Z0-9]{24}\b",
                VulnSeverity::Medium,
            ),
            // HashiCorp Vault
            (
                "Vault Token",
                r"\bs\.[a-zA-Z0-9\-_]{20,}\b",
                VulnSeverity::High,
            ),
            // Azure
            (
                "Azure Storage Key",
                r"\b[a-zA-Z0-9/+]{88}==\b",
                VulnSeverity::High,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secrets_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = SecretsScanner::new(config);
        assert_eq!(scanner.config.aggressive, false);
    }

    #[test]
    fn test_should_exclude_path() {
        assert!(should_exclude_path(Path::new("node_modules/test.rs")));
        assert!(should_exclude_path(Path::new("target/test.rs")));
        assert!(should_exclude_path(Path::new(".git/test.rs")));
        assert!(!should_exclude_path(Path::new("src/test.rs")));
    }

    #[test]
    fn test_is_false_positive() {
        assert!(is_false_positive("DEMO_KEY"));
        assert!(is_false_positive("TEST_SECRET"));
        assert!(is_false_positive("EXAMPLE_KEY_123"));
        assert!(is_false_positive("YOUR_KEY_HERE"));
        assert!(!is_false_positive("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_sensitive_filenames() {
        assert!(SENSITIVE_FILENAMES.contains(&".env"));
        assert!(SENSITIVE_FILENAMES.contains(&".env.production"));
        assert!(SENSITIVE_FILENAMES.contains(&"secrets.yml"));
        assert!(SENSITIVE_FILENAMES.contains(&"id_rsa"));
        assert!(SENSITIVE_FILENAMES.contains(&"keystore.jks"));
    }

    #[test]
    fn test_line_number() {
        let content = "line1\nline2\nline3\nline4";
        let config = ScannerConfig::new();
        let scanner = SecretsScanner::new(config);

        assert_eq!(scanner.line_number(content, 0), 1); // "line1"
        assert_eq!(scanner.line_number(content, 6), 2); // "line2"
        assert_eq!(scanner.line_number(content, 12), 3); // "line3"
        assert_eq!(scanner.line_number(content, 18), 4); // "line4"
    }
}
