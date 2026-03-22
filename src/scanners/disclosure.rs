//! Information Disclosure vulnerability scanner
//!
//! Detects information leakage including stack traces, debug information,
//! version headers, environment variables, and sensitive file exposure.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use std::time::Duration;

#[derive(Debug)]
struct SensitiveFile {
    path: &'static str,
    description: &'static str,
    severity: VulnSeverity,
    keywords: &'static [&'static str],
}

#[derive(Debug)]
struct DisclosurePattern {
    pattern: &'static str,
    description: &'static str,
    severity: VulnSeverity,
    cwe: &'static str,
}

pub struct DisclosureScanner {
    client: Client,
    config: ScannerConfig,
}

impl DisclosureScanner {
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

        // Always perform basic disclosure checks
        report.merge(self.check_version_headers(url).await?);
        report.merge(self.check_sensitive_files(url).await?);
        report.merge(self.check_debug_information(url).await?);

        // Aggressive mode: advanced disclosure checks
        if self.config.aggressive {
            report.merge(self.check_stack_traces(url).await?);
            report.merge(self.check_environment_leak(url).await?);
            report.merge(self.check_git_exposure(url).await?);
            report.merge(self.check_backup_files(url).await?);
            report.merge(self.check_config_exposure(url).await?);
            report.merge(self.check_source_code_leak(url).await?);
        }

        Ok(report)
    }

    /// Check for version disclosure in headers
    async fn check_version_headers(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        if let Ok(response) = self.client.head(url).send().await {
            let headers = response.headers();

            // Check Server header
            if let Some(server) = headers.get("Server") {
                if let Ok(server_str) = server.to_str() {
                    // Check for specific version numbers
                    let version_pattern = Regex::new(r"\d+\.\d+(\.\d+)?")
                        .expect("Invalid version regex pattern");

                    if version_pattern.is_match(server_str) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Low,
                            title: "Version Disclosure in Server Header".to_string(),
                            description: format!(
                                "Server header reveals specific version: '{}'. This information can aid attackers in targeting specific vulnerabilities.",
                                server_str
                            ),
                            location: Some(url.to_string()),
                            recommendation: Some("Configure server to hide specific version numbers. Use generic server identification or disable Server header.".to_string()),
                            cwe: Some("CWE-200".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
            }

            // Check X-Powered-By header
            if let Some(powered) = headers.get("X-Powered-By") {
                if let Ok(powered_str) = powered.to_str() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Technology Disclosure in X-Powered-By".to_string(),
                        description: format!(
                            "X-Powered-By header reveals technology stack: '{}'.",
                            powered_str
                        ),
                        location: Some(url.to_string()),
                        recommendation: Some("Remove X-Powered-By header. Hide framework and language information.".to_string()),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }

            // Check X-AspNet-Version
            if let Some(aspnet) = headers.get("X-AspNet-Version") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "ASP.NET Version Disclosure".to_string(),
                    description: format!("X-AspNet-Version header: {:?}", aspnet),
                    location: Some(url.to_string()),
                    recommendation: Some("Disable X-AspNet-Version header in web.config.".to_string()),
                    cwe: Some("CWE-200".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }

            // Check X-PHP-Version or similar
            if let Some(php) = headers.get("X-PHP-Version") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: "PHP Version Disclosure".to_string(),
                    description: format!("X-PHP-Version header: {:?}", php),
                    location: Some(url.to_string()),
                    recommendation: Some("Disable expose_php in php.ini.".to_string()),
                    cwe: Some("CWE-200".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }

            // Check for various revealing headers
            let revealing_headers = &[
                ("X-Debug-Info", "Debug information exposed"),
                ("X-Debug-Token", "Debug token exposed"),
                ("X-Runtime", "Runtime version exposed"),
                ("X-Generator", "Generator information exposed"),
                ("X-Drupal-Cache", "Drupal exposed"),
                ("X-WordPress", "WordPress exposed"),
                ("X-Magento-Version", "Magento version exposed"),
            ];

            for (header_name, desc) in revealing_headers {
                if let Some(value) = headers.get(*header_name) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: format!("Information Disclosure: {}", header_name),
                        description: format!("{}: {:?}", desc, value),
                        location: Some(url.to_string()),
                        recommendation: Some("Remove unnecessary headers that reveal internal information.".to_string()),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check for sensitive file exposure
    async fn check_sensitive_files(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let sensitive_files = &[
            SensitiveFile {
                path: "/.env",
                description: "Environment configuration file",
                severity: VulnSeverity::Critical,
                keywords: &["DB_PASSWORD", "API_KEY", "SECRET", "DATABASE_URL", "AWS"],
            },
            SensitiveFile {
                path: "/.env.local",
                description: "Local environment file",
                severity: VulnSeverity::Critical,
                keywords: &["DB_PASSWORD", "API_KEY", "SECRET"],
            },
            SensitiveFile {
                path: "/.env.production",
                description: "Production environment file",
                severity: VulnSeverity::Critical,
                keywords: &["DB_PASSWORD", "API_KEY", "SECRET"],
            },
            SensitiveFile {
                path: "/robots.txt",
                description: "Robots.txt file",
                severity: VulnSeverity::Info,
                keywords: &["user-agent", "disallow", "allow", "sitemap"],
            },
            SensitiveFile {
                path: "/sitemap.xml",
                description: "Sitemap file",
                severity: VulnSeverity::Info,
                keywords: &["<url>", "<loc>", "urlset"],
            },
            SensitiveFile {
                path: "/.git/config",
                description: "Git configuration",
                severity: VulnSeverity::Critical,
                keywords: &["[core]", "repositoryurl", "url"],
            },
            SensitiveFile {
                path: "/.htaccess",
                description: "Apache configuration",
                severity: VulnSeverity::Medium,
                keywords: &["RewriteRule", "AuthName", "Require"],
            },
            SensitiveFile {
                path: "/web.config",
                description: "IIS configuration",
                severity: VulnSeverity::Medium,
                keywords: &["<configuration>", "<system.web>", "connectionString"],
            },
            SensitiveFile {
                path: "/package.json",
                description: "NPM package file",
                severity: VulnSeverity::Low,
                keywords: &["dependencies", "version", "name"],
            },
            SensitiveFile {
                path: "/composer.json",
                description: "PHP composer file",
                severity: VulnSeverity::Low,
                keywords: &["require", "dependencies", "name"],
            },
            SensitiveFile {
                path: "/README.md",
                description: "README documentation",
                severity: VulnSeverity::Info,
                keywords: &["#", "installation", "documentation"],
            },
            SensitiveFile {
                path: "/CHANGELOG.md",
                description: "Changelog file",
                severity: VulnSeverity::Info,
                keywords: &["##", "version", "release"],
            },
        ];

        for file in sensitive_files {
            let file_url = if base_url.ends_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), file.path)
            } else {
                format!("{}{}", base_url, file.path)
            };

            if let Ok(response) = self.client.get(&file_url).send().await {
                if response.status().as_u16() == 200 {
                    if let Ok(text) = response.text().await {
                        let text_lower = text.to_lowercase();

                        // Check for expected keywords
                        let has_keywords = file.keywords.iter().any(|kw| {
                            text_lower.contains(&kw.to_lowercase())
                        });

                        if has_keywords || text.len() > 100 {
                            report.add_finding(Vuln {
                                severity: file.severity,
                                title: format!("Sensitive File Exposed: {}", file.description),
                                description: format!(
                                    "The {} is publicly accessible at {}. This may expose sensitive information.",
                                    file.description, file_url
                                ),
                                location: Some(file_url),
                                recommendation: Some("Restrict access to sensitive files. Use proper file permissions. Remove sensitive files from production deployments.".to_string()),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for debug information in responses
    async fn check_debug_information(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test with invalid path to trigger error pages
        let test_paths = &["/this-path-does-not-exist-404", "/debug-test-123", "/error-test"];

        for path in test_paths {
            let test_url = if url.ends_with('/') {
                format!("{}{}", url.trim_end_matches('/'), path)
            } else {
                format!("{}{}", url, path)
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();

                    // Check for debug mode indicators
                    let debug_indicators = &[
                        ("debug mode", "Debug mode enabled"),
                        ("development mode", "Development mode enabled"),
                        ("stack trace", "Stack trace exposed"),
                        ("exception", "Exception details exposed"),
                        ("error in", "Error path disclosure"),
                        ("line ", "Code line number disclosure"),
                        ("file:", "File path disclosure"),
                        ("\\laravel\\", "Laravel framework exposed"),
                        ("\\vendor\\", "Vendor path exposed"),
                        ("django", "Django framework exposed"),
                        ("rails", "Rails framework exposed"),
                        ("node_modules", "Node.js structure exposed"),
                        ("wp-content", "WordPress structure exposed"),
                        ("wordpress", "WordPress exposed"),
                    ];

                    for (indicator, desc) in debug_indicators {
                        if text_lower.contains(indicator) {
                            report.add_finding(Vuln {
                                severity: if text_lower.contains("stack trace") || text_lower.contains("exception") {
                                    VulnSeverity::High
                                } else {
                                    VulnSeverity::Medium
                                },
                                title: format!("Debug Information Disclosure: {}", desc),
                                description: format!(
                                    "Debug information exposed in error response at {}. Found indicator: '{}'",
                                    test_url, indicator
                                ),
                                location: Some(test_url),
                                recommendation: Some("Disable debug mode in production. Use custom error pages that do not reveal internal details.".to_string()),
                                cwe: Some("CWE-209".to_string()),
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

    /// Check for stack traces in error responses
    async fn check_stack_traces(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Trigger various types of errors
        let error_tests = &[
            ("/?id=<script>", "XSS attempt"),
            ("/?id=' OR '1'='1", "SQLi attempt"),
            ("/?path=../../../etc/passwd", "Path traversal attempt"),
            ("/api/test", "API test"),
            ("/nonexistent-xyz-123", "404 trigger"),
        ];

        for (suffix, desc) in error_tests {
            let test_url = format!("{}{}", url.trim_end_matches('/'), suffix);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();

                    // Stack trace patterns
                    let stack_patterns = &[
                        "at ",
                        "call stack",
                        "stacktrace",
                        "trace:",
                        "#0 ",
                        "#1 ",
                        "thrown in",
                        "called from",
                        "backtrace",
                    ];

                    let has_stack_trace = stack_patterns.iter().any(|p| text_lower.contains(p));

                    if has_stack_trace {
                        // Extract any file paths
                        let file_pattern = Regex::new(r"[A-Za-z]:\\[\w\\./-]+|/[\w/.-]+\.(?:php|js|py|rb|java|go|rs)").unwrap();
                        let _files: Vec<_> = file_pattern.find_iter(&text).map(|m| m.as_str()).collect();

                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Stack Trace Disclosure".to_string(),
                            description: format!(
                                "Full stack trace exposed via {} error. Internal file paths and function names visible.",
                                desc
                            ),
                            location: Some(test_url),
                            recommendation: Some("Disable detailed error messages. Implement custom error handlers. Never expose stack traces in production.".to_string()),
                            cwe: Some("CWE-209".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for environment variable leakage
    async fn check_environment_leak(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let disclosure_patterns = &[
            DisclosurePattern {
                pattern: "DB_PASSWORD",
                description: "Database password leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "DATABASE_URL",
                description: "Database connection string leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "API_KEY",
                description: "API key leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "SECRET_KEY",
                description: "Secret key leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "AWS_ACCESS_KEY",
                description: "AWS access key leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "AWS_SECRET",
                description: "AWS secret leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "PRIVATE_KEY",
                description: "Private key leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "JWT_SECRET",
                description: "JWT secret leaked",
                severity: VulnSeverity::High,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "SESSION_SECRET",
                description: "Session secret leaked",
                severity: VulnSeverity::High,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "REDIS_URL",
                description: "Redis connection leaked",
                severity: VulnSeverity::High,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "MAIL_PASSWORD",
                description: "Email password leaked",
                severity: VulnSeverity::High,
                cwe: "CWE-200",
            },
            DisclosurePattern {
                pattern: "STRIPE_SECRET",
                description: "Stripe secret leaked",
                severity: VulnSeverity::Critical,
                cwe: "CWE-200",
            },
        ];

        // Check main page
        if let Ok(response) = self.client.get(url).send().await {
            if let Ok(text) = response.text().await {
                let text_upper = text.to_uppercase();

                for pattern in disclosure_patterns {
                    if text_upper.contains(pattern.pattern) {
                        report.add_finding(Vuln {
                            severity: pattern.severity,
                            title: format!("Environment Variable Leak: {}", pattern.pattern),
                            description: format!(
                                "Environment variable '{}' found in response. {}",
                                pattern.pattern, pattern.description
                            ),
                            location: Some(url.to_string()),
                            recommendation: Some("Never expose environment variables in responses. Use secure configuration management. Sanitize all debug output.".to_string()),
                            cwe: Some(pattern.cwe.to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for .git directory exposure
    async fn check_git_exposure(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let git_paths = &[
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.git/logs/HEAD",
            "/.git/refs/heads/master",
            "/.gitignore",
            "/.git/",
        ];

        for path in git_paths {
            let git_url = if base_url.ends_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else {
                format!("{}{}", base_url, path)
            };

            if let Ok(response) = self.client.get(&git_url).send().await {
                let status = response.status().as_u16();

                if status == 200 {
                    if let Ok(text) = response.text().await {
                        let text_lower = text.to_lowercase();

                        if text_lower.contains("[core]")
                            || text_lower.contains("repository")
                            || text_lower.contains("ref:")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: ".git Directory Exposed".to_string(),
                                description: format!(
                                    "Git metadata is accessible at {}. The entire repository history can be downloaded.",
                                    git_url
                                ),
                                location: Some(git_url),
                                recommendation: Some("Ensure .git directory is not deployed. Use .gitignore properly. Configure web server to deny access to dotfiles.".to_string()),
                                cwe: Some("CWE-530".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for backup files exposure
    async fn check_backup_files(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let backup_patterns = &[
            ("index.php.bak", "PHP backup"),
            ("index.php~", "PHP temp file"),
            ("index.php.old", "PHP old version"),
            ("backup.sql", "SQL backup"),
            ("backup.zip", "Zip backup"),
            ("backup.tar.gz", "Archive backup"),
            ("dump.sql", "Database dump"),
            ("database.sql", "Database export"),
            ("db_backup.sql", "Named backup"),
            (".bak", "Generic backup"),
            (".backup", "Generic backup dir"),
            ("_backup", "Backup folder"),
            ("config.php.bak", "Config backup"),
            ("config.bak", "Config backup"),
            ("wp-config.php.bak", "WordPress config"),
            ("settings.py.bak", "Python config"),
        ];

        for (pattern, desc) in backup_patterns {
            let backup_url = if base_url.ends_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), pattern)
            } else {
                format!("{}/{}", base_url, pattern)
            };

            if let Ok(response) = self.client.get(&backup_url).send().await {
                if response.status().as_u16() == 200 {
                    report.add_finding(Vuln {
                        severity: if pattern.contains("sql") || pattern.contains("zip") || pattern.contains("tar") {
                            VulnSeverity::Critical
                        } else if pattern.contains("config") {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        },
                        title: format!("Backup File Exposed: {}", desc),
                        description: format!(
                            "Backup file accessible at {}. May contain sensitive source code or data.",
                            backup_url
                        ),
                        location: Some(backup_url),
                        recommendation: Some("Remove backup files from production. Use .gitignore for backup files. Implement proper deployment procedures.".to_string()),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check for configuration file exposure
    async fn check_config_exposure(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let config_files = &[
            ("/config.php", "PHP config"),
            ("/wp-config.php", "WordPress config"),
            ("/application/config/database.php", "CI database config"),
            ("/app/config/parameters.yml", "Symfony parameters"),
            ("/config/database.yml", "Rails database config"),
            ("/settings.py", "Django settings"),
            ("/.env.local", "Local environment"),
            ("/.env.production", "Production environment"),
            ("/config.ini", "INI configuration"),
            ("/config.json", "JSON configuration"),
            ("/application.properties", "Java properties"),
            ("/WEB-INF/web.xml", "Java web config"),
            ("/META-INF/context.xml", "Tomcat context"),
        ];

        for (path, desc) in config_files {
            let config_url = if base_url.ends_with('/') {
                format!("{}{}", base_url.trim_end_matches('/'), path)
            } else {
                format!("{}{}", base_url, path)
            };

            if let Ok(response) = self.client.get(&config_url).send().await {
                if response.status().as_u16() == 200 {
                    if let Ok(text) = response.text().await {
                        let text_lower = text.to_lowercase();

                        // Check for config content indicators
                        let has_config_content = text_lower.contains("password")
                            || text_lower.contains("database")
                            || text_lower.contains("api_key")
                            || text_lower.contains("secret")
                            || text_lower.contains("host")
                            || text_lower.contains("<configuration>");

                        if has_config_content {
                            report.add_finding(Vuln {
                                severity: if text_lower.contains("password") || text_lower.contains("secret") {
                                    VulnSeverity::Critical
                                } else {
                                    VulnSeverity::High
                                },
                                title: format!("Configuration File Exposed: {}", desc),
                                description: format!(
                                    "Configuration file accessible at {}. May contain credentials or sensitive configuration.",
                                    config_url
                                ),
                                location: Some(config_url),
                                recommendation: Some("Restrict access to configuration files. Use environment variables for secrets. Deploy minimal configuration to production.".to_string()),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for source code leak
    async fn check_source_code_leak(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test for source file access
        let source_extensions = &[
            ".php", ".asp", ".aspx", ".jsp", ".js", ".ts", ".py", ".rb", ".go", ".rs",
        ];

        let common_files = &["index", "main", "app", "config", "admin", "dashboard"];

        for ext in source_extensions {
            for file in common_files {
                let source_url = if base_url.ends_with('/') {
                    format!("{}{}{}", base_url.trim_end_matches('/'), file, ext)
                } else {
                    format!("{}/{}{}", base_url, file, ext)
                };

                if let Ok(response) = self.client.get(&source_url).send().await {
                    if response.status().as_u16() == 200 {
                        if let Ok(text) = response.text().await {
                            let text_lower = text.to_lowercase();

                            // Check for source code indicators
                            let is_source = text_lower.contains("<?php")
                                || text_lower.contains("function ")
                                || text_lower.contains("class ")
                                || text_lower.contains("import ")
                                || text_lower.contains("require")
                                || text_lower.contains("def ")
                                || text_lower.contains("public ");

                            if is_source {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Medium,
                                    title: "Source Code Exposure".to_string(),
                                    description: format!(
                                        "Source file accessible at {}. Source code may be exposed.",
                                        source_url
                                    ),
                                    location: Some(source_url),
                                    recommendation: Some("Ensure source files are not directly accessible. Use proper routing. Disable directory listing.".to_string()),
                                    cwe: Some("CWE-200".to_string()),
                                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                                });
                            }
                        }
                    }
                }
            }

            // Break after finding one source file
            if !report.findings.is_empty() {
                break;
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
        let scanner = DisclosureScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }
}
