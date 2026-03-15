//! Reconnaissance Scanner - Passive and Active reconnaissance

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use std::time::Duration;

pub struct ReconScanner {
    config: ScannerConfig,
}

impl ReconScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Passive reconnaissance
        report.merge(self.passive_recon(url).await?);

        // Active reconnaissance (aggressive mode)
        if self.config.aggressive {
            report.merge(self.active_recon(url).await?);
        }

        Ok(report)
    }

    /// Passive reconnaissance - information gathering without direct interaction
    async fn passive_recon(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Check for common backup files
        report.merge(self.check_backup_files(url).await?);

        // Check for exposed configuration files
        report.merge(self.check_config_exposure(url).await?);

        // Check for sensitive file extensions
        report.merge(self.check_sensitive_files(url).await?);

        Ok(report)
    }

    /// Check for backup files that might be exposed
    async fn check_backup_files(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Common backup file patterns
        let backup_extensions = vec![
            ".bak",
            ".backup",
            ".old",
            ".orig",
            ".save",
            ".tmp",
            "~",
            ".swp",
            ".swo",
            ".bak2",
            ".copy",
            ".dist",
        ];

        let backup_filenames = vec![
            "config.bak",
            "config.php.bak",
            "config.php~",
            ".env.bak",
            ".env.backup",
            ".env.old",
            "database.sql.bak",
            "dump.sql.bak",
            "backup.sql",
            "wp-config.php.bak",
        ];

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        // Test backup extensions on common files
        let test_files = vec!["index", "config", "database", "admin", "api"];

        for file in test_files {
            for ext in &backup_extensions {
                let backup_url = format!(
                    "{}{}{}",
                    base_url.to_string().trim_end_matches('/'),
                    if file.is_empty() { "" } else { "/" },
                    format!("{}{}", file, ext)
                );

                match client.head(&backup_url).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Backup File Exposed: {}{}", file, ext),
                                description: format!("Backup file is publicly accessible at {}", backup_url),
                                location: Some(backup_url),
                                recommendation: Some("Remove backup files from production. Use .gitignore to prevent committing backups.".to_string()),
                                cwe: Some("CWE-530".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Test common backup filenames
        for filename in &backup_filenames {
            let backup_url = format!("{}/{}", base_url.to_string().trim_end_matches('/'), filename);

            match client.head(&backup_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: format!("Sensitive Backup File: {}", filename),
                            description: format!("Critical backup file is exposed: {}", filename),
                            location: Some(backup_url),
                            recommendation: Some("Immediately remove sensitive backup files from public access.".to_string()),
                            cwe: Some("CWE-530".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Check for exposed configuration files
    async fn check_config_exposure(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        let sensitive_files = vec![
            // Environment files
            ".env",
            ".env.local",
            ".env.production",
            ".env.dev",
            ".env.dist",
            // Configuration files
            "config.json",
            "config.yml",
            "config.yaml",
            "config.ini",
            "settings.json",
            "application.properties",
            "application.yml",
            "web.config",
            // Docker files
            "docker-compose.yml",
            "Dockerfile",
            ".dockerignore",
            // CI/CD files
            ".gitlab-ci.yml",
            ".travis.yml",
            "jenkins.yml",
            // Database files
            "database.yml",
            "sequelize.config.js",
            "knexfile.js",
            "migrate.sql",
            // Key files
            "id_rsa",
            "private.key",
            ".pem",
            ".key",
            // Secret files
            "secrets.yml",
            "master.key",
            "credentials.json",
            "service-account.json",
            // AWS
            ".aws/credentials",
            // Common framework configs
            "wp-config.php",
            "configuration.php",
            "settings.php",
        ];

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        for filename in sensitive_files {
            let test_url = format!("{}/{}", base_url.to_string().trim_end_matches('/'), filename);

            match client.head(&test_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        let severity = if filename.contains(".env")
                            || filename.contains("key")
                            || filename.contains("credentials")
                            || filename.contains("secret")
                        {
                            VulnSeverity::Critical
                        } else {
                            VulnSeverity::High
                        };

                        report.add_finding(Vuln {
                            severity,
                            title: format!("Sensitive Configuration File Exposed: {}", filename),
                            description: format!("Configuration file is publicly accessible: {}", filename),
                            location: Some(test_url),
                            recommendation: Some("Remove sensitive configuration files from public access. Use environment variables for secrets.".to_string()),
                            cwe: Some("CWE-532".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Check for sensitive file extensions
    async fn check_sensitive_files(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Sensitive file extensions to check
        let sensitive_extensions = vec![
            (".sql", "SQL Database File"),
            (".db", "Database File"),
            (".sqlite", "SQLite Database"),
            (".mdb", "Access Database"),
            (".key", "Private Key File"),
            (".pem", "PEM Certificate/Key"),
            (".p12", "PKCS12 Certificate"),
            (".pfx", "PFX Certificate"),
            (".csr", "Certificate Signing Request"),
            (".crt", "Certificate File"),
            (".der", "DER Certificate"),
            (".log", "Log File"),
            (".tar", "Tar Archive"),
            (".gz", "Gzip Archive"),
            (".zip", "Zip Archive"),
            (".rar", "Rar Archive"),
            (".sql.gz", "Compressed SQL Dump"),
            (".bak", "Backup File"),
        ];

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        // Test common sensitive filenames with extensions
        let base_filenames = vec![
            "backup", "dump", "database", "db", "credentials", "config",
            "secrets", "private", "keys", "cert", "data", "logs",
        ];

        for (ext, desc) in &sensitive_extensions {
            for base_name in &base_filenames {
                let test_url = format!(
                    "{}//{}.{}",
                    base_url.to_string().trim_end_matches('/'),
                    base_name,
                    ext
                );

                match client.head(&test_url).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: format!("Sensitive File Exposed: {}", desc),
                                description: format!("{} file is accessible: {}", desc, test_url),
                                location: Some(test_url),
                                recommendation: Some("Remove sensitive files from public access.".to_string()),
                                cwe: Some("CWE-532".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
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

    /// Active reconnaissance - direct interaction to discover resources
    async fn active_recon(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Directory and file fuzzing
        report.merge(self.directory_fuzzing(url).await?);

        // Common endpoint discovery
        report.merge(self.endpoint_discovery(url).await?);

        // Comment discovery in HTML/JS
        report.merge(self.comment_discovery(url).await?);

        Ok(report)
    }

    /// Directory fuzzing - discover hidden directories and files
    async fn directory_fuzzing(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;

        // Common directories to check
        let directories = vec![
            "admin", "administrator", "wp-admin", "backend", "panel", "dashboard",
            "login", "auth", "account", "user", "users",
            "config", "configuration", "settings", "setup", "install",
            "backup", "backups", "old", "archive", "tmp", "temp",
            "test", "testing", "dev", "staging", "beta",
            "api", "v1", "v2", "rest", "graphql",
            "uploads", "upload", "files", "assets", "static", "public",
            "private", "protected", "internal", "secret",
            "logs", "log", "cache", "sessions", "cookies",
            "database", "db", "sql", "data",
            ".git", ".svn", ".hg", ".env", "backup",
            "robots.txt", "sitemap.xml", ".htaccess", "web.config",
        ];

        // Check for directory listing/access
        for dir in directories.iter().take(30) {
            let test_url = format!("{}/{}", base_url.to_string().trim_end_matches('/'), dir);

            match client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();

                    // Check for 200, 301, 302, 403 (all indicate directory exists)
                    if status.is_success()
                        || status.as_u16() == 301
                        || status.as_u16() == 302
                        || status.as_u16() == 403
                    {
                        // Check for directory listing
                        if let Ok(text) = response.text().await {
                            if text.contains("Index of")
                                || text.contains("Directory Listing")
                                || text.contains("Parent Directory")
                                || text.contains("<table>")
                            {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Medium,
                                    title: format!("Directory Listing Enabled: /{}", dir),
                                    description: format!("Directory {} has listing enabled, exposing files.", dir),
                                    location: Some(test_url.clone()),
                                    recommendation: Some("Disable directory listing. Use index.html or default configuration files.".to_string()),
                                    cwe: Some("CWE-538".to_string()),
                                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                });
                            }
                        }

                        report.add_finding(Vuln {
                            severity: VulnSeverity::Low,
                            title: format!("Discovered Directory: /{}", dir),
                            description: format!("Directory found with status code {}", status),
                            location: Some(test_url),
                            recommendation: Some("Ensure this directory should be publicly accessible.".to_string()),
                            cwe: Some("CWE-200".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Endpoint discovery - find hidden API endpoints and pages
    async fn endpoint_discovery(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;

        // Common API endpoints
        let api_endpoints = vec![
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/backup",
            "/api/export",
            "/api/debug",
            "/api/test",
            "/api/status",
            "/api/health",
            "/api/metrics",
            "/api/swagger",
            "/api/graphql",
            "/api/docs",
            "/api/v1/users",
            "/api/v1/admin",
            "/admin/dashboard",
            "/admin/config",
            "/admin/users",
            "/user/profile",
            "/auth/login",
            "/auth/register",
            "/auth/reset",
            "/debug",
            "/test",
            "/metrics",
            "/health",
            "/status",
        ];

        for endpoint in api_endpoints {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), endpoint);

            match client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();

                    // Check for non-404 responses
                    if status.as_u16() != 404 {
                        // Check for admin/debug endpoints
                        if endpoint.contains("admin")
                            || endpoint.contains("debug")
                            || endpoint.contains("config")
                            || endpoint.contains("backup")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: format!("Sensitive Endpoint Discovered: {}", endpoint),
                                description: format!("Administrative or debug endpoint is accessible: {}", endpoint),
                                location: Some(test_url),
                                recommendation: Some("Restrict access to administrative endpoints. Implement proper authentication.".to_string()),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                        } else {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Info,
                                title: format!("API Endpoint Discovered: {}", endpoint),
                                description: format!("API endpoint found: {} (status: {})", endpoint, status),
                                location: Some(test_url),
                                recommendation: Some("Review and document all API endpoints. Ensure proper access controls.".to_string()),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Comment discovery - extract sensitive information from HTML/JS comments
    async fn comment_discovery(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        match client.get(url).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    // Regex patterns for HTML/JS comments
                    let _comment_patterns = vec![
                        (r#"<!--[\s\S]*?-->"#, "HTML comment"),
                        (r#"//.*"#, "Single-line JS comment"),
                        (r#"/\*[\s\S]*?\*/"#, "Multi-line JS comment"),
                        (r#"#.*"#, "Shell/Python comment"),
                    ];

                    let re_html = Regex::new(r#"<!--[\s\S]*?-->"#).unwrap();
                    let re_js_single = Regex::new(r#"//.*"#).unwrap();
                    let _re_js_multi = Regex::new(r#"/\*[\s\S]*?\*/"#).unwrap();

                    // Sensitive keywords in comments
                    let sensitive_keywords = vec![
                        "TODO", "FIXME", "BUG", "HACK", "XXX",
                        "password", "secret", "api_key", "token", "private_key",
                        "admin", "debug", "test", "remove", "delete",
                        "sql", "query", "database", "connection",
                        "localhost", "127.0.0.1", "internal",
                        "http://", "https://",
                    ];

                    // Extract HTML comments
                    for comment in re_html.find_iter(&text) {
                        let comment_text = comment.as_str();

                        for keyword in &sensitive_keywords {
                            if comment_text.to_lowercase().contains(keyword) {
                                let truncated = if comment_text.len() > 200 {
                                    format!("{}...", &comment_text[..200])
                                } else {
                                    comment_text.to_string()
                                };

                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Low,
                                    title: format!("Sensitive Information in HTML Comment ({})", keyword),
                                    description: format!("Comment contains potentially sensitive information: {}", truncated),
                                    location: Some(url.to_string()),
                                    recommendation: Some("Remove sensitive comments from production code. Use developer notes instead.".to_string()),
                                    cwe: Some("CWE-546".to_string()),
                                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                                });
                                break;
                            }
                        }
                    }

                    // Extract JS comments (look for embedded scripts)
                    if text.contains("<script") {
                        let script_re = Regex::new(r#"<script[^>]*>([\s\S]*?)</script>"#).unwrap();

                        for script in script_re.captures_iter(&text) {
                            let script_content = &script[1];

                            // Check JS comments for sensitive info
                            for comment in re_js_single.find_iter(script_content) {
                                let comment_text = comment.as_str();
                                for keyword in &sensitive_keywords {
                                    if comment_text.to_lowercase().contains(keyword)
                                        && comment_text.len() > 10
                                    {
                                        report.add_finding(Vuln {
                                            severity: VulnSeverity::Info,
                                            title: format!("JavaScript Comment Contains: {}", keyword),
                                            description: format!("JS comment may contain sensitive information: {}", comment_text),
                                            location: Some(url.to_string()),
                                            recommendation: Some("Remove sensitive comments from production JavaScript.".to_string()),
                                            cwe: Some("CWE-546".to_string()),
                                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }
}
