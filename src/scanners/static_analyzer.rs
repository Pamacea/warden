//! Static code analysis scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;
use std::fs;

pub struct StaticScanner {
    #[allow(dead_code)]
    config: ScannerConfig,
}

impl StaticScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Basic pattern-based analysis (without AST)
        self.analyze_rust_files(path, &mut report)?;
        self.analyze_javascript_files(path, &mut report)?;
        self.analyze_typescript_files(path, &mut report)?;
        self.analyze_python_files(path, &mut report)?;
        self.analyze_go_files(path, &mut report)?;
        self.analyze_java_files(path, &mut report)?;
        self.analyze_php_files(path, &mut report)?;

        Ok(report)
    }

    fn analyze_rust_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|s| s == "rs").unwrap_or(false));

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Count unsafe blocks - detect both "unsafe " and "unsafe{"
                let unsafe_count = content.matches("unsafe").count();

                if unsafe_count > 0 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: format!("Unsafe Rust code detected ({} occurrences)", unsafe_count),
                        description: format!("File contains unsafe Rust blocks: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Review unsafe code for memory safety issues".to_string()),
                        cwe: Some("CWE-119".to_string()),
                        owasp: None,
                    });
                }

                // Check for unwrap calls
                if content.contains(".unwrap()") || content.contains(".expect(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Potential panic with unwrap/expect".to_string(),
                        description: format!("File contains unwrap/expect calls: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Consider using pattern matching or ? operator".to_string()),
                        cwe: Some("CWE-720".to_string()),
                        owasp: None,
                    });
                }
            }
        }

        Ok(())
    }

    fn analyze_javascript_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension().map(|s| s == "js" || s == "jsx" || s == "ts" || s == "tsx").unwrap_or(false)
            });

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for eval
                if content.contains("eval(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Use of eval() detected".to_string(),
                        description: format!("File uses eval(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Avoid eval() - use safer alternatives".to_string()),
                        cwe: Some("CWE-95".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for innerHTML
                if content.contains("innerHTML") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Use of innerHTML detected".to_string(),
                        description: format!("File uses innerHTML: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use textContent or sanitize input".to_string()),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for dangerous APIs
                let dangerous = ["dangerouslySetInnerHTML", "document.write"];
                for api in &dangerous {
                    if content.contains(api) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Use of {} detected", api),
                            description: format!("File uses {}: {}", api, entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Use safer alternatives".to_string()),
                            cwe: Some("CWE-79".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_python_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|s| s == "py").unwrap_or(false));

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for exec
                if content.contains("exec(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Use of exec() detected".to_string(),
                        description: format!("File uses exec(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Avoid exec() - use safer alternatives".to_string()),
                        cwe: Some("CWE-95".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for shell=True
                if content.contains("shell=True") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "shell=True detected in subprocess".to_string(),
                        description: format!("File uses shell=True: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Avoid shell=True - use list arguments".to_string()),
                        cwe: Some("CWE-78".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(())
    }

    /// TypeScript-specific analysis - enhanced for v0.3.0
    fn analyze_typescript_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path().extension().map(|s| s == "ts" || s == "tsx").unwrap_or(false)
            });

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for eval (also in TS)
                if content.contains("eval(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "TypeScript: Use of eval() detected".to_string(),
                        description: format!("File uses eval(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Avoid eval() - use safer alternatives".to_string()),
                        cwe: Some("CWE-95".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for innerHTML (TypeScript React)
                if content.contains("innerHTML") || content.contains("dangerouslySetInnerHTML") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "TypeScript: XSS via innerHTML detected".to_string(),
                        description: format!("File uses innerHTML: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use textContent or React's safe rendering".to_string()),
                        cwe: Some("CWE-79".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for any types (TypeScript anti-pattern)
                let any_count = content.matches(": any").count()
                    + content.matches(" as any").count()
                    + content.matches("<any>").count();

                if any_count > 0 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: format!("TypeScript: {} 'any' type(s) detected", any_count),
                        description: format!("File uses 'any' type: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use proper types instead of 'any' for type safety".to_string()),
                        cwe: None,
                        owasp: None,
                    });
                }

                // Check for @ts-ignore or @ts-nocheck
                if content.contains("@ts-ignore") || content.contains("@ts-nocheck") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "TypeScript: @ts-ignore/@ts-nocheck detected".to_string(),
                        description: format!("TypeScript checks disabled: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Remove @ts-ignore and fix type errors properly".to_string()),
                        cwe: None,
                        owasp: None,
                    });
                }

                // Check for non-null assertions (!)
                if content.contains("!") && content.contains("!= null") == false {
                    let non_null_count = content.matches("!").count() - content.matches("!=").count();
                    if non_null_count > 10 {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("TypeScript: {} non-null assertion(s) detected", non_null_count),
                            description: format!("File uses ! operator: {}", entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Consider optional chaining (?.) or proper null checks".to_string()),
                            cwe: None,
                            owasp: None,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Go-specific analysis - new for v0.3.0
    fn analyze_go_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|s| s == "go").unwrap_or(false));

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for exec.Command with user input
                if content.contains("exec.Command(") {
                    // Check if command includes variables
                    if content.contains("exec.Command(")
                        && (content.contains("+") || content.contains("fmt.") || content.contains("args...")) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Go: Potential command injection via exec.Command".to_string(),
                            description: format!("File uses exec.Command with variables: {}", entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Validate and sanitize command arguments. Use exec.CommandContext with explicit paths.".to_string()),
                            cwe: Some("CWE-78".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }

                // Check for sql.Open without proper escaping
                if content.contains("sql.Open(")
                    && (content.contains("fmt.Sprintf") || content.contains("+") || content.contains("+= \""))
                    && (content.contains("SELECT") || content.contains("INSERT") || content.contains("UPDATE")) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Go: Potential SQL injection in sql query".to_string(),
                        description: format!("File constructs SQL queries with concatenation: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use parameterized queries or prepared statements.".to_string()),
                        cwe: Some("CWE-89".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for ioutil.ReadAll with unbounded input
                if content.contains("ioutil.ReadAll(") || content.contains("io.ReadAll(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Go: Potential DoS via ReadAll on unbounded input".to_string(),
                        description: format!("File uses ReadAll: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use io.Reader with size limits or io.LimitReader.".to_string()),
                        cwe: Some("CWE-400".to_string()),
                        owasp: Some("A04:2021 - Unrestricted Resource Consumption".to_string()),
                    });
                }

                // Check for os.Exec without proper cleanup
                if content.contains("os.Exec(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Go: Use of os.Exec detected".to_string(),
                        description: format!("File uses os.Exec: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("os.Exec replaces the current process. Use exec.Command for safer process spawning.".to_string()),
                        cwe: Some("CWE-78".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for weak crypto
                let weak_crypto = ["md5", "sha1", "DES", "RC4"];
                for crypto in &weak_crypto {
                    if content.contains(crypto) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Go: Weak cryptographic algorithm ({})", crypto),
                            description: format!("File uses weak crypto: {}", entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Use SHA-256 or stronger for cryptographic operations.".to_string()),
                            cwe: Some("CWE-327".to_string()),
                            owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Java-specific analysis - new for v0.3.0
    fn analyze_java_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|s| s == "java").unwrap_or(false));

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for SQL injection with Statement
                if content.contains("Statement") && content.contains("execute(") {
                    if content.contains("+") || content.contains("concat(") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Java: SQL injection via Statement".to_string(),
                            description: format!("File uses Statement with string concatenation: {}", entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Use PreparedStatement with parameterized queries.".to_string()),
                            cwe: Some("CWE-89".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }

                // Check for Runtime.exec()
                if content.contains("Runtime.getRuntime().exec(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Java: Command injection via Runtime.exec()".to_string(),
                        description: format!("File uses Runtime.exec(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use ProcessBuilder with proper input validation.".to_string()),
                        cwe: Some("CWE-78".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for deserialization of untrusted data
                if content.contains("ObjectInputStream") || content.contains("XMLDecoder") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: "Java: Unsafe deserialization detected".to_string(),
                        description: format!("File uses unsafe deserialization: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use safe deserialization practices. Validate input types. Implement length limits.".to_string()),
                        cwe: Some("CWE-502".to_string()),
                        owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
                    });
                }

                // Check for weak crypto
                let weak_crypto = ["DES", "RC4", "MD5", "SHA1"];
                for crypto in &weak_crypto {
                    if content.contains(crypto) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Java: Weak cryptographic algorithm ({})", crypto),
                            description: format!("File uses weak crypto: {}", entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Use AES-256, SHA-256 or stronger for cryptographic operations.".to_string()),
                            cwe: Some("CWE-327".to_string()),
                            owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                        });
                        break;
                    }
                }

                // Check for hardcoded passwords
                if content.contains("password = \"")
                    || content.contains("password=\"")
                    || content.contains("secret=\"") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Java: Potential hardcoded credential".to_string(),
                        description: format!("File may contain hardcoded password: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use environment variables or secure vaults for credentials.".to_string()),
                        cwe: Some("CWE-798".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        Ok(())
    }

    /// PHP-specific analysis - new for v0.3.0
    fn analyze_php_files(&self, path: &Path, report: &mut ScanReport) -> Result<()> {
        let entries = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|s| s == "php").unwrap_or(false));

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                // Check for eval() (extremely dangerous in PHP)
                if content.contains("eval(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: "PHP: eval() detected - CRITICAL".to_string(),
                        description: format!("File uses eval(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("NEVER use eval() in PHP. It allows arbitrary code execution.".to_string()),
                        cwe: Some("CWE-95".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for exec(), system(), shell_exec(), passthru()
                let dangerous_funcs = ["exec(", "system(", "shell_exec(", "passthru("];
                for func in &dangerous_funcs {
                    if content.contains(func) {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("PHP: {}() detected - Command injection risk", func.trim_end_matches("(")),
                            description: format!("File uses {}: {}", func, entry.path().display()),
                            location: Some(entry.path().display().to_string()),
                            recommendation: Some("Use escapeshellarg() or proper parameterized functions.".to_string()),
                            cwe: Some("CWE-78".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }

                // Check for $_GET, $_POST directly in SQL
                if (content.contains("$_GET[") || content.contains("$_POST[") || content.contains("$_REQUEST["))
                    && (content.contains("mysql_query") || content.contains("mysqli_query") || content.contains("pg_query")) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: "PHP: SQL injection via direct user input".to_string(),
                        description: format!("File uses user input directly in SQL query: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use prepared statements or parameterized queries (mysqli_prepare, PDO)".to_string()),
                        cwe: Some("CWE-89".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }

                // Check for unserialize()
                if content.contains("unserialize(") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "PHP: unserialize() detected - Object injection risk".to_string(),
                        description: format!("File uses unserialize(): {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Avoid unserialize() with user input. Use JSON instead.".to_string()),
                        cwe: Some("CWE-502".to_string()),
                        owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
                    });
                }

                // Check for include/require with variables
                if content.contains("include $") || content.contains("require $") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "PHP: File inclusion via variable".to_string(),
                        description: format!("File uses dynamic include/require: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Validate file paths against a whitelist. Avoid user input in file paths.".to_string()),
                        cwe: Some("CWE-22".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }

                // Check for md5() or sha1() for passwords
                if (content.contains("md5(") || content.contains("sha1("))
                    && (content.contains("password") || content.contains("pass")) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "PHP: Weak password hashing detected".to_string(),
                        description: format!("File uses md5/sha1 for passwords: {}", entry.path().display()),
                        location: Some(entry.path().display().to_string()),
                        recommendation: Some("Use password_hash() with PASSWORD_DEFAULT (bcrypt/argon2).".to_string()),
                        cwe: Some("CWE-262".to_string()),
                        owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = StaticScanner::new(config);
        assert_eq!(scanner.config.aggressive, false);
    }
}
