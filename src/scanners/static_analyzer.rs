//! Static code analysis scanner
//!
//! This scanner performs pattern-based static analysis on source code files.
//! It uses parallel processing with `rayon` for efficient multi-core scanning
//! and respects `.gitignore` files via the `ignore` crate (same as ripgrep).

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use ignore::Walk;
use rayon::prelude::*;
use std::path::Path;

/// Result from analyzing a single file
#[derive(Debug, Clone)]
struct FileAnalysisResult {
    /// Path to the file
    path: String,
    /// Findings discovered in this file
    findings: Vec<Vuln>,
}

/// Parallel file analyzer using rayon
struct ParallelFileAnalyzer {
    /// Maximum number of threads to use
    max_threads: usize,
}

impl ParallelFileAnalyzer {
    /// Create a new parallel analyzer
    fn new(config: &ScannerConfig) -> Self {
        Self {
            max_threads: config.concurrency,
        }
    }

    /// Set up the thread pool
    fn setup_thread_pool(&self) {
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.max_threads)
            .build_global()
            .ok();
    }
}

/// Language detector for file extensions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Php,
}

impl Language {
    /// Detect language from file extension
    fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "rs" => Some(Language::Rust),
            "js" | "jsx" | "mjs" => Some(Language::JavaScript),
            "ts" | "tsx" => Some(Language::TypeScript),
            "py" => Some(Language::Python),
            "go" => Some(Language::Go),
            "java" => Some(Language::Java),
            "php" => Some(Language::Php),
            _ => None,
        }
    }

    /// Get file extensions for this language
    fn extensions(&self) -> &[&str] {
        match self {
            Language::Rust => &["rs"],
            Language::JavaScript => &["js", "jsx", "mjs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Python => &["py"],
            Language::Go => &["go"],
            Language::Java => &["java"],
            Language::Php => &["php"],
        }
    }
}

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

        // Set up parallel processing
        let analyzer = ParallelFileAnalyzer::new(&self.config);
        analyzer.setup_thread_pool();

        // Collect all files to analyze (respects .gitignore via ignore crate)
        let files: Vec<(String, Language)> = Walk::new(path)
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                // Skip directories and non-files
                if !entry.file_type().map_or(false, |ft| ft.is_file()) {
                    return false;
                }

                // Check extension
                entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .and_then(Language::from_extension)
                    .is_some()
            })
            .map(|entry| {
                let path_str = entry.path().display().to_string();
                let lang = entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .and_then(Language::from_extension)
                    .expect("Language should be valid after filter");
                (path_str, lang)
            })
            .collect();

        // Process files in parallel using rayon
        let findings: Vec<Vuln> = files
            .par_iter() // Parallel iterator
            .filter_map(|(path, lang)| {
                // Read and analyze each file
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|content| Self::analyze_file(path, *lang, &content))
            })
            .flatten()
            .collect();

        // Add all findings to the report
        for finding in findings {
            report.add_finding(finding);
        }

        Ok(report)
    }

    /// Analyze a single file and return findings
    fn analyze_file(path: &str, language: Language, content: &str) -> Option<Vec<Vuln>> {
        let mut findings = Vec::new();

        match language {
            Language::Rust => Self::analyze_rust_content(path, content, &mut findings),
            Language::JavaScript => Self::analyze_js_content(path, content, &mut findings),
            Language::TypeScript => {
                Self::analyze_ts_content(path, content, &mut findings);
            }
            Language::Python => Self::analyze_python_content(path, content, &mut findings),
            Language::Go => Self::analyze_go_content(path, content, &mut findings),
            Language::Java => Self::analyze_java_content(path, content, &mut findings),
            Language::Php => Self::analyze_php_content(path, content, &mut findings),
        }

        if findings.is_empty() {
            None
        } else {
            Some(findings)
        }
    }

    /// Rust-specific analysis
    fn analyze_rust_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Count unsafe blocks
        let unsafe_count = content.matches("unsafe").count();
        if unsafe_count > 0 {
            findings.push(Vuln {
                severity: VulnSeverity::Info,
                title: format!("Unsafe Rust code detected ({} occurrences)", unsafe_count),
                description: format!("File contains unsafe Rust blocks: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Review unsafe code for memory safety issues".to_string()),
                cwe: Some("CWE-119".to_string()),
                owasp: None,
            });
        }

        // Check for unwrap calls
        if content.contains(".unwrap()") || content.contains(".expect(") {
            findings.push(Vuln {
                severity: VulnSeverity::Low,
                title: "Potential panic with unwrap/expect".to_string(),
                description: format!("File contains unwrap/expect calls: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Consider using pattern matching or ? operator".to_string()),
                cwe: Some("CWE-720".to_string()),
                owasp: None,
            });
        }
    }

    /// JavaScript-specific analysis
    fn analyze_js_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for eval
        if content.contains("eval(") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Use of eval() detected".to_string(),
                description: format!("File uses eval(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Avoid eval() - use safer alternatives".to_string()),
                cwe: Some("CWE-95".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for innerHTML
        if content.contains("innerHTML") {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "Use of innerHTML detected".to_string(),
                description: format!("File uses innerHTML: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use textContent or sanitize input".to_string()),
                cwe: Some("CWE-79".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for dangerous APIs
        for api in &["dangerouslySetInnerHTML", "document.write"] {
            if content.contains(api) {
                findings.push(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Use of {} detected", api),
                    description: format!("File uses {}: {}", api, path),
                    location: Some(path.to_string()),
                    recommendation: Some("Use safer alternatives".to_string()),
                    cwe: Some("CWE-79".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }
    }

    /// TypeScript-specific analysis
    fn analyze_ts_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for eval
        if content.contains("eval(") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "TypeScript: Use of eval() detected".to_string(),
                description: format!("File uses eval(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Avoid eval() - use safer alternatives".to_string()),
                cwe: Some("CWE-95".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for innerHTML
        if content.contains("innerHTML") || content.contains("dangerouslySetInnerHTML") {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "TypeScript: XSS via innerHTML detected".to_string(),
                description: format!("File uses innerHTML: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use textContent or React's safe rendering".to_string()),
                cwe: Some("CWE-79".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for any types
        let any_count = content.matches(": any").count()
            + content.matches(" as any").count()
            + content.matches("<any>").count();

        if any_count > 0 {
            findings.push(Vuln {
                severity: VulnSeverity::Low,
                title: format!("TypeScript: {} 'any' type(s) detected", any_count),
                description: format!("File uses 'any' type: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use proper types instead of 'any' for type safety".to_string()),
                cwe: None,
                owasp: None,
            });
        }

        // Check for @ts-ignore or @ts-nocheck
        if content.contains("@ts-ignore") || content.contains("@ts-nocheck") {
            findings.push(Vuln {
                severity: VulnSeverity::Low,
                title: "TypeScript: @ts-ignore/@ts-nocheck detected".to_string(),
                description: format!("TypeScript checks disabled: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Remove @ts-ignore and fix type errors properly".to_string()),
                cwe: None,
                owasp: None,
            });
        }
    }

    /// Python-specific analysis
    fn analyze_python_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for exec
        if content.contains("exec(") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Use of exec() detected".to_string(),
                description: format!("File uses exec(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Avoid exec() - use safer alternatives".to_string()),
                cwe: Some("CWE-95".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for shell=True
        if content.contains("shell=True") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "shell=True detected in subprocess".to_string(),
                description: format!("File uses shell=True: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Avoid shell=True - use list arguments".to_string()),
                cwe: Some("CWE-78".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }
    }

    /// Go-specific analysis
    fn analyze_go_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for exec.Command with user input
        if content.contains("exec.Command(")
            && (content.contains("+") || content.contains("fmt.") || content.contains("args..."))
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Go: Potential command injection via exec.Command".to_string(),
                description: format!("File uses exec.Command with variables: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Validate and sanitize command arguments. Use exec.CommandContext with explicit paths.".to_string()),
                cwe: Some("CWE-78".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for sql.Open without proper escaping
        if content.contains("sql.Open(")
            && (content.contains("fmt.Sprintf") || content.contains("+") || content.contains("+= \""))
            && (content.contains("SELECT") || content.contains("INSERT") || content.contains("UPDATE"))
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Go: Potential SQL injection in sql query".to_string(),
                description: format!("File constructs SQL queries with concatenation: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use parameterized queries or prepared statements.".to_string()),
                cwe: Some("CWE-89".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for ReadAll
        if content.contains("ioutil.ReadAll(") || content.contains("io.ReadAll(") {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "Go: Potential DoS via ReadAll on unbounded input".to_string(),
                description: format!("File uses ReadAll: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use io.Reader with size limits or io.LimitReader.".to_string()),
                cwe: Some("CWE-400".to_string()),
                owasp: Some("A04:2021 - Unrestricted Resource Consumption".to_string()),
            });
        }

        // Check for weak crypto
        for crypto in &["md5", "sha1", "DES", "RC4"] {
            if content.contains(crypto) {
                findings.push(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Go: Weak cryptographic algorithm ({})", crypto),
                    description: format!("File uses weak crypto: {}", path),
                    location: Some(path.to_string()),
                    recommendation: Some("Use SHA-256 or stronger for cryptographic operations.".to_string()),
                    cwe: Some("CWE-327".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
                break;
            }
        }
    }

    /// Java-specific analysis
    fn analyze_java_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for SQL injection with Statement
        if content.contains("Statement")
            && content.contains("execute(")
            && (content.contains("+") || content.contains("concat("))
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Java: SQL injection via Statement".to_string(),
                description: format!("File uses Statement with string concatenation: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use PreparedStatement with parameterized queries.".to_string()),
                cwe: Some("CWE-89".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for Runtime.exec()
        if content.contains("Runtime.getRuntime().exec(") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Java: Command injection via Runtime.exec()".to_string(),
                description: format!("File uses Runtime.exec(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use ProcessBuilder with proper input validation.".to_string()),
                cwe: Some("CWE-78".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for deserialization of untrusted data
        if content.contains("ObjectInputStream") || content.contains("XMLDecoder") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "Java: Unsafe deserialization detected".to_string(),
                description: format!("File uses unsafe deserialization: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use safe deserialization practices. Validate input types. Implement length limits.".to_string()),
                cwe: Some("CWE-502".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        // Check for weak crypto
        for crypto in &["DES", "RC4", "MD5", "SHA1"] {
            if content.contains(crypto) {
                findings.push(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Java: Weak cryptographic algorithm ({})", crypto),
                    description: format!("File uses weak crypto: {}", path),
                    location: Some(path.to_string()),
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
            || content.contains("secret=\"")
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "Java: Potential hardcoded credential".to_string(),
                description: format!("File may contain hardcoded password: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use environment variables or secure vaults for credentials.".to_string()),
                cwe: Some("CWE-798".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }
    }

    /// PHP-specific analysis
    fn analyze_php_content(path: &str, content: &str, findings: &mut Vec<Vuln>) {
        // Check for eval() - extremely dangerous in PHP
        if content.contains("eval(") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "PHP: eval() detected - CRITICAL".to_string(),
                description: format!("File uses eval(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("NEVER use eval() in PHP. It allows arbitrary code execution.".to_string()),
                cwe: Some("CWE-95".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for dangerous functions
        for func in &["exec(", "system(", "shell_exec(", "passthru("] {
            if content.contains(func) {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("PHP: {}() detected - Command injection risk", func.trim_end_matches("(")),
                    description: format!("File uses {}: {}", func, path),
                    location: Some(path.to_string()),
                    recommendation: Some("Use escapeshellarg() or proper parameterized functions.".to_string()),
                    cwe: Some("CWE-78".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }

        // Check for $_GET, $_POST directly in SQL
        if (content.contains("$_GET[") || content.contains("$_POST[") || content.contains("$_REQUEST["))
            && (content.contains("mysql_query") || content.contains("mysqli_query") || content.contains("pg_query"))
        {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "PHP: SQL injection via direct user input".to_string(),
                description: format!("File uses user input directly in SQL query: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use prepared statements or parameterized queries (mysqli_prepare, PDO)".to_string()),
                cwe: Some("CWE-89".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for unserialize()
        if content.contains("unserialize(") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "PHP: unserialize() detected - Object injection risk".to_string(),
                description: format!("File uses unserialize(): {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Avoid unserialize() with user input. Use JSON instead.".to_string()),
                cwe: Some("CWE-502".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        // Check for include/require with variables
        if content.contains("include $") || content.contains("require $") {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "PHP: File inclusion via variable".to_string(),
                description: format!("File uses dynamic include/require: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Validate file paths against a whitelist. Avoid user input in file paths.".to_string()),
                cwe: Some("CWE-22".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for weak password hashing
        if (content.contains("md5(") || content.contains("sha1("))
            && (content.contains("password") || content.contains("pass"))
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "PHP: Weak password hashing detected".to_string(),
                description: format!("File uses md5/sha1 for passwords: {}", path),
                location: Some(path.to_string()),
                recommendation: Some("Use password_hash() with PASSWORD_DEFAULT (bcrypt/argon2).".to_string()),
                cwe: Some("CWE-262".to_string()),
                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }
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

    #[test]
    fn test_language_detection() {
        assert_eq!(Language::from_extension("rs"), Some(Language::Rust));
        assert_eq!(Language::from_extension("js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension("ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension("py"), Some(Language::Python));
        assert_eq!(Language::from_extension("go"), Some(Language::Go));
        assert_eq!(Language::from_extension("java"), Some(Language::Java));
        assert_eq!(Language::from_extension("php"), Some(Language::Php));
        assert_eq!(Language::from_extension("txt"), None);
    }

    #[test]
    fn test_rust_analysis() {
        let mut findings = Vec::new();
        StaticScanner::analyze_rust_content(
            "test.rs",
            "fn main() { unsafe { println!(\"hello\"); } }",
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("unsafe"));
    }

    #[test]
    fn test_python_analysis() {
        let mut findings = Vec::new();
        StaticScanner::analyze_python_content("test.py", "exec('print(\"hello\")')", &mut findings);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("exec"));
    }

    #[test]
    fn test_parallel_analyzer_setup() {
        let config = ScannerConfig::new().with_concurrency(4);
        let analyzer = ParallelFileAnalyzer::new(&config);
        assert_eq!(analyzer.max_threads, 4);
    }
}
