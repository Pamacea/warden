//! Static code analysis scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use std::path::Path;

pub struct StaticScanner {
    config: ScannerConfig,
}

impl StaticScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Find source files
        let rust_files = crate::utils::find_files(path, r"\.rs$")?;
        let js_files = crate::utils::find_files(path, r"\.(js|ts|jsx|tsx)$")?;
        let py_files = crate::utils::find_files(path, r"\.py$")?;

        // Scan Rust files for unsafe blocks
        for file in rust_files {
            report.merge(self.scan_rust_file(&file)?);
        }

        // Scan JavaScript files for dangerous patterns
        for file in js_files {
            report.merge(self.scan_js_file(&file)?);
        }

        // Scan Python files for dangerous patterns
        for file in py_files {
            report.merge(self.scan_python_file(&file)?);
        }

        Ok(report)
    }

    fn scan_rust_file(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let content = crate::utils::read_file_limited(path, 1024 * 1024)?;

        // Check for unsafe blocks
        let unsafe_count = content.matches("unsafe").count();

        if unsafe_count > 10 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Excessive use of unsafe blocks".to_string(),
                description: format!("Found {} unsafe blocks", unsafe_count),
                location: Some(path.display().to_string()),
                recommendation: Some("Minimize use of unsafe code. Document safety invariants.".to_string()),
                cwe: Some("CWE-242".to_string()),
                owasp: None,
            });
        }

        // Check for unwrap() calls
        let unwrap_count = content.matches(".unwrap()").count() + content.matches(".unwrap").count();

        if unwrap_count > 5 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: "Excessive use of unwrap()".to_string(),
                description: format!("Found {} unwrap() calls", unwrap_count),
                location: Some(path.display().to_string()),
                recommendation: Some("Use proper error handling instead of unwrap()".to_string()),
                cwe: Some("CWE-242".to_string()),
                owasp: None,
            });
        }

        Ok(report)
    }

    fn scan_js_file(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let content = crate::utils::read_file_limited(path, 1024 * 1024)?;

        // Check for eval()
        if content.contains("eval(") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Use of eval()".to_string(),
                description: "eval() can execute arbitrary code".to_string(),
                location: Some(path.display().to_string()),
                recommendation: Some("Avoid using eval(). Use safer alternatives.".to_string()),
                cwe: Some("CWE-94".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for innerHTML
        if content.contains(".innerHTML") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Use of innerHTML".to_string(),
                description: "innerHTML can lead to XSS vulnerabilities".to_string(),
                location: Some(path.display().to_string()),
                recommendation: Some("Use textContent or sanitize input".to_string()),
                cwe: Some("CWE-79".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        Ok(report)
    }

    fn scan_python_file(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let content = crate::utils::read_file_limited(path, 1024 * 1024)?;

        // Check for exec()
        if content.contains("exec(") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Use of exec()".to_string(),
                description: "exec() can execute arbitrary code".to_string(),
                location: Some(path.display().to_string()),
                recommendation: Some("Avoid using exec()".to_string()),
                cwe: Some("CWE-94".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for shell=True
        if content.contains("shell=True") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "shell=True in subprocess".to_string(),
                description: "shell=True can lead to command injection".to_string(),
                location: Some(path.display().to_string()),
                recommendation: Some("Avoid shell=True or use argument lists".to_string()),
                cwe: Some("CWE-78".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        Ok(report)
    }
}
