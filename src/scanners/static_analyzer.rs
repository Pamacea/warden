//! Static code analysis scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;
use std::fs;

pub struct StaticScanner {
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
        self.analyze_python_files(path, &mut report)?;

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
