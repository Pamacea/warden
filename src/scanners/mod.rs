//! Scanner modules

// AST parsers - temporarily disabled
// pub mod ast_parsers;
pub mod ddos;
pub mod http;
pub mod port;
pub mod static_analyzer;
pub mod stress;

// AST parsers exports - temporarily disabled
// pub use ast_parsers::{FileDiscoverer, JsTsParser, PythonParser, RustParser, SourceLocation};
pub use ddos::DdosScanner;
pub use http::HttpScanner;
pub use port::PortScanner;
pub use static_analyzer::StaticScanner;
pub use stress::StressScanner;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

/// Scanner engine that orchestrates all scanners
pub struct ScannerEngine {
    config: ScannerConfig,
}

impl ScannerEngine {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Run HTTP security scanner
    pub async fn scan_http(&mut self, url: &str) -> Result<ScanReport> {
        let http_scanner = HttpScanner::new(self.config.clone());
        Ok(http_scanner.scan(url).await?)
    }

    /// Run port scanner
    pub async fn scan_port(&mut self, url: &str) -> Result<ScanReport> {
        let port_scanner = PortScanner::new(self.config.clone());
        Ok(port_scanner.scan(url).await?)
    }

    /// Run static code analyzer
    pub async fn scan_static(&mut self, path: &PathBuf) -> Result<ScanReport> {
        let static_scanner = StaticScanner::new(self.config.clone());
        Ok(static_scanner.scan(path).await?)
    }

    /// Run DDoS resistance scanner
    pub async fn scan_ddos(&mut self, target: &Target) -> Result<ScanReport> {
        let ddos_scanner = DdosScanner::new(self.config.clone());
        Ok(ddos_scanner.scan(target).await?)
    }

    /// Run stress testing scanner
    pub async fn scan_stress(&mut self, target: &Target) -> Result<ScanReport> {
        let stress_scanner = StressScanner::new(self.config.clone());
        Ok(stress_scanner.scan(target).await?)
    }

    /// Run all applicable scanners for the target
    pub async fn scan(&mut self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                // HTTP scanner
                if self.config.http {
                    let http_scanner = HttpScanner::new(self.config.clone());
                    report.merge(http_scanner.scan(url).await?);
                }

                // Port scanner
                if self.config.port {
                    let port_scanner = PortScanner::new(self.config.clone());
                    report.merge(port_scanner.scan(url).await?);
                }
            }
            Target::Path(path) => {
                // Static scanner
                if self.config.static_analysis {
                    let static_scanner = StaticScanner::new(self.config.clone());
                    report.merge(static_scanner.scan(path).await?);
                }
            }
        }

        // DDoS scanner
        if self.config.ddos {
            let ddos_scanner = DdosScanner::new(self.config.clone());
            report.merge(ddos_scanner.scan(target).await?);
        }

        // Stress scanner
        if self.config.stress {
            let stress_scanner = StressScanner::new(self.config.clone());
            report.merge(stress_scanner.scan(target).await?);
        }

        Ok(report)
    }
}

/// Scanner configuration
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    pub aggressive: bool,
    pub timeout: Duration,
    pub concurrency: usize,
    pub http: bool,
    pub port: bool,
    pub static_analysis: bool,
    pub ddos: bool,
    pub stress: bool,
    pub user_agent: String,
}

impl ScannerConfig {
    pub fn new() -> Self {
        Self {
            aggressive: false,
            timeout: Duration::from_secs(5),
            concurrency: 50,
            http: true,
            port: true,
            static_analysis: true,
            ddos: false,
            stress: false,
            user_agent: format!("Warden/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn with_aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_ddos(mut self, ddos: bool) -> Self {
        self.ddos = ddos;
        self
    }

    pub fn with_stress(mut self, stress: bool) -> Self {
        self.stress = stress;
        self
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Target {
    Url(String),
    Path(PathBuf),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Url(url) => write!(f, "{}", url),
            Target::Path(path) => write!(f, "{}", path.display()),
        }
    }
}

/// Vulnerability finding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vuln {
    pub severity: VulnSeverity,
    pub title: String,
    pub description: String,
    pub location: Option<String>,
    pub recommendation: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
}

/// Vulnerability severity
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl VulnSeverity {
    pub fn color(&self) -> colored::Color {
        match self {
            VulnSeverity::Critical => colored::Color::Red,
            VulnSeverity::High => colored::Color::Red,
            VulnSeverity::Medium => colored::Color::Yellow,
            VulnSeverity::Low => colored::Color::Blue,
            VulnSeverity::Info => colored::Color::White,
        }
    }
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnSeverity::Critical => write!(f, "CRITICAL"),
            VulnSeverity::High => write!(f, "HIGH"),
            VulnSeverity::Medium => write!(f, "MEDIUM"),
            VulnSeverity::Low => write!(f, "LOW"),
            VulnSeverity::Info => write!(f, "INFO"),
        }
    }
}

/// Scan report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: Target,
    pub timestamp: String,
    pub findings: Vec<Vuln>,
    pub summary: ScanSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanReport {
    pub fn new(target: Target) -> Self {
        Self {
            target,
            timestamp: chrono::Utc::now().to_rfc3339(),
            findings: Vec::new(),
            summary: ScanSummary {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
        }
    }

    pub fn merge(&mut self, mut other: ScanReport) {
        self.findings.append(&mut other.findings);
        self.recalculate_summary();
    }

    pub fn add_finding(&mut self, vuln: Vuln) {
        self.findings.push(vuln);
        self.recalculate_summary();
    }

    fn recalculate_summary(&mut self) {
        self.summary.total = self.findings.len();
        self.summary.critical = self.findings.iter().filter(|v| v.severity == VulnSeverity::Critical).count();
        self.summary.high = self.findings.iter().filter(|v| v.severity == VulnSeverity::High).count();
        self.summary.medium = self.findings.iter().filter(|v| v.severity == VulnSeverity::Medium).count();
        self.summary.low = self.findings.iter().filter(|v| v.severity == VulnSeverity::Low).count();
        self.summary.info = self.findings.iter().filter(|v| v.severity == VulnSeverity::Info).count();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln_severity_display() {
        assert_eq!(VulnSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(VulnSeverity::High.to_string(), "HIGH");
        assert_eq!(VulnSeverity::Medium.to_string(), "MEDIUM");
        assert_eq!(VulnSeverity::Low.to_string(), "LOW");
        assert_eq!(VulnSeverity::Info.to_string(), "INFO");
    }

    #[test]
    fn test_scan_report_new() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        assert_eq!(report.summary.total, 0);
    }

    #[test]
    fn test_scan_report_add_finding() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        assert_eq!(report.summary.total, 1);
        assert_eq!(report.summary.high, 1);
    }

    #[test]
    fn test_scan_report_merge() {
        let mut report1 = ScanReport::new(Target::Url("http://example.com".to_string()));
        let mut report2 = ScanReport::new(Target::Url("http://example.com".to_string()));

        report1.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Critical".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        report2.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "High".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        report1.merge(report2);

        assert_eq!(report1.summary.total, 2);
        assert_eq!(report1.summary.critical, 1);
        assert_eq!(report1.summary.high, 1);
    }

    #[test]
    fn test_vuln_severity_color() {
        use colored::Color;

        assert_eq!(VulnSeverity::Critical.color(), Color::Red);
        assert_eq!(VulnSeverity::High.color(), Color::Red);
        assert_eq!(VulnSeverity::Medium.color(), Color::Yellow);
        assert_eq!(VulnSeverity::Low.color(), Color::Blue);
        assert_eq!(VulnSeverity::Info.color(), Color::White);
    }

    #[test]
    fn test_target_display() {
        let url = Target::Url("http://example.com".to_string());
        assert_eq!(url.to_string(), "http://example.com");

        let path = Target::Path(PathBuf::from("/tmp/test"));
        assert!(path.to_string().contains("test"));
    }

    #[test]
    fn test_vuln_serialization() {
        let vuln = Vuln {
            severity: VulnSeverity::Critical,
            title: "Test Vuln".to_string(),
            description: "Test".to_string(),
            location: Some("/test".to_string()),
            recommendation: Some("Fix".to_string()),
            cwe: Some("CWE-123".to_string()),
            owasp: Some("A01:2021".to_string()),
        };

        let serialized = serde_json::to_string(&vuln).unwrap();
        let deserialized: Vuln = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vuln.title, deserialized.title);
        assert_eq!(vuln.severity, deserialized.severity);
    }

    #[test]
    fn test_scanner_config_default() {
        let config = ScannerConfig::default();
        assert!(!config.aggressive);
        assert_eq!(config.timeout, Duration::from_secs(5));
        assert_eq!(config.concurrency, 50);
        assert!(config.http);
        assert!(config.port);
        assert!(config.static_analysis);
        assert!(!config.ddos);
        assert!(!config.stress);
    }

    #[test]
    fn test_scanner_config_builder() {
        let config = ScannerConfig::new()
            .with_aggressive(true)
            .with_timeout(Duration::from_secs(10))
            .with_concurrency(100)
            .with_ddos(true)
            .with_stress(true);

        assert!(config.aggressive);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.concurrency, 100);
        assert!(config.ddos);
        assert!(config.stress);
    }

    #[test]
    fn test_scan_report_serialization() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let serialized = serde_json::to_string(&report).unwrap();
        let deserialized: ScanReport = serde_json::from_str(&serialized).unwrap();

        assert_eq!(report.summary.total, deserialized.summary.total);
    }

    #[test]
    fn test_scan_report_exit_code() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        // No vulnerabilities
        assert_eq!(report.exit_code(), 0);

        // Critical
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Critical".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });
        assert_eq!(report.exit_code(), 1);
    }
}
