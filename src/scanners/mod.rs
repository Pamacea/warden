//! Scanner modules

#![allow(dead_code)] // Public API exports not yet used internally

// Core scanner trait and registry
pub mod r#trait;

// Tree-sitter parser cache for efficient AST reuse
pub mod parser_cache;

// AST parsers - temporarily disabled
// pub mod ast_parsers;

// Future API, Recon scanners - reserved for v0.6.0+
pub mod api;
pub mod recon;

// Core security scanners
pub mod business_logic;
pub mod cloud_metadata;
pub mod cors;
pub mod dependencies;
pub mod deserialization;
pub mod disclosure;
pub mod docker;
pub mod ddos;
pub mod elasticsearch;
pub mod enumeration;
pub mod file_upload;
pub mod graphql;
pub mod grpc;
pub mod http;
pub mod kubernetes;
pub mod ldap;
pub mod mongodb;
pub mod open_redirect;
pub mod path_traversal;
pub mod port;
pub mod race_condition;
pub mod rdp;
pub mod redis;
pub mod secrets;
pub mod serverless;
pub mod ssrf;
pub mod ssti;
pub mod static_analyzer;
pub mod stress;
pub mod terraform;
pub mod waf;
pub mod xxe;

// Public API exports - actively used in ScannerEngine
pub use dependencies::DependencyScanner;
pub use ddos::DdosScanner;
pub use http::HttpScanner;
pub use port::PortScanner;
pub use secrets::SecretsScanner;
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

    /// Run Secrets Leak scanner
    pub async fn scan_secrets(&mut self, path: &PathBuf) -> Result<ScanReport> {
        let scanner = SecretsScanner::new(self.config.clone());
        Ok(scanner.scan(path).await?)
    }

    /// Run Dependency Vulnerability scanner
    pub async fn scan_dependencies(&mut self, project_path: &PathBuf) -> Result<ScanReport> {
        let scanner = DependencyScanner::new(self.config.clone());
        Ok(scanner.scan(project_path.to_str().unwrap_or(".")).await?)
    }
}

/// Scanner configuration
#[derive(Clone, Debug)]
pub struct ScannerConfig {
    /// Scanning mode (determines aggressiveness)
    pub scan_mode: ScanMode,
    /// Legacy aggressive flag (use scan_mode instead)
    pub aggressive: bool,
    pub timeout: Duration,
    pub concurrency: usize,
    pub user_agent: String,
}

impl ScannerConfig {
    pub fn new() -> Self {
        let mode = ScanMode::Active;
        Self {
            scan_mode: mode,
            aggressive: false,
            timeout: Duration::from_secs(5),
            concurrency: mode.concurrency_level(),
            user_agent: format!("Warden/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn with_aggressive(mut self, aggressive: bool) -> Self {
        self.aggressive = aggressive;
        if aggressive {
            self.scan_mode = ScanMode::Aggressive;
            self.timeout = Duration::from_secs(10);
            self.concurrency = 100;
        }
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

    // These methods return self for API compatibility but don't store values
    // The actual scanner selection is done in orchestrator
    pub fn with_ddos(self, _include_ddos: bool) -> Self {
        self
    }

    pub fn with_stress(self, _include_stress: bool) -> Self {
        self
    }

    pub fn with_check_secrets(self, _check_secrets: bool) -> Self {
        self
    }

    pub fn with_check_deps(self, _check_deps: bool) -> Self {
        self
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Scanning mode - determines how aggressive the scan should be
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    /// Passive mode - no active requests, only static analysis
    Passive,
    /// Active mode - full testing with standard checks
    Active,
    /// Stealth mode - low and slow, minimizes detection
    Stealth,
    /// Aggressive mode - thorough testing with all checks
    Aggressive,
}

impl ScanMode {
    /// Get the display name for this mode
    pub fn name(&self) -> &str {
        match self {
            ScanMode::Passive => "Passive",
            ScanMode::Active => "Active",
            ScanMode::Stealth => "Stealth",
            ScanMode::Aggressive => "Aggressive",
        }
    }

    /// Get the icon for this mode
    #[allow(dead_code)]
    pub fn icon(&self) -> &str {
        match self {
            ScanMode::Passive => "👁️",
            ScanMode::Active => "🔍",
            ScanMode::Stealth => "🕵️",
            ScanMode::Aggressive => "⚔️",
        }
    }

    /// Check if this mode allows active requests
    #[allow(dead_code)]
    pub fn allows_active_requests(&self) -> bool {
        !matches!(self, ScanMode::Passive)
    }

    /// Get the timeout multiplier for this mode
    #[allow(dead_code)]
    pub fn timeout_multiplier(&self) -> f64 {
        match self {
            ScanMode::Passive => 0.5,   // Faster - no active requests
            ScanMode::Active => 1.0,    // Normal
            ScanMode::Stealth => 3.0,   // Slower - avoid detection
            ScanMode::Aggressive => 2.0, // Longer for thorough testing
        }
    }

    /// Get the concurrency level for this mode
    pub fn concurrency_level(&self) -> usize {
        match self {
            ScanMode::Passive => 10,    // Low - mostly sequential
            ScanMode::Active => 50,     // Normal
            ScanMode::Stealth => 5,     // Very low - avoid detection
            ScanMode::Aggressive => 100, // High - fast scanning
        }
    }

    /// Check if DDoS testing is allowed in this mode
    #[allow(dead_code)]
    pub fn allows_ddos(&self) -> bool {
        matches!(self, ScanMode::Aggressive)
    }

    /// Check if stress testing is allowed in this mode
    #[allow(dead_code)]
    pub fn allows_stress(&self) -> bool {
        matches!(self, ScanMode::Aggressive)
    }
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for ScanMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "passive" => Ok(ScanMode::Passive),
            "active" => Ok(ScanMode::Active),
            "stealth" => Ok(ScanMode::Stealth),
            "aggressive" | "agg" => Ok(ScanMode::Aggressive),
            _ => Err(format!("Unknown scan mode: {}. Valid options: passive, active, stealth, aggressive", s)),
        }
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
    #[allow(dead_code)]
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
        assert!(!config.secrets);
        assert!(!config.check_secrets);
        assert!(!config.check_deps);
    }

    #[test]
    fn test_scanner_config_builder() {
        let config = ScannerConfig::new()
            .with_aggressive(true)
            .with_timeout(Duration::from_secs(10))
            .with_concurrency(100)
            .with_ddos(true)
            .with_stress(true)
            .with_check_secrets(true)
            .with_check_deps(true);

        assert!(config.aggressive);
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.concurrency, 100);
        assert!(config.ddos);
        assert!(config.stress);
        assert!(config.check_secrets);
        assert!(config.check_deps);
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
