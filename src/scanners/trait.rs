//! Security Scanner Trait
//!
//! This module defines the common trait that all security scanners must implement.
//! This provides a unified interface for running different types of security scans
//! and allows for easy extensibility (Open/Closed Principle).
//!
//! # Example
//!
//! ```rust
//! use oalacea_warden::scanners::{SecurityScanner, ScannerConfig, Target, ScanReport};
//! use anyhow::Result;
//!
//! struct MyCustomScanner {
//!     config: ScannerConfig,
//! }
//!
//! impl SecurityScanner for MyCustomScanner {
//!     async fn scan(&self, target: &Target) -> Result<ScanReport> {
//!         // Implementation
//!         Ok(ScanReport::new(target.clone()))
//!     }
//!
//!     fn name(&self) -> &str {
//!         "my_custom_scanner"
//!     }
//!
//!     fn description(&self) -> &str {
//!         "My custom security scanner"
//!     }
//!
//!     fn supported_targets(&self) -> &[TargetType] {
//!         &[TargetType::Url, TargetType::Path]
//!     }
//! }
//! ```

use crate::scanners::{ScanReport, Target};
use async_trait::async_trait;

/// Types of targets that scanners can operate on
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetType {
    /// HTTP/HTTPS URL targets
    Url,
    /// File system path targets
    Path,
    /// Both URL and Path targets
    Any,
}

/// Common trait that all security scanners must implement
///
/// This trait provides a unified interface for running security scans
/// and enables easy addition of new scanners without modifying the core engine.
#[async_trait]
pub trait SecurityScanner: Send + Sync {
    /// Run the security scan against the specified target
    ///
    /// # Arguments
    ///
    /// * `target` - The target to scan (URL or file path)
    ///
    /// # Returns
    ///
    /// A `ScanReport` containing all findings from the scan
    async fn scan(&self, target: &Target) -> anyhow::Result<ScanReport>;

    /// Get the name of this scanner
    ///
    /// # Returns
    ///
    /// A string slice containing the scanner's name
    fn name(&self) -> &str;

    /// Get a description of what this scanner checks for
    ///
    /// # Returns
    ///
    /// A string slice containing the scanner's description
    fn description(&self) -> &str;

    /// Get the types of targets this scanner supports
    ///
    /// # Returns
    ///
    /// A slice of `TargetType` values indicating supported target types
    fn supported_targets(&self) -> &[TargetType];

    /// Check if this scanner supports a specific target type
    ///
    /// # Arguments
    ///
    /// * `target` - The target to check
    ///
    /// # Returns
    ///
    /// `true` if the scanner supports this target, `false` otherwise
    fn supports_target(&self, target: &Target) -> bool {
        let supported = self.supported_targets();
        supported.contains(&TargetType::Any)
            || match target {
                Target::Url(_) => supported.contains(&TargetType::Url),
                Target::Path(_) => supported.contains(&TargetType::Path),
            }
    }

    /// Get the severity level of findings this scanner typically produces
    ///
    /// # Returns
    ///
    /// The maximum severity level this scanner can detect
    fn max_severity(&self) -> ScannerSeverity {
        ScannerSeverity::High
    }
}

/// Severity level that a scanner can detect
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScannerSeverity {
    /// Informational findings only
    Info,
    /// Low severity findings
    Low,
    /// Medium severity findings
    Medium,
    /// High severity findings
    High,
    /// Critical severity findings
    Critical,
}

impl std::fmt::Display for ScannerSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerSeverity::Info => write!(f, "INFO"),
            ScannerSeverity::Low => write!(f, "LOW"),
            ScannerSeverity::Medium => write!(f, "MEDIUM"),
            ScannerSeverity::High => write!(f, "HIGH"),
            ScannerSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Scanner category for organization and filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerCategory {
    /// Active scanning (HTTP requests, port scanning)
    Active,
    /// Passive analysis (static code analysis)
    Passive,
    /// Infrastructure scanning (Docker, Kubernetes)
    Infrastructure,
    /// Dependency analysis
    Dependency,
    /// Reconnaissance and information gathering
    Recon,
    /// Stress and load testing
    Stress,
}

impl std::fmt::Display for ScannerCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerCategory::Active => write!(f, "Active"),
            ScannerCategory::Passive => write!(f, "Passive"),
            ScannerCategory::Infrastructure => write!(f, "Infrastructure"),
            ScannerCategory::Dependency => write!(f, "Dependency"),
            ScannerCategory::Recon => write!(f, "Reconnaissance"),
            ScannerCategory::Stress => write!(f, "Stress"),
        }
    }
}

/// Metadata about a scanner
#[derive(Debug, Clone)]
pub struct ScannerMetadata {
    /// Scanner name
    pub name: String,
    /// Scanner description
    pub description: String,
    /// Scanner version
    pub version: &'static str,
    /// Supported target types
    pub supported_targets: Vec<TargetType>,
    /// Scanner category
    pub category: ScannerCategory,
    /// Maximum severity level
    pub max_severity: ScannerSeverity,
    /// CWE IDs this scanner covers
    pub cwes: Vec<&'static str>,
    /// OWASP categories this scanner covers
    pub owasp: Vec<&'static str>,
}

impl ScannerMetadata {
    /// Create new scanner metadata
    pub fn new(
        name: String,
        description: String,
        category: ScannerCategory,
    ) -> Self {
        Self {
            name,
            description,
            version: env!("CARGO_PKG_VERSION"),
            supported_targets: Vec::new(),
            category,
            max_severity: ScannerSeverity::High,
            cwes: Vec::new(),
            owasp: Vec::new(),
        }
    }

    /// Add supported target types
    pub fn with_targets(mut self, targets: &[TargetType]) -> Self {
        self.supported_targets = targets.to_vec();
        self
    }

    /// Set maximum severity
    pub fn with_max_severity(mut self, severity: ScannerSeverity) -> Self {
        self.max_severity = severity;
        self
    }

    /// Add CWE IDs
    pub fn with_cwes(mut self, cwes: Vec<&'static str>) -> Self {
        self.cwes = cwes;
        self
    }

    /// Add OWASP categories
    pub fn with_owasp(mut self, owasp: Vec<&'static str>) -> Self {
        self.owasp = owasp;
        self
    }
}

/// Registry for all available scanners
///
/// The registry maintains a collection of all available scanners
/// and provides methods for discovering and running them based on target type.
pub struct ScannerRegistry {
    scanners: Vec<Box<dyn SecurityScanner>>,
}

impl ScannerRegistry {
    /// Create a new empty scanner registry
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    /// Register a new scanner
    pub fn register(&mut self, scanner: Box<dyn SecurityScanner>) {
        self.scanners.push(scanner);
    }

    /// Get all scanners that support a specific target
    pub fn scanners_for_target(&self, target: &Target) -> Vec<&dyn SecurityScanner> {
        self.scanners
            .iter()
            .filter(|s| s.supports_target(target))
            .map(|s| s.as_ref())
            .collect()
    }

    /// Get all scanners in a specific category
    pub fn scanners_by_category(&self, _category: ScannerCategory) -> Vec<&dyn SecurityScanner> {
        // For now, return all since we don't have category metadata on the trait
        // In the future, add a category() method to the trait
        self.scanners
            .iter()
            .map(|s| s.as_ref())
            .collect()
    }

    /// Get the total number of registered scanners
    pub fn count(&self) -> usize {
        self.scanners.len()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyScanner;

    #[async_trait]
    impl SecurityScanner for DummyScanner {
        async fn scan(&self, target: &Target) -> anyhow::Result<ScanReport> {
            Ok(ScanReport::new(target.clone()))
        }

        fn name(&self) -> &str {
            "dummy_scanner"
        }

        fn description(&self) -> &str {
            "A dummy scanner for testing"
        }

        fn supported_targets(&self) -> &[TargetType] {
            &[TargetType::Any]
        }
    }

    #[test]
    fn test_scanner_severity_ord() {
        assert!(ScannerSeverity::Critical > ScannerSeverity::High);
        assert!(ScannerSeverity::High > ScannerSeverity::Medium);
        assert!(ScannerSeverity::Medium > ScannerSeverity::Low);
        assert!(ScannerSeverity::Low > ScannerSeverity::Info);
    }

    #[test]
    fn test_target_type_support() {
        let scanner = DummyScanner;
        assert!(scanner.supports_target(&Target::Url("http://example.com".to_string())));
        assert!(scanner.supports_target(&Target::Path(std::path::PathBuf::from("/tmp"))));
    }

    #[test]
    fn test_scanner_registry() {
        let mut registry = ScannerRegistry::new();
        assert_eq!(registry.count(), 0);

        registry.register(Box::new(DummyScanner));
        assert_eq!(registry.count(), 1);

        let scanners = registry.scanners_for_target(&Target::Url("http://example.com".to_string()));
        assert_eq!(scanners.len(), 1);
    }

    #[test]
    fn test_scanner_metadata() {
        let metadata = ScannerMetadata::new(
            "test_scanner".to_string(),
            "A test scanner".to_string(),
            ScannerCategory::Active,
        )
        .with_targets(&[TargetType::Url])
        .with_max_severity(ScannerSeverity::Critical)
        .with_cwes(vec!["CWE-79", "CWE-89"])
        .with_owasp(vec!["A03:2021"]);

        assert_eq!(metadata.name, "test_scanner");
        assert_eq!(metadata.max_severity, ScannerSeverity::Critical);
        assert_eq!(metadata.cwes.len(), 2);
        assert_eq!(metadata.supported_targets.len(), 1);
    }
}
