//! Warden library
//!
//! This library provides the core functionality for the Warden security scanner.

pub mod config;
pub mod detection;
pub mod reporters;
pub mod scanners;
pub mod utils;

pub use config::Config;
pub use detection::{DetectInfo, Framework, Language};
pub use reporters::{ReportFormat, ScanReport};
pub use scanners::{Scanner, ScannerEngine, Vuln, VulnSeverity};

/// Warden version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
