//! Warden library
//!
//! This library provides the core functionality for the Warden security scanner.

pub mod cli;
pub mod config;
pub mod detection;
pub mod progress;
pub mod reporters;
pub mod scanners;
pub mod utils;

pub use cli::{Cli, Commands, ConfigAction};
pub use config::{Config, ConfigError, ProfileConfig};
pub use detection::{DetectInfo, Framework, Language};
pub use progress::{ErrorReporter, Prompt, ScanProgress, ScannerType, StatusPrinter};
pub use reporters::ReportFormat;
pub use scanners::{ScannerEngine, ScanReport, Vuln, VulnSeverity};

/// Warden version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
