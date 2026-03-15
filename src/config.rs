//! Configuration management
//!
//! This module handles configuration loading from multiple sources:
//! - Default values
//! - User configuration file (~/.warden/config.toml)
//! - Project configuration file (.warden.toml)
//! - Environment variables (WARDEN_*)
//! - Profiles (named configuration sets)
//!
//! # Configuration Precedence
//!
//! Configuration is loaded and merged in the following order (later sources override earlier ones):
//! 1. Default values
//! 2. User config file (~/.warden/config.toml)
//! 3. Project config file (.warden.toml) if it exists
//! 4. Environment variables
//! 5. Command-line arguments
//!
//! # Example Configuration File
//!
//! ```toml
//! # General settings
//! timeout = 10
//! concurrency = 50
//!
//! # Exclusions
//! exclude_dirs = ["node_modules", "target", "dist"]
//! exclude_files = ["*.min.js", "*.min.css"]
//!
//! # Profiles
//! [profile.quick]
//! timeout = 2
//! concurrency = 25
//!
//! [profile.deep]
//! timeout = 15
//! concurrency = 100
//! aggressive = true
//! ```

use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default timeout for requests (seconds)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Default concurrency level
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// User agent for HTTP requests
    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// Maximum file size for static analysis (bytes)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Enable aggressive mode by default
    #[serde(default)]
    pub aggressive: bool,

    /// Directories to exclude from scanning
    #[serde(default = "default_exclude_dirs")]
    pub exclude_dirs: Vec<String>,

    /// Files to exclude from scanning
    #[serde(default = "default_exclude_files")]
    pub exclude_files: Vec<String>,

    /// Named profiles for different scanning scenarios
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

/// Profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    /// Timeout override for this profile
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Concurrency override for this profile
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// Aggressive mode override
    #[serde(default)]
    pub aggressive: bool,

    /// Max file size override
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Enable secrets leak detection (Premium feature)
    #[serde(default)]
    pub check_secrets: bool,

    /// Enable dependency vulnerability checking (Premium feature)
    #[serde(default)]
    pub check_deps: bool,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            concurrency: default_concurrency(),
            aggressive: false,
            max_file_size: default_max_file_size(),
            check_secrets: false,
            check_deps: false,
        }
    }
}

/// Configuration file structure (supports profiles)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigFile {
    timeout: Option<u64>,
    concurrency: Option<usize>,
    user_agent: Option<String>,
    max_file_size: Option<u64>,
    aggressive: Option<bool>,
    exclude_dirs: Option<Vec<String>>,
    exclude_files: Option<Vec<String>>,
    /// Enable secrets leak detection (Premium feature)
    #[serde(default)]
    check_secrets: bool,
    /// Enable dependency vulnerability checking (Premium feature)
    #[serde(default)]
    check_deps: bool,
    #[serde(default)]
    profiles: HashMap<String, ProfileConfig>,
}

// Default value functions
fn default_timeout() -> u64 { 5 }
fn default_concurrency() -> usize { 50 }
fn default_user_agent() -> String {
    format!("Warden/{}", env!("CARGO_PKG_VERSION"))
}
fn default_max_file_size() -> u64 { 10 * 1024 * 1024 } // 10 MB
fn default_exclude_dirs() -> Vec<String> {
    vec![
        "node_modules".to_string(),
        "target".to_string(),
        "dist".to_string(),
        "build".to_string(),
        ".git".to_string(),
        "vendor".to_string(),
        "__pycache__".to_string(),
        "venv".to_string(),
        ".venv".to_string(),
        "env".to_string(),
        ".env".to_string(),
    ]
}
fn default_exclude_files() -> Vec<String> {
    vec![
        "*.min.js".to_string(),
        "*.min.css".to_string(),
        "*.map".to_string(),
        "*.bundle.js".to_string(),
        "*.chunk.js".to_string(),
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            concurrency: default_concurrency(),
            user_agent: default_user_agent(),
            max_file_size: default_max_file_size(),
            aggressive: false,
            exclude_dirs: default_exclude_dirs(),
            exclude_files: default_exclude_files(),
            profiles: HashMap::new(),
        }
    }
}

impl Config {
    /// Load configuration from all sources
    ///
    /// Merges configuration from:
    /// 1. Default values
    /// 2. ~/.warden/config.toml (user config)
    /// 3. .warden.toml (project config, if exists)
    /// 4. Environment variables
    ///
    /// Optionally applies a specific profile if specified.
    #[allow(dead_code)] // Reserved for config file loading feature
    pub fn load() -> Result<Self> {
        Self::load_with_profile(None)
    }

    /// Load configuration with a specific profile
    pub fn load_with_profile(profile_name: Option<String>) -> Result<Self> {
        let mut config = Self::default();

        // Load user config
        if let Some(user_config_path) = Self::user_config_path() {
            if user_config_path.exists() {
                config = config.merge_from_file(&user_config_path)
                    .with_context(|| {
                        format!("Failed to load user config from: {}", user_config_path.display())
                    })?;
            }
        }

        // Load project config
        let project_config_path = PathBuf::from(".warden.toml");
        if project_config_path.exists() {
            config = config.merge_from_file(&project_config_path)
                .with_context(|| {
                    format!("Failed to load project config from: {}", project_config_path.display())
                })?;
        }

        // Apply profile if specified
        if let Some(profile) = profile_name {
            config = config.apply_profile(&profile)?;
        }

        // Apply environment variables
        config = config.apply_env_vars();

        Ok(config)
    }

    /// Load configuration from a specific file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let config = Self::default();
        config.merge_from_file(path)
    }

    /// Get the user configuration file path
    pub fn user_config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|p| p.join(".warden").join("config.toml"))
    }

    /// Merge configuration from a file
    fn merge_from_file(mut self, path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config_file: ConfigFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        // Merge values (file overrides current)
        if let Some(timeout) = config_file.timeout {
            self.timeout = timeout;
        }
        if let Some(concurrency) = config_file.concurrency {
            self.concurrency = concurrency;
        }
        if let Some(user_agent) = config_file.user_agent {
            self.user_agent = user_agent;
        }
        if let Some(max_file_size) = config_file.max_file_size {
            self.max_file_size = max_file_size;
        }
        if let Some(aggressive) = config_file.aggressive {
            self.aggressive = aggressive;
        }
        if let Some(exclude_dirs) = config_file.exclude_dirs {
            self.exclude_dirs = exclude_dirs;
        }
        if let Some(exclude_files) = config_file.exclude_files {
            self.exclude_files = exclude_files;
        }

        // Store profiles
        self.profiles = config_file.profiles;

        Ok(self)
    }

    /// Apply a named profile to the configuration
    fn apply_profile(mut self, profile_name: &str) -> Result<Self> {
        if let Some(profile) = self.profiles.get(profile_name) {
            self.timeout = profile.timeout;
            self.concurrency = profile.concurrency;
            self.aggressive = profile.aggressive;
            self.max_file_size = profile.max_file_size;
            Ok(self)
        } else {
            Err(ConfigError::ProfileNotFound(profile_name.to_string()).into())
        }
    }

    /// Apply environment variable overrides
    fn apply_env_vars(mut self) -> Self {
        if let Ok(timeout) = std::env::var("WARDEN_TIMEOUT") {
            if let Ok(value) = timeout.parse::<u64>() {
                self.timeout = value;
            }
        }
        if let Ok(concurrency) = std::env::var("WARDEN_CONCURRENCY") {
            if let Ok(value) = concurrency.parse::<usize>() {
                self.concurrency = value;
            }
        }
        if let Ok(max_file_size) = std::env::var("WARDEN_MAX_FILE_SIZE") {
            if let Ok(value) = max_file_size.parse::<u64>() {
                self.max_file_size = value * 1024 * 1024; // Convert MB to bytes
            }
        }
        if let Ok(user_agent) = std::env::var("WARDEN_USER_AGENT") {
            self.user_agent = user_agent;
        }
        self
    }

    /// Save configuration to user config file
    pub fn save(&self) -> Result<()> {
        let config_dir = dirs::home_dir()
            .map(|p| p.join(".warden"))
            .ok_or_else(|| anyhow::anyhow!(ConfigError::NoHomeDirectory))?;

        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create config directory: {}", config_dir.display()))?;

        let config_path = config_dir.join("config.toml");
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration")?;

        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write config file: {}", config_path.display()))?;

        Ok(())
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        if self.timeout == 0 {
            errors.push(ConfigError::InvalidValue("timeout".to_string(), "must be greater than 0".to_string()));
        }
        if self.timeout > 300 {
            errors.push(ConfigError::InvalidValue("timeout".to_string(), "must be less than 300 seconds".to_string()));
        }
        if self.concurrency == 0 {
            errors.push(ConfigError::InvalidValue("concurrency".to_string(), "must be greater than 0".to_string()));
        }
        if self.concurrency > 1000 {
            errors.push(ConfigError::InvalidValue("concurrency".to_string(), "must be less than 1000".to_string()));
        }
        if self.max_file_size == 0 {
            errors.push(ConfigError::InvalidValue("max_file_size".to_string(), "must be greater than 0".to_string()));
        }
        if self.max_file_size > 1024 * 1024 * 1024 { // 1 GB
            errors.push(ConfigError::InvalidValue("max_file_size".to_string(), "must be less than 1 GB".to_string()));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Display configuration as colored output
    pub fn display(&self) {
        println!("{}", "\n┌─ Configuration ──────────────────────────────────".cyan().bold());
        println!("│ {}", format!("Timeout: {}s", self.timeout).white());
        println!("│ {}", format!("Concurrency: {}", self.concurrency).white());
        println!("│ {}", format!("Max file size: {} MB", self.max_file_size / 1024 / 1024).white());
        println!("│ {}", format!("Aggressive mode: {}", self.aggressive).white());
        println!("│ {}", format!("User agent: {}", self.user_agent).dimmed());
        println!("│");
        println!("│ {}", "Exclude dirs:".dimmed());
        for dir in &self.exclude_dirs {
            println!("│   - {}", dir.dimmed());
        }
        println!("│");
        println!("│ {}", "Exclude files:".dimmed());
        for file in &self.exclude_files {
            println!("│   - {}", file.dimmed());
        }

        if !self.profiles.is_empty() {
            println!("│");
            println!("│ {}", "Available profiles:".dimmed());
            for name in self.profiles.keys() {
                println!("│   - {}", name.cyan());
            }
        }

        println!("{}", "└──────────────────────────────────────────────────".cyan().bold());
        println!();
    }
}

/// Configuration errors
#[derive(Debug)]
#[allow(dead_code)] // Some variants kept for future use
pub enum ConfigError {
    ProfileNotFound(String),
    NoHomeDirectory,
    InvalidValue(String, String),
    FileNotFound(String),
    ParseError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::ProfileNotFound(name) => {
                write!(f, "{} Profile '{}' not found. Available profiles: See 'warden config show'",
                       "Error:".red().bold(), name)
            }
            ConfigError::NoHomeDirectory => {
                write!(f, "{} Cannot determine home directory for config file",
                       "Error:".red().bold())
            }
            ConfigError::InvalidValue(key, msg) => {
                write!(f, "{} Invalid value for '{}': {}",
                       "Error:".red().bold(), key, msg)
            }
            ConfigError::FileNotFound(path) => {
                write!(f, "{} Configuration file not found: {}",
                       "Error:".red().bold(), path)
            }
            ConfigError::ParseError(msg) => {
                write!(f, "{} Failed to parse configuration: {}",
                       "Error:".red().bold(), msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Print configuration errors with helpful suggestions
pub fn print_config_errors(errors: &[ConfigError]) {
    eprintln!("\n{} Configuration validation failed:\n", "✗".red().bold());

    for (i, error) in errors.iter().enumerate() {
        eprintln!("  {}. {}", i + 1, error);

        // Add helpful suggestions
        match error {
            ConfigError::InvalidValue(_key, _) => {
                eprintln!("     {}", format!("Hint: Check 'warden config show' or edit ~/.warden/config.toml")
                    .dimmed());
            }
            ConfigError::ProfileNotFound(name) => {
                eprintln!("     {}", format!("Hint: Run 'warden config init' to create default profiles")
                    .dimmed());
                if *name == "default" {
                    eprintln!("     {}", "The 'default' profile is applied automatically when no profile is specified."
                        .dimmed());
                }
            }
            _ => {}
        }
        eprintln!();
    }
}

/// Predefined scanning profiles
///
/// These profiles provide quick configuration for common scanning scenarios.
/// Each profile has specific timeout, concurrency, and aggressiveness settings.
impl Config {
    /// Get the built-in profile definitions
    #[allow(dead_code)]
    pub fn builtin_profiles() -> &'static [&'static str] {
        &["quick", "standard", "thorough", "stealth", "aggressive"]
    }

    /// Apply a built-in profile by name
    #[allow(dead_code)]
    pub fn with_builtin_profile(mut self, profile: &str) -> Result<Self> {
        let (timeout, concurrency, aggressive, max_file_size) = match profile {
            "quick" => (
                2,      // Fast timeout
                25,     // Lower concurrency
                false,  // Not aggressive
                5 * 1024 * 1024, // 5 MB max file
            ),
            "standard" => (
                5,      // Standard timeout
                50,     // Normal concurrency
                false,  // Not aggressive
                10 * 1024 * 1024, // 10 MB max file
            ),
            "thorough" => (
                15,     // Longer timeout
                100,    // High concurrency
                true,   // Aggressive
                50 * 1024 * 1024, // 50 MB max file
            ),
            "stealth" => (
                30,     // Very long timeout
                5,      // Very low concurrency
                false,  // Not aggressive
                10 * 1024 * 1024, // 10 MB max file
            ),
            "aggressive" => (
                10,     // Long timeout
                200,    // Very high concurrency
                true,   // Aggressive
                100 * 1024 * 1024, // 100 MB max file
            ),
            _ => return Err(ConfigError::ProfileNotFound(profile.to_string()).into()),
        };

        self.timeout = timeout;
        self.concurrency = concurrency;
        self.aggressive = aggressive;
        self.max_file_size = max_file_size;

        Ok(self)
    }

    /// Get profile description
    #[allow(dead_code)]
    pub fn profile_description(profile: &str) -> &'static str {
        match profile {
            "quick" => "Fast scanning for quick security checks (2s timeout, 25 concurrent)",
            "standard" => "Standard scanning with balanced settings (5s timeout, 50 concurrent)",
            "thorough" => "Deep scanning with extended checks (15s timeout, 100 concurrent, aggressive)",
            "stealth" => "Low-and-slow scanning to avoid detection (30s timeout, 5 concurrent)",
            "aggressive" => "Maximum coverage scanning (10s timeout, 200 concurrent, aggressive)",
            _ => "Unknown profile",
        }
    }
}

/// Scanner chain configuration
///
/// Allows defining custom sequences of scanners for specific scenarios.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)] // Reserved for v0.6.0 custom scanner chains
pub struct ScannerChain {
    /// Chain name
    pub name: String,

    /// Description of what this chain tests
    pub description: String,

    /// Ordered list of scanners to run
    pub scanners: Vec<String>,

    /// Whether to stop on first finding
    pub stop_on_first: bool,

    /// Maximum number of findings before stopping
    pub max_findings: Option<usize>,
}

impl ScannerChain {
    /// Create a new scanner chain
    #[allow(dead_code)]
    pub fn new(name: String, description: String) -> Self {
        Self {
            name,
            description,
            scanners: Vec::new(),
            stop_on_first: false,
            max_findings: None,
        }
    }

    /// Add a scanner to the chain
    #[allow(dead_code)]
    pub fn add_scanner(mut self, scanner: &str) -> Self {
        self.scanners.push(scanner.to_string());
        self
    }

    /// Set stop on first finding
    #[allow(dead_code)]
    pub fn with_stop_on_first(mut self, stop: bool) -> Self {
        self.stop_on_first = stop;
        self
    }

    /// Set max findings before stopping
    #[allow(dead_code)]
    pub fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = Some(max);
        self
    }

    /// Get built-in scanner chains
    #[allow(dead_code)]
    pub fn builtin_chains() -> Vec<ScannerChain> {
        vec![
            ScannerChain::new(
                "owasp".to_string(),
                "OWASP Top 10 2021 security checks".to_string(),
            )
            .add_scanner("http")
            .add_scanner("api")
            .add_scanner("static"),

            ScannerChain::new(
                "api-focus".to_string(),
                "API and authentication security testing".to_string(),
            )
            .add_scanner("api")
            .add_scanner("recon"),

            ScannerChain::new(
                "quick-audit".to_string(),
                "Fast security audit for CI/CD".to_string(),
            )
            .add_scanner("static")
            .add_scanner("http")
            .with_stop_on_first(true)
            .with_max_findings(10),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.timeout, 5);
        assert_eq!(config.concurrency, 50);
        assert_eq!(config.max_file_size, 10 * 1024 * 1024);
        assert!(!config.aggressive);
    }

    #[test]
    fn test_config_validate_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_invalid_timeout() {
        let mut config = Config::default();
        config.timeout = 0;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(errors) = result {
            assert!(errors.iter().any(|e| matches!(e, ConfigError::InvalidValue(k, _) if k == "timeout")));
        }
    }

    #[test]
    fn test_config_validate_invalid_concurrency() {
        let mut config = Config::default();
        config.concurrency = 0;
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_env_vars() {
        let _config = Config::default()
            .apply_env_vars();

        // Test with environment variable set
        std::env::set_var("WARDEN_TIMEOUT", "10");
        let config = Config::default()
            .apply_env_vars();
        assert_eq!(config.timeout, 10);
        std::env::remove_var("WARDEN_TIMEOUT");
    }

    #[test]
    fn test_profile_not_found() {
        let config = Config::default();
        let result = config.apply_profile("nonexistent");
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e.downcast_ref::<ConfigError>(), Some(ConfigError::ProfileNotFound(_))));
        }
    }
}
