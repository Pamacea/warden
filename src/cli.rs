//! Command-line interface definitions
//!
//! This module defines the CLI structure using clap, providing:
//! - Comprehensive help text with examples
//! - Shell completion support
//! - Subcommands for different operations

use clap::{Parser, Subcommand, ValueEnum, CommandFactory};
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = "Yanis <https://github.com/Pamacea>";

#[derive(Parser)]
#[command(name = "warden")]
#[command(about = "AI-powered security review CLI tool", long_about = None)]
#[command(version = VERSION)]
#[command(author = AUTHORS)]
#[command(after_help = BANNER_AFTER)]
#[command(after_long_help = EXAMPLES)]
pub struct Cli {
    /// Enable verbose output
    ///
    /// Shows detailed information about the scanning process,
    /// including individual scanner status and debug information.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Configuration file path
    ///
    /// Override the default configuration file location (~/.warden/config.toml).
    /// Can also be set via WARDEN_CONFIG environment variable.
    #[arg(short, long, global = true, env = "WARDEN_CONFIG")]
    pub config: Option<PathBuf>,

    /// Profile to use from configuration
    ///
    /// Allows switching between predefined configuration profiles.
    /// Can also be set via WARDEN_PROFILE environment variable.
    #[arg(short, long, global = true, env = "WARDEN_PROFILE")]
    pub profile: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a target for vulnerabilities
    ///
    /// The scan command performs comprehensive security analysis on web applications
    /// and codebases. It supports both URL scanning for live applications and
    /// directory scanning for static code analysis.
    ///
    /// # Scanners
    ///
    /// Depending on the target type and options, the following scanners may run:
    ///
    /// - **HTTP Scanner**: Analyzes HTTP headers, security headers, and common vulnerabilities
    /// - **Port Scanner**: Checks for open ports and services (URL targets only)
    /// - **Static Analyzer**: Examines source code for security issues (path targets only)
    /// - **DDoS Scanner**: Tests resistance to denial-of-service attacks (with --include-ddos)
    /// - **Stress Scanner**: Performance testing under load (with --include-stress)
    Scan {
        /// Target URL or directory
        ///
        /// Examples:
        ///   - https://example.com          (scan a live website)
        ///   - /path/to/project             (scan a codebase)
        ///   - .                            (scan current directory)
        ///
        /// If not specified, defaults to the current directory.
        #[arg(global = true)]
        target: Option<String>,

        /// Enable aggressive scanning mode
        ///
        /// Aggressive mode performs deeper analysis but may:
        /// - Take longer to complete
        /// - Generate more requests to the target
        /// - Produce more false positives
        ///
        /// Use with caution on production systems.
        #[arg(long, conflicts_with = "quick")]
        aggressive: bool,

        /// Enable quick scan mode
        ///
        /// Quick mode performs only basic checks, completing faster
        /// but with less comprehensive coverage.
        #[arg(long, conflicts_with = "aggressive")]
        quick: bool,

        /// Include DDoS resistance testing
        ///
        /// Tests the target's resistance to denial-of-service attacks.
        /// WARNING: This may impact the target's availability.
        /// Use only on systems you own or have explicit permission to test.
        #[arg(long)]
        include_ddos: bool,

        /// Include stress testing
        ///
        /// Performs load testing to identify performance bottlenecks.
        /// WARNING: This may impact the target's performance.
        /// Use only on systems you own or have explicit permission to test.
        #[arg(long)]
        include_stress: bool,

        /// Output format
        ///
        /// Available formats:
        ///   - console  (default): Human-readable terminal output
        ///   - json              : Machine-readable JSON format
        ///   - markdown          : Report in Markdown format
        ///   - ai                : AI-optimized format with actionable fixes
        ///   - html              : Interactive HTML report
        ///   - sarif             : SARIF format for CI/CD integration
        #[arg(long, default_value = "console", value_parser = validate_format)]
        format: String,

        /// Save report to file
        ///
        /// Specify a file path to save the scan report.
        /// The format is determined by the --format option.
        ///
        /// Example: --output report.json
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Auto-save report to project directory
        ///
        /// Automatically saves WARDEN_SECURITY_REPORT.md in the scanned directory.
        /// This file can be read by AI agents to understand and fix security issues.
        /// Enabled by default.
        #[arg(long, default_value = "true")]
        auto_save: bool,

        /// Disable auto-save
        ///
        /// Disables automatic report saving to the project directory.
        #[arg(long, conflicts_with = "auto_save")]
        no_auto_save: bool,

        /// Generate AI-fixable report
        ///
        /// Creates an additional WARDEN_FIXES.md file with ready-to-apply code fixes.
        /// AI agents can use this to automatically patch vulnerabilities.
        #[arg(long)]
        generate_fixes: bool,

        /// Request timeout in seconds
        ///
        /// Maximum time to wait for each HTTP request.
        /// Can also be set via WARDEN_TIMEOUT environment variable.
        #[arg(short, long, default_value = "5", env = "WARDEN_TIMEOUT", value_name = "SECONDS")]
        timeout: u64,

        /// Concurrent requests
        ///
        /// Number of parallel requests to make during scanning.
        /// Higher values are faster but may overwhelm the target.
        /// Can also be set via WARDEN_CONCURRENCY environment variable.
        #[arg(short, long, default_value = "50", env = "WARDEN_CONCURRENCY", value_name = "NUM")]
        concurrency: usize,

        /// Maximum file size for analysis (MB)
        ///
        /// Files larger than this will be skipped during static analysis.
        /// Can also be set via WARDEN_MAX_FILE_SIZE environment variable.
        #[arg(long, default_value = "10", env = "WARDEN_MAX_FILE_SIZE", value_name = "MB")]
        max_file_size: u64,

        /// Show security score
        ///
        /// Display a comprehensive security score (0-100) with grade (A+ to F)
        /// based on 10 security categories including input validation,
        /// authentication, cryptography, headers, session management,
        /// access control, data protection, error handling, communications, and code quality.
        #[arg(long)]
        score: bool,

        /// Enable secrets leak detection
        ///
        /// Scans for exposed API keys, tokens, passwords, and other sensitive
        /// credentials in source code and configuration files.
        #[arg(long, default_value = "false")]
        check_secrets: bool,

        /// Check dependency vulnerabilities
        ///
        /// Analyzes project dependencies (package.json, Cargo.toml, requirements.txt, etc.)
        /// for known security vulnerabilities using public vulnerability databases.
        #[arg(long, default_value = "false")]
        check_deps: bool,

        /// Full scan mode - use ALL available scanners
        ///
        /// Enables comprehensive scanning with all security scanners including:
        /// - HTTP, Port, Static Analysis, DDoS, Stress
        /// - API, GraphQL, gRPC scanners
        /// - CORS, SSRF, Open Redirect, Path Traversal
        /// - XXE, Deserialization, SSTI
        /// - Secrets, Dependencies, Enumeration
        /// - Docker, Terraform, Kubernetes, Cloud Metadata
        /// - Business Logic, Race Conditions
        /// - LDAP, MongoDB, Redis, Elasticsearch, RDP
        /// - File Upload, Information Disclosure, WAF
        ///
        /// WARNING: This may take significant time and generate many requests.
        #[arg(long)]
        full: bool,
    },

    /// Detect framework and language
    ///
    /// Analyzes a project directory to identify:
    /// - Programming languages used
    /// - Frameworks and libraries
    /// - Package managers
    /// - Platform/infrastructure hints
    ///
    /// This is useful for understanding the technology stack before
    /// running a full security scan.
    Detect {
        /// Project directory
        ///
        /// Path to the project directory to analyze.
        /// Defaults to current directory if not specified.
        #[arg(short, long, value_name = "PATH")]
        path: Option<String>,

        /// Output in JSON format
        ///
        /// If specified, outputs detection results as JSON
        /// instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Manage configuration
    ///
    /// View, edit, or validate Warden configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Generate shell completions
    ///
    /// Generates shell completion scripts for your preferred shell.
    /// Output can be written to a file or redirected to your shell's
    /// completion directory.
    ///
    /// # Examples
    ///
    /// Bash:
    ///   warden completions bash > ~/.local/share/bash-completion/completions/warden
    ///
    /// Zsh:
    ///   warden completions zsh > ~/.zsh/completions/_warden
    ///
    /// Fish:
    ///   warden completions fish > ~/.config/fish/completions/warden.fish
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Update Warden to the latest version
    ///
    /// Updates Warden by reinstalling from crates.io.
    /// This uses cargo to fetch and install the latest published version.
    ///
    /// Skips update if already running the latest version (unless --force is used).
    Update {
        /// Force update even if already at latest version
        ///
        /// Reinstalls Warden regardless of current version.
        #[arg(long)]
        force: bool,

        /// Use cargo install with --git for development version
        ///
        /// Installs from the main GitHub repository instead of crates.io.
        #[arg(long)]
        git: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current configuration
    ///
    /// Displays the effective configuration after merging defaults,
    /// config file, and environment variables.
    Show,

    /// Initialize default configuration
    ///
    /// Creates ~/.warden/config.toml with default values.
    /// Useful as a starting point for customization.
    Init,

    /// Validate configuration
    ///
    /// Checks if the current configuration is valid and displays
    /// any errors or warnings.
    Validate,

    /// Edit configuration file
    ///
    /// Opens the configuration file in your default editor.
    /// Creates the file first if it doesn't exist.
    Edit,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

fn validate_format(s: &str) -> Result<String, String> {
    match s.to_lowercase().as_str() {
        "console" | "json" | "markdown" | "md" | "ai" | "html" | "sarif" => Ok(s.to_lowercase()),
        _ => Err(format!(
            "Invalid format '{}'. Valid options: console, json, markdown (md), ai, html, sarif",
            s
        )),
    }
}

pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    use std::io;

    let mut cmd = Cli::command();

    match shell {
        Shell::Bash => {
            clap_complete::generate(
                clap_complete::shells::Bash,
                &mut cmd,
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Elvish => {
            clap_complete::generate(
                clap_complete::shells::Elvish,
                &mut cmd,
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Fish => {
            clap_complete::generate(
                clap_complete::shells::Fish,
                &mut cmd,
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::PowerShell => {
            clap_complete::generate(
                clap_complete::shells::PowerShell,
                &mut cmd,
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Zsh => {
            clap_complete::generate(
                clap_complete::shells::Zsh,
                &mut cmd,
                "warden",
                &mut io::stdout(),
            );
        }
    }

    Ok(())
}

/// Banner displayed after short help
const BANNER_AFTER: &str = r#"
For more information, visit: https://github.com/Pamacea/warden
Report issues at: https://github.com/Pamacea/warden/issues
"#;

/// Examples displayed in long help
const EXAMPLES: &str = r#"
EXAMPLES:

  # Scan a website
  $ warden scan https://example.com

  # Scan current directory with aggressive mode
  $ warden scan --aggressive

  # Scan a directory and save JSON report
  $ warden scan /path/to/project --format json --output report.json

  # Quick scan with custom timeout
  $ warden scan --quick --timeout 10

  # Scan with DDoS resistance testing (use carefully!)
  $ warden scan https://example.com --include-ddos

  # Detect technologies in a project
  $ warden detect /path/to/project

  # Initialize configuration file
  $ warden config init

  # View current configuration
  $ warden config show

  # Generate shell completions for Zsh
  $ warden completions zsh > ~/.zsh/completions/_warden

ENVIRONMENT VARIABLES:

  WARDEN_CONFIG        Path to configuration file
  WARDEN_PROFILE       Configuration profile to use
  WARDEN_TIMEOUT       Default request timeout (seconds)
  WARDEN_CONCURRENCY   Default concurrent requests
  WARDEN_MAX_FILE_SIZE Maximum file size for analysis (MB)

CONFIGURATION:

  Configuration files are loaded in order:
  1. ~/.warden/config.toml (user config)
  2. .warden.toml (project config, if exists)

  Environment variables override config file values.

PROFILES:

  Create named profiles in config.toml for different scenarios:
  [profile.quick]
  timeout = 2
  concurrency = 25
  max_file_size = 5

  [profile.deep]
  aggressive = true
  timeout = 10
  concurrency = 100
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_format_valid() {
        assert!(validate_format("console").is_ok());
        assert!(validate_format("json").is_ok());
        assert!(validate_format("markdown").is_ok());
        assert!(validate_format("md").is_ok());
        assert!(validate_format("CONSOLE").is_ok());
        assert!(validate_format("html").is_ok());
        assert!(validate_format("sarif").is_ok());
        assert!(validate_format("ai").is_ok());
    }

    #[test]
    fn test_validate_format_invalid() {
        assert!(validate_format("xml").is_err());
        assert!(validate_format("yaml").is_err());
        assert!(validate_format("").is_err());
    }
}
