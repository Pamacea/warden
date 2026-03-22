//! Progress reporting and user-friendly error handling
//!
//! This module provides:
//! - Progress bars for long-running operations
//! - Colored status messages
//! - User-friendly error formatting
//! - Interactive prompts for dangerous operations

use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};

/// Scanner types for progress reporting
#[derive(Debug, Clone, Copy)]
pub enum ScannerType {
    Http,
    Port,
    Static,
    Ddos,
    Stress,
    Secrets,
    Deps,
    Other,
}

impl ScannerType {
    pub fn name(&self) -> &str {
        match self {
            ScannerType::Http => "HTTP Security",
            ScannerType::Port => "Port Scanning",
            ScannerType::Static => "Static Analysis",
            ScannerType::Ddos => "DDoS Resistance",
            ScannerType::Stress => "Stress Testing",
            ScannerType::Secrets => "Secrets Detection",
            ScannerType::Deps => "Dependency Check",
            ScannerType::Other => "Additional Security",
        }
    }

    pub fn icon(&self) -> &str {
        match self {
            ScannerType::Http => "🌐",
            ScannerType::Port => "🔌",
            ScannerType::Static => "📄",
            ScannerType::Ddos => "🛡️",
            ScannerType::Stress => "⚡",
            ScannerType::Secrets => "🔑",
            ScannerType::Deps => "📦",
            ScannerType::Other => "🔍",
        }
    }
}

/// Progress manager for scanning operations
pub struct ScanProgress {
    overall_progress: ProgressBar,
    current_scanner: Option<(ScannerType, ProgressBar)>,
    completed_scanners: usize,
}

impl ScanProgress {
    /// Create a new progress manager
    pub fn new(total_scanners: usize) -> Self {
        let style = ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}")
            .progress_chars("##-");

        let overall_progress = ProgressBar::new(total_scanners as u64);
        overall_progress.set_style(style);
        overall_progress.set_message("Initializing scan...");
        overall_progress.enable_steady_tick(100);

        Self {
            overall_progress,
            current_scanner: None,
            completed_scanners: 0,
        }
    }

    /// Start a new scanner
    pub fn start_scanner(&mut self, scanner_type: ScannerType, total_tasks: Option<u64>) {
        let scanner_style = ProgressStyle::default_bar()
            .template(&format!("  {} {{spinner:.green}} [{{elapsed_precise}}] [{{wide_bar:.green/white}}] {{pos}}/{{len}} {{msg}}",
                scanner_type.icon()))
            .progress_chars("##-");

        let pb = if let Some(total) = total_tasks {
            ProgressBar::new(total)
        } else {
            ProgressBar::new_spinner()
        };

        pb.set_style(scanner_style);
        pb.set_message(scanner_type.name());
        pb.enable_steady_tick(80);

        self.current_scanner = Some((scanner_type, pb));
        self.overall_progress.set_message(&format!("Running: {}", scanner_type.name()));
    }

    /// Update current scanner progress
    pub fn update_scanner(&mut self, message: &str) {
        if let Some((_, pb)) = &mut self.current_scanner {
            pb.set_message(message);
        }
    }

    /// Increment current scanner progress
    #[allow(dead_code)]
    pub fn inc_scanner(&mut self, delta: u64) {
        if let Some((_, pb)) = &mut self.current_scanner {
            pb.inc(delta);
        }
    }

    /// Complete the current scanner
    pub fn finish_scanner(&mut self) {
        if let Some((scanner_type, pb)) = self.current_scanner.take() {
            pb.finish_with_message(&format!("{} {}", scanner_type.icon(), scanner_type.name()));
            self.completed_scanners += 1;
            self.overall_progress.inc(1);
        }
    }

    /// Update overall progress message
    #[allow(dead_code)]
    pub fn set_message(&mut self, msg: &str) {
        self.overall_progress.set_message(msg);
    }

    /// Finish all progress
    pub fn finish(self) {
        self.overall_progress.finish_with_message("Scan complete");
    }
}

impl Drop for ScanProgress {
    fn drop(&mut self) {
        // Ensure we finish the progress bar properly
        if let Some((_, pb)) = self.current_scanner.take() {
            pb.finish();
        }
        self.overall_progress.finish();
    }
}

/// User-friendly error reporting
pub struct ErrorReporter;

impl ErrorReporter {
    /// Print an error with context and suggestions
    pub fn print_error(error: &anyhow::Error) {
        eprintln!("\n{} {}\n", "✗".red().bold(), "An error occurred".red());

        // Print the error chain
        let mut cause = error.chain().peekable();
        while let Some(err) = cause.next() {
            let prefix = if cause.peek().is_some() {
                "  └─".dimmed().to_string()
            } else {
                format!("  {}", "Caused by:".dimmed())
            };
            eprintln!("{} {}", prefix, err);
        }

        // Add suggestion based on error type
        Self::print_suggestion(error);

        eprintln!();
    }

    /// Print helpful suggestion based on error
    fn print_suggestion(error: &anyhow::Error) {
        let error_msg = error.to_string().to_lowercase();

        let suggestion = if error_msg.contains("connection") || error_msg.contains("network") {
            Some(("Network issue detected", "Check your internet connection and verify the target URL is reachable"))
        } else if error_msg.contains("timeout") {
            Some(("Request timeout", "Try increasing the timeout with --timeout or --quick mode"))
        } else if error_msg.contains("permission") || error_msg.contains("denied") {
            Some(("Permission denied", "Check file/directory permissions or run with appropriate access rights"))
        } else if error_msg.contains("not found") {
            Some(("Resource not found", "Verify the target path or URL is correct"))
        } else if error_msg.contains("certificate") || error_msg.contains("tls") {
            Some(("Certificate error", "The target may have an invalid SSL certificate. Use --insecure to bypass (not recommended)"))
        } else {
            None
        };

        if let Some((title, hint)) = suggestion {
            eprintln!("  {}", format!("💡 {}: {}", title, hint).cyan());
        } else {
            eprintln!("  {}", "💡 Run with --verbose for more details".cyan());
        }

        eprintln!("  {}", "📖 For help: https://github.com/Pamacea/warden/issues".dimmed());
    }

    /// Print a warning message
    #[allow(dead_code)]
    pub fn print_warning(message: &str) {
        eprintln!("{} {}\n", "⚠".yellow().bold(), message.yellow());
    }

    /// Print a success message
    pub fn print_success(message: &str) {
        println!("{} {}\n", "✓".green().bold(), message.green());
    }

    /// Print an info message
    #[allow(dead_code)]
    pub fn print_info(message: &str) {
        println!("{} {}", "ℹ".blue().bold(), message);
    }

    /// Print a dangerous operation warning
    pub fn print_danger_warning(message: &str) {
        eprintln!("\n{} {}", "⚠ DANGER:".red().bold(), message.red());
        eprintln!("  {}", "This operation may impact the target system.".yellow());
        eprintln!("  {}", "Only use on systems you own or have explicit permission to test.".yellow());
        eprintln!();
    }
}

/// Confirmation prompts for dangerous operations
pub struct Prompt;

impl Prompt {
    /// Ask for confirmation before dangerous operation
    pub fn confirm_dangerous(operation: &str, target: &str) -> Result<bool> {
        use inquire::Confirm;

        ErrorReporter::print_danger_warning(&format!("You are about to: {}", operation));

        println!("  {}", format!("Target: {}", target).dimmed());

        let confirmed = Confirm::new("Do you want to continue?")
            .with_default(false)
            .prompt()?;

        if !confirmed {
            eprintln!("{} Operation cancelled.\n", "✗".red().bold());
        }

        Ok(confirmed)
    }

    /// Confirm file overwrite
    #[allow(dead_code)]
    pub fn confirm_overwrite(path: &str) -> Result<bool> {
        use inquire::Confirm;

        Ok(Confirm::new(&format!("File '{}' already exists. Overwrite?", path))
            .with_default(false)
            .prompt()?)
    }

    /// Select from options
    #[allow(dead_code)]
    pub fn select_option(message: &str, options: &[&str]) -> Result<String> {
        use inquire::Select;

        Ok(Select::new(message, options.to_vec()).prompt()?.to_string())
    }
}

/// Status message printer for operations
pub struct StatusPrinter {
    verbose: bool,
}

impl StatusPrinter {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn print(&self, message: &str) {
        println!("{} {}", "→".cyan(), message);
    }

    pub fn print_verbose(&self, message: &str) {
        if self.verbose {
            println!("  {}", message.dimmed());
        }
    }

    #[allow(dead_code)]
    pub fn print_step(&self, step: usize, total: usize, message: &str) {
        println!("{} [{}/{}] {}", "→".cyan(), step, total, message);
    }

    #[allow(dead_code)]
    pub fn print_scanner_start(&self, scanner: ScannerType) {
        println!("\n{} {} {}", scanner.icon(), "Starting".cyan(), scanner.name().cyan());
    }

    pub fn print_scanner_complete(&self, scanner: ScannerType, findings: usize) {
        let msg = if findings == 0 {
            format!("{} No vulnerabilities found", scanner.icon())
        } else {
            format!("{} Found {} potential issues", scanner.icon(), findings)
        };

        if findings > 0 {
            println!("{} {}", msg.yellow(), "(review required)".dimmed());
        } else {
            println!("{} {}", msg.green(), "(clean)".dimmed());
        }
    }

    pub fn print_header(&self, title: &str) {
        println!("\n{}", title.cyan().bold());
        println!("{}", "─".repeat(60).cyan());
    }

    pub fn print_footer(&self) {
        println!("{}", "─".repeat(60).cyan());
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_type_properties() {
        assert_eq!(ScannerType::Http.name(), "HTTP Security");
        assert_eq!(ScannerType::Port.icon(), "🔌");
        assert_eq!(ScannerType::Static.name(), "Static Analysis");
    }

    #[test]
    fn test_status_printer() {
        let printer = StatusPrinter::new(false);
        printer.print("Test message");
        printer.print_verbose("Verbose message");
        printer.print_step(1, 3, "Step one");
    }

    #[test]
    fn test_error_reporter() {
        let err = anyhow::anyhow!("Test error with context");
        ErrorReporter::print_error(&err);
    }
}
