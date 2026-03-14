//! Report generation and output

use crate::scanners::{ScanReport, Target, VulnSeverity};
use anyhow::Result;
use colored::Colorize;
use std::fs;

pub mod console;
pub mod json;
pub mod markdown;

pub use console::ConsoleReporter;
pub use json::JsonReporter;
pub use markdown::MarkdownReporter;

/// Report format
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFormat {
    Console,
    Json,
    Markdown,
}

impl std::str::FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "console" => Ok(ReportFormat::Console),
            "json" => Ok(ReportFormat::Json),
            "markdown" | "md" => Ok(ReportFormat::Markdown),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

impl ScanReport {
    pub fn print(&self, format: &ReportFormat) -> Result<()> {
        match format {
            ReportFormat::Console => ConsoleReporter::print(self),
            ReportFormat::Json => JsonReporter::print(self),
            ReportFormat::Markdown => MarkdownReporter::print(self),
        }
    }

    pub fn save(&self, path: &str, format: &ReportFormat) -> Result<()> {
        let content = match format {
            ReportFormat::Console => ConsoleReporter::format(self)?,
            ReportFormat::Json => JsonReporter::format(self)?,
            ReportFormat::Markdown => MarkdownReporter::format(self)?,
        };

        fs::write(path, content)?;
        Ok(())
    }

    pub fn exit_code(&self) -> i32 {
        if self.summary.critical > 0 || self.summary.high > 0 {
            1
        } else if self.summary.total > 0 {
            0
        } else {
            0
        }
    }
}

pub trait Reporter {
    fn print(report: &ScanReport) -> Result<()>;
    fn format(report: &ScanReport) -> Result<String>;
}

/// Get colored severity string
pub fn severity_color(severity: VulnSeverity) -> colored::ColoredString {
    match severity {
        VulnSeverity::Critical => "CRITICAL".red().bold(),
        VulnSeverity::High => "HIGH".red().bold(),
        VulnSeverity::Medium => "MEDIUM".yellow().bold(),
        VulnSeverity::Low => "LOW".blue().bold(),
        VulnSeverity::Info => "INFO".white().bold(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_format_from_str() {
        assert_eq!("console".parse::<ReportFormat>().unwrap(), ReportFormat::Console);
        assert_eq!("json".parse::<ReportFormat>().unwrap(), ReportFormat::Json);
        assert_eq!("markdown".parse::<ReportFormat>().unwrap(), ReportFormat::Markdown);
        assert_eq!("md".parse::<ReportFormat>().unwrap(), ReportFormat::Markdown);
    }

    #[test]
    fn test_severity_color() {
        let colored = severity_color(VulnSeverity::Critical);
        assert!(colored.to_string().contains("CRITICAL"));
    }
}
