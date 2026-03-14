//! Console reporter

use super::{severity_color, Reporter};
use crate::scanners::ScanReport;
use anyhow::Result;
use colored::Colorize;

pub struct ConsoleReporter;

impl Reporter for ConsoleReporter {
    fn print(report: &ScanReport) -> Result<()> {
        println!("{}", Self::format(report)?);
        Ok(())
    }

    fn format(report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "\n{} {}\n",
            "Scan Report".bold(),
            format!("({})", report.timestamp).dimmed()
        ));
        output.push_str(&format!("{} {}\n\n", "Target:".bold(), report.target));

        // Findings
        if report.findings.is_empty() {
            output.push_str(&format!("  {} No vulnerabilities found\n\n", "✓".green()));
        } else {
            output.push_str(&format!(
                "  {} {} findings\n\n",
                "⚠".yellow(),
                report.summary.total
            ));

            for (i, finding) in report.findings.iter().enumerate() {
                output.push_str(&format!(
                    "  {} {} {}\n",
                    format!("[{}]", i + 1).dimmed(),
                    severity_color(finding.severity),
                    finding.title.bold()
                ));

                if let Some(ref location) = finding.location {
                    output.push_str(&format!("    {} {}\n", "Location:".bold(), location));
                }

                output.push_str(&format!("    {} {}\n", "Description:".bold(), finding.description));

                if let Some(ref recommendation) = finding.recommendation {
                    output.push_str(&format!("    {} {}\n", "Fix:".green().bold(), recommendation));
                }

                output.push('\n');
            }
        }

        // Summary
        output.push_str(&format!(
            "{}\n",
            "─".repeat(80).dimmed()
        ));
        output.push_str(&format!("{} ", "Summary:".bold()));

        if report.summary.critical > 0 {
            output.push_str(&format!("{}: {} ", "CRITICAL".red().bold(), report.summary.critical));
        }
        if report.summary.high > 0 {
            output.push_str(&format!("{}: {} ", "HIGH".red().bold(), report.summary.high));
        }
        if report.summary.medium > 0 {
            output.push_str(&format!("{}: {} ", "MEDIUM".yellow().bold(), report.summary.medium));
        }
        if report.summary.low > 0 {
            output.push_str(&format!("{}: {} ", "LOW".blue().bold(), report.summary.low));
        }
        if report.summary.info > 0 {
            output.push_str(&format!("{}: {} ", "INFO".white().bold(), report.summary.info));
        }

        if report.summary.total == 0 {
            output.push_str(&format!("{}\n", "No vulnerabilities found".green()));
        }

        output.push('\n');

        Ok(output)
    }
}
