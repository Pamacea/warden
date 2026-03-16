//! Console reporter

use super::{severity_color, Reporter};
use crate::scanners::ScanReport;
use crate::scoring::SecurityScore;
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

        let security_score = SecurityScore::calculate(report);

        // Header
        output.push_str(&format!(
            "\n{} {}\n",
            "Scan Report".bold(),
            format!("({})", report.timestamp).dimmed()
        ));
        output.push_str(&format!("{} {}\n\n", "Target:".bold(), report.target));

        // Security score summary
        output.push_str(&format!("{} ", "Security Score:".bold()));
        let score_colored = if security_score.score >= 80.0 {
            format!("{:.1}/100", security_score.score).green().bold()
        } else if security_score.score >= 60.0 {
            format!("{:.1}/100", security_score.score).yellow().bold()
        } else {
            format!("{:.1}/100", security_score.score).red().bold()
        };
        output.push_str(&format!("{}\n", score_colored));

        let grade_colored = format!("[{}]", security_score.grade.as_str())
            .color(security_score.grade.color())
            .bold();
        output.push_str(&format!("{} {}\n", "Grade:".bold(), grade_colored));
        output.push('\n');

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Target, Vuln, VulnSeverity};

    #[test]
    fn test_console_format_empty_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let formatted = ConsoleReporter::format(&report).unwrap();

        assert!(formatted.contains("Scan Report"));
        assert!(formatted.contains("No vulnerabilities found"));
    }

    #[test]
    fn test_console_format_with_findings() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            location: Some("/test".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-123".to_string()),
            owasp: None,
        });

        let formatted = ConsoleReporter::format(&report).unwrap();

        assert!(formatted.contains("Test Vulnerability"));
        assert!(formatted.contains("Test description"));
        assert!(formatted.contains("/test"));
        assert!(formatted.contains("Fix it"));
        assert!(formatted.contains("HIGH"));
    }

    #[test]
    fn test_console_format_severity_levels() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        for severity in [
            VulnSeverity::Critical,
            VulnSeverity::High,
            VulnSeverity::Medium,
            VulnSeverity::Low,
            VulnSeverity::Info,
        ] {
            report.add_finding(Vuln {
                severity,
                title: format!("{:?} Test", severity),
                description: "Test".to_string(),
                location: None,
                recommendation: None,
                cwe: None,
                owasp: None,
            });
        }

        let formatted = ConsoleReporter::format(&report).unwrap();

        assert!(formatted.contains("CRITICAL"));
        assert!(formatted.contains("HIGH"));
        assert!(formatted.contains("MEDIUM"));
        assert!(formatted.contains("LOW"));
        assert!(formatted.contains("INFO"));
    }
}
