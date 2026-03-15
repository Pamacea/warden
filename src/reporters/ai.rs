//! AI-Readable reporter
//!
//! Generates reports optimized for AI agents like Claude Code to read and act upon.
//! Features:
//! - Absolute file paths (clickable in Claude Code)
//! - Line numbers for precise navigation
//! - Grouped by file for systematic fixing
//! - Structured JSON export for programmatic processing

use super::Reporter;
use crate::scanners::{ScanReport, VulnSeverity};
use anyhow::Result;
use std::collections::HashMap;

pub struct AiReadableReporter;

impl Reporter for AiReadableReporter {
    fn print(report: &ScanReport) -> Result<()> {
        println!("{}", Self::format(report)?);
        Ok(())
    }

    fn format(report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        // Header with clear AI context
        output.push_str("# Warden Security Scan Report\n\n");
        output.push_str("> **AI Agent Instructions:** This report is structured for systematic security fixes.\n");
        output.push_str("> Each finding includes file path, line numbers, and actionable recommendations.\n\n");

        output.push_str(&format!("**Target:** {}\n", report.target));
        output.push_str(&format!("**Scan Time:** {}\n", report.timestamp));
        output.push_str(&format!("**Warden Version:** {}\n\n", env!("CARGO_PKG_VERSION")));

        // Quick Summary for AI
        output.push_str("## 📊 Scan Summary\n\n");
        output.push_str("| Severity | Count | Priority |\n");
        output.push_str("|----------|-------|----------|\n");
        output.push_str(&format!("| 🔴 CRITICAL | {} | Fix Immediately |\n", report.summary.critical));
        output.push_str(&format!("| 🔴 HIGH | {} | Fix Soon |\n", report.summary.high));
        output.push_str(&format!("| 🟡 MEDIUM | {} | Fix Priority |\n", report.summary.medium));
        output.push_str(&format!("| 🔵 LOW | {} | Fix When Possible |\n", report.summary.low));
        output.push_str(&format!("| ⚪ INFO | {} | Review |\n", report.summary.info));
        output.push_str(&format!("| **Total** | **{}** |\n\n", report.summary.total));

        if report.findings.is_empty() {
            output.push_str("## ✅ Result\n\n");
            output.push_str("No security vulnerabilities found. Great job!\n\n");
            return Ok(output);
        }

        // Group findings by file for systematic fixing
        let findings_by_file = group_by_file(&report.findings);

        // Section 1: Files to Fix (indexed)
        output.push_str("## 📁 Files to Fix\n\n");
        for (file_path, findings) in &findings_by_file {
            let critical_count = findings.iter().filter(|f| matches!(f.severity, VulnSeverity::Critical | VulnSeverity::High)).count();
            let urgency = if critical_count > 0 { "🔴" } else { "🟡" };
            output.push_str(&format!("{} [`{}`]({}) - {} issue(s)\n",
                urgency,
                file_path,
                file_path,
                findings.len()
            ));
        }
        output.push_str("\n");

        // Section 2: Detailed Findings (ordered by severity)
        output.push_str("## 🔍 Detailed Findings\n\n");

        // Sort by severity (critical first)
        let mut sorted_findings = report.findings.clone();
        sorted_findings.sort_by_key(|f| {
            match f.severity {
                VulnSeverity::Critical => 0,
                VulnSeverity::High => 1,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 3,
                VulnSeverity::Info => 4,
            }
        });

        for (i, finding) in sorted_findings.iter().enumerate() {
            let emoji = match finding.severity {
                VulnSeverity::Critical => "🔴",
                VulnSeverity::High => "🔴",
                VulnSeverity::Medium => "🟡",
                VulnSeverity::Low => "🔵",
                VulnSeverity::Info => "⚪",
            };

            output.push_str(&format!("### {} {}. {}\n\n", emoji, i + 1, finding.title));

            // Priority indicator
            let priority = match finding.severity {
                VulnSeverity::Critical => "🚨 **CRITICAL** - Fix immediately",
                VulnSeverity::High => "⚠️ **HIGH** - Fix soon",
                VulnSeverity::Medium => "📌 **MEDIUM** - Fix priority",
                VulnSeverity::Low => "📝 **LOW** - Fix when possible",
                VulnSeverity::Info => "ℹ️ **INFO** - Review",
            };
            output.push_str(&format!("**Priority:** {}\n\n", priority));

            // Location with line numbers (AI-friendly format)
            if let Some(ref location) = finding.location {
                output.push_str(&format!("**Location:** `{}`\n\n", location));
                output.push_str(&format!("> **AI:** Use `Read` tool to view `{}`\n\n", location));
            }

            output.push_str(&format!("**Description:**\n\n{}\n\n", finding.description));

            if let Some(ref recommendation) = finding.recommendation {
                output.push_str(&format!("**Fix:**\n\n{}\n\n", recommendation));
            }

            if let Some(ref cwe) = finding.cwe {
                output.push_str(&format!("**CWE:** `{}`\n", cwe));
            }
            if let Some(ref owasp) = finding.owasp {
                output.push_str(&format!(" **OWASP:** `{}`\n\n", owasp));
            } else {
                output.push('\n');
            }

            output.push_str("---\n\n");
        }

        // Section 3: AI Action Plan
        output.push_str("## 🤖 Suggested Fix Order\n\n");
        let critical_high: Vec<_> = sorted_findings.iter()
            .filter(|f| matches!(f.severity, VulnSeverity::Critical | VulnSeverity::High))
            .collect();

        if !critical_high.is_empty() {
            output.push_str("### Phase 1: Critical & High (Do First)\n\n");
            for (i, finding) in critical_high.iter().enumerate() {
                if let Some(ref location) = finding.location {
                    output.push_str(&format!("{}. [`{}`]({}) - {}\n",
                        i + 1, location, location, finding.title));
                } else {
                    output.push_str(&format!("{}. {}\n", i + 1, finding.title));
                }
            }
            output.push('\n');
        }

        let medium: Vec<_> = sorted_findings.iter()
            .filter(|f| matches!(f.severity, VulnSeverity::Medium))
            .collect();

        if !medium.is_empty() {
            output.push_str("### Phase 2: Medium (Do Next)\n\n");
            for (i, finding) in medium.iter().enumerate() {
                if let Some(ref location) = finding.location {
                    output.push_str(&format!("{}. [`{}`]({}) - {}\n",
                        i + 1, location, location, finding.title));
                } else {
                    output.push_str(&format!("{}. {}\n", i + 1, finding.title));
                }
            }
            output.push('\n');
        }

        // Footer
        output.push_str(&format!(
            "\n*Generated by [Warden](https://github.com/Pamacea/warden) v{}* - AI-Readable Report\n",
            env!("CARGO_PKG_VERSION")
        ));

        Ok(output)
    }
}

/// Generate JSON export for programmatic AI processing
pub fn generate_ai_json(report: &ScanReport) -> Result<String> {
    use serde_json::json;

    let mut findings_array = Vec::new();

    for finding in &report.findings {
        let mut obj = serde_json::Map::new();
        obj.insert("severity".to_string(), json!(finding.severity.to_string()));
        obj.insert("title".to_string(), json!(finding.title));
        obj.insert("description".to_string(), json!(finding.description));

        if let Some(ref location) = finding.location {
            obj.insert("location".to_string(), json!(location));
            // Try to extract file path and line number
            if let Some((file, line)) = parse_location(location) {
                obj.insert("file".to_string(), json!(file));
                obj.insert("line".to_string(), json!(line));
            }
        }

        if let Some(ref recommendation) = finding.recommendation {
            obj.insert("recommendation".to_string(), json!(recommendation));
        }
        if let Some(ref cwe) = finding.cwe {
            obj.insert("cwe".to_string(), json!(cwe));
        }
        if let Some(ref owasp) = finding.owasp {
            obj.insert("owasp".to_string(), json!(owasp));
        }

        findings_array.push(obj);
    }

    let json_output = json!({
        "target": report.target.to_string(),
        "timestamp": report.timestamp,
        "version": env!("CARGO_PKG_VERSION"),
        "summary": {
            "critical": report.summary.critical,
            "high": report.summary.high,
            "medium": report.summary.medium,
            "low": report.summary.low,
            "info": report.summary.info,
            "total": report.summary.total
        },
        "findings": findings_array
    });

    Ok(serde_json::to_string_pretty(&json_output)?)
}

/// Group findings by file path
fn group_by_file(findings: &[crate::scanners::Vuln]) -> HashMap<String, Vec<&crate::scanners::Vuln>> {
    let mut map: HashMap<String, Vec<&crate::scanners::Vuln>> = HashMap::new();

    for finding in findings {
        if let Some(ref location) = finding.location {
            let file_path = if let Some((file, _)) = parse_location(location) {
                file.to_string()
            } else {
                location.clone()
            };
            map.entry(file_path).or_default().push(finding);
        }
    }

    map
}

/// Parse location string to extract (file_path, line_number)
/// Handles formats: "src/main.rs:42", "src/main.rs:42:50", etc.
/// Returns (file_path_without_line_numbers, line_number)
fn parse_location(location: &str) -> Option<(&str, Option<usize>)> {
    // Try to find line number (last occurrence of :)
    if let Some(colon_pos) = location.rfind(':') {
        let file_part = &location[..colon_pos];
        let line_part = &location[colon_pos + 1..];

        // Check if the part after : is a number
        if let Ok(line_num) = line_part.parse::<usize>() {
            // Remove any line/column numbers from file path
            // e.g., "src/auth.ts:15:30" -> "src/auth.ts"
            let clean_path = if let Some(first_colon) = file_part.find(':') {
                &file_part[..first_colon]
            } else {
                file_part
            };
            return Some((clean_path, Some(line_num)));
        }
    }

    Some((location, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Target, Vuln, VulnSeverity};

    #[test]
    fn test_parse_location_with_line() {
        assert_eq!(parse_location("src/main.rs:42"), Some(("src/main.rs", Some(42))));
        assert_eq!(parse_location("src/auth.ts:15:30"), Some(("src/auth.ts", Some(30))));
    }

    #[test]
    fn test_ai_format_includes_sections() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test Vulnerability".to_string(),
            description: "A test issue".to_string(),
            location: Some("src/main.rs:42".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        let formatted = AiReadableReporter::format(&report).unwrap();

        assert!(formatted.contains("Files to Fix"));
        assert!(formatted.contains("Detailed Findings"));
        assert!(formatted.contains("Suggested Fix Order"));
        assert!(formatted.contains("src/main.rs:42"));
    }

    #[test]
    fn test_ai_json_generation() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: Some("src/main.rs:42".to_string()),
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let json = generate_ai_json(&report).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["findings"].as_array().unwrap().len() == 1);
    }
}
