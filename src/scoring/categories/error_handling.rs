//! Error Handling Category
//!
//! Max points: 8
//!
//! Assesses:
//! - No stack traces exposed to users
//! - Generic error messages
//! - Security logging of errors
//! - Proper HTTP status codes
//! - No information leakage in errors

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const STACK_TRACE_KEYWORDS: &[&str] = &[
    "stack trace", "stacktrace", "call stack", "exception stack",
    "debug information", "debug mode", "development mode",
    "detailed error", "verbose error",
];

const ERROR_LEAK_KEYWORDS: &[&str] = &[
    "error leak", "information disclosure", "sensitive error",
    "internal error", "database error", "sql error",
    "path disclosure", "file path", "server path",
];

#[allow(dead_code)]
const GENERIC_ERROR_KEYWORDS: &[&str] = &[
    "generic error", "safe error", "error handling",
    "proper error", "secure error",
];

#[allow(dead_code)]
const LOGGING_KEYWORDS: &[&str] = &[
    "security logging", "audit log", "error logging",
    "log security event", "audit trail", "security event",
];

const DEBUG_MODE_KEYWORDS: &[&str] = &[
    "debug mode", "debug enabled", "development mode",
    "verbose mode", "detailed debug",
];

const CWE_STACK_TRACE: &str = "CWE-209";
const CWE_INFO_LEAK: &str = "CWE-200";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 8;
    let mut score = CategoryScore::new("Error Handling", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Stack trace exposure (-4 points)
        if contains_any(&title_lower, STACK_TRACE_KEYWORDS) || contains_any(&desc_lower, STACK_TRACE_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_STACK_TRACE.to_string()),
            );
            continue;
        }

        // Debug mode enabled (-4 points)
        if contains_any(&title_lower, DEBUG_MODE_KEYWORDS) || contains_any(&desc_lower, DEBUG_MODE_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_INFO_LEAK.to_string()),
            );
            continue;
        }

        // Information leakage in errors (-3 points)
        if contains_any(&title_lower, ERROR_LEAK_KEYWORDS) || contains_any(&desc_lower, ERROR_LEAK_KEYWORDS) {
            if title_lower.contains("database") || title_lower.contains("sql") ||
               title_lower.contains("path") || title_lower.contains("internal") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_INFO_LEAK.to_string()),
                );
                continue;
            }
        }

        // Verbose error messages (-2 points)
        if title_lower.contains("verbose error") || title_lower.contains("detailed error") {
            score.apply_penalty(
                2,
                vuln.title.clone(),
                vuln.severity,
                None,
            );
            continue;
        }
    }

    // Bonus for generic error messages
    let has_generic_errors = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("generic error") || title.contains("safe error")) &&
        (title.contains("detected") || title.contains("present"))
    });

    if has_generic_errors {
        score.apply_bonus(1, "Generic error messages detected".to_string());
    }

    // Bonus for security logging
    let has_logging = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("security logging") || title.contains("audit")) &&
        (title.contains("detected") || title.contains("present") || title.contains("enabled"))
    });

    if has_logging {
        score.apply_bonus(1, "Security logging detected".to_string());
    }

    score
}

fn contains_any(text: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|&kw| text.contains(kw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Target, Vuln};

    #[test]
    fn test_stack_trace_exposure() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Stack trace exposed in error page".to_string(),
            description: "Full stack trace shown to users on error".to_string(),
            location: Some("/error".to_string()),
            recommendation: Some("Use generic error messages".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 4); // 8 - 4
    }

    #[test]
    fn test_debug_mode_enabled() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Debug mode enabled in production".to_string(),
            description: "Application running with debug mode".to_string(),
            location: None,
            recommendation: Some("Disable debug mode".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 4); // 8 - 4
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 8);
    }
}
