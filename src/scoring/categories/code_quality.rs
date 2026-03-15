//! Code Quality Category
//!
//! Max points: 12
//!
//! Assesses:
//! - No unsafe code blocks (Rust specific)
//! - No panic scenarios that could crash the app
//! - Updated dependencies (no known vulnerabilities)
//! - Proper error handling
//! - Code complexity
//! - Use of linters and static analysis

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const UNSAFE_KEYWORDS: &[&str] = &[
    "unsafe block", "unsafe code", "raw pointer",
    "unsafe rust", "memory safety",
];

const PANIC_KEYWORDS: &[&str] = &[
    "panic", "unwrap", "expect", "panic!",
    "runtime panic", "unrecoverable error",
];

const DEPENDENCY_KEYWORDS: &[&str] = &[
    "vulnerable dependency", "outdated dependency",
    "security advisory", "cve in dependency", "dependency vulnerability",
    "package vulnerability", "library vulnerability",
];

const ERROR_HANDLING_KEYWORDS: &[&str] = &[
    "error handling", "proper error", "unwrap without check",
    "ignored error", "unchecked result",
];

const CODE_COMPLEXITY_KEYWORDS: &[&str] = &[
    "complex code", "high complexity", "cyclomatic complexity",
    "nested code", "code smell",
];

const DEADCODE_KEYWORDS: &[&str] = &[
    "dead code", "unused code", "unreachable code",
    "commented code", "debug code",
];

const CWE_UNSAFE_CODE: &str = "CWE-787";
const CWE_VULN_DEP: &str = "CWE-1392";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 12;
    let mut score = CategoryScore::new("Code Quality", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Vulnerable dependencies (-5 points each)
        if contains_any(&title_lower, DEPENDENCY_KEYWORDS) || contains_any(&desc_lower, DEPENDENCY_KEYWORDS) {
            let penalty = match vuln.severity {
                VulnSeverity::Critical => 5,
                VulnSeverity::High => 4,
                VulnSeverity::Medium => 3,
                VulnSeverity::Low => 2,
                VulnSeverity::Info => 1,
            };
            score.apply_penalty(
                penalty,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_VULN_DEP.to_string()),
            );
            continue;
        }

        // Unsafe code blocks (-3 points)
        if contains_any(&title_lower, UNSAFE_KEYWORDS) || contains_any(&desc_lower, UNSAFE_KEYWORDS) {
            score.apply_penalty(
                3,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_UNSAFE_CODE.to_string()),
            );
            continue;
        }

        // Panic/unwrap issues (-2 points)
        if contains_any(&title_lower, PANIC_KEYWORDS) || contains_any(&desc_lower, PANIC_KEYWORDS) {
            if title_lower.contains("unwrap") || title_lower.contains("expect") ||
               title_lower.contains("panic!") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Poor error handling (-2 points)
        if contains_any(&title_lower, ERROR_HANDLING_KEYWORDS) || contains_any(&desc_lower, ERROR_HANDLING_KEYWORDS) {
            if title_lower.contains("ignored") || title_lower.contains("unchecked") ||
               title_lower.contains("without check") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // High complexity (-1 point)
        if contains_any(&title_lower, CODE_COMPLEXITY_KEYWORDS) || contains_any(&desc_lower, CODE_COMPLEXITY_KEYWORDS) {
            score.apply_penalty(
                1,
                vuln.title.clone(),
                vuln.severity,
                None,
            );
            continue;
        }

        // Dead code (-1 point)
        if contains_any(&title_lower, DEADCODE_KEYWORDS) || contains_any(&desc_lower, DEADCODE_KEYWORDS) {
            score.apply_penalty(
                1,
                vuln.title.clone(),
                vuln.severity,
                None,
            );
            continue;
        }
    }

    // Bonus for updated dependencies
    let has_updated_deps = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("depend") &&
        (title.contains("updated") || title.contains("latest") || title.contains("secure"))
    });

    if has_updated_deps {
        score.apply_bonus(1, "Dependencies are up to date".to_string());
    }

    // Bonus for proper error handling
    let has_error_handling = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("error handling") &&
        (title.contains("good") || title.contains("proper") || title.contains("detected"))
    });

    if has_error_handling {
        score.apply_bonus(1, "Proper error handling detected".to_string());
    }

    // Bonus for using linters/static analysis
    let has_analysis = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("clippy") || title.contains("linter") || title.contains("static analysis")) &&
        (title.contains("used") || title.contains("enabled") || title.contains("passed"))
    });

    if has_analysis {
        score.apply_bonus(1, "Static analysis/linting detected".to_string());
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
    fn test_vulnerable_dependency() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Vulnerable dependency detected".to_string(),
            description: "Dependency 'hyper' has known CVE-2023-1234".to_string(),
            location: Some("Cargo.toml".to_string()),
            recommendation: Some("Update to version 1.0.0 or later".to_string()),
            cwe: Some("CWE-1392".to_string()),
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 8); // 12 - 4 for High
    }

    #[test]
    fn test_unsafe_code() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Unsafe block detected".to_string(),
            description: "Unsafe code block in main.rs".to_string(),
            location: Some("src/main.rs:42".to_string()),
            recommendation: Some("Review safety or remove unsafe".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 9); // 12 - 3
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 12);
    }
}
