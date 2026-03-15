//! Input Validation Category
//!
//! Max points: 12
//!
//! Assesses protection against:
//! - XSS (Cross-Site Scripting)
//! - SQL Injection
//! - Command Injection
//! - Path Traversal
//! - Open Redirect
//! - SSRF (Server-Side Request Forgery)

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

/// Keywords that indicate input validation vulnerabilities
const XSS_KEYWORDS: &[&str] = &[
    "xss", "cross-site scripting", "cross site scripting",
    "script injection", "html injection", "reflected xss",
    "stored xss", "dom xss",
];

const SQLI_KEYWORDS: &[&str] = &[
    "sqli", "sql injection", "sql injection",
    "blind sql injection", "union-based sql injection",
    "database injection",
];

const CMD_INJECTION_KEYWORDS: &[&str] = &[
    "command injection", "os command injection", "rce",
    "remote code execution", "code injection",
    "shell injection", "system command injection",
];

const PATH_TRAVERSAL_KEYWORDS: &[&str] = &[
    "path traversal", "directory traversal", "lfi",
    "local file inclusion", "file inclusion", "arbitrary file read",
    "../", "..\\",
];

const OPEN_REDIRECT_KEYWORDS: &[&str] = &[
    "open redirect", "unvalidated redirect", "url redirect",
    "redirect manipulation", "phishing via redirect",
];

const SSRF_KEYWORDS: &[&str] = &[
    "ssrf", "server-side request forgery", "server side request forgery",
    "internal port scan", "internal service access",
];

const CWE_XSS: &str = "CWE-79";
const CWE_SSQLI: &str = "CWE-89";
const CWE_CMD_INJECTION: &str = "CWE-78";
const CWE_PATH_TRAVERSAL: &str = "CWE-22";
const CWE_OPEN_REDIRECT: &str = "CWE-601";
const CWE_SSRF: &str = "CWE-918";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 12;
    let mut score = CategoryScore::new("Input Validation", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Check for XSS vulnerabilities (-5 points each)
        if contains_any(&title_lower, XSS_KEYWORDS) || contains_any(&desc_lower, XSS_KEYWORDS) {
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
                Some(CWE_XSS.to_string()),
            );
            continue;
        }

        // Check for SQL Injection (-5 points each)
        if contains_any(&title_lower, SQLI_KEYWORDS) || contains_any(&desc_lower, SQLI_KEYWORDS) {
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
                Some(CWE_SSQLI.to_string()),
            );
            continue;
        }

        // Check for Command Injection (-5 points each)
        if contains_any(&title_lower, CMD_INJECTION_KEYWORDS) || contains_any(&desc_lower, CMD_INJECTION_KEYWORDS) {
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
                Some(CWE_CMD_INJECTION.to_string()),
            );
            continue;
        }

        // Check for Path Traversal (-4 points each)
        if contains_any(&title_lower, PATH_TRAVERSAL_KEYWORDS) || contains_any(&desc_lower, PATH_TRAVERSAL_KEYWORDS) {
            let penalty = match vuln.severity {
                VulnSeverity::Critical => 4,
                VulnSeverity::High => 3,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 1,
                VulnSeverity::Info => 0,
            };
            score.apply_penalty(
                penalty,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_PATH_TRAVERSAL.to_string()),
            );
            continue;
        }

        // Check for Open Redirect (-3 points each)
        if contains_any(&title_lower, OPEN_REDIRECT_KEYWORDS) || contains_any(&desc_lower, OPEN_REDIRECT_KEYWORDS) {
            let penalty = match vuln.severity {
                VulnSeverity::High => 3,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 1,
                _ => 0,
            };
            score.apply_penalty(
                penalty,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_OPEN_REDIRECT.to_string()),
            );
            continue;
        }

        // Check for SSRF (-4 points each)
        if contains_any(&title_lower, SSRF_KEYWORDS) || contains_any(&desc_lower, SSRF_KEYWORDS) {
            let penalty = match vuln.severity {
                VulnSeverity::Critical => 4,
                VulnSeverity::High => 3,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 1,
                VulnSeverity::Info => 0,
            };
            score.apply_penalty(
                penalty,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_SSRF.to_string()),
            );
            continue;
        }
    }

    // Bonus for good practices
    // Check if report contains findings about input validation being present
    let has_validation_checks: bool = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        title.contains("validation") && (title.contains("present") || title.contains("implemented"))
    });

    if has_validation_checks {
        score.apply_bonus(1, "Input validation detected".to_string());
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
    fn test_xss_detection() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Reflected XSS vulnerability".to_string(),
            description: "Cross-site scripting in search parameter".to_string(),
            location: Some("/search?q=".to_string()),
            recommendation: Some("Sanitize input".to_string()),
            cwe: None,
            owasp: Some("A03:2021".to_string()),
        });

        let score = calculate(&report);
        assert_eq!(score.score, 7); // 12 - 5 for XSS
        assert_eq!(score.penalties.len(), 1);
        assert_eq!(score.penalties[0].points, 5);
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "SQL Injection in login form".to_string(),
            description: "Union-based SQL injection detected".to_string(),
            location: Some("/login".to_string()),
            recommendation: Some("Use prepared statements".to_string()),
            cwe: None,
            owasp: Some("A01:2021".to_string()),
        });

        let score = calculate(&report);
        assert_eq!(score.score, 7); // 12 - 5 for SQLi
        assert_eq!(score.penalties[0].cwe, Some(CWE_SSQLI.to_string()));
    }

    #[test]
    fn test_multiple_vulnerabilities() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "XSS vulnerability".to_string(),
            description: "Cross-site scripting".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "SQL Injection".to_string(),
            description: "SQL injection in user input".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 2); // 12 - 5 - 5
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 12); // Full points
    }
}
