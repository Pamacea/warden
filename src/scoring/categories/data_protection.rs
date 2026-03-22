//! Data Protection Category
//!
//! Max points: 8
//!
//! Assesses:
//! - Sensitive data masking in logs/error messages
//! - No client-side storage of sensitive data
//! - PII encryption at rest
//! - Data minimization
//! - Secure data transmission

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

#[allow(dead_code)]
const DATA_EXPOSURE_KEYWORDS: &[&str] = &[
    "data exposure", "sensitive data", "password in log",
    "credit card", "ssn", "social security", "personal data",
    "leaked data", "data leak", "information disclosure",
];

#[allow(dead_code)]
const PII_KEYWORDS: &[&str] = &[
    "pii", "personal identifiable", "personal information",
    "personal data", "customer data", "user data",
];

const LOCALSTORAGE_KEYWORDS: &[&str] = &[
    "localstorage", "session storage", "indexeddb",
    "cookie", "sensitive in storage", "token in storage",
    "password in storage", "client-side storage",
];

const LOGGING_KEYWORDS: &[&str] = &[
    "log", "logging", "stack trace", "debug information",
    "error message", "verbose error", "information leakage",
];

const ENCRYPTION_KEYWORDS: &[&str] = &[
    "encryption", "encrypt at rest", "data in transit",
    "plaintext", "unencrypted", "cleartext",
];

const CWE_DATA_EXPOSURE: &str = "CWE-200";
const CWE_SENSITIVE_DATA: &str = "CWE-312";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 8;
    let mut score = CategoryScore::new("Data Protection", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Sensitive data exposure (-4 points)
        if contains_any(&title_lower, DATA_EXPOSURE_KEYWORDS) || contains_any(&desc_lower, DATA_EXPOSURE_KEYWORDS) {
            if title_lower.contains("password") || title_lower.contains("credit card") ||
               title_lower.contains("ssn") || title_lower.contains("token") {
                score.apply_penalty(
                    4,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_DATA_EXPOSURE.to_string()),
                );
                continue;
            }
        }

        // PII in client-side storage (-3 points)
        if contains_any(&title_lower, LOCALSTORAGE_KEYWORDS) || contains_any(&desc_lower, LOCALSTORAGE_KEYWORDS) {
            if title_lower.contains("pii") || title_lower.contains("personal") ||
               title_lower.contains("password") || title_lower.contains("token") ||
               title_lower.contains("sensitive") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_SENSITIVE_DATA.to_string()),
                );
                continue;
            }
        }

        // Sensitive data in logs (-3 points)
        if contains_any(&title_lower, LOGGING_KEYWORDS) || contains_any(&desc_lower, LOGGING_KEYWORDS) {
            if title_lower.contains("password") || title_lower.contains("token") ||
               title_lower.contains("sensitive") || title_lower.contains("pii") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_DATA_EXPOSURE.to_string()),
                );
                continue;
            }
        }

        // Verbose error messages exposing data (-2 points)
        if contains_any(&title_lower, LOGGING_KEYWORDS) || contains_any(&desc_lower, LOGGING_KEYWORDS) {
            if title_lower.contains("verbose") || title_lower.contains("stack trace") ||
               title_lower.contains("debug information") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_DATA_EXPOSURE.to_string()),
                );
                continue;
            }
        }

        // Unencrypted sensitive data (-3 points)
        if contains_any(&title_lower, ENCRYPTION_KEYWORDS) || contains_any(&desc_lower, ENCRYPTION_KEYWORDS) {
            if title_lower.contains("plaintext") || title_lower.contains("unencrypted") ||
               title_lower.contains("cleartext") || title_lower.contains("no encryption") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }
    }

    // Bonus for data encryption
    let has_encryption = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("encryption") &&
        (title.contains("detected") || title.contains("present") || title.contains("enabled"))
    });

    if has_encryption {
        score.apply_bonus(1, "Data encryption detected".to_string());
    }

    // Bonus for proper error handling
    let has_proper_errors = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("error") &&
        (title.contains("generic") || title.contains("safe") || title.contains("proper"))
    });

    if has_proper_errors {
        score.apply_bonus(1, "Proper error handling detected".to_string());
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
    fn test_password_in_log() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Password logged in error message".to_string(),
            description: "Application logs passwords on login failure".to_string(),
            location: Some("/login".to_string()),
            recommendation: Some("Remove sensitive data from logs".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 4); // 8 - 4
    }

    #[test]
    fn test_token_in_localstorage() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "JWT token stored in localStorage".to_string(),
            description: "Authentication token stored in localStorage".to_string(),
            location: None,
            recommendation: Some("Use httpOnly cookies instead".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 5); // 8 - 3
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 8);
    }
}
