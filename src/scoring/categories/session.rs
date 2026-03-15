//! Session Management Category
//!
//! Max points: 8
//!
//! Assesses:
//! - Secure cookie flags (HttpOnly, Secure, SameSite)
//! - Session timeout configuration
//! - Session ID strength and randomness
//! - Session fixation prevention
//! - Proper session invalidation

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const COOKIE_KEYWORDS: &[&str] = &[
    "cookie", "httpOnly", "secure flag", "sameSite",
    "missing secure", "missing httponly", "missing samesite",
    "insecure cookie", "cookie security",
];

const SESSION_TIMEOUT_KEYWORDS: &[&str] = &[
    "session timeout", "session expiration", "inactive session",
    "long session", "never expires", "session duration",
];

const SESSION_ID_KEYWORDS: &[&str] = &[
    "session id", "session token", "session identifier",
    "weak session", "predictable session", "short session id",
    "sequential session",
];

const SESSION_FIXATION_KEYWORDS: &[&str] = &[
    "session fixation", "fixed session", "session hijacking",
    "session impersonation",
];

const SESSION_INVALIDATION_KEYWORDS: &[&str] = &[
    "session invalidation", "logout", "session termination",
    "session not cleared", "session persists",
];

const CWE_INSECURE_COOKIE: &str = "CWE-614";
const CWE_SESSION_FIXATION: &str = "CWE-384";
const CWE_WEAK_SESSION: &str = "CWE-384";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 8;
    let mut score = CategoryScore::new("Session Management", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Session fixation (-4 points)
        if contains_any(&title_lower, SESSION_FIXATION_KEYWORDS) || contains_any(&desc_lower, SESSION_FIXATION_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_SESSION_FIXATION.to_string()),
            );
            continue;
        }

        // Weak session ID (-3 points)
        if contains_any(&title_lower, SESSION_ID_KEYWORDS) || contains_any(&desc_lower, SESSION_ID_KEYWORDS) {
            if title_lower.contains("weak") || title_lower.contains("predictable") ||
               title_lower.contains("short") || title_lower.contains("sequential") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_WEAK_SESSION.to_string()),
                );
                continue;
            }
        }

        // Insecure cookies (-2 points per missing flag)
        if contains_any(&title_lower, COOKIE_KEYWORDS) || contains_any(&desc_lower, COOKIE_KEYWORDS) {
            if title_lower.contains("missing secure") || title_lower.contains("without secure") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_INSECURE_COOKIE.to_string()),
                );
                continue;
            }
            if title_lower.contains("missing httponly") || title_lower.contains("without httponly") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_INSECURE_COOKIE.to_string()),
                );
                continue;
            }
            if title_lower.contains("missing samesite") || title_lower.contains("without samesite") {
                score.apply_penalty(
                    1,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_INSECURE_COOKIE.to_string()),
                );
                continue;
            }
        }

        // Excessive session timeout (-2 points)
        if contains_any(&title_lower, SESSION_TIMEOUT_KEYWORDS) || contains_any(&desc_lower, SESSION_TIMEOUT_KEYWORDS) {
            if title_lower.contains("long") || title_lower.contains("never") ||
               title_lower.contains("excessive") || title_lower.contains("too long") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Session not invalidated on logout (-2 points)
        if contains_any(&title_lower, SESSION_INVALIDATION_KEYWORDS) || contains_any(&desc_lower, SESSION_INVALIDATION_KEYWORDS) {
            if title_lower.contains("not cleared") || title_lower.contains("persists") ||
               title_lower.contains("not invalidated") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }
    }

    // Bonus for secure cookies
    let has_secure_cookies = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("cookie") &&
        (title.contains("secure") && title.contains("httponly"))
    });

    if has_secure_cookies {
        score.apply_bonus(1, "Secure cookie configuration detected".to_string());
    }

    // Bonus for proper session timeout
    let has_timeout = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("session timeout") &&
        (title.contains("good") || title.contains("proper") || title.contains("reasonable"))
    });

    if has_timeout {
        score.apply_bonus(1, "Proper session timeout configured".to_string());
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
    fn test_session_fixation() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Session fixation vulnerability".to_string(),
            description: "Session ID not regenerated after login".to_string(),
            location: Some("/login".to_string()),
            recommendation: Some("Regenerate session after authentication".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 4); // 8 - 4
    }

    #[test]
    fn test_missing_secure_cookie() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Missing Secure flag on cookie".to_string(),
            description: "Session cookie transmitted over HTTP".to_string(),
            location: None,
            recommendation: Some("Add Secure flag".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 6); // 8 - 2
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 8);
    }
}
