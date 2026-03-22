//! Authentication & Authorization Category
//!
//! Max points: 12
//!
//! Assesses:
//! - Multi-Factor Authentication (MFA)
//! - Password policy strength
//! - Session management
//! - JWT security
//! - CSRF protection
//! - Rate limiting
//! - User enumeration prevention

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

#[allow(dead_code)]
const MFA_KEYWORDS: &[&str] = &[
    "mfa", "multi-factor", "2fa", "two-factor",
    "totp", "totp backup", "authenticator app",
];

const PASSWORD_KEYWORDS: &[&str] = &[
    "weak password", "password policy", "password complexity",
    "password requirements", "common password", "default password",
    "blank password", "short password",
];

const SESSION_KEYWORDS: &[&str] = &[
    "session fixation", "session hijacking", "session management",
    "session timeout", "insecure session", "session prediction",
];

const JWT_KEYWORDS: &[&str] = &[
    "jwt", "json web token", "weak jwt", "jwt algorithm",
    "jwt signature", "none algorithm", "jwt secret",
];

const CSRF_KEYWORDS: &[&str] = &[
    "csrf", "cross-site request forgery", "xsrf",
    "anti-csrf", "csrf token", "missing csrf",
];

const RATE_LIMIT_KEYWORDS: &[&str] = &[
    "rate limit", "rate limiting", "brute force",
    "login attempt", "account lockout", "throttle",
];

const ENUMERATION_KEYWORDS: &[&str] = &[
    "user enumeration", "account enumeration", "username enumeration",
    "email enumeration", "timing attack", "response differs",
];

const CWE_WEAK_PASSWORD: &str = "CWE-521";
const CWE_SESSION_FIXATION: &str = "CWE-384";
const CWE_WEAK_JWT: &str = "CWE-347";
const CWE_CSRF: &str = "CWE-352";
const CWE_RATE_LIMIT: &str = "CWE-307";
const CWE_ENUMERATION: &str = "CWE-204";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 12;
    let mut score = CategoryScore::new("Authentication", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // User enumeration (-4 points)
        if contains_any(&title_lower, ENUMERATION_KEYWORDS) || contains_any(&desc_lower, ENUMERATION_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_ENUMERATION.to_string()),
            );
            continue;
        }

        // Weak password policy (-3 points)
        if contains_any(&title_lower, PASSWORD_KEYWORDS) || contains_any(&desc_lower, PASSWORD_KEYWORDS) {
            score.apply_penalty(
                3,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_WEAK_PASSWORD.to_string()),
            );
            continue;
        }

        // Missing MFA (-3 points)
        if title_lower.contains("mfa") || title_lower.contains("2fa") {
            if title_lower.contains("missing") || title_lower.contains("no mfa") || title_lower.contains("without") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Session fixation (-4 points)
        if contains_any(&title_lower, SESSION_KEYWORDS) || contains_any(&desc_lower, SESSION_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_SESSION_FIXATION.to_string()),
            );
            continue;
        }

        // Weak JWT (-3 points)
        if contains_any(&title_lower, JWT_KEYWORDS) || contains_any(&desc_lower, JWT_KEYWORDS) {
            if title_lower.contains("weak") || title_lower.contains("none") || title_lower.contains("secret") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_WEAK_JWT.to_string()),
                );
                continue;
            }
        }

        // Missing CSRF protection (-3 points)
        if contains_any(&title_lower, CSRF_KEYWORDS) || contains_any(&desc_lower, CSRF_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("no csrf") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_CSRF.to_string()),
                );
                continue;
            }
        }

        // Missing rate limiting (-2 points)
        if contains_any(&title_lower, RATE_LIMIT_KEYWORDS) || contains_any(&desc_lower, RATE_LIMIT_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("no rate") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_RATE_LIMIT.to_string()),
                );
                continue;
            }
        }
    }

    // Check for MFA presence (bonus)
    let has_mfa = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("mfa") || title.contains("2fa")) &&
        (title.contains("enabled") || title.contains("detected") || title.contains("present"))
    });

    if has_mfa {
        score.apply_bonus(2, "Multi-factor authentication enabled".to_string());
    }

    // Check for CSRF protection (bonus)
    let has_csrf = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("csrf") &&
        (title.contains("present") || title.contains("detected") || title.contains("token found"))
    });

    if has_csrf {
        score.apply_bonus(1, "CSRF protection detected".to_string());
    }

    // Check for rate limiting (bonus)
    let has_rate_limit = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("rate limit") &&
        (title.contains("detected") || title.contains("present"))
    });

    if has_rate_limit {
        score.apply_bonus(1, "Rate limiting detected".to_string());
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
    fn test_user_enumeration() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "User enumeration possible".to_string(),
            description: "Response timing differs for valid vs invalid usernames".to_string(),
            location: Some("/api/user/check".to_string()),
            recommendation: Some("Use consistent responses".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 8); // 12 - 4
    }

    #[test]
    fn test_mfa_bonus() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: "MFA detected".to_string(),
            description: "Multi-factor authentication is enabled".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 12); // Full + bonus
        assert!(!score.bonuses.is_empty());
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 12);
    }
}
