//! Access Control Category
//!
//! Max points: 10
//!
//! Assesses:
//! - Principle of least privilege
//! - Proper permission checks
//! - IDOR (Insecure Direct Object Reference) prevention
//! - RBAC (Role-Based Access Control) implementation
//! - Privilege escalation prevention
//! - Authorization bypass prevention

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const IDOR_KEYWORDS: &[&str] = &[
    "idor", "insecure direct object reference", "direct object reference",
    "access other user", "access other resource", "unauthorized object access",
    "modify other user", "bypass authorization", "access control bypass",
];

const PRIVILEGE_ESCALATION_KEYWORDS: &[&str] = &[
    "privilege escalation", "privilege escalation", "vertical escalation",
    "horizontal escalation", "role escalation", "admin bypass",
    "gain admin", "escalate privileges",
];

const AUTHORIZATION_KEYWORDS: &[&str] = &[
    "authorization", "authorization bypass", "missing authorization",
    "no authorization", "authorization check", "unauthorized access",
];

const RBAC_KEYWORDS: &[&str] = &[
    "rbac", "role based", "role-based", "access control",
    "permission check", "role permission", "missing role check",
];

const HORIZONTAL_ESCALATION_KEYWORDS: &[&str] = &[
    "horizontal escalation", "access other user", "user impersonation",
    "switch user", "take over account",
];

const LEAST_PRIVILEGE_KEYWORDS: &[&str] = &[
    "least privilege", "excessive permission", "overprivileged",
    "unnecessary permission", "broad permission",
];

const CWE_IDOR: &str = "CWE-639";
const CWE_AUTHZ_BYPASS: &str = "CWE-285";
const CWE_PRIVILEGE_ESCALATION: &str = "CWE-269";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 10;
    let mut score = CategoryScore::new("Access Control", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Critical IDOR (-5 points)
        if contains_any(&title_lower, IDOR_KEYWORDS) || contains_any(&desc_lower, IDOR_KEYWORDS) {
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
                Some(CWE_IDOR.to_string()),
            );
            continue;
        }

        // Privilege escalation (-5 points)
        if contains_any(&title_lower, PRIVILEGE_ESCALATION_KEYWORDS) || contains_any(&desc_lower, PRIVILEGE_ESCALATION_KEYWORDS) {
            score.apply_penalty(
                5,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_PRIVILEGE_ESCALATION.to_string()),
            );
            continue;
        }

        // Authorization bypass (-5 points)
        if contains_any(&title_lower, AUTHORIZATION_KEYWORDS) || contains_any(&desc_lower, AUTHORIZATION_KEYWORDS) {
            if title_lower.contains("bypass") || title_lower.contains("missing") ||
               title_lower.contains("no authorization") || title_lower.contains("unauthorized access") {
                score.apply_penalty(
                    5,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_AUTHZ_BYPASS.to_string()),
                );
                continue;
            }
        }

        // Missing permission checks (-3 points)
        if contains_any(&title_lower, RBAC_KEYWORDS) || contains_any(&desc_lower, RBAC_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("no role") ||
               title_lower.contains("no permission") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Horizontal escalation (-3 points)
        if contains_any(&title_lower, HORIZONTAL_ESCALATION_KEYWORDS) || contains_any(&desc_lower, HORIZONTAL_ESCALATION_KEYWORDS) {
            score.apply_penalty(
                3,
                vuln.title.clone(),
                vuln.severity,
                None,
            );
            continue;
        }

        // Excessive privileges (-2 points)
        if contains_any(&title_lower, LEAST_PRIVILEGE_KEYWORDS) || contains_any(&desc_lower, LEAST_PRIVILEGE_KEYWORDS) {
            score.apply_penalty(
                2,
                vuln.title.clone(),
                vuln.severity,
                None,
            );
            continue;
        }
    }

    // Bonus for RBAC detection
    let has_rbac = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("rbac") || title.contains("role based")) &&
        (title.contains("detected") || title.contains("present") || title.contains("implemented"))
    });

    if has_rbac {
        score.apply_bonus(1, "Role-based access control detected".to_string());
    }

    // Bonus for proper permission checks
    let has_permissions = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("permission") &&
        (title.contains("check") || title.contains("validated"))
    });

    if has_permissions {
        score.apply_bonus(1, "Permission checks validated".to_string());
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
    fn test_idor_vulnerability() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "IDOR vulnerability in user profile".to_string(),
            description: "Can access other users' profiles by changing ID".to_string(),
            location: Some("/api/user/123".to_string()),
            recommendation: Some("Add proper authorization checks".to_string()),
            cwe: None,
            owasp: Some("A01:2021".to_string()),
        });

        let score = calculate(&report);
        assert_eq!(score.score, 6); // 10 - 4 for High severity IDOR
    }

    #[test]
    fn test_privilege_escalation() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Privilege escalation to admin".to_string(),
            description: "User can elevate to admin role".to_string(),
            location: Some("/api/user/promote".to_string()),
            recommendation: Some("Fix role assignment logic".to_string()),
            cwe: None,
            owasp: Some("A01:2021".to_string()),
        });

        let score = calculate(&report);
        assert_eq!(score.score, 5); // 10 - 5
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 10);
    }
}
