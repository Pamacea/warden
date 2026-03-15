//! HTTP Security Headers Category
//!
//! Max points: 10
//!
//! Assesses:
//! - Content-Security-Policy (CSP)
//! - X-Frame-Options
//! - Strict-Transport-Security (HSTS)
//! - X-Content-Type-Options
//! - Referrer-Policy
//! - Permissions-Policy
//! - Cross-Origin headers

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const CSP_KEYWORDS: &[&str] = &[
    "csp", "content-security-policy", "content security policy",
    "missing csp", "weak csp", "csp header", "unsafe-inline",
];

const FRAME_OPTIONS_KEYWORDS: &[&str] = &[
    "x-frame-options", "frame options", "clickjacking",
    "missing x-frame-options", "frame-ancestors",
];

const CONTENT_TYPE_KEYWORDS: &[&str] = &[
    "x-content-type-options", "content-type-options",
    "nosniff", "mime sniffing", "mime-sniff",
];

const REFERRER_KEYWORDS: &[&str] = &[
    "referrer-policy", "referer-policy",
    "missing referrer-policy", "leak referrer",
];

const PERMISSIONS_KEYWORDS: &[&str] = &[
    "permissions-policy", "feature-policy",
    "missing permissions-policy", "feature policy",
];

const CORS_KEYWORDS: &[&str] = &[
    "cors", "cross-origin", "access-control-allow-origin",
    "permissive cors", "cors misconfiguration", "origin *",
];

const XCSP_KEYWORDS: &[&str] = &[
    "x-xss-protection", "xss protection",
    "missing x-xss-protection",
];

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 10;
    let mut score = CategoryScore::new("Security Headers", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Missing CSP (-3 points)
        if contains_any(&title_lower, CSP_KEYWORDS) || contains_any(&desc_lower, CSP_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("no csp") {
                score.apply_penalty(
                    3,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
            // Weak CSP
            if title_lower.contains("weak") || title_lower.contains("unsafe") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Missing X-Frame-Options (-2 points)
        if contains_any(&title_lower, FRAME_OPTIONS_KEYWORDS) || contains_any(&desc_lower, FRAME_OPTIONS_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("clickjacking") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Permissive CORS (-2 points)
        if contains_any(&title_lower, CORS_KEYWORDS) || contains_any(&desc_lower, CORS_KEYWORDS) {
            if title_lower.contains("permissive") || title_lower.contains(" * ") ||
               title_lower.contains("origin: *") || title_lower.contains("any origin") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Missing X-Content-Type-Options (-1 point)
        if contains_any(&title_lower, CONTENT_TYPE_KEYWORDS) || contains_any(&desc_lower, CONTENT_TYPE_KEYWORDS) {
            if title_lower.contains("missing") {
                score.apply_penalty(
                    1,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Missing Referrer-Policy (-1 point)
        if contains_any(&title_lower, REFERRER_KEYWORDS) || contains_any(&desc_lower, REFERRER_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("leak") {
                score.apply_penalty(
                    1,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Missing Permissions-Policy (-1 point)
        if contains_any(&title_lower, PERMISSIONS_KEYWORDS) || contains_any(&desc_lower, PERMISSIONS_KEYWORDS) {
            if title_lower.contains("missing") {
                score.apply_penalty(
                    1,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }
    }

    // Bonus for having CSP
    let has_csp = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("csp") &&
        (title.contains("present") || title.contains("detected") || title.contains("set"))
    });

    if has_csp {
        score.apply_bonus(1, "Content-Security-Policy header present".to_string());
    }

    // Bonus for X-Frame-Options
    let has_frame_options = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("x-frame-options") || title.contains("frame options")) &&
        (title.contains("present") || title.contains("set") || title.contains("deny") || title.contains("sameorigin"))
    });

    if has_frame_options {
        score.apply_bonus(1, "X-Frame-Options header present".to_string());
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
    fn test_missing_csp() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Missing CSP header".to_string(),
            description: "Content-Security-Policy header not set".to_string(),
            location: None,
            recommendation: Some("Add CSP header".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 7); // 10 - 3
    }

    #[test]
    fn test_permissive_cors() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Permissive CORS configuration".to_string(),
            description: "Access-Control-Allow-Origin: *".to_string(),
            location: None,
            recommendation: Some("Restrict CORS origins".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 8); // 10 - 2
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 10);
    }
}
