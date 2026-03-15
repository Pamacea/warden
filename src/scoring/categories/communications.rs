//! Secure Communications Category
//!
//! Max points: 10
//!
//! Assesses:
//! - HTTPS only enforcement
//! - HSTS configuration
//! - Certificate validity
//! - No mixed content
//! - Secure protocols only
//! - Certificate pinning (optional)

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const HTTPS_KEYWORDS: &[&str] = &[
    "https", "http", "ssl", "tls", "encryption",
    "secure connection", "unencrypted", "plaintext",
];

const HTTP_AVAILABLE_KEYWORDS: &[&str] = &[
    "http available", "http redirect", "supports http",
    "unencrypted connection", "plaintext connection", "no https",
];

const MIXED_CONTENT_KEYWORDS: &[&str] = &[
    "mixed content", "mixed active content", "mixed passive content",
    "insecure resource", "http resource on https page",
];

const CERTIFICATE_KEYWORDS: &[&str] = &[
    "certificate", "cert", "ssl certificate", "tls certificate",
    "expired cert", "invalid cert", "self-signed cert",
    "certificate error", "cert validity",
];

const WEAK_PROTOCOL_KEYWORDS: &[&str] = &[
    "weak protocol", "ssl 2.0", "ssl 3.0", "tls 1.0",
    "tls 1.1", "insecure protocol",
];

const CERT_PINNING_KEYWORDS: &[&str] = &[
    "certificate pinning", "cert pinning", "public key pinning",
    "hpkp", "static pins",
];

const CWE_NO_HTTPS: &str = "CWE-319";
const CWE_MIXED_CONTENT: &str = "CWE-319";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 10;
    let mut score = CategoryScore::new("Communications", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // HTTP available / no HTTPS (-5 points)
        if contains_any(&title_lower, HTTP_AVAILABLE_KEYWORDS) || contains_any(&desc_lower, HTTP_AVAILABLE_KEYWORDS) {
            score.apply_penalty(
                5,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_NO_HTTPS.to_string()),
            );
            continue;
        }

        // Mixed content (-3 points)
        if contains_any(&title_lower, MIXED_CONTENT_KEYWORDS) || contains_any(&desc_lower, MIXED_CONTENT_KEYWORDS) {
            score.apply_penalty(
                3,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_MIXED_CONTENT.to_string()),
            );
            continue;
        }

        // Certificate issues (-4 points)
        if contains_any(&title_lower, CERTIFICATE_KEYWORDS) || contains_any(&desc_lower, CERTIFICATE_KEYWORDS) {
            if title_lower.contains("expired") || title_lower.contains("invalid") ||
               title_lower.contains("self-signed") || title_lower.contains("error") {
                score.apply_penalty(
                    4,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Weak protocols (-3 points)
        if contains_any(&title_lower, WEAK_PROTOCOL_KEYWORDS) || contains_any(&desc_lower, WEAK_PROTOCOL_KEYWORDS) {
            score.apply_penalty(
                3,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_NO_HTTPS.to_string()),
            );
            continue;
        }
    }

    // Bonus for HTTPS enforcement
    let has_https_only = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        title.contains("https") &&
        (title.contains("enforced") || title.contains("only") || title.contains("redirect"))
    });

    if has_https_only {
        score.apply_bonus(1, "HTTPS enforcement detected".to_string());
    }

    // Bonus for proper HSTS
    let has_hsts = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("hsts") || title.contains("strict-transport")) &&
        (title.contains("good") || title.contains("proper"))
    });

    if has_hsts {
        score.apply_bonus(1, "Proper HSTS configuration".to_string());
    }

    // Bonus for certificate pinning (rare, extra points)
    let has_pinning = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("pinning") || title.contains("hpkp"))
    });

    if has_pinning {
        score.apply_bonus(2, "Certificate pinning detected".to_string());
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
    fn test_http_available() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "HTTP available without redirect".to_string(),
            description: "Server responds on HTTP without redirecting to HTTPS".to_string(),
            location: None,
            recommendation: Some("Disable HTTP and redirect to HTTPS".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 5); // 10 - 5
    }

    #[test]
    fn test_mixed_content() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Mixed content detected".to_string(),
            description: "HTTP resources loaded on HTTPS page".to_string(),
            location: None,
            recommendation: Some("Use HTTPS for all resources".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 7); // 10 - 3
    }

    #[test]
    fn test_clean_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let score = calculate(&report);
        assert_eq!(score.score, 10);
    }
}
