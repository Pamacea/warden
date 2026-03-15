//! Cryptography Category
//!
//! Max points: 10
//!
//! Assesses:
//! - TLS/SSL version and configuration
//! - HSTS implementation
//! - Certificate validity
//! - Weak cryptographic algorithms
//! - Key length strength

use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::CategoryScore;

const TLS_KEYWORDS: &[&str] = &[
    "tls", "ssl", "tls version", "ssl version",
    "tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0",
    "tls 1.2", "tls 1.3",
];

const HSTS_KEYWORDS: &[&str] = &[
    "hsts", "strict-transport-security", "strict transport security",
    "missing hsts", "hsts header", "max-age",
];

const CERTIFICATE_KEYWORDS: &[&str] = &[
    "certificate", "cert", "ssl cert", "tls cert",
    "expired certificate", "self-signed certificate", "invalid certificate",
    "certificate chain", "certificate authority",
];

const WEAK_CRYPTO_KEYWORDS: &[&str] = &[
    "weak cipher", "weak encryption", "rc4", "des", "3des",
    "md5", "sha1", "sha-1", "null cipher", "export grade",
];

const KEY_LENGTH_KEYWORDS: &[&str] = &[
    "key length", "rsa key", "dh key", "ecdh",
    "weak key", "short key", "1024 bit", "512 bit",
];

const CWE_WEAK_TLS: &str = "CWE-319";
const CWE_WEAK_CRYPTO: &str = "CWE-327";
const CWE_MISSING_HSTS: &str = "CWE-319";

pub fn calculate(report: &ScanReport) -> CategoryScore {
    const MAX_POINTS: i32 = 10;
    let mut score = CategoryScore::new("Cryptography", MAX_POINTS);

    for vuln in &report.findings {
        let title_lower = vuln.title.to_lowercase();
        let desc_lower = vuln.description.to_lowercase();

        // Weak TLS version (-5 points)
        if contains_any(&title_lower, TLS_KEYWORDS) || contains_any(&desc_lower, TLS_KEYWORDS) {
            if title_lower.contains("1.0") || title_lower.contains("1.1") ||
               title_lower.contains("ssl 2") || title_lower.contains("ssl 3") ||
               desc_lower.contains("1.0") || desc_lower.contains("1.1") {
                score.apply_penalty(
                    5,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_WEAK_TLS.to_string()),
                );
                continue;
            }
        }

        // Missing HSTS (-2 points)
        if contains_any(&title_lower, HSTS_KEYWORDS) || contains_any(&desc_lower, HSTS_KEYWORDS) {
            if title_lower.contains("missing") || title_lower.contains("no hsts") {
                score.apply_penalty(
                    2,
                    vuln.title.clone(),
                    vuln.severity,
                    Some(CWE_MISSING_HSTS.to_string()),
                );
                continue;
            }
        }

        // Certificate issues (-4 points)
        if contains_any(&title_lower, CERTIFICATE_KEYWORDS) || contains_any(&desc_lower, CERTIFICATE_KEYWORDS) {
            if title_lower.contains("expired") || title_lower.contains("self-signed") ||
               title_lower.contains("invalid") || title_lower.contains("mismatch") {
                score.apply_penalty(
                    4,
                    vuln.title.clone(),
                    vuln.severity,
                    None,
                );
                continue;
            }
        }

        // Weak cryptography (-4 points)
        if contains_any(&title_lower, WEAK_CRYPTO_KEYWORDS) || contains_any(&desc_lower, WEAK_CRYPTO_KEYWORDS) {
            score.apply_penalty(
                4,
                vuln.title.clone(),
                vuln.severity,
                Some(CWE_WEAK_CRYPTO.to_string()),
            );
            continue;
        }

        // Weak key length (-3 points)
        if contains_any(&title_lower, KEY_LENGTH_KEYWORDS) || contains_any(&desc_lower, KEY_LENGTH_KEYWORDS) {
            if title_lower.contains("1024") || title_lower.contains("512") ||
               title_lower.contains("weak") || title_lower.contains("short") {
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

    // Bonus for TLS 1.3
    let has_tls13 = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info && title.contains("tls 1.3")
    });

    if has_tls13 {
        score.apply_bonus(1, "TLS 1.3 detected".to_string());
    }

    // Bonus for proper HSTS
    let has_proper_hsts = report.findings.iter().any(|v| {
        let title = v.title.to_lowercase();
        v.severity == VulnSeverity::Info &&
        (title.contains("hsts") || title.contains("strict-transport")) &&
        (title.contains("good") || title.contains("proper") || title.contains("valid"))
    });

    if has_proper_hsts {
        score.apply_bonus(1, "Proper HSTS configuration".to_string());
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
    fn test_weak_tls() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "TLS 1.0 supported".to_string(),
            description: "Server supports weak TLS 1.0 protocol".to_string(),
            location: None,
            recommendation: Some("Disable TLS 1.0 and 1.1".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 5); // 10 - 5
    }

    #[test]
    fn test_missing_hsts() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Missing HSTS header".to_string(),
            description: "Strict-Transport-Security header not set".to_string(),
            location: None,
            recommendation: Some("Add HSTS header".to_string()),
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 8); // 10 - 2
    }

    #[test]
    fn test_tls13_bonus() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: "TLS 1.3 detected".to_string(),
            description: "Server supports TLS 1.3".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let score = calculate(&report);
        assert_eq!(score.score, 10); // Full + bonus
    }
}
