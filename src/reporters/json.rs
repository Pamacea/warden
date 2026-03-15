//! JSON reporter

use super::Reporter;
use crate::scanners::ScanReport;
// use crate::scoring::SecurityScore;  // TODO: Re-enable when scoring is fully integrated
use anyhow::Result;
use serde_json::json;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn print(report: &ScanReport) -> Result<()> {
        println!("{}", Self::format(report)?);
        Ok(())
    }

    fn format(report: &ScanReport) -> Result<String> {
        // TODO: Re-enable security scoring when fully integrated
        // let security_score = SecurityScore::calculate(report);

        let output = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "target": report.target,
            "timestamp": report.timestamp,
            "findings": report.findings,
            "summary": report.summary,
            // "securityScore": {
            //     "score": security_score.score,
            //     "grade": security_score.grade.as_str(),
            //     "gradeDescription": security_score.grade.description(),
            //     "categories": security_score.categories.iter().map(|c| {
            //         json!({
            //             "name": c.name,
            //             "score": c.score,
            //             "maxPoints": c.max_points,
            //             "percentage": c.percentage(),
            //             "grade": c.grade().as_str(),
            //             "penalties": c.penalties.len(),
            //             "bonuses": c.bonuses.len(),
            //         })
            //     }).collect::<Vec<_>>(),
            //     "recommendations": security_score.recommendations,
            // }
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Target, Vuln, VulnSeverity};

    #[test]
    fn test_json_format_empty_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let formatted = JsonReporter::format(&report).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        // Target is serialized as an object with Url/Path field
        assert_eq!(parsed["target"]["Url"], "http://example.com");
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_json_format_with_findings() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            location: Some("/test".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-123".to_string()),
            owasp: Some("A01:2021".to_string()),
        });

        let formatted = JsonReporter::format(&report).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        let findings = parsed["findings"].as_array().unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "Critical");
        assert_eq!(findings[0]["title"], "Test Vulnerability");
        assert_eq!(findings[0]["description"], "Test description");
        assert_eq!(findings[0]["location"], "/test");
        assert_eq!(findings[0]["recommendation"], "Fix it");
        assert_eq!(findings[0]["cwe"], "CWE-123");
        assert_eq!(findings[0]["owasp"], "A01:2021");
    }

    #[test]
    fn test_json_format_summary() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Critical".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "High".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let formatted = JsonReporter::format(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&formatted).unwrap();

        assert_eq!(parsed["summary"]["total"], 2);
        assert_eq!(parsed["summary"]["critical"], 1);
        assert_eq!(parsed["summary"]["high"], 1);
        assert_eq!(parsed["summary"]["medium"], 0);
    }

    #[test]
    fn test_json_valid_schema() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let formatted = JsonReporter::format(&report).unwrap();

        // Should be valid JSON
        assert!(serde_json::from_str::<serde_json::Value>(&formatted).is_ok());

        // Should contain required fields
        let parsed = serde_json::from_str::<serde_json::Value>(&formatted).unwrap();
        assert!(parsed.get("version").is_some());
        assert!(parsed.get("target").is_some());
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("findings").is_some());
        assert!(parsed.get("summary").is_some());
    }
}
