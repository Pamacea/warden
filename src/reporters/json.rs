//! JSON reporter

use super::Reporter;
use crate::scanners::ScanReport;
use anyhow::Result;
use serde_json::json;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn print(report: &ScanReport) -> Result<()> {
        println!("{}", Self::format(report)?);
        Ok(())
    }

    fn format(report: &ScanReport) -> Result<String> {
        let output = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "target": report.target,
            "timestamp": report.timestamp,
            "findings": report.findings,
            "summary": report.summary,
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}
