//! Main orchestration logic for scans

use crate::{
    config::Config,
    detection::{self, DetectInfo},
    reporters::ReportFormat,
    scanners::{ScannerEngine, ScanReport, Target},
};
use anyhow::Result;
use colored::Colorize;

/// Run a security scan
pub async fn run_scan(
    target: Option<String>,
    aggressive: bool,
    include_ddos: bool,
    include_stress: bool,
    format: String,
    output: Option<String>,
    timeout: u64,
    concurrency: usize,
    config: Config,
) -> Result<()> {
    let target_str = target.unwrap_or_else(|| ".".to_string());

    println!("{} Target: {}", "→".cyan(), target_str);

    // Detect target type
    let scan_target = if target_str.starts_with("http://") || target_str.starts_with("https://") {
        Target::Url(target_str)
    } else {
        Target::Path(std::path::PathBuf::from(&target_str))
    };

    // Run detection for paths
    let detection_info = if matches!(scan_target, Target::Path(_)) {
        Some(run_detection(&scan_target)?)
    } else {
        None
    };

    // Print detection info
    if let Some(ref info) = detection_info {
        println!();
        println!("{} Detected:", "🔍".bold());
        if !info.languages.is_empty() {
            println!("  Languages: {}", info.languages.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", "));
        }
        if !info.frameworks.is_empty() {
            println!("  Frameworks: {}", info.frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", "));
        }
    }

    println!();
    println!("{} Starting scan...", "⚡".bold());

    // Create scanner engine
    let mut scanner_config = crate::scanners::ScannerConfig::new()
        .with_aggressive(aggressive)
        .with_timeout(std::time::Duration::from_secs(timeout))
        .with_concurrency(concurrency)
        .with_ddos(include_ddos)
        .with_stress(include_stress);

    let mut engine = ScannerEngine::new(scanner_config);

    // Run scan
    let report = engine.scan(&scan_target).await?;

    // Print report
    let report_format = format.parse::<ReportFormat>()?;
    report.print(&report_format)?;

    // Save to file if requested
    if let Some(output_path) = output {
        report.save(&output_path, &report_format)?;
        println!();
        println!("{} Report saved to {}", "✓".green(), output_path);
    }

    Ok(())
}

fn run_detection(target: &Target) -> Result<DetectInfo> {
    let path = match target {
        Target::Url(_) => return Ok(DetectInfo::new("".to_string())),
        Target::Path(p) => p,
    };

    let languages = detection::language::detect(path)?;
    let frameworks = detection::framework::detect(path, &languages)?;

    Ok(DetectInfo {
        languages,
        frameworks,
        path: path.display().to_string(),
        package_manager: None,
        version: None,
    })
}
