//! Main orchestration logic for scans

use crate::{
    config::Config,
    detection::{self, DetectInfo},
    progress::{ScanProgress, ScannerType, StatusPrinter},
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
    verbose: bool,
) -> Result<()> {
    let status = StatusPrinter::new(verbose);

    status.print_header(&format!("Warden Security Scan v{}", env!("CARGO_PKG_VERSION")));

    let target_str = target.unwrap_or_else(|| ".".to_string());

    // Detect target type
    let scan_target = if target_str.starts_with("http://") || target_str.starts_with("https://") {
        status.print(&format!("{} Target: {}", "🌐".cyan(), target_str.cyan()));
        Target::Url(target_str)
    } else {
        let path_display = if target_str == "." {
            std::env::current_dir()?
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(".")
                .to_string()
        } else {
            target_str.clone()
        };
        status.print(&format!("{} Target: {}", "📁".cyan(), path_display.cyan()));
        Target::Path(std::path::PathBuf::from(&target_str))
    };

    // Print configuration info in verbose mode
    if verbose {
        status.print_verbose(&format!("Timeout: {}s | Concurrency: {}", timeout, concurrency));
        if aggressive {
            status.print_verbose("Mode: Aggressive scanning enabled");
        }
        if include_ddos {
            status.print_verbose("DDoS resistance testing: Enabled");
        }
        if include_stress {
            status.print_verbose("Stress testing: Enabled");
        }
    }

    // Run detection for paths
    let detection_info = if matches!(scan_target, Target::Path(_)) {
        Some(run_detection(&scan_target, &status)?)
    } else {
        None
    };

    // Print detection info
    if let Some(ref info) = detection_info {
        status.print(&format!("{} Detected:", "🔍".cyan()));
        if !info.languages.is_empty() {
            status.print_verbose(&format!("  Languages: {}",
                info.languages.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")));
        }
        if !info.frameworks.is_empty() {
            status.print_verbose(&format!("  Frameworks: {}",
                info.frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ")));
        }
    }

    status.print_header("Starting Scan");

    // Calculate number of scanners for progress
    let mut scanner_count = 0;
    match &scan_target {
        Target::Url(_) => {
            scanner_count += 1; // HTTP
            scanner_count += 1; // Port
        }
        Target::Path(_) => {
            scanner_count += 1; // Static
        }
    }
    if include_ddos { scanner_count += 1; }
    if include_stress { scanner_count += 1; }

    // Create progress manager
    let mut progress = ScanProgress::new(scanner_count);

    // Create scanner engine
    let scanner_config = crate::scanners::ScannerConfig::new()
        .with_aggressive(aggressive)
        .with_timeout(std::time::Duration::from_secs(timeout))
        .with_concurrency(concurrency)
        .with_ddos(include_ddos)
        .with_stress(include_stress);

    let mut engine = ScannerEngine::new(scanner_config);

    // Run scan with progress tracking
    let report = match &scan_target {
        Target::Url(url) => {
            // HTTP scanner
            progress.start_scanner(ScannerType::Http, None);
            let mut report = engine.scan_http(url).await
                .unwrap_or_else(|e| {
                    progress.update_scanner(&format!("Error: {}", e));
                    ScanReport::new(scan_target.clone())
                });
            progress.finish_scanner();
            status.print_scanner_complete(ScannerType::Http, report.summary.total);

            // Port scanner
            progress.start_scanner(ScannerType::Port, Some(1024));
            let port_report = engine.scan_port(url).await
                .unwrap_or_else(|e| {
                    progress.update_scanner(&format!("Error: {}", e));
                    ScanReport::new(scan_target.clone())
                });
            progress.finish_scanner();
            status.print_scanner_complete(ScannerType::Port, port_report.summary.total);
            report.merge(port_report);

            // DDoS scanner
            if include_ddos {
                progress.start_scanner(ScannerType::Ddos, None);
                let ddos_report = engine.scan_ddos(&scan_target).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print_scanner_complete(ScannerType::Ddos, ddos_report.summary.total);
                report.merge(ddos_report);
            }

            // Stress scanner
            if include_stress {
                progress.start_scanner(ScannerType::Stress, None);
                let stress_report = engine.scan_stress(&scan_target).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print_scanner_complete(ScannerType::Stress, stress_report.summary.total);
                report.merge(stress_report);
            }

            report
        }
        Target::Path(path) => {
            // Static scanner
            progress.start_scanner(ScannerType::Static, None);
            let report = engine.scan_static(path).await
                .unwrap_or_else(|e| {
                    progress.update_scanner(&format!("Error: {}", e));
                    ScanReport::new(scan_target.clone())
                });
            progress.finish_scanner();
            status.print_scanner_complete(ScannerType::Static, report.summary.total);

            // DDoS scanner (for static analysis)
            if include_ddos {
                progress.start_scanner(ScannerType::Ddos, None);
                let ddos_report = engine.scan_ddos(&scan_target).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print_scanner_complete(ScannerType::Ddos, ddos_report.summary.total);
            }

            report
        }
    };

    progress.finish();
    status.print_footer();

    // Print summary
    print_scan_summary(&report);

    // Print detailed report
    let report_format = format.parse::<ReportFormat>().map_err(|e| anyhow::anyhow!(e))?;
    if report_format == ReportFormat::Console {
        println!();
        report.print(&report_format)?;
    } else {
        report.print(&report_format)?;
    }

    // Save to file if requested
    if let Some(output_path) = output {
        report.save(&output_path, &report_format)?;
        println!();
        crate::progress::ErrorReporter::print_success(&format!("Report saved to {}", output_path));
    }

    Ok(())
}

fn run_detection(target: &Target, status: &StatusPrinter) -> Result<DetectInfo> {
    let path = match target {
        Target::Url(_) => return Ok(DetectInfo::new("".to_string())),
        Target::Path(p) => p,
    };

    status.print_verbose("Running framework and language detection...");

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

fn print_scan_summary(report: &ScanReport) {
    use crate::reporters::severity_color;

    println!();
    println!("{}", "┌─ Scan Summary ──────────────────────────────────".cyan().bold());
    println!("│ {}", format!("Target: {}", report.target).white());
    println!("│ {}", format!("Time: {}", report.timestamp).dimmed());
    println!("│");
    println!("│ {}", format!("Total Findings: {}", report.summary.total).white());

    if report.summary.critical > 0 {
        println!("│ {} {}", "●".red(), format!("Critical: {}", report.summary.critical).red().bold());
    }
    if report.summary.high > 0 {
        println!("│ {} {}", "●".red(), format!("High: {}", report.summary.high).red());
    }
    if report.summary.medium > 0 {
        println!("│ {} {}", "●".yellow(), format!("Medium: {}", report.summary.medium).yellow());
    }
    if report.summary.low > 0 {
        println!("│ {} {}", "●".blue(), format!("Low: {}", report.summary.low).blue());
    }
    if report.summary.info > 0 {
        println!("│ {} {}", "●".white(), format!("Info: {}", report.summary.info));
    }

    if report.summary.total == 0 {
        println!("│ {}", "✓ No security issues found!".green().bold());
    } else {
        println!("│");
        println!("│ {}", format!("Risk Level: {}", get_risk_level(report)).yellow());
    }

    println!("{}", "└──────────────────────────────────────────────────".cyan().bold());
}

fn get_risk_level(report: &ScanReport) -> colored::ColoredString {
    if report.summary.critical > 0 {
        "CRITICAL".red().bold()
    } else if report.summary.high > 0 {
        "HIGH".red()
    } else if report.summary.medium > 0 {
        "MEDIUM".yellow()
    } else if report.summary.low > 0 {
        "LOW".blue()
    } else {
        "MINIMAL".green()
    }
}
