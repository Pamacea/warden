//! Main orchestration logic for scans

use crate::{
    config::Config,
    detection::{self, DetectInfo},
    progress::{ScanProgress, ScannerType, StatusPrinter},
    reporters::ReportFormat,
    scanners::{
        ScannerEngine, ScanReport, Target,
        // Import all scanners for full mode
        api::ApiScanner,
        graphql::GraphQLScanner,
        grpc::GrpcScanner,
        cors::CorsScanner,
        ssrf::SsrfScanner,
        open_redirect::OpenRedirectScanner,
        path_traversal::PathTraversalScanner,
        xxe::XxeScanner,
        deserialization::DeserializationScanner,
        ssti::SstiScanner,
        enumeration::EnumerationScanner,
        disclosure::DisclosureScanner,
        terraform::TerraformScanner,
        docker::DockerScanner,
        kubernetes::KubernetesScanner,
        cloud_metadata::CloudMetadataScanner,
        business_logic::BusinessLogicScanner,
        race_condition::RaceConditionScanner,
        ldap::LdapScanner,
        rdp::RdpScanner,
        waf::WafScanner,
    },
};
use crate::scoring::SecurityScore;
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
    _config: Config,
    verbose: bool,
    auto_save: bool,
    generate_fixes: bool,
    show_score: bool,
    check_secrets: bool,
    check_deps: bool,
    full: bool,
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
        if check_secrets {
            status.print_verbose("Secrets leak detection: Enabled");
        }
        if check_deps {
            status.print_verbose("Dependency vulnerability check: Enabled");
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
            if full {
                // Additional URL scanners in full mode
                scanner_count += 18; // API, GraphQL, gRPC, CORS, SSRF, Open Redirect, Path Traversal,
                                     // XXE, Deserialization, SSTI, Enumeration, Disclosure,
                                     // Business Logic, LDAP, RDP, WAF, Race Condition
            }
        }
        Target::Path(_) => {
            scanner_count += 1; // Static
            if full {
                // Additional path scanners in full mode
                scanner_count += 4; // Terraform, Docker, Kubernetes, Cloud Metadata
            }
        }
    }
    if include_ddos { scanner_count += 1; }
    if include_stress { scanner_count += 1; }
    if check_secrets { scanner_count += 1; }
    if check_deps { scanner_count += 1; }

    // Create progress manager
    let mut progress = ScanProgress::new(scanner_count);

    // Create scanner engine
    let scanner_config = crate::scanners::ScannerConfig::new()
        .with_aggressive(aggressive)
        .with_timeout(std::time::Duration::from_secs(timeout))
        .with_concurrency(concurrency)
        .with_ddos(include_ddos)
        .with_stress(include_stress)
        .with_check_secrets(check_secrets)
        .with_check_deps(check_deps);

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

            // Full mode: run all additional URL scanners
            if full {
                let scanner_config = crate::scanners::ScannerConfig::new()
                    .with_aggressive(aggressive)
                    .with_timeout(std::time::Duration::from_secs(timeout))
                    .with_concurrency(concurrency);

                // API Scanner
                progress.start_scanner(ScannerType::Other, Some(50));
                let api_report = ApiScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("API Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} API Scanner complete: {} findings", "✓".green(), api_report.summary.total));
                report.merge(api_report);

                // GraphQL Scanner
                progress.start_scanner(ScannerType::Other, Some(50));
                let graphql_report = GraphQLScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("GraphQL Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} GraphQL Scanner complete: {} findings", "✓".green(), graphql_report.summary.total));
                report.merge(graphql_report);

                // gRPC Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let grpc_report = GrpcScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("gRPC Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} gRPC Scanner complete: {} findings", "✓".green(), grpc_report.summary.total));
                report.merge(grpc_report);

                // CORS Scanner
                progress.start_scanner(ScannerType::Other, Some(20));
                let cors_report = CorsScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("CORS Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} CORS Scanner complete: {} findings", "✓".green(), cors_report.summary.total));
                report.merge(cors_report);

                // SSRF Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let ssrf_report = SsrfScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("SSRF Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} SSRF Scanner complete: {} findings", "✓".green(), ssrf_report.summary.total));
                report.merge(ssrf_report);

                // Open Redirect Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let open_redirect_report = OpenRedirectScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Open Redirect Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Open Redirect Scanner complete: {} findings", "✓".green(), open_redirect_report.summary.total));
                report.merge(open_redirect_report);

                // Path Traversal Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let path_traversal_report = PathTraversalScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Path Traversal Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Path Traversal Scanner complete: {} findings", "✓".green(), path_traversal_report.summary.total));
                report.merge(path_traversal_report);

                // XXE Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let xxe_report = XxeScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("XXE Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} XXE Scanner complete: {} findings", "✓".green(), xxe_report.summary.total));
                report.merge(xxe_report);

                // Deserialization Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let deser_report = DeserializationScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Deserialization Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Deserialization Scanner complete: {} findings", "✓".green(), deser_report.summary.total));
                report.merge(deser_report);

                // SSTI Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let ssti_report = SstiScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("SSTI Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} SSTI Scanner complete: {} findings", "✓".green(), ssti_report.summary.total));
                report.merge(ssti_report);

                // Enumeration Scanner
                progress.start_scanner(ScannerType::Other, Some(60));
                let enum_report = EnumerationScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Enumeration Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Enumeration Scanner complete: {} findings", "✓".green(), enum_report.summary.total));
                report.merge(enum_report);

                // Disclosure Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let disclosure_report = DisclosureScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Disclosure Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Disclosure Scanner complete: {} findings", "✓".green(), disclosure_report.summary.total));
                report.merge(disclosure_report);

                // Business Logic Scanner
                progress.start_scanner(ScannerType::Other, Some(50));
                let business_report = BusinessLogicScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Business Logic Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Business Logic Scanner complete: {} findings", "✓".green(), business_report.summary.total));
                report.merge(business_report);

                // LDAP Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let ldap_report = LdapScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("LDAP Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} LDAP Scanner complete: {} findings", "✓".green(), ldap_report.summary.total));
                report.merge(ldap_report);

                // RDP Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let rdp_report = RdpScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("RDP Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} RDP Scanner complete: {} findings", "✓".green(), rdp_report.summary.total));
                report.merge(rdp_report);

                // WAF Scanner
                progress.start_scanner(ScannerType::Other, Some(30));
                let waf_report = WafScanner::new(scanner_config.clone()).scan(url).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("WAF Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} WAF Scanner complete: {} findings", "✓".green(), waf_report.summary.total));
                report.merge(waf_report);

                // Race Condition Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let race_report = RaceConditionScanner::new(scanner_config.clone()).scan(&scan_target).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Race Condition Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Race Condition Scanner complete: {} findings", "✓".green(), race_report.summary.total));
                report.merge(race_report);
            }

            report
        }
        Target::Path(path) => {
            // Static scanner
            progress.start_scanner(ScannerType::Static, None);
            let mut report = engine.scan_static(path).await
                .unwrap_or_else(|e| {
                    progress.update_scanner(&format!("Error: {}", e));
                    ScanReport::new(scan_target.clone())
                });
            progress.finish_scanner();
            status.print_scanner_complete(ScannerType::Static, report.summary.total);

            // Secrets scanner
            if check_secrets {
                progress.start_scanner(ScannerType::Secrets, None);
                let secrets_report = engine.scan_secrets(path).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print_scanner_complete(ScannerType::Secrets, secrets_report.summary.total);
                report.merge(secrets_report);
            }

            // Dependency scanner
            if check_deps {
                progress.start_scanner(ScannerType::Deps, None);
                let deps_report = engine.scan_dependencies(path).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print_scanner_complete(ScannerType::Deps, deps_report.summary.total);
                report.merge(deps_report);
            }

            // Full mode: run all additional path scanners
            if full {
                let scanner_config = crate::scanners::ScannerConfig::new()
                    .with_aggressive(aggressive)
                    .with_timeout(std::time::Duration::from_secs(timeout))
                    .with_concurrency(concurrency);

                // Terraform Scanner
                progress.start_scanner(ScannerType::Other, Some(50));
                let terraform_report = TerraformScanner::new(scanner_config.clone()).scan(path).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Terraform Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Terraform Scanner complete: {} findings", "✓".green(), terraform_report.summary.total));
                report.merge(terraform_report);

                // Docker Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let docker_report = DockerScanner::new(scanner_config.clone()).scan(path).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Docker Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Docker Scanner complete: {} findings", "✓".green(), docker_report.summary.total));
                report.merge(docker_report);

                // Kubernetes Scanner
                progress.start_scanner(ScannerType::Other, Some(40));
                let k8s_report = KubernetesScanner::new(scanner_config.clone()).scan(&scan_target).await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Kubernetes Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Kubernetes Scanner complete: {} findings", "✓".green(), k8s_report.summary.total));
                report.merge(k8s_report);

                // Cloud Metadata Scanner (takes &str)
                progress.start_scanner(ScannerType::Other, Some(30));
                let cloud_report = CloudMetadataScanner::new(scanner_config.clone()).scan("").await
                    .unwrap_or_else(|e| {
                        progress.update_scanner(&format!("Cloud Metadata Scanner Error: {}", e));
                        ScanReport::new(scan_target.clone())
                    });
                progress.finish_scanner();
                status.print(&format!("{} Cloud Metadata Scanner complete: {} findings", "✓".green(), cloud_report.summary.total));
                report.merge(cloud_report);

                // XXE Scanner (URL-based, skip for path)
                // Deserialization Scanner (URL-based, skip for path)
                // SSTI Scanner (URL-based, skip for path)
                // File Upload Scanner (URL-based, skip for path)
                // Business Logic Scanner (URL-based, skip for path)
                // Enumeration Scanner (URL-based, skip for path)
                // Disclosure Scanner (URL-based, skip for path)
            }

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

    // Print security score if requested
    if show_score {
        println!();
        let security_score = SecurityScore::calculate(&report);
        println!("{}", security_score.render_terminal());
    }

    // Save to file if requested
    if let Some(output_path) = output {
        report.save(&output_path, &report_format)?;
        println!();
        crate::progress::ErrorReporter::print_success(&format!("Report saved to {}", output_path));
    }

    // Auto-save report to project directory (for AI agents)
    if auto_save {
        if let Ok(auto_save_path) = get_auto_save_path(&scan_target) {
            // Use AI-optimized format for auto-saved reports
            let ai_format = ReportFormat::Ai;
            report.save(&auto_save_path, &ai_format)?;
            println!();
            crate::progress::ErrorReporter::print_success(&format!("AI report saved to {}", auto_save_path));

            // Also generate JSON fixes if requested
            if generate_fixes {
                let json_path = auto_save_path.replace(".md", "_fixes.json");
                use crate::reporters::generate_ai_json;
                let json_content = generate_ai_json(&report)?;
                std::fs::write(&json_path, json_content)?;
                crate::progress::ErrorReporter::print_success(&format!("Fix data saved to {}", json_path));
            }
        }
    }

    Ok(())
}

/// Get the auto-save path for a scan target
/// Returns WARDEN_SECURITY_REPORT.md in the scanned directory
fn get_auto_save_path(target: &Target) -> Result<String> {
    let base_dir = match target {
        Target::Url(_) => {
            // For URLs, save in current directory
            std::env::current_dir()?
        }
        Target::Path(path) => {
            // For paths, save in that directory
            if path.is_absolute() {
                path.clone()
            } else {
                let current_dir = std::env::current_dir()?;
                current_dir.join(path)
            }
        }
    };

    Ok(base_dir.join("WARDEN_SECURITY_REPORT.md")
        .to_string_lossy()
        .to_string())
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
