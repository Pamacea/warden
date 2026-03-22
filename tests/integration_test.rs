//! Integration tests for Warden security scanner

use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;
use warden::detection::{self, Framework, Language};
use warden::reporters::{ReportFormat, Reporter};
use warden::scanners::{ScannerConfig, ScannerEngine, Target, Vuln, VulnSeverity};

/// Test end-to-end scan workflow with mock HTTP server
#[tokio::test]
async fn test_e2e_http_scan_workflow() {
    let mut server = mockito::Server::new_async().await;

    // Mock security headers check
    let _head_mock = server
        .mock("HEAD", "/")
        .with_status(200)
        .with_header("content-type", "text/html")
        .create();

    let url = format!("{}/", server.url());
    let mut engine = ScannerEngine::new(
        ScannerConfig::new()
            .with_timeout(Duration::from_secs(1))
            .with_aggressive(false),
    );

    let report = engine.scan_http(&url).await;

    assert!(report.is_ok());
    let report = report.unwrap();
    assert_eq!(report.target, Target::Url(url));
}

/// Test static analysis workflow
#[tokio::test]
async fn test_e2e_static_analysis_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create test files
    std::fs::write(
        src_dir.join("main.js"),
        "function test() { eval('dangerous'); }",
    )
    .unwrap();

    std::fs::write(
        src_dir.join("app.py"),
        "def test():\n    exec(user_input)\n    subprocess.call(cmd, shell=True)\n",
    )
    .unwrap();

    let mut engine = ScannerEngine::new(ScannerConfig::new());
    let report = engine.scan_static(&temp_dir.path().to_path_buf()).await;

    assert!(report.is_ok());
    let report = report.unwrap();

    // Should detect dangerous patterns
    assert!(report.findings.len() > 0);
}

/// Test report generation in all formats
#[test]
fn test_all_report_formats() {
    let mut report = warden::scanners::ScanReport::new(Target::Url("http://example.com".to_string()));

    report.add_finding(Vuln {
        severity: VulnSeverity::High,
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability for report generation".to_string(),
        location: Some("/api/test".to_string()),
        recommendation: Some("Fix immediately".to_string()),
        cwe: Some("CWE-79".to_string()),
        owasp: Some("A03:2021 - Injection".to_string()),
    });

    // Test Console format
    let console_output = warden::reporters::ConsoleReporter::format(&report).unwrap();
    assert!(console_output.contains("Test Vulnerability"));
    assert!(console_output.contains("HIGH"));

    // Test JSON format
    let json_output = warden::reporters::JsonReporter::format(&report).unwrap();
    let json_parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    assert_eq!(json_parsed["findings"].as_array().unwrap().len(), 1);

    // Test Markdown format
    let md_output = warden::reporters::MarkdownReporter::format(&report).unwrap();
    assert!(md_output.contains("# Security Scan Report"));
    assert!(md_output.contains("Test Vulnerability"));
}

/// Test report saving to file
#[test]
fn test_save_report_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let report = warden::scanners::ScanReport::new(Target::Url("http://example.com".to_string()));

    let console_path = temp_dir.path().join("report.txt");
    let json_path = temp_dir.path().join("report.json");
    let md_path = temp_dir.path().join("report.md");

    // Save in different formats
    report
        .save(console_path.to_str().unwrap(), &ReportFormat::Console)
        .unwrap();
    report
        .save(json_path.to_str().unwrap(), &ReportFormat::Json)
        .unwrap();
    report
        .save(md_path.to_str().unwrap(), &ReportFormat::Markdown)
        .unwrap();

    assert!(console_path.exists());
    assert!(json_path.exists());
    assert!(md_path.exists());
}

/// Test language detection on various projects
#[test]
fn test_detect_multiple_languages() {
    let temp_dir = TempDir::new().unwrap();

    // Create mixed project
    std::fs::write(temp_dir.path().join("Cargo.toml"), "[package]\nname=\"test\"").unwrap();
    std::fs::write(
        temp_dir.path().join("package.json"),
        r#"{"name": "test", "dependencies": {"next": "^14.0"}}"#,
    )
    .unwrap();
    std::fs::write(temp_dir.path().join("requirements.txt"), "flask==3.0.0").unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();

    assert!(languages.contains(&Language::Rust));
    assert!(languages.contains(&Language::JavaScript));
    assert!(languages.contains(&Language::TypeScript));
    assert!(languages.contains(&Language::Python));
}

/// Test framework detection for various tech stacks
#[test]
fn test_detect_multiple_frameworks() {
    let temp_dir = TempDir::new().unwrap();

    // Create Node.js project with multiple frameworks
    std::fs::write(
        temp_dir.path().join("package.json"),
        r#"{
            "dependencies": {
                "next": "^14.0.0",
                "express": "^4.18.0",
                "fastify": "^4.0.0"
            },
            "devDependencies": {
                "vite": "^5.0.0"
            }
        }"#,
    )
    .unwrap();

    let frameworks =
        detection::framework::detect(temp_dir.path(), &[Language::JavaScript, Language::TypeScript])
            .unwrap();

    assert!(frameworks.contains(&Framework::NextJS));
    assert!(frameworks.contains(&Framework::Express));
    assert!(frameworks.contains(&Framework::Fastify));
    assert!(frameworks.contains(&Framework::Vite));
}

/// Test detection info structure
#[test]
fn test_detection_info() {
    let temp_dir = TempDir::new().unwrap();

    // Create a Next.js project
    std::fs::write(
        temp_dir.path().join("package.json"),
        r#"{"dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}"#,
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    let frameworks =
        detection::framework::detect(temp_dir.path(), &languages).unwrap();

    assert!(!languages.is_empty());
    assert!(frameworks.contains(&Framework::NextJS));
}

/// Test scanner with realistic project structure
#[tokio::test]
async fn test_realistic_project_scan() {
    let temp_dir = TempDir::new().unwrap();

    // Create a realistic Next.js project structure
    let app_dir = temp_dir.path().join("app");
    std::fs::create_dir_all(&app_dir).unwrap();

    std::fs::write(
        temp_dir.path().join("package.json"),
        r#"{"name": "test-app", "dependencies": {"next": "^14.0.0", "react": "^18.0.0"}}"#,
    )
    .unwrap();

    // Create files with potential vulnerabilities
    std::fs::write(
        app_dir.join("page.tsx"),
        r#"
export default function Page({ searchParams }) {
    return <div dangerouslySetInnerHTML={{ __html: searchParams.content }} />
}
"#,
    )
    .unwrap();

    std::fs::write(
        app_dir.join("api.ts"),
        r#"
export async function GET(request: Request) {
    const url = new URL(request.url);
    const cmd = url.searchParams.get('cmd');
    // Dangerous: command injection risk
    const result = exec(cmd);
    return Response.json(result);
}
"#,
    )
    .unwrap();

    let config = ScannerConfig::new().with_aggressive(true);
    let scanner = warden::scanners::StaticScanner::new(config);

    let report = scanner.scan(temp_dir.path()).await;

    assert!(report.is_ok());
    let report = report.unwrap();

    // Should detect at least some issues
    assert!(!report.findings.is_empty(), "Should detect security issues in dangerous code");
}

/// Test concurrent scanning
#[tokio::test]
async fn test_concurrent_scanning() {
    let temp_dir = TempDir::new().unwrap();

    // Create multiple subdirectories with files
    for i in 0..5 {
        let subdir = temp_dir.path().join(format!("dir{}", i));
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(subdir.join("test.js"), "eval('test');").unwrap();
    }

    let config = ScannerConfig::new().with_concurrency(10);
    let scanner = warden::scanners::StaticScanner::new(config);

    let start = std::time::Instant::now();
    let report = scanner.scan(temp_dir.path()).await.unwrap();
    let duration = start.elapsed();

    // Should complete in reasonable time
    assert!(duration.as_secs() < 5);
    assert_eq!(report.findings.len(), 5); // One eval per file
}

/// Test vulnerability severity distribution
#[test]
fn test_vulnerability_severity_distribution() {
    let mut report = warden::scanners::ScanReport::new(Target::Url("http://test.com".to_string()));

    // Add vulnerabilities of each severity
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

    report.add_finding(Vuln {
        severity: VulnSeverity::Medium,
        title: "Medium".to_string(),
        description: "Test".to_string(),
        location: None,
        recommendation: None,
        cwe: None,
        owasp: None,
    });

    report.add_finding(Vuln {
        severity: VulnSeverity::Low,
        title: "Low".to_string(),
        description: "Test".to_string(),
        location: None,
        recommendation: None,
        cwe: None,
        owasp: None,
    });

    report.add_finding(Vuln {
        severity: VulnSeverity::Info,
        title: "Info".to_string(),
        description: "Test".to_string(),
        location: None,
        recommendation: None,
        cwe: None,
        owasp: None,
    });

    assert_eq!(report.summary.critical, 1);
    assert_eq!(report.summary.high, 1);
    assert_eq!(report.summary.medium, 1);
    assert_eq!(report.summary.low, 1);
    assert_eq!(report.summary.info, 1);
    assert_eq!(report.summary.total, 5);
}

/// Test error handling for invalid URLs
#[tokio::test]
async fn test_invalid_url_handling() {
    let mut engine = ScannerEngine::new(ScannerConfig::new());

    let result = engine.scan_http("not-a-valid-url").await;

    // Scanner returns empty report for invalid URLs (doesn't panic)
    assert!(result.is_ok());
}

/// Test large file handling
#[tokio::test]
async fn test_large_file_handling() {
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large.js");

    // Create a file larger than 1MB
    let large_content = "x".repeat(2_000_000);
    std::fs::write(&large_file, large_content).unwrap();

    let scanner = warden::scanners::StaticScanner::new(ScannerConfig::new());
    let report = scanner.scan(temp_dir.path()).await;

    // Should handle large files without crashing
    assert!(report.is_ok());
}

/// Test special characters in paths
#[tokio::test]
async fn test_special_characters_in_paths() {
    let temp_dir = TempDir::new().unwrap();

    // Create directories with special characters
    let special_dir = temp_dir.path().join("dir with spaces & special-chars_123");
    std::fs::create_dir_all(&special_dir).unwrap();

    std::fs::write(special_dir.join("test.js"), "eval('test');").unwrap();

    let scanner = warden::scanners::StaticScanner::new(ScannerConfig::new());
    let report = scanner.scan(temp_dir.path()).await.unwrap();

    // Should handle special characters
    assert!(report.findings.len() > 0);
}

/// Test empty and minimal projects
#[tokio::test]
async fn test_minimal_project_scan() {
    let temp_dir = TempDir::new().unwrap();
    let scanner = warden::scanners::StaticScanner::new(ScannerConfig::new());

    let report = scanner.scan(temp_dir.path()).await.unwrap();

    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.summary.total, 0);
}

/// Test report exit codes
#[test]
fn test_report_exit_codes() {
    // No vulnerabilities
    let clean_report = warden::scanners::ScanReport::new(Target::Url("http://test.com".to_string()));
    assert_eq!(clean_report.exit_code(), 0);

    // Only info/low
    let mut low_report = warden::scanners::ScanReport::new(Target::Url("http://test.com".to_string()));
    low_report.add_finding(Vuln {
        severity: VulnSeverity::Low,
        title: "Low".to_string(),
        description: "Test".to_string(),
        location: None,
        recommendation: None,
        cwe: None,
        owasp: None,
    });
    assert_eq!(low_report.exit_code(), 0);

    // Critical/High should return non-zero
    let mut crit_report = warden::scanners::ScanReport::new(Target::Url("http://test.com".to_string()));
    crit_report.add_finding(Vuln {
        severity: VulnSeverity::Critical,
        title: "Critical".to_string(),
        description: "Test".to_string(),
        location: None,
        recommendation: None,
        cwe: None,
        owasp: None,
    });
    assert_eq!(crit_report.exit_code(), 1);
}

/// Test target URL parsing
#[test]
fn test_target_url_parsing() {
    let url = Target::Url("https://example.com:8443/path?query=value".to_string());
    assert!(url.to_string().contains("example.com"));
    assert!(url.to_string().contains("8443"));
}

/// Test target path handling
#[test]
fn test_target_path_handling() {
    let path = Target::Path(PathBuf::from("/tmp/test/project"));
    assert!(path.to_string().contains("project"));

    #[cfg(windows)]
    {
        let windows_path = Target::Path(PathBuf::from("C:\\Users\\test\\project"));
        assert!(windows_path.to_string().contains("project"));
    }
}

/// Test scanner configuration combinations
#[test]
fn test_scanner_config_combinations() {
    // Default config
    let default = ScannerConfig::default();
    assert!(!default.aggressive);

    // Aggressive mode
    let aggressive = ScannerConfig::new().with_aggressive(true);
    assert!(aggressive.aggressive);

    // Custom timeout
    let custom_timeout = ScannerConfig::new().with_timeout(Duration::from_secs(30));
    assert_eq!(custom_timeout.timeout, Duration::from_secs(30));

    // High concurrency
    let high_concurrency = ScannerConfig::new().with_concurrency(200);
    assert_eq!(high_concurrency.concurrency, 200);
}

/// Test detection of Go project
#[test]
fn test_go_project_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("go.mod"),
        "module test\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    assert!(languages.contains(&Language::Go));

    let frameworks = detection::framework::detect(temp_dir.path(), &languages).unwrap();
    assert!(frameworks.contains(&Framework::Gin));
}

/// Test detection of Java project
#[test]
fn test_java_project_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("pom.xml"),
        r#"<?xml version="1.0"?>
<project>
    <groupId>com.test</groupId>
    <artifactId>test</artifactId>
    <version>1.0</version>
</project>"#,
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    assert!(languages.contains(&Language::Java));
}

/// Test detection of Ruby project
#[test]
fn test_ruby_project_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    assert!(languages.contains(&Language::Ruby));
}

/// Test detection of PHP project
#[test]
fn test_php_project_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("composer.json"),
        r#"{"name": "test/project", "require": {"laravel/framework": "^10.0"}}"#,
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    assert!(languages.contains(&Language::PHP));
}

/// Test detection of Rust frameworks
#[test]
fn test_rust_frameworks_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
"#,
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    let frameworks = detection::framework::detect(temp_dir.path(), &languages).unwrap();

    assert!(languages.contains(&Language::Rust));
    assert!(frameworks.contains(&Framework::Axum));
}

/// Test Python framework detection via pyproject.toml
#[test]
fn test_python_pyproject_detection() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("pyproject.toml"),
        r#"[project]
name = "test"
dependencies = [
    "fastapi>=0.100.0",
    "uvicorn[standard]>=0.23.0"
]
"#,
    )
    .unwrap();

    let languages = detection::language::detect(temp_dir.path()).unwrap();
    let frameworks = detection::framework::detect(temp_dir.path(), &languages).unwrap();

    assert!(languages.contains(&Language::Python));
    assert!(frameworks.contains(&Framework::FastAPI));
}
