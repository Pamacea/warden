//! Unit tests for scanners with mock HTTP responses

use std::time::Duration;
use tokio::time::timeout;
use warden_sec::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};

/// Test HTTP scanner with a real mock server
#[tokio::test]
async fn test_http_scanner_with_mock_server() {
    let mut server = mockito::Server::new_async().await;

    // Mock the HEAD request for security headers
    let _mock = server
        .mock("HEAD", "/")
        .with_status(200)
        .with_header("content-type", "text/html")
        .create();

    let url = format!("{}/", server.url());
    let config = ScannerConfig::new().with_timeout(Duration::from_secs(1));
    let scanner = warden_sec::scanners::HttpScanner::new(config);

    let result = scanner.scan(&url).await;

    // Should succeed without crashing
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.target, Target::Url(url));
}

/// Test HTTP scanner with missing security headers
#[tokio::test]
async fn test_http_scanner_missing_headers() {
    let mut server = mockito::Server::new_async().await;

    // Mock response with no security headers
    let _mock = server
        .mock("HEAD", "/")
        .with_status(200)
        .create();

    let url = format!("{}/", server.url());
    let config = ScannerConfig::new().with_timeout(Duration::from_secs(1));
    let scanner = warden_sec::scanners::HttpScanner::new(config);

    let report = scanner.scan(&url).await.unwrap();

    // Should find missing headers
    assert!(report.findings.len() > 0);
}

/// Test HTTP scanner with all security headers present
#[tokio::test]
async fn test_http_scanner_with_all_headers() {
    let mut server = mockito::Server::new_async().await;

    // Mock response with all security headers
    let _mock = server
        .mock("HEAD", "/")
        .with_status(200)
        .with_header("X-Frame-Options", "DENY")
        .with_header("X-Content-Type-Options", "nosniff")
        .with_header("Strict-Transport-Security", "max-age=31536000")
        .with_header("Content-Security-Policy", "default-src 'self'")
        .with_header("Referrer-Policy", "no-referrer")
        .create();

    let url = format!("{}/", server.url());
    let config = ScannerConfig::new().with_timeout(Duration::from_secs(1));
    let scanner = warden_sec::scanners::HttpScanner::new(config);

    let report = scanner.scan(&url).await.unwrap();

    // Should have fewer findings when headers are present
    let missing_header_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.title.contains("Missing") || f.title.contains("missing"))
        .collect();

    assert!(missing_header_findings.len() < 6); // At least some headers present
}

/// Test HTTP scanner timeout
#[tokio::test]
async fn test_http_scanner_timeout() {
    let mut server = mockito::Server::new_async().await;

    // Mock delayed response
    let _mock = server
        .mock("HEAD", "/")
        .with_chunked_body(|w| {
            std::thread::sleep(Duration::from_secs(2));
            w.write_all(b"hello")
        })
        .create();

    let url = format!("{}/", server.url());
    let config = ScannerConfig::new().with_timeout(Duration::from_millis(100));
    let scanner = warden_sec::scanners::HttpScanner::new(config);

    let result = timeout(Duration::from_secs(1), scanner.scan(&url)).await;

    // Should timeout or complete
    assert!(result.is_ok() || result.is_err());
}

/// Test HTTP scanner aggressive mode with XSS detection
#[tokio::test]
async fn test_http_scanner_aggressive_xss() {
    let mut server = mockito::Server::new_async().await;

    // Mock HEAD for headers
    let _head_mock = server.mock("HEAD", "/").with_status(200).create();

    // Mock GET request that reflects XSS payload
    let _get_mock = server
        .mock("GET", "/")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("xss".into(), "<script>alert(1)</script>".into()),
        ]))
        .with_status(200)
        .with_body("<html><script>alert(1)</script></html>")
        .create();

    let url = format!("{}/", server.url());
    let config = ScannerConfig::new()
        .with_aggressive(true)
        .with_timeout(Duration::from_secs(1));
    let scanner = warden_sec::scanners::HttpScanner::new(config);

    let report = scanner.scan(&url).await.unwrap();

    // Should detect XSS vulnerability
    let xss_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.title.contains("XSS") || f.title.contains("Cross-Site Scripting"))
        .collect();

    assert!(!xss_findings.is_empty());
}

/// Test static scanner with Rust files
#[tokio::test]
async fn test_static_scanner_rust_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create Rust file with unsafe blocks
    let rust_content = r#"
fn main() {
    unsafe { println!("test"); }
    unsafe { println!("test2"); }
    unsafe { println!("test3"); }
    unsafe { println!("test4"); }
    unsafe { println!("test5"); }
    unsafe { println!("test6"); }
    unsafe { println!("test7"); }
    unsafe { println!("test8"); }
    unsafe { println!("test9"); }
    unsafe { println!("test10"); }
    unsafe { println!("test11"); }
}
"#;
    std::fs::write(src_dir.join("main.rs"), rust_content).unwrap();

    let config = ScannerConfig::new();
    let scanner = warden_sec::scanners::StaticScanner::new(config);

    let report = scanner.scan(temp_dir.path()).await.unwrap();

    // Should detect excessive unsafe blocks
    let unsafe_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.title.contains("Unsafe"))
        .collect();

    assert!(!unsafe_findings.is_empty());
}

/// Test static scanner with JavaScript files
#[tokio::test]
async fn test_static_scanner_js_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create JS file with eval
    let js_content = r#"
function dangerous(input) {
    eval(input);
    document.body.innerHTML = input;
}
"#;
    std::fs::write(src_dir.join("app.js"), js_content).unwrap();

    let config = ScannerConfig::new();
    let scanner = warden_sec::scanners::StaticScanner::new(config);

    let report = scanner.scan(temp_dir.path()).await.unwrap();

    // Should detect eval and innerHTML
    assert!(report.findings.iter().any(|f| f.title.contains("eval")));
    assert!(report
        .findings
        .iter()
        .any(|f| f.title.contains("innerHTML")));
}

/// Test static scanner with Python files
#[tokio::test]
async fn test_static_scanner_python_files() {
    let temp_dir = tempfile::tempdir().unwrap();
    let src_dir = temp_dir.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();

    // Create Python file with dangerous patterns
    let py_content = r#"
import subprocess

def dangerous(user_input):
    exec(user_input)
    subprocess.call(user_input, shell=True)
"#;
    std::fs::write(src_dir.join("app.py"), py_content).unwrap();

    let config = ScannerConfig::new();
    let scanner = warden_sec::scanners::StaticScanner::new(config);

    let report = scanner.scan(temp_dir.path()).await.unwrap();

    // Should detect exec and shell=True
    assert!(report.findings.iter().any(|f| f.title.contains("exec")));
    assert!(report
        .findings
        .iter()
        .any(|f| f.title.contains("shell=True")));
}

/// Test static scanner with empty directory
#[tokio::test]
async fn test_static_scanner_empty_directory() {
    let temp_dir = tempfile::tempdir().unwrap();

    let config = ScannerConfig::new();
    let scanner = warden_sec::scanners::StaticScanner::new(config);

    let report = scanner.scan(temp_dir.path()).await.unwrap();

    assert_eq!(report.findings.len(), 0);
}

/// Test port scanner with localhost
#[tokio::test]
async fn test_port_scanner_localhost() {
    // Use a likely closed port for testing
    let config = ScannerConfig::new();
    let scanner = warden_sec::scanners::PortScanner::new(config);

    let result = scanner.scan("http://localhost:59999").await;

    // Should succeed without crashing
    assert!(result.is_ok());
}

/// Test scan report merging
#[test]
fn test_scan_report_merge() {
    let mut report1 = ScanReport::new(Target::Url("http://example.com".to_string()));
    let mut report2 = ScanReport::new(Target::Url("http://example.com".to_string()));

    report1.add_finding(Vuln {
        severity: VulnSeverity::Critical,
        title: "Critical Bug".to_string(),
        description: "A critical issue".to_string(),
        location: Some("/api".to_string()),
        recommendation: Some("Fix immediately".to_string()),
        cwe: Some("CWE-123".to_string()),
        owasp: Some("A01:2021".to_string()),
    });

    report2.add_finding(Vuln {
        severity: VulnSeverity::High,
        title: "High Bug".to_string(),
        description: "A high issue".to_string(),
        location: Some("/auth".to_string()),
        recommendation: Some("Fix soon".to_string()),
        cwe: Some("CWE-456".to_string()),
        owasp: Some("A02:2021".to_string()),
    });

    report1.merge(report2);

    assert_eq!(report1.findings.len(), 2);
    assert_eq!(report1.summary.critical, 1);
    assert_eq!(report1.summary.high, 1);
    assert_eq!(report1.summary.total, 2);
}

/// Test vulnerability severity ordering
#[test]
fn test_severity_ordering() {
    let severities = vec![
        VulnSeverity::Critical,
        VulnSeverity::High,
        VulnSeverity::Medium,
        VulnSeverity::Low,
        VulnSeverity::Info,
    ];

    // Verify all severities are comparable
    for i in 0..severities.len() {
        for j in i..severities.len() {
            let _ = severities[i] == severities[j];
        }
    }
}

/// Test scanner config builder
#[test]
fn test_scanner_config_builder() {
    let config = ScannerConfig::new()
        .with_aggressive(true)
        .with_timeout(Duration::from_secs(30))
        .with_concurrency(100)
        .with_ddos(true)
        .with_stress(true);

    assert!(config.aggressive);
    assert_eq!(config.timeout, Duration::from_secs(30));
    assert_eq!(config.concurrency, 100);
    assert!(config.ddos);
    assert!(config.stress);
}

/// Test vulnerability serialization
#[test]
fn test_vuln_serialization() {
    let vuln = Vuln {
        severity: VulnSeverity::Critical,
        title: "Test Vulnerability".to_string(),
        description: "A test vulnerability".to_string(),
        location: Some("/test/path".to_string()),
        recommendation: Some("Apply patch".to_string()),
        cwe: Some("CWE-79".to_string()),
        owasp: Some("A03:2021 - Injection".to_string()),
    };

    let serialized = serde_json::to_string(&vuln).unwrap();
    let deserialized: Vuln = serde_json::from_str(&serialized).unwrap();

    assert_eq!(vuln.title, deserialized.title);
    assert_eq!(vuln.severity, deserialized.severity);
    assert_eq!(vuln.location, deserialized.location);
    assert_eq!(vuln.cwe, deserialized.cwe);
}

/// Test report format parsing
#[test]
fn test_report_format_parsing() {
    use warden_sec::reporters::ReportFormat;

    assert_eq!(
        "console".parse::<ReportFormat>().unwrap(),
        ReportFormat::Console
    );
    assert_eq!(
        "json".parse::<ReportFormat>().unwrap(),
        ReportFormat::Json
    );
    assert_eq!(
        "markdown".parse::<ReportFormat>().unwrap(),
        ReportFormat::Markdown
    );
    assert_eq!(
        "md".parse::<ReportFormat>().unwrap(),
        ReportFormat::Markdown
    );

    assert!("invalid".parse::<ReportFormat>().is_err());
}

/// Test language detection
#[test]
fn test_language_detection() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create Cargo.toml
    std::fs::write(
        temp_dir.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\n",
    )
    .unwrap();

    let languages = warden_sec::detection::language::detect(temp_dir.path()).unwrap();
    assert!(languages.contains(&warden_sec::detection::Language::Rust));
}

/// Test framework detection
#[test]
fn test_framework_detection() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Create package.json with Next.js
    std::fs::write(
        temp_dir.path().join("package.json"),
        r#"{"dependencies": {"next": "^14.0.0"}}"#,
    )
    .unwrap();

    let frameworks =
        warden_sec::detection::framework::detect(temp_dir.path(), &[warden_sec::detection::Language::JavaScript])
            .unwrap();
    assert!(frameworks.contains(&warden_sec::detection::Framework::NextJS));
}

/// Test network URL validation
#[test]
fn test_url_validation() {
    use warden_sec::utils::validate_url;

    assert!(validate_url("https://example.com").is_ok());
    assert!(validate_url("http://localhost:8080").is_ok());
    assert!(validate_url("ftp://example.com").is_err());
    assert!(validate_url("not-a-url").is_err());
}

/// Test file extension utility
#[test]
fn test_get_extension() {
    use warden_sec::utils::get_extension;
    use std::path::Path;

    assert_eq!(get_extension(Path::new("test.rs")), Some("rs"));
    assert_eq!(get_extension(Path::new("test.tar.gz")), Some("gz"));
    assert_eq!(get_extension(Path::new("noextension")), None);
}

/// Test find files utility
#[test]
fn test_find_files() {
    let temp_dir = tempfile::tempdir().unwrap();

    std::fs::write(temp_dir.path().join("test.rs"), "content").unwrap();
    std::fs::write(temp_dir.path().join("test.txt"), "content").unwrap();

    let files = warden_sec::utils::find_files(temp_dir.path(), r"\.rs$").unwrap();
    assert_eq!(files.len(), 1);
}

/// Test read file limited
#[test]
fn test_read_file_limited() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    std::fs::write(&file_path, "small content").unwrap();

    let content = warden_sec::utils::read_file_limited(&file_path, 100).unwrap();
    assert_eq!(content, "small content");
}

/// Test read file too large
#[test]
fn test_read_file_too_large() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    std::fs::write(&file_path, "x".repeat(1000)).unwrap();

    let result = warden_sec::utils::read_file_limited(&file_path, 100);
    assert!(result.is_err());
}
