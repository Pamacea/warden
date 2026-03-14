//! Integration tests

use std::path::PathBuf;

#[tokio::test]
async fn test_detect_rust_project() {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("warden");

    // This is a placeholder test
    // Real integration tests would create test projects
    assert!(path.exists());
}

#[tokio::test]
async fn test_scan_empty_directory() {
    let temp_dir = tempfile::tempdir().unwrap();

    // Should not crash on empty directory
    let result = warden::scanners::StaticScanner::new(
        warden::scanners::ScannerConfig::new()
    ).scan(temp_dir.path()).await;

    assert!(result.is_ok());
}
