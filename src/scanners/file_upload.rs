//! File Upload vulnerability scanner
//!
//! Detects unrestricted file upload vulnerabilities where an attacker can upload
//! malicious files that may be executed on the server. Tests various bypass techniques
//! including MIME type manipulation, extension obfuscation, and webshell detection.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// MIME type bypass payloads - double extensions and alternative MIME types
const MIME_BYPASS_PAYLOADS: &[(&str, &str, &str, VulnSeverity)] = &[
    // (filename, content_type, content, severity)
    // Double extensions
    ("shell.php.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.php.jpeg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.php.png", "image/png", "test", VulnSeverity::High),
    ("shell.php.gif", "image/gif", "test", VulnSeverity::High),
    ("shell.php.bmp", "image/bmp", "test", VulnSeverity::High),
    ("shell.jsp.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.aspx.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.asp.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("webshell.php.txt", "text/plain", "test", VulnSeverity::High),
    ("shell.js.jpg", "image/jpeg", "test", VulnSeverity::Medium),
    ("shell.html.jpg", "image/jpeg", "test", VulnSeverity::Medium),
    // Null byte injection
    ("shell.php%00.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.php%00.png", "image/png", "test", VulnSeverity::High),
    ("shell.php%00.gif", "image/gif", "test", VulnSeverity::High),
    ("test.php%00.jpeg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.jsp%00.jpg", "image/jpeg", "test", VulnSeverity::High),
    ("shell.aspx%00.jpg", "image/jpeg", "test", VulnSeverity::High),
    // Alternative MIME types
    ("shell.php", "image/jpeg", "test", VulnSeverity::High),
    ("shell.php", "image/png", "test", VulnSeverity::High),
    ("shell.php", "image/gif", "test", VulnSeverity::High),
    ("shell.jsp", "image/jpeg", "test", VulnSeverity::High),
    ("shell.aspx", "image/jpeg", "test", VulnSeverity::High),
    ("shell.asp", "image/jpeg", "test", VulnSeverity::High),
];

/// Webshell detection signatures
const WEBSHELL_SIGNATURES: &[&str] = &[
    "<?php", "<?=", "eval(", "system(", "exec(", "passthru(",
    "shell_exec(", "popen(", "proc_open(", "assert(", "create_function(",
    "$_GET[", "$_POST[", "$_REQUEST[", "base64_decode(", "gzinflate(",
    "<%", "%>", "Runtime.getRuntime()", "ProcessBuilder",
    "<%@", "Process.Start(", "System.Diagnostics.Process",
];

/// File name manipulation payloads - path traversal
const FILENAME_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../evil.php",
    "../../../shell.php",
    "./../../upload.php",
    "/tmp/evil.php",
    "C:\\temp\\evil.php",
    "/var/www/html/shell.php",
    ".htaccess",
    "..htaccess",
    "web.config",
    "../config.php",
    "../.env",
];

/// Executable file extensions to test
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "php8", "phtml",
    "jsp", "jspx", "jsw", "jsv", "jspf",
    "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx", "cer",
    "exe", "dll", "com", "bat", "cmd", "vbs", "js",
    "sh", "bash", "ksh", "csh", "tcsh", "zsh",
    "pl", "py", "rb", "cgi",
];

/// Common upload endpoints
const UPLOAD_ENDPOINTS: &[&str] = &[
    "/upload", "/uploads", "/upload.php", "/upload.jsp", "/upload.aspx",
    "/api/upload", "/api/uploads", "/api/file/upload", "/api/image/upload",
    "/file/upload", "/files/upload", "/image/upload", "/media/upload",
    "/user/avatar", "/user/picture", "/user/photo", "/profile/avatar",
];

/// Response signatures indicating successful upload
const UPLOAD_SUCCESS_SIGNATURES: &[&str] = &[
    "upload success", "file uploaded", "upload complete", "successfully uploaded",
    "file saved", "file stored", "success", "uploaded",
    "file:", "filename:", "path:",
];

pub struct FileUploadScanner {
    client: Client,
    config: ScannerConfig,
}

impl FileUploadScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        eprintln!("[*] File Upload Scanner: Testing {}", url);
        eprintln!("    This scanner tests file upload validation bypasses.");

        // Phase 1: Discover upload endpoints
        let upload_urls = self.discover_upload_endpoints(url).await;
        eprintln!("    Found {} potential upload endpoints", upload_urls.len());

        if upload_urls.is_empty() {
            // Try direct URL as upload endpoint
            report.merge(self.test_url_as_upload(url).await?);
        } else {
            for upload_url in upload_urls {
                // Phase 2: Test extension bypasses
                report.merge(self.test_extension_bypass(&upload_url).await?);

                // Phase 3: Test filename manipulation
                report.merge(self.test_filename_manipulation(&upload_url).await?);

                // Phase 4: Test executable extensions (aggressive only)
                if self.config.aggressive {
                    report.merge(self.test_executable_extensions(&upload_url).await?);
                }
            }
        }

        Ok(report)
    }

    /// Discover potential file upload endpoints
    async fn discover_upload_endpoints(&self, base_url: &str) -> Vec<String> {
        let mut endpoints = Vec::new();

        let base_path = if base_url.contains('?') {
            base_url.split('?').next().unwrap_or(base_url)
        } else {
            base_url
        };

        // Try common upload endpoints
        for endpoint in UPLOAD_ENDPOINTS.iter().take(8) {
            let url = if base_path.ends_with('/') {
                format!("{}{}", base_path, endpoint.trim_start_matches('/'))
            } else {
                format!("{}{}", base_path, endpoint)
            };

            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() || resp.status().as_u16() == 405 {
                    endpoints.push(url);
                }
            }
        }

        endpoints
    }

    /// Test if the URL itself accepts file uploads
    async fn test_url_as_upload(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Try POST with form data
        let form_data = [("file", "test.txt"), ("upload", "test")];

        if let Ok(resp) = self.client.post(url).form(&form_data).send().await {
            let text = resp.text().await.unwrap_or_default();
            if self.is_upload_success(&text) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "File Upload Endpoint Discovered".to_string(),
                    description: format!("URL accepts file uploads: {}", url),
                    location: Some(url.to_string()),
                    recommendation: Some(
                        "Implement strict file validation. Check file extension, MIME type, and content.".to_string()
                    ),
                    cwe: Some("CWE-434".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Test extension bypass techniques
    async fn test_extension_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test double extensions with manual multipart encoding
        let test_files = &[
            ("shell.php.jpg", "test content"),
            ("test.php%00.jpg", "test content"),
            ("shell.php.txt", "test content"),
            ("webshell.php", "test content"),
            ("test.jsp.jpg", "test content"),
            ("shell.aspx.jpg", "test content"),
        ];

        for (filename, content) in test_files {
            let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
            let body = format!(
                "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n{}\r\n--{}--\r\n",
                boundary, filename, content, boundary
            );

            if let Ok(resp) = self.client
                .post(url)
                .header("content-type", format!("multipart/form-data; boundary={}", boundary))
                .body(body)
                .send()
                .await
            {
                let text = resp.text().await.unwrap_or_default();

                if self.is_upload_success(&text) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Extension Bypass: {}", filename),
                        description: format!(
                            "File upload validation bypassed using extension obfuscation. File '{}' was accepted.",
                            filename
                        ),
                        location: Some(format!("{} POST: file={}", url, filename)),
                        recommendation: Some(
                            "Validate file content using magic bytes. Use a whitelist of allowed extensions. Reject double extensions and null bytes.".to_string()
                        ),
                        cwe: Some("CWE-434".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test filename manipulation and path traversal
    async fn test_filename_manipulation(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test path traversal payloads
        for filename in FILENAME_TRAVERSAL_PAYLOADS.iter().take(8) {
            let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
            let body = format!(
                "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: text/plain\r\n\r\ntest content\r\n--{}--\r\n",
                boundary, filename, boundary
            );

            if let Ok(resp) = self.client
                .post(url)
                .header("content-type", format!("multipart/form-data; boundary={}", boundary))
                .body(body)
                .send()
                .await
            {
                let text = resp.text().await.unwrap_or_default();

                if self.is_upload_success(&text) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Path Traversal in Filename: {}", filename),
                        description: format!(
                            "Filename with path traversal sequence was accepted: {}. This may allow arbitrary file write.",
                            filename
                        ),
                        location: Some(format!("{} POST: file={}", url, filename)),
                        recommendation: Some(
                            "Sanitize filenames to remove path components. Use only the basename. Generate unique safe filenames.".to_string()
                        ),
                        cwe: Some("CWE-434".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test executable file extensions
    async fn test_executable_extensions(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test common executable extensions
        let test_extensions = &EXECUTABLE_EXTENSIONS[..12];

        for ext in test_extensions {
            let filename = format!("test.{}", ext);
            let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
            let body = format!(
                "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\ntest\r\n--{}--\r\n",
                boundary, filename, boundary
            );

            if let Ok(resp) = self.client
                .post(url)
                .header("content-type", format!("multipart/form-data; boundary={}", boundary))
                .body(body)
                .send()
                .await
            {
                let text = resp.text().await.unwrap_or_default();

                if self.is_upload_success(&text) {
                    report.add_finding(Vuln {
                        severity: if matches!(*ext, "php" | "jsp" | "aspx" | "asp" | "phtml") {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        },
                        title: format!("Executable Extension Allowed: .{}", ext),
                        description: format!(
                            "Server accepts files with executable extension: .{}. This could lead to code execution.",
                            ext
                        ),
                        location: Some(format!("{} POST: file=test.{}", url, ext)),
                        recommendation: Some(
                            "Use a whitelist of allowed extensions (jpg, png, pdf, etc.). Block all executable/script extensions.".to_string()
                        ),
                        cwe: Some("CWE-434".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check if response indicates successful upload
    fn is_upload_success(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        for signature in UPLOAD_SUCCESS_SIGNATURES {
            if text_lower.contains(&signature.to_lowercase()) {
                return true;
            }
        }

        // Check for path indicators
        if text_lower.contains("/upload/") || text_lower.contains("/files/") {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = FileUploadScanner::new(config);
        assert_eq!(scanner.config.user_agent.contains("Warden"), true);
    }

    #[test]
    fn test_mime_bypass_payloads_loaded() {
        assert!(!MIME_BYPASS_PAYLOADS.is_empty());
        assert!(MIME_BYPASS_PAYLOADS.len() > 10);
    }

    #[test]
    fn test_webshell_signatures_loaded() {
        assert!(!WEBSHELL_SIGNATURES.is_empty());
        assert!(WEBSHELL_SIGNATURES.contains(&"<?php"));
        assert!(WEBSHELL_SIGNATURES.contains(&"eval("));
        assert!(WEBSHELL_SIGNATURES.contains(&"system("));
    }

    #[test]
    fn test_filename_traversal_payloads_loaded() {
        assert!(!FILENAME_TRAVERSAL_PAYLOADS.is_empty());
        assert!(FILENAME_TRAVERSAL_PAYLOADS.contains(&"../../evil.php"));
    }

    #[test]
    fn test_executable_extensions_loaded() {
        assert!(!EXECUTABLE_EXTENSIONS.is_empty());
        assert!(EXECUTABLE_EXTENSIONS.contains(&"php"));
        assert!(EXECUTABLE_EXTENSIONS.contains(&"jsp"));
        assert!(EXECUTABLE_EXTENSIONS.contains(&"aspx"));
    }

    #[test]
    fn test_upload_endpoints_loaded() {
        assert!(!UPLOAD_ENDPOINTS.is_empty());
        assert!(UPLOAD_ENDPOINTS.contains(&"/upload"));
        assert!(UPLOAD_ENDPOINTS.contains(&"/api/upload"));
    }

    #[test]
    fn test_is_upload_success() {
        let scanner = FileUploadScanner::new(ScannerConfig::new());

        assert!(scanner.is_upload_success("Upload successful!"));
        assert!(scanner.is_upload_success("File has been uploaded"));
        assert!(scanner.is_upload_success("success"));

        assert!(!scanner.is_upload_success("Error: Invalid file"));
    }
}
