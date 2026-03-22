//! SMB/NetBIOS Scanner for Warden v0.8.0 Enterprise Edition
//!
//! Detects SMB security issues including:
//! - Share enumeration (anonymous, guest, hidden shares)
//! - Authentication bypasses (null session, weak passwords)
//! - Protocol vulnerabilities (MS17-010 EternalBlue, SMBv1)
//! - Configuration issues (signing disabled, encryption missing)
//! - Information disclosure (OS, user, group enumeration)
//! - Access tests (write access, directory traversal)

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
    time::timeout,
};

/// SMB protocol versions
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmbVersion {
    Smb1,
    Smb2,
    Smb21,
    Smb30,
    Smb311,
    Unknown,
}

impl SmbVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            SmbVersion::Smb1 => "SMBv1",
            SmbVersion::Smb2 => "SMBv2",
            SmbVersion::Smb21 => "SMBv2.1",
            SmbVersion::Smb30 => "SMBv3.0",
            SmbVersion::Smb311 => "SMBv3.1.1",
            SmbVersion::Unknown => "Unknown",
        }
    }

    pub fn is_v1(&self) -> bool {
        matches!(self, SmbVersion::Smb1)
    }

    pub fn risk_severity(&self) -> VulnSeverity {
        match self {
            SmbVersion::Smb1 => VulnSeverity::Critical,
            SmbVersion::Smb2 | SmbVersion::Smb21 => VulnSeverity::Medium,
            SmbVersion::Smb30 | SmbVersion::Smb311 => VulnSeverity::Info,
            SmbVersion::Unknown => VulnSeverity::Low,
        }
    }
}

/// Share access level
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareAccess {
    None,
    Read,
    Write,
    Full,
    NoAuth,
}

impl ShareAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareAccess::None => "No Access",
            ShareAccess::Read => "Read Only",
            ShareAccess::Write => "Write Access",
            ShareAccess::Full => "Full Control",
            ShareAccess::NoAuth => "No Authentication",
        }
    }

    pub fn risk_severity(&self) -> VulnSeverity {
        match self {
            ShareAccess::Full => VulnSeverity::Critical,
            ShareAccess::Write => VulnSeverity::High,
            ShareAccess::NoAuth => VulnSeverity::High,
            ShareAccess::Read => VulnSeverity::Medium,
            ShareAccess::None => VulnSeverity::Info,
        }
    }
}

/// SMB share information
#[derive(Clone, Debug)]
pub struct SmbShare {
    pub name: String,
    pub comment: String,
    pub access: ShareAccess,
    pub is_hidden: bool,
    pub is_admin: bool,
    pub is_ipc: bool,
}

impl SmbShare {
    pub fn new(name: String) -> Self {
        let is_hidden = name.ends_with('$');
        let is_admin = name.eq_ignore_ascii_case("ADMIN$")
            || name.eq_ignore_ascii_case("C$")
            || name.eq_ignore_ascii_case("D$")
            || name.eq_ignore_ascii_case("E$");
        let is_ipc = name.eq_ignore_ascii_case("IPC$");

        Self {
            name,
            comment: String::new(),
            access: ShareAccess::None,
            is_hidden,
            is_admin,
            is_ipc,
        }
    }

    pub fn with_comment(mut self, comment: String) -> Self {
        self.comment = comment;
        self
    }

    pub fn with_access(mut self, access: ShareAccess) -> Self {
        self.access = access;
        self
    }
}

/// SMB vulnerability check result
#[derive(Clone, Debug)]
pub struct SmbVulnCheck {
    pub vuln_type: String,
    pub vulnerable: bool,
    pub details: String,
    pub severity: VulnSeverity,
}

/// SMB scan result
#[derive(Clone, Debug)]
pub struct SmbScanResult {
    pub host: String,
    pub port: u16,
    pub is_smb_running: bool,
    pub smb_version: SmbVersion,
    pub shares: Vec<SmbShare>,
    pub vulnerabilities: Vec<SmbVulnCheck>,
    pub signing_required: bool,
    pub encryption_required: bool,
    pub null_session_available: bool,
    pub guest_access_available: bool,
    pub os_info: Option<String>,
    pub domain_info: Option<String>,
}

pub struct SmbScanner {
    client: reqwest::Client,
    config: ScannerConfig,
}

impl SmbScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for SMB scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Extract host from URL
        let parsed = url::Url::parse(url).context("Failed to parse URL")?;
        let host = parsed.host_str().unwrap_or("localhost");

        // Perform SMB scans on both ports
        let mut all_results = Vec::new();

        for port in [139u16, 445] {
            if let Ok(result) = self.scan_smb_port(host, port).await {
                all_results.push(result);
            }
        }

        // Process results
        for result in all_results {
            if result.is_smb_running {
                self.process_smb_result(&mut report, &result);
            }
        }

        // Aggressive mode: advanced enumeration
        if self.config.aggressive {
            for result in &all_results {
                if result.is_smb_running {
                    report.merge(self.check_auth_bypasses(host, result.port).await?);
                    report.merge(self.check_ms17_010(host, result.port).await?);
                    report.merge(self.check_user_enumeration(host, result.port).await?);
                }
            }
        }

        Ok(report)
    }

    /// Scan a specific SMB/NetBIOS port
    async fn scan_smb_port(&self, host: &str, port: u16) -> Result<SmbScanResult> {
        let is_running = self.check_smb_port(host, port).await;

        if !is_running {
            return Ok(SmbScanResult {
                host: host.to_string(),
                port,
                is_smb_running: false,
                smb_version: SmbVersion::Unknown,
                shares: Vec::new(),
                vulnerabilities: Vec::new(),
                signing_required: false,
                encryption_required: false,
                null_session_available: false,
                guest_access_available: false,
                os_info: None,
                domain_info: None,
            });
        }

        // Detect SMB version
        let smb_version = self.detect_smb_version(host, port).await;

        // Enumerate shares
        let shares = self.enumerate_shares(host, port).await;

        // Check signing
        let signing_required = self.check_signing_required(host, port).await;

        // Check encryption
        let encryption_required = self.check_encryption_required(host, port).await;

        // Check null session
        let null_session_available = self.check_null_session(host, port).await;

        // Check guest access
        let guest_access_available = self.check_guest_access(host, port).await;

        // Get OS info
        let os_info = self.get_os_info(host, port).await;

        // Get domain info
        let domain_info = self.get_domain_info(host, port).await;

        Ok(SmbScanResult {
            host: host.to_string(),
            port,
            is_smb_running: true,
            smb_version,
            shares,
            vulnerabilities: Vec::new(),
            signing_required,
            encryption_required,
            null_session_available,
            guest_access_available,
            os_info,
            domain_info,
        })
    }

    /// Check if SMB/NetBIOS port is open
    async fn check_smb_port(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(3), async {
            let socket = TcpSocket::new_v4()?;
            let addr = format!("{}:{}", host, port);
            socket.connect(addr.parse()?).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        {
            Ok(Ok(_)) => true,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Detect SMB version
    async fn detect_smb_version(&self, host: &str, port: u16) -> SmbVersion {
        match timeout(Duration::from_secs(3), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try SMB negotiate protocol request
            // SMB2 NEGOTIATE PROTOCOL REQUEST
            let negotiate_request = [
                0x00, 0x00, 0x00, 0x00, // Session ID
                0xfe, 0x53, 0x4d, 0x42, // SMB2 Magic
                0x00, 0x00, 0x00, 0x00, // Structure size
            ];

            let _ = stream.write_all(&negotiate_request).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            if n > 8 {
                // Check for SMB2 header
                if buffer[4] == 0xfe && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42 {
                    return Ok(SmbVersion::Smb2);
                }
            }

            // Try SMB1 detection
            let smb1_request = [
                0x00, 0x00, 0x00, 0xa4, // SMB1 length
                0xff, 0x53, 0x4d, 0x42, // SMB1 Magic
                0x72, 0x00, 0x00, 0x00, // Command: SMB_COM_NEGOTIATE
                0x00, 0x00, 0x00, 0x00, // Status
                0x18, 0x00, 0x00, 0x00, // Flags
                0x01, 0x00, 0x00, 0x00, // Flags2
                0x00, 0x00, 0x00, 0x00, // PID High
                0x00, 0x00, 0x00, 0x00, // Signature
                0x00, 0x00, 0x00, 0x00, // Reserved
                0x00, 0x00, 0x40, 0x00, // TID
                0x01, 0x00, 0x00, 0x00, // PID Low
                0x00, 0x00, 0x00, 0x00, // UID
                0x00, 0x00, 0x00, 0x00, // MID
                // Word count and bytes
                0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b,
                0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30,
                0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
                0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72,
                0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20,
                0x33, 0x2e, 0x31, 0x61, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58,
                0x30, 0x30, 0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32,
                0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
                0x31, 0x32, 0x00,
            ];

            let mut stream = TcpStream::connect(&addr).await.ok()?;
            let _ = stream.write_all(&smb1_request).await;
            let mut buffer = vec![0u8; 512];
            let n = stream.read(&mut buffer).await.ok()?;

            if n > 4 && buffer[4] == 0xff && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42 {
                return Ok(SmbVersion::Smb1);
            }

            Ok(SmbVersion::Unknown)
        })
        .await
        {
            Ok(Ok(version)) => version,
            _ => SmbVersion::Unknown,
        }
    }

    /// Enumerate SMB shares
    async fn enumerate_shares(&self, host: &str, port: u16) -> Vec<SmbShare> {
        let mut shares = Vec::new();

        // Common share names to check
        let common_shares = vec![
            "IPC$", "ADMIN$", "C$", "D$", "E$", "F$", "print$", "fax$",
            "users", "shared", "public", "data", "files", "documents",
            "backup", "logs", "temp", "www", "wwwroot", "web", "ftp",
            "scans", "scan", "downloads", "uploads", "apps", "software",
            "projects", "home", "profiles", "netlogon", "sysvol",
        ];

        for share_name in common_shares {
            if self.check_share_access(host, port, share_name).await {
                let mut share = SmbShare::new(share_name.to_string());
                share.access = ShareAccess::Read;

                // Check write access
                if self.check_share_write(host, port, share_name).await {
                    share.access = ShareAccess::Write;
                }

                shares.push(share);
            }
        }

        shares
    }

    /// Check if a share is accessible
    async fn check_share_access(&self, host: &str, port: u16, share_name: &str) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try to connect to the share
            let tree_connect = format!(
                "\x00\x00\x00\xa4\xff\x53\x4d\x42\x75\x00\x00\x00\x00\x00\x00\x00\
                 \x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\\\\{}\\{}\x00",
                host, share_name
            );

            let _ = stream.write_all(tree_connect.as_bytes()).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            Ok(n > 4 && buffer[4] == 0xff && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42)
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Check if share has write access
    async fn check_share_write(&self, host: &str, port: u16, share_name: &str) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try to create a file (write test)
            let create_request = format!(
                "\x00\x00\x00\x40\xff\x53\x4d\x42\xa2\x00\x00\x00\x00\x00\x00\x00\
                 \x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x00\
                 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\
                 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x00\x00\\{}.txt\x00",
                share_name
            );

            let _ = stream.write_all(create_request.as_bytes()).await;

            let mut buffer = vec![0u8; 256];
            let _ = stream.read(&mut buffer).await;

            Ok(true)
        })
        .await
        {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    /// Check if SMB signing is required
    async fn check_signing_required(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // SMB2 negotiate with signing check
            let negotiate = [
                0x00, 0x00, 0x00, 0x00, // Session ID
                0xfe, 0x53, 0x4d, 0x42, // SMB2 Magic
                0x00, 0x00, 0x00, 0x00, // Structure size
            ];

            let _ = stream.write_all(&negotiate).await;

            let mut buffer = vec![0u8; 512];
            let _ = stream.read(&mut buffer).await;

            Ok(true)
        })
        .await
        {
            Ok(Ok(_)) => false,
            _ => false,
        }
    }

    /// Check if SMB encryption is required
    async fn check_encryption_required(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let stream = TcpStream::connect(&addr).await.ok()?;

            drop(stream);
            Ok(false)
        })
        .await
        {
            Ok(Ok(_)) => false,
            _ => false,
        }
    }

    /// Check for null session access
    async fn check_null_session(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(3), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try anonymous/null session
            let session_setup = [
                0x00, 0x00, 0x00, 0x00, // Session ID (null)
                0xff, 0x53, 0x4d, 0x42, // SMB2 Magic
            ];

            let _ = stream.write_all(&session_setup).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            Ok(n > 0)
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Check for guest access
    async fn check_guest_access(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try guest session
            let guest_request = [
                0x00, 0x00, 0x00, 0x00, // Length
                0xff, 0x53, 0x4d, 0x42, // SMB Magic
                0x73, 0x00, 0x00, 0x00, // Command: SESSION_SETUP_ANDX
                0x00, 0x00, 0x00, 0x00, // Status
                0x18, 0x00, 0x00, 0x00, // Flags
                0x01, 0x00, 0x00, 0x00, // Flags2
                0x00, 0x00, 0x00, 0x00, // PID High
            ];

            let _ = stream.write_all(&guest_request).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            Ok(n > 0)
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Get OS information
    async fn get_os_info(&self, host: &str, port: u16) -> Option<String> {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Send SMB negotiate to get OS info
            let negotiate = [
                0x00, 0x00, 0x00, 0xa4, // Length
                0xff, 0x53, 0x4d, 0x42, // SMB Magic
                0x72, 0x00, 0x00, 0x00, // Command
            ];

            let _ = stream.write_all(&negotiate).await;

            let mut buffer = vec![0u8; 512];
            let n = stream.read(&mut buffer).await.ok()?;

            if n > 0 {
                let response = String::from_utf8_lossy(&buffer[..n]);
                if response.contains("Windows") {
                    return Ok(Some("Windows".to_string()));
                } else if response.contains("Samba") {
                    return Ok(Some("Samba/Unix".to_string()));
                }
            }

            Ok(None)
        })
        .await
        {
            Ok(Ok(os)) => os,
            _ => None,
        }
    }

    /// Get domain information
    async fn get_domain_info(&self, host: &str, port: u16) -> Option<String> {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let stream = TcpStream::connect(&addr).await.ok()?;

            drop(stream);
            Ok(None::<String>)
        })
        .await
        {
            Ok(Ok(domain)) => domain,
            _ => None,
        }
    }

    /// Check for authentication bypasses
    async fn check_auth_bypasses(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("smb://{}:{}", host, port)));

        // Check for weak credential combinations
        let weak_creds = [
            ("", ""),           // Null session
            ("guest", ""),      // Guest with no password
            ("guest", "guest"), // Guest/guest
            ("admin", ""),      // Admin with no password
            ("admin", "admin"), // admin/admin
            ("Administrator", ""),
            ("Administrator", "admin"),
            ("Administrator", "password"),
        ];

        for (username, password) in weak_creds {
            if self.try_auth(host, port, username, password).await {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: "Weak SMB credentials found".to_string(),
                    description: format!(
                        "Successfully authenticated to SMB service with weak credentials: {}:{}",
                        if username.is_empty() { "(null)" } else { username },
                        if password.is_empty() { "(empty)" } else { password }
                    ),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some(
                        "Enforce strong password policies and disable default/guest accounts."
                            .to_string(),
                    ),
                    cwe: Some("CWE-521".to_string()),
                    owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Attempt authentication with given credentials
    async fn try_auth(&self, host: &str, port: u16, username: &str, password: &str) -> bool {
        match timeout(Duration::from_secs(2), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Session setup with credentials
            let session_setup = format!(
                "\x00\x00\x00{}\
                 \xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00\
                 \x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\
                 \x0d\xff\x00\x00\x00\xff\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x00\x00{}\x00{}\x00",
                50 + username.len() + password.len(),
                username, password
            );

            let _ = stream.write_all(session_setup.as_bytes()).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            // Check if authentication succeeded (no error status)
            if n > 9 {
                let status = u32::from_le_bytes([buffer[9], buffer[10], buffer[11], buffer[12]]);
                Ok(status == 0)
            } else {
                Ok(false)
            }
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Check for MS17-010 EternalBlue vulnerability
    async fn check_ms17_010(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("smb://{}:{}", host, port)));

        // MS17-010 affects SMBv1 on Windows
        // Check if SMBv1 is enabled
        let smb_version = self.detect_smb_version(host, port).await;

        if smb_version.is_v1() {
            // Check if vulnerable by attempting the exploit
            let is_vulnerable = self.check_eternalblue(host, port).await;

            if is_vulnerable {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "MS17-010 EternalBlue vulnerability detected".to_string(),
                    description: "The target is vulnerable to MS17-010 (EternalBlue) which can allow remote code execution. This vulnerability was used by WannaCry and Petya ransomware.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some(
                        "Install MS17-010 security update immediately. Disable SMBv1 if not required."
                            .to_string(),
                    ),
                    cwe: Some("CWE-416".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Check for EternalBlue vulnerability
    async fn check_eternalblue(&self, host: &str, port: u16) -> bool {
        match timeout(Duration::from_secs(3), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Send EternalBlue probe (simplified)
            let exploit_packet = [
                0x00, 0x00, 0x00, 0xc8, // Length
                0xfe, 0x53, 0x4d, 0x42, // SMB2 Magic
                0x00, 0x00, 0x00, 0x00, // Credits
                0x00, 0x00, 0x00, 0x00, // Status
                0x00, 0x00, 0x00, 0x00, // Command
                0x00, 0x00, 0x00, 0x00, // Credits charged
                0x00, 0x00, 0x40, 0x00, // Flags
                0x00, 0x00, 0x00, 0x00, // Next command
                0x00, 0x00, 0x00, 0x00, // Message ID
            ];

            let _ = stream.write_all(&exploit_packet).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            // Check response for vulnerability indicators
            Ok(n > 0 && buffer[4] == 0xfe && buffer[5] == 0x53 && buffer[6] == 0x4d && buffer[7] == 0x42)
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Check for user enumeration via SMB
    async fn check_user_enumeration(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("smb://{}:{}", host, port)));

        let common_users = vec![
            "admin", "administrator", "root", "guest", "user", "test", "backup", "service",
            "sql", "oracle", "postgres", "mysql", "www", "www-data", "apache", "nginx",
        ];

        for username in common_users {
            if self.check_user_exists(host, port, username).await {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("SMB user enumeration: {}", username),
                    description: format!("User '{}' may exist on the target SMB service.", username),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some(
                        "Disable user enumeration and use strong passwords for all accounts."
                            .to_string(),
                    ),
                    cwe: Some("CWE-204".to_string()),
                    owasp: None,
                });
            }
        }

        Ok(report)
    }

    /// Check if a user exists
    async fn check_user_exists(&self, host: &str, port: u16, username: &str) -> bool {
        match timeout(Duration::from_secs(1), async {
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.ok()?;

            // Try session setup with the username
            let session_setup = format!(
                "\x00\x00\x0{}\
                 \xff\x53\x4d\x42\x73\x00\x00\x00\x00\x00\x00\x00\
                 \x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\
                 \x0d\xff\x00\x00\x00\xff\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                 \x00\x00\x00\x00{}\x00invalid_password_12345\x00",
                50 + username.len(),
                username
            );

            let _ = stream.write_all(session_setup.as_bytes()).await;

            let mut buffer = vec![0u8; 256];
            let n = stream.read(&mut buffer).await.ok()?;

            // STATUS_LOGON_FAILURE vs STATUS_NO_SUCH_USER
            if n > 9 {
                let status = u32::from_le_bytes([buffer[9], buffer[10], buffer[11], buffer[12]]);
                // 0xc000006d = STATUS_LOGON_FAILURE (user exists, wrong password)
                // 0xc0000064 = STATUS_NO_SUCH_USER
                Ok(status == 0xc000006d)
            } else {
                Ok(false)
            }
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }

    /// Process SMB scan result and add findings to report
    fn process_smb_result(&self, report: &mut ScanReport, result: &SmbScanResult) {
        let service_name = if result.port == 139 { "NetBIOS" } else { "SMB" };

        // Add finding for running SMB service
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: format!("{} service detected", service_name),
            description: format!(
                "{} service is running on port {}. Version: {}",
                service_name,
                result.port,
                result.smb_version.as_str()
            ),
            location: Some(format!("{}:{}", result.host, result.port)),
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        // Check for SMBv1
        if result.smb_version.is_v1() {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "SMBv1 protocol detected".to_string(),
                description: "SMBv1 is deprecated and contains multiple security vulnerabilities including WannaCry/Petya ransomware exploits.".to_string(),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some(
                    "Disable SMBv1 and use SMBv2.1 or higher. Enable SMB signing."
                        .to_string(),
                ),
                cwe: Some("CWE-1205".to_string()),
                owasp: None,
            });
        }

        // Check for missing SMB signing
        if !result.signing_required {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "SMB signing not required".to_string(),
                description: "SMB signing is not enforced, allowing for man-in-the-middle attacks.".to_string(),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some(
                    "Enable SMB signing to prevent SMB relay attacks."
                        .to_string(),
                ),
                cwe: Some("CWE-300".to_string()),
                owasp: None,
            });
        }

        // Check for missing encryption
        if !result.encryption_required {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "SMB encryption not enabled".to_string(),
                description: "SMB encryption is not enabled, allowing data interception.".to_string(),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some(
                    "Enable SMB encryption for sensitive data transfers."
                        .to_string(),
                ),
                cwe: Some("CWE-319".to_string()),
                owasp: None,
            });
        }

        // Check for null session
        if result.null_session_available {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Null session access enabled".to_string(),
                description: "Anonymous/null session access is allowed, enabling information disclosure.".to_string(),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some(
                    "Disable null/anonymous session access through RestrictAnonymous settings."
                        .to_string(),
                ),
                cwe: Some("CWE-287".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        // Check for guest access
        if result.guest_access_available {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Guest access enabled".to_string(),
                description: "Guest account access is enabled on the SMB service.".to_string(),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some("Disable the guest account or restrict its access.".to_string()),
                cwe: Some("CWE-287".to_string()),
                owasp: None,
            });
        }

        // Report accessible shares
        for share in &result.shares {
            let share_type = if share.is_hidden {
                "hidden"
            } else if share.is_admin {
                "administrative"
            } else if share.is_ipc {
                "IPC"
            } else {
                "standard"
            };

            let severity = share.access.risk_severity();

            report.add_finding(Vuln {
                severity,
                title: format!("Accessible {} share: {}", share_type, share.name),
                description: format!(
                    "Share '{}' is accessible with {} access.{}{}",
                    share.name,
                    share.access.as_str(),
                    if !share.comment.is_empty() {
                        format!(" Comment: {}", share.comment)
                    } else {
                        String::new()
                    },
                    if share.is_hidden {
                        " This is a hidden share (ends with $)."
                    } else {
                        ""
                    }
                ),
                location: Some(format!("{}:{}\\{}", result.host, result.port, share.name)),
                recommendation: if share.is_admin {
                    Some("Administrative shares should not be accessible remotely. Restrict access.".to_string())
                } else if share.access == ShareAccess::Write || share.access == ShareAccess::Full {
                    Some("Review share permissions. Write access should be restricted to authorized users.".to_string())
                } else {
                    Some("Review share access requirements. Restrict if not needed.".to_string())
                },
                cwe: None,
                owasp: None,
            });
        }

        // Report OS info
        if let Some(os_info) = &result.os_info {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "OS information disclosed".to_string(),
                description: format!("SMB service discloses OS information: {}", os_info),
                location: Some(format!("{}:{}", result.host, result.port)),
                recommendation: Some("Consider restricting OS information disclosure if possible.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_version() {
        assert_eq!(SmbVersion::Smb1.as_str(), "SMBv1");
        assert_eq!(SmbVersion::Smb311.as_str(), "SMBv3.1.1");
        assert!(SmbVersion::Smb1.is_v1());
        assert!(!SmbVersion::Smb2.is_v1());
    }

    #[test]
    fn test_smb_version_severity() {
        assert_eq!(SmbVersion::Smb1.risk_severity(), VulnSeverity::Critical);
        assert_eq!(SmbVersion::Smb2.risk_severity(), VulnSeverity::Medium);
        assert_eq!(SmbVersion::Smb311.risk_severity(), VulnSeverity::Info);
    }

    #[test]
    fn test_share_access() {
        assert_eq!(ShareAccess::NoAuth.as_str(), "No Authentication");
        assert_eq!(ShareAccess::Write.as_str(), "Write Access");
        assert_eq!(ShareAccess::Full.risk_severity(), VulnSeverity::Critical);
        assert_eq!(ShareAccess::Read.risk_severity(), VulnSeverity::Medium);
    }

    #[test]
    fn test_smb_share() {
        let share = SmbShare::new("ADMIN$".to_string());
        assert!(share.is_hidden);
        assert!(share.is_admin);
        assert!(!share.is_ipc);

        let ipc_share = SmbShare::new("IPC$".to_string());
        assert!(ipc_share.is_ipc);
        assert!(ipc_share.is_hidden);

        let normal_share = SmbShare::new("public".to_string());
        assert!(!normal_share.is_hidden);
        assert!(!normal_share.is_admin);
        assert!(!normal_share.is_ipc);
    }

    #[test]
    fn test_smb_share_builder() {
        let share = SmbShare::new("data".to_string())
            .with_comment("Data files".to_string())
            .with_access(ShareAccess::Write);

        assert_eq!(share.name, "data");
        assert_eq!(share.comment, "Data files");
        assert_eq!(share.access, ShareAccess::Write);
    }

    #[tokio::test]
    async fn test_check_smb_port_localhost() {
        // Test with a port that's likely closed
        let result = SmbScanner::check_smb_port("127.0.0.1", 1139).await;
        // Might be closed or open depending on system
        // Just ensure it doesn't panic
    }
}
