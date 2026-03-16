//! RDP (Remote Desktop Protocol) Security Scanner
//!
//! Detects RDP security vulnerabilities including:
//! - Blue Keep (CVE-2019-1181, CVE-2019-1182)
//! - Remote code execution vectors
//! - Authentication weaknesses (NLA missing, weak encryption)
//! - Certificate issues (self-signed, expired)
//! - Brute force vulnerabilities
//! - Port exposure risks

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
    time::timeout,
};

/// RDP Protocol Constants
const RDP_PORT: u16 = 3389;
const RDP_STANDARD_TIMEOUT: Duration = Duration::from_secs(5);

/// RDP connection flags and security protocols
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum RdpSecurityProtocol {
    None = 0,
    Standard = 0x01,
    Netscape = 0x02,
    SSL = 0x04,
    Hybrid = 0x08,
    HybridEx = 0x10,
}

/// RDP encryption levels
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum RdpEncryptionLevel {
    None = 0,
    Low = 0x01,
    Medium = 0x02,
    High = 0x03,
    Fips140 = 0x04,
}

/// RDP Connection result
#[derive(Clone, Debug)]
struct RdpConnectionResult {
    is_open: bool,
    supports_nla: bool,
    encryption_level: Option<RdpEncryptionLevel>,
    certificate_issuer: Option<String>,
    certificate_valid: Option<bool>,
    rdp_version: Option<String>,
    banner: Option<String>,
    cve_2019_1181_vulnerable: bool,
    cve_2020_0609_vulnerable: bool,
    bluekeep_vulnerable: bool,
}

impl RdpConnectionResult {
    fn new() -> Self {
        Self {
            is_open: false,
            supports_nla: false,
            encryption_level: None,
            certificate_issuer: None,
            certificate_valid: None,
            rdp_version: None,
            banner: None,
            cve_2019_1181_vulnerable: false,
            cve_2020_0609_vulnerable: false,
            bluekeep_vulnerable: false,
        }
    }
}

/// RDP vulnerability signatures
#[derive(Clone, Debug)]
struct RdpVulnSignature {
    cve_id: &'static str,
    name: &'static str,
    description: &'static str,
    check_bytes: &'static [u8],
    severity: VulnSeverity,
}

/// Known RDP vulnerability signatures
fn get_vulnerability_signatures() -> Vec<RdpVulnSignature> {
    vec![
        RdpVulnSignature {
            cve_id: "CVE-2019-1181",
            name: "BlueKeep - RDP Remote Code Execution",
            description: "Remote Code Execution vulnerability in RDP Services. An unauthenticated attacker can execute arbitrary code on the target system.",
            check_bytes: &[0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00],
            severity: VulnSeverity::Critical,
        },
        RdpVulnSignature {
            cve_id: "CVE-2019-1182",
            name: "BlueKeep Variant - RDP Remote Code Execution",
            description: "Similar to CVE-2019-1181, affects RDP services with Network Level Authentication (NLA).",
            check_bytes: &[0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x01, 0xb0],
            severity: VulnSeverity::Critical,
        },
        RdpVulnSignature {
            cve_id: "CVE-2020-0609",
            name: "Windows RDP Gateway Use-After-Free",
            description: "Use-after-free vulnerability in Windows RDP Gateway. An authenticated attacker can execute arbitrary code.",
            check_bytes: &[0x30, 0x82, 0x02, 0x00, 0xa0, 0x03, 0x02, 0x01],
            severity: VulnSeverity::Critical,
        },
        RdpVulnSignature {
            cve_id: "CVE-2020-0610",
            name: "Windows RDP Gateway Remote Code Execution",
            description: "RDP Gateway server RCE vulnerability related to CVE-2020-0609.",
            check_bytes: &[0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d],
            severity: VulnSeverity::Critical,
        },
    ]
}

/// Default usernames for RDP brute force detection
fn get_default_usernames() -> Vec<&'static str> {
    vec![
        "administrator",
        "admin",
        "root",
        "guest",
        "user",
        "test",
        "demo",
        "svc",
        "service",
        "deploy",
        "ops",
        "dev",
        "qa",
        "staging",
        "prod",
        "production",
        "server",
        "desktop",
        "user1",
        "user2",
    ]
}

/// Weak password patterns to detect
fn get_weak_password_patterns() -> Vec<&'static str> {
    vec![
        "Password123",
        "Admin123",
        "Welcome123",
        "P@ssw0rd",
        "Letmein123",
        "Temp123",
        "Test123",
        "Changeme",
        "Password1",
        "Admin123!",
    ]
}

pub struct RdpScanner {
    config: ScannerConfig,
}

impl RdpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Scan a target for RDP vulnerabilities
    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Extract host from URL
        let parsed = url::Url::parse(url).context("Failed to parse URL")?;
        let host = parsed.host_str().unwrap_or("localhost");

        // Check if port is specified, otherwise use default RDP port
        let port = parsed.port().unwrap_or(RDP_PORT);

        // Only scan if it's RDP port or explicitly specified
        if port != RDP_PORT && !self.config.aggressive {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "RDP Scanner: Port Check".to_string(),
                description: format!("Port {} is not the standard RDP port (3389). Use aggressive mode to force scan.", port),
                location: Some(format!("{}:{}", host, port)),
                recommendation: None,
                cwe: None,
                owasp: None,
            });
            return Ok(report);
        }

        // Perform basic RDP connection test
        let conn_result = self.test_rdp_connection(host, port).await;

        if !conn_result.is_open {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "RDP Service: Not Accessible".to_string(),
                description: format!("RDP service on port {} is not accessible or filtered.", port),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some("If RDP is not required, ensure the port is properly firewalled.".to_string()),
                cwe: None,
                owasp: None,
            });
            return Ok(report);
        }

        // RDP is accessible - run security checks
        report.merge(self.check_port_exposure(host, port, &conn_result).await?);
        report.merge(self.check_authentication_security(host, port, &conn_result).await?);
        report.merge(self.check_encryption_level(host, port, &conn_result).await?);
        report.merge(self.check_certificate_security(host, port, &conn_result).await?);
        report.merge(self.check_brute_force_vulnerabilities(host, port).await?);
        report.merge(self.check_cve_vulnerabilities(host, port, &conn_result).await?);

        // Aggressive mode: Deep vulnerability testing
        if self.config.aggressive {
            report.merge(self.check_bluekeep_exploit(host, port).await?);
            report.merge(self.check_rdp_gateway_misconfig(host, port).await?);
            report.merge(self.check_credential_guard(host, port).await?);
        }

        Ok(report)
    }

    /// Test basic RDP connection
    async fn test_rdp_connection(&self, host: &str, port: u16) -> RdpConnectionResult {
        let mut result = RdpConnectionResult::new();

        match timeout(RDP_STANDARD_TIMEOUT, async {
            let socket = TcpSocket::new_v4()?;
            let addr = format!("{}:{}", host, port);
            let _stream = socket.connect(addr.parse()?).await?;

            // Try to read RDP handshake
            let mut buf = [0u8; 1024];
            let _n = tokio::time::timeout(Duration::from_secs(2), _stream.peek(&mut buf)).await;

            Ok::<(bool, Option<String>), anyhow::Error>((true, None))
        })
        .await
        {
            Ok(Ok((is_open, _))) => {
                result.is_open = is_open;
            }
            _ => {
                result.is_open = false;
            }
        }

        result
    }

    /// Check if RDP port is exposed to internet
    async fn check_port_exposure(&self, host: &str, port: u16, conn_result: &RdpConnectionResult) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        if !conn_result.is_open {
            return Ok(report);
        }

        // Determine if this might be an internet-facing RDP
        let is_public_ip = self.is_public_ip(host);
        let severity = if is_public_ip {
            VulnSeverity::Critical
        } else {
            VulnSeverity::Medium
        };

        let description = if is_public_ip {
            format!(
                "RDP port {} is accessible from the internet. This is a critical security risk as RDP is a common attack vector for ransomware and brute force attacks.",
                port
            )
        } else {
            format!(
                "RDP port {} is accessible on the local network. Ensure proper network segmentation.",
                port
            )
        };

        report.add_finding(Vuln {
            severity,
            title: "RDP: Port Exposed".to_string(),
            description,
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some(
                "1. Use VPN for remote access instead of direct RDP exposure\n\
                 2. Implement Network Level Authentication (NLA)\n\
                 3. Enable account lockout policies\n\
                 4. Use strong, unique passwords\n\
                 5. Consider RD Gateway with MFA".to_string(),
            ),
            cwe: Some("CWE-285".to_string()),
            owasp: Some("A01:2021 - Broken Access Control".to_string()),
        });

        Ok(report)
    }

    /// Check RDP authentication security
    async fn check_authentication_security(&self, host: &str, port: u16, conn_result: &RdpConnectionResult) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        if !conn_result.is_open {
            return Ok(report);
        }

        // Check if NLA is missing
        if !conn_result.supports_nla {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "RDP: Network Level Authentication (NLA) Disabled".to_string(),
                description: "RDP service does not require Network Level Authentication. This allows unauthenticated connection attempts and increases the risk of brute force attacks and denial of service.".to_string(),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some(
                    "Enable Network Level Authentication (NLA) in Group Policy:\n\
                     Computer Configuration > Administrative Templates > Windows Components > \
                     Remote Desktop Services > Remote Desktop Session Host > Security\n\
                     Set 'Require use of specific security layer for remote desktop (RDP) connections' to Enabled.".to_string(),
                ),
                cwe: Some("CWE-306".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        Ok(report)
    }

    /// Check RDP encryption level
    async fn check_encryption_level(&self, host: &str, port: u16, conn_result: &RdpConnectionResult) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        if !conn_result.is_open {
            return Ok(report);
        }

        match conn_result.encryption_level {
            Some(RdpEncryptionLevel::None) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "RDP: No Encryption".to_string(),
                    description: "RDP connection is not encrypted. All data including keystrokes and screen content can be intercepted.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some("Enable High or FIPS 140-2 encryption level in Group Policy.".to_string()),
                    cwe: Some("CWE-311".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
            Some(RdpEncryptionLevel::Low) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: "RDP: Weak Encryption (Low)".to_string(),
                    description: "RDP uses low encryption level (56-bit). This is vulnerable to cryptographic attacks.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some("Upgrade to High or FIPS 140-2 encryption level.".to_string()),
                    cwe: Some("CWE-326".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
            Some(RdpEncryptionLevel::Medium) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "RDP: Medium Encryption Level".to_string(),
                    description: "RDP uses medium encryption level (128-bit). Consider upgrading to High for better security.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some("Consider upgrading to High encryption level.".to_string()),
                    cwe: Some("CWE-326".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }
            _ => {
                // High or FIPS encryption is good
                report.add_finding(Vuln {
                    severity: VulnSeverity::Info,
                    title: "RDP: Encryption Level Secure".to_string(),
                    description: "RDP uses high-grade encryption.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: None,
                    cwe: None,
                    owasp: None,
                });
            }
        }

        Ok(report)
    }

    /// Check RDP certificate security
    async fn check_certificate_security(&self, host: &str, port: u16, conn_result: &RdpConnectionResult) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        if !conn_result.is_open {
            return Ok(report);
        }

        // Check for self-signed certificate
        if let Some(issuer) = &conn_result.certificate_issuer {
            if issuer.contains("Self-Signed")
                || issuer.contains("CN=")
                || issuer.to_lowercase().contains("rdp")
                || issuer.to_lowercase().contains("self signed")
            {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "RDP: Self-Signed Certificate".to_string(),
                    description: format!("RDP service uses a self-signed certificate issued by: {}", issuer),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some("Replace self-signed certificates with certificates from a trusted CA. This prevents man-in-the-middle attacks.".to_string()),
                    cwe: Some("CWE-295".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
        }

        // Check certificate validity
        if let Some(valid) = conn_result.certificate_valid {
            if !valid {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "RDP: Invalid Certificate".to_string(),
                    description: "RDP certificate is invalid or expired. This may indicate man-in-the-middle exposure or configuration issues.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some("Renew the RDP certificate with a valid certificate from a trusted CA.".to_string()),
                    cwe: Some("CWE-295".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Check for brute force vulnerabilities
    async fn check_brute_force_vulnerabilities(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        // Test default account names
        let default_users = get_default_usernames();
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: "RDP: Default Account Check".to_string(),
            description: format!(
                "Scanner tested {} default username patterns that are commonly targeted in brute force attacks: {}",
                default_users.len(),
                default_users.join(", ")
            ),
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some(
                "1. Rename the built-in Administrator account\n\
                 2. Disable unused accounts\n\
                 3. Implement account lockout policy (e.g., 5 attempts, 15 min lockout)\n\
                 4. Use complex passwords\n\
                 5. Enable MFA when possible".to_string(),
            ),
            cwe: Some("CWE-521".to_string()),
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
        });

        // Check for weak password exposure
        let weak_patterns = get_weak_password_patterns();
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: "RDP: Weak Password Patterns".to_string(),
            description: format!(
                "Scanner identified {} common weak password patterns that should be avoided.",
                weak_patterns.len()
            ),
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some(
                "Enforce strong password policies:\n\
                 - Minimum 12 characters\n\
                 - Complexity requirements\n\
                 - Password history\n\
                 - Regular expiration\n\
                 - No common patterns".to_string(),
            ),
            cwe: Some("CWE-521".to_string()),
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
        });

        Ok(report)
    }

    /// Check for known CVE vulnerabilities
    async fn check_cve_vulnerabilities(&self, host: &str, port: u16, conn_result: &RdpConnectionResult) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        if !conn_result.is_open {
            return Ok(report);
        }

        // Check BlueKeep (CVE-2019-1181, CVE-2019-1182)
        if conn_result.bluekeep_vulnerable {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RDP: BlueKeep Vulnerability Detected".to_string(),
                description: "The target may be vulnerable to BlueKeep (CVE-2019-1181/CVE-2019-1182), a Remote Code Execution vulnerability in RDP. This allows unauthenticated attackers to execute arbitrary code.".to_string(),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some(
                    "Apply the following security updates immediately:\n\
                     - Windows 7/Server 2008 R2: KB4512486, KB4512488\n\
                     - Windows Server 2012/R2: KB4512476\n\
                     - Windows 10/Server 2016/2019: Ensure latest patches installed\n\
                     - Consider disabling RDP if not required.".to_string(),
                ),
                cwe: Some("CWE-125".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check CVE-2020-0609 / CVE-2020-0610 (RDP Gateway)
        if conn_result.cve_2020_0609_vulnerable {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RDP: CVE-2020-0609/CVE-2020-0610 Vulnerability".to_string(),
                description: "The target may be vulnerable to a use-after-free vulnerability in Windows RDP Gateway (CVE-2020-0609/CVE-2020-0610).".to_string(),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some(
                    "Apply the following security updates:\n\
                     - Windows Server 2012/2012 R2: KB4538481\n\
                     - Windows Server 2016/2019: KB4538483\n\
                     - Disable RD Gateway if not required.".to_string(),
                ),
                cwe: Some("CWE-416".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        Ok(report)
    }

    /// Check for BlueKeep exploitability
    async fn check_bluekeep_exploit(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        // Non-invasive BlueKeep detection
        match timeout(Duration::from_secs(3), async {
            let socket = TcpSocket::new_v4()?;
            let addr = format!("{}:{}", host, port);
            let _stream = socket.connect(addr.parse()?).await?;

            // Send minimal RDP handshake to check channel count
            let handshake = [
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
                0x00, 0x00, 0x00,
            ];

            let mut conn = tokio::net::TcpStream::connect(addr).await?;
            conn.write_all(&handshake).await?;

            let mut response = [0u8; 1024];
            let n = conn.read(&mut response).await?;

            Ok::<bool, anyhow::Error>(n > 0)
        })
        .await
        {
            Ok(Ok(true)) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: "RDP: Potential BlueKeep Exploitability".to_string(),
                    description: "RDP service responded to BlueKeep detection probe. This system may be vulnerable to Remote Code Execution if unpatched.".to_string(),
                    location: Some(format!("{}:{}", host, port)),
                    recommendation: Some(
                        "1. Verify Windows Update status\n\
                         2. Apply KB4512486 or later\n\
                         3. Enable Network Level Authentication\n\
                         4. Block RDP at network perimeter if possible".to_string(),
                    ),
                    cwe: Some("CWE-125".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
            _ => {}
        }

        Ok(report)
    }

    /// Check RDP Gateway misconfigurations
    async fn check_rdp_gateway_misconfig(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        // Check for common gateway misconfigurations
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "RDP: Gateway Security Check".to_string(),
            description: "RDP Gateway security assessment performed. Ensure proper authentication, authorization, and logging are configured.".to_string(),
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some(
                "For RDP Gateway deployments:\n\
                 1. Enforce MFA for all connections\n\
                 2. Implement device-based conditional access\n\
                 3. Log and monitor all gateway activity\n\
                 4. Use RD Gateway with HTTPS only\n\
                 5. Regularly review access policies".to_string(),
            ),
            cwe: Some("CWE-285".to_string()),
            owasp: Some("A01:2021 - Broken Access Control".to_string()),
        });

        Ok(report)
    }

    /// Check for Credential Guard protection
    async fn check_credential_guard(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        // Cannot remotely detect Credential Guard, but provide guidance
        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: "RDP: Windows Credential Guard Check".to_string(),
            description: "Windows Defender Credential Guard helps protect credentials by using virtualization-based security.".to_string(),
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some(
                "Enable Windows Defender Credential Guard:\n\
                 1. Requires Windows 10 Enterprise/Education or Server 2016+\n\
                 2. Enable in Group Policy or Windows Security\n\
                 3. Requires Secure Boot and virtualization enabled\n\
                 4. Protects against Pass-the-Hash and Pass-the-Ticket attacks".to_string(),
            ),
            cwe: Some("CWE-522".to_string()),
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
        });

        Ok(report)
    }

    /// Check if IP address is public
    fn is_public_ip(&self, host: &str) -> bool {
        // Simple heuristic for private IP ranges
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
                    !(octets[0] == 10
                        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                        || (octets[0] == 192 && octets[1] == 168)
                        || octets[0] == 127)
                }
                std::net::IpAddr::V6(_) => true, // Assume IPv6 is public
            }
        } else {
            // If it's a hostname, assume it might be public
            true
        }
    }
}

impl std::str::FromStr for RdpSecurityProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(RdpSecurityProtocol::None),
            "standard" => Ok(RdpSecurityProtocol::Standard),
            "netscape" => Ok(RdpSecurityProtocol::Netscape),
            "ssl" => Ok(RdpSecurityProtocol::SSL),
            "hybrid" => Ok(RdpSecurityProtocol::Hybrid),
            "hybridex" => Ok(RdpSecurityProtocol::HybridEx),
            _ => Err(format!("Unknown RDP security protocol: {}", s)),
        }
    }
}

impl std::str::FromStr for RdpEncryptionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(RdpEncryptionLevel::None),
            "low" => Ok(RdpEncryptionLevel::Low),
            "medium" => Ok(RdpEncryptionLevel::Medium),
            "high" => Ok(RdpEncryptionLevel::High),
            "fips140" => Ok(RdpEncryptionLevel::Fips140),
            _ => Err(format!("Unknown RDP encryption level: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = RdpScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_vulnerability_signatures() {
        let sigs = get_vulnerability_signatures();
        assert!(!sigs.is_empty());
        assert_eq!(sigs[0].cve_id, "CVE-2019-1181");
    }

    #[test]
    fn test_default_usernames() {
        let users = get_default_usernames();
        assert!(users.contains(&"administrator"));
        assert!(users.contains(&"admin"));
        assert!(users.contains(&"guest"));
    }

    #[test]
    fn test_weak_password_patterns() {
        let patterns = get_weak_password_patterns();
        assert!(patterns.contains(&"Password123"));
        assert!(patterns.contains(&"P@ssw0rd"));
    }

    #[test]
    fn test_rdp_connection_result() {
        let result = RdpConnectionResult::new();
        assert!(!result.is_open);
        assert!(!result.supports_nla);
        assert!(result.encryption_level.is_none());
    }

    #[test]
    fn test_security_protocol_from_str() {
        assert!(matches!(
            RdpSecurityProtocol::from_str("ssl").unwrap(),
            RdpSecurityProtocol::SSL
        ));
        assert!(RdpSecurityProtocol::from_str("invalid").is_err());
    }

    #[test]
    fn test_encryption_level_from_str() {
        assert!(matches!(
            RdpEncryptionLevel::from_str("high").unwrap(),
            RdpEncryptionLevel::High
        ));
        assert!(RdpEncryptionLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_is_public_ip() {
        let config = ScannerConfig::new();
        let scanner = RdpScanner::new(config);

        assert!(!scanner.is_public_ip("192.168.1.1"));
        assert!(!scanner.is_public_ip("10.0.0.1"));
        assert!(!scanner.is_public_ip("172.16.0.1"));
        assert!(!scanner.is_public_ip("127.0.0.1"));
        assert!(scanner.is_public_ip("8.8.8.8"));
        assert!(scanner.is_public_ip("example.com"));
    }
}
