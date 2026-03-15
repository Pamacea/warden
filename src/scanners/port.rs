//! Enhanced port scanner with service detection and advanced scanning

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
    time::timeout,
};

/// Port category classification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortCategory {
    WellKnown,   // 0-1023
    Registered,  // 1024-49151
    Dynamic,     // 49152-65535
}

impl PortCategory {
    pub fn from_port(port: u16) -> Self {
        match port {
            1..=1023 => PortCategory::WellKnown,
            1024..=49151 => PortCategory::Registered,
            _ => PortCategory::Dynamic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PortCategory::WellKnown => "well-known",
            PortCategory::Registered => "registered",
            PortCategory::Dynamic => "dynamic",
        }
    }
}

/// Service type classification for risk assessment
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceType {
    WebServer,
    Database,
    RemoteAccess,
    FileTransfer,
    Mail,
    Directory,
    Vpn,
    Container,
    Cache,
    MessageQueue,
    Monitoring,
    Dns,
    Other,
}

impl ServiceType {
    /// Get risk level for this service type
    pub fn risk_severity(&self) -> VulnSeverity {
        match self {
            ServiceType::Database => VulnSeverity::Medium,
            ServiceType::RemoteAccess => VulnSeverity::High,
            ServiceType::FileTransfer => VulnSeverity::Medium,
            ServiceType::Vpn => VulnSeverity::Medium,
            ServiceType::Container => VulnSeverity::High,
            ServiceType::Cache => VulnSeverity::Medium,
            ServiceType::WebServer => VulnSeverity::Low,
            ServiceType::Mail => VulnSeverity::Low,
            ServiceType::Directory => VulnSeverity::Medium,
            ServiceType::MessageQueue => VulnSeverity::Low,
            ServiceType::Monitoring => VulnSeverity::Low,
            ServiceType::Dns => VulnSeverity::Low,
            ServiceType::Other => VulnSeverity::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceType::WebServer => "Web Server",
            ServiceType::Database => "Database",
            ServiceType::RemoteAccess => "Remote Access",
            ServiceType::FileTransfer => "File Transfer",
            ServiceType::Mail => "Mail Server",
            ServiceType::Directory => "Directory Service",
            ServiceType::Vpn => "VPN",
            ServiceType::Container => "Container",
            ServiceType::Cache => "Cache",
            ServiceType::MessageQueue => "Message Queue",
            ServiceType::Monitoring => "Monitoring",
            ServiceType::Dns => "DNS",
            ServiceType::Other => "Other",
        }
    }
}

/// Service fingerprint with version detection
#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub service_type: ServiceType,
    pub banner: Option<String>,
}

impl ServiceInfo {
    pub fn new(port: u16, service: String, service_type: ServiceType) -> Self {
        Self {
            port,
            service,
            version: None,
            service_type,
            banner: None,
        }
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self
    }
}

/// Known service definitions with default probes
fn get_service_database() -> HashMap<u16, (&'static str, ServiceType, Vec<&'static str>)> {
    HashMap::from([
        // Web servers
        (80, ("HTTP", ServiceType::WebServer, vec!["HEAD / HTTP/1.0\r\n\r\n"])),
        (443, ("HTTPS", ServiceType::WebServer, vec![])),
        (8080, ("HTTP-Alt", ServiceType::WebServer, vec!["HEAD / HTTP/1.0\r\n\r\n"])),
        (8443, ("HTTPS-Alt", ServiceType::WebServer, vec![])),
        (8000, ("HTTP-Dev", ServiceType::WebServer, vec!["HEAD / HTTP/1.0\r\n\r\n"])),
        (8888, ("HTTP-Alt", ServiceType::WebServer, vec!["HEAD / HTTP/1.0\r\n\r\n"])),

        // Remote access
        (22, ("SSH", ServiceType::RemoteAccess, vec![])),
        (23, ("Telnet", ServiceType::RemoteAccess, vec![])),
        (3389, ("RDP", ServiceType::RemoteAccess, vec![])),
        (5900, ("VNC", ServiceType::RemoteAccess, vec![])),
        (5901, ("VNC", ServiceType::RemoteAccess, vec![])),

        // File transfer
        (21, ("FTP", ServiceType::FileTransfer, vec![])),
        (69, ("TFTP", ServiceType::FileTransfer, vec![])),
        (139, ("NetBIOS", ServiceType::FileTransfer, vec![])),
        (445, ("SMB", ServiceType::FileTransfer, vec![])),

        // Mail
        (25, ("SMTP", ServiceType::Mail, vec![])),
        (110, ("POP3", ServiceType::Mail, vec![])),
        (143, ("IMAP", ServiceType::Mail, vec![])),
        (993, ("IMAPS", ServiceType::Mail, vec![])),
        (995, ("POP3S", ServiceType::Mail, vec![])),
        (587, ("SMTP", ServiceType::Mail, vec![])),

        // Database
        (3306, ("MySQL", ServiceType::Database, vec![])),
        (5432, ("PostgreSQL", ServiceType::Database, vec![])),
        (1433, ("MSSQL", ServiceType::Database, vec![])),
        (1521, ("Oracle", ServiceType::Database, vec![])),
        (27017, ("MongoDB", ServiceType::Database, vec![])),
        (6379, ("Redis", ServiceType::Database, vec![])),
        (5672, ("RabbitMQ", ServiceType::MessageQueue, vec![])),
        (9042, ("Cassandra", ServiceType::Database, vec![])),
        (9300, ("Elasticsearch", ServiceType::Database, vec![])),

        // Directory services
        (389, ("LDAP", ServiceType::Directory, vec![])),
        (636, ("LDAPS", ServiceType::Directory, vec![])),

        // VPN
        (1194, ("OpenVPN", ServiceType::Vpn, vec![])),
        (500, ("IKE", ServiceType::Vpn, vec![])),
        (4500, ("IPsec-NAT", ServiceType::Vpn, vec![])),

        // Container
        (2375, ("Docker", ServiceType::Container, vec![])),
        (2376, ("Docker-SSL", ServiceType::Container, vec![])),

        // Cache
        (11211, ("Memcached", ServiceType::Cache, vec![])),

        // Monitoring
        (161, ("SNMP", ServiceType::Monitoring, vec![])),

        // DNS
        (53, ("DNS", ServiceType::Dns, vec![])),

        // Other common services
        (111, ("RPC", ServiceType::Other, vec![])),
        (135, ("MSRPC", ServiceType::Other, vec![])),
        (512, ("Exec", ServiceType::Other, vec![])),
        (513, ("Login", ServiceType::Other, vec![])),
        (514, ("Syslog", ServiceType::Other, vec![])),
        (873, ("RSYNC", ServiceType::Other, vec![])),
        (1025, ("NFS", ServiceType::Other, vec![])),
        (2049, ("NFS", ServiceType::Other, vec![])),
        (3300, ("MongoDB", ServiceType::Other, vec![])),
        (5000, ("UPnP", ServiceType::Other, vec![])),
        (5001, ("upnp", ServiceType::Other, vec![])),
        (5432, ("PostgreSQL", ServiceType::Other, vec![])),
        (6000, ("X11", ServiceType::Other, vec![])),
        (7001, ("Weblogic", ServiceType::WebServer, vec![])),
        (7002, ("Weblogic", ServiceType::WebServer, vec![])),
        (8008, ("HTTP", ServiceType::WebServer, vec![])),
        (8009, ("AJP", ServiceType::WebServer, vec![])),
        (8081, ("HTTP", ServiceType::WebServer, vec![])),
        (8686, ("HTTP", ServiceType::WebServer, vec![])),
        (9000, ("SonarQube", ServiceType::WebServer, vec![])),
        (9001, ("Http", ServiceType::WebServer, vec![])),
        (9090, ("HTTP", ServiceType::WebServer, vec![])),
        (9200, ("Elasticsearch", ServiceType::Database, vec![])),
        (9300, ("Elasticsearch", ServiceType::Database, vec![])),
        (10000, ("Webmin", ServiceType::WebServer, vec![])),
        (27018, ("MongoDB", ServiceType::Database, vec![])),
        (28017, ("MongoDB", ServiceType::Database, vec![])),
    ])
}

/// Port scanning options
#[derive(Clone, Debug)]
pub struct PortScanOptions {
    pub timeout: Duration,
    pub concurrency: usize,
    pub scan_well_known: bool,
    pub scan_registered: bool,
    pub scan_dynamic: bool,
    pub custom_ports: Vec<u16>,
    pub detect_versions: bool,
    pub grab_banners: bool,
}

impl Default for PortScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(500),
            concurrency: 100,
            scan_well_known: true,
            scan_registered: false,
            scan_dynamic: false,
            custom_ports: Vec::new(),
            detect_versions: true,
            grab_banners: true,
        }
    }
}

impl PortScanOptions {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_custom_ports(mut self, ports: Vec<u16>) -> Self {
        self.custom_ports = ports;
        self
    }

    pub fn with_version_detection(mut self, enable: bool) -> Self {
        self.detect_versions = enable;
        self
    }

    pub fn with_banner_grabbing(mut self, enable: bool) -> Self {
        self.grab_banners = enable;
        self
    }

    pub fn scan_all_ports(mut self) -> Self {
        self.scan_well_known = true;
        self.scan_registered = true;
        self.scan_dynamic = true;
        self
    }

    /// Get the list of ports to scan based on options
    pub fn get_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();

        if !self.custom_ports.is_empty() {
            ports.extend(self.custom_ports.clone());
            ports.sort();
            ports.dedup();
            return ports;
        }

        if self.scan_well_known {
            ports.extend(1..=1024);
        }
        if self.scan_registered {
            ports.extend(1025..=49151);
        }
        if self.scan_dynamic {
            ports.extend(49152..=65535);
        }

        // If no category selected, use common ports
        if ports.is_empty() {
            ports = vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 512, 513,
                514, 587, 636, 873, 993, 995, 1025, 1194, 1433, 1521, 2049, 2375, 2376, 3306,
                3389, 5432, 5672, 5900, 5901, 6379, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
                9000, 9042, 9090, 9200, 9300, 10000, 11211, 27017, 27018, 28017,
            ];
        }

        ports.sort();
        ports.dedup();
        ports
    }
}

/// Port scanning result
#[derive(Clone, Debug)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub category: PortCategory,
    pub service_info: Option<ServiceInfo>,
    pub response_time_ms: Option<u64>,
}

pub struct PortScanner {
    config: ScannerConfig,
    options: PortScanOptions,
}

impl PortScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let options = PortScanOptions {
            timeout: config.timeout,
            concurrency: config.concurrency,
            ..Default::default()
        };
        Self { config, options }
    }

    pub fn with_options(mut self, options: PortScanOptions) -> Self {
        self.options = options;
        self
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Extract host from URL
        let parsed = url::Url::parse(url).context("Failed to parse URL")?;
        let host = parsed.host_str().unwrap_or("localhost");

        // Get ports to scan
        let ports = self.options.get_ports();

        // Scan ports concurrently
        let results = self.scan_ports_concurrent(host, &ports).await?;

        // Process results
        for result in results {
            if result.is_open {
                self.add_port_finding(&mut report, host, &result);
            }
        }

        Ok(report)
    }

    /// Scan ports concurrently with semaphore control
    async fn scan_ports_concurrent(&self, host: &str, ports: &[u16]) -> Result<Vec<PortScanResult>> {
        use tokio::sync::Semaphore;
        use std::sync::Arc;

        let semaphore = Arc::new(Semaphore::new(self.options.concurrency));
        let mut tasks = Vec::new();

        for &port in ports {
            let semaphore = semaphore.clone();
            let host = host.to_string();
            let timeout = self.options.timeout;
            let detect_versions = self.options.detect_versions;
            let grab_banners = self.options.grab_banners;

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let start = std::time::Instant::now();
                let (is_open, service_info) = Self::check_and_identify_port(
                    &host,
                    port,
                    timeout,
                    detect_versions,
                    grab_banners,
                )
                .await;
                let response_time = if is_open {
                    Some(start.elapsed().as_millis() as u64)
                } else {
                    None
                };

                PortScanResult {
                    port,
                    is_open,
                    category: PortCategory::from_port(port),
                    service_info,
                    response_time_ms: response_time,
                }
            });

            tasks.push(task);
        }

        // Collect results
        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }

        // Sort by port number
        results.sort_by_key(|r| r.port);

        Ok(results)
    }

    /// Check if a port is open and optionally identify the service
    async fn check_and_identify_port(
        host: &str,
        port: u16,
        timeout_duration: Duration,
        detect_versions: bool,
        grab_banners: bool,
    ) -> (bool, Option<ServiceInfo>) {
        // First, check if port is open
        let is_open = Self::check_port(host, port, timeout_duration).await;
        if !is_open {
            return (false, None);
        }

        // Get basic service info
        let service_db = get_service_database();
        let service_info = if let Some((name, service_type, probes)) = service_db.get(&port) {
            let mut info = ServiceInfo::new(port, name.to_string(), *service_type);

            // Perform service detection
            if detect_versions || grab_banners {
                if let Some(detected) = Self::detect_service(host, port, probes, grab_banners, timeout_duration).await {
                    if let Some(version) = detected.version {
                        info = info.with_version(version);
                    }
                    if let Some(banner) = detected.banner {
                        info = info.with_banner(banner);
                    }
                    // Update service name if detected differently
                    if !detected.service.is_empty() && detected.service != *name {
                        info.service = detected.service;
                    }
                }
            }

            Some(info)
        } else {
            // Unknown service
            Some(ServiceInfo::new(port, "unknown".to_string(), ServiceType::Other))
        };

        (true, service_info)
    }

    /// Check if a specific port is open
    async fn check_port(host: &str, port: u16, timeout_duration: Duration) -> bool {
        match timeout(timeout_duration, async {
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

    /// Attempt to detect service version and grab banner
    async fn detect_service(
        host: &str,
        port: u16,
        probes: &[&str],
        grab_banner: bool,
        timeout_duration: Duration,
    ) -> Option<ServiceInfo> {
        match timeout(timeout_duration, async {
            // Try connecting with TcpStream for more control
            use tokio::net::TcpStream;

            let addr = format!("{}:{}", host, port);
            let mut stream = TcpStream::connect(&addr).await.map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?;

            // Try probes first if available
            for probe in probes {
                if !probe.is_empty() {
                    let _ = stream.write_all(probe.as_bytes()).await;
                }
            }

            // Read banner
            if grab_banner {
                let mut buffer = vec![0u8; 1024];
                match stream.read(&mut buffer).await {
                    Ok(n) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                        let version = Self::extract_version(&banner);
                        return Ok(Some((banner, version)));
                    }
                    _ => {}
                }
            }

            Ok::<Option<(String, Option<String>)>, anyhow::Error>(None)
        })
        .await
        {
            Ok(Ok(Some((banner, version)))) => {
                Some(ServiceInfo::new(port, String::new(), ServiceType::Other)
                    .with_banner(banner)
                    .with_version(version.unwrap_or_default()))
            },
            _ => None,
        }
    }

    /// Extract version information from banner
    fn extract_version(banner: &str) -> Option<String> {
        // Common version patterns
        let patterns = [
            r"Server:\s*([^\r\n]+)",
            r"SSH[-_]([\d.]+)",
            r"vsftpd\s+([\d.]+)",
            r"OpenSSH[_\-]([\d.]+p\d+)",
            r"nginx[/\s]([\d.]+)",
            r"Apache[/\s]([\d.]+)",
            r"MySQL[-\s]([\d.]+)",
            r"PostgreSQL\s+([\d.]+)",
            r"Redis\s+([\d.]+)",
            r"MongoDB\s+([\d.]+)",
            r"Elasticsearch/([\d.]+)",
            r"FTP server \(Version ([\d.]+)\)",
            r"220.*Version ([\d.]+)",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(caps) = re.captures(banner) {
                    if let Some(version) = caps.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    /// Add a finding for an open port
    fn add_port_finding(&self, report: &mut ScanReport, host: &str, result: &PortScanResult) {
        let service_info = result.service_info.as_ref();

        // Determine severity based on service type and port
        let severity = if let Some(info) = service_info {
            // Override with higher severity for certain sensitive ports
            match result.port {
                23 | 135 | 139 | 445 | 3389 => VulnSeverity::High,
                21 | 25 | 110 | 143 | 161 | 389 | 512 | 513 | 514 => VulnSeverity::Medium,
                _ => info.service_type.risk_severity(),
            }
        } else {
            VulnSeverity::Info
        };

        let service_name = service_info
            .map(|s| s.service.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let title = format!("Open port: {} ({})", result.port, service_name);

        let mut description = format!(
            "Port {} is open and accessible. Category: {}",
            result.port,
            result.category.as_str()
        );

        if let Some(info) = service_info {
            description.push_str(&format!(". Service Type: {}", info.service_type.as_str()));

            if let Some(version) = &info.version {
                description.push_str(&format!(". Version: {}", version));
            }

            if let Some(banner) = &info.banner {
                let banner_preview = if banner.len() > 100 {
                    format!("{}...", &banner[..100])
                } else {
                    banner.clone()
                };
                description.push_str(&format!("\nBanner: {}", banner_preview));
            }
        }

        if let Some(response_time) = result.response_time_ms {
            description.push_str(&format!("\nResponse time: {}ms", response_time));
        }

        let recommendation = match service_info.as_ref().map(|s| s.service_type) {
            Some(ServiceType::Database) => Some(
                "Database port exposed. Ensure proper authentication, network isolation, and encryption are enabled."
                    .to_string(),
            ),
            Some(ServiceType::RemoteAccess) => Some(
                "Remote access service exposed. Consider VPN, key-based authentication, and rate limiting."
                    .to_string(),
            ),
            Some(ServiceType::FileTransfer) => Some(
                "File transfer service exposed. Use SFTP/FTPS and enforce strong authentication."
                    .to_string(),
            ),
            Some(ServiceType::WebServer) => Some(
                "Web server exposed. Ensure TLS is configured and headers are hardened."
                    .to_string(),
            ),
            Some(ServiceType::Container) => Some(
                "Container service exposed! This is critical - restrict access immediately."
                    .to_string(),
            ),
            _ => Some(
                "Ensure only necessary ports are exposed and implement proper firewall rules."
                    .to_string(),
            ),
        };

        report.add_finding(Vuln {
            severity,
            title,
            description,
            location: Some(format!("{}:{}", host, result.port)),
            recommendation,
            cwe: None,
            owasp: None,
        });
    }
}

/// UDP scanner for common UDP services
pub struct UdpScanner {
    config: ScannerConfig,
    options: PortScanOptions,
}

impl UdpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let options = PortScanOptions {
            timeout: Duration::from_secs(2), // UDP needs more timeout
            concurrency: 50,
            ..Default::default()
        };
        Self { config, options }
    }

    /// Scan common UDP ports
    pub async fn scan(&self, host: &str) -> Result<Vec<(u16, bool, String)>> {
        let udp_ports = vec![
            (53, "DNS"),
            (67, "DHCP"),
            (68, "DHCP"),
            (123, "NTP"),
            (161, "SNMP"),
            (162, "SNMP-Trap"),
            (500, "IKE"),
            (514, "Syslog"),
            (520, "RIP"),
            (1434, "MSSQL-Monitor"),
            (1701, "L2TP"),
            (4500, "IPsec-NAT-T"),
        ];

        let mut results = Vec::new();

        for (port, service) in udp_ports {
            let is_open = self.check_udp_port(host, port).await;
            results.push((port, is_open, service.to_string()));
        }

        Ok(results)
    }

    /// Check if a UDP port is listening
    async fn check_udp_port(&self, host: &str, port: u16) -> bool {
        use tokio::net::UdpSocket;

        match timeout(self.options.timeout, async {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let addr = format!("{}:{}", host, port);

            // Send probe
            let probe = b"\x00"; // Minimal probe
            let _ = socket.send_to(probe, &addr).await;

            // Try to receive with timeout
            let mut buffer = vec![0u8; 1024];
            match timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await {
                Ok(Ok(_)) => Ok::<bool, anyhow::Error>(true),  // Got response
                _ => Ok(false),          // No response (could be open or filtered)
            }
        })
        .await
        {
            Ok(Ok(true)) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_category() {
        assert_eq!(PortCategory::from_port(80), PortCategory::WellKnown);
        assert_eq!(PortCategory::from_port(3306), PortCategory::Registered);
        assert_eq!(PortCategory::from_port(50000), PortCategory::Dynamic);
    }

    #[test]
    fn test_service_type_risk() {
        assert_eq!(ServiceType::Database.risk_severity(), VulnSeverity::Medium);
        assert_eq!(ServiceType::RemoteAccess.risk_severity(), VulnSeverity::High);
        assert_eq!(ServiceType::WebServer.risk_severity(), VulnSeverity::Low);
    }

    #[test]
    fn test_scan_options_default() {
        let options = PortScanOptions::default();
        let ports = options.get_ports();
        assert!(!ports.is_empty());
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn test_scan_options_custom() {
        let options = PortScanOptions::default()
            .with_custom_ports(vec![8080, 9000, 9000]);
        let ports = options.get_ports();
        assert_eq!(ports, vec![8080, 9000]);
    }

    #[test]
    fn test_extract_version() {
        // SSH version
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        let version = PortScanner::extract_version(banner);
        assert!(version.is_some());

        // HTTP version
        let banner = "Server: nginx/1.18.0 (Ubuntu)";
        let version = PortScanner::extract_version(banner);
        assert!(version.is_some());

        // No version
        let banner = "Welcome to FTP server";
        let version = PortScanner::extract_version(banner);
        assert!(version.is_none());
    }

    #[tokio::test]
    async fn test_check_port_localhost() {
        // Test with localhost (should have some ports closed)
        let result = PortScanner::check_port("127.0.0.1", 65000, Duration::from_millis(100)).await;
        assert!(!result); // Should be closed
    }

    #[test]
    fn test_service_info_builder() {
        let info = ServiceInfo::new(80, "HTTP".to_string(), ServiceType::WebServer)
            .with_version("1.0".to_string())
            .with_banner("Server: test".to_string());

        assert_eq!(info.port, 80);
        assert_eq!(info.service, "HTTP");
        assert_eq!(info.version, Some("1.0".to_string()));
        assert_eq!(info.banner, Some("Server: test".to_string()));
    }
}
