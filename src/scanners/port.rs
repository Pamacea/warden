//! Port scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::time::timeout;

pub struct PortScanner {
    config: ScannerConfig,
}

impl PortScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Extract host from URL
        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or("localhost");

        // Common ports to scan
        let common_ports = vec![
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900,
            6379, 8080, 8443, 8888, 9000, 27017,
        ];

        let open_ports = self.scan_ports(host, &common_ports).await?;

        for port in open_ports {
            let severity = match port {
                23 | 135 | 139 | 445 | 3306 | 3389 | 5432 | 6379 | 27017 => VulnSeverity::Medium,
                21 | 25 | 110 | 143 | 161 => VulnSeverity::Low,
                _ => VulnSeverity::Info,
            };

            report.add_finding(Vuln {
                severity,
                title: format!("Open port: {}", port),
                description: format!("Port {} is open and accessible", port),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some("Ensure only necessary ports are exposed".to_string()),
                cwe: None,
                owasp: None,
            });
        }

        Ok(report)
    }

    async fn scan_ports(&self, host: &str, ports: &[u16]) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();

        for &port in ports {
            if self.check_port(host, port).await {
                open_ports.push(port);
            }
        }

        Ok(open_ports)
    }

    async fn check_port(&self, host: &str, port: u16) -> bool {
        let timeout_duration = Duration::from_secs(1);

        match timeout(timeout_duration, async {
            let socket = TcpSocket::new_v4()?;
            let addr = format!("{}:{}", host, port);
            socket.connect(addr.parse()?).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }
}
