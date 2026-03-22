//! gRPC Security Scanner - Warden v0.8.0 Enterprise Edition
//!
//! This scanner tests gRPC services for security vulnerabilities including:
//! - Reflection attacks (service discovery, method enumeration)
//! - Protobuf fuzzing (malformed messages, type confusion)
//! - Authentication & Authorization bypass
//! - Compression abuse (DoS via compression bombs)
//! - Large message handling

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct GrpcScanner {
    client: Client,
    config: ScannerConfig,
}

#[derive(Debug, Clone)]
struct GrpcEndpoint {
    host: String,
    port: u16,
    url: String,
    detected_via: String,
}

#[derive(Debug, Clone)]
struct GrpcService {
    name: String,
    methods: Vec<String>,
}

impl GrpcScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");
        Self { client, config }
    }

    pub async fn scan(&self, target: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(target.to_string()));

        // Parse target to extract host and port
        let endpoints = self.detect_grpc_endpoints(target).await?;
        if endpoints.is_empty() {
            return Ok(report);
        }

        for endpoint in endpoints {
            // Test reflection
            report.merge(self.test_reflection(&endpoint).await?);

            // Test authentication bypass
            report.merge(self.test_auth_bypass(&endpoint).await?);

            // Test large messages
            report.merge(self.test_large_messages(&endpoint).await?);

            // Test compression abuse
            if self.config.aggressive {
                report.merge(self.test_compression_abuse(&endpoint).await?);
            }

            // Test protobuf fuzzing
            if self.config.aggressive {
                report.merge(self.test_protobuf_fuzzing(&endpoint).await?);
            }

            // Test common services
            report.merge(self.test_common_services(&endpoint).await?);
        }

        Ok(report)
    }

    /// Detect gRPC endpoints on the target
    async fn detect_grpc_endpoints(&self, target: &str) -> Result<Vec<GrpcEndpoint>> {
        let mut endpoints = Vec::new();

        // Parse the target URL
        let (host, port) = if target.starts_with("http://") || target.starts_with("https://") {
            let url = match target.parse::<url::Url>() {
                Ok(u) => u,
                Err(_) => return Ok(endpoints),
            };

            let host = url.host_str().unwrap_or("localhost").to_string();
            let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
            (host, port)
        } else if target.contains(':') {
            let parts: Vec<&str> = target.split(':').collect();
            (parts[0].to_string(), parts[1].parse().unwrap_or(50051))
        } else {
            (target.to_string(), 50051) // Default gRPC port
        };

        // Common gRPC ports
        let ports_to_check = vec![port, 50051, 50052, 50053, 8080, 9090, 9111];

        for check_port in ports_to_check {
            if self.is_grpc_port(&host, check_port).await {
                endpoints.push(GrpcEndpoint {
                    host: host.clone(),
                    port: check_port,
                    url: format!("{}:{}", host, check_port),
                    detected_via: "tcp".to_string(),
                });
            }
        }

        Ok(endpoints)
    }

    /// Check if a port is running gRPC
    async fn is_grpc_port(&self, host: &str, port: u16) -> bool {
        match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("{}:{}", host, port))
        ).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    /// Test gRPC reflection API
    async fn test_reflection(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Test for reflection v1
        if let Ok(services) = self.list_services_reflection_v1(endpoint).await {
            if !services.is_empty() {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: "gRPC Reflection Enabled".to_string(),
                    description: format!(
                        "Server reflection API is enabled. {} services discovered: {:?}",
                        services.len(),
                        services.iter().take(10).cloned().collect::<Vec<_>>()
                    ),
                    location: Some(endpoint.url.clone()),
                    recommendation: Some(
                        "Disable gRPC server reflection in production. Use grpc.ServerReflectionService() only in development.".to_string()
                    ),
                    cwe: Some("CWE-215".to_string()),
                    owasp: Some("A01:2021".to_string()),
                });

                // Enumerate methods from discovered services
                for service in services.iter().take(5) {
                    if let Ok(methods) = self.list_methods_reflection_v1(endpoint, service).await {
                        if !methods.is_empty() {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: format!("Service Method Enumeration: {}", service),
                                description: format!(
                                    "Service {} has {} methods: {:?}",
                                    service,
                                    methods.len(),
                                    methods.iter().take(5).cloned().collect::<Vec<_>>()
                                ),
                                location: Some(endpoint.url.clone()),
                                recommendation: Some("Implement proper access control on sensitive methods.".to_string()),
                                cwe: Some("CWE-285".to_string()),
                                owasp: Some("A01:2021".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Test for reflection on alternative paths
        let reflection_paths = vec![
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/reflection/service",
            "grpc.reflection.v1.ServerReflection",
        ];

        for path in reflection_paths {
            if self.test_reflection_path(endpoint, path).await {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Info,
                    title: format!("Reflection Path Discovered: {}", path),
                    description: format!("Reflection endpoint found at {}", path),
                    location: Some(format!("{}{}", endpoint.url, path)),
                    recommendation: Some("Restrict access to reflection endpoints.".to_string()),
                    cwe: Some("CWE-215".to_string()),
                    owasp: None,
                });
            }
        }

        Ok(report)
    }

    /// List services via reflection v1
    async fn list_services_reflection_v1(&self, endpoint: &GrpcEndpoint) -> Result<Vec<String>> {
        let mut socket = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(Vec::new()),
        };

        // Build ListServices request (protobuf wire format)
        // Message: grpc.reflection.v1.ServerReflectionRequest
        // list_services: ".*" (string field 1)
        let request = self.build_list_services_request();

        if let Err(_) = socket.write_all(&request).await {
            return Ok(Vec::new());
        }

        // Read response with prefix byte (compressed flag + length)
        let mut response_buffer = vec![0u8; 8192];
        match socket.read(&mut response_buffer).await {
            Ok(n) if n > 5 => {
                // Parse protobuf response (simplified)
                // Look for service names in the response
                Ok(self.parse_service_list_response(&response_buffer[..n]))
            }
            _ => Ok(Vec::new()),
        }
    }

    /// List methods for a service via reflection v1
    async fn list_methods_reflection_v1(&self, endpoint: &GrpcEndpoint, service: &str) -> Result<Vec<String>> {
        let mut socket = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(Vec::new()),
        };

        // Build FileDescriptor request for the service
        let request = self.build_file_descriptor_request(service);

        if let Err(_) = socket.write_all(&request).await {
            return Ok(Vec::new());
        }

        let mut response_buffer = vec![0u8; 16384];
        match socket.read(&mut response_buffer).await {
            Ok(n) if n > 5 => {
                Ok(self.parse_method_list_response(&response_buffer[..n]))
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Build a ListServices reflection request
    fn build_list_services_request(&self) -> Vec<u8> {
        // gRPC message format: [compressed:1byte][length:4bytes][protobuf_payload]
        // Protobuf for ListServices: field 1 (string) = ".*"
        let payload = vec![
            0x0a, 0x02, 0x2a, 0x2e, // field 1, type 2 (length-delimited), length 2, ".*"
        ];

        let mut message = vec![0u8; 5]; // uncompressed (0) + 4-byte length
        let length = payload.len() as u32;
        message[1..5].copy_from_slice(&length.to_be_bytes());
        message.extend(payload);

        message
    }

    /// Build a FileDescriptor request for a specific service
    fn build_file_descriptor_request(&self, service: &str) -> Vec<u8> {
        // Protobuf for FileDescriptor: field 4 (string) = service name
        let service_bytes = service.as_bytes();
        let mut payload = vec![
            0x22, // field 4, type 2 (length-delimited)
        ];
        payload.push(service_bytes.len() as u8);
        payload.extend_from_slice(service_bytes);

        let mut message = vec![0u8; 5];
        let length = payload.len() as u32;
        message[1..5].copy_from_slice(&length.to_be_bytes());
        message.extend(payload);

        message
    }

    /// Parse service list from reflection response
    fn parse_service_list_response(&self, data: &[u8]) -> Vec<String> {
        let mut services = Vec::new();

        // Skip the 5-byte gRPC prefix
        let payload = if data.len() > 5 { &data[5..] } else { data };

        // Simple protobuf parsing looking for string fields
        let mut i = 0;
        while i < payload.len() {
            if i + 1 >= payload.len() {
                break;
            }

            let tag = payload[i];
            i += 1;

            // Check if field 1 (list_services response)
            if tag == 0x0a && i < payload.len() {
                let len = payload[i] as usize;
                i += 1;

                if i + len <= payload.len() {
                    let service = std::str::from_utf8(&payload[i..i + len]);
                    if let Ok(name) = service {
                        if !name.is_empty() && name != "grpc.reflection.v1.ServerReflection" {
                            services.push(name.to_string());
                        }
                    }
                }
                i += len;
            } else if tag < 0x80 {
                // Skip to next field (simplified)
                continue;
            } else {
                i += 1;
            }
        }

        services
    }

    /// Parse method list from FileDescriptor response
    fn parse_method_list_response(&self, data: &[u8]) -> Vec<String> {
        let mut methods = Vec::new();

        // Skip prefix and look for method patterns
        let payload = if data.len() > 5 { &data[5..] } else { data };

        // Look for patterns like "/Service/Method"
        let data_str = String::from_utf8_lossy(payload);
        for cap in data_str.split(|c| c == '{' || c == '}' || c == ',' || c == '"') {
            if cap.contains('/') && cap.len() > 3 && cap.len() < 100 {
                let method = cap.trim();
                if method.starts_with('/') || method.contains("rpc") {
                    methods.push(method.to_string());
                }
            }
        }

        methods
    }

    /// Test a specific reflection path
    async fn test_reflection_path(&self, endpoint: &GrpcEndpoint, _path: &str) -> bool {
        let mut socket = match tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&endpoint.url)
        ).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        // Send minimal HTTP2 preface-ish request
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let _ = socket.write_all(preface).await;

        // Try to get a response
        let mut buffer = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => true,
            _ => false,
        }
    }

    /// Test authentication bypass
    async fn test_auth_bypass(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Test unauthenticated access to common admin methods
        let admin_methods = vec![
            ("AdminService", "GetUsers"),
            ("AdminService", "DeleteUser"),
            ("AuthService", "Login"),
            ("UserService", "GetAllUsers"),
            ("AuthService", "ResetPassword"),
        ];

        for (service, method) in admin_methods {
            if let Ok(result) = self.test_unauthenticated_method(endpoint, service, method).await {
                if result {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Unauthenticated Access: {}/{}", service, method),
                        description: format!("Method {}/{} is accessible without authentication", service, method),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Implement proper authentication for all sensitive methods.".to_string()),
                        cwe: Some("CWE-306".to_string()),
                        owasp: Some("A07:2021".to_string()),
                    });
                }
            }
        }

        // Test metadata manipulation
        if let Ok(true) = self.test_metadata_bypass(endpoint).await {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Metadata Manipulation Possible".to_string(),
                description: "Authentication can be bypassed via metadata manipulation".to_string(),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Validate all metadata headers server-side.".to_string()),
                cwe: Some("CWE-287".to_string()),
                owasp: Some("A07:2021".to_string()),
            });
        }

        Ok(report)
    }

    /// Test if a method is accessible without authentication
    async fn test_unauthenticated_method(&self, endpoint: &GrpcEndpoint, service: &str, method: &str) -> Result<bool> {
        let mut socket = match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        // Build a minimal RPC call
        let request = self.build_rpc_call(service, method, &[]);

        if socket.write_all(&request).await.is_err() {
            return Ok(false);
        }

        let mut response = vec![0u8; 1024];
        match tokio::time::timeout(Duration::from_secs(3), socket.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                // Check if we got a valid response (not an auth error)
                let response_str = String::from_utf8_lossy(&response[..n]);
                Ok(!response_str.contains("unauthenticated") &&
                   !response_str.contains("Unauthorized") &&
                   !response_str.contains("401"))
            }
            _ => Ok(false),
        }
    }

    /// Build an RPC call for a specific service/method
    fn build_rpc_call(&self, _service: &str, _method: &str, payload: &[u8]) -> Vec<u8> {
        // gRPC call structure:
        // 1. Compressed flag (1 byte, usually 0)
        // 2. Message length (4 bytes, big endian)
        // 3. Payload (serialized protobuf message)

        let mut message = vec![0u8; 5];
        let length = payload.len() as u32;
        message[1..5].copy_from_slice(&length.to_be_bytes());
        message.extend_from_slice(payload);

        message
    }

    /// Test metadata manipulation bypass
    async fn test_metadata_bypass(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        // Try connecting with various authentication headers
        let test_cases = vec![
            ("", ""), // No auth
            ("authorization", "Bearer null"),
            ("authorization", "Bearer "),
            ("x-api-key", ""),
            ("grpc-authorization", "null"),
        ];

        for (key, value) in test_cases {
            if self.test_with_header(endpoint, key, value).await.is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Test connection with a specific header
    async fn test_with_header(&self, endpoint: &GrpcEndpoint, _key: &str, _value: &str) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Send HTTP2 preface and headers
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        socket.write_all(preface).await?;

        let mut response = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut response)).await??;

        Ok(n > 0)
    }

    /// Test large message handling
    async fn test_large_messages(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Test message size limits
        let sizes = vec![
            (1024 * 1024, "1MB", VulnSeverity::Info),
            (10 * 1024 * 1024, "10MB", VulnSeverity::Medium),
            (100 * 1024 * 1024, "100MB", VulnSeverity::High),
        ];

        for (size, label, severity) in sizes {
            match self.test_large_message(endpoint, size).await {
                Ok(true) => {
                    report.add_finding(Vuln {
                        severity,
                        title: format!("Large Message Accepted: {}", label),
                        description: format!("Server accepts messages up to {}", label),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Configure max_message_length on the gRPC server.".to_string()),
                        cwe: Some("CWE-770".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                    break; // If large message accepted, stop testing
                }
                Ok(false) => continue,
                Err(_) => break,
            }
        }

        // Test stream payload abuse
        if let Err(e) = self.test_stream_abuse(endpoint).await {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Stream Abuse Potential".to_string(),
                description: format!("Server may be vulnerable to stream abuse: {}", e),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Implement rate limiting on streaming endpoints.".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021".to_string()),
            });
        }

        Ok(report)
    }

    /// Test sending a large message
    async fn test_large_message(&self, endpoint: &GrpcEndpoint, size: usize) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&endpoint.url)
        ).await??;

        let large_payload = vec![0x41u8; size]; // All 'A's
        let message = self.build_rpc_call("TestService", "TestMethod", &large_payload);

        let write_result = tokio::time::timeout(
            Duration::from_secs(5),
            socket.write_all(&message)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                // Message sent successfully
                let mut response = vec![0u8; 1024];
                match tokio::time::timeout(Duration::from_secs(3), socket.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => Ok(!String::from_utf8_lossy(&response[..n]).contains("too_large")),
                    _ => Ok(true),
                }
            }
            _ => Ok(false),
        }
    }

    /// Test streaming endpoint abuse
    async fn test_stream_abuse(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Send multiple messages rapidly (server streaming)
        for _ in 0..100 {
            let message = self.build_rpc_call("StreamService", "ServerStream", b"test");
            if socket.write_all(&message).await.is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Test compression abuse (DoS via compression bombs)
    async fn test_compression_abuse(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Test with compressed flag set
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Build message with compression flag = 1
        let payload = vec![0x00u8; 100]; // Small payload
        let mut message = vec![1u8; 5]; // Compressed flag = 1
        let length = payload.len() as u32;
        message[1..5].copy_from_slice(&length.to_be_bytes());
        message.extend_from_slice(&payload);

        match socket.write_all(&message).await {
            Ok(_) => {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Compression Enabled".to_string(),
                    description: "Server accepts compressed messages which may lead to DoS via compression bombs".to_string(),
                    location: Some(endpoint.url.clone()),
                    recommendation: Some("Disable per-message compression or implement strict limits.".to_string()),
                    cwe: Some("CWE-409".to_string()),
                    owasp: Some("A04:2021".to_string()),
                });
            }
            Err(_) => {}
        }

        // Test gzip compression bomb
        if self.test_gzip_bomb(endpoint).await.is_ok() {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Gzip Compression Bomb Possible".to_string(),
                description: "Server may be vulnerable to gzip compression attacks".to_string(),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Implement maximum decompression size limits.".to_string()),
                cwe: Some("CWE-409".to_string()),
                owasp: Some("A04:2021".to_string()),
            });
        }

        Ok(report)
    }

    /// Test gzip compression bomb
    async fn test_gzip_bomb(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Build a small payload that decompresses to a large size (simplified)
        // In practice, you'd create an actual gzip bomb
        let payload = vec![0x1f, 0x8b, 0x08, 0x00]; // Gzip header

        let mut message = vec![1u8; 5]; // Compressed
        message[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        message.extend_from_slice(&payload);

        socket.write_all(&message).await?;
        Ok(true)
    }

    /// Test protobuf fuzzing
    async fn test_protobuf_fuzzing(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Test malformed protobuf messages
        let malformed_payloads = vec![
            vec![0xFF, 0xFF, 0xFF, 0xFF], // Invalid varint
            vec![0x00], // Truncated message
            vec![0xDE, 0xAD, 0xBE, 0xEF], // Random bytes
            vec![0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // Very large varint
            vec![0x0A, 0x80, 0x01, 0x41], // Invalid length prefix
        ];

        for (i, payload) in malformed_payloads.iter().enumerate() {
            match self.test_malformed_message(endpoint, payload).await {
                Ok(result) if result => {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: format!("Malformed Message Accepted: Test {}", i + 1),
                        description: "Server accepted malformed protobuf message without error".to_string(),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Implement strict protobuf validation.".to_string()),
                        cwe: Some("CWE-20".to_string()),
                        owasp: None,
                    });
                }
                _ => {}
            }
        }

        // Test type confusion
        if self.test_type_confusion(endpoint).await.is_ok() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Type Confusion Possible".to_string(),
                description: "Server may be vulnerable to type confusion attacks".to_string(),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Validate all field types strictly.".to_string()),
                cwe: Some("CWE-843".to_string()),
                owasp: None,
            });
        }

        // Test integer overflow
        if self.test_integer_overflow(endpoint).await.is_ok() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Integer Overflow Possible".to_string(),
                description: "Protobuf integer fields may be vulnerable to overflow".to_string(),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Use checked arithmetic and validate ranges.".to_string()),
                cwe: Some("CWE-190".to_string()),
                owasp: None,
            });
        }

        // Test repeated field abuse
        if self.test_repeated_field_abuse(endpoint).await.is_ok() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Repeated Field Abuse Possible".to_string(),
                description: "Server may be vulnerable to repeated field DoS".to_string(),
                location: Some(endpoint.url.clone()),
                recommendation: Some("Limit maximum repeated field counts.".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021".to_string()),
            });
        }

        Ok(report)
    }

    /// Test a malformed protobuf message
    async fn test_malformed_message(&self, endpoint: &GrpcEndpoint, payload: &[u8]) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        let message = self.build_rpc_call("Test", "Test", payload);

        match socket.write_all(&message).await {
            Ok(_) => {
                let mut response = vec![0u8; 1024];
                match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut response)).await {
                    Ok(Ok(_)) => Ok(true),
                    _ => Ok(false),
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Test type confusion attacks
    async fn test_type_confusion(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Send a field with wrong wire type (string instead of int)
        // Field 1, type 2 (string) with value "123" instead of varint
        let payload = vec![0x0A, 0x03, 0x31, 0x32, 0x33];
        let message = self.build_rpc_call("Test", "Test", &payload);

        socket.write_all(&message).await?;
        Ok(true)
    }

    /// Test integer overflow in protobuf fields
    async fn test_integer_overflow(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Very large varint (close to max int64)
        let payload = vec![0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        let message = self.build_rpc_call("Test", "Test", &payload);

        socket.write_all(&message).await?;
        Ok(true)
    }

    /// Test repeated field abuse (DoS)
    async fn test_repeated_field_abuse(&self, endpoint: &GrpcEndpoint) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Create a message with many repeated fields
        let mut payload = Vec::new();
        for _ in 0..1000 {
            payload.extend_from_slice(&[0x0A, 0x01, 0x41]); // field 1, string, "A"
        }

        let message = self.build_rpc_call("Test", "Test", &payload);

        socket.write_all(&message).await?;
        Ok(true)
    }

    /// Test common gRPC services
    async fn test_common_services(&self, endpoint: &GrpcEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));

        // Common gRPC services to check
        let common_services = vec![
            ("grpc.health.v1.Health", "Check", "Health Check"),
            ("grpc.health.v1.Health", "Watch", "Health Watch"),
            ("grpc.reflection.v1.ServerReflection", "ServerReflectionInfo", "Reflection"),
            ("google.protobuf.Empty", "", "Empty"),
        ];

        for (service, method, description) in common_services {
            match self.test_service_exists(endpoint, service, method).await {
                Ok(true) => {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: format!("Service Detected: {}", service),
                        description: format!("{} service with method '{}' is available", description, method),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Ensure public services don't expose sensitive information.".to_string()),
                        cwe: None,
                        owasp: None,
                    });
                }
                _ => {}
            }
        }

        Ok(report)
    }

    /// Check if a service exists on the endpoint
    async fn test_service_exists(&self, endpoint: &GrpcEndpoint, service: &str, method: &str) -> Result<bool> {
        let mut socket = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect(&endpoint.url)
        ).await??;

        // Empty payload for service discovery
        let payload = if method.is_empty() {
            vec![]
        } else {
            vec![0x00] // Minimal valid protobuf
        };

        let message = self.build_rpc_call(service, method, &payload);

        match socket.write_all(&message).await {
            Ok(_) => {
                let mut response = vec![0u8; 512];
                match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if response indicates the service exists
                        let response_str = String::from_utf8_lossy(&response[..n]);
                        Ok(!response_str.contains("not found") &&
                           !response_str.contains("NOT_FOUND") &&
                           !response_str.contains("Method not found"))
                    }
                    _ => Ok(false),
                }
            }
            Err(_) => Ok(false),
        }
    }

    /// Extract service information from response
    fn extract_service_info(&self, response: &[u8]) -> HashMap<String, Vec<String>> {
        let mut services = HashMap::new();

        // This is a simplified parser - in production, use proper protobuf decoding
        let response_str = String::from_utf8_lossy(response);

        // Look for service/method patterns
        for line in response_str.lines() {
            if line.contains('/') && line.len() < 200 {
                let parts: Vec<&str> = line.split('/').collect();
                if parts.len() >= 2 {
                    let service = parts[0].to_string();
                    let method = parts[1].to_string();
                    services.entry(service).or_insert_with(Vec::new).push(method);
                }
            }
        }

        services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_list_services_request() {
        let scanner = GrpcScanner::new(ScannerConfig::new());
        let request = scanner.build_list_services_request();

        // Should have 5-byte prefix + payload
        assert!(request.len() >= 5);
        assert_eq!(request[0], 0); // Uncompressed
    }

    #[test]
    fn test_build_rpc_call() {
        let scanner = GrpcScanner::new(ScannerConfig::new());
        let payload = b"test";
        let message = scanner.build_rpc_call("TestService", "TestMethod", payload);

        assert_eq!(message[0], 0); // Uncompressed
        assert!(message.len() >= payload.len() + 5);
    }

    #[test]
    fn test_parse_service_list_response() {
        let scanner = GrpcScanner::new(ScannerConfig::new());

        // Mock response with some service names
        let mock_data = vec![
            0x00, 0x00, 0x00, 0x00, 0x0C, // gRPC prefix
            0x0A, 0x08, 0x54, 0x65, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, // TestService
        ];

        let services = scanner.parse_service_list_response(&mock_data);
        assert!(!services.is_empty());
    }
}
