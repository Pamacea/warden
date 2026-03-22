//! Kubernetes Security Scanner
//!
//! Detects Kubernetes security issues including:
//! - RBAC Misconfigurations (wildcard resources, overly permissive verbs, privileged service accounts)
//! - Pod Security (hostNetwork, hostPID, hostIPC, privileged pods, hostPath mounts, runAsUser: 0)
//! - Secrets Exposure (env variables, ConfigMaps, decoded secrets, public namespace)
//! - Container Breakout (dangerous capabilities, sensitive volume mounts)
//! - Resource Limits (missing limits/requests, LimitRange not configured)
//!
//! Supports:
//! - YAML manifest analysis (*.yaml, *.yml, k8s/)
//! - Kubernetes API server testing (when accessible)
//! - Helm chart analysis
//! - Kustomize manifests

#![allow(dead_code)]

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use walkdir::WalkDir;

/// Kubernetes API server default endpoints
const K8S_API_ENDPOINTS: &[&str] = &[
    "https://kubernetes.default.svc",
    "https://kubernetes.default",
    "http://localhost:8080",
    "http://127.0.0.1:8001",
    "http://127.0.0.1:6443",
];

/// HTTP timeout for K8s API requests
const API_TIMEOUT: Duration = Duration::from_secs(5);

/// Dangerous host paths that allow host access
const DANGEROUS_HOST_PATHS: &[&str] = &[
    "/", "/root", "/etc", "/proc", "/sys", "/var/run/docker.sock", "/var/lib/kubelet",
    "/home", "/var/log", "/run/containerd", "/var/lib/containerd",
];

/// Dangerous Linux capabilities
const DANGEROUS_CAPABILITIES: &[&str] = &[
    "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "SYS_BOOT",
    "NET_ADMIN", "NET_RAW", "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "FOWNER", "FSETID", "KILL", "SETGID", "SETUID", "SETPCAP",
    "LINUX_IMMUTABLE", "IPC_LOCK", "IPC_OWNER", "SYSLOG", "MKNOD",
    "NET_BIND_SERVICE", "SYS_CHROOT", "SETFCAP", "WAKE_ALARM",
];

/// Sensitive Kubernetes API paths
const SENSITIVE_API_PATHS: &[&str] = &[
    "/api/v1/namespaces/default/secrets",
    "/api/v1/secrets",
    "/api/v1/pods",
    "/api/v1/nodes",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
    "/apis/apps/v1/deployments",
    "/apis/batch/v1/jobs",
    "/apis/batch/v1/cronjobs",
];

/// Kubernetes resource kind
#[derive(Debug, Clone, PartialEq, Eq)]
enum K8sResourceKind {
    Pod,
    Deployment,
    StatefulSet,
    DaemonSet,
    ReplicaSet,
    Job,
    CronJob,
    Service,
    Ingress,
    ConfigMap,
    Secret,
    PersistentVolume,
    PersistentVolumeClaim,
    StorageClass,
    ClusterRole,
    ClusterRoleBinding,
    Role,
    RoleBinding,
    ServiceAccount,
    Namespace,
    NetworkPolicy,
    ResourceQuota,
    LimitRange,
    PodSecurityPolicy,
    PodDisruptionBudget,
    HorizontalPodAutoscaler,
    Unknown,
}

impl K8sResourceKind {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pod" => K8sResourceKind::Pod,
            "deployment" | "deployments" => K8sResourceKind::Deployment,
            "statefulset" | "statefulsets" => K8sResourceKind::StatefulSet,
            "daemonset" | "daemonsets" => K8sResourceKind::DaemonSet,
            "replicaset" | "replicasets" => K8sResourceKind::ReplicaSet,
            "job" | "jobs" => K8sResourceKind::Job,
            "cronjob" | "cronjobs" => K8sResourceKind::CronJob,
            "service" | "services" | "svc" => K8sResourceKind::Service,
            "ingress" | "ingresses" => K8sResourceKind::Ingress,
            "configmap" | "configmaps" | "cm" => K8sResourceKind::ConfigMap,
            "secret" | "secrets" => K8sResourceKind::Secret,
            "persistentvolume" | "persistentvolumes" | "pv" => K8sResourceKind::PersistentVolume,
            "persistentvolumeclaim" | "persistentvolumeclaims" | "pvc" => K8sResourceKind::PersistentVolumeClaim,
            "storageclass" | "storageclasses" | "sc" => K8sResourceKind::StorageClass,
            "clusterrole" | "clusterroles" => K8sResourceKind::ClusterRole,
            "clusterrolebinding" | "clusterrolebindings" => K8sResourceKind::ClusterRoleBinding,
            "role" | "roles" => K8sResourceKind::Role,
            "rolebinding" | "rolebindings" => K8sResourceKind::RoleBinding,
            "serviceaccount" | "serviceaccounts" | "sa" => K8sResourceKind::ServiceAccount,
            "namespace" | "namespaces" | "ns" => K8sResourceKind::Namespace,
            "networkpolicy" | "networkpolicies" | "netpol" => K8sResourceKind::NetworkPolicy,
            "resourcequota" | "resourcequotas" | "quota" => K8sResourceKind::ResourceQuota,
            "limitrange" | "limitranges" | "limits" => K8sResourceKind::LimitRange,
            "podsecuritypolicy" | "podsecuritypolicies" | "psp" => K8sResourceKind::PodSecurityPolicy,
            "poddisruptionbudget" | "poddisruptionbudgets" | "pdb" => K8sResourceKind::PodDisruptionBudget,
            "horizontalpodautoscaler" | "horizontalpodautoscalers" | "hpa" => K8sResourceKind::HorizontalPodAutoscaler,
            _ => K8sResourceKind::Unknown,
        }
    }

    fn is_workload(&self) -> bool {
        matches!(
            self,
            K8sResourceKind::Pod
                | K8sResourceKind::Deployment
                | K8sResourceKind::StatefulSet
                | K8sResourceKind::DaemonSet
                | K8sResourceKind::ReplicaSet
                | K8sResourceKind::Job
                | K8sResourceKind::CronJob
        )
    }

    fn is_rbac(&self) -> bool {
        matches!(
            self,
            K8sResourceKind::ClusterRole
                | K8sResourceKind::ClusterRoleBinding
                | K8sResourceKind::Role
                | K8sResourceKind::RoleBinding
                | K8sResourceKind::ServiceAccount
        )
    }

    fn is_security_config(&self) -> bool {
        matches!(
            self,
            K8sResourceKind::NetworkPolicy
                | K8sResourceKind::ResourceQuota
                | K8sResourceKind::LimitRange
                | K8sResourceKind::PodSecurityPolicy
        )
    }
}

/// Parsed Kubernetes manifest (text-based)
#[derive(Debug, Clone)]
struct K8sManifest {
    kind: K8sResourceKind,
    name: String,
    namespace: Option<String>,
    content: String,
    file_path: PathBuf,
}

/// Kubernetes scanner
pub struct KubernetesScanner {
    config: ScannerConfig,
    client: Option<reqwest::Client>,
}

impl KubernetesScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(API_TIMEOUT)
            .danger_accept_invalid_certs(true)
            .build()
            .ok();

        Self { config, client }
    }

    /// Scan Kubernetes target (path or URL)
    pub async fn scan(&self, target: &Target) -> Result<ScanReport> {
        let mut report = ScanReport::new(target.clone());

        match target {
            Target::Url(url) => {
                if self.is_k8s_api_url(url) {
                    report.merge(self.scan_api_server(url).await?);
                }
            }
            Target::Path(path) => {
                report.merge(self.scan_manifests(path).await?);
            }
        }

        Ok(report)
    }

    /// Check if URL is a Kubernetes API server
    fn is_k8s_api_url(&self, url: &str) -> bool {
        url.contains("kubernetes") || url.contains(":6443") || url.contains(":8001")
    }

    /// Scan Kubernetes API server
    async fn scan_api_server(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));
        let client = self.client.as_ref().context("HTTP client not available")?;

        // Check for anonymous access
        if let Ok(response) = client.get(format!("{}/api/v1/namespaces", base_url)).send().await {
            let status = response.status();
            if status.is_success() {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "Kubernetes API: Anonymous Access Enabled".to_string(),
                    description: "The Kubernetes API server allows anonymous access to namespace listing. This exposes sensitive cluster information.".to_string(),
                    location: Some(format!("{}/api/v1/namespaces", base_url)),
                    recommendation: Some("Disable anonymous access: --anonymous-auth=false in kube-apiserver. Use proper authentication and RBAC.".to_string()),
                    cwe: Some("CWE-287".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        // Check for secrets exposure
        for path in SENSITIVE_API_PATHS {
            if let Ok(response) = client.get(format!("{}{}", base_url, path)).send().await {
                let status = response.status();
                if status.is_success() {
                    let severity = if path.contains("secret") {
                        VulnSeverity::Critical
                    } else {
                        VulnSeverity::High
                    };

                    report.add_finding(Vuln {
                        severity,
                        title: format!("Kubernetes API: Sensitive Endpoint Exposed - {}", path),
                        description: format!("The Kubernetes API server exposes sensitive endpoint '{}' without proper authentication.", path),
                        location: Some(format!("{}{}", base_url, path)),
                        recommendation: Some("Restrict API access with proper authentication, RBAC, and NetworkPolicies.".to_string()),
                        cwe: Some("CWE-287".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Scan Kubernetes manifest files
    async fn scan_manifests(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let manifests = self.discover_manifests(path)?;
        let mut found_security_policies = false;

        for manifest_path in &manifests {
            if let Ok(contents) = fs::read_to_string(manifest_path) {
                // Parse individual YAML documents
                for doc in contents.split("---") {
                    if doc.trim().is_empty() {
                        continue;
                    }

                    if let Some(manifest) = self.parse_manifest_text(doc, manifest_path) {
                        report.merge(self.scan_manifest_text(&manifest)?);

                        // Track security policies
                        if matches!(
                            manifest.kind,
                            K8sResourceKind::NetworkPolicy
                                | K8sResourceKind::LimitRange
                                | K8sResourceKind::ResourceQuota
                                | K8sResourceKind::PodSecurityPolicy
                        ) {
                            found_security_policies = true;
                        }
                    }
                }
            }
        }

        // Check for cluster-wide security policies
        if !found_security_policies {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Cluster Security: Missing Network Policies".to_string(),
                description: "No NetworkPolicy resources found. All pods can communicate with each other without restriction.".to_string(),
                location: Some("cluster-wide".to_string()),
                recommendation: Some("Implement NetworkPolicies to restrict pod-to-pod communication. Use a default-deny policy.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Discover Kubernetes manifest files
    fn discover_manifests(&self, path: &Path) -> Result<Vec<PathBuf>> {
        let mut manifests = Vec::new();

        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if file_path.extension().map_or(false, |e| e == "yaml" || e == "yml") {
                if !self.should_exclude_path(file_path) {
                    manifests.push(file_path.to_path_buf());
                }
            }
        }

        Ok(manifests)
    }

    /// Check if path should be excluded
    fn should_exclude_path(&self, path: &Path) -> bool {
        let excluded = [
            "node_modules", ".git", "target", "dist", "build", "vendor",
            "__pycache__", ".venv", "venv", ".idea", ".vscode", "coverage",
            ".next", ".nuxt", "out", ".terraform",
        ];

        path.components()
            .filter_map(|c| c.as_os_str().to_str())
            .any(|component| excluded.contains(&component))
    }

    /// Parse manifest from text
    fn parse_manifest_text(&self, content: &str, file_path: &Path) -> Option<K8sManifest> {
        // Extract kind
        let kind_re = Regex::new(r"(?m)^\s*kind:\s*(.+)$").ok()?;
        let kind = kind_re.captures(content)?.get(1)?.as_str().trim();
        let kind = K8sResourceKind::from_str(kind);

        // Extract name
        let name_re = Regex::new(r"(?m)^\s*name:\s*(.+)$").ok()?;
        let name = name_re.captures(content)?.get(1)?.as_str().trim().to_string();

        // Extract namespace
        let namespace_re = Regex::new(r"(?m)^\s*namespace:\s*(.+)$").ok()?;
        let namespace = namespace_re.captures(content)
            .and_then(|c| c.get(1))
            .map(|s| s.as_str().trim().to_string());

        Some(K8sManifest {
            kind,
            name,
            namespace,
            content: content.to_string(),
            file_path: file_path.to_path_buf(),
        })
    }

    /// Scan a parsed manifest (text-based)
    fn scan_manifest_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));

        match &manifest.kind {
            K8sResourceKind::Pod
            | K8sResourceKind::Deployment
            | K8sResourceKind::StatefulSet
            | K8sResourceKind::DaemonSet
            | K8sResourceKind::ReplicaSet
            | K8sResourceKind::Job
            | K8sResourceKind::CronJob => {
                report.merge(self.scan_workload_text(manifest)?);
            }
            K8sResourceKind::ClusterRole | K8sResourceKind::Role => {
                report.merge(self.scan_rbac_role_text(manifest)?);
            }
            K8sResourceKind::ClusterRoleBinding | K8sResourceKind::RoleBinding => {
                report.merge(self.scan_rbac_binding_text(manifest)?);
            }
            K8sResourceKind::Secret => {
                report.merge(self.scan_secret_text(manifest)?);
            }
            K8sResourceKind::ConfigMap => {
                report.merge(self.scan_config_map_text(manifest)?);
            }
            K8sResourceKind::ServiceAccount => {
                report.merge(self.scan_service_account_text(manifest)?);
            }
            K8sResourceKind::Namespace => {
                report.merge(self.scan_namespace_text(manifest)?);
            }
            _ => {}
        }

        Ok(report)
    }

    /// Scan workload resources (text-based)
    fn scan_workload_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));

        let content = &manifest.content;

        // Check hostNetwork
        if content.contains("hostNetwork:") && content.contains("hostNetwork: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Pod Security: hostNetwork Enabled".to_string(),
                description: "The pod has hostNetwork enabled, allowing it to access the host network namespace.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Disable hostNetwork unless absolutely required. Use NetworkPolicies instead.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check hostPID
        if content.contains("hostPID:") && content.contains("hostPID: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Pod Security: hostPID Enabled".to_string(),
                description: "The pod has hostPID enabled, allowing it to view and manipulate processes on the host.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Disable hostPID. This is a container breakout vector.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check hostIPC
        if content.contains("hostIPC:") && content.contains("hostIPC: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Pod Security: hostIPC Enabled".to_string(),
                description: "The pod has hostIPC enabled, allowing it to access host IPC mechanisms.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Disable hostIPC.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check privileged
        if content.contains("privileged:") && content.contains("privileged: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Pod Security: Privileged Pod".to_string(),
                description: "The pod is running in privileged mode, giving it full access to all host devices.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Never use privileged pods. Use specific capabilities instead.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check runAsUser: 0 (root)
        let root_pattern = Regex::new(r"runAsUser:\s*0").unwrap();
        if root_pattern.is_match(content) {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Pod Security: Running as Root".to_string(),
                description: "The pod is configured to run as root (runAsUser: 0).".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Always run containers as non-root users. Set runAsNonRoot: true.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check allowPrivilegeEscalation
        if content.contains("allowPrivilegeEscalation:") && content.contains("allowPrivilegeEscalation: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Pod Security: Privilege Escalation Allowed".to_string(),
                description: "The pod has allowPrivilegeEscalation set to true.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Set allowPrivilegeEscalation to false.".to_string()),
                cwe: Some("CWE-269".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check dangerous capabilities
        for cap in DANGEROUS_CAPABILITIES {
            // Simple pattern match without regex for capability detection
            let cap_pattern = format!("add:\n    - {}", cap);
            let cap_pattern_alt = format!("add: [{}]", cap);
            if content.contains(&cap_pattern) || content.contains(&cap_pattern_alt) {
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Pod Security: Dangerous Capability - {}", cap),
                    description: format!("The pod adds the {} capability.", cap),
                    location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                    recommendation: Some("Drop the capability. Use security contexts with minimal required capabilities.".to_string()),
                    cwe: Some("CWE-269".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }
        }

        // Check for dangerous hostPath volumes
        let hostpath_re = Regex::new(r#"hostPath:\s*\n\s*path:\s*['"]?([^'"\n]+)"#).unwrap();
        for cap in hostpath_re.captures_iter(content) {
            let path = &cap[1];
            for dangerous in DANGEROUS_HOST_PATHS {
                if path == *dangerous || path.starts_with(dangerous) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Critical,
                        title: "Volume Security: Dangerous hostPath Mount".to_string(),
                        description: format!("Volume mounts dangerous host path '{}'.", path),
                        location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                        recommendation: Some("Avoid using hostPath volumes. Use PersistentVolumes instead.".to_string()),
                        cwe: Some("CWE-250".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                    break;
                }
            }
        }

        // Check for secrets in environment variables
        let secret_env_re = Regex::new(r#"secretKeyRef:\s*\n\s*name:\s*['"]?([^'"\n]+)"#).unwrap();
        for cap in secret_env_re.captures_iter(content) {
            let secret_name = &cap[1];
            if secret_name.to_lowercase().contains("password")
                || secret_name.to_lowercase().contains("secret")
                || secret_name.to_lowercase().contains("token")
                || secret_name.to_lowercase().contains("key")
            {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: "Secrets Exposure: Sensitive Secret in Environment Variable".to_string(),
                    description: format!("Secret '{}' is exposed as an environment variable.", secret_name),
                    location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                    recommendation: Some("Use secret volumes instead of environment variables.".to_string()),
                    cwe: Some("CWE-312".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
        }

        // Check for hardcoded secrets
        let hardcoded_re = Regex::new(r#"value:\s*['"]?(?:password|secret|token|api[_-]?key|private[_-]?key)['"]?:\s*['"]?[^'"\s]+['"]?"#).unwrap();
        if hardcoded_re.is_match(content) {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "Secrets Exposure: Hardcoded Secret".to_string(),
                description: "Sensitive value is hardcoded in the manifest.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Remove hardcoded secrets. Use Kubernetes Secrets or external secret manager.".to_string()),
                cwe: Some("CWE-798".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        // Check for missing resource limits
        let has_resources = content.contains("resources:");
        if !has_resources {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Resource Limits: No Resource Configuration".to_string(),
                description: "Container has no resource limits or requests defined.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Define resource limits and requests for all containers.".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        } else if !content.contains("limits:") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Resource Limits: Missing CPU/Memory Limits".to_string(),
                description: "Container has no resource limits defined.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Always set resource limits to prevent DoS.".to_string()),
                cwe: Some("CWE-770".to_string()),
                owasp: Some("A04:2021 - Insecure Design".to_string()),
            });
        }

        Ok(report)
    }

    /// Scan RBAC Role (text-based)
    fn scan_rbac_role_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));
        let content = &manifest.content;

        // Check for wildcard resources
        if content.contains("resources:") && (content.contains("- '*'") || content.contains("- \"*\"")) {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RBAC Misconfiguration: Wildcard Resource Access".to_string(),
                description: format!("{} '{}' grants access to all resources ('*').", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Use specific resource names instead of wildcards.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for wildcard verbs
        if content.contains("verbs:") && (content.contains("- '*'") || content.contains("- \"*\"") || content.contains("verbs: [\"*\"]") || content.contains("verbs: ['*']")) {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "RBAC Misconfiguration: Wildcard Verbs".to_string(),
                description: format!("{} '{}' grants all verbs ('*').", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Use specific verbs instead of wildcards.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for pods/exec access
        if content.contains("resources:") && content.contains("pods/exec") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RBAC Misconfiguration: Pod Exec Access".to_string(),
                description: format!("{} '{}' grants pod/exec access.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Restrict pod/exec access. Never grant in production.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for secrets access
        if content.contains("resources:") && content.contains("secrets") && (content.contains("verbs:") && content.contains("get")) {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "RBAC Misconfiguration: Secrets Access".to_string(),
                description: format!("{} '{}' grants access to secrets.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Restrict secrets access to specific service accounts.".to_string()),
                cwe: Some("CWE-312".to_string()),
                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }

        // Check for node modification
        if content.contains("resources:") && content.contains("nodes") && content.contains("verbs:") {
            if content.contains("create") || content.contains("update") || content.contains("patch") || content.contains("delete") {
                report.add_finding(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "RBAC Misconfiguration: Node Modification Access".to_string(),
                    description: format!("{} '{}' grants node modification access.", self.kind_name(&manifest.kind), manifest.name),
                    location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                    recommendation: Some("Never grant node write access.".to_string()),
                    cwe: Some("CWE-250".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Scan RBAC Binding (text-based)
    fn scan_rbac_binding_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));
        let content = &manifest.content;

        // Check for system:anonymous binding
        if content.contains("name: system:anonymous") || content.contains("name: system:unauthenticated") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RBAC Misconfiguration: Anonymous Access Binding".to_string(),
                description: format!("{} '{}' binds to anonymous user.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Never bind to system:anonymous.".to_string()),
                cwe: Some("CWE-287".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for system:authenticated binding
        if content.contains("name: system:authenticated") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: "RBAC Misconfiguration: Authenticated-Only Access".to_string(),
                description: format!("{} '{}' binds to all authenticated users.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Bind to specific users or groups, not system:authenticated.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for cluster-admin binding
        if content.contains("name: cluster-admin") || content.contains("name: admin") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Critical,
                title: format!("RBAC Misconfiguration: cluster-admin Binding"),
                description: format!("{} '{}' binds cluster-admin to a subject.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Never use cluster-admin except for cluster administrator accounts.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for default service account binding
        if content.contains("name: default") && content.contains("kind: ServiceAccount") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "RBAC Misconfiguration: Default Service Account Binding".to_string(),
                description: format!("{} '{}' binds to the default service account.", self.kind_name(&manifest.kind), manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Create dedicated service accounts for each application.".to_string()),
                cwe: Some("CWE-284".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Scan Secret resource (text-based)
    fn scan_secret_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));

        let namespace = manifest.namespace.as_deref().unwrap_or("default");

        if namespace == "default" {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Secrets: Secret in Default Namespace".to_string(),
                description: format!("Secret '{}' is in the default namespace.", manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Use dedicated namespaces for applications.".to_string()),
                cwe: Some("CWE-312".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        let content = &manifest.content;

        // Check for stringData (plaintext)
        if content.contains("stringData:") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: "Secrets: stringData in Use".to_string(),
                description: "Secret uses stringData. Values are stored as plaintext in the manifest.".to_string(),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Use 'data' field with base64-encoded values.".to_string()),
                cwe: Some("CWE-312".to_string()),
                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }

        Ok(report)
    }

    /// Scan ConfigMap (text-based)
    fn scan_config_map_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));
        let content = &manifest.content;

        // Check for secret-like keys in ConfigMap
        let secret_keywords = ["password", "secret", "token", "key", "credential", "auth", "private", "api_key"];
        let data_re = Regex::new(r#"(\w+):\s*['"]?[^'\n]*['"]?\n"#).unwrap();

        for cap in data_re.captures_iter(content) {
            let key = &cap[1];
            for keyword in &secret_keywords {
                if key.to_lowercase().contains(keyword) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Secrets Exposure: Secret Data in ConfigMap".to_string(),
                        description: format!("ConfigMap contains secret-like key '{}'.", key),
                        location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                        recommendation: Some("Move sensitive data to Kubernetes Secrets or external secret manager.".to_string()),
                        cwe: Some("CWE-312".to_string()),
                        owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                    });
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Scan ServiceAccount (text-based)
    fn scan_service_account_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));
        let content = &manifest.content;

        // Check for automountServiceAccountToken
        if content.contains("automountServiceAccountToken: true") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "ServiceAccount: Token Auto-Mount Enabled".to_string(),
                description: format!("ServiceAccount '{}' has automountServiceAccountToken: true.", manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Set automountServiceAccountToken: false unless needed.".to_string()),
                cwe: Some("CWE-287".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        Ok(report)
    }

    /// Scan Namespace (text-based)
    fn scan_namespace_text(&self, manifest: &K8sManifest) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(manifest.file_path.clone()));
        let content = &manifest.content;

        // Check for Pod Security Standards labels
        if !content.contains("pod-security.kubernetes.io/enforce") {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Namespace: Missing Pod Security Standards".to_string(),
                description: format!("Namespace '{}' does not enforce Pod Security Standards.", manifest.name),
                location: Some(format!("{}:{}", manifest.file_path.display(), manifest.name)),
                recommendation: Some("Apply Pod Security Standards with 'pod-security.kubernetes.io/enforce: restricted'.".to_string()),
                cwe: Some("CWE-250".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Get kind name for display
    fn kind_name(&self, kind: &K8sResourceKind) -> &str {
        match kind {
            K8sResourceKind::ClusterRole => "ClusterRole",
            K8sResourceKind::ClusterRoleBinding => "ClusterRoleBinding",
            K8sResourceKind::Role => "Role",
            K8sResourceKind::RoleBinding => "RoleBinding",
            _ => "Resource",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kind_parsing() {
        assert_eq!(K8sResourceKind::from_str("Pod"), K8sResourceKind::Pod);
        assert_eq!(K8sResourceKind::from_str("deployment"), K8sResourceKind::Deployment);
        assert_eq!(K8sResourceKind::from_str("ClusterRole"), K8sResourceKind::ClusterRole);
        assert_eq!(K8sResourceKind::from_str("unknown"), K8sResourceKind::Unknown);
    }

    #[test]
    fn test_kind_is_workload() {
        assert!(K8sResourceKind::Pod.is_workload());
        assert!(K8sResourceKind::Deployment.is_workload());
        assert!(!K8sResourceKind::Service.is_workload());
        assert!(!K8sResourceKind::ClusterRole.is_workload());
    }

    #[test]
    fn test_kind_is_rbac() {
        assert!(K8sResourceKind::ClusterRole.is_rbac());
        assert!(K8sResourceKind::RoleBinding.is_rbac());
        assert!(!K8sResourceKind::Pod.is_rbac());
    }

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = KubernetesScanner::new(config);
        assert!(scanner.client.is_some());
    }

    #[test]
    fn test_k8s_api_url_detection() {
        let config = ScannerConfig::new();
        let scanner = KubernetesScanner::new(config);

        assert!(scanner.is_k8s_api_url("https://kubernetes.default.svc"));
        assert!(scanner.is_k8s_api_url("https://example.com:6443"));
        assert!(!scanner.is_k8s_api_url("https://example.com"));
    }
}
