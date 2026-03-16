//! Jenkins CI/CD Integration
//!
//! This module provides comprehensive Jenkins integration for Warden v0.8.0 Enterprise Edition.
//!
//! Features:
//! - Pipeline build step integration
//! - Console output formatting with highlights
//! - Build failure on critical vulnerabilities
//! - Configurable thresholds
//! - Jenkinsfile generation
//! - Notification integration
//! - Build history tracking

use crate::scanners::{ScanReport, VulnSeverity};
use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Jenkins build failure threshold
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JenkinsFailureThreshold {
    /// Never fail the build
    #[default]
    Never,
    /// Fail only on critical vulnerabilities
    Critical,
    /// Fail on critical and high vulnerabilities
    High,
    /// Fail on critical, high, and medium vulnerabilities
    Medium,
    /// Fail on any vulnerability (including low)
    Low,
    /// Always fail the build (useful for testing)
    Always,
}

impl JenkinsFailureThreshold {
    /// Check if the build should fail based on vulnerability counts
    pub fn should_fail(&self, critical: usize, high: usize, medium: usize, low: usize) -> bool {
        match self {
            JenkinsFailureThreshold::Never => false,
            JenkinsFailureThreshold::Critical => critical > 0,
            JenkinsFailureThreshold::High => critical > 0 || high > 0,
            JenkinsFailureThreshold::Medium => critical > 0 || high > 0 || medium > 0,
            JenkinsFailureThreshold::Low => critical > 0 || high > 0 || medium > 0 || low > 0,
            JenkinsFailureThreshold::Always => true,
        }
    }

    /// Get the minimum severity that triggers failure
    pub fn min_failure_severity(&self) -> Option<VulnSeverity> {
        match self {
            JenkinsFailureThreshold::Never => None,
            JenkinsFailureThreshold::Critical => Some(VulnSeverity::Critical),
            JenkinsFailureThreshold::High => Some(VulnSeverity::High),
            JenkinsFailureThreshold::Medium => Some(VulnSeverity::Medium),
            JenkinsFailureThreshold::Low => Some(VulnSeverity::Low),
            JenkinsFailureThreshold::Always => Some(VulnSeverity::Info),
        }
    }

    /// Get threshold description
    pub fn description(&self) -> &str {
        match self {
            JenkinsFailureThreshold::Never => "Never fail build",
            JenkinsFailureThreshold::Critical => "Fail on critical vulnerabilities",
            JenkinsFailureThreshold::High => "Fail on high or critical vulnerabilities",
            JenkinsFailureThreshold::Medium => "Fail on medium or higher vulnerabilities",
            JenkinsFailureThreshold::Low => "Fail on any vulnerability",
            JenkinsFailureThreshold::Always => "Always fail build",
        }
    }
}

impl std::str::FromStr for JenkinsFailureThreshold {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "never" | "none" => Ok(JenkinsFailureThreshold::Never),
            "critical" => Ok(JenkinsFailureThreshold::Critical),
            "high" => Ok(JenkinsFailureThreshold::High),
            "medium" => Ok(JenkinsFailureThreshold::Medium),
            "low" => Ok(JenkinsFailureThreshold::Low),
            "always" => Ok(JenkinsFailureThreshold::Always),
            _ => Err(format!(
                "Unknown threshold: {}. Valid options: never, critical, high, medium, low, always",
                s
            )),
        }
    }
}

/// Jenkins report output format
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JenkinsReportFormat {
    /// Standard Jenkins console output
    #[default]
    Console,
    /// Parseable format for Jenkins plugins (Warnings Next Generation)
    Parseable,
    /// JSON format for downstream processing
    Json,
    /// Both console and parseable
    Combined,
}

impl std::str::FromStr for JenkinsReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "console" => Ok(JenkinsReportFormat::Console),
            "parseable" | "parsed" => Ok(JenkinsReportFormat::Parseable),
            "json" => Ok(JenkinsReportFormat::Json),
            "combined" | "both" => Ok(JenkinsReportFormat::Combined),
            _ => Err(format!(
                "Unknown format: {}. Valid options: console, parseable, json, combined",
                s
            )),
        }
    }
}

/// Jenkins notification configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JenkinsNotificationConfig {
    /// Enable notifications on build failure
    pub notify_on_failure: bool,
    /// Enable notifications on vulnerabilities found
    pub notify_on_findings: bool,
    /// Minimum severity to notify
    pub notify_threshold: VulnSeverity,
    /// Custom notification message prefix
    pub message_prefix: Option<String>,
    /// Include scan summary in notification
    pub include_summary: bool,
}

impl Default for JenkinsNotificationConfig {
    fn default() -> Self {
        Self {
            notify_on_failure: true,
            notify_on_findings: false,
            notify_threshold: VulnSeverity::High,
            message_prefix: None,
            include_summary: true,
        }
    }
}

/// Jenkins plugin configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JenkinsConfig {
    /// Build failure threshold
    pub failure_threshold: JenkinsFailureThreshold,
    /// Report output format
    pub report_format: JenkinsReportFormat,
    /// Notification configuration
    pub notifications: JenkinsNotificationConfig,
    /// Enable build history tracking
    pub track_history: bool,
    /// Custom build status message
    pub build_message: Option<String>,
    /// Include severity breakdown in output
    pub include_breakdown: bool,
    /// Highlight critical findings
    pub highlight_critical: bool,
    /// Maximum number of findings to display
    pub max_findings: Option<usize>,
}

impl Default for JenkinsConfig {
    fn default() -> Self {
        Self {
            failure_threshold: JenkinsFailureThreshold::default(),
            report_format: JenkinsReportFormat::default(),
            notifications: JenkinsNotificationConfig::default(),
            track_history: true,
            build_message: None,
            include_breakdown: true,
            highlight_critical: true,
            max_findings: Some(50),
        }
    }
}

impl JenkinsConfig {
    /// Create new Jenkins configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set failure threshold
    pub fn with_failure_threshold(mut self, threshold: JenkinsFailureThreshold) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set report format
    pub fn with_report_format(mut self, format: JenkinsReportFormat) -> Self {
        self.report_format = format;
        self
    }

    /// Enable notifications on failure
    pub fn with_notifications(mut self, enable: bool) -> Self {
        self.notifications.notify_on_failure = enable;
        self
    }

    /// Set maximum findings to display
    pub fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = Some(max);
        self
    }
}

/// Jenkins build step for Pipeline integration
#[derive(Clone, Debug)]
pub struct JenkinsBuildStep {
    /// Step name in Jenkins pipeline
    pub name: String,
    /// Warden command to execute
    pub command: String,
    /// Configuration for this step
    pub config: JenkinsConfig,
}

impl JenkinsBuildStep {
    /// Create a new Jenkins build step
    pub fn new(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: format!("warden scan {}", target.into()),
            config: JenkinsConfig::default(),
        }
    }

    /// Create build step with custom command
    pub fn with_command(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            config: JenkinsConfig::default(),
        }
    }

    /// Set configuration for this step
    pub fn with_config(mut self, config: JenkinsConfig) -> Self {
        self.config = config;
        self
    }

    /// Generate Jenkins Pipeline DSL for this step
    pub fn pipeline_dsl(&self) -> String {
        let threshold = match self.config.failure_threshold {
            JenkinsFailureThreshold::Never => "never",
            JenkinsFailureThreshold::Critical => "critical",
            JenkinsFailureThreshold::High => "high",
            JenkinsFailureThreshold::Medium => "medium",
            JenkinsFailureThreshold::Low => "low",
            JenkinsFailureThreshold::Always => "always",
        };

        format!(
            "stage('{0}') {{
    steps {{
        script {{
            try {{
                sh '{1}'
            }} catch (Exception e) {{
                currentBuild.result = 'FAILURE'
                throw e
            }}
        }}
    }}
    post {{
        failure {{
            echo 'Warden scan failed: {0}'
        }}
        unstable {{
            echo 'Warden scan found vulnerabilities above threshold ({2})'
        }}
    }}
}}
",
            self.name, self.command, threshold
        )
    }

    /// Generate Declarative Pipeline syntax
    pub fn declarative_pipeline(&self) -> String {
        format!(
            "stage('{0}') {{
    steps {{
        sh '{1}'
    }}
}}
",
            self.name, self.command
        )
    }
}

/// Jenkins console output formatter
pub struct JenkinsConsoleFormatter {
    config: JenkinsConfig,
}

impl JenkinsConsoleFormatter {
    /// Create new formatter with configuration
    pub fn new(config: JenkinsConfig) -> Self {
        Self { config }
    }

    /// Format scan report for Jenkins console output
    pub fn format_report(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&self.format_header(report));

        // Summary
        if self.config.include_breakdown {
            output.push_str(&self.format_summary(report));
        }

        // Findings
        output.push_str(&self.format_findings(report));

        // Build status
        output.push_str(&self.format_build_status(report));

        output
    }

    /// Format scan header
    fn format_header(&self, report: &ScanReport) -> String {
        format!(
            "\n{}\n{}\n",
            "=".repeat(80).cyan(),
            format!(
                "WARDEN SECURITY SCAN - {}",
                report.timestamp
            )
            .white()
            .bold()
        )
    }

    /// Format vulnerability summary
    fn format_summary(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n{} {}\n",
            "Target:".cyan().bold(),
            report.target
        ));
        output.push_str(&format!(
            "{}\n",
            "-".repeat(80).cyan()
        ));

        let summary = &report.summary;

        if summary.critical > 0 {
            output.push_str(&format!(
                "{} {}{} ",
                "o".red().bold(),
                "CRITICAL:".red().bold(),
                summary.critical
            ));
        }
        if summary.high > 0 {
            output.push_str(&format!(
                "{} {}{} ",
                "o".red().bold(),
                "HIGH:".red().bold(),
                summary.high
            ));
        }
        if summary.medium > 0 {
            output.push_str(&format!(
                "{} {}{} ",
                "o".yellow().bold(),
                "MEDIUM:".yellow().bold(),
                summary.medium
            ));
        }
        if summary.low > 0 {
            output.push_str(&format!(
                "{} {}{} ",
                "o".blue().bold(),
                "LOW:".blue().bold(),
                summary.low
            ));
        }
        if summary.info > 0 {
            output.push_str(&format!(
                "{} {}{} ",
                "o".white().bold(),
                "INFO:".white().bold(),
                summary.info
            ));
        }

        output.push_str(&format!(
            "{} {}{}\n",
            "o".white(),
            "TOTAL:".white().bold(),
            summary.total
        ));

        output
    }

    /// Format individual findings
    fn format_findings(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        if report.findings.is_empty() {
            output.push_str(&format!(
                "\n{}\n",
                "No vulnerabilities found!".green().bold()
            ));
            return output;
        }

        output.push_str(&format!(
            "\n{}\n",
            "VULNERABILITIES FOUND:".yellow().bold()
        ));
        output.push_str(&format!(
            "{}\n",
            "-".repeat(80).cyan()
        ));

        let max = self.config.max_findings.unwrap_or(report.findings.len());
        let findings: Vec<_> = report
            .findings
            .iter()
            .take(max)
            .collect();

        for (idx, vuln) in findings.iter().enumerate() {
            let severity_str = match vuln.severity {
                VulnSeverity::Critical => "[CRITICAL]".red().bold(),
                VulnSeverity::High => "[HIGH]".red(),
                VulnSeverity::Medium => "[MEDIUM]".yellow(),
                VulnSeverity::Low => "[LOW]".blue(),
                VulnSeverity::Info => "[INFO]".white(),
            };

            output.push_str(&format!(
                "\n{} {} {}\n",
                (idx + 1).to_string().cyan(),
                severity_str,
                vuln.title.bold()
            ));

            if let Some(ref location) = vuln.location {
                output.push_str(&format!(
                    "   {}\n",
                    format!("Location: {}", location).dimmed()
                ));
            }

            output.push_str(&format!(
                "   {}\n",
                vuln.description
            ));

            if let Some(ref recommendation) = vuln.recommendation {
                output.push_str(&format!(
                    "   {}\n",
                    format!("Recommendation: {}", recommendation).green()
                ));
            }

            if self.config.highlight_critical && vuln.severity == VulnSeverity::Critical {
                output.push_str(&format!(
                    "   {}\n",
                    ">>> CRITICAL VULNERABILITY - IMMEDIATE ACTION REQUIRED <<<".red().bold()
                ));
            }
        }

        if report.findings.len() > max {
            output.push_str(&format!(
                "\n... and {} more findings (use JSON report for full details)\n",
                report.findings.len() - max
            ));
        }

        output
    }

    /// Format build status result
    fn format_build_status(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "\n{}\n",
            "=".repeat(80).cyan()
        ));

        let should_fail = self.config.failure_threshold.should_fail(
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
        );

        if should_fail {
            output.push_str(&format!(
                "{}\n",
                "BUILD FAILED: Vulnerabilities exceed failure threshold".red().bold()
            ));
        } else if report.summary.total > 0 {
            output.push_str(&format!(
                "{}\n",
                "BUILD UNSTABLE: Vulnerabilities found but within threshold".yellow().bold()
            ));
        } else {
            output.push_str(&format!(
                "{}\n",
                "BUILD SUCCESS: No vulnerabilities detected".green().bold()
            ));
        }

        output
    }

    /// Format as parseable output for Jenkins plugins
    pub fn format_parseable(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        output.push_str("[WARDEN SCAN START]\n");
        output.push_str(&format!("target: {}\n", report.target));
        output.push_str(&format!("timestamp: {}\n", report.timestamp));

        for vuln in &report.findings {
            output.push_str("[FINDING]\n");
            output.push_str(&format!("severity: {}\n", vuln.severity));
            output.push_str(&format!("title: {}\n", vuln.title));
            output.push_str(&format!("description: {}\n", vuln.description));
            if let Some(ref location) = vuln.location {
                output.push_str(&format!("location: {}\n", location));
            }
            if let Some(ref cwe) = vuln.cwe {
                output.push_str(&format!("cwe: {}\n", cwe));
            }
        }

        output.push_str("[SUMMARY]\n");
        output.push_str(&format!("critical: {}\n", report.summary.critical));
        output.push_str(&format!("high: {}\n", report.summary.high));
        output.push_str(&format!("medium: {}\n", report.summary.medium));
        output.push_str(&format!("low: {}\n", report.summary.low));
        output.push_str(&format!("info: {}\n", report.summary.info));
        output.push_str(&format!("total: {}\n", report.summary.total));

        let should_fail = self.config.failure_threshold.should_fail(
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
        );
        output.push_str(&format!("build_status: {}\n", if should_fail { "FAILURE" } else { "SUCCESS" }));
        output.push_str("[WARDEN SCAN END]\n");

        output
    }
}

/// Main Jenkins plugin interface
pub struct JenkinsPlugin {
    config: JenkinsConfig,
}

impl JenkinsPlugin {
    /// Create new Jenkins plugin instance
    pub fn new(config: JenkinsConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn default_plugin() -> Self {
        Self::new(JenkinsConfig::default())
    }

    /// Process scan report and return Jenkins result
    pub fn process_report(&self, report: &ScanReport) -> JenkinsResult {
        let formatter = JenkinsConsoleFormatter::new(self.config.clone());
        let should_fail = self.config.failure_threshold.should_fail(
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
        );

        let output = match self.config.report_format {
            JenkinsReportFormat::Console => formatter.format_report(report),
            JenkinsReportFormat::Parseable => formatter.format_parseable(report),
            JenkinsReportFormat::Json => {
                serde_json::to_string_pretty(report).unwrap_or_else(|_| "Failed to serialize report".to_string())
            }
            JenkinsReportFormat::Combined => {
                format!(
                    "{}\n{}",
                    formatter.format_report(report),
                    formatter.format_parseable(report)
                )
            }
        };

        JenkinsResult {
            should_fail,
            exit_code: if should_fail { 1 } else { 0 },
            output,
            report: report.clone(),
        }
    }

    /// Generate Jenkinsfile content
    pub fn generate_jenkinsfile(&self, steps: &[JenkinsBuildStep]) -> String {
        let mut jenkinsfile = String::new();

        jenkinsfile.push_str("pipeline {\n");
        jenkinsfile.push_str("    agent any\n");
        jenkinsfile.push_str("    tools {\n");
        jenkinsfile.push_str("        // Install Warden - adjust version as needed\n");
        jenkinsfile.push_str("        // sh 'cargo install warden'\n");
        jenkinsfile.push_str("    }\n");
        jenkinsfile.push_str("    stages {\n");

        for step in steps {
            jenkinsfile.push_str(&step.declarative_pipeline());
        }

        jenkinsfile.push_str("    }\n");
        jenkinsfile.push_str("    post {\n");
        jenkinsfile.push_str("        always {\n");
        jenkinsfile.push_str("            // Archive Warden reports\n");
        jenkinsfile.push_str("            archiveArtifacts artifacts: 'warden-report.*', fingerprint: true\n");
        jenkinsfile.push_str("        }\n");
        jenkinsfile.push_str("        failure {\n");
        jenkinsfile.push_str("            emailext (\n");
        jenkinsfile.push_str("                subject: 'Build Failed: Warden Security Scan',\n");
        jenkinsfile.push_str("                body: 'Warden found critical vulnerabilities. Check the build logs.',\n");
        jenkinsfile.push_str("                to: '${DEFAULT_RECIPIENTS}'\n");
        jenkinsfile.push_str("            )\n");
        jenkinsfile.push_str("        }\n");
        jenkinsfile.push_str("    }\n");
        jenkinsfile.push_str("}\n");

        jenkinsfile
    }

    /// Generate scripted pipeline example
    pub fn generate_scripted_pipeline(&self, steps: &[JenkinsBuildStep]) -> String {
        let mut pipeline = String::new();

        pipeline.push_str("node {\n");
        pipeline.push_str("    try {\n");
        pipeline.push_str("        // Checkout code\n");
        pipeline.push_str("        checkout scm\n\n");

        for step in steps {
            pipeline.push_str(&format!("        stage('{}') {{\n", step.name));
            pipeline.push_str(&format!("            sh '{}'\n", step.command));
            pipeline.push_str("        }\n\n");
        }

        pipeline.push_str("    } catch (Exception e) {\n");
        pipeline.push_str("        currentBuild.result = 'FAILURE'\n");
        pipeline.push_str("        throw e\n");
        pipeline.push_str("    } finally {\n");
        pipeline.push_str("        // Archive reports\n");
        pipeline.push_str("        archiveArtifacts 'warden-report.*'\n");
        pipeline.push_str("    }\n");
        pipeline.push_str("}\n");

        pipeline
    }
}

/// Result of Jenkins scan processing
#[derive(Clone, Debug)]
pub struct JenkinsResult {
    /// Whether the build should fail
    pub should_fail: bool,
    /// Exit code for the build
    pub exit_code: i32,
    /// Formatted output
    pub output: String,
    /// Original scan report
    pub report: ScanReport,
}

impl fmt::Display for JenkinsResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::Target;

    fn create_test_report() -> ScanReport {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(crate::scanners::Vuln {
            severity: VulnSeverity::Critical,
            title: "SQL Injection".to_string(),
            description: "Critical SQL injection vulnerability found".to_string(),
            location: Some("/api/users?id=1".to_string()),
            recommendation: Some("Use parameterized queries".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        report.add_finding(crate::scanners::Vuln {
            severity: VulnSeverity::High,
            title: "XSS Vulnerability".to_string(),
            description: "Cross-site scripting vulnerability".to_string(),
            location: Some("/search?q=".to_string()),
            recommendation: Some("Sanitize user input".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        report
    }

    #[test]
    fn test_failure_threshold() {
        assert!(!JenkinsFailureThreshold::Never.should_fail(1, 1, 1, 1));
        assert!(JenkinsFailureThreshold::Critical.should_fail(1, 0, 0, 0));
        assert!(!JenkinsFailureThreshold::Critical.should_fail(0, 1, 0, 0));
        assert!(JenkinsFailureThreshold::High.should_fail(0, 1, 0, 0));
        assert!(JenkinsFailureThreshold::Medium.should_fail(0, 0, 1, 0));
        assert!(JenkinsFailureThreshold::Low.should_fail(0, 0, 0, 1));
        assert!(JenkinsFailureThreshold::Always.should_fail(0, 0, 0, 0));
    }

    #[test]
    fn test_failure_threshold_from_str() {
        assert_eq!(
            "never".parse::<JenkinsFailureThreshold>().unwrap(),
            JenkinsFailureThreshold::Never
        );
        assert_eq!(
            "critical".parse::<JenkinsFailureThreshold>().unwrap(),
            JenkinsFailureThreshold::Critical
        );
        assert_eq!(
            "high".parse::<JenkinsFailureThreshold>().unwrap(),
            JenkinsFailureThreshold::High
        );
    }

    #[test]
    fn test_jenkins_build_step() {
        let step = JenkinsBuildStep::new("Security Scan", "http://example.com");
        assert_eq!(step.name, "Security Scan");
        assert!(step.command.contains("http://example.com"));
    }

    #[test]
    fn test_jenkins_pipeline_dsl() {
        let step = JenkinsBuildStep::new("Security Scan", "http://example.com");
        let dsl = step.pipeline_dsl();
        assert!(dsl.contains("stage('Security Scan')"));
        assert!(dsl.contains("warden scan"));
    }

    #[test]
    fn test_jenkins_console_formatter() {
        let config = JenkinsConfig::default();
        let formatter = JenkinsConsoleFormatter::new(config);
        let report = create_test_report();

        let output = formatter.format_report(&report);
        assert!(output.contains("WARDEN SECURITY SCAN"));
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("SQL Injection"));
    }

    #[test]
    fn test_jenkins_parseable_format() {
        let config = JenkinsConfig::default();
        let formatter = JenkinsConsoleFormatter::new(config);
        let report = create_test_report();

        let output = formatter.format_parseable(&report);
        assert!(output.contains("[WARDEN SCAN START]"));
        assert!(output.contains("[FINDING]"));
        assert!(output.contains("severity:"));
        assert!(output.contains("[SUMMARY]"));
    }

    #[test]
    fn test_jenkins_plugin() {
        let plugin = JenkinsPlugin::default_plugin();
        let report = create_test_report();

        let result = plugin.process_report(&report);
        assert!(result.should_fail);
        assert_eq!(result.exit_code, 1);
        assert!(result.output.contains("WARDEN"));
    }

    #[test]
    fn test_jenkins_plugin_no_failure() {
        let config = JenkinsConfig {
            failure_threshold: JenkinsFailureThreshold::Never,
            ..Default::default()
        };
        let plugin = JenkinsPlugin::new(config);
        let report = create_test_report();

        let result = plugin.process_report(&report);
        assert!(!result.should_fail);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_jenkins_config_builder() {
        let config = JenkinsConfig::new()
            .with_failure_threshold(JenkinsFailureThreshold::High)
            .with_report_format(JenkinsReportFormat::Json)
            .with_notifications(true)
            .with_max_findings(100);

        assert_eq!(config.failure_threshold, JenkinsFailureThreshold::High);
        assert_eq!(config.report_format, JenkinsReportFormat::Json);
        assert!(config.notifications.notify_on_failure);
        assert_eq!(config.max_findings, Some(100));
    }
}
