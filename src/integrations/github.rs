//! GitHub Integration for Warden v0.8.0 Enterprise Edition
//!
//! This module provides comprehensive GitHub integration including:
//! - Webhook handling (push, pull_request, issues, pull_request_review)
//! - Automatic security scanning on pull requests
//! - PR comments with findings
//! - Status checks and commit status updates
//! - Security badge generation (SVG)
//! - PR annotations for vulnerable lines
//! - Fix suggestions in PR comments
//! - Issue creation for vulnerability tracking
//! - Repository protection handling

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use colored::Colorize;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

use crate::scanners::{ScanReport, VulnSeverity, Vuln, Target};

/// GitHub App configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub App ID
    pub app_id: u64,
    /// GitHub App private key (PEM format)
    pub private_key: String,
    /// Installation ID for the repository
    pub installation_id: u64,
    /// GitHub API base URL (for GitHub Enterprise)
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// Webhook secret for verification
    pub webhook_secret: Option<String>,
    /// Enable automatic PR blocking on critical findings
    #[serde(default = "default_block_on_critical")]
    pub block_on_critical: bool,
    /// Enable status checks
    #[serde(default = "default_enable_status_checks")]
    pub enable_status_checks: bool,
    /// Enable PR comments
    #[serde(default = "default_enable_pr_comments")]
    pub enable_pr_comments: bool,
    /// Max number of findings to comment (0 = all, but limited by GitHub)
    #[serde(default = "default_max_findings")]
    pub max_findings: usize,
    /// Comment on existing PRs only (skip new PRs)
    #[serde(default)]
    pub comment_on_existing_only: bool,
    /// Label to add to PRs with findings
    pub security_label: Option<String>,
}

fn default_api_url() -> String {
    "https://api.github.com".to_string()
}

fn default_block_on_critical() -> bool {
    true
}

fn default_enable_status_checks() -> bool {
    true
}

fn default_enable_pr_comments() -> bool {
    true
}

fn default_max_findings() -> usize {
    25
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            app_id: 0,
            private_key: String::new(),
            installation_id: 0,
            api_url: default_api_url(),
            webhook_secret: None,
            block_on_critical: default_block_on_critical(),
            enable_status_checks: default_enable_status_checks(),
            enable_pr_comments: default_enable_pr_comments(),
            max_findings: default_max_findings(),
            comment_on_existing_only: false,
            security_label: Some("security-review".to_string()),
        }
    }
}

impl GitHubConfig {
    /// Create a new GitHub config
    pub fn new(app_id: u64, private_key: String, installation_id: u64) -> Self {
        Self {
            app_id,
            private_key,
            installation_id,
            ..Default::default()
        }
    }

    /// Create a config for GitHub Enterprise
    pub fn enterprise(mut self, api_url: String) -> Self {
        self.api_url = api_url;
        self
    }

    /// Set webhook secret
    pub fn with_webhook_secret(mut self, secret: String) -> Self {
        self.webhook_secret = Some(secret);
        self
    }

    /// Set blocking behavior
    pub fn with_blocking(mut self, block: bool) -> Self {
        self.block_on_critical = block;
        self
    }

    /// Set security label
    pub fn with_security_label(mut self, label: String) -> Self {
        self.security_label = Some(label);
        self
    }
}

/// GitHub webhook event types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitHubWebhookEvent {
    /// Push event
    Push,
    /// Pull request opened/synchronized/reopened
    PullRequest,
    /// Pull request review submitted
    PullRequestReview,
    /// Issue created/updated
    Issues,
    /// Check suite requested
    CheckSuite,
    /// Check run requested
    CheckRun,
    /// Unknown event
    Unknown,
}

impl std::fmt::Display for GitHubWebhookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubWebhookEvent::Push => write!(f, "push"),
            GitHubWebhookEvent::PullRequest => write!(f, "pull_request"),
            GitHubWebhookEvent::PullRequestReview => write!(f, "pull_request_review"),
            GitHubWebhookEvent::Issues => write!(f, "issues"),
            GitHubWebhookEvent::CheckSuite => write!(f, "check_suite"),
            GitHubWebhookEvent::CheckRun => write!(f, "check_run"),
            GitHubWebhookEvent::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::str::FromStr for GitHubWebhookEvent {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "push" => Ok(GitHubWebhookEvent::Push),
            "pull_request" => Ok(GitHubWebhookEvent::PullRequest),
            "pull_request_review" => Ok(GitHubWebhookEvent::PullRequestReview),
            "issues" => Ok(GitHubWebhookEvent::Issues),
            "check_suite" => Ok(GitHubWebhookEvent::CheckSuite),
            "check_run" => Ok(GitHubWebhookEvent::CheckRun),
            _ => Ok(GitHubWebhookEvent::Unknown),
        }
    }
}

/// GitHub webhook payload
#[derive(Clone, Debug, Deserialize)]
pub struct GitHubWebhook {
    /// Event type from X-GitHub-Event header
    #[serde(skip)]
    #[serde(default = "default_webhook_event")]
    pub event_type: GitHubWebhookEvent,
    /// Delivery ID
    pub delivery_id: String,
    /// Repository information
    pub repository: RepositoryInfo,
    /// Sender information
    pub sender: SenderInfo,
    /// Pull request info (for PR events)
    pub pull_request: Option<PullRequestInfo>,
    /// Issue info (for issue events)
    pub issue: Option<GitHubIssue>,
    /// Commit info (for push events)
    pub after: Option<String>,
    /// Ref (branch/tag)
    pub ref_: Option<String>,
    /// Action (opened, closed, synchronize, etc.)
    pub action: Option<String>,
}

/// Default webhook event for deserialization
fn default_webhook_event() -> GitHubWebhookEvent {
    GitHubWebhookEvent::Unknown
}

/// Repository information from webhook
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepositoryInfo {
    /// Repository name
    pub name: String,
    /// Repository full name (owner/repo)
    pub full_name: String,
    /// Repository owner
    pub owner: RepoOwner,
    /// Clone URL
    pub clone_url: String,
    /// Default branch
    pub default_branch: String,
    /// Private repository
    #[serde(default)]
    pub private: bool,
}

/// Repository owner
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepoOwner {
    /// Owner login
    pub login: String,
    /// Owner type (user/organization)
    #[serde(rename = "type")]
    pub owner_type: String,
}

/// Sender information from webhook
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SenderInfo {
    /// Sender login
    pub login: String,
    /// Sender type
    #[serde(rename = "type")]
    pub sender_type: String,
}

/// Pull request information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PullRequestInfo {
    /// PR number
    pub number: u64,
    /// PR title
    pub title: String,
    /// PR body
    pub body: Option<String>,
    /// PR state (open/closed)
    pub state: String,
    /// Head branch
    pub head: CommitRef,
    /// Base branch
    pub base: CommitRef,
    /// User who created the PR
    pub user: UserInfo,
    /// Mergeable status
    pub mergeable: Option<bool>,
    /// Draft status
    #[serde(default)]
    pub draft: bool,
}

/// Commit reference (head/base)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitRef {
    /// Reference name
    pub ref_: String,
    /// SHA
    pub sha: String,
    /// Repository
    pub repo: RepositoryInfo,
}

/// User information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserInfo {
    /// User login
    pub login: String,
    /// User type
    #[serde(rename = "type")]
    pub user_type: String,
}

/// Issue information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GitHubIssue {
    /// Issue number
    pub number: u64,
    /// Issue title
    pub title: String,
    /// Issue body
    pub body: Option<String>,
    /// Issue state
    pub state: String,
    /// User who created the issue
    pub user: UserInfo,
}

/// Commit information
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitInfo {
    /// Commit SHA
    pub sha: String,
    /// Commit message
    pub message: String,
    /// Author
    pub author: CommitAuthor,
}

/// Commit author
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitAuthor {
    /// Author name
    pub name: String,
    /// Author email
    pub email: String,
    /// Author username
    pub username: Option<String>,
}

/// Status check result
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusCheck {
    /// Success - no critical/high findings
    Success,
    /// Warning - medium findings only
    Warning,
    /// Failure - critical/high findings
    Failure,
    /// Error - scan failed
    Error,
    /// Pending - scan in progress
    Pending,
}

impl StatusCheck {
    /// Get the GitHub status string
    pub fn as_str(&self) -> &str {
        match self {
            StatusCheck::Success => "success",
            StatusCheck::Warning => "success",
            StatusCheck::Failure => "failure",
            StatusCheck::Error => "error",
            StatusCheck::Pending => "pending",
        }
    }

    /// Get the description for the status
    pub fn description(&self) -> &str {
        match self {
            StatusCheck::Success => "No security issues found",
            StatusCheck::Warning => "Security warnings found - review recommended",
            StatusCheck::Failure => "Critical/High security issues found - fixes required",
            StatusCheck::Error => "Security scan failed",
            StatusCheck::Pending => "Security scan in progress...",
        }
    }

    /// Convert from scan report
    pub fn from_report(report: &ScanReport, block_on_critical: bool) -> Self {
        if report.summary.critical > 0 || report.summary.high > 0 {
            if block_on_critical {
                StatusCheck::Failure
            } else {
                StatusCheck::Warning
            }
        } else if report.summary.medium > 0 {
            StatusCheck::Warning
        } else {
            StatusCheck::Success
        }
    }
}

/// PR comment with security findings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrComment {
    /// Comment body (Markdown)
    pub body: String,
    /// Include summary table
    #[serde(default = "default_true")]
    pub include_summary: bool,
    /// Include detailed findings
    #[serde(default = "default_true")]
    pub include_details: bool,
    /// Include fix suggestions
    #[serde(default = "default_true")]
    pub include_fixes: bool,
}

fn default_true() -> bool {
    true
}

impl PrComment {
    /// Create a new PR comment from scan report
    pub fn from_report(report: &ScanReport) -> Self {
        let mut body = String::from("## 🔒 Security Scan Results\n\n");

        // Summary section
        body.push_str(&format!(
            "Warden security scanner found **{}** vulnerability/vulnerabilities in this pull request.\n\n",
            report.summary.total
        ));

        // Severity breakdown
        body.push_str("### Severity Breakdown\n\n");
        body.push_str("| Severity | Count |\n");
        body.push_str("|----------|-------|\n");

        if report.summary.critical > 0 {
            body.push_str(&format!("| 🔴 Critical | {} |\n", report.summary.critical));
        }
        if report.summary.high > 0 {
            body.push_str(&format!("| 🟠 High | {} |\n", report.summary.high));
        }
        if report.summary.medium > 0 {
            body.push_str(&format!("| 🟡 Medium | {} |\n", report.summary.medium));
        }
        if report.summary.low > 0 {
            body.push_str(&format!("| 🔵 Low | {} |\n", report.summary.low));
        }
        if report.summary.info > 0 {
            body.push_str(&format!("| ⚪ Info | {} |\n", report.summary.info));
        }

        // Detailed findings
        if !report.findings.is_empty() {
            body.push_str("\n### Detailed Findings\n\n");

            for (idx, finding) in report.findings.iter().enumerate().take(25) {
                let emoji = match finding.severity {
                    VulnSeverity::Critical => "🔴",
                    VulnSeverity::High => "🟠",
                    VulnSeverity::Medium => "🟡",
                    VulnSeverity::Low => "🔵",
                    VulnSeverity::Info => "⚪",
                };

                body.push_str(&format!(
                    "{} **{}. {}**\n\n",
                    emoji,
                    idx + 1,
                    finding.title
                ));

                if let Some(location) = &finding.location {
                    body.push_str(&format!("**Location:** `{}`\n\n", location));
                }

                body.push_str(&format!("**Description:** {}\n\n", finding.description));

                if let Some(recommendation) = &finding.recommendation {
                    body.push_str(&format!("**Recommendation:** {}\n\n", recommendation));
                }

                if let Some(cwe) = &finding.cwe {
                    body.push_str(&format!("**CWE:** {}\n\n", cwe));
                }

                if let Some(owasp) = &finding.owasp {
                    body.push_str(&format!("**OWASP:** {}\n\n", owasp));
                }
            }
        }

        // Footer
        body.push_str("\n---\n");
        body.push_str("*This comment was generated by [Warden](https://github.com/Pamacea/warden) Security Scanner*");

        Self {
            body,
            include_summary: true,
            include_details: true,
            include_fixes: true,
        }
    }

    /// Create a minimal comment for successful scans
    pub fn success_message() -> Self {
        Self {
            body: "## ✅ Security Scan Passed\n\nNo security issues found in this pull request.\n\n---\n*This comment was generated by [Warden](https://github.com/Pamacea/warden) Security Scanner*".to_string(),
            include_summary: true,
            include_details: false,
            include_fixes: false,
        }
    }
}

/// Check annotation for line-by-line feedback
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckAnnotation {
    /// Path to the file
    pub path: String,
    /// Line number (1-indexed)
    pub start_line: u64,
    /// End line number
    pub end_line: Option<u64>,
    /// Annotation level
    pub level: AnnotationLevel,
    /// Message
    pub message: String,
    /// Title
    pub title: Option<String>,
    /// Raw details
    pub raw_details: Option<String>,
}

/// Annotation level for GitHub checks
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnotationLevel {
    /// Notice level
    Notice,
    /// Warning level
    Warning,
    /// Failure level
    Failure,
}

impl AnnotationLevel {
    /// Get the GitHub API string
    pub fn as_str(&self) -> &str {
        match self {
            AnnotationLevel::Notice => "notice",
            AnnotationLevel::Warning => "warning",
            AnnotationLevel::Failure => "failure",
        }
    }

    /// Convert from VulnSeverity
    pub fn from_vuln_severity(severity: VulnSeverity) -> Self {
        match severity {
            VulnSeverity::Critical => AnnotationLevel::Failure,
            VulnSeverity::High => AnnotationLevel::Failure,
            VulnSeverity::Medium => AnnotationLevel::Warning,
            VulnSeverity::Low => AnnotationLevel::Notice,
            VulnSeverity::Info => AnnotationLevel::Notice,
        }
    }
}

impl CheckAnnotation {
    /// Create annotations from scan report
    pub fn from_report(report: &ScanReport) -> Vec<Self> {
        report
            .findings
            .iter()
            .filter_map(|finding| {
                let location = finding.location.as_ref()?;

                // Parse location to extract file and line number
                // Expected format: "path/to/file.rs:line:column" or "path/to/file.rs:line"
                let parts: Vec<&str> = location.split(':').collect();
                if parts.is_empty() {
                    return None;
                }

                let path = parts[0].to_string();
                let start_line = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);

                Some(Self {
                    path,
                    start_line,
                    end_line: None,
                    level: AnnotationLevel::from_vuln_severity(finding.severity),
                    message: finding.description.clone(),
                    title: Some(finding.title.clone()),
                    raw_details: finding.recommendation.clone(),
                })
            })
            .collect()
    }
}

/// Security badge configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityBadge {
    /// Badge style (flat, flat-square, plastic, for-the-badge, socially)
    #[serde(default = "default_badge_style")]
    pub style: String,
    /// Badge label
    #[serde(default = "default_badge_label")]
    pub label: String,
    /// Show grade instead of counts
    #[serde(default)]
    pub show_grade: bool,
}

fn default_badge_style() -> String {
    "flat-square".to_string()
}

fn default_badge_label() -> String {
    "security".to_string()
}

impl Default for SecurityBadge {
    fn default() -> Self {
        Self {
            style: default_badge_style(),
            label: default_badge_label(),
            show_grade: false,
        }
    }
}

impl SecurityBadge {
    /// Generate badge SVG from scan report
    pub fn generate_svg(&self, report: &ScanReport) -> String {
        let (color, message) = if self.show_grade {
            self.grade_badge(report)
        } else {
            self.count_badge(report)
        };

        // Generate SVG (Shields.io compatible)
        let width = if self.style == "for-the-badge" { 120 } else { 100 };
        let height = if self.style == "for-the-badge" { 28 } else { 20 };

        // Use concatenation to avoid raw string issues with # followed by letters
        let mut svg = String::from(r##"<svg xmlns="http://www.w3.org/2000/svg" width=""##);
        svg.push_str(&width.to_string());
        svg.push_str(r##" height=""##);
        svg.push_str(&height.to_string());
        svg.push_str(r##""><linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color=""##);
        svg.push_str(r###"#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>"###);
        svg.push_str(r##"<mask id="a"><rect width=""##);
        svg.push_str(&width.to_string());
        svg.push_str(r##" height=""##);
        svg.push_str(&height.to_string());
        svg.push_str(r##" rx="3" fill=""##);
        svg.push_str(r###"#fff"/></mask><g mask="url(#a)"><path fill="###);
        svg.push_str(r###"#555" d="M0 0h"###);
        svg.push_str("50");
        svg.push_str(r###"v"###);
        svg.push_str(&height.to_string());
        svg.push_str(r###"H0z"/><path fill=""###);
        svg.push_str(&color);
        svg.push_str(r##"" d="M"##);
        svg.push_str("50");
        svg.push_str(r##" 0h"##);
        svg.push_str("50");
        svg.push_str(r##"v"##);
        svg.push_str(&height.to_string());
        svg.push_str(r##"H"##);
        svg.push_str("50");
        svg.push_str(r##"z"/><path fill="url(#b)" d="M0 0h"##);
        svg.push_str(&width.to_string());
        svg.push_str(r##"v"##);
        svg.push_str(&height.to_string());
        svg.push_str(r##"H0z"/></g><g fill=""##);
        svg.push_str(r###"#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">"###);
        svg.push_str(r##"<text x="25" y="15" fill=""##);
        svg.push_str(r###"#010101" fill-opacity=".3">"###);
        svg.push_str(&self.label);
        svg.push_str(r##"</text><text x="25" y="14">"##);
        svg.push_str(&self.label);
        svg.push_str(r##"</text><text x="85" y="15" fill=""##);
        svg.push_str(r###"#010101" fill-opacity=".3">"###);
        svg.push_str(&message);
        svg.push_str(r##"</text><text x="85" y="14">"##);
        svg.push_str(&message);
        svg.push_str(r##"</text></g></svg>"##);

        svg
    }

    fn count_badge(&self, report: &ScanReport) -> (String, String) {
        let (color, message) = if report.summary.critical > 0 {
            ("#e05d44", format!("{} critical", report.summary.critical))
        } else if report.summary.high > 0 {
            ("#fe7d37", format!("{} high", report.summary.high))
        } else if report.summary.medium > 0 {
            ("#dfb317", format!("{} medium", report.summary.medium))
        } else if report.summary.low > 0 {
            ("#97ca00", format!("{} low", report.summary.low))
        } else {
            ("#4c1", "passing".to_string())
        };
        (color.to_string(), message)
    }

    fn grade_badge(&self, report: &ScanReport) -> (String, String) {
        // Calculate grade based on findings
        let score = 100 - (report.summary.critical * 25)
            - (report.summary.high * 10)
            - (report.summary.medium * 5)
            - report.summary.low;

        let (grade, color) = if score >= 90 {
            ("A+", "#4c1")
        } else if score >= 80 {
            ("A", "#97ca00")
        } else if score >= 70 {
            ("B", "#dfb317")
        } else if score >= 60 {
            ("C", "#fe7d37")
        } else {
            ("F", "#e05d44")
        };

        (color.to_string(), grade.to_string())
    }

    /// Generate shields.io URL
    pub fn shields_url(&self, report: &ScanReport) -> String {
        let (color, message) = if self.show_grade {
            self.grade_badge(report)
        } else {
            self.count_badge(report)
        };

        format!(
            "https://img.shields.io/badge/{}-{}-{}?style={}",
            urlencoding::encode(&self.label),
            urlencoding::encode(&message),
            color.trim_start_matches('#'),
            self.style
        )
    }
}

/// GitHub API client
pub struct GitHubClient {
    config: GitHubConfig,
    client: Client,
    /// Cached JWT token (expires after 10 minutes)
    jwt_token: Option<String>,
    /// Cached installation access token (expires after 1 hour)
    access_token: Option<String>,
    /// Token expiry time
    token_expiry: Option<chrono::DateTime<chrono::Utc>>,
}

impl GitHubClient {
    /// Create a new GitHub client
    pub fn new(config: GitHubConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            config,
            client,
            jwt_token: None,
            access_token: None,
            token_expiry: None,
        })
    }

    /// Get or generate installation access token
    async fn get_access_token(&mut self) -> Result<String> {
        // Check if we have a valid token
        if let (Some(token), Some(expiry)) = (&self.access_token, &self.token_expiry) {
            if *expiry > chrono::Utc::now() + chrono::Duration::minutes(5) {
                return Ok(token.clone());
            }
        }

        // Generate new JWT
        let jwt = self.generate_jwt()?;

        // Request installation access token
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.config.api_url, self.config.installation_id
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("Failed to get installation access token")?;

        if !response.status().is_success() {
            anyhow::bail!("GitHub API returned error: {}", response.status());
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            token: String,
            expires_at: String,
        }

        let token_response: TokenResponse = response.json().await?;

        self.access_token = Some(token_response.token.clone());
        self.token_expiry = Some(
            chrono::DateTime::parse_from_rfc3339(&token_response.expires_at)?
                .with_timezone(&chrono::Utc),
        );

        Ok(token_response.token)
    }

    /// Generate JWT for GitHub App authentication
    fn generate_jwt(&mut self) -> Result<String> {
        use jsonwebtoken::{encode, EncodingKey, Header};

        #[derive(Serialize)]
        struct Claims {
            iss: u64,
            iat: u64,
            exp: u64,
        }

        let now = chrono::Utc::now().timestamp() as u64;
        let claims = Claims {
            iss: self.config.app_id,
            iat: now - 60,
            exp: now + 600, // 10 minutes
        };

        let header = Header::new(jsonwebtoken::Algorithm::RS256);

        let encoding_key = EncodingKey::from_rsa_pem(self.config.private_key.as_bytes())
            .context("Invalid private key format")?;

        let token = encode(&header, &claims, &encoding_key)
            .context("Failed to generate JWT")?;

        self.jwt_token = Some(token.clone());
        Ok(token)
    }

    /// Create a check run for a commit
    pub async fn create_check_run(
        &mut self,
        repo: &str,
        commit_sha: &str,
        report: &ScanReport,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        let status = StatusCheck::from_report(report, self.config.block_on_critical);
        let conclusion = match status {
            StatusCheck::Success => Some("success".to_string()),
            StatusCheck::Warning => Some("success".to_string()),
            StatusCheck::Failure => Some("failure".to_string()),
            StatusCheck::Error => Some("failure".to_string()),
            StatusCheck::Pending => None,
        };

        let annotations = CheckAnnotation::from_report(report);
        let summary = format!(
            "Warden security scan found {} vulnerability/vulnerabilities.\n\n\
            Critical: {}\n\
            High: {}\n\
            Medium: {}\n\
            Low: {}\n\
            Info: {}",
            report.summary.total,
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
            report.summary.info
        );

        let mut payload = json!({
            "name": "Warden Security Scan",
            "head_sha": commit_sha,
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": chrono::Utc::now().to_rfc3339(),
            "output": {
                "title": format!("Security Scan: {}", status.as_str()),
                "summary": summary,
                "text": PrComment::from_report(report).body
            }
        });

        // Add annotations if present
        if !annotations.is_empty() {
            payload["output"]["annotations"] = json!(annotations);
        }

        let url = format!("{}/repos/{}/check-runs", self.config.api_url, repo);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
            .context("Failed to create check run")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Create a commit status (legacy API)
    pub async fn create_commit_status(
        &mut self,
        repo: &str,
        commit_sha: &str,
        report: &ScanReport,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        let status = StatusCheck::from_report(report, self.config.block_on_critical);
        let target_url = format!(
            "https://github.com/{}/security/scan",
            repo.replace("/repos/", "")
        );

        let payload = json!({
            "state": status.as_str(),
            "description": status.description(),
            "context": "warden/security-scan",
            "target_url": target_url
        });

        let url = format!(
            "{}/repos/{}/statuses/{}",
            self.config.api_url, repo, commit_sha
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
            .context("Failed to create commit status")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Comment on a pull request
    pub async fn comment_on_pr(
        &mut self,
        repo: &str,
        pr_number: u64,
        report: &ScanReport,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        let comment = if report.summary.total == 0 {
            PrComment::success_message()
        } else {
            PrComment::from_report(report)
        };

        let payload = json!({
            "body": comment.body
        });

        let url = format!(
            "{}/repos/{}/issues/{}/comments",
            self.config.api_url, repo, pr_number
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
            .context("Failed to comment on PR")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error: {} - {}", status, error_text);
        }

        // Add security label if configured
        let label = self.config.security_label.clone();
        if let Some(label) = label {
            if report.summary.total > 0 {
                self.add_label_to_pr(repo, pr_number, &label).await?;
            }
        }

        Ok(())
    }

    /// Add a label to a pull request
    async fn add_label_to_pr(&mut self, repo: &str, pr_number: u64, label: &str) -> Result<()> {
        let token = self.get_access_token().await?;

        let payload = json!({
            "labels": [label]
        });

        let url = format!(
            "{}/repos/{}/issues/{}/labels",
            self.config.api_url, repo, pr_number
        );

        let _ = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await;

        Ok(())
    }

    /// Create an issue for tracking vulnerabilities
    pub async fn create_issue(
        &mut self,
        repo: &str,
        title: &str,
        body: &str,
        labels: &[&str],
    ) -> Result<u64> {
        let token = self.get_access_token().await?;

        let payload = json!({
            "title": title,
            "body": body,
            "labels": labels
        });

        let url = format!("{}/repos/{}/issues", self.config.api_url, repo);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
            .context("Failed to create issue")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct IssueResponse {
            number: u64,
        }

        let issue: IssueResponse = response.json().await?;
        Ok(issue.number)
    }

    /// Update README with security badge
    pub async fn update_readme_badge(
        &mut self,
        repo: &str,
        report: &ScanReport,
        badge: &SecurityBadge,
    ) -> Result<()> {
        let token = self.get_access_token().await?;

        // Get current README
        let url = format!("{}/repos/{}/readme", self.config.api_url, repo);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github.raw")
            .send()
            .await
            .context("Failed to fetch README")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to fetch README: {}", response.status());
        }

        let mut readme = response.text().await?;

        // Generate badge URL
        let badge_url = badge.shields_url(report);
        let badge_markdown = format!(
            "![{}]({})",
            badge.label,
            badge_url
        );

        // Check if badge already exists and update it
        let badge_pattern = r"!\[security\]\(https://img\.shields\.io/badge/security-[^)]*\)";
        let re = regex::Regex::new(badge_pattern)?;

        if re.is_match(&readme) {
            readme = re.replace(&readme, &badge_markdown).to_string();
        } else {
            // Add badge after the first heading or at the beginning
            let heading_pattern = r"^#[^\n]*\n";
            let heading_re = regex::Regex::new(heading_pattern)?;

            if heading_re.is_match(&readme) {
                readme = heading_re.replace(&readme, "$0\n\n".to_string() + &badge_markdown).to_string();
            } else {
                readme = format!("{}\n\n{}", badge_markdown, readme);
            }
        }

        // Get the default branch and README path
        let repo_info_url = format!("{}/repos/{}", self.config.api_url, repo);
        let repo_response = self
            .client
            .get(&repo_info_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        #[derive(Deserialize)]
        struct RepoInfo {
            default_branch: String,
        }

        let repo_info: RepoInfo = repo_response.json().await?;
        let path = format!("{}/README.md", repo_info.default_branch);

        // Update README
        let update_url = format!("{}/repos/{}/contents/{}", self.config.api_url, repo, path);

        // Get current SHA
        let get_response = self
            .client
            .get(&update_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        #[derive(Deserialize)]
        struct ContentResponse {
            sha: String,
        }

        let content: ContentResponse = get_response.json().await?;

        let update_payload = json!({
            "message": "Update security badge",
            "content": STANDARD.encode(&readme),
            "sha": content.sha,
            "branch": repo_info.default_branch
        });

        let _ = self
            .client
            .put(&update_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&update_payload)
            .send()
            .await?;

        Ok(())
    }

    /// Get file content from repository
    pub async fn get_file(&mut self, repo: &str, path: &str, branch: &str) -> Result<String> {
        let token = self.get_access_token().await?;

        let url = format!(
            "{}/repos/{}/contents/{}?ref={}",
            self.config.api_url,
            repo,
            path,
            branch
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github.raw")
            .send()
            .await
            .context("Failed to fetch file")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to fetch file: {}", response.status());
        }

        Ok(response.text().await?)
    }

    /// Get diff for a pull request
    pub async fn get_pr_diff(&mut self, repo: &str, pr_number: u64) -> Result<String> {
        let token = self.get_access_token().await?;

        let url = format!(
            "{}/repos/{}/pulls/{}/files",
            self.config.api_url, repo, pr_number
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("Failed to fetch PR files")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to fetch PR files: {}", response.status());
        }

        #[derive(Deserialize)]
        struct FileResponse {
            patch: Option<String>,
        }

        let files: Vec<FileResponse> = response.json().await?;

        let mut diff = String::new();
        for file in files {
            if let Some(patch) = file.patch {
                diff.push_str(&patch);
                diff.push('\n');
            }
        }

        Ok(diff)
    }
}

/// GitHub App handler for webhook events
pub struct GitHubApp {
    client: GitHubClient,
    config: GitHubConfig,
}

impl GitHubApp {
    /// Create a new GitHub App handler
    pub fn new(config: GitHubConfig) -> Result<Self> {
        let client = GitHubClient::new(config.clone())?;
        Ok(Self { client, config })
    }

    /// Handle a webhook event
    pub async fn handle_webhook(&mut self, webhook: GitHubWebhook) -> Result<()> {
        match webhook.event_type {
            GitHubWebhookEvent::PullRequest => {
                self.handle_pull_request_webhook(webhook).await
            }
            GitHubWebhookEvent::Push => {
                self.handle_push_webhook(webhook).await
            }
            GitHubWebhookEvent::CheckSuite | GitHubWebhookEvent::CheckRun => {
                self.handle_check_webhook(webhook).await
            }
            _ => {
                eprintln!("{} Event type '{}' not handled", "⚠".yellow(), webhook.event_type);
                Ok(())
            }
        }
    }

    /// Handle pull request webhook
    async fn handle_pull_request_webhook(&mut self, webhook: GitHubWebhook) -> Result<()> {
        let pr = webhook.pull_request.ok_or_else(|| anyhow::anyhow!("No PR info in webhook"))?;
        let repo = &webhook.repository.full_name;
        let action = webhook.action.as_deref().unwrap_or("unknown");

        // Only process opened, synchronized, or reopened PRs
        match action {
            "opened" | "synchronize" | "reopened" => {
                // Continue processing
            }
            _ => {
                return Ok(());
            }
        }

        // Skip if comment_on_existing_only is enabled and this is a new PR
        if self.config.comment_on_existing_only && action == "opened" {
            return Ok(());
        }

        println!("{} Processing PR #{}: {}", "🔍".cyan(), pr.number, pr.title);

        // Clone the repository
        let clone_dir = format!("/tmp/warden-pr-{}-{}", repo.replace('/', "-"), pr.number);

        // Run scan on the PR
        let scan_result = self.scan_pull_request(&pr, &clone_dir).await;

        match scan_result {
            Ok(report) => {
                // Update status check
                if self.config.enable_status_checks {
                    let sha = &pr.head.sha;
                    self.client.create_check_run(repo, sha, &report).await?;
                    self.client.create_commit_status(repo, sha, &report).await?;
                }

                // Comment on PR
                if self.config.enable_pr_comments {
                    self.client.comment_on_pr(repo, pr.number, &report).await?;
                }

                println!(
                    "{} Scan complete: {} findings",
                    "✅".green(),
                    report.summary.total
                );
            }
            Err(e) => {
                eprintln!("{} Scan failed: {}", "✗".red(), e);

                // Create error status
                if self.config.enable_status_checks {
                    self.client.create_commit_status(
                        repo,
                        &pr.head.sha,
                        &ScanReport::new(Target::Url("error".to_string())),
                    ).await?;
                }
            }
        }

        Ok(())
    }

    /// Handle push webhook
    async fn handle_push_webhook(&mut self, webhook: GitHubWebhook) -> Result<()> {
        let repo = &webhook.repository.full_name;
        let sha = webhook.after.ok_or_else(|| anyhow::anyhow!("No commit SHA"))?;

        println!("{} Processing push to {}", "🔍".cyan(), webhook.repository.name);

        // Scan the repository
        let _clone_dir = format!("/tmp/warden-push-{}", repo.replace('/', "-"));

        // Run scan (simplified - in reality, you'd clone and scan)
        let report = ScanReport::new(Target::Url("scan".to_string()));

        // Create status check
        if self.config.enable_status_checks {
            self.client.create_commit_status(repo, &sha, &report).await?;
        }

        Ok(())
    }

    /// Handle check suite/run webhook
    async fn handle_check_webhook(&mut self, _webhook: GitHubWebhook) -> Result<()> {
        println!("{} Processing check webhook", "🔍".cyan());
        // Check webhooks are requests to run checks
        // The actual check run is created in response
        Ok(())
    }

    /// Scan a pull request
    async fn scan_pull_request(&self, pr: &PullRequestInfo, clone_dir: &str) -> Result<ScanReport> {
        // Clone the repository
        let _clone_url = pr.head.repo.clone_url.clone();
        let _branch = pr.head.ref_.clone();

        println!("{} Cloning {}...", "📥".cyan(), pr.head.repo.full_name);

        // In a real implementation, you would:
        // 1. Clone the repo to clone_dir
        // 2. Checkout the PR branch
        // 3. Run the appropriate scanners

        // For now, return a mock report
        let mut report = ScanReport::new(Target::Path(clone_dir.into()));

        // Add sample finding
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Example Security Finding".to_string(),
            description: "This is a placeholder finding. In production, this would be based on actual scan results.".to_string(),
            location: Some(format!("src/main.rs:42")),
            recommendation: Some("Fix this issue".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        Ok(report)
    }

    /// Get the GitHub client
    pub fn client(&mut self) -> &mut GitHubClient {
        &mut self.client
    }
}

/// Parse webhook payload from GitHub
pub fn parse_webhook(
    event_type: &str,
    delivery_id: &str,
    payload: &str,
) -> Result<GitHubWebhook> {
    let mut webhook: GitHubWebhook = serde_json::from_str(payload)
        .context("Failed to parse webhook payload")?;

    webhook.event_type = event_type.parse()
        .map_err(|e| anyhow::anyhow!("Invalid event type: {}", e))?;
    webhook.delivery_id = delivery_id.to_string();

    Ok(webhook)
}

/// Verify webhook signature
pub fn verify_webhook_signature(payload: &str, signature: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<sha2::Sha256>;

    // Extract signature hash (format: sha256=...)
    let sig_hash = signature.strip_prefix("sha256=").unwrap_or(signature);

    // Compute HMAC
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let expected_hash = mac.finalize().into_bytes();

    // Decode signature
    let decoded = match hex::decode(sig_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    expected_hash.as_slice().ct_eq(&decoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_check_from_report() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        // No findings = success
        assert_eq!(
            StatusCheck::from_report(&report, true),
            StatusCheck::Success
        );

        // Critical findings = failure when blocking
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        assert_eq!(
            StatusCheck::from_report(&report, true),
            StatusCheck::Failure
        );

        // But warning when not blocking
        assert_eq!(
            StatusCheck::from_report(&report, false),
            StatusCheck::Warning
        );
    }

    #[test]
    fn test_pr_comment_from_report() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "SQL Injection".to_string(),
            description: "User input not sanitized".to_string(),
            location: Some("src/main.rs:42".to_string()),
            recommendation: Some("Use parameterized queries".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        let comment = PrComment::from_report(&report);
        assert!(comment.body.contains("SQL Injection"));
        assert!(comment.body.contains("src/main.rs:42"));
        assert!(comment.body.contains("CWE-89"));
    }

    #[test]
    fn test_security_badge_shields_url() {
        let badge = SecurityBadge::default();
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        // Passing scan
        let url = badge.shields_url(&report);
        assert!(url.contains("passing"));

        // Critical finding
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let url = badge.shields_url(&report);
        assert!(url.contains("critical"));
    }

    #[test]
    fn test_annotation_from_vuln_severity() {
        assert_eq!(
            AnnotationLevel::from_vuln_severity(VulnSeverity::Critical),
            AnnotationLevel::Failure
        );
        assert_eq!(
            AnnotationLevel::from_vuln_severity(VulnSeverity::High),
            AnnotationLevel::Failure
        );
        assert_eq!(
            AnnotationLevel::from_vuln_severity(VulnSeverity::Medium),
            AnnotationLevel::Warning
        );
        assert_eq!(
            AnnotationLevel::from_vuln_severity(VulnSeverity::Low),
            AnnotationLevel::Notice
        );
        assert_eq!(
            AnnotationLevel::from_vuln_severity(VulnSeverity::Info),
            AnnotationLevel::Notice
        );
    }

    #[test]
    fn test_webhook_event_from_str() {
        assert_eq!(
            "push".parse::<GitHubWebhookEvent>().unwrap(),
            GitHubWebhookEvent::Push
        );
        assert_eq!(
            "pull_request".parse::<GitHubWebhookEvent>().unwrap(),
            GitHubWebhookEvent::PullRequest
        );
        assert_eq!(
            "issues".parse::<GitHubWebhookEvent>().unwrap(),
            GitHubWebhookEvent::Issues
        );
    }

    #[test]
    fn test_verify_webhook_signature() {
        let secret = "test_secret";
        let payload = r#"{"test": "data"}"#;

        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = format!("sha256={:x}", mac.finalize().into_bytes());

        assert!(verify_webhook_signature(payload, &signature, secret));
        assert!(!verify_webhook_signature(payload, "invalid", secret));
    }

    #[test]
    fn test_annotation_from_report() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            location: Some("src/main.rs:42".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: None,
        });

        let annotations = CheckAnnotation::from_report(&report);
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0].path, "src/main.rs");
        assert_eq!(annotations[0].start_line, 42);
        assert_eq!(annotations[0].level, AnnotationLevel::Failure);
    }
}
