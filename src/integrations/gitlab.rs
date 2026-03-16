//! GitLab Integration for Warden v0.8.0 Enterprise Edition
//!
//! This module provides comprehensive GitLab integration including:
//! - GitLab CI/CD pipeline integration
//! - Merge Request security scanning
//! - GitLab Security Dashboard integration
//! - Badge generation
//! - Webhook handling for GitLab events
//! - GitLab API client for projects, repositories, pipelines, MRs, and issues

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

/// GitLab API client configuration
#[derive(Clone, Debug)]
pub struct GitLabConfig {
    /// GitLab instance URL (e.g., https://gitlab.com)
    pub instance_url: String,
    /// Personal access token or project access token
    pub access_token: String,
    /// Project ID or path (e.g., "group/project" or numeric ID)
    pub project: String,
    /// Default branch name
    pub default_branch: String,
}

impl Default for GitLabConfig {
    fn default() -> Self {
        Self {
            instance_url: "https://gitlab.com".to_string(),
            access_token: String::new(),
            project: String::new(),
            default_branch: "main".to_string(),
        }
    }
}

impl GitLabConfig {
    pub fn new(instance_url: String, access_token: String, project: String) -> Self {
        Self {
            instance_url,
            access_token,
            project,
            default_branch: "main".to_string(),
        }
    }

    pub fn with_default_branch(mut self, branch: String) -> Self {
        self.default_branch = branch;
        self
    }

    /// Load from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            instance_url: std::env::var("GITLAB_INSTANCE_URL")
                .unwrap_or_else(|_| "https://gitlab.com".to_string()),
            access_token: std::env::var("GITLAB_ACCESS_TOKEN")
                .context("GITLAB_ACCESS_TOKEN environment variable not set")?,
            project: std::env::var("CI_PROJECT_PATH")
                .or_else(|_| std::env::var("GITLAB_PROJECT"))
                .context("GITLAB_PROJECT or CI_PROJECT_PATH not set")?,
            default_branch: std::env::var("GITLAB_DEFAULT_BRANCH")
                .unwrap_or_else(|_| "main".to_string()),
        })
    }
}

/// GitLab API client
#[derive(Clone)]
pub struct GitLabClient {
    config: GitLabConfig,
    client: reqwest::Client,
}

impl GitLabClient {
    pub fn new(config: GitLabConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(format!("Warden/{}", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self { config, client })
    }

    /// Get the base API URL
    fn api_url(&self) -> String {
        format!("{}/api/v4", self.config.instance_url.trim_end_matches('/'))
    }

    /// Get URL encoded project path
    fn encoded_project(&self) -> String {
        urlencoding::encode(&self.config.project).to_string()
    }

    /// Make a GET request to the GitLab API
    async fn get(&self, endpoint: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.api_url(), endpoint);
        let response = self.client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.config.access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("GitLab API request failed: {}", response.status());
        }

        Ok(response)
    }

    /// Make a POST request to the GitLab API
    async fn post(&self, endpoint: &str, body: serde_json::Value) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.api_url(), endpoint);
        let response = self.client
            .post(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.config.access_token))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("GitLab API POST request failed: {}", response.status());
        }

        Ok(response)
    }

    /// Make a PUT request to the GitLab API
    async fn put(&self, endpoint: &str, body: serde_json::Value) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.api_url(), endpoint);
        let response = self.client
            .put(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.config.access_token))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("GitLab API PUT request failed: {}", response.status());
        }

        Ok(response)
    }

    // ========================================================================
    // Projects API
    // ========================================================================

    /// Get project information
    pub async fn get_project(&self) -> Result<GitLabProject> {
        let response = self.get(&format!("/projects/{}", self.encoded_project())).await?;
        Ok(response.json().await?)
    }

    /// Get project repository info
    pub async fn get_repository(&self) -> Result<GitLabRepository> {
        let response = self
            .get(&format!(
                "/projects/{}/repository",
                self.encoded_project()
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// List repository branches
    pub async fn list_branches(&self) -> Result<Vec<GitLabBranch>> {
        let response = self
            .get(&format!(
                "/projects/{}/repository/branches",
                self.encoded_project()
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get a specific file from the repository
    pub async fn get_file(&self, file_path: &str, ref_name: &str) -> Result<GitLabFile> {
        let encoded_path = urlencoding::encode(file_path);
        let response = self
            .get(&format!(
                "/projects/{}/repository/files/{}?ref={}",
                self.encoded_project(),
                encoded_path,
                ref_name
            ))
            .await?;
        Ok(response.json().await?)
    }

    // ========================================================================
    // Pipelines API
    // ========================================================================

    /// List project pipelines
    pub async fn list_pipelines(&self, page: u32, per_page: u32) -> Result<Vec<GitLabPipeline>> {
        let response = self
            .get(&format!(
                "/projects/{}/pipelines?page={}&per_page={}",
                self.encoded_project(),
                page,
                per_page
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get a specific pipeline
    pub async fn get_pipeline(&self, pipeline_id: u64) -> Result<GitLabPipeline> {
        let response = self
            .get(&format!(
                "/projects/{}/pipelines/{}",
                self.encoded_project(),
                pipeline_id
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get pipeline jobs
    pub async fn get_pipeline_jobs(&self, pipeline_id: u64) -> Result<Vec<GitLabJob>> {
        let response = self
            .get(&format!(
                "/projects/{}/pipelines/{}/jobs",
                self.encoded_project(),
                pipeline_id
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Create a new pipeline
    pub async fn create_pipeline(
        &self,
        ref_name: &str,
        variables: Vec<HashMap<String, String>>,
    ) -> Result<GitLabPipeline> {
        let body = serde_json::json!({
            "ref": ref_name,
            "variables": variables
        });
        let response = self
            .post(&format!("/projects/{}/pipeline", self.encoded_project()), body)
            .await?;
        Ok(response.json().await?)
    }

    /// Retry a failed pipeline job
    pub async fn retry_job(&self, job_id: u64) -> Result<GitLabJob> {
        let response = self
            .post(
                &format!(
                    "/projects/{}/jobs/{}/retry",
                    self.encoded_project(),
                    job_id
                ),
                serde_json::Value::Null,
            )
            .await?;
        Ok(response.json().await?)
    }

    // ========================================================================
    // Merge Requests API
    // ========================================================================

    /// List merge requests
    pub async fn list_merge_requests(&self, state: &str) -> Result<Vec<GitLabMergeRequest>> {
        let response = self
            .get(&format!(
                "/projects/{}/merge_requests?state={}",
                self.encoded_project(),
                state
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get a specific merge request
    pub async fn get_merge_request(&self, mr_iid: u64) -> Result<GitLabMergeRequest> {
        let response = self
            .get(&format!(
                "/projects/{}/merge_requests/{}",
                self.encoded_project(),
                mr_iid
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get merge request changes
    pub async fn get_merge_request_changes(&self, mr_iid: u64) -> Result<GitLabMRChanges> {
        let response = self
            .get(&format!(
                "/projects/{}/merge_requests/{}/changes",
                self.encoded_project(),
                mr_iid
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get merge request discussions
    pub async fn get_merge_request_discussions(
        &self,
        mr_iid: u64,
    ) -> Result<Vec<GitLabDiscussion>> {
        let response = self
            .get(&format!(
                "/projects/{}/merge_requests/{}/discussions",
                self.encoded_project(),
                mr_iid
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Create a merge request discussion comment
    pub async fn create_mr_note(
        &self,
        mr_iid: u64,
        body: &str,
    ) -> Result<GitLabNote> {
        let note_body = serde_json::json!({ "body": body });
        let response = self
            .post(
                &format!(
                    "/projects/{}/merge_requests/{}/notes",
                    self.encoded_project(),
                    mr_iid
                ),
                note_body,
            )
            .await?;
        Ok(response.json().await?)
    }

    /// Create a discussion on a specific merge request diff
    pub async fn create_mr_discussion(
        &self,
        mr_iid: u64,
        position: GitLabPosition,
        body: &str,
    ) -> Result<GitLabDiscussion> {
        let discussion_body = serde_json::json!({
            "body": body,
            "position": position
        });
        let response = self
            .post(
                &format!(
                    "/projects/{}/merge_requests/{}/discussions",
                    self.encoded_project(),
                    mr_iid
                ),
                discussion_body,
            )
            .await?;
        Ok(response.json().await?)
    }

    /// Approve a merge request
    pub async fn approve_merge_request(&self, mr_iid: u64) -> Result<GitLabApproval> {
        let response = self
            .post(
                &format!(
                    "/projects/{}/merge_requests/{}/approve",
                    self.encoded_project(),
                    mr_iid
                ),
                serde_json::Value::Null,
            )
            .await?;
        Ok(response.json().await?)
    }

    // ========================================================================
    // Issues API
    // ========================================================================

    /// List project issues
    pub async fn list_issues(&self, state: &str) -> Result<Vec<GitLabIssue>> {
        let response = self
            .get(&format!(
                "/projects/{}/issues?state={}",
                self.encoded_project(),
                state
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Create a new issue
    pub async fn create_issue(
        &self,
        title: &str,
        description: &str,
        labels: &[&str],
    ) -> Result<GitLabIssue> {
        let body = serde_json::json!({
            "title": title,
            "description": description,
            "labels": labels.join(",")
        });
        let response = self
            .post(&format!("/projects/{}/issues", self.encoded_project()), body)
            .await?;
        Ok(response.json().await?)
    }

    /// Create an issue comment
    pub async fn create_issue_note(&self, issue_iid: u64, body: &str) -> Result<GitLabNote> {
        let note_body = serde_json::json!({ "body": body });
        let response = self
            .post(
                &format!(
                    "/projects/{}/issues/{}/notes",
                    self.encoded_project(),
                    issue_iid
                ),
                note_body,
            )
            .await?;
        Ok(response.json().await?)
    }

    // ========================================================================
    // Commits API
    // ========================================================================

    /// Get commit information
    pub async fn get_commit(&self, sha: &str) -> Result<GitLabCommit> {
        let response = self
            .get(&format!(
                "/projects/{}/repository/commits/{}",
                self.encoded_project(),
                sha
            ))
            .await?;
        Ok(response.json().await?)
    }

    /// Get commit diff
    pub async fn get_commit_diff(&self, sha: &str) -> Result<Vec<GitLabDiff>> {
        let response = self
            .get(&format!(
                "/projects/{}/repository/commits/{}/diff",
                self.encoded_project(),
                sha
            ))
            .await?;
        Ok(response.json().await?)
    }
}

// ========================================================================
// GitLab Types
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabProject {
    pub id: u64,
    pub iid: u64,
    pub name: String,
    pub path_with_namespace: String,
    pub default_branch: String,
    pub web_url: String,
    pub ssh_url_to_repo: String,
    pub http_url_to_repo: String,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    #[serde(default)]
    pub security_and_compliance_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabRepository {
    pub name: String,
    pub description: Option<String>,
    pub default_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabBranch {
    pub name: String,
    pub merged: bool,
    pub protected: bool,
    pub default: bool,
    pub can_push: bool,
    pub web_url: String,
    pub commit: GitLabCommitShort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCommitShort {
    pub id: String,
    pub short_id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub author_name: String,
    pub author_email: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabFile {
    pub file_name: String,
    pub file_path: String,
    pub size: u64,
    pub encoding: String,
    pub content: String,
    pub content_sha256: String,
    pub ref_name: String,
    pub blob_id: String,
    pub commit_id: String,
    pub last_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPipeline {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub sha: String,
    pub ref_name: String,
    pub status: String,
    #[serde(default)]
    pub coverage: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub web_url: String,
    #[serde(default)]
    pub yaml_errors: Option<String>,
    #[serde(default)]
    pub user: Option<GitLabUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabJob {
    pub id: u64,
    pub name: String,
    pub stage: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration: Option<f64>,
    pub web_url: String,
    pub pipeline: GitLabPipelineReference,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPipelineReference {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub sha: String,
    pub ref_name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMergeRequest {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub merged_at: Option<DateTime<Utc>>,
    pub source_branch: String,
    pub target_branch: String,
    pub author: GitLabUser,
    pub assignees: Vec<GitLabUser>,
    pub web_url: String,
    pub draft: bool,
    pub work_in_progress: bool,
    #[serde(default)]
    pub changes_count: Option<String>,
    #[serde(default)]
    pub merge_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMRChanges {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub source_branch: String,
    pub target_branch: String,
    pub changes: Vec<GitLabDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabDiff {
    pub old_path: String,
    pub new_path: String,
    #[serde(default)]
    pub diff: String,
    #[serde(default)]
    pub new_file: bool,
    #[serde(default)]
    pub renamed_file: bool,
    #[serde(default)]
    pub deleted_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabDiscussion {
    pub id: String,
    #[serde(default)]
    pub individual_note: bool,
    pub notes: Vec<GitLabNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabNote {
    pub id: u64,
    #[serde(rename = "type")]
    pub note_type: Option<String>,
    pub body: String,
    pub author: GitLabUser,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub position: Option<GitLabPosition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPosition {
    pub base_sha: String,
    pub head_sha: String,
    pub start_sha: String,
    #[serde(default)]
    pub old_path: String,
    #[serde(default)]
    pub new_path: String,
    #[serde(default)]
    pub position_type: String,
    #[serde(default)]
    pub new_line: Option<u64>,
    #[serde(default)]
    pub old_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabApproval {
    pub id: u64,
    pub merge_request_id: u64,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub approved_by: Vec<GitLabApprover>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabApprover {
    pub user: GitLabUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIssue {
    pub id: u64,
    pub iid: u64,
    pub project_id: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub labels: Vec<String>,
    pub assignees: Vec<GitLabUser>,
    pub author: GitLabUser,
    pub web_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabCommit {
    pub id: String,
    pub short_id: String,
    pub title: String,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    pub authored_date: DateTime<Utc>,
    pub committer_name: String,
    pub committer_email: String,
    pub committed_date: DateTime<Utc>,
    pub web_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabUser {
    pub id: u64,
    pub username: String,
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
}

// ========================================================================
// GitLab CI/CD Integration
// ========================================================================

/// GitLab CI/CD configuration generator
pub struct GitLabCiGenerator {
    project_path: String,
    enable_security_scan: bool,
    fail_on_critical: bool,
    fail_on_high: bool,
}

impl GitLabCiGenerator {
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            enable_security_scan: true,
            fail_on_critical: true,
            fail_on_high: false,
        }
    }

    pub fn with_security_scan(mut self, enable: bool) -> Self {
        self.enable_security_scan = enable;
        self
    }

    pub fn with_failure_policy(mut self, critical: bool, high: bool) -> Self {
        self.fail_on_critical = critical;
        self.fail_on_high = high;
        self
    }

    /// Generate .gitlab-ci.yml content
    pub fn generate_ci_config(&self) -> String {
        let mut config = String::new();

        // Header
        config.push_str("# Warden Security Scan - GitLab CI/CD Pipeline\n");
        config.push_str("# Generated by Warden v0.8.0 Enterprise Edition\n\n");

        // Variables
        config.push_str("variables:\n");
        config.push_str("  WARDEN_VERSION: \"latest\"\n");
        config.push_str("  SECURE_LOG_LEVEL: \"info\"\n\n");

        // Define stages
        config.push_str("stages:\n");
        config.push_str("  - test\n");
        config.push_str("  - security\n");
        config.push_str("  - report\n\n");

        // Warden scan job
        if self.enable_security_scan {
            config.push_str(&self.generate_warden_job());
        }

        // Report job
        config.push_str(&self.generate_report_job());

        // Badge job
        config.push_str(&self.generate_badge_job());

        // Artifacts configuration
        config.push_str("\n# Cache configuration\n");
        config.push_str("cache:\n");
        config.push_str("  key: ${CI_COMMIT_REF_SLUG}\n");
        config.push_str("  paths:\n");
        config.push_str("    - ~/.cargo/registry\n");
        config.push_str("    - target/\n\n");

        config
    }

    fn generate_warden_job(&self) -> String {
        let mut job = String::from("warden_security_scan:\n");
        job.push_str("  stage: security\n");
        job.push_str("  image: ghcr.io/warden-security/warden:latest\n");
        job.push_str("  allow_failure: ");
        job.push_str(if !self.fail_on_critical && !self.fail_on_high {
            "true\n"
        } else {
            "false\n"
        });
        job.push_str("  script:\n");
        job.push_str("    - warden scan . --output json --report warden-report.json\n");
        job.push_str("  artifacts:\n");
        job.push_str("    reports:\n");
        job.push_str("      sast: gl-sast-report.json\n");
        job.push_str("    paths:\n");
        job.push_str("      - warden-report.json\n");
        job.push_str("      - warden-report.html\n");
        job.push_str("      - gl-sast-report.json\n");
        job.push_str("    expire_in: 1 week\n");
        job.push_str("  only:\n");
        job.push_str("    - merge_requests\n");
        job.push_str("    - main\n");
        job.push_str("    - master\n\n");

        // Exit code handling
        if self.fail_on_critical || self.fail_on_high {
            job.push_str("  after_script:\n");
            job.push_str("    - |\n");
            job.push_str("        if [ -f warden-report.json ]; then\n");
            job.push_str("          CRITICAL=$(jq '.summary.critical // 0' warden-report.json)\n");
            job.push_str("          HIGH=$(jq '.summary.high // 0' warden-report.json)\n");
            if self.fail_on_critical {
                job.push_str("          if [ \"$CRITICAL\" -gt 0 ]; then\n");
                job.push_str("            echo \"CRITICAL vulnerabilities found: $CRITICAL\"\n");
                job.push_str("            exit 1\n");
                job.push_str("          fi\n");
            }
            if self.fail_on_high {
                job.push_str("          if [ \"$HIGH\" -gt 0 ]; then\n");
                job.push_str("            echo \"HIGH vulnerabilities found: $HIGH\"\n");
                job.push_str("            exit 1\n");
                job.push_str("          fi\n");
            }
            job.push_str("        fi\n\n");
        }

        job
    }

    fn generate_report_job(&self) -> String {
        "warden_report:\n\
         stage: report\n\
         image: alpine:latest\n\
         script:\n\
         - echo \"Security scan complete. Check artifacts for details.\"\n\
         dependencies:\n\
         - warden_security_scan\n\
         artifacts:\n\
         paths:\n\
         - warden-report.json\n\
         - warden-report.html\n\
         expire_in: 30 days\n\
         only:\n\
         - main\n\
         - master\n\n"
            .to_string()
    }

    fn generate_badge_job(&self) -> String {
        "warden_badge:\n\
         stage: report\n\
         image: alpine:latest\n\
         script:\n\
         - apk add --no-cache curl jq\n\
         - |\n\
             CRITICAL=$(jq '.summary.critical // 0' warden-report.json)\n\
             HIGH=$(jq '.summary.high // 0' warden-report.json)\n\
             MEDIUM=$(jq '.summary.medium // 0' warden-report.json)\n\
             TOTAL=$(jq '.summary.total // 0' warden-report.json)\n\
             SCORE=$(jq '.score // 0' warden-report.json)\n\
             if [ \"$TOTAL\" -eq 0 ]; then\n\
               STATUS=\"passing\"\n\
               COLOR=\"brightgreen\"\n\
             elif [ \"$CRITICAL\" -gt 0 ]; then\n\
               STATUS=\"critical\"\n\
               COLOR=\"red\"\n\
             elif [ \"$HIGH\" -gt 0 ]; then\
               STATUS=\"warning\"\n\
               COLOR=\"orange\"\n\
             else\n\
               STATUS=\"info\"\n\
               COLOR=\"yellow\"\n\
             fi\n\
             curl \"https://img.shields.io/badge/security-$STATUS-$SCORE-$COLOR\" -o security-badge.svg\n\
         artifacts:\n\
         paths:\n\
         - security-badge.svg\n\
         expire_in: 90 days\n\
         dependencies:\n\
         - warden_security_scan\n\
         only:\n\
         - main\n\
         - master\n\n"
            .to_string()
    }

    /// Write .gitlab-ci.yml to file
    pub async fn write_to_file(&self) -> Result<()> {
        let ci_path = Path::new(&self.project_path).join(".gitlab-ci.yml");
        let content = self.generate_ci_config();
        fs::write(&ci_path, content).await?;
        Ok(())
    }

    /// Generate GitLab SAST report format
    pub fn generate_sast_report(
        scan_report: &crate::scanners::ScanReport,
    ) -> GitLabSastReport {
        let vulnerabilities = scan_report
            .findings
            .iter()
            .map(|vuln| GitLabSastVulnerability {
                category: "sast".to_string(),
                name: vuln.title.clone(),
                message: vuln.description.clone(),
                severity: match vuln.severity {
                    crate::scanners::VulnSeverity::Critical => "Critical",
                    crate::scanners::VulnSeverity::High => "High",
                    crate::scanners::VulnSeverity::Medium => "Medium",
                    crate::scanners::VulnSeverity::Low => "Low",
                    crate::scanners::VulnSeverity::Info => "Info",
                }
                .to_string(),
                confidence: "High".to_string(),
                location: GitLabSastLocation {
                    file: vuln.location.clone().unwrap_or_else(|| "unknown".to_string()),
                    start_line: 1,
                    end_line: 1,
                    class: None,
                    method: None,
                },
                identifiers: vec![GitLabSastIdentifier {
                    type_: "CWE".to_string(),
                    name: vuln.cwe.clone().unwrap_or_else(|| "CWE-Unknown".to_string()),
                    value: vuln.cwe.clone().unwrap_or_default(),
                    url: Some(format!(
                        "https://cwe.mitre.org/data/definitions/{}.html",
                        vuln.cwe
                            .as_ref()
                            .and_then(|c| c.strip_prefix("CWE-"))
                            .unwrap_or("0")
                    )),
                }],
                scanner: GitLabSastScanner {
                    id: "warden".to_string(),
                    name: "Warden Security Scanner".to_string(),
                },
                ..Default::default()
            })
            .collect();

        GitLabSastReport {
            version: "v15.0.0".to_string(),
            vulnerabilities,
            scan: GitLabSastScan {
                scanner: GitLabSastScanner {
                    id: "warden".to_string(),
                    name: "Warden Security Scanner".to_string(),
                },
                type_: "sast".to_string(),
                start_time: scan_report.timestamp.clone(),
                end_time: chrono::Utc::now().to_rfc3339(),
                status: "success".to_string(),
            },
        }
    }
}

/// GitLab SAST report format for integration with GitLab Security Dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastReport {
    pub version: String,
    pub vulnerabilities: Vec<GitLabSastVulnerability>,
    pub scan: GitLabSastScan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastVulnerability {
    pub category: String,
    pub name: String,
    pub message: String,
    pub severity: String,
    pub confidence: String,
    pub location: GitLabSastLocation,
    #[serde(rename = "identifiers")]
    pub identifiers: Vec<GitLabSastIdentifier>,
    pub scanner: GitLabSastScanner,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<GitLabSastLink>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl Default for GitLabSastVulnerability {
    fn default() -> Self {
        Self {
            category: String::new(),
            name: String::new(),
            message: String::new(),
            severity: "Info".to_string(),
            confidence: "Unknown".to_string(),
            location: GitLabSastLocation {
                file: String::new(),
                start_line: 0,
                end_line: 0,
                class: None,
                method: None,
            },
            identifiers: Vec::new(),
            scanner: GitLabSastScanner {
                id: "warden".to_string(),
                name: "Warden".to_string(),
            },
            links: None,
            details: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastLocation {
    pub file: String,
    pub start_line: u64,
    pub end_line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastIdentifier {
    #[serde(rename = "type")]
    pub type_: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastScanner {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastLink {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabSastScan {
    pub scanner: GitLabSastScanner,
    #[serde(rename = "type")]
    pub type_: String,
    pub start_time: String,
    pub end_time: String,
    pub status: String,
}

// ========================================================================
// Merge Request Security Scanner
// ========================================================================

/// Merge request security scanner for GitLab
pub struct GitLabMRScanner {
    client: GitLabClient,
}

impl GitLabMRScanner {
    pub fn new(client: GitLabClient) -> Self {
        Self { client }
    }

    /// Scan a merge request for security issues
    pub async fn scan_merge_request(
        &self,
        mr_iid: u64,
        scan_report: &crate::scanners::ScanReport,
    ) -> Result<GitLabMRScanResult> {
        let mr = self.client.get_merge_request(mr_iid).await?;
        let changes = self.client.get_merge_request_changes(mr_iid).await?;

        let result = GitLabMRScanResult {
            mr_iid,
            source_branch: mr.source_branch.clone(),
            target_branch: mr.target_branch.clone(),
            files_changed: changes.changes.len(),
            vulnerabilities_found: scan_report.findings.len(),
            critical: scan_report.summary.critical,
            high: scan_report.summary.high,
            medium: scan_report.summary.medium,
            low: scan_report.summary.low,
            passed: scan_report.summary.critical == 0,
        };

        // Post summary comment to MR
        let comment = self.generate_mr_comment(scan_report, &mr);
        self.client.create_mr_note(mr_iid, &comment).await?;

        // For critical findings, create inline comments
        for (idx, vuln) in scan_report.findings.iter().enumerate() {
            if vuln.severity == crate::scanners::VulnSeverity::Critical
                || vuln.severity == crate::scanners::VulnSeverity::High
            {
                if let Some(location) = &vuln.location {
                    // Try to create inline comment for file-specific findings
                    let _ = self.create_inline_comment(mr_iid, vuln, &changes).await;
                }
            }
        }

        Ok(result)
    }

    /// Generate a summary comment for the MR
    fn generate_mr_comment(
        &self,
        report: &crate::scanners::ScanReport,
        mr: &GitLabMergeRequest,
    ) -> String {
        let mut comment = String::from("## Warden Security Scan Report\n\n");

        // Status badge
        let status = if report.summary.critical > 0 {
            ":rotating_light: **CRITICAL**"
        } else if report.summary.high > 0 {
            ":warning: **WARNING**"
        } else if report.summary.medium > 0 {
            ":heavy_exclamation_mark: **NEEDS REVIEW**"
        } else {
            ":white_check_mark: **PASSED**"
        };

        comment.push_str(&format!("**Status:** {}\n\n", status));

        // Summary table
        comment.push_str("| Severity | Count |\n");
        comment.push_str("|----------|-------|\n");
        comment.push_str(&format!("| CRITICAL | {} |\n", report.summary.critical));
        comment.push_str(&format!("| HIGH | {} |\n", report.summary.high));
        comment.push_str(&format!("| MEDIUM | {} |\n", report.summary.medium));
        comment.push_str(&format!("| LOW | {} |\n", report.summary.low));
        comment.push_str(&format!("| **Total** | **{}** |\n\n", report.summary.total));

        // Top findings
        if !report.findings.is_empty() {
            comment.push_str("### Top Findings\n\n");
            for (i, finding) in report.findings.iter().take(5).enumerate() {
                let icon = match finding.severity {
                    crate::scanners::VulnSeverity::Critical => ":rotating_light:",
                    crate::scanners::VulnSeverity::High => ":warning:",
                    crate::scanners::VulnSeverity::Medium => ":heavy_exclamation_mark:",
                    crate::scanners::VulnSeverity::Low => ":information_source:",
                    crate::scanners::VulnSeverity::Info => ":grey_question:",
                };
                comment.push_str(&format!(
                    "{} **{}.** {} - `{}`\n",
                    icon, i + 1, finding.title, finding.severity
                ));
                if let Some(loc) = &finding.location {
                    comment.push_str(&format!("   - Location: `{}`\n", loc));
                }
                comment.push('\n');
            }
        }

        // Footer
        comment.push_str("---\n");
        comment.push_str("*Scan performed by Warden v0.8.0 Enterprise Edition*\n");
        comment.push_str(&format!("*Scan ID: `{}`*\n", uuid::Uuid::new_v4()));

        comment
    }

    /// Create an inline comment for a vulnerability
    async fn create_inline_comment(
        &self,
        mr_iid: u64,
        vuln: &crate::scanners::Vuln,
        changes: &GitLabMRChanges,
    ) -> Result<()> {
        if let Some(location) = &vuln.location {
            // Parse file location from finding
            if let Some(file_path) = location.split(':').next() {
                // Find matching diff
                if let Some(diff) = changes.changes.iter().find(|d| {
                    d.new_path == file_path || d.old_path == file_path
                }) {
                    let position = GitLabPosition {
                        base_sha: changes.changes.first().map(|_| String::new()).unwrap_or_default(),
                        head_sha: String::new(),
                        start_sha: String::new(),
                        old_path: diff.old_path.clone(),
                        new_path: diff.new_path.clone(),
                        position_type: "text".to_string(),
                        new_line: None,
                        old_line: None,
                    };

                    let comment = format!(
                        ":rotating_light: **Security Finding**\n\n**{}**\n\n{}\n\n**Severity:** {}\n\n{}",
                        vuln.title,
                        vuln.description,
                        vuln.severity,
                        vuln.recommendation.as_ref().map(|r| r.as_str()).unwrap_or("")
                    );

                    let _ = self
                        .client
                        .create_mr_discussion(mr_iid, position, &comment)
                        .await;
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMRScanResult {
    pub mr_iid: u64,
    pub source_branch: String,
    pub target_branch: String,
    pub files_changed: usize,
    pub vulnerabilities_found: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub passed: bool,
}

// ========================================================================
// Badge Generator
// ========================================================================

/// Generate SVG badges for GitLab projects
pub struct GitLabBadgeGenerator;

impl GitLabBadgeGenerator {
    /// Generate security score badge
    pub fn security_score(score: u8) -> String {
        let (color, status) = if score >= 90 {
            ("brightgreen", "passing")
        } else if score >= 70 {
            ("yellowgreen", "good")
        } else if score >= 50 {
            ("yellow", "warning")
        } else if score >= 30 {
            ("orange", "critical")
        } else {
            ("red", "failing")
        };

        Self::generate_svg("security", &format!("{}%", score), color, status)
    }

    /// Generate vulnerability count badge
    pub fn vulnerability_count(critical: usize, high: usize, total: usize) -> String {
        let (color, label) = if critical > 0 {
            ("red", format!("{} critical", critical))
        } else if high > 0 {
            ("orange", format!("{} high", high))
        } else if total > 0 {
            ("yellow", format!("{} issues", total))
        } else {
            ("brightgreen", "no issues".to_string())
        };

        Self::generate_svg("vulnerabilities", &label, color, "info")
    }

    /// Generate pipeline status badge (for reference)
    pub fn pipeline_status(status: &str) -> String {
        let (color, label) = match status {
            "success" | "passed" => ("brightgreen", "passing"),
            "failed" => ("red", "failing"),
            "running" => ("blue", "running"),
            "pending" => ("yellow", "pending"),
            "skipped" => ("lightgrey", "skipped"),
            _ => ("lightgrey", "unknown"),
        };

        Self::generate_svg("pipeline", label, color, status)
    }

    /// Generate custom badge
    pub fn custom(label: &str, message: &str, color: &str) -> String {
        Self::generate_svg(label, message, color, "info")
    }

    /// Generate SVG badge
    fn generate_svg(label: &str, message: &str, color: &str, _status: &str) -> String {
        // Calculate widths based on text
        let label_width = label.len() * 7 + 20;
        let message_width = message.len() * 7 + 20;
        let total_width = label_width + message_width;

        // Build SVG manually to avoid format string escaping issues
        let mut svg = String::from(r##"<svg xmlns="http://www.w3.org/2000/svg" width=""##);
        svg.push_str(&total_width.to_string());
        svg.push_str(r##" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width=""##);
        svg.push_str(&total_width.to_string());
        svg.push_str(r##"" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h"##);
        svg.push_str(&label_width.to_string());
        svg.push_str(r##"v20H0z"/>
    <path fill=""##);
        svg.push_str(Self::color_code(color));
        svg.push_str(r##"" d="M"##);
        svg.push_str(&label_width.to_string());
        svg.push_str(r##" 0h"##);
        svg.push_str(&message_width.to_string());
        svg.push_str(r##"v20H"##);
        svg.push_str(&label_width.to_string());
        svg.push_str(r##"z"/>
    <path fill="url(#b)" d="M0 0h"##);
        svg.push_str(&total_width.to_string());
        svg.push_str(r##"v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x=""##);
        svg.push_str(&(label_width / 2 + 5).to_string());
        svg.push_str(r##"" y="15" fill="#010101" fill-opacity=".3">"##);
        svg.push_str(label);
        svg.push_str(r##"</text>
    <text x=""##);
        svg.push_str(&(label_width / 2 + 5).to_string());
        svg.push_str(r##"" y="14">"##);
        svg.push_str(label);
        svg.push_str(r##"</text>
    <text x=""##);
        svg.push_str(&(label_width + message_width / 2 + 5).to_string());
        svg.push_str(r##"" y="15" fill="#010101" fill-opacity=".3">"##);
        svg.push_str(message);
        svg.push_str(r##"</text>
    <text x=""##);
        svg.push_str(&(label_width + message_width / 2 + 5).to_string());
        svg.push_str(r##"" y="14">"##);
        svg.push_str(message);
        svg.push_str(r##"</text>
  </g>
</svg>"##);

        svg
    }

    fn color_code(color: &str) -> &'static str {
        match color {
            "brightgreen" => "#4c1",
            "green" => "#97ca00",
            "yellowgreen" => "#a4a61d",
            "yellow" => "#dfb317",
            "orange" => "#fe7d37",
            "red" => "#e05d44",
            "blue" => "#007ec6",
            "grey" => "#9f9f9f",
            "lightgrey" => "#9f9f9f",
            _ => "#4c1",
        }
    }
}

// ========================================================================
// Webhook Handler for GitLab Events
// ========================================================================

/// GitLab webhook event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitLabWebhookEvent {
    Push(GitLabPushEvent),
    MergeRequest(GitLabMREvent),
    Issue(GitLabIssueEvent),
    Pipeline(GitLabPipelineEvent),
    Note(GitLabNoteEvent),
    Unknown(serde_json::Value),
}

/// Parse a GitLab webhook event
pub fn parse_gitlab_webhook(
    event_type: &str,
    payload: &str,
) -> Result<GitLabWebhookEvent> {
    match event_type {
        "Push Hook" => Ok(GitLabWebhookEvent::Push(serde_json::from_str(payload)?)),
        "Merge Request Hook" => Ok(GitLabWebhookEvent::MergeRequest(serde_json::from_str(
            payload,
        )?)),
        "Issue Hook" => Ok(GitLabWebhookEvent::Issue(serde_json::from_str(payload)?)),
        "Pipeline Hook" => Ok(GitLabWebhookEvent::Pipeline(serde_json::from_str(
            payload,
        )?)),
        "Note Hook" => Ok(GitLabWebhookEvent::Note(serde_json::from_str(payload)?)),
        _ => Ok(GitLabWebhookEvent::Unknown(serde_json::from_str(payload)?)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPushEvent {
    pub object_kind: String,
    pub event_name: String,
    pub before: String,
    pub after: String,
    pub ref_: String, // renamed from 'ref' which is a Rust keyword
    #[serde(default)]
    pub checkout_sha: Option<String>,
    pub user_id: u64,
    pub user_name: String,
    pub user_username: String,
    pub user_email: String,
    pub user_avatar: String,
    pub project_id: u64,
    pub project: GitLabWebhookProject,
    pub repository: GitLabWebhookRepository,
    pub total_commits_count: u64,
    pub commits: Vec<GitLabWebhookCommit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabWebhookProject {
    pub id: u64,
    pub name: String,
    pub path_with_namespace: String,
    pub web_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabWebhookRepository {
    pub name: String,
    pub url: String,
    pub description: Option<String>,
    pub homepage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabWebhookCommit {
    pub id: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub author: GitLabWebhookCommitAuthor,
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub modified: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabWebhookCommitAuthor {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMREvent {
    pub object_kind: String,
    pub event_type: String,
    pub user: GitLabUser,
    pub project: GitLabWebhookProject,
    pub object_attributes: GitLabMRAttributes,
    #[serde(default)]
    pub labels: Vec<GitLabWebhookLabel>,
    #[serde(default)]
    pub changes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabMRAttributes {
    pub id: u64,
    pub iid: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub source_branch: String,
    pub target_branch: String,
    pub author_id: u64,
    pub assignee_id: Option<u64>,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabWebhookLabel {
    pub id: u64,
    pub title: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIssueEvent {
    pub object_kind: String,
    pub user: GitLabUser,
    pub project: GitLabWebhookProject,
    pub object_attributes: GitLabIssueAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabIssueAttributes {
    pub id: u64,
    pub iid: u64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPipelineEvent {
    pub object_kind: String,
    pub user: GitLabUser,
    pub project: GitLabWebhookProject,
    pub object_attributes: GitLabPipelineAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPipelineAttributes {
    pub id: u64,
    pub iid: u64,
    pub name: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub status: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub variables: Vec<GitLabPipelineVariable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabPipelineVariable {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabNoteEvent {
    pub object_kind: String,
    pub user: GitLabUser,
    pub project: GitLabWebhookProject,
    pub object_attributes: GitLabNoteAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabNoteAttributes {
    pub id: u64,
    pub note: String,
    pub noteable_type: String,
    pub noteable_id: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ========================================================================
// GitLab Integration Service
// ========================================================================

/// Main GitLab integration service
pub struct GitLabIntegration {
    client: GitLabClient,
    ci_generator: GitLabCiGenerator,
}

impl GitLabIntegration {
    pub fn new(config: GitLabConfig) -> Result<Self> {
        let client = GitLabClient::new(config.clone())?;
        let ci_generator = GitLabCiGenerator::new(config.project.clone());

        Ok(Self {
            client,
            ci_generator,
        })
    }

    /// Setup GitLab CI/CD integration
    pub async fn setup_ci_cd(&self) -> Result<()> {
        self.ci_generator.write_to_file().await?;
        Ok(())
    }

    /// Scan and report on a merge request
    pub async fn scan_merge_request(
        &self,
        mr_iid: u64,
        scan_report: &crate::scanners::ScanReport,
    ) -> Result<GitLabMRScanResult> {
        let scanner = GitLabMRScanner::new(self.client.clone());
        scanner.scan_merge_request(mr_iid, scan_report).await
    }

    /// Create security issues for critical findings
    pub async fn create_security_issues(
        &self,
        scan_report: &crate::scanners::ScanReport,
    ) -> Result<Vec<GitLabIssue>> {
        let mut issues = Vec::new();

        for vuln in scan_report
            .findings
            .iter()
            .filter(|v| {
                v.severity == crate::scanners::VulnSeverity::Critical
                    || v.severity == crate::scanners::VulnSeverity::High
            })
        {
            let title = format!("[Security] {} - {}", vuln.severity, vuln.title);
            let description = format!(
                "## Security Vulnerability Detected\n\n\
                 **Severity:** {}\n\n\
                 **Description:** {}\n\n\
                 **Location:** `{}`\n\n\
                 **Recommendation:** {}\n\n\
                 **CWE:** {}\n\n\
                 **OWASP:** {}\n\n\
                 ---\n\
                 *Automatically created by Warden v0.8.0 Enterprise Edition*",
                vuln.severity,
                vuln.description,
                vuln.location.as_deref().unwrap_or("unknown"),
                vuln.recommendation.as_deref().unwrap_or("N/A"),
                vuln.cwe.as_deref().unwrap_or("N/A"),
                vuln.owasp.as_deref().unwrap_or("N/A")
            );

            let labels = vec!["security", "vulnerability", "automated"];

            let issue = self
                .client
                .create_issue(&title, &description, &labels)
                .await?;

            issues.push(issue);
        }

        Ok(issues)
    }

    /// Upload security artifacts to GitLab
    pub async fn upload_artifacts(
        &self,
        report_path: &Path,
        artifact_name: &str,
    ) -> Result<String> {
        // This would use GitLab's project file upload API
        // For now, return a placeholder URL
        Ok(format!(
            "{}/uploads/{}/{}",
            self.client.api_url().trim_end_matches("/api/v4"),
            artifact_name,
            artifact_name
        ))
    }

    /// Generate badges for the project
    pub fn generate_badges(
        &self,
        scan_report: &crate::scanners::ScanReport,
    ) -> (String, String) {
        let score_badge = GitLabBadgeGenerator::security_score(
            ((100 - scan_report.summary.critical * 25 - scan_report.summary.high * 10)
                .max(0)) as u8,
        );
        let vuln_badge = GitLabBadgeGenerator::vulnerability_count(
            scan_report.summary.critical,
            scan_report.summary.high,
            scan_report.summary.total,
        );

        (score_badge, vuln_badge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitlab_config_default() {
        let config = GitLabConfig::default();
        assert_eq!(config.instance_url, "https://gitlab.com");
        assert_eq!(config.default_branch, "main");
        assert!(config.access_token.is_empty());
        assert!(config.project.is_empty());
    }

    #[test]
    fn test_gitlab_ci_generator() {
        let generator = GitLabCiGenerator::new("/test/project".to_string());
        let config = generator.generate_ci_config();

        assert!(config.contains("warden_security_scan"));
        assert!(config.contains("stages:"));
        assert!(config.contains("security"));
    }

    #[test]
    fn test_badge_generator() {
        let badge = GitLabBadgeGenerator::security_score(95);
        assert!(badge.contains("passing"));
        assert!(badge.contains("<svg"));

        let badge = GitLabBadgeGenerator::vulnerability_count(0, 0, 0);
        assert!(badge.contains("no issues"));
    }

    #[test]
    fn test_sast_report_generation() {
        use crate::scanners::{ScanReport, Target, Vuln, VulnSeverity};

        let mut report = ScanReport::new(Target::Path("/test".into()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Test".to_string(),
            description: "Test vulnerability".to_string(),
            location: Some("/test/file.rs:10".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        let sast_report = GitLabCiGenerator::generate_sast_report(&report);
        assert_eq!(sast_report.vulnerabilities.len(), 1);
        assert_eq!(sast_report.vulnerabilities[0].severity, "Critical");
    }
}
