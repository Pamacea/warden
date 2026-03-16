//! Integration modules for third-party services
//!
//! This module provides integrations with various platforms and services for Warden v0.8.0 Enterprise Edition.
//! - GitHub (webhooks, PR comments, status checks, security badges)
//! - Jenkins Pipeline integration
//! - GitLab CI/CD (pipelines, MR scanning, badges, webhooks)
//! - Azure DevOps support (planned)

pub mod github;
pub mod gitlab;
pub mod jenkins;

pub use github::{
    CheckAnnotation, AnnotationLevel, CommitInfo, CommitRef, GitHubApp, GitHubClient,
    GitHubConfig, GitHubIssue, GitHubWebhook, GitHubWebhookEvent, PrComment, PullRequestInfo,
    RepoOwner, RepositoryInfo, SecurityBadge, SenderInfo, StatusCheck, UserInfo,
    parse_webhook, verify_webhook_signature,
};

pub use jenkins::{
    JenkinsBuildStep, JenkinsConfig, JenkinsConsoleFormatter, JenkinsFailureThreshold,
    JenkinsNotificationConfig, JenkinsPlugin, JenkinsReportFormat, JenkinsResult,
};

// GitLab integration exports
pub use gitlab::{
    // Client and Configuration
    GitLabClient, GitLabConfig, GitLabIntegration,

    // CI/CD
    GitLabCiGenerator,

    // Merge Request Scanning
    GitLabMRScanner, GitLabMRScanResult,

    // SAST Reporting
    GitLabSastReport, GitLabSastVulnerability, GitLabSastLocation,

    // Badges
    GitLabBadgeGenerator,

    // Webhooks
    GitLabWebhookEvent, parse_gitlab_webhook,

    // Types
    GitLabProject, GitLabRepository, GitLabBranch, GitLabFile,
    GitLabPipeline, GitLabJob, GitLabMergeRequest, GitLabMRChanges,
    GitLabDiff, GitLabDiscussion, GitLabNote, GitLabPosition,
    GitLabApproval, GitLabIssue, GitLabCommit, GitLabUser,

    // Webhook Event Types
    GitLabPushEvent, GitLabMREvent, GitLabIssueEvent,
    GitLabPipelineEvent, GitLabNoteEvent,
};

/// Integration platform type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiPlatform {
    Jenkins,
    GitHubActions,
    GitLabCi,
    AzureDevOps,
}

impl std::fmt::Display for CiPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiPlatform::Jenkins => write!(f, "Jenkins"),
            CiPlatform::GitHubActions => write!(f, "GitHub Actions"),
            CiPlatform::GitLabCi => write!(f, "GitLab CI"),
            CiPlatform::AzureDevOps => write!(f, "Azure DevOps"),
        }
    }
}

impl std::str::FromStr for CiPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "jenkins" => Ok(CiPlatform::Jenkins),
            "github" | "github-actions" | "gha" => Ok(CiPlatform::GitHubActions),
            "gitlab" | "gitlab-ci" | "glci" => Ok(CiPlatform::GitLabCi),
            "azure" | "azure-devops" | "azdo" => Ok(CiPlatform::AzureDevOps),
            _ => Err(format!(
                "Unknown CI platform: {}. Valid options: jenkins, github, gitlab, azure",
                s
            )),
        }
    }
}

/// Common CI environment variables
pub const ENV_CI_PLATFORM: &str = "WARDEN_CI_PLATFORM";
pub const ENV_BUILD_URL: &str = "BUILD_URL";
pub const ENV_BUILD_NUMBER: &str = "BUILD_NUMBER";
pub const ENV_JOB_NAME: &str = "JOB_NAME";
pub const ENV_WORKSPACE: &str = "WORKSPACE";

/// Detect the current CI platform from environment variables
pub fn detect_ci_platform() -> Option<CiPlatform> {
    // Check for Jenkins
    if std::env::var("JENKINS_URL").is_ok() || std::env::var("BUILD_URL").is_ok() {
        return Some(CiPlatform::Jenkins);
    }

    // Check for GitHub Actions
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return Some(CiPlatform::GitHubActions);
    }

    // Check for GitLab CI
    if std::env::var("GITLAB_CI").is_ok() {
        return Some(CiPlatform::GitLabCi);
    }

    // Check for Azure DevOps
    if std::env::var("TF_BUILD").is_ok() {
        return Some(CiPlatform::AzureDevOps);
    }

    None
}

/// Get CI environment information
#[derive(Clone, Debug)]
pub struct CiEnvironment {
    pub platform: CiPlatform,
    pub build_url: Option<String>,
    pub build_number: Option<String>,
    pub job_name: Option<String>,
    pub workspace: Option<String>,
}

impl CiEnvironment {
    /// Detect and create CI environment from current environment
    pub fn detect() -> Option<Self> {
        let platform = detect_ci_platform()?;
        Some(Self {
            platform,
            build_url: std::env::var(ENV_BUILD_URL).ok(),
            build_number: std::env::var(ENV_BUILD_NUMBER).ok(),
            job_name: std::env::var(ENV_JOB_NAME).ok(),
            workspace: std::env::var(ENV_WORKSPACE).ok(),
        })
    }

    /// Check if running in CI environment
    pub fn is_ci() -> bool {
        detect_ci_platform().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_platform_from_str() {
        assert_eq!("jenkins".parse::<CiPlatform>().unwrap(), CiPlatform::Jenkins);
        assert_eq!("github".parse::<CiPlatform>().unwrap(), CiPlatform::GitHubActions);
        assert_eq!("gitlab".parse::<CiPlatform>().unwrap(), CiPlatform::GitLabCi);
        assert_eq!("azure".parse::<CiPlatform>().unwrap(), CiPlatform::AzureDevOps);
    }

    #[test]
    fn test_ci_platform_display() {
        assert_eq!(CiPlatform::Jenkins.to_string(), "Jenkins");
        assert_eq!(CiPlatform::GitHubActions.to_string(), "GitHub Actions");
    }
}
