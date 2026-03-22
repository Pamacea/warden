//! Oalacea Warden library
//!
//! This library provides the core functionality for the Warden security scanner.

pub mod analysis;
pub mod audit;
pub mod auth;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod detection;
pub mod error;
pub mod integrations;
pub mod ml;
pub mod payloads;
pub mod progress;
pub mod recon;
pub mod reporters;
pub mod scanners;
pub mod scoring;
pub mod utils;

pub use analysis::{
    false_positives::{
        ExploitComplexity, ExploitabilityFactors, FalsePositiveAnalyzer,
        FalsePositiveFilter, FindingCluster, PrivilegeLevel, ProbabilisticScore,
        SimilarityConfig, UserFeedback, VulnContext,
    },
};
pub use auth::{
    // RBAC exports
    AuditAction, AuditEntry, AuditCategory, AuditExportFormat, AuditLog, AuditTrail, Permission,
    PermissionCategory, PermissionCheck, PermissionSet, PermissionSource, Role, RoleBuilder,
    RoleInheritance, RbacError, RbacManager, RbacResult, User, UserId, UserRoleAssignment,
    // SAML exports
    IdentityProviderType, SamlAuthManager, SamlAuthnRequest, SamlAuthResult,
    SamlConfig, SamlError, SamlMetadataGenerator, SamlSession,
    ServiceProviderConfig, WardenRole,
};
pub use cli::{Cli, Commands, ConfigAction};
pub use config::{Config, ConfigError, ProfileConfig};
pub use error::{ScannerError, StaticAnalysisError};
pub use detection::{DetectInfo, Framework, Language};
pub use ml::{
    AdaptiveSeverity, Anomaly, AnomalyConfig, AnomalyReport, AnomalySeverity, AnomalyType,
    BehavioralProfile, EndpointStats, FeatureConfig, MlDetector, MlUserFeedback, ParameterStats,
    TfidfFeatures, VulnCluster, ZeroDayCandidate,
};
pub use payloads::{
    BypassTechnique, ExpectedBehavior, FuzzingGrammar, PayloadCategory, PayloadContext,
    PayloadDataType, PayloadGenerator, PayloadLearning, PayloadSeverity, PayloadStats,
    PayloadStrategy, ResponseAnalysis, SmartPayload, SmartPayloadSelector,
};
pub use progress::{ErrorReporter, Prompt, ScanProgress, ScannerType, StatusPrinter};
pub use recon::{
    smart::{
        ActiveReconResult, ApiEndpointInfo, Asset, AssetType, AttackSurfaceMap,
        DnsRecord, HeaderAnalysis, ParameterInfo, ReconResult, SearchEngineFinding,
        ShodanFinding, SmartReconScanner, SubdomainResult, TechnologyFingerprint,
    },
};
pub use reporters::ReportFormat;
pub use scanners::{ScannerEngine, ScanReport, Vuln, VulnSeverity};
pub use scanners::r#trait::{
    ScannerCategory, ScannerMetadata, ScannerRegistry, ScannerSeverity, SecurityScanner, TargetType,
};
pub use scanners::parser_cache::{parse_file_cached, CachedParse, ParserCache, ParserLanguage};
pub use scoring::{CategoryScore, Grade, SecurityScore};

/// Daemon exports for v0.8.0 Enterprise Edition
pub use daemon::{
    ContinuousDaemon, DaemonConfig, DaemonStatus, DaemonStatistics, MonitorEvent,
    NotificationLevel, ScanJob, ScanJobStatus, ScanMetrics, ScanMonitor, ScanPriority,
    ScanTrigger, ScheduledScan, Scheduler, WebhookClient, WebhookConfig, WebhookType,
};

/// Integration exports for v0.8.0 Enterprise Edition
pub use integrations::{
    CiEnvironment, CiPlatform, detect_ci_platform,
    // GitHub integration
    CheckAnnotation, AnnotationLevel, CommitInfo, CommitRef, GitHubApp, GitHubClient,
    GitHubConfig, GitHubIssue, GitHubWebhook, GitHubWebhookEvent, PrComment, PullRequestInfo,
    RepoOwner, RepositoryInfo, SecurityBadge, SenderInfo, StatusCheck, UserInfo,
    parse_webhook, verify_webhook_signature,
    // Jenkins integration
    JenkinsBuildStep, JenkinsConfig, JenkinsConsoleFormatter, JenkinsFailureThreshold,
    JenkinsNotificationConfig, JenkinsPlugin, JenkinsReportFormat, JenkinsResult,
    // GitLab integration
    GitLabClient, GitLabConfig, GitLabIntegration, GitLabCiGenerator,
    GitLabMRScanner, GitLabMRScanResult, GitLabBadgeGenerator,
    GitLabWebhookEvent, parse_gitlab_webhook,
    GitLabProject, GitLabRepository, GitLabPipeline, GitLabMergeRequest,
    GitLabIssue, GitLabSastReport,
};

/// Audit logging exports for v0.8.0 Enterprise Edition (SOC2/ISO27001 compliant)
pub use audit::{
    AuditConfig, AuditError, AuditEvent, AuditFilter, AuditLogger, AuditMetadata,
    AuditResult, AuditStatistics, ChainOfCustody, ChainMetadata, ChainStatistics,
    EventResult, EventSeverity, EventType, LogEntry, LogVerification,
    RetentionPolicy, RetentionManager, SiemConfig, SiemDestination, SiemExporter,
    SyslogConfig, AlertConfig, AlertManager, AlertNotification, AlertRule,
    AlertThreshold, NotificationChannel, RetentionAction, ArchiveLocation,
    AUDIT_LOG_VERSION, DEFAULT_AUDIT_DIR, MAX_ENTRY_SIZE_BYTES,
};

/// Warden version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
