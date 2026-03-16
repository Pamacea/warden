//! Role-Based Access Control (RBAC) System
//!
//! This module implements a comprehensive RBAC system for Warden v0.8.0 Enterprise Edition.
//!
//! # Features
//!
//! - **Role Definitions**: Admin, User, Viewer, and Custom roles
//! - **Permission Management**: Granular per-scanner, per-target, and per-report permissions
//! - **Role Management**: Create custom roles, assign users, role inheritance
//! - **Audit Trail**: Log all actions, role changes, permission denials
//! - **Storage**: JSON file-based storage for users, roles, and audit logs
//!
//! # Usage
//!
//! ```rust
//! use warden::auth::{RbacManager, Role, Permission};
//!
//! // Initialize RBAC manager
//! let rbac = RbacManager::new("./data").await?;
//!
//! // Create a user
//! let user = rbac.create_user("alice", "alice@example.com").await?;
//!
//! // Assign a role
//! rbac.assign_role(user.id(), &Role::Admin).await?;
//!
//! // Check permissions
//! if rbac.check_permission(&user, Permission::ScanHttp).await? {
//!     // Allow HTTP scanning
//! }
//! ```
//!
//! # Default Roles
//!
//! ## Admin
//! - Full access to all scanners
//! - Can create and modify roles
//! - Can assign roles to users
//! - Can modify configuration
//! - Full access to all reports
//! - Can manage audit logs
//!
//! ## User
//! - Limited scanner access (configurable)
//! - Cannot create or modify roles
//! - Cannot assign roles
//! - Read-only access to own reports
//! - Cannot modify configuration
//!
//! ## Viewer
//! - Read-only access to reports
//! - Cannot initiate scans
//! - Cannot modify anything
//! - Limited to assigned targets
//!
//! # Permission Categories
//!
//! - **Scanner Permissions**: Control which security scanners can be used
//! - **Target Permissions**: Control which targets can be scanned
//! - **Report Permissions**: Control access to scan reports
//! - **Configuration Permissions**: Control ability to modify Warden configuration
//! - **Admin Permissions**: Control user and role management

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

// =============================================================================
// Role Definitions
// =============================================================================

/// Built-in roles with predefined permission sets
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Administrator with full access
    Admin,
    /// Standard user with limited scanner access
    User,
    /// Read-only viewer
    Viewer,
    /// Custom role with specific permissions
    Custom(String),
}

impl Role {
    /// Get the display name of the role
    pub fn display_name(&self) -> String {
        match self {
            Role::Admin => "Administrator".to_string(),
            Role::User => "Standard User".to_string(),
            Role::Viewer => "Viewer".to_string(),
            Role::Custom(name) => format!("Custom: {}", name),
        }
    }

    /// Get the default permission set for this role
    pub fn default_permissions(&self) -> PermissionSet {
        match self {
            Role::Admin => PermissionSet::admin(),
            Role::User => PermissionSet::user(),
            Role::Viewer => PermissionSet::viewer(),
            Role::Custom(_) => PermissionSet::none(),
        }
    }

    /// Get a short identifier for the role
    pub fn id(&self) -> String {
        match self {
            Role::Admin => "admin".to_string(),
            Role::User => "user".to_string(),
            Role::Viewer => "viewer".to_string(),
            Role::Custom(name) => format!("custom:{}", name),
        }
    }

    /// Parse a role from a string
    pub fn from_str(s: &str) -> Result<Self, RbacError> {
        match s {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            "viewer" => Ok(Role::Viewer),
            s if s.starts_with("custom:") => {
                let name = s.strip_prefix("custom:").unwrap_or(s);
                Ok(Role::Custom(name.to_string()))
            }
            _ => Err(RbacError::InvalidRole(s.to_string())),
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// Builder for creating custom roles
pub struct RoleBuilder {
    name: String,
    permissions: PermissionSet,
    inherits: Option<Role>,
    description: String,
}

impl RoleBuilder {
    /// Create a new custom role builder
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            permissions: PermissionSet::none(),
            inherits: None,
            description: String::new(),
        }
    }

    /// Set the role description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a permission to the role
    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.grant(permission);
        self
    }

    /// Add multiple permissions to the role
    pub fn with_permissions(mut self, permissions: impl IntoIterator<Item = Permission>) -> Self {
        for perm in permissions {
            self.permissions.grant(perm);
        }
        self
    }

    /// Set role inheritance
    pub fn inherits(mut self, role: Role) -> Self {
        self.inherits = Some(role);
        self
    }

    /// Build the custom role
    pub fn build(self) -> Role {
        Role::Custom(self.name)
    }

    /// Build with the permission set
    pub fn build_with_permissions(self) -> (Role, PermissionSet, Option<Role>, String) {
        (Role::Custom(self.name), self.permissions, self.inherits, self.description)
    }
}

/// Role inheritance configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleInheritance {
    /// The child role
    pub child: Role,
    /// The parent role to inherit from
    pub parent: Role,
    /// Whether inheritance is active
    pub active: bool,
}

impl RoleInheritance {
    /// Create a new role inheritance
    pub fn new(child: Role, parent: Role) -> Self {
        Self {
            child,
            parent,
            active: true,
        }
    }

    /// Deactivate the inheritance
    pub fn deactivate(mut self) -> Self {
        self.active = false;
        self
    }
}

// =============================================================================
// Permissions
// =============================================================================

/// Individual permission that can be granted to a role
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Scanner Permissions
    /// Can run HTTP security scanner
    ScanHttp,
    /// Can run Port scanner
    ScanPort,
    /// Can run Static code analyzer
    ScanStatic,
    /// Can run API scanner
    ScanApi,
    /// Can run Reconnaissance scanner
    ScanRecon,
    /// Can run DDoS resistance scanner
    ScanDdos,
    /// Can run Stress testing scanner
    ScanStress,
    /// Can run Secrets leak scanner
    ScanSecrets,
    /// Can run Dependency vulnerability scanner
    ScanDependencies,
    /// Can run all scanners (wildcard)
    ScanAll,

    // Target Permissions
    /// Can scan specific targets (white-listed)
    ScanTargetWhitelist,
    /// Can scan any target
    ScanTargetAny,
    /// Can scan internal network targets
    ScanTargetInternal,
    /// Can scan external/Internet targets
    ScanTargetExternal,

    // Report Permissions
    /// Can view own reports
    ViewOwnReports,
    /// Can view all reports
    ViewAllReports,
    /// Can export reports
    ExportReports,
    /// Can delete reports
    DeleteReports,

    // Configuration Permissions
    /// Can view configuration
    ViewConfig,
    /// Can modify configuration
    ModifyConfig,
    /// Can create and modify profiles
    ManageProfiles,

    // Admin Permissions
    /// Can create users
    CreateUser,
    /// Can delete users
    DeleteUser,
    /// Can assign roles to users
    AssignRoles,
    /// Can create custom roles
    CreateRole,
    /// Can modify roles
    ModifyRole,
    /// Can delete roles
    DeleteRole,
    /// Can view audit logs
    ViewAuditLogs,
    /// Can export audit logs
    ExportAuditLogs,
    /// Can clear audit logs
    ClearAuditLogs,

    // Special Permissions
    /// Bypass all permission checks (super admin)
    BypassAll,
}

impl Permission {
    /// Get all scanner permissions
    pub fn all_scanners() -> Vec<Permission> {
        vec![
            Permission::ScanHttp,
            Permission::ScanPort,
            Permission::ScanStatic,
            Permission::ScanApi,
            Permission::ScanRecon,
            Permission::ScanDdos,
            Permission::ScanStress,
            Permission::ScanSecrets,
            Permission::ScanDependencies,
        ]
    }

    /// Get the category of this permission
    pub fn category(&self) -> PermissionCategory {
        match self {
            Permission::ScanHttp
            | Permission::ScanPort
            | Permission::ScanStatic
            | Permission::ScanApi
            | Permission::ScanRecon
            | Permission::ScanDdos
            | Permission::ScanStress
            | Permission::ScanSecrets
            | Permission::ScanDependencies
            | Permission::ScanAll => PermissionCategory::Scanner,

            Permission::ScanTargetWhitelist
            | Permission::ScanTargetAny
            | Permission::ScanTargetInternal
            | Permission::ScanTargetExternal => PermissionCategory::Target,

            Permission::ViewOwnReports
            | Permission::ViewAllReports
            | Permission::ExportReports
            | Permission::DeleteReports => PermissionCategory::Report,

            Permission::ViewConfig
            | Permission::ModifyConfig
            | Permission::ManageProfiles => PermissionCategory::Configuration,

            Permission::CreateUser
            | Permission::DeleteUser
            | Permission::AssignRoles
            | Permission::CreateRole
            | Permission::ModifyRole
            | Permission::DeleteRole
            | Permission::ViewAuditLogs
            | Permission::ExportAuditLogs
            | Permission::ClearAuditLogs
            | Permission::BypassAll => PermissionCategory::Admin,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Permission::ScanHttp => "scan.http",
            Permission::ScanPort => "scan.port",
            Permission::ScanStatic => "scan.static",
            Permission::ScanApi => "scan.api",
            Permission::ScanRecon => "scan.recon",
            Permission::ScanDdos => "scan.ddos",
            Permission::ScanStress => "scan.stress",
            Permission::ScanSecrets => "scan.secrets",
            Permission::ScanDependencies => "scan.dependencies",
            Permission::ScanAll => "scan.*",
            Permission::ScanTargetWhitelist => "target.whitelist",
            Permission::ScanTargetAny => "target.any",
            Permission::ScanTargetInternal => "target.internal",
            Permission::ScanTargetExternal => "target.external",
            Permission::ViewOwnReports => "report.view_own",
            Permission::ViewAllReports => "report.view_all",
            Permission::ExportReports => "report.export",
            Permission::DeleteReports => "report.delete",
            Permission::ViewConfig => "config.view",
            Permission::ModifyConfig => "config.modify",
            Permission::ManageProfiles => "config.manage_profiles",
            Permission::CreateUser => "admin.create_user",
            Permission::DeleteUser => "admin.delete_user",
            Permission::AssignRoles => "admin.assign_roles",
            Permission::CreateRole => "admin.create_role",
            Permission::ModifyRole => "admin.modify_role",
            Permission::DeleteRole => "admin.delete_role",
            Permission::ViewAuditLogs => "admin.view_audit",
            Permission::ExportAuditLogs => "admin.export_audit",
            Permission::ClearAuditLogs => "admin.clear_audit",
            Permission::BypassAll => "admin.bypass_all",
        };
        write!(f, "{}", s)
    }
}

/// Permission category for grouping
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionCategory {
    Scanner,
    Target,
    Report,
    Configuration,
    Admin,
}

/// A set of permissions with role inheritance support
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionSet {
    /// Direct permissions granted to this role
    permissions: HashSet<String>,
    /// Permissions inherited from parent roles
    inherited: HashSet<String>,
}

impl PermissionSet {
    /// Create an empty permission set
    pub fn none() -> Self {
        Self {
            permissions: HashSet::new(),
            inherited: HashSet::new(),
        }
    }

    /// Create admin permission set (all permissions)
    pub fn admin() -> Self {
        let mut set = Self::none();
        for perm in Permission::all_scanners() {
            set.grant(perm);
        }
        set.grant(Permission::ScanAll);
        set.grant(Permission::ScanTargetAny);
        set.grant(Permission::ViewAllReports);
        set.grant(Permission::ExportReports);
        set.grant(Permission::DeleteReports);
        set.grant(Permission::ViewConfig);
        set.grant(Permission::ModifyConfig);
        set.grant(Permission::ManageProfiles);
        set.grant(Permission::CreateUser);
        set.grant(Permission::DeleteUser);
        set.grant(Permission::AssignRoles);
        set.grant(Permission::CreateRole);
        set.grant(Permission::ModifyRole);
        set.grant(Permission::DeleteRole);
        set.grant(Permission::ViewAuditLogs);
        set.grant(Permission::ExportAuditLogs);
        set.grant(Permission::ClearAuditLogs);
        set.grant(Permission::BypassAll);
        set
    }

    /// Create standard user permission set
    pub fn user() -> Self {
        let mut set = Self::none();
        set.grant(Permission::ScanHttp);
        set.grant(Permission::ScanPort);
        set.grant(Permission::ScanStatic);
        set.grant(Permission::ScanTargetWhitelist);
        set.grant(Permission::ViewOwnReports);
        set.grant(Permission::ExportReports);
        set.grant(Permission::ViewConfig);
        set
    }

    /// Create viewer permission set (read-only)
    pub fn viewer() -> Self {
        let mut set = Self::none();
        set.grant(Permission::ViewOwnReports);
        set
    }

    /// Grant a permission
    pub fn grant(&mut self, permission: Permission) {
        self.permissions.insert(permission.to_string());
    }

    /// Revoke a permission
    pub fn revoke(&mut self, permission: &Permission) {
        self.permissions.remove(&permission.to_string());
    }

    /// Check if a permission is granted
    pub fn has(&self, permission: &Permission) -> bool {
        // Check bypass first
        if self.permissions.contains(&Permission::BypassAll.to_string())
            || self.inherited.contains(&Permission::BypassAll.to_string())
        {
            return true;
        }

        // Check wildcard
        if self.permissions.contains(&Permission::ScanAll.to_string())
            || self.inherited.contains(&Permission::ScanAll.to_string())
        {
            if matches!(permission.category(), PermissionCategory::Scanner) {
                return true;
            }
        }

        // Check direct permission
        if self.permissions.contains(&permission.to_string()) {
            return true;
        }

        // Check inherited permission
        self.inherited.contains(&permission.to_string())
    }

    /// Add inherited permissions from a parent role
    pub fn inherit_from(&mut self, parent: &PermissionSet) {
        self.inherited = parent.permissions.clone().into_iter().collect();
    }

    /// Get all permissions (direct + inherited)
    pub fn all_permissions(&self) -> HashSet<String> {
        let mut all = self.permissions.clone();
        all.extend(self.inherited.clone());
        all
    }

    /// Get permissions by category
    pub fn by_category(&self, category: PermissionCategory) -> Vec<Permission> {
        let all = self.all_permissions();
        Permission::all_scanners()
            .into_iter()
            .filter(|p| p.category() == category && all.contains(&p.to_string()))
            .collect()
    }
}

// =============================================================================
// User Management
// =============================================================================

/// Unique user identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(Uuid);

impl UserId {
    /// Generate a new user ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from UUID string
    pub fn from_str(s: &str) -> Result<Self, RbacError> {
        let uuid = Uuid::parse_str(s).map_err(|_| RbacError::InvalidUserId(s.to_string()))?;
        Ok(Self(uuid))
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// User account
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// Unique user ID
    id: UserId,
    /// Username
    username: String,
    /// Email address
    email: String,
    /// Whether the user is active
    active: bool,
    /// When the user was created
    created_at: DateTime<Utc>,
    /// When the user was last updated
    updated_at: DateTime<Utc>,
    /// User metadata
    metadata: HashMap<String, String>,
}

impl User {
    /// Create a new user
    pub fn new(username: impl Into<String>, email: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            username: username.into(),
            email: email.into(),
            active: true,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    /// Get the user ID
    pub fn id(&self) -> &UserId {
        &self.id
    }

    /// Get the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the email
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Check if the user is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the active status
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
        self.updated_at = Utc::now();
    }

    /// Get metadata value
    pub fn metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Set metadata value
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
        self.updated_at = Utc::now();
    }
}

/// Assignment of a role to a user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRoleAssignment {
    /// The user ID
    pub user_id: UserId,
    /// The assigned role
    pub role: Role,
    /// When the assignment was created
    pub assigned_at: DateTime<Utc>,
    /// When the assignment expires (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Who made the assignment
    pub assigned_by: Option<UserId>,
    /// Assignment metadata
    pub metadata: HashMap<String, String>,
}

impl UserRoleAssignment {
    /// Create a new role assignment
    pub fn new(user_id: UserId, role: Role) -> Self {
        Self {
            user_id,
            role,
            assigned_at: Utc::now(),
            expires_at: None,
            assigned_by: None,
            metadata: HashMap::new(),
        }
    }

    /// Set expiration for the assignment
    pub fn expires_at(mut self, expires: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires);
        self
    }

    /// Set who made the assignment
    pub fn assigned_by(mut self, by: UserId) -> Self {
        self.assigned_by = Some(by);
        self
    }

    /// Check if the assignment is still valid
    pub fn is_valid(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() < expires
        } else {
            true
        }
    }
}

// =============================================================================
// Audit Trail
// =============================================================================

/// Actions that can be audited
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // User actions
    UserCreated,
    UserDeleted,
    UserModified,
    UserActivated,
    UserDeactivated,

    // Role actions
    RoleCreated,
    RoleDeleted,
    RoleModified,
    RoleAssigned,
    RoleRevoked,

    // Permission actions
    PermissionGranted,
    PermissionRevoked,

    // Scan actions
    ScanInitiated,
    ScanCompleted,
    ScanFailed,
    ScanCancelled,

    // Report actions
    ReportViewed,
    ReportExported,
    ReportDeleted,

    // Config actions
    ConfigViewed,
    ConfigModified,

    // Audit actions
    AuditLogViewed,
    AuditLogExported,
    AuditLogCleared,

    // Permission denials
    PermissionDenied,
}

impl AuditAction {
    /// Get the category of this action
    pub fn category(&self) -> AuditCategory {
        match self {
            AuditAction::UserCreated
            | AuditAction::UserDeleted
            | AuditAction::UserModified
            | AuditAction::UserActivated
            | AuditAction::UserDeactivated => AuditCategory::User,

            AuditAction::RoleCreated
            | AuditAction::RoleDeleted
            | AuditAction::RoleModified
            | AuditAction::RoleAssigned
            | AuditAction::RoleRevoked
            | AuditAction::PermissionGranted
            | AuditAction::PermissionRevoked => AuditCategory::Role,

            AuditAction::ScanInitiated
            | AuditAction::ScanCompleted
            | AuditAction::ScanFailed
            | AuditAction::ScanCancelled => AuditCategory::Scan,

            AuditAction::ReportViewed
            | AuditAction::ReportExported
            | AuditAction::ReportDeleted => AuditCategory::Report,

            AuditAction::ConfigViewed
            | AuditAction::ConfigModified => AuditCategory::Configuration,

            AuditAction::AuditLogViewed
            | AuditAction::AuditLogExported
            | AuditAction::AuditLogCleared
            | AuditAction::PermissionDenied => AuditCategory::Audit,
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuditAction::UserCreated => "user.created",
            AuditAction::UserDeleted => "user.deleted",
            AuditAction::UserModified => "user.modified",
            AuditAction::UserActivated => "user.activated",
            AuditAction::UserDeactivated => "user.deactivated",
            AuditAction::RoleCreated => "role.created",
            AuditAction::RoleDeleted => "role.deleted",
            AuditAction::RoleModified => "role.modified",
            AuditAction::RoleAssigned => "role.assigned",
            AuditAction::RoleRevoked => "role.revoked",
            AuditAction::PermissionGranted => "permission.granted",
            AuditAction::PermissionRevoked => "permission.revoked",
            AuditAction::ScanInitiated => "scan.initiated",
            AuditAction::ScanCompleted => "scan.completed",
            AuditAction::ScanFailed => "scan.failed",
            AuditAction::ScanCancelled => "scan.cancelled",
            AuditAction::ReportViewed => "report.viewed",
            AuditAction::ReportExported => "report.exported",
            AuditAction::ReportDeleted => "report.deleted",
            AuditAction::ConfigViewed => "config.viewed",
            AuditAction::ConfigModified => "config.modified",
            AuditAction::AuditLogViewed => "audit.viewed",
            AuditAction::AuditLogExported => "audit.exported",
            AuditAction::AuditLogCleared => "audit.cleared",
            AuditAction::PermissionDenied => "permission.denied",
        };
        write!(f, "{}", s)
    }
}

/// Audit entry categories
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    User,
    Role,
    Scan,
    Report,
    Configuration,
    Audit,
}

/// A single audit log entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: Uuid,
    /// The action that was performed
    pub action: AuditAction,
    /// User who performed the action
    pub actor: Option<UserId>,
    /// Target user (if applicable)
    pub target_user: Option<UserId>,
    /// Target role (if applicable)
    pub target_role: Option<Role>,
    /// The permission involved (if applicable)
    pub permission: Option<Permission>,
    /// IP address of the actor
    pub ip_address: Option<String>,
    /// User agent of the actor
    pub user_agent: Option<String>,
    /// Additional context
    pub context: HashMap<String, String>,
    /// When the action occurred
    pub timestamp: DateTime<Utc>,
    /// Whether the action succeeded
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(action: AuditAction) -> Self {
        Self {
            id: Uuid::new_v4(),
            action,
            actor: None,
            target_user: None,
            target_role: None,
            permission: None,
            ip_address: None,
            user_agent: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
            success: true,
            error: None,
        }
    }

    /// Set the actor
    pub fn actor(mut self, user: &User) -> Self {
        self.actor = Some(user.id().clone());
        self
    }

    /// Set the target user
    pub fn target_user(mut self, user: &User) -> Self {
        self.target_user = Some(user.id().clone());
        self
    }

    /// Set the target role
    pub fn target_role(mut self, role: Role) -> Self {
        self.target_role = Some(role);
        self
    }

    /// Set the permission
    pub fn permission(mut self, perm: Permission) -> Self {
        self.permission = Some(perm);
        self
    }

    /// Set IP address
    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set user agent
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Add context
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Mark as failed with error
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error = Some(error.into());
        self
    }
}

/// Export format for audit logs
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportFormat {
    Json,
    Csv,
    JsonLines,
}

/// Audit trail storage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLog {
    /// List of audit entries
    entries: Vec<AuditEntry>,
    /// Maximum number of entries to keep
    max_entries: usize,
}

impl AuditLog {
    /// Create a new audit log
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: 10000,
        }
    }

    /// Add an entry to the audit log
    pub fn add(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
        self.trim();
    }

    /// Trim old entries if exceeding max
    fn trim(&mut self) {
        if self.entries.len() > self.max_entries {
            let remove = self.entries.len() - self.max_entries;
            self.entries.drain(0..remove);
        }
    }

    /// Get all entries
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Filter entries by user
    pub fn by_user(&self, user: &User) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.actor.as_ref() == Some(user.id()))
            .collect()
    }

    /// Filter entries by action
    pub fn by_action(&self, action: AuditAction) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.action == action)
            .collect()
    }

    /// Filter entries by date range
    pub fn by_date_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Get only failed entries (permission denials, etc)
    pub fn failures(&self) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| !e.success)
            .collect()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Export to specified format
    pub fn export(&self, format: AuditExportFormat) -> Result<String, RbacError> {
        match format {
            AuditExportFormat::Json => {
                serde_json::to_string_pretty(&self.entries)
                    .map_err(|e| RbacError::ExportError(e.to_string()))
            }
            AuditExportFormat::JsonLines => {
                self.entries
                    .iter()
                    .map(|e| serde_json::to_string(e).map_err(|e| RbacError::ExportError(e.to_string())))
                    .collect::<Result<Vec<_>, _>>()
                    .map(|lines| lines.join("\n"))
            }
            AuditExportFormat::Csv => {
                let mut output = String::from("timestamp,action,actor,target_user,success,error\n");
                for entry in &self.entries {
                    output.push_str(&format!(
                        "{},{},{:?},{:?},{},{}\n",
                        entry.timestamp,
                        entry.action,
                        entry.actor,
                        entry.target_user,
                        entry.success,
                        entry.error.as_deref().unwrap_or("")
                    ));
                }
                Ok(output)
            }
        }
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Audit trail manager
#[derive(Clone)]
pub struct AuditTrail {
    log: Arc<RwLock<AuditLog>>,
    storage_path: PathBuf,
}

impl AuditTrail {
    /// Create a new audit trail
    pub fn new(storage_path: &Path) -> Result<Self> {
        let audit_path = storage_path.join("audit.json");
        let log = if audit_path.exists() {
            let content = fs::read_to_string(&audit_path)
                .context("Failed to read audit log")?;
            serde_json::from_str(&content)
                .context("Failed to parse audit log")?
        } else {
            AuditLog::new()
        };

        Ok(Self {
            log: Arc::new(RwLock::new(log)),
            storage_path: storage_path.to_path_buf(),
        })
    }

    /// Log an action
    pub fn log(&self, entry: AuditEntry) -> RbacResult<()> {
        let mut log = self.log.write()
            .map_err(|_| RbacError::LockError)?;
        log.add(entry);
        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }
        Ok(())
    }

    /// Get all entries
    pub fn entries(&self) -> RbacResult<Vec<AuditEntry>> {
        let log = self.log.read()
            .map_err(|_| RbacError::LockError)?;
        Ok(log.entries().to_vec())
    }

    /// Get entries by user
    pub fn by_user(&self, user: &User) -> RbacResult<Vec<AuditEntry>> {
        let log = self.log.read()
            .map_err(|_| RbacError::LockError)?;
        Ok(log.by_user(user).into_iter().cloned().collect())
    }

    /// Get failed entries
    pub fn failures(&self) -> RbacResult<Vec<AuditEntry>> {
        let log = self.log.read()
            .map_err(|_| RbacError::LockError)?;
        Ok(log.failures().into_iter().cloned().collect())
    }

    /// Export audit log
    pub fn export(&self, format: AuditExportFormat) -> RbacResult<String> {
        let log = self.log.read()
            .map_err(|_| RbacError::LockError)?;
        log.export(format)
    }

    /// Clear audit log
    pub fn clear(&self) -> RbacResult<()> {
        let mut log = self.log.write()
            .map_err(|_| RbacError::LockError)?;
        log.clear();
        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }
        Ok(())
    }

    /// Persist audit log to disk (internal, returns anyhow::Error)
    fn persist_internal(&self) -> Result<()> {
        let log = self.log.read()
            .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        let content = serde_json::to_string_pretty(&*log)
            .context("Failed to serialize audit log")?;
        fs::write(self.storage_path.join("audit.json"), content)
            .context("Failed to write audit log")?;
        Ok(())
    }
}

// =============================================================================
// RBAC Manager
// =============================================================================

/// Storage for RBAC data
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RbacStorage {
    users: HashMap<String, User>,
    role_assignments: Vec<UserRoleAssignment>,
    custom_roles: HashMap<String, (PermissionSet, Option<Role>, String)>,
}

impl Default for RbacStorage {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            role_assignments: Vec::new(),
            custom_roles: HashMap::new(),
        }
    }
}

/// Result type for RBAC operations
pub type RbacResult<T> = Result<T, RbacError>;

/// RBAC errors
#[derive(Clone, Debug, thiserror::Error)]
pub enum RbacError {
    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Invalid role: {0}")]
    InvalidRole(String),

    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Role already assigned to user")]
    RoleAlreadyAssigned,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("Lock error")]
    LockError,

    #[error("IO error: {0}")]
    IoError(String),
}

/// Main RBAC manager
#[derive(Clone)]
pub struct RbacManager {
    storage: Arc<RwLock<RbacStorage>>,
    storage_path: PathBuf,
    audit: AuditTrail,
}

impl RbacManager {
    /// Create a new RBAC manager
    pub async fn new(storage_path: impl AsRef<Path>) -> Result<Self> {
        let storage_path = storage_path.as_ref();

        // Create storage directory if it doesn't exist
        fs::create_dir_all(storage_path)
            .context("Failed to create storage directory")?;

        // Load or create storage
        let storage_file = storage_path.join("rbac.json");
        let storage = if storage_file.exists() {
            let content = fs::read_to_string(&storage_file)?;
            serde_json::from_str(&content)?
        } else {
            RbacStorage::default()
        };

        // Create audit trail
        let audit = AuditTrail::new(storage_path)?;

        let manager = Self {
            storage: Arc::new(RwLock::new(storage)),
            storage_path: storage_path.to_path_buf(),
            audit,
        };

        Ok(manager)
    }

    /// Persist storage to disk (internal, returns anyhow::Error)
    fn persist_internal(&self) -> Result<()> {
        let storage = self.storage.read()
            .map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;
        let content = serde_json::to_string_pretty(&*storage)
            .context("Failed to serialize storage")?;
        fs::write(self.storage_path.join("rbac.json"), content)
            .context("Failed to write storage")?;
        Ok(())
    }

    // =========================================================================
    // User Management
    // =========================================================================

    /// Create a new user
    pub async fn create_user(&self, username: &str, email: &str) -> RbacResult<User> {
        let mut storage = self.storage.write()
            .map_err(|_| RbacError::LockError)?;

        // Check if user already exists
        if storage.users.contains_key(username) {
            return Err(RbacError::StorageError(format!("User '{}' already exists", username)));
        }

        let user = User::new(username, email);
        storage.users.insert(username.to_string(), user.clone());

        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }

        // Log the action
        let _ = self.audit.log(
            AuditEntry::new(AuditAction::UserCreated)
                .target_user(&user)
        );

        Ok(user)
    }

    /// Get a user by username
    pub async fn get_user(&self, username: &str) -> RbacResult<User> {
        let storage = self.storage.read()
            .map_err(|_| RbacError::LockError)?;

        storage.users.get(username)
            .cloned()
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))
    }

    /// Delete a user
    pub async fn delete_user(&self, username: &str) -> RbacResult<()> {
        let mut storage = self.storage.write()
            .map_err(|_| RbacError::LockError)?;

        let user = storage.users.get(username)
            .ok_or_else(|| RbacError::UserNotFound(username.to_string()))?
            .clone();

        // Remove role assignments
        storage.role_assignments.retain(|a| a.user_id != *user.id());

        // Remove user
        storage.users.remove(username);

        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }

        // Log the action
        let _ = self.audit.log(
            AuditEntry::new(AuditAction::UserDeleted)
                .target_user(&user)
        );

        Ok(())
    }

    /// List all users
    pub async fn list_users(&self) -> RbacResult<Vec<User>> {
        let storage = self.storage.read()
            .map_err(|_| RbacError::LockError)?;
        Ok(storage.users.values().cloned().collect())
    }

    // =========================================================================
    // Role Management
    // =========================================================================

    /// Assign a role to a user
    pub async fn assign_role(&self, user_id: &UserId, role: &Role) -> RbacResult<()> {
        let mut storage = self.storage.write()
            .map_err(|_| RbacError::LockError)?;

        // Check if user exists
        let user = storage.users.values()
            .find(|u| u.id() == user_id)
            .ok_or_else(|| RbacError::UserNotFound(user_id.to_string()))?
            .clone();

        // Check if role is already assigned
        if storage.role_assignments.iter()
            .any(|a| a.user_id == *user_id && a.role == *role)
        {
            return Err(RbacError::RoleAlreadyAssigned);
        }

        // Create assignment
        let assignment = UserRoleAssignment::new(user_id.clone(), role.clone());
        storage.role_assignments.push(assignment);

        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }

        // Log the action
        let _ = self.audit.log(
            AuditEntry::new(AuditAction::RoleAssigned)
                .target_user(&user)
                .target_role(role.clone())
        );

        Ok(())
    }

    /// Revoke a role from a user
    pub async fn revoke_role(&self, user_id: &UserId, role: &Role) -> RbacResult<()> {
        let mut storage = self.storage.write()
            .map_err(|_| RbacError::LockError)?;

        // Find user
        let user = storage.users.values()
            .find(|u| u.id() == user_id)
            .ok_or_else(|| RbacError::UserNotFound(user_id.to_string()))?
            .clone();

        // Remove assignment
        let initial_len = storage.role_assignments.len();
        storage.role_assignments.retain(|a| !(a.user_id == *user_id && a.role == *role));

        if storage.role_assignments.len() == initial_len {
            return Err(RbacError::StorageError("Role assignment not found".to_string()));
        }

        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }

        // Log the action
        let _ = self.audit.log(
            AuditEntry::new(AuditAction::RoleRevoked)
                .target_user(&user)
                .target_role(role.clone())
        );

        Ok(())
    }

    /// Get all roles assigned to a user
    pub async fn get_user_roles(&self, user_id: &UserId) -> RbacResult<Vec<Role>> {
        let storage = self.storage.read()
            .map_err(|_| RbacError::LockError)?;

        let roles: Vec<Role> = storage.role_assignments.iter()
            .filter(|a| a.user_id == *user_id && a.is_valid())
            .map(|a| a.role.clone())
            .collect();

        Ok(roles)
    }

    /// Create a custom role
    pub async fn create_custom_role(
        &self,
        name: &str,
        permissions: PermissionSet,
        inherits: Option<Role>,
        description: String,
    ) -> RbacResult<()> {
        let mut storage = self.storage.write()
            .map_err(|_| RbacError::LockError)?;

        storage.custom_roles.insert(
            name.to_string(),
            (permissions, inherits, description)
        );

        if let Err(e) = self.persist_internal() {
            return Err(RbacError::StorageError(e.to_string()));
        }

        // Log the action
        let _ = self.audit.log(
            AuditEntry::new(AuditAction::RoleCreated)
                .target_role(Role::Custom(name.to_string()))
        );

        Ok(())
    }

    /// Get permission set for a role (including inheritance)
    pub async fn get_role_permissions(&self, role: &Role) -> PermissionSet {
        self.get_role_permissions_internal(role, &mut Vec::new())
    }

    /// Internal recursive function to get permissions with cycle detection
    fn get_role_permissions_internal(&self, role: &Role, visited: &mut Vec<String>) -> PermissionSet {
        // Detect cycles
        let role_id = role.id();
        if visited.contains(&role_id) {
            return role.default_permissions();
        }
        visited.push(role_id.clone());

        let storage = self.storage.read().ok();

        let base_permissions = role.default_permissions();

        match role {
            Role::Custom(name) => {
                if let Some(storage) = storage {
                    if let Some((permissions, inherits, _)) = storage.custom_roles.get(name) {
                        let mut set = permissions.clone();
                        if let Some(parent) = inherits {
                            let parent_perms = self.get_role_permissions_internal(parent, visited);
                            set.inherit_from(&parent_perms);
                        }
                        visited.pop(); // Remove from visited before returning
                        return set;
                    }
                }
                visited.pop();
                PermissionSet::none()
            }
            _ => base_permissions,
        }
    }

    // =========================================================================
    // Permission Checking
    // =========================================================================

    /// Check if a user has a specific permission
    pub async fn check_permission(&self, user: &User, permission: Permission) -> RbacResult<bool> {
        // Check bypass
        let user_perms = self.get_effective_permissions(user).await?;
        if user_perms.has(&Permission::BypassAll) {
            return Ok(true);
        }

        let has_permission = user_perms.has(&permission);

        // Log permission check
        let entry = AuditEntry::new(AuditAction::PermissionDenied)
            .actor(user)
            .permission(permission.clone());

        if has_permission {
            let _ = self.audit.log(
                AuditEntry::new(AuditAction::ConfigViewed) // Generic successful action
                    .actor(user)
                    .with_context("permission", permission.to_string())
            );
            Ok(true)
        } else {
            let _ = self.audit.log(
                entry.failed(format!("Permission denied: {}", permission))
            );
            Ok(false)
        }
    }

    /// Check permission and return detailed result
    pub async fn check_permission_detailed(
        &self,
        user: &User,
        permission: Permission,
    ) -> RbacResult<PermissionCheck> {
        let has_perm = self.check_permission(user, permission.clone()).await?;

        Ok(PermissionCheck {
            permission: permission.clone(),
            granted: has_perm,
            source: if has_perm {
                PermissionSource::Direct
            } else {
                PermissionSource::None
            },
            roles: self.get_user_roles(user.id()).await?,
        })
    }

    /// Get all effective permissions for a user (from all roles)
    pub async fn get_effective_permissions(&self, user: &User) -> RbacResult<PermissionSet> {
        let roles = self.get_user_roles(user.id()).await?;

        let mut effective = PermissionSet::none();

        for role in &roles {
            let role_perms = self.get_role_permissions(role).await;
            // Merge permissions
            for perm_str in role_perms.all_permissions() {
                effective.permissions.insert(perm_str);
            }
        }

        Ok(effective)
    }

    /// Require a permission (return error if not granted)
    pub async fn require_permission(
        &self,
        user: &User,
        permission: Permission,
    ) -> RbacResult<()> {
        let has_perm = self.check_permission(user, permission.clone()).await?;
        if has_perm {
            Ok(())
        } else {
            Err(RbacError::PermissionDenied(permission.to_string()))
        }
    }

    // =========================================================================
    // Target Access Control
    // =========================================================================

    /// Check if user can scan a specific target
    pub async fn can_scan_target(&self, user: &User, _target: &str) -> RbacResult<bool> {
        let perms = self.get_effective_permissions(user).await?;

        // Check if user can scan any target
        if perms.has(&Permission::ScanTargetAny) || perms.has(&Permission::BypassAll) {
            return Ok(true);
        }

        // Check whitelist permission
        if perms.has(&Permission::ScanTargetWhitelist) {
            // TODO: Implement actual whitelist checking
            // For now, allow if whitelist permission is granted
            return Ok(true);
        }

        Ok(false)
    }

    // =========================================================================
    // Audit Trail
    // =========================================================================

    /// Get the audit trail
    pub fn audit(&self) -> &AuditTrail {
        &self.audit
    }

    /// Get audit entries for a user
    pub async fn get_user_audit_log(&self, user: &User) -> RbacResult<Vec<AuditEntry>> {
        Ok(self.audit.by_user(user)?)
    }

    /// Get all permission denials
    pub async fn get_permission_denials(&self) -> RbacResult<Vec<AuditEntry>> {
        Ok(self.audit.failures()?)
    }

    /// Export audit logs
    pub async fn export_audit_logs(&self, format: AuditExportFormat) -> RbacResult<String> {
        self.audit.export(format)
            .map_err(|e| RbacError::ExportError(e.to_string()))
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /// Get user ID from username
    pub async fn get_user_id(&self, username: &str) -> RbacResult<UserId> {
        let user = self.get_user(username).await?;
        Ok(user.id().clone())
    }

    /// Check if a user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        self.get_user(username).await.is_ok()
    }

    /// Display user information
    pub fn display_user(&self, user: &User) -> String {
        format!(
            "{} {} ({})",
            "User:".cyan().bold(),
            user.username().white().bold(),
            user.email().dimmed()
        )
    }

    /// Display role information
    pub fn display_role(&self, role: &Role) -> String {
        format!(
            "{} {}",
            "Role:".cyan().bold(),
            role.display_name().white().bold()
        )
    }
}

/// Permission check result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionCheck {
    /// The permission that was checked
    pub permission: Permission,
    /// Whether the permission was granted
    pub granted: bool,
    /// Source of the permission
    pub source: PermissionSource,
    /// Roles that provide this permission
    pub roles: Vec<Role>,
}

/// Where a permission comes from
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionSource {
    /// Directly granted
    Direct,
    /// Inherited from parent role
    Inherited,
    /// No permission found
    None,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_role_display_name() {
        assert_eq!(Role::Admin.display_name(), "Administrator");
        assert_eq!(Role::User.display_name(), "Standard User");
        assert_eq!(Role::Viewer.display_name(), "Viewer");
        assert_eq!(Role::Custom("Tester".to_string()).display_name(), "Custom: Tester");
    }

    #[tokio::test]
    async fn test_permission_set_admin() {
        let set = PermissionSet::admin();
        assert!(set.has(&Permission::BypassAll));
        assert!(set.has(&Permission::ScanHttp));
        assert!(set.has(&Permission::CreateUser));
    }

    #[tokio::test]
    async fn test_permission_set_user() {
        let set = PermissionSet::user();
        assert!(set.has(&Permission::ScanHttp));
        assert!(set.has(&Permission::ViewOwnReports));
        assert!(!set.has(&Permission::BypassAll));
        assert!(!set.has(&Permission::CreateUser));
    }

    #[tokio::test]
    async fn test_permission_set_viewer() {
        let set = PermissionSet::viewer();
        assert!(set.has(&Permission::ViewOwnReports));
        assert!(!set.has(&Permission::ScanHttp));
    }

    #[tokio::test]
    async fn test_user_creation() {
        let user = User::new("alice", "alice@example.com");
        assert_eq!(user.username(), "alice");
        assert_eq!(user.email(), "alice@example.com");
        assert!(user.is_active());
    }

    #[tokio::test]
    async fn test_role_assignment() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("bob", "bob@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Admin).await.unwrap();

        let roles = rbac.get_user_roles(user_id).await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0], Role::Admin);
    }

    #[tokio::test]
    async fn test_permission_check() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("charlie", "charlie@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Viewer).await.unwrap();

        // Viewer can view reports
        assert!(rbac.check_permission(&user, Permission::ViewOwnReports).await.unwrap());
        // Viewer cannot scan
        assert!(!rbac.check_permission(&user, Permission::ScanHttp).await.unwrap());
    }

    #[tokio::test]
    async fn test_admin_has_all_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("admin_user", "admin@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Admin).await.unwrap();

        assert!(rbac.check_permission(&user, Permission::ScanHttp).await.unwrap());
        assert!(rbac.check_permission(&user, Permission::CreateUser).await.unwrap());
        assert!(rbac.check_permission(&user, Permission::ModifyConfig).await.unwrap());
    }

    #[tokio::test]
    async fn test_audit_log() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("dave", "dave@example.com").await.unwrap();

        let logs = rbac.get_user_audit_log(&user).await.unwrap();
        assert!(!logs.is_empty());
        assert_eq!(logs[0].action, AuditAction::UserCreated);
    }

    #[tokio::test]
    async fn test_role_revocation() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("eve", "eve@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Admin).await.unwrap();
        assert_eq!(rbac.get_user_roles(user_id).await.unwrap().len(), 1);

        rbac.revoke_role(user_id, &Role::Admin).await.unwrap();
        assert_eq!(rbac.get_user_roles(user_id).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_custom_role() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let mut perms = PermissionSet::none();
        perms.grant(Permission::ScanHttp);
        perms.grant(Permission::ViewOwnReports);

        rbac.create_custom_role(
            "scanner_only",
            perms,
            None,
            "Can only run HTTP scans".to_string(),
        ).await.unwrap();

        let user = rbac.create_user("scanner", "scanner@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Custom("scanner_only".to_string())).await.unwrap();

        assert!(rbac.check_permission(&user, Permission::ScanHttp).await.unwrap());
        assert!(rbac.check_permission(&user, Permission::ViewOwnReports).await.unwrap());
        assert!(!rbac.check_permission(&user, Permission::ScanPort).await.unwrap());
    }

    #[tokio::test]
    async fn test_user_deletion() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("frank", "frank@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Admin).await.unwrap();

        rbac.delete_user("frank").await.unwrap();

        assert!(rbac.get_user("frank").await.is_err());
    }

    #[tokio::test]
    async fn test_audit_export() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        rbac.create_user("export_test", "export@example.com").await.unwrap();

        let json = rbac.export_audit_logs(AuditExportFormat::Json).await.unwrap();
        assert!(json.contains("user.created"));
    }

    #[tokio::test]
    async fn test_target_access_control() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let viewer = rbac.create_user("viewer_user", "viewer@example.com").await.unwrap();
        let viewer_id = viewer.id();

        rbac.assign_role(viewer_id, &Role::Viewer).await.unwrap();

        // Viewer cannot scan targets
        assert!(!rbac.can_scan_target(&viewer, "http://example.com").await.unwrap());

        let admin = rbac.create_user("admin_target", "admin_target@example.com").await.unwrap();
        let admin_id = admin.id();

        rbac.assign_role(admin_id, &Role::Admin).await.unwrap();

        // Admin can scan any target
        assert!(rbac.can_scan_target(&admin, "http://example.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_role_builder() {
        let builder = RoleBuilder::new("auditor")
            .description("Can view all reports and logs")
            .with_permission(Permission::ViewAllReports)
            .with_permission(Permission::ViewAuditLogs);

        let (role, perms, inherits, desc) = builder.build_with_permissions();

        assert_eq!(role, Role::Custom("auditor".to_string()));
        assert!(perms.has(&Permission::ViewAllReports));
        assert!(perms.has(&Permission::ViewAuditLogs));
        assert_eq!(desc, "Can view all reports and logs");
        assert!(inherits.is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path();

        // Create user and role
        {
            let rbac = RbacManager::new(storage_path).await.unwrap();
            let user = rbac.create_user("persist", "persist@example.com").await.unwrap();
            rbac.assign_role(user.id(), &Role::User).await.unwrap();
        }

        // Load and verify
        {
            let rbac = RbacManager::new(storage_path).await.unwrap();
            let user = rbac.get_user("persist").await.unwrap();
            assert_eq!(user.username(), "persist");

            let roles = rbac.get_user_roles(user.id()).await.unwrap();
            assert_eq!(roles.len(), 1);
            assert_eq!(roles[0], Role::User);
        }
    }

    #[tokio::test]
    async fn test_multiple_role_assignment() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("multi_role", "multi@example.com").await.unwrap();
        let user_id = user.id();

        rbac.assign_role(user_id, &Role::Viewer).await.unwrap();
        rbac.assign_role(user_id, &Role::User).await.unwrap();

        let roles = rbac.get_user_roles(user_id).await.unwrap();
        assert_eq!(roles.len(), 2);
    }

    #[tokio::test]
    async fn test_effective_permissions_merge() {
        let temp_dir = TempDir::new().unwrap();
        let rbac = RbacManager::new(temp_dir.path()).await.unwrap();

        let user = rbac.create_user("merged", "merged@example.com").await.unwrap();
        let user_id = user.id();

        // Assign both Viewer and User roles
        rbac.assign_role(user_id, &Role::Viewer).await.unwrap();
        rbac.assign_role(user_id, &Role::User).await.unwrap();

        let perms = rbac.get_effective_permissions(&user).await.unwrap();

        // Should have permissions from both roles
        assert!(perms.has(&Permission::ViewOwnReports)); // From Viewer
        assert!(perms.has(&Permission::ScanHttp)); // From User
    }
}
