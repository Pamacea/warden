//! Authentication and Authorization Module for Warden v0.8.0 Enterprise Edition
//!
//! This module provides comprehensive authentication and authorization capabilities
//! for enterprise deployments of Warden security scanner.
//!
//! # Features
//!
//! - **RBAC**: Role-Based Access Control for fine-grained permissions
//!   - Admin, User, Viewer, and custom roles
//!   - Per-scanner and per-target permissions
//!   - Audit trail for all actions
//!
//! - **SAML 2.0 / SSO**: Single Sign-On integration with major identity providers
//!   - Okta
//!   - Microsoft Entra ID (Azure AD)
//!   - Auth0
//!   - Keycloak
//!   - Generic SAML 2.0 compliant IdPs
//!
//! # Module Structure
//!
//! - [`rbac`]: Role-Based Access Control system
//! - [`saml`]: SAML 2.0 authentication and SSO integration (when enabled)
//!
//! # Example Usage (RBAC)
//!
//! ```rust,no_run
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

pub mod rbac;
pub mod saml;

// Re-export RBAC types
pub use rbac::{
    AuditAction, AuditEntry, AuditCategory, AuditExportFormat, AuditLog, AuditTrail, Permission,
    PermissionCategory, PermissionCheck, PermissionSet, PermissionSource, Role, RoleBuilder,
    RoleInheritance, RbacError, RbacManager, RbacResult, User, UserId, UserRoleAssignment,
};

// Re-export SAML types
pub use saml::{
    IdentityProviderType, SamlAuthManager, SamlAuthnRequest, SamlAuthResult,
    SamlConfig, SamlError, SamlMetadataGenerator, SamlSession,
    ServiceProviderConfig, WardenRole,
};

/// Warden authentication version
pub const AUTH_VERSION: &str = "0.8.0-enterprise";
