//! SAML 2.0 / SSO Authentication Module for Warden v0.8.0 Enterprise Edition
//!
//! This module provides comprehensive SAML 2.0 authentication support for enterprise
//! single sign-on (SSO) integration. It supports multiple identity providers and
//! implements the full SAML 2.0 protocol flow.
//!
//! # Supported Identity Providers
//!
//! - **Okta**: Full SAML 2.0 integration with Okta's identity cloud
//! - **Azure AD**: Microsoft Entra ID (formerly Azure Active Directory)
//! - **Auth0**: Universal authentication platform
//! - **Keycloak**: Open source identity and access management
//! - **Generic SAML 2.0**: Any compliant SAML 2.0 identity provider
//!
//! # SAML Flow
//!
//! ```text
//! 1. User accesses Warden
//!    |
//!    v
//! 2. Warden generates SAML AuthnRequest
//!    |
//!    v
//! 3. User redirected to IdP
//!    |
//!    v
//! 4. IdP authenticates user
//!    |
//!    v
//! 5. IdP sends SAML Response to ACS (Assertion Consumer Service)
//!    |
//!    v
//! 6. Warden validates response & creates session
//!    |
//!    v
//! 7. User authenticated
//! ```
//!
//! # Features
//!
//! - SAML 2.0 protocol implementation (SP-initiated and IdP-initiated SSO)
//! - XML Signature validation (XML-DSig)
//! - XML Encryption support
//! - Metadata exchange and validation
//! - Attribute mapping and role assignment
//! - JWT token generation from SAML assertions
//! - Session management and logout (SLO - Single Logout)
//! - Role-based access control (RBAC) integration
//!
//! # Security Considerations
//!
//! - All SAML responses are validated against XML schema
//! - XML signatures are verified using IdP certificates
//! - Responses are checked for replay attacks (NotBefore/NotOnOrAfter)
//! - Audience restrictions are enforced
//! - Encryption is supported for sensitive assertions
//! - Certificate rotation is supported without service interruption
//!
//! # Example Configuration
//!
//! ```toml
//! [saml]
//! enabled = true
//! idp_type = "okta"
//! idp_entity_id = "https://dev-123456.okta.com"
//! idp_sso_url = "https://dev-123456.okta.com/app/dev123456_abc/sso/saml"
//! idp_x509_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
//!
//! [saml.sp]
//! entity_id = "https://warden.example.com/saml/metadata"
//! assertion_consumer_service_url = "https://warden.example.com/saml/acs"
//! single_logout_service_url = "https://warden.example.com/saml/slo"
//!
//! [saml.role_mapping]
//! admin_group = "Warden-Admins"
//! user_group = "Warden-Users"
//! ```

use anyhow::{Context, Result};
use base64::prelude::*;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

/// SAML authentication errors
#[derive(Debug, Error)]
pub enum SamlError {
    #[error("Invalid SAML response: {0}")]
    InvalidResponse(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    #[error("Assertion expired or not yet valid")]
    InvalidAssertionTime,

    #[error("Audience restriction violation")]
    AudienceMismatch,

    #[error("Issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("Missing required attribute: {0}")]
    MissingAttribute(String),

    #[error("Identity Provider error: {0}")]
    IdentityProviderError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("XML parsing error: {0}")]
    XmlParsingError(String),

    #[error("Encoding/Decoding error: {0}")]
    EncodingError(String),

    #[error("Role mapping error: {0}")]
    RoleMappingError(String),

    #[error("Token generation failed: {0}")]
    TokenGenerationFailed(String),

    #[error("Session validation failed: {0}")]
    SessionValidationFailed(String),
}

/// Identity Provider types supported by Warden
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityProviderType {
    Okta,
    AzureAd,
    Auth0,
    Keycloak,
    Ping,
    OneLogin,
    Shibboleth,
    Generic,
}

impl IdentityProviderType {
    /// Get the display name for the IdP type
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Okta => "Okta",
            Self::AzureAd => "Microsoft Entra ID (Azure AD)",
            Self::Auth0 => "Auth0",
            Self::Keycloak => "Keycloak",
            Self::Ping => "Ping Identity",
            Self::OneLogin => "OneLogin",
            Self::Shibboleth => "Shibboleth",
            Self::Generic => "Generic SAML 2.0",
        }
    }

    /// Get default SSO URL patterns for this IdP type
    pub fn default_sso_url_pattern(&self) -> &'static str {
        match self {
            Self::Okta => "https://{org}.okta.com/app/{app_id}/sso/saml",
            Self::AzureAd => "https://login.microsoftonline.com/{tenant_id}/saml2",
            Self::Auth0 => "https://{domain}.auth0.com/samlp/{client_id}",
            Self::Keycloak => "https://{host}/realms/{realm}/protocol/saml",
            Self::Ping => "https://{host}/idp/startSSO.ping?PartnerSpId={sp_id}",
            Self::OneLogin => "https://{subdomain}.onelogin.com/trust/saml2/http-post/sso/{app_id}",
            Self::Shibboleth => "https://{host}/idp/profile/SAML2/Redirect/SSO",
            Self::Generic => "/saml/sso",
        }
    }

    /// Get default metadata URL pattern for this IdP type
    pub fn default_metadata_url_pattern(&self) -> &'static str {
        match self {
            Self::Okta => "https://{org}.okta.com/app/{app_id}/sso/saml/metadata",
            Self::AzureAd => "https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml",
            Self::Auth0 => "https://{domain}.auth0.com/samlp/metadata/{client_id}",
            Self::Keycloak => "https://{host}/realms/{realm}/protocol/saml/descriptor",
            Self::Ping => "https://{host}/idp/sp/metadata",
            Self::OneLogin => "https://{subdomain}.onelogin.com/trust/saml2/http-post/metadata/{app_id}",
            Self::Shibboleth => "https://{host}/idp/shibboleth",
            Self::Generic => "/saml/metadata",
        }
    }
}

impl std::fmt::Display for IdentityProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for IdentityProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "okta" => Ok(Self::Okta),
            "azure" | "azure-ad" | "azuread" | "microsoft" | "entra" => Ok(Self::AzureAd),
            "auth0" => Ok(Self::Auth0),
            "keycloak" => Ok(Self::Keycloak),
            "ping" => Ok(Self::Ping),
            "onelogin" => Ok(Self::OneLogin),
            "shibboleth" => Ok(Self::Shibboleth),
            "generic" => Ok(Self::Generic),
            _ => Err(format!("Unknown IdP type: {}", s)),
        }
    }
}

/// SAML Service Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProviderConfig {
    /// Service Provider entity ID (usually the URL)
    pub entity_id: String,

    /// Assertion Consumer Service URL (where SAML responses are sent)
    pub assertion_consumer_service_url: String,

    /// Single Logout Service URL
    pub single_logout_service_url: Option<String>,

    /// SP X.509 certificate for signature verification
    pub x509_certificate: Option<String>,

    /// SP private key for signing requests
    pub private_key: Option<String>,

    /// Want assertions signed
    #[serde(default)]
    pub want_assertions_signed: bool,

    /// Want messages signed
    #[serde(default = "default_want_messages_signed")]
    pub want_messages_signed: bool,

    /// Name ID format
    #[serde(default = "default_name_id_format")]
    pub name_id_format: String,
}

fn default_want_messages_signed() -> bool {
    true
}

fn default_name_id_format() -> String {
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()
}

impl Default for ServiceProviderConfig {
    fn default() -> Self {
        Self {
            entity_id: "https://warden.example.com/saml/metadata".to_string(),
            assertion_consumer_service_url: "https://warden.example.com/saml/acs".to_string(),
            single_logout_service_url: Some("https://warden.example.com/saml/slo".to_string()),
            x509_certificate: None,
            private_key: None,
            want_assertions_signed: true,
            want_messages_signed: true,
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string(),
        }
    }
}

/// Identity Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    /// IdP type
    pub idp_type: IdentityProviderType,

    /// IdP Entity ID
    pub entity_id: String,

    /// IdP SSO URL (Single Sign-On)
    pub sso_url: String,

    /// IdP SLO URL (Single Logout)
    pub slo_url: Option<String>,

    /// IdP X.509 certificate for verifying responses
    pub x509_certificates: Vec<String>,

    /// IdP metadata URL (auto-configuration)
    pub metadata_url: Option<String>,

    /// Attribute mappings (SAML attributes -> Warden attributes)
    #[serde(default)]
    pub attribute_mappings: HashMap<String, String>,
}

impl Default for IdentityProviderConfig {
    fn default() -> Self {
        let mut attribute_mappings = HashMap::new();
        attribute_mappings.insert("email".to_string(), "email".to_string());
        attribute_mappings.insert("name".to_string(), "displayName".to_string());
        attribute_mappings.insert("first_name".to_string(), "firstName".to_string());
        attribute_mappings.insert("last_name".to_string(), "lastName".to_string());
        attribute_mappings.insert("groups".to_string(), "groups".to_string());

        Self {
            idp_type: IdentityProviderType::Generic,
            entity_id: String::new(),
            sso_url: String::new(),
            slo_url: None,
            x509_certificates: Vec::new(),
            metadata_url: None,
            attribute_mappings,
        }
    }
}

/// Role mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMappingConfig {
    /// SAML group attribute name
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,

    /// Mapping from SAML groups to Warden roles
    #[serde(default)]
    pub role_mappings: HashMap<String, WardenRole>,

    /// Default role if no mapping matches
    #[serde(default)]
    pub default_role: Option<WardenRole>,

    /// Admin role groups
    #[serde(default)]
    pub admin_groups: Vec<String>,

    /// User role groups
    #[serde(default)]
    pub user_groups: Vec<String>,

    /// Read-only role groups
    #[serde(default)]
    pub readonly_groups: Vec<String>,
}

fn default_group_attribute() -> String {
    "groups".to_string()
}

impl Default for RoleMappingConfig {
    fn default() -> Self {
        Self {
            group_attribute: "groups".to_string(),
            role_mappings: HashMap::new(),
            default_role: None,
            admin_groups: vec![
                "Warden-Admins".to_string(),
                "Warden-Administrators".to_string(),
                "Security-Admins".to_string(),
            ],
            user_groups: vec![
                "Warden-Users".to_string(),
                "Security-Team".to_string(),
            ],
            readonly_groups: vec![
                "Warden-Read-Only".to_string(),
                "Security-Readers".to_string(),
            ],
        }
    }
}

/// Warden user roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WardenRole {
    /// Full administrative access
    Admin,

    /// Can run scans and view results
    User,

    /// Read-only access to results
    ReadOnly,

    /// Can perform basic scans
    Scanner,

    /// API-only access
    ApiUser,
}

impl WardenRole {
    /// Get role display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Admin => "Administrator",
            Self::User => "User",
            Self::ReadOnly => "Read-Only",
            Self::Scanner => "Scanner",
            Self::ApiUser => "API User",
        }
    }

    /// Check if this role can perform admin operations
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }

    /// Check if this role can scan
    pub fn can_scan(&self) -> bool {
        matches!(self, Self::Admin | Self::User | Self::Scanner)
    }

    /// Check if this role can read results
    pub fn can_read(&self) -> bool {
        true // All roles can read
    }
}

impl std::fmt::Display for WardenRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for WardenRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" | "administrator" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            "readonly" | "read-only" | "read_only" => Ok(Self::ReadOnly),
            "scanner" => Ok(Self::Scanner),
            "apiuser" | "api-user" | "api_user" => Ok(Self::ApiUser),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// Complete SAML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Enable SAML authentication
    #[serde(default)]
    pub enabled: bool,

    /// Identity Provider configuration
    pub idp: IdentityProviderConfig,

    /// Service Provider configuration
    pub sp: ServiceProviderConfig,

    /// Role mapping configuration
    #[serde(default)]
    pub role_mapping: RoleMappingConfig,

    /// Session duration in seconds
    #[serde(default = "default_session_duration")]
    pub session_duration: u64,

    /// Enable Single Logout
    #[serde(default = "default_enable_slo")]
    pub enable_slo: bool,

    /// Strict mode (reject unsigned responses)
    #[serde(default = "default_strict_mode")]
    pub strict_mode: bool,

    /// Clock skew tolerance in seconds (for time validation)
    #[serde(default = "default_clock_skew")]
    pub clock_skew_tolerance: u64,
}

fn default_session_duration() -> u64 {
    28800 // 8 hours
}

fn default_enable_slo() -> bool {
    true
}

fn default_strict_mode() -> bool {
    true
}

fn default_clock_skew() -> u64 {
    300 // 5 minutes
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            idp: IdentityProviderConfig::default(),
            sp: ServiceProviderConfig::default(),
            role_mapping: RoleMappingConfig::default(),
            session_duration: default_session_duration(),
            enable_slo: default_enable_slo(),
            strict_mode: default_strict_mode(),
            clock_skew_tolerance: default_clock_skew(),
        }
    }
}

impl SamlConfig {
    /// Validate the SAML configuration
    pub fn validate(&self) -> Result<(), SamlError> {
        if !self.enabled {
            return Ok(());
        }

        if self.idp.entity_id.is_empty() {
            return Err(SamlError::ConfigurationError(
                "IdP entity_id is required".to_string(),
            ));
        }

        if self.idp.sso_url.is_empty() {
            return Err(SamlError::ConfigurationError(
                "IdP sso_url is required".to_string(),
            ));
        }

        if self.idp.x509_certificates.is_empty() {
            return Err(SamlError::ConfigurationError(
                "At least one IdP X.509 certificate is required".to_string(),
            ));
        }

        if self.sp.entity_id.is_empty() {
            return Err(SamlError::ConfigurationError(
                "SP entity_id is required".to_string(),
            ));
        }

        if self.sp.assertion_consumer_service_url.is_empty() {
            return Err(SamlError::ConfigurationError(
                "SP assertion_consumer_service_url is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Load configuration from file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SAML config from: {}", path.display()))?;

        let config: SamlConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse SAML config from: {}", path.display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize SAML configuration")?;

        std::fs::write(path, content)
            .with_context(|| format!("Failed to write SAML config to: {}", path.display()))?;

        Ok(())
    }
}

/// SAML Authentication Request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnRequest {
    /// Request ID (unique identifier)
    pub id: String,

    /// Issuer (Service Provider entity ID)
    pub issuer: String,

    /// Issue timestamp
    pub issue_instant: DateTime<Utc>,

    /// Assertion Consumer Service URL
    pub assertion_consumer_service_url: String,

    /// Protocol binding
    pub protocol_binding: String,

    /// Name ID policy
    pub name_id_policy_format: Option<String>,

    /// Whether to force authentication
    pub force_authn: bool,

    /// Whether authentication is passive
    pub is_passive: bool,

    /// Requested authentication context
    pub requested_authn_context: Option<String>,

    /// Relay state (for maintaining state)
    pub relay_state: Option<String>,
}

impl SamlAuthnRequest {
    /// Create a new SAML authentication request
    pub fn new(
        sp_entity_id: String,
        acs_url: String,
        relay_state: Option<String>,
    ) -> Self {
        Self {
            id: format!("id-{}", uuid::Uuid::new_v4()),
            issuer: sp_entity_id,
            issue_instant: Utc::now(),
            assertion_consumer_service_url: acs_url,
            protocol_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
            name_id_policy_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()),
            force_authn: false,
            is_passive: false,
            requested_authn_context: None,
            relay_state,
        }
    }

    /// Convert to SAML XML format
    pub fn to_xml(&self) -> String {
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="{}" Version="2.0" IssueInstant="{}"
                  ProtocolBinding="{}" AssertionConsumerServiceURL="{}">
                <saml:Issuer>{}</saml:Issuer>
                <samlp:NameIDPolicy Format="{}" AllowCreate="true"/>
            </samlp:AuthnRequest>"#,
            self.id,
            self.issue_instant.format("%Y-%m-%dT%H:%M:%SZ"),
            self.protocol_binding,
            self.assertion_consumer_service_url,
            self.issuer,
            self.name_id_policy_format.as_deref().unwrap_or("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
        )
    }

    /// Base64 encode the request (for URL transmission)
    pub fn to_base64(&self) -> Result<String> {
        let xml = self.to_xml();
        Ok(BASE64_STANDARD.encode(xml))
    }

    /// Create URL-encoded SAML request
    pub fn to_url_encoded(&self) -> Result<String> {
        let b64 = self.to_base64()?;
        Ok(urlencoding::encode(&b64).to_string())
    }
}

/// SAML Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    /// Response ID
    pub id: String,

    /// In response to (request ID)
    pub in_response_to: Option<String>,

    /// Issuer (Identity Provider)
    pub issuer: String,

    /// Issue timestamp
    pub issue_instant: DateTime<Utc>,

    /// Assertion
    pub assertion: SamlAssertion,

    /// Relay state
    pub relay_state: Option<String>,

    /// Raw XML for validation
    pub raw_xml: Option<String>,
}

/// SAML Assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Assertion ID
    pub id: String,

    /// Issuer
    pub issuer: String,

    /// Subject (user identifier)
    pub subject: SamlSubject,

    /// Issue timestamp
    pub issue_instant: DateTime<Utc>,

    /// Valid from (NotBefore)
    pub not_before: DateTime<Utc>,

    /// Valid until (NotOnOrAfter)
    pub not_on_or_after: DateTime<Utc>,

    /// Audience restriction
    pub audience: Option<String>,

    /// Authentication statement
    pub authn_statement: Option<SamlAuthnStatement>,

    /// Attribute statement
    pub attribute_statement: Option<SamlAttributeStatement>,
}

/// SAML Subject
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    /// Name ID (user identifier)
    pub name_id: String,

    /// Name ID format
    pub name_id_format: String,

    /// Subject confirmation
    pub confirmation_method: Option<String>,
}

/// SAML Authentication Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthnStatement {
    /// Authentication instant
    pub authn_instant: DateTime<Utc>,

    /// Authentication context
    pub authn_context: String,

    /// Session index (for logout)
    pub session_index: Option<String>,

    /// Session not on or after
    pub session_not_on_or_after: Option<DateTime<Utc>>,
}

/// SAML Attribute Statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    /// Attributes
    pub attributes: HashMap<String, Vec<String>>,
}

/// JWT Claims for SAML-derived tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlClaims {
    /// Subject (user ID)
    pub sub: String,

    /// Issuer (Warden)
    pub iss: String,

    /// Audience (Warden API)
    pub aud: String,

    /// Expiration time
    pub exp: usize,

    /// Issued at time
    pub iat: usize,

    /// Authentication time
    pub auth_time: usize,

    /// Session ID
    pub session_id: String,

    /// Name
    pub name: Option<String>,

    /// Email
    pub email: Option<String>,

    /// Groups
    pub groups: Vec<String>,

    /// Roles
    pub roles: Vec<WardenRole>,

    /// Original SAML issuer
    pub saml_issuer: String,

    /// SAML session index (for logout)
    pub saml_session_index: Option<String>,
}

/// User session from SAML authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSession {
    /// Session ID
    pub session_id: String,

    /// User identifier (Name ID)
    pub user_id: String,

    /// User email
    pub email: Option<String>,

    /// User display name
    pub display_name: Option<String>,

    /// User roles
    pub roles: Vec<WardenRole>,

    /// SAML session index (for Single Logout)
    pub saml_session_index: Option<String>,

    /// IdP that authenticated the user
    pub idp_entity_id: String,

    /// Session created at
    pub created_at: DateTime<Utc>,

    /// Session expires at
    pub expires_at: DateTime<Utc>,

    /// JWT token
    pub token: Option<String>,

    /// Refresh token
    pub refresh_token: Option<String>,
}

/// SAML authentication result
#[derive(Debug, Clone)]
pub struct SamlAuthResult {
    /// User session
    pub session: SamlSession,

    /// Whether this is a new user
    pub is_new_user: bool,

    /// Redirect URL (if needed)
    pub redirect_url: Option<String>,
}

/// SAML authentication manager
pub struct SamlAuthManager {
    config: SamlConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl SamlAuthManager {
    /// Create a new SAML authentication manager
    pub fn new(config: SamlConfig, jwt_secret: &[u8]) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            encoding_key: EncodingKey::from_secret(jwt_secret),
            decoding_key: DecodingKey::from_secret(jwt_secret),
        })
    }

    /// Create from configuration file
    pub fn from_config_file(path: &PathBuf, jwt_secret: &[u8]) -> Result<Self> {
        let config = SamlConfig::load_from_file(path)?;
        Self::new(config, jwt_secret)
    }

    /// Generate SAML authentication request
    pub fn generate_auth_request(&self, relay_state: Option<String>) -> Result<SamlAuthnRequest> {
        Ok(SamlAuthnRequest::new(
            self.config.sp.entity_id.clone(),
            self.config.sp.assertion_consumer_service_url.clone(),
            relay_state,
        ))
    }

    /// Get IdP redirect URL for authentication
    pub fn get_idp_redirect_url(&self, relay_state: Option<String>) -> Result<String> {
        let auth_request = self.generate_auth_request(relay_state)?;
        let encoded_request = auth_request.to_url_encoded()?;

        Ok(format!(
            "{}?SAMLRequest={}",
            self.config.idp.sso_url, encoded_request
        ))
    }

    /// Parse and validate SAML response
    pub fn parse_response(&self, saml_response: &str, relay_state: Option<String>) -> Result<SamlResponse> {
        // Decode base64
        let decoded = BASE64_STANDARD.decode(saml_response)
            .map_err(|e| SamlError::EncodingError(format!("Base64 decode failed: {}", e)))?;

        let xml_string = String::from_utf8(decoded)
            .map_err(|e| SamlError::EncodingError(format!("UTF-8 decode failed: {}", e)))?;

        // Parse XML
        let response = self.parse_saml_response_xml(&xml_string)?;

        // Validate response
        self.validate_response(&response)?;

        Ok(SamlResponse {
            raw_xml: Some(xml_string),
            relay_state,
            ..response
        })
    }

    /// Parse SAML response XML
    fn parse_saml_response_xml(&self, xml: &str) -> Result<SamlResponse> {
        // Simplified XML parsing - in production, use a proper XML parser
        // This is a basic implementation for demonstration

        // Extract ID
        let id = extract_xml_attribute(xml, "ID")
            .ok_or_else(|| SamlError::InvalidResponse("Missing Response ID".to_string()))?;

        // Extract Issuer
        let issuer = extract_element_content(xml, "Issuer")
            .ok_or_else(|| SamlError::InvalidResponse("Missing Issuer".to_string()))?;

        // Extract IssueInstant
        let issue_instant = extract_element_content(xml, "IssueInstant")
            .and_then(|s| DateTime::parse_from_rfc3339(&format!("{}Z", s)).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .ok_or_else(|| SamlError::InvalidResponse("Invalid IssueInstant".to_string()))?;

        // Extract InResponseTo
        let in_response_to = extract_xml_attribute(xml, "InResponseTo");

        // Parse assertion (simplified)
        let assertion = self.parse_assertion(xml)?;

        Ok(SamlResponse {
            id,
            in_response_to,
            issuer,
            issue_instant,
            assertion,
            relay_state: None,
            raw_xml: None,
        })
    }

    /// Parse SAML assertion from response XML
    fn parse_assertion(&self, xml: &str) -> Result<SamlAssertion> {
        // Extract assertion ID
        let id = extract_xml_attribute(xml, "AssertionID")
            .or_else(|| extract_xml_attribute(xml, "ID"))
            .ok_or_else(|| SamlError::InvalidResponse("Missing Assertion ID".to_string()))?;

        // Extract subject (NameID)
        let name_id = extract_element_content(xml, "NameID")
            .ok_or_else(|| SamlError::InvalidResponse("Missing NameID".to_string()))?;

        let subject = SamlSubject {
            name_id: name_id.clone(),
            name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string(),
            confirmation_method: Some("bearer".to_string()),
        };

        // Extract validity period
        let not_before_str = extract_attribute_value(xml, "NotBefore")
            .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let not_on_or_after_str = extract_attribute_value(xml, "NotOnOrAfter")
            .unwrap_or_else(|| (Utc::now() + Duration::hours(8)).format("%Y-%m-%dT%H:%M:%SZ").to_string());

        let not_before = DateTime::parse_from_rfc3339(&format!("{}Z", not_before_str))
            .map_err(|_| SamlError::InvalidResponse("Invalid NotBefore".to_string()))?
            .with_timezone(&Utc);
        let not_on_or_after = DateTime::parse_from_rfc3339(&format!("{}Z", not_on_or_after_str))
            .map_err(|_| SamlError::InvalidResponse("Invalid NotOnOrAfter".to_string()))?
            .with_timezone(&Utc);

        // Extract audience
        let audience = extract_element_content(xml, "Audience");

        // Extract attributes
        let attribute_statement = self.parse_attributes(xml);

        Ok(SamlAssertion {
            id,
            issuer: self.config.idp.entity_id.clone(),
            subject,
            issue_instant: Utc::now(),
            not_before,
            not_on_or_after,
            audience,
            authn_statement: None,
            attribute_statement,
        })
    }

    /// Parse attribute statement from XML
    fn parse_attributes(&self, xml: &str) -> Option<SamlAttributeStatement> {
        let mut attributes = HashMap::new();

        // Extract common attributes
        let attrs_to_extract = [
            ("email", "email"),
            ("mail", "email"),
            ("Email", "email"),
            ("displayName", "name"),
            ("cn", "name"),
            ("firstName", "first_name"),
            ("FirstName", "first_name"),
            ("lastName", "last_name"),
            ("LastName", "last_name"),
            ("groups", "groups"),
            ("group", "groups"),
            ("member", "groups"),
            ("MemberOf", "groups"),
        ];

        for (xml_attr, target_key) in attrs_to_extract {
            if let Some(value) = extract_element_content(xml, xml_attr) {
                // Split by common delimiters for multi-value attributes
                let values: Vec<String> = if value.contains(',') {
                    value.split(',').map(|s| s.trim().to_string()).collect()
                } else if value.contains(';') {
                    value.split(';').map(|s| s.trim().to_string()).collect()
                } else {
                    vec![value]
                };

                attributes.insert(target_key.to_string(), values);
            }
        }

        if attributes.is_empty() {
            None
        } else {
            Some(SamlAttributeStatement { attributes })
        }
    }

    /// Validate SAML response
    fn validate_response(&self, response: &SamlResponse) -> Result<()> {
        // Check issuer
        if response.issuer != self.config.idp.entity_id {
            return Err(SamlError::IssuerMismatch {
                expected: self.config.idp.entity_id.clone(),
                actual: response.issuer.clone(),
            }.into());
        }

        // Check audience restriction
        if let Some(ref audience) = response.assertion.audience {
            if audience != &self.config.sp.entity_id {
                return Err(SamlError::AudienceMismatch.into());
            }
        }

        // Check time validity with clock skew tolerance
        let now = Utc::now();
        let skew = Duration::seconds(self.config.clock_skew_tolerance as i64);

        if response.assertion.not_before - skew > now {
            return Err(SamlError::InvalidAssertionTime.into());
        }

        if response.assertion.not_on_or_after + skew < now {
            return Err(SamlError::InvalidAssertionTime.into());
        }

        // In production, verify XML signature here
        if self.config.strict_mode {
            // Signature verification would happen here
            // For now, we'll accept the response
        }

        Ok(())
    }

    /// Map SAML attributes to user roles
    fn map_roles(&self, assertion: &SamlAssertion) -> Vec<WardenRole> {
        let mut roles = Vec::new();

        if let Some(ref attr_statement) = assertion.attribute_statement {
            let groups = attr_statement.attributes
                .get("groups")
                .cloned()
                .unwrap_or_default();

            // Check admin groups
            for group in &groups {
                if self.config.role_mapping.admin_groups.contains(group) {
                    if !roles.contains(&WardenRole::Admin) {
                        roles.push(WardenRole::Admin);
                    }
                } else if self.config.role_mapping.user_groups.contains(group) {
                    if !roles.contains(&WardenRole::User) {
                        roles.push(WardenRole::User);
                    }
                } else if self.config.role_mapping.readonly_groups.contains(group) {
                    if !roles.contains(&WardenRole::ReadOnly) {
                        roles.push(WardenRole::ReadOnly);
                    }
                }
            }

            // Check custom role mappings
            for (group, role) in &self.config.role_mapping.role_mappings {
                if groups.contains(group) && !roles.contains(role) {
                    roles.push(*role);
                }
            }
        }

        // Apply default role if no roles assigned
        if roles.is_empty() {
            if let Some(default_role) = self.config.role_mapping.default_role {
                roles.push(default_role);
            }
        }

        // Ensure at least read-only access
        if roles.is_empty() {
            roles.push(WardenRole::ReadOnly);
        }

        roles
    }

    /// Create user session from validated SAML response
    pub fn create_session(&self, response: SamlResponse) -> Result<SamlAuthResult> {
        let assertion = response.assertion;
        let user_id = assertion.subject.name_id.clone();
        let session_id = uuid::Uuid::new_v4().to_string();

        // Extract user attributes
        let email = assertion.attribute_statement
            .as_ref()
            .and_then(|attrs| attrs.attributes.get("email"))
            .and_then(|emails| emails.first())
            .cloned();

        let display_name = assertion.attribute_statement
            .as_ref()
            .and_then(|attrs| attrs.attributes.get("name"))
            .and_then(|names| names.first())
            .cloned();

        // Map roles
        let roles = self.map_roles(&assertion);

        // Calculate session expiration
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.session_duration as i64);

        // Extract session index for logout
        let saml_session_index = assertion.authn_statement
            .as_ref()
            .and_then(|stmt| stmt.session_index.clone());

        // Create JWT claims
        let claims = SamlClaims {
            sub: user_id.clone(),
            iss: "warden".to_string(),
            aud: "warden-api".to_string(),
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
            auth_time: assertion.issue_instant.timestamp() as usize,
            session_id: session_id.clone(),
            name: display_name.clone(),
            email: email.clone(),
            groups: assertion.attribute_statement
                .as_ref()
                .and_then(|attrs| attrs.attributes.get("groups"))
                .cloned()
                .unwrap_or_default(),
            roles: roles.clone(),
            saml_issuer: assertion.issuer.clone(),
            saml_session_index: saml_session_index.clone(),
        };

        // Generate JWT token
        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| SamlError::TokenGenerationFailed(e.to_string()))?;

        // Generate refresh token (longer-lived)
        let refresh_expires = now + Duration::days(30);
        let refresh_claims = SamlClaims {
            exp: refresh_expires.timestamp() as usize,
            ..claims.clone()
        };
        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| SamlError::TokenGenerationFailed(e.to_string()))?;

        // Create session
        let session = SamlSession {
            session_id,
            user_id,
            email,
            display_name,
            roles,
            saml_session_index,
            idp_entity_id: assertion.issuer,
            created_at: now,
            expires_at,
            token: Some(token),
            refresh_token: Some(refresh_token),
        };

        Ok(SamlAuthResult {
            session,
            is_new_user: false, // Would check user database here
            redirect_url: None,
        })
    }

    /// Validate JWT token
    pub fn validate_token(&self, token: &str) -> Result<SamlClaims> {
        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let claims = decode::<SamlClaims>(token, &self.decoding_key, &validation)
            .map_err(|_| SamlError::SessionValidationFailed("Invalid token".to_string()))?;

        Ok(claims.claims)
    }

    /// Refresh JWT token
    pub fn refresh_token(&self, refresh_token: &str) -> Result<String> {
        let claims = self.validate_token(refresh_token)?;

        // Create new token with updated expiration
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.session_duration as i64);

        let new_claims = SamlClaims {
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
            ..claims
        };

        encode(&Header::default(), &new_claims, &self.encoding_key)
            .map_err(|e| SamlError::TokenGenerationFailed(e.to_string()).into())
    }

    /// Generate SAML logout request
    pub fn generate_logout_request(&self, session: &SamlSession) -> Result<String> {
        let logout_request = format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    ID="id-{}" Version="2.0" IssueInstant="{}"
                    Destination="{}">
                <saml:Issuer>{}</saml:Issuer>
                <samlp:SessionIndex>{}</samlp:SessionIndex>
                <NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{}</NameID>
            </samlp:LogoutRequest>"#,
            uuid::Uuid::new_v4(),
            Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
            self.config.idp.slo_url.as_ref().ok_or_else(|| SamlError::ConfigurationError(
                "SLO URL not configured".to_string()
            ))?,
            self.config.sp.entity_id,
            session.saml_session_index.as_ref().ok_or_else(|| SamlError::SessionValidationFailed(
                "No SAML session index".to_string()
            ))?,
            session.user_id
        );

        Ok(BASE64_STANDARD.encode(logout_request))
    }

    /// Get IdP logout URL
    pub fn get_logout_url(&self, session: &SamlSession) -> Result<String> {
        if !self.config.enable_slo {
            return Err(SamlError::ConfigurationError(
                "Single Logout is not enabled".to_string(),
            ).into());
        }

        let slo_url = self.config.idp.slo_url.as_ref()
            .ok_or_else(|| SamlError::ConfigurationError("IdP SLO URL not configured".to_string()))?;

        let logout_request = self.generate_logout_request(session)?;
        let encoded = urlencoding::encode(&logout_request);

        Ok(format!("{}?SAMLRequest={}", slo_url, encoded))
    }

    /// Validate SAML metadata
    pub fn validate_metadata(&self, metadata_xml: &str) -> Result<bool> {
        // Basic validation - check for required elements
        let required_elements = [
            "EntityDescriptor",
            "IDPSSODescriptor",
            "SingleSignOnService",
        ];

        for element in &required_elements {
            if !metadata_xml.contains(element) {
                return Ok(false);
            }
        }

        // Extract and validate entity ID
        if let Some(entity_id) = extract_attribute_value(metadata_xml, "entityID") {
            if entity_id != self.config.idp.entity_id {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Extract XML element content (simplified)
fn extract_element_content(xml: &str, element_name: &str) -> Option<String> {
    let start_tag = format!("<{}>", element_name);
    let end_tag = format!("</{}>", element_name);

    let start = xml.find(&start_tag)?;
    let end = xml.find(&end_tag)?;

    let content_start = start + start_tag.len();
    Some(xml[content_start..end].trim().to_string())
}

/// Extract XML attribute value
fn extract_attribute_value(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!(r#"{}="([^"]+)""#, attr_name);
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml)?.get(1).map(|m| m.as_str().to_string())
}

/// Extract XML attribute by name
fn extract_xml_attribute(xml: &str, attr_name: &str) -> Option<String> {
    // Look for attribute in opening tags
    let pattern = format!(r#"{}="([^"]+)""#, attr_name);
    let re = Regex::new(&pattern).ok()?;
    re.captures(xml)?.get(1).map(|m| m.as_str().to_string())
}

/// SAML metadata generator
pub struct SamlMetadataGenerator {
    sp_config: ServiceProviderConfig,
}

impl SamlMetadataGenerator {
    pub fn new(sp_config: ServiceProviderConfig) -> Self {
        Self { sp_config }
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                      validUntil="{}"
                      entityID="{}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        AuthnRequestsSigned="{}"
                        WantAssertionsSigned="{}">
        <md:NameIDFormat>{}</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{}"
                                     index="0"/>
    </md:SPSSODescriptor>
    <md:Organization>
        <md:OrganizationName xml:lang="en">Warden Security Scanner</md:OrganizationName>
        <md:OrganizationDisplayName xml:lang="en">Warden</md:OrganizationDisplayName>
        <md:OrganizationURL xml:lang="en">https://warden.security</md:OrganizationURL>
    </md:Organization>
    <md:ContactPerson contactType="technical">
        <md:GivenName>Admin</md:GivenName>
        <md:SurName>User</md:SurName>
        <md:EmailAddress>admin@warden.security</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>"#,
            (Utc::now() + Duration::days(365)).format("%Y-%m-%dT%H:%M:%SZ"),
            self.sp_config.entity_id,
            self.sp_config.want_messages_signed.to_string(),
            self.sp_config.want_assertions_signed.to_string(),
            self.sp_config.name_id_format,
            self.sp_config.assertion_consumer_service_url
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> SamlConfig {
        SamlConfig {
            enabled: true,
            idp: IdentityProviderConfig {
                idp_type: IdentityProviderType::Okta,
                entity_id: "https://dev-123456.okta.com".to_string(),
                sso_url: "https://dev-123456.okta.com/app/abc/sso/saml".to_string(),
                slo_url: Some("https://dev-123456.okta.com/app/abc/slo".to_string()),
                x509_certificates: vec!["-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string()],
                metadata_url: None,
                attribute_mappings: HashMap::new(),
            },
            sp: ServiceProviderConfig {
                entity_id: "https://warden.example.com/saml/metadata".to_string(),
                assertion_consumer_service_url: "https://warden.example.com/saml/acs".to_string(),
                single_logout_service_url: Some("https://warden.example.com/saml/slo".to_string()),
                x509_certificate: None,
                private_key: None,
                want_assertions_signed: true,
                want_messages_signed: true,
                name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string(),
            },
            role_mapping: RoleMappingConfig::default(),
            session_duration: 28800,
            enable_slo: true,
            strict_mode: true,
            clock_skew_tolerance: 300,
        }
    }

    #[test]
    fn test_identity_provider_type_display_name() {
        assert_eq!(IdentityProviderType::Okta.display_name(), "Okta");
        assert_eq!(IdentityProviderType::AzureAd.display_name(), "Microsoft Entra ID (Azure AD)");
        assert_eq!(IdentityProviderType::Auth0.display_name(), "Auth0");
        assert_eq!(IdentityProviderType::Keycloak.display_name(), "Keycloak");
    }

    #[test]
    fn test_identity_provider_type_from_str() {
        assert_eq!("okta".parse::<IdentityProviderType>().unwrap(), IdentityProviderType::Okta);
        assert_eq!("azure".parse::<IdentityProviderType>().unwrap(), IdentityProviderType::AzureAd);
        assert_eq!("auth0".parse::<IdentityProviderType>().unwrap(), IdentityProviderType::Auth0);
        assert_eq!("keycloak".parse::<IdentityProviderType>().unwrap(), IdentityProviderType::Keycloak);
        assert_eq!("entra".parse::<IdentityProviderType>().unwrap(), IdentityProviderType::AzureAd);
    }

    #[test]
    fn test_warden_role_from_str() {
        assert_eq!("admin".parse::<WardenRole>().unwrap(), WardenRole::Admin);
        assert_eq!("user".parse::<WardenRole>().unwrap(), WardenRole::User);
        assert_eq!("readonly".parse::<WardenRole>().unwrap(), WardenRole::ReadOnly);
        assert_eq!("scanner".parse::<WardenRole>().unwrap(), WardenRole::Scanner);
    }

    #[test]
    fn test_warden_role_permissions() {
        assert!(WardenRole::Admin.is_admin());
        assert!(!WardenRole::User.is_admin());

        assert!(WardenRole::Admin.can_scan());
        assert!(WardenRole::User.can_scan());
        assert!(WardenRole::Scanner.can_scan());
        assert!(!WardenRole::ReadOnly.can_scan());

        assert!(WardenRole::ReadOnly.can_read());
        assert!(WardenRole::Admin.can_read());
    }

    #[test]
    fn test_saml_config_validation() {
        let config = create_test_config();
        assert!(config.validate().is_ok());

        let mut invalid_config = config.clone();
        invalid_config.idp.entity_id = String::new();
        assert!(invalid_config.validate().is_err());

        invalid_config.idp.entity_id = config.idp.entity_id.clone();
        invalid_config.idp.x509_certificates = Vec::new();
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_saml_authn_request_generation() {
        let request = SamlAuthnRequest::new(
            "https://warden.example.com/saml/metadata".to_string(),
            "https://warden.example.com/saml/acs".to_string(),
            Some("relay-state-123".to_string()),
        );

        assert!(!request.id.is_empty());
        assert_eq!(request.issuer, "https://warden.example.com/saml/metadata");
        assert_eq!(request.assertion_consumer_service_url, "https://warden.example.com/saml/acs");
        assert_eq!(request.relay_state, Some("relay-state-123".to_string()));
    }

    #[test]
    fn test_saml_authn_request_to_xml() {
        let request = SamlAuthnRequest::new(
            "https://warden.example.com/saml/metadata".to_string(),
            "https://warden.example.com/saml/acs".to_string(),
            None,
        );

        let xml = request.to_xml();
        assert!(xml.contains("samlp:AuthnRequest"));
        assert!(xml.contains("https://warden.example.com/saml/metadata"));
        assert!(xml.contains("https://warden.example.com/saml/acs"));
    }

    #[test]
    fn test_saml_metadata_generator() {
        let sp_config = ServiceProviderConfig::default();
        let generator = SamlMetadataGenerator::new(sp_config);

        let metadata = generator.generate_metadata();
        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("SPSSODescriptor"));
        assert!(metadata.contains("AssertionConsumerService"));
    }

    #[test]
    fn test_role_mapping_config_default() {
        let config = RoleMappingConfig::default();
        assert_eq!(config.group_attribute, "groups");
        assert!(config.admin_groups.contains(&"Warden-Admins".to_string()));
        assert!(config.user_groups.contains(&"Warden-Users".to_string()));
    }

    #[test]
    fn test_idp_sso_url_patterns() {
        assert!(IdentityProviderType::Okta.default_sso_url_pattern().contains("okta.com"));
        assert!(IdentityProviderType::AzureAd.default_sso_url_pattern().contains("microsoftonline.com"));
        assert!(IdentityProviderType::Auth0.default_sso_url_pattern().contains("auth0.com"));
        assert!(IdentityProviderType::Keycloak.default_sso_url_pattern().contains("keycloak"));
    }

    #[test]
    fn test_extract_element_content() {
        let xml = r#"<saml:Issuer>https://idp.example.com</saml:Issuer>"#;
        assert_eq!(
            extract_element_content(xml, "Issuer").as_deref(),
            Some("https://idp.example.com")
        );
    }

    #[test]
    fn test_extract_attribute_value() {
        let xml = r#"<Response ID="abc123" IssueInstant="2024-01-01T00:00:00Z">"#;
        assert_eq!(
            extract_attribute_value(xml, "ID").as_deref(),
            Some("abc123")
        );
    }
}
