//! ML-Based Detection Module for Warden v0.8.0 Enterprise Edition
//!
//! This module provides machine learning capabilities for:
//! - Pattern Recognition: Similarity analysis, clustering, zero-day detection
//! - Scoring Adaptatif: User feedback learning, dynamic severity adjustment
//! - Anomaly Detection: Behavioral analysis, response time statistics
//! - Feature Extraction: TF-IDF, n-gram analysis, automatic feature extraction
//!
//! # Design Philosophy
//!
//! - **No external ML dependencies**: Pure Rust statistical implementations
//! - **Online learning**: Incremental updates without batch retraining
//! - **Lightweight**: Minimal memory footprint and CPU usage
//! - **Explainable**: Clear reasoning for all detections

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// Re-export VulnSeverity from scanners for convenience
pub use crate::scanners::VulnSeverity;

/// ML-based detection engine
///
/// Core component for intelligent vulnerability detection using
/// statistical analysis and pattern recognition without external ML dependencies.
#[derive(Clone, Debug)]
pub struct MlDetector {
    /// Learned patterns from previous scans
    patterns: PatternStore,
    /// Anomaly detection thresholds
    anomaly_config: AnomalyConfig,
    /// Feature extraction settings
    feature_config: FeatureConfig,
    /// User feedback for adaptive scoring
    feedback_store: FeedbackStore,
}

impl Default for MlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MlDetector {
    /// Create a new ML detector with default configuration
    pub fn new() -> Self {
        Self {
            patterns: PatternStore::new(),
            anomaly_config: AnomalyConfig::default(),
            feature_config: FeatureConfig::default(),
            feedback_store: FeedbackStore::new(),
        }
    }

    /// Create ML detector with custom anomaly thresholds
    pub fn with_anomaly_config(mut self, config: AnomalyConfig) -> Self {
        self.anomaly_config = config;
        self
    }

    /// Create ML detector with custom feature extraction settings
    pub fn with_feature_config(mut self, config: FeatureConfig) -> Self {
        self.feature_config = config;
        self
    }

    /// Analyze HTTP response for anomalies
    ///
    /// Detects unusual response patterns that may indicate:
    /// - Information disclosure via error messages
    /// - Backend technology fingerprinting
    /// - WAF/IDS presence
    /// - Potential injection points
    pub fn analyze_response(&mut self, response: &HttpResponse) -> AnomalyReport {
        let mut anomalies = Vec::new();

        // Check response time anomaly
        if let Some(time) = response.response_time_ms {
            if self.is_response_time_anomalous(time) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::ResponseTime,
                    severity: AnomalySeverity::Medium,
                    description: format!(
                        "Response time {}ms exceeds expected baseline ({}ms)",
                        time, self.anomaly_config.baseline_response_time_ms
                    ),
                    confidence: self.calculate_time_confidence(time),
                });
            }
        }

        // Check status code anomaly
        if self.is_status_code_anomalous(response.status_code) {
            anomalies.push(Anomaly {
                anomaly_type: AnomalyType::UnexpectedStatusCode,
                severity: AnomalySeverity::Low,
                description: format!(
                    "Unexpected status code {} for {} request",
                    response.status_code, response.method
                ),
                confidence: 0.7,
            });
        }

        // Check for information disclosure in headers
        for (header_name, header_value) in &response.headers {
            if let Some(disclosure) = self.detect_information_disclosure(header_name, header_value) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::InformationDisclosure,
                    severity: disclosure.severity,
                    description: disclosure.description,
                    confidence: disclosure.confidence,
                });
            }
        }

        // Analyze body content for patterns
        if let Some(ref body) = response.body {
            if let Some(pattern) = self.analyze_body_patterns(body) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::SuspiciousPattern,
                    severity: pattern.severity,
                    description: pattern.description,
                    confidence: pattern.confidence,
                });
            }

            // Extract and analyze features
            let features = self.extract_features(body);
            if let Some(detected_technology) = self.detect_technology(&features) {
                anomalies.push(Anomaly {
                    anomaly_type: AnomalyType::TechnologyFingerprint,
                    severity: AnomalySeverity::Low,
                    description: format!("Detected technology: {}", detected_technology),
                    confidence: 0.8,
                });
            }
        }

        AnomalyReport {
            url: response.url.clone(),
            anomalies,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Cluster similar findings for pattern recognition
    ///
    /// Groups vulnerabilities by similarity to identify:
    /// - Recurring vulnerabilities across endpoints
    /// - Systemic security issues
    /// - Related attack surfaces
    pub fn cluster_findings(&self, findings: &[crate::scanners::Vuln]) -> Vec<VulnCluster> {
        let mut clusters: Vec<VulnCluster> = Vec::new();
        let mut assigned = HashSet::new();

        for (i, finding) in findings.iter().enumerate() {
            if assigned.contains(&i) {
                continue;
            }

            let mut cluster = VulnCluster {
                cluster_id: clusters.len(),
                similarity_threshold: 0.7,
                findings: vec![finding.clone()],
                pattern_description: self.generate_pattern_description(finding),
                confidence: 0.0,
            };

            // Find similar findings
            for (j, other) in findings.iter().enumerate() {
                if i != j && !assigned.contains(&j) {
                    let similarity = self.calculate_similarity(finding, other);
                    if similarity >= cluster.similarity_threshold {
                        cluster.findings.push(other.clone());
                        assigned.insert(j);
                    }
                }
            }

            cluster.confidence = self.calculate_cluster_confidence(&cluster);
            clusters.push(cluster);
            assigned.insert(i);
        }

        // Sort by confidence and finding count
        clusters.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        clusters
    }

    /// Detect zero-day vulnerabilities via anomaly analysis
    ///
    /// Identifies potential unknown vulnerabilities by:
    /// - Analyzing behavioral deviations from learned patterns
    /// - Detecting unexpected parameter interactions
    /// - Finding unexplored attack surfaces
    pub fn detect_zero_day(&self, behavior: &BehavioralProfile) -> Vec<ZeroDayCandidate> {
        let mut candidates = Vec::new();

        // Check for unexpected parameter behaviors
        for (param, stats) in &behavior.parameter_stats {
            if self.is_parameter_behavior_anomalous(stats) {
                candidates.push(ZeroDayCandidate {
                    severity: VulnSeverity::High,
                    description: format!(
                        "Parameter '{}' exhibits anomalous behavior: unexpected {}",
                        param, stats.anomaly_description
                    ),
                    confidence: stats.anomaly_score,
                    affected_components: vec![param.clone()],
                    suggested_testing: self.generate_zero_day_tests(param, stats),
                });
            }
        }

        // Check for endpoint behavior anomalies
        for (endpoint, stats) in &behavior.endpoint_stats {
            if self.is_endpoint_behavior_anomalous(stats) {
                candidates.push(ZeroDayCandidate {
                    severity: VulnSeverity::Medium,
                    description: format!(
                        "Endpoint '{}' shows unusual response patterns: {}",
                        endpoint, stats.anomaly_description
                    ),
                    confidence: stats.anomaly_score,
                    affected_components: vec![endpoint.clone()],
                    suggested_testing: self.generate_zero_day_tests(endpoint, stats),
                });
            }
        }

        candidates
    }

    /// Calculate adaptive severity score based on user feedback
    ///
    /// Adjusts vulnerability severity based on:
    /// - Historical confirmation/rejection rates
    /// - Contextual factors from user feedback
    /// - Environment-specific risk tolerance
    pub fn adaptive_severity(&self, vuln: &crate::scanners::Vuln) -> AdaptiveSeverity {
        let base_severity = vuln.severity;
        let pattern_key = self.generate_pattern_key(vuln);

        let adjustment = self
            .feedback_store
            .get_severity_adjustment(&pattern_key)
            .unwrap_or(0.0);

        let confidence = self.feedback_store.get_confidence(&pattern_key);

        let adjusted_severity = if adjustment > 0.3 {
            self.increase_severity(base_severity)
        } else if adjustment < -0.3 {
            self.decrease_severity(base_severity)
        } else {
            base_severity
        };

        AdaptiveSeverity {
            original_severity: base_severity,
            adjusted_severity,
            adjustment,
            confidence: confidence.unwrap_or(0.5),
            reason: self.generate_adjustment_reason(adjustment, confidence),
        }
    }

    /// Learn from user feedback
    ///
    /// Incorporates user confirmation/rejection to improve future detections
    pub fn learn_from_feedback(&mut self, feedback: MlUserFeedback) -> Result<()> {
        let pattern_key = self.generate_pattern_key(&feedback.vuln);

        self.feedback_store.add_feedback(pattern_key.clone(), feedback.clone())?;

        // Update patterns based on feedback
        if feedback.confirmed {
            // Strengthen pattern weight
            self.patterns.strengthen_pattern(&pattern_key);
        } else {
            // Weaken pattern weight
            self.patterns.weaken_pattern(&pattern_key);
        }

        Ok(())
    }

    /// Extract TF-IDF features from text
    ///
    /// Term Frequency-Inverse Document Frequency for:
    /// - Response body analysis
    /// - Error message classification
    /// - Technology fingerprinting
    pub fn extract_tfidf_features(&self, documents: &[String]) -> TfidfFeatures {
        let mut vocabulary: HashMap<String, usize> = HashMap::new();
        let mut document_frequency: HashMap<usize, usize> = HashMap::new();
        let mut term_frequency: Vec<HashMap<usize, f64>> = Vec::new();

        // Build vocabulary
        for doc in documents {
            let terms = self.tokenize(doc);
            let mut doc_term_count: HashMap<usize, usize> = HashMap::new();

            for term in terms {
                // Check if term exists first, then insert if needed
                let term_id = if let Some(&id) = vocabulary.get(&term) {
                    id
                } else {
                    let id = vocabulary.len();
                    vocabulary.insert(term.clone(), id);
                    id
                };
                *doc_term_count.entry(term_id).or_insert(0) += 1;
            }

            // Update document frequency
            for term_id in doc_term_count.keys() {
                *document_frequency.entry(*term_id).or_insert(0) += 1;
            }
        }

        // Calculate TF-IDF
        for doc in documents {
            let terms = self.tokenize(doc);
            let mut doc_terms: HashMap<usize, usize> = HashMap::new();
            let doc_len = terms.len() as f64;

            for term in terms {
                if let Some(&term_id) = vocabulary.get(&term) {
                    *doc_terms.entry(term_id).or_insert(0) += 1;
                }
            }

            let mut tfidf: HashMap<usize, f64> = HashMap::new();
            for (term_id, count) in doc_terms {
                let tf = count as f64 / doc_len;
                let idf = if let Some(&df) = document_frequency.get(&term_id) {
                    (documents.len() as f64 / df as f64).ln() + 1.0
                } else {
                    1.0
                };
                tfidf.insert(term_id, tf * idf);
            }

            term_frequency.push(tfidf);
        }

        TfidfFeatures {
            vocabulary,
            document_frequency,
            term_frequency,
        }
    }

    /// Extract n-gram features from payloads
    ///
    /// Character and word n-grams for:
    /// - Payload pattern analysis
    /// - Injection detection
    /// - Encoding recognition
    pub fn extract_ngram_features(&self, text: &str, n: usize) -> Vec<NgramFeature> {
        let chars: Vec<char> = text.chars().collect();
        let mut features = Vec::new();

        // Character n-grams
        for i in 0..chars.len().saturating_sub(n - 1) {
            let ngram: String = chars[i..i + n].iter().collect();
            let frequency = self.count_ngram_occurrences(text, &ngram);

            features.push(NgramFeature {
                ngram,
                ngram_type: NgramType::Character,
                frequency,
                position: i,
            });
        }

        // Word n-grams
        let words: Vec<&str> = text.split_whitespace().collect();
        for i in 0..words.len().saturating_sub(n - 1) {
            let ngram = words[i..i + n].join(" ");
            let frequency = self.count_ngram_occurrences(text, &ngram);

            features.push(NgramFeature {
                ngram,
                ngram_type: NgramType::Word,
                frequency,
                position: i,
            });
        }

        features
    }

    // Private helper methods

    fn is_response_time_anomalous(&self, time_ms: u64) -> bool {
        let baseline = self.anomaly_config.baseline_response_time_ms;
        let threshold = self.anomaly_config.response_time_threshold_multiplier;

        time_ms as f64 > baseline as f64 * threshold
    }

    fn calculate_time_confidence(&self, time_ms: u64) -> f64 {
        let baseline = self.anomaly_config.baseline_response_time_ms as f64;
        let ratio = time_ms as f64 / baseline;

        // Confidence increases with deviation from baseline
        (ratio - 1.0).min(1.0).max(0.0)
    }

    fn is_status_code_anomalous(&self, status: u16) -> bool {
        // Consider unexpected status codes anomalous
        matches!(status, 400 | 401 | 403 | 404 | 500 | 502 | 503)
    }

    fn detect_information_disclosure(
        &self,
        header_name: &str,
        header_value: &str,
    ) -> Option<DisclosureInfo> {
        let sensitive_headers = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-php-version",
            "x-debug-info",
            "x-stack-trace",
        ];

        let header_lower = header_name.to_lowercase();

        if sensitive_headers.contains(&header_lower.as_str()) {
            return Some(DisclosureInfo {
                severity: AnomalySeverity::Low,
                description: format!(
                    "Information disclosure via '{}': {}",
                    header_name, header_value
                ),
                confidence: 0.9,
            });
        }

        // Check for leaky headers
        if header_lower.contains("version") || header_lower.contains("debug") {
            return Some(DisclosureInfo {
                severity: AnomalySeverity::Low,
                description: format!(
                    "Potential version info in '{}': {}",
                    header_name, header_value
                ),
                confidence: 0.6,
            });
        }

        None
    }

    fn analyze_body_patterns(&self, body: &str) -> Option<PatternInfo> {
        // Common error patterns that may indicate vulnerabilities
        let patterns = [
            ("sql syntax", AnomalySeverity::High, "Possible SQL injection point"),
            ("mysql_fetch", AnomalySeverity::High, "MySQL error disclosure"),
            ("ORA-", AnomalySeverity::Medium, "Oracle database error"),
            ("Microsoft OLE DB", AnomalySeverity::Medium, "Database error disclosure"),
            ("Warning: mysql", AnomalySeverity::High, "MySQL error disclosure"),
            ("Parse error", AnomalySeverity::Low, "PHP error disclosure"),
            ("fatal error", AnomalySeverity::Medium, "Application error disclosure"),
            ("stack trace", AnomalySeverity::Medium, "Stack trace disclosure"),
            ("exception", AnomalySeverity::Low, "Exception information disclosure"),
            ("debug", AnomalySeverity::Low, "Debug information present"),
        ];

        let body_lower = body.to_lowercase();

        for (pattern, severity, description) in patterns {
            if body_lower.contains(pattern) {
                return Some(PatternInfo {
                    severity,
                    description: description.to_string(),
                    confidence: 0.8,
                });
            }
        }

        None
    }

    fn extract_features(&self, text: &str) -> FeatureVector {
        let words = self.tokenize(text);
        let mut features = FeatureVector::new();

        // Word frequency
        for word in &words {
            *features.word_frequency.entry(word.clone()).or_insert(0) += 1;
        }

        // Character patterns
        for c in text.chars() {
            *features.char_frequency.entry(c).or_insert(0) += 1;
        }

        // Special sequences
        let sql_keywords_joined = self.feature_config.sql_keywords.join(" ");
        features.has_sql_keywords = text
            .to_lowercase()
            .contains(&sql_keywords_joined)
                || self.feature_config.sql_keywords.iter().any(|k| text.to_lowercase().contains(k));

        features.has_xss_patterns = text
            .to_lowercase()
            .contains("<script")
            || text.to_lowercase().contains("javascript:");

        features.has_path_traversal = text.contains("../") || text.contains("..\\");

        features
    }

    fn detect_technology(&self, features: &FeatureVector) -> Option<String> {
        // Simple technology fingerprinting
        if features.has_sql_keywords {
            return Some("Database-backed application".to_string());
        }

        if features.has_xss_patterns {
            return Some("JavaScript-heavy application".to_string());
        }

        // Check for framework-specific patterns
        for (pattern, tech) in &self.patterns.technology_signatures {
            if features.word_frequency.contains_key(pattern) {
                return Some(tech.clone());
            }
        }

        None
    }

    fn tokenize(&self, text: &str) -> Vec<String> {
        text.to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }

    fn calculate_similarity(
        &self,
        a: &crate::scanners::Vuln,
        b: &crate::scanners::Vuln,
    ) -> f64 {
        let mut similarity = 0.0;

        // Title similarity
        similarity += self.jaccard_similarity(&a.title, &b.title) * 0.4;

        // Severity match
        if a.severity == b.severity {
            similarity += 0.2;
        }

        // Description similarity
        similarity += self.jaccard_similarity(&a.description, &b.description) * 0.3;

        // CWE match
        match (&a.cwe, &b.cwe) {
            (Some(cwe_a), Some(cwe_b)) if cwe_a == cwe_b => similarity += 0.1,
            _ => {}
        };

        similarity.min(1.0)
    }

    fn jaccard_similarity(&self, a: &str, b: &str) -> f64 {
        let set_a: HashSet<&str> = a.split_whitespace().collect();
        let set_b: HashSet<&str> = b.split_whitespace().collect();

        if set_a.is_empty() || set_b.is_empty() {
            return 0.0;
        }

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();

        intersection as f64 / union as f64
    }

    fn calculate_cluster_confidence(&self, cluster: &VulnCluster) -> f64 {
        let base_confidence = 0.5;
        let finding_boost = (cluster.findings.len() as f64).log10() * 0.1;
        (base_confidence + finding_boost).min(1.0)
    }

    fn generate_pattern_description(&self, vuln: &crate::scanners::Vuln) -> String {
        format!(
            "{}: {} - {}",
            vuln.severity, vuln.title, vuln.description
        )
    }

    fn is_parameter_behavior_anomalous(&self, stats: &ParameterStats) -> bool {
        stats.anomaly_score > self.anomaly_config.anomaly_threshold
    }

    fn is_endpoint_behavior_anomalous(&self, stats: &EndpointStats) -> bool {
        stats.anomaly_score > self.anomaly_config.anomaly_threshold
    }

    fn generate_zero_day_tests(&self, target: &str, stats: &dyn StatsContainer) -> Vec<String> {
        vec![
            format!("Fuzz parameter '{}' with boundary values", target),
            format!("Test parameter '{}' with type confusion payloads", target),
            format!("Explore parameter '{}' for business logic bypasses", target),
        ]
    }

    fn increase_severity(&self, severity: crate::scanners::VulnSeverity) -> crate::scanners::VulnSeverity {
        use crate::scanners::VulnSeverity::*;
        match severity {
            Info => Low,
            Low => Medium,
            Medium => High,
            High => Critical,
            Critical => Critical,
        }
    }

    fn decrease_severity(&self, severity: crate::scanners::VulnSeverity) -> crate::scanners::VulnSeverity {
        use crate::scanners::VulnSeverity::*;
        match severity {
            Critical => High,
            High => Medium,
            Medium => Low,
            Low => Info,
            Info => Info,
        }
    }

    fn generate_pattern_key(&self, vuln: &crate::scanners::Vuln) -> String {
        format!(
            "{}:{}:{}",
            vuln.severity,
            vuln.title
                .to_lowercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("_"),
            vuln.cwe.as_ref().unwrap_or(&"unknown".to_string())
        )
    }

    fn generate_adjustment_reason(&self, adjustment: f64, confidence: Option<f64>) -> String {
        let conf = confidence.unwrap_or(0.5);

        if adjustment > 0.3 {
            format!(
                "Increased severity due to high confirmation rate ({:.0}% confidence)",
                conf * 100.0
            )
        } else if adjustment < -0.3 {
            format!(
                "Decreased severity due to high false positive rate ({:.0}% confidence)",
                conf * 100.0
            )
        } else {
            "No adjustment - insufficient data".to_string()
        }
    }

    fn count_ngram_occurrences(&self, text: &str, ngram: &str) -> usize {
        text.matches(ngram).count()
    }
}

/// Store for learned patterns
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PatternStore {
    /// Pattern weights learned from feedback
    pattern_weights: HashMap<String, f64>,
    /// Technology signatures for fingerprinting
    technology_signatures: Vec<(String, String)>,
}

impl PatternStore {
    pub fn new() -> Self {
        Self {
            pattern_weights: HashMap::new(),
            technology_signatures: vec![
                ("express".to_string(), "Express.js".to_string()),
                ("django".to_string(), "Django".to_string()),
                ("rails".to_string(), "Ruby on Rails".to_string()),
                ("laravel".to_string(), "Laravel".to_string()),
                ("spring".to_string(), "Spring Framework".to_string()),
                ("flask".to_string(), "Flask".to_string()),
                ("react".to_string(), "React".to_string()),
                ("vue".to_string(), "Vue.js".to_string()),
                ("angular".to_string(), "Angular".to_string()),
                ("wordpress".to_string(), "WordPress".to_string()),
                ("drupal".to_string(), "Drupal".to_string()),
                ("joomla".to_string(), "Joomla".to_string()),
            ],
        }
    }

    pub fn strengthen_pattern(&mut self, key: &str) {
        *self.pattern_weights.entry(key.to_string()).or_insert(0.5) += 0.1;
    }

    pub fn weaken_pattern(&mut self, key: &str) {
        *self.pattern_weights.entry(key.to_string()).or_insert(0.5) -= 0.1;
    }
}

/// Anomaly detection configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Baseline response time in milliseconds
    pub baseline_response_time_ms: u64,
    /// Multiplier for threshold
    pub response_time_threshold_multiplier: f64,
    /// Threshold for anomaly detection
    pub anomaly_threshold: f64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            baseline_response_time_ms: 500,
            response_time_threshold_multiplier: 3.0,
            anomaly_threshold: 0.7,
        }
    }
}

/// Feature extraction configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// SQL injection keywords
    pub sql_keywords: Vec<String>,
    /// XSS patterns
    pub xss_patterns: Vec<String>,
    /// Path traversal patterns
    pub path_traversal_patterns: Vec<String>,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            sql_keywords: vec![
                "select".to_string(),
                "union".to_string(),
                "insert".to_string(),
                "update".to_string(),
                "delete".to_string(),
                "drop".to_string(),
                "exec".to_string(),
                "script".to_string(),
            ],
            xss_patterns: vec![
                "<script>".to_string(),
                "javascript:".to_string(),
                "onerror=".to_string(),
                "onload=".to_string(),
            ],
            path_traversal_patterns: vec![
                "../".to_string(),
                "..\\".to_string(),
                "%2e%2e".to_string(),
            ],
        }
    }
}

/// Store for user feedback
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedbackStore {
    /// Severity adjustments per pattern
    severity_adjustments: HashMap<String, f64>,
    /// Confidence scores per pattern
    confidences: HashMap<String, f64>,
    /// Feedback counts
    feedback_counts: HashMap<String, (usize, usize)>, // (confirmed, rejected)
}

impl FeedbackStore {
    pub fn new() -> Self {
        Self {
            severity_adjustments: HashMap::new(),
            confidences: HashMap::new(),
            feedback_counts: HashMap::new(),
        }
    }

    pub fn add_feedback(&mut self, key: String, feedback: MlUserFeedback) -> Result<()> {
        let counts = self
            .feedback_counts
            .entry(key.clone())
            .or_insert((0, 0));

        if feedback.confirmed {
            counts.0 += 1;
        } else {
            counts.1 += 1;
        }

        // Calculate adjustment
        let total = (counts.0 + counts.1) as f64;
        let adjustment = (counts.0 as f64 - counts.1 as f64) / total;

        self.severity_adjustments.insert(key.clone(), adjustment);

        // Calculate confidence based on total feedback
        let confidence = (total / (total + 5.0)).min(0.95);
        self.confidences.insert(key, confidence);

        Ok(())
    }

    pub fn get_severity_adjustment(&self, key: &str) -> Option<f64> {
        self.severity_adjustments.get(key).copied()
    }

    pub fn get_confidence(&self, key: &str) -> Option<f64> {
        self.confidences.get(key).copied()
    }
}

/// HTTP response for analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub method: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub response_time_ms: Option<u64>,
}

/// Anomaly detection report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub url: String,
    pub anomalies: Vec<Anomaly>,
    pub timestamp: String,
}

/// Individual anomaly
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anomaly {
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub confidence: f64,
}

/// Type of anomaly
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    ResponseTime,
    UnexpectedStatusCode,
    InformationDisclosure,
    SuspiciousPattern,
    TechnologyFingerprint,
}

/// Anomaly severity
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
}

/// Information disclosure info
#[derive(Clone, Debug)]
struct DisclosureInfo {
    severity: AnomalySeverity,
    description: String,
    confidence: f64,
}

/// Pattern info
#[derive(Clone, Debug)]
struct PatternInfo {
    severity: AnomalySeverity,
    description: String,
    confidence: f64,
}

/// Feature vector
#[derive(Clone, Debug, Default)]
struct FeatureVector {
    word_frequency: HashMap<String, usize>,
    char_frequency: HashMap<char, usize>,
    has_sql_keywords: bool,
    has_xss_patterns: bool,
    has_path_traversal: bool,
}

impl FeatureVector {
    fn new() -> Self {
        Self::default()
    }
}

/// Vulnerability cluster
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnCluster {
    pub cluster_id: usize,
    pub similarity_threshold: f64,
    pub findings: Vec<crate::scanners::Vuln>,
    pub pattern_description: String,
    pub confidence: f64,
}

/// Behavioral profile for anomaly detection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub parameter_stats: HashMap<String, ParameterStats>,
    pub endpoint_stats: HashMap<String, EndpointStats>,
}

/// Parameter statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParameterStats {
    pub anomaly_score: f64,
    pub anomaly_description: String,
    pub input_variance: f64,
    pub response_correlation: f64,
}

/// Endpoint statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointStats {
    pub anomaly_score: f64,
    pub anomaly_description: String,
    pub response_variance: f64,
    pub status_distribution: HashMap<u16, f64>,
}

/// Trait for stats containers
trait StatsContainer {
    fn anomaly_score(&self) -> f64;
    fn anomaly_description(&self) -> &str;
}

impl StatsContainer for ParameterStats {
    fn anomaly_score(&self) -> f64 {
        self.anomaly_score
    }

    fn anomaly_description(&self) -> &str {
        &self.anomaly_description
    }
}

impl StatsContainer for EndpointStats {
    fn anomaly_score(&self) -> f64 {
        self.anomaly_score
    }

    fn anomaly_description(&self) -> &str {
        &self.anomaly_description
    }
}

/// Zero-day vulnerability candidate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroDayCandidate {
    pub severity: VulnSeverity,
    pub description: String,
    pub confidence: f64,
    pub affected_components: Vec<String>,
    pub suggested_testing: Vec<String>,
}

/// Adaptive severity result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdaptiveSeverity {
    pub original_severity: crate::scanners::VulnSeverity,
    pub adjusted_severity: crate::scanners::VulnSeverity,
    pub adjustment: f64,
    pub confidence: f64,
    pub reason: String,
}

/// User feedback for ML learning
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlUserFeedback {
    pub vuln: crate::scanners::Vuln,
    pub confirmed: bool,
    pub timestamp: String,
    pub notes: Option<String>,
}

/// TF-IDF features
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TfidfFeatures {
    pub vocabulary: HashMap<String, usize>,
    pub document_frequency: HashMap<usize, usize>,
    pub term_frequency: Vec<HashMap<usize, f64>>,
}

/// N-gram feature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NgramFeature {
    pub ngram: String,
    pub ngram_type: NgramType,
    pub frequency: usize,
    pub position: usize,
}

/// N-gram type
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NgramType {
    Character,
    Word,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Vuln, VulnSeverity};

    #[test]
    fn test_ml_detector_default() {
        let detector = MlDetector::new();
        assert_eq!(detector.anomaly_config.baseline_response_time_ms, 500);
    }

    #[test]
    fn test_analyze_response_with_anomaly() {
        let mut detector = MlDetector::new();

        let response = HttpResponse {
            url: "http://example.com/test".to_string(),
            method: "GET".to_string(),
            status_code: 500,
            headers: vec![
                ("Server".to_string(), "Apache/2.4.41".to_string()),
                ("X-Powered-By".to_string(), "PHP/7.4.3".to_string()),
            ]
            .into_iter()
            .collect(),
            body: Some("<html><body>SQL syntax error</body></html>".to_string()),
            response_time_ms: Some(2000),
        };

        let report = detector.analyze_response(&response);

        // Should detect response time anomaly
        assert!(report.anomalies.len() > 0);
    }

    #[test]
    fn test_cluster_findings() {
        let detector = MlDetector::new();

        let findings = vec![
            Vuln {
                severity: VulnSeverity::High,
                title: "SQL Injection".to_string(),
                description: "Possible SQL injection in login form".to_string(),
                location: Some("/login".to_string()),
                recommendation: Some("Use prepared statements".to_string()),
                cwe: Some("CWE-89".to_string()),
                owasp: Some("A03:2021".to_string()),
            },
            Vuln {
                severity: VulnSeverity::High,
                title: "SQL Injection".to_string(),
                description: "SQL injection in search parameter".to_string(),
                location: Some("/search".to_string()),
                recommendation: Some("Use parameterized queries".to_string()),
                cwe: Some("CWE-89".to_string()),
                owasp: Some("A03:2021".to_string()),
            },
        ];

        let clusters = detector.cluster_findings(&findings);

        // Should cluster similar findings
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].findings.len(), 2);
    }

    #[test]
    fn test_extract_tfidf_features() {
        let detector = MlDetector::new();

        let documents = vec![
            "SQL injection vulnerability in login form".to_string(),
            "XSS attack possible in search results".to_string(),
        ];

        let features = detector.extract_tfidf_features(&documents);

        // Should build vocabulary
        assert!(!features.vocabulary.is_empty());
        assert_eq!(features.term_frequency.len(), 2);
    }

    #[test]
    fn test_extract_ngram_features() {
        let detector = MlDetector::new();

        let text = "test payload";
        let features = detector.extract_ngram_features(text, 3);

        // Should extract character n-grams
        assert!(!features.is_empty());
    }

    #[test]
    fn test_adaptive_severity() {
        let detector = MlDetector::new();

        let vuln = Vuln {
            severity: VulnSeverity::Medium,
            title: "Test Vulnerability".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        };

        let result = detector.adaptive_severity(&vuln);

        // Without feedback, should return original severity
        assert_eq!(result.original_severity, VulnSeverity::Medium);
        assert_eq!(result.adjusted_severity, VulnSeverity::Medium);
    }

    #[test]
    fn test_learn_from_feedback() {
        let mut detector = MlDetector::new();

        let vuln = Vuln {
            severity: VulnSeverity::Medium,
            title: "Test Vulnerability".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        };

        let feedback = MlUserFeedback {
            vuln: vuln.clone(),
            confirmed: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
            notes: None,
        };

        let result = detector.learn_from_feedback(feedback);

        assert!(result.is_ok());
    }

    #[test]
    fn test_pattern_store() {
        let mut store = PatternStore::new();

        store.strengthen_pattern("test:pattern");
        store.weaken_pattern("test:pattern");

        // Should have technology signatures
        assert!(!store.technology_signatures.is_empty());
    }

    #[test]
    fn test_anomaly_config_default() {
        let config = AnomalyConfig::default();

        assert_eq!(config.baseline_response_time_ms, 500);
        assert_eq!(config.response_time_threshold_multiplier, 3.0);
    }

    #[test]
    fn test_feedback_store() {
        let mut store = FeedbackStore::new();

        let vuln = Vuln {
            severity: VulnSeverity::Medium,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        };

        let feedback = MlUserFeedback {
            vuln,
            confirmed: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
            notes: None,
        };

        let result = store.add_feedback("test_key".to_string(), feedback);

        assert!(result.is_ok());
        assert!(store.get_severity_adjustment("test_key").is_some());
    }
}
