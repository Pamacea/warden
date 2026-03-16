//! False Positive Reduction Module
//!
//! Advanced false positive detection and reduction system for Warden Enterprise Edition.
//!
//! # Features
//!
//! - **Contextual Filtering**: Analyze vulnerability context and exploitability
//! - **Similarity Analysis**: Deduplicate and cluster similar findings
//! - **Probabilistic Scoring**: Confidence intervals for scores
//! - **User Feedback**: Learn from confirmed false positives
//! - **Noise Reduction**: Filter irrelevant results

use crate::scanners::{ScanReport, Vuln, VulnSeverity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for similarity analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimilarityConfig {
    /// Minimum similarity threshold (0.0 - 1.0)
    pub threshold: f64,
    /// Weight for title similarity
    pub title_weight: f64,
    /// Weight for location similarity
    pub location_weight: f64,
    /// Weight for description similarity
    pub description_weight: f64,
    /// Enable fuzzy matching
    pub fuzzy_matching: bool,
    /// Maximum edit distance for fuzzy matching
    pub max_edit_distance: usize,
}

impl Default for SimilarityConfig {
    fn default() -> Self {
        Self {
            threshold: 0.75,
            title_weight: 0.5,
            location_weight: 0.3,
            description_weight: 0.2,
            fuzzy_matching: true,
            max_edit_distance: 3,
        }
    }
}

/// Probabilistic score with confidence interval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbabilisticScore {
    /// Point estimate (0-100)
    pub score: f64,
    /// Lower bound of confidence interval
    pub lower_bound: f64,
    /// Upper bound of confidence interval
    pub upper_bound: f64,
    /// Confidence level (e.g., 0.95 for 95%)
    pub confidence: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Sample size used for calculation
    pub sample_size: usize,
}

impl ProbabilisticScore {
    /// Create a new probabilistic score
    pub fn new(score: f64, std_dev: f64, confidence: f64, sample_size: usize) -> Self {
        // Calculate z-score for confidence level
        let z = Self::z_score(confidence);
        let margin_of_error = z * std_dev / (sample_size as f64).sqrt();

        Self {
            score: score.clamp(0.0, 100.0),
            lower_bound: (score - margin_of_error).clamp(0.0, 100.0),
            upper_bound: (score + margin_of_error).clamp(0.0, 100.0),
            confidence,
            std_dev,
            sample_size,
        }
    }

    /// Create a deterministic score (no uncertainty)
    pub fn deterministic(score: f64) -> Self {
        Self {
            score: score.clamp(0.0, 100.0),
            lower_bound: score.clamp(0.0, 100.0),
            upper_bound: score.clamp(0.0, 100.0),
            confidence: 1.0,
            std_dev: 0.0,
            sample_size: usize::MAX,
        }
    }

    /// Get z-score for confidence level using approximation
    fn z_score(confidence: f64) -> f64 {
        // Approximation of inverse normal CDF
        match confidence {
            c if c >= 0.99 => 2.576,
            c if c >= 0.95 => 1.96,
            c if c >= 0.90 => 1.645,
            c if c >= 0.80 => 1.282,
            _ => 1.0,
        }
    }

    /// Check if score is within acceptable range
    pub fn is_acceptable(&self, min_score: f64) -> bool {
        self.lower_bound >= min_score
    }

    /// Width of confidence interval
    pub fn interval_width(&self) -> f64 {
        self.upper_bound - self.lower_bound
    }

    /// Relative uncertainty (width / score)
    pub fn relative_uncertainty(&self) -> f64 {
        if self.score > 0.0 {
            self.interval_width() / self.score
        } else {
            0.0
        }
    }
}

/// User feedback on a finding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserFeedback {
    /// Unique identifier for the finding pattern
    pub pattern_id: String,
    /// User's judgment (true positive or false positive)
    pub is_false_positive: bool,
    /// Timestamp of feedback
    pub timestamp: u64,
    /// User ID or identifier
    pub user_id: Option<String>,
    /// Additional notes
    pub notes: Option<String>,
    /// Confidence in the feedback (1-5)
    pub confidence: u8,
}

impl UserFeedback {
    pub fn new(pattern_id: String, is_false_positive: bool) -> Self {
        Self {
            pattern_id,
            is_false_positive,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            user_id: None,
            notes: None,
            confidence: 3, // Default medium confidence
        }
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.clamp(1, 5);
        self
    }
}

/// Cluster of similar findings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingCluster {
    /// Unique cluster ID
    pub id: String,
    /// Representative finding (best example of the cluster)
    pub representative: Vuln,
    /// All findings in this cluster
    pub findings: Vec<Vuln>,
    /// Cluster confidence score
    pub confidence: f64,
    /// Cluster size
    pub size: usize,
    /// Common patterns in this cluster
    pub patterns: Vec<String>,
}

impl FindingCluster {
    pub fn new(id: String, representative: Vuln) -> Self {
        Self {
            id,
            representative,
            findings: Vec::new(),
            confidence: 1.0,
            size: 1,
            patterns: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Vuln) {
        self.findings.push(finding);
        self.size += 1;
    }

    /// Get consolidated description for the cluster
    pub fn consolidated_description(&self) -> String {
        if self.size == 1 {
            self.representative.description.clone()
        } else {
            format!(
                "{} ({} similar findings consolidated)",
                self.representative.description,
                self.size - 1
            )
        }
    }
}

/// Filter criteria for false positive detection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FalsePositiveFilter {
    /// Patterns to always filter
    pub always_filter: Vec<String>,
    /// Patterns to never filter
    pub never_filter: Vec<String>,
    /// Severity threshold (filter findings below this)
    pub min_severity: Option<VulnSeverity>,
    /// Confidence threshold (filter findings below this confidence)
    pub min_confidence: f64,
    /// Age threshold (filter findings older than this, in seconds)
    pub max_age_seconds: Option<u64>,
    /// Environment-specific filters
    pub environment_filters: HashMap<String, Vec<String>>,
}

impl Default for FalsePositiveFilter {
    fn default() -> Self {
        Self {
            always_filter: vec![
                // Common false positive patterns
                "robots.txt".to_string(),
                "sitemap.xml".to_string(),
                "favicon.ico".to_string(),
                ".well-known".to_string(),
                "example.com".to_string(),
                "test@example.com".to_string(),
                "placeholder".to_string(),
            ],
            never_filter: vec![],
            min_severity: None,
            min_confidence: 0.3,
            max_age_seconds: None,
            environment_filters: HashMap::new(),
        }
    }
}

/// Context information for vulnerability analysis
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnContext {
    /// URL or path where vulnerability was found
    pub location: String,
    /// Technology stack detected
    pub tech_stack: Vec<String>,
    /// Environment (production, staging, development)
    pub environment: String,
    /// Authentication requirements
    pub auth_required: bool,
    /// Network accessibility
    pub network_accessible: bool,
    /// Exploitability factors
    pub exploitability: ExploitabilityFactors,
}

/// Factors affecting exploitability
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExploitabilityFactors {
    /// Requires authentication
    pub requires_auth: bool,
    /// Requires user interaction
    pub requires_interaction: bool,
    /// Network access required
    pub network_access: bool,
    /// Complexity of exploitation
    pub complexity: ExploitComplexity,
    /// Privileges required
    pub privileges_required: PrivilegeLevel,
}

/// Exploitation complexity
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExploitComplexity {
    Low,
    Medium,
    High,
}

/// Required privilege level
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    None,
    Low,
    High,
}

/// Main false positive analyzer
pub struct FalsePositiveAnalyzer {
    config: SimilarityConfig,
    filter: FalsePositiveFilter,
    /// Learned patterns from user feedback
    learned_patterns: HashMap<String, (f64, usize)>,
    /// User feedback history
    feedback_history: Vec<UserFeedback>,
    /// Known false positive signatures
    fp_signatures: HashSet<String>,
}

impl FalsePositiveAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: SimilarityConfig::default(),
            filter: FalsePositiveFilter::default(),
            learned_patterns: HashMap::new(),
            feedback_history: Vec::new(),
            fp_signatures: Self::builtin_fp_signatures(),
        }
    }

    /// Create analyzer with custom configuration
    pub fn with_config(config: SimilarityConfig) -> Self {
        Self {
            config,
            filter: FalsePositiveFilter::default(),
            learned_patterns: HashMap::new(),
            feedback_history: Vec::new(),
            fp_signatures: Self::builtin_fp_signatures(),
        }
    }

    /// Create analyzer with custom filter
    pub fn with_filter(mut self, filter: FalsePositiveFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Built-in false positive signatures
    fn builtin_fp_signatures() -> HashSet<String> {
        let mut sigs = HashSet::new();

        // Development/testing patterns
        sigs.insert("localhost".to_string());
        sigs.insert("127.0.0.1".to_string());
        sigs.insert("0.0.0.0".to_string());
        sigs.insert("::1".to_string());
        sigs.insert("test".to_string());
        sigs.insert("demo".to_string());
        sigs.insert("example".to_string());
        sigs.insert("sample".to_string());
        sigs.insert("placeholder".to_string());
        sigs.insert("TODO".to_string());
        sigs.insert("FIXME".to_string());
        sigs.insert("XXX".to_string());

        // Documentation/common files
        sigs.insert("README".to_string());
        sigs.insert("LICENSE".to_string());
        sigs.insert("CHANGELOG".to_string());
        sigs.insert("CONTRIBUTING".to_string());

        // Static asset patterns
        sigs.insert(".css".to_string());
        sigs.insert(".js".to_string());
        sigs.insert(".png".to_string());
        sigs.insert(".jpg".to_string());
        sigs.insert(".svg".to_string());
        sigs.insert(".ico".to_string());
        sigs.insert(".woff".to_string());
        sigs.insert(".woff2".to_string());
        sigs.insert(".ttf".to_string());
        sigs.insert(".eot".to_string());

        sigs
    }

    /// Analyze and filter a scan report for false positives
    pub fn analyze_report(&mut self, report: &ScanReport) -> Result<ScanReport> {
        let mut filtered_report = report.clone();
        filtered_report.findings.clear();

        // First pass: contextual filtering
        let context_aware_findings: Vec<(Vuln, f64)> = report
            .findings
            .iter()
            .filter_map(|vuln| {
                let confidence = self.evaluate_context(vuln);
                if confidence >= self.filter.min_confidence {
                    Some((vuln.clone(), confidence))
                } else {
                    None
                }
            })
            .collect();

        // Second pass: similarity clustering and deduplication
        let clusters = self.cluster_findings(&context_aware_findings)?;

        // Third pass: apply learned patterns
        for cluster in clusters {
            if self.should_keep_cluster(&cluster) {
                filtered_report.add_finding(cluster.representative);
            }
        }

        // Note: recalculate_summary is private, but add_finding already updates the summary
        Ok(filtered_report)
    }

    /// Evaluate the context of a vulnerability
    fn evaluate_context(&self, vuln: &Vuln) -> f64 {
        let mut confidence = 1.0;

        // Check against known FP signatures
        for sig in &self.filter.always_filter {
            if vuln.title.contains(sig)
                || vuln.description.contains(sig)
                || vuln.location.as_ref().map_or(false, |l| l.contains(sig))
            {
                confidence *= 0.1;
            }
        }

        // Check built-in signatures
        for sig in &self.fp_signatures {
            if vuln.location.as_ref().map_or(false, |l| l.contains(sig)) {
                confidence *= 0.5;
            }
        }

        // Severity-based confidence adjustment
        confidence *= match vuln.severity {
            VulnSeverity::Critical => 1.0,
            VulnSeverity::High => 0.95,
            VulnSeverity::Medium => 0.85,
            VulnSeverity::Low => 0.7,
            VulnSeverity::Info => 0.5,
        };

        // Check for recommendation quality
        if vuln.recommendation.as_ref().map_or(false, |r| r.len() < 10) {
            confidence *= 0.8;
        }

        (confidence as f64).clamp(0.0, 1.0)
    }

    /// Cluster similar findings together
    fn cluster_findings(&self, findings: &[(Vuln, f64)]) -> Result<Vec<FindingCluster>> {
        let mut clusters: Vec<FindingCluster> = Vec::new();
        let mut assigned = HashSet::new();

        for (i, (finding, confidence)) in findings.iter().enumerate() {
            if assigned.contains(&i) {
                continue;
            }

            let mut cluster = FindingCluster::new(
                format!("cluster-{}", clusters.len()),
                finding.clone(),
            );
            cluster.confidence = *confidence;
            assigned.insert(i);

            // Find similar findings
            for (j, (other_finding, _)) in findings.iter().enumerate() {
                if i == j || assigned.contains(&j) {
                    continue;
                }

                let similarity = self.calculate_similarity(finding, other_finding);
                if similarity >= self.config.threshold {
                    cluster.add_finding(other_finding.clone());
                    assigned.insert(j);
                    cluster.confidence = cluster.confidence.min(*confidence);
                }
            }

            clusters.push(cluster);
        }

        Ok(clusters)
    }

    /// Calculate similarity between two vulnerabilities
    fn calculate_similarity(&self, a: &Vuln, b: &Vuln) -> f64 {
        let title_sim = self.string_similarity(&a.title, &b.title);
        let desc_sim = self.string_similarity(&a.description, &b.description);
        let loc_sim = match (&a.location, &b.location) {
            (Some(loc_a), Some(loc_b)) => self.string_similarity(loc_a, loc_b),
            _ => 0.0,
        };

        // Severity similarity (same severity = higher similarity)
        let severity_sim = if a.severity == b.severity { 1.0 } else { 0.5 };

        let combined = title_sim * self.config.title_weight
            + desc_sim * self.config.description_weight
            + loc_sim * self.config.location_weight
            + severity_sim * 0.1;

        combined.clamp(0.0, 1.0)
    }

    /// Calculate string similarity using Jaro-Winkler distance
    fn string_similarity(&self, a: &str, b: &str) -> f64 {
        if a == b {
            return 1.0;
        }

        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();

        if self.config.fuzzy_matching {
            self.jaro_winkler(&a_lower, &b_lower)
        } else {
            if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
                0.8
            } else {
                0.0
            }
        }
    }

    /// Jaro-Winkler similarity metric
    fn jaro_winkler(&self, a: &str, b: &str) -> f64 {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();

        let a_len = a_chars.len();
        let b_len = b_chars.len();

        if a_len == 0 && b_len == 0 {
            return 1.0;
        }
        if a_len == 0 || b_len == 0 {
            return 0.0;
        }

        let match_distance = a_len.max(b_len) / 2 - 1;
        if match_distance < 0 {
            return 0.0;
        }

        let mut a_matches = vec![false; a_len];
        let mut b_matches = vec![false; b_len];
        let mut matches = 0;

        for i in 0..a_len {
            let start = i.saturating_sub(match_distance);
            let end = (i + match_distance + 1).min(b_len);

            for j in start..end {
                if !b_matches[j] && a_chars[i] == b_chars[j] {
                    a_matches[i] = true;
                    b_matches[j] = true;
                    matches += 1;
                    break;
                }
            }
        }

        if matches == 0 {
            return 0.0;
        }

        let mut transpositions = 0;
        let mut k = 0;
        for i in 0..a_len {
            if a_matches[i] {
                while !b_matches[k] {
                    k += 1;
                }
                if a_chars[i] != b_chars[k] {
                    transpositions += 1;
                }
                k += 1;
            }
        }

        let jaro = (
            matches as f64 / a_len as f64
                + matches as f64 / b_len as f64
                + (matches - transpositions / 2) as f64 / matches as f64
        ) / 3.0;

        // Winkler modification for common prefix
        let prefix_len = a_chars
            .iter()
            .zip(b_chars.iter())
            .take_while(|(a, b)| a == b)
            .take(4)
            .count();

        let jaro_winkler = jaro + prefix_len as f64 * 0.1 * (1.0 - jaro);

        jaro_winkler.clamp(0.0, 1.0)
    }

    /// Determine if a cluster should be kept based on learned patterns
    fn should_keep_cluster(&self, cluster: &FindingCluster) -> bool {
        let signature = self.extract_signature(&cluster.representative);

        // Check learned patterns
        if let Some((fp_probability, sample_count)) = self.learned_patterns.get(&signature) {
            // Only filter if we have enough samples
            if *sample_count >= 3 && *fp_probability > 0.7 {
                return false;
            }
        }

        // Check filter thresholds
        if cluster.confidence < self.filter.min_confidence {
            return false;
        }

        if let Some(min_severity) = self.filter.min_severity {
            if (cluster.representative.severity as i32) < (min_severity as i32) {
                return false;
            }
        }

        true
    }

    /// Extract a signature from a vulnerability for pattern matching
    fn extract_signature(&self, vuln: &Vuln) -> String {
        format!(
            "{}::{}::{}",
            vuln.severity as i32,
            vuln.title
                .to_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>(),
            vuln.location
                .as_ref()
                .map(|l| {
                    l.to_lowercase()
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .collect::<String>()
                })
                .unwrap_or_default()
        )
    }

    /// Add user feedback and update learned patterns
    pub fn add_feedback(&mut self, feedback: UserFeedback) {
        // Store feedback
        self.feedback_history.push(feedback.clone());

        // Update learned patterns
        let entry = self.learned_patterns
            .entry(feedback.pattern_id.clone())
            .or_insert((0.5, 0));

        // Bayesian update
        let alpha = if feedback.is_false_positive { 1.0 } else { 0.0 };
        let weight = feedback.confidence as f64 / 5.0;

        let (current_prob, count) = *entry;
        let new_prob = (current_prob * count as f64 + alpha * weight) / (count as f64 + weight);
        *entry = (new_prob, count + 1);

        // Update signatures if high confidence FP
        if feedback.is_false_positive && feedback.confidence >= 4 {
            self.fp_signatures.insert(feedback.pattern_id);
        }
    }

    /// Get probabilistic score for a finding
    pub fn probabilistic_score(&self, vuln: &Vuln) -> ProbabilisticScore {
        let base_score = match vuln.severity {
            VulnSeverity::Critical => 95.0,
            VulnSeverity::High => 80.0,
            VulnSeverity::Medium => 60.0,
            VulnSeverity::Low => 40.0,
            VulnSeverity::Info => 20.0,
        };

        let confidence = self.evaluate_context(vuln);
        let adjusted_score = base_score * confidence;

        // Calculate uncertainty based on confidence and pattern history
        let signature = self.extract_signature(vuln);
        let std_dev = if let Some((_, count)) = self.learned_patterns.get(&signature) {
            // More samples = less uncertainty
            10.0_f64 / (1.0_f64 + (*count as f64).ln())
        } else {
            15.0 // Higher uncertainty for new patterns
        };

        let sample_size = self.learned_patterns.get(&signature).map(|(_, c)| *c).unwrap_or(1);

        ProbabilisticScore::new(adjusted_score, std_dev, 0.95, sample_size)
    }

    /// Get report statistics
    pub fn get_stats(&self) -> AnalyzerStats {
        AnalyzerStats {
            total_patterns_learned: self.learned_patterns.len(),
            feedback_count: self.feedback_history.len(),
            fp_signature_count: self.fp_signatures.len(),
            avg_confidence: self
                .feedback_history
                .iter()
                .map(|f| f.confidence as f64)
                .sum::<f64>()
                / self.feedback_history.len().max(1) as f64,
        }
    }

    /// Export learned patterns to file
    pub fn export_patterns(&self, path: &PathBuf) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.learned_patterns)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Import learned patterns from file
    pub fn import_patterns(&mut self, path: &PathBuf) -> Result<()> {
        let data = std::fs::read_to_string(path)?;
        self.learned_patterns = serde_json::from_str(&data)?;
        Ok(())
    }

    /// Update filter configuration
    pub fn update_filter(&mut self, filter: FalsePositiveFilter) {
        self.filter = filter;
    }

    /// Get current filter configuration
    pub fn get_filter(&self) -> &FalsePositiveFilter {
        &self.filter
    }
}

impl Default for FalsePositiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyzer statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyzerStats {
    pub total_patterns_learned: usize,
    pub feedback_count: usize,
    pub fp_signature_count: usize,
    pub avg_confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::Target;

    #[test]
    fn test_probabilistic_score_deterministic() {
        let score = ProbabilisticScore::deterministic(85.0);
        assert_eq!(score.score, 85.0);
        assert_eq!(score.lower_bound, 85.0);
        assert_eq!(score.upper_bound, 85.0);
        assert_eq!(score.std_dev, 0.0);
    }

    #[test]
    fn test_probabilistic_score_bounds() {
        let score = ProbabilisticScore::new(50.0, 10.0, 0.95, 100);
        assert!(score.lower_bound < score.score);
        assert!(score.upper_bound > score.score);
        assert!(score.lower_bound >= 0.0);
        assert!(score.upper_bound <= 100.0);
    }

    #[test]
    fn test_user_feedback_creation() {
        let feedback = UserFeedback::new("test-pattern".to_string(), true)
            .with_user_id("user1".to_string())
            .with_notes("Test note".to_string())
            .with_confidence(5);

        assert!(feedback.is_false_positive);
        assert_eq!(feedback.user_id, Some("user1".to_string()));
        assert_eq!(feedback.notes, Some("Test note".to_string()));
        assert_eq!(feedback.confidence, 5);
    }

    #[test]
    fn test_finding_cluster() {
        let vuln = Vuln {
            severity: VulnSeverity::High,
            title: "Test Vulnerability".to_string(),
            description: "Test description".to_string(),
            location: Some("/test/path".to_string()),
            recommendation: Some("Fix it".to_string()),
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
        };

        let mut cluster = FindingCluster::new("test-cluster".to_string(), vuln.clone());
        assert_eq!(cluster.size, 1);

        cluster.add_finding(vuln.clone());
        assert_eq!(cluster.size, 2);
        assert_eq!(cluster.findings.len(), 1);
    }

    #[test]
    fn test_string_similarity() {
        let analyzer = FalsePositiveAnalyzer::new();

        assert_eq!(analyzer.string_similarity("test", "test"), 1.0);
        assert!(analyzer.string_similarity("test", "toast") > 0.5);
        assert!(analyzer.string_similarity("completely", "different") < 0.5);
    }

    #[test]
    fn test_jaro_winkler() {
        let analyzer = FalsePositiveAnalyzer::new();

        let sim = analyzer.jaro_winkler("martha", "marhta");
        assert!(sim > 0.9); // Should be very similar

        let sim = analyzer.jaro_winkler("test", "text");
        assert!(sim > 0.7 && sim < 0.9);
    }

    #[test]
    fn test_false_positive_filtering() {
        let mut analyzer = FalsePositiveAnalyzer::new();

        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        // Add a finding with common FP pattern
        report.add_finding(Vuln {
            severity: VulnSeverity::Low,
            title: "robots.txt file exposed".to_string(),
            description: "robots.txt is accessible".to_string(),
            location: Some("/robots.txt".to_string()),
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        // Add a legitimate finding
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "SQL Injection".to_string(),
            description: "Critical SQL injection vulnerability".to_string(),
            location: Some("/api/users".to_string()),
            recommendation: Some("Use parameterized queries".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        let filtered = analyzer.analyze_report(&report).unwrap();

        // robots.txt should be filtered out
        assert!(!filtered.findings.iter().any(|f| f.title.contains("robots.txt")));
        // SQL Injection should remain
        assert!(filtered.findings.iter().any(|f| f.title.contains("SQL")));
    }

    #[test]
    fn test_clustering_deduplication() {
        let mut analyzer = FalsePositiveAnalyzer::new();

        let vuln1 = Vuln {
            severity: VulnSeverity::Medium,
            title: "XSS in search parameter".to_string(),
            description: "Cross-site scripting in search".to_string(),
            location: Some("/search?q=".to_string()),
            recommendation: None,
            cwe: Some("CWE-79".to_string()),
            owasp: None,
        };

        let vuln2 = Vuln {
            severity: VulnSeverity::Medium,
            title: "XSS in search parameter".to_string(),
            description: "Cross-site scripting in search".to_string(),
            location: Some("/search?q=".to_string()),
            recommendation: None,
            cwe: Some("CWE-79".to_string()),
            owasp: None,
        };

        let findings = vec![(vuln1, 1.0), (vuln2, 1.0)];
        let clusters = analyzer.cluster_findings(&findings).unwrap();

        // Should be clustered into one
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].size, 2);
    }

    #[test]
    fn test_feedback_learning() {
        let mut analyzer = FalsePositiveAnalyzer::new();

        let feedback = UserFeedback::new("test-pattern".to_string(), true)
            .with_confidence(5);
        analyzer.add_feedback(feedback);

        let stats = analyzer.get_stats();
        assert_eq!(stats.feedback_count, 1);
        assert!(stats.total_patterns_learned >= 1);
    }

    #[test]
    fn test_similarity_config_default() {
        let config = SimilarityConfig::default();
        assert_eq!(config.threshold, 0.75);
        assert_eq!(config.title_weight, 0.5);
        assert!(config.fuzzy_matching);
    }

    #[test]
    fn test_fp_signature_extraction() {
        let analyzer = FalsePositiveAnalyzer::new();

        let vuln = Vuln {
            severity: VulnSeverity::High,
            title: "SQL Injection Vulnerability".to_string(),
            description: "SQL injection found".to_string(),
            location: Some("/api/users".to_string()),
            recommendation: None,
            cwe: None,
            owasp: None,
        };

        let signature = analyzer.extract_signature(&vuln);
        assert!(signature.contains("2")); // High severity
        assert!(signature.contains("sql"));
    }

    #[test]
    fn test_analyzer_stats() {
        let analyzer = FalsePositiveAnalyzer::new();
        let stats = analyzer.get_stats();

        assert_eq!(stats.total_patterns_learned, 0);
        assert_eq!(stats.feedback_count, 0);
        assert!(stats.fp_signature_count > 0); // Built-in signatures
    }

    #[test]
    fn test_false_positive_filter_default() {
        let filter = FalsePositiveFilter::default();

        assert!(!filter.always_filter.is_empty());
        assert_eq!(filter.min_confidence, 0.3);
    }
}
