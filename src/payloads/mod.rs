//! Smart Payload Selection System for Warden v0.8.0 Enterprise Edition
//!
//! This module provides intelligent payload generation and selection
//! capabilities for security scanning. It includes:
//!
//! - **Adaptive Payload Generation**: Mutates payloads based on WAF responses
//! - **Context-Aware Selection**: Chooses optimal payloads for each situation
//! - **Grammar-Based Fuzzing**: Protocol-specific payload generation
//! - **Learning System**: Improves payload selection based on past results

pub mod smart;

// Re-exports for convenience
pub use smart::{
    BypassTechnique, ExpectedBehavior, FuzzingGrammar, PayloadCategory, PayloadLearning,
    PayloadSeverity, PayloadStats, ResponseAnalysis, SmartPayload, SmartPayloadSelector,
};

/// Predefined payload strategies for common scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadStrategy {
    /// Conservative testing (minimal impact)
    Conservative,
    /// Standard testing (balanced)
    Standard,
    /// Aggressive testing (thorough but noisier)
    Aggressive,
    /// Stealth mode (low and slow)
    Stealth,
    /// Bypass-focused (WAF evasion)
    Bypass,
}

impl PayloadStrategy {
    /// Get the strategy name
    pub fn name(&self) -> &str {
        match self {
            Self::Conservative => "conservative",
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
            Self::Stealth => "stealth",
            Self::Bypass => "bypass",
        }
    }

    /// Get max payloads per category for this strategy
    pub fn max_payloads(&self) -> usize {
        match self {
            Self::Conservative => 10,
            Self::Standard => 50,
            Self::Aggressive => 200,
            Self::Stealth => 20,
            Self::Bypass => 100,
        }
    }

    /// Get delay between requests for this strategy
    pub fn delay_ms(&self) -> u64 {
        match self {
            Self::Conservative => 500,
            Self::Standard => 100,
            Self::Aggressive => 0,
            Self::Stealth => 2000,
            Self::Bypass => 300,
        }
    }

    /// Check if adaptive selection is enabled
    pub fn is_adaptive(&self) -> bool {
        matches!(self, Self::Standard | Self::Aggressive | Self::Bypass)
    }
}

/// Payload context for context-aware generation
#[derive(Debug, Clone)]
pub struct PayloadContext {
    /// Target URL
    pub target_url: String,
    /// Detected technology stack
    pub technology: Option<String>,
    /// Detected WAF
    pub waf: Option<String>,
    /// Injection point (parameter name, header, etc.)
    pub injection_point: String,
    /// Data type expected
    pub data_type: PayloadDataType,
}

/// Data type for payload context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDataType {
    String,
    Integer,
    Float,
    Boolean,
    Json,
    Xml,
    GraphQL,
    Unknown,
}

impl PayloadContext {
    /// Create a new payload context
    pub fn new(target_url: String, injection_point: String) -> Self {
        Self {
            target_url,
            technology: None,
            waf: None,
            injection_point,
            data_type: PayloadDataType::Unknown,
        }
    }

    /// Set detected technology
    pub fn with_technology(mut self, tech: String) -> Self {
        self.technology = Some(tech);
        self
    }

    /// Set detected WAF
    pub fn with_waf(mut self, waf: String) -> Self {
        self.waf = Some(waf);
        self
    }

    /// Set expected data type
    pub fn with_data_type(mut self, data_type: PayloadDataType) -> Self {
        self.data_type = data_type;
        self
    }
}

/// Combined payload generator with strategy and context
pub struct PayloadGenerator {
    /// The underlying smart selector
    selector: SmartPayloadSelector,
    /// Current strategy
    strategy: PayloadStrategy,
}

impl PayloadGenerator {
    /// Create a new payload generator
    pub fn new(strategy: PayloadStrategy) -> Self {
        let mut selector = SmartPayloadSelector::new(None);
        selector.max_payloads_per_category = strategy.max_payloads();
        selector.adaptive = strategy.is_adaptive();

        Self { selector, strategy }
    }

    /// Generate payloads for a category with context
    pub async fn generate(
        &mut self,
        category: PayloadCategory,
        context: &PayloadContext,
    ) -> Vec<String> {
        // Load payloads
        let _ = self.selector.load_payloads(&[category]).await;

        // Create response analysis based on context
        let analysis = context.waf.as_ref().map(|waf| ResponseAnalysis {
            status_code: 200,
            body_snippet: String::new(),
            headers: std::collections::HashMap::new(),
            detected_waf: Some(waf.clone()),
            blocked: true,
            rate_limited: false,
            has_challenge: false,
            response_time_ms: 100,
            content_length: None,
        });

        // Select payloads
        let selected = self.selector.select_payloads(category, analysis.as_ref());

        // Extract and potentially mutate based on context
        let mut results = Vec::new();
        for payload in selected {
            results.push(payload.payload.clone());

            // Add mutations if strategy allows
            if matches!(self.strategy, PayloadStrategy::Aggressive | PayloadStrategy::Bypass) {
                let mutations = self.selector.generate_mutations(&payload.payload, category);
                results.extend(mutations.into_iter().take(5));
            }
        }

        // Limit by strategy
        results.into_iter().take(self.strategy.max_payloads()).collect()
    }

    /// Record a payload test result
    pub fn record_result(&mut self, category: PayloadCategory, payload: &str, successful: bool) {
        self.selector.record_result(category, payload, successful);
    }

    /// Get the current strategy
    pub fn strategy(&self) -> PayloadStrategy {
        self.strategy
    }

    /// Change the strategy
    pub fn set_strategy(&mut self, strategy: PayloadStrategy) {
        self.strategy = strategy;
        self.selector.max_payloads_per_category = strategy.max_payloads();
        self.selector.adaptive = strategy.is_adaptive();
    }

    /// Get the underlying selector
    pub fn selector(&self) -> &SmartPayloadSelector {
        &self.selector
    }

    /// Get mutable reference to the selector
    pub fn selector_mut(&mut self) -> &mut SmartPayloadSelector {
        &mut self.selector
    }
}

impl Default for PayloadGenerator {
    fn default() -> Self {
        Self::new(PayloadStrategy::Standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_names() {
        assert_eq!(PayloadStrategy::Conservative.name(), "conservative");
        assert_eq!(PayloadStrategy::Standard.name(), "standard");
        assert_eq!(PayloadStrategy::Aggressive.name(), "aggressive");
        assert_eq!(PayloadStrategy::Stealth.name(), "stealth");
        assert_eq!(PayloadStrategy::Bypass.name(), "bypass");
    }

    #[test]
    fn test_strategy_max_payloads() {
        assert_eq!(PayloadStrategy::Conservative.max_payloads(), 10);
        assert_eq!(PayloadStrategy::Standard.max_payloads(), 50);
        assert_eq!(PayloadStrategy::Aggressive.max_payloads(), 200);
        assert_eq!(PayloadStrategy::Stealth.max_payloads(), 20);
        assert_eq!(PayloadStrategy::Bypass.max_payloads(), 100);
    }

    #[test]
    fn test_strategy_delay_ms() {
        assert_eq!(PayloadStrategy::Conservative.delay_ms(), 500);
        assert_eq!(PayloadStrategy::Standard.delay_ms(), 100);
        assert_eq!(PayloadStrategy::Aggressive.delay_ms(), 0);
        assert_eq!(PayloadStrategy::Stealth.delay_ms(), 2000);
        assert_eq!(PayloadStrategy::Bypass.delay_ms(), 300);
    }

    #[test]
    fn test_strategy_is_adaptive() {
        assert!(!PayloadStrategy::Conservative.is_adaptive());
        assert!(PayloadStrategy::Standard.is_adaptive());
        assert!(PayloadStrategy::Aggressive.is_adaptive());
        assert!(!PayloadStrategy::Stealth.is_adaptive());
        assert!(PayloadStrategy::Bypass.is_adaptive());
    }

    #[test]
    fn test_payload_context_creation() {
        let context = PayloadContext::new(
            "https://example.com".to_string(),
            "search".to_string(),
        );

        assert_eq!(context.target_url, "https://example.com");
        assert_eq!(context.injection_point, "search");
        assert_eq!(context.data_type, PayloadDataType::Unknown);
    }

    #[test]
    fn test_payload_context_builder() {
        let context = PayloadContext::new(
            "https://example.com".to_string(),
            "search".to_string(),
        )
        .with_technology("React".to_string())
        .with_waf("Cloudflare".to_string())
        .with_data_type(PayloadDataType::String);

        assert_eq!(context.technology, Some("React".to_string()));
        assert_eq!(context.waf, Some("Cloudflare".to_string()));
        assert_eq!(context.data_type, PayloadDataType::String);
    }

    #[test]
    fn test_payload_generator_creation() {
        let generator = PayloadGenerator::new(PayloadStrategy::Standard);

        assert_eq!(generator.strategy(), PayloadStrategy::Standard);
    }

    #[test]
    fn test_payload_generator_default() {
        let generator = PayloadGenerator::default();

        assert_eq!(generator.strategy(), PayloadStrategy::Standard);
    }

    #[test]
    fn test_payload_generator_set_strategy() {
        let mut generator = PayloadGenerator::new(PayloadStrategy::Conservative);

        generator.set_strategy(PayloadStrategy::Aggressive);

        assert_eq!(generator.strategy(), PayloadStrategy::Aggressive);
    }

    #[test]
    fn test_payload_data_type() {
        assert_eq!(PayloadDataType::String, PayloadDataType::String);
        assert_eq!(PayloadDataType::Integer, PayloadDataType::Integer);
        assert_eq!(PayloadDataType::Float, PayloadDataType::Float);
        assert_eq!(PayloadDataType::Boolean, PayloadDataType::Boolean);
        assert_eq!(PayloadDataType::Json, PayloadDataType::Json);
        assert_eq!(PayloadDataType::Xml, PayloadDataType::Xml);
        assert_eq!(PayloadDataType::GraphQL, PayloadDataType::GraphQL);
        assert_eq!(PayloadDataType::Unknown, PayloadDataType::Unknown);
    }
}
