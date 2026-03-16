//! ML-Based Detection Module for Warden v0.8.0 Enterprise Edition
//!
//! This module provides machine learning capabilities for intelligent
//! vulnerability detection using statistical analysis and pattern recognition
//! without external ML dependencies.
//!
//! # Modules
//!
//! - [`detection`]: Core ML-based detection engine
//!
//! # Features
//!
//! - **Pattern Recognition**: Similarity analysis, clustering, zero-day detection
//! - **Adaptive Scoring**: User feedback learning, dynamic severity adjustment
//! - **Anomaly Detection**: Behavioral analysis, response time statistics
//! - **Feature Extraction**: TF-IDF, n-gram analysis, automatic feature extraction
//!
//! # Example
//!
//! ```no_run
//! use warden::ml::detection::MlDetector;
//! use warden::scanners::Vuln;
//!
//! let mut detector = MlDetector::new();
//!
//! // Analyze HTTP response for anomalies
//! let response = HttpResponse { ... };
//! let report = detector.analyze_response(&response);
//!
//! // Cluster similar findings
//! let clusters = detector.cluster_findings(&findings);
//!
//! // Learn from user feedback
//! detector.learn_from_feedback(feedback)?;
//! ```

pub mod detection;

pub use detection::{
    AdaptiveSeverity, Anomaly, AnomalyConfig, AnomalyReport, AnomalySeverity, AnomalyType,
    BehavioralProfile, EndpointStats, FeatureConfig, FeedbackStore, HttpResponse, MlDetector,
    MlUserFeedback, NgramFeature, NgramType, ParameterStats, PatternStore, TfidfFeatures,
    VulnCluster, ZeroDayCandidate,
};
