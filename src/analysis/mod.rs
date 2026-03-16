//! Analysis Module
//!
//! Advanced analysis capabilities for Warden Enterprise Edition.
//! Includes false positive reduction, similarity analysis, and noise reduction.

pub mod false_positives;

pub use false_positives::{
    FalsePositiveAnalyzer, FalsePositiveFilter, FindingCluster,
    ProbabilisticScore, SimilarityConfig, UserFeedback,
};
