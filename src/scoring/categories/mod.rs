//! Scoring categories
//!
//! Each category analyzes a specific security domain and assigns points based on
//! findings and best practices.

#![allow(unused_imports)]

pub mod access_control;
pub mod auth;
pub mod code_quality;
pub mod communications;
pub mod crypto;
pub mod data_protection;
pub mod error_handling;
pub mod headers;
pub mod input_validation;
pub mod session;

// Re-export category functions
pub use access_control::calculate as calculate_access_control;
pub use auth::calculate as calculate_auth;
pub use code_quality::calculate as calculate_code_quality;
pub use communications::calculate as calculate_communications;
pub use crypto::calculate as calculate_crypto;
pub use data_protection::calculate as calculate_data_protection;
pub use error_handling::calculate as calculate_error_handling;
pub use headers::calculate as calculate_headers;
pub use input_validation::calculate as calculate_input_validation;
pub use session::calculate as calculate_session;
