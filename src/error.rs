//! Centralized error types for Oalacea Warden
//!
//! This module provides structured error types using `thiserror` for better
//! error handling and debugging throughout the application.
//!
//! # Example
//!
//! ```rust
//! use oalacea_warden::error::{ScannerError, Result};
//!
//! fn scan_file(path: &Path) -> Result<ScanReport> {
//!     let content = std::fs::read_to_string(path)
//!         .map_err(|e| ScannerError::FileNotFound(path.to_path_buf()))?;
//!     // ...
//!     Ok(report)
//! }
//! ```

use std::path::PathBuf;

/// Common result type for scanner operations
pub type Result<T> = std::result::Result<T, ScannerError>;

/// Main error type for scanner operations
///
/// This error type provides specific variants for different failure scenarios
/// that can occur during security scanning operations.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// File not found or inaccessible
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    /// I/O error during file operations
    #[error("I/O error: {path} - {error}")]
    IoError {
        path: PathBuf,
        error: String,
    },

    /// Parse error when analyzing file content
    #[error("Parse error in {file}: {message}")]
    ParseError {
        file: String,
        message: String,
    },

    /// Network error during HTTP scanning
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Timeout during scanning operation
    #[error("Scan timeout after {seconds}s: {target}")]
    Timeout {
        target: String,
        seconds: u64,
    },

    /// Invalid configuration provided
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Authentication failure
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization failure
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Invalid target provided
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    /// Unsupported operation for this target type
    #[error("Unsupported operation '{op}' for target '{target}'")]
    UnsupportedOperation {
        op: String,
        target: String,
    },

    /// Detection error (framework/language detection failed)
    #[error("Detection failed: {0}")]
    DetectionError(String),

    /// Analysis error (static analysis failed)
    #[error("Analysis failed for {path}: {reason}")]
    AnalysisError {
        path: PathBuf,
        reason: String,
    },

    /// Report generation error
    #[error("Report generation failed: {0}")]
    ReportError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Regex compilation error
    #[error("Regex compilation error: {0}")]
    RegexError(String),

    /// Tree-sitter parsing error
    #[error("AST parsing error in {file}: {message}")]
    AstError {
        file: String,
        message: String,
    },

    /// Scan cancelled by user
    #[error("Scan cancelled")]
    Cancelled,

    /// Scan already in progress
    #[error("Scan already in progress")]
    AlreadyInProgress,

    /// Internal error (bugs, unexpected conditions)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Feature not yet implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl ScannerError {
    /// Create a file not found error
    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound(path.into())
    }

    /// Create an I/O error with context
    pub fn io_error(path: impl Into<PathBuf>, error: impl std::fmt::Display) -> Self {
        Self::IoError {
            path: path.into(),
            error: error.to_string(),
        }
    }

    /// Create a parse error
    pub fn parse_error(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ParseError {
            file: file.into(),
            message: message.into(),
        }
    }

    /// Create a network error
    pub fn network_error(msg: impl Into<String>) -> Self {
        Self::NetworkError(msg.into())
    }

    /// Create a timeout error
    pub fn timeout(target: impl Into<String>, seconds: u64) -> Self {
        Self::Timeout {
            target: target.into(),
            seconds,
        }
    }

    /// Create an invalid config error
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Create an analysis error
    pub fn analysis_error(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::AnalysisError {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create an unsupported operation error
    pub fn unsupported(op: impl Into<String>, target: impl Into<String>) -> Self {
        Self::UnsupportedOperation {
            op: op.into(),
            target: target.into(),
        }
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NetworkError(_)
                | Self::Timeout { .. }
                | Self::RateLimitExceeded(_)
                | Self::IoError { .. }
        )
    }

    /// Check if this error should be shown to end users
    pub fn is_user_facing(&self) -> bool {
        !matches!(self, Self::Internal(_) | Self::NotImplemented(_))
    }
}

// Implement From traits for common error types

impl From<std::io::Error> for ScannerError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::FileNotFound(PathBuf::from("<unknown>")),
            std::io::ErrorKind::PermissionDenied => {
                Self::AuthorizationDenied(err.to_string())
            }
            std::io::ErrorKind::TimedOut => Self::Timeout {
                target: "<unknown>".to_string(),
                seconds: 0,
            },
            _ => Self::IoError {
                path: PathBuf::from("<unknown>"),
                error: err.to_string(),
            },
        }
    }
}

impl From<regex::Error> for ScannerError {
    fn from(err: regex::Error) -> Self {
        Self::RegexError(err.to_string())
    }
}

impl From<serde_json::Error> for ScannerError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<toml::de::Error> for ScannerError {
    fn from(err: toml::de::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<reqwest::Error> for ScannerError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Self::Timeout {
                target: "<unknown>".to_string(),
                seconds: 0,
            }
        } else if err.is_connect() {
            Self::NetworkError(err.to_string())
        } else {
            Self::NetworkError(err.to_string())
        }
    }
}

/// HTTP scanning specific errors
#[derive(Debug, thiserror::Error)]
pub enum HttpScanError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("HTTP request failed: {status} for {url}")]
    RequestFailed {
        url: String,
        status: u16,
    },

    #[error("Redirect limit exceeded for {0}")]
    RedirectLimitExceeded(String),

    #[error("SSL/TLS error: {0}")]
    TlsError(String),

    #[error("DNS resolution failed: {0}")]
    DnsError(String),
}

/// Port scanning specific errors
#[derive(Debug, thiserror::Error)]
pub enum PortScanError {
    #[error("Invalid port: {0}")]
    InvalidPort(u16),

    #[error("Port scan timeout: {0}")]
    Timeout(String),

    #[error("Permission denied for raw socket access")]
    PermissionDenied,

    #[error("Host unreachable: {0}")]
    HostUnreachable(String),
}

/// Static analysis specific errors
#[derive(Debug, thiserror::Error)]
pub enum StaticAnalysisError {
    #[error("Unsupported file type: {extension}")]
    UnsupportedFileType {
        extension: String,
    },

    #[error("File too large to analyze: {size} bytes (max: {max} bytes)")]
    FileTooLarge {
        size: usize,
        max: usize,
    },

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Syntax error: {0}")]
    SyntaxError(String),
}

/// Severity level for errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Info level (e.g., deprecation warnings)
    Info,
    /// Warning level (e.g., deprecated features)
    Warning,
    /// Error level (operation failed but can be retried)
    Error,
    /// Fatal error (operation cannot proceed)
    Fatal,
}

impl ScannerError {
    /// Get the severity level of this error
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            Self::FileNotFound(_) => ErrorSeverity::Error,
            Self::IoError { .. } => ErrorSeverity::Error,
            Self::ParseError { .. } => ErrorSeverity::Warning,
            Self::NetworkError(_) => ErrorSeverity::Error,
            Self::Timeout { .. } => ErrorSeverity::Warning,
            Self::InvalidConfig(_) => ErrorSeverity::Fatal,
            Self::AuthenticationFailed(_) => ErrorSeverity::Error,
            Self::AuthorizationDenied(_) => ErrorSeverity::Fatal,
            Self::RateLimitExceeded(_) => ErrorSeverity::Warning,
            Self::InvalidTarget(_) => ErrorSeverity::Error,
            Self::UnsupportedOperation { .. } => ErrorSeverity::Error,
            Self::DetectionError(_) => ErrorSeverity::Warning,
            Self::AnalysisError { .. } => ErrorSeverity::Warning,
            Self::ReportError(_) => ErrorSeverity::Error,
            Self::SerializationError(_) => ErrorSeverity::Error,
            Self::RegexError(_) => ErrorSeverity::Fatal,
            Self::AstError { .. } => ErrorSeverity::Warning,
            Self::Cancelled => ErrorSeverity::Info,
            Self::AlreadyInProgress => ErrorSeverity::Error,
            Self::Internal(_) => ErrorSeverity::Fatal,
            Self::NotImplemented(_) => ErrorSeverity::Fatal,
        }
    }
}

/// Helper trait for converting errors with context
pub trait ErrorContext<T> {
    /// Add context to an error
    fn with_context(self, context: impl Into<String>) -> Result<T>;

    /// Add a file path context to an error
    fn with_file(self, file: impl Into<PathBuf>) -> Result<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| ScannerError::Internal(format!("{}: {}", context.into(), e)))
    }

    fn with_file(self, file: impl Into<PathBuf>) -> Result<T> {
        self.map_err(|e| {
            ScannerError::IoError {
                path: file.into(),
                error: e.to_string(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_error_display() {
        let err = ScannerError::file_not_found("/test/file.rs");
        assert!(err.to_string().contains("File not found"));
    }

    #[test]
    fn test_scanner_error_retryable() {
        assert!(ScannerError::network_error("connection refused").is_retryable());
        assert!(ScannerError::timeout("example.com", 30).is_retryable());
        assert!(!ScannerError::invalid_config("bad value").is_retryable());
        assert!(!ScannerError::file_not_found("/test").is_retryable());
    }

    #[test]
    fn test_scanner_error_severity() {
        assert_eq!(
            ScannerError::timeout("example.com", 30).severity(),
            ErrorSeverity::Warning
        );
        assert_eq!(
            ScannerError::invalid_config("bad").severity(),
            ErrorSeverity::Fatal
        );
        assert_eq!(
            ScannerError::Cancelled.severity(),
            ErrorSeverity::Info
        );
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let scanner_err: ScannerError = io_err.into();
        assert!(matches!(scanner_err, ScannerError::FileNotFound(_)));
    }

    #[test]
    fn test_from_regex_error() {
        let regex_err = regex::Error::Syntax("invalid regex".to_string());
        let scanner_err: ScannerError = regex_err.into();
        assert!(matches!(scanner_err, ScannerError::RegexError(_)));
    }

    #[test]
    fn test_error_helpers() {
        let err = ScannerError::analysis_error("/test/file.rs", "invalid syntax");
        assert!(matches!(err, ScannerError::AnalysisError { .. }));

        let err = ScannerError::unsupported("scan", "http://example.com");
        assert!(matches!(err, ScannerError::UnsupportedOperation { .. }));
    }
}
