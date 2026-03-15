//! Network utilities

#![allow(dead_code)] // Reserved for v0.6.0 features

use anyhow::{Context, Result};
use std::time::Duration;

/// Validate a URL
pub fn validate_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url).context("Invalid URL")?;

    match parsed.scheme() {
        "http" | "https" => Ok(parsed.to_string()),
        _ => anyhow::bail!("URL must use http or https scheme"),
    }
}

/// Check if a URL is accessible
pub async fn check_url(url: &str, timeout: Duration) -> Result<bool> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()?;

    let response = client
        .head(url)
        .send()
        .await
        .context("Failed to connect to URL")?;

    Ok(response.status().is_success() || response.status().is_redirection())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(validate_url("not-a-url").is_err());
        assert!(validate_url("").is_err());
    }

    #[test]
    fn test_validate_url_wrong_scheme() {
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("file:///path/to/file").is_err());
    }

    #[test]
    fn test_validate_url_with_path() {
        assert!(validate_url("https://example.com/path/to/resource").is_ok());
    }

    #[test]
    fn test_validate_url_with_query() {
        assert!(validate_url("https://example.com?query=test").is_ok());
    }

    #[test]
    fn test_validate_url_with_port() {
        assert!(validate_url("https://example.com:8443").is_ok());
    }

    #[test]
    fn test_validate_url_normalizes() {
        let result = validate_url("http://EXAMPLE.COM").unwrap();
        assert!(result.contains("example.com"));
    }

    #[tokio::test]
    async fn test_check_url_unreachable() {
        // Use a non-routable IP address
        let result = check_url("http://192.0.2.1:12345", Duration::from_millis(100)).await;
        // Should fail or timeout, not crash
        assert!(result.is_err() || result.unwrap() == false);
    }

    #[tokio::test]
    async fn test_check_url_invalid_url() {
        let result = check_url("not-a-url", Duration::from_secs(1)).await;
        assert!(result.is_err());
    }
}
