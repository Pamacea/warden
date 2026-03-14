//! Network utilities

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
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(validate_url("not-a-url").is_err());
    }

    #[test]
    fn test_validate_url_wrong_scheme() {
        assert!(validate_url("ftp://example.com").is_err());
    }
}
