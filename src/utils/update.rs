//! Self-update functionality
//!
//! Handles updating Warden to the latest version from crates.io or GitHub.

use anyhow::Result;
use colored::Colorize;
use std::process::Command;
use std::time::Duration;

/// Check if a newer version is available on crates.io (blocking)
pub fn check_latest_version_blocking() -> Result<Option<String>> {
    let current_version = env!("CARGO_PKG_VERSION");

    // Fetch latest version from crates.io API (blocking)
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .get("https://crates.io/api/v1/crates/warden-sec")
        .send()?;

    if !response.status().is_success() {
        return Ok(None);
    }

    let json: serde_json::Value = response.json()?;

    if let Some(crate_data) = json.get("crate") {
        if let Some(latest) = crate_data.get("max_stable_version") {
            if let Some(latest_str) = latest.as_str() {
                if latest_str != current_version {
                    return Ok(Some(latest_str.to_string()));
                }
            }
        }
    }

    Ok(None)
}

/// Update Warden to the latest version (blocking)
pub fn update_warden(force: bool, use_git: bool) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");

    println!("{}", "🔄 Checking for updates...".bold());

    // Check if newer version exists (unless forced)
    if !force {
        if let Some(latest) = check_latest_version_blocking()? {
            println!(
                "{} {} → {}",
                "Update available:".yellow().bold(),
                current_version.dimmed(),
                latest.green().bold()
            );
        } else {
            println!(
                "{} {}",
                "✓".green(),
                format!("Already up to date (v{})", current_version).dimmed()
            );
            if !force {
                println!("\n{}", "Use --force to reinstall anyway".dimmed());
                return Ok(());
            }
        }
    }

    println!();
    println!("{}", "Installing latest version...".bold());

    let status = if use_git {
        println!("{}", "Installing from GitHub...".dimmed());
        Command::new("cargo")
            .args(["install", "warden-sec", "--git", "https://github.com/Pamacea/warden"])
            .status()?
    } else {
        println!("{}", "Installing from crates.io...".dimmed());
        Command::new("cargo")
            .args(["install", "warden-sec", "--force"])
            .status()?
    };

    if status.success() {
        println!();
        println!(
            "{} {}",
            "✓".green().bold(),
            "Warden updated successfully!".green()
        );
        println!();
        println!("{}", "Run 'warden --version' to verify".dimmed());
        Ok(())
    } else {
        Err(anyhow::anyhow!("Update failed with exit code: {:?}", status.code()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_format() {
        let version = env!("CARGO_PKG_VERSION");
        // Version should be in format X.Y.Z
        assert!(version.split('.').count() == 3);
    }
}
