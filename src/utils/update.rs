//! Self-update functionality
//!
//! Handles updating Warden to the latest version from crates.io or GitHub.

use anyhow::Result;
use colored::Colorize;
use std::env;
use std::fs::{self, File};
use std::io::Write;
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

    // Windows: Use self-update mechanism to avoid file lock
    if cfg!(windows) {
        return self_update_windows(force, use_git);
    }

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

/// Windows self-update mechanism
///
/// On Windows, the executable is locked while running. This function:
/// 1. Downloads the new version to a temp location
/// 2. Creates a batch script to replace the binary after warden exits
/// 3. Exits cleanly, allowing the batch script to replace the binary
fn self_update_windows(_force: bool, use_git: bool) -> Result<()> {
    let temp_dir = env::temp_dir();
    let temp_binary = temp_dir.join("warden-new.exe");
    let update_script = temp_dir.join("warden-update.bat");

    // Get current executable path
    let current_exe = env::current_exe()?;

    println!("{}", "Windows self-update mode...".dimmed());
    println!("{} {}", "Temp directory:".dimmed(), temp_dir.display());

    // Build cargo install command with --root to install to temp directory
    let temp_root = temp_dir.join("cargo-install");
    fs::create_dir_all(&temp_root)?;

    println!("{}", "Downloading new version...".dimmed());

    // Store path as owned String to avoid temporary value issues
    let temp_root_str = temp_root.to_string_lossy().to_string();

    let cargo_args = if use_git {
        vec![
            "install", "warden-sec",
            "--git", "https://github.com/Pamacea/warden",
            "--root", &temp_root_str,
        ]
    } else {
        vec![
            "install", "warden-sec",
            "--force",
            "--root", &temp_root_str,
        ]
    };

    let status = Command::new("cargo")
        .args(&cargo_args)
        .status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("Cargo install failed with exit code: {:?}", status.code()));
    }

    // Find the installed binary
    let installed_binary = temp_root.join("bin").join("warden.exe");

    if !installed_binary.exists() {
        return Err(anyhow::anyhow!("Installed binary not found at {:?}", installed_binary));
    }

    // Copy to temp location
    fs::copy(&installed_binary, &temp_binary)?;

    // Create the update batch script
    let script_content = format!(
        r#"
@echo off
set "BINARY={}"
set "CURRENT={}"
set "TEMP_DIR={}"
set "SCRIPT=%~nx0"

echo Waiting for Warden to close...
REM Wait longer to ensure warden.exe has fully terminated
timeout /t 3 /nobreak > nul

REM Check if warden is still running
tasklist /FI "IMAGENAME eq warden.exe" 2>nul | find /I "warden.exe" >nul
if %ERRORLEVEL% EQU 0 (
    echo Warden is still running, waiting 5 more seconds...
    timeout /t 5 /nobreak > nul
)

echo Updating Warden binary...
move /Y "%BINARY%" "%CURRENT%" > nul 2>&1
if errorlevel 1 (
    echo Update failed - Access denied.
    echo.
    echo Possible reasons:
    echo   - Warden is still running
    echo   - Insufficient permissions
    echo   - Antivirus is blocking the operation
    echo.
    echo Try:
    echo   1. Close all terminal windows and VS Code instances
    echo   2. Run warden update --force again
    echo   3. Or run as Administrator
    pause
    exit /b 1
)

REM Cleanup
rmdir /S /Q "%TEMP_DIR%" > nul 2>&1
del "%SCRIPT%" > nul 2>&1

echo.
echo ==================================================
echo   Warden v{} updated successfully!
echo ==================================================
echo.
echo Run 'warden --version' to verify
echo.
timeout /t 3 /nobreak
"#,
        temp_binary.display(),
        current_exe.display(),
        temp_root.display(),
        env!("CARGO_PKG_VERSION")
    );

    let mut script_file = File::create(&update_script)?;
    script_file.write_all(script_content.as_bytes())?;

    println!();
    println!("{}", "✓ Download complete!".green());
    println!();
    println!("{}", "Warden will now close to complete the update.".yellow());
    println!("{}", "A batch script will automatically replace the binary.".dimmed());
    println!();

    // Launch the update script detached using START to ensure it runs independently
    // This is critical on Windows to avoid the parent process blocking the replacement
    let script_path = update_script.to_string_lossy().to_string();
    let script_arg = format!("start /B /MIN \"\" \"{}\"", script_path);
    Command::new("cmd")
        .arg("/C")
        .arg(&script_arg)
        .spawn()?;

    // Exit immediately - the batch script will wait and do the replacement
    std::process::exit(0);
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
