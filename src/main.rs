//! Warden - AI-powered security review CLI tool
//!
//! 100% Rust security scanning for web applications.

mod cli;
mod config;
mod detection;
mod orchestrator;
mod progress;
mod reporters;
mod scanners;
mod utils;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use crate::cli::{Cli, Commands};
use crate::config::{Config, ConfigError};
use crate::progress::{ErrorReporter, Prompt};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            err.print().ok();
            std::process::exit(1);
        }
    };

    // Setup tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(if cli.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .with_target(false)
        .with_level(!cli.verbose)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    // Print banner
    print_banner();

    // Load configuration
    let config = match load_config(&cli) {
        Ok(config) => config,
        Err(e) => {
            if let Some(ConfigError::ProfileNotFound(name)) = e.downcast_ref::<ConfigError>() {
                eprintln!("{} Profile '{}' not found", "✗".red().bold(), name);
                eprintln!("  {}", "Available profiles: Run 'warden config show' to see profiles".dimmed());
                eprintln!("  {}", "Create new profiles in ~/.warden/config.toml".dimmed());
                eprintln!();
            } else {
                ErrorReporter::print_error(&e);
            }
            std::process::exit(1);
        }
    };

    // Validate configuration
    if let Err(errors) = config.validate() {
        config::print_config_errors(&errors);
        std::process::exit(1);
    }

    // Execute command
    let result = match cli.command {
        Commands::Scan {
            target,
            aggressive,
            quick: _,
            include_ddos,
            include_stress,
            format,
            output,
            auto_save,
            generate_fixes,
            no_auto_save: _,
            timeout,
            concurrency,
            max_file_size: _,
            score,
        } => {
            // Prompt for dangerous operations
            if include_ddos || include_stress {
                let target_str = target.as_ref().map(|t| t.as_str()).unwrap_or(".");
                if !Prompt::confirm_dangerous("Aggressive scanning with DDoS/Stress tests", target_str)? {
                    return Ok(());
                }
            }

            orchestrator::run_scan(
                target,
                aggressive,
                include_ddos,
                include_stress,
                format,
                output,
                timeout,
                concurrency,
                config,
                cli.verbose,
                auto_save,
                generate_fixes,
                score,
            )
            .await
        }
        Commands::Detect { path, json } => {
            detection::run_detect(path, json, config).await
        }
        Commands::Config { action } => {
            handle_config_command(action, config)?;
            Ok(())
        }
        Commands::Completions { shell } => {
            cli::print_completions(shell)?;
            Ok(())
        }
        Commands::Update { force, git } => {
            utils::update_warden(force, git)?;
            Ok(())
        }
    };

    // Handle errors
    if let Err(e) = result {
        ErrorReporter::print_error(&e);
        std::process::exit(1);
    }

    Ok(())
}

/// Load configuration from file or use defaults
fn load_config(cli: &Cli) -> Result<Config> {
    if let Some(config_path) = &cli.config {
        // Load from specified file
        Config::load_from_file(config_path)
    } else {
        // Load with profile if specified
        Config::load_with_profile(cli.profile.clone())
    }
}

/// Handle configuration subcommands
fn handle_config_command(action: cli::ConfigAction, mut config: Config) -> Result<()> {
    use crate::progress::StatusPrinter;

    let printer = StatusPrinter::new(false);

    match action {
        cli::ConfigAction::Show => {
            printer.print_header("Current Configuration");
            config.display();
        }
        cli::ConfigAction::Init => {
            printer.print("Initializing default configuration...");

            // Create default config with some example profiles
            config.profiles.insert(
                "quick".to_string(),
                config::ProfileConfig {
                    timeout: 2,
                    concurrency: 25,
                    aggressive: false,
                    max_file_size: 5 * 1024 * 1024,
                }
            );

            config.profiles.insert(
                "deep".to_string(),
                config::ProfileConfig {
                    timeout: 15,
                    concurrency: 100,
                    aggressive: true,
                    max_file_size: 50 * 1024 * 1024,
                }
            );

            config.save()?;
            ErrorReporter::print_success("Configuration initialized at ~/.warden/config.toml");
            println!("\n{}", "Created profiles:".dimmed());
            println!("  {} - Quick scans (2s timeout, 25 concurrent)", "quick".cyan());
            println!("  {} - Deep scans (15s timeout, 100 concurrent, aggressive)", "deep".cyan());
            println!("\n{}", "Usage:".dimmed());
            println!("  {} --profile quick", "warden scan".green());
            println!("  {} --profile deep", "warden scan".green());
        }
        cli::ConfigAction::Validate => {
            printer.print("Validating configuration...");
            match config.validate() {
                Ok(_) => ErrorReporter::print_success("Configuration is valid"),
                Err(errors) => {
                    config::print_config_errors(&errors);
                    return Err(anyhow::anyhow!("Configuration validation failed"));
                }
            }
        }
        cli::ConfigAction::Edit => {
            let config_path = Config::user_config_path()
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

            // Create if doesn't exist
            if !config_path.exists() {
                config.save()?;
            }

            // Open in default editor
            edit::edit_file(&config_path)?;
            ErrorReporter::print_success(&format!("Configuration file opened: {}", config_path.display()));
        }
    }

    Ok(())
}

fn print_banner() {
    println!();
    println!(
        "     {}{}{}",
        "╔═══════════════════════════════════════╗".bold(),
        "".white(),
        ""
    );
    println!(
        "     {}   {}                         {}",
        "║".bold(),
        "Warden".bold().blue(),
        "║".bold()
    );
    println!(
        "     {}   {}                         {}",
        "║".bold(),
        format!("v{}", env!("CARGO_PKG_VERSION")).dimmed(),
        "║".bold()
    );
    println!(
        "     {}   {}                         {}",
        "║".bold(),
        "Security Review".white(),
        "║".bold()
    );
    println!(
        "     {}{}{}",
        "╚═══════════════════════════════════════╝".bold(),
        "".white(),
        ""
    );
    println!();
}
