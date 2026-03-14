//! Warden - AI-powered security review CLI tool
//!
//! 100% Rust security scanning for web applications.

mod cli;
mod config;
mod detection;
mod orchestrator;
mod reporters;
mod scanners;
mod utils;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::cli::Commands;
use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = cli::Cli::parse();

    // Setup tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(if cli.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    // Print banner
    print_banner();

    // Load configuration
    let config = Config::load()?;

    // Execute command
    match cli.command {
        Commands::Scan {
            target,
            aggressive,
            include_ddos,
            include_stress,
            format,
            output,
            timeout,
            concurrency,
        } => {
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
            )
            .await?
        }
        Commands::Detect { path } => {
            detection::run_detect(path, config).await?
        }
        Commands::Completions { shell } => {
            cli::print_completions(shell)?;
            Ok(())
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
        "     {}   {}                           {}",
        "║".bold(),
        "Warden".bold().blue(),
        "║".bold()
    );
    println!(
        "     {}   {}                           {}",
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
