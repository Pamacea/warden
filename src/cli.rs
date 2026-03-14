//! Command-line interface definitions

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "warden")]
#[command(about = "AI-powered security review CLI tool", long_about = None)]
#[command(version = "0.2.0")]
#[command(author = "Yanis")]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a target for vulnerabilities
    Scan {
        /// Target URL or directory (default: current directory)
        #[arg(global = true)]
        target: Option<String>,

        /// Enable aggressive scanning mode
        #[arg(long)]
        aggressive: bool,

        /// Include DDoS resistance testing
        #[arg(long)]
        include_ddos: bool,

        /// Include stress testing
        #[arg(long)]
        include_stress: bool,

        /// Output format
        #[arg(long, default_value = "console")]
        format: String,

        /// Save report to file
        #[arg(short, long)]
        output: Option<String>,

        /// Request timeout in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,

        /// Concurrent requests
        #[arg(short, long, default_value = "50")]
        concurrency: usize,
    },

    /// Detect framework and language
    Detect {
        /// Project directory (default: current directory)
        #[arg(short, long)]
        path: Option<String>,
    },

    /// Generate shell completions
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
}

pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    use std::io;

    match shell {
        Shell::Bash => {
            clap_complete::generate(
                clap_complete::shells::Bash,
                &mut Cli::command(),
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Elvish => {
            clap_complete::generate(
                clap_complete::shells::Elvish,
                &mut Cli::command(),
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Fish => {
            clap_complete::generate(
                clap_complete::shells::Fish,
                &mut Cli::command(),
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::PowerShell => {
            clap_complete::generate(
                clap_complete::shells::PowerShell,
                &mut Cli::command(),
                "warden",
                &mut io::stdout(),
            );
        }
        Shell::Zsh => {
            clap_complete::generate(
                clap_complete::shells::Zsh,
                &mut Cli::command(),
                "warden",
                &mut io::stdout(),
            );
        }
    }

    Ok(())
}
