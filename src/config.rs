//! Configuration management

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default timeout for requests (seconds)
    pub timeout: u64,

    /// Default concurrency level
    pub concurrency: usize,

    /// User agent for HTTP requests
    pub user_agent: String,

    /// Maximum file size for static analysis (bytes)
    pub max_file_size: u64,

    /// Directories to exclude from scanning
    pub exclude_dirs: Vec<String>,

    /// Files to exclude from scanning
    pub exclude_files: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout: 5,
            concurrency: 50,
            user_agent: format!("Warden/{}", env!("CARGO_PKG_VERSION")),
            max_file_size: 10 * 1024 * 1024, // 10 MB
            exclude_dirs: vec![
                "node_modules".to_string(),
                "target".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".git".to_string(),
                "vendor".to_string(),
                "__pycache__".to_string(),
            ],
            exclude_files: vec![
                "*.min.js".to_string(),
                "*.min.css".to_string(),
                "*.map".to_string(),
            ],
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try to load from ~/.warden/config.toml
        let config_path = dirs::home_dir()
            .map(|p| p.join(".warden").join("config.toml"));

        if let Some(path) = config_path {
            if path.exists() {
                let content = std::fs::read_to_string(path)?;
                let config: Config = toml::from_str(&content)?;
                return Ok(config);
            }
        }

        Ok(Config::default())
    }

    pub fn save(&self) -> Result<()> {
        let config_dir = dirs::home_dir()
            .map(|p| p.join(".warden"))
            .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;

        std::fs::create_dir_all(&config_dir)?;

        let config_path = config_dir.join("config.toml");
        let content = toml::to_string_pretty(self)?;

        std::fs::write(config_path, content)?;

        Ok(())
    }
}
