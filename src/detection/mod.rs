//! Framework and language detection

pub mod framework;
pub mod language;
pub mod platform;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub use framework::Framework;
pub use language::Language;

/// Information about a detected project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectInfo {
    /// Detected language(s)
    pub languages: Vec<Language>,

    /// Detected framework(s)
    pub frameworks: Vec<Framework>,

    /// Project root path
    pub path: String,

    /// Package manager detected
    pub package_manager: Option<String>,

    /// Version information
    pub version: Option<String>,
}

impl DetectInfo {
    pub fn new(path: String) -> Self {
        Self {
            languages: Vec::new(),
            frameworks: Vec::new(),
            path,
            package_manager: None,
            version: None,
        }
    }

    pub fn has_framework(&self, framework: Framework) -> bool {
        self.frameworks.contains(&framework)
    }

    pub fn has_language(&self, language: Language) -> bool {
        self.languages.contains(&language)
    }
}

/// Run detection on a path
pub async fn run_detect(path: Option<String>, _config: crate::config::Config) -> Result<()> {
    let target_path = path.unwrap_or_else(|| ".".to_string());
    let path = Path::new(&target_path).canonicalize()?;

    println!("{} Scanning: {}", "→".cyan(), path.display());

    // Detect language
    let languages = language::detect(&path)?;
    if languages.is_empty() {
        println!("  {}", "No language detected".yellow());
    } else {
        println!("  {}: {}", "Languages".green(), languages.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", "));
    }

    // Detect framework
    let frameworks = framework::detect(&path, &languages)?;
    if frameworks.is_empty() {
        println!("  {}", "No framework detected".yellow());
    } else {
        println!("  {}: {}", "Frameworks".green(), frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", "));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_info_new() {
        let info = DetectInfo::new("/test".to_string());
        assert_eq!(info.path, "/test");
        assert!(info.languages.is_empty());
        assert!(info.frameworks.is_empty());
    }

    #[test]
    fn test_has_framework() {
        let mut info = DetectInfo::new("/test".to_string());
        info.frameworks.push(Framework::NestJS);
        assert!(info.has_framework(Framework::NestJS));
        assert!(!info.has_framework(Framework::Axum));
    }
}
