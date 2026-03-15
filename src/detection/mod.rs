//! Framework and language detection

pub mod framework;
pub mod language;
pub mod platform;

use anyhow::Result;
use colored::Colorize;
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

    /// Format detection info for display
    pub fn display(&self) -> String {
        let mut output = vec![];

        output.push(format!("{} {}", "Path:".cyan(), self.path));

        if !self.languages.is_empty() {
            output.push(format!("{} {}", "Languages:".green(),
                self.languages.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")));
        }

        if !self.frameworks.is_empty() {
            output.push(format!("{} {}", "Frameworks:".blue(),
                self.frameworks.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ")));
        }

        if let Some(ref pm) = self.package_manager {
            output.push(format!("{} {}", "Package Manager:".yellow(), pm));
        }

        output.join("\n")
    }
}

/// Run detection on a path
pub async fn run_detect(path: Option<String>, json: bool, _config: crate::config::Config) -> Result<()> {
    let target_path = path.unwrap_or_else(|| ".".to_string());
    let path = Path::new(&target_path).canonicalize()?;

    // Detect language
    let languages = language::detect(&path)?;

    // Detect framework
    let frameworks = framework::detect(&path, &languages)?;

    // Create detection info
    let info = DetectInfo {
        path: path.display().to_string(),
        languages,
        frameworks,
        package_manager: None,
        version: None,
    };

    if json {
        // Output as JSON
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        // Output as human-readable text
        println!();
        println!("{}", "┌─ Detection Results ──────────────────────────────".cyan().bold());
        println!("│");

        if info.languages.is_empty() {
            println!("│  {}", "No language detected".dimmed());
        } else {
            println!("│  {}", "Languages:".green().bold());
            for lang in &info.languages {
                println!("│    • {}", lang);
            }
        }

        println!("│");

        if info.frameworks.is_empty() {
            println!("│  {}", "No framework detected".dimmed());
        } else {
            println!("│  {}", "Frameworks:".blue().bold());
            for framework in &info.frameworks {
                println!("│    • {}", framework);
            }
        }

        println!("│");
        println!("│  {}", format!("Path: {}", info.path).dimmed());
        println!("{}", "└──────────────────────────────────────────────────".cyan().bold());
        println!();
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

    #[test]
    fn test_detect_info_serialization() {
        let info = DetectInfo {
            languages: vec![Language::Rust, Language::JavaScript],
            frameworks: vec![Framework::Axum],
            path: "/test".to_string(),
            package_manager: Some("cargo".to_string()),
            version: Some("1.0.0".to_string()),
        };

        let serialized = serde_json::to_string(&info).unwrap();
        let deserialized: DetectInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(info.path, deserialized.path);
        assert_eq!(info.languages.len(), deserialized.languages.len());
    }
}
