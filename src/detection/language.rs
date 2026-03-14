//! Language detection

use crate::detection::Language;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Detect the programming language(s) of a project
pub fn detect(path: &Path) -> Result<Vec<Language>> {
    let mut languages = Vec::new();

    // Check for language markers
    if path.join("Cargo.toml").exists() {
        languages.push(Language::Rust);
    }

    if path.join("package.json").exists() {
        languages.push(Language::JavaScript);
        languages.push(Language::TypeScript);
    }

    if path.join("requirements.txt").exists()
        || path.join("pyproject.toml").exists()
        || path.join("Pipfile").exists()
        || path.join("setup.py").exists()
    {
        languages.push(Language::Python);
    }

    if path.join("go.mod").exists() {
        languages.push(Language::Go);
    }

    if path.join("pom.xml").exists() || path.join("build.gradle").exists() {
        languages.push(Language::Java);
    }

    if path.join("Gemfile").exists() {
        languages.push(Language::Ruby);
    }

    if path.join("composer.json").exists() {
        languages.push(Language::PHP);
    }

    // Fallback: scan directory for source files
    if languages.is_empty() {
        languages = detect_by_extension(path)?;
    }

    Ok(languages)
}

/// Detect language by file extensions
fn detect_by_extension(path: &Path) -> Result<Vec<Language>> {
    let mut lang_counts: std::collections::HashMap<Language, usize> =
        std::collections::HashMap::new();

    let entries = fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .take(10); // Limit scan depth

    for entry in entries {
        let entry_path = entry.path();
        if let Ok(files) = fs::read_dir(&entry_path) {
            for file in files.filter_map(|f| f.ok()).take(100) {
                if let Some(ext) = file.path().extension() {
                    let lang = match ext.to_str() {
                        Some("rs") => Some(Language::Rust),
                        Some("js") | Some("mjs") => Some(Language::JavaScript),
                        Some("ts") | Some("tsx") => Some(Language::TypeScript),
                        Some("py") => Some(Language::Python),
                        Some("go") => Some(Language::Go),
                        Some("java") => Some(Language::Java),
                        Some("rb") => Some(Language::Ruby),
                        Some("php") => Some(Language::PHP),
                        _ => None,
                    };

                    if let Some(lang) = lang {
                        *lang_counts.entry(lang).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    let mut languages: Vec<_> = lang_counts.into_iter().collect();
    languages.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending

    Ok(languages.into_iter().map(|(lang, _)| lang).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Ruby,
    PHP,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Rust => write!(f, "Rust"),
            Language::JavaScript => write!(f, "JavaScript"),
            Language::TypeScript => write!(f, "TypeScript"),
            Language::Python => write!(f, "Python"),
            Language::Go => write!(f, "Go"),
            Language::Java => write!(f, "Java"),
            Language::Ruby => write!(f, "Ruby"),
            Language::PHP => write!(f, "PHP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_display() {
        assert_eq!(Language::Rust.to_string(), "Rust");
        assert_eq!(Language::Python.to_string(), "Python");
    }
}
