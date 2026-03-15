//! Language detection

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
    use tempfile::TempDir;

    #[test]
    fn test_language_display() {
        assert_eq!(Language::Rust.to_string(), "Rust");
        assert_eq!(Language::Python.to_string(), "Python");
        assert_eq!(Language::JavaScript.to_string(), "JavaScript");
        assert_eq!(Language::TypeScript.to_string(), "TypeScript");
        assert_eq!(Language::Go.to_string(), "Go");
        assert_eq!(Language::Java.to_string(), "Java");
        assert_eq!(Language::Ruby.to_string(), "Ruby");
        assert_eq!(Language::PHP.to_string(), "PHP");
    }

    #[test]
    fn test_detect_rust_project() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_toml = temp_dir.path().join("Cargo.toml");
        std::fs::write(&cargo_toml, "[package]\nname = \"test\"\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Rust));
    }

    #[test]
    fn test_detect_javascript_project() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(&package_json, "{\"name\": \"test\"}").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::JavaScript));
        assert!(languages.contains(&Language::TypeScript));
    }

    #[test]
    fn test_detect_python_project() {
        let temp_dir = TempDir::new().unwrap();

        // Test with requirements.txt
        let requirements = temp_dir.path().join("requirements.txt");
        std::fs::write(&requirements, "flask==2.0.0\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Python));
    }

    #[test]
    fn test_detect_python_via_pyproject() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject = temp_dir.path().join("pyproject.toml");
        std::fs::write(&pyproject, "[project]\nname = \"test\"\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Python));
    }

    #[test]
    fn test_detect_go_project() {
        let temp_dir = TempDir::new().unwrap();
        let go_mod = temp_dir.path().join("go.mod");
        std::fs::write(&go_mod, "module test\n\ngo 1.21\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Go));
    }

    #[test]
    fn test_detect_java_project() {
        let temp_dir = TempDir::new().unwrap();
        let pom_xml = temp_dir.path().join("pom.xml");
        std::fs::write(&pom_xml, "<project></project>").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Java));
    }

    #[test]
    fn test_detect_java_via_gradle() {
        let temp_dir = TempDir::new().unwrap();
        let build_gradle = temp_dir.path().join("build.gradle");
        std::fs::write(&build_gradle, "plugins {}\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Java));
    }

    #[test]
    fn test_detect_ruby_project() {
        let temp_dir = TempDir::new().unwrap();
        let gemfile = temp_dir.path().join("Gemfile");
        std::fs::write(&gemfile, "source 'https://rubygems.org'\n").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Ruby));
    }

    #[test]
    fn test_detect_php_project() {
        let temp_dir = TempDir::new().unwrap();
        let composer = temp_dir.path().join("composer.json");
        std::fs::write(&composer, "{\"name\": \"test\"}").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::PHP));
    }

    #[test]
    fn test_detect_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.is_empty());
    }

    #[test]
    fn test_detect_by_extension_rust() {
        let temp_dir = TempDir::new().unwrap();
        let src_dir = temp_dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();

        // Create multiple Rust files
        std::fs::write(src_dir.join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(src_dir.join("lib.rs"), "pub fn test() {}").unwrap();

        let languages = detect(temp_dir.path()).unwrap();
        assert!(languages.contains(&Language::Rust));
    }

    #[test]
    fn test_language_serialization() {
        let lang = Language::Rust;
        let serialized = serde_json::to_string(&lang).unwrap();
        let deserialized: Language = serde_json::from_str(&serialized).unwrap();
        assert_eq!(lang, deserialized);
    }

    #[test]
    fn test_all_languages_serializable() {
        let languages = vec![
            Language::Rust,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Go,
            Language::Java,
            Language::Ruby,
            Language::PHP,
        ];

        for lang in languages {
            let serialized = serde_json::to_string(&lang).unwrap();
            let deserialized: Language = serde_json::from_str(&serialized).unwrap();
            assert_eq!(lang, deserialized);
        }
    }
}
