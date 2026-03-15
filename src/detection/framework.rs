//! Framework detection

use super::Language;
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Detect the framework(s) of a project
pub fn detect(path: &Path, languages: &[Language]) -> Result<Vec<Framework>> {
    let mut frameworks = Vec::new();

    // Check for package.json and dependencies
    if path.join("package.json").exists() {
        let pkg_content = fs::read_to_string(path.join("package.json"))?;
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&pkg_content) {
            frameworks.extend(detect_node_framework(&pkg));
        }
    }

    // Check for Rust frameworks
    if languages.contains(&Language::Rust) {
        frameworks.extend(detect_rust_framework(path)?);
    }

    // Check for Python frameworks
    if languages.contains(&Language::Python) {
        frameworks.extend(detect_python_framework(path)?);
    }

    // Check for Go frameworks
    if languages.contains(&Language::Go) {
        frameworks.extend(detect_go_framework(path)?);
    }

    // Check for Java frameworks
    if languages.contains(&Language::Java) {
        frameworks.push(Framework::SpringBoot);
    }

    Ok(frameworks)
}

fn detect_node_framework(pkg: &serde_json::Value) -> Vec<Framework> {
    let mut frameworks = Vec::new();

    if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
        if deps.contains_key("@nestjs/core") || deps.contains_key("@nestjs/common") {
            frameworks.push(Framework::NestJS);
        }
        if deps.contains_key("express") {
            frameworks.push(Framework::Express);
        }
        if deps.contains_key("fastify") {
            frameworks.push(Framework::Fastify);
        }
        if deps.contains_key("hono") {
            frameworks.push(Framework::Hono);
        }
        if deps.contains_key("koa") {
            frameworks.push(Framework::Koa);
        }
        if deps.contains_key("next") {
            frameworks.push(Framework::NextJS);
        }
        if deps.contains_key("nuxt") {
            frameworks.push(Framework::Nuxt);
        }
        if deps.contains_key("@sveltejs/kit") {
            frameworks.push(Framework::SvelteKit);
        }
        if deps.contains_key("@remix-run/react") {
            frameworks.push(Framework::Remix);
        }
        if deps.contains_key("vite") {
            frameworks.push(Framework::Vite);
        }
    }

    if let Some(dev_deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
        if dev_deps.contains_key("vite") && !frameworks.contains(&Framework::Vite) {
            frameworks.push(Framework::Vite);
        }
    }

    frameworks
}

fn detect_rust_framework(path: &Path) -> Result<Vec<Framework>> {
    let mut frameworks = Vec::new();

    let cargo_path = path.join("Cargo.toml");
    if cargo_path.exists() {
        let content = fs::read_to_string(cargo_path)?;

        if content.contains("actix-web") || content.contains("actix_web") {
            frameworks.push(Framework::ActixWeb);
        }
        if content.contains("axum") {
            frameworks.push(Framework::Axum);
        }
        if content.contains("rocket") {
            frameworks.push(Framework::Rocket);
        }
        if content.contains("warp") {
            frameworks.push(Framework::Warp);
        }
    }

    Ok(frameworks)
}

fn detect_python_framework(path: &Path) -> Result<Vec<Framework>> {
    let mut frameworks = Vec::new();

    let requirements_path = path.join("requirements.txt");
    if requirements_path.exists() {
        let content = fs::read_to_string(requirements_path)?.to_lowercase();

        if content.contains("django") {
            frameworks.push(Framework::Django);
        }
        if content.contains("flask") {
            frameworks.push(Framework::Flask);
        }
        if content.contains("fastapi") {
            frameworks.push(Framework::FastAPI);
        }
    }

    let pyproject_path = path.join("pyproject.toml");
    if pyproject_path.exists() {
        let content = fs::read_to_string(pyproject_path)?.to_lowercase();

        if content.contains("django") {
            frameworks.push(Framework::Django);
        }
        if content.contains("flask") {
            frameworks.push(Framework::Flask);
        }
        if content.contains("fastapi") {
            frameworks.push(Framework::FastAPI);
        }
    }

    Ok(frameworks)
}

fn detect_go_framework(path: &Path) -> Result<Vec<Framework>> {
    let mut frameworks = Vec::new();

    let go_mod_path = path.join("go.mod");
    if go_mod_path.exists() {
        let content = fs::read_to_string(go_mod_path)?;

        if content.contains("gin-gonic/gin") || content.contains("gin ") {
            frameworks.push(Framework::Gin);
        }
        if content.contains("labstack/echo") || content.contains("echo ") {
            frameworks.push(Framework::Echo);
        }
        if content.contains("fiber ") {
            frameworks.push(Framework::Fiber);
        }
    }

    Ok(frameworks)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Framework {
    // Node.js
    NestJS,
    Express,
    Fastify,
    Hono,
    Koa,
    NextJS,
    Nuxt,
    SvelteKit,
    Remix,
    Vite,
    // Rust
    ActixWeb,
    Axum,
    Rocket,
    Warp,
    // Python
    Django,
    Flask,
    FastAPI,
    // Go
    Gin,
    Echo,
    Fiber,
    // Java
    SpringBoot,
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Framework::NestJS => write!(f, "NestJS"),
            Framework::Express => write!(f, "Express"),
            Framework::Fastify => write!(f, "Fastify"),
            Framework::Hono => write!(f, "Hono"),
            Framework::Koa => write!(f, "Koa"),
            Framework::NextJS => write!(f, "Next.js"),
            Framework::Nuxt => write!(f, "Nuxt"),
            Framework::SvelteKit => write!(f, "SvelteKit"),
            Framework::Remix => write!(f, "Remix"),
            Framework::Vite => write!(f, "Vite"),
            Framework::ActixWeb => write!(f, "Actix-Web"),
            Framework::Axum => write!(f, "Axum"),
            Framework::Rocket => write!(f, "Rocket"),
            Framework::Warp => write!(f, "Warp"),
            Framework::Django => write!(f, "Django"),
            Framework::Flask => write!(f, "Flask"),
            Framework::FastAPI => write!(f, "FastAPI"),
            Framework::Gin => write!(f, "Gin"),
            Framework::Echo => write!(f, "Echo"),
            Framework::Fiber => write!(f, "Fiber"),
            Framework::SpringBoot => write!(f, "Spring Boot"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_framework_display() {
        assert_eq!(Framework::NestJS.to_string(), "NestJS");
        assert_eq!(Framework::Axum.to_string(), "Axum");
        assert_eq!(Framework::Vite.to_string(), "Vite");
        assert_eq!(Framework::NextJS.to_string(), "Next.js");
        assert_eq!(Framework::SpringBoot.to_string(), "Spring Boot");
    }

    #[test]
    fn test_detect_nestjs() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@nestjs/core": "^10.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::NestJS));
    }

    #[test]
    fn test_detect_express() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Express));
    }

    #[test]
    fn test_detect_fastify() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"fastify": "^4.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Fastify));
    }

    #[test]
    fn test_detect_hono() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"hono": "^3.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Hono));
    }

    #[test]
    fn test_detect_nextjs() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"next": "^14.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::NextJS));
    }

    #[test]
    fn test_detect_vite() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"devDependencies": {"vite": "^5.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Vite));
    }

    #[test]
    fn test_detect_actix_web() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_toml = temp_dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            r#"[dependencies]
actix-web = "4.0"
"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Rust]).unwrap();
        assert!(frameworks.contains(&Framework::ActixWeb));
    }

    #[test]
    fn test_detect_axum() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_toml = temp_dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            r#"[dependencies]
axum = "0.7"
"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Rust]).unwrap();
        assert!(frameworks.contains(&Framework::Axum));
    }

    #[test]
    fn test_detect_rocket() {
        let temp_dir = TempDir::new().unwrap();
        let cargo_toml = temp_dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo_toml,
            r#"[dependencies]
rocket = "0.5"
"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Rust]).unwrap();
        assert!(frameworks.contains(&Framework::Rocket));
    }

    #[test]
    fn test_detect_django() {
        let temp_dir = TempDir::new().unwrap();
        let requirements = temp_dir.path().join("requirements.txt");
        std::fs::write(&requirements, "Django==4.2.0\n").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Python]).unwrap();
        assert!(frameworks.contains(&Framework::Django));
    }

    #[test]
    fn test_detect_flask() {
        let temp_dir = TempDir::new().unwrap();
        let requirements = temp_dir.path().join("requirements.txt");
        std::fs::write(&requirements, "Flask==3.0.0\n").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Python]).unwrap();
        assert!(frameworks.contains(&Framework::Flask));
    }

    #[test]
    fn test_detect_fastapi() {
        let temp_dir = TempDir::new().unwrap();
        let pyproject = temp_dir.path().join("pyproject.toml");
        std::fs::write(
            &pyproject,
            r#"[project]
dependencies = ["fastapi>=0.100.0"]
"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Python]).unwrap();
        assert!(frameworks.contains(&Framework::FastAPI));
    }

    #[test]
    fn test_detect_gin() {
        let temp_dir = TempDir::new().unwrap();
        let go_mod = temp_dir.path().join("go.mod");
        std::fs::write(
            &go_mod,
            "module test\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Go]).unwrap();
        assert!(frameworks.contains(&Framework::Gin));
    }

    #[test]
    fn test_detect_echo() {
        let temp_dir = TempDir::new().unwrap();
        let go_mod = temp_dir.path().join("go.mod");
        std::fs::write(
            &go_mod,
            "module test\n\ngo 1.21\n\nrequire github.com/labstack/echo/v4 v4.11.0\n",
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::Go]).unwrap();
        assert!(frameworks.contains(&Framework::Echo));
    }

    #[test]
    fn test_framework_serialization() {
        let fw = Framework::NestJS;
        let serialized = serde_json::to_string(&fw).unwrap();
        let deserialized: Framework = serde_json::from_str(&serialized).unwrap();
        assert_eq!(fw, deserialized);
    }

    #[test]
    fn test_detect_no_framework() {
        let temp_dir = TempDir::new().unwrap();
        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.is_empty());
    }

    #[test]
    fn test_detect_multiple_node_frameworks() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"next": "^14.0.0", "express": "^4.18.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::NextJS));
        assert!(frameworks.contains(&Framework::Express));
    }
}
