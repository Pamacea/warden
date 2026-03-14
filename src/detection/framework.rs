//! Framework detection

use super::Language;
use crate::detection::Framework;
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

    #[test]
    fn test_framework_display() {
        assert_eq!(Framework::NestJS.to_string(), "NestJS");
        assert_eq!(Framework::Axum.to_string(), "Axum");
        assert_eq!(Framework::Vite.to_string(), "Vite");
    }
}
