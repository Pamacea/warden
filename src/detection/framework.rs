//! Framework detection
//!
//! Each detected framework enables specific security checks:
//! - SQL/NoSQL injection patterns
//! - Authentication misconfigurations
//! - XSS vulnerabilities in frontend frameworks
//! - Infrastructure as code security issues
//! - Secrets leakage in configs

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

    // Check for infrastructure files (Docker, K8s, Vercel, Cloudflare)
    frameworks.extend(detect_infrastructure(path));

    // Check for database configs (PostgreSQL, MongoDB, Redis, SQLite)
    frameworks.extend(detect_databases(path));

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

/// Detect infrastructure and DevOps tools
fn detect_infrastructure(path: &Path) -> Vec<Framework> {
    let mut frameworks = Vec::new();

    // Docker detection
    if path.join("Dockerfile").exists()
        || path.join("docker-compose.yml").exists()
        || path.join("docker-compose.yaml").exists()
        || path.join(".dockerignore").exists()
    {
        frameworks.push(Framework::Docker);
    }

    // Kubernetes detection
    if path.join("k8s").exists()
        || path.join("kubernetes").exists()
        || path.join(".kube").exists()
        || glob_walk(path, "*.yaml").iter().any(|c| c.contains("kind: Deployment") || c.contains("kind: Service"))
    {
        frameworks.push(Framework::Kubernetes);
    }

    // Vercel detection
    if path.join("vercel.json").exists()
        || path.join(".vercel").exists()
        || path.join(".vercelignore").exists()
    {
        frameworks.push(Framework::Vercel);
    }

    // Cloudflare Workers detection
    if path.join("wrangler.toml").exists()
        || path.join("worker.js").exists()
        || path.join("worker.ts").exists()
    {
        frameworks.push(Framework::CloudflareWorkers);
    }

    frameworks
}

/// Detect database configurations and clients
fn detect_databases(path: &Path) -> Vec<Framework> {
    let mut frameworks = Vec::new();

    // Check for common database files
    let db_files = vec![
        ("prisma/schema.prisma", vec![Framework::Prisma, Framework::PostgreSQL]),
        ("mikro-orm.config.ts", vec![Framework::MikroORM]),
        ("drizzle.config.ts", vec![Framework::Drizzle]),
        ("knexfile.js", vec![Framework::Knex]),
        ("sequelize.config.js", vec![Framework::Sequelize]),
        ("TypeORM.config.js", vec![Framework::TypeORM]),
    ];

    for (file_path, detected_fw) in db_files {
        if path.join(file_path).exists() {
            frameworks.extend(detected_fw);
        }
    }

    // Check environment files for database URLs
    let env_content = read_env_file(path);
    if !env_content.is_empty() {
        let env_lower = env_content.to_lowercase();
        if env_lower.contains("postgres://") || env_lower.contains("postgresql://") {
            frameworks.push(Framework::PostgreSQL);
        }
        if env_lower.contains("mongodb://") || env_lower.contains("mongodb+srv://") {
            frameworks.push(Framework::MongoDB);
        }
        if env_lower.contains("mariadb://") || env_lower.contains("mysql://") {
            frameworks.push(Framework::MariaDB);
        }
        if env_lower.contains("redis://") || env_lower.contains("rediss://") {
            frameworks.push(Framework::Redis);
        }
        if env_lower.contains("sqlite:") || env_lower.contains(".db") || env_lower.contains(".sqlite") {
            frameworks.push(Framework::SQLite);
        }
    }

    // Check package.json for database clients
    if let Some(pkg_content) = read_package_json(path) {
        let deps = extract_all_deps(&pkg_content);

        // MongoDB
        if deps.iter().any(|d| d == "mongoose" || d == "mongodb") {
            frameworks.push(Framework::Mongoose);
            if !frameworks.contains(&Framework::MongoDB) {
                frameworks.push(Framework::MongoDB);
            }
        }

        // PostgreSQL clients
        if deps.iter().any(|d| d == "pg" || d == "postgres") {
            if !frameworks.contains(&Framework::PostgreSQL) {
                frameworks.push(Framework::PostgreSQL);
            }
        }

        // Redis client
        if deps.iter().any(|d| d == "redis" || d == "ioredis") {
            if !frameworks.contains(&Framework::Redis) {
                frameworks.push(Framework::Redis);
            }
        }

        // Better SQLite
        if deps.iter().any(|d| d == "better-sqlite3" || d == "sqlite3") {
            if !frameworks.contains(&Framework::SQLite) {
                frameworks.push(Framework::SQLite);
            }
        }
    }

    frameworks
}

/// Read and combine all .env files
fn read_env_file(path: &Path) -> String {
    let env_files = [".env", ".env.local", ".env.example", ".env.production"];
    let mut content = String::new();

    for file in env_files {
        if let Ok(c) = fs::read_to_string(path.join(file)) {
            content.push_str(&c);
            content.push('\n');
        }
    }

    content
}

/// Read package.json content
fn read_package_json(path: &Path) -> Option<serde_json::Value> {
    let pkg_content = fs::read_to_string(path.join("package.json")).ok()?;
    serde_json::from_str::<serde_json::Value>(&pkg_content).ok()
}

/// Extract all dependency names from package.json
fn extract_all_deps(pkg: &serde_json::Value) -> Vec<String> {
    let mut deps = Vec::new();

    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(obj) = pkg.get(key).and_then(|d| d.as_object()) {
            deps.extend(obj.keys().cloned());
        }
    }

    deps
}

/// Simple glob pattern matching for file content
fn glob_walk(path: &Path, pattern: &str) -> Vec<String> {
    let mut results = Vec::new();

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                results.extend(glob_walk(&entry_path, pattern));
            } else if let Some(name) = entry_path.file_name() {
                if name.to_string_lossy().contains(pattern) {
                    if let Ok(content) = fs::read_to_string(&entry_path) {
                        results.push(content);
                    }
                }
            }
        }
    }

    results
}

fn detect_node_framework(pkg: &serde_json::Value) -> Vec<Framework> {
    let mut frameworks = Vec::new();

    let deps = extract_all_deps(pkg);

    for dep_name in deps {
        match dep_name.as_str() {
            // ===== BACKEND FRAMEWORKS =====
            "@nestjs/core" | "@nestjs/common" => frameworks.push(Framework::NestJS),
            "express" => frameworks.push(Framework::Express),
            "fastify" => frameworks.push(Framework::Fastify),
            "hono" => frameworks.push(Framework::Hono),
            "koa" => frameworks.push(Framework::Koa),

            // ===== FRONTEND FRAMEWORKS =====
            "next" => frameworks.push(Framework::NextJS),
            "nuxt" => frameworks.push(Framework::Nuxt),
            "@angular/core" | "@angular/animations" => frameworks.push(Framework::Angular),
            "vue" => frameworks.push(Framework::Vue),
            "@sveltejs/kit" => frameworks.push(Framework::SvelteKit),
            "@remix-run/react" => frameworks.push(Framework::Remix),
            "react" | "react-dom" => frameworks.push(Framework::React),

            // ===== BUILD TOOLS =====
            "vite" if !frameworks.contains(&Framework::Vite) => frameworks.push(Framework::Vite),

            // ===== ORM / DATABASE =====
            "@prisma/client" | "prisma" => frameworks.push(Framework::Prisma),
            "@supabase/supabase-js" => frameworks.push(Framework::Supabase),
            "@neondatabase/serverless" | "@neondatabase/neon" => frameworks.push(Framework::NeonDB),
            "mongoose" => { frameworks.push(Framework::Mongoose); }
            "drizzle-orm" => frameworks.push(Framework::Drizzle),
            "sequelize" => frameworks.push(Framework::Sequelize),
            "typeorm" => frameworks.push(Framework::TypeORM),
            "mikro-orm" => frameworks.push(Framework::MikroORM),
            "knex" => frameworks.push(Framework::Knex),

            // ===== AUTHENTICATION =====
            "next-auth" | "next-auth@beta" => frameworks.push(Framework::NextAuth),
            "better-auth" => frameworks.push(Framework::BetterAuth),
            "@clerk/clerk-react" | "@clerk/clerk-sdk-node" => frameworks.push(Framework::Clerk),
            "@supabase/auth-helpers-nextjs" | "@supabase/auth-helpers-react" => frameworks.push(Framework::SupabaseAuth),

            // ===== STATE MANAGEMENT =====
            "zustand" => frameworks.push(Framework::Zustand),
            "@reduxjs/toolkit" | "redux" | "react-redux" => frameworks.push(Framework::Redux),
            "@tanstack/react-query" | "@tanstack/react-query-next" => frameworks.push(Framework::TanStackQuery),

            // ===== TESTING =====
            "jest" => frameworks.push(Framework::Jest),
            "vitest" => frameworks.push(Framework::Vitest),
            "@playwright/test" | "playwright" => frameworks.push(Framework::Playwright),
            "cypress" => frameworks.push(Framework::Cypress),

            // ===== GRAPHQL =====
            "graphql" | "@apollo/client" | "@apollo/server" => frameworks.push(Framework::GraphQL),
            "altair-graphql" => frameworks.push(Framework::Altair),
            "graphql-yoga" | "@graphql-yoga" => frameworks.push(Framework::GraphQLYoga),

            // ===== STYLING =====
            "tailwindcss" => frameworks.push(Framework::Tailwind),
            "shadcn-ui" | "@shadcn/ui" => frameworks.push(Framework::ShadcnUI),
            "@chakra-ui/react" => frameworks.push(Framework::ChakraUI),
            "@mantine/core" => frameworks.push(Framework::Mantine),

            // ===== UTILS =====
            "axios" => frameworks.push(Framework::Axios),
            "zod" => frameworks.push(Framework::Zod),

            _ => {}
        }
    }

    // Remove duplicates while preserving order
    frameworks.sort_by_key(|_a| std::usize::MAX);
    frameworks.dedup();

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

        // SQL libraries for Rust
        if content.contains("sqlx") || content.contains("diesel") {
            if content.contains("postgres") {
                frameworks.push(Framework::PostgreSQL);
            }
            if content.contains("mysql") {
                frameworks.push(Framework::MariaDB);
            }
            if content.contains("sqlite") {
                frameworks.push(Framework::SQLite);
            }
        }

        // Redis
        if content.contains("redis") {
            frameworks.push(Framework::Redis);
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

        // Python database libraries
        if content.contains("psycopg2") || content.contains("asyncpg") {
            frameworks.push(Framework::PostgreSQL);
        }
        if content.contains("pymongo") {
            frameworks.push(Framework::MongoDB);
        }
        if content.contains("redis") {
            frameworks.push(Framework::Redis);
        }
        if content.contains("pymysql") || content.contains("mysqlclient") {
            frameworks.push(Framework::MariaDB);
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

        // SQL Alchemy (ORM)
        if content.contains("sqlalchemy") {
            frameworks.push(Framework::SQLAlchemy);
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

        // Go database drivers
        if content.contains("lib/pq") {
            frameworks.push(Framework::PostgreSQL);
        }
        if content.contains("mongo-driver") {
            frameworks.push(Framework::MongoDB);
        }
        if content.contains("redis") {
            frameworks.push(Framework::Redis);
        }
        if content.contains("go-sql-driver/mysql") {
            frameworks.push(Framework::MariaDB);
        }
    }

    Ok(frameworks)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Framework {
    // ===== BACKEND FRAMEWORKS =====
    #[serde(rename = "nestjs")]
    NestJS,
    #[serde(rename = "express")]
    Express,
    #[serde(rename = "fastify")]
    Fastify,
    #[serde(rename = "hono")]
    Hono,
    #[serde(rename = "koa")]
    Koa,

    // ===== FRONTEND FRAMEWORKS =====
    #[serde(rename = "nextjs")]
    NextJS,
    #[serde(rename = "nuxt")]
    Nuxt,
    #[serde(rename = "angular")]
    Angular,
    #[serde(rename = "vue")]
    Vue,
    #[serde(rename = "react")]
    React,
    #[serde(rename = "sveltekit")]
    SvelteKit,
    #[serde(rename = "remix")]
    Remix,

    // ===== BUILD TOOLS =====
    #[serde(rename = "vite")]
    Vite,

    // ===== ORM / DATABASE =====
    #[serde(rename = "prisma")]
    Prisma,
    #[serde(rename = "drizzle")]
    Drizzle,
    #[serde(rename = "sequelize")]
    Sequelize,
    #[serde(rename = "typeorm")]
    TypeORM,
    #[serde(rename = "mikroorm")]
    MikroORM,
    #[serde(rename = "knex")]
    Knex,
    #[serde(rename = "mongoose")]
    Mongoose,
    #[serde(rename = "supabase")]
    Supabase,
    #[serde(rename = "neondb")]
    NeonDB,

    // ===== DATABASES =====
    #[serde(rename = "postgresql")]
    PostgreSQL,
    #[serde(rename = "mongodb")]
    MongoDB,
    #[serde(rename = "mariadb")]
    MariaDB,
    #[serde(rename = "redis")]
    Redis,
    #[serde(rename = "sqlite")]
    SQLite,

    // ===== AUTHENTICATION =====
    #[serde(rename = "nextauth")]
    NextAuth,
    #[serde(rename = "betterauth")]
    BetterAuth,
    #[serde(rename = "clerk")]
    Clerk,
    #[serde(rename = "supabaseauth")]
    SupabaseAuth,

    // ===== STATE MANAGEMENT =====
    #[serde(rename = "zustand")]
    Zustand,
    #[serde(rename = "redux")]
    Redux,
    #[serde(rename = "tanstackquery")]
    TanStackQuery,

    // ===== TESTING =====
    #[serde(rename = "jest")]
    Jest,
    #[serde(rename = "vitest")]
    Vitest,
    #[serde(rename = "playwright")]
    Playwright,
    #[serde(rename = "cypress")]
    Cypress,

    // ===== GRAPHQL =====
    #[serde(rename = "graphql")]
    GraphQL,
    #[serde(rename = "altair")]
    Altair,
    #[serde(rename = "graphqlyoga")]
    GraphQLYoga,

    // ===== STYLING =====
    #[serde(rename = "tailwind")]
    Tailwind,
    #[serde(rename = "shadcnui")]
    ShadcnUI,
    #[serde(rename = "chakraui")]
    ChakraUI,
    #[serde(rename = "mantine")]
    Mantine,

    // ===== DEVOPS / INFRASTRUCTURE =====
    #[serde(rename = "docker")]
    Docker,
    #[serde(rename = "kubernetes")]
    Kubernetes,
    #[serde(rename = "vercel")]
    Vercel,
    #[serde(rename = "cloudflareworkers")]
    CloudflareWorkers,

    // ===== RUST =====
    #[serde(rename = "actixweb")]
    ActixWeb,
    #[serde(rename = "axum")]
    Axum,
    #[serde(rename = "rocket")]
    Rocket,
    #[serde(rename = "warp")]
    Warp,

    // ===== PYTHON =====
    #[serde(rename = "django")]
    Django,
    #[serde(rename = "flask")]
    Flask,
    #[serde(rename = "fastapi")]
    FastAPI,
    #[serde(rename = "sqlalchemy")]
    SQLAlchemy,

    // ===== GO =====
    #[serde(rename = "gin")]
    Gin,
    #[serde(rename = "echo")]
    Echo,
    #[serde(rename = "fiber")]
    Fiber,

    // ===== JAVA =====
    #[serde(rename = "springboot")]
    SpringBoot,

    // ===== UTILS =====
    #[serde(rename = "axios")]
    Axios,
    #[serde(rename = "zod")]
    Zod,
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
            Framework::Angular => write!(f, "Angular"),
            Framework::Vue => write!(f, "Vue.js"),
            Framework::React => write!(f, "React"),
            Framework::SvelteKit => write!(f, "SvelteKit"),
            Framework::Remix => write!(f, "Remix"),
            Framework::Vite => write!(f, "Vite"),
            Framework::Prisma => write!(f, "Prisma"),
            Framework::Drizzle => write!(f, "Drizzle"),
            Framework::Sequelize => write!(f, "Sequelize"),
            Framework::TypeORM => write!(f, "TypeORM"),
            Framework::MikroORM => write!(f, "MikroORM"),
            Framework::Knex => write!(f, "Knex"),
            Framework::Mongoose => write!(f, "Mongoose"),
            Framework::Supabase => write!(f, "Supabase"),
            Framework::NeonDB => write!(f, "Neon DB"),
            Framework::PostgreSQL => write!(f, "PostgreSQL"),
            Framework::MongoDB => write!(f, "MongoDB"),
            Framework::MariaDB => write!(f, "MariaDB"),
            Framework::Redis => write!(f, "Redis"),
            Framework::SQLite => write!(f, "SQLite"),
            Framework::NextAuth => write!(f, "NextAuth"),
            Framework::BetterAuth => write!(f, "Better Auth"),
            Framework::Clerk => write!(f, "Clerk"),
            Framework::SupabaseAuth => write!(f, "Supabase Auth"),
            Framework::Zustand => write!(f, "Zustand"),
            Framework::Redux => write!(f, "Redux"),
            Framework::TanStackQuery => write!(f, "TanStack Query"),
            Framework::Jest => write!(f, "Jest"),
            Framework::Vitest => write!(f, "Vitest"),
            Framework::Playwright => write!(f, "Playwright"),
            Framework::Cypress => write!(f, "Cypress"),
            Framework::GraphQL => write!(f, "GraphQL"),
            Framework::Altair => write!(f, "Altair"),
            Framework::GraphQLYoga => write!(f, "GraphQL Yoga"),
            Framework::Tailwind => write!(f, "Tailwind"),
            Framework::ShadcnUI => write!(f, "shadcn/ui"),
            Framework::ChakraUI => write!(f, "Chakra UI"),
            Framework::Mantine => write!(f, "Mantine"),
            Framework::Docker => write!(f, "Docker"),
            Framework::Kubernetes => write!(f, "Kubernetes"),
            Framework::Vercel => write!(f, "Vercel"),
            Framework::CloudflareWorkers => write!(f, "Cloudflare Workers"),
            Framework::ActixWeb => write!(f, "Actix-Web"),
            Framework::Axum => write!(f, "Axum"),
            Framework::Rocket => write!(f, "Rocket"),
            Framework::Warp => write!(f, "Warp"),
            Framework::Django => write!(f, "Django"),
            Framework::Flask => write!(f, "Flask"),
            Framework::FastAPI => write!(f, "FastAPI"),
            Framework::SQLAlchemy => write!(f, "SQLAlchemy"),
            Framework::Gin => write!(f, "Gin"),
            Framework::Echo => write!(f, "Echo"),
            Framework::Fiber => write!(f, "Fiber"),
            Framework::SpringBoot => write!(f, "Spring Boot"),
            Framework::Axios => write!(f, "Axios"),
            Framework::Zod => write!(f, "Zod"),
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
        assert_eq!(Framework::Angular.to_string(), "Angular");
        assert_eq!(Framework::Vue.to_string(), "Vue.js");
        assert_eq!(Framework::React.to_string(), "React");
        assert_eq!(Framework::Prisma.to_string(), "Prisma");
        assert_eq!(Framework::Mongoose.to_string(), "Mongoose");
        assert_eq!(Framework::Drizzle.to_string(), "Drizzle");
        assert_eq!(Framework::PostgreSQL.to_string(), "PostgreSQL");
        assert_eq!(Framework::MongoDB.to_string(), "MongoDB");
        assert_eq!(Framework::Clerk.to_string(), "Clerk");
        assert_eq!(Framework::SupabaseAuth.to_string(), "Supabase Auth");
        assert_eq!(Framework::Redis.to_string(), "Redis");
        assert_eq!(Framework::SQLite.to_string(), "SQLite");
        assert_eq!(Framework::Vercel.to_string(), "Vercel");
        assert_eq!(Framework::CloudflareWorkers.to_string(), "Cloudflare Workers");
        assert_eq!(Framework::Jest.to_string(), "Jest");
        assert_eq!(Framework::Vitest.to_string(), "Vitest");
        assert_eq!(Framework::Playwright.to_string(), "Playwright");
        assert_eq!(Framework::GraphQL.to_string(), "GraphQL");
        assert_eq!(Framework::Zustand.to_string(), "Zustand");
        assert_eq!(Framework::Redux.to_string(), "Redux");
        assert_eq!(Framework::Tailwind.to_string(), "Tailwind");
        assert_eq!(Framework::ShadcnUI.to_string(), "shadcn/ui");
        assert_eq!(Framework::Docker.to_string(), "Docker");
        assert_eq!(Framework::Kubernetes.to_string(), "Kubernetes");
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
    fn test_detect_angular() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@angular/core": "^17.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Angular));
    }

    #[test]
    fn test_detect_vue() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"vue": "^3.4.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Vue));
    }

    #[test]
    fn test_detect_react() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::React));
    }

    #[test]
    fn test_detect_prisma() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@prisma/client": "^5.0.0"}, "devDependencies": {"prisma": "^5.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Prisma));
    }

    #[test]
    fn test_detect_mongoose() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"mongoose": "^8.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Mongoose));
        assert!(frameworks.contains(&Framework::MongoDB));
    }

    #[test]
    fn test_detect_drizzle() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"drizzle-orm": "^0.29.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Drizzle));
    }

    #[test]
    fn test_detect_sequelize() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"sequelize": "^6.35.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Sequelize));
    }

    #[test]
    fn test_detect_typeorm() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"typeorm": "^0.3.17"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::TypeORM));
    }

    #[test]
    fn test_detect_clerk() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@clerk/clerk-react": "^4.30.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Clerk));
    }

    #[test]
    fn test_detect_supabase_auth() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@supabase/auth-helpers-nextjs": "^0.8.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::SupabaseAuth));
    }

    #[test]
    fn test_detect_zustand() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"zustand": "^4.4.7"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Zustand));
    }

    #[test]
    fn test_detect_redux() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@reduxjs/toolkit": "^2.0.0", "react-redux": "^9.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Redux));
    }

    #[test]
    fn test_detect_jest() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"devDependencies": {"jest": "^29.7.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Jest));
    }

    #[test]
    fn test_detect_vitest() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"devDependencies": {"vitest": "^1.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Vitest));
    }

    #[test]
    fn test_detect_playwright() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"devDependencies": {"@playwright/test": "^1.40.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Playwright));
    }

    #[test]
    fn test_detect_graphql() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"graphql": "^16.8.0", "@apollo/client": "^3.8.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::GraphQL));
    }

    #[test]
    fn test_detect_tailwind() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"devDependencies": {"tailwindcss": "^3.4.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Tailwind));
    }

    #[test]
    fn test_detect_shadcn() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"@shadcn/ui": "^1.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::ShadcnUI));
    }

    #[test]
    fn test_detect_docker() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("Dockerfile"), "FROM node:20\n").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Docker));
    }

    #[test]
    fn test_detect_vercel() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("vercel.json"), "{}").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Vercel));
    }

    #[test]
    fn test_detect_cloudflare_workers() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(temp_dir.path().join("wrangler.toml"), "name = \"worker\"\n").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::CloudflareWorkers));
    }

    #[test]
    fn test_detect_postgresql_in_env() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".env"),
            "DATABASE_URL=postgres://user:pass@localhost:5432/db\n",
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::PostgreSQL));
    }

    #[test]
    fn test_detect_mongodb_in_env() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".env"),
            "MONGO_URI=mongodb://localhost:27017/db\n",
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::MongoDB));
    }

    #[test]
    fn test_detect_redis_in_env() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::write(
            temp_dir.path().join(".env"),
            "REDIS_URL=redis://localhost:6379\n",
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::Redis));
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
            r#"{"dependencies": {"next": "^14.0.0", "express": "^4.18.0", "prisma": "^5.0.0", "zustand": "^4.4.0", "@reduxjs/toolkit": "^2.0.0"}}"#,
        )
        .unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::NextJS));
        assert!(frameworks.contains(&Framework::Express));
        assert!(frameworks.contains(&Framework::Prisma));
        assert!(frameworks.contains(&Framework::Zustand));
        assert!(frameworks.contains(&Framework::Redux));
    }

    #[test]
    fn test_detect_full_stack_infrastructure() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        std::fs::write(
            &package_json,
            r#"{"dependencies": {"next": "^14.0.0", "drizzle-orm": "^0.29.0", "better-auth": "^1.0.0", "vitest": "^1.0.0", "tailwindcss": "^3.4.0"}}"#,
        )
        .unwrap();
        std::fs::write(temp_dir.path().join("Dockerfile"), "FROM node:20\n").unwrap();
        std::fs::write(temp_dir.path().join("vercel.json"), "{}\n").unwrap();

        let frameworks = detect(temp_dir.path(), &[Language::JavaScript]).unwrap();
        assert!(frameworks.contains(&Framework::NextJS));
        assert!(frameworks.contains(&Framework::Drizzle));
        assert!(frameworks.contains(&Framework::BetterAuth));
        assert!(frameworks.contains(&Framework::Vitest));
        assert!(frameworks.contains(&Framework::Tailwind));
        assert!(frameworks.contains(&Framework::Docker));
        assert!(frameworks.contains(&Framework::Vercel));
    }
}
