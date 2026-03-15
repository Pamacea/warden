# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.3] - 2025-03-15

### Added
- **Self-Update Command** - New `warden update` command for automatic updates
  - Checks crates.io for newer versions
  - Installs latest version via `cargo install warden-sec --force`
  - `--force` flag to reinstall even if already up-to-date
  - `--git` flag to install from GitHub repository

## [0.6.2] - 2025-03-15

### Fixed
- **Excluded Directories** - Static analyzer now excludes dependency directories by default
  - `node_modules/` - JavaScript/TypeScript dependencies
  - `vendor/`, `vendor/bundle/` - PHP/Ruby dependencies
  - `target/`, `dist/`, `build/` - Build outputs
  - `.git/`, `.idea/`, `.vscode/` - VCS and IDE folders
  - `__pycache__/`, `.venv/`, `venv/` - Python cache and virtual environments
  - `.next/`, `.nuxt/`, `out/` - Framework build caches
  - `coverage/`, `.terraform/` - Test and infrastructure caches

### Improved
- **Security Scan Accuracy** - No more false positives from third-party dependencies
- **Scan Performance** - Faster scans by excluding unnecessary directories
- **Relevant Findings** - Only reports vulnerabilities in your actual source code

## [0.6.1] - 2025-03-15

### Added
- **AI-Readable Report Format** - New `ai` format optimized for Claude Code and AI agents
  - Structured markdown with clickable file paths and line numbers
  - "Files to Fix" section grouped by file for systematic fixing
  - "Suggested Fix Order" with priority-based phases
  - AI Agent Instructions section for clear context

- **Auto-Save by Default** - Reports automatically saved to project directory
  - Creates `WARDEN_SECURITY_REPORT.md` in scanned directory
  - Perfect for AI agents to read and act upon findings
  - `--no-auto-save` flag to disable if needed

- **JSON Fix Data Export** - Optional structured JSON for programmatic processing
  - `--generate-fixes` flag creates `WARDEN_SECURITY_REPORT_fixes.json`
  - Contains: file, line, severity, title, description, recommendation, CWE
  - Easy to parse for automated fix generation

### Improved
- Better file path handling with absolute paths in AI reports
- Line number extraction from location strings (e.g., `src/main.rs:42`)
- Test coverage increased to 314 tests

### Technical
- New `reporters::ai` module for AI-optimized reporting
- Enhanced `ScanReport` with AI format support
- New `get_auto_save_path()` function for smart path resolution

## [0.6.0] - 2025-03-15

### Added
- **Massive Framework Detection** - 50+ frameworks and libraries detected
  - Frontend: React, Angular, Vue.js, SvelteKit, Remix, Vite
  - Backend: NestJS, Express, Fastify, Hono, Koa
  - ORM: Prisma, Mongoose, Drizzle, Sequelize, TypeORM, MikroORM, Knex
  - Database: PostgreSQL, MongoDB, MariaDB, Redis, SQLite
  - Auth: NextAuth, Better Auth, Clerk, Supabase Auth
  - State: Zustand, Redux, TanStack Query
  - Testing: Jest, Vitest, Playwright, Cypress
  - GraphQL: GraphQL, Altair, GraphQL Yoga
  - Styling: Tailwind, shadcn/ui, Chakra UI, Mantine
  - Infrastructure: Docker, Kubernetes, Vercel, Cloudflare Workers

- **Advanced Detection Capabilities**
  - Scan `.env` files for database connection strings
  - Detect Docker configuration (Dockerfile, docker-compose.yml)
  - Detect Kubernetes manifests
  - Detect Vercel deployments (vercel.json)
  - Detect Cloudflare Workers (wrangler.toml)
  - Multi-language package scanning (package.json, Cargo.toml, go.mod, requirements.txt)

- **Scanning Modes** - New mode-based scanning system
  - Passive mode - no active requests, only static analysis
  - Active mode - full testing with standard checks
  - Stealth mode - low and slow, minimizes detection
  - Aggressive mode - thorough testing with all checks
  - Each mode has configurable timeout, concurrency, and behavior

- **Profile-based Configuration** - Quick configuration profiles
  - `quick` - Fast scanning (2s timeout, 25 concurrent)
  - `standard` - Balanced scanning (5s timeout, 50 concurrent)
  - `thorough` - Deep scanning (15s timeout, 100 concurrent, aggressive)
  - `stealth` - Low-and-slow (30s timeout, 5 concurrent)
  - `aggressive` - Maximum coverage (10s timeout, 200 concurrent)

- **Scanner Chains** - Custom scanner sequences
  - Predefined chains: OWASP, API-focus, Quick Audit
  - Custom chains with ordered scanner lists
  - Stop-on-first finding option
  - Max findings threshold

### Improved
- **Zero Warning Compilation** - All code now compiles with 0 warnings
- Better separation between scanning modes and configuration
- Enhanced profile system for flexible scanning
- 308 passing tests with comprehensive coverage

### Technical
- Added `ScanMode` enum with mode-specific behaviors
- Added `ScannerChain` for custom scanner sequences
- Extended `Config` with profile support
- Better documentation and code organization
- Security-oriented framework detection (each framework enables specific vulnerability checks)

## [0.5.0] - 2025-03-15

### Added
- **Reconnaissance Scanner** (New module)
  - Passive reconnaissance (backup file detection, config exposure, sensitive files)
  - Active reconnaissance (directory fuzzing, endpoint discovery, comment discovery)
  - Backup file enumeration (.bak, .old, .orig, ~, .swp)
  - Configuration file exposure (.env, config.json, docker-compose.yml)
  - Directory listing detection
  - Hidden directory and file discovery
  - API endpoint enumeration
  - HTML/JavaScript comment extraction for sensitive info

- **Enhanced Report Formats**
  - HTML reports with interactive UI, filtering, and keyboard shortcuts
  - SARIF format for GitHub Security integration
  - Enhanced JSON and Markdown reports
  - Responsive HTML design with dark theme

- **Reporting Enhancements**
  - Write reports to file in multiple formats
  - HTML export with severity filtering
  - SARIF export for CI/CD integration
  - Improved summary statistics

## [0.4.0] - 2025-03-15

### Added
- **API Security Scanner** (New module)
  - GraphQL introspection and depth limiting detection
  - REST API parameter tampering detection
  - Mass assignment vulnerability detection
  - API versioning issues detection
  - WebSocket security testing (WSS vs WS, origin validation)

- **Authentication Testing**
  - JWT token analysis (algorithm detection, expiration, sensitive data)
  - OAuth 2.0 flow testing (PKCE, state parameter, implicit grant)
  - Session fixation detection
  - Session cookie security flags (HttpOnly, Secure, SameSite)

- **API Vulnerabilities**
  - IDOR (Insecure Direct Object Reference) detection
  - Parameter pollution testing
  - Open redirect via API parameters

## [0.3.0] - 2025-03-15

### Added
- **HTTP Scanner Enhancements**
  - Advanced XSS payloads (DOM-based, blind XSS)
  - SQL injection detection (error-based, blind, time-based)
  - NoSQL injection detection (MongoDB, Redis, CouchDB, JSON)
  - CSRF token analysis
  - Clickjacking detection (X-Frame-Options bypass detection)
  - Open redirect detection

- **Port Scanner Enhancements**
  - Enhanced version detection (50+ new patterns)
  - Banner grabbing for all common services
  - UDP port scanning support (DNS, NTP, SNMP, etc.)
  - Custom port ranges support

- **Static Analysis Enhancements**
  - TypeScript support (any types, ts-ignore, non-null assertions)
  - Go support (command injection, SQLi, ReadAll DoS, crypto)
  - Java support (Statement SQLi, Runtime.exec, unsafe deserialization)
  - PHP support (eval, exec, SQLi, unserialize, file inclusion, weak hashing)

## [0.2.0] - 2025-03-15

### Added
- Initial release of Warden
- Native HTTP scanner with XSS, headers, SSRF detection
- Native port scanner with concurrent scanning
- Static code analysis for Rust, JavaScript, Python
- DDoS resistance testing (HTTP flood, Slowloris)
- Stress testing capabilities
- Framework detection (NestJS, Rust, Vite, Express, Fastify, Django, Flask, FastAPI, Go, Spring Boot)
- OWASP Top 10 2021 coverage
- CLI with colored output
- Multi-platform support (Windows, macOS, Linux)

[Unreleased]: https://github.com/Pamacea/warden/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/Pamacea/warden/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Pamacea/warden/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Pamacea/warden/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Pamacea/warden/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Pamacea/warden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Pamacea/warden/releases/tag/v0.2.0
