# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.3] - 2026-03-22

### Added
- **`--full` Scan Mode** - Run all available security scanners
  - URL scanners: API, GraphQL, gRPC, CORS, SSRF, Open Redirect, Path Traversal, XXE, Deserialization, SSTI, Enumeration, Disclosure, Business Logic, LDAP, RDP, WAF, Race Condition
  - Path scanners: Terraform, Docker, Kubernetes, Cloud Metadata
  - Activates with `warden scan --full <target>`

### Fixed
- **Code Safety** - Improved error handling throughout codebase
  - Replaced `unwrap()` with descriptive `expect()` messages on Mutex locks
  - Fixed `started_at.unwrap()` potential panic with `unwrap_or_else()` fallback
  - Added clear error messages for concurrent access failures

### Removed
- Dead code elimination - removed unused scanner methods and fields
- Cleaned up unused imports and variables
- All compiler warnings resolved (0 errors, 0 warnings)

## [0.8.2] - 2026-03-22

### Oalacea Branding & Architecture

> **Package renamed to `oalacea-warden` | Trait-based scanner architecture | Parallel scanning**

### Changed
- **Package Rename** - `warden-sec` → `oalacea-warden` (CLI command remains `warden`)
- **Architecture** - New `SecurityScanner` trait for extensible scanner system
- **Performance** - Parallel file scanning with `rayon` (multi-core)
- **File Discovery** - Added `ignore` crate (ripgrep) for .gitignore-aware file traversal
- **Error Handling** - Centralized `thiserror` types (`ScannerError`, `HttpScanError`, etc.)
- **Tree-sitter** - Parser cache for AST reuse across security checks

### Technical
- Added `ScannerRegistry`, `ScannerMetadata`, `ScannerCategory` types
- Added `ParserCache` with thread-safe caching and automatic eviction
- Improved static analyzer with language-specific parallel processing
- Better error messages with severity levels and retryable detection

### Dependencies
- Added: `async-trait`, `ignore`, `once_cell`
- Updated: Package metadata for Oalacea Security Suite

## [0.8.1] - 2026-03-16

### Fixed
- **Windows Self-Update Bug** - Fixed "Access denied (os error 5)" error
  - Improved batch script with longer wait times
  - Added warden.exe process detection before replacement
  - Better error messages for troubleshooting
  - Uses START /B /MIN to run script independently

## [0.8.0] - 2026-03-16

### MEGA RELEASE

> **25+ new security scanners | ML-powered detection | CI/CD integration | Enterprise features**

### Advanced Testing Scanners (6 new)
- **Deserialization Scanner** - Java, Python, PHP, JSON, YAML, .NET serialization
- **Race Condition Detector** - TOCTOU, password reset races, concurrent request testing
- **Business Logic Scanner** - Price manipulation, coupon abuse, privilege escalation
- **File Upload Scanner** - MIME bypass, webshell upload, path traversal
- **WebSocket Scanner** - Message injection, DoS, authentication bypass
- **gRPC Scanner** - Protobuf fuzzing, reflection attack, service enumeration

### Cloud & Infrastructure Scanners (5 new)
- **Docker Security Scanner** - Container escape, volume mounting, privileged mode
- **Kubernetes Scanner** - RBAC misconfig, pod escape, secrets exposure
- **Terraform/TFSec Scanner** - IaC security scanning, secrets detection, IAM misconfig
- **Lambda/Serverless Scanner** - AWS/Azure/GCP functions, IAM issues, timeout checks
- **Cloud Metadata Scanner** - AWS/GCP/Azure/DigitalOcean metadata endpoints

### Database & NoSQL Scanners (3 new)
- **Redis Scanner** - NoSQL injection, authentication, dangerous commands, Lua scripting
- **MongoDB Scanner** - NoSQL injection, operator abuse, auth bypass
- **Elasticsearch Scanner** - Query injection, scripting, cluster abuse, DoS

### Protocol & Network Scanners (3 new)
- **SMB/NetBIOS Scanner** - Share enumeration, null sessions, SMBv1 vulnerabilities
- **RDP Scanner** - Blue Keep, NLA, encryption level checks
- **LDAP Scanner** - Injection, anonymous bind, enumeration

### AI & Automation Features (5 new)
- **ML-Based Detection Engine** - Pattern recognition, zero-day detection, anomaly detection
- **Smart Payload Selection** - Adaptive payload generation, fuzzing grammars
- **False Positive Reduction** - Context-aware filtering, similarity analysis
- **Continuous Scanning Daemon** - Background scanning, job queue, scheduling
- **Smart Reconnaissance** - Subdomain enumeration, attack surface mapping

### CI/CD Integration (4 new)
- **GitHub App Integration** - Auto-scan on PR, status checks, security badges, PR annotations
- **GitLab Integration** - CI/CD pipeline scanning, MR scanning, badges, API client
- **Jenkins Plugin** - Build steps, console formatting, failure thresholds
- **VS Code Extension** - Real-time feedback, diagnostics, tree view

### Enterprise Features (4 new)
- **SAML/SSO Authentication** - Okta, Azure AD, Auth0 identity provider integration
- **RBAC System** - Role-based access control, permissions, audit trail
- **Audit Logging** - Event logging, immutable logs, SIEM export (SOC2/ISO27001 compliant)
- **Compliance Ready** - Audit trails, chain of custody, retention policies

### Technical Improvements
- 20+ new scanner modules (~15,000 LOC)
- 5 new ML/AI modules (~5,000 LOC)
- 4 new CI/CD integration modules (~6,000 LOC)
- 4 new enterprise authentication/audit modules (~4,000 LOC)
- Enhanced `src/lib.rs` with 30+ new module exports
- Binary size optimized: ~8 MB (under 10 MB target)
- All 315+ tests passing

### Wordlists Added (~7,000 payloads)
- `wordlists/deserialization.txt` (~150 payloads)
- `wordlists/race_condition.txt` (~100 payloads)
- `wordlists/business_logic.txt` (~200 payloads)
- `wordlists/file_upload.txt` (~80 payloads)
- `wordlists/websocket.txt` (~120 payloads)
- `wordlists/grpc.txt` (~90 payloads)
- `wordlists/docker.txt` (~150 payloads)
- `wordlists/kubernetes.txt` (~180 payloads)
- `wordlists/terraform.txt` (~120 payloads)
- `wordlists/serverless.txt` (~100 payloads)
- `wordlists/cloud_metadata.txt` (~80 payloads)
- `wordlists/redis.txt` (~150 payloads)
- `wordlists/mongodb.txt` (~120 payloads)
- `wordlists/elasticsearch.txt` (~100 payloads)
- `wordlists/smb.txt` (~90 payloads)
- `wordlists/rdp.txt` (~70 payloads)
- `wordlists/ldap.txt` (~130 payloads)

### Breaking Changes
- Module restructure: `src/ml`, `src/daemon`, `src/integrations`, `src/auth`, `src/audit`
- `VulnSeverity` now re-exported from `crate::scanners` module
- Some scanner APIs updated for async/await consistency

### Deprecations
- Legacy scoring module methods replaced by new `ml::detection` module

## [0.7.5] - 2026-03-15

### Added
- **WAF Detection & Bypass Scanner** - Comprehensive WAF/CDN fingerprinting
  - 20+ solutions detected: Cloudflare, AWS WAF, Akamai, ModSecurity, F5 BIG-IP, Imperva, Fortinet, Barracuda, Sucuri, Fastly, Azure Front Door, Google Cloud Armor, Wordfence, etc.
  - Passive fingerprinting via response headers and error pages
  - 18 bypass techniques documented (SQLi, XSS, Path Traversal, Headers)
  - Wordlist: `wordlists/waf_bypass.txt` (~200 payloads)

- **GraphQL Security Scanner** - Advanced GraphQL testing
  - Endpoint detection (/graphql, /graphiql, /playground, etc.)
  - Introspection testing (schema discovery vulnerability)
  - Injection testing (query injection, alias abuse)
  - DoS testing (nested queries, batch queries, field duplication)
  - GET-based CSRF vulnerability detection
  - Query complexity/size limit testing
  - Wordlist: `wordlists/graphql.txt` (~100 payloads)

- **SSRF Scanner** - Server-Side Request Forgery detection
  - Internal network scanning (localhost, 127.0.0.1, private ranges)
  - Cloud metadata endpoints (AWS, GCP, Azure)
  - Protocol bypass testing (file://, dict://, gopher://)
  - Encoding bypasses (octal, hex, decimal, IPv6)
  - DNS rebinding techniques
  - Header-based SSRF (X-Forwarded-For, Host, etc.)
  - Wordlist: `wordlists/ssrf.txt` (~150 payloads)

- **XXE Scanner** - XML External Entity injection
  - File read payloads (/etc/passwd, /winnt/repair/sam)
  - SSRF via XXE (internal network access)
  - Blind XXE with out-of-band detection
  - Multiple XML parser support (libxml2, Java SAX, .NET XmlDocument)
  - Parameter entity XXE
  - DoS via XML bombs (billion laughs attack)
  - Wordlist: `wordlists/xxe.txt` (~80 payloads)

- **SSTI Scanner** - Server-Side Template Injection
  - 8 template engines detected: Jinja2, Twig, ERB, FreeMarker, Velocity, Smarty, Mako, Pug, EJS
  - Polyglot detection payloads ({{7*7}}, ${7*7}, <%= 7*7 %>)
  - RCE payloads for each engine
  - Template engine fingerprinting
  - Blind SSTI detection via time-based
  - Wordlist: `wordlists/ssti.txt` (~120 payloads)

- **Prisma Support** - Enhanced dependency scanning
  - schema.prisma file parsing
  - Prisma registry integration (prismaisma.org)
  - CVE detection for Prisma providers

### Technical
- 5 new scanner modules (~2500 LOC)
- 5 new wordlists (~650 total payloads)
- Dependency scanner extended with Prisma ecosystem
- Binary size: 5.8 MB (optimized)

## [0.7.1] - 2026-03-15

### Fixed
- **Windows Self-Update** - Fixed "Access denied (os error 5)" error
  - Downloads new version to temporary directory
  - Creates detached batch script to replace binary after warden exits
  - Eliminates file lock issue on Windows PowerShell

### Added
- Documentation for v0.7.5 roadmap with advanced scanner plans

## [0.7.0] - 2026-03-15

### Added
- **Secrets Leak Scanner** - Hardcoded secrets detection
  - API keys: AWS, GitHub, GitLab, Bitbucket, Stripe, PayPal, Slack
  - Tokens: OAuth, JWT, Bearer tokens, API tokens
  - Passwords and credentials in code
  - Cryptographic keys and certificates
  - Database connection strings
  - Wordlist: `wordlists/secrets.txt`

- **Dependency Vulnerability Scanner** - CVE detection via OSV API
  - Rust (crates.io), Node.js (npm), Python (PyPI)
  - Go (modules), PHP (Packagist), Ruby (RubyGems)
  - Real-time CVE queries to OSV API
  - Severity mapping (CVSS score → VulnSeverity)
  - Automated update recommendations

- **Security Scoring System** - Hardcore grading (A+ to F)
  - 10 categories: Input Validation, Authentication, Cryptography, Headers, Session Management, Access Control, Data Protection, Error Handling, Communications, Code Quality
  - OWASP ASVS-inspired scoring
  - Grade calculation: A+ (95-100), A (90-94), B (80-89), C (70-79), D (60-69), E (50-59), F (0-49)
  - Penalties and bonuses system
  - Prioritized recommendations

- **HTML Reporter** - Interactive security reports
  - SVG charts: donut chart for score, radar chart for categories
  - Category breakdown with progress bars
  - Penalty and bonus details
  - Priority recommendations with impact
  - Responsive design with dark theme

### Added
- **New CLI Flags**
  - `--check-secrets` - Enable secrets scanning
  - `--check-deps` - Enable dependency vulnerability scanning
  - `--score` - Display security score
  - `--report-format html` - Generate HTML report

### Technical
- New `scoring` module with 10 sub-modules (~8200 LOC)
- Refactored scoring from single file to categories structure
- Binary size: 5.8 MB (optimized)

## [0.6.4] - 2026-03-15

### Added
- **Path Traversal Scanner** - Directory traversal detection
  - 200+ payloads for Linux and Windows
  - Various encodings (URL encoding, double encoding, Unicode)
  - Null byte injection
  - Wordlist: `wordlists/path_traversal.txt`

- **CORS Scanner** - CORS misconfiguration detection
  - Origin reflection testing
  - Null origin testing
  - Subdomain bypass testing
  - ACACO (Access-Control-Allow-Credentials) checks
  - Wordlist: `wordlists/cors_origins.txt`

- **Open Redirect Scanner** - URL redirection vulnerabilities
  - 85 payloads for redirect parameter testing
  - Parameter pollution
  - Subdomain bypass
  - JavaScript URI bypass
  - Wordlist: `wordlists/redirects.txt`

- **User Enumeration Scanner** - Timing and response analysis
  - Login timing analysis
  - Response diffing
  - Username variations
  - Wordlist: `wordlists/enumeration.txt`

- **Information Disclosure Scanner** - Sensitive info detection
  - Stack traces exposure
  - Debug information
  - Sensitive file exposure
  - Wordlist: `wordlists/sensitive_paths.txt`

### Technical
- Scoring system infrastructure (10 categories)
- 7 wordlists with 1190+ payloads
- OWASP coverage improved: ~70% → ~85%

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

[Unreleased]: https://github.com/Pamacea/warden/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/Pamacea/warden/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Pamacea/warden/compare/v0.7.5...v0.8.0
[0.7.5]: https://github.com/Pamacea/warden/compare/v0.7.1...v0.7.5
[0.7.1]: https://github.com/Pamacea/warden/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Pamacea/warden/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/Pamacea/warden/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/Pamacea/warden/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/Pamacea/warden/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Pamacea/warden/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Pamacea/warden/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Pamacea/warden/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Pamacea/warden/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Pamacea/warden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Pamacea/warden/releases/tag/v0.2.0
