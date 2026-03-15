# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Pamacea/warden/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Pamacea/warden/releases/tag/v0.2.0

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

[Unreleased]: https://github.com/Pamacea/warden/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Pamacea/warden/releases/tag/v0.2.0
