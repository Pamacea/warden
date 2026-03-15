# Warden

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/warden-sec)](https://crates.io/crates/warden-sec)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org/)


AI-powered security review CLI tool for web applications. 100% Rust, zero dependencies.

**Features:**
- Multi-framework support: NestJS, Rust, Vite, Express, Fastify, Django, Flask, FastAPI, Go, Spring Boot
- Native scanners: HTTP, Port, Static Analysis, DDoS resistance testing
- OWASP Top 10 2021: 100% coverage
- Single binary, no runtime dependencies

## Quick Start

### Installation

```bash
cargo install warden-sec
```

### Usage

```bash
# In your project directory
warden scan

# External target
warden scan https://example.com

# With options
warden scan --aggressive --include-ddos
```

## What It Tests

### Framework-Specific
- **NestJS**: Guard bypass, pipe injection, GraphQL introspection, WebSocket auth, throttler bypass
- **Rust**: Unsafe blocks, integer overflow, Serde RCE, actix/axum vulnerabilities
- **Vite**: HMR injection, source map leaks, dependency pre-bundling, env var leakage

### General Vulnerabilities
- **Injection**: SQLi, NoSQL, SSTI, XXE, LDAP, Command injection
- **Cross-Site**: XSS (reflected, stored, DOM), CSRF, CORS misconfig
- **Server-Side**: SSRF, deserialization, path traversal, file upload
- **Auth**: Authentication bypass, privilege escalation, IDOR, JWT manipulation
- **DoS**: ReDoS, GraphQL deep nesting, HTTP flood, Slowloris, connection exhaustion

## Included Scanners

| Scanner | Type | Speed |
|---------|------|-------|
| HTTP | Native Rust | ⚡⚡⚡ |
| Port | Native Rust | ⚡⚡⚡ |
| Static Analysis | AST-based | ⚡⚡ |
| DDoS | Native Rust | ⚡⚡⚡ |
| Stress | Native Rust | ⚡⚡⚡ |

## Safety

- Always test against dev/staging first
- Never test production without written authorization
- Backup your code (use git)

## License

MIT — Use at your own risk. Only test systems you own or have explicit permission to test.

## Credits

Inspired by [Guardian](https://github.com/Pamacea/guardian) - The original Node.js + Docker version.
