# Warden

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/warden-sec)](https://crates.io/crates/warden-sec)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org/)

**AI-powered security review CLI tool for web applications.** 100% Rust, zero dependencies.

## Features

- **50+ Frameworks Detected** - React, Angular, Vue, NestJS, Express, Prisma, Mongoose, Drizzle, Docker, Kubernetes, and more
- **5 Scanning Modes** - Passive, Active, Stealth, Aggressive, Custom profiles
- **Native Scanners** - HTTP, Port, Static Analysis, DDoS resistance, Stress testing
- **OWASP Top 10 2021** - 100% coverage
- **AI Agent Integration** - Auto-saves `WARDEN_SECURITY_REPORT.md` for Claude Code and other AI agents
- **Zero Dependencies** - Single binary, no runtime dependencies
- **314 Tests** - Comprehensive test coverage

## Supported Technologies

### Frontend Frameworks
React, Angular, Vue.js, SvelteKit, Remix, Next.js, Nuxt, Vite

### Backend Frameworks
NestJS, Express, Fastify, Hono, Koa, Actix-Web, Axum, Rocket, Django, Flask, FastAPI, Gin, Echo, Fiber, Spring Boot

### ORM & Database
Prisma, Mongoose, Drizzle, Sequelize, TypeORM, MikroORM, Knex, PostgreSQL, MongoDB, MariaDB, Redis, SQLite

### Authentication
NextAuth, Better Auth, Clerk, Supabase Auth

### State Management
Zustand, Redux, TanStack Query

### Testing
Jest, Vitest, Playwright, Cypress

### API
GraphQL, Apollo, Altair, GraphQL Yoga

### Infrastructure
Docker, Kubernetes, Vercel, Cloudflare Workers

### Styling
Tailwind, shadcn/ui, Chakra UI, Mantine

## Quick Start

### Installation

```bash
# Install from crates.io
cargo install warden-sec

# Or build from source
cargo install --path .
```

### Usage

```bash
# In your project directory
warden scan

# External target
warden scan https://example.com

# With options
warden scan --aggressive --include-ddos

# Use a profile
warden scan --profile thorough

# Passive mode (no active requests)
warden scan --mode passive

# AI-optimized format (for Claude Code and other AI agents)
warden scan --format ai

# Generate JSON fix data for automated processing
warden scan --format ai --generate-fixes
```

## AI Agent Integration

Warden automatically saves `WARDEN_SECURITY_REPORT.md` in the scanned directory, optimized for AI agents like Claude Code:

```bash
# Just run a scan - report is auto-saved
warden scan

# Claude Code can now:
# 1. Read WARDEN_SECURITY_REPORT.md
# 2. Navigate to files using provided paths and line numbers
# 3. Fix vulnerabilities
# 4. Re-run scan to verify
```

**Report Features for AI Agents:**
- 📁 **Files to Fix** - Grouped by file with issue counts
- 🔍 **Detailed Findings** - With clickable `file:line` paths
- 🤖 **Suggested Fix Order** - Priority-based phases
- 📊 **Structured JSON** - With `--generate-fixes` for programmatic processing

**Example AI Workflow:**
```markdown
1. warden scan --format ai
2. # AI reads WARDEN_SECURITY_REPORT.md
3. # AI fixes src/main.rs:42 (SQL Injection)
4. # AI fixes src/auth.rs:15 (Missing auth)
5. warden scan --format ai  # Verify fixes
```

## Scanning Modes

| Mode | Description | Speed | Detection Risk |
|------|-------------|-------|----------------|
| **Passive** | Static analysis only | ⚡⚡⚡ | None |
| **Active** | Standard testing | ⚡⚡ | Low |
| **Stealth** | Low-and-slow | ⚡ | Very Low |
| **Aggressive** | Full testing | ⚡⚡⚡ | Medium |

## Profiles

```bash
# Quick scan (2s timeout, 25 concurrent)
warden scan --profile quick

# Standard scan (5s timeout, 50 concurrent)
warden scan --profile standard

# Thorough scan (15s timeout, 100 concurrent, aggressive)
warden scan --profile thorough

# Stealth scan (30s timeout, 5 concurrent)
warden scan --profile stealth

# Aggressive scan (10s timeout, 200 concurrent)
warden scan --profile aggressive
```

## What It Tests

### Framework-Specific Vulnerabilities
- **React/NestJS**: XSS via state, guard bypass, pipe injection
- **Prisma/Drizzle**: SQL injection, raw query analysis
- **Mongoose**: NoSQL injection, prototype pollution
- **NextAuth/Clerk**: Token leaks, session misconfig
- **Docker/Kubernetes**: Secrets in configs, exposed ports
- **GraphQL**: Introspection, depth limiting DoS

### General Vulnerabilities
- **Injection**: SQLi, NoSQL, SSTI, XXE, LDAP, Command injection
- **Cross-Site**: XSS (reflected, stored, DOM), CSRF, CORS misconfig
- **Server-Side**: SSRF, deserialization, path traversal, file upload
- **Auth**: Authentication bypass, privilege escalation, IDOR, JWT manipulation
- **DoS**: ReDoS, GraphQL deep nesting, HTTP flood, Slowloris

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
