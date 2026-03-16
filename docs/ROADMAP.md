# Warden Development Roadmap

## Current Version: v0.7.5 (In Progress - 2026-03-15)

### ✅ Completed - v0.7.x Series

#### v0.7.1 (2026-03-15)
- ✅ **Windows Update Fix** - Self-update mechanism without "Access denied" error
- ✅ Documentation for v0.7.5 roadmap

#### v0.7.0 Premium Edition (2026-03-15)
- ✅ **Secrets Leak Scanner** - Hardcoded API keys, tokens, passwords detection
- ✅ **Dependency Vulnerability Scanner** - CVE detection via OSV API
- ✅ **Security Scoring System** - 10 categories with grades A+ to F
- ✅ **HTML Reporter** - Interactive SVG charts with security score
- ✅ **New CLI Flags** - `--check-secrets`, `--check-deps`, `--score`, `--report-format html`
- ✅ **Binary Size** - Optimized to 5.8 MB

#### v0.6.4 (2025-03-15)
- ✅ **Path Traversal Scanner** - 200+ payloads for Linux/Windows
- ✅ **CORS Scanner** - Misconfiguration detection, origin reflection tests
- ✅ **Open Redirect Scanner** - 85 payloads, parameter pollution
- ✅ **User Enumeration Scanner** - Timing analysis, response diffing
- ✅ **Information Disclosure Scanner** - Stack traces, debug info
- ✅ **Wordlists Extended** - 1190+ payloads across 7 files

#### v0.5.0 (2025-03-15)
- ✅ **Reconnaissance Scanner**
- ✅ **Enhanced Report Formats** (HTML, SARIF, JSON, Markdown)
- ✅ **Responsive HTML design with dark theme**

---

## v0.7.5 - Advanced Security Scanners (Target: Q2 2026)

### 🎯 Scanners en développement

| Scanner | Status | Wordlist | Description |
|---------|--------|----------|-------------|
| **WAF Detection** | 🔄 In Progress | `waf_bypass.txt` (~200) | Cloudflare, AWS WAF, Akamai, ModSecurity fingerprinting |
| **GraphQL** | 🔄 In Progress | `graphql.txt` (~100) | Introspection, injection, batch queries, DoS |
| **SSRF** | 🔄 In Progress | `ssrf.txt` (~150) | Internal networks, cloud metadata, DNS rebinding |
| **XXE** | 🔄 In Progress | `xxe.txt` (~80) | File read, SSRF, DoS, blind OOB |
| **SSTI** | 🔄 In Progress | `ssti.txt` (~120) | Jinja2, Twig, ERB, FreeMarker, RCE |
| **Prisma** | 🔄 In Progress | - | schema.prisma parsing + prismaisma.org CVE API |

### 📦 Dependency Coverage

| Technologie | Support | Méthode |
|--------------|---------|---------|
| **Rust** | ✅ v0.7.0 | crates.io |
| **Node.js** | ✅ v0.7.0 | npm registry |
| **Python** | ✅ v0.7.0 | PyPI |
| **Go** | ✅ v0.7.0 | Go modules |
| **PHP** | ✅ v0.7.0 | Packagist |
| **Ruby** | ✅ v0.7.0 | RubyGems |
| **Prisma** | 🔄 v0.7.5 | prismaisma.org API |
| **TanStack** | ✅ v0.7.0 | Via npm |
| **React** | ✅ v0.7.0 | Via npm |

---

## v0.8.0 - Enterprise Features (Target: Q3 2026)

### Advanced Testing
- [ ] **Deserialization Scanner** - Java, Python, PHP, JSON, YAML
- [ ] **Race Condition Detector** - Concurrent request testing
- [ ] **Business Logic Scanner** - Price manipulation, coupon abuse, privilege escalation
- [ ] **File Upload Scanner** - MIME bypass, webshell upload, path traversal

### Protocol Support
- [ ] **WebSocket Scanner** - Message injection, DoS, authentication bypass
- [ ] **gRPC Scanner** - Protobuf fuzzing, reflection attack
- [ ] **SMB/NetBIOS Scanner** - Internal network reconnaissance
- [ ] **Redis/MongoDB Scanner** - NoSQL injection, authentication testing

### Cloud & Container
- [ ] **Docker Security** - Container escape, volume mounting, privileged mode
- [ ] **Kubernetes Scanner** - RBAC misconfig, pod escape, secrets exposure
- [ ] **Lambda/Serverless** - Injection in cloud functions
- [ ] **Terraform/TFSec** - IaC security scanning

### API Security
- [ ] **REST API Fuzzer** - OpenAPI/Swagger based testing
- [ ] **GraphQL Depth Limiting** - Query complexity analysis
- [ ] **gRPC Reflection** - Service discovery, proto dumping
- [ ] **WebSocket Channel Confusion** - Channel hijacking

---

## v0.9.0 - AI & Automation (Target: Q4 2026)

### Machine Learning
- [ ] **ML-based Detection** - Pattern recognition for zero-day
- [ ] **Smart Payload Selection** - Adaptive payload generation
- [ ] **False Positive Reduction** - Context-aware filtering
- [ ] **Risk Scoring Algorithm** - OWASP ML-based risk assessment

### Automation
- [ ] **Continuous Scanning** - Daemon mode, webhook integration
- [ ] **Smart Reconnaissance** - Automated attack surface discovery
- [ ] **Report Correlation** - Historical analysis, trend detection
- [ ] **Auto-Remediation** - Suggest and apply fixes

### CI/CD Integration
- [ ] **GitHub App** - Auto-scan on PR, security badges
- [ ] **GitLab Integration** - CI/CD pipeline scanning
- [ ] **Jenkins Plugin** - Build step integration
- [ ] **VS Code Extension** - Real-time security feedback

---

## v1.0.0 - Production Enterprise (Target: 2027)

### Distribution
- [ ] **Package Managers** - cargo, npm, pip, go install, brew, chocolatey
- [ ] **Pre-built Binaries** - 10+ platforms (Windows, Linux, macOS, ARM)
- [ ] **Verified Builds** - Reproducible builds, signing
- [ ] **Docker Images** - Multi-arch containers

### Enterprise Features
- [ ] **SAML/SSO** - Identity provider integration
- [ ] **RBAC** - Role-based access control
- [ ] **Audit Logging** - Compliance ready (SOC2, ISO27001)
- [ ] **SLA Guarantees** - Enterprise support contracts

### Compliance
- [ ] **OWASP ASVS** - Full Level 2 coverage
- [ ] **PCI DSS** - Payment card industry compliance
- [   ] **HIPAA** - Healthcare data protection
- [ ] **GDPR** - Privacy compliance scanning

### Advanced Features
- [ ] **Distributed Scanning** - Cluster mode, load balancing
- [ ] **Result Caching** - Incremental scanning, smart diffs
- [ ] **Custom Rules Engine** - User-defined vulnerability patterns
- [ ] **Plugin System** - Community-contributed scanners

---

*Last updated: 2026-03-15*
