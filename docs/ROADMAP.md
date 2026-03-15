# Warden Development Roadmap

## Current Version: v0.3.0 (2025-03-15)

### ✅ Completed
- Everything from v0.2.0
- **HTTP Scanner Enhancements**
  - ✅ Advanced XSS payloads (DOM-based, blind XSS)
  - ✅ SQL injection detection (error-based, blind, time-based)
  - ✅ NoSQL injection detection (MongoDB, Redis, CouchDB, JSON)
  - ✅ CSRF token analysis
  - ✅ Clickjacking detection (X-Frame-Options bypass detection)
  - ✅ Open redirect detection
- **Port Scanner Enhancements**
  - ✅ Enhanced version detection (50+ patterns)
  - ✅ Banner grabbing for all common services
  - ✅ UDP port scanning support
  - ✅ Custom port ranges support
- **Static Analysis Enhancements**
  - ✅ TypeScript support (any types, ts-ignore, non-null assertions)
  - ✅ Go support (command injection, SQLi, ReadAll DoS, crypto)
  - ✅ Java support (Statement SQLi, Runtime.exec, unsafe deserialization)
  - ✅ PHP support (eval, exec, SQLi, unserialize, file inclusion, weak hashing)

---

## v0.4.0 - Authentication & API Testing (Target: Q2 2025)

## v0.4.0 - Authentication & API Testing (Target: Q3 2025)

### Authentication Testing
- [ ] JWT token analysis and manipulation
- [ ] OAuth 2.0 flow testing
- [ ] Session fixation detection
- [ ] Privilege escalation detection
- [ ] IDOR (Insecure Direct Object Reference) detection

### API Testing
- [ ] GraphQL introspection and depth limiting
- [ ] REST API parameter tampering
- [ ] API versioning issues
- [ ] Rate limiting detection
- [ ] Mass assignment detection

### WebSocket Testing
- [ ] WebSocket connection security
- [ ] Message injection
- [ ] DoS via rapid messages

---

## v0.5.0 - Intelligence & Reporting (Target: Q3 2025)

### Passive Reconnaissance
- [ ] Subdomain enumeration
- [ ] DNS reconnaissance
- [ ] Certificate transparency search
- [ ] Wayback machine scraping
- [ ] GitHub dorking for secrets

### Active Reconnaissance
- [ ] Directory fuzzing
- [ ] Endpoint discovery
- [ ] JavaScript file analysis
- [ ] Comment discovery
- [ ] Backup file discovery

### Reporting
- [ ] HTML reports with interactive findings
- [ ] PDF export
- [ ] SARIF format for GitHub Security
- [ ] JIRA integration
- [ ] Slack notification support

---

## v0.6.0 - Production Ready (Target: Q4 2025)

### Scanning Modes
- [ ] Passive mode (no active requests)
- [ ] Active mode (full testing)
- [ ] Stealth mode (low and slow)
- [ ] Aggressive mode (thorough testing)

### Configuration
- [ ] Profile-based configuration
- [ ] Custom scanner chains
- [ ] Exclusion patterns
- [ ] Rate limiting profiles
- [ ] Authentication profiles

### Performance & Scale
- [ ] Distributed scanning
- [ ] Result caching
- [ ] Incremental scanning
- [ ] Smart concurrency
- [ ] Large project support (>100k LOC)

### Integration
- [ ] CI/CD pipeline integration
- [ ] GitHub App
- [ ] GitLab integration
- [ ] Jenkins plugin
- [ ] VS Code extension

### Advanced Vulnerabilities
- [ ] Business logic detection (price manipulation, coupon abuse)
- [ ] Race condition detection
- [ ] Deserialization testing (Java, Python, PHP, JSON)
- [ ] File upload vulnerabilities

### AI Features
- [ ] ML-based vulnerability detection
- [ ] Smart payload selection
- [ ] Adaptive scanning
- [ ] False positive reduction
- [ ] Risk scoring algorithm

### Distribution
- [ ] All major package managers
- [ ] Pre-built binaries for 10+ platforms
- [ ] Verified builds
- [ ] Reproducible builds
- [ ] Signed releases

### Stability
- [ ] 100% test coverage
- [ ] Comprehensive documentation
- [ ] SLA guarantees
- [ ] Enterprise support
- [ ] Security audit

---

*Last updated: 2025-03-15*
