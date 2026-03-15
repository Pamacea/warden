# Warden Development Roadmap

## Current Version: v0.4.0 (2025-03-15)

### ✅ Completed
- Everything from v0.3.0
- **HTTP Scanner Enhancements**
  - ✅ JWT token analysis and manipulation (algorithm, expiration, sensitive data)
  - ✅ OAuth 2.0 flow testing (PKCE, state parameter, implicit grant)
  - ✅ Session fixation detection
  - ✅ Session cookie security flags (HttpOnly, Secure, SameSite)

- **API Security Scanner** (New module)
  - ✅ GraphQL introspection and depth limiting detection
  - ✅ REST API parameter tampering detection
  - ✅ IDOR (Insecure Direct Object Reference) detection
  - ✅ Mass assignment vulnerability detection
  - ✅ API versioning issues detection
  - ✅ WebSocket security testing (WSS vs WS, origin validation)
  - ✅ Parameter pollution testing

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
