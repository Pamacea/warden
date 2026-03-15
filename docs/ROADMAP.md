# Warden Development Roadmap

## Current Version: v0.5.0 (2025-03-15)

### ✅ Completed
- Everything from v0.4.0
- **Reconnaissance Scanner** (New module)
  - ✅ Passive reconnaissance (backup file detection, config exposure, sensitive files)
  - ✅ Active reconnaissance (directory fuzzing, endpoint discovery)
  - ✅ Backup file enumeration (.bak, .old, .orig, ~, .swp)
  - ✅ Configuration file exposure (.env, config.json, docker-compose.yml)
  - ✅ Directory listing detection
  - ✅ Hidden directory and file discovery
  - ✅ API endpoint enumeration
  - ✅ HTML/JavaScript comment extraction for sensitive info

- **Enhanced Report Formats**
  - ✅ HTML reports with interactive UI, filtering, keyboard shortcuts
  - ✅ SARIF format for GitHub Security integration
  - ✅ Enhanced JSON and Markdown reports
  - ✅ Responsive HTML design with dark theme

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
