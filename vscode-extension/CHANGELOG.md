# Warden VS Code Extension Changelog

## [0.8.0] - 2025-03-16

### Added

- Initial release of Warden VS Code Extension
- Real-time security scanning for JavaScript, TypeScript, Python, and Rust
- OWASP Top 10 vulnerability detection
- Secrets leak detection (API keys, tokens, credentials)
- Dependency vulnerability scanning
- Inline code warnings with severity indicators
- Security findings panel with grouped views
- Security dashboard with visual metrics
- Scan on save and scan on open options
- Multiple scan modes (Passive, Active, Stealth, Aggressive)
- URL scanning capability
- Quick fixes for common security issues
- Ignoring findings functionality
- Configuration through VS Code settings
- Status bar integration
- Command palette commands
- Context menu integration

### Features

- **File Scanning**: Scan individual files or entire projects
- **URL Scanning**: Scan web applications directly from VS Code
- **Diagnostics Integration**: Native VS Code diagnostics for vulnerabilities
- **Tree View**: Findings organized by severity or file
- **Dashboard**: Webview panel with security metrics and insights
- **Code Actions**: Quick fixes for applicable vulnerabilities
- **Configuration**: Comprehensive settings for all aspects
- **Notifications**: Configurable notifications per severity level

### Configuration

- `warden.enabled` - Enable/disable extension
- `warden.executablePath` - Path to Warden CLI
- `warden.scanOnSave` - Auto-scan on file save
- `warden.scanOnOpen` - Auto-scan on file open
- `warden.showInlineWarnings` - Show warnings in editor
- `warden.severityLevel` - Minimum severity to report
- `warden.timeout` - Scan timeout in milliseconds
- `warden.maxConcurrentScans` - Maximum parallel scans
- `warden.scanMode` - Scanning mode (Passive/Active/Stealth/Aggressive)
- `warden.enableSecretsDetection` - Enable secrets scanning
- `warden.enableDependencyCheck` - Enable dependency scanning
- `warden.ignorePatterns` - Glob patterns to ignore
- `warden.notifications` - Per-severity notification settings
- `warden.panel.position` - Panel position (bottom/right)
- `warden.autoRefresh` - Auto-refresh findings on changes

### Commands

- `warden.scanCurrentFile` - Scan active file
- `warden.scanProject` - Scan entire workspace
- `warden.scanUrl` - Scan a URL
- `warden.showFindings` - Open findings panel
- `warden.refreshFindings` - Refresh findings
- `warden.clearFindings` - Clear all findings
- `warden.configureWarden` - Open settings
- `warden.ignoreFinding` - Ignore a finding
- `warden.copyFindingId` - Copy finding ID
- `warden.applyQuickFix` - Apply quick fix
- `warden.showDashboard` - Open security dashboard

### Supported Languages

- JavaScript / JSX
- TypeScript / TSX
- Python
- Rust

## [0.1.0] - Unreleased

### Planned Features

- SARIF export integration
- Custom rule support
- Team findings sharing
- Historical scan comparison
- CI/CD integration helpers
- Additional language support
- Performance optimizations
- False positive management
- Rule customization
- API security testing
