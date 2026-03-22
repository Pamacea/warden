# Oalacea Warden User Guide

## Installation

### Via cargo (Recommended)

```bash
cargo install oalacea-warden
```

### Via Pre-built Binary

Download from [GitHub Releases](https://github.com/Pamacea/warden/releases/latest)

| Platform | Binary |
|----------|--------|
| Windows x64 | `oalacea-warden-x86_64-pc-windows-msvc.exe` |
| macOS x64 | `oalacea-warden-x86_64-apple-darwin` |
| macOS ARM | `oalacea-warden-aarch64-apple-darwin` |
| Linux x64 | `oalacea-warden-x86_64-unknown-linux-gnu` |

### Via Package Manager

```bash
# Homebrew (macOS/Linux)
brew install oalacea-warden

# Scoop (Windows)
scoop install oalacea-warden

# AUR (Arch Linux)
yay -S oalacea-warden
```

## Quick Start

### Basic Scan

```bash
# Scan current directory
oalacea-warden scan

# Scan external target
oalacea-warden scan https://example.com

# Scan specific directory
oalacea-warden scan /path/to/project
```

### With Options

```bash
# Aggressive mode (more tests, longer duration)
oalacea-warden scan --aggressive

# Include DDoS resistance testing
oalacea-warden scan --include-ddos

# JSON output for CI/CD
oalacea-warden scan --format json > report.json

# Verbose output
oalacea-warden scan --verbose

# Save report to file
oalacea-warden scan --output report.md
```

## Commands

### `oalacea-warden scan`

Scan a target for vulnerabilities.

```bash
oalacea-warden scan [OPTIONS] [TARGET]
```

**Arguments:**
- `TARGET` - URL or directory to scan (default: current directory)

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--aggressive` | Enable aggressive scanning mode | false |
| `--include-ddos` | Include DDoS resistance testing | false |
| `--include-stress` | Include stress testing | false |
| `--format` | Output format: console, json, markdown | console |
| `--output` | Save report to file | - |
| `--timeout` | Request timeout in seconds | 5 |
| `--concurrency` | Concurrent requests | 50 |
| `--verbose, -v` | Verbose output | false |
| `--help, -h` | Print help | - |

### `oalacea-warden detect`

Detect framework and language without scanning.

```bash
oalacea-warden detect [PATH]
```

**Example:**
```bash
$ oalacea-warden detect
Detected:
  Language: Rust
  Framework: Axum
  Edition: 2021
  Package Manager: Cargo
```

### `oalacea-warden version`

Display version information.

```bash
oalacea-warden --version
# or
oalacea-warden -V
```

## Output Formats

### Console (Default)

```bash
$ oalacea-warden scan

╔═══════════════════════════════════════╗
║   Oalacea Warden v0.8.2              ║
║   Security Review                     ║
╚═══════════════════════════════════════╝

Scanning http://localhost:3000...

┌─────────────────────────────────────────┐
│ HTTP Scanner                            │
├─────────────────────────────────────────┤
│ ✓ XSS Testing                          │
│ ✓ Security Headers                     │
│ ⚠ SSRF Testing                         │
│   → Potential SSRF in /api/fetch       │
└─────────────────────────────────────────┘

Summary: 2 findings (1 high, 1 medium)
```

### JSON

```bash
$ oalacea-warden scan --format json
{
  "version": "0.8.2",
  "target": "http://localhost:3000",
  "timestamp": "2025-03-14T10:30:00Z",
  "findings": [
    {
      "severity": "HIGH",
      "title": "XSS Vulnerability",
      "description": "Reflected XSS in search parameter",
      "location": "/api/search?q="
    }
  ],
  "summary": {
    "total": 2,
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0
  }
}
```

### Markdown

```bash
$ oalacea-warden scan --format markdown --output report.md
```

Generates a detailed markdown report with:
- Executive summary
- Detailed findings
- Remediation recommendations
- Test coverage

## Framework-Specific Features

### NestJS

```bash
# Oalacea Warden auto-detects NestJS and runs:
# - Guard bypass testing
# - Pipe injection testing
# - GraphQL introspection
# - WebSocket authentication
# - Throttler bypass

oalacea-warden scannestjs-project/
```

### Rust

```bash
# Runs Rust-specific checks:
# - Unsafe block analysis
# - Integer overflow detection
# - Serde deserialization RCE
# - Framework-specific (Axum, Actix, Rocket)

oalacea-warden scanrust-project/
```

### Vite

```bash
# Runs Vite-specific checks:
# - HMR websocket exposure
# - Source map leaks
# - Environment variable leakage
# - Dev server detection

oalacea-warden scanvite-project/
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/install@v0
        with:
          crate: oalacea-warden
          use-tool-cache: true
      - run: oalacea-warden scan --format json --output report.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
```

### GitLab CI

```yaml
security:
  image: rust:latest
  script:
    - cargo install oalacea-warden
    - oalacea-warden scan --format json --output report.json
  artifacts:
    paths:
      - report.json
```

## Advanced Usage

### Custom Wordlists

```bash
oalacea-warden scan --wordlist /path/to/custom.txt
```

### Exclude Paths

```bash
oalacea-warden scan --exclude node_modules --exclude dist
```

### Rate Limiting

```bash
oalacea-warden scan --rate-limit 100  # Max 100 requests/second
```

### Timeout Control

```bash
oalacea-warden scan --timeout 10  # 10 second timeout per request
```

## Troubleshooting

### Permission Denied

```bash
# On Unix-like systems
chmod +x oalacea-warden

# Or install via cargo
cargo install oalacea-warden
```

### Port Already in Use

```bash
# Warden doesn't bind ports, but if you see errors:
# Check if your target is running
curl http://localhost:3000
```

### Slow Scanning

```bash
# Reduce concurrency for slower targets
oalacea-warden scan --concurrency 10

# Or increase for faster networks
oalacea-warden scan --concurrency 100
```

### Memory Issues

```bash
# Oalacea Warden uses ~50-100MB normally. If more:
# Check for memory leaks in your target
# Reduce concurrency
oalacea-warden scan --concurrency 10
```

## Best Practices

1. **Start with non-aggressive mode**
   ```bash
   oalacea-warden scan
   # Then if needed:
   oalacea-warden scan --aggressive
   ```

2. **Always scan dev/staging first**
   ```bash
   oalacea-warden scan http://localhost:3000
   # Before:
   oalacea-warden scan https://production.example.com
   ```

3. **Save reports for comparison**
   ```bash
   oalacea-warden scan --output report-$(date +%Y%m%d).md
   ```

4. **Use JSON for CI/CD**
   ```bash
   oalacea-warden scan --format json | jq '.findings | length'
   ```

5. **Review findings carefully**
   - False positives can occur
   - Context matters for severity
   - Always verify before fixing

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no vulnerabilities |
| 1 | Vulnerabilities found |
| 2 | Error occurred |
| 3 | Interrupted by user |

## Examples

### Scan REST API

```bash
oalacea-warden scan https://api.example.com --aggressive
```

### Scan GraphQL Endpoint

```bash
oalacea-warden scan https://graphql.example.com --include-graphql
```

### Scan Multi-Service Project

```bash
oalacea-warden scan ./microservices --concurrency 100
```

### Generate SARIF Report for GitHub Security

```bash
oalacea-warden scan --format json --output sarif.json
# Convert to SARIF with external tool
```

## Support

- **Issues**: [GitHub Issues](https://github.com/Pamacea/warden/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Pamacea/warden/discussions)
- **Docs**: [Full Documentation](https://warden.secure.dev)
