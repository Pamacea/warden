# Warden User Guide

## Installation

### Via cargo (Recommended)

```bash
cargo install warden
```

### Via Pre-built Binary

Download from [GitHub Releases](https://github.com/Pamacea/warden/releases/latest)

| Platform | Binary |
|----------|--------|
| Windows x64 | `warden-x86_64-pc-windows-msvc.exe` |
| macOS x64 | `warden-x86_64-apple-darwin` |
| macOS ARM | `warden-aarch64-apple-darwin` |
| Linux x64 | `warden-x86_64-unknown-linux-gnu` |

### Via Package Manager

```bash
# Homebrew (macOS/Linux)
brew install warden

# Scoop (Windows)
scoop install warden

# AUR (Arch Linux)
yay -S warden
```

## Quick Start

### Basic Scan

```bash
# Scan current directory
warden scan

# Scan external target
warden scan https://example.com

# Scan specific directory
warden scan /path/to/project
```

### With Options

```bash
# Aggressive mode (more tests, longer duration)
warden scan --aggressive

# Include DDoS resistance testing
warden scan --include-ddos

# JSON output for CI/CD
warden scan --format json > report.json

# Verbose output
warden scan --verbose

# Save report to file
warden scan --output report.md
```

## Commands

### `warden scan`

Scan a target for vulnerabilities.

```bash
warden scan [OPTIONS] [TARGET]
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

### `warden detect`

Detect framework and language without scanning.

```bash
warden detect [PATH]
```

**Example:**
```bash
$ warden detect
Detected:
  Language: Rust
  Framework: Axum
  Edition: 2021
  Package Manager: Cargo
```

### `warden version`

Display version information.

```bash
warden --version
# or
warden -V
```

## Output Formats

### Console (Default)

```bash
$ warden scan

╔═══════════════════════════════════════╗
║   Warden v0.2.0                       ║
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
$ warden scan --format json
{
  "version": "0.2.0",
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
$ warden scan --format markdown --output report.md
```

Generates a detailed markdown report with:
- Executive summary
- Detailed findings
- Remediation recommendations
- Test coverage

## Framework-Specific Features

### NestJS

```bash
# Guardian auto-detects NestJS and runs:
# - Guard bypass testing
# - Pipe injection testing
# - GraphQL introspection
# - WebSocket authentication
# - Throttler bypass

warden scannestjs-project/
```

### Rust

```bash
# Runs Rust-specific checks:
# - Unsafe block analysis
# - Integer overflow detection
# - Serde deserialization RCE
# - Framework-specific (Axum, Actix, Rocket)

warden scanrust-project/
```

### Vite

```bash
# Runs Vite-specific checks:
# - HMR websocket exposure
# - Source map leaks
# - Environment variable leakage
# - Dev server detection

warden scanvite-project/
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
          crate: warden
          use-tool-cache: true
      - run: warden scan --format json --output report.json
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
    - cargo install warden
    - warden scan --format json --output report.json
  artifacts:
    paths:
      - report.json
```

## Advanced Usage

### Custom Wordlists

```bash
warden scan --wordlist /path/to/custom.txt
```

### Exclude Paths

```bash
warden scan --exclude node_modules --exclude dist
```

### Rate Limiting

```bash
warden scan --rate-limit 100  # Max 100 requests/second
```

### Timeout Control

```bash
warden scan --timeout 10  # 10 second timeout per request
```

## Troubleshooting

### Permission Denied

```bash
# On Unix-like systems
chmod +x warden

# Or install via cargo
cargo install warden
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
warden scan --concurrency 10

# Or increase for faster networks
warden scan --concurrency 100
```

### Memory Issues

```bash
# Warden uses ~50-100MB normally. If more:
# Check for memory leaks in your target
# Reduce concurrency
warden scan --concurrency 10
```

## Best Practices

1. **Start with non-aggressive mode**
   ```bash
   warden scan
   # Then if needed:
   warden scan --aggressive
   ```

2. **Always scan dev/staging first**
   ```bash
   warden scan http://localhost:3000
   # Before:
   warden scan https://production.example.com
   ```

3. **Save reports for comparison**
   ```bash
   warden scan --output report-$(date +%Y%m%d).md
   ```

4. **Use JSON for CI/CD**
   ```bash
   warden scan --format json | jq '.findings | length'
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
warden scan https://api.example.com --aggressive
```

### Scan GraphQL Endpoint

```bash
warden scan https://graphql.example.com --include-graphql
```

### Scan Multi-Service Project

```bash
warden scan ./microservices --concurrency 100
```

### Generate SARIF Report for GitHub Security

```bash
warden scan --format json --output sarif.json
# Convert to SARIF with external tool
```

## Support

- **Issues**: [GitHub Issues](https://github.com/Pamacea/warden/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Pamacea/warden/discussions)
- **Docs**: [Full Documentation](https://warden.secure.dev)
