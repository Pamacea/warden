# Warden Security - VS Code Extension

[![Version](https://img.shields.io/visual-studio-marketplace/v/warden-security.warden-security)](https://marketplace.visualstudio.com/items?itemName=warden-security.warden-security)
[![Rating](https://img.shields.io/visual-studio-marketplace/r/warden-security.warden-security)](https://marketplace.visualstudio.com/items?itemName=warden-security.warden-security)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/warden-security.warden-security)](https://marketplace.visualstudio.com/items?itemName=warden-security.warden-security)

AI-powered security review tool for web applications - Real-time vulnerability scanning and security insights directly in VS Code.

## Features

### Real-time Security Scanning

- **On-Demand Scanning**: Scan current file or entire project with a single command
- **Automatic Scanning**: Configure automatic scans on save or file open
- **URL Scanning**: Scan web applications directly from VS Code

### Vulnerability Detection

- **OWASP Top 10**: Detects common web vulnerabilities
- **Secrets Detection**: Find leaked API keys, tokens, and credentials
- **Dependency Scanning**: Identify vulnerable dependencies
- **Static Analysis**: AST-based code analysis for JavaScript, TypeScript, Python, and Rust

### Visual Feedback

- **Inline Warnings**: See security issues directly in your code
- **Diagnostics Panel**: Full list of findings with severity levels
- **Security Dashboard**: Visual overview of your project's security posture
- **Code Actions**: Quick fixes for common security issues

### Scan Modes

- **Passive**: No active requests, static analysis only
- **Active**: Full testing with standard checks
- **Stealth**: Low and slow, minimizes detection
- **Aggressive**: Thorough testing with all checks

## Installation

### From Marketplace

1. Open VS Code
2. Press `Ctrl+Shift+X` to open Extensions
3. Search for "Warden Security"
4. Click Install

### From Source

1. Clone the repository
2. Install dependencies:
   ```bash
   cd vscode-extension
   npm install
   ```
3. Compile the extension:
   ```bash
   npm run compile
   ```
4. Press F5 to launch in Extension Development Host

## Usage

### Basic Commands

| Command | Description |
|---------|-------------|
| `Warden: Scan Current File` | Scan the currently active file |
| `Warden: Scan Project` | Scan the entire workspace |
| `Warden: Scan URL` | Scan a web application URL |
| `Warden: Show Findings Panel` | Open the security findings sidebar |

### Configuration

Configure Warden through VS Code settings (`settings.json`):

```json
{
  // Enable Warden
  "warden.enabled": true,

  // Warden executable path
  "warden.executablePath": "warden",

  // Automatic scanning
  "warden.scanOnSave": true,
  "warden.scanOnOpen": false,

  // Minimum severity to report
  "warden.severityLevel": "Low",

  // Scanning mode
  "warden.scanMode": "Active",

  // Enable premium features
  "warden.enableSecretsDetection": true,
  "warden.enableDependencyCheck": true,

  // Ignore patterns
  "warden.ignorePatterns": [
    "node_modules/**",
    "dist/**",
    "*.min.js"
  ]
}
```

### Supported Languages

- JavaScript / JSX
- TypeScript / TSX
- Python
- Rust

## Requirements

- [Warden CLI](https://github.com/Pamacea/warden) must be installed and accessible in your PATH
- VS Code 1.85.0 or higher

## Installing Warden CLI

### Cargo (Recommended)

```bash
cargo install warden-sec
```

### From Release

Download the latest release from [GitHub Releases](https://github.com/Pamacea/warden/releases).

### Building from Source

```bash
git clone https://github.com/Pamacea/warden.git
cd warden
cargo install --path .
```

## Development

### Project Structure

```
vscode-extension/
├── src/
│   ├── extension.ts       # Main extension entry point
│   ├── types.ts           # TypeScript type definitions
│   ├── config.ts          # Configuration management
│   ├── warden-cli.ts      # Warden CLI interface
│   ├── diagnostic-manager.ts  # VS Code diagnostics
│   ├── findings-provider.ts   # Tree view provider
│   ├── dashboard-panel.ts     # Security dashboard
│   └── scanner.ts         # Scan orchestration
├── package.json           # Extension manifest
├── tsconfig.json          # TypeScript configuration
└── README.md              # This file
```

### Building

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run compile

# Watch for changes
npm run watch

# Run linter
npm run lint

# Run tests
npm test
```

### Publishing

```bash
# Install vsce
npm install -g @vscode/vsce

# Package extension
vsce package

# Publish to marketplace
vsce publish
```

## Contributing

Contributions are welcome! Please read our [contributing guidelines](../../CONTRIBUTING.md) before submitting PRs.

## License

MIT License - see [LICENSE](../../LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Pamacea/warden/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Pamacea/warden/discussions)
- **Documentation**: [Full Documentation](https://warden.pamacea.com)

## Changelog

See [CHANGELOG.md](../../CHANGELOG.md) for version history.

## Related Projects

- [Warden CLI](https://github.com/Pamacea/warden) - The core security scanning tool
- [Warden GitHub Action](https://github.com/marketplace/actions/warden-security-scan) - CI/CD integration

---

Made with ❤️ by the Warden Security Team
