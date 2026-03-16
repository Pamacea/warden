# Warden VS Code Extension - Installation Guide

## Quick Start

### 1. Install Warden CLI

The extension requires the Warden CLI to be installed on your system.

#### Option A: Install via Cargo (Recommended)

```bash
cargo install warden-sec
```

#### Option B: Download Pre-built Binary

Download the latest release from:
- [GitHub Releases](https://github.com/Pamacea/warden/releases)

Extract and add to your PATH.

#### Option C: Build from Source

```bash
git clone https://github.com/Pamacea/warden.git
cd warden
cargo install --path .
```

### 2. Verify Installation

```bash
warden --version
```

You should see output like: `warden 0.8.0`

### 3. Install VS Code Extension

#### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X` or `Cmd+Shift+X`)
3. Search for "Warden Security"
4. Click "Install"

#### From Local File

1. Build the extension:
   ```bash
   cd vscode-extension
   npm install
   npm run compile
   npm run package
   ```

2. In VS Code:
   - Go to Extensions → Click "..." → "Install from VSIX..."
   - Select the generated `.vsix` file

### 4. Configure (Optional)

Open VS Code Settings and search for "Warden":

```json
{
  "warden.scanOnSave": true,
  "warden.severityLevel": "Low",
  "warden.scanMode": "Active"
}
```

## Usage

### Scan Current File

- Command Palette: `Warden: Scan Current File`
- Or press the shield icon in the editor title bar

### Scan Project

- Command Palette: `Warden: Scan Project`
- Right-click folder in Explorer → "Warden: Scan Project"

### View Findings

- Open the "Warden Security" panel in the Activity Bar
- Findings are grouped by severity (Critical, High, Medium, Low, Info)

## Troubleshooting

### "Warden CLI not found"

1. Verify Warden is installed: `warden --version`
2. Check it's in your PATH: `which warden` (Linux/Mac) or `where warden` (Windows)
3. Set custom path in settings:
   ```json
   {
     "warden.executablePath": "/full/path/to/warden"
   }
   ```

### Scans timing out

Increase the timeout setting:
```json
{
  "warden.timeout": 60000
}
```

### Too many false positives

Adjust minimum severity:
```json
{
  "warden.severityLevel": "Medium"
}
```

Add ignore patterns:
```json
{
  "warden.ignorePatterns": [
    "test/**",
    "examples/**"
  ]
}
```

## Advanced Configuration

### Scan Modes

- **Passive**: Static analysis only, no active requests
- **Active**: Full security testing (default)
- **Stealth**: Slow scanning to avoid detection
- **Aggressive**: Maximum thoroughness

### Notifications

Configure notifications per severity:
```json
{
  "warden.notifications": {
    "onCritical": true,
    "onHigh": true,
    "onMedium": false,
    "onLow": false,
    "onInfo": false
  }
}
```

### Panel Position

```json
{
  "warden.panel.position": "right"  // or "bottom"
}
```

## Development

For extension development:

```bash
cd vscode-extension
npm install
npm run watch
```

Then press F5 to open a new VS Code window with the extension loaded.

## Support

- [Documentation](https://warden.pamacea.com)
- [GitHub Issues](https://github.com/Pamacea/warden/issues)
- [Discussions](https://github.com/Pamacea/warden/discussions)
