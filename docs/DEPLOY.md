# Warden Deployment Guide

## Publishing to crates.io

### Prerequisites

```bash
# Login to crates.io
cargo login
```

### Release Checklist

- [ ] Update version in `Cargo.toml`
- [ ] Update `CHANGELOG.md`
- [ ] Run tests: `cargo test --all-features`
- [ ] Run clippy: `cargo clippy -- -D warnings`
- [ ] Check formatting: `cargo fmt -- --check`
- [ ] Build release: `cargo build --release`
- [ ] Test binary: `./target/release/warden --version`

### Publishing

```bash
# Dry run to check for issues
cargo publish --dry-run

# Publish for real
cargo publish
```

## GitHub Releases

### Building Release Binaries

Use `cargo-cross` for cross-compilation:

```bash
# Install cross
cargo install cross

# Build for all targets
cross build --release --target x86_64-pc-windows-msvc
cross build --release --target x86_64-apple-darwin
cross build --release --target aarch64-apple-darwin
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target aarch64-unknown-linux-gnu
```

### GitHub Actions Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  release:
    types: [created]

jobs:
  build:
    strategy:
      matrix:
        include:
          - target: x86_64-pc-windows-msvc
            os: windows-latest
            artifact: warden-x86_64-pc-windows-msvc.exe
          - target: x86_64-apple-darwin
            os: macos-latest
            artifact: warden-x86_64-apple-darwin
          - target: aarch64-apple-darwin
            os: macos-latest
            artifact: warden-aarch64-apple-darwin
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
            artifact: warden-x86_64-unknown-linux-gnu
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
            artifact: warden-aarch64-unknown-linux-gnu

    runs-on: ${{ matrix.os }}

    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Install Rust
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable
          target: ${{ matrix.target }}

      - name: Build
        run: cargo build --release --target ${{ matrix.target }}

      - name: Strip binary
        shell: bash
        run: |
          if [ "${{ runner.os }}" != "Windows" ]; then
            strip "target/${{ matrix.target }}/release/warden"
          fi

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: ${{ matrix.artifact }}
          path: target/${{ matrix.target }}/release/warden${{ matrix.os == 'Windows' && '.exe' || '' }}

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v3

      - name: Upload to GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            warden-*
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Creating a Release

```bash
# Tag the release
git tag v0.2.0
git push origin v0.2.0

# Or use GitHub UI to create release
# GitHub Actions will build and attach binaries
```

## Package Managers

### Homebrew (macOS/Linux)

Create a tap repository:

```bash
# Create homebrew-warden repo
mkdir homebrew-warden
cd homebrew-warden

# Create Formula/warden.rb
class Warden < Formula
  desc "AI-powered security review CLI tool"
  homepage "https://github.com/Pamacea/warden"
  url "https://github.com/Pamacea/warden/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "..." # Use shasum of the tarball

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/warden", "--version"
  end
end
```

User installation:
```bash
brew tap pamacea/warden
brew install warden
```

### Scoop (Windows)

Create `bucket/warden.json`:

```json
{
  "version": "0.2.0",
  "description": "AI-powered security review CLI tool",
  "homepage": "https://github.com/Pamacea/warden",
  "license": "MIT",
  "url": "https://github.com/Pamacea/warden/releases/download/v0.2.0/warden-x86_64-pc-windows-msvc.exe",
  "hash": "...",
  "bin": "warden-x86_64-pc-windows-msvc.exe",
  "shortcuts": [
    [
      "warden-x86_64-pc-windows-msvc.exe",
      "Warden"
    ]
  ]
}
```

User installation:
```bash
scoop bucket add warden https://github.com/Pamacea/warden-scoop
scoop install warden
```

### AUR (Arch Linux)

Create `PKGBUILD`:

```bash
pkgname=warden
pkgver=0.2.0
pkgrel=1
pkgdesc="AI-powered security review CLI tool"
arch=('x86_64' 'aarch64')
url="https://github.com/Pamacea/warden"
license=('MIT')
makedepends=('cargo')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('...')

build() {
  cd "$pkgname-$pkgver"
  cargo build --release --locked
}

package() {
  cd "$pkgname-$pkgver"
  install -Dm755 "target/release/warden" "$pkgdir/usr/bin/warden"
  install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
```

## Docker Image

### Dockerfile

```dockerfile
# Dockerfile
FROM rust:1.85-alpine AS builder

WORKDIR /app
COPY . .

RUN cargo build --release

FROM alpine:latest
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/warden /usr/local/bin/warden

ENTRYPOINT ["warden"]
```

### Build and Push

```bash
# Build
docker build -t pamacea/warden:0.2.0 .

# Tag
docker tag pamacea/warden:0.2.0 pamacea/warden:latest

# Push
docker push pamacea/warden:0.2.0
docker push pamacea/warden:latest
```

### Usage

```bash
docker run --rm -v $(pwd):/app pamacea/warden scan /app
```

## CI/CD Integration

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
cargo fmt -- --check
cargo clippy -- -D warnings
cargo test --all-features
```

### GitHub Actions - CI

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, beta]

    steps:
      - uses: actions/checkout@v3

      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}

      - name: Run tests
        run: cargo test --all-features

      - name: Run clippy
        run: cargo clippy -- -D warnings

      - name: Check formatting
        run: cargo fmt -- --check
```

### Dependabot

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
```

## Versioning

Warden follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes (backwards compatible)

### Version Bump

```bash
# Install cargo-bump
cargo install cargo-bump

# Bump version
cargo bump patch  # 0.2.0 -> 0.2.1
cargo bump minor  # 0.2.0 -> 0.3.0
cargo bump major  # 0.2.0 -> 1.0.0

# Or manually edit Cargo.toml and run
cargo update
```

## Monitoring

### Downloads Tracking

- crates.io provides download statistics
- GitHub releases provides asset download counts
- Add analytics to binary for usage stats (optional, privacy-respecting)

### Error Reporting

Consider integrating:
- `sentry` for error tracking
- `backtrace` for crash reports
- User feedback mechanism

## Security

### Vulnerability Scanning

```bash
# Scan for security advisories
cargo install cargo-audit
cargo audit

# Check for outdated dependencies
cargo install cargo-outdated
cargo outdated
```

### Supply Chain

```bash
# Verify supply chain
cargo install cargo-vet
cargo vet
```

## Documentation

### Docs.rs

Documentation is automatically built and published to <https://docs.rs/warden> when publishing to crates.io.

Ensure:
- All public items are documented
- Examples are provided
- `#![warn(missing_docs)]` in lib.rs

### Website

Deploy documentation via GitHub Pages:

```yaml
# .github/workflows/docs.yml
name: Docs

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions-rust-lang/setup-rust-toolchain@v1

      - name: Build docs
        run: cargo doc --no-deps

      - name: Deploy to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./target/doc
```

## Support Channels

- **Documentation**: <https://warden.secure.dev>
- **Issues**: <https://github.com/Pamacea/warden/issues>
- **Discussions**: <https://github.com/Pamacea/warden/discussions>
- **Email**: support@warden.secure.dev
