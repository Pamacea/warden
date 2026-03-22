# Oalacea Warden Architecture

## Overview

Oalacea Warden is a 100% Rust security review CLI tool designed for speed, safety, and simplicity.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Oalacea Warden CLI                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                       Command Layer (clap)                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                   │                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Orchestrator (tokio)                           │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐   │  │
│  │  │ Detection  │  │  Scanner   │  │  Reporter  │  │  Config  │   │  │
│  │  │   Module   │  │  Engine    │  │   Module   │  │          │   │  │
│  │  └────────────┘  └────────────┘  └────────────┘  └──────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                   │                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Scanner Modules                             │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐             │  │
│  │  │   HTTP  │  │  Port   │  │  Static │  │  DDoS   │             │  │
│  │  │ Scanner │  │ Scanner │  │ Scanner │  │ Scanner │             │  │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘             │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
oalacea-warden/
├── src/
│   ├── main.rs                 # CLI entry point
│   ├── cli.rs                  # Command line definitions
│   ├── orchestrator.rs         # Main orchestration logic
│   │
│   ├── detection/
│   │   ├── mod.rs              # Detection module
│   │   ├── framework.rs        # Framework detection
│   │   ├── language.rs         # Language detection
│   │   └── platform.rs         # Platform detection
│   │
│   ├── scanners/
│   │   ├── mod.rs              # Scanner orchestrator
│   │   ├── http.rs             # HTTP-based scanners
│   │   ├── port.rs             # Port scanning
│   │   ├── static.rs           # Static code analysis
│   │   ├── ddos.rs             # DDoS resistance testing
│   │   └── stress.rs           # Stress testing
│   │
│   ├── reporters/
│   │   ├── mod.rs              # Reporter module
│   │   ├── console.rs          # Console output
│   │   ├── markdown.rs         # Markdown reports
│   │   └── json.rs             # JSON output
│   │
│   ├── config/
│   │   ├── mod.rs              # Configuration
│   │   └── settings.rs         # Settings struct
│   │
│   └── utils/
│       ├── mod.rs              # Utilities
│       ├── network.rs          # Network utilities
│       ├── fs.rs               # File system utilities
│       └── templates.rs        # Template handling
│
├── templates/
│   └── review.md.tera          # Review prompt template
│
├── wordlists/
│   ├── common.txt              # Embedded wordlists
│   ├── xss.txt
│   └── sqli.txt
│
├── benches/                    # Benchmarks
├── tests/                      # Integration tests
├── Cargo.toml
└── README.md
```

## Core Components

### 1. CLI Layer (clap)

```rust
// src/cli.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "oalacea-warden")]
#[command(about = "AI-powered security review CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target for vulnerabilities
    Scan {
        /// Target URL or directory
        target: Option<String>,

        /// Enable aggressive scanning
        #[arg(long)]
        aggressive: bool,

        /// Include DDoS testing
        #[arg(long)]
        include_ddos: bool,

        /// Output format
        #[arg(long, default_value = "console")]
        format: String,
    },

    /// Detect framework and language
    Detect {
        /// Project directory
        path: Option<String>,
    },
}
```

### 2. Scanner Engine

```rust
// src/scanners/mod.rs
use tokio::task::JoinSet;
use anyhow::Result;

pub struct ScannerEngine {
    config: ScannerConfig,
}

impl ScannerEngine {
    pub async fn run_scan(&self, target: &Target) -> Result<ScanReport> {
        let mut tasks = JoinSet::new();

        // Spawn scanners in parallel
        tasks.spawn(self.http_scan(target.clone()));
        tasks.spawn(self.port_scan(target.clone()));
        tasks.spawn(self.static_scan(target.clone()));

        // Collect results
        let mut report = ScanReport::new();
        while let Some(result) = tasks.join_next().await {
            report.merge(result??);
        }

        Ok(report)
    }
}
```

### 3. HTTP Scanner

```rust
// src/scanners/http.rs
use reqwest::Client;
use tokio::sync::Semaphore;

pub struct HttpScanner {
    client: Client,
    concurrency: usize,
}

impl HttpScanner {
    pub async fn scan_xss(&self, target: &str) -> Result<Vec<Vuln>> {
        let payloads = self.xss_payloads();
        let semaphore = Semaphore::new(self.concurrency);
        let mut tasks = JoinSet::new();

        for payload in payloads {
            let permit = semaphore.clone().acquire_owned().await?;
            let client = self.client.clone();
            let target = target.to_string();

            tasks.spawn(async move {
                let _permit = permit;
                Self::test_xss_payload(&client, &target, &payload).await
            });
        }

        // Collect vulnerabilities
        Ok(tasks.join_all().await.into_iter().filter_map(|r| r.ok()).flatten().collect())
    }
}
```

### 4. Port Scanner

```rust
// src/scanners/port.rs
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::time::timeout;

pub struct PortScanner {
    timeout: Duration,
}

impl PortScanner {
    pub async fn scan_range(&self, host: &str, range: RangeInclusive<u16>) -> Result<Vec<OpenPort>> {
        let addresses: Vec<_> = range
            .map(|port| (host.to_string(), port))
            .collect();

        let results = stream::iter(addresses)
            .map(|(host, port)| async move {
                Self::check_port(&host, port, self.timeout).await
            })
            .buffer_unordered(100) // 100 concurrent scans
            .collect::<Vec<_>>()
            .await;

        Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
    }
}
```

### 5. Static Analysis

```rust
// src/scanners/static.rs
use tree_sitter::{Parser, Language, Query};

pub struct StaticScanner {
    parser: Parser,
    language: Language,
}

impl StaticScanner {
    pub fn for_rust() -> Self {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_rust::language()).unwrap();

        Self { parser, language: tree_sitter_rust::language() }
    }

    pub fn scan_unsafe_blocks(&self, code: &str) -> Result<Vec<UnsafeBlock>> {
        let tree = self.parser.parse(code, None)?;

        // Query for unsafe blocks
        let query = Query::new(
            self.language,
            r#"(unsafe_block (_) @unsafe)"#
        )?;

        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), code.as_bytes());

        let mut results = Vec::new();
        for m in matches {
            for capture in m.captures {
                let node = capture.node;
                results.push(UnsafeBlock {
                    line: node.start_position().row + 1,
                    column: node.start_position().column,
                    text: &code[node.byte_range()],
                });
            }
        }

        Ok(results)
    }
}
```

## Data Flow

```
User Input (CLI)
    │
    ▼
Parse & Validate (clap)
    │
    ▼
Detect Target (Detection Module)
    │
    ├─→ Framework? (NestJS, Rust, Vite, ...)
    ├─→ Language? (JS, Python, Go, ...)
    └─→ Platform? (Local, URL)
    │
    ▼
Select Scanners (Scanner Engine)
    │
    ├─→ HTTP Scanner (reqwest + tokio)
    ├─→ Port Scanner (tokio::net)
    ├─→ Static Scanner (tree-sitter)
    └─→ DDoS Scanner (rayon)
    │
    ▼
Collect Results (JoinSet)
    │
    ▼
Generate Report (Reporters)
    │
    └─→ Console / Markdown / JSON
```

## Performance Optimizations

### 1. Parallelism

```rust
// Rayon for CPU-bound tasks
use rayon::prelude::*;

results.par_iter()
    .filter(|r| r.severity >= Severity::High)
    .collect()

// Tokio for I/O-bound tasks
use tokio::task::JoinSet;

let mut tasks = JoinSet::new();
for target in targets {
    tasks.spawn(scan(target));
}
```

### 2. Connection Pooling

```rust
// Reuse HTTP connections
let client = reqwest::Client::builder()
    .pool_max_idle_per_host(100)
    .pool_idle_timeout(Duration::from_secs(30))
    .build()?;
```

### 3. Zero-Copy Parsing

```rust
// Use bytes::Bytes for zero-copy
use bytes::Bytes;

fn parse_response(data: Bytes) -> Response {
    // No allocation, references into data
}
```

## Extension Points

### Adding a New Scanner

```rust
// 1. Create scanner module
// src/scanners/my_scanner.rs

pub struct MyScanner {
    config: MyConfig,
}

impl MyScanner {
    pub async fn scan(&self, target: &str) -> Result<Vec<Vuln>> {
        // Implementation
    }
}

// 2. Register in orchestrator
// src/scanners/mod.rs
pub mod my_scanner;

// 3. Add to CLI
// src/cli.rs
Scan {
    #[arg(long)]
    enable_my_scanner: bool,
}
```

### Adding Wordlists

```rust
// src/utils/wordlists.rs

pub static XSS_PAYLOADS: &[&str] = &[
    include_str!("../wordlists/xss.txt"),
];

// Wordlists are embedded at compile time
```

## Security Considerations

1. **Input Validation**: All URLs and paths validated before scanning
2. **Timeout Enforcement**: All operations have configurable timeouts
3. **Rate Limiting**: Built-in rate limiting to avoid overwhelming targets
4. **Memory Safety**: Rust's type system prevents memory corruption
5. **No Shell Execution**: No command injection vulnerabilities

## Testing Strategy

```rust
// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xss_payload() {
        let payload = "<script>alert(1)</script>";
        assert!(is_xss_payload(payload));
    }
}

// Integration tests
// tests/integration_test.rs
#[tokio::test]
async fn test_full_scan() {
    let result = oalacea_warden::scan("http://localhost:8080").await;
    assert!(result.is_ok());
}

// Benchmarks
// benches/scanners.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_http_scan(c: &mut Criterion) {
    c.bench_function("http_scan", |b| {
        b.iter(|| http_scan(black_box("http://example.com")))
    });
}
```

## Deployment

Oalacea Warden is distributed via:
1. **crates.io**: `cargo install oalacea-warden`
2. **GitHub Releases**: Pre-built binaries for all platforms
3. **Homebrew**: `brew install oalacea-warden`
4. **Scoop**: `scoop install oalacea-warden`
