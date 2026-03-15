//! Benchmark tests

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use warden_sec::scanners::{HttpScanner, PortScanner, ScannerConfig};

fn bench_http_scan(c: &mut Criterion) {
    let config = ScannerConfig::new();
    let scanner = HttpScanner::new(config);

    c.bench_function("http_scan_create", |b| {
        b.iter(|| {
            HttpScanner::new(black_box(ScannerConfig::new()));
        });
    });
}

fn bench_port_scan(c: &mut Criterion) {
    let config = ScannerConfig::new();
    let scanner = PortScanner::new(config);

    c.bench_function("port_scan_create", |b| {
        b.iter(|| {
            PortScanner::new(black_box(ScannerConfig::new()));
        });
    });
}

criterion_group!(benches, bench_http_scan, bench_port_scan);
criterion_main!(benches);
