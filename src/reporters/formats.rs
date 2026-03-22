//! Advanced Report Formatters - HTML, SARIF, PDF-like formats

#![allow(dead_code)]

use crate::scanners::{ScanReport, VulnSeverity};
use anyhow::Result;
use serde_json::json;
use std::fs::File;
use std::io::Write;

/// Generate HTML report with interactive findings
pub fn generate_html_report(report: &ScanReport) -> Result<String> {
    let timestamp = &report.timestamp;
    let target = &report.target;
    let total = report.summary.total;
    let critical = report.summary.critical;
    let high = report.summary.high;
    let medium = report.summary.medium;
    let low = report.summary.low;

    // Build CSS separately to avoid format! escaping issues
    let css = r#"<style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px);
                    border-radius: 15px; padding: 30px; margin-bottom: 30px; border: 1px solid rgba(255,255,255,0.2); }
        .header h1 { color: #fff; font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { color: #a0aec0; font-size: 1.1em; }
        .header .meta { display: flex; gap: 30px; margin-top: 20px; color: #718096; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                     gap: 20px; margin-bottom: 30px; }
        .summary-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px);
                         border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.2); }
        .summary-card h3 { color: #a0aec0; font-size: 0.9em; text-transform: uppercase;
                           letter-spacing: 1px; margin-bottom: 10px; }
        .summary-card .count { font-size: 2.5em; font-weight: bold; }
        .summary-card.total .count { color: #fff; }
        .summary-card.critical .count { color: #fc8181; }
        .summary-card.high .count { color: #f6ad55; }
        .summary-card.medium .count { color: #f6e05e; }
        .summary-card.low .count { color: #63b3ed; }
        .findings { background: rgba(255,255,255,0.1); backdrop-filter: blur(10px);
                     border-radius: 15px; padding: 30px; border: 1px solid rgba(255,255,255,0.2); }
        .findings h2 { color: #fff; margin-bottom: 20px; font-size: 1.8em; }
        .filter-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .filter-btn { background: rgba(255,255,255,0.1); color: #fff; border: 1px solid rgba(255,255,255,0.3);
                       padding: 8px 16px; border-radius: 8px; cursor: pointer; transition: all 0.3s; }
        .filter-btn:hover, .filter-btn.active { background: rgba(99, 179, 237, 0.3); border-color: #63b3ed; }
        .finding { background: rgba(0,0,0,0.3); border-radius: 10px; padding: 20px; margin-bottom: 15px;
                    border-left: 4px solid #718096; transition: all 0.3s; }
        .finding:hover { transform: translateX(5px); }
        .finding.critical { border-left-color: #fc8181; }
        .finding.high { border-left-color: #f6ad55; }
        .finding.medium { border-left-color: #f6e05e; }
        .finding.low { border-left-color: #63b3ed; }
        .finding.info { border-left-color: #a0aec0; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { color: #fff; font-size: 1.2em; font-weight: 600; }
        .finding-severity { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }
        .finding-severity.critical { background: #fc8181; color: #1a202c; }
        .finding-severity.high { background: #f6ad55; color: #1a202c; }
        .finding-severity.medium { background: #f6e05e; color: #1a202c; }
        .finding-severity.low { background: #63b3ed; color: #1a202c; }
        .finding-severity.info { background: #a0aec0; color: #1a202c; }
        .finding-description { color: #e2e8f0; margin-bottom: 10px; line-height: 1.6; }
        .finding-location { color: #718096; font-size: 0.9em; margin-bottom: 10px; }
        .finding-location code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; }
        .finding-recommendation { background: rgba(99, 179, 237, 0.1); border-left: 3px solid #63b3ed;
                                 padding: 12px; border-radius: 0 8px 8px 0; }
        .finding-recommendation strong { color: #63b3ed; }
        .finding-recommendation { color: #e2e8f0; font-size: 0.95em; }
        .finding-meta { display: flex; gap: 20px; margin-top: 10px; font-size: 0.85em; color: #718096; }
        .finding-meta span { display: flex; align-items: center; gap: 5px; }
        .footer { text-align: center; color: #718096; margin-top: 30px; padding: 20px; }
        .footer a { color: #63b3ed; text-decoration: none; }
        @media (max-width: 768px) {
            .header .meta { flex-direction: column; gap: 10px; }
            .filter-buttons { justify-content: center; }
        }
    </style>"#;

    let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Warden Security Report - {}</title>
    {}
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Warden Security Report</h1>
            <p class="subtitle">AI-powered vulnerability assessment</p>
            <div class="meta">
                <span>📅 Scanned: <strong>{}</strong></span>
                <span>🎯 Target: <strong>{}</strong></span>
                <span>📊 Total Findings: <strong>{}</strong></span>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card total">
                <h3>Total Findings</h3>
                <div class="count">{}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="count">{}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="count">{}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="count">{}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="count">{}</div>
            </div>
        </div>

        <div class="findings">
            <h2>🔍 Vulnerability Findings</h2>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
                <button class="filter-btn" onclick="filterFindings('high')">High</button>
                <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
                <button class="filter-btn" onclick="filterFindings('low')">Low</button>
                <button class="filter-btn" onclick="filterFindings('info')">Info</button>
            </div>
            <div id="findings-container">
"#, timestamp, css, timestamp, target, total, total, critical, high, medium, low);

    // Add each finding
    for (index, finding) in report.findings.iter().enumerate() {
        let severity_class = match finding.severity {
            VulnSeverity::Critical => "critical",
            VulnSeverity::High => "high",
            VulnSeverity::Medium => "medium",
            VulnSeverity::Low => "low",
            VulnSeverity::Info => "info",
        };

        html.push_str(&format!(r#"
                <div class="finding {}" data-severity="{}">
                    <div class="finding-header">
                        <span class="finding-title">{}. {}</span>
                        <span class="finding-severity {}">{}</span>
                    </div>
                    <p class="finding-description">{}</p>
"#, severity_class, severity_class, index + 1, finding.title, severity_class, finding.severity, finding.description));

        if let Some(location) = &finding.location {
            html.push_str(&format!(r#"                    <p class="finding-location">📍 Location: <code>{}</code></p>"#, location));
        }

        if let Some(recommendation) = &finding.recommendation {
            html.push_str(&format!(r#"                    <div class="finding-recommendation">
                        <strong>💡 Recommendation:</strong> {}
                    </div>"#, recommendation));
        }

        // Add CWE and OWASP if present
        if finding.cwe.is_some() || finding.owasp.is_some() {
            html.push_str(r#"                    <div class="finding-meta">"#);
            if let Some(cwe) = &finding.cwe {
                html.push_str(&format!(r#"                        <span>🏷️ {}</span>"#, cwe));
            }
            if let Some(owasp) = &finding.owasp {
                html.push_str(&format!(r#"                        <span>📚 {}</span>"#, owasp));
            }
            html.push_str(r#"                    </div>"#);
        }

        html.push_str(r#"                </div>"#);
    }

    // Add footer and scripts
    html.push_str(r#"            </div>
        </div>

        <div class="footer">
            <p>Generated by <a href="https://github.com/Pamacea/warden" target="_blank">Warden</a> - AI-Powered Security CLI</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Report generated on <span id="report-time"></span></p>
        </div>
    </div>

    <script>
        function filterFindings(severity) {
            const findings = document.querySelectorAll('.finding');
            const buttons = document.querySelectorAll('.filter-btn');

            // Update button states
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            // Filter findings
            findings.forEach(finding => {
                if (severity === 'all' || finding.dataset.severity === severity) {
                    finding.style.display = 'block';
                } else {
                    finding.style.display = 'none';
                }
            });
        }

        document.getElementById('report-time').textContent = new Date().toISOString();

        // Add keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === '1') filterFindings('all');
            if (e.key === '2') filterFindings('critical');
            if (e.key === '3') filterFindings('high');
            if (e.key === '4') filterFindings('medium');
            if (e.key === '5') filterFindings('low');
            if (e.key === '6') filterFindings('info');
        });
    </script>
</body>
</html>"#);

    Ok(html)
}

/// Generate SARIF format report for GitHub Security
pub fn generate_sarif_report(report: &ScanReport) -> Result<String> {
    let mut sarif_results = Vec::new();

    for finding in &report.findings {
        let rule_id = finding.title.to_lowercase().replace(' ', "-").chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();

        let level = match finding.severity {
            VulnSeverity::Critical => "error",
            VulnSeverity::High => "error",
            VulnSeverity::Medium => "warning",
            VulnSeverity::Low => "note",
            VulnSeverity::Info => "note",
        };

        let rank = match finding.severity {
            VulnSeverity::Critical => 100.0,
            VulnSeverity::High => 75.0,
            VulnSeverity::Medium => 50.0,
            VulnSeverity::Low => 25.0,
            VulnSeverity::Info => 10.0,
        };

        let mut result = json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": finding.description.clone()
            },
            "rank": rank
        });

        // Add location if available
        if let Some(location) = &finding.location {
            let mut locations = serde_json::Map::new();
            locations.insert("physicalLocation".to_string(), json!({
                "artifactLocation": {
                    "uri": location
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            }));
            result["locations"] = json!(vec![locations]);
        }

        // Add CWE if available
        if let Some(cwe) = &finding.cwe {
            result["ruleId"] = json!(format!("{} {}", cwe, rule_id));
        }

        sarif_results.push(result);
    }

    let mut runs = serde_json::Map::new();
    runs.insert("tool".to_string(), json!({
        "driver": {
            "name": "Warden",
            "version": env!("CARGO_PKG_VERSION"),
            "informationUri": "https://github.com/Pamacea/warden",
            "rules": report.findings.iter().map(|f| {
                let rule_id = f.title.to_lowercase().replace(' ', "-").chars()
                    .filter(|c| c.is_alphanumeric() || *c == '-')
                    .collect::<String>();
                json!({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {
                        "text": f.title
                    },
                    "fullDescription": {
                        "text": f.description
                    },
                    "helpUri": format!("https://cwe.mitre.org/data/definitions/{}.html",
                        f.cwe.as_ref().and_then(|c| c.strip_prefix("CWE-")).unwrap_or("0"))
                })
            }).collect::<Vec<_>>()
        }
    }));
    runs.insert("results".to_string(), json!(sarif_results));

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": vec![runs]
    });

    Ok(serde_json::to_string_pretty(&sarif)?)
}

/// Generate JSON report
#[allow(dead_code)]
pub fn generate_json_report(report: &ScanReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Generate Markdown report
#[allow(dead_code)]
pub fn generate_markdown_report(report: &ScanReport) -> Result<String> {
    let mut md = format!("# 🛡️ Warden Security Report\n\n");
    md.push_str(&format!("**Generated:** {}\n", report.timestamp));
    md.push_str(&format!("**Target:** `{}`\n\n", report.target));

    // Summary
    md.push_str("## 📊 Executive Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|-------|\n");
    md.push_str(&format!("| **Critical** | {} |\n", report.summary.critical));
    md.push_str(&format!("| **High** | {} |\n", report.summary.high));
    md.push_str(&format!("| **Medium** | {} |\n", report.summary.medium));
    md.push_str(&format!("| **Low** | {} |\n", report.summary.low));
    md.push_str(&format!("| **Info** | {} |\n", report.summary.info));
    md.push_str(&format!("| **Total** | **{}** |\n\n", report.summary.total));

    // Findings
    md.push_str("## 🔍 Detailed Findings\n\n");

    for (index, finding) in report.findings.iter().enumerate() {
        let emoji = match finding.severity {
            VulnSeverity::Critical => "🔴",
            VulnSeverity::High => "🟠",
            VulnSeverity::Medium => "🟡",
            VulnSeverity::Low => "🔵",
            VulnSeverity::Info => "⚪",
        };

        md.push_str(&format!("### {} #{}: {} ({})\n\n",
            emoji, index + 1, finding.title, finding.severity));

        md.push_str(&format!("**Description:** {}\n\n", finding.description));

        if let Some(location) = &finding.location {
            md.push_str(&format!("**Location:** `{}`\n\n", location));
        }

        if let Some(recommendation) = &finding.recommendation {
            md.push_str(&format!("**💡 Recommendation:** {}\n\n", recommendation));
        }

        if let Some(cwe) = &finding.cwe {
            md.push_str(&format!("**CWE:** {}\n", cwe));
        }
        if let Some(owasp) = &finding.owasp {
            md.push_str(&format!("**OWASP:** {}\n", owasp));
        }
        md.push_str("\n---\n\n");
    }

    md.push_str(&format!("\n---\n\n*Generated by [Warden](https://github.com/Pamacea/warden) v{}*\n", env!("CARGO_PKG_VERSION")));

    Ok(md)
}

/// Write report to file
#[allow(dead_code)]
pub fn write_report(content: &str, output_path: &str) -> Result<()> {
    let mut file = File::create(output_path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
