//! HTML Reporter with interactive charts and visualizations
//!
//! Generates comprehensive HTML security reports with:
//! - SVG charts (radar, donut, progress bars)
//! - SecurityScore integration with A+ to F grades
//! - Interactive filtering and animations
//! - Responsive design

use super::Reporter;
use crate::scanners::{ScanReport, VulnSeverity};
use crate::scoring::SecurityScore;
use anyhow::Result;

/// HTML Reporter that generates interactive HTML reports
pub struct HtmlReporter;

impl Reporter for HtmlReporter {
    fn print(report: &ScanReport) -> Result<()> {
        println!("{}", Self::format(report)?);
        Ok(())
    }

    fn format(report: &ScanReport) -> Result<String> {
        let html = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Warden Security Report - {}</title>
    {}
</head>
<body>
    {}
</body>
</html>"#,
            report.target,
            Self::css_styles(),
            Self::render_body(report)
        );
        Ok(html)
    }
}

impl HtmlReporter {
    /// Generate CSS styles for the HTML report
    fn css_styles() -> &'static str {
        r#"<style>
        :root {
            /* Severity Colors */
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #3b82f6;
            --color-info: #6b7280;
            --color-aplus: #22c55e;
            --color-a: #84cc16;
            --color-b: #eab308;
            --color-c: #f97316;
            --color-d: #ef4444;
            --color-f: #dc2626;

            /* UI Colors */
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: #334155;
            --accent-color: #3b82f6;
            --accent-hover: #2563eb;

            /* Spacing */
            --spacing-xs: 0.25rem;
            --spacing-sm: 0.5rem;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;

            /* Border Radius */
            --radius-sm: 0.25rem;
            --radius-md: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;

            /* Shadows */
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--spacing-lg);
        }

        /* Header Styles */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-xl);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-lg);
            animation: slideDown 0.5s ease-out;
        }

        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: var(--spacing-md);
        }

        .header-title {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
        }

        .header-title h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-color) 0%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-badge {
            background: var(--accent-color);
            color: white;
            padding: var(--spacing-xs) var(--spacing-md);
            border-radius: var(--radius-lg);
            font-size: 0.875rem;
            font-weight: 600;
        }

        .header-meta {
            display: flex;
            gap: var(--spacing-xl);
            flex-wrap: wrap;
            margin-top: var(--spacing-lg);
            padding-top: var(--spacing-lg);
            border-top: 1px solid var(--border-color);
        }

        .meta-item {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            color: var(--text-secondary);
        }

        .meta-item strong {
            color: var(--text-primary);
        }

        /* Score Card */
        .score-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: var(--spacing-lg);
            margin-bottom: var(--spacing-xl);
        }

        .score-card {
            background: var(--bg-secondary);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-md);
            animation: fadeIn 0.6s ease-out;
        }

        .score-card-main {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            text-align: center;
        }

        .score-value {
            font-size: 4rem;
            font-weight: 800;
            line-height: 1;
            margin: var(--spacing-md) 0;
        }

        .score-grade {
            display: inline-block;
            padding: var(--spacing-sm) var(--spacing-lg);
            border-radius: var(--radius-lg);
            font-size: 1.25rem;
            font-weight: 700;
            text-transform: uppercase;
        }

        .score-grade.grade-a-plus { background: var(--color-aplus); color: white; }
        .score-grade.grade-a { background: var(--color-a); color: white; }
        .score-grade.grade-b { background: var(--color-b); color: var(--bg-primary); }
        .score-grade.grade-c { background: var(--color-c); color: var(--bg-primary); }
        .score-grade.grade-d { background: var(--color-d); color: white; }
        .score-grade.grade-f { background: var(--color-f); color: white; }

        .score-description {
            color: var(--text-secondary);
            margin-top: var(--spacing-md);
        }

        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: var(--spacing-md);
            margin-bottom: var(--spacing-xl);
        }

        .summary-card {
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            padding: var(--spacing-lg);
            border: 1px solid var(--border-color);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
        }

        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }

        .summary-card.critical { border-left: 4px solid var(--color-critical); }
        .summary-card.high { border-left: 4px solid var(--color-high); }
        .summary-card.medium { border-left: 4px solid var(--color-medium); }
        .summary-card.low { border-left: 4px solid var(--color-low); }
        .summary-card.info { border-left: 4px solid var(--color-info); }

        .summary-card-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: var(--spacing-xs);
        }

        .summary-card-value {
            font-size: 2rem;
            font-weight: 700;
        }

        .summary-card.critical .summary-card-value { color: var(--color-critical); }
        .summary-card.high .summary-card-value { color: var(--color-high); }
        .summary-card.medium .summary-card-value { color: var(--color-medium); }
        .summary-card.low .summary-card-value { color: var(--color-low); }
        .summary-card.info .summary-card-value { color: var(--color-info); }

        /* Chart Section */
        .chart-section {
            background: var(--bg-secondary);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-xl);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-md);
            animation: fadeIn 0.7s ease-out;
        }

        .chart-section h2 {
            margin-bottom: var(--spacing-lg);
            font-size: 1.5rem;
        }

        .chart-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 400px;
        }

        /* Findings Section */
        .findings-section {
            background: var(--bg-secondary);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-md);
            animation: fadeIn 0.8s ease-out;
        }

        .findings-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: var(--spacing-lg);
            flex-wrap: wrap;
            gap: var(--spacing-md);
        }

        .findings-header h2 {
            font-size: 1.5rem;
        }

        .filter-buttons {
            display: flex;
            gap: var(--spacing-sm);
            flex-wrap: wrap;
        }

        .filter-btn {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
            padding: var(--spacing-sm) var(--spacing-md);
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s;
        }

        .filter-btn:hover {
            background: var(--bg-primary);
            color: var(--text-primary);
        }

        .filter-btn.active {
            background: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }

        /* Finding Card */
        .finding {
            background: var(--bg-tertiary);
            border-radius: var(--radius-lg);
            padding: var(--spacing-lg);
            margin-bottom: var(--spacing-md);
            border-left: 4px solid var(--color-info);
            transition: all 0.3s;
            animation: slideIn 0.3s ease-out;
        }

        .finding:hover {
            transform: translateX(4px);
            box-shadow: var(--shadow-md);
        }

        .finding.critical { border-left-color: var(--color-critical); }
        .finding.high { border-left-color: var(--color-high); }
        .finding.medium { border-left-color: var(--color-medium); }
        .finding.low { border-left-color: var(--color-low); }
        .finding.info { border-left-color: var(--color-info); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: var(--spacing-md);
            margin-bottom: var(--spacing-md);
        }

        .finding-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .finding-severity {
            padding: var(--spacing-xs) var(--spacing-md);
            border-radius: var(--radius-lg);
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .finding-severity.critical { background: var(--color-critical); color: white; }
        .finding-severity.high { background: var(--color-high); color: white; }
        .finding-severity.medium { background: var(--color-medium); color: var(--bg-primary); }
        .finding-severity.low { background: var(--color-low); color: white; }
        .finding-severity.info { background: var(--color-info); color: white; }

        .finding-description {
            color: var(--text-secondary);
            margin-bottom: var(--spacing-md);
            line-height: 1.7;
        }

        .finding-location {
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-bottom: var(--spacing-sm);
        }

        .finding-location code {
            background: var(--bg-primary);
            padding: var(--spacing-xs) var(--spacing-sm);
            border-radius: var(--radius-sm);
            font-family: 'Monaco', 'Menlo', monospace;
        }

        .finding-recommendation {
            background: rgba(59, 130, 246, 0.1);
            border-left: 3px solid var(--accent-color);
            padding: var(--spacing-md);
            border-radius: 0 var(--radius-md) var(--radius-md) 0;
            margin-bottom: var(--spacing-sm);
        }

        .finding-recommendation strong {
            color: var(--accent-color);
        }

        .finding-meta {
            display: flex;
            gap: var(--spacing-lg);
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        .finding-meta span {
            display: flex;
            align-items: center;
            gap: var(--spacing-xs);
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: var(--spacing-xl);
            color: var(--text-secondary);
        }

        .empty-state-icon {
            font-size: 4rem;
            margin-bottom: var(--spacing-md);
        }

        .empty-state-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: var(--spacing-sm);
        }

        /* Footer */
        .footer {
            text-align: center;
            padding: var(--spacing-xl);
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        .footer a {
            color: var(--accent-color);
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        /* Responsive */
        @media (max-width: 768px) {
            .container {
                padding: var(--spacing-md);
            }

            .header-title h1 {
                font-size: 1.5rem;
            }

            .score-value {
                font-size: 3rem;
            }

            .header-meta {
                flex-direction: column;
                gap: var(--spacing-sm);
            }

            .filter-buttons {
                width: 100%;
            }

            .filter-btn {
                flex: 1;
                min-width: 60px;
            }

            .finding-header {
                flex-direction: column;
            }

            .chart-container {
                min-height: 300px;
            }
        }

        /* SVG Chart Styles */
        .radar-chart {
            max-width: 100%;
            height: auto;
        }

        .radar-axis {
            stroke: var(--border-color);
            stroke-width: 1;
        }

        .radar-web {
            fill: none;
            stroke: var(--border-color);
            stroke-width: 1;
            stroke-dasharray: 4;
        }

        .radar-polygon {
            fill: rgba(59, 130, 246, 0.2);
            stroke: var(--accent-color);
            stroke-width: 2;
        }

        .radar-point {
            fill: var(--accent-color);
            stroke: var(--bg-secondary);
            stroke-width: 2;
            cursor: pointer;
            transition: r 0.2s;
        }

        .radar-point:hover {
            r: 8;
        }

        .radar-label {
            fill: var(--text-secondary);
            font-size: 12px;
            text-anchor: middle;
        }

        .radar-value {
            fill: var(--text-primary);
            font-size: 11px;
            font-weight: 600;
            text-anchor: middle;
        }

        /* Category Progress Bars */
        .category-list {
            display: flex;
            flex-direction: column;
            gap: var(--spacing-md);
        }

        .category-item {
            display: flex;
            flex-direction: column;
            gap: var(--spacing-xs);
        }

        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .category-name {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .category-score {
            font-size: 0.875rem;
            font-weight: 700;
            color: var(--text-secondary);
        }

        .category-grade {
            display: inline-block;
            padding: 2px 8px;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 700;
            margin-left: var(--spacing-sm);
        }

        .category-grade.a-plus, .category-grade.a { background: var(--color-aplus); color: white; }
        .category-grade.b { background: var(--color-b); color: var(--bg-primary); }
        .category-grade.c { background: var(--color-c); color: var(--bg-primary); }
        .category-grade.d, .category-grade.e { background: var(--color-d); color: white; }
        .category-grade.f { background: var(--color-f); color: white; }

        .progress-bar {
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: var(--radius-lg);
            overflow: hidden;
            position: relative;
        }

        .progress-fill {
            height: 100%;
            border-radius: var(--radius-lg);
            transition: width 0.6s ease-out;
            position: relative;
        }

        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            animation: shimmer 2s infinite;
        }

        .progress-fill.a-plus, .progress-fill.a { background: linear-gradient(90deg, var(--color-aplus), var(--color-a)); }
        .progress-fill.b { background: var(--color-b); }
        .progress-fill.c { background: var(--color-c); }
        .progress-fill.d, .progress-fill.e { background: var(--color-d); }
        .progress-fill.f { background: var(--color-f); }

        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        /* Grade Circle Chart */
        .grade-circle-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: var(--spacing-md);
        }

        .grade-circle {
            width: 180px;
            height: 180px;
            position: relative;
        }

        .grade-circle svg {
            transform: rotate(-90deg);
        }

        .grade-circle-bg {
            fill: none;
            stroke: var(--bg-tertiary);
            stroke-width: 12;
        }

        .grade-circle-progress {
            fill: none;
            stroke-width: 12;
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-out;
        }

        .grade-circle-progress.a-plus, .grade-circle-progress.a { stroke: var(--color-aplus); }
        .grade-circle-progress.b { stroke: var(--color-b); }
        .grade-circle-progress.c { stroke: var(--color-c); }
        .grade-circle-progress.d, .grade-circle-progress.e { stroke: var(--color-d); }
        .grade-circle-progress.f { stroke: var(--color-f); }

        .grade-circle-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .grade-circle-value {
            font-size: 2.5rem;
            font-weight: 800;
            line-height: 1;
        }

        .grade-circle-letter {
            font-size: 3rem;
            font-weight: 900;
            line-height: 1;
        }

        .grade-circle-description {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: var(--spacing-sm);
        }

        /* Recommendations Section */
        .recommendations-section {
            background: var(--bg-secondary);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-xl);
            border: 1px solid var(--border-color);
            box-shadow: var(--shadow-md);
            animation: fadeIn 0.9s ease-out;
        }

        .recommendations-section h2 {
            margin-bottom: var(--spacing-lg);
            font-size: 1.5rem;
        }

        .recommendation-item {
            background: var(--bg-tertiary);
            border-radius: var(--radius-lg);
            padding: var(--spacing-md);
            margin-bottom: var(--spacing-sm);
            border-left: 4px solid var(--color-info);
            display: flex;
            gap: var(--spacing-md);
            align-items: flex-start;
        }

        .recommendation-item.critical { border-left-color: var(--color-critical); }
        .recommendation-item.high { border-left-color: var(--color-high); }
        .recommendation-item.medium { border-left-color: var(--color-medium); }
        .recommendation-item.low { border-left-color: var(--color-low); }

        .recommendation-priority {
            padding: var(--spacing-xs) var(--spacing-sm);
            border-radius: var(--radius-md);
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .recommendation-priority.critical { background: var(--color-critical); color: white; }
        .recommendation-priority.high { background: var(--color-high); color: white; }
        .recommendation-priority.medium { background: var(--color-medium); color: var(--bg-primary); }
        .recommendation-priority.low { background: var(--color-low); color: white; }

        .recommendation-content {
            flex: 1;
        }

        .recommendation-category {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: var(--spacing-xs);
        }

        .recommendation-text {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .recommendation-impact {
            font-size: 0.75rem;
            color: var(--accent-color);
            margin-top: var(--spacing-xs);
        }

        /* Penalties/Bonuses List */
        .penalties-section, .bonuses-section {
            background: var(--bg-secondary);
            border-radius: var(--radius-xl);
            padding: var(--spacing-xl);
            margin-bottom: var(--spacing-lg);
            border: 1px solid var(--border-color);
        }

        .penalties-section h3, .bonuses-section h3 {
            margin-bottom: var(--spacing-md);
            font-size: 1.125rem;
        }

        .penalty-item, .bonus-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--spacing-sm) 0;
            border-bottom: 1px solid var(--border-color);
        }

        .penalty-item:last-child, .bonus-item:last-child {
            border-bottom: none;
        }

        .penalty-points {
            color: var(--color-critical);
            font-weight: 700;
        }

        .bonus-points {
            color: var(--color-aplus);
            font-weight: 700;
        }

        /* Score Details Grid */
        .score-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: var(--spacing-lg);
            margin-bottom: var(--spacing-xl);
        }

        .score-detail-card {
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            padding: var(--spacing-lg);
            border: 1px solid var(--border-color);
        }

        .score-detail-card h4 {
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-bottom: var(--spacing-sm);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .score-detail-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
    </style>"#
    }

    /// Render the body content of the HTML report
    fn render_body(report: &ScanReport) -> String {
        let mut html = String::new();

        // Calculate security score using the scoring module
        let security_score = SecurityScore::calculate(report);

        // Container start
        html.push_str(r#"<div class="container">"#);

        // Header
        html.push_str(&Self::render_header(report, &security_score));

        // Score section with grade circle
        html.push_str(&Self::render_score_section_with_grade(&security_score));

        // Summary cards
        html.push_str(&Self::render_summary_cards(report));

        // Score details grid (penalties/bonuses summary)
        html.push_str(&Self::render_score_details(&security_score));

        // Category breakdown with progress bars and radar chart
        html.push_str(&Self::render_category_breakdown(&security_score));

        // Recommendations section
        if !security_score.recommendations.is_empty() {
            html.push_str(&Self::render_recommendations(&security_score));
        }

        // Findings section
        html.push_str(&Self::render_findings_section(report));

        // Footer
        html.push_str(&Self::render_footer());

        // Container end
        html.push_str(r#"</div>"#);

        // JavaScript for interactivity
        html.push_str(&Self::javascript(&security_score));

        html
    }

    /// Render the header section with security score info
    fn render_header(report: &ScanReport, security_score: &SecurityScore) -> String {
        format!(
            r#"<div class="header">
            <div class="header-top">
                <div class="header-title">
                    <h1>🛡️ Warden Security Report</h1>
                    <span class="header-badge">v{}</span>
                </div>
                <div class="header-badge" style="background: {}; color: white;">Grade: {}</div>
            </div>
            <div class="header-meta">
                <div class="meta-item">
                    <span>📅</span>
                    <span>Scanned: <strong>{}</strong></span>
                </div>
                <div class="meta-item">
                    <span>🎯</span>
                    <span>Target: <strong>{}</strong></span>
                </div>
                <div class="meta-item">
                    <span>📊</span>
                    <span>Total Findings: <strong>{}</strong></span>
                </div>
                <div class="meta-item">
                    <span>⭐</span>
                    <span>Score: <strong>{:.1}/100</strong></span>
                </div>
            </div>
        </div>"#,
            env!("CARGO_PKG_VERSION"),
            Self::get_grade_color(security_score.grade),
            security_score.grade.as_str(),
            report.timestamp,
            report.target,
            report.summary.total,
            security_score.score
        )
    }

    /// Get color for grade (hex format)
    fn get_grade_color(grade: crate::scoring::Grade) -> &'static str {
        match grade {
            crate::scoring::Grade::APlus => "#22c55e",
            crate::scoring::Grade::A => "#84cc16",
            crate::scoring::Grade::B => "#eab308",
            crate::scoring::Grade::C => "#f97316",
            crate::scoring::Grade::D => "#ef4444",
            crate::scoring::Grade::E => "#ef4444",
            crate::scoring::Grade::F => "#dc2626",
        }
    }

    /// Render the score section with grade circle SVG
    fn render_score_section_with_grade(security_score: &SecurityScore) -> String {
        let grade_class = format!("grade-{}",
            match security_score.grade {
                crate::scoring::Grade::APlus => "a-plus",
                crate::scoring::Grade::A => "a",
                crate::scoring::Grade::B => "b",
                crate::scoring::Grade::C => "c",
                crate::scoring::Grade::D => "d",
                crate::scoring::Grade::E => "e",
                crate::scoring::Grade::F => "f",
            }
        );

        // Calculate circle parameters
        let radius = 70.0;
        let circumference = 2.0 * std::f64::consts::PI * radius;
        let offset = circumference - (security_score.score / 100.0) * circumference;

        format!(
            r#"<div class="score-section">
            <div class="score-card score-card-main">
                <h3>Security Score</h3>
                <div class="grade-circle-container">
                    <div class="grade-circle">
                        <svg width="180" height="180" viewBox="0 0 180 180">
                            <circle class="grade-circle-bg" cx="90" cy="90" r="{}" />
                            <circle class="grade-circle-progress {}"
                                cx="90" cy="90" r="{}"
                                stroke-dasharray="{}"
                                stroke-dashoffset="{}"
                                data-score="{}"
                            />
                        </svg>
                        <div class="grade-circle-text">
                            <div class="grade-circle-letter {}">{}</div>
                            <div class="grade-circle-value">{:.0}</div>
                            <div class="grade-circle-description">{}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>"#,
            radius, grade_class, radius, circumference, offset, security_score.score,
            grade_class, security_score.grade.as_str(), security_score.score,
            security_score.grade.description()
        )
    }

    /// Render the summary cards
    fn render_summary_cards(report: &ScanReport) -> String {
        format!(
            r#"<div class="summary-grid">
            <div class="summary-card critical" onclick="filterBySeverity('critical')">
                <div class="summary-card-label">Critical</div>
                <div class="summary-card-value">{}</div>
            </div>
            <div class="summary-card high" onclick="filterBySeverity('high')">
                <div class="summary-card-label">High</div>
                <div class="summary-card-value">{}</div>
            </div>
            <div class="summary-card medium" onclick="filterBySeverity('medium')">
                <div class="summary-card-label">Medium</div>
                <div class="summary-card-value">{}</div>
            </div>
            <div class="summary-card low" onclick="filterBySeverity('low')">
                <div class="summary-card-label">Low</div>
                <div class="summary-card-value">{}</div>
            </div>
            <div class="summary-card info" onclick="filterBySeverity('info')">
                <div class="summary-card-label">Info</div>
                <div class="summary-card-value">{}</div>
            </div>
        </div>"#,
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
            report.summary.info
        )
    }

    /// Render score details grid (penalties/bonuses summary)
    fn render_score_details(security_score: &SecurityScore) -> String {
        let total_penalties: i32 = security_score.all_penalties.iter().map(|p| p.points).sum();
        let total_bonuses: i32 = security_score.all_bonuses.iter().map(|b| b.points).sum();

        format!(
            r#"<div class="score-details-grid">
            <div class="score-detail-card">
                <h4>Penalties Applied</h4>
                <div class="score-detail-value" style="color: var(--color-critical);">-{} pts</div>
                <div style="font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem;">
                    {} issue(s)
                </div>
            </div>
            <div class="score-detail-card">
                <h4>Bonuses Awarded</h4>
                <div class="score-detail-value" style="color: var(--color-aplus);">+{} pts</div>
                <div style="font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem;">
                    {} best practice(s)
                </div>
            </div>
            <div class="score-detail-card">
                <h4>Categories Scored</h4>
                <div class="score-detail-value" style="color: var(--accent-color);">{}</div>
                <div style="font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem;">
                    Security areas evaluated
                </div>
            </div>
            <div class="score-detail-card">
                <h4>Recommendations</h4>
                <div class="score-detail-value" style="color: var(--color-high);">{}</div>
                <div style="font-size: 0.875rem; color: var(--text-muted); margin-top: 0.5rem;">
                    Priority actions
                </div>
            </div>
        </div>"#,
            total_penalties,
            security_score.all_penalties.len(),
            total_bonuses,
            security_score.all_bonuses.len(),
            security_score.categories.len(),
            security_score.recommendations.len()
        )
    }

    /// Render category breakdown with progress bars and radar chart
    fn render_category_breakdown(security_score: &SecurityScore) -> String {
        let categories_for_chart: Vec<(String, f64)> = security_score.categories
            .iter()
            .map(|cat| (cat.name.clone(), cat.percentage()))
            .collect();

        let progress_bars = Self::render_category_progress_bars(security_score);
        let radar_chart = Self::render_enhanced_radar_chart(&categories_for_chart);

        format!(
            r#"<div class="score-details-grid" style="grid-template-columns: 1fr 1fr;">
            <div class="chart-section">
                <h2>📊 Category Scores</h2>
                <div class="category-list">
                    {}
                </div>
            </div>
            <div class="chart-section">
                <h2>📈 Radar Overview</h2>
                <div class="chart-container" style="min-height: 350px;">
                    {}
                </div>
            </div>
        </div>"#,
            progress_bars, radar_chart
        )
    }

    /// Render category progress bars
    fn render_category_progress_bars(security_score: &SecurityScore) -> String {
        let mut html = String::new();

        for category in &security_score.categories {
            let percentage = category.percentage();
            let grade = category.grade();
            let grade_class = match grade {
                crate::scoring::Grade::APlus => "a-plus",
                crate::scoring::Grade::A => "a",
                crate::scoring::Grade::B => "b",
                crate::scoring::Grade::C => "c",
                crate::scoring::Grade::D => "d",
                crate::scoring::Grade::E => "e",
                crate::scoring::Grade::F => "f",
            };

            html.push_str(&format!(
                r#"<div class="category-item">
                    <div class="category-header">
                        <span class="category-name">{}</span>
                        <span>
                            <span class="category-score">{}/{} ({:.0}%)</span>
                            <span class="category-grade {}">{}</span>
                        </span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill {}" style="width: {:.0}%"></div>
                    </div>
                </div>"#,
                category.name,
                category.score,
                category.max_points,
                percentage,
                grade_class,
                grade.as_str(),
                grade_class,
                percentage
            ));
        }

        html
    }

    /// Render enhanced radar chart with better visuals
    fn render_enhanced_radar_chart(categories: &[(String, f64)]) -> String {
        let n = categories.len();
        if n == 0 {
            return String::new();
        }

        let center_x: f64 = 200.0;
        let center_y: f64 = 180.0;
        let radius: f64 = 120.0;
        let angle_step = 360.0_f64 / n as f64;

        let mut html = String::from(r#"<svg class="radar-chart" viewBox="0 0 400 360" xmlns="http://www.w3.org/2000/svg">"#);

        // Draw web (concentric polygons)
        for (i, level) in [0.25_f64, 0.5_f64, 0.75_f64, 1.0_f64].iter().enumerate() {
            let points: Vec<String> = categories
                .iter()
                .enumerate()
                .map(|(j, _)| {
                    let angle = (j as f64 * angle_step - 90.0).to_radians();
                    let r = radius * level;
                    let x = center_x + r * angle.cos();
                    let y = center_y + r * angle.sin();
                    format!("{},{}", x, y)
                })
                .collect();

            let opacity = 0.3 + (i as f64 * 0.2);
            html.push_str(&format!(
                r#"<polygon class="radar-web" points="{}" style="stroke-opacity: {};" />"#,
                points.join(" "),
                opacity
            ));
        }

        // Draw axes
        for (i, _) in categories.iter().enumerate() {
            let angle = (i as f64 * angle_step - 90.0).to_radians();
            let end_x = center_x + radius * angle.cos();
            let end_y = center_y + radius * angle.sin();

            html.push_str(&format!(
                r#"<line class="radar-axis" x1="{}" y1="{}" x2="{}" y2="{}" />"#,
                center_x, center_y, end_x, end_y
            ));
        }

        // Draw data polygon with gradient
        let data_points: Vec<String> = categories
            .iter()
            .enumerate()
            .map(|(i, (_, score))| {
                let angle = (i as f64 * angle_step - 90.0).to_radians();
                let r = radius * (score / 100.0).max(0.1);
                let x = center_x + r * angle.cos();
                let y = center_y + r * angle.sin();
                format!("{},{}", x, y)
            })
            .collect();

        // Add gradient definition
        html.push_str(r#"<defs>
            <linearGradient id="radarGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:var(--accent-color);stop-opacity:0.6" />
                <stop offset="100%" style="stop-color:#60a5fa;stop-opacity:0.3" />
            </linearGradient>
        </defs>"#);

        html.push_str(&format!(
            r#"<polygon class="radar-polygon" points="{}" style="fill: url(#radarGradient);" />"#,
            data_points.join(" ")
        ));

        // Draw labels and values
        for (i, (category, score)) in categories.iter().enumerate() {
            let angle = (i as f64 * angle_step - 90.0).to_radians();

            // Adjust label position based on angle
            let label_radius = radius + 35.0;
            let label_x = center_x + label_radius * angle.cos();
            let label_y = center_y + label_radius * angle.sin();

            // Shorten category names
            let short_name = if category.len() > 12 {
                format!("{}...", &category[..9])
            } else {
                category.clone()
            };

            // Text anchor based on position
            let text_anchor = if label_x < center_x { "end" } else { "start" };

            html.push_str(&format!(
                r#"<text class="radar-label" x="{}" y="{}" text-anchor="{}">{}</text>"#,
                label_x, label_y - 8.0, text_anchor, short_name
            ));

            // Score with color
            let score_color = if *score >= 80.0 {
                "#22c55e"
            } else if *score >= 60.0 {
                "#eab308"
            } else {
                "#ef4444"
            };

            html.push_str(&format!(
                r#"<text class="radar-value" x="{}" y="{}" fill="{}" text-anchor="{}">{:.0}</text>"#,
                label_x, label_y + 10.0, score_color, text_anchor, score
            ));
        }

        // Draw data points with hover effect
        for (i, (_, score)) in categories.iter().enumerate() {
            let angle = (i as f64 * angle_step - 90.0).to_radians();
            let r = radius * (score / 100.0).max(0.1);
            let x = center_x + r * angle.cos();
            let y = center_y + r * angle.sin();

            html.push_str(&format!(
                r#"<circle class="radar-point" cx="{}" cy="{}" r="6" data-category="{}" data-score="{}" />"#,
                x, y, categories[i].0, score
            ));
        }

        html.push_str(r#"</svg>"#);
        html
    }

    /// Render recommendations section
    fn render_recommendations(security_score: &SecurityScore) -> String {
        let mut html = String::new();

        html.push_str(r#"<div class="recommendations-section">"#);
        html.push_str(r#"<h2>🎯 Priority Recommendations</h2>"#);

        for rec in &security_score.recommendations {
            let priority_class = match rec.priority {
                crate::scoring::RecommendationPriority::Critical => "critical",
                crate::scoring::RecommendationPriority::High => "high",
                crate::scoring::RecommendationPriority::Medium => "medium",
                crate::scoring::RecommendationPriority::Low => "low",
            };

            html.push_str(&format!(
                r#"<div class="recommendation-item {}">
                    <span class="recommendation-priority {}">{}</span>
                    <div class="recommendation-content">
                        <div class="recommendation-category">{}</div>
                        <div class="recommendation-text">{}</div>
                        <div class="recommendation-impact">Potential impact: +{} pts</div>
                    </div>
                </div>"#,
                priority_class, priority_class, rec.priority, rec.category, rec.text, rec.impact
            ));
        }

        html.push_str(r#"</div>"#);
        html
    }

    /// Render the findings section
    fn render_findings_section(report: &ScanReport) -> String {
        let mut html = String::new();

        html.push_str(r#"<div class="findings-section">"#);
        html.push_str(&format!(
            r#"<div class="findings-header">
                <h2>🔍 Vulnerability Findings</h2>
                <div class="filter-buttons">
                    <button class="filter-btn active" data-filter="all">All ({})</button>
                    <button class="filter-btn" data-filter="critical">Critical ({})</button>
                    <button class="filter-btn" data-filter="high">High ({})</button>
                    <button class="filter-btn" data-filter="medium">Medium ({})</button>
                    <button class="filter-btn" data-filter="low">Low ({})</button>
                    <button class="filter-btn" data-filter="info">Info ({})</button>
                </div>
            </div>"#,
            report.summary.total,
            report.summary.critical,
            report.summary.high,
            report.summary.medium,
            report.summary.low,
            report.summary.info
        ));

        html.push_str(r#"<div id="findings-container">"#);

        if report.findings.is_empty() {
            html.push_str(Self::render_empty_state());
        } else {
            for (index, finding) in report.findings.iter().enumerate() {
                html.push_str(&Self::render_finding(index, finding));
            }
        }

        html.push_str(r#"</div>"#);
        html.push_str(r#"</div>"#);

        html
    }

    /// Render empty state when no findings
    fn render_empty_state() -> &'static str {
        r#"<div class="empty-state">
            <div class="empty-state-icon">✅</div>
            <div class="empty-state-title">No vulnerabilities found</div>
            <p>The target appears to be secure based on the scan performed.</p>
        </div>"#
    }

    /// Render a single finding
    fn render_finding(index: usize, finding: &crate::scanners::Vuln) -> String {
        let severity_class = match finding.severity {
            VulnSeverity::Critical => "critical",
            VulnSeverity::High => "high",
            VulnSeverity::Medium => "medium",
            VulnSeverity::Low => "low",
            VulnSeverity::Info => "info",
        };

        let mut html = format!(
            r#"<div class="finding {}" data-severity="{}">"#,
            severity_class, severity_class
        );

        // Header
        html.push_str(&format!(
            r#"<div class="finding-header">
                <span class="finding-title">{}. {}</span>
                <span class="finding-severity {}">{}</span>
            </div>"#,
            index + 1,
            finding.title,
            severity_class,
            finding.severity
        ));

        // Description
        html.push_str(&format!(
            r#"<p class="finding-description">{}</p>"#,
            finding.description
        ));

        // Location
        if let Some(location) = &finding.location {
            html.push_str(&format!(
                r#"<p class="finding-location">📍 Location: <code>{}</code></p>"#,
                location
            ));
        }

        // Recommendation
        if let Some(recommendation) = &finding.recommendation {
            html.push_str(&format!(
                r#"<div class="finding-recommendation">
                    <strong>💡 Recommendation:</strong> {}
                </div>"#,
                recommendation
            ));
        }

        // Meta tags (CWE, OWASP)
        if finding.cwe.is_some() || finding.owasp.is_some() {
            html.push_str(r#"<div class="finding-meta">"#);

            if let Some(cwe) = &finding.cwe {
                html.push_str(&format!(r#"<span>🏷️ {}</span>"#, cwe));
            }

            if let Some(owasp) = &finding.owasp {
                html.push_str(&format!(r#"<span>📚 {}</span>"#, owasp));
            }

            html.push_str(r#"</div>"#);
        }

        html.push_str(r#"</div>"#);

        html
    }

    /// Render the footer
    fn render_footer() -> String {
        format!(
            r#"<div class="footer">
            <p>Generated by <a href="https://github.com/Pamacea/warden" target="_blank">Warden</a> v{} - AI-Powered Security CLI</p>
            <p style="margin-top: 0.5rem;">Report generated on <span id="report-timestamp"></span></p>
        </div>"#,
            env!("CARGO_PKG_VERSION")
        )
    }

    /// Generate JavaScript for interactivity
    fn javascript(security_score: &SecurityScore) -> String {
        // Build category data for JavaScript
        let mut category_data = String::new();
        for cat in &security_score.categories {
            category_data.push_str(&format!(
                "{{ name: '{}', score: {}, grade: '{}' }},",
                cat.name.replace("'", "\\'"),
                cat.percentage(),
                cat.grade().as_str()
            ));
        }

        format!(
            r#"<script>
        // Category data
        const categoryData = [{}];

        // Filter findings by severity
        function filterBySeverity(severity) {{
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => {{
                if (btn.dataset.filter === severity) {{
                    btn.classList.add('active');
                }} else {{
                    btn.classList.remove('active');
                }}
            }});

            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {{
                if (severity === 'all' || finding.dataset.severity === severity) {{
                    finding.style.display = 'block';
                }} else {{
                    finding.style.display = 'none';
                }}
            }});
        }}

        // Add click handlers to filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                filterBySeverity(btn.dataset.filter);
            }});
        }});

        // Set report timestamp
        const timestampEl = document.getElementById('report-timestamp');
        if (timestampEl) {{
            timestampEl.textContent = new Date().toLocaleString();
        }}

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {{
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

            switch(e.key) {{
                case '1': filterBySeverity('all'); break;
                case '2': filterBySeverity('critical'); break;
                case '3': filterBySeverity('high'); break;
                case '4': filterBySeverity('medium'); break;
                case '5': filterBySeverity('low'); break;
                case '6': filterBySeverity('info'); break;
            }}
        }});

        // Animate progress bars on load
        document.addEventListener('DOMContentLoaded', () => {{
            const progressBars = document.querySelectorAll('.progress-fill');
            progressBars.forEach(bar => {{
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {{
                    bar.style.width = width;
                }}, 100);
            }});

            // Animate grade circle
            const circleProgress = document.querySelector('.grade-circle-progress');
            if (circleProgress) {{
                const targetScore = circleProgress.dataset.score;
                const circumference = 2 * Math.PI * 70;
                const targetOffset = circumference - (targetScore / 100) * circumference;
                circleProgress.style.strokeDashoffset = circumference;
                setTimeout(() => {{
                    circleProgress.style.strokeDashoffset = targetOffset;
                }}, 200);
            }}
        }});

        // Radar chart point interactions
        document.querySelectorAll('.radar-point').forEach(point => {{
            point.addEventListener('mouseenter', (e) => {{
                const category = e.target.dataset.category;
                const score = e.target.dataset.score;
                e.target.style.r = '9';
                e.target.setAttribute('title', category + ': ' + score + '/100');
            }});
            point.addEventListener('mouseleave', (e) => {{
                e.target.style.r = '6';
            }});
        }});

        // Category item hover effects
        document.querySelectorAll('.category-item').forEach(item => {{
            item.addEventListener('mouseenter', () => {{
                item.style.transform = 'translateX(4px)';
            }});
            item.addEventListener('mouseleave', () => {{
                item.style.transform = 'translateX(0)';
            }});
        }});
        </script>"#,
            category_data
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::{Target, Vuln, VulnSeverity};

    #[test]
    fn test_html_format_empty_report() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let formatted = HtmlReporter::format(&report).unwrap();

        assert!(formatted.contains("<!DOCTYPE html>"));
        assert!(formatted.contains("Warden Security Report"));
        assert!(formatted.contains("No vulnerabilities found"));
        assert!(formatted.contains("</html>"));
    }

    #[test]
    fn test_html_format_with_findings() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "SQL Injection Vulnerability".to_string(),
            description: "User input is not properly sanitized".to_string(),
            location: Some("/api/users".to_string()),
            recommendation: Some("Use parameterized queries".to_string()),
            cwe: Some("CWE-89".to_string()),
            owasp: Some("A03:2021".to_string()),
        });

        let formatted = HtmlReporter::format(&report).unwrap();

        assert!(formatted.contains("SQL Injection Vulnerability"));
        assert!(formatted.contains("User input is not properly sanitized"));
        assert!(formatted.contains("/api/users"));
        assert!(formatted.contains("parameterized queries"));
        assert!(formatted.contains("CWE-89"));
        assert!(formatted.contains("A03:2021"));
        assert!(formatted.contains("high"));
    }

    #[test]
    fn test_html_css_styles() {
        let styles = HtmlReporter::css_styles();
        assert!(styles.contains(":root"));
        assert!(styles.contains("--color-critical"));
        assert!(styles.contains("--color-high"));
        assert!(styles.contains(".finding"));
        assert!(styles.contains(".filter-btn"));
    }

    #[test]
    fn test_security_score_integration() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        // No vulnerabilities - should be A+
        let score = SecurityScore::calculate(&report);
        assert!(score.score >= 90.0);
        assert!(matches!(score.grade, crate::scoring::Grade::A | crate::scoring::Grade::APlus));

        // Add multiple critical vulnerabilities that will reduce the score
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "SQL Injection".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "XSS".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });
        report.add_finding(Vuln {
            severity: VulnSeverity::High,
            title: "Auth Bypass".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let score_with_vuln = SecurityScore::calculate(&report);
        // With multiple critical vulnerabilities, score should definitely be lower
        assert!(score_with_vuln.score < score.score);
    }

    #[test]
    fn test_enhanced_radar_chart_generation() {
        let categories = vec![
            ("Input Validation".to_string(), 100.0),
            ("Authentication".to_string(), 75.0),
            ("Cryptography".to_string(), 50.0),
        ];

        let svg = HtmlReporter::render_enhanced_radar_chart(&categories);

        assert!(svg.contains("<svg"));
        assert!(svg.contains("radar-chart"));
        assert!(svg.contains("radar-web"));
        assert!(svg.contains("radar-polygon"));
        assert!(svg.contains("radar-point"));
        assert!(svg.contains("radarGradient"));
    }

    #[test]
    fn test_html_structure_complete() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let formatted = HtmlReporter::format(&report).unwrap();

        // Check all major sections are present
        assert!(formatted.contains("<head>"));
        assert!(formatted.contains("</head>"));
        assert!(formatted.contains("<body>"));
        assert!(formatted.contains("</body>"));
        assert!(formatted.contains("<style>"));
        assert!(formatted.contains("</style>"));
        assert!(formatted.contains("<script>"));
        assert!(formatted.contains("</script>"));
        assert!(formatted.contains("class=\"container\""));
        assert!(formatted.contains("class=\"header\""));
        assert!(formatted.contains("class=\"findings-section\""));
    }

    #[test]
    fn test_html_filter_buttons() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));
        report.add_finding(Vuln {
            severity: VulnSeverity::Critical,
            title: "Test".to_string(),
            description: "Test".to_string(),
            location: None,
            recommendation: None,
            cwe: None,
            owasp: None,
        });

        let formatted = HtmlReporter::format(&report).unwrap();

        assert!(formatted.contains("filter-buttons"));
        assert!(formatted.contains("data-filter=\"all\""));
        assert!(formatted.contains("data-filter=\"critical\""));
        assert!(formatted.contains("data-filter=\"high\""));
        assert!(formatted.contains("data-filter=\"medium\""));
        assert!(formatted.contains("data-filter=\"low\""));
        assert!(formatted.contains("data-filter=\"info\""));
        assert!(formatted.contains("filterBySeverity"));
    }

    #[test]
    fn test_html_severity_classes() {
        let mut report = ScanReport::new(Target::Url("http://example.com".to_string()));

        for severity in [
            VulnSeverity::Critical,
            VulnSeverity::High,
            VulnSeverity::Medium,
            VulnSeverity::Low,
            VulnSeverity::Info,
        ] {
            report.add_finding(Vuln {
                severity,
                title: format!("{:?} Test", severity),
                description: "Test".to_string(),
                location: None,
                recommendation: None,
                cwe: None,
                owasp: None,
            });
        }

        let formatted = HtmlReporter::format(&report).unwrap();

        assert!(formatted.contains("class=\"finding critical\""));
        assert!(formatted.contains("class=\"finding high\""));
        assert!(formatted.contains("class=\"finding medium\""));
        assert!(formatted.contains("class=\"finding low\""));
        assert!(formatted.contains("class=\"finding info\""));
    }

    #[test]
    fn test_html_responsive_styles() {
        let styles = HtmlReporter::css_styles();
        assert!(styles.contains("@media (max-width: 768px)"));
    }

    #[test]
    fn test_html_keyboard_shortcuts() {
        let report = ScanReport::new(Target::Url("http://example.com".to_string()));
        let formatted = HtmlReporter::format(&report).unwrap();

        // Check for keyboard shortcuts in switch statement format
        assert!(formatted.contains("case '1'"));
        assert!(formatted.contains("case '2'"));
        assert!(formatted.contains("filterBySeverity"));
    }
}
