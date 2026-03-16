/**
 * Security Dashboard Panel
 *
 * Webview panel showing security metrics and insights
 */

import * as vscode from 'vscode';
import { ScanReport, SecurityScore, VulnSeverity } from './types';
import { DiagnosticManager } from './diagnostic-manager';

/**
 * Dashboard panel class
 */
export class DashboardPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private context: vscode.ExtensionContext,
    private diagnosticManager: DiagnosticManager
  ) {}

  /**
   * Show or create the dashboard panel
   */
  show(): void {
    if (this.panel) {
      this.panel.reveal();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'wardenDashboard',
      'Warden Security Dashboard',
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(this.context.extensionUri, 'media'),
        ],
      }
    );

    this.panel.webview.html = this.getWebviewContent();

    // Handle messages from webview
    this.panel.webview.onDidReceiveMessage(
      (message) => this.handleMessage(message),
      undefined,
      this.disposables
    );

    // Update when panel is disposed
    this.panel.onDidDispose(
      () => {
        this.panel = undefined;
        this.disposables.forEach((d) => d.dispose());
      },
      undefined,
      this.disposables
    );
  }

  /**
   * Update the dashboard with new data
   */
  update(): void {
    if (!this.panel) {
      return;
    }

    const counts = this.diagnosticManager.getCountBySeverity();
    const total = this.diagnosticManager.getTotalCount();

    this.panel.webview.postMessage({
      type: 'update',
      data: {
        counts,
        total,
        findings: this.getRecentFindings(),
      },
    });
  }

  /**
   * Get webview HTML content
   */
  private getWebviewContent(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Warden Security Dashboard</title>
    <style>
        :root {
            --bg-color: var(--vscode-editor-background);
            --fg-color: var(--vscode-editor-foreground);
            --border-color: var(--vscode-panel-border);
            --primary-color: var(--vscode-textLink-foreground);
            --critical-color: #f14c4c;
            --high-color: #ff6b6b;
            --medium-color: #ffab00;
            --low-color: #3794ff;
            --info-color: #85c8e8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--vscode-font-family);
            background-color: var(--bg-color);
            color: var(--fg-color);
            padding: 20px;
            line-height: 1.5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 20px;
        }

        h1 {
            font-size: 24px;
            margin-bottom: 8px;
        }

        .subtitle {
            color: var(--vscode-descriptionForeground);
            font-size: 14px;
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .metric-card {
            background-color: var(--vscode-editor-inactiveSelectionBackground);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
        }

        .metric-title {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 8px;
            text-transform: uppercase;
        }

        .metric-value {
            font-size: 32px;
            font-weight: bold;
        }

        .metric-value.critical { color: var(--critical-color); }
        .metric-value.high { color: var(--high-color); }
        .metric-value.medium { color: var(--medium-color); }
        .metric-value.low { color: var(--low-color); }
        .metric-value.info { color: var(--info-color); }

        .severity-bar {
            height: 8px;
            background-color: var(--vscode-progressBar-background);
            border-radius: 4px;
            overflow: hidden;
            display: flex;
            margin-top: 8px;
        }

        .severity-segment {
            height: 100%;
            transition: width 0.3s ease;
        }

        .severity-segment.critical { background-color: var(--critical-color); }
        .severity-segment.high { background-color: var(--high-color); }
        .severity-segment.medium { background-color: var(--medium-color); }
        .severity-segment.low { background-color: var(--low-color); }
        .severity-segment.info { background-color: var(--info-color); }

        .section {
            margin-bottom: 24px;
        }

        .section-title {
            font-size: 18px;
            margin-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }

        .findings-list {
            list-style: none;
        }

        .finding-item {
            background-color: var(--vscode-editor-inactiveSelectionBackground);
            border-left: 4px solid;
            border-radius: 4px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .finding-item:hover {
            background-color: var(--vscode-list-hoverBackground);
        }

        .finding-item.critical { border-color: var(--critical-color); }
        .finding-item.high { border-color: var(--high-color); }
        .finding-item.medium { border-color: var(--medium-color); }
        .finding-item.low { border-color: var(--low-color); }
        .finding-item.info { border-color: var(--info-color); }

        .finding-title {
            font-weight: 600;
            margin-bottom: 4px;
        }

        .finding-location {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }

        .actions {
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }

        .btn {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-size: 14px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .btn:hover {
            background-color: var(--vscode-button-hoverBackground);
        }

        .btn-secondary {
            background-color: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }

        .btn-secondary:hover {
            background-color: var(--vscode-button-secondaryHoverBackground);
        }

        .empty-state {
            text-align: center;
            padding: 48px;
            color: var(--vscode-descriptionForeground);
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Warden Security Dashboard</h1>
            <p class="subtitle">Real-time security analysis for your project</p>
        </header>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-title">Total Findings</div>
                <div class="metric-value" id="total-count">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Critical</div>
                <div class="metric-value critical" id="critical-count">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">High</div>
                <div class="metric-value high" id="high-count">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Medium</div>
                <div class="metric-value medium" id="medium-count">0</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Low / Info</div>
                <div class="metric-value info" id="low-count">0</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Severity Distribution</h2>
            <div class="severity-bar" id="severity-bar"></div>
        </div>

        <div class="section">
            <h2 class="section-title">Recent Findings</h2>
            <ul class="findings-list" id="findings-list">
                <li class="empty-state">
                    <div class="empty-state-icon">shield</div>
                    <div>No findings yet. Scan your project to see security issues.</div>
                </li>
            </ul>
        </div>

        <div class="actions">
            <button class="btn" onclick="scanCurrentFile()">Scan Current File</button>
            <button class="btn btn-secondary" onclick="scanProject()">Scan Project</button>
            <button class="btn btn-secondary" onclick="showFindings()">View All Findings</button>
        </div>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function updateDashboard(data) {
            document.getElementById('total-count').textContent = data.total;
            document.getElementById('critical-count').textContent = data.counts.critical;
            document.getElementById('high-count').textContent = data.counts.high;
            document.getElementById('medium-count').textContent = data.counts.medium;
            document.getElementById('low-count').textContent = data.counts.low + data.counts.info;

            // Update severity bar
            updateSeverityBar(data.counts, data.total);

            // Update findings list
            updateFindingsList(data.findings);
        }

        function updateSeverityBar(counts, total) {
            const bar = document.getElementById('severity-bar');
            if (total === 0) {
                bar.innerHTML = '<div class="severity-segment" style="width: 100%; background-color: var(--vscode-descriptionForeground);"></div>';
                return;
            }

            const critical = (counts.critical / total) * 100;
            const high = (counts.high / total) * 100;
            const medium = (counts.medium / total) * 100;
            const low = ((counts.low + counts.info) / total) * 100;

            bar.innerHTML = \`
                \${critical > 0 ? \`<div class="severity-segment critical" style="width: \${critical}%"></div>\` : ''}
                \${high > 0 ? \`<div class="severity-segment high" style="width: \${high}%"></div>\` : ''}
                \${medium > 0 ? \`<div class="severity-segment medium" style="width: \${medium}%"></div>\` : ''}
                \${low > 0 ? \`<div class="severity-segment low" style="width: \${low}%"></div>\` : ''}
            \`;
        }

        function updateFindingsList(findings) {
            const list = document.getElementById('findings-list');

            if (!findings || findings.length === 0) {
                list.innerHTML = \`
                    <li class="empty-state">
                        <div class="empty-state-icon">shield</div>
                        <div>No findings yet. Scan your project to see security issues.</div>
                    </li>
                \`;
                return;
            }

            list.innerHTML = findings.map(finding => \`
                <li class="finding-item \${finding.severity.toLowerCase()}" onclick="openFinding('\${finding.id}')">
                    <div class="finding-title">\${finding.title}</div>
                    <div class="finding-location">\${finding.location || 'Unknown location'}</div>
                </li>
            \`).join('');
        }

        function scanCurrentFile() {
            vscode.postMessage({ type: 'scanCurrentFile' });
        }

        function scanProject() {
            vscode.postMessage({ type: 'scanProject' });
        }

        function showFindings() {
            vscode.postMessage({ type: 'showFindings' });
        }

        function openFinding(id) {
            vscode.postMessage({ type: 'openFinding', data: id });
        }

        // Listen for messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'update':
                    updateDashboard(message.data);
                    break;
            }
        });

        // Request initial data
        vscode.postMessage({ type: 'init' });
    </script>
</body>
</html>`;
  }

  /**
   * Get recent findings
   */
  private getRecentFindings(): any[] {
    const allFindings = this.diagnosticManager.getAllFindings();
    const recent: any[] = [];

    for (const [uri, findings] of allFindings) {
      for (const finding of findings) {
        if (!finding.ignored) {
          recent.push({
            ...finding,
            uri,
          });
        }
      }
    }

    return recent.slice(0, 10);
  }

  /**
   * Handle messages from webview
   */
  private handleMessage(message: any): void {
    switch (message.type) {
      case 'init':
        this.update();
        break;
      case 'scanCurrentFile':
        vscode.commands.executeCommand('warden.scanCurrentFile');
        break;
      case 'scanProject':
        vscode.commands.executeCommand('warden.scanProject');
        break;
      case 'showFindings':
        vscode.commands.executeCommand('warden.showFindings');
        break;
      case 'openFinding':
        // Handle opening finding
        break;
    }
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    this.panel?.dispose();
    this.disposables.forEach((d) => d.dispose());
  }
}
