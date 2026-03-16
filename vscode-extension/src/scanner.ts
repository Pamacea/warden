/**
 * Scanner Manager
 *
 * Manages scanning operations and coordinates between components
 */

import * as vscode from 'vscode';
import { WardenCli } from './warden-cli';
import { ConfigManager } from './config';
import { DiagnosticManager } from './diagnostic-manager';
import { FindingsProvider } from './findings-provider';
import { DashboardPanel } from './dashboard-panel';
import { ScanMode, Vuln, ScanState, Target } from './types';

/**
 * Scan queue item
 */
interface QueuedScan {
  id: string;
  target: Target;
  mode: ScanMode;
  priority: number;
}

/**
 * Scanner manager class
 */
export class ScannerManager {
  private cli: WardenCli;
  private scanQueue: QueuedScan[] = [];
  private activeScans: Map<string, ScanState> = new Map();
  private maxConcurrentScans: number = 3;
  private isProcessing: boolean = false;

  constructor(
    private configManager: ConfigManager,
    private diagnosticManager: DiagnosticManager,
    private findingsProvider: FindingsProvider,
    private dashboardPanel: DashboardPanel
  ) {
    this.cli = new WardenCli(configManager.getExecutablePath());
    this.updateConfig();
  }

  /**
   * Update configuration
   */
  private updateConfig(): void {
    const config = this.configManager.getConfiguration();
    this.cli = new WardenCli(this.configManager.getExecutablePath());
    this.maxConcurrentScans = config.maxConcurrentScans;
  }

  /**
   * Queue a scan operation
   */
  async queueScan(
    target: Target,
    mode: ScanMode = ScanMode.Active,
    priority: number = 0
  ): Promise<string> {
    const scanId = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    this.scanQueue.push({
      id: scanId,
      target,
      mode,
      priority,
    });

    // Sort by priority (higher first)
    this.scanQueue.sort((a, b) => b.priority - a.priority);

    // Create pending state
    this.activeScans.set(scanId, {
      id: scanId,
      target,
      mode,
      status: 'pending',
      startTime: Date.now(),
      findings: [],
    });

    this.processQueue();

    return scanId;
  }

  /**
   * Process the scan queue
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessing || this.scanQueue.length === 0) {
      return;
    }

    // Count active scans
    const runningCount = Array.from(this.activeScans.values()).filter(
      (s) => s.status === 'running'
    ).length;

    if (runningCount >= this.maxConcurrentScans) {
      return;
    }

    this.isProcessing = true;

    while (this.scanQueue.length > 0 && runningCount < this.maxConcurrentScans) {
      const scan = this.scanQueue.shift();
      if (scan) {
        this.runScan(scan);
      }
    }

    this.isProcessing = false;
  }

  /**
   * Run a single scan
   */
  private async runScan(queuedScan: QueuedScan): Promise<void> {
    const state = this.activeScans.get(queuedScan.id);
    if (!state) {
      return;
    }

    state.status = 'running';
    this.notifyScanUpdate(state);

    try {
      let result;

      if (queuedScan.target.Url) {
        result = await this.cli.scanUrl(
          queuedScan.target.Url,
          queuedScan.mode
        );
      } else if (queuedScan.target.Path) {
        const config = this.configManager.getConfiguration();
        result = await this.cli.scanPath(queuedScan.target.Path, queuedScan.mode, {
          checkSecrets: config.enableSecretsDetection,
          checkDeps: config.enableDependencyCheck,
          severityLevel: config.severityLevel,
          timeout: config.timeout,
        });
      } else {
        throw new Error('Invalid scan target');
      }

      if (result.success && result.report) {
        state.status = 'completed';
        state.endTime = Date.now();
        state.findings = result.report.findings;

        // Update diagnostics
        this.processFindings(result.report.findings, result.report.target);

        // Show notification if configured
        this.showNotifications(result.report.findings);

        // Update dashboard
        this.dashboardPanel.update();
      } else {
        state.status = 'failed';
        state.error = result.error;
        vscode.window.showErrorMessage(
          `Warden scan failed: ${result.error || 'Unknown error'}`
        );
      }
    } catch (error) {
      state.status = 'failed';
      state.error = error instanceof Error ? error.message : String(error);
      vscode.window.showErrorMessage(
        `Warden scan error: ${state.error}`
      );
    } finally {
      this.notifyScanUpdate(state);
      this.processQueue();
    }
  }

  /**
   * Process findings and update diagnostics
   */
  private processFindings(findings: Vuln[], target: Target): void {
    if (target.Path) {
      // File/directory scan - update diagnostics for each file
      const findingsByFile = this.groupFindingsByFile(findings);

      for (const [filePath, fileFindings] of findingsByFile) {
        const uri = vscode.Uri.file(filePath);
        this.diagnosticManager.setFindings(uri, fileFindings);
      }
    } else if (target.Url) {
      // URL scan - show in dashboard only
    }

    // Refresh findings provider
    this.findingsProvider.refresh();
  }

  /**
   * Group findings by file path
   */
  private groupFindingsByFile(findings: Vuln[]): Map<string, Vuln[]> {
    const grouped = new Map<string, Vuln[]>();

    for (const finding of findings) {
      let filePath = finding.location || '';

      // Extract file path from location if it contains line numbers
      const match = filePath.match(/^([^:]+):/);
      if (match) {
        filePath = match[1];
      }

      if (!filePath) {
        continue;
      }

      if (!grouped.has(filePath)) {
        grouped.set(filePath, []);
      }

      grouped.get(filePath)!.push(finding);
    }

    return grouped;
  }

  /**
   * Show notifications based on configuration
   */
  private showNotifications(findings: Vuln[]): void {
    const config = this.configManager.getConfiguration();

    // Group by severity
    const bySeverity: Record<string, Vuln[]> = {
      Critical: [],
      High: [],
      Medium: [],
      Low: [],
      Info: [],
    };

    for (const finding of findings) {
      bySeverity[finding.severity].push(finding);
    }

    // Show notifications for enabled severities
    for (const [severity, severityFindings] of Object.entries(bySeverity)) {
      if (severityFindings.length > 0) {
        const shouldNotify = this.configManager.shouldNotify(
          severity as any
        );

        if (shouldNotify) {
          this.showSeverityNotification(
            severity as any,
            severityFindings.length
          );
        }
      }
    }
  }

  /**
   * Show notification for a specific severity
   */
  private showSeverityNotification(severity: string, count: number): void {
    const message = `Warden found ${count} ${severity} issue${count > 1 ? 's' : ''}`;

    switch (severity) {
      case 'Critical':
        vscode.window.showErrorMessage(message, 'Show Findings').then((selection) => {
          if (selection === 'Show Findings') {
            vscode.commands.executeCommand('warden.showFindings');
          }
        });
        break;
      case 'High':
        vscode.window.showWarningMessage(message, 'Show Findings').then((selection) => {
          if (selection === 'Show Findings') {
            vscode.commands.executeCommand('warden.showFindings');
          }
        });
        break;
      default:
        vscode.window.showInformationMessage(message, 'Show Findings').then((selection) => {
          if (selection === 'Show Findings') {
            vscode.commands.executeCommand('warden.showFindings');
          }
        });
    }
  }

  /**
   * Notify about scan updates
   */
  private notifyScanUpdate(state: ScanState): void {
    vscode.commands.executeCommand('warden.scanUpdate', state);
  }

  /**
   * Cancel a scan
   */
  cancelScan(scanId: string): void {
    const state = this.activeScans.get(scanId);
    if (state && state.status === 'running') {
      // Remove from queue if pending
      this.scanQueue = this.scanQueue.filter((s) => s.id !== scanId);

      // Cancel via CLI
      this.cli.cancelAllScans();

      state.status = 'cancelled';
      state.endTime = Date.now();
      this.notifyScanUpdate(state);
    }
  }

  /**
   * Cancel all scans
   */
  cancelAllScans(): void {
    this.cli.cancelAllScans();

    for (const state of this.activeScans.values()) {
      if (state.status === 'running' || state.status === 'pending') {
        state.status = 'cancelled';
        state.endTime = Date.now();
      }
    }

    this.scanQueue = [];
  }

  /**
   * Get active scan states
   */
  getActiveScans(): ScanState[] {
    return Array.from(this.activeScans.values()).filter(
      (s) => s.status === 'running' || s.status === 'pending'
    );
  }

  /**
   * Scan the current file
   */
  async scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('No active file to scan');
      return;
    }

    const document = editor.document;
    if (document.isUntitled) {
      vscode.window.showWarningMessage('Cannot scan unsaved files');
      return;
    }

    const filePath = document.uri.fsPath;
    const config = this.configManager.getConfiguration();

    if (!this.configManager.shouldScanFile(filePath)) {
      vscode.window.showInformationMessage('File is ignored by Warden configuration');
      return;
    }

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Warden: Scanning ${document.fileName}`,
        cancellable: true,
      },
      async (progress, token) => {
        token.onCancellationRequested(() => {
          // Cancel active scans
          this.cancelAllScans();
        });

        const scanId = await this.queueScan(
          { Path: filePath },
          config.scanMode,
          10 // High priority for current file
        );

        // Wait for scan to complete
        await this.waitForScan(scanId);
      }
    );
  }

  /**
   * Scan the entire project
   */
  async scanProject(): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
      vscode.window.showWarningMessage('No workspace folder found');
      return;
    }

    const config = this.configManager.getConfiguration();

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Warden: Scanning project ${workspaceFolder.name}`,
        cancellable: true,
      },
      async (progress, token) => {
        token.onCancellationRequested(() => {
          this.cancelAllScans();
        });

        progress.report({ message: 'Initializing scan...' });

        const scanId = await this.queueScan(
          { Path: workspaceFolder.uri.fsPath },
          config.scanMode,
          5 // Medium priority for project scan
        );

        // Wait for scan to complete
        await this.waitForScan(scanId);
      }
    );
  }

  /**
   * Wait for a scan to complete
   */
  private async waitForScan(scanId: string): Promise<void> {
    return new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        const state = this.activeScans.get(scanId);
        if (!state || (state.status !== 'running' && state.status !== 'pending')) {
          clearInterval(checkInterval);
          resolve();
        }
      }, 500);
    });
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    this.cancelAllScans();
  }
}
