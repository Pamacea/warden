"use strict";
/**
 * Scanner Manager
 *
 * Manages scanning operations and coordinates between components
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScannerManager = void 0;
const vscode = __importStar(require("vscode"));
const warden_cli_1 = require("./warden-cli");
const types_1 = require("./types");
/**
 * Scanner manager class
 */
class ScannerManager {
    constructor(configManager, diagnosticManager, findingsProvider, dashboardPanel) {
        this.configManager = configManager;
        this.diagnosticManager = diagnosticManager;
        this.findingsProvider = findingsProvider;
        this.dashboardPanel = dashboardPanel;
        this.scanQueue = [];
        this.activeScans = new Map();
        this.maxConcurrentScans = 3;
        this.isProcessing = false;
        this.cli = new warden_cli_1.WardenCli(configManager.getExecutablePath());
        this.updateConfig();
    }
    /**
     * Update configuration
     */
    updateConfig() {
        const config = this.configManager.getConfiguration();
        this.cli = new warden_cli_1.WardenCli(this.configManager.getExecutablePath());
        this.maxConcurrentScans = config.maxConcurrentScans;
    }
    /**
     * Queue a scan operation
     */
    async queueScan(target, mode = types_1.ScanMode.Active, priority = 0) {
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
    async processQueue() {
        if (this.isProcessing || this.scanQueue.length === 0) {
            return;
        }
        // Count active scans
        const runningCount = Array.from(this.activeScans.values()).filter((s) => s.status === 'running').length;
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
    async runScan(queuedScan) {
        const state = this.activeScans.get(queuedScan.id);
        if (!state) {
            return;
        }
        state.status = 'running';
        this.notifyScanUpdate(state);
        try {
            let result;
            if (queuedScan.target.Url) {
                result = await this.cli.scanUrl(queuedScan.target.Url, queuedScan.mode);
            }
            else if (queuedScan.target.Path) {
                const config = this.configManager.getConfiguration();
                result = await this.cli.scanPath(queuedScan.target.Path, queuedScan.mode, {
                    checkSecrets: config.enableSecretsDetection,
                    checkDeps: config.enableDependencyCheck,
                    severityLevel: config.severityLevel,
                    timeout: config.timeout,
                });
            }
            else {
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
            }
            else {
                state.status = 'failed';
                state.error = result.error;
                vscode.window.showErrorMessage(`Warden scan failed: ${result.error || 'Unknown error'}`);
            }
        }
        catch (error) {
            state.status = 'failed';
            state.error = error instanceof Error ? error.message : String(error);
            vscode.window.showErrorMessage(`Warden scan error: ${state.error}`);
        }
        finally {
            this.notifyScanUpdate(state);
            this.processQueue();
        }
    }
    /**
     * Process findings and update diagnostics
     */
    processFindings(findings, target) {
        if (target.Path) {
            // File/directory scan - update diagnostics for each file
            const findingsByFile = this.groupFindingsByFile(findings);
            for (const [filePath, fileFindings] of findingsByFile) {
                const uri = vscode.Uri.file(filePath);
                this.diagnosticManager.setFindings(uri, fileFindings);
            }
        }
        else if (target.Url) {
            // URL scan - show in dashboard only
        }
        // Refresh findings provider
        this.findingsProvider.refresh();
    }
    /**
     * Group findings by file path
     */
    groupFindingsByFile(findings) {
        const grouped = new Map();
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
            grouped.get(filePath).push(finding);
        }
        return grouped;
    }
    /**
     * Show notifications based on configuration
     */
    showNotifications(findings) {
        const config = this.configManager.getConfiguration();
        // Group by severity
        const bySeverity = {
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
                const shouldNotify = this.configManager.shouldNotify(severity);
                if (shouldNotify) {
                    this.showSeverityNotification(severity, severityFindings.length);
                }
            }
        }
    }
    /**
     * Show notification for a specific severity
     */
    showSeverityNotification(severity, count) {
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
    notifyScanUpdate(state) {
        vscode.commands.executeCommand('warden.scanUpdate', state);
    }
    /**
     * Cancel a scan
     */
    cancelScan(scanId) {
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
    cancelAllScans() {
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
    getActiveScans() {
        return Array.from(this.activeScans.values()).filter((s) => s.status === 'running' || s.status === 'pending');
    }
    /**
     * Scan the current file
     */
    async scanCurrentFile() {
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
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Warden: Scanning ${document.fileName}`,
            cancellable: true,
        }, async (progress, token) => {
            token.onCancellationRequested(() => {
                // Cancel active scans
                this.cancelAllScans();
            });
            const scanId = await this.queueScan({ Path: filePath }, config.scanMode, 10 // High priority for current file
            );
            // Wait for scan to complete
            await this.waitForScan(scanId);
        });
    }
    /**
     * Scan the entire project
     */
    async scanProject() {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showWarningMessage('No workspace folder found');
            return;
        }
        const config = this.configManager.getConfiguration();
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Warden: Scanning project ${workspaceFolder.name}`,
            cancellable: true,
        }, async (progress, token) => {
            token.onCancellationRequested(() => {
                this.cancelAllScans();
            });
            progress.report({ message: 'Initializing scan...' });
            const scanId = await this.queueScan({ Path: workspaceFolder.uri.fsPath }, config.scanMode, 5 // Medium priority for project scan
            );
            // Wait for scan to complete
            await this.waitForScan(scanId);
        });
    }
    /**
     * Wait for a scan to complete
     */
    async waitForScan(scanId) {
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
    dispose() {
        this.cancelAllScans();
    }
}
exports.ScannerManager = ScannerManager;
//# sourceMappingURL=scanner.js.map