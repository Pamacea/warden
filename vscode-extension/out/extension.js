"use strict";
/**
 * Warden Security - VS Code Extension
 *
 * Main extension entry point
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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const config_1 = require("./config");
const diagnostic_manager_1 = require("./diagnostic-manager");
const findings_provider_1 = require("./findings-provider");
const dashboard_panel_1 = require("./dashboard-panel");
const scanner_1 = require("./scanner");
/**
 * Extension activation
 */
async function activate(context) {
    // Initialize components
    const configManager = new config_1.ConfigManager();
    const diagnosticManager = new diagnostic_manager_1.DiagnosticManager();
    // Create tree data providers
    const findingsProvider = new findings_provider_1.FindingsProvider(diagnosticManager);
    const fileFindingsProvider = new findings_provider_1.FileFindingsProvider(diagnosticManager);
    // Create dashboard panel
    const dashboardPanel = new dashboard_panel_1.DashboardPanel(context, diagnosticManager);
    // Create scanner manager
    const scannerManager = new scanner_1.ScannerManager(configManager, diagnosticManager, findingsProvider, dashboardPanel);
    // Register tree views
    const findingsView = vscode.window.createTreeView('warden.findings', {
        treeDataProvider: findingsProvider,
        showCollapseAll: true,
    });
    // Register commands
    registerCommands(context, {
        configManager,
        diagnosticManager,
        findingsProvider,
        dashboardPanel,
        scannerManager,
    });
    // Register event handlers
    registerEventHandlers(context, {
        configManager,
        diagnosticManager,
        findingsProvider,
        scannerManager,
    });
    // Validate Warden installation
    await validateWardenInstallation(configManager);
    // Show welcome message on first activation
    await showWelcomeMessage(context);
    // Status bar item
    const statusBarItem = createStatusBarItem(context, configManager);
    context.subscriptions.push(configManager, diagnosticManager, findingsView, statusBarItem, {
        dispose: () => {
            scannerManager.dispose();
            dashboardPanel.dispose();
        },
    });
    console.log('Warden Security extension activated');
}
/**
 * Register all commands
 */
function registerCommands(context, services) {
    // Scan Current File
    const scanCurrentFileCommand = vscode.commands.registerCommand('warden.scanCurrentFile', async () => {
        await services.scannerManager.scanCurrentFile();
    });
    // Scan Project
    const scanProjectCommand = vscode.commands.registerCommand('warden.scanProject', async () => {
        await services.scannerManager.scanProject();
    });
    // Show Findings Panel
    const showFindingsCommand = vscode.commands.registerCommand('warden.showFindings', () => {
        vscode.commands.executeCommand('workbench.view.extension.warden-container');
    });
    // Scan URL
    const scanUrlCommand = vscode.commands.registerCommand('warden.scanUrl', async () => {
        const url = await vscode.window.showInputBox({
            prompt: 'Enter URL to scan',
            placeHolder: 'https://example.com',
            validateInput: (value) => {
                if (!value || !isValidUrl(value)) {
                    return 'Please enter a valid URL';
                }
                return null;
            },
        });
        if (url) {
            await services.scannerManager.queueScan({ Url: url });
        }
    });
    // Refresh Findings
    const refreshFindingsCommand = vscode.commands.registerCommand('warden.refreshFindings', () => {
        services.findingsProvider.refresh();
        services.dashboardPanel.update();
    });
    // Clear Findings
    const clearFindingsCommand = vscode.commands.registerCommand('warden.clearFindings', async () => {
        const confirm = await vscode.window.showWarningMessage('Clear all security findings?', 'Clear', 'Cancel');
        if (confirm === 'Clear') {
            services.diagnosticManager.clearAll();
            services.findingsProvider.refresh();
            services.dashboardPanel.update();
        }
    });
    // Configure Warden
    const configureCommand = vscode.commands.registerCommand('warden.configureWarden', async () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'warden');
    });
    // Ignore Finding
    const ignoreFindingCommand = vscode.commands.registerCommand('warden.ignoreFinding', async (item) => {
        if (item && item.vuln) {
            const reason = await vscode.window.showInputBox({
                prompt: 'Reason for ignoring (optional)',
                placeHolder: 'False positive',
            });
            const uri = vscode.Uri.parse(item.uri);
            services.diagnosticManager.ignoreFinding(uri, item.vuln.id, reason);
            services.findingsProvider.refresh();
        }
    });
    // Copy Finding ID
    const copyFindingIdCommand = vscode.commands.registerCommand('warden.copyFindingId', async (item) => {
        if (item && item.vuln) {
            await vscode.env.clipboard.writeText(item.vuln.id || '');
            vscode.window.showInformationMessage('Finding ID copied to clipboard');
        }
    });
    // Apply Quick Fix
    const applyQuickFixCommand = vscode.commands.registerCommand('warden.applyQuickFix', async (item) => {
        if (item && item.vuln && item.vuln.quickFix) {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active editor');
                return;
            }
            const workspaceEdit = new vscode.WorkspaceEdit();
            const uri = editor.document.uri;
            for (const edit of item.vuln.quickFix.edits) {
                const range = new vscode.Range(new vscode.Position(edit.range.start.line, edit.range.start.character), new vscode.Position(edit.range.end.line, edit.range.end.character));
                workspaceEdit.replace(uri, range, edit.newText);
            }
            await vscode.workspace.applyEdit(workspaceEdit);
            vscode.window.showInformationMessage('Quick fix applied');
        }
    });
    // Open Finding
    const openFindingCommand = vscode.commands.registerCommand('warden.openFinding', async (uri, range) => {
        const document = await vscode.workspace.openTextDocument(vscode.Uri.parse(uri));
        const editor = await vscode.window.showTextDocument(document);
        if (range) {
            const vscodeRange = new vscode.Range(new vscode.Position(range.start.line, range.start.character), new vscode.Position(range.end.line, range.end.character));
            editor.selection = new vscode.Selection(vscodeRange.start, vscodeRange.end);
            editor.revealRange(vscodeRange, vscode.TextEditorRevealType.InCenter);
        }
    });
    // Show Dashboard
    const showDashboardCommand = vscode.commands.registerCommand('warden.showDashboard', () => {
        services.dashboardPanel.show();
    });
    // Config changed notification
    const configChangedCommand = vscode.commands.registerCommand('warden.configChanged', (config) => {
        // Handle config changes
        services.scannerManager['updateConfig']();
    });
    // Scan update notification
    const scanUpdateCommand = vscode.commands.registerCommand('warden.scanUpdate', (state) => {
        // Update status bar based on scan state
    });
    // Register all commands
    context.subscriptions.push(scanCurrentFileCommand, scanProjectCommand, showFindingsCommand, scanUrlCommand, refreshFindingsCommand, clearFindingsCommand, configureCommand, ignoreFindingCommand, copyFindingIdCommand, applyQuickFixCommand, openFindingCommand, showDashboardCommand, configChangedCommand, scanUpdateCommand);
}
/**
 * Register event handlers
 */
function registerEventHandlers(context, services) {
    // Document save handler
    const saveHandler = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = services.configManager.getConfiguration();
        if (config.scanOnSave && services.configManager.shouldScanFile(document.uri.fsPath)) {
            await services.scannerManager.scanCurrentFile();
        }
    });
    // Document open handler
    const openHandler = vscode.workspace.onDidOpenTextDocument(async (document) => {
        const config = services.configManager.getConfiguration();
        if (config.scanOnOpen && services.configManager.shouldScanFile(document.uri.fsPath)) {
            await services.scannerManager.scanCurrentFile();
        }
    });
    // Document close handler - clear diagnostics
    const closeHandler = vscode.workspace.onDidCloseTextDocument((document) => {
        services.diagnosticManager.clearFile(document.uri);
        services.findingsProvider.refresh();
    });
    context.subscriptions.push(saveHandler, openHandler, closeHandler);
}
/**
 * Validate Warden installation
 */
async function validateWardenInstallation(configManager) {
    const isValid = await configManager.validateInstallation();
    if (!isValid) {
        const action = await vscode.window.showWarningMessage('Warden CLI not found or not accessible. Please install Warden or configure the path.', 'Configure Path', 'Install Warden', 'Dismiss');
        switch (action) {
            case 'Configure Path':
                vscode.commands.executeCommand('workbench.action.openSettings', 'warden.executablePath');
                break;
            case 'Install Warden':
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/Pamacea/warden#installation'));
                break;
        }
    }
}
/**
 * Show welcome message
 */
async function showWelcomeMessage(context) {
    const shown = context.globalState.get('warden.welcomeShown');
    if (!shown) {
        const action = await vscode.window.showInformationMessage('Welcome to Warden Security! Start by scanning your project or current file.', 'Scan Project', 'Learn More', 'Dismiss');
        switch (action) {
            case 'Scan Project':
                vscode.commands.executeCommand('warden.scanProject');
                break;
            case 'Learn More':
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/Pamacea/warden'));
                break;
        }
        await context.globalState.update('warden.welcomeShown', true);
    }
}
/**
 * Create status bar item
 */
function createStatusBarItem(context, configManager) {
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'warden.showFindings';
    statusBarItem.tooltip = 'Show Warden Security Findings';
    statusBarItem.text = '$(shield) Warden';
    statusBarItem.show();
    return statusBarItem;
}
/**
 * Validate URL
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Extension deactivation
 */
function deactivate() {
    console.log('Warden Security extension deactivated');
}
//# sourceMappingURL=extension.js.map