"use strict";
/**
 * Warden CLI Interface
 *
 * Handles communication with the Warden CLI executable
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
exports.WardenCli = void 0;
exports.findWardenExecutable = findWardenExecutable;
exports.parseWardenOutput = parseWardenOutput;
exports.findingsToDiagnostics = findingsToDiagnostics;
exports.createCodeAction = createCodeAction;
const vscode = __importStar(require("vscode"));
const child_process_1 = require("child_process");
const types_1 = require("./types");
/**
 * Warden CLI client class
 */
class WardenCli {
    constructor(executablePath) {
        this.activeProcesses = new Map();
        this.executablePath = executablePath;
    }
    /**
     * Scan a file or directory
     */
    async scanPath(path, mode = types_1.ScanMode.Active, options = {}) {
        const startTime = Date.now();
        try {
            const args = this.buildScanArgs(path, mode, options);
            const result = await this.runCommand(args, options.timeout || 30000);
            const report = JSON.parse(result);
            return {
                success: true,
                report,
                duration: Date.now() - startTime,
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error),
                duration: Date.now() - startTime,
            };
        }
    }
    /**
     * Scan a URL
     */
    async scanUrl(url, mode = types_1.ScanMode.Active, options = {}) {
        const startTime = Date.now();
        try {
            const args = ['scan', url, '--mode', mode, '--json'];
            if (options.aggressive) {
                args.push('--aggressive');
            }
            const result = await this.runCommand(args, options.timeout || 30000);
            const report = JSON.parse(result);
            return {
                success: true,
                report,
                duration: Date.now() - startTime,
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error),
                duration: Date.now() - startTime,
            };
        }
    }
    /**
     * Scan a file and get raw output for parsing
     */
    async scanFileRaw(filePath) {
        const args = ['scan', filePath, '--json'];
        return this.runCommand(args, 30000);
    }
    /**
     * Build scan arguments
     */
    buildScanArgs(path, mode, options) {
        const args = ['scan', path, '--mode', mode, '--json'];
        if (options.checkSecrets) {
            args.push('--check-secrets');
        }
        if (options.checkDeps) {
            args.push('--check-deps');
        }
        if (options.severityLevel) {
            args.push('--min-severity', options.severityLevel);
        }
        return args;
    }
    /**
     * Run a Warden command and return the output
     */
    runCommand(args, timeout) {
        return new Promise((resolve, reject) => {
            let stdout = '';
            let stderr = '';
            const proc = (0, child_process_1.spawn)(this.executablePath, args, {
                stdio: ['ignore', 'pipe', 'pipe'],
                env: { ...process.env },
            });
            const scanId = `scan-${Date.now()}`;
            this.activeProcesses.set(scanId, proc);
            const timer = setTimeout(() => {
                proc.kill();
                reject(new Error(`Scan timeout after ${timeout}ms`));
            }, timeout);
            proc.stdout?.on('data', (data) => {
                stdout += data.toString();
            });
            proc.stderr?.on('data', (data) => {
                stderr += data.toString();
            });
            proc.on('close', (code) => {
                clearTimeout(timer);
                this.activeProcesses.delete(scanId);
                if (code === 0) {
                    resolve(stdout);
                }
                else {
                    reject(new Error(stderr || `Warden exited with code ${code}`));
                }
            });
            proc.on('error', (error) => {
                clearTimeout(timer);
                this.activeProcesses.delete(scanId);
                reject(new Error(`Failed to run Warden: ${error.message}`));
            });
        });
    }
    /**
     * Get Warden version
     */
    async getVersion() {
        try {
            const args = ['--version'];
            const result = await this.runCommand(args, 5000);
            return result.trim();
        }
        catch {
            return null;
        }
    }
    /**
     * Get available scanners
     */
    async getAvailableScanners() {
        try {
            const args = ['--list-scanners'];
            const result = await this.runCommand(args, 5000);
            return result.split('\n').filter((s) => s.trim());
        }
        catch {
            return [];
        }
    }
    /**
     * Cancel all active scans
     */
    cancelAllScans() {
        for (const [id, proc] of this.activeProcesses) {
            proc.kill();
            this.activeProcesses.delete(id);
        }
    }
    /**
     * Check if Warden is available
     */
    static async isAvailable(path) {
        try {
            const cli = new WardenCli(path);
            const version = await cli.getVersion();
            return version !== null;
        }
        catch {
            return false;
        }
    }
}
exports.WardenCli = WardenCli;
/**
 * Find Warden executable in system
 */
async function findWardenExecutable() {
    const commonPaths = {
        win32: [
            'warden.exe',
            'C:\\Program Files\\warden\\warden.exe',
            'C:\\Program Files (x86)\\warden\\warden.exe',
            `${process.env.USERPROFILE}\\.cargo\\bin\\warden.exe`,
            `${process.env.APPDATA}\\warden\\warden.exe`,
        ],
        darwin: [
            'warden',
            '/usr/local/bin/warden',
            '/opt/homebrew/bin/warden',
            `${process.env.HOME}/.cargo/bin/warden`,
        ],
        linux: [
            'warden',
            '/usr/bin/warden',
            '/usr/local/bin/warden',
            `${process.env.HOME}/.cargo/bin/warden`,
            `${process.env.HOME}/.local/bin/warden`,
        ],
    };
    const platform = process.platform;
    const paths = commonPaths[platform] || commonPaths.linux;
    const fs = require('fs');
    for (const path of paths) {
        try {
            if (fs.existsSync(path)) {
                // Check if executable
                await fs.promises.access(path, fs.constants.X_OK);
                return path;
            }
        }
        catch {
            // Continue to next path
        }
    }
    return null;
}
/**
 * Parse Warden JSON output
 */
function parseWardenOutput(output) {
    try {
        // Extract JSON from output (might have other text before/after)
        const jsonMatch = output.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            return null;
        }
        return JSON.parse(jsonMatch[0]);
    }
    catch {
        return null;
    }
}
/**
 * Convert Warden findings to VS Code diagnostics
 */
function findingsToDiagnostics(uri, findings) {
    return findings.map((vuln) => {
        const range = vuln.line
            ? new vscode.Range(new vscode.Position(vuln.line - 1, vuln.column || 0), new vscode.Position((vuln.endLine || vuln.line) - 1, vuln.endColumn || 100))
            : new vscode.Range(0, 0, 0, 100);
        const diagnostic = new vscode.Diagnostic(range, `[Warden] ${vuln.title}: ${vuln.description}`, severityToDiagnosticSeverity(vuln.severity));
        diagnostic.source = 'Warden';
        diagnostic.code = vuln.cwe || vuln.owasp;
        diagnostic.relatedInformation = [];
        if (vuln.recommendation) {
            diagnostic.relatedInformation.push(new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, range), `Fix: ${vuln.recommendation}`));
        }
        return diagnostic;
    });
}
/**
 * Convert Warden severity to VS Code diagnostic severity
 */
function severityToDiagnosticSeverity(severity) {
    switch (severity) {
        case types_1.VulnSeverity.Critical:
        case types_1.VulnSeverity.High:
            return vscode.DiagnosticSeverity.Error;
        case types_1.VulnSeverity.Medium:
            return vscode.DiagnosticSeverity.Warning;
        case types_1.VulnSeverity.Low:
            return vscode.DiagnosticSeverity.Information;
        case types_1.VulnSeverity.Info:
            return vscode.DiagnosticSeverity.Hint;
    }
}
/**
 * Create a code action for a vulnerability
 */
function createCodeAction(vuln, document) {
    if (!vuln.recommendation && !vuln.quickFix) {
        return null;
    }
    const action = new vscode.CodeAction(`Warden: ${vuln.quickFix?.description || 'Apply Security Fix'}`, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [];
    action.isPreferred = true;
    if (vuln.quickFix && vuln.quickFix.edits.length > 0) {
        const edit = new vscode.WorkspaceEdit();
        const uri = document.uri;
        for (const codeEdit of vuln.quickFix.edits) {
            const range = new vscode.Range(new vscode.Position(codeEdit.range.start.line, codeEdit.range.start.character), new vscode.Position(codeEdit.range.end.line, codeEdit.range.end.character));
            edit.replace(uri, range, codeEdit.newText);
        }
        action.edit = edit;
    }
    return action;
}
//# sourceMappingURL=warden-cli.js.map