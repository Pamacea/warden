/**
 * Warden CLI Interface
 *
 * Handles communication with the Warden CLI executable
 */

import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import { Readable } from 'stream';
import {
  Target,
  ScanReport,
  ScanRequest,
  ScanResponse,
  ScanMode,
  Vuln,
  VulnSeverity,
} from './types';

/**
 * Warden CLI client class
 */
export class WardenCli {
  private executablePath: string;
  private activeProcesses: Map<string, ChildProcess> = new Map();

  constructor(executablePath: string) {
    this.executablePath = executablePath;
  }

  /**
   * Scan a file or directory
   */
  async scanPath(
    path: string,
    mode: ScanMode = ScanMode.Active,
    options: {
      checkSecrets?: boolean;
      checkDeps?: boolean;
      severityLevel?: VulnSeverity;
      timeout?: number;
    } = {}
  ): Promise<ScanResponse> {
    const startTime = Date.now();

    try {
      const args = this.buildScanArgs(path, mode, options);
      const result = await this.runCommand(args, options.timeout || 30000);

      const report: ScanReport = JSON.parse(result);
      return {
        success: true,
        report,
        duration: Date.now() - startTime,
      };
    } catch (error) {
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
  async scanUrl(
    url: string,
    mode: ScanMode = ScanMode.Active,
    options: {
      timeout?: number;
      aggressive?: boolean;
    } = {}
  ): Promise<ScanResponse> {
    const startTime = Date.now();

    try {
      const args = ['scan', url, '--mode', mode, '--json'];

      if (options.aggressive) {
        args.push('--aggressive');
      }

      const result = await this.runCommand(args, options.timeout || 30000);
      const report: ScanReport = JSON.parse(result);

      return {
        success: true,
        report,
        duration: Date.now() - startTime,
      };
    } catch (error) {
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
  async scanFileRaw(filePath: string): Promise<string> {
    const args = ['scan', filePath, '--json'];
    return this.runCommand(args, 30000);
  }

  /**
   * Build scan arguments
   */
  private buildScanArgs(
    path: string,
    mode: ScanMode,
    options: {
      checkSecrets?: boolean;
      checkDeps?: boolean;
      severityLevel?: VulnSeverity;
    }
  ): string[] {
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
  private runCommand(args: string[], timeout: number): Promise<string> {
    return new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';

      const proc = spawn(this.executablePath, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env },
      });

      const scanId = `scan-${Date.now()}`;
      this.activeProcesses.set(scanId, proc);

      const timer = setTimeout(() => {
        proc.kill();
        reject(new Error(`Scan timeout after ${timeout}ms`));
      }, timeout);

      proc.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      proc.on('close', (code: number) => {
        clearTimeout(timer);
        this.activeProcesses.delete(scanId);

        if (code === 0) {
          resolve(stdout);
        } else {
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
  async getVersion(): Promise<string | null> {
    try {
      const args = ['--version'];
      const result = await this.runCommand(args, 5000);
      return result.trim();
    } catch {
      return null;
    }
  }

  /**
   * Get available scanners
   */
  async getAvailableScanners(): Promise<string[]> {
    try {
      const args = ['--list-scanners'];
      const result = await this.runCommand(args, 5000);
      return result.split('\n').filter((s) => s.trim());
    } catch {
      return [];
    }
  }

  /**
   * Cancel all active scans
   */
  cancelAllScans(): void {
    for (const [id, proc] of this.activeProcesses) {
      proc.kill();
      this.activeProcesses.delete(id);
    }
  }

  /**
   * Check if Warden is available
   */
  static async isAvailable(path: string): Promise<boolean> {
    try {
      const cli = new WardenCli(path);
      const version = await cli.getVersion();
      return version !== null;
    } catch {
      return false;
    }
  }
}

/**
 * Find Warden executable in system
 */
export async function findWardenExecutable(): Promise<string | null> {
  const commonPaths: Record<string, string[]> = {
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

  const platform = process.platform as keyof typeof commonPaths;
  const paths = commonPaths[platform] || commonPaths.linux;

  const fs = require('fs');
  for (const path of paths) {
    try {
      if (fs.existsSync(path)) {
        // Check if executable
        await fs.promises.access(path, fs.constants.X_OK);
        return path;
      }
    } catch {
      // Continue to next path
    }
  }

  return null;
}

/**
 * Parse Warden JSON output
 */
export function parseWardenOutput(output: string): ScanReport | null {
  try {
    // Extract JSON from output (might have other text before/after)
    const jsonMatch = output.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return null;
    }

    return JSON.parse(jsonMatch[0]);
  } catch {
    return null;
  }
}

/**
 * Convert Warden findings to VS Code diagnostics
 */
export function findingsToDiagnostics(
  uri: vscode.Uri,
  findings: Vuln[]
): vscode.Diagnostic[] {
  return findings.map((vuln) => {
    const range = vuln.line
      ? new vscode.Range(
          new vscode.Position(vuln.line - 1, vuln.column || 0),
          new vscode.Position(
            (vuln.endLine || vuln.line) - 1,
            vuln.endColumn || 100
          )
        )
      : new vscode.Range(0, 0, 0, 100);

    const diagnostic = new vscode.Diagnostic(
      range,
      `[Warden] ${vuln.title}: ${vuln.description}`,
      severityToDiagnosticSeverity(vuln.severity)
    );

    diagnostic.source = 'Warden';
    diagnostic.code = vuln.cwe || vuln.owasp;
    diagnostic.relatedInformation = [];

    if (vuln.recommendation) {
      diagnostic.relatedInformation.push(
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(uri, range),
          `Fix: ${vuln.recommendation}`
        )
      );
    }

    return diagnostic;
  });
}

/**
 * Convert Warden severity to VS Code diagnostic severity
 */
function severityToDiagnosticSeverity(
  severity: VulnSeverity
): vscode.DiagnosticSeverity {
  switch (severity) {
    case VulnSeverity.Critical:
    case VulnSeverity.High:
      return vscode.DiagnosticSeverity.Error;
    case VulnSeverity.Medium:
      return vscode.DiagnosticSeverity.Warning;
    case VulnSeverity.Low:
      return vscode.DiagnosticSeverity.Information;
    case VulnSeverity.Info:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/**
 * Create a code action for a vulnerability
 */
export function createCodeAction(
  vuln: Vuln,
  document: vscode.TextDocument
): vscode.CodeAction | null {
  if (!vuln.recommendation && !vuln.quickFix) {
    return null;
  }

  const action = new vscode.CodeAction(
    `Warden: ${vuln.quickFix?.description || 'Apply Security Fix'}`,
    vscode.CodeActionKind.QuickFix
  );

  action.diagnostics = [];
  action.isPreferred = true;

  if (vuln.quickFix && vuln.quickFix.edits.length > 0) {
    const edit = new vscode.WorkspaceEdit();
    const uri = document.uri;

    for (const codeEdit of vuln.quickFix.edits) {
      const range = new vscode.Range(
        new vscode.Position(
          codeEdit.range.start.line,
          codeEdit.range.start.character
        ),
        new vscode.Position(
          codeEdit.range.end.line,
          codeEdit.range.end.character
        )
      );
      edit.replace(uri, range, codeEdit.newText);
    }

    action.edit = edit;
  }

  return action;
}
