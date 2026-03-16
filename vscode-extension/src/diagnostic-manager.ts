/**
 * Diagnostic Manager
 *
 * Manages VS Code diagnostics for Warden findings
 */

import * as vscode from 'vscode';
import { Vuln, VulnSeverity, WardenDiagnostic } from './types';
import { findingsToDiagnostics } from './warden-cli';

/**
 * Diagnostic collection key
 */
const DIAGNOSTIC_COLLECTION = 'warden-security';

/**
 * Diagnostic manager class
 */
export class DiagnosticManager {
  private collection: vscode.DiagnosticCollection;
  private findingsByFile: Map<string, Vuln[]> = new Map();
  private disposables: vscode.Disposable[] = [];

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection(
      DIAGNOSTIC_COLLECTION
    );
    this.disposables.push(this.collection);
  }

  /**
   * Set findings for a file
   */
  setFindings(uri: vscode.Uri, findings: Vuln[]): void {
    const key = uri.toString();
    this.findingsByFile.set(key, findings);

    const diagnostics = findingsToDiagnostics(uri, findings);
    this.collection.set(uri, diagnostics);
  }

  /**
   * Get findings for a file
   */
  getFindings(uri: vscode.Uri): Vuln[] {
    return this.findingsByFile.get(uri.toString()) || [];
  }

  /**
   * Clear findings for a file
   */
  clearFile(uri: vscode.Uri): void {
    const key = uri.toString();
    this.findingsByFile.delete(key);
    this.collection.delete(uri);
  }

  /**
   * Clear all findings
   */
  clearAll(): void {
    this.findingsByFile.clear();
    this.collection.clear();
  }

  /**
   * Get all findings across all files
   */
  getAllFindings(): Map<string, Vuln[]> {
    return new Map(this.findingsByFile);
  }

  /**
   * Get findings grouped by severity
   */
  getFindingsBySeverity(): Map<VulnSeverity, Vuln[]> {
    const grouped = new Map<VulnSeverity, Vuln[]>();
    grouped.set(VulnSeverity.Critical, []);
    grouped.set(VulnSeverity.High, []);
    grouped.set(VulnSeverity.Medium, []);
    grouped.set(VulnSeverity.Low, []);
    grouped.set(VulnSeverity.Info, []);

    for (const findings of this.findingsByFile.values()) {
      for (const finding of findings) {
        if (finding.ignored) {
          continue;
        }
        const list = grouped.get(finding.severity);
        if (list) {
          list.push(finding);
        }
      }
    }

    return grouped;
  }

  /**
   * Get total count of findings
   */
  getTotalCount(): number {
    let total = 0;
    for (const findings of this.findingsByFile.values()) {
      total += findings.filter((f) => !f.ignored).length;
    }
    return total;
  }

  /**
   * Get count by severity
   */
  getCountBySeverity(): Record<VulnSeverity, number> {
    const counts: Record<VulnSeverity, number> = {
      [VulnSeverity.Critical]: 0,
      [VulnSeverity.High]: 0,
      [VulnSeverity.Medium]: 0,
      [VulnSeverity.Low]: 0,
      [VulnSeverity.Info]: 0,
    };

    for (const findings of this.findingsByFile.values()) {
      for (const finding of findings) {
        if (finding.ignored) {
          continue;
        }
        counts[finding.severity]++;
      }
    }

    return counts;
  }

  /**
   * Ignore a finding
   */
  ignoreFinding(uri: vscode.Uri, findingId: string, reason?: string): void {
    const findings = this.getFindings(uri);
    const finding = findings.find((f) => f.id === findingId);

    if (finding) {
      finding.ignored = true;
      finding.ignoreReason = reason;
      this.setFindings(uri, findings);
    }
  }

  /**
   * Unignore a finding
   */
  unignoreFinding(uri: vscode.Uri, findingId: string): void {
    const findings = this.getFindings(uri);
    const finding = findings.find((f) => f.id === findingId);

    if (finding) {
      finding.ignored = false;
      finding.ignoreReason = undefined;
      this.setFindings(uri, findings);
    }
  }

  /**
   * Get the diagnostic collection
   */
  getCollection(): vscode.DiagnosticCollection {
    return this.collection;
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
    this.collection.dispose();
  }
}
