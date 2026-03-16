/**
 * Findings Tree Provider
 *
 * Provides the tree view for security findings in the sidebar
 */

import * as vscode from 'vscode';
import {
  Vuln,
  VulnSeverity,
  FindingTreeItem,
  SEVERITY_ORDER,
} from './types';
import { DiagnosticManager } from './diagnostic-manager';

/**
 * Finding node types
 */
enum NodeType {
  Root = 'root',
  Severity = 'severity',
  File = 'file',
  Finding = 'finding',
}

/**
 * Severity icons
 */
const SEVERITY_ICONS: Record<VulnSeverity, string> = {
  [VulnSeverity.Critical]: '$(error)',
  [VulnSeverity.High]: '$(error)',
  [VulnSeverity.Medium]: '$(warning)',
  [VulnSeverity.Low]: '$(info)',
  [VulnSeverity.Info]: '$(circle-small)',
};

/**
 * Severity colors for badges
 */
const SEVERITY_COLORS: Record<VulnSeverity, string> = {
  [VulnSeverity.Critical]: '#f14c4c',
  [VulnSeverity.High]: '#f14c4c',
  [VulnSeverity.Medium]: '#ffab00',
  [VulnSeverity.Low]: '#3794ff',
  [VulnSeverity.Info]: '#85c8e8',
};

/**
 * Tree data provider for findings
 */
export class FindingsProvider implements vscode.TreeDataProvider<FindingTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingTreeItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private diagnosticManager: DiagnosticManager) {}

  /**
   * Refresh the tree view
   */
  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  /**
   * Get tree item for display
   */
  getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    const item = new vscode.TreeItem(
      element.label,
      element.collapsibleState
    );

    item.id = element.id;
    item.description = element.description;
    item.iconPath = new vscode.ThemeIcon(element.icon);
    item.contextValue = element.severity
      ? `severity:${element.severity}`
      : undefined;

    // Add tooltip
    if (element.vuln) {
      item.tooltip = new vscode.MarkdownString(
        this.buildTooltip(element.vuln)
      );
    }

    // Add command for finding items
    if (element.vuln && element.uri) {
      item.command = {
        command: 'warden.openFinding',
        title: 'Open Finding',
        arguments: [element.uri, element.range],
      };
    }

    return item;
  }

  /**
   * Get children of a tree node
   */
  async getChildren(element?: FindingTreeItem): Promise<FindingTreeItem[]> {
    if (!element) {
      // Root level - return severity categories
      return this.getSeverityCategories();
    }

    switch (element.id) {
      case NodeType.Severity:
        return this.getFindingsBySeverity(element.severity!);
      default:
        return [];
    }
  }

  /**
   * Get severity category nodes
   */
  private getSeverityCategories(): FindingTreeItem[] {
    const findingsBySeverity =
      this.diagnosticManager.getFindingsBySeverity();
    const categories: FindingTreeItem[] = [];

    for (const [severity, findings] of findingsBySeverity) {
      if (findings.length > 0) {
        categories.push({
          id: `${NodeType.Severity}-${severity}`,
          label: `${severity} (${findings.length})`,
          icon: SEVERITY_ICONS[severity],
          severity,
          collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
        });
      }
    }

    // Sort by severity (highest first)
    categories.sort((a, b) => {
      const orderA = SEVERITY_ORDER[a.severity!];
      const orderB = SEVERITY_ORDER[b.severity!];
      return orderB - orderA;
    });

    return categories;
  }

  /**
   * Get findings for a specific severity
   */
  private getFindingsBySeverity(severity: VulnSeverity): FindingTreeItem[] {
    const allFindings = this.diagnosticManager.getAllFindings();
    const items: FindingTreeItem[] = [];

    for (const [uri, findings] of allFindings) {
      for (const finding of findings) {
        if (finding.severity === severity && !finding.ignored) {
          items.push({
            id: finding.id || `finding-${Date.now()}-${Math.random()}`,
            label: finding.title,
            description: finding.location || '',
            icon: SEVERITY_ICONS[severity],
            severity,
            collapsibleState: vscode.TreeItemCollapsibleState.None,
            vuln: finding,
            uri,
            range: finding.line
              ? {
                  start: { line: finding.line - 1, character: finding.column || 0 },
                  end: {
                    line: (finding.endLine || finding.line) - 1,
                    character: finding.endColumn || 100,
                  },
                }
              : undefined,
          });
        }
      }
    }

    return items;
  }

  /**
   * Convert severity description string to VulnSeverity enum
   */
  private getSeverityFromDescription(description: string): VulnSeverity {
    switch (description) {
      case 'Critical':
        return VulnSeverity.Critical;
      case 'High':
        return VulnSeverity.High;
      case 'Medium':
        return VulnSeverity.Medium;
      case 'Low':
        return VulnSeverity.Low;
      case 'Info':
      default:
        return VulnSeverity.Info;
    }
  }

  /**
   * Build tooltip markdown for a finding
   */
  private buildTooltip(vuln: Vuln): string {
    let md = `## ${vuln.title}\n\n`;
    md += `**Severity:** \`${vuln.severity}\`\n\n`;

    if (vuln.cwe) {
      md += `**CWE:** ${vuln.cwe}\n\n`;
    }

    if (vuln.owasp) {
      md += `**OWASP:** ${vuln.owasp}\n\n`;
    }

    md += `### Description\n${vuln.description}\n\n`;

    if (vuln.recommendation) {
      md += `### Recommendation\n${vuln.recommendation}\n\n`;
    }

    if (vuln.location) {
      md += `**Location:** \`${vuln.location}\`\n\n`;
    }

    return md;
  }

  /**
   * Reveal a finding in the tree
   */
  async revealFinding(findingId: string): Promise<void> {
    // Implementation to expand tree and show finding
    this._onDidChangeTreeData.fire();
  }
}

/**
 * File-based findings provider (groups by file instead of severity)
 */
export class FileFindingsProvider implements vscode.TreeDataProvider<FindingTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FindingTreeItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  constructor(private diagnosticManager: DiagnosticManager) {}

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    const item = new vscode.TreeItem(
      element.label,
      element.collapsibleState
    );

    item.id = element.id;
    item.description = element.description;
    item.iconPath = new vscode.ThemeIcon(element.icon);

    if (element.vuln && element.uri) {
      item.command = {
        command: 'warden.openFinding',
        title: 'Open Finding',
        arguments: [element.uri, element.range],
      };
    }

    return item;
  }

  async getChildren(element?: FindingTreeItem): Promise<FindingTreeItem[]> {
    if (!element) {
      return this.getFileNodes();
    }

    return this.getFindingsForFile(element);
  }

  private getFileNodes(): FindingTreeItem[] {
    const allFindings = this.diagnosticManager.getAllFindings();
    const items: FindingTreeItem[] = [];

    for (const [uri, findings] of allFindings) {
      const activeFindings = findings.filter((f) => !f.ignored);
      if (activeFindings.length > 0) {
        const filename = vscode.Uri.parse(uri).fsPath.split('/').pop() || uri;
        const highestSeverity = this.getHighestSeverity(activeFindings);
        items.push({
          id: `file-${uri}`,
          label: `${filename} (${activeFindings.length})`,
          description: highestSeverity,
          icon: this.getSeverityIcon(activeFindings),
          severity: this.getSeverityFromDescription(highestSeverity),
          collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
          uri,
        });
      }
    }

    return items.sort((a, b) => a.label.localeCompare(b.label));
  }

  private getFindingsForFile(element: FindingTreeItem): FindingTreeItem[] {
    const uri = element.uri!;
    const findings = this.diagnosticManager.getFindings(vscode.Uri.parse(uri));

    return findings
      .filter((f) => !f.ignored)
      .map((finding) => ({
        id: finding.id || `finding-${Date.now()}-${Math.random()}`,
        label: finding.title,
        description: `${finding.severity}`,
        icon: SEVERITY_ICONS[finding.severity],
        severity: finding.severity,
        collapsibleState: vscode.TreeItemCollapsibleState.None,
        vuln: finding,
        uri,
        range: finding.line
          ? {
              start: { line: finding.line - 1, character: finding.column || 0 },
              end: {
                line: (finding.endLine || finding.line) - 1,
                character: finding.endColumn || 100,
              },
            }
          : undefined,
      }))
      .sort((a, b) => SEVERITY_ORDER[b.severity!] - SEVERITY_ORDER[a.severity!]);
  }

  private getHighestSeverity(findings: Vuln[]): string {
    let highest = VulnSeverity.Info;
    for (const finding of findings) {
      if (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[highest]) {
        highest = finding.severity;
      }
    }
    return highest;
  }

  private getSeverityIcon(findings: Vuln[]): string {
    return SEVERITY_ICONS[this.getHighestSeverity(findings) as VulnSeverity];
  }

  private getSeverityFromDescription(description: string): VulnSeverity {
    switch (description) {
      case 'Critical':
        return VulnSeverity.Critical;
      case 'High':
        return VulnSeverity.High;
      case 'Medium':
        return VulnSeverity.Medium;
      case 'Low':
        return VulnSeverity.Low;
      case 'Info':
      default:
        return VulnSeverity.Info;
    }
  }
}
