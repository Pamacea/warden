"use strict";
/**
 * Findings Tree Provider
 *
 * Provides the tree view for security findings in the sidebar
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
exports.FileFindingsProvider = exports.FindingsProvider = void 0;
const vscode = __importStar(require("vscode"));
const types_1 = require("./types");
/**
 * Finding node types
 */
var NodeType;
(function (NodeType) {
    NodeType["Root"] = "root";
    NodeType["Severity"] = "severity";
    NodeType["File"] = "file";
    NodeType["Finding"] = "finding";
})(NodeType || (NodeType = {}));
/**
 * Severity icons
 */
const SEVERITY_ICONS = {
    [types_1.VulnSeverity.Critical]: '$(error)',
    [types_1.VulnSeverity.High]: '$(error)',
    [types_1.VulnSeverity.Medium]: '$(warning)',
    [types_1.VulnSeverity.Low]: '$(info)',
    [types_1.VulnSeverity.Info]: '$(circle-small)',
};
/**
 * Severity colors for badges
 */
const SEVERITY_COLORS = {
    [types_1.VulnSeverity.Critical]: '#f14c4c',
    [types_1.VulnSeverity.High]: '#f14c4c',
    [types_1.VulnSeverity.Medium]: '#ffab00',
    [types_1.VulnSeverity.Low]: '#3794ff',
    [types_1.VulnSeverity.Info]: '#85c8e8',
};
/**
 * Tree data provider for findings
 */
class FindingsProvider {
    constructor(diagnosticManager) {
        this.diagnosticManager = diagnosticManager;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }
    /**
     * Refresh the tree view
     */
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    /**
     * Get tree item for display
     */
    getTreeItem(element) {
        const item = new vscode.TreeItem(element.label, element.collapsibleState);
        item.id = element.id;
        item.description = element.description;
        item.iconPath = new vscode.ThemeIcon(element.icon);
        item.contextValue = element.severity
            ? `severity:${element.severity}`
            : undefined;
        // Add tooltip
        if (element.vuln) {
            item.tooltip = new vscode.MarkdownString(this.buildTooltip(element.vuln));
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
    async getChildren(element) {
        if (!element) {
            // Root level - return severity categories
            return this.getSeverityCategories();
        }
        switch (element.id) {
            case NodeType.Severity:
                return this.getFindingsBySeverity(element.severity);
            default:
                return [];
        }
    }
    /**
     * Get severity category nodes
     */
    getSeverityCategories() {
        const findingsBySeverity = this.diagnosticManager.getFindingsBySeverity();
        const categories = [];
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
            const orderA = types_1.SEVERITY_ORDER[a.severity];
            const orderB = types_1.SEVERITY_ORDER[b.severity];
            return orderB - orderA;
        });
        return categories;
    }
    /**
     * Get findings for a specific severity
     */
    getFindingsBySeverity(severity) {
        const allFindings = this.diagnosticManager.getAllFindings();
        const items = [];
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
    getSeverityFromDescription(description) {
        switch (description) {
            case 'Critical':
                return types_1.VulnSeverity.Critical;
            case 'High':
                return types_1.VulnSeverity.High;
            case 'Medium':
                return types_1.VulnSeverity.Medium;
            case 'Low':
                return types_1.VulnSeverity.Low;
            case 'Info':
            default:
                return types_1.VulnSeverity.Info;
        }
    }
    /**
     * Build tooltip markdown for a finding
     */
    buildTooltip(vuln) {
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
    async revealFinding(findingId) {
        // Implementation to expand tree and show finding
        this._onDidChangeTreeData.fire();
    }
}
exports.FindingsProvider = FindingsProvider;
/**
 * File-based findings provider (groups by file instead of severity)
 */
class FileFindingsProvider {
    constructor(diagnosticManager) {
        this.diagnosticManager = diagnosticManager;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    getTreeItem(element) {
        const item = new vscode.TreeItem(element.label, element.collapsibleState);
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
    async getChildren(element) {
        if (!element) {
            return this.getFileNodes();
        }
        return this.getFindingsForFile(element);
    }
    getFileNodes() {
        const allFindings = this.diagnosticManager.getAllFindings();
        const items = [];
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
    getFindingsForFile(element) {
        const uri = element.uri;
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
            .sort((a, b) => types_1.SEVERITY_ORDER[b.severity] - types_1.SEVERITY_ORDER[a.severity]);
    }
    getHighestSeverity(findings) {
        let highest = types_1.VulnSeverity.Info;
        for (const finding of findings) {
            if (types_1.SEVERITY_ORDER[finding.severity] > types_1.SEVERITY_ORDER[highest]) {
                highest = finding.severity;
            }
        }
        return highest;
    }
    getSeverityIcon(findings) {
        return SEVERITY_ICONS[this.getHighestSeverity(findings)];
    }
    getSeverityFromDescription(description) {
        switch (description) {
            case 'Critical':
                return types_1.VulnSeverity.Critical;
            case 'High':
                return types_1.VulnSeverity.High;
            case 'Medium':
                return types_1.VulnSeverity.Medium;
            case 'Low':
                return types_1.VulnSeverity.Low;
            case 'Info':
            default:
                return types_1.VulnSeverity.Info;
        }
    }
}
exports.FileFindingsProvider = FileFindingsProvider;
//# sourceMappingURL=findings-provider.js.map