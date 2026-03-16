"use strict";
/**
 * Diagnostic Manager
 *
 * Manages VS Code diagnostics for Warden findings
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
exports.DiagnosticManager = void 0;
const vscode = __importStar(require("vscode"));
const types_1 = require("./types");
const warden_cli_1 = require("./warden-cli");
/**
 * Diagnostic collection key
 */
const DIAGNOSTIC_COLLECTION = 'warden-security';
/**
 * Diagnostic manager class
 */
class DiagnosticManager {
    constructor() {
        this.findingsByFile = new Map();
        this.disposables = [];
        this.collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION);
        this.disposables.push(this.collection);
    }
    /**
     * Set findings for a file
     */
    setFindings(uri, findings) {
        const key = uri.toString();
        this.findingsByFile.set(key, findings);
        const diagnostics = (0, warden_cli_1.findingsToDiagnostics)(uri, findings);
        this.collection.set(uri, diagnostics);
    }
    /**
     * Get findings for a file
     */
    getFindings(uri) {
        return this.findingsByFile.get(uri.toString()) || [];
    }
    /**
     * Clear findings for a file
     */
    clearFile(uri) {
        const key = uri.toString();
        this.findingsByFile.delete(key);
        this.collection.delete(uri);
    }
    /**
     * Clear all findings
     */
    clearAll() {
        this.findingsByFile.clear();
        this.collection.clear();
    }
    /**
     * Get all findings across all files
     */
    getAllFindings() {
        return new Map(this.findingsByFile);
    }
    /**
     * Get findings grouped by severity
     */
    getFindingsBySeverity() {
        const grouped = new Map();
        grouped.set(types_1.VulnSeverity.Critical, []);
        grouped.set(types_1.VulnSeverity.High, []);
        grouped.set(types_1.VulnSeverity.Medium, []);
        grouped.set(types_1.VulnSeverity.Low, []);
        grouped.set(types_1.VulnSeverity.Info, []);
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
    getTotalCount() {
        let total = 0;
        for (const findings of this.findingsByFile.values()) {
            total += findings.filter((f) => !f.ignored).length;
        }
        return total;
    }
    /**
     * Get count by severity
     */
    getCountBySeverity() {
        const counts = {
            [types_1.VulnSeverity.Critical]: 0,
            [types_1.VulnSeverity.High]: 0,
            [types_1.VulnSeverity.Medium]: 0,
            [types_1.VulnSeverity.Low]: 0,
            [types_1.VulnSeverity.Info]: 0,
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
    ignoreFinding(uri, findingId, reason) {
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
    unignoreFinding(uri, findingId) {
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
    getCollection() {
        return this.collection;
    }
    /**
     * Dispose of resources
     */
    dispose() {
        this.disposables.forEach((d) => d.dispose());
        this.collection.dispose();
    }
}
exports.DiagnosticManager = DiagnosticManager;
//# sourceMappingURL=diagnostic-manager.js.map