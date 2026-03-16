"use strict";
/**
 * Warden VS Code Extension - Type Definitions
 *
 * Types matching the Rust backend structure for seamless integration
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScanMode = exports.SEVERITY_ORDER = exports.VulnSeverity = void 0;
/**
 * Vulnerability severity levels (matching Rust VulnSeverity)
 */
var VulnSeverity;
(function (VulnSeverity) {
    VulnSeverity["Critical"] = "Critical";
    VulnSeverity["High"] = "High";
    VulnSeverity["Medium"] = "Medium";
    VulnSeverity["Low"] = "Low";
    VulnSeverity["Info"] = "Info";
})(VulnSeverity || (exports.VulnSeverity = VulnSeverity = {}));
/**
 * Severity ordering for comparison
 */
exports.SEVERITY_ORDER = {
    [VulnSeverity.Critical]: 5,
    [VulnSeverity.High]: 4,
    [VulnSeverity.Medium]: 3,
    [VulnSeverity.Low]: 2,
    [VulnSeverity.Info]: 1,
};
/**
 * Scan mode (matching Rust ScanMode)
 */
var ScanMode;
(function (ScanMode) {
    ScanMode["Passive"] = "Passive";
    ScanMode["Active"] = "Active";
    ScanMode["Stealth"] = "Stealth";
    ScanMode["Aggressive"] = "Aggressive";
})(ScanMode || (exports.ScanMode = ScanMode = {}));
//# sourceMappingURL=types.js.map