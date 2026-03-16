"use strict";
/**
 * Warden Configuration Management
 *
 * Handles VS Code settings and Warden-specific configuration
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
exports.ConfigManager = void 0;
const vscode = __importStar(require("vscode"));
const types_1 = require("./types");
/**
 * Configuration keys matching package.json
 */
const CONFIG_KEYS = {
    ENABLED: 'warden.enabled',
    EXECUTABLE_PATH: 'warden.executablePath',
    SCAN_ON_SAVE: 'warden.scanOnSave',
    SCAN_ON_OPEN: 'warden.scanOnOpen',
    SHOW_INLINE_WARNINGS: 'warden.showInlineWarnings',
    SEVERITY_LEVEL: 'warden.severityLevel',
    TIMEOUT: 'warden.timeout',
    MAX_CONCURRENT_SCANS: 'warden.maxConcurrentScans',
    SCAN_MODE: 'warden.scanMode',
    ENABLE_SECRETS_DETECTION: 'warden.enableSecretsDetection',
    ENABLE_DEPENDENCY_CHECK: 'warden.enableDependencyCheck',
    IGNORE_PATTERNS: 'warden.ignorePatterns',
    NOTIFICATIONS: 'warden.notifications',
    PANEL_POSITION: 'warden.panel.position',
    AUTO_REFRESH: 'warden.autoRefresh',
};
/**
 * Configuration manager class
 */
class ConfigManager {
    constructor() {
        this.disposables = [];
        this.config = vscode.workspace.getConfiguration('warden');
        this.setupWatcher();
    }
    /**
     * Get the current Warden configuration
     */
    getConfiguration() {
        return {
            enabled: this.getBoolean(CONFIG_KEYS.ENABLED, true),
            executablePath: this.getString(CONFIG_KEYS.EXECUTABLE_PATH, 'warden'),
            scanOnSave: this.getBoolean(CONFIG_KEYS.SCAN_ON_SAVE, false),
            scanOnOpen: this.getBoolean(CONFIG_KEYS.SCAN_ON_OPEN, false),
            showInlineWarnings: this.getBoolean(CONFIG_KEYS.SHOW_INLINE_WARNINGS, true),
            severityLevel: this.getSeverityLevel(),
            timeout: this.getNumber(CONFIG_KEYS.TIMEOUT, 30000),
            maxConcurrentScans: this.getNumber(CONFIG_KEYS.MAX_CONCURRENT_SCANS, 3),
            scanMode: this.getScanMode(),
            enableSecretsDetection: this.getBoolean(CONFIG_KEYS.ENABLE_SECRETS_DETECTION, true),
            enableDependencyCheck: this.getBoolean(CONFIG_KEYS.ENABLE_DEPENDENCY_CHECK, true),
            ignorePatterns: this.getStringArray(CONFIG_KEYS.IGNORE_PATTERNS, []),
            notifications: this.getNotificationConfig(),
            panel: {
                position: this.getString(CONFIG_KEYS.PANEL_POSITION, 'right'),
            },
            autoRefresh: this.getBoolean(CONFIG_KEYS.AUTO_REFRESH, true),
        };
    }
    /**
     * Get a boolean configuration value
     */
    getBoolean(key, defaultValue) {
        return this.config.get(key, defaultValue);
    }
    /**
     * Get a string configuration value
     */
    getString(key, defaultValue) {
        return this.config.get(key, defaultValue);
    }
    /**
     * Get a number configuration value
     */
    getNumber(key, defaultValue) {
        return this.config.get(key, defaultValue);
    }
    /**
     * Get a string array configuration value
     */
    getStringArray(key, defaultValue) {
        return this.config.get(key, defaultValue);
    }
    /**
     * Get the severity level from configuration
     */
    getSeverityLevel() {
        const value = this.getString(CONFIG_KEYS.SEVERITY_LEVEL, 'Low');
        return this.parseSeverityLevel(value);
    }
    /**
     * Parse severity level from string
     */
    parseSeverityLevel(value) {
        const validLevels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
        if (validLevels.includes(value)) {
            return value;
        }
        return types_1.VulnSeverity.Low;
    }
    /**
     * Get the scan mode from configuration
     */
    getScanMode() {
        const value = this.getString(CONFIG_KEYS.SCAN_MODE, 'Active');
        return this.parseScanMode(value);
    }
    /**
     * Parse scan mode from string
     */
    parseScanMode(value) {
        const validModes = ['Passive', 'Active', 'Stealth', 'Aggressive'];
        if (validModes.includes(value)) {
            return value;
        }
        return types_1.ScanMode.Active;
    }
    /**
     * Get notification configuration
     */
    getNotificationConfig() {
        const config = this.config.get('notifications', {
            onCritical: true,
            onHigh: true,
            onMedium: false,
            onLow: false,
            onInfo: false,
        });
        return {
            onCritical: config.onCritical ?? true,
            onHigh: config.onHigh ?? true,
            onMedium: config.onMedium ?? false,
            onLow: config.onLow ?? false,
            onInfo: config.onInfo ?? false,
        };
    }
    /**
     * Update a configuration value
     */
    async update(key, value, global = false) {
        await this.config.update(key, value, global);
    }
    /**
     * Set up configuration change watcher
     */
    setupWatcher() {
        const watcher = vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration('warden')) {
                this.config = vscode.workspace.getConfiguration('warden');
                this.onConfigChanged();
            }
        });
        this.disposables.push(watcher);
    }
    /**
     * Called when configuration changes
     */
    onConfigChanged() {
        // Notify other parts of the extension about config changes
        vscode.commands.executeCommand('warden.configChanged', this.getConfiguration());
    }
    /**
     * Check if Warden should scan a file based on ignore patterns
     */
    shouldScanFile(filePath) {
        const config = this.getConfiguration();
        if (!config.enabled) {
            return false;
        }
        // Check ignore patterns
        for (const pattern of config.ignorePatterns) {
            const minimatch = require('minimatch');
            if (minimatch(filePath, pattern)) {
                return false;
            }
        }
        return true;
    }
    /**
     * Check if notification should be shown for a severity level
     */
    shouldNotify(severity) {
        const config = this.getConfiguration();
        switch (severity) {
            case types_1.VulnSeverity.Critical:
                return config.notifications.onCritical;
            case types_1.VulnSeverity.High:
                return config.notifications.onHigh;
            case types_1.VulnSeverity.Medium:
                return config.notifications.onMedium;
            case types_1.VulnSeverity.Low:
                return config.notifications.onLow;
            case types_1.VulnSeverity.Info:
                return config.notifications.onInfo;
        }
    }
    /**
     * Check if severity level meets the configured minimum
     */
    meetsSeverityThreshold(severity) {
        const config = this.getConfiguration();
        const minLevel = SEVERITY_ORDER[config.severityLevel];
        const severityLevel = SEVERITY_ORDER[severity];
        return severityLevel >= minLevel;
    }
    /**
     * Get the executable path with platform-specific handling
     */
    getExecutablePath() {
        const config = this.getConfiguration();
        let path = config.executablePath;
        // Add .exe on Windows if not present
        if (process.platform === 'win32' && !path.endsWith('.exe')) {
            path = path + '.exe';
        }
        return path;
    }
    /**
     * Find the Warden executable in common locations
     */
    async findExecutable() {
        const commonPaths = [];
        switch (process.platform) {
            case 'win32':
                commonPaths.push('C:\\Program Files\\warden\\warden.exe', 'C:\\Program Files (x86)\\warden\\warden.exe', `${process.env.USERPROFILE}\\.cargo\\bin\\warden.exe`, `${process.env.APPDATA}\\warden\\warden.exe`);
                break;
            case 'darwin':
                commonPaths.push('/usr/local/bin/warden', '/opt/homebrew/bin/warden', `${process.env.HOME}/.cargo/bin/warden`);
                break;
            case 'linux':
                commonPaths.push('/usr/bin/warden', '/usr/local/bin/warden', `${process.env.HOME}/.cargo/bin/warden`, `${process.env.HOME}/.local/bin/warden`);
                break;
        }
        // Check if executable exists in common paths
        const fs = require('fs');
        for (const path of commonPaths) {
            if (fs.existsSync(path)) {
                return path;
            }
        }
        return undefined;
    }
    /**
     * Validate the Warden installation
     */
    async validateInstallation() {
        const execPath = this.getExecutablePath();
        try {
            const { spawn } = require('child_process');
            return new Promise((resolve) => {
                const proc = spawn(execPath, ['--version'], {
                    stdio: ['ignore', 'pipe', 'pipe'],
                    timeout: 5000,
                });
                let stdout = '';
                let stderr = '';
                proc.stdout.on('data', (data) => {
                    stdout += data.toString();
                });
                proc.stderr.on('data', (data) => {
                    stderr += data.toString();
                });
                proc.on('close', (code) => {
                    resolve(code === 0 || stdout.includes('warden'));
                });
                proc.on('error', () => {
                    resolve(false);
                });
            });
        }
        catch {
            return false;
        }
    }
    /**
     * Dispose of resources
     */
    dispose() {
        this.disposables.forEach((d) => d.dispose());
    }
}
exports.ConfigManager = ConfigManager;
/**
 * Severity order for threshold comparison
 */
const SEVERITY_ORDER = {
    [types_1.VulnSeverity.Critical]: 5,
    [types_1.VulnSeverity.High]: 4,
    [types_1.VulnSeverity.Medium]: 3,
    [types_1.VulnSeverity.Low]: 2,
    [types_1.VulnSeverity.Info]: 1,
};
//# sourceMappingURL=config.js.map