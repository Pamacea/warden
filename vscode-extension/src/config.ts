/**
 * Warden Configuration Management
 *
 * Handles VS Code settings and Warden-specific configuration
 */

import * as vscode from 'vscode';
import { VulnSeverity, ScanMode, WardenConfiguration, NotificationConfig } from './types';

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
} as const;

/**
 * Configuration manager class
 */
export class ConfigManager {
  private config: vscode.WorkspaceConfiguration;
  private disposables: vscode.Disposable[] = [];

  constructor() {
    this.config = vscode.workspace.getConfiguration('warden');
    this.setupWatcher();
  }

  /**
   * Get the current Warden configuration
   */
  getConfiguration(): WardenConfiguration {
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
        position: this.getString(CONFIG_KEYS.PANEL_POSITION, 'right') as 'bottom' | 'right',
      },
      autoRefresh: this.getBoolean(CONFIG_KEYS.AUTO_REFRESH, true),
    };
  }

  /**
   * Get a boolean configuration value
   */
  private getBoolean(key: string, defaultValue: boolean): boolean {
    return this.config.get(key, defaultValue);
  }

  /**
   * Get a string configuration value
   */
  private getString(key: string, defaultValue: string): string {
    return this.config.get(key, defaultValue);
  }

  /**
   * Get a number configuration value
   */
  private getNumber(key: string, defaultValue: number): number {
    return this.config.get(key, defaultValue);
  }

  /**
   * Get a string array configuration value
   */
  private getStringArray(key: string, defaultValue: string[]): string[] {
    return this.config.get(key, defaultValue);
  }

  /**
   * Get the severity level from configuration
   */
  private getSeverityLevel(): VulnSeverity {
    const value = this.getString(CONFIG_KEYS.SEVERITY_LEVEL, 'Low');
    return this.parseSeverityLevel(value);
  }

  /**
   * Parse severity level from string
   */
  private parseSeverityLevel(value: string): VulnSeverity {
    const validLevels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    if (validLevels.includes(value)) {
      return value as VulnSeverity;
    }
    return VulnSeverity.Low;
  }

  /**
   * Get the scan mode from configuration
   */
  private getScanMode(): ScanMode {
    const value = this.getString(CONFIG_KEYS.SCAN_MODE, 'Active');
    return this.parseScanMode(value);
  }

  /**
   * Parse scan mode from string
   */
  private parseScanMode(value: string): ScanMode {
    const validModes = ['Passive', 'Active', 'Stealth', 'Aggressive'];
    if (validModes.includes(value)) {
      return value as ScanMode;
    }
    return ScanMode.Active;
  }

  /**
   * Get notification configuration
   */
  private getNotificationConfig(): NotificationConfig {
    const config = this.config.get<{ [key: string]: boolean }>('notifications', {
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
  async update(key: string, value: unknown, global = false): Promise<void> {
    await this.config.update(key, value, global);
  }

  /**
   * Set up configuration change watcher
   */
  private setupWatcher(): void {
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
  private onConfigChanged(): void {
    // Notify other parts of the extension about config changes
    vscode.commands.executeCommand('warden.configChanged', this.getConfiguration());
  }

  /**
   * Check if Warden should scan a file based on ignore patterns
   */
  shouldScanFile(filePath: string): boolean {
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
  shouldNotify(severity: VulnSeverity): boolean {
    const config = this.getConfiguration();
    switch (severity) {
      case VulnSeverity.Critical:
        return config.notifications.onCritical;
      case VulnSeverity.High:
        return config.notifications.onHigh;
      case VulnSeverity.Medium:
        return config.notifications.onMedium;
      case VulnSeverity.Low:
        return config.notifications.onLow;
      case VulnSeverity.Info:
        return config.notifications.onInfo;
    }
  }

  /**
   * Check if severity level meets the configured minimum
   */
  meetsSeverityThreshold(severity: VulnSeverity): boolean {
    const config = this.getConfiguration();
    const minLevel = SEVERITY_ORDER[config.severityLevel];
    const severityLevel = SEVERITY_ORDER[severity];
    return severityLevel >= minLevel;
  }

  /**
   * Get the executable path with platform-specific handling
   */
  getExecutablePath(): string {
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
  async findExecutable(): Promise<string | undefined> {
    const commonPaths: string[] = [];

    switch (process.platform) {
      case 'win32':
        commonPaths.push(
          'C:\\Program Files\\warden\\warden.exe',
          'C:\\Program Files (x86)\\warden\\warden.exe',
          `${process.env.USERPROFILE}\\.cargo\\bin\\warden.exe`,
          `${process.env.APPDATA}\\warden\\warden.exe`
        );
        break;
      case 'darwin':
        commonPaths.push(
          '/usr/local/bin/warden',
          '/opt/homebrew/bin/warden',
          `${process.env.HOME}/.cargo/bin/warden`
        );
        break;
      case 'linux':
        commonPaths.push(
          '/usr/bin/warden',
          '/usr/local/bin/warden',
          `${process.env.HOME}/.cargo/bin/warden`,
          `${process.env.HOME}/.local/bin/warden`
        );
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
  async validateInstallation(): Promise<boolean> {
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

        proc.stdout.on('data', (data: Buffer) => {
          stdout += data.toString();
        });

        proc.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });

        proc.on('close', (code: number) => {
          resolve(code === 0 || stdout.includes('warden'));
        });

        proc.on('error', () => {
          resolve(false);
        });
      });
    } catch {
      return false;
    }
  }

  /**
   * Dispose of resources
   */
  dispose(): void {
    this.disposables.forEach((d) => d.dispose());
  }
}

/**
 * Severity order for threshold comparison
 */
const SEVERITY_ORDER: Record<VulnSeverity, number> = {
  [VulnSeverity.Critical]: 5,
  [VulnSeverity.High]: 4,
  [VulnSeverity.Medium]: 3,
  [VulnSeverity.Low]: 2,
  [VulnSeverity.Info]: 1,
};
