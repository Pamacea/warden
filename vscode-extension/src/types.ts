/**
 * Warden VS Code Extension - Type Definitions
 *
 * Types matching the Rust backend structure for seamless integration
 */

/**
 * Vulnerability severity levels (matching Rust VulnSeverity)
 */
export enum VulnSeverity {
  Critical = 'Critical',
  High = 'High',
  Medium = 'Medium',
  Low = 'Low',
  Info = 'Info',
}

/**
 * Severity ordering for comparison
 */
export const SEVERITY_ORDER: Record<VulnSeverity, number> = {
  [VulnSeverity.Critical]: 5,
  [VulnSeverity.High]: 4,
  [VulnSeverity.Medium]: 3,
  [VulnSeverity.Low]: 2,
  [VulnSeverity.Info]: 1,
};

/**
 * Scan target types (matching Rust Target enum)
 */
export type TargetType = 'Url' | 'Path';

export interface Target {
  Url?: string;
  Path?: string;
}

/**
 * Vulnerability finding (matching Rust Vuln struct)
 */
export interface Vuln {
  severity: VulnSeverity;
  title: string;
  description: string;
  location?: string;
  recommendation?: string;
  cwe?: string;
  owasp?: string;
  id?: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  source?: string;
  hasQuickFix?: boolean;
  quickFix?: VulnQuickFix;
  ignored?: boolean;
  ignoreReason?: string;
}

/**
 * Quick fix for a vulnerability
 */
export interface VulnQuickFix {
  type: 'replace' | 'insert' | 'delete' | 'comment';
  description: string;
  edits: CodeEdit[];
}

/**
 * Code edit for quick fix
 */
export interface CodeEdit {
  range: Range;
  newText: string;
}

/**
 * Position in source code
 */
export interface Position {
  line: number;
  character: number;
}

/**
 * Range in source code
 */
export interface Range {
  start: Position;
  end: Position;
}

/**
 * Scan summary (matching Rust ScanSummary)
 */
export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Security score category
 */
export interface SecurityScoreCategory {
  name: string;
  score: number;
  maxPoints: number;
  percentage: number;
  grade: string;
  penalties: string[];
  bonuses: string[];
}

/**
 * Security score (matching Rust SecurityScore)
 */
export interface SecurityScore {
  score: number;
  grade: string;
  gradeDescription: string;
  categories: SecurityScoreCategory[];
  recommendations: string[];
}

/**
 * Scan report (matching Rust ScanReport)
 */
export interface ScanReport {
  version: string;
  target: Target;
  timestamp: string;
  findings: Vuln[];
  summary: ScanSummary;
  securityScore: SecurityScore;
}

/**
 * Scan mode (matching Rust ScanMode)
 */
export enum ScanMode {
  Passive = 'Passive',
  Active = 'Active',
  Stealth = 'Stealth',
  Aggressive = 'Aggressive',
}

/**
 * Scan request from VS Code extension
 */
export interface ScanRequest {
  target: Target;
  mode: ScanMode;
  options: ScanOptions;
}

/**
 * Scan options
 */
export interface ScanOptions {
  timeout: number;
  checkSecrets: boolean;
  checkDeps: boolean;
  severityLevel: VulnSeverity;
  includePaths?: string[];
  excludePaths?: string[];
}

/**
 * Scan response from Warden CLI
 */
export interface ScanResponse {
  success: boolean;
  report?: ScanReport;
  error?: string;
  duration: number;
}

/**
 * Diagnostic information from Warden
 */
export interface WardenDiagnostic {
  id: string;
  uri: string;
  vuln: Vuln;
  range: Range;
  severity: number; // VS Code DiagnosticSeverity
  message: string;
  source: string;
  code: string;
  tags?: string[];
}

/**
 * Finding tree item for the sidebar
 */
export interface FindingTreeItem {
  id: string;
  label: string;
  description?: string;
  icon: string;
  severity: VulnSeverity;
  collapsibleState: number;
  parent?: FindingTreeItem;
  children?: FindingTreeItem[];
  vuln?: Vuln;
  uri?: string;
  range?: Range;
}

/**
 * Grouped findings by severity
 */
export interface GroupedFindings {
  critical: Vuln[];
  high: Vuln[];
  medium: Vuln[];
  low: Vuln[];
  info: Vuln[];
}

/**
 * Warden configuration
 */
export interface WardenConfiguration {
  enabled: boolean;
  executablePath: string;
  scanOnSave: boolean;
  scanOnOpen: boolean;
  showInlineWarnings: boolean;
  severityLevel: VulnSeverity;
  timeout: number;
  maxConcurrentScans: number;
  scanMode: ScanMode;
  enableSecretsDetection: boolean;
  enableDependencyCheck: boolean;
  ignorePatterns: string[];
  notifications: NotificationConfig;
  panel: PanelConfig;
  autoRefresh: boolean;
}

/**
 * Notification configuration
 */
export interface NotificationConfig {
  onCritical: boolean;
  onHigh: boolean;
  onMedium: boolean;
  onLow: boolean;
  onInfo: boolean;
}

/**
 * Panel configuration
 */
export interface PanelConfig {
  position: 'bottom' | 'right';
}

/**
 * Scan state for tracking active scans
 */
export interface ScanState {
  id: string;
  target: Target;
  mode: ScanMode;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: number;
  endTime?: number;
  progress?: number;
  findings: Vuln[];
  error?: string;
}

/**
 * File scan result
 */
export interface FileScanResult {
  uri: string;
  findings: Vuln[];
  scanTime: number;
  timestamp: string;
}

/**
 * LSP capabilities
 */
export interface LSPCapabilities {
  codeActionProvider: boolean;
  diagnosticProvider: boolean;
  documentHighlightProvider: boolean;
  hoverProvider: boolean;
  completionProvider: boolean;
}

/**
 * Notification data
 */
export interface WardenNotificationData {
  severity: VulnSeverity;
  count: number;
  findings: Vuln[];
}

/**
 * Telemetry data
 */
export interface TelemetryData {
  event: string;
  properties: Record<string, unknown>;
  measures?: Record<string, number>;
}

/**
 * Quick fix action
 */
export interface QuickFixAction {
  title: string;
  kind: string;
  edit?: {
    uri: string;
    edits: CodeEdit[];
  };
  command?: string;
  arguments?: unknown[];
}
