/**
 * Warden Language Server
 *
 * Provides LSP capabilities for advanced IDE integration
 */

import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  DidChangeConfigurationNotification,
  TextDocumentSyncKind,
  InitializeResult,
  Diagnostic,
  CodeAction,
  CodeActionKind,
} from 'vscode-languageserver/node';

import { TextDocument } from 'vscode-languageserver-textdocument';
import { Vuln, VulnSeverity, ScanReport } from './types';

// Create a connection for the server
const connection = createConnection(ProposedFeatures.all);

// Create a simple text document manager
const documents = new TextDocuments(TextDocument);

let hasConfigurationCapability = false;
let hasWorkspaceFolderCapability = false;

/**
 * Initialize the language server
 */
connection.onInitialize((params: InitializeParams) => {
  const capabilities = params.capabilities;

  hasConfigurationCapability = !!(
    capabilities.workspace && !!capabilities.workspace.configuration
  );
  hasWorkspaceFolderCapability = !!(
    capabilities.workspace && !!capabilities.workspace.workspaceFolders
  );

  const result: InitializeResult = {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      codeActionProvider: true,
      diagnosticProvider: {
        interFileDependencies: false,
        workspaceDiagnostics: false,
      },
    },
  };
  return result;
});

/**
 * Handle document changes
 */
documents.onDidChangeContent((change) => {
  validateDocument(change.document);
});

/**
 * Validate document and provide diagnostics
 */
async function validateDocument(textDocument: TextDocument): Promise<void> {
  // In a real implementation, this would call the Warden CLI
  // For now, we'll return an empty diagnostic array

  const diagnostics: Diagnostic[] = [];

  // Send diagnostics to the client
  connection.sendDiagnostics({
    uri: textDocument.uri,
    diagnostics,
  });
}

/**
 * Handle code actions
 */
connection.onCodeAction((params) => {
  const textDocument = documents.get(params.textDocument.uri);
  if (!textDocument) {
    return [];
  }

  const codeActions: CodeAction[] = [];

  // In a real implementation, this would provide quick fixes
  // for security vulnerabilities

  return codeActions;
});

/**
 * Handle configuration changes
 */
connection.onDidChangeConfiguration((change) => {
  if (hasConfigurationCapability) {
    // Reset all document diagnostics
    documents.all().forEach(validateDocument);
  }
});

// Make the text document manager listen on the connection
// for open, change and close text document events
documents.listen(connection);

// Listen on the connection
connection.listen();
