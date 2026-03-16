/**
 * Extension Tests
 */

import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Warden Extension Test Suite', () => {
  vscode.window.showInformationMessage('Start all tests.');

  test('Extension should be present', () => {
    assert.ok(vscode.extensions.getExtension('warden-security.warden-security'));
  });

  test('Extension should activate', async () => {
    const extension = vscode.extensions.getExtension('warden-security.warden-security');
    assert.ok(extension);
    await extension?.activate();
    assert.strictEqual(extension?.isActive, true);
  });

  test('Commands should be registered', async () => {
    const commands = await vscode.commands.getCommands(true);
    assert.ok(commands.includes('warden.scanCurrentFile'));
    assert.ok(commands.includes('warden.scanProject'));
    assert.ok(commands.includes('warden.showFindings'));
  });
});
