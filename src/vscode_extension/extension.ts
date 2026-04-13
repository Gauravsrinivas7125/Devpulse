/**
 * DevPulse - VS Code Extension Entry Point
 * Main activation and command registration
 */

import * as vscode from 'vscode';
import { SecurityPanelProvider } from './security_panel';
import DevPulseAPIClient from './api-integration';

let extensionContext: vscode.ExtensionContext;
let apiClient: DevPulseAPIClient;

/**
 * Activate the extension
 */
export function activate(context: vscode.ExtensionContext) {
  extensionContext = context;
  apiClient = new DevPulseAPIClient();

  console.log('DevPulse Security Scanner activated');

  // Register security panel provider
  const securityPanelProvider = new SecurityPanelProvider(context.extensionUri);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      SecurityPanelProvider.viewType,
      securityPanelProvider
    )
  );

  // Register commands
  registerCommands(context);

  // Show welcome message
  vscode.window.showInformationMessage('DevPulse Security Scanner is ready!');
}

/**
 * Register all extension commands
 */
function registerCommands(context: vscode.ExtensionContext) {
  // Command: Scan current file
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage('No file is currently open');
        return;
      }

      await scanFile(editor.document);
    })
  );

  // Command: Scan entire workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.scanWorkspace', async () => {
      await scanWorkspace();
    })
  );

  // Command: Authenticate with DevPulse
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.authenticate', async () => {
      await authenticate();
    })
  );

  // Command: List collections
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.listCollections', async () => {
      await listCollections();
    })
  );

  // Command: View security findings
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.viewFindings', async () => {
      await viewFindings();
    })
  );

  // Command: Generate compliance report
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.generateReport', async () => {
      await generateReport();
    })
  );

  // Command: Trigger kill switch
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.triggerKillSwitch', async () => {
      await triggerKillSwitch();
    })
  );

  // Command: Open settings
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.openSettings', async () => {
      await vscode.commands.executeCommand(
        'workbench.action.openSettings',
        'devpulse'
      );
    })
  );

  // Command: Show help
  context.subscriptions.push(
    vscode.commands.registerCommand('devpulse.showHelp', async () => {
      showHelp();
    })
  );
}

/**
 * Scan current file
 */
async function scanFile(document: vscode.TextDocument) {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    await authenticate();
    return;
  }

  const progress = vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Scanning file...',
      cancellable: false,
    },
    async () => {
      try {
        const collectionId = await vscode.window.showInputBox({
          prompt: 'Enter collection ID',
          placeHolder: 'col_xxx',
        });

        if (!collectionId) return;

        const result = await apiClient.scanCollection(collectionId);

        vscode.window.showInformationMessage(
          `Scan complete! Risk score: ${result.risk_score.toFixed(1)}, Findings: ${result.total_findings}`
        );

        // Show findings in output channel
        const outputChannel = vscode.window.createOutputChannel('DevPulse');
        outputChannel.clear();
        outputChannel.appendLine(`Scan Results for ${collectionId}`);
        outputChannel.appendLine(`Risk Score: ${result.risk_score}`);
        outputChannel.appendLine(`Total Findings: ${result.total_findings}`);
        outputChannel.appendLine('');
        outputChannel.appendLine('Findings:');
        result.findings.forEach((finding: any) => {
          outputChannel.appendLine(`- [${finding.severity}] ${finding.title}`);
        });
        outputChannel.show();
      } catch (error) {
        vscode.window.showErrorMessage(`Scan failed: ${String(error)}`);
      }
    }
  );
}

/**
 * Scan entire workspace
 */
async function scanWorkspace() {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    await authenticate();
    return;
  }

  vscode.window.showInformationMessage('Workspace scan initiated');
}

/**
 * Authenticate with DevPulse
 */
async function authenticate() {
  const email = await vscode.window.showInputBox({
    prompt: 'Enter your DevPulse email',
    placeHolder: 'user@example.com',
  });

  if (!email) return;

  const password = await vscode.window.showInputBox({
    prompt: 'Enter your password',
    password: true,
  });

  if (!password) return;

  try {
    const result = await apiClient.authenticate(email, password);
    vscode.window.showInformationMessage(`Authenticated as ${email}`);
  } catch (error) {
    vscode.window.showErrorMessage(`Authentication failed: ${String(error)}`);
  }
}

/**
 * List collections
 */
async function listCollections() {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    return;
  }

  try {
    const collections = await apiClient.listCollections();

    if (collections.length === 0) {
      vscode.window.showInformationMessage('No collections found');
      return;
    }

    const items = collections.map((col: any) => ({
      label: col.name,
      description: `${col.format} - ${col.total_requests} requests`,
      id: col.id,
    }));

    const selected = await vscode.window.showQuickPick(items);
    if (selected) {
      vscode.window.showInformationMessage(`Selected: ${selected.label}`);
    }
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to list collections: ${String(error)}`);
  }
}

/**
 * View findings
 */
async function viewFindings() {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    return;
  }

  try {
    const metrics = await apiClient.getRiskMetrics();
    const outputChannel = vscode.window.createOutputChannel('DevPulse Findings');
    outputChannel.clear();
    outputChannel.appendLine('Security Findings');
    outputChannel.appendLine(`Risk Score: ${metrics.risk_score}`);
    outputChannel.appendLine(`Total Findings: ${metrics.total_findings}`);
    outputChannel.show();
  } catch (error) {
    vscode.window.showErrorMessage(`Failed to fetch findings: ${String(error)}`);
  }
}

/**
 * Generate compliance report
 */
async function generateReport() {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    return;
  }

  const collectionId = await vscode.window.showInputBox({
    prompt: 'Enter collection ID',
  });

  if (!collectionId) return;

  const reportType = await vscode.window.showQuickPick(['PCI', 'OWASP', 'CWE']);

  if (!reportType) return;

  try {
    const report = await apiClient.generateComplianceReport(collectionId, reportType);
    vscode.window.showInformationMessage(`Report generated successfully`);
  } catch (error) {
    vscode.window.showErrorMessage(`Report generation failed: ${String(error)}`);
  }
}

/**
 * Trigger kill switch
 */
async function triggerKillSwitch() {
  if (!apiClient.isAuthenticated()) {
    vscode.window.showErrorMessage('Please authenticate first');
    return;
  }

  const confirm = await vscode.window.showWarningMessage(
    'Are you sure you want to trigger the kill switch?',
    'Yes',
    'No'
  );

  if (confirm !== 'Yes') return;

  const reason = await vscode.window.showInputBox({
    prompt: 'Enter reason for kill switch',
  });

  if (!reason) return;

  try {
    const result = await apiClient.triggerKillSwitch(reason);
    vscode.window.showWarningMessage('Kill switch triggered!');
  } catch (error) {
    vscode.window.showErrorMessage(`Kill switch failed: ${String(error)}`);
  }
}

/**
 * Show help
 */
function showHelp() {
  const helpText = `
DevPulse Security Scanner - Help

Commands:
- devpulse.scanFile: Scan the current file
- devpulse.scanWorkspace: Scan the entire workspace
- devpulse.authenticate: Authenticate with DevPulse
- devpulse.listCollections: List your API collections
- devpulse.viewFindings: View security findings
- devpulse.generateReport: Generate a compliance report
- devpulse.triggerKillSwitch: Trigger the kill switch
- devpulse.openSettings: Open extension settings
- devpulse.showHelp: Show this help message

For more information, visit: https://devpulse.io
  `;

  const panel = vscode.window.createWebviewPanel(
    'devpulseHelp',
    'DevPulse Help',
    vscode.ViewColumn.One
  );

  panel.webview.html = `
    <html>
      <head>
        <style>
          body { font-family: monospace; padding: 20px; background: #1e1e1e; color: #d4d4d4; }
          pre { background: #252526; padding: 10px; border-radius: 5px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <pre>${helpText}</pre>
      </body>
    </html>
  `;
}

/**
 * Deactivate the extension
 */
export function deactivate() {
  console.log('DevPulse Security Scanner deactivated');
}
