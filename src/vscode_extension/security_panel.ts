/**
 * DevPulse - VS Code Security Panel
 * Real-time security findings in VS Code
 */

import * as vscode from 'vscode';

// ============================================================================
// SECURITY PANEL PROVIDER
// ============================================================================

export class SecurityPanelProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = 'devpulse.securityPanel';
  private _view?: vscode.WebviewView;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    context: vscode.WebviewViewContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage((data) => {
      this._handleMessage(data);
    });
  }

  private _getHtmlForWebview(webview: vscode.Webview): string {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'media', 'security-panel.js')
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'media', 'security-panel.css')
    );

    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>DevPulse Security</title>
        <link rel="stylesheet" href="${styleUri}" />
      </head>
      <body>
        <div class="security-panel">
          <div class="header">
            <h2>🛡️ DevPulse Security</h2>
            <button id="refresh-btn" class="refresh-btn">Refresh</button>
          </div>

          <div class="risk-score-section">
            <div class="risk-score-card">
              <div class="score-number" id="risk-score">--</div>
              <div class="score-label">Risk Score</div>
              <div class="score-trend" id="score-trend">--</div>
            </div>
          </div>

          <div class="findings-section">
            <h3>Findings</h3>
            <div class="findings-filter">
              <button class="filter-btn active" data-severity="all">All</button>
              <button class="filter-btn" data-severity="critical">Critical</button>
              <button class="filter-btn" data-severity="high">High</button>
              <button class="filter-btn" data-severity="medium">Medium</button>
            </div>
            <div id="findings-list" class="findings-list">
              <div class="loading">Loading findings...</div>
            </div>
          </div>

          <div class="stats-section">
            <h3>Statistics</h3>
            <div class="stats-grid">
              <div class="stat-card">
                <div class="stat-number" id="total-findings">0</div>
                <div class="stat-label">Total Findings</div>
              </div>
              <div class="stat-card">
                <div class="stat-number" id="critical-count">0</div>
                <div class="stat-label">Critical</div>
              </div>
              <div class="stat-card">
                <div class="stat-number" id="high-count">0</div>
                <div class="stat-label">High</div>
              </div>
              <div class="stat-card">
                <div class="stat-number" id="medium-count">0</div>
                <div class="stat-label">Medium</div>
              </div>
            </div>
          </div>

          <div class="actions-section">
            <button id="scan-btn" class="action-btn primary">Run Scan</button>
            <button id="export-btn" class="action-btn secondary">Export Report</button>
          </div>
        </div>
        <script src="${scriptUri}"></script>
      </body>
      </html>`;
  }

  private _handleMessage(message: any) {
    switch (message.command) {
      case 'refresh':
        this._refreshFindings();
        break;
      case 'runScan':
        this._runScan();
        break;
      case 'exportReport':
        this._exportReport();
        break;
      case 'selectFinding':
        this._selectFinding(message.findingId);
        break;
    }
  }

  private _refreshFindings() {
    // Fetch findings from DevPulse API
    this._postMessage({
      command: 'showFindings',
      findings: this._getMockFindings(),
    });
  }

  private _runScan() {
    vscode.window.showInformationMessage('Starting security scan...');
    // Trigger scan in DevPulse backend
    this._postMessage({
      command: 'scanStarted',
      scanId: 'scan_' + Date.now(),
    });
  }

  private _exportReport() {
    vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file('devpulse-security-report.pdf'),
      filters: {
        'PDF Files': ['pdf'],
        'JSON Files': ['json'],
      },
    }).then((fileUri) => {
      if (fileUri) {
        vscode.window.showInformationMessage(`Report exported to ${fileUri.fsPath}`);
      }
    });
  }

  private _selectFinding(findingId: string) {
    // Show finding details in editor
    vscode.window.showInformationMessage(`Showing finding: ${findingId}`);
  }

  private _postMessage(message: any) {
    if (this._view) {
      this._view.webview.postMessage(message);
    }
  }

  private _getMockFindings() {
    return [
      {
        id: 'finding_1',
        title: 'SQL Injection Vulnerability',
        severity: 'critical',
        endpoint: 'POST /api/users',
        parameter: 'email',
        description: 'User input is not properly sanitized',
        remediation: 'Use parameterized queries',
        cweId: 'CWE-89',
      },
      {
        id: 'finding_2',
        title: 'Missing Authentication',
        severity: 'high',
        endpoint: 'GET /api/admin',
        parameter: null,
        description: 'Admin endpoint accessible without authentication',
        remediation: 'Add JWT validation middleware',
        cweId: 'CWE-306',
      },
      {
        id: 'finding_3',
        title: 'Weak Password Policy',
        severity: 'medium',
        endpoint: 'POST /api/auth/register',
        parameter: 'password',
        description: 'Password requirements are too weak',
        remediation: 'Enforce strong password policy',
        cweId: 'CWE-521',
      },
    ];
  }
}

// ============================================================================
// SECURITY DIAGNOSTICS
// ============================================================================

export class SecurityDiagnosticsProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('devpulse-security');
  }

  public updateDiagnostics(uri: vscode.Uri, findings: any[]) {
    const diagnostics: vscode.Diagnostic[] = findings.map((finding) => {
      const range = new vscode.Range(0, 0, 0, 1);
      const severity = this._getSeverityLevel(finding.severity);
      const diagnostic = new vscode.Diagnostic(
        range,
        `[DevPulse] ${finding.title}: ${finding.description}`,
        severity
      );
      diagnostic.code = finding.cweId;
      diagnostic.source = 'DevPulse Security';
      return diagnostic;
    });

    this.diagnosticCollection.set(uri, diagnostics);
  }

  public clearDiagnostics(uri: vscode.Uri) {
    this.diagnosticCollection.delete(uri);
  }

  public clearAll() {
    this.diagnosticCollection.clear();
  }

  private _getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
      case 'critical':
        return vscode.DiagnosticSeverity.Error;
      case 'high':
        return vscode.DiagnosticSeverity.Error;
      case 'medium':
        return vscode.DiagnosticSeverity.Warning;
      case 'low':
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Hint;
    }
  }
}

// ============================================================================
// SECURITY HOVER PROVIDER
// ============================================================================

export class SecurityHoverProvider implements vscode.HoverProvider {
  public provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
    token: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.Hover> {
    // Get word at position
    const range = document.getWordRangeAtPosition(position);
    if (!range) return null;

    const word = document.getText(range);

    // Check if word is a security-related keyword
    const securityKeywords: { [key: string]: string } = {
      'password': '🔐 Password field - ensure proper hashing and validation',
      'token': '🔑 Token field - verify JWT signature and expiration',
      'auth': '🛡️ Authentication - check for proper authorization checks',
      'sql': '⚠️ SQL query - ensure parameterized queries to prevent injection',
      'api': '🌐 API endpoint - verify authentication and authorization',
      'secret': '🔒 Secret - ensure proper encryption and rotation',
    };

    for (const [keyword, message] of Object.entries(securityKeywords)) {
      if (word.toLowerCase().includes(keyword)) {
        return new vscode.Hover(message);
      }
    }

    return null;
  }
}

// ============================================================================
// SECURITY CODE LENS
// ============================================================================

export class SecurityCodeLensProvider implements vscode.CodeLensProvider {
  public provideCodeLenses(
    document: vscode.TextDocument,
    token: vscode.CancellationToken
  ): vscode.CodeLens[] {
    const codeLenses: vscode.CodeLens[] = [];

    // Find security-related patterns
    const patterns = [
      { regex: /password\s*[:=]/gi, title: '🔐 Check password handling' },
      { regex: /token\s*[:=]/gi, title: '🔑 Verify token security' },
      { regex: /secret\s*[:=]/gi, title: '🔒 Verify secret storage' },
      { regex: /api\s*\(/gi, title: '🌐 Check API security' },
    ];

    patterns.forEach((pattern) => {
      let match;
      while ((match = pattern.regex.exec(document.getText())) !== null) {
        const position = document.positionAt(match.index);
        const range = new vscode.Range(position, position);
        const codeLens = new vscode.CodeLens(range, {
          title: pattern.title,
          command: 'devpulse.showSecurityInfo',
          arguments: [pattern.title],
        });
        codeLenses.push(codeLens);
      }
    });

    return codeLenses;
  }
}

// ============================================================================
// EXPORT
// ============================================================================

export default {
  SecurityPanelProvider,
  SecurityDiagnosticsProvider,
  SecurityHoverProvider,
  SecurityCodeLensProvider,
};
