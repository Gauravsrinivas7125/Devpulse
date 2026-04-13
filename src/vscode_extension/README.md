# DevPulse Security

**The nervous system for AI-native companies** — API security scanning, LLM cost intelligence, and autonomous protection inside VS Code.

## Features

### API Security Scanning
- **Import Collections**: Import Postman, Bruno, or OpenAPI collections directly from VS Code
- **OWASP Top 10 (2023)**: Automatic security scanning against OWASP API Security Top 10
- **Credential Detection**: Detects hardcoded AWS keys, GitHub tokens, Slack tokens, Stripe keys, JWTs, API keys, and database connection strings

### Risk Intelligence (Patent 1)
- **Unified Risk Score**: Combined security severity + LLM cost anomaly scoring
- **Real-time Dashboard**: View risk scores, severity breakdowns, and trends

### Thinking Token Analytics (Patent 2)
- **Differential Analysis**: Separate reasoning vs completion token tracking for o1/o3 models
- **Cost Attribution**: Timing-based cost attribution with anomaly detection

### Autonomous Kill Switch (Patent 3)
- **Budget Enforcement**: Set global, per-model, and per-operation budget limits
- **Loop Detection**: Automatic detection of infinite agent loops (repeat + circular patterns)
- **Audit Trail**: Complete audit trail of all kill events

### Shadow API Scanner
- **Workspace Scanning**: Scan your entire workspace for undocumented API endpoints
- **Risk Classification**: Identifies shadow APIs in `/debug/`, `/internal/`, `/admin/`, `/config/`, `/test/`, `/backup/` paths

### Compliance
- **PCI DSS v4.0.1**: Full OWASP-to-PCI requirement mapping
- **GDPR Assessment**: Automated GDPR article applicability assessment
- **PDF Reports**: Export compliance reports as PDF

## Commands

| Command | Description |
|---------|-------------|
| `DevPulse: Scan Current File` | Scan the active file for security issues |
| `DevPulse: Import Collection` | Import a Postman/OpenAPI collection |
| `DevPulse: Show Risk Score` | View unified risk score dashboard |
| `DevPulse: Generate Compliance Report` | Generate PCI DSS + GDPR report |
| `DevPulse: Activate Kill Switch` | Manually activate the kill switch |
| `DevPulse: Scan Workspace for Shadow APIs` | Scan workspace for undocumented endpoints |
| `DevPulse: Set Kill Switch Budget` | Configure budget limits for auto-kill |
| `DevPulse: View Kill Switch Audit Trail` | View history of kill events |
| `DevPulse: Refresh Findings` | Refresh security findings |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `devpulse.apiUrl` | `http://localhost:8000` | DevPulse API server URL |
| `devpulse.apiToken` | ` ` | Authentication token for DevPulse API |
| `devpulse.autoScan` | `false` | Automatically scan files on save |

## Getting Started

1. Install the extension from VS Code Marketplace
2. Start the DevPulse backend server (`uvicorn backend.main:app`)
3. Configure your API URL and token in VS Code settings
4. Import a Postman collection or scan a file to get started

## Requirements

- VS Code 1.85.0 or later
- DevPulse backend server running (see [backend setup](https://github.com/darshanbharathwajnhcm-del/Devpulse))

## License

MIT
