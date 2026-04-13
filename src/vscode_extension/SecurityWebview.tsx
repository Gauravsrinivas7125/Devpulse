import React, { useState, useEffect } from 'react';

/**
 * DevPulse - Security Webview for VS Code Extension
 * Displays security scan results and vulnerability findings
 */

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  path?: string;
  line?: number;
}

interface ScanResult {
  scan_id: string;
  timestamp: string;
  risk_score: number;
  findings: Finding[];
}

const SecurityWebview: React.FC = () => {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Simulate fetching scan results from the extension host
    const fetchScanResults = async () => {
      try {
        setLoading(true);
        // In a real extension, this would use vscode.postMessage to request data
        // For simulation, we'll wait and then set dummy data
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const dummyData: ScanResult = {
          scan_id: "scan_" + Math.random().toString(36).substring(7),
          timestamp: new Date().toISOString(),
          risk_score: 42.5,
          findings: [
            {
              id: "f1",
              title: "Broken Object Level Authorization (BOLA)",
              severity: "critical",
              description: "Unauthorized access to other users' data via object ID manipulation.",
              path: "src/api/users.ts",
              line: 42
            },
            {
              id: "f2",
              title: "Unrestricted Resource Consumption",
              severity: "high",
              description: "Missing rate limiting on the /api/search endpoint.",
              path: "src/api/search.ts",
              line: 15
            },
            {
              id: "f3",
              title: "Improper Assets Management",
              severity: "medium",
              description: "Exposed staging API endpoints in production environment.",
              path: "src/config/api.ts",
              line: 8
            }
          ]
        };
        
        setScanResult(dummyData);
        setLoading(false);
      } catch (err) {
        setError("Failed to load security scan results.");
        setLoading(false);
      }
    };

    fetchScanResults();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-600 text-white';
      case 'high': return 'bg-orange-500 text-white';
      case 'medium': return 'bg-yellow-500 text-black';
      case 'low': return 'bg-blue-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full p-8 text-gray-500">
        <div className="animate-spin mr-2">⏳</div>
        Loading security findings...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-red-600 bg-red-50 rounded-lg border border-red-200">
        <strong>Error:</strong> {error}
      </div>
    );
  }

  return (
    <div className="p-4 font-sans text-gray-900 bg-white">
      <header className="mb-6 border-b pb-4">
        <h1 className="text-xl font-bold flex items-center">
          <span className="mr-2">🛡️</span> DevPulse Security Scan
        </h1>
        <div className="mt-2 flex items-center justify-between text-sm text-gray-600">
          <span>Scan ID: <code className="bg-gray-100 px-1 rounded">{scanResult?.scan_id}</code></span>
          <span>Risk Score: <span className={`font-bold ${scanResult && scanResult.risk_score > 40 ? 'text-red-600' : 'text-green-600'}`}>{scanResult?.risk_score}/100</span></span>
        </div>
      </header>

      <section>
        <h2 className="text-lg font-semibold mb-4 flex items-center">
          Findings ({scanResult?.findings.length})
        </h2>
        
        <div className="space-y-4">
          {scanResult?.findings.map((finding) => (
            <div key={finding.id} className="border rounded-lg overflow-hidden shadow-sm hover:shadow-md transition-shadow">
              <div className={`px-3 py-1 text-xs font-bold uppercase tracking-wider ${getSeverityColor(finding.severity)}`}>
                {finding.severity}
              </div>
              <div className="p-3">
                <h3 className="font-bold text-md mb-1">{finding.title}</h3>
                <p className="text-sm text-gray-600 mb-3">{finding.description}</p>
                
                {finding.path && (
                  <div className="flex items-center text-xs text-blue-600 font-mono bg-blue-50 p-2 rounded cursor-pointer hover:bg-blue-100">
                    <span className="mr-1">📄</span>
                    {finding.path}:{finding.line}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <footer className="mt-8 pt-4 border-t text-center text-xs text-gray-400">
        Last updated: {scanResult && new Date(scanResult.timestamp).toLocaleString()}
      </footer>
    </div>
  );
};

export default SecurityWebview;
