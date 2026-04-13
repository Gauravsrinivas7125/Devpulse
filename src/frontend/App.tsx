/**
 * DevPulse - Main Application Shell
 * Central routing and layout for the entire frontend
 */

import React, { useEffect, useState, useCallback, Component } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';

import { OnboardingWizard, NotificationContainer, showNotification } from './onboarding_notifications';
import { ResponsiveNav, ResponsiveContainer } from './mobile_responsive';
import DashboardPage from './dashboards';
import AuthService from './auth-service';
import { KillSwitchPage, ShadowAPIPage, PCICompliancePage, TokenAnalyticsPage, ForgotPasswordPage, ResetPasswordPage, PrivacyPolicyPage, TermsOfServicePage } from './pages';

interface User {
  id: string;
  email: string;
  name: string;
  workspace_id: string;
  onboarding_completed?: boolean;
}

interface AppState {
  isAuthenticated: boolean;
  user: User | null;
  showOnboarding: boolean;
  loading: boolean;
}

const App: React.FC = () => {
  const [state, setState] = useState<AppState>({
    isAuthenticated: false,
    user: null,
    showOnboarding: false,
    loading: true,
  });

  useEffect(() => {
    const initializeApp = async () => {
      try {
        const token = localStorage.getItem('devpulse_token');
        if (!token) {
          setState((prev) => ({ ...prev, loading: false }));
          return;
        }

        const response = await fetch('/api/auth/verify', {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!response.ok) {
          localStorage.removeItem('devpulse_token');
          setState((prev) => ({ ...prev, loading: false }));
          return;
        }

        const user = (await response.json()) as User;
        setState({
          isAuthenticated: true,
          user,
          showOnboarding: !user.onboarding_completed,
          loading: false,
        });
      } catch (error) {
        console.error('Failed to initialize app:', error);
        setState((prev) => ({ ...prev, loading: false }));
      }
    };

    void initializeApp();
  }, []);

  const handleOnboardingComplete = () => {
    setState((prev) => ({ ...prev, showOnboarding: false }));
    showNotification('success', 'Welcome!', 'Onboarding completed successfully');
  };

  const handleOnboardingSkip = () => {
    setState((prev) => ({ ...prev, showOnboarding: false }));
  };

  const handleLogout = () => {
    AuthService.logout();
    setState({
      isAuthenticated: false,
      user: null,
      showOnboarding: false,
      loading: false,
    });
  };

  if (state.loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-100">
        <div className="text-center">
          <div className="inline-block h-12 w-12 animate-spin rounded-full border-b-2 border-blue-600"></div>
          <p className="mt-4 text-gray-600">Loading DevPulse...</p>
        </div>
      </div>
    );
  }

  if (!state.isAuthenticated) {
    return (
      <Router>
        <NotificationContainer />
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    );
  }

  return (
    <Router>
      <div className="flex h-screen flex-col bg-gray-50">
        <header className="bg-white shadow">
          <ResponsiveNav
            items={[
              { label: 'Dashboard', href: '/dashboard', icon: '📊' },
              { label: 'Collections', href: '/collections', icon: '📦' },
              { label: 'Security', href: '/security', icon: '🔒' },
              { label: 'Analytics', href: '/analytics', icon: '📈' },
              { label: 'Cost Intel', href: '/cost-intelligence', icon: '💰' },
              { label: 'Webhooks', href: '/webhooks', icon: '🔔' },
              { label: 'Compliance', href: '/compliance', icon: '✅' },
              { label: 'Settings', href: '/settings', icon: '⚙️' },
            ]}
            logo={<span className="text-2xl font-bold text-blue-600">DevPulse</span>}
          />
        </header>

        <main className="flex-1 overflow-auto">
          <ResponsiveContainer>
            <ErrorBoundary>
            <Routes>
              <Route path="/dashboard" element={<DashboardPage token={localStorage.getItem('devpulse_token')} />} />
              <Route path="/collections" element={<CollectionsPage />} />
              <Route path="/security" element={<SecurityPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/cost-intelligence" element={<CostIntelligencePage />} />
              <Route path="/webhooks" element={<WebhooksPage />} />
              <Route path="/compliance" element={<CompliancePage />} />
              <Route path="/kill-switch" element={<KillSwitchPage />} />
              <Route path="/shadow-api" element={<ShadowAPIPage />} />
              <Route path="/pci-compliance" element={<PCICompliancePage />} />
              <Route path="/token-analytics" element={<TokenAnalyticsPage />} />
              <Route path="/settings" element={<SettingsPage onLogout={handleLogout} />} />
              <Route path="/privacy" element={<PrivacyPolicyPage />} />
              <Route path="/terms" element={<TermsOfServicePage />} />
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
            </ErrorBoundary>
          </ResponsiveContainer>
        </main>

        <NotificationContainer />

        {state.showOnboarding && (
          <OnboardingWizard onComplete={handleOnboardingComplete} onSkip={handleOnboardingSkip} />
        )}
      </div>
    </Router>
  );
};

const LandingPage: React.FC = () => (
  <div className="min-h-screen bg-slate-950 text-white">
    <section className="mx-auto flex min-h-screen max-w-6xl flex-col justify-center px-6 py-16">
      <div className="max-w-3xl">
        <p className="mb-4 text-sm font-semibold uppercase tracking-[0.3em] text-blue-300">DevPulse</p>
        <h1 className="mb-6 text-5xl font-bold leading-tight">API security scanning and LLM cost visibility in one workflow.</h1>
        <p className="mb-8 text-lg text-slate-300">
          Import collections, run scans, review findings, and trigger kill-switch actions from a single workspace designed for engineering teams.
        </p>
        <div className="flex flex-wrap gap-4">
          <Link to="/signup" className="rounded-lg bg-blue-600 px-6 py-3 font-semibold text-white hover:bg-blue-500">
            Start free
          </Link>
          <Link to="/login" className="rounded-lg border border-slate-700 px-6 py-3 font-semibold text-slate-100 hover:border-slate-500">
            Sign in
          </Link>
        </div>
        <p className="mt-4 text-sm text-slate-500">
          <Link to="/forgot-password" className="hover:text-slate-300">Forgot your password?</Link>
        </p>
      </div>
      <div className="mt-16 grid gap-6 md:grid-cols-3">
        {[
          ['Import collections', 'Bring in Postman collections and centralize your API inventory.'],
          ['Prioritize risk', 'Review findings with severity and risk score context.'],
          ['Act immediately', 'Trigger protective workflows and team notifications when risk spikes.'],
        ].map(([title, description]) => (
          <div key={title} className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
            <h2 className="mb-3 text-xl font-semibold">{title}</h2>
            <p className="text-slate-300">{description}</p>
          </div>
        ))}
      </div>
    </section>
  </div>
);

const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await AuthService.login({ email, password });

    if (result.success) {
      showNotification('success', 'Login Successful', 'Welcome back to DevPulse');
      window.location.href = '/dashboard';
    } else {
      setError(result.error || 'Login failed');
    }

    setLoading(false);
  };

  return (
    <div className="flex h-screen items-center justify-center bg-gradient-to-r from-blue-600 to-blue-700">
      <div className="w-full max-w-md rounded-lg bg-white p-8 shadow-lg">
        <h1 className="mb-6 text-3xl font-bold text-gray-900">DevPulse</h1>
        {error && <div className="mb-4 rounded bg-red-100 p-3 text-red-700">{error}</div>}
        <form className="space-y-4" onSubmit={handleSubmit}>
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-blue-600 py-2 text-white transition hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        <p className="mt-4 text-center text-gray-600">
          Don&apos;t have an account? <Link to="/signup" className="text-blue-600 hover:underline">Sign up</Link>
        </p>
        <p className="mt-2 text-center text-gray-500 text-sm">
          <Link to="/forgot-password" className="hover:text-blue-600">Forgot password?</Link>
        </p>
      </div>
    </div>
  );
};

const SignupPage: React.FC = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await AuthService.signup({ name, email, password });

    if (result.success) {
      showNotification('success', 'Signup Successful', 'Welcome to DevPulse');
      window.location.href = '/dashboard';
    } else {
      setError(result.error || 'Signup failed');
    }

    setLoading(false);
  };

  return (
    <div className="flex h-screen items-center justify-center bg-gradient-to-r from-blue-600 to-blue-700">
      <div className="w-full max-w-md rounded-lg bg-white p-8 shadow-lg">
        <h1 className="mb-6 text-3xl font-bold text-gray-900">Sign Up</h1>
        {error && <div className="mb-4 rounded bg-red-100 p-3 text-red-700">{error}</div>}
        <form className="space-y-4" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Full Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-blue-600 py-2 text-white transition hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? 'Creating account...' : 'Create account'}
          </button>
        </form>
        <p className="mt-4 text-center text-gray-600">
          Already have an account? <Link to="/login" className="text-blue-600 hover:underline">Log in</Link>
        </p>
      </div>
    </div>
  );
};

const CollectionsPage: React.FC = () => {
  const [collections, setCollections] = useState<Array<{id: string; name: string; format: string; total_requests: number; created_at: string}>>([]);
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(true);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const fetchCollections = useCallback(async () => {
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/collections`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setCollections(data.collections || []);
      }
    } catch (err) {
      console.error('Failed to fetch collections:', err);
    } finally {
      setLoading(false);
    }
  }, [API_URL]);

  useEffect(() => { void fetchCollections(); }, [fetchCollections]);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/collections/import`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: formData,
      });
      if (res.ok) {
        showNotification('success', 'Collection Imported', 'Your collection was imported successfully.');
        void fetchCollections();
      } else {
        const err = await res.json();
        showNotification('error', 'Import Failed', err.detail || 'Failed to import collection');
      }
    } catch (err) {
      showNotification('error', 'Import Failed', String(err));
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const token = localStorage.getItem('devpulse_token');
      await fetch(`${API_URL}/api/collections/${id}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      showNotification('success', 'Deleted', 'Collection removed.');
      void fetchCollections();
    } catch (err) {
      showNotification('error', 'Delete Failed', String(err));
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Collections</h1>
          <p className="text-gray-600">Import and manage your API collections.</p>
        </div>
        <label className={`cursor-pointer rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 ${uploading ? 'opacity-50' : ''}`}>
          {uploading ? 'Uploading...' : 'Import Collection'}
          <input type="file" accept=".json" className="hidden" onChange={handleUpload} disabled={uploading} />
        </label>
      </div>

      {loading ? (
        <p className="text-gray-500">Loading collections...</p>
      ) : collections.length === 0 ? (
        <div className="rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
          <p className="text-lg text-gray-500">No collections yet</p>
          <p className="text-sm text-gray-400">Import a Postman, Bruno, or OpenAPI collection to get started.</p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {collections.map((col) => (
            <div key={col.id} className="rounded-lg border bg-white p-5 shadow-sm">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-semibold text-gray-900">{col.name}</h3>
                <span className="rounded bg-blue-100 px-2 py-0.5 text-xs text-blue-700">{col.format}</span>
              </div>
              <p className="text-sm text-gray-600">{col.total_requests} requests</p>
              <p className="text-xs text-gray-400">Created {new Date(col.created_at).toLocaleDateString()}</p>
              <div className="mt-3 flex gap-2">
                <Link to={`/security?collection=${col.id}`} className="rounded bg-green-600 px-3 py-1 text-xs text-white hover:bg-green-700">Scan</Link>
                <button onClick={() => handleDelete(col.id)} className="rounded bg-red-100 px-3 py-1 text-xs text-red-700 hover:bg-red-200">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const SecurityPage: React.FC = () => {
  const [riskScore, setRiskScore] = useState<{risk_score: number; risk_level: string; total_findings: number; by_severity: Record<string, number>} | null>(null);
  const [scans, setScans] = useState<Array<{id: string; collection_name: string; status: string; risk_score: number; risk_level: string; total_findings: number; created_at: string}>>([]);
  const [findings, setFindings] = useState<Array<{id: string; title: string; severity: string; category: string; description: string; remediation: string}>>([]);
  const [loading, setLoading] = useState(true);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const token = localStorage.getItem('devpulse_token');
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    Promise.all([
      fetch(`${API_URL}/api/risk-score`, { headers }).then(r => r.ok ? r.json() : null),
      fetch(`${API_URL}/api/scans`, { headers }).then(r => r.ok ? r.json() : null),
      fetch(`${API_URL}/api/findings`, { headers }).then(r => r.ok ? r.json() : null),
    ]).then(([risk, scanData, findingsData]) => {
      if (risk) setRiskScore(risk);
      if (scanData) setScans(scanData.scans || []);
      if (findingsData) setFindings(findingsData.findings || []);
    }).catch(console.error).finally(() => setLoading(false));
  }, [API_URL]);

  const severityColor: Record<string, string> = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH: 'bg-orange-500 text-white',
    MEDIUM: 'bg-yellow-400 text-gray-900',
    LOW: 'bg-blue-400 text-white',
    INFO: 'bg-gray-300 text-gray-800',
  };

  if (loading) return <div className="p-6"><p className="text-gray-500">Loading security data...</p></div>;

  return (
    <div className="p-6">
      <h1 className="mb-6 text-3xl font-bold">Security</h1>

      {/* Risk Score Summary */}
      <div className="mb-8 grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border bg-white p-5 shadow-sm">
          <p className="text-sm text-gray-500">Risk Score</p>
          <p className="text-3xl font-bold">{riskScore?.risk_score ?? 0}</p>
          <p className={`text-sm font-semibold ${riskScore?.risk_level === 'CRITICAL' ? 'text-red-600' : riskScore?.risk_level === 'HIGH' ? 'text-orange-500' : riskScore?.risk_level === 'MEDIUM' ? 'text-yellow-600' : 'text-green-600'}`}>
            {riskScore?.risk_level ?? 'LOW'}
          </p>
        </div>
        <div className="rounded-lg border bg-white p-5 shadow-sm">
          <p className="text-sm text-gray-500">Total Findings</p>
          <p className="text-3xl font-bold">{riskScore?.total_findings ?? findings.length}</p>
        </div>
        <div className="rounded-lg border bg-white p-5 shadow-sm">
          <p className="text-sm text-gray-500">Critical</p>
          <p className="text-3xl font-bold text-red-600">{riskScore?.by_severity?.critical ?? 0}</p>
        </div>
        <div className="rounded-lg border bg-white p-5 shadow-sm">
          <p className="text-sm text-gray-500">High</p>
          <p className="text-3xl font-bold text-orange-500">{riskScore?.by_severity?.high ?? 0}</p>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="mb-8">
        <h2 className="mb-4 text-xl font-semibold">Scan History</h2>
        {scans.length === 0 ? (
          <p className="text-gray-500">No scans yet. Import a collection and run a scan to see results.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b bg-gray-50 text-left text-sm text-gray-600">
                  <th className="p-3">Collection</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Risk</th>
                  <th className="p-3">Findings</th>
                  <th className="p-3">Date</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id} className="border-b hover:bg-gray-50">
                    <td className="p-3 font-medium">{scan.collection_name}</td>
                    <td className="p-3"><span className="rounded bg-green-100 px-2 py-0.5 text-xs text-green-700">{scan.status}</span></td>
                    <td className="p-3">
                      <span className={`rounded px-2 py-0.5 text-xs ${severityColor[scan.risk_level] || 'bg-gray-200'}`}>{scan.risk_score}</span>
                    </td>
                    <td className="p-3">{scan.total_findings}</td>
                    <td className="p-3 text-sm text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Findings List */}
      <div>
        <h2 className="mb-4 text-xl font-semibold">Findings</h2>
        {findings.length === 0 ? (
          <p className="text-gray-500">No findings to display.</p>
        ) : (
          <div className="space-y-3">
            {findings.map((f) => (
              <div key={f.id} className="rounded-lg border bg-white p-4 shadow-sm">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold">{f.title}</h3>
                  <span className={`rounded px-2 py-0.5 text-xs ${severityColor[f.severity] || 'bg-gray-200'}`}>{f.severity}</span>
                </div>
                <p className="mt-1 text-sm text-gray-600">{f.description}</p>
                {f.remediation && <p className="mt-1 text-sm text-blue-600">Fix: {f.remediation}</p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

const CompliancePage: React.FC = () => {
  const [collections, setCollections] = useState<Array<{id: string; name: string}>>([]);
  const [selectedCollection, setSelectedCollection] = useState('');
  const [report, setReport] = useState<{compliance_status: string; compliance_percentage: number; requirements: Array<{id: string; title: string; status: string; description: string}>} | null>(null);
  const [generating, setGenerating] = useState(false);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const token = localStorage.getItem('devpulse_token');
    fetch(`${API_URL}/api/collections`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }).then(r => r.ok ? r.json() : { collections: [] }).then(d => {
      setCollections(d.collections || []);
      if (d.collections?.length > 0) setSelectedCollection(d.collections[0].id);
    }).catch(console.error);
  }, [API_URL]);

  const generateReport = async () => {
    if (!selectedCollection) return;
    setGenerating(true);
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/compliance/pci-dss?collection_id=${selectedCollection}`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setReport(data);
        showNotification('success', 'Report Generated', 'PCI DSS compliance report is ready.');
      } else {
        const err = await res.json();
        showNotification('error', 'Generation Failed', err.detail || 'Failed to generate report');
      }
    } catch (err) {
      showNotification('error', 'Error', String(err));
    } finally {
      setGenerating(false);
    }
  };

  const statusColor: Record<string, string> = {
    compliant: 'text-green-600',
    partial: 'text-yellow-600',
    'non-compliant': 'text-red-600',
  };

  return (
    <div className="p-6">
      <h1 className="mb-6 text-3xl font-bold">Compliance</h1>

      {/* Report Generator */}
      <div className="mb-8 rounded-lg border bg-white p-6 shadow-sm">
        <h2 className="mb-4 text-xl font-semibold">Generate PCI DSS Report</h2>
        <div className="flex gap-4">
          <select
            value={selectedCollection}
            onChange={(e) => setSelectedCollection(e.target.value)}
            className="flex-1 rounded-lg border px-4 py-2"
          >
            {collections.length === 0 && <option value="">No collections available</option>}
            {collections.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <button
            onClick={generateReport}
            disabled={generating || !selectedCollection}
            className="rounded-lg bg-blue-600 px-6 py-2 text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Report Results */}
      {report && (
        <div className="rounded-lg border bg-white p-6 shadow-sm">
          <div className="mb-6 flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold">PCI DSS Compliance Report</h2>
              <p className={`font-semibold ${statusColor[report.compliance_status] || 'text-gray-600'}`}>
                Status: {report.compliance_status}
              </p>
            </div>
            <div className="text-right">
              <p className="text-3xl font-bold">{report.compliance_percentage}%</p>
              <p className="text-sm text-gray-500">Compliance Score</p>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="mb-6 h-3 w-full rounded-full bg-gray-200">
            <div
              className={`h-3 rounded-full ${report.compliance_percentage >= 80 ? 'bg-green-500' : report.compliance_percentage >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
              style={{ width: `${report.compliance_percentage}%` }}
            />
          </div>

          {/* Requirements */}
          {report.requirements && (
            <div className="space-y-3">
              <h3 className="font-semibold text-gray-700">Requirements</h3>
              {report.requirements.map((req) => (
                <div key={req.id} className="rounded border p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">{req.id}: {req.title}</span>
                    <span className={`text-sm font-semibold ${statusColor[req.status] || 'text-gray-600'}`}>{req.status}</span>
                  </div>
                  <p className="mt-1 text-sm text-gray-600">{req.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const SettingsPage: React.FC<{ onLogout: () => void }> = ({ onLogout }) => {
  const [plan, setPlan] = useState<{plan: string; limits: Record<string, unknown>} | null>(null);
  const [teamMembers, setTeamMembers] = useState<Array<{id: string; email: string; role: string; status: string}>>([]);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('viewer');
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const token = localStorage.getItem('devpulse_token');
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    Promise.all([
      fetch(`${API_URL}/api/plan/limits`, { headers }).then(r => r.ok ? r.json() : null),
      fetch(`${API_URL}/api/team/members`, { headers }).then(r => r.ok ? r.json() : null),
    ]).then(([planData, teamData]) => {
      if (planData) setPlan(planData);
      if (teamData) setTeamMembers(teamData.members || []);
    }).catch(console.error);
  }, [API_URL]);

  const handleCheckout = async (targetPlan: string) => {
    setCheckoutLoading(targetPlan);
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/billing/create-checkout-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ plan: targetPlan, success_url: window.location.origin + '/settings?billing=success', cancel_url: window.location.origin + '/settings?billing=cancelled' }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.checkout_url) {
          window.location.href = data.checkout_url;
        } else {
          showNotification('error', 'Checkout Error', 'No checkout URL returned.');
        }
      } else {
        const err = await res.json();
        showNotification('error', 'Checkout Failed', err.detail || err.error || 'Failed to create checkout session.');
      }
    } catch (err) {
      showNotification('error', 'Error', String(err));
    } finally {
      setCheckoutLoading(null);
    }
  };

  const handleManageBilling = async () => {
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/billing/portal-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ return_url: window.location.origin + '/settings' }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.portal_url) {
          window.location.href = data.portal_url;
        }
      } else {
        showNotification('error', 'Error', 'Failed to open billing portal.');
      }
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const inviteMember = async () => {
    if (!inviteEmail) return;
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/team/invite`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
      });
      if (res.ok) {
        const data = await res.json();
        setTeamMembers(prev => [...prev, data.member]);
        setInviteEmail('');
        showNotification('success', 'Invited', `Invitation sent to ${inviteEmail}`);
      } else {
        const err = await res.json();
        showNotification('error', 'Invite Failed', err.detail || 'Failed to invite');
      }
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const removeMember = async (id: string) => {
    try {
      const token = localStorage.getItem('devpulse_token');
      await fetch(`${API_URL}/api/team/members/${id}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      setTeamMembers(prev => prev.filter(m => m.id !== id));
      showNotification('success', 'Removed', 'Team member removed.');
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const currentPlan = plan?.plan || 'free';

  const plans = [
    {
      name: 'free', label: 'Free', price: '$0', period: '/month',
      features: ['5 API Collections', '10 Scans / month', 'Basic Risk Scoring', 'Community Support'],
    },
    {
      name: 'pro', label: 'Pro', price: '$49', period: '/month', popular: true,
      features: ['Unlimited Collections', '500 Scans / month', 'Advanced Risk Scoring', 'Kill Switch', 'Shadow API Scanner', 'PCI DSS Reports', 'Priority Support'],
    },
    {
      name: 'enterprise', label: 'Enterprise', price: '$199', period: '/month',
      features: ['Everything in Pro', 'Unlimited Scans', 'Custom Integrations', 'SSO / SAML', 'Dedicated Support', 'SLA Guarantee', 'Custom Compliance'],
    },
  ];

  return (
    <div className="p-6">
      <h1 className="mb-6 text-3xl font-bold">Settings</h1>

      {/* Plan & Billing */}
      <div className="mb-8 rounded-lg border bg-white p-6 shadow-sm" id="billing">
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-xl font-semibold">Plan & Billing</h2>
          {currentPlan !== 'free' && (
            <button onClick={handleManageBilling} className="rounded-lg border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50">
              Manage Billing
            </button>
          )}
        </div>

        {/* Plan Comparison Cards */}
        <div className="grid gap-4 md:grid-cols-3">
          {plans.map((p) => (
            <div key={p.name} className={`relative rounded-lg border-2 p-6 ${currentPlan === p.name ? 'border-blue-500 bg-blue-50' : p.popular ? 'border-purple-300' : 'border-gray-200'}`}>
              {p.popular && currentPlan !== p.name && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-purple-600 px-3 py-0.5 text-xs font-medium text-white">Most Popular</span>
              )}
              {currentPlan === p.name && (
                <span className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full bg-blue-600 px-3 py-0.5 text-xs font-medium text-white">Current Plan</span>
              )}
              <h3 className="mb-1 text-lg font-bold">{p.label}</h3>
              <div className="mb-4">
                <span className="text-3xl font-bold">{p.price}</span>
                <span className="text-gray-500">{p.period}</span>
              </div>
              <ul className="mb-6 space-y-2">
                {p.features.map((f) => (
                  <li key={f} className="flex items-center gap-2 text-sm text-gray-700">
                    <svg className="h-4 w-4 flex-shrink-0 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                    {f}
                  </li>
                ))}
              </ul>
              {currentPlan === p.name ? (
                <button disabled className="w-full rounded-lg bg-gray-200 px-4 py-2 text-sm text-gray-500">Current Plan</button>
              ) : (
                <button
                  onClick={() => handleCheckout(p.name)}
                  disabled={checkoutLoading !== null}
                  className={`w-full rounded-lg px-4 py-2 text-sm font-medium text-white ${p.popular ? 'bg-gradient-to-r from-blue-600 to-purple-600 hover:opacity-90' : 'bg-gray-900 hover:bg-gray-700'} disabled:opacity-50`}
                >
                  {checkoutLoading === p.name ? 'Redirecting...' : currentPlan === 'enterprise' ? 'Switch Plan' : 'Upgrade'}
                </button>
              )}
            </div>
          ))}
        </div>

        {plan?.limits && (
          <div className="mt-6">
            <h3 className="mb-3 text-sm font-semibold text-gray-500 uppercase">Your Plan Limits</h3>
            <div className="grid gap-3 md:grid-cols-3">
              {Object.entries(plan.limits).map(([key, value]) => (
                <div key={key} className="rounded border p-3">
                  <p className="text-xs text-gray-500">{key.replace(/_/g, ' ')}</p>
                  <p className="font-semibold">{typeof value === 'boolean' ? (value ? 'Included' : 'Not included') : String(value)}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Team Management */}
      <div className="mb-8 rounded-lg border bg-white p-6 shadow-sm">
        <h2 className="mb-4 text-xl font-semibold">Team Members</h2>
        <div className="mb-4 flex gap-2">
          <input
            type="email"
            placeholder="Email address"
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            className="flex-1 rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} className="rounded-lg border px-3 py-2">
            <option value="viewer">Viewer</option>
            <option value="editor">Editor</option>
            <option value="admin">Admin</option>
          </select>
          <button onClick={inviteMember} className="rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700">
            Invite
          </button>
        </div>
        {teamMembers.length === 0 ? (
          <p className="text-gray-500">No team members yet.</p>
        ) : (
          <div className="space-y-2">
            {teamMembers.map((m) => (
              <div key={m.id} className="flex items-center justify-between rounded border p-3">
                <div>
                  <p className="font-medium">{m.email}</p>
                  <p className="text-xs text-gray-500">{m.role} - {m.status}</p>
                </div>
                <button onClick={() => removeMember(m.id)} className="text-sm text-red-600 hover:underline">Remove</button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Account Actions */}
      <div className="rounded-lg border bg-white p-6 shadow-sm">
        <h2 className="mb-4 text-xl font-semibold">Account</h2>
        <button onClick={onLogout} className="rounded-lg bg-gray-900 px-4 py-2 text-white hover:bg-gray-700">
          Logout
        </button>
      </div>
    </div>
  );
};

// ============================================================================
// ANALYTICS PAGE (God-Level Intelligence)
// ============================================================================

const AnalyticsPage: React.FC = () => {
  const [analytics, setAnalytics] = useState<{
    scan_trends: Array<{date: string; scans: number; avg_risk: number}>;
    finding_heatmap: Record<string, Record<string, number>>;
    activity: Array<{event_type: string; timestamp: string; data: Record<string, unknown>}>;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const token = localStorage.getItem('devpulse_token');
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    fetch(`${API_URL}/api/analytics/comprehensive`, { headers })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setAnalytics(data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [API_URL]);

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold">Analytics</h1>
        <p className="text-gray-600">Comprehensive security intelligence and trend analysis.</p>
      </div>

      {loading ? (
        <p className="text-gray-500">Loading analytics...</p>
      ) : !analytics ? (
        <div className="rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
          <p className="text-lg text-gray-500">No analytics data yet</p>
          <p className="text-sm text-gray-400">Run scans to generate analytics insights.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Scan Trends */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold">Scan Trends</h2>
            {analytics.scan_trends && analytics.scan_trends.length > 0 ? (
              <div className="grid gap-4 md:grid-cols-3">
                {analytics.scan_trends.slice(-7).map((day) => (
                  <div key={day.date} className="rounded border p-3">
                    <p className="text-xs text-gray-500">{day.date}</p>
                    <p className="text-lg font-bold">{day.scans} scans</p>
                    <p className="text-sm text-gray-600">Avg risk: {day.avg_risk.toFixed(1)}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500">No scan trend data available.</p>
            )}
          </div>

          {/* Finding Heatmap */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold">Finding Heatmap</h2>
            {analytics.finding_heatmap && Object.keys(analytics.finding_heatmap).length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="p-2 text-left">Category</th>
                      <th className="p-2 text-center text-red-600">Critical</th>
                      <th className="p-2 text-center text-orange-600">High</th>
                      <th className="p-2 text-center text-yellow-600">Medium</th>
                      <th className="p-2 text-center text-blue-600">Low</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(analytics.finding_heatmap).map(([category, severities]) => (
                      <tr key={category} className="border-b hover:bg-gray-50">
                        <td className="p-2 font-medium">{category}</td>
                        <td className="p-2 text-center">{(severities as Record<string, number>).critical || 0}</td>
                        <td className="p-2 text-center">{(severities as Record<string, number>).high || 0}</td>
                        <td className="p-2 text-center">{(severities as Record<string, number>).medium || 0}</td>
                        <td className="p-2 text-center">{(severities as Record<string, number>).low || 0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500">No heatmap data available.</p>
            )}
          </div>

          {/* Activity Feed */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold">Recent Activity</h2>
            {analytics.activity && analytics.activity.length > 0 ? (
              <div className="space-y-2">
                {analytics.activity.slice(0, 20).map((event, idx) => (
                  <div key={idx} className="flex items-center gap-3 rounded border p-3">
                    <span className="rounded bg-blue-100 px-2 py-0.5 text-xs text-blue-700">{event.event_type}</span>
                    <span className="flex-1 text-sm text-gray-700">{JSON.stringify(event.data).slice(0, 100)}</span>
                    <span className="text-xs text-gray-400">{new Date(event.timestamp).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500">No recent activity.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};


// ============================================================================
// COST INTELLIGENCE PAGE (God-Level LLM Cost Tracking)
// ============================================================================

const CostIntelligencePage: React.FC = () => {
  const [summary, setSummary] = useState<{
    total_cost_usd: number;
    total_requests: number;
    utilization: Array<{window: string; total_cost: number; budget: number | null; usage_pct: number | null}>;
    anomalies: Array<{type: string; message: string; timestamp: string}>;
    models: Array<{model: string; total_cost: number; requests: number}>;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => {
    const token = localStorage.getItem('devpulse_token');
    const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};

    fetch(`${API_URL}/api/cost-tracker/summary`, { headers })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setSummary(data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [API_URL]);

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold">Cost Intelligence</h1>
        <p className="text-gray-600">Multi-model LLM cost tracking with anomaly detection.</p>
      </div>

      {loading ? (
        <p className="text-gray-500">Loading cost data...</p>
      ) : !summary ? (
        <div className="rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
          <p className="text-lg text-gray-500">No cost data yet</p>
          <p className="text-sm text-gray-400">Track LLM API calls to see cost intelligence.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-3">
            <div className="rounded-lg border bg-white p-6 shadow-sm">
              <p className="text-sm text-gray-600">Total Cost</p>
              <p className="text-3xl font-bold text-green-600">${summary.total_cost_usd.toFixed(4)}</p>
            </div>
            <div className="rounded-lg border bg-white p-6 shadow-sm">
              <p className="text-sm text-gray-600">Total Requests</p>
              <p className="text-3xl font-bold">{summary.total_requests.toLocaleString()}</p>
            </div>
            <div className="rounded-lg border bg-white p-6 shadow-sm">
              <p className="text-sm text-gray-600">Anomalies Detected</p>
              <p className="text-3xl font-bold text-red-600">{summary.anomalies?.length || 0}</p>
            </div>
          </div>

          {/* Utilization Windows */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold">Utilization Windows</h2>
            <div className="grid gap-4 md:grid-cols-4">
              {(summary.utilization || []).map((w) => (
                <div key={w.window} className="rounded border p-4">
                  <p className="text-sm font-medium text-gray-500">{w.window}</p>
                  <p className="text-2xl font-bold">${w.total_cost.toFixed(4)}</p>
                  {w.budget !== null && (
                    <div className="mt-2">
                      <div className="h-2 rounded-full bg-gray-200">
                        <div
                          className={`h-2 rounded-full ${(w.usage_pct || 0) > 80 ? 'bg-red-500' : 'bg-green-500'}`}
                          style={{ width: `${Math.min(100, w.usage_pct || 0)}%` }}
                        />
                      </div>
                      <p className="mt-1 text-xs text-gray-500">{w.usage_pct?.toFixed(1)}% of ${w.budget} budget</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Model Breakdown */}
          <div className="rounded-lg border bg-white p-6 shadow-sm">
            <h2 className="mb-4 text-xl font-semibold">Cost by Model</h2>
            {(summary.models || []).length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="p-2 text-left">Model</th>
                      <th className="p-2 text-right">Requests</th>
                      <th className="p-2 text-right">Total Cost</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.models.map((m) => (
                      <tr key={m.model} className="border-b hover:bg-gray-50">
                        <td className="p-2 font-medium">{m.model}</td>
                        <td className="p-2 text-right">{m.requests}</td>
                        <td className="p-2 text-right font-semibold">${m.total_cost.toFixed(4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500">No model data available.</p>
            )}
          </div>

          {/* Anomalies */}
          {(summary.anomalies || []).length > 0 && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-6 shadow-sm">
              <h2 className="mb-4 text-xl font-semibold text-red-800">Cost Anomalies</h2>
              <div className="space-y-2">
                {summary.anomalies.map((a, idx) => (
                  <div key={idx} className="flex items-center gap-3 rounded border border-red-200 bg-white p-3">
                    <span className="rounded bg-red-100 px-2 py-0.5 text-xs text-red-700">{a.type}</span>
                    <span className="flex-1 text-sm text-gray-700">{a.message}</span>
                    <span className="text-xs text-gray-400">{new Date(a.timestamp).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};


// ============================================================================
// WEBHOOKS PAGE (Multi-Platform Notifications)
// ============================================================================

interface WebhookItem {
  webhook_id: string;
  name: string;
  platform: string;
  url: string;
  events: string[];
  enabled: boolean;
}

const WebhooksPage: React.FC = () => {
  const [webhooks, setWebhooks] = useState<WebhookItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formPlatform, setFormPlatform] = useState('slack');
  const [formUrl, setFormUrl] = useState('');
  const [formEvents, setFormEvents] = useState<string[]>(['scan.completed']);
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const fetchWebhooks = useCallback(async () => {
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/webhooks`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setWebhooks(data.webhooks || []);
      }
    } catch (err) {
      console.error('Failed to fetch webhooks:', err);
    } finally {
      setLoading(false);
    }
  }, [API_URL]);

  useEffect(() => { void fetchWebhooks(); }, [fetchWebhooks]);

  const createWebhook = async () => {
    if (!formName || !formUrl) return;
    try {
      const token = localStorage.getItem('devpulse_token');
      const res = await fetch(`${API_URL}/api/webhooks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ name: formName, platform: formPlatform, url: formUrl, events: formEvents }),
      });
      if (res.ok) {
        showNotification('success', 'Webhook Created', 'Webhook registered successfully.');
        setShowForm(false);
        setFormName('');
        setFormUrl('');
        void fetchWebhooks();
      } else {
        const err = await res.json();
        showNotification('error', 'Failed', err.detail || 'Failed to create webhook');
      }
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const deleteWebhook = async (id: string) => {
    try {
      const token = localStorage.getItem('devpulse_token');
      await fetch(`${API_URL}/api/webhooks/${id}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      showNotification('success', 'Deleted', 'Webhook removed.');
      void fetchWebhooks();
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const testWebhook = async (id: string) => {
    try {
      const token = localStorage.getItem('devpulse_token');
      await fetch(`${API_URL}/api/webhooks/test/${id}`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      showNotification('success', 'Test Sent', 'Test event dispatched to webhook.');
    } catch (err) {
      showNotification('error', 'Error', String(err));
    }
  };

  const platformColors: Record<string, string> = {
    slack: 'bg-purple-100 text-purple-700',
    discord: 'bg-indigo-100 text-indigo-700',
    teams: 'bg-blue-100 text-blue-700',
    generic: 'bg-gray-100 text-gray-700',
  };

  const allEvents = [
    'scan.completed', 'scan.failed', 'finding.critical', 'finding.high',
    'cost.anomaly', 'cost.budget_exceeded', 'webhook.test', 'compliance.report_generated',
    'policy.limit_reached', 'session.completed',
  ];

  const toggleEvent = (event: string) => {
    setFormEvents(prev => prev.includes(event) ? prev.filter(e => e !== event) : [...prev, event]);
  };

  return (
    <div className="p-6">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Webhooks</h1>
          <p className="text-gray-600">Configure notifications for Slack, Discord, Teams, or custom endpoints.</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          {showForm ? 'Cancel' : 'Add Webhook'}
        </button>
      </div>

      {/* Create Form */}
      {showForm && (
        <div className="mb-6 rounded-lg border bg-white p-6 shadow-sm">
          <h2 className="mb-4 text-lg font-semibold">New Webhook</h2>
          <div className="grid gap-4 md:grid-cols-2">
            <input
              type="text"
              placeholder="Webhook name"
              value={formName}
              onChange={e => setFormName(e.target.value)}
              className="rounded-lg border px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
            <select
              value={formPlatform}
              onChange={e => setFormPlatform(e.target.value)}
              className="rounded-lg border px-4 py-2"
            >
              <option value="slack">Slack</option>
              <option value="discord">Discord</option>
              <option value="teams">Microsoft Teams</option>
              <option value="generic">Generic HTTP</option>
            </select>
            <input
              type="url"
              placeholder="Webhook URL"
              value={formUrl}
              onChange={e => setFormUrl(e.target.value)}
              className="rounded-lg border px-4 py-2 md:col-span-2 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
          <div className="mt-4">
            <p className="mb-2 text-sm font-medium text-gray-700">Events:</p>
            <div className="flex flex-wrap gap-2">
              {allEvents.map(event => (
                <button
                  key={event}
                  onClick={() => toggleEvent(event)}
                  className={`rounded-full px-3 py-1 text-xs ${formEvents.includes(event) ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                >
                  {event}
                </button>
              ))}
            </div>
          </div>
          <button onClick={createWebhook} className="mt-4 rounded-lg bg-green-600 px-6 py-2 text-white hover:bg-green-700">
            Create Webhook
          </button>
        </div>
      )}

      {/* Webhook List */}
      {loading ? (
        <p className="text-gray-500">Loading webhooks...</p>
      ) : webhooks.length === 0 ? (
        <div className="rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
          <p className="text-lg text-gray-500">No webhooks configured</p>
          <p className="text-sm text-gray-400">Add a webhook to receive real-time notifications.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks.map((wh) => (
            <div key={wh.webhook_id} className="flex items-center gap-4 rounded-lg border bg-white p-4 shadow-sm">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <h3 className="font-semibold">{wh.name}</h3>
                  <span className={`rounded px-2 py-0.5 text-xs ${platformColors[wh.platform] || 'bg-gray-100 text-gray-700'}`}>
                    {wh.platform}
                  </span>
                  <span className={`rounded px-2 py-0.5 text-xs ${wh.enabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                    {wh.enabled ? 'Active' : 'Disabled'}
                  </span>
                </div>
                <p className="mt-1 text-xs text-gray-500">{wh.url}</p>
                <div className="mt-1 flex flex-wrap gap-1">
                  {wh.events.map(e => (
                    <span key={e} className="rounded bg-gray-50 px-1.5 py-0.5 text-xs text-gray-500">{e}</span>
                  ))}
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={() => testWebhook(wh.webhook_id)} className="rounded bg-blue-100 px-3 py-1 text-xs text-blue-700 hover:bg-blue-200">
                  Test
                </button>
                <button onClick={() => deleteWebhook(wh.webhook_id)} className="rounded bg-red-100 px-3 py-1 text-xs text-red-700 hover:bg-red-200">
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};


// ============================================================================
// ERROR BOUNDARY
// ============================================================================

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: React.ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[60vh] items-center justify-center p-8">
          <div className="max-w-lg rounded-lg border border-red-200 bg-red-50 p-8 text-center shadow-lg">
            <h2 className="mb-3 text-2xl font-bold text-red-800">Something went wrong</h2>
            <p className="mb-4 text-red-600">{this.state.error?.message || 'An unexpected error occurred.'}</p>
            <button
              onClick={() => { this.setState({ hasError: false, error: null }); window.location.href = '/dashboard'; }}
              className="rounded-lg bg-red-600 px-6 py-2 text-white hover:bg-red-700"
            >
              Return to Dashboard
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export default App;
