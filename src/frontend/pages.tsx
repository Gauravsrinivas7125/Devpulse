/**
 * DevPulse - Frontend Pages
 * Missing UI pages for Kill Switch, Shadow API, PCI Compliance, and Token Analytics
 */

import React, { useState, useEffect } from 'react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

/**
 * Kill Switch Page
 */
export const KillSwitchPage: React.FC = () => {
  const [isActive, setIsActive] = useState(false);
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [history] = useState<any[]>([]);

  const handleTrigger = async () => {
    if (!reason.trim()) {
      alert('Please provide a reason');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/kill-switch/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason })
      });

      if (response.ok) {
        setIsActive(true);
        setReason('');
        alert('Kill switch activated! Slack alert sent.');
      }
    } catch (error) {
      console.error('Error triggering kill switch:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeactivate = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/kill-switch/deactivate', {
        method: 'POST'
      });

      if (response.ok) {
        setIsActive(false);
        alert('Kill switch deactivated');
      }
    } catch (error) {
      console.error('Error deactivating kill switch:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Kill Switch</h1>

      <div className={`p-6 rounded-lg mb-6 ${isActive ? 'bg-red-100 border-2 border-red-500' : 'bg-green-100 border-2 border-green-500'}`}>
        <h2 className="text-2xl font-bold mb-4">
          Status: <span className={isActive ? 'text-red-600' : 'text-green-600'}>
            {isActive ? 'ACTIVE' : 'INACTIVE'}
          </span>
        </h2>

        {!isActive ? (
          <div className="space-y-4">
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Enter reason for activation..."
              className="w-full p-3 border rounded-lg"
              rows={4}
            />
            <button
              onClick={handleTrigger}
              disabled={loading}
              className="bg-red-600 text-white px-6 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50"
            >
              {loading ? 'Activating...' : 'Activate Kill Switch'}
            </button>
          </div>
        ) : (
          <div>
            <p className="mb-4 text-red-700">The kill switch is currently active. All API access is blocked.</p>
            <button
              onClick={handleDeactivate}
              disabled={loading}
              className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50"
            >
              {loading ? 'Deactivating...' : 'Deactivate Kill Switch'}
            </button>
          </div>
        )}
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="text-xl font-bold mb-4">Recent Activity</h3>
        {history.length === 0 ? (
          <p className="text-gray-500">No activity yet</p>
        ) : (
          <div className="space-y-2">
            {history.map((event, idx) => (
              <div key={idx} className="p-3 bg-gray-50 rounded">
                <p className="font-semibold">{event.action}</p>
                <p className="text-sm text-gray-600">{event.timestamp}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Shadow API Detection Page
 */
export const ShadowAPIPage: React.FC = () => {
  const [shadowAPIs, setShadowAPIs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchShadowAPIs();
  }, []);

  const fetchShadowAPIs = async () => {
    try {
      const response = await fetch('/api/shadow-api/list');
      const data = await response.json();
      setShadowAPIs(data.apis || []);
    } catch (error) {
      console.error('Error fetching shadow APIs:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredAPIs = filter === 'all' 
    ? shadowAPIs 
    : shadowAPIs.filter(api => api.risk_level === filter);

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Shadow API Detection</h1>

      <div className="mb-6 flex gap-4">
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-4 py-2 border rounded-lg"
        >
          <option value="all">All APIs</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button
          onClick={fetchShadowAPIs}
          className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700"
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <p>Loading...</p>
      ) : (
        <div className="grid gap-4">
          {filteredAPIs.length === 0 ? (
            <p className="text-gray-500">No shadow APIs detected</p>
          ) : (
            filteredAPIs.map((api, idx) => (
              <div key={idx} className="bg-white p-4 rounded-lg shadow border-l-4" style={{
                borderColor: api.risk_level === 'critical' ? '#dc2626' : api.risk_level === 'high' ? '#ea580c' : api.risk_level === 'medium' ? '#f59e0b' : '#10b981'
              }}>
                <h3 className="font-bold text-lg">{api.endpoint}</h3>
                <p className="text-sm text-gray-600 mb-2">{api.method}</p>
                <div className="flex gap-4 text-sm">
                  <span className="bg-gray-100 px-2 py-1 rounded">Risk: {api.risk_level}</span>
                  <span className="bg-gray-100 px-2 py-1 rounded">Requests: {api.request_count}</span>
                  <span className="bg-gray-100 px-2 py-1 rounded">Detected: {api.first_seen}</span>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

/**
 * PCI Compliance Page
 */
export const PCICompliancePage: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch('/api/compliance/reports');
      const data = await response.json();
      setReports(data.reports || []);
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateReport = async () => {
    setGenerating(true);
    try {
      const response = await fetch('/api/compliance/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'PCI' })
      });

      if (response.ok) {
        alert('Report generated successfully');
        fetchReports();
      }
    } catch (error) {
      console.error('Error generating report:', error);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">PCI Compliance</h1>

      <button
        onClick={generateReport}
        disabled={generating}
        className="mb-6 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
      >
        {generating ? 'Generating...' : 'Generate Report'}
      </button>

      {loading ? (
        <p>Loading...</p>
      ) : (
        <div className="grid gap-4">
          {reports.length === 0 ? (
            <p className="text-gray-500">No reports generated yet</p>
          ) : (
            reports.map((report, idx) => (
              <div key={idx} className="bg-white p-6 rounded-lg shadow">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="font-bold text-lg">{report.type} Compliance</h3>
                    <p className="text-sm text-gray-600">Generated: {report.generated_at}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-3xl font-bold text-blue-600">{report.compliance_percentage}%</p>
                    <p className="text-sm text-gray-600">Compliant</p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-green-50 p-4 rounded">
                    <p className="text-sm text-gray-600">Passed</p>
                    <p className="text-2xl font-bold text-green-600">{report.passed_requirements}</p>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded">
                    <p className="text-sm text-gray-600">Warnings</p>
                    <p className="text-2xl font-bold text-yellow-600">{report.warning_requirements}</p>
                  </div>
                  <div className="bg-red-50 p-4 rounded">
                    <p className="text-sm text-gray-600">Failed</p>
                    <p className="text-2xl font-bold text-red-600">{report.failed_requirements}</p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

/**
 * Token Analytics Page
 */
export const TokenAnalyticsPage: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [dailyData, setDailyData] = useState<any[]>([]);
  const [modelData, setModelData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const fetchAnalytics = async () => {
    try {
      const response = await fetch('/api/tokens/analytics');
      const data = await response.json();
      setStats(data.stats);
      setDailyData(data.daily_breakdown || []);
      setModelData(data.model_breakdown || []);
    } catch (error) {
      console.error('Error fetching analytics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <p>Loading...</p>;

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Token Analytics</h1>

      {stats && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-gray-600 text-sm">Total Tokens</p>
            <p className="text-3xl font-bold">{stats.total_tokens?.toLocaleString()}</p>
          </div>
          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-gray-600 text-sm">Total Cost</p>
            <p className="text-3xl font-bold">${stats.total_cost?.toFixed(2)}</p>
          </div>
          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-gray-600 text-sm">Daily Average</p>
            <p className="text-3xl font-bold">${stats.average_daily_cost?.toFixed(2)}</p>
          </div>
          <div className="bg-white p-6 rounded-lg shadow">
            <p className="text-gray-600 text-sm">Most Used Model</p>
            <p className="text-2xl font-bold">{stats.most_expensive_model}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6 mb-6">
        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="font-bold text-lg mb-4">Daily Costs</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={dailyData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="cost" stroke="#3b82f6" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white p-6 rounded-lg shadow">
          <h3 className="font-bold text-lg mb-4">Cost by Model</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={modelData}
                dataKey="cost"
                nameKey="model"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label
              >
                {modelData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={['#3b82f6', '#10b981', '#f59e0b', '#ef4444'][index % 4]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h3 className="font-bold text-lg mb-4">Model Breakdown</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left p-3">Model</th>
                <th className="text-right p-3">Tokens</th>
                <th className="text-right p-3">Calls</th>
                <th className="text-right p-3">Cost</th>
              </tr>
            </thead>
            <tbody>
              {modelData.map((model, idx) => (
                <tr key={idx} className="border-b hover:bg-gray-50">
                  <td className="p-3">{model.model}</td>
                  <td className="text-right p-3">{model.tokens?.toLocaleString()}</td>
                  <td className="text-right p-3">{model.calls}</td>
                  <td className="text-right p-3 font-semibold">${model.cost?.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};


// ============================================================================
// PASSWORD RESET PAGES
// ============================================================================

export const ForgotPasswordPage: React.FC = () => {
  const [email, setEmail] = React.useState('');
  const [sent, setSent] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const handleSubmit = async () => {
    if (!email) { setError('Please enter your email'); return; }
    setLoading(true);
    setError('');
    try {
      await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      setSent(true);
    } catch (err) {
      setError('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (sent) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="bg-gray-800 p-8 rounded-lg text-center max-w-md w-full">
          <div className="text-green-400 text-5xl mb-4">✓</div>
          <h2 className="text-white text-xl font-bold mb-4">Check Your Email</h2>
          <p className="text-gray-400">If that email exists in our system, a reset link has been sent. Check your inbox (and spam folder).</p>
          <a href="/login" className="inline-block mt-6 text-blue-400 hover:text-blue-300 underline text-sm">Back to Login</a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg w-full max-w-md">
        <h2 className="text-white text-xl font-bold mb-2">Forgot Password</h2>
        <p className="text-gray-400 text-sm mb-6">Enter your email and we'll send you a reset link.</p>
        {error && <div className="bg-red-900/40 text-red-300 text-sm px-4 py-2 rounded mb-4">{error}</div>}
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="you@example.com"
          className="w-full bg-gray-700 text-white rounded px-4 py-2 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded font-semibold hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Sending...' : 'Send Reset Link'}
        </button>
        <a href="/login" className="block mt-4 text-center text-gray-500 hover:text-gray-300 text-sm">Back to Login</a>
      </div>
    </div>
  );
};

export const ResetPasswordPage: React.FC = () => {
  const [newPassword, setNewPassword] = React.useState('');
  const [confirmPassword, setConfirmPassword] = React.useState('');
  const [done, setDone] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const token = new URLSearchParams(window.location.search).get('token') || '';

  const handleSubmit = async () => {
    if (!newPassword || newPassword.length < 8) {
      setError('Password must be at least 8 characters'); return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match'); return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: newPassword })
      });
      const data = await res.json();
      if (res.ok) {
        setDone(true);
      } else {
        setError(data.detail || 'Reset failed. Link may have expired.');
      }
    } catch (err) {
      setError('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="bg-gray-800 p-8 rounded-lg text-center max-w-md w-full">
          <div className="text-red-400 text-5xl mb-4">✗</div>
          <h2 className="text-white text-xl font-bold mb-2">Invalid Link</h2>
          <p className="text-gray-400 text-sm mb-6">This reset link is missing a token. Please request a new one.</p>
          <a href="/forgot-password" className="text-blue-400 hover:text-blue-300 underline text-sm">Request New Link</a>
        </div>
      </div>
    );
  }

  if (done) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-900">
        <div className="bg-gray-800 p-8 rounded-lg text-center max-w-md w-full">
          <div className="text-green-400 text-5xl mb-4">✓</div>
          <h2 className="text-white text-xl font-bold mb-2">Password Reset!</h2>
          <p className="text-gray-400 text-sm mb-6">Your password has been updated successfully.</p>
          <a href="/login" className="inline-block bg-blue-600 text-white px-6 py-2 rounded font-semibold hover:bg-blue-700">Back to Login</a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="bg-gray-800 p-8 rounded-lg w-full max-w-md">
        <h2 className="text-white text-xl font-bold mb-2">Set New Password</h2>
        <p className="text-gray-400 text-sm mb-6">Choose a strong password for your account.</p>
        {error && <div className="bg-red-900/40 text-red-300 text-sm px-4 py-2 rounded mb-4">{error}</div>}
        <input
          type="password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
          placeholder="New password (min 8 chars)"
          className="w-full bg-gray-700 text-white rounded px-4 py-2 mb-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <input
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Confirm new password"
          className="w-full bg-gray-700 text-white rounded px-4 py-2 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={handleSubmit}
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded font-semibold hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Resetting...' : 'Reset Password'}
        </button>
      </div>
    </div>
  );
};

export default {
  KillSwitchPage,
  ShadowAPIPage,
  PCICompliancePage,
  TokenAnalyticsPage,
  ForgotPasswordPage,
  ResetPasswordPage
};
