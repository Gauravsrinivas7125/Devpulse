/**
 * DevPulse - Metrics & Security Dashboards
 * Comprehensive analytics and security monitoring
 */

import React, { useState } from 'react';

interface SecurityMetric {
  severity: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  trend: number;
}

interface DashboardData {
  riskScore: number;
  totalFindings: number;
  apisCovered: number;
  teamMembers: number;
  scansDone: number;
  complianceScore: number;
  metrics: {
    byType: { [key: string]: number };
    bySeverity: SecurityMetric[];
    trends: { date: string; score: number }[];
  };
}

export const MetricsDashboard: React.FC<{ data: DashboardData }> = ({ data }) => {
  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-gradient-to-r from-blue-600 to-blue-700 p-8 text-white">
        <h1 className="mb-2 text-4xl font-bold">Metrics Dashboard</h1>
        <p className="text-blue-100">Real-time analytics and performance metrics</p>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        <MetricCard
          title="Risk Score"
          value={data.riskScore}
          unit="/100"
          trend={data.metrics.bySeverity.reduce((a, b) => a + b.trend, 0) / data.metrics.bySeverity.length}
          icon="Risk"
          color="bg-red-50"
        />
        <MetricCard title="Total Findings" value={data.totalFindings} trend={-5} icon="Findings" color="bg-yellow-50" />
        <MetricCard title="APIs Covered" value={data.apisCovered} trend={12} icon="APIs" color="bg-blue-50" />
        <MetricCard title="Team Members" value={data.teamMembers} trend={3} icon="Team" color="bg-green-50" />
        <MetricCard title="Scans Completed" value={data.scansDone} trend={25} icon="Scans" color="bg-purple-50" />
        <MetricCard title="Compliance Score" value={data.complianceScore} unit="%" trend={8} icon="Compliance" color="bg-indigo-50" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <ChartCard title="Risk Score Trend">
          <TrendChart data={data.metrics.trends} />
        </ChartCard>
        <ChartCard title="Findings by Severity">
          <SeverityChart data={data.metrics.bySeverity} />
        </ChartCard>
      </div>

      <ChartCard title="Findings by Type">
        <FindingsTypeChart data={data.metrics.byType} />
      </ChartCard>
    </div>
  );
};

export const SecurityDashboard: React.FC<{ data: DashboardData }> = ({ data }) => {
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');

  const filteredFindings = data.metrics.bySeverity.filter((f) => {
    if (filter === 'all') return true;
    return f.severity === filter;
  });

  return (
    <div className="space-y-6">
      <div className="rounded-lg bg-gradient-to-r from-red-600 to-red-700 p-8 text-white">
        <h1 className="mb-2 text-4xl font-bold">Security Dashboard</h1>
        <p className="text-red-100">Real-time security monitoring and threat detection</p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <RiskGauge score={data.riskScore} />
        </div>

        <div className="space-y-4 lg:col-span-2">
          <SecurityStatCard
            title="Critical Vulnerabilities"
            count={data.metrics.bySeverity.find((f) => f.severity === 'critical')?.count || 0}
            severity="critical"
          />
          <SecurityStatCard
            title="High Risk Issues"
            count={data.metrics.bySeverity.find((f) => f.severity === 'high')?.count || 0}
            severity="high"
          />
          <SecurityStatCard
            title="Medium Priority"
            count={data.metrics.bySeverity.find((f) => f.severity === 'medium')?.count || 0}
            severity="medium"
          />
        </div>
      </div>

      <div className="flex space-x-2">
        {(['all', 'critical', 'high', 'medium', 'low'] as const).map((severity) => (
          <button
            key={severity}
            onClick={() => setFilter(severity)}
            className={`rounded-lg px-4 py-2 font-medium transition-colors ${
              filter === severity ? 'bg-red-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            {severity.charAt(0).toUpperCase() + severity.slice(1)}
          </button>
        ))}
      </div>

      <ChartCard title={`${filteredFindings.length} Findings`}>
        <FindingsList findings={filteredFindings} />
      </ChartCard>

      <ChartCard title="Security Events Timeline">
        <SecurityTimeline />
      </ChartCard>
    </div>
  );
};

const sampleDashboardData: DashboardData = {
  riskScore: 72,
  totalFindings: 46,
  apisCovered: 18,
  teamMembers: 7,
  scansDone: 124,
  complianceScore: 88,
  metrics: {
    byType: {
      Authentication: 12,
      Authorization: 8,
      Injection: 10,
      Secrets: 6,
      Misconfiguration: 10
    },
    bySeverity: [
      { severity: 'critical', count: 3, trend: 8 },
      { severity: 'high', count: 9, trend: 5 },
      { severity: 'medium', count: 17, trend: -3 },
      { severity: 'low', count: 17, trend: -8 }
    ],
    trends: [
      { date: 'Mon', score: 61 },
      { date: 'Tue', score: 64 },
      { date: 'Wed', score: 67 },
      { date: 'Thu', score: 70 },
      { date: 'Fri', score: 72 }
    ]
  }
};

interface MetricCardProps {
  title: string;
  value: number;
  unit?: string;
  trend: number;
  icon: string;
  color: string;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, unit, trend, icon, color }) => {
  const trendColor = trend >= 0 ? 'text-red-600' : 'text-green-600';
  const trendIcon = trend >= 0 ? 'Up' : 'Down';

  return (
    <div className={`${color} rounded-lg border border-gray-200 p-6`}>
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">
            {value}
            {unit && <span className="text-lg text-gray-600">{unit}</span>}
          </p>
        </div>
        <span className="text-sm font-semibold uppercase tracking-wide text-gray-500">{icon}</span>
      </div>
      <div className={`flex items-center ${trendColor}`}>
        <span>{trendIcon}</span>
        <span className="ml-1 font-semibold">{Math.abs(trend)}%</span>
      </div>
    </div>
  );
};

const ChartCard: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="rounded-lg border border-gray-200 bg-white p-6 shadow-md">
    <h2 className="mb-4 text-xl font-bold text-gray-900">{title}</h2>
    {children}
  </div>
);

const RiskGauge: React.FC<{ score: number }> = ({ score }) => {
  const getColor = (value: number) => {
    if (value >= 80) return '#dc2626';
    if (value >= 60) return '#f59e0b';
    if (value >= 40) return '#eab308';
    return '#22c55e';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative h-48 w-48">
        <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="45" fill="none" stroke="#e5e7eb" strokeWidth="8" />
          <circle
            cx="60"
            cy="60"
            r="45"
            fill="none"
            stroke={getColor(score)}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-300"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center">
            <p className="text-4xl font-bold text-gray-900">{score}</p>
            <p className="text-sm text-gray-600">Risk Score</p>
          </div>
        </div>
      </div>
    </div>
  );
};

const SecurityStatCard: React.FC<{ title: string; count: number; severity: 'critical' | 'high' | 'medium' | 'low' }> = ({ title, count, severity }) => {
  const colors = {
    critical: 'bg-red-50 border-red-200 text-red-700',
    high: 'bg-orange-50 border-orange-200 text-orange-700',
    medium: 'bg-yellow-50 border-yellow-200 text-yellow-700',
    low: 'bg-green-50 border-green-200 text-green-700'
  };

  return (
    <div className={`${colors[severity]} rounded-lg border p-4`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="font-medium">{title}</p>
          <p className="text-2xl font-bold">{count}</p>
        </div>
        <span className="text-sm font-semibold uppercase tracking-wide">{severity}</span>
      </div>
    </div>
  );
};

const TrendChart: React.FC<{ data: { date: string; score: number }[] }> = ({ data }) => (
  <div className="flex h-64 items-end justify-between space-x-2">
    {data.map((point) => (
      <div
        key={point.date}
        className="flex-1 rounded-t-lg bg-blue-500 transition-colors hover:bg-blue-600"
        style={{ height: `${point.score}%` }}
        title={`${point.date}: ${point.score}`}
      />
    ))}
  </div>
);

const SeverityChart: React.FC<{ data: SecurityMetric[] }> = ({ data }) => (
  <div className="space-y-3">
    {data.map((item) => (
      <div key={item.severity}>
        <div className="mb-1 flex justify-between">
          <span className="font-medium capitalize">{item.severity}</span>
          <span className="font-bold">{item.count}</span>
        </div>
        <div className="h-2 w-full rounded-full bg-gray-200">
          <div
            className={`h-2 rounded-full ${
              item.severity === 'critical'
                ? 'bg-red-600'
                : item.severity === 'high'
                  ? 'bg-orange-600'
                  : item.severity === 'medium'
                    ? 'bg-yellow-600'
                    : 'bg-green-600'
            }`}
            style={{ width: `${Math.min(item.count * 10, 100)}%` }}
          />
        </div>
      </div>
    ))}
  </div>
);

const FindingsTypeChart: React.FC<{ data: { [key: string]: number } }> = ({ data }) => (
  <div className="space-y-3">
    {Object.entries(data).map(([type, count]) => (
      <div key={type}>
        <div className="mb-1 flex justify-between">
          <span className="font-medium">{type}</span>
          <span className="font-bold">{count}</span>
        </div>
        <div className="h-2 w-full rounded-full bg-gray-200">
          <div className="h-2 rounded-full bg-blue-600" style={{ width: `${Math.min(count * 5, 100)}%` }} />
        </div>
      </div>
    ))}
  </div>
);

const FindingsList: React.FC<{ findings: SecurityMetric[] }> = ({ findings }) => (
  <div className="space-y-3">
    {findings.map((finding) => (
      <div key={finding.severity} className="flex items-center justify-between rounded-lg bg-gray-50 p-3">
        <span className="font-medium capitalize">{finding.severity}</span>
        <span className="text-2xl font-bold">{finding.count}</span>
      </div>
    ))}
  </div>
);

const SecurityTimeline: React.FC = () => (
  <div className="space-y-4">
    {[
      { time: '2 hours ago', event: 'Critical vulnerability detected' },
      { time: '5 hours ago', event: 'Security scan completed' },
      { time: '1 day ago', event: 'Team member invited' },
      { time: '2 days ago', event: 'API collection imported' }
    ].map((item) => (
      <div key={`${item.time}-${item.event}`} className="flex items-start space-x-4">
        <span className="text-sm font-semibold uppercase tracking-wide text-gray-500">Event</span>
        <div>
          <p className="font-medium text-gray-900">{item.event}</p>
          <p className="text-sm text-gray-600">{item.time}</p>
        </div>
      </div>
    ))}
  </div>
);

const DashboardPage: React.FC = () => (
  <div className="space-y-10 py-6">
    <MetricsDashboard data={sampleDashboardData} />
    <SecurityDashboard data={sampleDashboardData} />
  </div>
);

export default DashboardPage;
