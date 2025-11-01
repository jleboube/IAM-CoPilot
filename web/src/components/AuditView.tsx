import { useState } from 'react';
import { toast } from 'react-hot-toast';
import { Activity, AlertTriangle, AlertCircle, Info } from 'lucide-react';
import { apiClient } from '../services/api';
import type { AuditResult, Finding } from '../types';

export default function AuditView() {
  const [awsAccountId, setAwsAccountId] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [auditScope, setAuditScope] = useState('roles');
  const [loading, setLoading] = useState(false);
  const [auditResults, setAuditResults] = useState<AuditResult | null>(null);

  const handleStartAudit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!awsAccountId.trim()) {
      toast.error('Please enter an AWS Account ID');
      return;
    }

    setLoading(true);
    setAuditResults(null);

    try {
      const response = await apiClient.startAudit({
        aws_account_id: awsAccountId,
        role_arn: roleArn || undefined,
        audit_scope: auditScope,
        include_cloudtrail: true,
      });

      toast.success('Audit started successfully!');

      // Poll for results
      const auditId = response.audit_id;
      setTimeout(async () => {
        try {
          const results = await apiClient.getAuditResults(auditId);
          setAuditResults(results);
          toast.success('Audit completed!');
        } catch (error) {
          console.error('Failed to fetch audit results:', error);
          toast.error('Audit is still running or failed');
        } finally {
          setLoading(false);
        }
      }, 3000);
    } catch (error: any) {
      console.error('Audit failed:', error);
      toast.error(error.response?.data?.detail || 'Failed to start audit');
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <Activity className="text-primary-500" />
          IAM Security Audit
        </h1>
        <p className="mt-2 text-gray-400">
          Analyze IAM configuration for security risks and excessive permissions
        </p>
      </div>

      {/* Audit Form */}
      <div className="card">
        <form onSubmit={handleStartAudit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              AWS Account ID *
            </label>
            <input
              type="text"
              value={awsAccountId}
              onChange={(e) => setAwsAccountId(e.target.value)}
              placeholder="123456789012"
              className="input"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Cross-Account Role ARN (Optional)
            </label>
            <input
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/AuditRole"
              className="input"
            />
            <p className="mt-2 text-sm text-gray-500">
              Provide a role ARN if auditing a different account
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Audit Scope
            </label>
            <select
              value={auditScope}
              onChange={(e) => setAuditScope(e.target.value)}
              className="input"
            >
              <option value="roles">Roles Only</option>
              <option value="users">Users Only</option>
              <option value="policies">Policies Only</option>
              <option value="all">All (Comprehensive)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Running Audit...
              </>
            ) : (
              <>
                <Activity size={20} />
                Start Security Audit
              </>
            )}
          </button>
        </form>
      </div>

      {/* Audit Results */}
      {auditResults && (
        <>
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <StatCard
              title="Total Resources"
              value={auditResults.recommendations.total_resources}
              color="blue"
            />
            <StatCard
              title="High Risk"
              value={auditResults.recommendations.high_risk}
              color="red"
            />
            <StatCard
              title="Medium Risk"
              value={auditResults.recommendations.medium_risk}
              color="yellow"
            />
            <StatCard
              title="Low Risk"
              value={auditResults.recommendations.low_risk}
              color="green"
            />
          </div>

          {/* Findings */}
          <div className="card">
            <h2 className="text-xl font-bold mb-4">Security Findings</h2>
            {auditResults.findings.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                No security issues found. Great job!
              </div>
            ) : (
              <div className="space-y-4">
                {auditResults.findings.map((finding, index) => (
                  <FindingCard key={index} finding={finding} />
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ title, value, color }: {
  title: string;
  value: number;
  color: 'blue' | 'red' | 'yellow' | 'green';
}) {
  const colorClasses = {
    blue: 'bg-blue-900/20 border-blue-700 text-blue-400',
    red: 'bg-red-900/20 border-red-700 text-red-400',
    yellow: 'bg-yellow-900/20 border-yellow-700 text-yellow-400',
    green: 'bg-green-900/20 border-green-700 text-green-400',
  };

  return (
    <div className={`card border ${colorClasses[color]}`}>
      <p className="text-sm opacity-80">{title}</p>
      <p className="text-3xl font-bold mt-2">{value}</p>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const severityConfig = {
    high: {
      icon: <AlertTriangle className="h-5 w-5" />,
      color: 'border-red-700 bg-red-900/20',
      textColor: 'text-red-400',
    },
    medium: {
      icon: <AlertCircle className="h-5 w-5" />,
      color: 'border-yellow-700 bg-yellow-900/20',
      textColor: 'text-yellow-400',
    },
    low: {
      icon: <Info className="h-5 w-5" />,
      color: 'border-blue-700 bg-blue-900/20',
      textColor: 'text-blue-400',
    },
  };

  const config = severityConfig[finding.severity];

  return (
    <div className={`p-4 rounded-lg border ${config.color}`}>
      <div className="flex items-start gap-3">
        <div className={config.textColor}>{config.icon}</div>
        <div className="flex-1">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="font-semibold text-white">{finding.resource_name}</h3>
              <p className="text-xs text-gray-500 mt-1">{finding.resource_arn}</p>
            </div>
            <span className={`text-xs font-medium px-2 py-1 rounded ${config.textColor}`}>
              {finding.severity.toUpperCase()}
            </span>
          </div>
          <p className="text-sm text-gray-300 mt-3">{finding.finding}</p>
          <div className="mt-3 p-3 bg-gray-800 rounded">
            <p className="text-sm text-gray-400">
              <strong>Recommendation:</strong> {finding.recommendation}
            </p>
            {finding.permission_reduction_percent && (
              <p className="text-sm text-green-400 mt-2">
                Potential reduction: {finding.permission_reduction_percent}% fewer permissions
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
