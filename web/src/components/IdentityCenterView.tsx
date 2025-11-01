import { useState } from 'react';
import { toast } from 'react-hot-toast';
import { Shield, Users, Key, Building2, AlertTriangle } from 'lucide-react';
import { apiClient } from '../services/api';
import type {
  IdentityCenterRequest,
  IdentityCenterOverview,
  IdentityCenterAuditResult,
  IdentityCenterFinding,
} from '../types';

export default function IdentityCenterView() {
  const [awsAccountId, setAwsAccountId] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [loading, setLoading] = useState(false);
  const [overview, setOverview] = useState<IdentityCenterOverview | null>(null);
  const [auditResult, setAuditResult] = useState<IdentityCenterAuditResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'audit'>('overview');

  const handleGetOverview = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!awsAccountId.trim()) {
      toast.error('Please enter an AWS Account ID');
      return;
    }

    setLoading(true);
    setActiveTab('overview');

    const request: IdentityCenterRequest = {
      aws_account_id: awsAccountId,
      role_arn: roleArn || undefined,
      region,
    };

    try {
      const data = await apiClient.getIdentityCenterOverview(request);
      setOverview(data);

      if (!data.enabled) {
        toast.error(data.message || 'Identity Center is not enabled');
      } else {
        toast.success('Identity Center overview loaded successfully!');
      }
    } catch (error: any) {
      console.error('Failed to load Identity Center overview:', error);
      toast.error(error.response?.data?.detail || 'Failed to load Identity Center overview');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAudit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!awsAccountId.trim()) {
      toast.error('Please enter an AWS Account ID');
      return;
    }

    setLoading(true);
    setActiveTab('audit');

    const request: IdentityCenterRequest = {
      aws_account_id: awsAccountId,
      role_arn: roleArn || undefined,
      region,
    };

    try {
      const data = await apiClient.auditIdentityCenter(request);
      setAuditResult(data);

      if (!data.enabled) {
        toast.error(data.message || 'Identity Center is not enabled');
      } else {
        toast.success(
          `Audit complete! Found ${data.findings.length} findings across ${data.resources_audited} resources.`
        );
      }
    } catch (error: any) {
      console.error('Failed to run Identity Center audit:', error);
      toast.error(error.response?.data?.detail || 'Failed to run Identity Center audit');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'text-red-600 bg-red-100';
      case 'HIGH':
        return 'text-red-500 bg-red-50';
      case 'MEDIUM':
        return 'text-yellow-600 bg-yellow-100';
      case 'LOW':
        return 'text-blue-500 bg-blue-50';
      case 'INFO':
        return 'text-gray-500 bg-gray-100';
      default:
        return 'text-gray-500 bg-gray-100';
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <Shield className="text-primary-500" />
          IAM Identity Center
        </h1>
        <p className="mt-2 text-gray-400">
          Manage and audit AWS IAM Identity Center (formerly AWS SSO)
        </p>
      </div>

      {/* Form */}
      <div className="card">
        <h2 className="text-xl font-bold mb-4">Configuration</h2>
        <form className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              AWS Account ID (Management Account) *
            </label>
            <input
              type="text"
              value={awsAccountId}
              onChange={(e) => setAwsAccountId(e.target.value)}
              placeholder="123456789012"
              className="input"
              required
            />
            <p className="mt-1 text-sm text-gray-500">
              Must be the management account of your AWS Organization
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Cross-Account Role ARN (Optional)
            </label>
            <input
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/ViewRole"
              className="input"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Region *
            </label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="input"
              required
            >
              <option value="us-east-1">us-east-1</option>
              <option value="us-east-2">us-east-2</option>
              <option value="us-west-1">us-west-1</option>
              <option value="us-west-2">us-west-2</option>
              <option value="eu-west-1">eu-west-1</option>
              <option value="eu-central-1">eu-central-1</option>
              <option value="ap-southeast-1">ap-southeast-1</option>
              <option value="ap-southeast-2">ap-southeast-2</option>
              <option value="ap-northeast-1">ap-northeast-1</option>
            </select>
            <p className="mt-1 text-sm text-gray-500">
              Region where Identity Center is configured
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button
              type="button"
              onClick={handleGetOverview}
              disabled={loading}
              className="btn-primary flex items-center justify-center gap-2"
            >
              {loading && activeTab === 'overview' ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  Loading...
                </>
              ) : (
                <>
                  <Building2 size={20} />
                  Get Overview
                </>
              )}
            </button>

            <button
              type="button"
              onClick={handleRunAudit}
              disabled={loading}
              className="btn-secondary flex items-center justify-center gap-2"
            >
              {loading && activeTab === 'audit' ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  Running Audit...
                </>
              ) : (
                <>
                  <AlertTriangle size={20} />
                  Run Security Audit
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Overview Results */}
      {overview && overview.enabled && activeTab === 'overview' && (
        <>
          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard
              icon={<Key className="h-6 w-6" />}
              title="Permission Sets"
              value={overview.stats?.total_permission_sets || 0}
              color="blue"
            />
            <StatCard
              icon={<Users className="h-6 w-6" />}
              title="Users"
              value={overview.stats?.total_users || 0}
              color="green"
            />
            <StatCard
              icon={<Users className="h-6 w-6" />}
              title="Groups"
              value={overview.stats?.total_groups || 0}
              color="purple"
            />
            <StatCard
              icon={<Shield className="h-6 w-6" />}
              title="Assignments"
              value={overview.stats?.total_assignments || 0}
              color="orange"
            />
            <StatCard
              icon={<Building2 className="h-6 w-6" />}
              title="Org Accounts"
              value={overview.stats?.total_org_accounts || 0}
              color="indigo"
            />
          </div>

          {/* Permission Sets */}
          {overview.permission_sets.length > 0 && (
            <div className="card">
              <h2 className="text-xl font-bold mb-4">Permission Sets</h2>
              <div className="space-y-4">
                {overview.permission_sets.map((ps) => (
                  <div key={ps.arn} className="p-4 bg-gray-700 rounded-lg">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h3 className="font-semibold text-white">{ps.name}</h3>
                        {ps.description && (
                          <p className="text-sm text-gray-400 mt-1">{ps.description}</p>
                        )}
                        <div className="mt-2 space-y-1 text-sm">
                          <p className="text-gray-500">
                            <span className="font-medium">Session Duration:</span> {ps.session_duration}
                          </p>
                          {ps.managed_policies.length > 0 && (
                            <p className="text-gray-500">
                              <span className="font-medium">Managed Policies:</span>{' '}
                              {ps.managed_policies.map((p) => p.Name).join(', ')}
                            </p>
                          )}
                          {ps.inline_policy && (
                            <p className="text-yellow-500">
                              <span className="font-medium">Has Inline Policy</span>
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Users and Groups */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Users */}
            {overview.users.length > 0 && (
              <div className="card">
                <h2 className="text-xl font-bold mb-4">Identity Store Users</h2>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {overview.users.map((user) => (
                    <div key={user.user_id} className="p-3 bg-gray-700 rounded">
                      <p className="font-medium text-white">{user.user_name}</p>
                      {user.display_name && (
                        <p className="text-sm text-gray-400">{user.display_name}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Groups */}
            {overview.groups.length > 0 && (
              <div className="card">
                <h2 className="text-xl font-bold mb-4">Identity Store Groups</h2>
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {overview.groups.map((group) => (
                    <div key={group.group_id} className="p-3 bg-gray-700 rounded">
                      <p className="font-medium text-white">{group.display_name}</p>
                      {group.description && (
                        <p className="text-sm text-gray-400">{group.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Audit Results */}
      {auditResult && auditResult.enabled && activeTab === 'audit' && (
        <>
          {/* Audit Summary */}
          <div className="card">
            <h2 className="text-xl font-bold mb-4">Audit Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
              <div className="text-center">
                <p className="text-sm text-gray-400">Total Findings</p>
                <p className="text-2xl font-bold mt-1">{auditResult.summary?.total_findings || 0}</p>
              </div>
              <div className="text-center">
                <p className="text-sm text-red-400">Critical</p>
                <p className="text-2xl font-bold text-red-500 mt-1">
                  {auditResult.summary?.critical || 0}
                </p>
              </div>
              <div className="text-center">
                <p className="text-sm text-orange-400">High</p>
                <p className="text-2xl font-bold text-orange-500 mt-1">
                  {auditResult.summary?.high || 0}
                </p>
              </div>
              <div className="text-center">
                <p className="text-sm text-yellow-400">Medium</p>
                <p className="text-2xl font-bold text-yellow-500 mt-1">
                  {auditResult.summary?.medium || 0}
                </p>
              </div>
              <div className="text-center">
                <p className="text-sm text-blue-400">Low</p>
                <p className="text-2xl font-bold text-blue-500 mt-1">
                  {auditResult.summary?.low || 0}
                </p>
              </div>
              <div className="text-center">
                <p className="text-sm text-gray-400">Info</p>
                <p className="text-2xl font-bold text-gray-500 mt-1">
                  {auditResult.summary?.info || 0}
                </p>
              </div>
            </div>
          </div>

          {/* Findings */}
          {auditResult.findings.length > 0 && (
            <div className="card">
              <h2 className="text-xl font-bold mb-4">Security Findings</h2>
              <div className="space-y-4">
                {auditResult.findings.map((finding: IdentityCenterFinding, index: number) => (
                  <div key={index} className="p-4 bg-gray-700 rounded-lg">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-semibold ${getSeverityColor(
                            finding.severity
                          )}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-sm text-gray-400">{finding.resource_type}</span>
                      </div>
                      <span className="text-xs text-gray-500">{finding.finding_type}</span>
                    </div>

                    <h3 className="font-semibold text-white mb-1">{finding.resource_id}</h3>
                    <p className="text-sm text-gray-300 mb-2">{finding.description}</p>

                    <div className="mt-3 p-3 bg-gray-800 rounded">
                      <p className="text-xs text-gray-400 font-medium mb-1">Recommendation:</p>
                      <p className="text-sm text-gray-300">{finding.recommendation}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {auditResult.findings.length === 0 && (
            <div className="card text-center py-8">
              <Shield className="h-16 w-16 text-green-500 mx-auto mb-4" />
              <h3 className="text-xl font-bold text-white mb-2">No Security Issues Found</h3>
              <p className="text-gray-400">
                Your Identity Center configuration follows security best practices!
              </p>
            </div>
          )}
        </>
      )}

      {/* Not Enabled Message */}
      {((overview && !overview.enabled && activeTab === 'overview') ||
        (auditResult && !auditResult.enabled && activeTab === 'audit')) && (
        <div className="card text-center py-8">
          <AlertTriangle className="h-16 w-16 text-yellow-500 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-white mb-2">Identity Center Not Enabled</h3>
          <p className="text-gray-400">
            {overview?.message || auditResult?.message || 'IAM Identity Center is not enabled in this region'}
          </p>
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  title,
  value,
  color,
}: {
  icon: React.ReactNode;
  title: string;
  value: number;
  color: 'blue' | 'green' | 'purple' | 'orange' | 'indigo';
}) {
  const colorClasses = {
    blue: 'text-blue-500',
    green: 'text-green-500',
    purple: 'text-purple-500',
    orange: 'text-orange-500',
    indigo: 'text-indigo-500',
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className="text-2xl font-bold mt-2">{value}</p>
        </div>
        <div className={colorClasses[color]}>{icon}</div>
      </div>
    </div>
  );
}
