import { useState } from 'react';
import { toast } from 'react-hot-toast';
import { Building2, Users, FileText, AlertTriangle, CheckCircle } from 'lucide-react';
import { apiClient } from '../services/api';
import type {
  OrganizationsRequest,
  OrganizationsOverview,
  OrganizationsAuditResult,
  OrganizationsFinding,
} from '../types';

export default function OrganizationsView() {
  const [roleArn, setRoleArn] = useState('');
  const [loading, setLoading] = useState(false);
  const [overview, setOverview] = useState<OrganizationsOverview | null>(null);
  const [auditResult, setAuditResult] = useState<OrganizationsAuditResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'audit'>('overview');

  const handleGetOverview = async (e: React.FormEvent) => {
    e.preventDefault();

    setLoading(true);
    setActiveTab('overview');

    const request: OrganizationsRequest = {
      role_arn: roleArn || undefined,
    };

    try {
      const data = await apiClient.getOrganizationsOverview(request);
      setOverview(data);

      if (!data.enabled) {
        toast.error(data.message || 'Organizations is not enabled');
      } else {
        toast.success('Organizations overview loaded successfully!');
      }
    } catch (error: any) {
      console.error('Failed to load Organizations overview:', error);
      toast.error(error.response?.data?.detail || 'Failed to load Organizations overview');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAudit = async (e: React.FormEvent) => {
    e.preventDefault();

    setLoading(true);
    setActiveTab('audit');

    const request: OrganizationsRequest = {
      role_arn: roleArn || undefined,
    };

    try {
      const data = await apiClient.auditOrganizations(request);
      setAuditResult(data);

      if (!data.enabled) {
        toast.error(data.message || 'Organizations is not enabled');
      } else {
        toast.success(
          `Audit complete! Found ${data.findings.length} findings across ${data.resources_audited} resources.`
        );
      }
    } catch (error: any) {
      console.error('Failed to run Organizations audit:', error);
      toast.error(error.response?.data?.detail || 'Failed to run Organizations audit');
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
          <Building2 className="text-primary-500" />
          AWS Organizations
        </h1>
        <p className="mt-2 text-gray-400">
          Manage and audit AWS Organizations structure, accounts, and Service Control Policies
        </p>
      </div>

      {/* Form */}
      <div className="card">
        <h2 className="text-xl font-bold mb-4">Configuration</h2>
        <form className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Cross-Account Role ARN (Optional)
            </label>
            <input
              type="text"
              value={roleArn}
              onChange={(e) => setRoleArn(e.target.value)}
              placeholder="arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
              className="input"
            />
            <p className="mt-1 text-sm text-gray-500">
              Must be called from the management (master) account
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
          {/* Organization Info */}
          {overview.organization && (
            <div className="card">
              <h2 className="text-xl font-bold mb-4">Organization Details</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Organization ID</p>
                  <p className="text-white font-mono">{overview.organization.id}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Management Account</p>
                  <p className="text-white">{overview.organization.master_account_email}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Feature Set</p>
                  <p className="text-white">{overview.organization.feature_set}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Policy Types</p>
                  <p className="text-white">{overview.organization.available_policy_types.length}</p>
                </div>
              </div>
            </div>
          )}

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              icon={<Users className="h-6 w-6" />}
              title="Accounts"
              value={overview.stats?.total_accounts || 0}
              color="blue"
            />
            <StatCard
              icon={<Building2 className="h-6 w-6" />}
              title="OUs"
              value={overview.stats?.total_ous || 0}
              color="purple"
            />
            <StatCard
              icon={<FileText className="h-6 w-6" />}
              title="SCPs"
              value={overview.stats?.total_scps || 0}
              color="green"
            />
            <StatCard
              icon={<CheckCircle className="h-6 w-6" />}
              title="Feature Set"
              value={overview.stats?.feature_set === 'ALL' ? 'All' : 'Basic'}
              color="orange"
            />
          </div>

          {/* Accounts */}
          {overview.accounts.length > 0 && (
            <div className="card">
              <h2 className="text-xl font-bold mb-4">Organization Accounts</h2>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {overview.accounts.map((account) => (
                  <div key={account.id} className="p-4 bg-gray-700 rounded-lg flex items-center justify-between">
                    <div>
                      <p className="font-semibold text-white">{account.name}</p>
                      <p className="text-sm text-gray-400">{account.email}</p>
                      <p className="text-xs text-gray-500 font-mono mt-1">{account.id}</p>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        account.status === 'ACTIVE'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-yellow-100 text-yellow-700'
                      }`}
                    >
                      {account.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Service Control Policies */}
          {overview.service_control_policies.length > 0 && (
            <div className="card">
              <h2 className="text-xl font-bold mb-4">Service Control Policies</h2>
              <div className="space-y-4">
                {overview.service_control_policies.map((scp) => (
                  <div key={scp.id} className="p-4 bg-gray-700 rounded-lg">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <h3 className="font-semibold text-white">{scp.name}</h3>
                        {scp.description && (
                          <p className="text-sm text-gray-400 mt-1">{scp.description}</p>
                        )}
                      </div>
                      {scp.aws_managed && (
                        <span className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs font-semibold">
                          AWS Managed
                        </span>
                      )}
                    </div>
                    {scp.targets && scp.targets.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-gray-500 font-medium mb-1">
                          Attached to {scp.targets.length} target(s)
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {scp.targets.slice(0, 5).map((target, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-gray-600 text-gray-300 rounded text-xs"
                            >
                              {target.name}
                            </span>
                          ))}
                          {scp.targets.length > 5 && (
                            <span className="px-2 py-1 bg-gray-600 text-gray-300 rounded text-xs">
                              +{scp.targets.length - 5} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
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
                {auditResult.findings.map((finding: OrganizationsFinding, index: number) => (
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
              <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
              <h3 className="text-xl font-bold text-white mb-2">No Security Issues Found</h3>
              <p className="text-gray-400">
                Your Organizations configuration follows security best practices!
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
          <h3 className="text-xl font-bold text-white mb-2">Organizations Not Enabled</h3>
          <p className="text-gray-400">
            {overview?.message || auditResult?.message || 'This account is not part of an AWS Organization'}
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
  value: number | string;
  color: 'blue' | 'green' | 'purple' | 'orange';
}) {
  const colorClasses = {
    blue: 'text-blue-500',
    green: 'text-green-500',
    purple: 'text-purple-500',
    orange: 'text-orange-500',
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
