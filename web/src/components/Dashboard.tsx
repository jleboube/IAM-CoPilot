import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, Activity, TrendingDown, AlertTriangle, BookOpen } from 'lucide-react';
import { apiClient } from '../services/api';
import type { Policy } from '../types';

export default function Dashboard() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      const data = await apiClient.listPolicies(0, 10);
      setPolicies(data.policies);
    } catch (error) {
      console.error('Failed to load policies:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="mt-2 text-gray-400">
            Welcome to IAM Copilot - AI-Powered AWS IAM Management
          </p>
        </div>
        <a
          href={`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/docs`}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary flex items-center gap-2"
        >
          <BookOpen size={18} />
          API Docs
        </a>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={<FileText className="h-8 w-8" />}
          title="Policies Generated"
          value={policies.length}
          color="blue"
        />
        <StatCard
          icon={<Activity className="h-8 w-8" />}
          title="Active Audits"
          value="0"
          color="green"
        />
        <StatCard
          icon={<TrendingDown className="h-8 w-8" />}
          title="Avg. Permission Reduction"
          value="0%"
          color="purple"
        />
        <StatCard
          icon={<AlertTriangle className="h-8 w-8" />}
          title="High Risk Findings"
          value="0"
          color="red"
        />
      </div>

      {/* Quick Actions */}
      <div className="card">
        <h2 className="text-xl font-bold mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <Link to="/generate" className="btn-primary text-center">
            Generate Policy from Description
          </Link>
          <Link to="/audit" className="btn-secondary text-center">
            Run IAM Audit
          </Link>
          <Link to="/graph" className="btn-secondary text-center">
            View Access Graph
          </Link>
          <Link to="/identity-center" className="btn-secondary text-center">
            IAM Identity Center
          </Link>
          <Link to="/organizations" className="btn-secondary text-center">
            AWS Organizations
          </Link>
        </div>
      </div>

      {/* Recent Policies */}
      <div className="card">
        <h2 className="text-xl font-bold mb-4">Recent Policies</h2>
        {loading ? (
          <div className="text-center py-8 text-gray-400">Loading...</div>
        ) : policies.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No policies generated yet. <Link to="/generate" className="text-primary-500 hover:underline">Create your first policy</Link>
          </div>
        ) : (
          <div className="space-y-4">
            {policies.map((policy) => (
              <div key={policy.id} className="p-4 bg-gray-700 rounded-lg">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="font-semibold text-white">{policy.name}</h3>
                    <p className="text-sm text-gray-400 mt-1">{policy.description}</p>
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(policy.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ icon, title, value, color }: {
  icon: React.ReactNode;
  title: string;
  value: string | number;
  color: 'blue' | 'green' | 'purple' | 'red';
}) {
  const colorClasses = {
    blue: 'text-blue-500',
    green: 'text-green-500',
    purple: 'text-purple-500',
    red: 'text-red-500',
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
