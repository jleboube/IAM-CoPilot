import { useEffect, useState } from 'react';
import { Settings, Save, RotateCcw, Key, Plus, Trash2, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { apiClient } from '../services/api';
import type {
  UserSettings,
  BedrockModelOption,
  AWSCredentialsResponse,
  AWSCredentialsCreate
} from '../types';

export default function SettingsView() {
  const [settings, setSettings] = useState<UserSettings | null>(null);
  const [availableModels, setAvailableModels] = useState<BedrockModelOption[]>([]);
  const [awsCredentials, setAWSCredentials] = useState<AWSCredentialsResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'bedrock' | 'aws-config' | 'credentials'>('bedrock');

  // New credentials form state
  const [showAddCredentials, setShowAddCredentials] = useState(false);
  const [newCredentials, setNewCredentials] = useState<AWSCredentialsCreate>({
    label: '',
    access_key_id: '',
    secret_access_key: '',
    session_token: '',
    aws_region: 'us-east-1',
    aws_account_id: '',
    is_default: false,
  });

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const [settingsData, modelsData, credentialsData] = await Promise.all([
        apiClient.getUserSettings(),
        apiClient.getAvailableModels(),
        apiClient.getAWSCredentials(),
      ]);
      setSettings(settingsData);
      setAvailableModels(modelsData.models);
      setAWSCredentials(credentialsData);
    } catch (error: any) {
      toast.error(`Failed to load settings: ${error.response?.data?.detail || error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async () => {
    if (!settings) return;

    try {
      setSaving(true);
      const updatedSettings = await apiClient.updateUserSettings({
        bedrock_model_id: settings.bedrock_model_id,
        bedrock_max_tokens: settings.bedrock_max_tokens,
        bedrock_temperature: settings.bedrock_temperature,
        default_aws_region: settings.default_aws_region,
        default_aws_output_format: settings.default_aws_output_format,
      });
      setSettings(updatedSettings);
      toast.success('Settings saved successfully');
    } catch (error: any) {
      toast.error(`Failed to save settings: ${error.response?.data?.detail || error.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleResetSettings = async () => {
    if (!confirm('Are you sure you want to reset all settings to defaults?')) return;

    try {
      setSaving(true);
      const resetSettings = await apiClient.resetUserSettings();
      setSettings(resetSettings);
      toast.success('Settings reset to defaults');
    } catch (error: any) {
      toast.error(`Failed to reset settings: ${error.response?.data?.detail || error.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleAddCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await apiClient.createAWSCredentials(newCredentials);
      setAWSCredentials([...awsCredentials, created]);
      setShowAddCredentials(false);
      setNewCredentials({
        label: '',
        access_key_id: '',
        secret_access_key: '',
        session_token: '',
        aws_region: 'us-east-1',
        aws_account_id: '',
        is_default: false,
      });
      toast.success('AWS credentials added successfully');
    } catch (error: any) {
      toast.error(`Failed to add credentials: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleDeleteCredentials = async (id: number) => {
    if (!confirm('Are you sure you want to delete these credentials?')) return;

    try {
      await apiClient.deleteAWSCredentials(id);
      setAWSCredentials(awsCredentials.filter(c => c.id !== id));
      toast.success('Credentials deleted successfully');
    } catch (error: any) {
      toast.error(`Failed to delete credentials: ${error.response?.data?.detail || error.message}`);
    }
  };

  const handleSetDefaultCredentials = async (id: number) => {
    try {
      await apiClient.setDefaultAWSCredentials(id);
      setAWSCredentials(awsCredentials.map(c => ({
        ...c,
        is_default: c.id === id
      })));
      toast.success('Default credentials updated');
    } catch (error: any) {
      toast.error(`Failed to update default: ${error.response?.data?.detail || error.message}`);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-500"></div>
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="card">
        <p className="text-red-500">Failed to load settings</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Settings className="h-8 w-8" />
            Settings
          </h1>
          <p className="mt-2 text-gray-400">
            Configure your Bedrock model, AWS settings, and credentials
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleResetSettings}
            disabled={saving}
            className="btn-secondary flex items-center gap-2"
          >
            <RotateCcw size={18} />
            Reset to Defaults
          </button>
          <button
            onClick={handleSaveSettings}
            disabled={saving}
            className="btn-primary flex items-center gap-2"
          >
            <Save size={18} />
            {saving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <div className="flex gap-6">
          <button
            onClick={() => setActiveTab('bedrock')}
            className={`pb-3 px-1 border-b-2 transition-colors ${
              activeTab === 'bedrock'
                ? 'border-primary-500 text-white'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            Bedrock Model
          </button>
          <button
            onClick={() => setActiveTab('aws-config')}
            className={`pb-3 px-1 border-b-2 transition-colors ${
              activeTab === 'aws-config'
                ? 'border-primary-500 text-white'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            AWS Configuration
          </button>
          <button
            onClick={() => setActiveTab('credentials')}
            className={`pb-3 px-1 border-b-2 transition-colors ${
              activeTab === 'credentials'
                ? 'border-primary-500 text-white'
                : 'border-transparent text-gray-400 hover:text-gray-300'
            }`}
          >
            AWS Credentials
          </button>
        </div>
      </div>

      {/* Tab Content */}
      <div className="card">
        {activeTab === 'bedrock' && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold">Bedrock Model Settings</h2>

            {/* Model Selection */}
            <div>
              <label className="block text-sm font-medium mb-2">Bedrock Model</label>
              <select
                value={settings.bedrock_model_id}
                onChange={(e) => setSettings({ ...settings, bedrock_model_id: e.target.value })}
                className="input w-full"
              >
                {availableModels.map((model) => (
                  <option key={model.model_id} value={model.model_id}>
                    {model.display_name} - {model.description}
                  </option>
                ))}
              </select>
              <p className="text-sm text-gray-400 mt-1">
                Choose the AI model for policy generation and analysis
              </p>
            </div>

            {/* Max Tokens */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Max Tokens: {settings.bedrock_max_tokens}
              </label>
              <input
                type="range"
                min="1000"
                max="8192"
                step="512"
                value={settings.bedrock_max_tokens}
                onChange={(e) => setSettings({ ...settings, bedrock_max_tokens: parseInt(e.target.value) })}
                className="w-full"
              />
              <p className="text-sm text-gray-400 mt-1">
                Maximum tokens for model responses (1000-8192)
              </p>
            </div>

            {/* Temperature */}
            <div>
              <label className="block text-sm font-medium mb-2">
                Temperature: {settings.bedrock_temperature.toFixed(1)}
              </label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={settings.bedrock_temperature}
                onChange={(e) => setSettings({ ...settings, bedrock_temperature: parseFloat(e.target.value) })}
                className="w-full"
              />
              <p className="text-sm text-gray-400 mt-1">
                Model creativity (0.0 = focused, 1.0 = creative). Recommended: 0.0 for policy generation
              </p>
            </div>
          </div>
        )}

        {activeTab === 'aws-config' && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold">AWS Configuration</h2>

            {/* Default Region */}
            <div>
              <label className="block text-sm font-medium mb-2">Default AWS Region</label>
              <select
                value={settings.default_aws_region}
                onChange={(e) => setSettings({ ...settings, default_aws_region: e.target.value })}
                className="input w-full"
              >
                <option value="us-east-1">US East (N. Virginia)</option>
                <option value="us-east-2">US East (Ohio)</option>
                <option value="us-west-1">US West (N. California)</option>
                <option value="us-west-2">US West (Oregon)</option>
                <option value="eu-west-1">Europe (Ireland)</option>
                <option value="eu-west-2">Europe (London)</option>
                <option value="eu-central-1">Europe (Frankfurt)</option>
                <option value="ap-southeast-1">Asia Pacific (Singapore)</option>
                <option value="ap-southeast-2">Asia Pacific (Sydney)</option>
                <option value="ap-northeast-1">Asia Pacific (Tokyo)</option>
              </select>
              <p className="text-sm text-gray-400 mt-1">
                Default region for AWS operations
              </p>
            </div>

            {/* Output Format */}
            <div>
              <label className="block text-sm font-medium mb-2">Default Output Format</label>
              <select
                value={settings.default_aws_output_format}
                onChange={(e) => setSettings({ ...settings, default_aws_output_format: e.target.value })}
                className="input w-full"
              >
                <option value="json">JSON</option>
                <option value="yaml">YAML</option>
                <option value="text">Text</option>
                <option value="table">Table</option>
              </select>
              <p className="text-sm text-gray-400 mt-1">
                Preferred format for AWS CLI-style outputs
              </p>
            </div>
          </div>
        )}

        {activeTab === 'credentials' && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-bold">AWS Credentials</h2>
              <button
                onClick={() => setShowAddCredentials(!showAddCredentials)}
                className="btn-primary flex items-center gap-2"
              >
                <Plus size={18} />
                Add Credentials
              </button>
            </div>

            {/* Add Credentials Form */}
            {showAddCredentials && (
              <form onSubmit={handleAddCredentials} className="space-y-4 p-4 bg-dark-700 rounded-lg border border-gray-700">
                <h3 className="font-semibold">Add New AWS Credentials</h3>

                <div>
                  <label className="block text-sm font-medium mb-2">Label *</label>
                  <input
                    type="text"
                    value={newCredentials.label}
                    onChange={(e) => setNewCredentials({ ...newCredentials, label: e.target.value })}
                    className="input w-full"
                    placeholder="e.g., Production, Development"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Access Key ID *</label>
                  <input
                    type="text"
                    value={newCredentials.access_key_id}
                    onChange={(e) => setNewCredentials({ ...newCredentials, access_key_id: e.target.value })}
                    className="input w-full font-mono"
                    placeholder="AKIA..."
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Secret Access Key *</label>
                  <input
                    type="password"
                    value={newCredentials.secret_access_key}
                    onChange={(e) => setNewCredentials({ ...newCredentials, secret_access_key: e.target.value })}
                    className="input w-full font-mono"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">Session Token (optional)</label>
                  <input
                    type="password"
                    value={newCredentials.session_token}
                    onChange={(e) => setNewCredentials({ ...newCredentials, session_token: e.target.value })}
                    className="input w-full font-mono"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-2">Region</label>
                    <select
                      value={newCredentials.aws_region}
                      onChange={(e) => setNewCredentials({ ...newCredentials, aws_region: e.target.value })}
                      className="input w-full"
                    >
                      <option value="us-east-1">us-east-1</option>
                      <option value="us-west-2">us-west-2</option>
                      <option value="eu-west-1">eu-west-1</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2">Account ID (optional)</label>
                    <input
                      type="text"
                      value={newCredentials.aws_account_id}
                      onChange={(e) => setNewCredentials({ ...newCredentials, aws_account_id: e.target.value })}
                      className="input w-full font-mono"
                      placeholder="123456789012"
                      maxLength={12}
                    />
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="is_default"
                    checked={newCredentials.is_default}
                    onChange={(e) => setNewCredentials({ ...newCredentials, is_default: e.target.checked })}
                    className="rounded"
                  />
                  <label htmlFor="is_default" className="text-sm">Set as default</label>
                </div>

                <div className="flex gap-3">
                  <button type="submit" className="btn-primary">Add Credentials</button>
                  <button
                    type="button"
                    onClick={() => setShowAddCredentials(false)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}

            {/* Credentials List */}
            <div className="space-y-3">
              {awsCredentials.length === 0 ? (
                <p className="text-gray-400 text-center py-8">
                  No AWS credentials configured. Add credentials to use IAM Copilot features.
                </p>
              ) : (
                awsCredentials.map((cred) => (
                  <div
                    key={cred.id}
                    className="p-4 bg-dark-700 rounded-lg border border-gray-700 flex items-center justify-between"
                  >
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Key size={18} className="text-gray-400" />
                        <h3 className="font-semibold">{cred.label}</h3>
                        {cred.is_default && (
                          <span className="px-2 py-0.5 bg-primary-500/20 text-primary-400 text-xs rounded">
                            Default
                          </span>
                        )}
                      </div>
                      <div className="mt-2 text-sm text-gray-400 space-y-1">
                        <p>Region: {cred.aws_region}</p>
                        {cred.aws_account_id && <p>Account: {cred.aws_account_id}</p>}
                        {cred.last_used && <p>Last used: {new Date(cred.last_used).toLocaleDateString()}</p>}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {!cred.is_default && (
                        <button
                          onClick={() => handleSetDefaultCredentials(cred.id)}
                          className="btn-secondary text-sm flex items-center gap-1"
                        >
                          <Check size={14} />
                          Set Default
                        </button>
                      )}
                      <button
                        onClick={() => handleDeleteCredentials(cred.id)}
                        className="btn-secondary text-red-400 hover:bg-red-500/20"
                      >
                        <Trash2 size={18} />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>

      {/* Info Box */}
      <div className="card bg-blue-500/10 border-blue-500/20">
        <p className="text-sm text-blue-400">
          <strong>Note:</strong> All settings changes take effect immediately without requiring a restart.
          Your AWS credentials are encrypted and stored securely.
        </p>
      </div>
    </div>
  );
}
