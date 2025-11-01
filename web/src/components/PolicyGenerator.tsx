import { useState } from 'react';
import { toast } from 'react-hot-toast';
import { Sparkles, Copy, Check } from 'lucide-react';
import { apiClient } from '../services/api';
import type { PolicyGenerateResponse } from '../types';

export default function PolicyGenerator() {
  const [description, setDescription] = useState('');
  const [resourceArns, setResourceArns] = useState('');
  const [awsAccountId, setAwsAccountId] = useState('');
  const [loading, setLoading] = useState(false);
  const [generatedPolicy, setGeneratedPolicy] = useState<PolicyGenerateResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!description.trim()) {
      toast.error('Please enter a policy description');
      return;
    }

    setLoading(true);
    setGeneratedPolicy(null);

    try {
      const resource_arns = resourceArns
        .split('\n')
        .map(arn => arn.trim())
        .filter(arn => arn.length > 0);

      const response = await apiClient.generatePolicy({
        description,
        resource_arns: resource_arns.length > 0 ? resource_arns : undefined,
        aws_account_id: awsAccountId || undefined,
      });

      setGeneratedPolicy(response);
      toast.success('Policy generated successfully!');
    } catch (error: any) {
      console.error('Policy generation failed:', error);
      toast.error(error.response?.data?.detail || 'Failed to generate policy');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async () => {
    if (generatedPolicy) {
      try {
        await navigator.clipboard.writeText(
          JSON.stringify(generatedPolicy.policy_json, null, 2)
        );
        setCopied(true);
        toast.success('Policy copied to clipboard!');
        setTimeout(() => setCopied(false), 2000);
      } catch (error) {
        toast.error('Failed to copy to clipboard');
      }
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-2">
          <Sparkles className="text-primary-500" />
          Generate IAM Policy
        </h1>
        <p className="mt-2 text-gray-400">
          Describe what you need in plain English, and AI will generate a secure IAM policy
        </p>
      </div>

      {/* Form */}
      <div className="card">
        <form onSubmit={handleGenerate} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Policy Description *
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Example: Allow Lambda function to read objects from S3 bucket named 'my-data-bucket' and write logs to CloudWatch"
              className="input min-h-[120px]"
              required
            />
            <p className="mt-2 text-sm text-gray-500">
              Describe the permissions you need in natural language
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Resource ARNs (Optional)
            </label>
            <textarea
              value={resourceArns}
              onChange={(e) => setResourceArns(e.target.value)}
              placeholder="arn:aws:s3:::my-bucket/*&#10;arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
              className="input min-h-[100px]"
            />
            <p className="mt-2 text-sm text-gray-500">
              One ARN per line (optional - AI will suggest ARNs if not provided)
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              AWS Account ID (Optional)
            </label>
            <input
              type="text"
              value={awsAccountId}
              onChange={(e) => setAwsAccountId(e.target.value)}
              placeholder="123456789012"
              className="input"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Generating Policy...
              </>
            ) : (
              <>
                <Sparkles size={20} />
                Generate Policy with AI
              </>
            )}
          </button>
        </form>
      </div>

      {/* Generated Policy */}
      {generatedPolicy && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold">Generated Policy</h2>
            <button
              onClick={copyToClipboard}
              className="btn-secondary flex items-center gap-2"
            >
              {copied ? <Check size={18} /> : <Copy size={18} />}
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
          </div>

          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-1">Policy Name</h3>
              <p className="text-white font-mono">{generatedPolicy.name}</p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-1">Description</h3>
              <p className="text-white">{generatedPolicy.description}</p>
            </div>

            <div>
              <h3 className="text-sm font-medium text-gray-400 mb-2">Policy JSON</h3>
              <pre className="bg-gray-900 p-4 rounded-lg overflow-x-auto border border-gray-700">
                <code className="text-sm text-green-400">
                  {JSON.stringify(generatedPolicy.policy_json, null, 2)}
                </code>
              </pre>
            </div>

            {generatedPolicy.simulation_results && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Validation Results</h3>
                <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
                  <p className="text-green-400">
                    ✓ Policy validated successfully
                  </p>
                  <p className="text-sm text-gray-400 mt-2">
                    {generatedPolicy.simulation_results.summary}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
