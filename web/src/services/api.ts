/**
 * API client for IAM Copilot backend
 */
import axios, { AxiosInstance } from 'axios';
import type {
  PolicyGenerateRequest,
  PolicyGenerateResponse,
  Policy,
  SimulationResult,
  AuditRequest,
  AuditResponse,
  AuditResult,
  AccessGraph,
  IdentityCenterRequest,
  IdentityCenterOverview,
  IdentityCenterAuditResult,
  OrganizationsRequest,
  OrganizationsOverview,
  OrganizationsAuditResult,
} from '../types';

class APIClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
      headers: {
        'Content-Type': 'application/json',
      },
      withCredentials: true, // Include cookies in all requests
    });
  }

  // Authentication endpoints
  async verifyGoogleToken(idToken: string): Promise<any> {
    const response = await this.client.post('/api/v1/auth/google/verify', { id_token: idToken });
    return response.data;
  }

  async getCurrentUser(): Promise<any> {
    const response = await this.client.get('/api/v1/auth/me');
    return response.data;
  }

  async logout(): Promise<void> {
    await this.client.post('/api/v1/auth/logout');
  }

  // Policy endpoints
  async generatePolicy(request: PolicyGenerateRequest): Promise<PolicyGenerateResponse> {
    const response = await this.client.post('/api/v1/policies/generate', request);
    return response.data;
  }

  async simulatePolicy(
    policy_document: any,
    action_names: string[],
    resource_arns?: string[]
  ): Promise<SimulationResult> {
    const response = await this.client.post('/api/v1/policies/simulate', {
      policy_document,
      action_names,
      resource_arns,
    });
    return response.data;
  }

  async getPolicy(policyId: number): Promise<Policy> {
    const response = await this.client.get(`/api/v1/policies/${policyId}`);
    return response.data;
  }

  async listPolicies(skip = 0, limit = 100): Promise<{ policies: Policy[]; total: number }> {
    const response = await this.client.get('/api/v1/policies/', {
      params: { skip, limit },
    });
    return response.data;
  }

  // Audit endpoints
  async startAudit(request: AuditRequest): Promise<AuditResponse> {
    const response = await this.client.post('/api/v1/policies/audit', request);
    return response.data;
  }

  async getAuditResults(auditId: number): Promise<AuditResult> {
    const response = await this.client.get(`/api/v1/policies/audit/${auditId}`);
    return response.data;
  }

  // Access graph endpoint
  async getAccessGraph(accountId: string, roleArn?: string): Promise<AccessGraph> {
    const response = await this.client.get(`/api/v1/policies/access-graph/${accountId}`, {
      params: { role_arn: roleArn },
    });
    return response.data;
  }

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    const response = await this.client.get('/health');
    return response.data;
  }

  // Identity Center endpoints
  async getIdentityCenterOverview(request: IdentityCenterRequest): Promise<IdentityCenterOverview> {
    const response = await this.client.post('/api/v1/identity-center/overview', request);
    return response.data;
  }

  async auditIdentityCenter(request: IdentityCenterRequest): Promise<IdentityCenterAuditResult> {
    const response = await this.client.post('/api/v1/identity-center/audit', request);
    return response.data;
  }

  // Organizations endpoints
  async getOrganizationsOverview(request: OrganizationsRequest): Promise<OrganizationsOverview> {
    const response = await this.client.post('/api/v1/organizations/overview', request);
    return response.data;
  }

  async auditOrganizations(request: OrganizationsRequest): Promise<OrganizationsAuditResult> {
    const response = await this.client.post('/api/v1/organizations/audit', request);
    return response.data;
  }
}

export const apiClient = new APIClient();

// Export authentication methods for easy access
export const verifyGoogleToken = (idToken: string) => apiClient.verifyGoogleToken(idToken);
export const getCurrentUser = () => apiClient.getCurrentUser();
export const logout = () => apiClient.logout();
