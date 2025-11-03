/**
 * TypeScript types for IAM Copilot
 */

export interface Policy {
  id: number;
  name: string;
  description: string;
  natural_language_input: string;
  policy_json: PolicyDocument;
  aws_policy_arn?: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyDocument {
  Version: string;
  Statement: PolicyStatement[];
}

export interface PolicyStatement {
  Effect: 'Allow' | 'Deny';
  Action: string | string[];
  Resource?: string | string[];
  Condition?: Record<string, any>;
}

export interface PolicyGenerateRequest {
  description: string;
  resource_arns?: string[];
  principal_type?: string;
  aws_account_id?: string;
}

export interface PolicyGenerateResponse {
  policy_id: number;
  name: string;
  policy_json: PolicyDocument;
  description: string;
  natural_language_input: string;
  validation_status: string;
  simulation_results?: any;
  created_at: string;
}

export interface SimulationResult {
  evaluation_results: EvaluationResult[];
  matched_statements: string[];
  denied_actions: string[];
  allowed_actions: string[];
  summary: string;
}

export interface EvaluationResult {
  EvalActionName: string;
  EvalDecision: string;
  MatchedStatements?: any[];
}

export interface AuditRequest {
  aws_account_id: string;
  role_arn?: string;
  audit_scope?: string;
  include_cloudtrail?: boolean;
}

export interface AuditResponse {
  audit_id: number;
  status: string;
  aws_account_id: string;
  started_at?: string;
  message: string;
}

export interface AuditResult {
  audit_id: number;
  status: string;
  aws_account_id: string;
  findings: Finding[];
  recommendations: AuditStats;
  error_message?: string;
  created_at: string;
  completed_at?: string;
}

export interface Finding {
  resource_type: string;
  resource_name: string;
  resource_arn: string;
  severity: 'high' | 'medium' | 'low';
  finding: string;
  recommendation: string;
  permission_reduction_percent?: number;
}

export interface AuditStats {
  total_resources: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  total_excessive_permissions: number;
}

export interface AccessGraphNode {
  id: string;
  type: 'user' | 'role' | 'policy' | 'resource';
  name: string;
  arn?: string;
  metadata?: Record<string, any>;
}

export interface AccessGraphEdge {
  source: string;
  target: string;
  relationship: string;
  actions?: string[];
}

export interface AccessGraph {
  nodes: AccessGraphNode[];
  edges: AccessGraphEdge[];
  stats: {
    total_nodes: number;
    total_edges: number;
    roles: number;
    users: number;
    policies: number;
  };
}

// Identity Center Types
export interface IdentityCenterRequest {
  aws_account_id: string;
  role_arn?: string;
  region?: string;
}

export interface SSOInstance {
  instance_arn: string;
  identity_store_id: string;
  name: string;
  status: string;
}

export interface ManagedPolicy {
  Name: string;
  Arn: string;
}

export interface CustomerManagedPolicy {
  Name: string;
  Path: string;
}

export interface PermissionSet {
  name: string;
  arn: string;
  description: string;
  session_duration: string;
  relay_state: string;
  created_date?: string;
  inline_policy?: string;
  managed_policies: ManagedPolicy[];
  customer_managed_policies: CustomerManagedPolicy[];
}

export interface AccountAssignment {
  principal_type: string;
  principal_id: string;
  permission_set_arn: string;
  account_id: string;
}

export interface IdentityStoreUser {
  user_id: string;
  user_name: string;
  display_name: string;
  name?: any;
  emails: any[];
  identity_store_id: string;
}

export interface IdentityStoreGroup {
  group_id: string;
  display_name: string;
  description: string;
  identity_store_id: string;
}

export interface OrganizationAccount {
  id: string;
  name: string;
  email: string;
  status: string;
  joined_method: string;
  joined_timestamp?: string;
}

export interface IdentityCenterStats {
  total_permission_sets: number;
  total_users: number;
  total_groups: number;
  total_assignments: number;
  total_org_accounts: number;
}

export interface IdentityCenterOverview {
  enabled: boolean;
  message?: string;
  instance?: SSOInstance;
  permission_sets: PermissionSet[];
  users: IdentityStoreUser[];
  groups: IdentityStoreGroup[];
  assignments: AccountAssignment[];
  organization_accounts: OrganizationAccount[];
  stats?: IdentityCenterStats;
}

export interface IdentityCenterFinding {
  severity: string;
  resource_type: string;
  resource_id: string;
  finding_type: string;
  description: string;
  recommendation: string;
  details: Record<string, any>;
}

export interface IdentityCenterAuditSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface IdentityCenterAuditStats {
  permission_sets: {
    total: number;
    with_inline_policy: number;
    with_managed_policies: number;
    with_customer_managed_policies: number;
  };
  assignments: {
    total: number;
    user_assignments: number;
    group_assignments: number;
    unique_accounts: number;
  };
  identity_store: {
    total_users: number;
    total_groups: number;
  };
  organization: {
    total_accounts: number;
  };
}

export interface IdentityCenterAuditResult {
  enabled: boolean;
  message?: string;
  instance?: SSOInstance;
  findings: IdentityCenterFinding[];
  resources_audited: number;
  stats?: IdentityCenterAuditStats;
  summary?: IdentityCenterAuditSummary;
}

// Organizations Types
export interface OrganizationsRequest {
  role_arn?: string;
}

export interface Organization {
  id: string;
  arn: string;
  master_account_arn: string;
  master_account_id: string;
  master_account_email: string;
  feature_set: string;
  available_policy_types: any[];
}

export interface ServiceControlPolicy {
  id: string;
  arn: string;
  name: string;
  description: string;
  type: string;
  aws_managed: boolean;
  content?: any;
  targets?: PolicyTarget[];
}

export interface PolicyTarget {
  target_id: string;
  arn: string;
  name: string;
  type: string;
}

export interface OrganizationStats {
  total_accounts: number;
  total_ous: number;
  total_scps: number;
  feature_set: string;
}

export interface OrganizationsOverview {
  enabled: boolean;
  message?: string;
  organization?: Organization;
  accounts: OrganizationAccount[];
  organizational_tree?: any;
  service_control_policies: ServiceControlPolicy[];
  stats?: OrganizationStats;
}

export interface OrganizationsFinding {
  severity: string;
  resource_type: string;
  resource_id: string;
  finding_type: string;
  description: string;
  recommendation: string;
  details: Record<string, any>;
}

export interface OrganizationsAuditSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface OrganizationsAuditStats {
  organization: {
    feature_set: string;
    policy_types_enabled: number;
  };
  accounts: {
    total: number;
    active: number;
    suspended: number;
  };
  scps: {
    total: number;
    customer_managed: number;
    aws_managed: number;
    total_attachments: number;
  };
  structure: {
    total_ous: number;
  };
}

export interface OrganizationsAuditResult {
  enabled: boolean;
  message?: string;
  organization?: Organization;
  findings: OrganizationsFinding[];
  resources_audited: number;
  stats?: OrganizationsAuditStats;
  summary?: OrganizationsAuditSummary;
}

// Settings Types
export interface UserSettings {
  id: number;
  user_id: number;
  bedrock_model_id: string;
  bedrock_max_tokens: number;
  bedrock_temperature: number;
  default_aws_region: string;
  default_aws_output_format: string;
  created_at: string;
  updated_at: string;
}

export interface UserSettingsUpdate {
  bedrock_model_id?: string;
  bedrock_max_tokens?: number;
  bedrock_temperature?: number;
  default_aws_region?: string;
  default_aws_output_format?: string;
}

export interface BedrockModelOption {
  model_id: string;
  display_name: string;
  description: string;
  max_tokens: number;
}

export interface BedrockModelsResponse {
  models: BedrockModelOption[];
}

export interface AWSCredentialsCreate {
  label: string;
  access_key_id: string;
  secret_access_key: string;
  session_token?: string;
  aws_region?: string;
  aws_account_id?: string;
  is_default?: boolean;
  cross_account_role_arn?: string;
}

export interface AWSCredentialsUpdate {
  label?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  aws_region?: string;
  aws_account_id?: string;
  is_default?: boolean;
  cross_account_role_arn?: string;
}

export interface AWSCredentialsResponse {
  id: number;
  user_id: number;
  label: string;
  aws_region: string;
  aws_account_id?: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
  last_used?: string;
  cross_account_role_arn?: string;
}
