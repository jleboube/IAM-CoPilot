"""
Pydantic schemas for AWS Organizations operations.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


# ========== Organization Schemas ==========

class PolicyType(BaseModel):
    """Available policy type."""
    Type: str = Field(..., description="Policy type")
    Status: str = Field(..., description="Status of the policy type")


class Organization(BaseModel):
    """Organization details."""
    id: str = Field(..., description="Organization ID")
    arn: str = Field(..., description="Organization ARN")
    master_account_arn: str = Field(..., description="Management account ARN")
    master_account_id: str = Field(..., description="Management account ID")
    master_account_email: str = Field(..., description="Management account email")
    feature_set: str = Field(..., description="Feature set (ALL or CONSOLIDATED_BILLING)")
    available_policy_types: List[PolicyType] = Field(default_factory=list, description="Available policy types")


# ========== Account Schemas ==========

class OrganizationAccount(BaseModel):
    """Account in the organization."""
    id: str = Field(..., description="Account ID")
    arn: str = Field(..., description="Account ARN")
    name: str = Field(..., description="Account name")
    email: str = Field(..., description="Account email")
    status: str = Field(..., description="Account status")
    joined_method: Optional[str] = Field(None, description="How the account joined")
    joined_timestamp: Optional[datetime] = Field(None, description="When the account joined")


# ========== Organizational Unit Schemas ==========

class OrganizationalUnit(BaseModel):
    """Organizational Unit details."""
    id: str = Field(..., description="OU ID")
    arn: str = Field(..., description="OU ARN")
    name: str = Field(..., description="OU name")


class OUStructure(BaseModel):
    """OU structure with nested children."""
    id: str = Field(..., description="Parent ID")
    organizational_units: List[Dict[str, Any]] = Field(default_factory=list, description="Child OUs")
    accounts: List[OrganizationAccount] = Field(default_factory=list, description="Accounts in this OU")


class Root(BaseModel):
    """Root details."""
    id: str = Field(..., description="Root ID")
    arn: str = Field(..., description="Root ARN")
    name: str = Field(..., description="Root name")
    policy_types: List[PolicyType] = Field(default_factory=list, description="Enabled policy types")
    structure: Optional[Dict[str, Any]] = Field(None, description="OU structure under this root")


class OrganizationalTree(BaseModel):
    """Complete organizational tree."""
    roots: List[Root] = Field(default_factory=list, description="Organization roots")


# ========== Policy Schemas ==========

class PolicyTarget(BaseModel):
    """Target where a policy is attached."""
    target_id: str = Field(..., description="Target ID")
    arn: str = Field(..., description="Target ARN")
    name: str = Field(..., description="Target name")
    type: str = Field(..., description="Target type (ACCOUNT, ORGANIZATIONAL_UNIT, ROOT)")


class ServiceControlPolicy(BaseModel):
    """Service Control Policy details."""
    id: str = Field(..., description="Policy ID")
    arn: str = Field(..., description="Policy ARN")
    name: str = Field(..., description="Policy name")
    description: str = Field(default="", description="Policy description")
    type: str = Field(..., description="Policy type")
    aws_managed: bool = Field(default=False, description="Whether this is an AWS managed policy")
    content: Optional[Dict[str, Any]] = Field(None, description="Policy document")
    targets: List[PolicyTarget] = Field(default_factory=list, description="Attached targets")


# ========== Statistics Schemas ==========

class OrganizationStats(BaseModel):
    """Organization statistics."""
    total_accounts: int = Field(..., description="Total number of accounts")
    total_ous: int = Field(..., description="Total number of OUs")
    total_scps: int = Field(..., description="Total number of SCPs")
    feature_set: str = Field(..., description="Feature set enabled")


class OrganizationsOverview(BaseModel):
    """Complete overview of AWS Organizations."""
    enabled: bool = Field(..., description="Whether Organizations is enabled")
    message: Optional[str] = Field(None, description="Message if not enabled")
    organization: Optional[Organization] = Field(None, description="Organization details")
    accounts: List[OrganizationAccount] = Field(default_factory=list, description="All accounts")
    organizational_tree: Optional[OrganizationalTree] = Field(None, description="Complete OU tree")
    service_control_policies: List[ServiceControlPolicy] = Field(default_factory=list, description="All SCPs")
    stats: Optional[OrganizationStats] = Field(None, description="Statistics")


# ========== Audit Schemas ==========

class OrganizationsFinding(BaseModel):
    """Security finding from Organizations audit."""
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    resource_type: str = Field(..., description="Type of resource")
    resource_id: str = Field(..., description="Resource identifier")
    finding_type: str = Field(..., description="Type of finding")
    description: str = Field(..., description="Description of the issue")
    recommendation: str = Field(..., description="Recommendation to fix the issue")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class OrganizationsAuditSummary(BaseModel):
    """Summary of audit findings by severity."""
    total_findings: int = Field(..., description="Total number of findings")
    critical: int = Field(..., description="Number of critical findings")
    high: int = Field(..., description="Number of high severity findings")
    medium: int = Field(..., description="Number of medium severity findings")
    low: int = Field(..., description="Number of low severity findings")
    info: int = Field(..., description="Number of informational findings")


class OrganizationConfigStats(BaseModel):
    """Organization configuration statistics."""
    feature_set: str = Field(..., description="Feature set")
    policy_types_enabled: int = Field(..., description="Number of policy types enabled")


class AccountStats(BaseModel):
    """Account statistics."""
    total: int = Field(..., description="Total accounts")
    active: int = Field(..., description="Active accounts")
    suspended: int = Field(..., description="Suspended accounts")


class SCPStats(BaseModel):
    """SCP statistics."""
    total: int = Field(..., description="Total SCPs")
    customer_managed: int = Field(..., description="Customer managed SCPs")
    aws_managed: int = Field(..., description="AWS managed SCPs")
    total_attachments: int = Field(..., description="Total policy attachments")


class StructureStats(BaseModel):
    """Structure statistics."""
    total_ous: int = Field(..., description="Total OUs")


class OrganizationsAuditStats(BaseModel):
    """Detailed statistics from audit."""
    organization: OrganizationConfigStats = Field(..., description="Organization config statistics")
    accounts: AccountStats = Field(..., description="Account statistics")
    scps: SCPStats = Field(..., description="SCP statistics")
    structure: StructureStats = Field(..., description="Structure statistics")


class OrganizationsAuditResult(BaseModel):
    """Result of an Organizations audit."""
    enabled: bool = Field(..., description="Whether Organizations is enabled")
    message: Optional[str] = Field(None, description="Message if not enabled")
    organization: Optional[Organization] = Field(None, description="Organization details")
    findings: List[OrganizationsFinding] = Field(default_factory=list, description="All findings")
    resources_audited: int = Field(..., description="Number of resources audited")
    stats: Optional[OrganizationsAuditStats] = Field(None, description="Detailed statistics")
    summary: Optional[OrganizationsAuditSummary] = Field(None, description="Summary of findings")


# ========== Request Schemas ==========

class OrganizationsRequest(BaseModel):
    """Request to access AWS Organizations."""
    role_arn: Optional[str] = Field(None, description="Optional cross-account role ARN")
