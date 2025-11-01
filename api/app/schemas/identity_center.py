"""
Pydantic schemas for IAM Identity Center operations.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


# ========== SSO Instance Schemas ==========

class SSOInstance(BaseModel):
    """SSO instance details."""
    instance_arn: str = Field(..., description="ARN of the SSO instance")
    identity_store_id: str = Field(..., description="ID of the Identity Store")
    name: str = Field(..., description="Name of the SSO instance")
    status: str = Field(..., description="Status of the instance")


# ========== Permission Set Schemas ==========

class ManagedPolicy(BaseModel):
    """AWS Managed Policy reference."""
    Name: str = Field(..., description="Name of the managed policy")
    Arn: str = Field(..., description="ARN of the managed policy")


class CustomerManagedPolicy(BaseModel):
    """Customer Managed Policy reference."""
    Name: str = Field(..., description="Name of the customer managed policy")
    Path: str = Field(..., description="Path of the policy")


class PermissionSet(BaseModel):
    """Permission Set details."""
    name: str = Field(..., description="Name of the permission set")
    arn: str = Field(..., description="ARN of the permission set")
    description: str = Field(default="", description="Description of the permission set")
    session_duration: str = Field(..., description="Session duration in ISO 8601 format")
    relay_state: str = Field(default="", description="Relay state URL")
    created_date: Optional[datetime] = Field(None, description="Creation timestamp")
    inline_policy: Optional[str] = Field(None, description="Inline policy JSON")
    managed_policies: List[ManagedPolicy] = Field(default_factory=list, description="Attached AWS managed policies")
    customer_managed_policies: List[CustomerManagedPolicy] = Field(default_factory=list, description="Attached customer managed policies")


# ========== Account Assignment Schemas ==========

class AccountAssignment(BaseModel):
    """Account assignment details."""
    principal_type: str = Field(..., description="Type of principal (USER or GROUP)")
    principal_id: str = Field(..., description="ID of the principal")
    permission_set_arn: str = Field(..., description="ARN of the permission set")
    account_id: str = Field(..., description="AWS account ID")


# ========== Identity Store Schemas ==========

class IdentityStoreEmail(BaseModel):
    """Email address in Identity Store."""
    Value: str = Field(..., description="Email address")
    Type: Optional[str] = Field(None, description="Email type")
    Primary: Optional[bool] = Field(None, description="Whether this is the primary email")


class IdentityStoreName(BaseModel):
    """Name in Identity Store."""
    FamilyName: Optional[str] = Field(None, description="Family name")
    GivenName: Optional[str] = Field(None, description="Given name")
    MiddleName: Optional[str] = Field(None, description="Middle name")
    Formatted: Optional[str] = Field(None, description="Formatted full name")


class IdentityStoreUser(BaseModel):
    """Identity Store user details."""
    user_id: str = Field(..., description="User ID")
    user_name: str = Field(..., description="Username")
    display_name: str = Field(default="", description="Display name")
    name: Optional[IdentityStoreName] = Field(None, description="User name details")
    emails: List[Dict[str, Any]] = Field(default_factory=list, description="Email addresses")
    identity_store_id: str = Field(..., description="Identity Store ID")


class IdentityStoreGroup(BaseModel):
    """Identity Store group details."""
    group_id: str = Field(..., description="Group ID")
    display_name: str = Field(..., description="Display name")
    description: str = Field(default="", description="Description")
    identity_store_id: str = Field(..., description="Identity Store ID")


class GroupMembership(BaseModel):
    """Group membership details."""
    membership_id: str = Field(..., description="Membership ID")
    member_id: str = Field(..., description="User ID of the member")
    identity_store_id: str = Field(..., description="Identity Store ID")


# ========== Organization Schemas ==========

class OrganizationAccount(BaseModel):
    """AWS Organization account details."""
    id: str = Field(..., description="Account ID")
    name: str = Field(..., description="Account name")
    email: str = Field(..., description="Account email")
    status: str = Field(..., description="Account status")
    joined_method: str = Field(..., description="How the account joined")
    joined_timestamp: Optional[datetime] = Field(None, description="When the account joined")


# ========== Overview Schemas ==========

class IdentityCenterStats(BaseModel):
    """Statistics for Identity Center resources."""
    total_permission_sets: int = Field(..., description="Total number of permission sets")
    total_users: int = Field(..., description="Total number of users")
    total_groups: int = Field(..., description="Total number of groups")
    total_assignments: int = Field(..., description="Total number of assignments")
    total_org_accounts: int = Field(..., description="Total number of organization accounts")


class IdentityCenterOverview(BaseModel):
    """Complete overview of Identity Center configuration."""
    enabled: bool = Field(..., description="Whether Identity Center is enabled")
    message: Optional[str] = Field(None, description="Message if not enabled")
    instance: Optional[SSOInstance] = Field(None, description="SSO instance details")
    permission_sets: List[PermissionSet] = Field(default_factory=list, description="All permission sets")
    users: List[IdentityStoreUser] = Field(default_factory=list, description="All users")
    groups: List[IdentityStoreGroup] = Field(default_factory=list, description="All groups")
    assignments: List[AccountAssignment] = Field(default_factory=list, description="All assignments")
    organization_accounts: List[OrganizationAccount] = Field(default_factory=list, description="All organization accounts")
    stats: Optional[IdentityCenterStats] = Field(None, description="Statistics")


# ========== Audit Schemas ==========

class IdentityCenterFinding(BaseModel):
    """Security finding from Identity Center audit."""
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    resource_type: str = Field(..., description="Type of resource")
    resource_id: str = Field(..., description="Resource identifier")
    finding_type: str = Field(..., description="Type of finding")
    description: str = Field(..., description="Description of the issue")
    recommendation: str = Field(..., description="Recommendation to fix the issue")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")


class IdentityCenterAuditSummary(BaseModel):
    """Summary of audit findings by severity."""
    total_findings: int = Field(..., description="Total number of findings")
    critical: int = Field(..., description="Number of critical findings")
    high: int = Field(..., description="Number of high severity findings")
    medium: int = Field(..., description="Number of medium severity findings")
    low: int = Field(..., description="Number of low severity findings")
    info: int = Field(..., description="Number of informational findings")


class PermissionSetStats(BaseModel):
    """Statistics for permission sets."""
    total: int = Field(..., description="Total permission sets")
    with_inline_policy: int = Field(..., description="Permission sets with inline policies")
    with_managed_policies: int = Field(..., description="Permission sets with managed policies")
    with_customer_managed_policies: int = Field(..., description="Permission sets with customer managed policies")


class AssignmentStats(BaseModel):
    """Statistics for assignments."""
    total: int = Field(..., description="Total assignments")
    user_assignments: int = Field(..., description="Assignments to users")
    group_assignments: int = Field(..., description="Assignments to groups")
    unique_accounts: int = Field(..., description="Unique accounts with assignments")


class IdentityStoreStats(BaseModel):
    """Statistics for Identity Store."""
    total_users: int = Field(..., description="Total users")
    total_groups: int = Field(..., description="Total groups")


class OrganizationStats(BaseModel):
    """Statistics for Organization."""
    total_accounts: int = Field(..., description="Total accounts in organization")


class IdentityCenterAuditStats(BaseModel):
    """Detailed statistics from audit."""
    permission_sets: PermissionSetStats = Field(..., description="Permission set statistics")
    assignments: AssignmentStats = Field(..., description="Assignment statistics")
    identity_store: IdentityStoreStats = Field(..., description="Identity Store statistics")
    organization: OrganizationStats = Field(..., description="Organization statistics")


class IdentityCenterAuditResult(BaseModel):
    """Result of an Identity Center audit."""
    enabled: bool = Field(..., description="Whether Identity Center is enabled")
    message: Optional[str] = Field(None, description="Message if not enabled")
    instance: Optional[SSOInstance] = Field(None, description="SSO instance details")
    findings: List[IdentityCenterFinding] = Field(default_factory=list, description="All findings")
    resources_audited: int = Field(..., description="Number of resources audited")
    stats: Optional[IdentityCenterAuditStats] = Field(None, description="Detailed statistics")
    summary: Optional[IdentityCenterAuditSummary] = Field(None, description="Summary of findings")


# ========== Request Schemas ==========

class IdentityCenterRequest(BaseModel):
    """Request to access Identity Center."""
    aws_account_id: str = Field(..., description="AWS account ID (must be the management account)")
    role_arn: Optional[str] = Field(None, description="Optional cross-account role ARN")
    region: str = Field(default="us-east-1", description="AWS region where Identity Center is configured")


class PermissionSetRequest(BaseModel):
    """Request for permission set details."""
    aws_account_id: str = Field(..., description="AWS account ID")
    role_arn: Optional[str] = Field(None, description="Optional cross-account role ARN")
    region: str = Field(default="us-east-1", description="AWS region")
    permission_set_arn: str = Field(..., description="ARN of the permission set")


class AccountAssignmentsRequest(BaseModel):
    """Request for account assignments."""
    aws_account_id: str = Field(..., description="AWS account ID")
    role_arn: Optional[str] = Field(None, description="Optional cross-account role ARN")
    region: str = Field(default="us-east-1", description="AWS region")
    account_id: str = Field(..., description="Account ID to get assignments for")
    permission_set_arn: str = Field(..., description="Permission set ARN")
