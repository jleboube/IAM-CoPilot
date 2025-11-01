"""
Pydantic schemas for IAM policy operations
"""
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class PolicyGenerateRequest(BaseModel):
    """Request to generate IAM policy from natural language"""
    description: str = Field(..., description="Natural language description of desired permissions", min_length=10)
    resource_arns: list[str] | None = Field(None, description="Optional specific resource ARNs to include")
    principal_type: str = Field("role", description="Type of principal: role, user, or group")
    aws_account_id: str | None = Field(None, description="AWS account ID for policy context")


class PolicyGenerateResponse(BaseModel):
    """Generated IAM policy response"""
    policy_id: int
    name: str
    policy_json: dict[str, Any]
    description: str
    natural_language_input: str
    validation_status: str
    simulation_results: dict[str, Any] | None = None
    created_at: datetime


class PolicySimulateRequest(BaseModel):
    """Request to simulate IAM policy"""
    policy_document: dict[str, Any] = Field(..., description="IAM policy JSON document")
    action_names: list[str] = Field(..., description="List of AWS actions to simulate")
    resource_arns: list[str] | None = Field(None, description="Optional resource ARNs")
    principal_arn: str | None = Field(None, description="Principal ARN for simulation")


class PolicySimulateResponse(BaseModel):
    """Policy simulation results"""
    evaluation_results: list[dict[str, Any]]
    matched_statements: list[str]
    denied_actions: list[str]
    allowed_actions: list[str]
    summary: str


class AuditRequest(BaseModel):
    """Request to audit IAM configuration"""
    aws_account_id: str = Field(..., description="AWS account ID to audit")
    role_arn: str | None = Field(None, description="Optional cross-account role ARN")
    audit_scope: str = Field("roles", description="Scope: roles, users, policies, or all")
    include_cloudtrail: bool = Field(True, description="Include CloudTrail analysis for unused permissions")


class AuditResponse(BaseModel):
    """Audit job response"""
    audit_id: int
    status: str
    aws_account_id: str
    started_at: datetime | None = None
    message: str


class AuditResultResponse(BaseModel):
    """Individual audit finding"""
    id: int
    resource_type: str
    resource_arn: str
    resource_name: str
    unused_permissions: list[str] | None
    permission_reduction_percent: int | None
    recommended_policy: dict[str, Any] | None
    severity: str
    created_at: datetime


class AccessGraphNode(BaseModel):
    """Node in the access graph"""
    id: str
    type: str  # user, role, policy, resource
    name: str
    arn: str | None = None
    metadata: dict[str, Any] = {}


class AccessGraphEdge(BaseModel):
    """Edge in the access graph"""
    source: str
    target: str
    relationship: str  # assumes, attached, allows, denies
    actions: list[str] | None = None


class AccessGraphResponse(BaseModel):
    """Access graph visualization data"""
    nodes: list[AccessGraphNode]
    edges: list[AccessGraphEdge]
    stats: dict[str, Any]
