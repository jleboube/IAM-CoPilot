"""
Pydantic schemas for enhanced policy validation and condition keys
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional


class ValidatePolicyRequest(BaseModel):
    """Request to validate an IAM policy."""
    policy_document: Dict[str, Any] = Field(..., description="IAM policy document to validate")
    validation_level: str = Field(
        'comprehensive',
        description="Validation level: 'basic', 'standard', or 'comprehensive'"
    )


class ValidationResult(BaseModel):
    """Result of policy validation."""
    valid: bool = Field(..., description="Whether the policy is valid")
    errors: List[str] = Field(default_factory=list, description="Validation errors")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")
    info: List[str] = Field(default_factory=list, description="Informational messages")
    validation_level: str = Field(..., description="Level of validation performed")
    summary: Optional[str] = Field(None, description="Human-readable summary")


class ConditionKeySuggestion(BaseModel):
    """A condition key suggestion."""
    key: str = Field(..., description="Condition key name")
    type: str = Field(..., description="Data type (String, Numeric, Date, etc.)")
    description: str = Field(..., description="Description of the condition key")


class ConditionKeySuggestionsRequest(BaseModel):
    """Request for condition key suggestions."""
    service: Optional[str] = Field(None, description="AWS service prefix (e.g., 's3', 'ec2', 'iam')")
    prefix: Optional[str] = Field(None, description="Prefix for autocomplete")


class ConditionKeySuggestionsResponse(BaseModel):
    """Response with condition key suggestions."""
    suggestions: List[ConditionKeySuggestion]
    total: int
    service: Optional[str]


class ConditionOperatorsResponse(BaseModel):
    """Response with available condition operators."""
    operators: Dict[str, str] = Field(..., description="Map of operator to data type")


class ValidateConditionRequest(BaseModel):
    """Request to validate a specific condition."""
    operator: str = Field(..., description="Condition operator (e.g., 'StringEquals')")
    condition_key: str = Field(..., description="Condition key (e.g., 'aws:SourceIp')")
    condition_value: Any = Field(..., description="Condition value")
    service: Optional[str] = Field(None, description="AWS service for context")


class ValidateConditionResponse(BaseModel):
    """Response from condition validation."""
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    key_info: Optional[Dict[str, str]] = None


class PermissionsBoundarySetRequest(BaseModel):
    """Request to set permissions boundary on user or role."""
    resource_type: str = Field(..., description="Type of resource: 'user' or 'role'")
    resource_name: str = Field(..., description="Name of the user or role")
    boundary_policy_arn: str = Field(..., description="ARN of the permissions boundary policy")
    aws_account_id: Optional[str] = Field(None, description="AWS account ID")
    role_arn: Optional[str] = Field(None, description="Cross-account role ARN")


class PermissionsBoundaryDeleteRequest(BaseModel):
    """Request to delete permissions boundary from user or role."""
    resource_type: str = Field(..., description="Type of resource: 'user' or 'role'")
    resource_name: str = Field(..., description="Name of the user or role")
    aws_account_id: Optional[str] = Field(None, description="AWS account ID")
    role_arn: Optional[str] = Field(None, description="Cross-account role ARN")


class PermissionsBoundaryResponse(BaseModel):
    """Response from permissions boundary operation."""
    success: bool
    message: str
    resource_type: str
    resource_name: str
    boundary_policy_arn: Optional[str] = None
