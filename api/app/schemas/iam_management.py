"""
Pydantic schemas for IAM management operations
"""
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


# User Management Schemas
class UserCreateRequest(BaseModel):
    """Request to create a new IAM user"""
    user_name: str = Field(..., description="Name of the IAM user", min_length=1, max_length=64)
    path: str = Field("/", description="Path for the user")
    permissions_boundary: str | None = Field(None, description="ARN of permissions boundary policy")
    tags: dict[str, str] | None = Field(None, description="Tags to attach to the user")


class UserCreateResponse(BaseModel):
    """Response after creating a user"""
    user_name: str
    user_arn: str
    user_id: str
    created_at: datetime
    message: str


class UserUpdateRequest(BaseModel):
    """Request to update an IAM user"""
    user_name: str = Field(..., description="Current username")
    new_user_name: str | None = Field(None, description="New username (optional)")
    new_path: str | None = Field(None, description="New path (optional)")


class UserDeleteRequest(BaseModel):
    """Request to delete an IAM user"""
    user_name: str = Field(..., description="Name of the user to delete")
    force: bool = Field(False, description="Force delete (remove all attached items first)")


class UserPasswordRequest(BaseModel):
    """Request to set/reset user password"""
    user_name: str = Field(..., description="Name of the user")
    password: str | None = Field(None, description="New password (auto-generated if not provided)")
    require_reset: bool = Field(True, description="Require password reset on next login")


class UserPasswordResponse(BaseModel):
    """Response after password operation"""
    user_name: str
    password: str | None = Field(None, description="Generated password (if auto-generated)")
    message: str


# Access Key Management Schemas
class AccessKeyCreateRequest(BaseModel):
    """Request to create access key for user"""
    user_name: str = Field(..., description="Name of the user")


class AccessKeyCreateResponse(BaseModel):
    """Response after creating access key"""
    access_key_id: str
    secret_access_key: str
    user_name: str
    created_at: datetime
    status: str
    message: str = "Access key created successfully. Save the secret key - it cannot be retrieved later."


class AccessKeyRotateRequest(BaseModel):
    """Request to rotate access keys"""
    user_name: str = Field(..., description="Name of the user")
    access_key_id: str = Field(..., description="Access key to rotate")
    delete_old: bool = Field(False, description="Delete old key after creating new one")


class AccessKeyDeleteRequest(BaseModel):
    """Request to delete access key"""
    user_name: str = Field(..., description="Name of the user")
    access_key_id: str = Field(..., description="Access key to delete")


class AccessKeyListResponse(BaseModel):
    """Response listing access keys"""
    user_name: str
    access_keys: list[dict[str, Any]]


# Group Management Schemas
class GroupCreateRequest(BaseModel):
    """Request to create a new IAM group"""
    group_name: str = Field(..., description="Name of the IAM group", min_length=1, max_length=128)
    path: str = Field("/", description="Path for the group")


class GroupCreateResponse(BaseModel):
    """Response after creating a group"""
    group_name: str
    group_arn: str
    group_id: str
    created_at: datetime
    message: str


class GroupDeleteRequest(BaseModel):
    """Request to delete an IAM group"""
    group_name: str = Field(..., description="Name of the group to delete")
    force: bool = Field(False, description="Force delete (remove all users and policies first)")


class GroupMembershipRequest(BaseModel):
    """Request to manage group membership"""
    group_name: str = Field(..., description="Name of the group")
    user_name: str = Field(..., description="Name of the user")


# Role Management Schemas
class RoleCreateRequest(BaseModel):
    """Request to create a new IAM role"""
    role_name: str = Field(..., description="Name of the IAM role", min_length=1, max_length=64)
    assume_role_policy: dict[str, Any] = Field(..., description="Trust policy document")
    description: str | None = Field(None, description="Description of the role")
    max_session_duration: int = Field(3600, description="Maximum session duration in seconds", ge=3600, le=43200)
    path: str = Field("/", description="Path for the role")
    permissions_boundary: str | None = Field(None, description="ARN of permissions boundary policy")
    tags: dict[str, str] | None = Field(None, description="Tags to attach to the role")


class RoleCreateResponse(BaseModel):
    """Response after creating a role"""
    role_name: str
    role_arn: str
    role_id: str
    created_at: datetime
    message: str


class RoleUpdateRequest(BaseModel):
    """Request to update an IAM role"""
    role_name: str = Field(..., description="Name of the role")
    description: str | None = Field(None, description="New description")
    max_session_duration: int | None = Field(None, description="New max session duration")


class RoleDeleteRequest(BaseModel):
    """Request to delete an IAM role"""
    role_name: str = Field(..., description="Name of the role to delete")
    force: bool = Field(False, description="Force delete (remove all attached policies first)")


class RoleTrustPolicyRequest(BaseModel):
    """Request to update role trust policy"""
    role_name: str = Field(..., description="Name of the role")
    assume_role_policy: dict[str, Any] = Field(..., description="New trust policy document")


# Policy Management Schemas
class PolicyCreateRequest(BaseModel):
    """Request to create a managed policy"""
    policy_name: str = Field(..., description="Name of the policy", min_length=1, max_length=128)
    policy_document: dict[str, Any] = Field(..., description="Policy document")
    description: str | None = Field(None, description="Description of the policy")
    path: str = Field("/", description="Path for the policy")
    tags: dict[str, str] | None = Field(None, description="Tags to attach to the policy")


class PolicyCreateResponse(BaseModel):
    """Response after creating a policy"""
    policy_name: str
    policy_arn: str
    policy_id: str
    created_at: datetime
    message: str


class PolicyDeleteRequest(BaseModel):
    """Request to delete a managed policy"""
    policy_arn: str = Field(..., description="ARN of the policy to delete")
    force: bool = Field(False, description="Force delete (detach from all principals first)")


class PolicyAttachRequest(BaseModel):
    """Request to attach policy to a principal"""
    policy_arn: str = Field(..., description="ARN of the policy")
    principal_type: str = Field(..., description="Type: user, group, or role")
    principal_name: str = Field(..., description="Name of the principal")


class PolicyDetachRequest(BaseModel):
    """Request to detach policy from a principal"""
    policy_arn: str = Field(..., description="ARN of the policy")
    principal_type: str = Field(..., description="Type: user, group, or role")
    principal_name: str = Field(..., description="Name of the principal")


class PolicyAttachedEntitiesResponse(BaseModel):
    """Response listing attached entities for a policy"""
    policy_arn: str
    users: list[dict[str, str]]
    groups: list[dict[str, str]]
    roles: list[dict[str, str]]


# MFA Management Schemas
class MFADeviceEnableRequest(BaseModel):
    """Request to enable MFA device for user"""
    user_name: str = Field(..., description="Name of the user")
    serial_number: str = Field(..., description="Serial number of the MFA device")
    authentication_code1: str = Field(..., description="First authentication code from device")
    authentication_code2: str = Field(..., description="Second authentication code from device")


class MFADeviceDisableRequest(BaseModel):
    """Request to disable MFA device"""
    user_name: str = Field(..., description="Name of the user")
    serial_number: str = Field(..., description="Serial number of the MFA device")


class MFADeviceListResponse(BaseModel):
    """Response listing MFA devices"""
    user_name: str
    mfa_devices: list[dict[str, Any]]


# Permission Boundary Schemas
class PermissionBoundarySetRequest(BaseModel):
    """Request to set permissions boundary"""
    principal_type: str = Field(..., description="Type: user or role")
    principal_name: str = Field(..., description="Name of the principal")
    permissions_boundary: str = Field(..., description="ARN of the permissions boundary policy")


class PermissionBoundaryDeleteRequest(BaseModel):
    """Request to delete permissions boundary"""
    principal_type: str = Field(..., description="Type: user or role")
    principal_name: str = Field(..., description="Name of the principal")


# Tag Management Schemas
class TagResourceRequest(BaseModel):
    """Request to tag IAM resource"""
    resource_arn: str = Field(..., description="ARN of the resource")
    tags: dict[str, str] = Field(..., description="Tags to add")


class UntagResourceRequest(BaseModel):
    """Request to remove tags from IAM resource"""
    resource_arn: str = Field(..., description="ARN of the resource")
    tag_keys: list[str] = Field(..., description="Tag keys to remove")


# Generic Response Schemas
class GenericSuccessResponse(BaseModel):
    """Generic success response"""
    success: bool
    message: str
    details: dict[str, Any] | None = None


class IAMResourceListResponse(BaseModel):
    """Generic response for listing IAM resources"""
    resource_type: str
    resources: list[dict[str, Any]]
    total: int
    is_truncated: bool = False


# Account Settings Schemas
class PasswordPolicyUpdateRequest(BaseModel):
    """Request to update account password policy"""
    minimum_password_length: int = Field(14, description="Minimum password length", ge=6, le=128)
    require_symbols: bool = Field(True, description="Require at least one symbol")
    require_numbers: bool = Field(True, description="Require at least one number")
    require_uppercase_characters: bool = Field(True, description="Require at least one uppercase letter")
    require_lowercase_characters: bool = Field(True, description="Require at least one lowercase letter")
    allow_users_to_change_password: bool = Field(True, description="Allow users to change their own password")
    expire_passwords: bool = Field(True, description="Enable password expiration")
    max_password_age: int = Field(90, description="Password expiration in days", ge=1, le=1095)
    password_reuse_prevention: int = Field(24, description="Number of previous passwords to prevent reuse", ge=1, le=24)
    hard_expiry: bool = Field(False, description="Prevent password reuse after expiration")


class PasswordPolicyGetResponse(BaseModel):
    """Response with current password policy"""
    policy: dict[str, Any]
    message: str


# AWS Console/CLI Only Features Documentation
class RestrictedFeature(BaseModel):
    """Documentation for features restricted to Console/CLI"""
    feature_name: str
    restriction_type: str  # "console_only", "cli_only", or "not_available_via_api"
    description: str
    alternative: str | None = None
