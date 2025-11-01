"""
Authentication and User Management Schemas - Google OAuth
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class GoogleTokenRequest(BaseModel):
    """Request body for Google token verification."""
    id_token: str = Field(..., description="Google ID token")


class GoogleAuthResponse(BaseModel):
    """Google OAuth authentication response."""
    id: int
    email: str
    full_name: Optional[str]
    avatar_url: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    """User information response."""
    id: int
    email: str
    full_name: Optional[str]
    avatar_url: Optional[str]
    is_active: bool
    is_verified: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    """Update user profile."""
    full_name: Optional[str] = Field(None, max_length=255)


class AWSCredentialsCreate(BaseModel):
    """Add AWS credentials for user."""
    label: str = Field(..., max_length=100, description="Label for this credential set (e.g., 'Production')")
    access_key_id: str = Field(..., min_length=16, max_length=128, description="AWS Access Key ID")
    secret_access_key: str = Field(..., min_length=16, description="AWS Secret Access Key")
    session_token: Optional[str] = Field(None, description="AWS Session Token (for temporary credentials)")
    aws_region: str = Field(default="us-east-1", description="AWS Region")
    aws_account_id: Optional[str] = Field(None, pattern=r'^\d{12}$', description="AWS Account ID (12 digits)")
    is_default: bool = Field(default=False, description="Set as default credential set")
    cross_account_role_arn: Optional[str] = Field(None, description="Cross-account role ARN (alternative to keys)")


class AWSCredentialsUpdate(BaseModel):
    """Update AWS credentials."""
    label: Optional[str] = Field(None, max_length=100)
    access_key_id: Optional[str] = Field(None, min_length=16, max_length=128)
    secret_access_key: Optional[str] = Field(None, min_length=16)
    session_token: Optional[str] = None
    aws_region: Optional[str] = None
    aws_account_id: Optional[str] = Field(None, pattern=r'^\d{12}$')
    is_default: Optional[bool] = None
    cross_account_role_arn: Optional[str] = None


class AWSCredentialsResponse(BaseModel):
    """AWS credentials response (without sensitive data)."""
    id: int
    user_id: int
    label: str
    aws_region: str
    aws_account_id: Optional[str]
    is_default: bool
    created_at: datetime
    updated_at: datetime
    last_used: Optional[datetime]
    cross_account_role_arn: Optional[str]

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    """Audit log entry response."""
    id: int
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    aws_account_id: Optional[str]
    aws_region: Optional[str]
    ip_address: Optional[str]
    success: bool
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
