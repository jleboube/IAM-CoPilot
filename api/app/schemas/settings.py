"""
User Settings Schemas for AWS and Bedrock configuration
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class UserSettingsResponse(BaseModel):
    """User settings response."""
    id: int
    user_id: int

    # Bedrock Configuration
    bedrock_model_id: str = Field(..., description="Bedrock model ID or inference profile ARN")
    bedrock_max_tokens: int = Field(..., ge=1, le=100000, description="Maximum tokens for Bedrock responses")
    bedrock_temperature: float = Field(..., ge=0.0, le=1.0, description="Temperature for Bedrock model")

    # AWS Configuration
    default_aws_region: str = Field(..., description="Default AWS region")
    default_aws_output_format: str = Field(..., description="Default AWS CLI output format")

    # Metadata
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserSettingsUpdate(BaseModel):
    """Update user settings."""
    bedrock_model_id: Optional[str] = Field(None, max_length=255, description="Bedrock model ID or inference profile ARN")
    bedrock_max_tokens: Optional[int] = Field(None, ge=1, le=100000, description="Maximum tokens for Bedrock responses")
    bedrock_temperature: Optional[float] = Field(None, ge=0.0, le=1.0, description="Temperature for Bedrock model")
    default_aws_region: Optional[str] = Field(None, max_length=50, description="Default AWS region")
    default_aws_output_format: Optional[str] = Field(None, max_length=20, description="Default AWS CLI output format")


class UserSettingsCreate(BaseModel):
    """Create user settings with default values."""
    bedrock_model_id: str = Field(default="us.anthropic.claude-3-5-sonnet-20241022-v2:0", description="Bedrock model ID or inference profile ARN")
    bedrock_max_tokens: int = Field(default=4096, ge=1, le=100000, description="Maximum tokens for Bedrock responses")
    bedrock_temperature: float = Field(default=0.0, ge=0.0, le=1.0, description="Temperature for Bedrock model")
    default_aws_region: str = Field(default="us-east-1", max_length=50, description="Default AWS region")
    default_aws_output_format: str = Field(default="json", max_length=20, description="Default AWS CLI output format")


class BedrockModelOption(BaseModel):
    """Available Bedrock model option."""
    model_id: str = Field(..., description="Model ID or inference profile ARN")
    display_name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="Model description")
    max_tokens: int = Field(..., description="Maximum tokens supported")


class BedrockModelsResponse(BaseModel):
    """List of available Bedrock models."""
    models: list[BedrockModelOption]
