"""
User Settings Model for storing user-specific configuration
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database import Base


class UserSettings(Base):
    """
    User-specific settings for AWS and Bedrock configuration.

    Each user can configure their own preferences for:
    - Bedrock model selection and parameters
    - Default AWS region
    - Other AWS-related preferences

    Settings are applied immediately without requiring application restart.
    """
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)

    # Bedrock Configuration
    bedrock_model_id = Column(String(255), default="us.anthropic.claude-3-5-sonnet-20241022-v2:0", nullable=False)
    bedrock_max_tokens = Column(Integer, default=4096, nullable=False)
    bedrock_temperature = Column(Float, default=0.0, nullable=False)

    # AWS Configuration
    default_aws_region = Column(String(50), default="us-east-1", nullable=False)

    # Additional AWS settings that might be configured by company admins
    # These can be expanded as needed
    default_aws_output_format = Column(String(20), default="json", nullable=False)  # json, yaml, text, table

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationship
    user = relationship("User", backref="settings")

    def __repr__(self):
        return f"<UserSettings(id={self.id}, user_id={self.user_id}, bedrock_model='{self.bedrock_model_id}')>"
