"""
User and AWS Credentials Models for Multi-Tenant Support
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    """
    User model for authentication and multi-tenant support.

    Each user can have their own AWS credentials and use the platform
    independently without sharing AWS resources.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    google_id = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=True, nullable=False)  # Google users are pre-verified
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    aws_credentials = relationship("UserAWSCredentials", back_populates="user", cascade="all, delete-orphan")
    # TODO: Add these relationships when Policy, AuditReport, and MonitoringReport models are updated with user_id foreign keys
    # policies = relationship("Policy", back_populates="user", cascade="all, delete-orphan")
    # audit_reports = relationship("AuditReport", back_populates="user", cascade="all, delete-orphan")
    # monitoring_reports = relationship("MonitoringReport", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}')>"


class UserAWSCredentials(Base):
    """
    Encrypted AWS credentials for each user.

    Supports multiple credential sets per user for different AWS accounts.
    Credentials are encrypted at rest using Fernet encryption.
    """
    __tablename__ = "user_aws_credentials"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # Credential label for user to identify (e.g., "Production", "Development")
    label = Column(String(100), nullable=False)

    # Encrypted AWS credentials
    encrypted_access_key_id = Column(Text, nullable=False)
    encrypted_secret_access_key = Column(Text, nullable=False)
    encrypted_session_token = Column(Text, nullable=True)  # For temporary credentials

    # AWS configuration
    aws_region = Column(String(50), default="us-east-1", nullable=False)
    aws_account_id = Column(String(12), nullable=True)  # Optional, for display

    # Default credential set flag
    is_default = Column(Boolean, default=False, nullable=False)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_used = Column(DateTime, nullable=True)

    # Cross-account role ARN (alternative to storing keys)
    cross_account_role_arn = Column(String(255), nullable=True)

    # Relationship
    user = relationship("User", back_populates="aws_credentials")

    def __repr__(self):
        return f"<UserAWSCredentials(id={self.id}, user_id={self.user_id}, label='{self.label}')>"


class RefreshToken(Base):
    """
    Refresh tokens for JWT authentication.

    Allows users to stay logged in and refresh their access tokens
    without re-entering credentials.
    """
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(500), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    # Device/session tracking
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)

    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"


class AuditLog(Base):
    """
    Audit log for tracking user actions and AWS operations.

    Critical for security and compliance in a multi-tenant environment.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Action details
    action = Column(String(100), nullable=False)  # e.g., "generate_policy", "create_user"
    resource_type = Column(String(50), nullable=True)  # e.g., "policy", "user", "role"
    resource_id = Column(String(255), nullable=True)

    # AWS context
    aws_account_id = Column(String(12), nullable=True)
    aws_region = Column(String(50), nullable=True)

    # Request details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    additional_data = Column(Text, nullable=True)  # JSON string for additional context (renamed from 'metadata' to avoid SQLAlchemy conflict)

    def __repr__(self):
        return f"<AuditLog(id={self.id}, user_id={self.user_id}, action='{self.action}')>"
