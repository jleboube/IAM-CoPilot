"""
Database models for IAM policies and audits
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
import enum

from app.database import Base


class AuditStatus(str, enum.Enum):
    """Audit job status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Policy(Base):
    """Generated IAM policy"""
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    natural_language_input = Column(Text, nullable=False)
    policy_json = Column(JSON, nullable=False)
    aws_policy_arn = Column(String(512), nullable=True)
    aws_account_id = Column(String(12), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = Column(String(255), nullable=True)

    # Relationships
    audits = relationship("PolicyAudit", back_populates="policy")


class PolicyAudit(Base):
    """Audit job for analyzing IAM policies"""
    __tablename__ = "policy_audits"

    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=True)
    aws_account_id = Column(String(12), nullable=False, index=True)
    role_arn = Column(String(512), nullable=True)
    status = Column(Enum(AuditStatus), default=AuditStatus.PENDING, nullable=False, index=True)
    findings = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    policy = relationship("Policy", back_populates="audits")
    results = relationship("AuditResult", back_populates="audit")


class AuditResult(Base):
    """Individual findings from an audit"""
    __tablename__ = "audit_results"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("policy_audits.id"), nullable=False)
    resource_type = Column(String(50), nullable=False)  # role, user, policy
    resource_arn = Column(String(512), nullable=False, index=True)
    resource_name = Column(String(255), nullable=False)
    unused_permissions = Column(JSON, nullable=True)
    permission_reduction_percent = Column(Integer, nullable=True)
    recommended_policy = Column(JSON, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    audit = relationship("PolicyAudit", back_populates="results")
