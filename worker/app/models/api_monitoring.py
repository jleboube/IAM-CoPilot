"""
Database models for AWS API monitoring.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from app.database import Base


class ServiceType(str, enum.Enum):
    """AWS service types being monitored."""
    IAM = "IAM"
    IDENTITY_CENTER = "IdentityCenter"
    ORGANIZATIONS = "Organizations"


class ChangeType(str, enum.Enum):
    """Types of API changes."""
    NEW_OPERATION = "new_operation"
    MODIFIED_OPERATION = "modified_operation"
    DEPRECATED_OPERATION = "deprecated_operation"
    REMOVED_OPERATION = "removed_operation"
    NEW_PARAMETER = "new_parameter"
    REMOVED_PARAMETER = "removed_parameter"
    MODIFIED_PARAMETER = "modified_parameter"
    NEW_ERROR = "new_error"
    MODIFIED_SHAPE = "modified_shape"


class APISnapshot(Base):
    """
    Represents a snapshot of an AWS service API at a point in time.
    """
    __tablename__ = "api_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    service_type = Column(Enum(ServiceType), nullable=False, index=True)
    service_version = Column(String(50), nullable=True)  # API version from AWS
    snapshot_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Complete API definition (from boto3 service model or parsed from docs)
    api_definition = Column(JSON, nullable=False)

    # Summary statistics
    total_operations = Column(Integer, nullable=False)
    total_shapes = Column(Integer, nullable=False)

    # Metadata
    source = Column(String(100), nullable=False)  # e.g., "boto3", "aws_docs", "openapi"
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    changes_as_current = relationship("APIChange", back_populates="current_snapshot", foreign_keys="APIChange.current_snapshot_id")
    changes_as_previous = relationship("APIChange", back_populates="previous_snapshot", foreign_keys="APIChange.previous_snapshot_id")


class APIChange(Base):
    """
    Represents a detected change between two API snapshots.
    """
    __tablename__ = "api_changes"

    id = Column(Integer, primary_key=True, index=True)
    service_type = Column(Enum(ServiceType), nullable=False, index=True)
    change_type = Column(Enum(ChangeType), nullable=False, index=True)

    # Snapshot references
    current_snapshot_id = Column(Integer, ForeignKey("api_snapshots.id"), nullable=False)
    previous_snapshot_id = Column(Integer, ForeignKey("api_snapshots.id"), nullable=True)

    # Change details
    operation_name = Column(String(255), nullable=True, index=True)  # e.g., "CreateUser", "ListRoles"
    change_path = Column(String(500), nullable=True)  # JSON path to the change, e.g., "operations.CreateUser.input.members.UserName"

    # Before and after values
    previous_value = Column(JSON, nullable=True)
    current_value = Column(JSON, nullable=True)

    # Human-readable description
    description = Column(Text, nullable=False)

    # Impact assessment
    impact_level = Column(String(20), nullable=False)  # "breaking", "non-breaking", "enhancement"

    # When this change was detected
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    current_snapshot = relationship("APISnapshot", back_populates="changes_as_current", foreign_keys=[current_snapshot_id])
    previous_snapshot = relationship("APISnapshot", back_populates="changes_as_previous", foreign_keys=[previous_snapshot_id])


class MonitoringReport(Base):
    """
    Represents a complete monitoring report for a specific date.
    """
    __tablename__ = "monitoring_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_date = Column(DateTime(timezone=True), nullable=False, index=True)

    # Report content
    summary = Column(JSON, nullable=False)  # Summary statistics
    changes_by_service = Column(JSON, nullable=False)  # Structured changes grouped by service

    # AI-friendly report
    ai_report = Column(Text, nullable=False)  # Structured text report for AI consumption

    # Metadata
    total_changes = Column(Integer, nullable=False)
    services_monitored = Column(JSON, nullable=False)  # List of services included

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
