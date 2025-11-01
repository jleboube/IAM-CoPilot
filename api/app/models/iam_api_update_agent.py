"""
Database models for IAM API Update Agent.

Tracks agent runs, planned changes, and applied modifications.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Enum, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from app.database import Base


class AgentRunStatus(str, enum.Enum):
    """Status of an agent run."""
    PENDING = "pending"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    APPLYING = "applying"
    COMPLETED = "completed"
    FAILED = "failed"


class ChangeType(str, enum.Enum):
    """Type of change the agent will make."""
    ADD_OPERATION = "add_operation"
    REMOVE_OPERATION = "remove_operation"
    DEPRECATE_OPERATION = "deprecate_operation"
    UPDATE_OPERATION = "update_operation"
    ADD_PARAMETER = "add_parameter"
    REMOVE_PARAMETER = "remove_parameter"
    UPDATE_SCHEMA = "update_schema"


class ChangeStatus(str, enum.Enum):
    """Status of a planned change."""
    PLANNED = "planned"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentRun(Base):
    """
    Represents a single run of the IAM API Update Agent.
    """
    __tablename__ = "agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    monitoring_report_id = Column(Integer, ForeignKey("monitoring_reports.id"), nullable=False, index=True)
    status = Column(Enum(AgentRunStatus), nullable=False, default=AgentRunStatus.PENDING)

    # Run metadata
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Analysis results
    total_changes_detected = Column(Integer, default=0)
    total_changes_planned = Column(Integer, default=0)
    total_changes_applied = Column(Integer, default=0)
    total_changes_failed = Column(Integer, default=0)

    # Agent reasoning
    analysis_summary = Column(Text, nullable=True)  # LLM's analysis of the report
    error_message = Column(Text, nullable=True)

    # Relationships
    planned_changes = relationship("PlannedChange", back_populates="agent_run", cascade="all, delete-orphan")
    applied_changes = relationship("AppliedChange", back_populates="agent_run", cascade="all, delete-orphan")


class PlannedChange(Base):
    """
    Represents a change that the agent plans to make.
    """
    __tablename__ = "planned_changes"

    id = Column(Integer, primary_key=True, index=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=False, index=True)
    status = Column(Enum(ChangeStatus), nullable=False, default=ChangeStatus.PLANNED)

    # Change details
    change_type = Column(Enum(ChangeType), nullable=False)
    service_type = Column(String(50), nullable=False)  # IAM, IdentityCenter, Organizations
    operation_name = Column(String(255), nullable=True)

    # What needs to change
    target_file = Column(String(500), nullable=True)  # e.g., "api/app/services/iam_service.py"
    description = Column(Text, nullable=False)
    reasoning = Column(Text, nullable=True)  # Why this change is needed

    # Implementation plan
    implementation_plan = Column(JSON, nullable=True)  # Structured plan from LLM
    generated_code = Column(Text, nullable=True)  # Code to add/modify

    # Execution
    applied_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    agent_run = relationship("AgentRun", back_populates="planned_changes")
    applied_change = relationship("AppliedChange", back_populates="planned_change", uselist=False)


class AppliedChange(Base):
    """
    Represents a change that was actually applied to the codebase.
    """
    __tablename__ = "applied_changes"

    id = Column(Integer, primary_key=True, index=True)
    agent_run_id = Column(Integer, ForeignKey("agent_runs.id"), nullable=False, index=True)
    planned_change_id = Column(Integer, ForeignKey("planned_changes.id"), nullable=True)

    # File modifications
    file_path = Column(String(500), nullable=False)
    change_type = Column(String(50), nullable=False)  # created, modified, deleted

    # Content
    original_content = Column(Text, nullable=True)  # Backup of original
    new_content = Column(Text, nullable=True)  # New content
    diff = Column(Text, nullable=True)  # Diff for review

    # Git integration
    commit_sha = Column(String(40), nullable=True)
    branch_name = Column(String(255), nullable=True)
    pull_request_url = Column(String(500), nullable=True)

    # Metadata
    applied_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)

    # Relationships
    agent_run = relationship("AgentRun", back_populates="applied_changes")
    planned_change = relationship("PlannedChange", back_populates="applied_change")
