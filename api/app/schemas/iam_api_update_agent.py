"""
Pydantic schemas for IAM API Update Agent
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime


class TriggerAgentRequest(BaseModel):
    """Request to trigger the IAM API Update Agent."""
    monitoring_report_id: Optional[int] = Field(None, description="Specific report ID to process. If None, uses latest.")
    auto_apply: bool = Field(False, description="Whether to automatically apply code changes (use with caution)")
    reason: Optional[str] = Field(None, description="Reason for triggering the agent")


class PlannedChangeResponse(BaseModel):
    """Response schema for a planned change."""
    id: int
    change_type: str
    service_type: str
    operation_name: Optional[str]
    target_file: Optional[str]
    description: str
    reasoning: Optional[str]
    has_generated_code: bool
    code_preview: Optional[str]
    status: str
    error_message: Optional[str]

    class Config:
        from_attributes = True


class AgentRunSummary(BaseModel):
    """Summary of an agent run."""
    id: int
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    changes_planned: int
    changes_applied: int

    class Config:
        from_attributes = True


class AgentRunResponse(BaseModel):
    """Response from running the agent."""
    success: bool
    agent_run_id: Optional[int] = None
    monitoring_report_id: Optional[int] = None
    changes_detected: Optional[int] = None
    changes_planned: Optional[int] = None
    changes_generated: Optional[int] = None
    changes_applied: Optional[int] = None
    summary: Optional[str] = None
    error: Optional[str] = None
    planned_changes: Optional[List[PlannedChangeResponse]] = None

    class Config:
        from_attributes = True


class AgentRunDetails(BaseModel):
    """Detailed information about an agent run."""
    id: int
    status: str
    monitoring_report_id: int
    started_at: datetime
    completed_at: Optional[datetime]
    total_changes_detected: int
    total_changes_planned: int
    total_changes_applied: int
    total_changes_failed: int
    analysis_summary: Optional[str]
    error_message: Optional[str]
    planned_changes: List[PlannedChangeResponse]

    class Config:
        from_attributes = True


class CodebaseAnalysisResponse(BaseModel):
    """Response from codebase analysis."""
    service_type: str
    implemented_operations: List[str]
    file_exists: bool
    file_path: Optional[str]
    total_operations: int


class OperationCheckResponse(BaseModel):
    """Response from operation existence check."""
    exists: bool
    method_name: Optional[str]
    operation_name: str
    service_type: str
    file_path: Optional[str]
    reason: Optional[str]
