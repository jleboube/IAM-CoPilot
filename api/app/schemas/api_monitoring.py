"""
Pydantic schemas for API monitoring
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime


class APISnapshotResponse(BaseModel):
    """Response schema for API snapshot"""
    id: int
    service_type: str
    service_version: Optional[str]
    snapshot_date: datetime
    total_operations: int
    total_shapes: int
    source: str
    created_at: datetime

    class Config:
        from_attributes = True


class APIChangeResponse(BaseModel):
    """Response schema for API change"""
    id: int
    service_type: str
    change_type: str
    operation_name: Optional[str]
    change_path: Optional[str]
    previous_value: Optional[Any]
    current_value: Optional[Any]
    description: str
    impact_level: str
    detected_at: datetime

    class Config:
        from_attributes = True


class MonitoringReportSummary(BaseModel):
    """Summary of a monitoring report"""
    id: int
    report_date: datetime
    total_changes: int
    services_monitored: List[str]
    created_at: datetime

    class Config:
        from_attributes = True


class MonitoringReportResponse(BaseModel):
    """Full monitoring report response"""
    id: int
    report_date: datetime
    summary: Dict[str, Any]
    changes_by_service: Dict[str, Any]
    ai_report: str
    total_changes: int
    services_monitored: List[str]
    created_at: datetime

    class Config:
        from_attributes = True


class TriggerMonitoringRequest(BaseModel):
    """Request to trigger manual API monitoring"""
    reason: Optional[str] = Field(None, description="Optional reason for manual trigger")


class TriggerMonitoringResponse(BaseModel):
    """Response from triggering API monitoring"""
    task_id: str
    status: str
    message: str


class ChangesByServiceResponse(BaseModel):
    """Response with changes for a specific service"""
    service_type: str
    changes: List[APIChangeResponse]
    total_changes: int


class BreakingChangesResponse(BaseModel):
    """Response with breaking changes"""
    changes: List[APIChangeResponse]
    total_breaking_changes: int
    days_covered: int
