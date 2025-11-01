"""
API Monitoring Router

Provides endpoints for accessing API monitoring reports and triggering manual checks.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from app.database import get_db
from app.schemas.api_monitoring import (
    MonitoringReportSummary,
    MonitoringReportResponse,
    TriggerMonitoringRequest,
    TriggerMonitoringResponse,
    ChangesByServiceResponse,
    BreakingChangesResponse,
    APIChangeResponse
)
from app.services.api_monitoring_service import APIMonitoringService
from app.models.api_monitoring import MonitoringReport, APIChange, ServiceType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/monitoring", tags=["API Monitoring"])


@router.get("/latest-report", response_model=MonitoringReportResponse)
def get_latest_report(db: Session = Depends(get_db)):
    """
    Get the most recent API monitoring report.

    This endpoint returns the latest monitoring report including:
    - Summary statistics
    - Changes by service
    - AI-consumable report text
    """
    monitoring_service = APIMonitoringService(db)
    report = monitoring_service.get_latest_report()

    if not report:
        raise HTTPException(
            status_code=404,
            detail="No monitoring reports found. Trigger a monitoring run first."
        )

    return report


@router.get("/reports", response_model=List[MonitoringReportSummary])
def get_reports(
    limit: int = 30,
    db: Session = Depends(get_db)
):
    """
    Get a list of recent monitoring reports.

    Args:
        limit: Maximum number of reports to return (default: 30)

    Returns:
        List of monitoring report summaries
    """
    monitoring_service = APIMonitoringService(db)
    reports = monitoring_service.get_reports(limit=limit)

    return reports


@router.get("/reports/{report_id}", response_model=MonitoringReportResponse)
def get_report_by_id(
    report_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific monitoring report by ID.

    Args:
        report_id: ID of the report to retrieve

    Returns:
        Full monitoring report
    """
    report = db.query(MonitoringReport).filter(
        MonitoringReport.id == report_id
    ).first()

    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report {report_id} not found"
        )

    return report


@router.get("/changes/{service_type}", response_model=ChangesByServiceResponse)
def get_changes_for_service(
    service_type: str,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    Get recent changes for a specific service.

    Args:
        service_type: Service to get changes for (IAM, IdentityCenter, Organizations)
        limit: Maximum number of changes to return (default: 100)

    Returns:
        List of changes for the service
    """
    # Validate service type
    try:
        service_enum = ServiceType[service_type]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service type. Must be one of: {', '.join([s.name for s in ServiceType])}"
        )

    monitoring_service = APIMonitoringService(db)
    changes = monitoring_service.get_changes_for_service(service_type, limit=limit)

    return {
        'service_type': service_type,
        'changes': changes,
        'total_changes': len(changes)
    }


@router.get("/breaking-changes", response_model=BreakingChangesResponse)
def get_breaking_changes(
    days: int = 30,
    db: Session = Depends(get_db)
):
    """
    Get all breaking changes from the last N days.

    Args:
        days: Number of days to look back (default: 30)

    Returns:
        List of breaking changes
    """
    monitoring_service = APIMonitoringService(db)
    changes = monitoring_service.get_breaking_changes(days=days)

    return {
        'changes': changes,
        'total_breaking_changes': len(changes),
        'days_covered': days
    }


@router.post("/trigger", response_model=TriggerMonitoringResponse)
def trigger_monitoring(
    request: TriggerMonitoringRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Manually trigger an API monitoring run.

    This will run synchronously to:
    1. Discover current API definitions
    2. Create snapshots
    3. Detect changes
    4. Generate reports

    The task runs in the background and results will be available via the reports endpoints.
    """
    try:
        # Import monitoring service
        from app.services.api_monitoring_service import APIMonitoringService
        import uuid

        # Create a task ID
        task_id = str(uuid.uuid4())

        # Run monitoring in background
        def run_monitoring():
            monitoring_service = APIMonitoringService(db)
            monitoring_service.run_daily_monitoring()

        background_tasks.add_task(run_monitoring)

        logger.info(f"Manual monitoring triggered: {task_id}, reason: {request.reason}")

        return {
            'task_id': task_id,
            'status': 'queued',
            'message': 'API monitoring task queued successfully. Check reports endpoint for results.'
        }

    except Exception as e:
        logger.error(f"Failed to trigger monitoring: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to trigger monitoring: {str(e)}"
        )


@router.get("/health")
def monitoring_health(db: Session = Depends(get_db)):
    """
    Health check for monitoring service.

    Returns information about:
    - Latest report date
    - Total reports
    - Recent activity
    """
    monitoring_service = APIMonitoringService(db)
    latest_report = monitoring_service.get_latest_report()

    total_reports = db.query(MonitoringReport).count()
    total_changes = db.query(APIChange).count()

    return {
        'status': 'healthy',
        'total_reports': total_reports,
        'total_changes_tracked': total_changes,
        'latest_report_date': latest_report.report_date.isoformat() if latest_report else None,
        'latest_report_id': latest_report.id if latest_report else None
    }
