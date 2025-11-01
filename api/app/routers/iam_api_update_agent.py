"""
IAM API Update Agent Router

Provides endpoints for triggering and managing the IAM API Update Agent.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from app.database import get_db
from app.schemas.iam_api_update_agent import (
    TriggerAgentRequest,
    AgentRunResponse,
    AgentRunSummary,
    AgentRunDetails,
    PlannedChangeResponse,
    CodebaseAnalysisResponse,
    OperationCheckResponse
)
from app.services.iam_api_update_agent_service import IAMAPIUpdateAgentService
from app.services.agent_codebase_analyzer import AgentCodebaseAnalyzer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agent", tags=["IAM API Update Agent"])


@router.post("/trigger", response_model=AgentRunResponse)
def trigger_agent(
    request: TriggerAgentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Trigger the IAM API Update Agent to process monitoring reports.

    This agent will:
    1. Analyze the latest (or specified) API monitoring report
    2. Determine what code changes are needed
    3. Generate code using LLM (Bedrock)
    4. Optionally apply changes (if auto_apply=True)

    **Warning:** Set auto_apply=True only in safe environments. The agent will
    modify your codebase!

    Args:
        request: Agent trigger request
        background_tasks: FastAPI background tasks
        db: Database session

    Returns:
        Agent run results including all planned changes
    """
    logger.info(f"Agent triggered: report_id={request.monitoring_report_id}, auto_apply={request.auto_apply}")

    try:
        agent_service = IAMAPIUpdateAgentService(db)

        # Run agent synchronously for now (could be made async)
        result = agent_service.run_agent(
            monitoring_report_id=request.monitoring_report_id,
            auto_apply=request.auto_apply
        )

        return result

    except Exception as e:
        logger.error(f"Failed to trigger agent: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to trigger agent: {str(e)}"
        )


@router.get("/runs", response_model=List[AgentRunSummary])
def get_agent_runs(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Get recent agent runs.

    Args:
        limit: Maximum number of runs to return (default: 10)
        db: Database session

    Returns:
        List of agent run summaries
    """
    agent_service = IAMAPIUpdateAgentService(db)
    runs = agent_service.get_recent_runs(limit=limit)

    return runs


@router.get("/runs/{agent_run_id}", response_model=AgentRunDetails)
def get_agent_run_details(
    agent_run_id: int,
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific agent run.

    Args:
        agent_run_id: ID of the agent run
        db: Database session

    Returns:
        Detailed run information including all planned changes and generated code
    """
    agent_service = IAMAPIUpdateAgentService(db)
    details = agent_service.get_agent_run_details(agent_run_id)

    if 'error' in details:
        raise HTTPException(status_code=404, detail=details['error'])

    return details


@router.get("/analyze/{service_type}", response_model=CodebaseAnalysisResponse)
def analyze_service_implementation(
    service_type: str,
    db: Session = Depends(get_db)
):
    """
    Analyze what operations are currently implemented for a service.

    Useful for understanding the current state of the codebase.

    Args:
        service_type: Service name (IAM, IdentityCenter, Organizations)
        db: Database session

    Returns:
        Analysis of current implementation
    """
    # Validate service type
    valid_services = ['IAM', 'IdentityCenter', 'Organizations']
    if service_type not in valid_services:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service type. Must be one of: {', '.join(valid_services)}"
        )

    analyzer = AgentCodebaseAnalyzer()
    analysis = analyzer.analyze_service_implementation(service_type)

    return analysis


@router.get("/check-operation/{service_type}/{operation_name}", response_model=OperationCheckResponse)
def check_operation_exists(
    service_type: str,
    operation_name: str,
    db: Session = Depends(get_db)
):
    """
    Check if a specific AWS operation is already implemented.

    Args:
        service_type: Service name (IAM, IdentityCenter, Organizations)
        operation_name: AWS operation name (e.g., "CreateUser", "ListRoles")
        db: Database session

    Returns:
        Information about whether the operation exists in the codebase
    """
    # Validate service type
    valid_services = ['IAM', 'IdentityCenter', 'Organizations']
    if service_type not in valid_services:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service type. Must be one of: {', '.join(valid_services)}"
        )

    analyzer = AgentCodebaseAnalyzer()
    check_result = analyzer.check_operation_exists(service_type, operation_name)

    return check_result


@router.get("/health")
def agent_health(db: Session = Depends(get_db)):
    """
    Health check for the IAM API Update Agent.

    Returns:
        Service health information
    """
    from app.models.iam_api_update_agent import AgentRun

    total_runs = db.query(AgentRun).count()
    recent_run = db.query(AgentRun).order_by(AgentRun.started_at.desc()).first()

    return {
        'status': 'healthy',
        'total_agent_runs': total_runs,
        'last_run_date': recent_run.started_at.isoformat() if recent_run else None,
        'last_run_status': recent_run.status.value if recent_run else None,
        'services': {
            'parser': 'operational',
            'analyzer': 'operational',
            'planner': 'operational',
            'generator': 'operational'
        }
    }


@router.get("/planned-changes/{agent_run_id}/{change_id}/code")
def get_generated_code(
    agent_run_id: int,
    change_id: int,
    db: Session = Depends(get_db)
):
    """
    Get the full generated code for a specific planned change.

    Args:
        agent_run_id: ID of the agent run
        change_id: ID of the planned change
        db: Database session

    Returns:
        Full generated code
    """
    from app.models.iam_api_update_agent import PlannedChange

    planned_change = db.query(PlannedChange).filter(
        PlannedChange.id == change_id,
        PlannedChange.agent_run_id == agent_run_id
    ).first()

    if not planned_change:
        raise HTTPException(
            status_code=404,
            detail="Planned change not found"
        )

    if not planned_change.generated_code:
        raise HTTPException(
            status_code=404,
            detail="No code has been generated for this change yet"
        )

    return {
        'change_id': change_id,
        'agent_run_id': agent_run_id,
        'operation_name': planned_change.operation_name,
        'target_file': planned_change.target_file,
        'change_type': planned_change.change_type.value,
        'generated_code': planned_change.generated_code,
        'description': planned_change.description
    }
