"""
API endpoints for AWS Organizations operations.
"""

from fastapi import APIRouter, HTTPException, status
import logging

from app.schemas.organizations import (
    OrganizationsRequest,
    OrganizationsOverview,
    OrganizationsAuditResult
)
from app.services.organizations_service import OrganizationsService
from app.services.organizations_audit_service import OrganizationsAuditService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
    responses={404: {"description": "Not found"}}
)


@router.post("/overview", response_model=OrganizationsOverview)
async def get_organizations_overview(request: OrganizationsRequest):
    """
    Get a comprehensive overview of AWS Organizations configuration.

    This endpoint provides:
    - Organization details (master account, feature set)
    - All member accounts
    - Complete organizational unit (OU) structure
    - All Service Control Policies (SCPs) with attachments
    - Statistics

    **Note:** This must be called from the management (master) account of the organization.

    **Required AWS Permissions:**
    - organizations:DescribeOrganization
    - organizations:ListAccounts
    - organizations:ListRoots
    - organizations:ListOrganizationalUnitsForParent
    - organizations:ListAccountsForParent
    - organizations:ListPolicies
    - organizations:DescribePolicy
    - organizations:ListPoliciesForTarget
    - organizations:ListTargetsForPolicy
    """
    try:
        logger.info("Getting Organizations overview")

        service = OrganizationsService(role_arn=request.role_arn)
        overview = service.get_organizations_overview()

        logger.info("Successfully retrieved Organizations overview")
        return overview

    except Exception as e:
        logger.error(f"Failed to get Organizations overview: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get Organizations overview: {str(e)}"
        )


@router.post("/audit", response_model=OrganizationsAuditResult)
async def audit_organizations(request: OrganizationsRequest):
    """
    Run a comprehensive security audit of AWS Organizations configuration.

    This audit checks for:
    - **Organization Configuration**:
      - Limited feature set (CONSOLIDATED_BILLING vs ALL)
      - Service Control Policies not enabled

    - **Account Management**:
      - Suspended accounts
      - Accounts at root level (not in OUs)

    - **Service Control Policies (SCPs)**:
      - No custom SCPs defined
      - Overly permissive SCP statements
      - SCPs without deny statements
      - Unused SCPs (not attached to targets)
      - SCPs attached to root (affecting management account)

    - **Organizational Structure**:
      - No OUs for organizing accounts
      - Overly deep OU nesting (>5 levels)

    Returns detailed findings with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    and actionable recommendations.

    **Note:** Must be called from the management account.

    **Required AWS Permissions:**
    Same as `/overview` endpoint
    """
    try:
        logger.info("Running Organizations audit")

        audit_service = OrganizationsAuditService(role_arn=request.role_arn)
        audit_result = audit_service.run_comprehensive_audit()

        logger.info(
            f"Organizations audit complete: {audit_result.get('resources_audited', 0)} resources audited, "
            f"{len(audit_result.get('findings', []))} findings"
        )
        return audit_result

    except Exception as e:
        logger.error(f"Failed to audit Organizations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to audit Organizations: {str(e)}"
        )
