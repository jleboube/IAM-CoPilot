"""
API endpoints for IAM Identity Center operations.
"""

from fastapi import APIRouter, HTTPException, status
from typing import List
import logging

from app.schemas.identity_center import (
    IdentityCenterRequest,
    IdentityCenterOverview,
    IdentityCenterAuditResult,
    PermissionSet,
    IdentityStoreUser,
    IdentityStoreGroup,
    SSOInstance
)
from app.services.identity_center_service import IdentityCenterService
from app.services.identity_center_audit_service import IdentityCenterAuditService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/identity-center",
    tags=["Identity Center"],
    responses={404: {"description": "Not found"}}
)


@router.post("/overview", response_model=IdentityCenterOverview)
async def get_identity_center_overview(request: IdentityCenterRequest):
    """
    Get a comprehensive overview of IAM Identity Center configuration.

    This endpoint provides:
    - SSO instance details
    - All permission sets with their policies
    - Identity Store users and groups
    - Account assignments
    - Organization accounts
    - Statistics

    **Note:** The AWS account must be the management account of the organization,
    and Identity Center must be enabled in the specified region.

    **Required AWS Permissions:**
    - sso:ListInstances
    - sso:DescribeInstance
    - sso:ListPermissionSets
    - sso:DescribePermissionSet
    - sso:GetInlinePolicyForPermissionSet
    - sso:ListManagedPoliciesInPermissionSet
    - sso:ListCustomerManagedPolicyReferencesInPermissionSet
    - sso:ListAccountAssignments
    - sso:ListAccountsForProvisionedPermissionSet
    - identitystore:ListUsers
    - identitystore:ListGroups
    - organizations:ListAccounts
    """
    try:
        logger.info(f"Getting Identity Center overview for account {request.aws_account_id}")

        service = IdentityCenterService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        overview = service.get_identity_center_overview()

        logger.info(f"Successfully retrieved Identity Center overview")
        return overview

    except Exception as e:
        logger.error(f"Failed to get Identity Center overview: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get Identity Center overview: {str(e)}"
        )


@router.post("/audit", response_model=IdentityCenterAuditResult)
async def audit_identity_center(request: IdentityCenterRequest):
    """
    Run a comprehensive security audit of IAM Identity Center configuration.

    This audit checks for:
    - High-risk managed policies (AdministratorAccess, etc.)
    - Wildcard permissions in inline policies
    - Overly long session durations
    - Unused permission sets
    - Empty permission sets
    - Widely-assigned permission sets
    - Direct user assignments of high-risk permissions (should use groups)
    - Unused users and groups
    - Users without email addresses
    - Active accounts without Identity Center access

    Returns detailed findings with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    and actionable recommendations.

    **Note:** The AWS account must be the management account of the organization.

    **Required AWS Permissions:**
    Same as `/overview` endpoint
    """
    try:
        logger.info(f"Running Identity Center audit for account {request.aws_account_id}")

        audit_service = IdentityCenterAuditService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        audit_result = audit_service.run_comprehensive_audit()

        logger.info(
            f"Identity Center audit complete: {audit_result.get('resources_audited', 0)} resources audited, "
            f"{len(audit_result.get('findings', []))} findings"
        )
        return audit_result

    except Exception as e:
        logger.error(f"Failed to audit Identity Center: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to audit Identity Center: {str(e)}"
        )


@router.post("/instances", response_model=List[SSOInstance])
async def list_sso_instances(request: IdentityCenterRequest):
    """
    List all SSO instances in the region.

    Typically there is only one SSO instance per region.

    **Required AWS Permissions:**
    - sso:ListInstances
    """
    try:
        logger.info(f"Listing SSO instances for account {request.aws_account_id}")

        service = IdentityCenterService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        instances = service.list_sso_instances()

        logger.info(f"Found {len(instances)} SSO instance(s)")
        return instances

    except Exception as e:
        logger.error(f"Failed to list SSO instances: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list SSO instances: {str(e)}"
        )


@router.post("/permission-sets", response_model=List[PermissionSet])
async def list_permission_sets(request: IdentityCenterRequest):
    """
    List all permission sets in the SSO instance.

    Permission sets define the level of access that users and groups have to AWS accounts.

    **Required AWS Permissions:**
    - sso:ListInstances
    - sso:ListPermissionSets
    - sso:DescribePermissionSet
    - sso:GetInlinePolicyForPermissionSet
    - sso:ListManagedPoliciesInPermissionSet
    - sso:ListCustomerManagedPolicyReferencesInPermissionSet
    """
    try:
        logger.info(f"Listing permission sets for account {request.aws_account_id}")

        service = IdentityCenterService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        # Get SSO instance first
        instance = service.get_sso_instance()
        if not instance:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No SSO instance found in this region"
            )

        permission_sets = service.list_permission_sets(instance['instance_arn'])

        logger.info(f"Found {len(permission_sets)} permission set(s)")
        return permission_sets

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list permission sets: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list permission sets: {str(e)}"
        )


@router.post("/users", response_model=List[IdentityStoreUser])
async def list_identity_store_users(request: IdentityCenterRequest):
    """
    List users from the Identity Store.

    Returns up to 50 users by default.

    **Required AWS Permissions:**
    - sso:ListInstances
    - identitystore:ListUsers
    """
    try:
        logger.info(f"Listing Identity Store users for account {request.aws_account_id}")

        service = IdentityCenterService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        # Get SSO instance to get Identity Store ID
        instance = service.get_sso_instance()
        if not instance:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No SSO instance found in this region"
            )

        users = service.list_identity_store_users(instance['identity_store_id'])

        logger.info(f"Found {len(users)} user(s)")
        return users

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list Identity Store users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list Identity Store users: {str(e)}"
        )


@router.post("/groups", response_model=List[IdentityStoreGroup])
async def list_identity_store_groups(request: IdentityCenterRequest):
    """
    List groups from the Identity Store.

    Returns up to 50 groups by default.

    **Required AWS Permissions:**
    - sso:ListInstances
    - identitystore:ListGroups
    """
    try:
        logger.info(f"Listing Identity Store groups for account {request.aws_account_id}")

        service = IdentityCenterService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            region=request.region
        )

        # Get SSO instance to get Identity Store ID
        instance = service.get_sso_instance()
        if not instance:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No SSO instance found in this region"
            )

        groups = service.list_identity_store_groups(instance['identity_store_id'])

        logger.info(f"Found {len(groups)} group(s)")
        return groups

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list Identity Store groups: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list Identity Store groups: {str(e)}"
        )
