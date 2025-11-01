"""
API endpoints for IAM management operations (users, groups, roles, policies)
"""
from fastapi import APIRouter, Depends, HTTPException, status
import structlog
import secrets
import string

from app.services.iam_service import IAMService
from app.schemas.iam_management import (
    UserCreateRequest, UserCreateResponse, UserUpdateRequest, UserDeleteRequest,
    UserPasswordRequest, UserPasswordResponse,
    AccessKeyCreateRequest, AccessKeyCreateResponse, AccessKeyRotateRequest,
    AccessKeyDeleteRequest, AccessKeyListResponse,
    GroupCreateRequest, GroupCreateResponse, GroupDeleteRequest, GroupMembershipRequest,
    RoleCreateRequest, RoleCreateResponse, RoleUpdateRequest, RoleDeleteRequest,
    RoleTrustPolicyRequest,
    PolicyCreateRequest, PolicyCreateResponse, PolicyDeleteRequest,
    PolicyAttachRequest, PolicyDetachRequest, PolicyAttachedEntitiesResponse,
    PasswordPolicyUpdateRequest, PasswordPolicyGetResponse,
    GenericSuccessResponse, IAMResourceListResponse
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/iam", tags=["iam_management"])


def get_iam_service(role_arn: str | None = None) -> IAMService:
    """Dependency to get IAM service instance"""
    return IAMService(role_arn=role_arn)


# ==================== User Management Endpoints ====================

@router.post("/users", response_model=UserCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: UserCreateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Create a new IAM user"""
    try:
        logger.info("user_creation_requested", user_name=request.user_name)

        tags = None
        if request.tags:
            tags = [{"Key": k, "Value": v} for k, v in request.tags.items()]

        user = iam_service.create_user(
            user_name=request.user_name,
            path=request.path,
            permissions_boundary=request.permissions_boundary,
            tags=tags
        )

        return UserCreateResponse(
            user_name=user['UserName'],
            user_arn=user['Arn'],
            user_id=user['UserId'],
            created_at=user['CreateDate'],
            message=f"User {user['UserName']} created successfully"
        )

    except Exception as e:
        logger.error("user_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )


@router.put("/users/{user_name}", response_model=GenericSuccessResponse)
async def update_user(
    user_name: str,
    request: UserUpdateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Update an IAM user"""
    try:
        logger.info("user_update_requested", user_name=user_name)

        result = iam_service.update_user(
            user_name=user_name,
            new_user_name=request.new_user_name,
            new_path=request.new_path
        )

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("user_update_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user: {str(e)}"
        )


@router.delete("/users/{user_name}", response_model=GenericSuccessResponse)
async def delete_user(
    user_name: str,
    force: bool = False,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Delete an IAM user"""
    try:
        logger.info("user_deletion_requested", user_name=user_name, force=force)

        result = iam_service.delete_user(user_name=user_name, force=force)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("user_deletion_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user: {str(e)}"
        )


@router.post("/users/{user_name}/password", response_model=UserPasswordResponse)
async def set_user_password(
    user_name: str,
    request: UserPasswordRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """
    Set or reset user password
    Note: This operation requires console access for the user.
    AWS API limitation: Cannot set passwords via API for users without console access.
    """
    try:
        logger.info("password_change_requested", user_name=user_name)

        # Generate password if not provided
        password = request.password
        if not password:
            # Generate secure password: 16 chars with upper, lower, digits, symbols
            alphabet = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(alphabet) for _ in range(16))

        # Create login profile (enables console access)
        try:
            iam_service.client.create_login_profile(
                UserName=user_name,
                Password=password,
                PasswordResetRequired=request.require_reset
            )
            message = "Password set and console access enabled"
        except iam_service.client.exceptions.EntityAlreadyExistsException:
            # Update existing login profile
            iam_service.client.update_login_profile(
                UserName=user_name,
                Password=password,
                PasswordResetRequired=request.require_reset
            )
            message = "Password updated successfully"

        return UserPasswordResponse(
            user_name=user_name,
            password=password if not request.password else None,
            message=message
        )

    except Exception as e:
        logger.error("password_change_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to set password: {str(e)}"
        )


# ==================== Access Key Management Endpoints ====================

@router.post("/users/{user_name}/access-keys", response_model=AccessKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_access_key(
    user_name: str,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Create access key for user"""
    try:
        logger.info("access_key_creation_requested", user_name=user_name)

        access_key = iam_service.create_access_key(user_name=user_name)

        return AccessKeyCreateResponse(
            access_key_id=access_key['AccessKeyId'],
            secret_access_key=access_key['SecretAccessKey'],
            user_name=access_key['UserName'],
            created_at=access_key['CreateDate'],
            status=access_key['Status']
        )

    except Exception as e:
        logger.error("access_key_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create access key: {str(e)}"
        )


@router.get("/users/{user_name}/access-keys", response_model=AccessKeyListResponse)
async def list_access_keys(
    user_name: str,
    iam_service: IAMService = Depends(get_iam_service)
):
    """List access keys for user"""
    try:
        logger.info("access_key_list_requested", user_name=user_name)

        access_keys = iam_service.list_access_keys(user_name=user_name)

        return AccessKeyListResponse(
            user_name=user_name,
            access_keys=[
                {
                    'access_key_id': key['AccessKeyId'],
                    'status': key['Status'],
                    'create_date': key['CreateDate'].isoformat()
                }
                for key in access_keys
            ]
        )

    except Exception as e:
        logger.error("access_key_list_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list access keys: {str(e)}"
        )


@router.delete("/users/{user_name}/access-keys/{access_key_id}", response_model=GenericSuccessResponse)
async def delete_access_key(
    user_name: str,
    access_key_id: str,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Delete an access key"""
    try:
        logger.info("access_key_deletion_requested", user_name=user_name, access_key_id=access_key_id)

        result = iam_service.delete_access_key(user_name=user_name, access_key_id=access_key_id)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("access_key_deletion_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete access key: {str(e)}"
        )


@router.post("/users/{user_name}/access-keys/{access_key_id}/rotate", response_model=AccessKeyCreateResponse)
async def rotate_access_key(
    user_name: str,
    access_key_id: str,
    delete_old: bool = False,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Rotate access key (create new, optionally delete old)"""
    try:
        logger.info("access_key_rotation_requested", user_name=user_name, access_key_id=access_key_id)

        # Create new access key
        new_key = iam_service.create_access_key(user_name=user_name)

        # Optionally delete old key
        if delete_old:
            iam_service.delete_access_key(user_name=user_name, access_key_id=access_key_id)

        return AccessKeyCreateResponse(
            access_key_id=new_key['AccessKeyId'],
            secret_access_key=new_key['SecretAccessKey'],
            user_name=new_key['UserName'],
            created_at=new_key['CreateDate'],
            status=new_key['Status'],
            message=f"Access key rotated successfully. Old key {'deleted' if delete_old else 'still active'}"
        )

    except Exception as e:
        logger.error("access_key_rotation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to rotate access key: {str(e)}"
        )


# ==================== Group Management Endpoints ====================

@router.post("/groups", response_model=GroupCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_group(
    request: GroupCreateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Create a new IAM group"""
    try:
        logger.info("group_creation_requested", group_name=request.group_name)

        group = iam_service.create_group(group_name=request.group_name, path=request.path)

        return GroupCreateResponse(
            group_name=group['GroupName'],
            group_arn=group['Arn'],
            group_id=group['GroupId'],
            created_at=group['CreateDate'],
            message=f"Group {group['GroupName']} created successfully"
        )

    except Exception as e:
        logger.error("group_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create group: {str(e)}"
        )


@router.delete("/groups/{group_name}", response_model=GenericSuccessResponse)
async def delete_group(
    group_name: str,
    force: bool = False,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Delete an IAM group"""
    try:
        logger.info("group_deletion_requested", group_name=group_name, force=force)

        result = iam_service.delete_group(group_name=group_name, force=force)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("group_deletion_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete group: {str(e)}"
        )


@router.post("/groups/{group_name}/members", response_model=GenericSuccessResponse)
async def add_user_to_group(
    group_name: str,
    request: GroupMembershipRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Add user to group"""
    try:
        logger.info("add_user_to_group_requested", group_name=group_name, user_name=request.user_name)

        result = iam_service.add_user_to_group(group_name=group_name, user_name=request.user_name)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("add_user_to_group_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add user to group: {str(e)}"
        )


@router.delete("/groups/{group_name}/members/{user_name}", response_model=GenericSuccessResponse)
async def remove_user_from_group(
    group_name: str,
    user_name: str,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Remove user from group"""
    try:
        logger.info("remove_user_from_group_requested", group_name=group_name, user_name=user_name)

        result = iam_service.remove_user_from_group(group_name=group_name, user_name=user_name)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("remove_user_from_group_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove user from group: {str(e)}"
        )


# ==================== Role Management Endpoints ====================

@router.post("/roles", response_model=RoleCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    request: RoleCreateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Create a new IAM role"""
    try:
        logger.info("role_creation_requested", role_name=request.role_name)

        tags = None
        if request.tags:
            tags = [{"Key": k, "Value": v} for k, v in request.tags.items()]

        role = iam_service.create_role(
            role_name=request.role_name,
            assume_role_policy=request.assume_role_policy,
            description=request.description or "",
            max_session_duration=request.max_session_duration,
            path=request.path,
            permissions_boundary=request.permissions_boundary,
            tags=tags
        )

        return RoleCreateResponse(
            role_name=role['RoleName'],
            role_arn=role['Arn'],
            role_id=role['RoleId'],
            created_at=role['CreateDate'],
            message=f"Role {role['RoleName']} created successfully"
        )

    except Exception as e:
        logger.error("role_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create role: {str(e)}"
        )


@router.put("/roles/{role_name}", response_model=GenericSuccessResponse)
async def update_role(
    role_name: str,
    request: RoleUpdateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Update an IAM role"""
    try:
        logger.info("role_update_requested", role_name=role_name)

        result = iam_service.update_role(
            role_name=role_name,
            description=request.description,
            max_session_duration=request.max_session_duration
        )

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("role_update_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update role: {str(e)}"
        )


@router.delete("/roles/{role_name}", response_model=GenericSuccessResponse)
async def delete_role(
    role_name: str,
    force: bool = False,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Delete an IAM role"""
    try:
        logger.info("role_deletion_requested", role_name=role_name, force=force)

        result = iam_service.delete_role(role_name=role_name, force=force)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("role_deletion_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete role: {str(e)}"
        )


@router.put("/roles/{role_name}/trust-policy", response_model=GenericSuccessResponse)
async def update_role_trust_policy(
    role_name: str,
    request: RoleTrustPolicyRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Update role trust policy (assume role policy document)"""
    try:
        logger.info("trust_policy_update_requested", role_name=role_name)

        result = iam_service.update_assume_role_policy(
            role_name=role_name,
            assume_role_policy=request.assume_role_policy
        )

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("trust_policy_update_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update trust policy: {str(e)}"
        )


# ==================== Policy Management Endpoints ====================

@router.post("/policies", response_model=PolicyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    request: PolicyCreateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Create a managed policy"""
    try:
        logger.info("policy_creation_requested", policy_name=request.policy_name)

        # Validate policy document
        validation = iam_service.validate_policy_document(request.policy_document)
        if not validation['valid']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid policy document: {validation['errors']}"
            )

        tags = None
        if request.tags:
            tags = [{"Key": k, "Value": v} for k, v in request.tags.items()]

        policy = iam_service.create_managed_policy(
            policy_name=request.policy_name,
            policy_document=request.policy_document,
            description=request.description or "",
            path=request.path,
            tags=tags
        )

        return PolicyCreateResponse(
            policy_name=policy['PolicyName'],
            policy_arn=policy['Arn'],
            policy_id=policy['PolicyId'],
            created_at=policy['CreateDate'],
            message=f"Policy {policy['PolicyName']} created successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("policy_creation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create policy: {str(e)}"
        )


@router.delete("/policies", response_model=GenericSuccessResponse)
async def delete_policy(
    policy_arn: str,
    force: bool = False,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Delete a managed policy"""
    try:
        logger.info("policy_deletion_requested", policy_arn=policy_arn, force=force)

        result = iam_service.delete_managed_policy(policy_arn=policy_arn, force=force)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("policy_deletion_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete policy: {str(e)}"
        )


@router.post("/policies/attach", response_model=GenericSuccessResponse)
async def attach_policy(
    request: PolicyAttachRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Attach policy to a principal (user, group, or role)"""
    try:
        logger.info("policy_attach_requested", policy_arn=request.policy_arn, principal=request.principal_name)

        if request.principal_type == "user":
            result = iam_service.attach_policy_to_user(request.principal_name, request.policy_arn)
        elif request.principal_type == "group":
            result = iam_service.attach_policy_to_group(request.principal_name, request.policy_arn)
        elif request.principal_type == "role":
            result = iam_service.attach_policy_to_role(request.principal_name, request.policy_arn)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="principal_type must be one of: user, group, role"
            )

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("policy_attach_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to attach policy: {str(e)}"
        )


@router.post("/policies/detach", response_model=GenericSuccessResponse)
async def detach_policy(
    request: PolicyDetachRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Detach policy from a principal (user, group, or role)"""
    try:
        logger.info("policy_detach_requested", policy_arn=request.policy_arn, principal=request.principal_name)

        if request.principal_type == "user":
            result = iam_service.detach_policy_from_user(request.principal_name, request.policy_arn)
        elif request.principal_type == "group":
            result = iam_service.detach_policy_from_group(request.principal_name, request.policy_arn)
        elif request.principal_type == "role":
            result = iam_service.detach_policy_from_role(request.principal_name, request.policy_arn)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="principal_type must be one of: user, group, role"
            )

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("policy_detach_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to detach policy: {str(e)}"
        )


# ==================== Account Settings Endpoints ====================

@router.put("/account/password-policy", response_model=GenericSuccessResponse)
async def update_password_policy(
    request: PasswordPolicyUpdateRequest,
    iam_service: IAMService = Depends(get_iam_service)
):
    """Update account password policy"""
    try:
        logger.info("password_policy_update_requested")

        policy_settings = {
            'MinimumPasswordLength': request.minimum_password_length,
            'RequireSymbols': request.require_symbols,
            'RequireNumbers': request.require_numbers,
            'RequireUppercaseCharacters': request.require_uppercase_characters,
            'RequireLowercaseCharacters': request.require_lowercase_characters,
            'AllowUsersToChangePassword': request.allow_users_to_change_password,
            'ExpirePasswords': request.expire_passwords,
            'MaxPasswordAge': request.max_password_age if request.expire_passwords else None,
            'PasswordReusePrevention': request.password_reuse_prevention,
            'HardExpiry': request.hard_expiry
        }

        # Remove None values
        policy_settings = {k: v for k, v in policy_settings.items() if v is not None}

        result = iam_service.update_account_password_policy(**policy_settings)

        return GenericSuccessResponse(
            success=True,
            message=result['message']
        )

    except Exception as e:
        logger.error("password_policy_update_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update password policy: {str(e)}"
        )


@router.get("/account/password-policy", response_model=PasswordPolicyGetResponse)
async def get_password_policy(
    iam_service: IAMService = Depends(get_iam_service)
):
    """Get current account password policy"""
    try:
        logger.info("password_policy_get_requested")

        response = iam_service.client.get_account_password_policy()
        policy = response.get('PasswordPolicy', {})

        return PasswordPolicyGetResponse(
            policy=policy,
            message="Password policy retrieved successfully"
        )

    except iam_service.client.exceptions.NoSuchEntityException:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No password policy configured for this account"
        )
    except Exception as e:
        logger.error("password_policy_get_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get password policy: {str(e)}"
        )


# ==================== AWS Restrictions Documentation ====================

@router.get("/restrictions")
async def get_aws_restrictions():
    """
    Get documentation of AWS features restricted to Console/CLI only
    """
    return {
        "restricted_features": [
            {
                "feature_name": "Root User Management",
                "restriction_type": "console_only",
                "description": "Root user credentials and MFA can only be managed through AWS Console",
                "alternative": "Use IAM users with appropriate permissions instead"
            },
            {
                "feature_name": "Account Closure",
                "restriction_type": "console_only",
                "description": "AWS account closure must be initiated through Console",
                "alternative": None
            },
            {
                "feature_name": "Billing IAM Features",
                "restriction_type": "console_only",
                "description": "Some billing-related IAM features require Console access",
                "alternative": "Use AWS Organizations for delegated billing management"
            },
            {
                "feature_name": "Service-Linked Role Creation (some services)",
                "restriction_type": "not_available_via_api",
                "description": "Some AWS services automatically create service-linked roles that cannot be created via API",
                "alternative": "Service-linked roles are created automatically when needed by the service"
            },
            {
                "feature_name": "Hardware MFA Device Association",
                "restriction_type": "console_only",
                "description": "Hardware MFA devices must be associated through Console",
                "alternative": "Virtual MFA can be managed via API"
            },
            {
                "feature_name": "IAM Access Analyzer (some features)",
                "restriction_type": "console_only",
                "description": "Some IAM Access Analyzer features work best through Console",
                "alternative": "API available for programmatic access to findings"
            }
        ],
        "note": "This list covers major restrictions. AWS continues to add API support for more features over time."
    }
